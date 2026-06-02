/**
 * AWS supply-chain / change-validation collectors.
 * Covers KSI-CMT-RMV (Redeploying vs Modifying), KSI-CMT-VTD (Validating
 * Throughout Deployment), and KSI-SCR-MON (Monitoring Supply Chain Risk).
 */
import { DescribeRepositoriesCommand, ListImagesCommand } from '@aws-sdk/client-ecr';
import { DescribeLaunchTemplatesCommand } from '@aws-sdk/client-ec2';
import { DescribeAutoScalingGroupsCommand } from '@aws-sdk/client-auto-scaling';
import { ListFunctionsCommand, GetFunctionCodeSigningConfigCommand } from '@aws-sdk/client-lambda';
import { ListPipelinesCommand, GetPipelineCommand } from '@aws-sdk/client-codepipeline';
import { ListProjectsCommand, BatchGetProjectsCommand } from '@aws-sdk/client-codebuild';
import { ListSigningProfilesCommand } from '@aws-sdk/client-signer';
import { GetConfigurationCommand as InspectorGetConfigCommand, ListFindingsCommand as InspectorListFindingsCommand } from '@aws-sdk/client-inspector2';

import * as aws from '../../core/auth/aws.ts';
import type { ProviderBlock, RawEvidence, AffectedResource, AlternativeSatisfier, ThirdPartyToolMatch } from '../../core/envelope.ts';
import { finding } from '../../core/findings.ts';
import type { CollectorContext } from '../../core/ksi-map.ts';
import { detect as detectThirdParty } from '../../core/detect/third-party-tools.ts';

function ev(source: string, data: unknown): RawEvidence { return { source, captured_at: new Date().toISOString(), data: data === undefined ? null : data }; }

interface Ctx { region: string; auth: aws.AwsAuth; account: string | null; }
async function setupCtx(c: CollectorContext): Promise<Ctx> {
  const region = c.aws?.region ?? 'us-east-1';
  const auth = c.aws?.auth ?? aws.makeAwsAuth(region);
  let account = c.aws?.account_id ?? null;
  if (!account) { try { account = (await aws.whoAmI(auth)).account; } catch { /* */ } }
  return { region, auth, account };
}

// =====================================================================
// KSI-CMT-RMV — Redeploying vs Modifying (immutable infrastructure)
// =====================================================================
export async function collectCmtRmv(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // ECR repositories — immutability check
  interface RepoStatus { name: string; mutability: string; scanOnPush: boolean; }
  const ecrRepos: RepoStatus[] = [];
  try {
    const ecr = aws.ecr(ctx.auth);
    let tok: string | undefined;
    do {
      const r = await ecr.send(new DescribeRepositoriesCommand({ nextToken: tok, maxResults: 100 }));
      for (const repo of r.repositories ?? []) {
        ecrRepos.push({
          name: repo.repositoryName ?? '?',
          mutability: repo.imageTagMutability ?? 'MUTABLE',
          scanOnPush: !!repo.imageScanningConfiguration?.scanOnPush,
        });
      }
      tok = r.nextToken;
    } while (tok);
    evidence.push(ev('ecr.DescribeRepositories', ecrRepos));
  } catch (e: any) { warnings.push(`ECR: ${e.message}`); }

  // Launch templates + ASG version pinning
  let launchTemplateCount = 0;
  let asgsUsingLatest: string[] = [];
  let asgsTotal = 0;
  try {
    const ec2 = aws.ec2(ctx.auth);
    const lt = await ec2.send(new DescribeLaunchTemplatesCommand({ MaxResults: 200 }));
    launchTemplateCount = lt.LaunchTemplates?.length ?? 0;
    evidence.push(ev('ec2.DescribeLaunchTemplates', { count: launchTemplateCount }));

    const asg = aws.autoScaling(ctx.auth);
    const a = await asg.send(new DescribeAutoScalingGroupsCommand({}));
    for (const g of a.AutoScalingGroups ?? []) {
      asgsTotal++;
      const lts = g.LaunchTemplate;
      const mip = g.MixedInstancesPolicy?.LaunchTemplate?.LaunchTemplateSpecification;
      const v = lts?.Version ?? mip?.Version;
      if (v === '$Latest' || v === '$Default') asgsUsingLatest.push(g.AutoScalingGroupName ?? '?');
    }
    evidence.push(ev('autoscaling.version_pinning', { total: asgsTotal, using_floating_version: asgsUsingLatest }));
  } catch (e: any) { warnings.push(`Launch templates / ASGs: ${e.message}`); }

  // Lambda code signing
  let lambdaTotal = 0;
  let lambdaWithCodeSigning = 0;
  try {
    const lambda = aws.lambda(ctx.auth);
    let tok: string | undefined;
    do {
      const r = await lambda.send(new ListFunctionsCommand({ Marker: tok, MaxItems: 50 }));
      for (const f of r.Functions ?? []) {
        lambdaTotal++;
        if (!f.FunctionName) continue;
        try {
          const cs = await lambda.send(new GetFunctionCodeSigningConfigCommand({ FunctionName: f.FunctionName }));
          if (cs.CodeSigningConfigArn) lambdaWithCodeSigning++;
        } catch { /* no signing config */ }
      }
      tok = r.NextMarker;
    } while (tok);
    evidence.push(ev('lambda.code_signing', { total: lambdaTotal, with_signing: lambdaWithCodeSigning }));
  } catch (e: any) { warnings.push(`Lambda: ${e.message}`); }

  // Signer profiles
  let signingProfileCount = 0;
  try {
    const sg = aws.signer(ctx.auth);
    const r = await sg.send(new ListSigningProfilesCommand({}));
    signingProfileCount = r.profiles?.length ?? 0;
    evidence.push(ev('signer.profile_count', { count: signingProfileCount }));
  } catch (e: any) { warnings.push(`Signer: ${e.message}`); }

  const mutableRepos = ecrRepos.filter((r) => r.mutability !== 'IMMUTABLE');

  const findings = [
    finding({
      rule: 'aws.ecr.image_tag_immutable',
      passed: mutableRepos.length === 0,
      severity: 'high',
      current: {
        summary: ecrRepos.length === 0
          ? 'No ECR repositories found (containers may live outside ECR).'
          : (mutableRepos.length === 0
            ? `All ${ecrRepos.length} ECR repo(s) are IMMUTABLE.`
            : `${mutableRepos.length} of ${ecrRepos.length} ECR repo(s) are MUTABLE.`),
        observations: { all_repos: ecrRepos, mutable: mutableRepos.map((r) => r.name) },
      },
      target: { summary: 'Every prod ECR repository has imageTagMutability=IMMUTABLE.', rationale: 'NIST CM-2, SA-10. Mutable tags break the immutable-infrastructure guarantee.' },
      gap: mutableRepos.length === 0 ? undefined : {
        description: 'Mutable tags let `:latest` (or any tag) be silently overwritten — defeats immutability.',
        affected_resources: mutableRepos.map<AffectedResource>((r) => ({
          type: 'aws_ecr_repository', identifier: r.name, name: r.name, attributes: { mutability: r.mutability },
        })),
      },
      remediation: mutableRepos.length === 0 ? undefined : {
        summary: 'Set imageTagMutability=IMMUTABLE on each repo.',
        options: [{
          approach: 'Apply via Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'Pushes to existing tags will start failing; pipelines must push unique tags.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Audit pipelines first to ensure they push unique tags.' },
          steps: ['Audit pipelines for `docker push :latest`; replace with unique tags (commit SHA).', 'Set image_tag_mutability="IMMUTABLE" via Terraform.', 'Verify pipelines work.'],
          example_code: `resource "aws_ecr_repository" "app" {
  name                 = "app"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
}`,
          references: [{ title: 'ECR image tag mutability', url: 'https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['cm-2','cm-2.2','sa-10'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-CMT-VTD', relationship: 'shares-remediation', note: 'Immutable images are a prerequisite for attestation-based deployment gates.' },
        { ksi_id: 'KSI-SVC-VRI', relationship: 'shares-remediation', note: 'Resource-integrity validation requires immutability.' },
      ],
    }),

    finding({
      rule: 'aws.asg.version_pinning_not_latest',
      passed: asgsUsingLatest.length === 0,
      severity: 'high',
      current: {
        summary: asgsUsingLatest.length === 0
          ? `All ${asgsTotal} ASG(s) pin to a specific launch-template version.`
          : `${asgsUsingLatest.length} of ${asgsTotal} ASG(s) reference \`$Latest\` or \`$Default\`.`,
        observations: { total_asgs: asgsTotal, using_floating_version: asgsUsingLatest, launch_template_count: launchTemplateCount },
      },
      target: { summary: 'Prod ASGs reference a specific launch-template version (not \`$Latest\`/\`$Default\`).', rationale: 'NIST CM-2. Floating versions cause non-deterministic launches; immutability requires pinning.' },
      gap: asgsUsingLatest.length === 0 ? undefined : {
        description: 'Floating-version ASGs may launch a different config than expected on next scale event.',
        affected_resources: asgsUsingLatest.map<AffectedResource>((n) => ({
          type: 'aws_autoscaling_group', identifier: n, name: n, attributes: { version: '$Latest or $Default' },
        })),
      },
      remediation: asgsUsingLatest.length === 0 ? undefined : {
        summary: 'Pin each ASG to a specific launch-template version.',
        options: [{
          approach: 'Update launch_template.version in Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'low', notes: 'Pipeline updates must bump the version explicitly.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Per ASG + pipeline change.' },
          steps: ['Reference a specific version in Terraform.', 'Update deploy pipeline to bump version explicitly.', 'Verify next scale event uses the pinned version.'],
          example_code: `resource "aws_autoscaling_group" "app" {
  launch_template {
    id      = aws_launch_template.app.id
    version = aws_launch_template.app.latest_version
  }
}`,
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['cm-2'],
    }),

    finding({
      rule: 'aws.lambda.code_signing_in_use',
      // Vacuously satisfied when there are no Lambdas (nothing to sign).
      passed: lambdaTotal === 0 || lambdaWithCodeSigning >= 1,
      severity: 'medium',
      current: {
        summary: lambdaWithCodeSigning === 0 && lambdaTotal === 0
          ? 'No Lambda functions (and no code signing in use).'
          : `${lambdaWithCodeSigning} of ${lambdaTotal} Lambda function(s) have code signing configured. ${signingProfileCount} Signer profile(s).`,
        observations: { lambda_total: lambdaTotal, with_signing: lambdaWithCodeSigning, signing_profiles: signingProfileCount },
      },
      target: { summary: 'Prod Lambda functions have code-signing configurations with required signing.', rationale: 'NIST SI-7. Code-signing is the Lambda equivalent of image immutability.' },
      gap: (lambdaWithCodeSigning >= 1 || lambdaTotal === 0) ? undefined : {
        description: 'Lambda code can be replaced without signature verification.',
        affected_resources: [{ type: 'aws_lambda_function', identifier: 'aggregate', attributes: { total: lambdaTotal, without_signing: lambdaTotal - lambdaWithCodeSigning } }],
      },
      remediation: (lambdaWithCodeSigning >= 1 || lambdaTotal === 0) ? undefined : {
        summary: 'Create AWS Signer profile + code-signing config; attach to prod functions.',
        options: [{
          approach: 'Set up code signing via Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'low', notes: 'Signer charges per signature.' },
          availability_impact: { level: 'medium', notes: 'Deploys must include signed packages; unsigned deploys will fail.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Signer setup + CI/CD changes.' },
          steps: ['Create aws_signer_signing_profile.', 'Create aws_lambda_code_signing_config.', 'Update CI to sign packages.', 'Attach code_signing_config_arn to Lambda functions.'],
          example_code: `resource "aws_signer_signing_profile" "lambda" {
  platform_id = "AWSLambda-SHA384-ECDSA"
}
resource "aws_lambda_code_signing_config" "this" {
  allowed_publishers { signing_profile_version_arns = [aws_signer_signing_profile.lambda.version_arn] }
  policies { untrusted_artifact_on_deployment = "Enforce" }
}`,
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['si-7','si-7.1'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-SVC-VRI', relationship: 'shares-remediation', note: 'Code signing is the Lambda VRI evidence.' },
      ],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-CMT-VTD — Validating Throughout Deployment
// =====================================================================
export async function collectCmtVtd(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // CodePipeline inventory + stage analysis
  interface PipelineRecord { name: string; stages: Array<{ name: string; actions: string[] }>; hasTestStage: boolean; hasScanStage: boolean; hasManualApproval: boolean; }
  const pipelines: PipelineRecord[] = [];
  try {
    const cp = aws.codepipeline(ctx.auth);
    const lst = await cp.send(new ListPipelinesCommand({}));
    for (const p of lst.pipelines ?? []) {
      if (!p.name) continue;
      try {
        const d = await cp.send(new GetPipelineCommand({ name: p.name }));
        const stages = (d.pipeline?.stages ?? []).map((s: any) => ({
          name: s.name,
          actions: (s.actions ?? []).map((a: any) => a.actionTypeId?.category + '/' + a.actionTypeId?.provider),
        }));
        const stageNames = stages.map((s) => s.name.toLowerCase());
        const actionCategories = stages.flatMap((s) => s.actions);
        const rec: PipelineRecord = {
          name: p.name,
          stages,
          hasTestStage: stageNames.some((n) => /test|qa/i.test(n)) || actionCategories.some((a) => /Test/.test(a)),
          hasScanStage: stageNames.some((n) => /scan|security/i.test(n)),
          hasManualApproval: actionCategories.some((a) => /Approval/.test(a)),
        };
        pipelines.push(rec);
      } catch (e: any) { warnings.push(`GetPipeline ${p.name}: ${e.message}`); }
    }
    evidence.push(ev('codepipeline.pipeline_audit', pipelines));
  } catch (e: any) { warnings.push(`CodePipeline: ${e.message}`); }

  // CodeBuild projects — surface count + buildspec source pointer
  interface BuildProjectInfo { name: string; source: string | null; }
  const buildProjects: BuildProjectInfo[] = [];
  try {
    const cb = aws.codebuild(ctx.auth);
    let tok: string | undefined;
    const allNames: string[] = [];
    do {
      const r = await cb.send(new ListProjectsCommand({ nextToken: tok }));
      allNames.push(...(r.projects ?? []));
      tok = r.nextToken;
    } while (tok);
    if (allNames.length > 0) {
      const batch = await cb.send(new BatchGetProjectsCommand({ names: allNames.slice(0, 100) }));
      for (const p of batch.projects ?? []) {
        buildProjects.push({ name: p.name ?? '?', source: p.source?.type ?? null });
      }
    }
    evidence.push(ev('codebuild.projects', { count: buildProjects.length, sample: buildProjects.slice(0, 10) }));
  } catch (e: any) { warnings.push(`CodeBuild: ${e.message}`); }

  // Inspector — enabled?
  let inspectorEnabled = false;
  let inspectorCriticalFindings = 0;
  try {
    const ins = aws.inspector2(ctx.auth);
    const cfg = await ins.send(new InspectorGetConfigCommand({}));
    inspectorEnabled = !!cfg.ec2Configuration || !!cfg.ecrConfiguration;
    evidence.push(ev('inspector2.config', cfg));
    try {
      const f = await ins.send(new InspectorListFindingsCommand({
        filterCriteria: { severity: [{ comparison: 'EQUALS', value: 'CRITICAL' }] },
        maxResults: 100,
      }));
      inspectorCriticalFindings = f.findings?.length ?? 0;
      evidence.push(ev('inspector2.critical_finding_count', inspectorCriticalFindings));
    } catch { /* */ }
  } catch (e: any) { warnings.push(`Inspector2: ${e.message}`); }

  const prodPipelinesWithoutTest = pipelines.filter((p) => !p.hasTestStage).map((p) => p.name);
  const prodPipelinesWithoutScan = pipelines.filter((p) => !p.hasScanStage).map((p) => p.name);

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'GitHub Actions / GitLab CI / your own CI/CD product (self-eating)',
      description: 'CI runs outside AWS native services; gates live in pipeline YAML in source repos. Detection requires repo access.',
      evidence_required: [
        'Pipeline YAML excerpt with SAST/SCA/secret-scan steps',
        'Sample build log showing scanner pass',
        'Branch protection requiring CI green before merge',
      ],
      detected: pipelines.length === 0,
      detection_signals: pipelines.length === 0 ? ['No CodePipeline pipelines found — CI likely lives off-AWS.'] : [],
    },
  ];

  const findings = [
    finding({
      rule: 'aws.codepipeline.prod_pipelines_have_test_stage',
      passed: pipelines.length === 0 || prodPipelinesWithoutTest.length === 0,
      severity: 'high',
      current: {
        summary: pipelines.length === 0
          ? 'No CodePipeline pipelines (CI likely off-AWS).'
          : (prodPipelinesWithoutTest.length === 0
            ? `All ${pipelines.length} pipeline(s) have a Test stage.`
            : `${prodPipelinesWithoutTest.length} of ${pipelines.length} pipeline(s) have no Test stage.`),
        observations: pipelines.map((p) => ({ name: p.name, stages: p.stages.map((s) => s.name), hasTest: p.hasTestStage, hasScan: p.hasScanStage, hasApproval: p.hasManualApproval })),
      },
      target: { summary: 'Every pipeline deploying to prod has at least one stage running automated tests.', rationale: 'NIST CM-3.2, SA-11. Test gates are the validate-during-deployment KSI core.' },
      gap: (pipelines.length === 0 || prodPipelinesWithoutTest.length === 0) ? undefined : {
        description: 'Pipelines without test gates can deploy untested code.',
        affected_resources: prodPipelinesWithoutTest.map<AffectedResource>((n) => ({
          type: 'aws_codepipeline', identifier: n, name: n, attributes: {},
        })),
      },
      remediation: (pipelines.length === 0 || prodPipelinesWithoutTest.length === 0) ? undefined : {
        summary: 'Add a Test stage to each prod pipeline with CodeBuild project running tests.',
        options: [{
          approach: 'Add a Test stage between Build and Deploy via Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'low', notes: 'CodeBuild minutes.' },
          availability_impact: { level: 'medium', notes: 'Failing tests will block deploys; expected behavior.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per pipeline.' },
          steps: ['Define a CodeBuild project that runs tests.', 'Add a Test stage in each pipeline.', 'Verify failing tests block deploy.'],
          references: [{ title: 'CodePipeline + CodeBuild test', url: 'https://docs.aws.amazon.com/codepipeline/latest/userguide/welcome.html' }],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['cm-3.2','sa-11','sa-11.1'],
    }),

    finding({
      rule: 'aws.codepipeline.prod_pipelines_have_scan_stage',
      passed: pipelines.length === 0 || prodPipelinesWithoutScan.length === 0,
      severity: 'high',
      current: {
        summary: pipelines.length === 0
          ? 'No CodePipeline pipelines (CI likely off-AWS).'
          : (prodPipelinesWithoutScan.length === 0
            ? `All ${pipelines.length} pipeline(s) have a scan/security stage.`
            : `${prodPipelinesWithoutScan.length} of ${pipelines.length} pipeline(s) have no scan stage.`),
        observations: { pipelines_without_scan_stage: prodPipelinesWithoutScan },
      },
      target: { summary: 'Each prod pipeline has a stage named "scan" or "security" that runs SAST/SCA/IaC scanners.', rationale: 'NIST RA-5, CM-3.2.' },
      gap: (pipelines.length === 0 || prodPipelinesWithoutScan.length === 0) ? undefined : {
        description: 'Without scan gates, vulnerable code can ship.',
        affected_resources: prodPipelinesWithoutScan.map<AffectedResource>((n) => ({ type: 'aws_codepipeline', identifier: n, name: n, attributes: {} })),
      },
      remediation: (pipelines.length === 0 || prodPipelinesWithoutScan.length === 0) ? undefined : {
        summary: 'Add a Scan stage invoking SAST/SCA tooling.',
        options: [{
          approach: 'Add scan stage with Inspector or 3rd-party scanner.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'Scanner minutes.' },
          availability_impact: { level: 'medium', notes: 'Failing scans block deploys.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Pipeline updates + scanner tuning.' },
          steps: ['Add Inspector / SAST scan to a CodeBuild project.', 'Wire as a pipeline stage that fails the build on critical findings.', 'Tune false positives.'],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['ra-5','cm-3.2'],
    }),

    finding({
      rule: 'aws.inspector.enabled_for_supported_types',
      passed: inspectorEnabled,
      severity: 'high',
      current: {
        summary: inspectorEnabled ? 'Inspector is enabled.' : 'Inspector is not enabled — vuln scanning of EC2/ECR/Lambda is off.',
        observations: { enabled: inspectorEnabled, critical_findings: inspectorCriticalFindings },
      },
      target: { summary: 'Inspector enabled for EC2, ECR, Lambda. Critical findings gate deploys via EventBridge → Lambda block.', rationale: 'NIST RA-5, SI-2.' },
      gap: inspectorEnabled ? undefined : {
        description: 'No native runtime/build-time vuln scanning.',
        affected_resources: [{ type: 'aws_inspector2_enabler', identifier: ctx.account ?? '', attributes: { enabled: false } }],
      },
      remediation: inspectorEnabled ? undefined : {
        summary: 'Enable Inspector via Terraform.',
        options: [{
          approach: 'Enable for all supported types.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'medium', notes: 'Per-finding charges; hundreds-thousands/month at scale.' },
          availability_impact: { level: 'none', notes: 'Pure observation.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Enable + triage initial findings.' },
          steps: ['Enable Inspector.', 'Subscribe accounts via Organizations delegated admin.', 'Wire EventBridge → ticket on Critical findings.'],
          example_code: `resource "aws_inspector2_enabler" "this" {
  account_ids    = [data.aws_caller_identity.this.account_id]
  resource_types = ["EC2", "ECR", "LAMBDA"]
}`,
          references: [{ title: 'Inspector2', url: 'https://docs.aws.amazon.com/inspector/latest/user/what-is-inspector.html' }],
        }],
      },
      alternative_satisfiers: [
        { via: '3rd-party scanner (Snyk, Wiz Code, Aqua, Trivy)', description: 'External vuln scanner running in CI.', evidence_required: ['Scanner config', 'Recent finding export'], detected: false },
      ],
      nist_controls: ['ra-5','si-2'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, ksi_level_alternatives: altSatisfiers, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-SCR-MON — Monitoring Supply Chain Risk (HYBRID)
// Active vulnerability monitoring for 3rd-party deps + container base images.
// =====================================================================
export async function collectScrMon(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // Inspector configuration + finding counts by severity
  let inspectorEnabled = false;
  let inspectorEnabledTypes: string[] = [];
  let criticalFindings = 0;
  let highFindings = 0;
  try {
    const ins = aws.inspector2(ctx.auth);
    const cfg = await ins.send(new InspectorGetConfigCommand({}));
    inspectorEnabled = !!cfg.ec2Configuration || !!cfg.ecrConfiguration;
    if (cfg.ec2Configuration) inspectorEnabledTypes.push('EC2');
    if (cfg.ecrConfiguration) inspectorEnabledTypes.push('ECR');
    evidence.push(ev('inspector2.config_for_scr_mon', cfg));

    try {
      const cr = await ins.send(new InspectorListFindingsCommand({
        filterCriteria: { severity: [{ comparison: 'EQUALS', value: 'CRITICAL' }] },
        maxResults: 100,
      }));
      criticalFindings = cr.findings?.length ?? 0;
    } catch { /* */ }
    try {
      const hi = await ins.send(new InspectorListFindingsCommand({
        filterCriteria: { severity: [{ comparison: 'EQUALS', value: 'HIGH' }] },
        maxResults: 100,
      }));
      highFindings = hi.findings?.length ?? 0;
    } catch { /* */ }
    evidence.push(ev('inspector2.finding_counts', { critical: criticalFindings, high: highFindings }));
  } catch (e: any) { warnings.push(`Inspector2: ${e.message}`); }

  // ECR scan-on-push
  let ecrReposTotal = 0;
  let ecrReposWithScanOnPush = 0;
  try {
    const ecr = aws.ecr(ctx.auth);
    const r = await ecr.send(new DescribeRepositoriesCommand({ maxResults: 100 }));
    for (const repo of r.repositories ?? []) {
      ecrReposTotal++;
      if (repo.imageScanningConfiguration?.scanOnPush) ecrReposWithScanOnPush++;
    }
    evidence.push(ev('ecr.scan_on_push_audit', { total: ecrReposTotal, with_scan: ecrReposWithScanOnPush }));
  } catch (e: any) { warnings.push(`ECR scan audit: ${e.message}`); }

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'Snyk / Aqua / Wiz Code / Trivy in CI',
      description: '3rd-party SCA scanner running in CI.',
      evidence_required: ['Scanner config in pipeline', 'Recent finding export', 'Severity-SLA policy'],
      detected: false,
      detection_signals: [],
    },
    {
      via: 'Dependabot / Renovate for dep updates',
      description: 'Source-control-side dep monitoring + PR automation.',
      evidence_required: ['.github/dependabot.yml or renovate.json', 'Sample auto-PR'],
      detected: false,
      detection_signals: [],
    },
  ];

  const findings = [
    finding({
      rule: 'aws.inspector.enabled_with_findings_managed',
      passed: inspectorEnabled,
      severity: 'high',
      current: {
        summary: inspectorEnabled
          ? `Inspector enabled for: ${inspectorEnabledTypes.join(', ')}. Findings: ${criticalFindings} critical, ${highFindings} high.`
          : 'Inspector not enabled — no native runtime/build-time vuln scanning.',
        observations: { enabled: inspectorEnabled, enabled_types: inspectorEnabledTypes, critical: criticalFindings, high: highFindings },
      },
      target: { summary: 'Inspector enabled for ECR + EC2 + Lambda. Critical findings within SLA (default 30d); high findings tracked.', rationale: 'NIST RA-5, SI-2. Supply-chain vuln scanning core.' },
      gap: inspectorEnabled ? undefined : {
        description: 'No native vuln scanning.',
        affected_resources: [{ type: 'aws_inspector2_enabler', identifier: ctx.account ?? '', attributes: { enabled: false } }],
      },
      remediation: inspectorEnabled ? undefined : {
        summary: 'See KSI-CMT-VTD remediation — same Inspector enabler.',
        options: [{
          approach: 'Enable Inspector via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'medium', notes: 'Per-finding charges.' },
          availability_impact: { level: 'none', notes: 'Pure observation.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Enable + finding triage.' },
          steps: ['See CMT-VTD remediation.'],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['ra-5','si-2'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-CMT-VTD', relationship: 'shares-remediation', note: 'Same Inspector + scan-stage infrastructure.' },
      ],
    }),

    finding({
      rule: 'aws.ecr.scan_on_push_enabled',
      passed: ecrReposTotal === 0 || ecrReposWithScanOnPush === ecrReposTotal,
      severity: 'high',
      current: {
        summary: ecrReposTotal === 0
          ? 'No ECR repos.'
          : `${ecrReposWithScanOnPush} of ${ecrReposTotal} ECR repo(s) have scan-on-push enabled.`,
        observations: { total: ecrReposTotal, with_scan_on_push: ecrReposWithScanOnPush },
      },
      target: { summary: 'All ECR repos have scan-on-push enabled. Combined with Inspector for continuous re-scan.', rationale: 'NIST RA-5.' },
      gap: (ecrReposTotal === 0 || ecrReposWithScanOnPush === ecrReposTotal) ? undefined : {
        description: 'Some repos accept images without vulnerability scanning.',
        affected_resources: [{ type: 'aws_ecr_repository', identifier: 'aggregate', attributes: { without_scan: ecrReposTotal - ecrReposWithScanOnPush } }],
      },
      remediation: (ecrReposTotal === 0 || ecrReposWithScanOnPush === ecrReposTotal) ? undefined : {
        summary: 'Enable scan-on-push on every repo via Terraform.',
        options: [{
          approach: 'Set image_scanning_configuration via Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free (with Inspector).' },
          availability_impact: { level: 'none', notes: 'Pure observation.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Apply Terraform.' },
          steps: ['Set image_scanning_configuration.scan_on_push=true on every repo.', 'Apply.'],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['ra-5'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, ksi_level_alternatives: altSatisfiers, third_party_tools_detected: thirdParty };
}
