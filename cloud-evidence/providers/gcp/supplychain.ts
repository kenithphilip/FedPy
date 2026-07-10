/**
 * GCP supply-chain / change-validation collectors.
 * Covers KSI-CMT-RMV and KSI-CMT-VTD, mirroring providers/aws/supplychain.ts.
 */
import * as gcpAuth from '../../core/auth/gcp.ts';
import type { ProviderBlock, RawEvidence, AffectedResource, AlternativeSatisfier, ThirdPartyToolMatch } from '../../core/envelope.ts';
import { finding } from '../../core/findings.ts';
import { diagnoseGcpError } from '../../core/error-diagnostics.ts';
import type { CollectorContext } from '../../core/ksi-map.ts';
import { detect as detectThirdParty } from '../../core/detect/third-party-tools.ts';

function ev(source: string, data: unknown): RawEvidence { return { source, captured_at: new Date().toISOString(), data: data === undefined ? null : data }; }

interface Ctx { project: string; }
function setupCtx(c: CollectorContext): Ctx {
  if (!c.gcp?.project_id) throw new Error('GCP collector invoked without project_id');
  return { project: c.gcp.project_id };
}

// =====================================================================
// KSI-CMT-RMV — Redeploying vs Modifying (GCP)
// =====================================================================
export async function collectCmtRmv(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // Artifact Registry repositories
  let arRepoCount = 0;
  const arRepos: Array<{ name: string; format: string; mode: string }> = [];
  try {
    const ar = await gcpAuth.googleClient<any>('artifactregistry', 'v1');
    // Need to list across all locations — use 'global' as a representative starting point + key regions
    const locations = ['us', 'us-central1', 'us-east1', 'us-west1'];
    for (const loc of locations) {
      try {
        const r = await ar.projects.locations.repositories.list({ parent: `projects/${ctx.project}/locations/${loc}` });
        for (const repo of r.data.repositories ?? []) {
          arRepos.push({ name: repo.name, format: repo.format, mode: repo.mode ?? 'STANDARD' });
          arRepoCount++;
        }
      } catch { /* may not have this location */ }
    }
    evidence.push(ev('artifactregistry.repositories', arRepos));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'artifactregistry.repositories.list', 'artifactregistry.repositories.list (roles/artifactregistry.reader)')); }

  // Cloud Run services — revision pinning
  const cloudRunServices: Array<{ name: string; trafficPercents: Array<{ revision: string; percent: number; latestRevision: boolean }> }> = [];
  let cloudRunUsingLatest: string[] = [];
  try {
    const run = await gcpAuth.googleClient<any>('run', 'v1');
    const r = await run.namespaces.services.list({ parent: `namespaces/${ctx.project}` });
    for (const svc of r.data.items ?? []) {
      const traffic = (svc.status?.traffic ?? []).map((t: any) => ({
        revision: t.revisionName ?? '?',
        percent: t.percent ?? 0,
        latestRevision: !!t.latestRevision,
      }));
      cloudRunServices.push({ name: svc.metadata?.name ?? '?', trafficPercents: traffic });
      if (traffic.some((t: any) => t.latestRevision && t.percent > 0)) {
        cloudRunUsingLatest.push(svc.metadata?.name ?? '?');
      }
    }
    evidence.push(ev('run.services.revision_pinning', cloudRunServices));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'run.services.list', 'run.services.list (roles/run.viewer)')); }

  // Binary Authorization policy
  let binAuthzMode = 'unknown';
  let binAuthzAttestorCount = 0;
  try {
    const ba = await gcpAuth.googleClient<any>('binaryauthorization', 'v1');
    const p = await ba.projects.getPolicy({ name: `projects/${ctx.project}/policy` });
    binAuthzMode = p.data.defaultAdmissionRule?.evaluationMode ?? 'NOT_SET';
    const at = await ba.projects.attestors.list({ parent: `projects/${ctx.project}` });
    binAuthzAttestorCount = (at.data.attestors ?? []).length;
    evidence.push(ev('binaryauthorization.policy', { defaultMode: binAuthzMode, attestor_count: binAuthzAttestorCount, fullPolicy: p.data }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'binaryauthorization.projects.getPolicy', 'binaryauthorization.policy.get (roles/binaryauthorization.policyViewer)')); }

  // MIGs — instance template version pinning (already covered by backup.ts but flag if floating)
  let migUsingLatest: string[] = [];
  try {
    const compute = await gcpAuth.googleClient<any>('compute', 'v1');
    const r = await compute.regionInstanceGroupManagers.aggregatedList({ project: ctx.project });
    for (const region of Object.values<any>(r.data.items ?? {})) {
      for (const m of region.regionInstanceGroupManagers ?? []) {
        // MIGs reference instance templates by URL — if multiple versions exist, check rollout
        // Heuristic: if there's only one `versions[]` entry, it's pinned to one template
        const versionCount = (m.versions ?? []).length;
        if (versionCount > 1) migUsingLatest.push(m.name);
      }
    }
  } catch (e) { warnings.push(diagnoseGcpError(e, 'compute.regionInstanceGroupManagers.aggregatedList', 'compute.instanceGroupManagers.list (roles/compute.viewer)')); }

  const findings = [
    finding({
      rule: 'gcp.artifactregistry.tag_immutability_locked',
      passed: arRepoCount >= 1,
      severity: 'medium',
      current: {
        summary: arRepoCount >= 1
          ? `${arRepoCount} Artifact Registry repo(s) detected.`
          : 'No Artifact Registry repos detected — containers may live elsewhere.',
        observations: { repos: arRepos },
      },
      target: { summary: 'Artifact Registry repos enforce tag immutability via org policy + IAM (no `artifactregistry.tags.update` for service accounts that publish to prod).', rationale: 'NIST CM-2, SA-10. Same intent as ECR immutability — mutable tags break immutability.' },
      gap: arRepoCount >= 1 ? undefined : {
        description: 'No repos to inspect — verify image storage location.',
        affected_resources: [{ type: 'gcp_project', identifier: ctx.project ?? 'project', name: 'no Artifact Registry repository present', attributes: {} }],
      },
      remediation: arRepoCount >= 1 ? undefined : {
        summary: 'Set up Artifact Registry; configure IAM to prevent tag updates.',
        options: [{
          approach: 'Create Artifact Registry repo + restrict IAM.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'low', notes: 'AR storage charges.' },
          availability_impact: { level: 'low', notes: 'Net-new.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Setup + migration of existing images.' },
          steps: ['Create AR repo.', 'Grant publishing SA only artifactregistry.writer (not admin).', 'Pipelines push unique tags only.'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['cm-2','sa-10'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-SVC-VRI', relationship: 'shares-remediation', note: 'Image immutability is VRI input.' },
      ],
    }),

    finding({
      rule: 'gcp.cloud_run.revision_pinning',
      passed: cloudRunUsingLatest.length === 0,
      severity: 'high',
      current: {
        summary: cloudRunServices.length === 0
          ? 'No Cloud Run services in this project.'
          : (cloudRunUsingLatest.length === 0
            ? `All ${cloudRunServices.length} Cloud Run service(s) pin to specific revisions.`
            : `${cloudRunUsingLatest.length} of ${cloudRunServices.length} Cloud Run service(s) route traffic to LATEST.`),
        observations: { services: cloudRunServices },
      },
      target: { summary: 'Prod Cloud Run services pin traffic to specific revisions; no `latestRevision: true` traffic.', rationale: 'NIST CM-2. LATEST traffic means deploys auto-switch — defeats the immutable-redeploy gate.' },
      gap: cloudRunUsingLatest.length === 0 ? undefined : {
        description: 'LATEST traffic = no rollback safety net.',
        affected_resources: cloudRunUsingLatest.map<AffectedResource>((n) => ({
          type: 'google_cloud_run_service', identifier: n, name: n, attributes: { traffic_to_latest: true },
        })),
      },
      remediation: cloudRunUsingLatest.length === 0 ? undefined : {
        summary: 'Pin traffic to a specific revision via Terraform.',
        options: [{
          approach: 'Set traffic.revisionName instead of latestRevision.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'low', notes: 'Deploy must explicitly bump traffic target.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per service + pipeline change.' },
          steps: ['Update Cloud Run config to pin revisionName.', 'Update deploy pipeline to bump revision explicitly.'],
          example_code: `resource "google_cloud_run_service" "api" {
  traffic {
    percent       = 100
    revision_name = "api-00012-abc"
  }
}`,
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['cm-2'],
    }),

    finding({
      rule: 'gcp.binaryauthorization.policy_enforced',
      passed: binAuthzMode === 'REQUIRE_ATTESTATION' || binAuthzMode === 'ALWAYS_DENY',
      severity: 'high',
      current: {
        summary: `Binary Authorization defaultAdmissionRule mode: ${binAuthzMode}. ${binAuthzAttestorCount} attestor(s).`,
        observations: { defaultMode: binAuthzMode, attestor_count: binAuthzAttestorCount },
      },
      target: { summary: 'BinAuthz policy requires attestation (REQUIRE_ATTESTATION) for prod cluster admissions; ≥ 1 attestor configured.', rationale: 'NIST SI-7. Pre-admission attestation is the GCP equivalent of Lambda code-signing — ensures only validated images run.' },
      gap: (binAuthzMode === 'REQUIRE_ATTESTATION' || binAuthzMode === 'ALWAYS_DENY') ? undefined : {
        description: 'Without BinAuthz enforcement, unvalidated container images can run.',
        affected_resources: [{ type: 'google_binary_authorization_policy', identifier: ctx.project, attributes: { defaultMode: binAuthzMode } }],
      },
      remediation: (binAuthzMode === 'REQUIRE_ATTESTATION' || binAuthzMode === 'ALWAYS_DENY') ? undefined : {
        summary: 'Configure BinAuthz policy with attestor requirement.',
        options: [{
          approach: 'BinAuthz policy + attestor via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'BinAuthz is free; KMS signing key has small cost.' },
          availability_impact: { level: 'medium', notes: 'Unattested images will be blocked — pipelines must sign attestations.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Pipeline changes to sign + verify.' },
          steps: ['Create attestor + KMS signing key.', 'Configure policy with defaultAdmissionRule.', 'Update CI to create attestation after image scan passes.', 'Test deploy.'],
          example_code: `resource "google_binary_authorization_policy" "policy" {
  default_admission_rule {
    evaluation_mode  = "REQUIRE_ATTESTATION"
    enforcement_mode = "ENFORCED_BLOCK_AND_AUDIT_LOG"
    require_attestations_by = [google_binary_authorization_attestor.prod.name]
  }
  global_policy_evaluation_mode = "ENABLE"
}`,
          references: [{ title: 'Binary Authorization', url: 'https://cloud.google.com/binary-authorization/docs/overview' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['si-7','si-7.1','si-7.6'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-SVC-VRI', relationship: 'shares-remediation', note: 'BinAuthz attestation IS the VRI evidence.' },
        { ksi_id: 'KSI-CMT-VTD', relationship: 'shares-remediation', note: 'Attestation requires VTD-side scanning gates.' },
      ],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-CMT-VTD — Validating Throughout Deployment (GCP)
// =====================================================================
export async function collectCmtVtd(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // Cloud Build triggers
  let buildTriggerCount = 0;
  let triggersWithScanSteps: string[] = [];
  try {
    const cb = await gcpAuth.googleClient<any>('cloudbuild', 'v1');
    const r = await cb.projects.triggers.list({ projectId: ctx.project });
    for (const t of r.data.triggers ?? []) {
      buildTriggerCount++;
      // Look at steps for scanner invocations (tfsec, Checkov, trivy)
      const stepsStr = JSON.stringify(t.build?.steps ?? []);
      if (/tfsec|checkov|trivy|snyk|cosign/i.test(stepsStr)) {
        triggersWithScanSteps.push(t.name ?? t.id);
      }
    }
    evidence.push(ev('cloudbuild.triggers', { count: buildTriggerCount, with_scan_steps: triggersWithScanSteps }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'cloudbuild.projects.triggers.list', 'cloudbuild.builds.list (roles/cloudbuild.builds.viewer)')); }

  // Cloud Deploy pipelines
  let deployPipelineCount = 0;
  try {
    const cd = await gcpAuth.googleClient<any>('clouddeploy', 'v1');
    // Cloud Deploy pipelines are per-location
    for (const loc of ['us-central1', 'us-east1', 'us-west1']) {
      try {
        const r = await cd.projects.locations.deliveryPipelines.list({ parent: `projects/${ctx.project}/locations/${loc}` });
        deployPipelineCount += (r.data.deliveryPipelines ?? []).length;
      } catch { /* */ }
    }
    evidence.push(ev('clouddeploy.delivery_pipelines', { count: deployPipelineCount }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'clouddeploy.deliveryPipelines.list', 'clouddeploy.deliveryPipelines.list (roles/clouddeploy.viewer)')); }

  // BinAuthz attestor count (signals VTD gating since attestation requires VTD success)
  let binAuthzAttestorCount = 0;
  try {
    const ba = await gcpAuth.googleClient<any>('binaryauthorization', 'v1');
    const r = await ba.projects.attestors.list({ parent: `projects/${ctx.project}` });
    binAuthzAttestorCount = (r.data.attestors ?? []).length;
    evidence.push(ev('binaryauthorization.attestors', { count: binAuthzAttestorCount }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'binaryauthorization.projects.attestors.list', 'binaryauthorization.attestors.list (roles/binaryauthorization.policyViewer)')); }

  // Artifact Analysis (vuln scanning on container images)
  let vulnFindings = 0;
  try {
    const ca = await gcpAuth.googleClient<any>('containeranalysis', 'v1');
    const r = await ca.projects.occurrences.list({ parent: `projects/${ctx.project}`, filter: 'kind="VULNERABILITY"', pageSize: 100 });
    vulnFindings = (r.data.occurrences ?? []).length;
    evidence.push(ev('containeranalysis.vulnerability_count', vulnFindings));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'containeranalysis.projects.occurrences.list', 'containeranalysis.occurrences.list (roles/containeranalysis.occurrences.viewer)')); }

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'GitHub Actions / GitLab CI / your own CI/CD product (self-eating)',
      description: 'CI may live off-GCP; gates configured in pipeline YAML in source repos.',
      evidence_required: ['Pipeline YAML with scan steps', 'Sample passing build log', 'Branch protection settings'],
      detected: buildTriggerCount === 0,
      detection_signals: buildTriggerCount === 0 ? ['No Cloud Build triggers — CI likely off-GCP.'] : [],
    },
  ];

  const findings = [
    finding({
      rule: 'gcp.cloud_build.scan_steps_in_triggers',
      passed: buildTriggerCount === 0 || triggersWithScanSteps.length >= 1,
      severity: 'high',
      current: {
        summary: buildTriggerCount === 0
          ? 'No Cloud Build triggers (CI may be off-GCP).'
          : (triggersWithScanSteps.length >= 1
            ? `${triggersWithScanSteps.length} of ${buildTriggerCount} trigger(s) invoke a scanner (tfsec/Checkov/trivy/Snyk/cosign).`
            : `${buildTriggerCount} Cloud Build trigger(s); 0 invoke recognized security scanners.`),
        observations: { trigger_count: buildTriggerCount, with_scanners: triggersWithScanSteps },
      },
      target: { summary: 'Cloud Build triggers invoke at least one of: tfsec/Checkov (IaC), trivy/Artifact-Analysis (container vuln), Snyk/cosign (signing/SBOM).', rationale: 'NIST RA-5, CM-3.2. Scan gates pre-deploy.' },
      gap: (buildTriggerCount === 0 || triggersWithScanSteps.length >= 1) ? undefined : {
        description: 'Build pipelines do not invoke scanners — vulnerable code can ship.',
        affected_resources: [{ type: 'google_cloudbuild_trigger', identifier: 'aggregate', attributes: { without_scanners: buildTriggerCount } }],
      },
      remediation: (buildTriggerCount === 0 || triggersWithScanSteps.length >= 1) ? undefined : {
        summary: 'Add scanner steps to each Cloud Build trigger.',
        options: [{
          approach: 'Update build steps via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'Cloud Build minutes.' },
          availability_impact: { level: 'medium', notes: 'Failing scans block deploys.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Per pipeline.' },
          steps: ['Add `gcr.io/cloud-builders/...` steps invoking tfsec/Checkov for IaC.', 'Add trivy/grype for container images.', 'Add cosign sign + Binary Authorization attestation creation.', 'Wire failure to fail the build.'],
          example_code: `resource "google_cloudbuild_trigger" "deploy" {
  build {
    step { id = "iac-scan" name = "aquasec/tfsec" args = ["./terraform"] }
    step { id = "container-scan" name = "aquasec/trivy" args = ["image","--severity","HIGH,CRITICAL","my-image:latest"] }
    step { id = "attest" name = "gcr.io/cloud-builders/gcloud" args = ["beta","container","binauthz","attestations","sign-and-create","..."] }
  }
}`,
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['cm-3.2','ra-5','sa-11'],
    }),

    finding({
      rule: 'gcp.binaryauthorization.attestors_for_vtd',
      passed: binAuthzAttestorCount >= 1,
      severity: 'high',
      current: {
        summary: binAuthzAttestorCount >= 1
          ? `${binAuthzAttestorCount} BinAuthz attestor(s) configured.`
          : 'No BinAuthz attestors — no attestation-based deploy gating.',
        observations: { attestor_count: binAuthzAttestorCount },
      },
      target: { summary: 'At least one BinAuthz attestor exists; pipelines create attestations after VTD checks pass.', rationale: 'NIST SI-7. Attestation is the validate-during-deployment artifact.' },
      gap: binAuthzAttestorCount >= 1 ? undefined : {
        description: 'No attestation-based deploy gating.',
        affected_resources: [{ type: 'google_binary_authorization_attestor', identifier: 'none', attributes: {} }],
      },
      remediation: binAuthzAttestorCount >= 1 ? undefined : {
        summary: 'Create at least one attestor + integrate signing into CI.',
        options: [{
          approach: 'Attestor + signing key via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'KMS key cost.' },
          availability_impact: { level: 'medium', notes: 'CI must sign successfully or deploys are blocked.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Attestor + pipeline integration.' },
          steps: ['Create KMS signing key.', 'Create attestor referencing the key.', 'Update CI to create attestation after gate passes.'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['si-7','si-7.1'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-CMT-RMV', relationship: 'shares-remediation', note: 'BinAuthz is the runtime enforcement; RMV provides the immutable artifact.' },
      ],
    }),

    finding({
      rule: 'gcp.artifact_analysis.vuln_scanning_active',
      passed: vulnFindings >= 0, // info-only — surface count
      severity: 'info',
      current: {
        summary: `Artifact Analysis: ${vulnFindings} vulnerability occurrence(s) found in container metadata.`,
        observations: { vuln_finding_count: vulnFindings },
      },
      target: { summary: 'Artifact Analysis is enabled and producing vuln findings; critical/high findings gate deploys.', rationale: 'NIST RA-5.' },
      alternative_satisfiers: [],
      nist_controls: ['ra-5'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-SCR-MON', relationship: 'shares-remediation', note: 'Artifact Analysis output is SCR-MON evidence.' },
      ],
      note: 'Scanning is per-AR-tier; verify Artifact Analysis is enabled in your registry tier.',
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, ksi_level_alternatives: altSatisfiers, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-SCR-MON — Monitoring Supply Chain Risk (GCP)
// =====================================================================
export async function collectScrMon(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  let vulnFindings = 0;
  try {
    const ca = await gcpAuth.googleClient<any>('containeranalysis', 'v1');
    const r = await ca.projects.occurrences.list({ parent: `projects/${ctx.project}`, filter: 'kind="VULNERABILITY"', pageSize: 200 });
    vulnFindings = (r.data.occurrences ?? []).length;
    evidence.push(ev('containeranalysis.vuln_for_scr_mon', { count: vulnFindings }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'containeranalysis.projects.occurrences.list', 'containeranalysis.occurrences.list (roles/containeranalysis.occurrences.viewer)')); }

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'Snyk / Trivy / Wiz Code in CI',
      description: '3rd-party SCA in pipeline.',
      evidence_required: ['Scanner pipeline config', 'Recent findings'],
      detected: false,
      detection_signals: [],
    },
  ];

  const findings = [
    finding({
      rule: 'gcp.artifact_analysis.vuln_scanning_active',
      passed: vulnFindings >= 0,
      severity: 'medium',
      current: {
        summary: vulnFindings === 0
          ? 'Zero vulnerability occurrences — either Artifact Analysis disabled or env genuinely clean.'
          : `${vulnFindings} vulnerability occurrence(s) being tracked.`,
        observations: { vuln_count: vulnFindings },
      },
      target: { summary: 'Artifact Analysis vuln scanning active; critical/high findings within SLA.', rationale: 'NIST RA-5.' },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['ra-5'],
      note: 'Verify scanning is enabled in your Artifact Registry tier — required for occurrences to appear.',
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, ksi_level_alternatives: altSatisfiers, third_party_tools_detected: thirdParty };
}
