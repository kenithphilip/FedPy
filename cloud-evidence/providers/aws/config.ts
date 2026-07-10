/**
 * AWS config-domain CNA collectors.
 * Covers KSI-CNA-EIS (Enforcing Intended State) and KSI-CNA-IBP (Implementing Best Practices).
 */
import {
  DescribeConfigurationRecordersCommand,
  DescribeConfigurationRecorderStatusCommand,
  DescribeConformancePacksCommand,
  DescribeConformancePackComplianceCommand,
  DescribeConfigRulesCommand,
  DescribeRemediationConfigurationsCommand,
} from '@aws-sdk/client-config-service';
import { GetEnabledStandardsCommand, GetFindingsCommand as ShGetFindingsCommand } from '@aws-sdk/client-securityhub';
import { DescribeStacksCommand } from '@aws-sdk/client-cloudformation';

import * as aws from '../../core/auth/aws.ts';
import type { ProviderBlock, RawEvidence, AffectedResource, AlternativeSatisfier, ThirdPartyToolMatch } from '../../core/envelope.ts';
import { finding } from '../../core/findings.ts';
import { diagnoseAwsError } from '../../core/error-diagnostics.ts';
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
// KSI-CNA-EIS — Enforcing Intended State (drift detection + auto-remediation)
// =====================================================================
export async function collectCnaEis(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];
  const cfg = aws.configService(ctx.auth);

  let recorderEnabled = false;
  let recorderHealthy = false;
  try {
    const recs = await cfg.send(new DescribeConfigurationRecordersCommand({}));
    recorderEnabled = (recs.ConfigurationRecorders ?? []).length > 0;
    const stat = await cfg.send(new DescribeConfigurationRecorderStatusCommand({}));
    recorderHealthy = (stat.ConfigurationRecordersStatus ?? []).some((s: any) => s.recording === true && s.lastStatus === 'SUCCESS');
    evidence.push(ev('config.recorder_status', { recorders: recs.ConfigurationRecorders, status: stat.ConfigurationRecordersStatus }));
  } catch (e: any) { warnings.push(`Config recorder: ${e.message}`); }

  let conformancePacks: any[] = [];
  let nonCompliantPacks = 0;
  let allPackComplianceRead = true;
  try {
    const cp = await cfg.send(new DescribeConformancePacksCommand({}));
    conformancePacks = cp.ConformancePackDetails ?? [];
    for (const p of conformancePacks) {
      try {
        const comp = await cfg.send(new DescribeConformancePackComplianceCommand({ ConformancePackName: p.ConformancePackName! }));
        const failing = (comp.ConformancePackRuleComplianceList ?? []).filter((r: any) => r.ComplianceType === 'NON_COMPLIANT');
        if (failing.length > 0) nonCompliantPacks++;
      } catch (e: any) {
        // A failed compliance read must NOT be silently treated as "compliant" —
        // that would produce a false PASS. Record the miss so the finding gates.
        allPackComplianceRead = false;
        warnings.push(diagnoseAwsError(e, `config.DescribeConformancePackCompliance ${p.ConformancePackName}`, 'config:DescribeConformancePackCompliance'));
      }
    }
    evidence.push(ev('config.conformance_packs', { total: conformancePacks.length, with_non_compliant_rules: nonCompliantPacks }));
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'config.DescribeConformancePacks', 'config:DescribeConformancePacks')); }

  let configRules = 0;
  let rulesWithRemediation = 0;
  try {
    const rules = await cfg.send(new DescribeConfigRulesCommand({}));
    configRules = (rules.ConfigRules ?? []).length;
    const ruleNames: string[] = (rules.ConfigRules ?? []).map((r: any) => r.ConfigRuleName).filter(Boolean);
    // DescribeRemediationConfigurations caps ConfigRuleNames at 25 per call.
    // Batch so accounts with many rules don't get a ValidationException.
    for (let i = 0; i < ruleNames.length; i += 25) {
      const batch = ruleNames.slice(i, i + 25);
      const rem = await cfg.send(new DescribeRemediationConfigurationsCommand({ ConfigRuleNames: batch }));
      rulesWithRemediation += (rem.RemediationConfigurations ?? []).length;
    }
    evidence.push(ev('config.rules_and_remediation', { rules: configRules, with_remediation: rulesWithRemediation }));
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'config.DescribeConfigRules', 'config:DescribeConfigRules + config:DescribeRemediationConfigurations')); }

  let cfDriftedStacks: string[] = [];
  let cfStacksCollected = false;
  try {
    const cfn = aws.cloudformation(ctx.auth);
    const r = await cfn.send(new DescribeStacksCommand({}));
    for (const s of r.Stacks ?? []) {
      if (s.DriftInformation?.StackDriftStatus === 'DRIFTED') cfDriftedStacks.push(s.StackName ?? '?');
    }
    cfStacksCollected = true;
    evidence.push(ev('cloudformation.drift', { total_stacks: r.Stacks?.length ?? 0, drifted: cfDriftedStacks }));
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'cloudformation.DescribeStacks', 'cloudformation:DescribeStacks')); }

  const findings = [
    finding({
      rule: 'aws.config.recorder_enabled_and_healthy',
      passed: recorderEnabled && recorderHealthy,
      severity: 'critical',
      current: {
        summary: recorderEnabled && recorderHealthy
          ? 'AWS Config recorder enabled and recording successfully.'
          : (recorderEnabled ? 'Config recorder exists but unhealthy.' : 'No AWS Config recorder configured.'),
        observations: { recorderEnabled, recorderHealthy },
      },
      target: { summary: 'AWS Config recorder is enabled, recording all supported resource types, last status SUCCESS within 24h.', rationale: 'NIST CA-7. Config is the source of truth for drift detection.' },
      gap: (recorderEnabled && recorderHealthy) ? undefined : {
        description: 'Without Config, drift detection is blind.',
        affected_resources: [{ type: 'aws_config_configuration_recorder', identifier: ctx.account ?? '', attributes: { enabled: recorderEnabled, healthy: recorderHealthy } }],
      },
      remediation: (recorderEnabled && recorderHealthy) ? undefined : {
        summary: 'Enable AWS Config in every region; ideally aggregate via Organizations.',
        options: [{
          approach: 'Enable AWS Config via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'medium', notes: 'Config charges per item recorded + per rule eval. For mature envs, $hundreds-thousands/month.' },
          availability_impact: { level: 'none', notes: 'Pure observation.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Enable + verify per region.' },
          steps: ['Create config recorder + delivery channel in each region.', 'Subscribe to ALL_SUPPORTED resource types.', 'Verify recording.'],
          example_code: `resource "aws_config_configuration_recorder" "this" {
  name     = "default"
  role_arn = aws_iam_role.config.arn
  recording_group { all_supported = true  include_global_resource_types = true }
}
resource "aws_config_delivery_channel" "this" {
  name           = "default"
  s3_bucket_name = aws_s3_bucket.config.bucket
  depends_on     = [aws_config_configuration_recorder.this]
}
resource "aws_config_configuration_recorder_status" "this" {
  name       = aws_config_configuration_recorder.this.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.this]
}`,
          references: [{ title: 'AWS Config', url: 'https://docs.aws.amazon.com/config/latest/developerguide/WhatIsConfig.html' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ca-7','ca-7.1'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-CMT-LMC', relationship: 'shares-remediation', note: 'Config records change history alongside CloudTrail.' },
        { ksi_id: 'KSI-MLA-EVC', relationship: 'shares-remediation', note: 'Config rules ARE the config-evaluation evidence.' },
      ],
    }),

    finding({
      rule: 'aws.config.conformance_pack_aligned',
      passed: conformancePacks.length >= 1 && nonCompliantPacks === 0 && allPackComplianceRead,
      severity: 'high',
      current: {
        summary: conformancePacks.length === 0
          ? 'No conformance packs deployed.'
          : (nonCompliantPacks === 0
            ? `${conformancePacks.length} conformance pack(s); all compliant.`
            : `${conformancePacks.length} conformance pack(s); ${nonCompliantPacks} have non-compliant rules.`),
        observations: { packs: conformancePacks.map((p: any) => ({ name: p.ConformancePackName })), non_compliant_count: nonCompliantPacks },
      },
      target: { summary: 'At least one FedRAMP-aligned conformance pack deployed (e.g. operational-best-practices-for-fedramp-low/moderate) with no rule non-compliance.', rationale: 'NIST CA-2(1). Conformance packs are pre-built rulesets aligned to compliance frameworks.' },
      gap: (conformancePacks.length >= 1 && nonCompliantPacks === 0) ? undefined : {
        description: 'Missing or non-compliant conformance pack = gaps in posture coverage.',
        affected_resources: [{ type: 'aws_config_conformance_pack', identifier: 'aggregate', attributes: { total: conformancePacks.length, non_compliant: nonCompliantPacks } }],
      },
      remediation: (conformancePacks.length >= 1 && nonCompliantPacks === 0) ? undefined : {
        summary: 'Deploy AWS-managed FedRAMP conformance pack; triage non-compliance.',
        options: [{
          approach: 'Deploy via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'medium', notes: 'Each rule eval has cost.' },
          availability_impact: { level: 'none', notes: 'Pure evaluation.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Triage initial non-compliance.' },
          steps: ['Deploy FedRAMP Moderate conformance pack.', 'Triage non-compliant rules: remediate, suppress with justification, or document exception.', 'Aim for 95%+ compliance.'],
          references: [{ title: 'Conformance packs', url: 'https://docs.aws.amazon.com/config/latest/developerguide/conformance-packs.html' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ca-2.1','ca-7.1'],
    }),

    finding({
      rule: 'aws.config.auto_remediation_present',
      passed: rulesWithRemediation >= 1,
      severity: 'medium',
      current: {
        summary: rulesWithRemediation >= 1
          ? `${rulesWithRemediation} Config rule(s) have auto-remediation; ${configRules} rules total.`
          : `${configRules} Config rule(s); 0 have auto-remediation configured.`,
        observations: { rules: configRules, with_remediation: rulesWithRemediation },
      },
      target: { summary: 'Auto-remediation configured for at least the critical Config rules (deny-public-buckets, deny-unrestricted-egress, etc.).', rationale: 'NIST CA-7. Enforcement (not just detection) closes the drift loop.' },
      gap: rulesWithRemediation >= 1 ? undefined : {
        description: 'Drift is detected but not enforced — humans must intervene.',
        affected_resources: [{ type: 'aws_config_remediation_configuration', identifier: 'none', attributes: { config_rules: configRules } }],
      },
      remediation: rulesWithRemediation >= 1 ? undefined : {
        summary: 'Add auto-remediation for the highest-severity Config rules.',
        options: [{
          approach: 'Attach SSM Automation document for remediation.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'SSM Automation execution charges.' },
          availability_impact: { level: 'medium', notes: 'Auto-remediation can disrupt legitimate access. Pilot in monitor-then-enforce mode.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per rule.' },
          steps: ['Select a critical Config rule (e.g. s3-bucket-public-read-prohibited).', 'Attach SSM doc AWS-DisableS3BucketPublicReadWrite.', 'Test in nonprod.', 'Promote to prod.'],
          references: [{ title: 'Config Auto Remediation', url: 'https://docs.aws.amazon.com/config/latest/developerguide/remediation.html' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ca-7','si-7'],
    }),

    finding({
      rule: 'aws.cloudformation.no_drifted_stacks',
      passed: cfStacksCollected && cfDriftedStacks.length === 0,
      severity: 'medium',
      current: {
        summary: cfDriftedStacks.length === 0
          ? 'No CloudFormation stacks currently DRIFTED.'
          : `${cfDriftedStacks.length} CFN stack(s) DRIFTED.`,
        observations: { drifted: cfDriftedStacks },
      },
      target: { summary: 'CFN stacks in IN_SYNC. Drift detected, reviewed, and reconciled.', rationale: 'NIST CM-2(2). IaC drift = manual changes bypassing change management.' },
      gap: cfDriftedStacks.length === 0 ? undefined : {
        description: 'Drift indicates manual changes outside IaC.',
        affected_resources: cfDriftedStacks.map<AffectedResource>((n: string) => ({
          type: 'aws_cloudformation_stack', identifier: n, name: n, attributes: {},
        })),
      },
      remediation: cfDriftedStacks.length === 0 ? undefined : {
        summary: 'For each drifted stack: reconcile (update IaC to match reality) or revert (apply IaC to overwrite drift).',
        options: [{
          approach: 'Run drift detection + remediate per stack.',
          mechanism: 'process',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'Reverting drift could break apps depending on the drifted state.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per stack.' },
          steps: ['Identify drift details via DetectStackDrift.', 'Decide: reconcile IaC or revert.', 'Apply.', 'Add Config rule to alert on future drift.'],
        }],
      },
      alternative_satisfiers: [
        { via: 'Terraform Cloud / Atlantis with drift detection', description: 'TF-based IaC has equivalent drift-detection tooling.', evidence_required: ['TF drift-detection workflow', 'recent drift report'], detected: false },
      ],
      nist_controls: ['cm-2','cm-2.2'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-SVC-ACM', relationship: 'shares-remediation', note: 'IaC + drift detection is the SVC-ACM core.' },
      ],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-CNA-IBP — Implementing Best Practices (Security Hub posture)
// =====================================================================
export async function collectCnaIbp(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  let enabledStandards: string[] = [];
  let criticalFindings = 0;
  let highFindings = 0;
  let criticalFindingsCollected = false;
  try {
    const sh = aws.securityhub(ctx.auth);
    const std = await sh.send(new GetEnabledStandardsCommand({}));
    enabledStandards = (std.StandardsSubscriptions ?? []).map((s: any) => s.StandardsArn ?? '').filter(Boolean);
    evidence.push(ev('securityhub.GetEnabledStandards', enabledStandards));

    const critF = await sh.send(new ShGetFindingsCommand({
      Filters: { SeverityLabel: [{ Value: 'CRITICAL', Comparison: 'EQUALS' }], WorkflowStatus: [{ Value: 'NEW', Comparison: 'EQUALS' }] },
      MaxResults: 100,
    }));
    criticalFindings = critF.Findings?.length ?? 0;
    const highF = await sh.send(new ShGetFindingsCommand({
      Filters: { SeverityLabel: [{ Value: 'HIGH', Comparison: 'EQUALS' }], WorkflowStatus: [{ Value: 'NEW', Comparison: 'EQUALS' }] },
      MaxResults: 100,
    }));
    highFindings = highF.Findings?.length ?? 0;
    criticalFindingsCollected = true;
    evidence.push(ev('securityhub.finding_counts', { critical_new: criticalFindings, high_new: highFindings }));
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'securityhub.GetFindings', 'securityhub:GetFindings + securityhub:GetEnabledStandards')); }

  const fsbpEnabled = enabledStandards.some((arn) => /aws-foundational-security-best-practices/.test(arn));
  const cisEnabled = enabledStandards.some((arn) => /cis-aws-foundations/.test(arn));

  const findings = [
    finding({
      rule: 'aws.security_hub.enabled_with_fsbp_and_cis',
      passed: fsbpEnabled && cisEnabled,
      severity: 'high',
      current: {
        summary: enabledStandards.length === 0
          ? 'Security Hub has no standards enabled (likely Security Hub not enabled at all).'
          : `Standards enabled: FSBP=${fsbpEnabled}, CIS=${cisEnabled}.`,
        observations: { enabled_standards: enabledStandards },
      },
      target: { summary: 'Security Hub enabled with FSBP + CIS AWS Foundations Benchmark.', rationale: 'NIST CM-6, SA-8. FSBP + CIS encode AWS\'s own security best practices.' },
      gap: (fsbpEnabled && cisEnabled) ? undefined : {
        description: 'Best-practice signals are missing.',
        affected_resources: [{ type: 'aws_securityhub_account', identifier: ctx.account ?? '', attributes: { fsbp: fsbpEnabled, cis: cisEnabled } }],
      },
      remediation: (fsbpEnabled && cisEnabled) ? undefined : {
        summary: 'Enable Security Hub + subscribe to FSBP and CIS.',
        options: [{
          approach: 'Enable via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'medium', notes: 'Per-check + per-finding-ingestion charges.' },
          availability_impact: { level: 'none', notes: 'Pure observation.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Setup + triage initial findings.' },
          steps: ['Enable Security Hub.', 'Subscribe to FSBP + CIS standards.', 'Configure finding aggregation if multi-region.', 'Triage initial findings.'],
          example_code: `resource "aws_securityhub_account" "this" {}
resource "aws_securityhub_standards_subscription" "fsbp" {
  standards_arn = "arn:aws:securityhub:::ruleset/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.this]
}
resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.4.0"
  depends_on    = [aws_securityhub_account.this]
}`,
          references: [{ title: 'Security Hub', url: 'https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html' }],
        }],
      },
      alternative_satisfiers: [
        { via: '3rd-party CSPM (Wiz, Lacework, Prisma Cloud)', description: 'CSPM can substitute for Security Hub posture management.', evidence_required: ['CSPM tenant config', 'recent posture export'], detected: false },
      ],
      nist_controls: ['cm-6','sa-8'],
    }),

    finding({
      rule: 'aws.security_hub.no_open_critical_findings',
      passed: criticalFindingsCollected && criticalFindings === 0,
      severity: 'critical',
      current: {
        summary: `${criticalFindings} CRITICAL Security Hub finding(s) in NEW state.`,
        observations: { critical_new: criticalFindings, high_new: highFindings },
      },
      target: { summary: 'Zero open CRITICAL findings. HIGH findings have an SLA + tracker.', rationale: 'NIST SI-4, RA-5. Critical findings are exploitable today.' },
      gap: criticalFindings === 0 ? undefined : {
        description: 'Open critical findings are active risk.',
        affected_resources: [{ type: 'aws_securityhub_finding', identifier: 'aggregate', attributes: { count: criticalFindings } }],
      },
      remediation: criticalFindings === 0 ? undefined : {
        summary: 'Triage each critical finding; resolve, suppress with justification, or move to NOTIFIED with ticket.',
        options: [{
          approach: 'Triage in Security Hub console; close out each.',
          mechanism: 'process',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'low', notes: 'Depends on remediation.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per finding.' },
          steps: ['Sort by severity + age.', 'For each: resolve, suppress, or NOTIFIED + ticket.'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['si-4','ra-5'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-SVC-EIS', relationship: 'shares-remediation', note: 'Findings → tickets → fixes is the SVC-EIS closed-loop.' },
      ],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-SVC-ACM — Automating Configuration Management
// Distinguished from CNA-EIS (enforcement) + MLA-EVC (measurement) by focusing on
// "is IaC the source of truth?" — stack coverage + drift ratio + IaC pipeline presence.
// =====================================================================
export async function collectSvcAcm(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // CFN stack count + drift status (sample)
  let stackCount = 0;
  let driftedStacks: string[] = [];
  let cfStacksCollected = false;
  try {
    const cfn = aws.cloudformation(ctx.auth);
    const r = await cfn.send(new DescribeStacksCommand({}));
    for (const s of r.Stacks ?? []) {
      stackCount++;
      if (s.DriftInformation?.StackDriftStatus === 'DRIFTED') driftedStacks.push(s.StackName ?? '?');
    }
    cfStacksCollected = true;
    evidence.push(ev('cloudformation.stack_inventory', { total: stackCount, drifted: driftedStacks }));
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'cloudformation.DescribeStacks', 'cloudformation:DescribeStacks')); }

  // SSM State Manager associations (proxy for desired-state automation)
  // Not enumerating fully; surface count via Config rules
  let configRuleCount = 0;
  try {
    const cfg = aws.configService(ctx.auth);
    const rules = await cfg.send(new DescribeConfigRulesCommand({}));
    configRuleCount = rules.ConfigRules?.length ?? 0;
    evidence.push(ev('config.rules_count_for_acm', { count: configRuleCount }));
  } catch (e: any) { warnings.push(`Config rules: ${e.message}`); }

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'Terraform Cloud / Atlantis / Spacelift / off-AWS IaC',
      description: 'IaC runs outside CloudFormation. Detection requires the IaC tool\'s state.',
      evidence_required: ['Terraform Cloud workspaces inventory', 'Last-apply timestamps', 'Drift-detection schedule + recent reports'],
      detected: false,
      detection_signals: ['No CloudFormation stacks AND/OR low Config recorder coverage suggests off-cloud IaC.'],
    },
    {
      via: 'Pulumi / Crossplane / Config Connector',
      description: 'Alternative IaC frameworks.',
      evidence_required: ['Tool config + state location', 'Reconciliation interval'],
      detected: false,
      detection_signals: [],
    },
  ];

  const findings = [
    finding({
      rule: 'aws.iac_or_config_management_present',
      passed: stackCount >= 1 || configRuleCount >= 1,
      severity: 'high',
      current: {
        summary: stackCount >= 1
          ? `${stackCount} CloudFormation stack(s) + ${configRuleCount} Config rule(s).`
          : (configRuleCount >= 1 ? `0 CFN stacks; ${configRuleCount} Config rule(s) provide some automation.` : 'No CloudFormation stacks AND no Config rules — IaC may live entirely off-AWS or be absent.'),
        observations: { cfn_stack_count: stackCount, config_rule_count: configRuleCount },
      },
      target: { summary: 'Either ≥1 CFN stack OR a documented off-AWS IaC tool (Terraform Cloud/etc.) — and Config rules deployed for drift detection.', rationale: 'NIST CM-2, CM-3, CM-6.' },
      gap: (stackCount >= 1 || configRuleCount >= 1) ? undefined : {
        description: 'Cannot verify any automated config management.',
        affected_resources: [{ type: 'aws_cloudformation_stack', identifier: 'aggregate', attributes: { stack_count: 0, config_rule_count: 0 } }],
      },
      remediation: (stackCount >= 1 || configRuleCount >= 1) ? undefined : {
        summary: 'Document IaC tool of record + deploy Config rules.',
        options: [{
          approach: 'Adopt Terraform + deploy Config conformance pack.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'medium', notes: 'Config rule cost + Terraform Cloud (optional).' },
          availability_impact: { level: 'low', notes: 'Net-new IaC layer over existing infra.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'months', notes: 'Modeling existing infra as IaC is a long-term refactor.' },
          steps: ['Pick IaC tool of record.', 'Import existing resources.', 'Deploy Config conformance pack for drift detection.', 'Establish review cadence.'],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['cm-2','cm-3','cm-6'],
    }),

    finding({
      rule: 'aws.cfn_stacks_no_drift',
      passed: cfStacksCollected && (stackCount === 0 || driftedStacks.length === 0),
      severity: 'medium',
      current: {
        summary: stackCount === 0
          ? 'No CFN stacks to evaluate drift on.'
          : (driftedStacks.length === 0
            ? `All ${stackCount} CFN stack(s) are IN_SYNC.`
            : `${driftedStacks.length} of ${stackCount} CFN stack(s) are DRIFTED.`),
        observations: { drifted: driftedStacks },
      },
      target: { summary: 'CFN stacks reflect IaC source of truth (no manual overrides).', rationale: 'NIST CM-2(2). Drift = lost source-of-truth.' },
      gap: (stackCount === 0 || driftedStacks.length === 0) ? undefined : {
        description: 'Drifted stacks indicate manual changes outside IaC.',
        affected_resources: driftedStacks.map<AffectedResource>((n: string) => ({
          type: 'aws_cloudformation_stack', identifier: n, name: n, attributes: { drift_status: 'DRIFTED' },
        })),
      },
      remediation: (stackCount === 0 || driftedStacks.length === 0) ? undefined : {
        summary: 'Reconcile or revert drift per stack.',
        options: [{
          approach: 'Per-stack triage (see CNA-EIS Finding "aws.cloudformation.no_drifted_stacks").',
          mechanism: 'process',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'Reverting may disrupt apps.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per stack.' },
          steps: ['Run DetectStackDrift.', 'Reconcile IaC or revert.', 'Apply.'],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['cm-2','cm-2.2'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-CNA-EIS', relationship: 'shares-remediation', note: 'Same drift signal.' },
      ],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, ksi_level_alternatives: altSatisfiers, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-SVC-EIS — Evaluating and Improving Security
// Distinguished from MLA-EVC (triage cadence) by focusing on closed-loop improvements:
// custom-action routing to ticketing, MTTR trends, improvement-decision evidence.
// =====================================================================
export async function collectSvcEis(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // Security Hub finding workflow lifecycle (resolved vs notified vs new)
  let resolvedCount = 0;
  let notifiedCount = 0;
  let newCount = 0;
  let securityHubCollected = false;
  try {
    const sh = aws.securityhub(ctx.auth);
    for (const status of ['RESOLVED', 'NOTIFIED', 'NEW']) {
      const r = await sh.send(new ShGetFindingsCommand({
        Filters: { WorkflowStatus: [{ Value: status, Comparison: 'EQUALS' }] },
        MaxResults: 100,
      }));
      const count = r.Findings?.length ?? 0;
      if (status === 'RESOLVED') resolvedCount = count;
      else if (status === 'NOTIFIED') notifiedCount = count;
      else newCount = count;
    }
    securityHubCollected = true;
    evidence.push(ev('securityhub.lifecycle_for_eis', { resolved: resolvedCount, notified: notifiedCount, new: newCount }));
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'securityhub.GetFindings', 'securityhub:GetFindings')); }

  // Custom action target presence (proxy for ticketing wiring)
  // securityhub.DescribeActionTargets requires the command; we'd need to add it but it's optional
  // We'll surface lifecycle metrics for now.

  const totalLifecycle = resolvedCount + notifiedCount + newCount;
  const resolvedRatio = totalLifecycle > 0 ? resolvedCount / totalLifecycle : 0;

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'External CSPM/CNAPP with closed-loop ticketing (Wiz, Lacework)',
      description: 'External tool drives the improvement loop.',
      evidence_required: ['CSPM finding-resolution audit log', 'Improvement-decision records'],
      detected: false,
      detection_signals: [],
    },
  ];

  const findings = [
    finding({
      rule: 'aws.security_hub.improvement_loop_active',
      passed: securityHubCollected && (totalLifecycle === 0 || resolvedRatio >= 0.3),
      severity: 'medium',
      current: {
        summary: totalLifecycle === 0
          ? 'No Security Hub findings yet — either Security Hub disabled or env is genuinely clean.'
          : `Finding lifecycle: ${resolvedCount} RESOLVED, ${notifiedCount} NOTIFIED, ${newCount} NEW (${Math.round(resolvedRatio*100)}% resolved).`,
        observations: { resolved: resolvedCount, notified: notifiedCount, new: newCount, resolved_ratio: resolvedRatio },
      },
      target: { summary: 'At least 30% of findings move to RESOLVED — the loop is closing. Improvement-decision log captures baseline changes.', rationale: 'NIST CA-7, PM-31. Persistent evaluation must lead to action.' },
      gap: (totalLifecycle === 0 || resolvedRatio >= 0.3) ? undefined : {
        description: 'Findings are being seen but not closed — the improvement loop is broken.',
        affected_resources: [{ type: 'aws_securityhub_finding', identifier: 'aggregate', attributes: { resolved: resolvedCount, total: totalLifecycle } }],
      },
      remediation: (totalLifecycle === 0 || resolvedRatio >= 0.3) ? undefined : {
        summary: 'Wire findings to ticketing + establish triage SLA + improvement-decision log.',
        options: [{
          approach: 'Custom action → Lambda → JIRA + improvement-decision log per resolved finding.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'Lambda + ticket-system API calls.' },
          availability_impact: { level: 'none', notes: 'Pure observability.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Integration + process change.' },
          steps: [
            'Create Security Hub custom action.',
            'Build Lambda that creates JIRA tickets.',
            'For each resolved finding, log the decision in a Confluence/Notion page.',
            'Review monthly.',
          ],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['ca-7','pm-31'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-MLA-EVC', relationship: 'shares-remediation', note: 'MLA-EVC = triage cadence; SVC-EIS = improvement outcomes. Same source data.' },
      ],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, ksi_level_alternatives: altSatisfiers, third_party_tools_detected: thirdParty };
}
