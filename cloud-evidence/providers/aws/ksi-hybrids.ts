/**
 * AWS KSI HYBRID collectors — currently-uncovered indicators.
 *
 * Each KSI here is a "persistently review the effectiveness of X" or "mitigate X"
 * obligation (MUST at Low and Moderate, verbatim from the 20x machine-readable
 * data). High applicability is derived from the NIST 800-53 Rev5 baseline via the
 * requirement controls (see docs/analysis/ksi-gaps.md). KSI-SVC-PRR is reported as
 * not-applicable at High by the registry (high.applies is false in the source).
 *
 * These collectors emit the api-testable PROXY half of each HYBRID requirement:
 * the read-only cloud signal that the underlying capability exists and is healthy.
 * The human review minutes / process artifact is the other half, attached via the
 * process_artifacts_required slot registered in ksi-map.ts.
 *
 * STRICTLY READ-ONLY: List, Get and Describe calls only, through the read-only
 * wrapped client factories in core/auth/aws.ts. Every external call is wrapped with
 * diagnoseAwsError so an AccessDenied names the exact IAM action to grant.
 */
import { DescribeConfigRulesCommand, DescribeRemediationConfigurationsCommand, DescribeConformancePacksCommand } from '@aws-sdk/client-config-service';
import { ListDetectorsCommand, GetDetectorCommand } from '@aws-sdk/client-guardduty';
import { ListRulesCommand, ListTargetsByRuleCommand } from '@aws-sdk/client-eventbridge';
import { DescribeTrailsCommand } from '@aws-sdk/client-cloudtrail';
import { DescribeLogGroupsCommand } from '@aws-sdk/client-cloudwatch-logs';
import { DescribeDBInstancesCommand, DescribeDBClustersCommand } from '@aws-sdk/client-rds';
import { ListBackupPlansCommand, GetBackupPlanCommand } from '@aws-sdk/client-backup';
import { GetRegistryScanningConfigurationCommand, DescribeRepositoriesCommand } from '@aws-sdk/client-ecr';
import { ListBucketsCommand, GetPublicAccessBlockCommand } from '@aws-sdk/client-s3';

import * as aws from '../../core/auth/aws.ts';
import type { ProviderBlock, RawEvidence, AffectedResource, Finding } from '../../core/envelope.ts';
import type { KeyWord } from '../../core/envelope.ts';
import { finding, severityForKeyWord } from '../../core/findings.ts';
import type { CollectorContext } from '../../core/ksi-map.ts';
import { classifyError, diagnoseAwsError } from '../../core/error-diagnostics.ts';

const MAX_PAGINATION_ITERATIONS = 1000;

function ev(source: string, data: unknown): RawEvidence {
  return { source, captured_at: new Date().toISOString(), data: data === undefined ? null : data };
}

/** Push a warning only for real (permission/throttle/network) errors. */
function warnIfActionable(warnings: string[], err: unknown, source: string, requiredAction: string): void {
  const klass = classifyError(err);
  if (klass === 'not_found' || klass === 'not_enabled') return;
  warnings.push(diagnoseAwsError(err, source, requiredAction));
}

/** Obligation strength at the run tier. These requirements are MUST at Low/Moderate. */
function tierKeyWord(): KeyWord {
  return 'MUST';
}

interface Ctx { region: string; auth: aws.AwsAuth; account: string | null; }
async function setupCtx(c: CollectorContext): Promise<Ctx> {
  const region = c.aws?.region ?? 'us-east-1';
  const auth = c.aws?.auth ?? aws.makeAwsAuth(region);
  let account = c.aws?.account_id ?? null;
  if (!account) { try { account = (await aws.whoAmI(auth)).account; } catch { /* */ } }
  return { region, auth, account };
}

function block(account: string | null, region: string, evidence: RawEvidence[], findings: Finding[], warnings: string[]): ProviderBlock {
  return { provider: 'aws', account_id: account, region_set: [region], evidence, findings, warnings };
}

// =====================================================================
// KSI-CMT-RVP — Reviewing Change Procedures (drift-enforcement capability)
// =====================================================================
export async function collectCmtRvp(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];
  const kw = tierKeyWord();

  let configRules = 0;
  let remediations = 0;
  let conformancePacks = 0;
  try {
    const cfg = aws.configService(ctx.auth);
    const rules = await cfg.send(new DescribeConfigRulesCommand({}));
    const ruleNames = (rules.ConfigRules ?? []).map((r) => r.ConfigRuleName).filter(Boolean) as string[];
    configRules = ruleNames.length;
    evidence.push(ev('config.DescribeConfigRules', { count: configRules, sample: ruleNames.slice(0, 10) }));
    for (let i = 0; i < ruleNames.length; i += 25) {
      try {
        const rem = await cfg.send(new DescribeRemediationConfigurationsCommand({ ConfigRuleNames: ruleNames.slice(i, i + 25) }));
        remediations += (rem.RemediationConfigurations ?? []).length;
      } catch (e) { warnIfActionable(warnings, e, 'config.DescribeRemediationConfigurations', 'config:DescribeRemediationConfigurations'); }
    }
    try {
      const packs = await cfg.send(new DescribeConformancePacksCommand({}));
      conformancePacks = (packs.ConformancePackDetails ?? []).length;
    } catch (e) { warnIfActionable(warnings, e, 'config.DescribeConformancePacks', 'config:DescribeConformancePacks'); }
    evidence.push(ev('config.drift_enforcement', { config_rules: configRules, remediation_configs: remediations, conformance_packs: conformancePacks }));
  } catch (e) { warnIfActionable(warnings, e, 'config.DescribeConfigRules', 'config:DescribeConfigRules'); }

  const passed = configRules > 0;
  const findings: Finding[] = [finding({
    rule: 'aws.cmt.change_procedure_enforcement_present',
    passed,
    severity: severityForKeyWord(kw),
    applicable_key_word: kw,
    current: {
      summary: passed
        ? `Drift-detection/enforcement capability active: ${configRules} AWS Config rule(s), ${remediations} auto-remediation(s), ${conformancePacks} conformance pack(s).`
        : 'No AWS Config rules found — no automated detection of out-of-procedure changes.',
      observations: { config_rules: configRules, remediation_configs: remediations, conformance_packs: conformancePacks },
    },
    target: {
      summary: 'Automated controls continuously detect (and ideally auto-remediate) changes that bypass documented change procedures.',
      rationale: 'KSI-CMT-RVP / NIST CM-3, CM-5. Reviewing change-procedure effectiveness requires an automated signal that out-of-band changes are caught; AWS Config rules + remediation provide it. The periodic human review is attached as a process artifact.',
    },
    gap: passed ? undefined : {
      description: 'Without Config rules (or an equivalent drift tool) there is no automated evidence that change procedures are enforced.',
      affected_resources: [{ type: 'aws_config', identifier: ctx.account ?? 'account', name: 'AWS Config' }],
    },
    remediation: passed ? undefined : {
      summary: 'Enable AWS Config with rules covering your change-controlled resource types (or wire a drift detector).',
      options: [{
        approach: 'Deploy AWS Config + a conformance pack (e.g. Operational Best Practices for FedRAMP).',
        mechanism: 'terraform', owner_team: 'Platform',
        cost_impact: { level: 'low', notes: 'Per-rule evaluation + config item charges.' },
        availability_impact: { level: 'none', notes: 'Read-only assessment.' },
        customer_visible: { level: 'none', notes: 'Internal.' },
        effort_estimate: { magnitude: 'days', notes: 'Initial rule set + tuning.' },
        steps: ['Enable AWS Config recorder in each in-scope region.', 'Deploy a conformance pack of managed rules.', 'Add remediation configurations for auto-correctable findings.'],
      }],
    },
    alternative_satisfiers: [
      { via: 'Drift detection via Wiz / Terraform Cloud / ArgoCD', description: 'A CNAPP or GitOps drift detector flags resources that diverge from the version-controlled desired state — equivalent evidence that out-of-procedure changes are caught.', evidence_required: ['Drift-detection tool + scope', 'Sample drift alert + resolution'], detected: false, detection_signals: [] },
    ],
    nist_controls: ['cm-3', 'cm-3.2', 'cm-3.4', 'cm-5', 'cm-7.1', 'cm-9'],
  })];
  return block(ctx.account, ctx.region, evidence, findings, warnings);
}

// =====================================================================
// KSI-INR-AAR — Generating After Action Reports (automated alerting + response wired)
// =====================================================================
export async function collectInrAar(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];
  const kw = tierKeyWord();

  let guardDutyEnabled = false;
  try {
    const gd = aws.guardduty(ctx.auth);
    const dets = await gd.send(new ListDetectorsCommand({}));
    const ids = dets.DetectorIds ?? [];
    for (const id of ids) {
      try {
        const d = await gd.send(new GetDetectorCommand({ DetectorId: id }));
        if (d.Status === 'ENABLED') guardDutyEnabled = true;
      } catch (e) { warnIfActionable(warnings, e, 'guardduty.GetDetector', 'guardduty:GetDetector'); }
    }
    evidence.push(ev('guardduty.detectors', { count: ids.length, enabled: guardDutyEnabled }));
  } catch (e) { warnIfActionable(warnings, e, 'guardduty.ListDetectors', 'guardduty:ListDetectors'); }

  let rulesWithTargets = 0;
  let totalRules = 0;
  try {
    const eb = aws.eventbridge(ctx.auth);
    let tok: string | undefined; let iter = 0;
    do {
      const r = await eb.send(new ListRulesCommand({ NextToken: tok, Limit: 100 }));
      for (const rule of r.Rules ?? []) {
        totalRules++;
        if (!rule.Name) continue;
        try {
          const t = await eb.send(new ListTargetsByRuleCommand({ Rule: rule.Name }));
          if ((t.Targets ?? []).length > 0) rulesWithTargets++;
        } catch (e) { warnIfActionable(warnings, e, `eventbridge.ListTargetsByRule ${rule.Name}`, 'events:ListTargetsByRule'); }
      }
      const next = r.NextToken;
      tok = next && next !== tok ? next : undefined;
    } while (tok && ++iter < MAX_PAGINATION_ITERATIONS);
    evidence.push(ev('eventbridge.rules', { total: totalRules, with_targets: rulesWithTargets }));
  } catch (e) { warnIfActionable(warnings, e, 'eventbridge.ListRules', 'events:ListRules'); }

  const passed = guardDutyEnabled && rulesWithTargets > 0;
  const findings: Finding[] = [finding({
    rule: 'aws.inr.automated_alerting_response_wired',
    passed,
    severity: severityForKeyWord(kw),
    applicable_key_word: kw,
    current: {
      summary: passed
        ? `Threat detection active (GuardDuty enabled) and ${rulesWithTargets}/${totalRules} EventBridge rule(s) route to a response target.`
        : `Automated alerting/response not fully wired (GuardDuty enabled: ${guardDutyEnabled}; EventBridge rules with targets: ${rulesWithTargets}).`,
      observations: { guardduty_enabled: guardDutyEnabled, eventbridge_rules: totalRules, rules_with_targets: rulesWithTargets },
    },
    target: {
      summary: 'Incidents are automatically detected and routed to a response workflow, producing the inputs for after-action reports.',
      rationale: 'KSI-INR-AAR / NIST IR-3, IR-4, IR-4.1, IR-8. After-action reports depend on automated detection + routing so incidents are captured and reviewed.',
    },
    gap: passed ? undefined : {
      description: 'Missing automated detection or response routing reduces the fidelity of incident records that feed after-action reviews.',
      affected_resources: [{ type: 'aws_incident_pipeline', identifier: ctx.account ?? 'account', name: 'GuardDuty + EventBridge' }],
    },
    remediation: passed ? undefined : {
      summary: 'Enable GuardDuty and route findings to an incident-response target via EventBridge.',
      options: [{
        approach: 'Enable GuardDuty + an EventBridge rule on findings targeting SNS/Lambda/your IR tool.',
        mechanism: 'terraform', owner_team: 'Security',
        cost_impact: { level: 'low', notes: 'GuardDuty per-event pricing.' },
        availability_impact: { level: 'none', notes: 'Detective only.' },
        customer_visible: { level: 'none', notes: 'Internal.' },
        effort_estimate: { magnitude: 'hours', notes: 'Enable + wire routing.' },
        steps: ['Enable GuardDuty in each region.', 'Create an EventBridge rule on GuardDuty findings.', 'Target your IR tool (PagerDuty/Opsgenie/SOAR/SNS).'],
      }],
    },
    alternative_satisfiers: [
      { via: 'PagerDuty / Opsgenie / Splunk SOAR', description: 'An external incident-response platform ingests alerts and drives the response + after-action workflow.', evidence_required: ['IR platform + integration', 'Sample incident + after-action report'], detected: false, detection_signals: [] },
    ],
    nist_controls: ['ir-3', 'ir-4', 'ir-4.1', 'ir-8'],
  })];
  return block(ctx.account, ctx.region, evidence, findings, warnings);
}

// =====================================================================
// KSI-INR-RPI — Reviewing Past Incidents (incident-history retention)
// =====================================================================
export async function collectInrRpi(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];
  const kw = tierKeyWord();

  let multiRegionTrail = false;
  let trailCount = 0;
  try {
    const ct = aws.cloudtrail(ctx.auth);
    const r = await ct.send(new DescribeTrailsCommand({}));
    for (const t of r.trailList ?? []) {
      trailCount++;
      if (t.IsMultiRegionTrail) multiRegionTrail = true;
    }
    evidence.push(ev('cloudtrail.DescribeTrails', { count: trailCount, multi_region: multiRegionTrail }));
  } catch (e) { warnIfActionable(warnings, e, 'cloudtrail.DescribeTrails', 'cloudtrail:DescribeTrails'); }

  let logGroups = 0;
  let groupsWithRetention = 0;
  try {
    const logs = aws.cloudwatchlogs(ctx.auth);
    let tok: string | undefined; let iter = 0;
    do {
      const r = await logs.send(new DescribeLogGroupsCommand({ nextToken: tok, limit: 50 }));
      for (const g of r.logGroups ?? []) {
        logGroups++;
        if (g.retentionInDays && g.retentionInDays > 0) groupsWithRetention++;
      }
      const next = r.nextToken;
      tok = next && next !== tok ? next : undefined;
    } while (tok && ++iter < MAX_PAGINATION_ITERATIONS);
    evidence.push(ev('logs.DescribeLogGroups', { total: logGroups, with_retention: groupsWithRetention }));
  } catch (e) { warnIfActionable(warnings, e, 'logs.DescribeLogGroups', 'logs:DescribeLogGroups'); }

  const passed = multiRegionTrail;
  const findings: Finding[] = [finding({
    rule: 'aws.inr.incident_history_retained',
    passed,
    severity: severityForKeyWord(kw),
    applicable_key_word: kw,
    current: {
      summary: passed
        ? `Durable incident history available: ${trailCount} CloudTrail trail(s) (multi-region present); ${groupsWithRetention}/${logGroups} log group(s) have a retention policy.`
        : `No multi-region CloudTrail trail found (${trailCount} trail(s)). Past-incident review may lack a complete activity record.`,
      observations: { trails: trailCount, multi_region_trail: multiRegionTrail, log_groups: logGroups, groups_with_retention: groupsWithRetention },
    },
    target: {
      summary: 'Activity and incident records are retained long enough (multi-region trail + log retention) to review past incidents for patterns.',
      rationale: 'KSI-INR-RPI / NIST IR-4, IR-5, AU-11. Reviewing past incidents requires a durable, queryable record of activity.',
    },
    gap: passed ? undefined : {
      description: 'Without a multi-region trail, cross-region incident activity may not be captured for review.',
      affected_resources: [{ type: 'aws_cloudtrail', identifier: ctx.account ?? 'account', name: 'CloudTrail' }],
    },
    remediation: passed ? undefined : {
      summary: 'Create a multi-region CloudTrail trail and set retention on incident-relevant log groups.',
      options: [{
        approach: 'Enable a multi-region organization trail to S3 with a retention/lifecycle policy.',
        mechanism: 'terraform', owner_team: 'Security',
        cost_impact: { level: 'low', notes: 'S3 storage + data-event charges if enabled.' },
        availability_impact: { level: 'none', notes: 'Logging only.' },
        customer_visible: { level: 'none', notes: 'Internal.' },
        effort_estimate: { magnitude: 'hours', notes: 'Create trail + lifecycle.' },
        steps: ['Create a multi-region CloudTrail trail.', 'Set CloudWatch Logs retention on incident-relevant groups.', 'Confirm retention meets your incident-review window.'],
      }],
    },
    alternative_satisfiers: [
      { via: 'SIEM (Splunk / Sentinel / Chronicle) long-term retention', description: 'A SIEM retaining security events provides the searchable incident history for pattern review.', evidence_required: ['SIEM retention policy', 'Sample historical incident query'], detected: false, detection_signals: [] },
    ],
    nist_controls: ['ir-3', 'ir-4', 'ir-4.1', 'ir-5', 'ir-8'],
  })];
  return block(ctx.account, ctx.region, evidence, findings, warnings);
}

// =====================================================================
// KSI-RPL-ARP — Aligning Recovery Plan (alternate processing posture)
// =====================================================================
export async function collectRplArp(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];
  const kw = tierKeyWord();

  const singleAz: string[] = [];
  let instances = 0;
  let clusters = 0;
  try {
    const rds = aws.rds(ctx.auth);
    const inst = await rds.send(new DescribeDBInstancesCommand({}));
    for (const i of inst.DBInstances ?? []) {
      instances++;
      if (!i.MultiAZ) singleAz.push(i.DBInstanceIdentifier ?? '?');
    }
    const clu = await rds.send(new DescribeDBClustersCommand({}));
    clusters = (clu.DBClusters ?? []).length;
    evidence.push(ev('rds.recovery_posture', { instances, single_az: singleAz, clusters }));
  } catch (e) { warnIfActionable(warnings, e, 'rds.DescribeDBInstances', 'rds:DescribeDBInstances'); }

  const passed = singleAz.length === 0;
  const findings: Finding[] = [finding({
    rule: 'aws.rpl.alternate_processing_posture',
    passed,
    severity: severityForKeyWord(kw),
    applicable_key_word: kw,
    current: {
      summary: passed
        ? `Alternate-processing posture present: all ${instances} RDS instance(s) are Multi-AZ (plus ${clusters} cluster(s)).`
        : `${singleAz.length} of ${instances} RDS instance(s) are single-AZ — no automatic alternate-processing site.`,
      observations: { instances, single_az_instances: singleAz, clusters },
    },
    target: {
      summary: 'Critical data stores run with an alternate processing capability (Multi-AZ / cross-region) aligned to the recovery plan.',
      rationale: 'KSI-RPL-ARP / NIST CP-2, CP-6, CP-7, CP-10. Reviewing recovery-plan alignment requires that alternate processing actually exists.',
    },
    gap: passed ? undefined : {
      description: 'Single-AZ data stores cannot meet recovery objectives that assume an alternate processing site.',
      affected_resources: singleAz.map<AffectedResource>((n) => ({ type: 'aws_db_instance', identifier: n, name: n, attributes: { multi_az: false } })),
    },
    remediation: passed ? undefined : {
      summary: 'Convert single-AZ stores to Multi-AZ and document cross-region recovery.',
      options: [{
        approach: 'Set multi_az = true (and consider a cross-region read replica) via Terraform.',
        mechanism: 'terraform', owner_team: 'SRE',
        cost_impact: { level: 'medium', notes: 'Standby instance + cross-AZ/region transfer.' },
        availability_impact: { level: 'low', notes: 'Conversion is online for most engines.' },
        customer_visible: { level: 'none', notes: 'Internal.' },
        effort_estimate: { magnitude: 'days', notes: 'Per store incl. validation.' },
        steps: ['Enable Multi-AZ on each prod store.', 'Add a cross-region replica for the recovery site if RTO requires it.', 'Update the recovery plan to match.'],
      }],
    },
    alternative_satisfiers: [
      { via: 'Cross-region DR via backup vault replication / pilot-light', description: 'Cross-region backup replication + a documented restore runbook can satisfy alternate-processing alignment without standing standby compute.', evidence_required: ['Cross-region backup config', 'DR runbook + last restore test'], detected: false, detection_signals: [] },
    ],
    nist_controls: ['cp-2', 'cp-6', 'cp-7', 'cp-10', 'cp-10.2'],
  })];
  return block(ctx.account, ctx.region, evidence, findings, warnings);
}

// =====================================================================
// KSI-RPL-RRO — Reviewing Recovery Objectives (backup plans codify RPO)
// =====================================================================
export async function collectRplRro(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];
  const kw = tierKeyWord();

  let plansWithSchedule = 0;
  let totalPlans = 0;
  const planDetails: Array<{ name: string; rules: number }> = [];
  try {
    const bk = aws.backup(ctx.auth);
    let tok: string | undefined; let iter = 0;
    const planIds: Array<{ id: string; name: string }> = [];
    do {
      const r = await bk.send(new ListBackupPlansCommand({ NextToken: tok }));
      for (const p of r.BackupPlansList ?? []) {
        if (p.BackupPlanId) planIds.push({ id: p.BackupPlanId, name: p.BackupPlanName ?? p.BackupPlanId });
      }
      const next = r.NextToken;
      tok = next && next !== tok ? next : undefined;
    } while (tok && ++iter < MAX_PAGINATION_ITERATIONS);
    totalPlans = planIds.length;
    for (const p of planIds) {
      try {
        const detail = await bk.send(new GetBackupPlanCommand({ BackupPlanId: p.id }));
        const rules = detail.BackupPlan?.Rules ?? [];
        const scheduled = rules.filter((r) => r.ScheduleExpression).length;
        planDetails.push({ name: p.name, rules: scheduled });
        if (scheduled > 0) plansWithSchedule++;
      } catch (e) { warnIfActionable(warnings, e, `backup.GetBackupPlan ${p.name}`, 'backup:GetBackupPlan'); }
    }
    evidence.push(ev('backup.plans', { total: totalPlans, with_schedule: plansWithSchedule, details: planDetails }));
  } catch (e) { warnIfActionable(warnings, e, 'backup.ListBackupPlans', 'backup:ListBackupPlans'); }

  const passed = plansWithSchedule > 0;
  const findings: Finding[] = [finding({
    rule: 'aws.rpl.recovery_objectives_codified',
    passed,
    severity: severityForKeyWord(kw),
    applicable_key_word: kw,
    current: {
      summary: passed
        ? `${plansWithSchedule}/${totalPlans} AWS Backup plan(s) have scheduled rules — backup frequency codifies an effective RPO that can be reviewed against targets.`
        : `No scheduled AWS Backup plan found (${totalPlans} plan(s)). RPO is not codified for automated review.`,
      observations: { total_plans: totalPlans, plans_with_schedule: plansWithSchedule, details: planDetails },
    },
    target: {
      summary: 'Backup schedules encode the effective RPO so it can be reviewed against the documented RTO/RPO targets.',
      rationale: 'KSI-RPL-RRO / NIST CP-2.3, CP-10. Reviewing recovery objectives requires a machine-readable backup cadence to compare against targets.',
    },
    gap: passed ? undefined : {
      description: 'Without scheduled backup plans there is no automated signal of the achieved RPO to review against objectives.',
      affected_resources: [{ type: 'aws_backup_plan', identifier: ctx.account ?? 'account', name: 'AWS Backup' }],
    },
    remediation: passed ? undefined : {
      summary: 'Define AWS Backup plans with schedules matching your RPO targets.',
      options: [{
        approach: 'Create a backup plan with a schedule + retention per data class via Terraform.',
        mechanism: 'terraform', owner_team: 'SRE',
        cost_impact: { level: 'low', notes: 'Backup storage.' },
        availability_impact: { level: 'none', notes: 'Backups are non-disruptive.' },
        customer_visible: { level: 'none', notes: 'Internal.' },
        effort_estimate: { magnitude: 'hours', notes: 'Per plan.' },
        steps: ['Create an AWS Backup plan with a schedule matching your RPO.', 'Assign resources via tags.', 'Compare the schedule to documented RPO in the recovery-objective review.'],
      }],
    },
    alternative_satisfiers: [
      { via: 'Native engine backups (RDS automated backups / snapshots) + a documented RPO register', description: 'Engine-native automated backups with a retention window can codify RPO outside AWS Backup.', evidence_required: ['Automated-backup retention config', 'RPO/RTO register'], detected: false, detection_signals: [] },
    ],
    nist_controls: ['cp-2.3', 'cp-9', 'cp-10'],
  })];
  return block(ctx.account, ctx.region, evidence, findings, warnings);
}

// =====================================================================
// KSI-SCR-MIT — Mitigating Supply Chain Risk (image scanning on push)
// =====================================================================
export async function collectScrMit(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];
  const kw = tierKeyWord();

  let scanType = 'unknown';
  let scanOnPush = false;
  let repoCount = 0;
  try {
    const ecr = aws.ecr(ctx.auth);
    try {
      const reg = await ecr.send(new GetRegistryScanningConfigurationCommand({}));
      scanType = reg.scanningConfiguration?.scanType ?? 'BASIC';
      const rules = reg.scanningConfiguration?.rules ?? [];
      scanOnPush = rules.some((r) => r.scanFrequency === 'SCAN_ON_PUSH' || r.scanFrequency === 'CONTINUOUS_SCAN');
    } catch (e) { warnIfActionable(warnings, e, 'ecr.GetRegistryScanningConfiguration', 'ecr:GetRegistryScanningConfiguration'); }
    try {
      const repos = await ecr.send(new DescribeRepositoriesCommand({}));
      repoCount = (repos.repositories ?? []).length;
      if (!scanOnPush) {
        scanOnPush = (repos.repositories ?? []).some((r) => r.imageScanningConfiguration?.scanOnPush);
      }
    } catch (e) { warnIfActionable(warnings, e, 'ecr.DescribeRepositories', 'ecr:DescribeRepositories'); }
    evidence.push(ev('ecr.scanning', { scan_type: scanType, scan_on_push: scanOnPush, repositories: repoCount }));
  } catch (e) { warnIfActionable(warnings, e, 'ecr.GetRegistryScanningConfiguration', 'ecr:GetRegistryScanningConfiguration'); }

  const passed = scanOnPush;
  const findings: Finding[] = [finding({
    rule: 'aws.scr.image_scanning_active',
    passed,
    severity: severityForKeyWord(kw),
    applicable_key_word: kw,
    current: {
      summary: passed
        ? `Supply-chain scanning active: ECR ${scanType} scanning on push across ${repoCount} repository(ies).`
        : `ECR scan-on-push not enabled (scan type: ${scanType}, repos: ${repoCount}). Upstream component vulnerabilities may go undetected at ingestion.`,
      observations: { scan_type: scanType, scan_on_push: scanOnPush, repositories: repoCount },
    },
    target: {
      summary: 'Third-party / upstream software is automatically scanned (and ideally signed/attested) so supply-chain risk is detected and mitigated.',
      rationale: 'KSI-SCR-MIT / NIST SA-10, SA-11, SR-5, SR-6, SI-7.1. Mitigating supply-chain risk requires automated detection of vulnerable upstream components.',
    },
    gap: passed ? undefined : {
      description: 'Without scan-on-push, vulnerable upstream packages can enter the registry undetected.',
      affected_resources: [{ type: 'aws_ecr_registry', identifier: ctx.account ?? 'account', name: 'ECR registry', attributes: { scan_type: scanType } }],
    },
    remediation: passed ? undefined : {
      summary: 'Enable ECR enhanced scanning (Inspector) with scan-on-push, and add image signing.',
      options: [{
        approach: 'Set registry scanning to ENHANCED + SCAN_ON_PUSH; sign images with AWS Signer / cosign.',
        mechanism: 'terraform', owner_team: 'Platform',
        cost_impact: { level: 'low', notes: 'Inspector per-image scan pricing.' },
        availability_impact: { level: 'none', notes: 'Scanning only.' },
        customer_visible: { level: 'none', notes: 'Internal.' },
        effort_estimate: { magnitude: 'hours', notes: 'Registry config + CI signing.' },
        steps: ['Set ECR registry scanning to ENHANCED with SCAN_ON_PUSH.', 'Add image signing (AWS Signer / Sigstore cosign) in CI.', 'Enforce signature verification at deploy (Binary Authorization / admission control).'],
      }],
    },
    alternative_satisfiers: [
      { via: 'Wiz / Prisma / Snyk / Anchore + Sigstore cosign', description: 'A dedicated container/supply-chain scanner plus signing/attestation provides equivalent (often deeper) supply-chain mitigation.', evidence_required: ['Scanner + registry coverage', 'Signing/attestation policy'], detected: false, detection_signals: [] },
    ],
    nist_controls: ['ac-20', 'sa-9', 'sa-10', 'sa-11', 'sr-5', 'sr-6', 'si-7.1'],
  })];
  return block(ctx.account, ctx.region, evidence, findings, warnings);
}

// =====================================================================
// KSI-SVC-PRR — Preventing Residual Risk (no data exposed via shared resources)
// =====================================================================
export async function collectSvcPrr(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];
  const kw = tierKeyWord();

  const bucketsWithoutBlock: string[] = [];
  let bucketCount = 0;
  try {
    const s3 = aws.s3(ctx.auth);
    const r = await s3.send(new ListBucketsCommand({}));
    for (const b of r.Buckets ?? []) {
      if (!b.Name) continue;
      bucketCount++;
      try {
        const pab = await s3.send(new GetPublicAccessBlockCommand({ Bucket: b.Name }));
        const cfg = pab.PublicAccessBlockConfiguration;
        const fullyBlocked = !!cfg && cfg.BlockPublicAcls && cfg.BlockPublicPolicy && cfg.IgnorePublicAcls && cfg.RestrictPublicBuckets;
        if (!fullyBlocked) bucketsWithoutBlock.push(b.Name);
      } catch (e) {
        const klass = classifyError(e);
        // No public-access-block configured at all → treated as not fully blocked.
        if (klass === 'not_found') bucketsWithoutBlock.push(b.Name);
        else warnIfActionable(warnings, e, `s3.GetPublicAccessBlock ${b.Name}`, 's3:GetBucketPublicAccessBlock');
      }
    }
    evidence.push(ev('s3.public_access_block', { buckets: bucketCount, without_full_block: bucketsWithoutBlock }));
  } catch (e) { warnIfActionable(warnings, e, 's3.ListBuckets', 's3:ListAllMyBuckets'); }

  const publiclyAccessibleDbs: string[] = [];
  try {
    const rds = aws.rds(ctx.auth);
    const inst = await rds.send(new DescribeDBInstancesCommand({}));
    for (const i of inst.DBInstances ?? []) {
      if (i.PubliclyAccessible) publiclyAccessibleDbs.push(i.DBInstanceIdentifier ?? '?');
    }
    evidence.push(ev('rds.public_accessibility', { publicly_accessible: publiclyAccessibleDbs }));
  } catch (e) { warnIfActionable(warnings, e, 'rds.DescribeDBInstances', 'rds:DescribeDBInstances'); }

  const exposures = bucketsWithoutBlock.length + publiclyAccessibleDbs.length;
  const passed = exposures === 0;
  const findings: Finding[] = [finding({
    rule: 'aws.svc.no_residual_exposure_via_shared_resources',
    passed,
    severity: severityForKeyWord(kw),
    applicable_key_word: kw,
    current: {
      summary: passed
        ? `No residual exposure found: all ${bucketCount} S3 bucket(s) enforce full public-access block and no RDS instance is publicly accessible.`
        : `${bucketsWithoutBlock.length} bucket(s) lack full public-access block; ${publiclyAccessibleDbs.length} RDS instance(s) are publicly accessible.`,
      observations: { buckets: bucketCount, buckets_without_full_block: bucketsWithoutBlock, publicly_accessible_dbs: publiclyAccessibleDbs },
    },
    target: {
      summary: 'Information is not exposed to unauthorized parties through shared/multi-tenant resources (no public buckets, no publicly reachable databases).',
      rationale: 'KSI-SVC-PRR / NIST SC-4 (information in shared resources). Residual data must not leak via misconfigured shared resources.',
    },
    gap: passed ? undefined : {
      description: 'Public buckets / publicly accessible databases can leak residual federal data through shared infrastructure.',
      affected_resources: [
        ...bucketsWithoutBlock.map<AffectedResource>((n) => ({ type: 'aws_s3_bucket', identifier: n, name: n, attributes: { public_access_block: 'incomplete' } })),
        ...publiclyAccessibleDbs.map<AffectedResource>((n) => ({ type: 'aws_db_instance', identifier: n, name: n, attributes: { publicly_accessible: true } })),
      ],
    },
    remediation: passed ? undefined : {
      summary: 'Enforce S3 public-access block account-wide and disable public accessibility on databases.',
      options: [{
        approach: 'Enable account-level S3 Block Public Access + set publicly_accessible=false on RDS.',
        mechanism: 'terraform', owner_team: 'Platform',
        cost_impact: { level: 'none', notes: 'No cost.' },
        availability_impact: { level: 'medium', notes: 'Disabling public DB access can break clients that depend on it — verify first.' },
        customer_visible: { level: 'low', notes: 'Only if an integration relied on public access.' },
        effort_estimate: { magnitude: 'hours', notes: 'Apply per resource.' },
        steps: ['Enable account-level S3 Block Public Access.', 'Set BlockPublicAcls/IgnorePublicAcls/BlockPublicPolicy/RestrictPublicBuckets on each bucket.', 'Set publicly_accessible=false on RDS and move behind private networking.'],
      }],
    },
    alternative_satisfiers: [
      { via: 'CSPM (Wiz / Prisma / Orca) public-exposure policy', description: 'A CSPM continuously flags publicly exposed storage/databases and can block via guardrails.', evidence_required: ['CSPM exposure policy', 'Sample exposure finding + resolution'], detected: false, detection_signals: [] },
    ],
    nist_controls: ['sc-4'],
  })];
  return block(ctx.account, ctx.region, evidence, findings, warnings);
}
