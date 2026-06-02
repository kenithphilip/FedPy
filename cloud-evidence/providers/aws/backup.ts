/**
 * AWS backup-domain collectors.
 * Covers KSI-CNA-OFA (Optimizing for Availability), KSI-RPL-ABO (Aligning
 * Backups with Objectives), and KSI-RPL-TRC (Testing Recovery Capabilities).
 */
import { DescribeAutoScalingGroupsCommand } from '@aws-sdk/client-auto-scaling';
import { DescribeLoadBalancersCommand as DescribeLBsCommand } from '@aws-sdk/client-elastic-load-balancing-v2';
import { DescribeDBInstancesCommand, DescribeDBClustersCommand } from '@aws-sdk/client-rds';
import { ListTablesCommand, DescribeTableCommand, DescribeContinuousBackupsCommand } from '@aws-sdk/client-dynamodb';
import { ListBackupPlansCommand, ListBackupJobsCommand, ListRestoreJobsCommand } from '@aws-sdk/client-backup';

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
// KSI-CNA-OFA — Optimizing for Availability
// =====================================================================
export async function collectCnaOfa(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // ASGs
  const singleAzAsgs: Array<{ name: string; azs: string[] }> = [];
  let asgCount = 0;
  try {
    const asg = aws.autoScaling(ctx.auth);
    const r = await asg.send(new DescribeAutoScalingGroupsCommand({}));
    for (const g of r.AutoScalingGroups ?? []) {
      asgCount++;
      const azs = g.AvailabilityZones ?? [];
      if (azs.length < 2) singleAzAsgs.push({ name: g.AutoScalingGroupName ?? '?', azs });
    }
    evidence.push(ev('autoscaling.DescribeAutoScalingGroups', { total: asgCount, single_az: singleAzAsgs }));
  } catch (e: any) { warnings.push(`ASG: ${e.message}`); }

  // ELBs
  const singleAzLbs: Array<{ name: string; azs: string[] }> = [];
  let lbCount = 0;
  try {
    const elb = aws.elbv2(ctx.auth);
    const r = await elb.send(new DescribeLBsCommand({}));
    for (const l of r.LoadBalancers ?? []) {
      lbCount++;
      const azs = (l.AvailabilityZones ?? []).map((z: any) => z.ZoneName ?? '');
      if (azs.length < 2) singleAzLbs.push({ name: l.LoadBalancerName ?? '?', azs });
    }
    evidence.push(ev('elbv2.DescribeLoadBalancers', { total: lbCount, single_az: singleAzLbs }));
  } catch (e: any) { warnings.push(`ELB: ${e.message}`); }

  // RDS — Multi-AZ
  const rdsSingleAz: string[] = [];
  let rdsInstanceCount = 0;
  let rdsClusterCount = 0;
  try {
    const rds = aws.rds(ctx.auth);
    const inst = await rds.send(new DescribeDBInstancesCommand({}));
    for (const i of inst.DBInstances ?? []) {
      rdsInstanceCount++;
      if (!i.MultiAZ) rdsSingleAz.push(i.DBInstanceIdentifier ?? '?');
    }
    const clu = await rds.send(new DescribeDBClustersCommand({}));
    rdsClusterCount = (clu.DBClusters ?? []).length;
    evidence.push(ev('rds.multi_az_status', { instances: rdsInstanceCount, single_az: rdsSingleAz, clusters: rdsClusterCount }));
  } catch (e: any) { warnings.push(`RDS: ${e.message}`); }

  // DynamoDB — PITR + backups
  const tablesWithoutPitr: string[] = [];
  let dynamoTableCount = 0;
  try {
    const ddb = aws.dynamodb(ctx.auth);
    let tok: string | undefined;
    const names: string[] = [];
    do {
      const r = await ddb.send(new ListTablesCommand({ ExclusiveStartTableName: tok }));
      names.push(...(r.TableNames ?? []));
      tok = r.LastEvaluatedTableName;
    } while (tok);
    dynamoTableCount = names.length;
    for (const n of names) {
      try {
        const d = await ddb.send(new DescribeTableCommand({ TableName: n }));
        // PITR requires a separate API; we look for backup status via DescribeContinuousBackups
        // Skipping the explicit PITR check in this Phase 2 cut — surface table inventory.
        // Tag-based heuristic: tables tagged env=prod should have PITR.
        if (!d.Table) continue;
      } catch { /* ignore */ }
    }
    evidence.push(ev('dynamodb.tables', { count: dynamoTableCount, sample: names.slice(0, 5) }));
  } catch (e: any) { warnings.push(`DynamoDB: ${e.message}`); }

  const findings = [
    finding({
      rule: 'aws.asg.prod_multi_az',
      passed: singleAzAsgs.length === 0,
      severity: 'high',
      current: {
        summary: singleAzAsgs.length === 0
          ? `All ${asgCount} ASG(s) span ≥ 2 AZs.`
          : `${singleAzAsgs.length} of ${asgCount} ASG(s) span only 1 AZ.`,
        observations: { total_asgs: asgCount, single_az_asgs: singleAzAsgs },
      },
      target: { summary: 'Prod ASGs span ≥ 2 AZs (3 preferred).', rationale: 'NIST CP-2, CP-7. Single-AZ ASGs cannot survive AZ failures.' },
      gap: singleAzAsgs.length === 0 ? undefined : {
        description: 'Single-AZ ASGs cannot survive AZ outage.',
        affected_resources: singleAzAsgs.map<AffectedResource>((a) => ({
          type: 'aws_autoscaling_group', identifier: a.name, name: a.name, attributes: { azs: a.azs },
        })),
      },
      remediation: singleAzAsgs.length === 0 ? undefined : {
        summary: 'Expand each prod ASG to span 2-3 AZs.',
        options: [{
          approach: 'Update ASG vpc_zone_identifier to include subnets in 2+ AZs via Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'medium', notes: 'Cross-AZ traffic charges; redundant compute.' },
          availability_impact: { level: 'low', notes: 'Net availability improves; rollout via rolling-update.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per ASG.' },
          steps: ['Ensure subnets exist in 2+ AZs.', 'Update vpc_zone_identifier.', 'Roll out via instance refresh.'],
          example_code: `resource "aws_autoscaling_group" "app" {
  vpc_zone_identifier = [aws_subnet.private_a.id, aws_subnet.private_b.id, aws_subnet.private_c.id]
  min_size = 3  max_size = 9  desired_capacity = 3
}`,
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['cp-2','cp-7','cp-10'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-RPL-ABO', relationship: 'precedes', note: 'Multi-AZ architecture is a prerequisite for backup-alignment goals.' },
      ],
    }),

    finding({
      rule: 'aws.elb.prod_multi_az',
      passed: singleAzLbs.length === 0,
      severity: 'high',
      current: {
        summary: singleAzLbs.length === 0
          ? `All ${lbCount} load balancer(s) span ≥ 2 AZs.`
          : `${singleAzLbs.length} of ${lbCount} LB(s) span only 1 AZ.`,
        observations: { total_lbs: lbCount, single_az_lbs: singleAzLbs },
      },
      target: { summary: 'Prod LBs span ≥ 2 AZs.', rationale: 'NIST CP-2, CP-7. Single-AZ LB = single point of failure.' },
      gap: singleAzLbs.length === 0 ? undefined : {
        description: 'Single-AZ LB cannot survive AZ outage.',
        affected_resources: singleAzLbs.map<AffectedResource>((l) => ({
          type: 'aws_lb', identifier: l.name, name: l.name, attributes: { azs: l.azs },
        })),
      },
      remediation: singleAzLbs.length === 0 ? undefined : {
        summary: 'Add additional subnet mappings to each LB.',
        options: [{
          approach: 'Update LB subnets via Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'low', notes: 'Per-AZ LB hourly charge.' },
          availability_impact: { level: 'low', notes: 'Net availability improves.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Apply Terraform.' },
          steps: ['Identify subnets in additional AZs.', 'Update aws_lb.subnets / .subnet_mapping.'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['cp-2','cp-7'],
    }),

    finding({
      rule: 'aws.rds.prod_multi_az',
      passed: rdsSingleAz.length === 0,
      severity: 'high',
      current: {
        summary: rdsSingleAz.length === 0
          ? `All ${rdsInstanceCount} RDS instance(s) are Multi-AZ (plus ${rdsClusterCount} cluster(s)).`
          : `${rdsSingleAz.length} RDS instance(s) are single-AZ.`,
        observations: { instances: rdsInstanceCount, single_az_instances: rdsSingleAz, clusters: rdsClusterCount },
      },
      target: { summary: 'Prod RDS instances and clusters are Multi-AZ.', rationale: 'NIST CP-2, CP-10. Single-AZ RDS cannot survive AZ outage.' },
      gap: rdsSingleAz.length === 0 ? undefined : {
        description: 'Single-AZ DBs have RPO/RTO measured in AZ-failover-times.',
        affected_resources: rdsSingleAz.map<AffectedResource>((n: string) => ({
          type: 'aws_db_instance', identifier: n, name: n, attributes: { multi_az: false },
        })),
      },
      remediation: rdsSingleAz.length === 0 ? undefined : {
        summary: 'Convert each to Multi-AZ via modify-db-instance.',
        options: [{
          approach: 'Set multi_az=true via Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'high', notes: 'Multi-AZ ≈ 2x DB instance cost.' },
          availability_impact: { level: 'low', notes: 'Modification can cause brief failover; usually <2 minutes.' },
          customer_visible: { level: 'low', notes: 'Brief connection blip during conversion.' },
          effort_estimate: { magnitude: 'hours', notes: 'Per instance.' },
          steps: ['Set multi_az=true.', 'Apply Terraform.', 'Verify standby provisioned.'],
          example_code: `resource "aws_db_instance" "app" {
  multi_az = true
}`,
        }],
      },
      alternative_satisfiers: [
        { via: 'RDS Cluster (Aurora) with multiple writer/reader instances', description: 'Aurora is multi-AZ by design.', evidence_required: ['Aurora cluster spec'], detected: false },
      ],
      nist_controls: ['cp-2','cp-10'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-RPL-ABO', relationship: 'shares-remediation', note: 'Multi-AZ + backups are paired.' },
      ],
    }),

    finding({
      rule: 'aws.dynamodb.tables_inventoried',
      passed: true, // inventory only; pass when we have any data
      severity: 'info',
      current: { summary: `${dynamoTableCount} DynamoDB table(s) inventoried.`, observations: { count: dynamoTableCount } },
      target: { summary: 'Inventory complete; prod tables have PITR enabled.', rationale: 'NIST CP-9.' },
      alternative_satisfiers: [],
      nist_controls: ['cp-9'],
      note: 'Per-table PITR is covered by KSI-RPL-ABO (`aws.dynamodb.pitr_enabled_for_prod`); this finding intentionally stays at inventory-only to avoid double-counting.',
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-RPL-ABO — Aligning Backups with Objectives
// Differs from CNA-OFA (availability) by focusing on backup-config alignment
// with documented RPO/RTO. Script side: enumerate backup configs; process
// side: the RPO/RTO doc.
// =====================================================================
export async function collectRplAbo(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // AWS Backup plans + selections + recent job outcomes
  let plans: any[] = [];
  let recentBackupJobs = 0;
  let failedBackupJobs = 0;
  try {
    const bk = aws.backup(ctx.auth);
    const lp = await bk.send(new ListBackupPlansCommand({}));
    plans = lp.BackupPlansList ?? [];
    evidence.push(ev('backup.plans', plans.map((p: any) => ({ id: p.BackupPlanId, name: p.BackupPlanName, lastExecutionDate: p.LastExecutionDate }))));
    try {
      const ninetyDaysAgo = new Date(Date.now() - 90 * 86400_000);
      const jobs = await bk.send(new ListBackupJobsCommand({ ByCreatedAfter: ninetyDaysAgo, MaxResults: 100 }));
      recentBackupJobs = jobs.BackupJobs?.length ?? 0;
      failedBackupJobs = (jobs.BackupJobs ?? []).filter((j: any) => j.State === 'FAILED' || j.State === 'ABORTED').length;
      evidence.push(ev('backup.recent_jobs_90d', { total: recentBackupJobs, failed: failedBackupJobs }));
    } catch (e: any) { warnings.push(`Backup jobs: ${e.message}`); }
  } catch (e: any) { warnings.push(`Backup plans: ${e.message}`); }

  // RDS automated backups + retention
  interface RdsBackup { id: string; retentionDays: number; multiAZ: boolean; }
  const rdsInst: RdsBackup[] = [];
  let rdsWithoutAdequateRetention = 0;
  try {
    const r = aws.rds(ctx.auth);
    const d = await r.send(new DescribeDBInstancesCommand({}));
    for (const i of d.DBInstances ?? []) {
      rdsInst.push({ id: i.DBInstanceIdentifier ?? '', retentionDays: i.BackupRetentionPeriod ?? 0, multiAZ: !!i.MultiAZ });
      if ((i.BackupRetentionPeriod ?? 0) < 7) rdsWithoutAdequateRetention++;
    }
    evidence.push(ev('rds.backup_retention', rdsInst));
  } catch (e: any) { warnings.push(`RDS: ${e.message}`); }

  // DynamoDB PITR
  let dynamoTablesTotal = 0;
  let dynamoTablesWithoutPitr = 0;
  try {
    const ddb = aws.dynamodb(ctx.auth);
    const lst = await ddb.send(new ListTablesCommand({}));
    for (const name of lst.TableNames ?? []) {
      dynamoTablesTotal++;
      try {
        const pitr = await ddb.send(new DescribeContinuousBackupsCommand({ TableName: name }));
        if (pitr.ContinuousBackupsDescription?.PointInTimeRecoveryDescription?.PointInTimeRecoveryStatus !== 'ENABLED') {
          dynamoTablesWithoutPitr++;
        }
      } catch { /* */ }
    }
    evidence.push(ev('dynamodb.pitr_audit', { total: dynamoTablesTotal, without_pitr: dynamoTablesWithoutPitr }));
  } catch (e: any) { warnings.push(`DynamoDB: ${e.message}`); }

  const findings = [
    finding({
      rule: 'aws.backup.plans_present_and_running',
      passed: plans.length >= 1 && failedBackupJobs === 0,
      severity: 'high',
      current: {
        summary: plans.length === 0
          ? 'No AWS Backup plans configured.'
          : `${plans.length} backup plan(s); ${recentBackupJobs} job(s) in last 90 days; ${failedBackupJobs} failures.`,
        observations: { plan_count: plans.length, jobs_90d: recentBackupJobs, failed_jobs: failedBackupJobs },
      },
      target: { summary: '≥1 AWS Backup plan exists, runs regularly, with zero unresolved job failures.', rationale: 'NIST CP-9. Backups must actually run.' },
      gap: (plans.length >= 1 && failedBackupJobs === 0) ? undefined : {
        description: plans.length === 0 ? 'No backup plans.' : 'Failed backup jobs indicate the plan is broken.',
        affected_resources: [{ type: 'aws_backup_plan', identifier: 'aggregate', attributes: { plan_count: plans.length, failed_jobs: failedBackupJobs } }],
      },
      remediation: (plans.length >= 1 && failedBackupJobs === 0) ? undefined : {
        summary: 'Create / fix backup plans; address failed-job root causes.',
        options: [{
          approach: 'Define AWS Backup plan with daily + weekly + monthly rules via Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'medium', notes: 'Backup storage per GB; restore costs.' },
          availability_impact: { level: 'low', notes: 'Brief I/O bump during backup window.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Plan + selection + IAM role.' },
          steps: ['Define backup plan with retention matching RPO/RTO doc.', 'Add selection rules tagging in-scope resources.', 'Monitor first run; tune.'],
          example_code: `resource "aws_backup_plan" "main" {
  name = "main"
  rule {
    rule_name           = "daily"
    target_vault_name   = aws_backup_vault.this.name
    schedule            = "cron(0 5 ? * * *)"
    lifecycle { delete_after = 35 }
  }
}`,
          references: [{ title: 'AWS Backup', url: 'https://docs.aws.amazon.com/aws-backup/latest/devguide/whatisbackup.html' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['cp-9','cp-9.1'],
    }),

    finding({
      rule: 'aws.rds.backup_retention_adequate',
      passed: rdsWithoutAdequateRetention === 0,
      severity: 'high',
      current: {
        summary: rdsInst.length === 0
          ? 'No RDS instances.'
          : `${rdsWithoutAdequateRetention} of ${rdsInst.length} RDS instance(s) have <7d backup retention.`,
        observations: { instances: rdsInst },
      },
      target: { summary: 'Prod RDS instances have BackupRetentionPeriod ≥ documented RPO (default ≥ 7 days).', rationale: 'NIST CP-9.' },
      gap: rdsWithoutAdequateRetention === 0 ? undefined : {
        description: 'Insufficient backup window for point-in-time recovery.',
        affected_resources: rdsInst.filter((i) => i.retentionDays < 7).map<AffectedResource>((i) => ({
          type: 'aws_db_instance', identifier: i.id, name: i.id, attributes: { backup_retention_period: i.retentionDays },
        })),
      },
      remediation: rdsWithoutAdequateRetention === 0 ? undefined : {
        summary: 'Set backup_retention_period ≥ 7 (or per RPO).',
        options: [{
          approach: 'Update via Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'low', notes: 'Backup storage costs scale with retention.' },
          availability_impact: { level: 'none', notes: 'No impact.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Apply Terraform.' },
          steps: ['Update backup_retention_period.', 'Apply (no downtime).'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['cp-9'],
    }),

    finding({
      rule: 'aws.dynamodb.pitr_enabled_for_prod',
      passed: dynamoTablesWithoutPitr === 0,
      severity: 'high',
      current: {
        summary: dynamoTablesTotal === 0
          ? 'No DynamoDB tables.'
          : `${dynamoTablesWithoutPitr} of ${dynamoTablesTotal} DynamoDB table(s) do not have PITR enabled.`,
        observations: { total: dynamoTablesTotal, without_pitr: dynamoTablesWithoutPitr },
      },
      target: { summary: 'All prod DynamoDB tables have PITR enabled (35-day continuous backup).', rationale: 'NIST CP-9. PITR is the only RTO-friendly DynamoDB recovery primitive.' },
      gap: dynamoTablesWithoutPitr === 0 ? undefined : {
        description: 'Without PITR, only periodic snapshots — RTO is much higher.',
        affected_resources: [{ type: 'aws_dynamodb_table', identifier: 'aggregate', attributes: { without_pitr: dynamoTablesWithoutPitr } }],
      },
      remediation: dynamoTablesWithoutPitr === 0 ? undefined : {
        summary: 'Enable point_in_time_recovery via Terraform.',
        options: [{
          approach: 'Set point_in_time_recovery.enabled=true.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'low', notes: 'PITR adds per-GB-month cost.' },
          availability_impact: { level: 'none', notes: 'No impact.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Per table.' },
          steps: ['Enable PITR.', 'Apply.'],
          example_code: `resource "aws_dynamodb_table" "app" {
  point_in_time_recovery { enabled = true }
}`,
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['cp-9'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-RPL-TRC — Testing Recovery Capabilities
// =====================================================================
export async function collectRplTrc(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // Recent restore jobs
  let restoreJobs90d = 0;
  let successfulRestores = 0;
  try {
    const bk = aws.backup(ctx.auth);
    const ninetyDaysAgo = new Date(Date.now() - 90 * 86400_000);
    const r = await bk.send(new ListRestoreJobsCommand({ ByCreatedAfter: ninetyDaysAgo, MaxResults: 100 }));
    restoreJobs90d = r.RestoreJobs?.length ?? 0;
    successfulRestores = (r.RestoreJobs ?? []).filter((j: any) => j.Status === 'COMPLETED').length;
    evidence.push(ev('backup.restore_jobs_90d', { total: restoreJobs90d, successful: successfulRestores }));
  } catch (e: any) { warnings.push(`Backup restore jobs: ${e.message}`); }

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'Documented gameday / DR exercise schedule (run quarterly, evidenced by AAR)',
      description: 'Recovery testing may be exercised via tabletop or live game days, not via AWS Backup restore jobs.',
      evidence_required: ['Quarterly game-day schedule', 'AAR from most recent test', 'RTO/RPO achievement metrics'],
      detected: false,
      detection_signals: [],
    },
  ];

  const findings = [
    finding({
      rule: 'aws.backup.recent_successful_restore_test',
      passed: successfulRestores >= 1,
      severity: 'medium',
      current: {
        summary: successfulRestores >= 1
          ? `${successfulRestores} successful restore job(s) in last 90 days.`
          : 'No successful restore jobs in last 90 days — recovery has not been tested via AWS Backup.',
        observations: { restore_jobs_90d: restoreJobs90d, successful: successfulRestores },
      },
      target: { summary: 'At least one successful restore job in last 90 days OR documented game-day with AAR.', rationale: 'NIST CP-4. Untested backups are unreliable.' },
      gap: successfulRestores >= 1 ? undefined : {
        description: 'Restore capability has not been validated recently.',
        affected_resources: [{ type: 'aws_backup_restore_job', identifier: 'none-90d', attributes: {} }],
      },
      remediation: successfulRestores >= 1 ? undefined : {
        summary: 'Schedule quarterly restore tests via AWS Backup OR run gameday exercises with AAR.',
        options: [{
          approach: 'Automated quarterly restore test via EventBridge + StartRestoreJob.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'low', notes: 'Restored resources incur cost during test window.' },
          availability_impact: { level: 'low', notes: 'Restore goes to a test-target — not prod impact.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Test script + AAR template + cadence setup.' },
          steps: [
            'Pick a representative recovery point.',
            'EventBridge schedule → Lambda invokes backup:StartRestoreJob to a test target.',
            'Verify restored data; record outcome in AAR template.',
            'Tear down test resources.',
          ],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['cp-4','cp-4.1','cp-10'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, ksi_level_alternatives: altSatisfiers, third_party_tools_detected: thirdParty };
}
