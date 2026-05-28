/**
 * GCP backup-domain CNA collector.
 * Covers KSI-CNA-OFA — Optimizing for Availability.
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

export async function collectCnaOfa(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  const zonalMigs: string[] = [];
  let totalMigs = 0;
  try {
    const compute = await gcpAuth.googleClient<any>('compute', 'v1');
    const r = await compute.regionInstanceGroupManagers.aggregatedList({ project: ctx.project });
    const regional = r.data.items ?? {};
    for (const region of Object.values<any>(regional)) totalMigs += (region.regionInstanceGroupManagers ?? []).length;
    const r2 = await compute.instanceGroupManagers.aggregatedList({ project: ctx.project });
    const zonal = r2.data.items ?? {};
    for (const zone of Object.values<any>(zonal)) {
      for (const m of zone.instanceGroupManagers ?? []) {
        zonalMigs.push(m.name);
        totalMigs++;
      }
    }
    evidence.push(ev('compute.mig_inventory', { total: totalMigs, zonal: zonalMigs }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'compute.regionInstanceGroupManagers.aggregatedList/instanceGroupManagers.aggregatedList', 'compute.instanceGroupManagers.list (roles/compute.viewer)')); }

  const sqlZonal: string[] = [];
  let sqlCount = 0;
  try {
    const sqladmin = await gcpAuth.googleClient<any>('sqladmin', 'v1');
    const r = await sqladmin.instances.list({ project: ctx.project });
    for (const i of r.data.items ?? []) {
      sqlCount++;
      if (i.settings?.availabilityType !== 'REGIONAL') sqlZonal.push(i.name);
    }
    evidence.push(ev('sqladmin.availability', { total: sqlCount, zonal: sqlZonal }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'sqladmin.instances.list', 'cloudsql.instances.list (roles/cloudsql.viewer)')); }

  const singleRegionBuckets: string[] = [];
  let bucketCount = 0;
  try {
    const storage = await gcpAuth.googleClient<any>('storage', 'v1');
    const r = await storage.buckets.list({ project: ctx.project });
    for (const b of r.data.items ?? []) {
      bucketCount++;
      if (b.locationType === 'region') singleRegionBuckets.push(b.name);
    }
    evidence.push(ev('storage.bucket_location_type', { total: bucketCount, single_region: singleRegionBuckets.length, sample: singleRegionBuckets.slice(0, 10) }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'storage.buckets.list', 'storage.buckets.list (roles/storage.admin or roles/viewer)')); }

  const findings = [
    finding({
      rule: 'gcp.mig.prod_regional',
      passed: zonalMigs.length === 0,
      severity: 'high',
      current: {
        summary: zonalMigs.length === 0
          ? `All ${totalMigs} MIG(s) are regional.`
          : `${zonalMigs.length} of ${totalMigs} MIG(s) are zonal.`,
        observations: { total: totalMigs, zonal: zonalMigs },
      },
      target: { summary: 'Prod MIGs are regional (multi-zone).', rationale: 'NIST CP-2, CP-7.' },
      gap: zonalMigs.length === 0 ? undefined : {
        description: 'Zonal MIGs cannot survive zone outage.',
        affected_resources: zonalMigs.map<AffectedResource>((n: string) => ({
          type: 'google_compute_instance_group_manager', identifier: n, name: n, attributes: { type: 'zonal' },
        })),
      },
      remediation: zonalMigs.length === 0 ? undefined : {
        summary: 'Recreate as regional MIG via Terraform.',
        options: [{
          approach: 'Migrate zonal → regional.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'low', notes: 'Cross-zone traffic charges.' },
          availability_impact: { level: 'low', notes: 'Blue/green migration; net availability improves.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per MIG.' },
          steps: ['Create regional MIG alongside zonal.', 'Shift LB traffic.', 'Decommission zonal MIG.'],
          example_code: 'resource "google_compute_region_instance_group_manager" "app" {\n  name               = "app"\n  region             = "us-central1"\n  distribution_policy_zones = ["us-central1-a","us-central1-b","us-central1-c"]\n  target_size        = 3\n}',
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['cp-2','cp-7'],
    }),
    finding({
      rule: 'gcp.cloudsql.prod_regional_ha',
      passed: sqlZonal.length === 0,
      severity: 'high',
      current: {
        summary: sqlZonal.length === 0
          ? `All ${sqlCount} Cloud SQL instance(s) are REGIONAL.`
          : `${sqlZonal.length} of ${sqlCount} Cloud SQL instance(s) are ZONAL.`,
        observations: { total: sqlCount, zonal: sqlZonal },
      },
      target: { summary: 'Prod Cloud SQL instances have availabilityType=REGIONAL.', rationale: 'NIST CP-2, CP-10.' },
      gap: sqlZonal.length === 0 ? undefined : {
        description: 'Zonal Cloud SQL cannot survive zone outage.',
        affected_resources: sqlZonal.map<AffectedResource>((n: string) => ({
          type: 'google_sql_database_instance', identifier: n, name: n, attributes: { availabilityType: 'ZONAL' },
        })),
      },
      remediation: sqlZonal.length === 0 ? undefined : {
        summary: 'Set availability_type=REGIONAL via Terraform.',
        options: [{
          approach: 'Update Cloud SQL availability_type.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'high', notes: 'Regional HA ≈ 2x DB instance cost.' },
          availability_impact: { level: 'low', notes: 'Brief downtime during conversion.' },
          customer_visible: { level: 'low', notes: 'Brief connection blip.' },
          effort_estimate: { magnitude: 'hours', notes: 'Per instance.' },
          steps: ['Set availability_type=REGIONAL.', 'Apply Terraform.', 'Verify standby.'],
          example_code: 'resource "google_sql_database_instance" "main" {\n  settings { availability_type = "REGIONAL" }\n}',
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['cp-2','cp-10'],
    }),
    finding({
      rule: 'gcp.storage.prod_buckets_redundant',
      passed: singleRegionBuckets.length === 0,
      severity: 'medium',
      current: {
        summary: singleRegionBuckets.length === 0
          ? `All ${bucketCount} bucket(s) are MULTI_REGION or DUAL_REGION.`
          : `${singleRegionBuckets.length} of ${bucketCount} bucket(s) are single-REGION.`,
        observations: { total: bucketCount, single_region: singleRegionBuckets.slice(0, 20) },
      },
      target: { summary: 'Prod buckets are MULTI_REGION or DUAL_REGION (or documented residency exception).', rationale: 'NIST CP-9.' },
      gap: singleRegionBuckets.length === 0 ? undefined : {
        description: 'Single-region buckets at risk of region outage.',
        affected_resources: singleRegionBuckets.slice(0, 20).map<AffectedResource>((n: string) => ({
          type: 'google_storage_bucket', identifier: n, name: n, attributes: { locationType: 'region' },
        })),
      },
      remediation: singleRegionBuckets.length === 0 ? undefined : {
        summary: 'Replicate to multi-region OR document residency exception.',
        options: [{
          approach: 'Migrate to multi-region bucket.',
          mechanism: 'process',
          owner_team: 'SRE',
          cost_impact: { level: 'high', notes: 'Multi-region storage costs more per GB.' },
          availability_impact: { level: 'low', notes: 'Migration via data copy.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Per bucket.' },
          steps: ['Identify residency requirements.', 'Create multi-region bucket.', 'Copy + cutover.', 'Delete original.'],
        }],
      },
      alternative_satisfiers: [
        { via: 'Documented data-residency exception', description: 'Single-region allowed when residency requires.', evidence_required: ['Documented residency requirement'], detected: false },
      ],
      nist_controls: ['cp-9'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-RPL-ABO — Aligning Backups with Objectives (GCP)
// =====================================================================
export async function collectRplAbo(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // Cloud SQL backups
  interface SqlBackup { name: string; backupEnabled: boolean; pitr: boolean; retainedBackups: number; }
  const sqlBackups: SqlBackup[] = [];
  let sqlWithoutPitr = 0;
  try {
    const sqladmin = await gcpAuth.googleClient<any>('sqladmin', 'v1');
    const r = await sqladmin.instances.list({ project: ctx.project });
    for (const i of r.data.items ?? []) {
      const bc = i.settings?.backupConfiguration;
      const rec = {
        name: i.name,
        backupEnabled: !!bc?.enabled,
        pitr: !!bc?.pointInTimeRecoveryEnabled,
        retainedBackups: bc?.backupRetentionSettings?.retainedBackups ?? 0,
      };
      sqlBackups.push(rec);
      if (!rec.pitr) sqlWithoutPitr++;
    }
    evidence.push(ev('sqladmin.backup_audit', sqlBackups));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'sqladmin.instances.list', 'cloudsql.instances.list (roles/cloudsql.viewer)')); }

  // Compute Engine snapshot schedules (per-disk resource policies)
  let snapshotPolicyCount = 0;
  try {
    const compute = await gcpAuth.googleClient<any>('compute', 'v1');
    // resourcePolicies.aggregatedList lists snapshot schedule policies across regions
    const r = await compute.resourcePolicies.aggregatedList({ project: ctx.project });
    const items = r.data.items ?? {};
    for (const region of Object.values<any>(items)) {
      for (const p of region.resourcePolicies ?? []) {
        if (p.snapshotSchedulePolicy) snapshotPolicyCount++;
      }
    }
    evidence.push(ev('compute.snapshot_schedule_policies', { count: snapshotPolicyCount }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'compute.resourcePolicies.aggregatedList', 'compute.resourcePolicies.list (roles/compute.viewer)')); }

  // GCS versioning + retention
  let bucketsWithoutVersioning: string[] = [];
  try {
    const storage = await gcpAuth.googleClient<any>('storage', 'v1');
    const r = await storage.buckets.list({ project: ctx.project });
    for (const b of r.data.items ?? []) {
      if (!b.versioning?.enabled && !b.retentionPolicy) bucketsWithoutVersioning.push(b.name);
    }
    evidence.push(ev('storage.versioning_audit', { without_versioning_or_retention: bucketsWithoutVersioning }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'storage.buckets.list', 'storage.buckets.list (roles/storage.admin or roles/viewer)')); }

  const findings = [
    finding({
      rule: 'gcp.cloudsql.pitr_enabled',
      passed: sqlWithoutPitr === 0,
      severity: 'high',
      current: {
        summary: sqlBackups.length === 0
          ? 'No Cloud SQL instances.'
          : `${sqlWithoutPitr} of ${sqlBackups.length} Cloud SQL instance(s) do not have PITR enabled.`,
        observations: { all: sqlBackups },
      },
      target: { summary: 'All prod Cloud SQL instances have backupConfiguration.pointInTimeRecoveryEnabled=true with retention ≥ 7 days.', rationale: 'NIST CP-9.' },
      gap: sqlWithoutPitr === 0 ? undefined : {
        description: 'Without PITR, only periodic full backups — RTO is much higher.',
        affected_resources: sqlBackups.filter((s) => !s.pitr).map<AffectedResource>((s) => ({
          type: 'google_sql_database_instance', identifier: s.name, name: s.name, attributes: { pitr: false },
        })),
      },
      remediation: sqlWithoutPitr === 0 ? undefined : {
        summary: 'Enable PITR + backup retention via Terraform.',
        options: [{
          approach: 'Update settings.backup_configuration.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'low', notes: 'PITR storage charges.' },
          availability_impact: { level: 'none', notes: 'No impact.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Apply Terraform.' },
          steps: ['Set backup_configuration.point_in_time_recovery_enabled=true.', 'Apply (no downtime).'],
          example_code: `resource "google_sql_database_instance" "main" {
  settings {
    backup_configuration {
      enabled                         = true
      point_in_time_recovery_enabled  = true
      backup_retention_settings { retained_backups = 7 retention_unit = "COUNT" }
    }
  }
}`,
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['cp-9'],
    }),

    finding({
      rule: 'gcp.compute.snapshot_schedules_present',
      passed: snapshotPolicyCount >= 1,
      severity: 'medium',
      current: {
        summary: snapshotPolicyCount >= 1
          ? `${snapshotPolicyCount} snapshot schedule policy/policies configured.`
          : 'No snapshot schedule policies. Persistent disks lack automated snapshots.',
        observations: { policy_count: snapshotPolicyCount },
      },
      target: { summary: 'Prod persistent disks have a snapshot schedule policy attached.', rationale: 'NIST CP-9.' },
      gap: snapshotPolicyCount >= 1 ? undefined : {
        description: 'PD recovery limited to manual snapshots.',
        affected_resources: [{ type: 'google_compute_resource_policy', identifier: 'none', attributes: {} }],
      },
      remediation: snapshotPolicyCount >= 1 ? undefined : {
        summary: 'Create snapshot schedule + attach to disks.',
        options: [{
          approach: 'Define schedule via Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'low', notes: 'Snapshot storage.' },
          availability_impact: { level: 'none', notes: 'Pure observation.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Apply.' },
          steps: ['Create snapshot_schedule_policy.', 'Attach to disks via resource_policies.', 'Apply.'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['cp-9'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-RPL-TRC — Testing Recovery Capabilities (GCP)
// =====================================================================
export async function collectRplTrc(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // Cloud SQL backup runs (recent successful)
  let recentBackupRuns = 0;
  try {
    const sqladmin = await gcpAuth.googleClient<any>('sqladmin', 'v1');
    const inst = await sqladmin.instances.list({ project: ctx.project });
    for (const i of (inst.data.items ?? []).slice(0, 5)) { // sample first 5
      try {
        const r = await sqladmin.backupRuns.list({ project: ctx.project, instance: i.name, maxResults: 20 });
        const successful = (r.data.items ?? []).filter((b: any) => b.status === 'SUCCESSFUL').length;
        recentBackupRuns += successful;
      } catch { /* */ }
    }
    evidence.push(ev('sqladmin.backup_runs', { recent_successful: recentBackupRuns }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'sqladmin.backupRuns.list', 'cloudsql.backupRuns.list (roles/cloudsql.viewer)')); }

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'Documented quarterly DR game-day with AAR',
      description: 'Recovery testing may be exercised via tabletop / live game days.',
      evidence_required: ['Quarterly schedule', 'Most recent AAR', 'RTO/RPO achieved'],
      detected: false,
      detection_signals: [],
    },
  ];

  const findings = [
    finding({
      rule: 'gcp.cloudsql.recent_successful_backups',
      passed: recentBackupRuns >= 1,
      severity: 'medium',
      current: {
        summary: recentBackupRuns >= 1
          ? `${recentBackupRuns} successful Cloud SQL backup run(s) recently — proves backup mechanism works.`
          : 'No recent successful Cloud SQL backup runs detected.',
        observations: { recent_successful_runs: recentBackupRuns },
      },
      target: { summary: 'Recent successful backup runs OR documented restore-test cadence in AAR.', rationale: 'NIST CP-4. Untested backups are unreliable.' },
      gap: recentBackupRuns >= 1 ? undefined : {
        description: 'No backup-success evidence.',
        affected_resources: [{ type: 'google_sql_backup_run', identifier: 'none', attributes: {} }],
      },
      remediation: recentBackupRuns >= 1 ? undefined : {
        summary: 'Schedule quarterly restore-to-test-instance exercises; document in AAR.',
        options: [{
          approach: 'Automated quarterly restore drill (Cloud Function clones backup to test instance).',
          mechanism: 'process',
          owner_team: 'SRE',
          cost_impact: { level: 'low', notes: 'Test-instance cost during drill window.' },
          availability_impact: { level: 'low', notes: 'Restore goes to test target.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Drill script + AAR template.' },
          steps: ['Schedule Cloud Function quarterly.', 'Clone backup to test SQL instance.', 'Verify data.', 'Record AAR.', 'Tear down.'],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['cp-4','cp-4.1'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, ksi_level_alternatives: altSatisfiers, third_party_tools_detected: thirdParty };
}
