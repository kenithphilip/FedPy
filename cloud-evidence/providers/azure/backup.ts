/**
 * Azure availability + backup collectors.
 *
 *   - KSI-CNA-OFA — Optimizing for Availability. Two findings: VMs are deployed
 *     across availability zones, and storage accounts use redundant SKUs
 *     (ZRS / GRS / GZRS / RA-GZRS) rather than LRS.
 *   - KSI-RPL-ABO — Aligning Backups with Objectives. Surfaces that backup
 *     infrastructure (Recovery Services Vaults / Backup Vaults) exists, that
 *     workloads are actually being protected (backup-protected items present),
 *     and that recent backup jobs are succeeding.
 *   - KSI-RPL-TRC — Testing Recovery Capabilities. Looks for at least one
 *     successful Restore job in the last 90 days; alternative satisfier is a
 *     documented gameday / DR exercise with AAR.
 *
 * All via Azure Resource Graph (Resources + RecoveryServicesResources tables);
 * no new permissions beyond AZ-1's Reader role.
 */
import * as azure from '../../core/auth/azure.ts';
import type { ProviderBlock, RawEvidence, Finding, AlternativeSatisfier } from '../../core/envelope.ts';
import type { CollectorContext } from '../../core/ksi-map.ts';
import { finding } from '../../core/findings.ts';

function ev(source: string, data: unknown): RawEvidence {
  return { source, captured_at: new Date().toISOString(), data: data === undefined ? null : data };
}

async function runKql(subscriptions: string[], query: string): Promise<{ rows: any[]; error?: string }> {
  if (subscriptions.length === 0) return { rows: [], error: 'No subscriptions configured (config.azure.subscriptions is empty).' };
  let client: any;
  try { client = azure.resourceGraph(); }
  catch (e: any) { return { rows: [], error: `Azure Resource Graph client construction failed: ${e?.message ?? e}` }; }
  const rows: any[] = [];
  let skipToken: string | undefined;
  let pages = 0;
  try {
    do {
      const r = await client.resources({
        subscriptions, query,
        options: { top: 1000, resultFormat: 'objectArray', ...(skipToken ? { $skipToken: skipToken } : {}) },
      });
      const data = Array.isArray(r?.data) ? r.data : [];
      rows.push(...data);
      skipToken = r?.$skipToken ?? r?.skipToken ?? undefined;
    } while (skipToken && ++pages < 50);
  } catch (e: any) {
    return { rows, error: `Resource Graph query failed: ${e?.message ?? e}` };
  }
  return { rows };
}

function subscriptionsOf(ctx: CollectorContext): string[] {
  const list = ctx.azure?.subscription_ids ?? [];
  if (list.length) return list;
  const one = ctx.azure?.subscription_id;
  return one ? [one] : [];
}

// Storage replication SKUs that are NOT zone- or geo-redundant.
// LRS = locally-redundant within a single datacenter, so loss-of-DC = loss-of-data.
const SINGLE_DC_SKUS = new Set(['Standard_LRS', 'Premium_LRS']);

// =====================================================================
// KSI-CNA-OFA — Optimizing for Availability
// =====================================================================
export async function collectCnaOfa(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // 1) VMs across availability zones.
  const vms = await runKql(subs,
    'Resources | where type =~ "microsoft.compute/virtualmachines" ' +
    '| extend zone = tostring(zones[0]) ' +
    '| project subscriptionId, id, name, zone');
  if (vms.error) warnings.push(vms.error);
  const total = vms.rows.length;
  const zoned = vms.rows.filter((v) => typeof v.zone === 'string' && v.zone.length > 0);
  const distinctZones = new Set(zoned.map((v) => String(v.zone)));
  evidence.push(ev('resourcegraph.vm_availability_zones', {
    total, with_zone: zoned.length, distinct_zones: distinctZones.size, zones: [...distinctZones], sample: vms.rows.slice(0, 20),
  }));

  findings.push(finding({
    rule: 'azure.cna.ofa.vms_use_availability_zones', passed: total === 0 || (zoned.length === total && distinctZones.size >= 2), severity: 'medium',
    current: {
      summary: total === 0
        ? 'No VMs observed.'
        : `${zoned.length}/${total} VM(s) declare an availability zone; ${distinctZones.size} distinct zone(s) in use.`,
      observations: { total, with_zone: zoned.length, distinct_zones: distinctZones.size, zones: [...distinctZones] },
    },
    target: { summary: 'Every VM is pinned to an availability zone, and the fleet spans ≥ 2 zones — single-zone outage doesn\'t take the workload down.', rationale: 'NIST CP-7, CP-7(1), CP-9. Multi-zone deployment is the FedRAMP-recommended availability primitive on Azure.' },
    gap: { description: 'VMs are not spread across availability zones — a single-zone outage will take the workload offline.', affected_resources: vms.rows.filter((v) => !v.zone).slice(0, 50).map((v: any) => ({ type: 'azure_vm', identifier: v.id, attributes: {} })) },
    remediation: {
      summary: 'Redeploy in-scope VMs into availability zones, ideally with a Virtual Machine Scale Set spread across all 3 zones in the region.',
      options: [
        { approach: 'Terraform azurerm_linux_virtual_machine + zones argument.', mechanism: 'terraform', steps: ['Set `zone = "1"` / `"2"` / `"3"` on the VM (one per AZ for HA)', 'Or use azurerm_linux_virtual_machine_scale_set with zones = ["1","2","3"]'] },
      ],
    },
    nist_controls: ['cp-7', 'cp-7.1', 'cp-9'],
  }));

  // 2) Storage account replication.
  const sa = await runKql(subs,
    'Resources | where type =~ "microsoft.storage/storageaccounts" ' +
    '| extend sku = tostring(sku.name) ' +
    '| project id, name, subscriptionId, sku');
  if (sa.error) warnings.push(sa.error);
  const lrsCount = sa.rows.filter((s) => SINGLE_DC_SKUS.has(String(s.sku ?? ''))).length;
  evidence.push(ev('resourcegraph.storage_replication', { total: sa.rows.length, single_dc: lrsCount, sample: sa.rows.slice(0, 20) }));

  findings.push(finding({
    rule: 'azure.cna.ofa.storage_redundant_replication', passed: sa.rows.length === 0 || lrsCount === 0, severity: 'medium',
    current: {
      summary: lrsCount === 0
        ? sa.rows.length === 0 ? 'No storage accounts observed.' : `All ${sa.rows.length} storage account(s) use a zone- or geo-redundant SKU.`
        : `${lrsCount}/${sa.rows.length} storage account(s) use a single-datacenter SKU (LRS) — loss of the datacenter means loss of data.`,
      observations: { total: sa.rows.length, single_dc: lrsCount },
    },
    target: { summary: 'Storage accounts use Zone- or Geo-Redundant Storage (ZRS / GRS / GZRS / RA-GZRS), not LRS.', rationale: 'NIST CP-6, CP-9. FedRAMP requires data redundancy across availability zones.' },
    gap: { description: 'Storage accounts on LRS are not protected against datacenter loss.', affected_resources: sa.rows.filter((s) => SINGLE_DC_SKUS.has(String(s.sku ?? ''))).slice(0, 50).map((s: any) => ({ type: 'azure_storage_account', identifier: s.id, attributes: { sku: s.sku } })) },
    remediation: {
      summary: 'Migrate the listed storage accounts to ZRS / GZRS / RA-GZRS via the Azure Portal or `az storage account update --sku Standard_ZRS`. Migration is online for most cases.',
      options: [
        { approach: 'Terraform azurerm_storage_account.account_replication_type.', mechanism: 'terraform', steps: ['Set account_replication_type = "ZRS" (or "GZRS" for cross-region)', 'Plan + apply', 'Confirm replication via az storage account show'] },
      ],
    },
    nist_controls: ['cp-6', 'cp-9'],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}

// =====================================================================
// KSI-RPL-ABO — Aligning Backups with Objectives
// HYBRID: cloud signal proves the backup *plumbing* exists and is running;
// the operator still attaches the documented RPO/RTO doc + alignment review
// minutes via process_artifacts_required in ksi-map.ts.
// =====================================================================
const VAULT_TYPES_FILTER =
  '(type =~ "microsoft.recoveryservices/vaults" or type =~ "microsoft.dataprotection/backupvaults")';

export async function collectRplAbo(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // 1) Vaults present (Recovery Services Vaults OR new Backup Vaults).
  const vaults = await runKql(subs,
    `Resources | where ${VAULT_TYPES_FILTER} ` +
    '| project id, name, type, subscriptionId, location');
  if (vaults.error) warnings.push(vaults.error);
  evidence.push(ev('resourcegraph.backup_vaults', {
    total: vaults.rows.length,
    by_type: vaults.rows.reduce<Record<string, number>>((acc, v) => {
      const t = String(v.type ?? 'unknown'); acc[t] = (acc[t] ?? 0) + 1; return acc;
    }, {}),
    sample: vaults.rows.slice(0, 20),
  }));

  findings.push(finding({
    rule: 'azure.rpl.abo.recovery_vault_present', passed: vaults.rows.length >= 1, severity: 'high',
    current: {
      summary: vaults.rows.length === 0
        ? 'No Recovery Services Vault or Backup Vault observed in any configured subscription.'
        : `${vaults.rows.length} backup vault(s) observed across the configured subscriptions.`,
      observations: { total: vaults.rows.length },
    },
    target: { summary: 'At least one Recovery Services Vault or Backup Vault exists to hold backup data.', rationale: 'NIST CP-9, CP-9(1). A vault is the prerequisite for any Azure-native backup retention.' },
    gap: { description: 'No vault means no Azure-native backups can run — RPO is effectively unbounded.', affected_resources: [{ type: 'azure_subscription', identifier: 'aggregate', attributes: { vault_count: 0 } }] },
    remediation: {
      summary: 'Provision a Recovery Services Vault per in-scope region and bind a backup policy.',
      options: [
        { approach: 'Terraform azurerm_recovery_services_vault + azurerm_backup_policy_vm.', mechanism: 'terraform', steps: [
          'Create azurerm_recovery_services_vault per region',
          'Define azurerm_backup_policy_vm with a daily frequency + retention matching RPO',
          'Attach via azurerm_backup_protected_vm to the in-scope VMs',
        ] },
      ],
    },
    nist_controls: ['cp-9', 'cp-9.1'],
  }));

  // 2) Protected items present (something is actually being backed up).
  // RecoveryServicesResources table holds backup-protected items for the classic vault stack.
  const protectedItems = await runKql(subs,
    'RecoveryServicesResources | where type =~ "microsoft.recoveryservices/vaults/backupprotecteditems" ' +
    '| project id, name, subscriptionId, properties');
  if (protectedItems.error) warnings.push(protectedItems.error);
  evidence.push(ev('resourcegraph.backup_protected_items', {
    total: protectedItems.rows.length,
    sample: protectedItems.rows.slice(0, 10).map((r: any) => ({ id: r.id, name: r.name })),
  }));

  // Pass IF there are no vaults (vacuously — finding #1 already failed and
  // dominates) OR there are protected items. The intent is "if you have a
  // vault, you also have items in it".
  const protectedItemsPassed = vaults.rows.length === 0 || protectedItems.rows.length >= 1;
  findings.push(finding({
    rule: 'azure.rpl.abo.protected_items_present', passed: protectedItemsPassed, severity: 'high',
    current: {
      summary: protectedItems.rows.length === 0
        ? (vaults.rows.length === 0 ? 'No vaults, so no protected items expected.' : 'Vaults exist but no backup-protected items are configured under them.')
        : `${protectedItems.rows.length} backup-protected item(s) observed.`,
      observations: { vaults: vaults.rows.length, protected_items: protectedItems.rows.length },
    },
    target: { summary: 'Every in-scope workload (VMs, SQL, file shares, blobs) is registered as a backup-protected item under a vault policy.', rationale: 'NIST CP-9. An empty vault provides no recovery capability.' },
    gap: { description: 'Vaults exist but no protected items — the backup plumbing is provisioned but not actually protecting anything.', affected_resources: [{ type: 'azure_recovery_services_vault', identifier: 'aggregate', attributes: { vaults: vaults.rows.length, protected_items: 0 } }] },
    remediation: {
      summary: 'Register the in-scope workloads as protected items under the vault, applying a policy whose retention meets or exceeds the documented RPO.',
      options: [
        { approach: 'Terraform azurerm_backup_protected_vm / azurerm_backup_container_storage_account.', mechanism: 'terraform', steps: [
          'For each in-scope VM: declare azurerm_backup_protected_vm with backup_policy_id',
          'For Azure Files: declare azurerm_backup_container_storage_account + azurerm_backup_protected_file_share',
          'For SQL on VM / SQL MI: declare azurerm_backup_policy_vm_workload',
        ] },
      ],
    },
    nist_controls: ['cp-9', 'cp-9.1', 'cp-9.8'],
    cross_ksi_dependencies: [
      { ksi_id: 'KSI-RPL-TRC', relationship: 'precedes', note: 'Backup coverage is a prerequisite to meaningful restore testing.' },
      { ksi_id: 'KSI-CNA-OFA', relationship: 'shares-remediation', note: 'Availability and backup are paired CP family controls.' },
    ],
  }));

  // 3) Backup jobs running cleanly in last 30 days.
  // The RecoveryServicesResources `backupjobs` rows carry properties.startTime
  // and properties.status; we surface counts by status. Pass = at least one
  // recent Completed job and no Failed jobs in window.
  const jobs = await runKql(subs,
    'RecoveryServicesResources | where type =~ "microsoft.recoveryservices/vaults/backupjobs" ' +
    '| extend op = tostring(properties.operation), status = tostring(properties.status), startTime = todatetime(properties.startTime) ' +
    '| where startTime > ago(30d) and op =~ "Backup" ' +
    '| project id, name, subscriptionId, op, status, startTime');
  if (jobs.error) warnings.push(jobs.error);
  // JS-authoritative re-filter so collector behaviour does not depend on the
  // mock honouring the KQL `where` clauses.
  const thirtyDaysAgo = Date.now() - 30 * 86400_000;
  const recentBackupJobs = jobs.rows.filter((j: any) => {
    const op = String(j.op ?? '').toLowerCase();
    if (op && op !== 'backup') return false;
    const t = j.startTime ? Date.parse(j.startTime) : Number.NaN;
    return Number.isFinite(t) ? t >= thirtyDaysAgo : true;
  });
  const completed = recentBackupJobs.filter((j: any) => String(j.status ?? '').toLowerCase() === 'completed').length;
  const failed = recentBackupJobs.filter((j: any) => {
    const s = String(j.status ?? '').toLowerCase();
    return s === 'failed' || s === 'completedwitherrors';
  }).length;
  evidence.push(ev('resourcegraph.backup_jobs_30d', {
    total: recentBackupJobs.length, completed, failed, sample: recentBackupJobs.slice(0, 20),
  }));

  // Pass criteria: if no vaults / items configured, this finding is vacuous
  // (the upstream findings have already flagged the absence). Otherwise we
  // need at least one Completed job and zero Failed.
  const jobsPassed = vaults.rows.length === 0
    || protectedItems.rows.length === 0
    || (completed >= 1 && failed === 0);
  findings.push(finding({
    rule: 'azure.rpl.abo.recent_backup_jobs_clean', passed: jobsPassed, severity: 'high',
    current: {
      summary: recentBackupJobs.length === 0
        ? (vaults.rows.length === 0 || protectedItems.rows.length === 0 ? 'No backup jobs expected (no vault/items).' : 'No backup jobs observed in the last 30 days — backup may have stopped running.')
        : `${recentBackupJobs.length} backup job(s) in last 30 days: ${completed} completed, ${failed} failed.`,
      observations: { recent_jobs: recentBackupJobs.length, completed, failed },
    },
    target: { summary: '≥ 1 successful backup job per protected workload per 24 hours, and zero failed jobs in the 30-day window.', rationale: 'NIST CP-9(1). A configured-but-never-running backup is identical to no backup at all.' },
    gap: { description: failed > 0 ? 'Backup jobs are failing — restore-capability assumption is invalidated until failures clear.' : 'No recent successful backup jobs — backup pipeline may be paused.', affected_resources: recentBackupJobs.filter((j: any) => String(j.status ?? '').toLowerCase() !== 'completed').slice(0, 50).map((j: any) => ({ type: 'azure_backup_job', identifier: j.id ?? j.name ?? 'unknown', attributes: { status: j.status } })) },
    remediation: {
      summary: 'Investigate failed backup jobs via Azure Monitor / Backup Center; resolve root cause before relying on the vault for recovery.',
      options: [
        { approach: 'Backup Center → Jobs → filter "Failed" + "Last 30 days"; inspect error code per job.', mechanism: 'console', steps: [
          'Open Backup Center in the Azure portal',
          'Pivot Jobs by Status=Failed in the last 30 days',
          'Resolve per-error guidance (most commonly: VM agent unreachable, retention policy too short, RBAC drift on backup operator)',
        ] },
      ],
    },
    nist_controls: ['cp-9', 'cp-9.1'],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}

// =====================================================================
// KSI-RPL-TRC — Testing Recovery Capabilities
// HYBRID: cloud signal looks for a recent successful Restore job. Alternative
// satisfier covers gameday / tabletop exercise paths (with AAR attached as a
// process artifact in ksi-map.ts).
// =====================================================================
export async function collectRplTrc(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // Restore jobs in last 90 days.
  const jobs = await runKql(subs,
    'RecoveryServicesResources | where type =~ "microsoft.recoveryservices/vaults/backupjobs" ' +
    '| extend op = tostring(properties.operation), status = tostring(properties.status), startTime = todatetime(properties.startTime) ' +
    '| where startTime > ago(90d) and op =~ "Restore" ' +
    '| project id, name, subscriptionId, op, status, startTime');
  if (jobs.error) warnings.push(jobs.error);

  // JS-authoritative re-filter: tests' mock just routes on substring and
  // returns canned rows, so we re-apply the time + operation predicates here.
  const ninetyDaysAgo = Date.now() - 90 * 86400_000;
  const restoreJobs = jobs.rows.filter((j: any) => {
    const op = String(j.op ?? '').toLowerCase();
    if (op && op !== 'restore') return false;
    const t = j.startTime ? Date.parse(j.startTime) : Number.NaN;
    return Number.isFinite(t) ? t >= ninetyDaysAgo : true;
  });
  const successfulRestores = restoreJobs.filter((j: any) => String(j.status ?? '').toLowerCase() === 'completed').length;

  evidence.push(ev('resourcegraph.restore_jobs_90d', {
    total: restoreJobs.length, successful: successfulRestores, sample: restoreJobs.slice(0, 20),
  }));

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'Documented gameday / tabletop DR exercise (run quarterly, evidenced by AAR)',
      description: 'Recovery testing may be exercised via tabletop or live game days rather than via Azure-Backup restore jobs.',
      evidence_required: [
        'Quarterly game-day schedule',
        'AAR from most recent test',
        'RTO/RPO achievement metrics from the test',
      ],
      detected: false,
      detection_signals: [],
    },
  ];

  findings.push(finding({
    rule: 'azure.rpl.trc.recent_successful_restore', passed: successfulRestores >= 1, severity: 'medium',
    current: {
      summary: successfulRestores >= 1
        ? `${successfulRestores} successful Restore job(s) in last 90 days.`
        : (restoreJobs.length === 0
          ? 'No Restore jobs in the last 90 days — recovery capability has not been exercised via Azure Backup.'
          : `${restoreJobs.length} Restore job(s) in last 90 days but none completed successfully.`),
      observations: { restore_jobs_90d: restoreJobs.length, successful: successfulRestores },
    },
    target: { summary: 'At least one successful Azure-Backup Restore job in the last 90 days, OR a documented quarterly gameday with AAR.', rationale: 'NIST CP-4, CP-4(1), CP-10(2). Untested backups cannot be relied upon — recovery has to be exercised.' },
    gap: { description: 'Restore capability has not been validated via Azure Backup in the last 90 days.', affected_resources: [{ type: 'azure_backup_restore_job', identifier: 'none-90d', attributes: {} }] },
    remediation: {
      summary: 'Schedule a quarterly restore test (to an isolated target) OR run a gameday with AAR. Either path satisfies CP-4 review.',
      options: [
        { approach: 'Automated quarterly restore test via Azure Automation runbook + Backup REST API.', mechanism: 'terraform', steps: [
          'Pick a representative recovery point under a vault',
          'Azure Automation schedule → runbook calls RecoveryPoints/RestoreToTarget against a non-prod RG',
          'Verify restored item; record outcome in AAR template',
          'Tear down the restored test resources',
        ] },
        { approach: 'Manual quarterly restore test driven by Backup Center.', mechanism: 'console', steps: [
          'Backup Center → Restore → select a recent recovery point',
          'Target a non-prod resource group',
          'Validate functional integrity; capture screenshots into the AAR',
        ] },
      ],
    },
    alternative_satisfiers: altSatisfiers,
    nist_controls: ['cp-4', 'cp-4.1', 'cp-10', 'cp-10.2'],
    cross_ksi_dependencies: [
      { ksi_id: 'KSI-RPL-ABO', relationship: 'depends-on', note: 'Restore testing assumes a vault + protected items exist (see RPL-ABO).' },
    ],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings, ksi_level_alternatives: altSatisfiers };
}
