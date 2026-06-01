/**
 * Azure availability + backup collectors.
 *
 *   - KSI-CNA-OFA — Optimizing for Availability. Two findings: VMs are deployed
 *     across availability zones, and storage accounts use redundant SKUs
 *     (ZRS / GRS / GZRS / RA-GZRS) rather than LRS.
 *
 * Future-home for the RPL family (Recovery Point + Recovery Time / Backup
 * coverage). All via Azure Resource Graph; no new permissions beyond AZ-1's
 * Reader role.
 */
import * as azure from '../../core/auth/azure.ts';
import type { ProviderBlock, RawEvidence, Finding } from '../../core/envelope.ts';
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
