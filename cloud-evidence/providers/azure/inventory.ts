/**
 * Azure inventory collector — KSI-PIY-GIV.
 *
 * Azure Resource Graph IS the authoritative real-time inventory: a managed
 * service that indexes every Azure resource across every subscription a
 * principal can read, queryable via KQL with a 1-second freshness SLO.
 * The KSI signal is simply "is the inventory query path live?" — measured
 * via a non-zero asset count across the configured subscriptions.
 *
 * A breakdown by type is included as an observation to give the human
 * reviewer a top-of-mind picture of the environment shape (similar to the
 * AWS Config aggregator inventory + GCP Cloud Asset Inventory breakdowns).
 *
 * Reader role is sufficient (`Microsoft.ResourceGraph/resources/read`),
 * which AZ-1 already requires.
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

// =====================================================================
// KSI-PIY-GIV — Generating Inventories
// =====================================================================
export async function collectPiyGiv(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // Per-type summary across all configured subs.
  const summary = await runKql(subs,
    'Resources | summarize count = count() by type ' +
    '| order by count desc');
  if (summary.error) warnings.push(summary.error);

  const total = summary.rows.reduce<number>((acc, r: any) => acc + Number(r.count ?? 0), 0);
  const distinctTypes = summary.rows.length;
  // Top 20 types for the human-eyeball view.
  const topTypes = summary.rows.slice(0, 20).map((r: any) => ({ type: String(r.type ?? ''), count: Number(r.count ?? 0) }));

  evidence.push(ev('resourcegraph.inventory_summary', {
    total_resources: total,
    distinct_types: distinctTypes,
    top_types: topTypes,
    subscriptions: subs.length,
  }));

  findings.push(finding({
    rule: 'azure.piy.giv.inventory_signal_active',
    passed: total > 0,
    severity: 'high',
    current: {
      summary: total > 0
        ? `Azure Resource Graph returned ${total} resource(s) across ${distinctTypes} distinct type(s) and ${subs.length} subscription(s) — inventory is live.`
        : 'Azure Resource Graph returned zero resources — either the configured subscriptions are empty, or the Reader role on the runner principal isn\'t actually granted.',
      observations: {
        total_resources: total,
        distinct_types: distinctTypes,
        subscriptions: subs.length,
        top_types: topTypes,
      },
    },
    target: { summary: 'Azure Resource Graph returns non-zero assets across the configured subscriptions — the inventory backbone is live and the runner principal has `Reader` everywhere.', rationale: 'NIST CM-8, CM-8(1), PM-5. The KSI requires real-time generation of an authoritative inventory; Resource Graph is the Azure-canonical authoritative source.' },
    gap: { description: 'No inventory signal — either no subscriptions are configured, or the runner principal lacks Reader. Either way, downstream KSIs that rely on inventory will silently report empty.', affected_resources: [{ type: 'azure_subscription', identifier: 'aggregate', attributes: { subscriptions: subs.length, total_resources: 0 } }] },
    remediation: {
      summary: 'Confirm `azure.subscription_ids` lists every in-scope subscription, and that the runner principal is bound to the `Reader` role at the management-group (or per-subscription) scope.',
      options: [
        { approach: 'az CLI — assign Reader at the management group scope.', mechanism: 'cli', steps: [
          'az role assignment create --role Reader --assignee <principal-objectId> --scope /providers/Microsoft.Management/managementGroups/<mg-id>',
          'Re-run the collector and re-check the inventory finding',
        ] },
      ],
    },
    nist_controls: ['cm-8', 'cm-8.1', 'pm-5'],
    cross_ksi_dependencies: [{ ksi_id: 'KSI-CMT-LMC', relationship: 'shares-remediation', note: 'Same Resource Graph reach gates Change-Management evidence (CMT-LMC).' }],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}
