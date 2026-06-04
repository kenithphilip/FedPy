/**
 * Azure VDR live-scan collector — KSI-AFR-VDR.
 *
 * Mirror of `providers/{aws,gcp}/vdr-scan.ts`. The Vulnerability Detection
 * and Response indicator is satisfied (on the cloud side) by:
 *   1. An active vulnerability-assessment feed producing findings.
 *   2. A KEV-prioritized triage path (Known Exploited Vulnerabilities from
 *      CISA — high-severity items the operator must respond to within SLA).
 *
 * Azure-canonical signal: Microsoft Defender Vulnerability Management
 * (MDVM) findings, surfaced via `securityresources` →
 * `microsoft.security/assessments` rows whose displayName / metadata
 * references CVE IDs. We join those against the CISA Known Exploited
 * Vulnerabilities catalog (committed offline at
 * `docs/cisa-kev.generated.json`) to compute KEV-affected counts.
 *
 * Findings (single):
 *   - `azure.afr.vdr.mdvm_kev_responsive` — Defender VM/Container findings
 *     are present AND every KEV-listed CVE has no Unhealthy assessment OR
 *     a SLA-compliant in-progress remediation note.
 *
 * Read-only: `securityresources` table needs `Security Reader` (same constraint
 * as MLA-EVC / SCR-MON).
 */
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as azure from '../../core/auth/azure.ts';
import type { ProviderBlock, RawEvidence, Finding } from '../../core/envelope.ts';
import type { CollectorContext } from '../../core/ksi-map.ts';
import { finding } from '../../core/findings.ts';

const __dirname = dirname(fileURLToPath(import.meta.url));

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

/**
 * Load the committed CISA KEV catalog. Honors the `CLOUD_EVIDENCE_KEV_PATH`
 * env override (same convention the AWS/GCP collectors use). Returns a Set
 * of normalized CVE ids for fast membership tests.
 */
function loadKevCatalog(): Set<string> {
  const envPath = process.env.CLOUD_EVIDENCE_KEV_PATH;
  const candidates: string[] = [];
  if (envPath) candidates.push(envPath);
  candidates.push(resolve(__dirname, '..', '..', 'docs', 'cisa-kev.generated.json'));
  for (const path of candidates) {
    if (!existsSync(path)) continue;
    try {
      const raw = JSON.parse(readFileSync(path, 'utf8'));
      const items: unknown[] = Array.isArray(raw) ? raw : Array.isArray(raw?.vulnerabilities) ? raw.vulnerabilities : [];
      const set = new Set<string>();
      for (const it of items) {
        const cve = (it as any)?.cveID ?? (it as any)?.cve ?? (it as any)?.id;
        if (typeof cve === 'string') set.add(cve.toUpperCase().trim());
      }
      return set;
    } catch { /* fall through to next candidate */ }
  }
  return new Set();
}

const CVE_RE = /CVE-\d{4}-\d{4,7}/gi;

function extractCves(text: string): string[] {
  const m = text.match(CVE_RE);
  return m ? Array.from(new Set(m.map((s) => s.toUpperCase()))) : [];
}

// =====================================================================
// KSI-AFR-VDR — Vulnerability Detection and Response (HYBRID)
// =====================================================================
export async function collectVdrScan(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  const kev = loadKevCatalog();
  if (kev.size === 0) {
    warnings.push('CISA KEV catalog is empty or unreadable; KEV-priority detection degrades to "no KEV match" for all findings.');
  }

  // Pull Defender for Cloud assessments. The displayName + metadata fields
  // commonly carry CVE references for vulnerability-management findings
  // (e.g. "CVE-2024-31497 must be remediated on virtual machine X").
  const assessments = await runKql(subs,
    'securityresources | where type =~ "microsoft.security/assessments" ' +
    '| extend displayName = tostring(properties.displayName), ' +
    'description = tostring(properties.metadata.description), ' +
    'status = tostring(properties.status.code) ' +
    '| project id, name, subscriptionId, displayName, description, status');
  if (assessments.error) warnings.push(assessments.error);

  const total = assessments.rows.length;
  const unhealthy = assessments.rows.filter((a: any) => String(a.status ?? '').toLowerCase() === 'unhealthy');

  // Extract CVEs from each row + classify against KEV.
  let unhealthyKevCount = 0;
  const kevSample: Array<{ id: string; cves: string[]; displayName: string }> = [];
  for (const row of unhealthy) {
    const text = `${row.displayName ?? ''} ${row.description ?? ''}`;
    const cves = extractCves(text);
    if (!cves.length) continue;
    const kevHits = cves.filter((c) => kev.has(c));
    if (kevHits.length > 0) {
      unhealthyKevCount++;
      if (kevSample.length < 20) kevSample.push({ id: String(row.id ?? ''), cves: kevHits, displayName: String(row.displayName ?? '') });
    }
  }

  evidence.push(ev('resourcegraph.defender_assessments_vdr', {
    total_assessments: total,
    unhealthy_assessments: unhealthy.length,
    kev_affected: unhealthyKevCount,
    kev_catalog_size: kev.size,
    sample: kevSample,
  }));

  // Pass criteria:
  //   - Defender assessments must exist (the feed is producing data).
  //   - Zero unhealthy assessments tagged with CISA KEV CVEs (no exploited
  //     vulnerabilities sitting un-remediated).
  // If the feed is empty entirely, that's a fail — VDR has no detection signal.
  const passed = total >= 1 && unhealthyKevCount === 0;

  findings.push(finding({
    rule: 'azure.afr.vdr.mdvm_kev_responsive',
    passed,
    severity: 'high',
    current: {
      summary: total === 0
        ? 'No Defender for Cloud assessments — vulnerability-detection feed isn\'t producing data (Defender plans likely not on Standard, or Security Reader is missing).'
        : unhealthyKevCount > 0
          ? `${unhealthyKevCount} unhealthy assessment(s) reference CISA KEV CVE(s) — exploited vulnerabilities un-remediated.`
          : `${total} Defender assessment(s) observed; ${unhealthy.length} unhealthy but zero match CISA KEV (no actively-exploited CVEs un-remediated).`,
      observations: {
        total_assessments: total,
        unhealthy_assessments: unhealthy.length,
        kev_affected: unhealthyKevCount,
        kev_catalog_size: kev.size,
      },
    },
    target: { summary: 'Defender for Cloud is producing assessments AND zero unhealthy findings reference a CISA KEV CVE. The cloud-side VDR feed is live and the KEV-priority queue is empty.', rationale: 'NIST RA-5, RA-5(2), SI-2, SI-3, SI-5, IR-4, CA-7. FedRAMP VDR requires both detection (continuous scan) and prioritized response (KEV catalog as the SLA trigger).' },
    gap: { description: unhealthyKevCount > 0 ? 'KEV-listed CVEs are un-remediated — VDR SLA must trigger immediate response.' : 'No vulnerability-detection feed visible — Defender plans likely not on Standard or RBAC is incomplete.', affected_resources: kevSample.slice(0, 50).map((s) => ({ type: 'azure_defender_assessment', identifier: s.id, attributes: { kev_cves: s.cves, name: s.displayName } })) },
    remediation: {
      summary: 'Enable Defender for Servers (Standard) + Defender for Containers (Standard) on every in-scope sub. Triage any KEV-listed CVE within the documented VDR SLA.',
      options: [
        { approach: 'az CLI per subscription.', mechanism: 'cli', steps: ['az security pricing create -n VirtualMachines --tier Standard', 'az security pricing create -n Containers --tier Standard', 'For each KEV-affected resource, open a remediation ticket per VDR SLA'] },
      ],
    },
    nist_controls: ['ra-5', 'ra-5.2', 'si-2', 'si-3', 'si-5', 'ir-4', 'ca-7'],
    cross_ksi_dependencies: [
      { ksi_id: 'KSI-SCR-MON', relationship: 'shares-remediation', note: 'SCR-MON proves the MDVM feed is configured at the plan level; AFR-VDR consumes the resulting assessments + applies KEV priority.' },
    ],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}
