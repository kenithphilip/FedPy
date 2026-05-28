/**
 * GCP VDR (Vulnerability Detection & Response) live-scan collector.
 *
 * Pulls vulnerability occurrences (READ-ONLY) from Container/Artifact Analysis,
 * normalizes them into the VDR ledger, joins the CISA KEV catalog, and reports
 * SLA breaches via the VDR-TFR-* timeframe tables. Reuses the shared
 * buildVdrFindings + ledger machinery from the AWS module.
 *
 * STRICTLY READ-ONLY: occurrences.list only. Wrapped with diagnoseGcpError.
 * Degrades gracefully when Container Analysis is not enabled.
 */
import * as gcpAuth from '../../core/auth/gcp.ts';
import type { ProviderBlock, RawEvidence } from '../../core/envelope.ts';
import type { CollectorContext } from '../../core/ksi-map.ts';
import { diagnoseGcpError } from '../../core/error-diagnostics.ts';
import { loadKevCatalog } from '../../core/kev-feed.ts';
import { buildLedger, type LedgerEntry } from '../../core/vdr-ledger.ts';
import { summarizeVdr } from '../../core/vdr-report.ts';
import { normalizeSeverity, impactLevelFromEnv, buildVdrFindings } from '../aws/vdr-scan.ts';

function ev(source: string, data: unknown): RawEvidence { return { source, captured_at: new Date().toISOString(), data: data === undefined ? null : data }; }

const CVE_RE = /CVE-\d{4}-\d{3,}/i;

function extractCve(occ: any): string | undefined {
  const note = String(occ?.noteName ?? '');
  const m1 = note.match(CVE_RE);
  if (m1) return m1[0].toUpperCase();
  const short = String(occ?.vulnerability?.shortDescription ?? '');
  const m2 = short.match(CVE_RE);
  if (m2) return m2[0].toUpperCase();
  return undefined;
}

/** Pure converter: Container Analysis occurrences → ledger entries. Exported for tests. */
export function toGcpLedgerEntries(occurrences: any[]): LedgerEntry[] {
  const out: LedgerEntry[] = [];
  for (const occ of occurrences ?? []) {
    if (!occ || typeof occ !== 'object') continue;
    const vuln = occ.vulnerability ?? {};
    out.push({
      cve: extractCve(occ),
      severity: normalizeSeverity(vuln.effectiveSeverity ?? vuln.severity),
      first_seen: typeof occ.createTime === 'string' ? new Date(occ.createTime).toISOString() : new Date().toISOString(),
      source: 'artifact-analysis',
      resource: typeof occ.resourceUri === 'string' ? occ.resourceUri : undefined,
      kev: false, // buildLedger enriches from the KEV catalog
      state: vuln.fixAvailable === false ? 'detected' : 'detected',
    });
  }
  return out;
}

export async function collectVdrScan(c: CollectorContext): Promise<ProviderBlock> {
  if (!c.gcp?.project_id) throw new Error('GCP collector invoked without project_id');
  const project = c.gcp.project_id;
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];
  const tier = impactLevelFromEnv();

  let detectionEnabled = false;
  const raw: any[] = [];
  try {
    const ca = await gcpAuth.googleClient<any>('containeranalysis', 'v1');
    let pageToken: string | undefined;
    let iter = 0;
    do {
      const r = await ca.projects.occurrences.list({
        parent: `projects/${project}`,
        filter: 'kind="VULNERABILITY"',
        pageSize: 500,
        pageToken,
      });
      detectionEnabled = true; // the API responded → capability reachable
      for (const occ of r.data.occurrences ?? []) raw.push(occ);
      const next = r.data.nextPageToken;
      pageToken = next && next !== pageToken ? next : undefined;
    } while (pageToken && ++iter < 1000);
    evidence.push(ev('containeranalysis.occurrences.list', { count: raw.length }));
  } catch (e) {
    warnings.push(diagnoseGcpError(e, 'containeranalysis.projects.occurrences.list', 'containeranalysis.occurrences.list (roles/containeranalysis.occurrences.viewer)'));
  }

  const kev = await loadKevCatalog();
  if (kev.warnings.length) warnings.push(...kev.warnings.map((w) => `KEV: ${w}`));
  const ledger = buildLedger(toGcpLedgerEntries(raw), kev, { tier });
  const summary = summarizeVdr(ledger);
  evidence.push(ev('vdr.summary', summary));

  const findings = buildVdrFindings(detectionEnabled, summary, kev.source, 'MUST', project, 'gcp');
  return { provider: 'gcp', project_id: project, evidence, findings, warnings };
}
