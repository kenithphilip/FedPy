/**
 * LOOP-B.B5 — Organisational-risk reader (cloud-evidence side).
 *
 * The tracker (tracker/server) owns the operator-entered `organisational_risks`
 * table (Tier 1/2 risks per NIST SP 800-39 §2.3 that have no finding source:
 * third-party, supply-chain, environmental, contractual, operational, …). This
 * module is the read-only bridge the risk-register aggregator uses:
 *
 *   pullOrganisationalRisks() — HTTP GET the tracker's organisational risks, then
 *     write out/.organisational-risks.json (a provenance-stamped, signed snapshot).
 *   loadCachedOrganisationalRisks() — read the snapshot with no network (air-gapped).
 *
 * Unlike B.B3/B.B4 acceptances + compensating controls, organisational-risk rows
 * are not individually Ed25519-signed (their audit trail is the tracker's
 * created_at/updated_at/closed_* columns); the SNAPSHOT file is signed by
 * core/sign.ts so its integrity rides the run manifest.
 *
 * REO: never fabricates a risk. Tracker unreachable AND no cached snapshot ⇒ the
 * list is empty and the aggregator emits only finding + acceptance entries, with
 * the absence noted in the register's provenance (observable, never silent).
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { canonicalize, signDetached, type DetachedSignature } from './sign.ts';
import type { RiskBand, RiskTreatment } from './risk-register.ts';
import { log } from './log.ts';

export const ORGANISATIONAL_RISKS_SNAPSHOT = '.organisational-risks.json';

export type OrganisationalRiskCategory =
  | 'third-party' | 'supply-chain' | 'environmental' | 'contractual'
  | 'operational' | 'organisational' | 'other';

export interface PulledOrganisationalRisk {
  uuid: string;
  title: string;
  description: string;
  category: OrganisationalRiskCategory;
  likelihood: RiskBand;
  impact: RiskBand;
  inherent_risk: RiskBand;
  residual_risk: RiskBand;
  treatment: RiskTreatment;
  /** Owner label (role or display name) resolved by the tracker. */
  owner: string | null;
  review_date: string;
  nist_control_ids: string[] | null;
  compensating_control_uuids: string[] | null;
  status: 'open' | 'closed';
  closed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface OrganisationalRiskSnapshot {
  schema_version: '1.0.0';
  fetched_at: string;
  tracker_url: string;
  items: PulledOrganisationalRisk[];
  provenance: { emitter: string; emittedAt: string; sourceCalls: string[]; signingKeyId: string };
  signature?: DetachedSignature;
}

export class OrganisationalRiskFetchError extends Error {
  constructor(public readonly status: number, public readonly body: string) {
    super(`Organisational-risk fetch failed: HTTP ${status} — ${body.slice(0, 200)}`);
    this.name = 'OrganisationalRiskFetchError';
  }
}

interface HttpResponseLike {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
}
type FetchLike = (url: string, init?: { headers?: Record<string, string> }) => Promise<HttpResponseLike>;

export interface PullOptions {
  /** Injectable fetch (tests mock the wire layer per CLAUDE.md Rule 2.4). */
  fetchImpl?: FetchLike;
  /** Injectable clock for deterministic snapshots. */
  now?: () => Date;
}

/**
 * GET the tracker's organisational risks and write the signed
 * out/.organisational-risks.json snapshot. Returns the items.
 */
export async function pullOrganisationalRisks(
  trackerUrl: string,
  apiToken: string,
  outDir: string,
  opts: PullOptions = {},
): Promise<PulledOrganisationalRisk[]> {
  const fetchImpl = opts.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
  if (!fetchImpl) throw new Error('pullOrganisationalRisks: no fetch implementation available');
  const base = trackerUrl.replace(/\/+$/, '');
  const url = `${base}/api/organisational-risks`;
  const res = await fetchImpl(url, { headers: { Authorization: `Bearer ${apiToken}` } });
  if (!res.ok) throw new OrganisationalRiskFetchError(res.status, await safeText(res));
  const data = (await res.json()) as { items?: PulledOrganisationalRisk[] };
  if (!data || !Array.isArray(data.items)) {
    throw new Error('pullOrganisationalRisks: malformed tracker response (missing items[]).');
  }
  writeSnapshot(outDir, base, data.items, opts.now);
  log.info({ event: 'organisational-risk.pulled', count: data.items.length, tracker: base }, 'organisational-risk snapshot written');
  return data.items;
}

async function safeText(res: HttpResponseLike): Promise<string> {
  try { return await res.text(); } catch { return ''; }
}

function writeSnapshot(outDir: string, trackerUrl: string, items: PulledOrganisationalRisk[], now?: () => Date): void {
  const emittedAt = (now ? now() : new Date()).toISOString();
  const snapshot: OrganisationalRiskSnapshot = {
    schema_version: '1.0.0',
    fetched_at: emittedAt,
    tracker_url: trackerUrl,
    items,
    provenance: {
      emitter: 'core/organisational-risk-reader.ts',
      emittedAt,
      sourceCalls: [`GET ${trackerUrl}/api/organisational-risks`],
      signingKeyId: '',
    },
  };
  const canonical = canonicalize({ ...snapshot, signature: undefined });
  const sig = signDetached(Buffer.from(canonical, 'utf8'), outDir);
  snapshot.provenance.signingKeyId = sig.keyId;
  snapshot.signature = sig;
  writeFileSync(resolve(outDir, ORGANISATIONAL_RISKS_SNAPSHOT), JSON.stringify(snapshot, null, 2));
}

/** Read the cached snapshot (no network). Empty list + log line when absent. */
export function loadCachedOrganisationalRisks(outDir: string): PulledOrganisationalRisk[] {
  const p = resolve(outDir, ORGANISATIONAL_RISKS_SNAPSHOT);
  if (!existsSync(p)) {
    log.info({ event: 'organisational-risk:missing-snapshot', path: p }, 'no organisational-risk snapshot; register omits organisational entries');
    return [];
  }
  try {
    const doc = JSON.parse(readFileSync(p, 'utf8')) as OrganisationalRiskSnapshot;
    return Array.isArray(doc.items) ? doc.items : [];
  } catch (e) {
    log.warn({ event: 'organisational-risk:unreadable-snapshot', err: String(e) }, 'organisational-risk snapshot unreadable; ignoring');
    return [];
  }
}
