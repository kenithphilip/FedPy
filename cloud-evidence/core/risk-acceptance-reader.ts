/**
 * LOOP-B.B3 — Risk-acceptance reader (cloud-evidence side).
 *
 * The tracker (tracker/server) owns the signed risk-acceptance workflow. This
 * module is the read-only bridge the OSCAL POA&M emitter uses to learn which
 * findings have an approved, unexpired risk acceptance:
 *
 *   pullActiveAcceptances() — HTTP GET the tracker's approved acceptances,
 *     VERIFY every record's Ed25519 signature against the tracker's published
 *     public key, then write out/.risk-acceptances.json (signed snapshot).
 *   loadCachedAcceptances() — read the snapshot with no network (air-gapped runs).
 *   activeAcceptanceFor()   — per-finding lookup by (ksi_id, rule, provider),
 *     enforcing status='approved' AND expiration_date>now() on the read side too
 *     (defence-in-depth against a tracker whose enforcer hasn't run yet).
 *
 * REO: never fabricates an acceptance. If the tracker is unreachable AND no
 * cached snapshot exists, zero acceptance props are emitted and every risk stays
 * `open` — observable via the risk-acceptance:missing-snapshot log line, never
 * silent. Signature verification failures HARD-FAIL the pull (no snapshot is
 * written for a record whose signature does not verify).
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { canonicalize, signDetached, publicKeyFingerprint, type DetachedSignature } from './sign.ts';
import { log } from './log.ts';

export const RISK_ACCEPTANCES_SNAPSHOT = '.risk-acceptances.json';

export type AcceptanceType = 'deviation-request' | 'risk-adjustment' | 'false-positive' | 'operational-requirement';
export type AcceptanceStatus = 'pending' | 'approved' | 'expired' | 'revoked';

export interface PulledAcceptance {
  uuid: string;
  finding_uuid: string;
  poam_item_uuid: string;
  ksi_id: string;
  rule: string;
  provider: string;
  accepted_by_user_id: number;
  accepted_at: string;
  expiration_date: string;
  business_justification: string;
  acceptance_type: AcceptanceType;
  status: AcceptanceStatus;
  approved_by_user_id: number | null;
  approved_at: string | null;
  signature: string;
  signing_key_id: string;
  approval_signature: string | null;
  approval_signing_key_id: string | null;
  compensating_control_uuids: string[];
}

export interface AcceptanceSnapshot {
  schema_version: '1.0.0';
  fetched_at: string;
  tracker_url: string;
  public_key: string;
  public_key_fingerprint: string;
  items: PulledAcceptance[];
  provenance: { emitter: string; emittedAt: string; sourceCalls: string[]; signingKeyId: string };
  signature?: DetachedSignature;
}

export class RiskAcceptanceFetchError extends Error {
  constructor(public readonly status: number, public readonly body: string) {
    super(`Risk-acceptance fetch failed: HTTP ${status} — ${body.slice(0, 200)}`);
    this.name = 'RiskAcceptanceFetchError';
  }
}

export class RiskAcceptanceSignatureError extends Error {
  constructor(public readonly uuid: string) {
    super(`Risk-acceptance ${uuid} signature did not verify against the tracker public key; refusing to write snapshot.`);
    this.name = 'RiskAcceptanceSignatureError';
  }
}

/**
 * The exact object the tracker signs (tracker/server/risk-acceptance-sign.ts
 * acceptancePayload()). MUST stay byte-compatible — canonicalize() here and in
 * the tracker produce identical bytes for this shape.
 */
export function acceptanceSignedPayload(a: PulledAcceptance): Record<string, unknown> {
  return {
    finding_uuid: a.finding_uuid,
    accepted_by_user_id: a.accepted_by_user_id,
    accepted_at: a.accepted_at,
    expiration_date: a.expiration_date,
    business_justification: a.business_justification,
    acceptance_type: a.acceptance_type,
    compensating_control_uuids: [...a.compensating_control_uuids].sort(),
  };
}

/** Verify one record's Ed25519 signature against the tracker's public key PEM. */
export function verifyAcceptanceSignature(a: PulledAcceptance, publicKeyPem: string): boolean {
  try {
    const canonical = canonicalize(acceptanceSignedPayload(a));
    const pub = createPublicKey(publicKeyPem);
    return cryptoVerify(null, Buffer.from(canonical, 'utf8'), pub, Buffer.from(a.signature, 'base64'));
  } catch {
    return false;
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
 * GET the tracker's approved acceptances, verify each signature, and write the
 * signed out/.risk-acceptances.json snapshot. Returns the verified items.
 */
export async function pullActiveAcceptances(
  trackerUrl: string,
  apiToken: string,
  outDir: string,
  opts: PullOptions = {},
): Promise<PulledAcceptance[]> {
  const fetchImpl = opts.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
  if (!fetchImpl) throw new Error('pullActiveAcceptances: no fetch implementation available');
  const base = trackerUrl.replace(/\/+$/, '');
  const url = `${base}/api/risk-acceptances?status=approved`;
  const res = await fetchImpl(url, { headers: { Authorization: `Bearer ${apiToken}` } });
  if (!res.ok) throw new RiskAcceptanceFetchError(res.status, await safeText(res));
  const data = (await res.json()) as { items?: PulledAcceptance[]; public_key?: string };
  if (!data || !Array.isArray(data.items) || typeof data.public_key !== 'string') {
    throw new Error('pullActiveAcceptances: malformed tracker response (missing items[] or public_key).');
  }
  for (const acc of data.items) {
    if (!verifyAcceptanceSignature(acc, data.public_key)) throw new RiskAcceptanceSignatureError(acc.uuid);
  }
  writeSnapshot(outDir, base, data.items, data.public_key, opts.now);
  log.info({ event: 'risk-acceptance.pulled', count: data.items.length, tracker: base }, 'risk-acceptance snapshot written');
  return data.items;
}

async function safeText(res: HttpResponseLike): Promise<string> {
  try { return await res.text(); } catch { return ''; }
}

function writeSnapshot(outDir: string, trackerUrl: string, items: PulledAcceptance[], publicKey: string, now?: () => Date): void {
  const emittedAt = (now ? now() : new Date()).toISOString();
  const snapshot: AcceptanceSnapshot = {
    schema_version: '1.0.0',
    fetched_at: emittedAt,
    tracker_url: trackerUrl,
    public_key: publicKey,
    public_key_fingerprint: publicKeyFingerprint(publicKey),
    items,
    provenance: {
      emitter: 'core/risk-acceptance-reader.ts',
      emittedAt,
      sourceCalls: [`GET ${trackerUrl}/api/risk-acceptances?status=approved`],
      signingKeyId: '',
    },
  };
  const canonical = canonicalize({ ...snapshot, signature: undefined });
  const sig = signDetached(Buffer.from(canonical, 'utf8'), outDir);
  snapshot.provenance.signingKeyId = sig.keyId;
  snapshot.signature = sig;
  writeFileSync(resolve(outDir, RISK_ACCEPTANCES_SNAPSHOT), JSON.stringify(snapshot, null, 2));
}

/** Read the cached snapshot (no network). Empty list + log line when absent. */
export function loadCachedAcceptances(outDir: string): PulledAcceptance[] {
  const p = resolve(outDir, RISK_ACCEPTANCES_SNAPSHOT);
  if (!existsSync(p)) {
    log.info({ event: 'risk-acceptance:missing-snapshot', path: p }, 'no risk-acceptance snapshot; every risk stays open');
    return [];
  }
  try {
    const doc = JSON.parse(readFileSync(p, 'utf8')) as AcceptanceSnapshot;
    return Array.isArray(doc.items) ? doc.items : [];
  } catch (e) {
    log.warn({ event: 'risk-acceptance:unreadable-snapshot', err: String(e) }, 'risk-acceptance snapshot unreadable; ignoring');
    return [];
  }
}

/**
 * Find the active (approved, unexpired) acceptance for a finding tuple, or null.
 * Enforces status + expiration on the read side so an expired-but-not-yet-swept
 * tracker row never propagates to OSCAL deviation-approved.
 */
export function activeAcceptanceFor(
  ksiId: string,
  rule: string,
  provider: string,
  list: PulledAcceptance[],
  now: Date = new Date(),
): PulledAcceptance | null {
  const nowMs = now.getTime();
  for (const a of list) {
    if (a.status !== 'approved') continue;
    if (a.ksi_id !== ksiId || a.rule !== rule || a.provider !== provider) continue;
    const expMs = Date.parse(a.expiration_date);
    if (!Number.isFinite(expMs) || expMs <= nowMs) continue;
    return a;
  }
  return null;
}
