/**
 * LOOP-B.B4 — Compensating-control reader (cloud-evidence side).
 *
 * The tracker (tracker/server) owns the signed compensating-controls registry.
 * This module is the read-only bridge the OSCAL POA&M emitter uses to resolve a
 * B.B3 acceptance's compensating_control_uuids to structured, AO-signed records:
 *
 *   pullCompensatingControls() — HTTP GET the tracker's active controls, VERIFY
 *     every record's Ed25519 signature against the tracker's published public key,
 *     then write out/.compensating-controls.json (signed snapshot).
 *   loadCachedCompensatingControls() — read the snapshot with no network (air-gapped).
 *   getCompensatingControl() — per-uuid lookup, enforcing status='active' AND
 *     (expiration_date IS NULL OR > now) on the read side too (defence-in-depth
 *     against a tracker whose data is stale) so a draft/expired/retired control
 *     never propagates its content into risk.remediations[].
 *
 * REO: never fabricates a control. If the tracker is unreachable AND no cached
 * snapshot exists, the list is empty and every cited uuid surfaces as
 * REQUIRES-OPERATOR-INPUT on the POA&M — observable, never silent. Signature
 * verification failures HARD-FAIL the pull (no snapshot written for a bad record).
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { canonicalize, signDetached, publicKeyFingerprint, type DetachedSignature } from './sign.ts';
import { log } from './log.ts';

export const COMPENSATING_CONTROLS_SNAPSHOT = '.compensating-controls.json';

export type ControlStatus = 'draft' | 'active' | 'retired';

export interface PulledCompensatingControl {
  uuid: string;
  title: string;
  description: string;
  nist_control_ids: string[];
  implemented_by_user_id: number;
  implemented_at: string;
  signed_off_by_user_id: number | null;
  signed_off_at: string | null;
  expiration_date: string | null;
  evidence_url: string | null;
  evidence_sha256: string | null;
  status: ControlStatus;
  signature: string;
  signing_key_id: string;
}

export interface CompensatingControlSnapshot {
  schema_version: '1.0.0';
  fetched_at: string;
  tracker_url: string;
  public_key: string;
  public_key_fingerprint: string;
  items: PulledCompensatingControl[];
  provenance: { emitter: string; emittedAt: string; sourceCalls: string[]; signingKeyId: string };
  signature?: DetachedSignature;
}

export class CompensatingControlFetchError extends Error {
  constructor(public readonly status: number, public readonly body: string) {
    super(`Compensating-control fetch failed: HTTP ${status} — ${body.slice(0, 200)}`);
    this.name = 'CompensatingControlFetchError';
  }
}

export class CompensatingControlSignatureError extends Error {
  constructor(public readonly uuid: string) {
    super(`Compensating-control ${uuid} signature did not verify against the tracker public key; refusing to write snapshot.`);
    this.name = 'CompensatingControlSignatureError';
  }
}

/**
 * The exact object the tracker signs (tracker/server/compensating-control-sign.ts
 * compensatingControlPayload()). MUST stay byte-compatible — canonicalize() here
 * and in the tracker produce identical bytes for this shape. nist_control_ids is
 * sorted so order does not affect the signature.
 */
export function compensatingControlSignedPayload(c: PulledCompensatingControl): Record<string, unknown> {
  return {
    title: c.title,
    description: c.description,
    nist_control_ids: [...c.nist_control_ids].sort(),
    implemented_by_user_id: c.implemented_by_user_id,
    implemented_at: c.implemented_at,
    evidence_url: c.evidence_url,
    evidence_sha256: c.evidence_sha256,
  };
}

/** Verify one record's Ed25519 signature against the tracker's public key PEM. */
export function verifyCompensatingControlSignature(c: PulledCompensatingControl, publicKeyPem: string): boolean {
  try {
    const canonical = canonicalize(compensatingControlSignedPayload(c));
    const pub = createPublicKey(publicKeyPem);
    return cryptoVerify(null, Buffer.from(canonical, 'utf8'), pub, Buffer.from(c.signature, 'base64'));
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
 * GET the tracker's active compensating controls, verify each signature, and write
 * the signed out/.compensating-controls.json snapshot. Returns the verified items.
 */
export async function pullCompensatingControls(
  trackerUrl: string,
  apiToken: string,
  outDir: string,
  opts: PullOptions = {},
): Promise<PulledCompensatingControl[]> {
  const fetchImpl = opts.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
  if (!fetchImpl) throw new Error('pullCompensatingControls: no fetch implementation available');
  const base = trackerUrl.replace(/\/+$/, '');
  const url = `${base}/api/compensating-controls?status=active`;
  const res = await fetchImpl(url, { headers: { Authorization: `Bearer ${apiToken}` } });
  if (!res.ok) throw new CompensatingControlFetchError(res.status, await safeText(res));
  const data = (await res.json()) as { items?: PulledCompensatingControl[]; public_key?: string };
  if (!data || !Array.isArray(data.items) || typeof data.public_key !== 'string') {
    throw new Error('pullCompensatingControls: malformed tracker response (missing items[] or public_key).');
  }
  for (const cc of data.items) {
    if (!verifyCompensatingControlSignature(cc, data.public_key)) throw new CompensatingControlSignatureError(cc.uuid);
  }
  writeSnapshot(outDir, base, data.items, data.public_key, opts.now);
  log.info({ event: 'compensating-control.pulled', count: data.items.length, tracker: base }, 'compensating-control snapshot written');
  return data.items;
}

async function safeText(res: HttpResponseLike): Promise<string> {
  try { return await res.text(); } catch { return ''; }
}

function writeSnapshot(outDir: string, trackerUrl: string, items: PulledCompensatingControl[], publicKey: string, now?: () => Date): void {
  const emittedAt = (now ? now() : new Date()).toISOString();
  const snapshot: CompensatingControlSnapshot = {
    schema_version: '1.0.0',
    fetched_at: emittedAt,
    tracker_url: trackerUrl,
    public_key: publicKey,
    public_key_fingerprint: publicKeyFingerprint(publicKey),
    items,
    provenance: {
      emitter: 'core/compensating-control-reader.ts',
      emittedAt,
      sourceCalls: [`GET ${trackerUrl}/api/compensating-controls?status=active`],
      signingKeyId: '',
    },
  };
  const canonical = canonicalize({ ...snapshot, signature: undefined });
  const sig = signDetached(Buffer.from(canonical, 'utf8'), outDir);
  snapshot.provenance.signingKeyId = sig.keyId;
  snapshot.signature = sig;
  writeFileSync(resolve(outDir, COMPENSATING_CONTROLS_SNAPSHOT), JSON.stringify(snapshot, null, 2));
}

/** Read the cached snapshot (no network). Empty list + log line when absent. */
export function loadCachedCompensatingControls(outDir: string): PulledCompensatingControl[] {
  const p = resolve(outDir, COMPENSATING_CONTROLS_SNAPSHOT);
  if (!existsSync(p)) {
    log.info({ event: 'compensating-control:missing-snapshot', path: p }, 'no compensating-control snapshot; cited uuids surface as REQUIRES-OPERATOR-INPUT');
    return [];
  }
  try {
    const doc = JSON.parse(readFileSync(p, 'utf8')) as CompensatingControlSnapshot;
    return Array.isArray(doc.items) ? doc.items : [];
  } catch (e) {
    log.warn({ event: 'compensating-control:unreadable-snapshot', err: String(e) }, 'compensating-control snapshot unreadable; ignoring');
    return [];
  }
}

/**
 * Resolve a compensating control by uuid, enforcing status='active' AND unexpired
 * on the read side (defence-in-depth). Returns null for an unknown, draft, retired,
 * or expired uuid so the POA&M emitter surfaces it as REQUIRES-OPERATOR-INPUT
 * rather than propagating stale mitigation content.
 */
export function getCompensatingControl(
  uuid: string,
  list: PulledCompensatingControl[],
  now: Date = new Date(),
): PulledCompensatingControl | null {
  const nowMs = now.getTime();
  for (const cc of list) {
    if (cc.uuid !== uuid) continue;
    if (cc.status !== 'active') return null;
    if (cc.expiration_date !== null) {
      const expMs = Date.parse(cc.expiration_date);
      if (!Number.isFinite(expMs) || expMs <= nowMs) return null;
    }
    return cc;
  }
  return null;
}
