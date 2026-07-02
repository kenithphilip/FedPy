/**
 * Tests for core/compensating-control-reader.ts — the LOOP-B.B4 cloud-evidence
 * bridge that pulls + verifies + snapshots signed compensating controls from the
 * tracker.
 *
 * Signatures are REAL Ed25519 (per CLAUDE.md Rule 2.4 only the HTTP wire layer is
 * mocked): each fixture record is signed with a test keypair over the exact
 * canonical payload the tracker signs, then verified through the production path.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from 'node:crypto';
import { canonicalize } from '../../core/sign.ts';
import {
  pullCompensatingControls,
  loadCachedCompensatingControls,
  getCompensatingControl,
  verifyCompensatingControlSignature,
  compensatingControlSignedPayload,
  CompensatingControlSignatureError,
  CompensatingControlFetchError,
  COMPENSATING_CONTROLS_SNAPSHOT,
  type PulledCompensatingControl,
} from '../../core/compensating-control-reader.ts';

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-cc-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) { try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ } }
});

function keypair(): { priv: KeyObject; pubPem: string } {
  const kp = generateKeyPairSync('ed25519');
  return { priv: kp.privateKey, pubPem: kp.publicKey.export({ type: 'spki', format: 'pem' }) as string };
}

function makeControl(priv: KeyObject, over: Partial<PulledCompensatingControl> = {}): PulledCompensatingControl {
  const base: PulledCompensatingControl = {
    uuid: over.uuid ?? 'cc-1',
    title: over.title ?? 'MFA break-glass vault',
    description: over.description ?? 'x'.repeat(220),
    nist_control_ids: over.nist_control_ids ?? ['AC-2', 'SC-7'],
    implemented_by_user_id: over.implemented_by_user_id ?? 1,
    implemented_at: over.implemented_at ?? '2026-07-02T00:00:00.000Z',
    signed_off_by_user_id: over.signed_off_by_user_id ?? 2,
    signed_off_at: over.signed_off_at ?? '2026-07-02T01:00:00.000Z',
    expiration_date: over.expiration_date ?? null,
    evidence_url: over.evidence_url ?? null,
    evidence_sha256: over.evidence_sha256 ?? null,
    status: over.status ?? 'active',
    signature: '',
    signing_key_id: over.signing_key_id ?? 'k-test',
  };
  const canonical = canonicalize(compensatingControlSignedPayload(base));
  base.signature = cryptoSign(null, Buffer.from(canonical, 'utf8'), priv).toString('base64');
  return { ...base, ...('signature' in over ? { signature: over.signature! } : {}) };
}

function fakeFetch(body: unknown, ok = true, status = 200) {
  return async () => ({ ok, status, json: async () => body, text: async () => JSON.stringify(body) });
}

describe('verifyCompensatingControlSignature', () => {
  it('returns true for a correctly-signed record and false when tampered', () => {
    const { priv, pubPem } = keypair();
    const cc = makeControl(priv);
    expect(verifyCompensatingControlSignature(cc, pubPem)).toBe(true);
    expect(verifyCompensatingControlSignature({ ...cc, description: 'tampered' }, pubPem)).toBe(false);
  });
});

describe('pullCompensatingControls', () => {
  it('writes .compensating-controls.json with verified signatures + provenance', async () => {
    const dir = tmp();
    const { priv, pubPem } = keypair();
    const items = [makeControl(priv, { uuid: 'c-1' }), makeControl(priv, { uuid: 'c-2' })];
    const out = await pullCompensatingControls('http://tracker.example/', 'tok', dir, {
      fetchImpl: fakeFetch({ items, public_key: pubPem }) as any,
    });
    expect(out.length).toBe(2);
    const p = join(dir, COMPENSATING_CONTROLS_SNAPSHOT);
    expect(existsSync(p)).toBe(true);
    const snap = JSON.parse(readFileSync(p, 'utf8'));
    expect(snap.items.length).toBe(2);
    expect(snap.public_key).toBe(pubPem);
    expect(snap.provenance.emitter).toBe('core/compensating-control-reader.ts');
    expect(snap.provenance.signingKeyId.length).toBeGreaterThan(0);
    expect(snap.signature.algorithm).toBe('ed25519');
  });

  it('refuses to write the snapshot when any record signature is invalid', async () => {
    const dir = tmp();
    const { priv, pubPem } = keypair();
    const good = makeControl(priv, { uuid: 'good' });
    const bad = makeControl(priv, { uuid: 'bad', signature: 'AAAA' });
    await expect(pullCompensatingControls('http://tracker.example', 'tok', dir, {
      fetchImpl: fakeFetch({ items: [good, bad], public_key: pubPem }) as any,
    })).rejects.toBeInstanceOf(CompensatingControlSignatureError);
    expect(existsSync(join(dir, COMPENSATING_CONTROLS_SNAPSHOT))).toBe(false);
  });

  it('throws CompensatingControlFetchError on a non-2xx response', async () => {
    const dir = tmp();
    await expect(pullCompensatingControls('http://tracker.example', 'tok', dir, {
      fetchImpl: fakeFetch({ error: 'unauthorized' }, false, 401) as any,
    })).rejects.toBeInstanceOf(CompensatingControlFetchError);
  });
});

describe('loadCachedCompensatingControls', () => {
  it('reads a previously-written snapshot and returns [] when absent', async () => {
    const dir = tmp();
    expect(loadCachedCompensatingControls(dir)).toEqual([]);
    const { priv, pubPem } = keypair();
    await pullCompensatingControls('http://tracker.example', 'tok', dir, {
      fetchImpl: fakeFetch({ items: [makeControl(priv, { uuid: 'cached' })], public_key: pubPem }) as any,
    });
    const cached = loadCachedCompensatingControls(dir);
    expect(cached.length).toBe(1);
    expect(cached[0]!.uuid).toBe('cached');
  });
});

describe('getCompensatingControl', () => {
  const { priv } = keypair();
  const now = new Date('2026-07-15T00:00:00.000Z');

  it('returns null for an unknown uuid', () => {
    expect(getCompensatingControl('nope', [makeControl(priv)], now)).toBeNull();
  });

  it('returns the record for an active, unexpired uuid', () => {
    const cc = makeControl(priv, { uuid: 'live', expiration_date: '2026-12-01T00:00:00.000Z' });
    expect(getCompensatingControl('live', [cc], now)?.uuid).toBe('live');
  });

  it('returns null for a draft or retired control (status check)', () => {
    expect(getCompensatingControl('d', [makeControl(priv, { uuid: 'd', status: 'draft' })], now)).toBeNull();
    expect(getCompensatingControl('r', [makeControl(priv, { uuid: 'r', status: 'retired' })], now)).toBeNull();
  });

  it('returns null for an expired control (expiration check)', () => {
    const cc = makeControl(priv, { uuid: 'exp', expiration_date: '2026-07-01T00:00:00.000Z' });
    expect(getCompensatingControl('exp', [cc], now)).toBeNull();
  });
});
