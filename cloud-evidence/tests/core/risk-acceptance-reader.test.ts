/**
 * Tests for core/risk-acceptance-reader.ts — the LOOP-B.B3 cloud-evidence bridge
 * that pulls + verifies + snapshots signed risk acceptances from the tracker.
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
  pullActiveAcceptances,
  loadCachedAcceptances,
  activeAcceptanceFor,
  verifyAcceptanceSignature,
  acceptanceSignedPayload,
  RiskAcceptanceSignatureError,
  RiskAcceptanceFetchError,
  RISK_ACCEPTANCES_SNAPSHOT,
  type PulledAcceptance,
} from '../../core/risk-acceptance-reader.ts';

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-ra-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) { try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ } }
});

// ─── Signed-fixture helpers ────────────────────────────────────────────────────
function keypair(): { priv: KeyObject; pubPem: string } {
  const kp = generateKeyPairSync('ed25519');
  return { priv: kp.privateKey, pubPem: kp.publicKey.export({ type: 'spki', format: 'pem' }) as string };
}

function makeAcceptance(priv: KeyObject, over: Partial<PulledAcceptance> = {}): PulledAcceptance {
  const base: PulledAcceptance = {
    uuid: over.uuid ?? 'acc-1',
    finding_uuid: over.finding_uuid ?? 'finding-1',
    poam_item_uuid: over.poam_item_uuid ?? 'poam-1',
    ksi_id: over.ksi_id ?? 'KSI-IAM-MFA',
    rule: over.rule ?? 'aws.iam.root_mfa_enabled',
    provider: over.provider ?? 'aws',
    accepted_by_user_id: over.accepted_by_user_id ?? 1,
    accepted_at: over.accepted_at ?? '2026-07-02T00:00:00.000Z',
    expiration_date: over.expiration_date ?? '2026-12-01T00:00:00.000Z',
    business_justification: over.business_justification ?? 'j'.repeat(120),
    acceptance_type: over.acceptance_type ?? 'risk-adjustment',
    status: over.status ?? 'approved',
    approved_by_user_id: over.approved_by_user_id ?? 2,
    approved_at: over.approved_at ?? '2026-07-02T01:00:00.000Z',
    signature: '',
    signing_key_id: over.signing_key_id ?? 'k-test',
    approval_signature: over.approval_signature ?? null,
    approval_signing_key_id: over.approval_signing_key_id ?? null,
    compensating_control_uuids: over.compensating_control_uuids ?? [],
  };
  const canonical = canonicalize(acceptanceSignedPayload(base));
  base.signature = cryptoSign(null, Buffer.from(canonical, 'utf8'), priv).toString('base64');
  return { ...base, ...('signature' in over ? { signature: over.signature! } : {}) };
}

function fakeFetch(body: unknown, ok = true, status = 200) {
  return async () => ({
    ok, status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  });
}

// ─── Tests ─────────────────────────────────────────────────────────────────────
describe('verifyAcceptanceSignature', () => {
  it('returns true for a correctly-signed record and false when tampered', () => {
    const { priv, pubPem } = keypair();
    const acc = makeAcceptance(priv);
    expect(verifyAcceptanceSignature(acc, pubPem)).toBe(true);
    expect(verifyAcceptanceSignature({ ...acc, business_justification: 'tampered' }, pubPem)).toBe(false);
  });
});

describe('pullActiveAcceptances', () => {
  it('writes .risk-acceptances.json with verified signatures', async () => {
    const dir = tmp();
    const { priv, pubPem } = keypair();
    const items = [makeAcceptance(priv, { uuid: 'a-1' }), makeAcceptance(priv, { uuid: 'a-2' })];
    const out = await pullActiveAcceptances('http://tracker.example/', 'tok', dir, {
      fetchImpl: fakeFetch({ items, public_key: pubPem }) as any,
    });
    expect(out.length).toBe(2);
    const p = join(dir, RISK_ACCEPTANCES_SNAPSHOT);
    expect(existsSync(p)).toBe(true);
    const snap = JSON.parse(readFileSync(p, 'utf8'));
    expect(snap.items.length).toBe(2);
    expect(snap.public_key).toBe(pubPem);
    expect(snap.provenance.emitter).toBe('core/risk-acceptance-reader.ts');
    expect(snap.provenance.signingKeyId.length).toBeGreaterThan(0);
    expect(snap.signature.algorithm).toBe('ed25519');
  });

  it('refuses to write the snapshot when any record signature is invalid', async () => {
    const dir = tmp();
    const { priv, pubPem } = keypair();
    const good = makeAcceptance(priv, { uuid: 'good' });
    const bad = makeAcceptance(priv, { uuid: 'bad', signature: 'AAAA' }); // wrong signature
    await expect(pullActiveAcceptances('http://tracker.example', 'tok', dir, {
      fetchImpl: fakeFetch({ items: [good, bad], public_key: pubPem }) as any,
    })).rejects.toBeInstanceOf(RiskAcceptanceSignatureError);
    expect(existsSync(join(dir, RISK_ACCEPTANCES_SNAPSHOT))).toBe(false);
  });

  it('throws RiskAcceptanceFetchError on a non-2xx response', async () => {
    const dir = tmp();
    await expect(pullActiveAcceptances('http://tracker.example', 'tok', dir, {
      fetchImpl: fakeFetch({ error: 'unauthorized' }, false, 401) as any,
    })).rejects.toBeInstanceOf(RiskAcceptanceFetchError);
  });
});

describe('loadCachedAcceptances', () => {
  it('reads a previously-written snapshot and returns [] when absent', async () => {
    const dir = tmp();
    expect(loadCachedAcceptances(dir)).toEqual([]);
    const { priv, pubPem } = keypair();
    await pullActiveAcceptances('http://tracker.example', 'tok', dir, {
      fetchImpl: fakeFetch({ items: [makeAcceptance(priv, { uuid: 'cached' })], public_key: pubPem }) as any,
    });
    const cached = loadCachedAcceptances(dir);
    expect(cached.length).toBe(1);
    expect(cached[0]!.uuid).toBe('cached');
  });
});

describe('activeAcceptanceFor', () => {
  const { priv } = keypair();
  const now = new Date('2026-07-15T00:00:00.000Z');

  it('matches by (ksi_id, rule, provider) tuple', () => {
    const list = [makeAcceptance(priv)];
    const hit = activeAcceptanceFor('KSI-IAM-MFA', 'aws.iam.root_mfa_enabled', 'aws', list, now);
    expect(hit?.uuid).toBe('acc-1');
    expect(activeAcceptanceFor('KSI-IAM-MFA', 'other-rule', 'aws', list, now)).toBeNull();
    expect(activeAcceptanceFor('KSI-IAM-MFA', 'aws.iam.root_mfa_enabled', 'gcp', list, now)).toBeNull();
  });

  it('filters out records whose status is not approved', () => {
    const list = [makeAcceptance(priv, { status: 'pending' }), makeAcceptance(priv, { status: 'revoked' })];
    expect(activeAcceptanceFor('KSI-IAM-MFA', 'aws.iam.root_mfa_enabled', 'aws', list, now)).toBeNull();
  });

  it('filters out records whose expiration_date is at/before now', () => {
    const list = [makeAcceptance(priv, { expiration_date: '2026-07-01T00:00:00.000Z' })];
    expect(activeAcceptanceFor('KSI-IAM-MFA', 'aws.iam.root_mfa_enabled', 'aws', list, now)).toBeNull();
  });
});
