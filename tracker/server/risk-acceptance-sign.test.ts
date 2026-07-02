/**
 * Tests for server/risk-acceptance-sign.ts — canonicalisation + Ed25519 signing.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';

let tmpDir: string;

beforeAll(() => {
  tmpDir = mkdtempSync(resolve(tmpdir(), 'tracker-rasign-'));
  process.env.DB_PATH = resolve(tmpDir, 'sign-test.db');
});
afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

describe('risk-acceptance-sign', () => {
  it('canonicalises payload deterministically across key order', async () => {
    const { canonicalize } = await import('./risk-acceptance-sign.ts');
    const a = canonicalize({ b: 1, a: 'x', c: ['z', 'y'] });
    const b = canonicalize({ c: ['z', 'y'], a: 'x', b: 1 });
    expect(a).toBe(b);
    expect(a).toBe('{"a":"x","b":1,"c":["z","y"]}');
  });

  it('signature verifies against the resident public key', async () => {
    const { signPayload, verifyPayload, acceptancePayload, getPublicKeyPem } = await import('./risk-acceptance-sign.ts');
    const payload = acceptancePayload({
      finding_uuid: 'f-1', accepted_by_user_id: 7, accepted_at: '2026-07-02T00:00:00.000Z',
      expiration_date: '2026-10-02T00:00:00.000Z', business_justification: 'x'.repeat(100),
      acceptance_type: 'risk-adjustment', compensating_control_uuids: ['cc-2', 'cc-1'],
    });
    const { signature, signing_key_id } = signPayload(payload);
    expect(signature.length).toBeGreaterThan(0);
    expect(signing_key_id.length).toBe(16);
    expect(verifyPayload(payload, signature, getPublicKeyPem())).toBe(true);
    // Uses the active resident key when no PEM is passed.
    expect(verifyPayload(payload, signature)).toBe(true);
  });

  it('detects a tampered payload (verify returns false)', async () => {
    const { signPayload, verifyPayload, acceptancePayload } = await import('./risk-acceptance-sign.ts');
    const base = {
      finding_uuid: 'f-9', accepted_by_user_id: 3, accepted_at: '2026-07-02T00:00:00.000Z',
      expiration_date: '2026-10-02T00:00:00.000Z', business_justification: 'y'.repeat(120),
      acceptance_type: 'deviation-request' as const, compensating_control_uuids: ['cc-1'],
    };
    const { signature } = signPayload(acceptancePayload(base));
    const tampered = acceptancePayload({ ...base, business_justification: 'z'.repeat(120) });
    expect(verifyPayload(tampered, signature)).toBe(false);
  });

  it('compensating_control_uuids order does not change the signed bytes', async () => {
    const { canonicalize, acceptancePayload } = await import('./risk-acceptance-sign.ts');
    const p1 = acceptancePayload({
      finding_uuid: 'f', accepted_by_user_id: 1, accepted_at: 't', expiration_date: 'e',
      business_justification: 'j', acceptance_type: 'false-positive', compensating_control_uuids: ['b', 'a', 'c'],
    });
    const p2 = acceptancePayload({
      finding_uuid: 'f', accepted_by_user_id: 1, accepted_at: 't', expiration_date: 'e',
      business_justification: 'j', acceptance_type: 'false-positive', compensating_control_uuids: ['c', 'b', 'a'],
    });
    expect(canonicalize(p1)).toBe(canonicalize(p2));
  });
});
