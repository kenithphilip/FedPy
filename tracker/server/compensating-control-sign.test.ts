/**
 * Tests for server/compensating-control-sign.ts — LOOP-B.B4 payload canonicalisation
 * + Ed25519 signing/verification. Uses a temp DB so getSigningKey() persists a real
 * resident keypair (shared with B.B3); signatures are REAL Ed25519, never mocked.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import {
  canonicalize,
  compensatingControlPayload,
  activationPayload,
  signPayload,
  verifyPayload,
  getPublicKeyPem,
  type CompensatingControlPayloadInput,
} from './compensating-control-sign.ts';

let tmpDir: string;
beforeAll(() => {
  tmpDir = mkdtempSync(resolve(tmpdir(), 'tracker-ccsign-'));
  process.env.DB_PATH = resolve(tmpDir, 'cc-sign-test.db');
});
afterAll(() => { rmSync(tmpDir, { recursive: true, force: true }); });

function payload(over: Partial<CompensatingControlPayloadInput> = {}): CompensatingControlPayloadInput {
  return {
    title: 'MFA break-glass vault',
    description: 'x'.repeat(220),
    nist_control_ids: ['SC-7', 'AC-2', 'AC-2(3)'],
    implemented_by_user_id: 1,
    implemented_at: '2026-07-02T00:00:00.000Z',
    evidence_url: 'https://runbooks.example/bg',
    evidence_sha256: null,
    ...over,
  };
}

describe('compensatingControlPayload canonicalisation', () => {
  it('canonicalises deterministically and is order-stable across nist-id input order', () => {
    const a = compensatingControlPayload(payload({ nist_control_ids: ['SC-7', 'AC-2', 'AC-2(3)'] }));
    const b = compensatingControlPayload(payload({ nist_control_ids: ['AC-2(3)', 'AC-2', 'SC-7'] }));
    expect(canonicalize(a)).toBe(canonicalize(b));
    // Sorted, no whitespace, keys ascending.
    expect(canonicalize(a).startsWith('{"description":')).toBe(true);
    expect((a.nist_control_ids as string[])).toEqual(['AC-2', 'AC-2(3)', 'SC-7']);
  });
});

describe('signPayload / verifyPayload', () => {
  it('produces a signature that verifies and rejects a tampered payload', () => {
    const p = compensatingControlPayload(payload());
    const { signature } = signPayload(p);
    expect(verifyPayload(p, signature, getPublicKeyPem())).toBe(true);
    const tampered = compensatingControlPayload(payload({ description: 'y'.repeat(220) }));
    expect(verifyPayload(tampered, signature, getPublicKeyPem())).toBe(false);
  });

  it('signs the activation event and detects a swapped approver', () => {
    const { signature } = signPayload(activationPayload('cc-1', 2, '2026-07-02T01:00:00.000Z'));
    expect(verifyPayload(activationPayload('cc-1', 2, '2026-07-02T01:00:00.000Z'), signature, getPublicKeyPem())).toBe(true);
    expect(verifyPayload(activationPayload('cc-1', 9, '2026-07-02T01:00:00.000Z'), signature, getPublicKeyPem())).toBe(false);
  });
});
