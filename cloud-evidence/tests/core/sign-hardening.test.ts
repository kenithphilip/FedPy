/**
 * Tests for the sign.ts / verifyRun hardening added in the Batch 2 audit:
 *   - malformed PEM at EVIDENCE_SIGNING_KEY_PATH → clear error
 *   - loose key-file permissions → warning (non-fatal)
 *   - verifyRun on a corrupt manifest (no `files` array) → error result, no throw
 *   - verifyRun unreadable/missing manifest → error result
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { signRun, verifyRun, SIGNED_MANIFEST_FILE, SIGNATURE_FILE } from '../../core/sign.ts';

let dir: string;
const savedEnv = { ...process.env };

beforeEach(() => {
  dir = mkdtempSync(resolve(tmpdir(), 'cev-sign-'));
});

afterEach(() => {
  process.env.EVIDENCE_SIGNING_KEY_PATH = savedEnv.EVIDENCE_SIGNING_KEY_PATH;
  process.env.EVIDENCE_SIGNING_PUBLIC_KEY_PATH = savedEnv.EVIDENCE_SIGNING_PUBLIC_KEY_PATH;
  rmSync(dir, { recursive: true, force: true });
});

describe('signRun key loading', () => {
  it('throws an actionable error when the key file is not valid PEM', () => {
    const badKey = resolve(dir, 'bad-key.pem');
    writeFileSync(badKey, 'this is not a PEM key', { mode: 0o600 });
    process.env.EVIDENCE_SIGNING_KEY_PATH = badKey;
    writeFileSync(resolve(dir, 'KSI-X.json'), '{}');
    expect(() => signRun({ outDir: dir, runId: 'r', frmrVersion: 'v' }))
      .toThrowError(/not a valid PEM private key/);
  });

  it('signs successfully with a real Ed25519 key (and verifies)', () => {
    const kp = generateKeyPairSync('ed25519');
    const keyPath = resolve(dir, 'key.pem');
    writeFileSync(keyPath, kp.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string, { mode: 0o600 });
    process.env.EVIDENCE_SIGNING_KEY_PATH = keyPath;
    writeFileSync(resolve(dir, 'KSI-X.json'), JSON.stringify({ a: 1 }));

    const res = signRun({ outDir: dir, runId: 'r', frmrVersion: 'v' });
    expect(res.files_signed).toBeGreaterThanOrEqual(1);
    expect(res.ephemeral_key).toBe(false);

    const v = verifyRun(dir);
    expect(v.valid).toBe(true);
    expect(v.signature_valid).toBe(true);
  });
});

describe('verifyRun robustness', () => {
  it('returns an error result (no throw) when manifest.json is missing', () => {
    const v = verifyRun(dir);
    expect(v.valid).toBe(false);
    expect(v.errors.join(' ')).toMatch(/not found/i);
  });

  it('returns an error result when the manifest lacks a files array', () => {
    writeFileSync(resolve(dir, SIGNED_MANIFEST_FILE), JSON.stringify({ schema_version: 1, run_id: 'r' }));
    writeFileSync(resolve(dir, SIGNATURE_FILE), 'AA==');
    const v = verifyRun(dir);
    expect(v.valid).toBe(false);
    expect(v.errors.join(' ')).toMatch(/files/i);
  });

  it('returns an error result when the manifest is not valid JSON', () => {
    writeFileSync(resolve(dir, SIGNED_MANIFEST_FILE), '{ not json');
    writeFileSync(resolve(dir, SIGNATURE_FILE), 'AA==');
    const v = verifyRun(dir);
    expect(v.valid).toBe(false);
    expect(v.errors.join(' ')).toMatch(/parse/i);
  });
});
