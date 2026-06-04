/**
 * Tests for core/sign.ts — sign + verify + tamper detection.
 *
 * Uses a tmp dir + ephemeral keypair (no env var set, so the module
 * generates one and persists it).
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { signRun, verifyRun, canonicalize, SIGNED_MANIFEST_FILE, SIGNATURE_FILE } from '../../core/sign.ts';

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(resolve(tmpdir(), 'cev-sign-'));
  // Ensure no signing key env is set so we exercise the ephemeral-key path.
  delete process.env.EVIDENCE_SIGNING_KEY_PATH;
  delete process.env.EVIDENCE_SIGNING_PUBLIC_KEY_PATH;
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

function writeEvidence(name: string, body: object): void {
  writeFileSync(resolve(tmp, name), JSON.stringify(body, null, 2));
}

describe('canonicalize', () => {
  it('produces a stable serialization regardless of key insertion order', () => {
    const a = canonicalize({ b: 1, a: { d: 2, c: [3, { f: 5, e: 4 }] } });
    const b = canonicalize({ a: { c: [3, { e: 4, f: 5 }], d: 2 }, b: 1 });
    expect(a).toBe(b);
  });

  it('preserves array order', () => {
    expect(canonicalize([3, 1, 2])).toBe('[3,1,2]');
  });
});

describe('signRun + verifyRun', () => {
  it('signs all .json/.xml/.pem files in the directory and verifies clean', () => {
    writeEvidence('KSI-IAM-MFA.json', { ksi_id: 'KSI-IAM-MFA', passed: true });
    writeEvidence('KSI-IAM-AAM.json', { ksi_id: 'KSI-IAM-AAM', passed: false });

    const r = signRun({ outDir: tmp, runId: 'run-1', frmrVersion: '2025-06.r1' });
    // 2 evidence files + 2 ephemeral key files (signing-key.pem + signing-pub.pem)
    // = 4 total. The ephemeral pem files are part of the signed set so a
    // future verifier can detect substitution of the key material itself
    // (defense-in-depth — paired with OSC-3's broader signing scope).
    expect(r.files_signed).toBe(4);
    expect(r.ephemeral_key).toBe(true);
    expect(existsSync(resolve(tmp, SIGNED_MANIFEST_FILE))).toBe(true);
    expect(existsSync(resolve(tmp, SIGNATURE_FILE))).toBe(true);

    const v = verifyRun(tmp);
    expect(v.valid, v.errors.join('; ')).toBe(true);
    expect(v.signature_valid).toBe(true);
    expect(v.file_results).toHaveLength(4);
    expect(v.file_results.every((f) => f.matched)).toBe(true);
    expect(v.extra_files).toHaveLength(0);
  });

  it('detects a file that was tampered after signing', () => {
    writeEvidence('KSI-IAM-MFA.json', { ksi_id: 'KSI-IAM-MFA', passed: false });
    signRun({ outDir: tmp, runId: 'run-1', frmrVersion: '2025-06.r1' });

    // tamper: flip the passed flag
    writeEvidence('KSI-IAM-MFA.json', { ksi_id: 'KSI-IAM-MFA', passed: true });

    const v = verifyRun(tmp);
    expect(v.valid).toBe(false);
    expect(v.signature_valid).toBe(true); // signature is over the manifest, not the file
    const f = v.file_results.find((x) => x.name === 'KSI-IAM-MFA.json')!;
    expect(f.matched).toBe(false);
    expect(v.errors.some((e) => /hash mismatch/i.test(e))).toBe(true);
  });

  it('detects a new file added after signing (unsigned files)', () => {
    writeEvidence('KSI-IAM-MFA.json', { ksi_id: 'KSI-IAM-MFA', passed: true });
    signRun({ outDir: tmp, runId: 'run-1', frmrVersion: '2025-06.r1' });

    writeEvidence('KSI-EVIL-INJECT.json', { ksi_id: 'KSI-EVIL', passed: true });

    const v = verifyRun(tmp);
    expect(v.valid).toBe(false);
    expect(v.extra_files).toContain('KSI-EVIL-INJECT.json');
  });

  it('detects a file that was deleted after signing (missing files)', () => {
    writeEvidence('KSI-IAM-MFA.json', { ksi_id: 'KSI-IAM-MFA', passed: true });
    writeEvidence('KSI-IAM-AAM.json', { ksi_id: 'KSI-IAM-AAM', passed: true });
    signRun({ outDir: tmp, runId: 'run-1', frmrVersion: '2025-06.r1' });

    rmSync(resolve(tmp, 'KSI-IAM-AAM.json'));

    const v = verifyRun(tmp);
    expect(v.valid).toBe(false);
    expect(v.file_results.find((f) => f.name === 'KSI-IAM-AAM.json')?.missing).toBe(true);
  });

  it('detects a tampered manifest (signature invalid)', () => {
    writeEvidence('KSI-IAM-MFA.json', { ksi_id: 'KSI-IAM-MFA', passed: true });
    signRun({ outDir: tmp, runId: 'run-1', frmrVersion: '2025-06.r1' });

    // tamper: change manifest content (e.g. swap a hash) without re-signing
    const manifestPath = resolve(tmp, SIGNED_MANIFEST_FILE);
    const m = JSON.parse(readFileSync(manifestPath, 'utf8'));
    m.files[0].sha256 = '0'.repeat(64);
    writeFileSync(manifestPath, JSON.stringify(m, null, 2));

    const v = verifyRun(tmp);
    expect(v.signature_valid).toBe(false);
    expect(v.valid).toBe(false);
  });

  it('detects a mismatched expected public key', () => {
    writeEvidence('KSI-IAM-MFA.json', { ksi_id: 'KSI-IAM-MFA', passed: true });
    signRun({ outDir: tmp, runId: 'run-1', frmrVersion: '2025-06.r1' });

    // Write a different "expected" public key
    const otherTmp = mkdtempSync(resolve(tmpdir(), 'cev-sign-other-'));
    try {
      // Run signRun in another dir to get a different keypair
      writeFileSync(resolve(otherTmp, 'KSI-X.json'), '{}');
      signRun({ outDir: otherTmp, runId: 'run-2', frmrVersion: '2025-06.r1' });
      const otherPub = resolve(otherTmp, 'signing-pub.pem');

      const v = verifyRun(tmp, otherPub);
      expect(v.valid).toBe(false);
      expect(v.errors.some((e) => /public key/i.test(e))).toBe(true);
    } finally {
      rmSync(otherTmp, { recursive: true, force: true });
    }
  });
});
