/**
 * Tests for server/totp.ts — RFC 6238 TOTP + backup codes.
 *
 * Includes the RFC 6238 Appendix B test vectors so we know our HMAC math
 * matches the spec, plus tests for backup-code single-use semantics.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';

let tmpDir: string;

beforeAll(() => {
  tmpDir = mkdtempSync(resolve(tmpdir(), 'tracker-totp-'));
  process.env.DB_PATH = resolve(tmpDir, 'totp-test.db');
});

afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

describe('base32 encoding', () => {
  it('round-trips arbitrary buffers', async () => {
    const { base32Encode, base32Decode } = await import('./totp.ts');
    for (const input of [Buffer.from('hello'), Buffer.from([0]), Buffer.from('a-very-long-string-to-test-encoding')]) {
      const encoded = base32Encode(input);
      const decoded = base32Decode(encoded);
      expect(decoded.equals(input)).toBe(true);
    }
  });
});

describe('TOTP RFC 6238 test vector', () => {
  // The RFC 6238 Appendix B uses ASCII "12345678901234567890" as the secret.
  // For T = 1111111109 (epoch seconds), TOTP = "081804".
  it('produces the expected code for the canonical vector', async () => {
    const { generateTotp, base32Encode } = await import('./totp.ts');
    const secretB32 = base32Encode(Buffer.from('12345678901234567890'));
    // Compute at T = 1111111109 (which is mid-step at counter = 0x0023523ED)
    const code = generateTotp(secretB32, 1111111109);
    expect(code).toBe('081804');
  });
});

describe('TOTP verification window', () => {
  it('accepts the current step', async () => {
    const { generateSecret, generateTotp, verifyTotp } = await import('./totp.ts');
    const secret = generateSecret();
    const t = 1700000000;
    const code = generateTotp(secret, t);
    expect(verifyTotp(secret, code, t)).toBe(true);
  });

  it('accepts ±1 step skew', async () => {
    const { generateSecret, generateTotp, verifyTotp } = await import('./totp.ts');
    const secret = generateSecret();
    const t = 1700000000;
    const pastCode = generateTotp(secret, t - 30);  // previous window
    const futureCode = generateTotp(secret, t + 30); // next window
    expect(verifyTotp(secret, pastCode, t)).toBe(true);
    expect(verifyTotp(secret, futureCode, t)).toBe(true);
  });

  it('rejects codes outside the window', async () => {
    const { generateSecret, generateTotp, verifyTotp } = await import('./totp.ts');
    const secret = generateSecret();
    const t = 1700000000;
    const oldCode = generateTotp(secret, t - 120); // way outside
    expect(verifyTotp(secret, oldCode, t)).toBe(false);
  });

  it('rejects malformed codes', async () => {
    const { generateSecret, verifyTotp } = await import('./totp.ts');
    const secret = generateSecret();
    expect(verifyTotp(secret, '12345')).toBe(false);  // 5 digits
    expect(verifyTotp(secret, '1234567')).toBe(false); // 7 digits
    expect(verifyTotp(secret, 'abcdef')).toBe(false);  // not digits
  });
});

describe('otpauth URI', () => {
  it('produces a parseable otpauth:// URI', async () => {
    const { otpauthUri } = await import('./totp.ts');
    const uri = otpauthUri('JBSWY3DPEHPK3PXP', 'alice@example.com', 'AcmeCorp');
    expect(uri).toMatch(/^otpauth:\/\/totp\/AcmeCorp%3Aalice%40example\.com\?/);
    expect(uri).toContain('secret=JBSWY3DPEHPK3PXP');
    expect(uri).toContain('issuer=AcmeCorp');
    expect(uri).toContain('algorithm=SHA1');
    expect(uri).toContain('digits=6');
    expect(uri).toContain('period=30');
  });
});

describe('enrollment + verification end-to-end', () => {
  it('enrolls a user, requires verification, completes, and verifies codes', async () => {
    const { db } = await import('./db.ts');
    // Seed a user
    db().prepare(`INSERT OR IGNORE INTO users (id, email, name, password_hash, role) VALUES (?, ?, ?, ?, ?)`)
      .run(1, 'alice@example.com', 'Alice', 'placeholder', 'admin');

    const totp = await import('./totp.ts');
    const enr = totp.startEnrollment(1, 'alice@example.com');
    expect(enr.secret_b32).toMatch(/^[A-Z2-7]+$/);
    expect(enr.backup_codes.length).toBe(8);
    expect(enr.backup_codes.every((c) => /^[a-f0-9]{10}$/.test(c))).toBe(true);

    // Before completion: 2FA not yet enrolled
    expect(totp.get2faStatus(1).enrolled).toBe(false);

    const code = totp.generateTotp(enr.secret_b32);
    expect(totp.completeEnrollment(1, code)).toBe(true);
    expect(totp.get2faStatus(1).enrolled).toBe(true);

    // verifyCodeOrBackup accepts a fresh code
    const fresh = totp.generateTotp(enr.secret_b32);
    const r = totp.verifyCodeOrBackup(1, fresh);
    expect(r.ok).toBe(true);
    expect(r.via).toBe('totp');
  });

  it('backup codes are single-use', async () => {
    const { db } = await import('./db.ts');
    db().prepare(`INSERT OR IGNORE INTO users (id, email, name, password_hash, role) VALUES (?, ?, ?, ?, ?)`)
      .run(2, 'bob@example.com', 'Bob', 'placeholder', 'member');

    const totp = await import('./totp.ts');
    const enr = totp.startEnrollment(2, 'bob@example.com');
    totp.completeEnrollment(2, totp.generateTotp(enr.secret_b32));

    const code = enr.backup_codes[0]!;
    const r1 = totp.verifyCodeOrBackup(2, code);
    expect(r1.ok).toBe(true);
    expect(r1.via).toBe('backup');
    // Second use of same code fails
    const r2 = totp.verifyCodeOrBackup(2, code);
    expect(r2.ok).toBe(false);
    // Status reflects consumed count
    expect(totp.get2faStatus(2).backup_codes_remaining).toBe(7);
  });

  it('atomic backup-code consumption prevents the read-modify-write race', async () => {
    // Regression test for the 2026-05 audit. Pre-fix, two concurrent
    // verifyCodeOrBackup calls with the same code BOTH returned ok=true.
    // With the unique-constraint INSERT, only one wins.
    const { db } = await import('./db.ts');
    db().prepare(`INSERT OR IGNORE INTO users (id, email, name, password_hash, role) VALUES (?, ?, ?, ?, ?)`)
      .run(10, 'race@example.com', 'Race', 'placeholder', 'member');
    const totp = await import('./totp.ts');
    const enr = totp.startEnrollment(10, 'race@example.com');
    totp.completeEnrollment(10, totp.generateTotp(enr.secret_b32));

    const code = enr.backup_codes[0]!;
    // Better-sqlite3 is synchronous, so true parallelism isn't possible in
    // a single Node process — but we can simulate the read-then-write
    // pattern by issuing two consecutive verify calls and asserting that
    // exactly one succeeds. The unique constraint enforces this.
    const results = [
      totp.verifyCodeOrBackup(10, code),
      totp.verifyCodeOrBackup(10, code),
    ];
    const successes = results.filter((r) => r.ok).length;
    expect(successes).toBe(1);
  });

  it('re-enrolling clears prior used-backup-code records', async () => {
    const { db } = await import('./db.ts');
    db().prepare(`INSERT OR IGNORE INTO users (id, email, name, password_hash, role) VALUES (?, ?, ?, ?, ?)`)
      .run(11, 'reenroll@example.com', 'Re', 'placeholder', 'member');
    const totp = await import('./totp.ts');

    const enr1 = totp.startEnrollment(11, 'reenroll@example.com');
    totp.completeEnrollment(11, totp.generateTotp(enr1.secret_b32));
    totp.verifyCodeOrBackup(11, enr1.backup_codes[0]!);  // consume code #1
    expect(totp.get2faStatus(11).backup_codes_remaining).toBe(7);

    // Re-enroll → fresh batch
    const enr2 = totp.startEnrollment(11, 'reenroll@example.com');
    totp.completeEnrollment(11, totp.generateTotp(enr2.secret_b32));
    expect(totp.get2faStatus(11).backup_codes_remaining).toBe(8);
  });

  it('disable2fa clears all 2FA state', async () => {
    const { db } = await import('./db.ts');
    db().prepare(`INSERT OR IGNORE INTO users (id, email, name, password_hash, role) VALUES (?, ?, ?, ?, ?)`)
      .run(3, 'carol@example.com', 'Carol', 'placeholder', 'member');

    const totp = await import('./totp.ts');
    const enr = totp.startEnrollment(3, 'carol@example.com');
    totp.completeEnrollment(3, totp.generateTotp(enr.secret_b32));
    expect(totp.get2faStatus(3).enrolled).toBe(true);

    totp.disable2fa(3);
    const s = totp.get2faStatus(3);
    expect(s.enrolled).toBe(false);
    expect(s.required).toBe(false);
    expect(s.backup_codes_remaining).toBe(0);
  });
});
