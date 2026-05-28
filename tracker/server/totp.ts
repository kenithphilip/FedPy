/**
 * TOTP (RFC 6238) — Two-factor authentication via authenticator app.
 *
 * Implementation:
 *   - Secret: 160-bit (20-byte) random, base32-encoded (RFC 3548 alphabet)
 *   - Algorithm: HMAC-SHA1 (the de-facto standard supported by every authenticator app)
 *   - Time step: 30 seconds
 *   - Code length: 6 digits
 *   - Verification window: ±1 step (so a code is valid for 30–60s of clock skew)
 *
 * Why hand-roll instead of importing `otplib`?
 *   - Zero new runtime dependencies (Node has crypto built in).
 *   - Auditability: the entire RFC 6238 algorithm fits in ~50 lines.
 *   - We control behavior (replay protection, backup codes) without depending
 *     on a library's defaults.
 *
 * Backup codes:
 *   - 8 single-use 10-character codes generated at enrollment.
 *   - Stored as SHA-256 hashes in users.totp_backup_codes (comma-separated).
 *   - When a code is consumed, its hash is removed from the list.
 *   - Re-enrollment regenerates all codes.
 */
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { db } from './db.ts';

const STEP_SEC = 30;
const DIGITS = 6;
const WINDOW = 1; // ±1 step for clock skew

// ---- Base32 (RFC 4648, no padding when encoding the secret) ----

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 0x1f];
  return out;
}

export function base32Decode(s: string): Buffer {
  const clean = s.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error(`invalid base32 character: ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

// ---- TOTP core (RFC 6238) ----

function hotp(secret: Buffer, counter: number, digits = DIGITS): string {
  const buf = Buffer.alloc(8);
  // counter is 64-bit big-endian
  buf.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac('sha1', secret).update(buf).digest();
  // HMAC-SHA1 always produces 20 bytes; offset is in [0,15] so the four reads
  // are always defined. Non-null assertions silence TS noUncheckedIndexedAccess.
  const offset = mac[mac.length - 1]! & 0x0f;
  const bin = ((mac[offset]! & 0x7f) << 24) | ((mac[offset + 1]! & 0xff) << 16) |
              ((mac[offset + 2]! & 0xff) << 8)  | (mac[offset + 3]! & 0xff);
  const otp = bin % 10 ** digits;
  return otp.toString().padStart(digits, '0');
}

export function generateTotp(secretB32: string, atSec: number = Math.floor(Date.now() / 1000)): string {
  const counter = Math.floor(atSec / STEP_SEC);
  return hotp(base32Decode(secretB32), counter);
}

/**
 * Verify a TOTP code, accepting ±WINDOW step skew.
 * Returns true if the code matches the secret at any time in the window.
 */
export function verifyTotp(secretB32: string, code: string, atSec: number = Math.floor(Date.now() / 1000)): boolean {
  if (!/^\d{6}$/.test(code)) return false;
  const secret = base32Decode(secretB32);
  const counter = Math.floor(atSec / STEP_SEC);
  for (let delta = -WINDOW; delta <= WINDOW; delta++) {
    const candidate = hotp(secret, counter + delta);
    if (candidate.length === code.length && timingSafeEqual(Buffer.from(candidate), Buffer.from(code))) {
      return true;
    }
  }
  return false;
}

// ---- Secret generation + URI ----

export function generateSecret(): string {
  return base32Encode(randomBytes(20));
}

/**
 * Generate an otpauth:// URI for QR-code rendering in the SPA.
 * Format: otpauth://totp/<issuer>:<accountName>?secret=...&issuer=...&algorithm=SHA1&digits=6&period=30
 */
export function otpauthUri(secret: string, accountName: string, issuer = 'FedRAMP-20x-Tracker'): string {
  const label = encodeURIComponent(`${issuer}:${accountName}`);
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: String(DIGITS),
    period: String(STEP_SEC),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

// ---- Backup codes ----

const BACKUP_CODE_COUNT = 8;
const BACKUP_CODE_BYTES = 5; // 10 hex chars

export function generateBackupCodes(): string[] {
  const codes: string[] = [];
  for (let i = 0; i < BACKUP_CODE_COUNT; i++) {
    codes.push(randomBytes(BACKUP_CODE_BYTES).toString('hex'));
  }
  return codes;
}

function hashBackup(code: string): string {
  return createHash('sha256').update(code.toLowerCase().trim()).digest('hex');
}

export function hashBackupCodes(codes: string[]): string {
  return codes.map(hashBackup).join(',');
}

/**
 * Try to consume a backup code for `userId`. If the code matches one of the
 * registered hashes AND has not already been consumed, mark it consumed and
 * return true. Atomic — safe against concurrent /api/2fa/verify requests
 * (the read-modify-write here was a race per the post-audit fix).
 */
export function consumeBackupCode(userId: number, code: string): boolean {
  const target = hashBackup(code);
  return db().transaction(() => {
    // 1. Verify the hash is actually in the user's registered set.
    const row = db().prepare('SELECT totp_backup_codes FROM users WHERE id = ?').get(userId) as { totp_backup_codes?: string } | undefined;
    if (!row?.totp_backup_codes) return false;
    const stored = row.totp_backup_codes.split(',').filter(Boolean);
    if (!stored.includes(target)) return false;
    // 2. Attempt to mark consumed. UNIQUE constraint on (user_id, code_hash)
    //    guarantees only one INSERT succeeds across concurrent requests.
    const r = db().prepare(
      `INSERT OR IGNORE INTO totp_backup_codes_used (user_id, code_hash) VALUES (?, ?)`,
    ).run(userId, target);
    return r.changes > 0;
  })();
}

// ---- High-level helpers ----

export interface TotpEnrollment {
  /** The raw base32 secret to display once + embed in QR. */
  secret_b32: string;
  /** otpauth:// URI for QR rendering. */
  otpauth_uri: string;
  /** Plaintext backup codes — show ONCE then discard. */
  backup_codes: string[];
}

/**
 * Start TOTP enrollment for `userId`. Stores the secret + backup-code hashes
 * but leaves `totp_enrolled_at` null until the user verifies a first code.
 */
export function startEnrollment(userId: number, accountName: string): TotpEnrollment {
  const secret = generateSecret();
  const codes = generateBackupCodes();
  db().transaction(() => {
    db().prepare(`UPDATE users SET totp_secret_b32 = ?, totp_backup_codes = ?, totp_enrolled_at = NULL WHERE id = ?`)
      .run(secret, hashBackupCodes(codes), userId);
    // Discard any prior "used" records — re-enrolling issues a fresh batch.
    db().prepare(`DELETE FROM totp_backup_codes_used WHERE user_id = ?`).run(userId);
  })();
  return {
    secret_b32: secret,
    otpauth_uri: otpauthUri(secret, accountName),
    backup_codes: codes,
  };
}

/**
 * Complete enrollment: verify a code against the pending secret and, if valid,
 * stamp totp_enrolled_at. Returns true on success.
 */
export function completeEnrollment(userId: number, code: string): boolean {
  const row = db().prepare('SELECT totp_secret_b32 FROM users WHERE id = ?').get(userId) as { totp_secret_b32?: string } | undefined;
  if (!row?.totp_secret_b32) return false;
  if (!verifyTotp(row.totp_secret_b32, code)) return false;
  db().prepare(`UPDATE users SET totp_enrolled_at = datetime('now') WHERE id = ?`).run(userId);
  return true;
}

/** Disable 2FA for a user (admin op or self-service after re-auth). */
export function disable2fa(userId: number): void {
  db().transaction(() => {
    db().prepare(`UPDATE users SET totp_secret_b32 = NULL, totp_enrolled_at = NULL, totp_backup_codes = NULL, require_2fa = 0 WHERE id = ?`).run(userId);
    db().prepare(`DELETE FROM totp_backup_codes_used WHERE user_id = ?`).run(userId);
  })();
}

/** Read the user's 2FA status. */
export interface TwoFaStatus {
  enrolled: boolean;
  required: boolean;
  backup_codes_remaining: number;
}

export function get2faStatus(userId: number): TwoFaStatus {
  const row = db().prepare(`SELECT totp_enrolled_at, totp_backup_codes, require_2fa FROM users WHERE id = ?`).get(userId) as any;
  const totalCodes = row?.totp_backup_codes ? row.totp_backup_codes.split(',').filter(Boolean).length : 0;
  const usedCodes = totalCodes > 0
    ? (db().prepare(`SELECT COUNT(*) AS c FROM totp_backup_codes_used WHERE user_id = ?`).get(userId) as { c: number }).c
    : 0;
  return {
    enrolled: !!row?.totp_enrolled_at,
    required: row?.require_2fa === 1,
    backup_codes_remaining: Math.max(0, totalCodes - usedCodes),
  };
}

/**
 * Verify either a TOTP code or a backup code for `userId`. Returns true if
 * either succeeded. Backup codes are single-use (removed on success).
 */
export function verifyCodeOrBackup(userId: number, code: string): { ok: boolean; via?: 'totp' | 'backup' } {
  const row = db().prepare(`SELECT totp_secret_b32, totp_enrolled_at FROM users WHERE id = ?`).get(userId) as any;
  if (!row?.totp_secret_b32 || !row.totp_enrolled_at) return { ok: false };
  if (verifyTotp(row.totp_secret_b32, code)) return { ok: true, via: 'totp' };
  if (consumeBackupCode(userId, code)) return { ok: true, via: 'backup' };
  return { ok: false };
}
