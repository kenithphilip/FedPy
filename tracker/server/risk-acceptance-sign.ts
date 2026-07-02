/**
 * LOOP-B.B3 — Risk-acceptance signing (Ed25519 over RFC-8785-style canonical JSON).
 *
 * Why this exists:
 *   A risk-acceptance decision (NIST CA-5 / RA-7 / FedRAMP Deviation Request) is
 *   only trustworthy if it is non-repudiable. Every acceptance record — and every
 *   Authorizing-Official approval — is signed with the tracker's resident Ed25519
 *   key. The signature over the canonical-JSON payload IS the audit record: anyone
 *   with the public key (returned alongside GET /api/risk-acceptances) can verify
 *   that the justification / expiration / approver were not altered after signing.
 *
 * Key material:
 *   The tracker had no signing subsystem before B.B3, so this module introduces
 *   one. The resident keypair lives in the `signing_keys` table (PEM-encoded). A
 *   production deployment should front this with a KMS/HSM (tracked as B.B3-EXT-1
 *   in docs/loops/LOOP-B-RISKS.md); the local-tracker design keeps the private key
 *   in the DB the same way password hashes + hashed session tokens already live
 *   there. Key rotation is additive (insert a new row, set active=1) — historical
 *   public keys stay resolvable by key_id so old signatures keep verifying.
 *
 * Canonicalisation:
 *   `canonicalize()` is byte-identical to cloud-evidence's core/sign.ts so the
 *   cloud-evidence reader (core/risk-acceptance-reader.ts) verifies these
 *   signatures without a shared library — the two repos are independent workspaces.
 *   Do NOT "improve" one without the other; the wire contract depends on them
 *   producing the same bytes for the same payload.
 */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from 'node:crypto';
import { db } from './db.ts';

/**
 * Canonical JSON: sorted keys, no whitespace, UTF-8. Stable across runs and
 * byte-identical to cloud-evidence/core/sign.ts:canonicalize(). The payloads we
 * sign are flat (strings, one integer, an array of strings), for which this
 * subset agrees exactly with RFC 8785.
 */
export function canonicalize(obj: unknown): string {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalize).join(',') + ']';
  const keys = Object.keys(obj as Record<string, unknown>).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize((obj as Record<string, unknown>)[k])).join(',') + '}';
}

/** Stable signer key id: SHA-256 of the SPKI PEM, first 16 hex chars. */
export function publicKeyFingerprint(publicKeyPem: string): string {
  return createHash('sha256').update(publicKeyPem).digest('hex').slice(0, 16);
}

export interface ResidentKey {
  keyId: string;
  privateKey: KeyObject;
  publicKeyPem: string;
}

/**
 * Return the active resident signing key, generating + persisting one on first
 * use. No in-process cache: better-sqlite3 is synchronous and single-threaded, so
 * repeated reads are cheap, and skipping the cache keeps tests that swap DB_PATH
 * honest (no stale key material leaks across databases).
 */
export function getSigningKey(): ResidentKey {
  const row = db().prepare(
    `SELECT key_id, private_key_pem, public_key_pem FROM signing_keys WHERE active = 1 ORDER BY created_at DESC, key_id LIMIT 1`,
  ).get() as { key_id: string; private_key_pem: string; public_key_pem: string } | undefined;
  if (row) {
    return { keyId: row.key_id, privateKey: createPrivateKey(row.private_key_pem), publicKeyPem: row.public_key_pem };
  }
  const kp = generateKeyPairSync('ed25519');
  const privatePem = kp.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  const publicKeyPem = kp.publicKey.export({ type: 'spki', format: 'pem' }) as string;
  const keyId = publicKeyFingerprint(publicKeyPem);
  db().prepare(
    `INSERT INTO signing_keys (key_id, private_key_pem, public_key_pem, active) VALUES (?, ?, ?, 1)`,
  ).run(keyId, privatePem, publicKeyPem);
  return { keyId, privateKey: kp.privateKey, publicKeyPem };
}

/** PEM of the active public key (returned to the cloud-evidence reader). */
export function getPublicKeyPem(): string {
  return getSigningKey().publicKeyPem;
}

/** All public keys ever used, newest first — lets a verifier resolve by key_id after rotation. */
export function listPublicKeys(): Array<{ key_id: string; public_key_pem: string; active: boolean; created_at: string }> {
  const rows = db().prepare(
    `SELECT key_id, public_key_pem, active, created_at FROM signing_keys ORDER BY created_at DESC, key_id`,
  ).all() as Array<{ key_id: string; public_key_pem: string; active: number; created_at: string }>;
  return rows.map((r) => ({ key_id: r.key_id, public_key_pem: r.public_key_pem, active: r.active === 1, created_at: r.created_at }));
}

/** Sign the canonical form of `payload`; returns base64 signature + the key id used. */
export function signPayload(payload: unknown): { signature: string; signing_key_id: string } {
  const { privateKey, keyId } = getSigningKey();
  const sig = cryptoSign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey);
  return { signature: sig.toString('base64'), signing_key_id: keyId };
}

/**
 * Verify a base64 signature over the canonical form of `payload`. When
 * `publicKeyPem` is omitted the active resident public key is used.
 */
export function verifyPayload(payload: unknown, signatureBase64: string, publicKeyPem?: string): boolean {
  try {
    const pem = publicKeyPem ?? getSigningKey().publicKeyPem;
    return cryptoVerify(null, Buffer.from(canonicalize(payload), 'utf8'), createPublicKey(pem), Buffer.from(signatureBase64, 'base64'));
  } catch {
    return false;
  }
}

// ─── Payload shapes (the exact objects that get signed) ───────────────────────
//
// acceptancePayload() MUST stay byte-for-byte compatible with the cloud-evidence
// reader's acceptanceSignedPayload() (cloud-evidence/core/risk-acceptance-reader.ts).
// compensating_control_uuids is sorted so signing + verification are order-stable.

export interface AcceptancePayloadInput {
  finding_uuid: string;
  accepted_by_user_id: number;
  accepted_at: string;
  expiration_date: string;
  business_justification: string;
  acceptance_type: string;
  compensating_control_uuids: string[];
}

export function acceptancePayload(a: AcceptancePayloadInput): Record<string, unknown> {
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

export function approvalPayload(uuid: string, approvedByUserId: number, approvedAt: string): Record<string, unknown> {
  return { acceptance_uuid: uuid, approved_by_user_id: approvedByUserId, approved_at: approvedAt };
}
