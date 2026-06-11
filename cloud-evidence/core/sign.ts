/**
 * Evidence signing & verification (Ed25519).
 *
 * Why this exists:
 *   FedRAMP 20x evidence is intended for continuous audit. An assessor / 3PAO
 *   needs to trust that the JSON files they're reading are *exactly* what
 *   the collector produced — not edited post-hoc, not from a different run,
 *   not partial. Without integrity protection, anyone with write access to
 *   `out/` could silently flip a `passed: false` to `passed: true`.
 *
 * Design:
 *   1. After every successful run, the orchestrator calls `signRun()` which:
 *      a. Hashes every `*.json` file in the output directory (SHA-256).
 *      b. Builds a `manifest.json` of `{ files: [{name, sha256, bytes}], run_id,
 *         frmr_version, signed_at, signer_public_key }`.
 *      c. Signs the canonical-JSON serialization of the manifest with Ed25519.
 *      d. Writes `manifest.json` and `manifest.sig` (base64).
 *   2. A verifier can `verifyRun()` to re-hash each file, compare against the
 *      manifest, and verify the signature against the embedded public key
 *      (which a deployer would have also published independently — e.g.
 *      committed to git, posted at /trust/cloud-evidence-key.pem).
 *
 * Key material:
 *   - The PRIVATE key is read from `EVIDENCE_SIGNING_KEY_PATH` (PEM, PKCS8).
 *   - If that env var is not set, we generate an ephemeral keypair and write
 *     it next to the manifest as `signing-key.pem` + `signing-pub.pem` — only
 *     useful for local development; production should use a stable key
 *     managed by KMS / HSM and read from a path mounted at runtime.
 *   - Optionally, set `EVIDENCE_SIGNING_PUBLIC_KEY_PATH` to override which
 *     public key gets embedded in the manifest (useful when the signer
 *     reads the private key from KMS but you want a canonical published
 *     public key URI).
 */
import { createHash, generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify, createPrivateKey, createPublicKey, type KeyObject } from 'node:crypto';
import { readFileSync, writeFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { log } from './log.ts';

const MANIFEST_NAME = 'manifest.json';
const SIGNATURE_NAME = 'manifest.sig';

export interface ManifestFileEntry {
  name: string;
  sha256: string;
  bytes: number;
}

export interface SignedManifest {
  schema_version: 1;
  run_id: string;
  frmr_version: string;
  signed_at: string;
  /** PEM-encoded Ed25519 public key for verifier convenience. */
  signer_public_key: string;
  /** Sorted by name for deterministic canonicalization. */
  files: ManifestFileEntry[];
}

/** Canonical JSON: sorted keys, no whitespace, UTF-8. Stable across runs. */
export function canonicalize(obj: unknown): string {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalize).join(',') + ']';
  const keys = Object.keys(obj as Record<string, unknown>).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize((obj as any)[k])).join(',') + '}';
}

function sha256Hex(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

/**
 * Files covered by the run manifest. Originally JSON-only, but companion
 * artifacts (OSCAL XML, signing keys, run-summary) need integrity protection
 * too — otherwise a tampered XML payload could ship past 3PAO review even
 * though the manifest verified clean. Extensions we cover:
 *
 *   - `.json`   — every per-KSI evidence file + OSCAL JSON + reports
 *   - `.xml`    — OSCAL XML representations (OSC-3)
 *   - `.pem`    — embedded signing key + public key (so a future verifier
 *                 can detect substitution of the key material itself)
 *   - `.md`     — operator-facing Markdown reports (e.g. the monthly ConMon
 *                 analysis report + SCN notice draft) shipped in the upload
 *   - `.pdf`    — operator-facing PDF reports (e.g. the monthly ConMon
 *                 analysis report) shipped to the FedRAMP secure repository
 *
 * Manifest itself + signature blob are excluded (they can't sign themselves).
 */
const SIGNED_EXTENSIONS = ['.json', '.xml', '.pem', '.md', '.pdf'];

function listSignedFiles(dir: string): string[] {
  return readdirSync(dir)
    .filter((f) => SIGNED_EXTENSIONS.some((ext) => f.endsWith(ext)) && f !== MANIFEST_NAME)
    .filter((f) => {
      try { return statSync(resolve(dir, f)).isFile(); } catch { return false; }
    })
    .sort();
}

function loadOrGenerateKeyPair(outDir: string): { privateKey: KeyObject; publicKey: KeyObject; ephemeral: boolean } {
  const privPath = process.env.EVIDENCE_SIGNING_KEY_PATH;
  if (privPath) {
    if (!existsSync(privPath)) {
      throw new Error(`EVIDENCE_SIGNING_KEY_PATH=${privPath} does not exist`);
    }
    // Defense-in-depth: a signing key that is group/world-readable is a
    // credential-exposure risk. Warn loudly (don't hard-fail — the operator
    // may be running in a locked-down container where perms look broad).
    try {
      const st = statSync(privPath);
      const perms = st.mode & 0o077;
      if (perms !== 0) {
        log.warn({
          event: 'sign.key_permissions_loose',
          path: privPath,
          mode: '0' + (st.mode & 0o777).toString(8),
          note: 'Signing key is readable by group/other. Run `chmod 600` on it to limit exposure.',
        });
      }
    } catch { /* stat failure is non-fatal; the read below will surface real errors */ }

    let privatePem: string;
    try {
      privatePem = readFileSync(privPath, 'utf8');
    } catch (e: any) {
      if (e?.code === 'EACCES') {
        throw new Error(`Cannot read EVIDENCE_SIGNING_KEY_PATH=${privPath}: permission denied. Ensure the runner user can read the key file.`);
      }
      throw new Error(`Cannot read EVIDENCE_SIGNING_KEY_PATH=${privPath}: ${e?.message ?? String(e)}`);
    }
    let privateKey: KeyObject;
    try {
      privateKey = createPrivateKey(privatePem);
    } catch (e: any) {
      throw new Error(`EVIDENCE_SIGNING_KEY_PATH=${privPath} is not a valid PEM private key (expected PKCS8 Ed25519): ${e?.message ?? String(e)}`);
    }
    let publicKey: KeyObject;
    const pubPath = process.env.EVIDENCE_SIGNING_PUBLIC_KEY_PATH;
    if (pubPath && existsSync(pubPath)) {
      publicKey = createPublicKey(readFileSync(pubPath, 'utf8'));
    } else {
      publicKey = createPublicKey(privateKey);
    }
    return { privateKey, publicKey, ephemeral: false };
  }
  // Generate ephemeral keypair and persist to outDir so a verifier can use it.
  const kp = generateKeyPairSync('ed25519');
  writeFileSync(resolve(outDir, 'signing-key.pem'), kp.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  writeFileSync(resolve(outDir, 'signing-pub.pem'), kp.publicKey.export({ type: 'spki', format: 'pem' }));
  log.warn({
    event: 'sign.ephemeral_key_generated',
    out_dir: outDir,
    note: 'Set EVIDENCE_SIGNING_KEY_PATH to a stable Ed25519 key for production runs.',
  });
  return { privateKey: kp.privateKey, publicKey: kp.publicKey, ephemeral: true };
}

export interface SignRunOptions {
  outDir: string;
  runId: string;
  frmrVersion: string;
}

export interface SignRunResult {
  manifest_path: string;
  signature_path: string;
  files_signed: number;
  ephemeral_key: boolean;
}

/**
 * Hash every signed-eligible file in `outDir` (.json + .xml + .pem; see
 * SIGNED_EXTENSIONS), write `manifest.json` listing them, and write
 * `manifest.sig` (base64) over the canonical JSON.
 */
export function signRun(opts: SignRunOptions): SignRunResult {
  // Materialize the keypair FIRST so the ephemeral .pem files it writes are
  // present when we enumerate signed files below. Without this, the ephemeral
  // keys would be created after the file list snapshot and a later verifyRun
  // would flag them as "unsigned extras".
  const { privateKey, publicKey, ephemeral } = loadOrGenerateKeyPair(opts.outDir);
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;

  const files = listSignedFiles(opts.outDir);
  const entries: ManifestFileEntry[] = files.map((name) => {
    const buf = readFileSync(resolve(opts.outDir, name));
    return { name, sha256: sha256Hex(buf), bytes: buf.length };
  });

  const manifest: SignedManifest = {
    schema_version: 1,
    run_id: opts.runId,
    frmr_version: opts.frmrVersion,
    signed_at: new Date().toISOString(),
    signer_public_key: publicPem,
    files: entries,
  };

  const canonical = canonicalize(manifest);
  // For Ed25519, the "algorithm" arg to crypto.sign must be null.
  const sig = cryptoSign(null, Buffer.from(canonical, 'utf8'), privateKey);

  const manifestPath = resolve(opts.outDir, MANIFEST_NAME);
  const sigPath = resolve(opts.outDir, SIGNATURE_NAME);
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  writeFileSync(sigPath, sig.toString('base64'));

  log.info({
    event: 'sign.run_signed',
    files_signed: entries.length,
    manifest_path: manifestPath,
    signature_path: sigPath,
    ephemeral_key: ephemeral,
  });

  return {
    manifest_path: manifestPath,
    signature_path: sigPath,
    files_signed: entries.length,
    ephemeral_key: ephemeral,
  };
}

export interface VerifyResult {
  valid: boolean;
  /** Per-file: did the on-disk hash match the manifest? */
  file_results: Array<{ name: string; matched: boolean; expected_sha256: string; actual_sha256?: string; missing?: boolean }>;
  /** Did the signature verify against the manifest's embedded public key? */
  signature_valid: boolean;
  /** Files present on disk but absent from the manifest. */
  extra_files: string[];
  errors: string[];
}

/**
 * Verify an `out/` directory against its manifest.json + manifest.sig.
 *
 * If `expectedPublicKeyPath` is provided, also assert that the manifest's
 * embedded public key matches the one at that path (defense against a
 * substituted key).
 */
export function verifyRun(outDir: string, expectedPublicKeyPath?: string): VerifyResult {
  const manifestPath = resolve(outDir, MANIFEST_NAME);
  const sigPath = resolve(outDir, SIGNATURE_NAME);
  const errors: string[] = [];

  if (!existsSync(manifestPath)) {
    return { valid: false, file_results: [], signature_valid: false, extra_files: [], errors: [`${MANIFEST_NAME} not found in ${outDir}`] };
  }
  if (!existsSync(sigPath)) {
    return { valid: false, file_results: [], signature_valid: false, extra_files: [], errors: [`${SIGNATURE_NAME} not found in ${outDir}`] };
  }

  let manifestRaw: string;
  try {
    manifestRaw = readFileSync(manifestPath, 'utf8');
  } catch (e: any) {
    const hint = e?.code === 'EACCES' ? ' (permission denied — check read access for the verifying user)' : '';
    return { valid: false, file_results: [], signature_valid: false, extra_files: [], errors: [`Cannot read ${MANIFEST_NAME}: ${e?.message ?? String(e)}${hint}`] };
  }
  let manifest: SignedManifest;
  try {
    manifest = JSON.parse(manifestRaw);
  } catch (e: any) {
    return { valid: false, file_results: [], signature_valid: false, extra_files: [], errors: [`Failed to parse manifest: ${e.message}`] };
  }
  if (!manifest || !Array.isArray(manifest.files)) {
    return { valid: false, file_results: [], signature_valid: false, extra_files: [], errors: ['Manifest is missing a valid `files` array — file may be corrupt.'] };
  }

  // Verify signature
  let publicKey: KeyObject;
  try {
    publicKey = createPublicKey(manifest.signer_public_key);
  } catch (e: any) {
    return { valid: false, file_results: [], signature_valid: false, extra_files: [], errors: [`Invalid embedded public key: ${e.message}`] };
  }

  if (expectedPublicKeyPath) {
    if (!existsSync(expectedPublicKeyPath)) {
      errors.push(`Expected public key file ${expectedPublicKeyPath} does not exist`);
    } else {
      try {
        const expectedKey = createPublicKey(readFileSync(expectedPublicKeyPath, 'utf8'));
        const a = (publicKey.export({ type: 'spki', format: 'der' }) as Buffer).toString('base64');
        const b = (expectedKey.export({ type: 'spki', format: 'der' }) as Buffer).toString('base64');
        if (a !== b) {
          errors.push('Manifest public key does not match expected public key.');
        }
      } catch (e: any) {
        errors.push(`Could not read/parse expected public key ${expectedPublicKeyPath}: ${e?.message ?? String(e)}`);
      }
    }
  }

  let sigValid = false;
  try {
    const sigBuf = Buffer.from(readFileSync(sigPath, 'utf8'), 'base64');
    const canonical = canonicalize(manifest);
    sigValid = cryptoVerify(null, Buffer.from(canonical, 'utf8'), publicKey, sigBuf);
  } catch (e: any) {
    errors.push(`Cannot read/verify signature file ${SIGNATURE_NAME}: ${e?.message ?? String(e)}`);
  }
  if (!sigValid) errors.push('Manifest signature did not verify.');

  // Verify file hashes
  const manifestNames = new Set(manifest.files.map((f) => f.name));
  const fileResults = manifest.files.map((f) => {
    const p = resolve(outDir, f.name);
    if (!existsSync(p)) {
      return { name: f.name, matched: false, expected_sha256: f.sha256, missing: true };
    }
    try {
      const actual = sha256Hex(readFileSync(p));
      const matched = actual === f.sha256;
      if (!matched) errors.push(`File ${f.name} hash mismatch: expected ${f.sha256.slice(0, 12)}…, got ${actual.slice(0, 12)}…`);
      return { name: f.name, matched, expected_sha256: f.sha256, actual_sha256: actual };
    } catch (e: any) {
      // Unreadable file (EACCES) is a verification failure, not a crash.
      errors.push(`Cannot read ${f.name} for hashing: ${e?.message ?? String(e)}`);
      return { name: f.name, matched: false, expected_sha256: f.sha256 };
    }
  });

  // Extra files (present but unsigned)
  const extraFiles = listSignedFiles(outDir).filter((n) => !manifestNames.has(n));
  if (extraFiles.length > 0) {
    errors.push(`Unsigned files present in ${outDir}: ${extraFiles.join(', ')}`);
  }

  const allFilesOk = fileResults.every((r) => r.matched);
  return {
    valid: sigValid && allFilesOk && extraFiles.length === 0 && errors.length === 0,
    file_results: fileResults,
    signature_valid: sigValid,
    extra_files: extraFiles,
    errors,
  };
}

// ─── Detached single-artifact signing (Ed25519) ──────────────────────────────
//
// signRun() above signs an entire output directory via a manifest. Some
// emitters (e.g. the LOOP-W.W1 prohibited-vendor catalog) also want a
// self-contained, independently-verifiable Ed25519 signature embedded in the
// artifact's own provenance block, so a downstream consumer can verify the
// single file without the run manifest. signDetached() composes the SAME key
// material as signRun (EVIDENCE_SIGNING_KEY_PATH, or an ephemeral keypair
// persisted to outDir) — it never invents a separate signing identity.

export interface DetachedSignature {
  algorithm: 'ed25519';
  /** SHA-256 fingerprint (first 16 hex chars) of the signer's SPKI public-key PEM. */
  keyId: string;
  /** PEM-encoded Ed25519 public key, so a verifier needs nothing else. */
  publicKeyPem: string;
  /** Base64 Ed25519 signature over the exact bytes passed in. */
  signatureBase64: string;
  /** True when the keypair was generated ad hoc (no EVIDENCE_SIGNING_KEY_PATH). */
  ephemeralKey: boolean;
}

/** Stable signer key id: SHA-256 of the SPKI PEM, first 16 hex chars. */
export function publicKeyFingerprint(publicKeyPem: string): string {
  return sha256Hex(Buffer.from(publicKeyPem)).slice(0, 16);
}

/**
 * Produce a detached Ed25519 signature over `bytes` using the run's signing key.
 * `outDir` is where an ephemeral keypair is persisted when EVIDENCE_SIGNING_KEY_PATH
 * is not set (identical behaviour to signRun).
 */
export function signDetached(bytes: Buffer, outDir: string): DetachedSignature {
  const { privateKey, publicKey, ephemeral } = loadOrGenerateKeyPair(outDir);
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
  const sig = cryptoSign(null, bytes, privateKey);
  return {
    algorithm: 'ed25519',
    keyId: publicKeyFingerprint(publicKeyPem),
    publicKeyPem,
    signatureBase64: sig.toString('base64'),
    ephemeralKey: ephemeral,
  };
}

/** Verify a detached signature produced by signDetached() against `bytes`. */
export function verifyDetached(bytes: Buffer, sig: { publicKeyPem: string; signatureBase64: string }): boolean {
  try {
    const publicKey = createPublicKey(sig.publicKeyPem);
    return cryptoVerify(null, bytes, publicKey, Buffer.from(sig.signatureBase64, 'base64'));
  } catch {
    return false;
  }
}

/** Re-export the file names so the orchestrator/CLI can reference them. */
export const SIGNED_MANIFEST_FILE = MANIFEST_NAME;
export const SIGNATURE_FILE = SIGNATURE_NAME;
