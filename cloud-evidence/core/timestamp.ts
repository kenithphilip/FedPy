/**
 * RFC 3161 trusted timestamp wrapper.
 *
 * After the orchestrator signs the run manifest (core/sign.ts), it can ALSO
 * request a trusted-third-party timestamp over the manifest's SHA-256 hash.
 * This is what an assessor needs to prove "the evidence existed on this date,
 * not later" — your own Ed25519 signature only proves "I signed it" but says
 * nothing about WHEN.
 *
 * Why an external TSA matters:
 *   - You could backdate `signed_at` in your own manifest. A reviewer must
 *     trust your clock, your build process, and your operator.
 *   - An RFC 3161 timestamp token (TST) is countersigned by an authority
 *     whose root cert chains to a well-known TSA CA (DigiCert, GlobalSign,
 *     Apple, etc.). Verifiers don't need to trust YOU — only the TSA.
 *
 * Why we shell out to openssl:
 *   - The Node ecosystem has no actively-maintained, audit-quality RFC 3161
 *     client. `openssl ts -query / -verify` is the industry standard, ships
 *     with every modern OS / CI runner, and produces files (.tsq, .tsr) that
 *     a third party can independently verify with their own openssl.
 *   - Failure mode is graceful: missing openssl or unreachable TSA → warn,
 *     continue, run still emits the (un-timestamped) signed manifest.
 *
 * Environment variables:
 *   EVIDENCE_TSA_URL          TSA endpoint (default: http://timestamp.digicert.com)
 *   EVIDENCE_TSA_CA_BUNDLE    PEM of TSA CA certs for verification
 *   CLOUD_EVIDENCE_NO_TSA=1   Skip timestamping entirely
 *
 * Outputs (alongside manifest.json + manifest.sig):
 *   manifest.tsq    Time-Stamp Request (DER, hex / b64 form depends on openssl)
 *   manifest.tsr    Time-Stamp Response (DER) — this is the legally meaningful token
 *   manifest.tst.json  Our own light-weight metadata: TSA URL, timestamp captured, sha256
 */
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { URL } from 'node:url';
import { log } from './log.ts';

const DEFAULT_TSA_URL = 'http://timestamp.digicert.com';
const REQ_NAME = 'manifest.tsq';
const RESP_NAME = 'manifest.tsr';
const META_NAME = 'manifest.tst.json';

export interface TimestampOptions {
  /** Directory containing manifest.json — outputs are written here. */
  outDir: string;
  /** TSA URL. Default: process.env.EVIDENCE_TSA_URL or DigiCert. */
  tsaUrl?: string;
  /** Path to PEM bundle of TSA CA certs (for verification). */
  tsaCaBundle?: string;
  /** Override the openssl binary (for tests). */
  opensslBin?: string;
  /** Override the HTTP poster (for tests). */
  httpPost?: (url: string, body: Buffer, contentType: string) => Promise<{ status: number; body: Buffer; contentType?: string }>;
}

export interface TimestampResult {
  /** True if a TSR was successfully obtained and stored. */
  obtained: boolean;
  /** Reason it was skipped or failed, if applicable. */
  reason?: string;
  /** TSA URL we hit. */
  tsa_url: string;
  /** SHA-256 of the manifest at the time of stamping. */
  manifest_sha256: string;
  /** ISO timestamp of when we made the request (NOT the TSA's authoritative time). */
  requested_at: string;
  /** Output file paths. */
  request_path?: string;
  response_path?: string;
  meta_path: string;
}

function which(bin: string): string | null {
  // POSIX `command -v` is a shell builtin; invoke a shell to find it.
  // We don't interpolate user input here — `bin` is a literal from our env / call site.
  const r = spawnSync('/bin/sh', ['-c', `command -v ${bin}`], { encoding: 'utf8' });
  if (r.status === 0 && r.stdout.trim()) return r.stdout.trim();
  return null;
}

async function defaultHttpPost(
  url: string,
  body: Buffer,
  contentType: string,
): Promise<{ status: number; body: Buffer; contentType?: string }> {
  return new Promise((resolveP, rejectP) => {
    const u = new URL(url);
    const lib = u.protocol === 'https:' ? httpsRequest : httpRequest;
    const req = lib(
      {
        method: 'POST',
        hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname + u.search,
        headers: {
          'Content-Type': contentType,
          'Content-Length': body.length,
        },
        timeout: 15_000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () =>
          resolveP({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks),
            contentType: res.headers['content-type'] as string | undefined,
          }),
        );
      },
    );
    req.on('error', rejectP);
    req.on('timeout', () => {
      req.destroy(new Error('TSA request timed out after 15s'));
    });
    req.write(body);
    req.end();
  });
}

/**
 * Request a TSR over the manifest's contents and store it next to the manifest.
 *
 * Steps:
 *   1. Read manifest.json bytes and compute SHA-256.
 *   2. Use `openssl ts -query` to build a TimeStampReq over the manifest bytes.
 *   3. POST the .tsq to the TSA with content-type application/timestamp-query.
 *   4. Validate response content-type is application/timestamp-reply.
 *   5. Write manifest.tsq, manifest.tsr, manifest.tst.json.
 *
 * Returns gracefully (obtained: false, reason: …) on any failure so the
 * orchestrator can continue. Errors are NOT thrown — operators should see
 * a warning and keep the (un-timestamped) signed manifest.
 */
export async function timestampManifest(opts: TimestampOptions): Promise<TimestampResult> {
  const tsaUrl = opts.tsaUrl ?? process.env.EVIDENCE_TSA_URL ?? DEFAULT_TSA_URL;
  const requestedAt = new Date().toISOString();
  const manifestPath = resolve(opts.outDir, 'manifest.json');
  const metaPath = resolve(opts.outDir, META_NAME);

  const writeMeta = (extra: Partial<TimestampResult>): TimestampResult => {
    const meta: TimestampResult = {
      obtained: false,
      tsa_url: tsaUrl,
      manifest_sha256: '',
      requested_at: requestedAt,
      meta_path: metaPath,
      ...extra,
    };
    writeFileSync(metaPath, JSON.stringify(meta, null, 2));
    return meta;
  };

  if (process.env.CLOUD_EVIDENCE_NO_TSA === '1') {
    log.info({ event: 'tsa.skipped', reason: 'CLOUD_EVIDENCE_NO_TSA=1' });
    return writeMeta({ reason: 'disabled via CLOUD_EVIDENCE_NO_TSA' });
  }
  if (!existsSync(manifestPath)) {
    return writeMeta({ reason: 'manifest.json not found; nothing to timestamp' });
  }

  const manifestBytes = readFileSync(manifestPath);
  const manifestSha = createHash('sha256').update(manifestBytes).digest('hex');

  const openssl = opts.opensslBin ?? which('openssl');
  if (!openssl) {
    log.warn({ event: 'tsa.openssl_missing', note: 'Install openssl with RFC 3161 support to enable trusted timestamps.' });
    return writeMeta({ manifest_sha256: manifestSha, reason: 'openssl binary not on PATH' });
  }

  // Build the TimeStampReq with openssl: ts -query -data <manifest> -sha256 -cert -no_nonce
  // -no_nonce is omitted — we want a nonce so replay isn't possible.
  const tsqPath = resolve(opts.outDir, REQ_NAME);
  const tsrPath = resolve(opts.outDir, RESP_NAME);

  const tsqResult = spawnSync(openssl, ['ts', '-query', '-data', manifestPath, '-sha256', '-cert', '-out', tsqPath], { encoding: 'utf8' });
  if (tsqResult.status !== 0) {
    log.warn({ event: 'tsa.query_build_failed', stderr: tsqResult.stderr?.slice(0, 1000) });
    return writeMeta({ manifest_sha256: manifestSha, reason: `openssl ts -query failed: ${tsqResult.stderr?.split('\n')[0] ?? 'unknown'}` });
  }

  const tsqBytes = readFileSync(tsqPath);
  const post = opts.httpPost ?? defaultHttpPost;
  let httpRes: { status: number; body: Buffer; contentType?: string };
  try {
    httpRes = await post(tsaUrl, tsqBytes, 'application/timestamp-query');
  } catch (e: any) {
    log.warn({ event: 'tsa.http_failed', tsa_url: tsaUrl, err_message: e?.message });
    return writeMeta({ manifest_sha256: manifestSha, reason: `TSA POST failed: ${e.message}`, request_path: tsqPath });
  }

  if (httpRes.status !== 200) {
    log.warn({ event: 'tsa.http_status', tsa_url: tsaUrl, status: httpRes.status });
    return writeMeta({ manifest_sha256: manifestSha, reason: `TSA returned HTTP ${httpRes.status}`, request_path: tsqPath });
  }
  const ct = (httpRes.contentType ?? '').toLowerCase();
  if (!ct.includes('application/timestamp-reply') && !ct.includes('application/octet-stream')) {
    log.warn({ event: 'tsa.bad_content_type', tsa_url: tsaUrl, content_type: ct });
    return writeMeta({ manifest_sha256: manifestSha, reason: `TSA replied with unexpected content-type "${ct}"`, request_path: tsqPath });
  }
  if (httpRes.body.length < 50) {
    return writeMeta({ manifest_sha256: manifestSha, reason: 'TSA response too small to be a valid TSR', request_path: tsqPath });
  }

  writeFileSync(tsrPath, httpRes.body);

  log.info({ event: 'tsa.stamped', tsa_url: tsaUrl, manifest_sha256: manifestSha, tsr_bytes: httpRes.body.length });

  return writeMeta({
    obtained: true,
    manifest_sha256: manifestSha,
    request_path: tsqPath,
    response_path: tsrPath,
  });
}

export interface VerifyTimestampResult {
  valid: boolean;
  reason?: string;
  manifest_sha256_at_verify: string;
  manifest_sha256_at_stamp?: string;
  tsa_url?: string;
}

/**
 * Verify a stored TSR against the current manifest.
 *
 * Requires openssl + (optionally) a CA bundle. With no CA bundle, we can
 * verify the response is structurally valid and that the digest matches the
 * manifest's current bytes — but we cannot prove the TSA's signature unless
 * we have the TSA's root cert.
 */
export function verifyTimestamp(outDir: string, opts: { tsaCaBundle?: string; opensslBin?: string } = {}): VerifyTimestampResult {
  const manifestPath = resolve(outDir, 'manifest.json');
  const tsqPath = resolve(outDir, REQ_NAME);
  const tsrPath = resolve(outDir, RESP_NAME);
  const metaPath = resolve(outDir, META_NAME);

  if (!existsSync(manifestPath)) return { valid: false, reason: 'manifest.json missing', manifest_sha256_at_verify: '' };
  if (!existsSync(tsrPath)) return { valid: false, reason: 'manifest.tsr missing', manifest_sha256_at_verify: '' };

  const manifestSha = createHash('sha256').update(readFileSync(manifestPath)).digest('hex');

  let meta: TimestampResult | null = null;
  if (existsSync(metaPath)) {
    try { meta = JSON.parse(readFileSync(metaPath, 'utf8')); } catch { /* ignore */ }
  }
  if (meta && meta.manifest_sha256 && meta.manifest_sha256 !== manifestSha) {
    return {
      valid: false,
      reason: `manifest hash changed since stamping: stamped ${meta.manifest_sha256.slice(0, 12)}…, current ${manifestSha.slice(0, 12)}…`,
      manifest_sha256_at_verify: manifestSha,
      manifest_sha256_at_stamp: meta.manifest_sha256,
      tsa_url: meta.tsa_url,
    };
  }

  const caBundle = opts.tsaCaBundle ?? process.env.EVIDENCE_TSA_CA_BUNDLE;
  const openssl = opts.opensslBin ?? which('openssl');
  if (!openssl) {
    return {
      valid: false,
      reason: 'openssl binary not on PATH (cannot verify TSR signature)',
      manifest_sha256_at_verify: manifestSha,
      manifest_sha256_at_stamp: meta?.manifest_sha256,
      tsa_url: meta?.tsa_url,
    };
  }

  // Verify TSR against manifest data
  const args = ['ts', '-verify', '-data', manifestPath, '-in', tsrPath];
  if (caBundle) args.push('-CAfile', caBundle);
  if (existsSync(tsqPath)) args.push('-queryfile', tsqPath);
  const r = spawnSync(openssl, args, { encoding: 'utf8' });
  if (r.status !== 0) {
    return {
      valid: false,
      reason: `openssl ts -verify failed: ${(r.stderr ?? '').split('\n').slice(0, 3).join(' | ').slice(0, 500)}`,
      manifest_sha256_at_verify: manifestSha,
      manifest_sha256_at_stamp: meta?.manifest_sha256,
      tsa_url: meta?.tsa_url,
    };
  }

  return {
    valid: true,
    manifest_sha256_at_verify: manifestSha,
    manifest_sha256_at_stamp: meta?.manifest_sha256,
    tsa_url: meta?.tsa_url,
  };
}

export const TSA_REQUEST_FILE = REQ_NAME;
export const TSA_RESPONSE_FILE = RESP_NAME;
export const TSA_META_FILE = META_NAME;
