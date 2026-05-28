/**
 * Tests for core/timestamp.ts.
 *
 * We can't depend on a real public TSA in unit tests (network, flakiness,
 * rate limits), so we:
 *   1. Verify the openssl `ts -query` step actually produces a valid TSQ.
 *   2. Inject a fake httpPost that captures the request and returns a
 *      pre-canned binary body — enough to exercise the success path through
 *      writing the .tsr and meta files.
 *   3. Verify graceful-degradation paths: missing manifest, CLOUD_EVIDENCE_NO_TSA=1,
 *      bad content-type, non-200, empty body.
 *   4. Verify tamper detection in verifyTimestamp() — if the manifest's
 *      hash changes after stamping, verify returns valid=false with the
 *      mismatch reason (no openssl needed for this check).
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { timestampManifest, verifyTimestamp, TSA_REQUEST_FILE, TSA_RESPONSE_FILE, TSA_META_FILE } from '../../core/timestamp.ts';

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(resolve(tmpdir(), 'cev-tsa-'));
  delete process.env.CLOUD_EVIDENCE_NO_TSA;
  delete process.env.EVIDENCE_TSA_URL;
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

function writeManifest(body: object = { x: 1 }): void {
  writeFileSync(resolve(tmp, 'manifest.json'), JSON.stringify(body));
}

describe('timestampManifest — graceful degradation', () => {
  it('writes meta with skipped reason when CLOUD_EVIDENCE_NO_TSA=1', async () => {
    process.env.CLOUD_EVIDENCE_NO_TSA = '1';
    writeManifest();
    const r = await timestampManifest({ outDir: tmp });
    expect(r.obtained).toBe(false);
    expect(r.reason).toMatch(/disabled/);
    expect(existsSync(resolve(tmp, TSA_META_FILE))).toBe(true);
  });

  it('returns reason when manifest.json is missing', async () => {
    const r = await timestampManifest({ outDir: tmp });
    expect(r.obtained).toBe(false);
    expect(r.reason).toMatch(/manifest.json not found/);
  });

  it('returns reason on non-200 HTTP response from TSA', async () => {
    writeManifest();
    const r = await timestampManifest({
      outDir: tmp,
      tsaUrl: 'http://fake.tsa.example/',
      httpPost: async () => ({ status: 500, body: Buffer.alloc(0) }),
    });
    expect(r.obtained).toBe(false);
    expect(r.reason).toMatch(/HTTP 500/);
  });

  it('returns reason on bad content-type', async () => {
    writeManifest();
    const r = await timestampManifest({
      outDir: tmp,
      tsaUrl: 'http://fake.tsa.example/',
      httpPost: async () => ({ status: 200, body: Buffer.from('<html>error</html>'), contentType: 'text/html' }),
    });
    expect(r.obtained).toBe(false);
    expect(r.reason).toMatch(/content-type/i);
  });

  it('returns reason when TSA response body is too small', async () => {
    writeManifest();
    const r = await timestampManifest({
      outDir: tmp,
      tsaUrl: 'http://fake.tsa.example/',
      httpPost: async () => ({ status: 200, body: Buffer.from('x'), contentType: 'application/timestamp-reply' }),
    });
    expect(r.obtained).toBe(false);
    expect(r.reason).toMatch(/too small/);
  });
});

describe('timestampManifest — happy path with mocked TSA', () => {
  it('successfully writes .tsq, .tsr, and meta when TSA returns a plausible response', async () => {
    writeManifest({ ksi: 'KSI-IAM-MFA', files: 5 });
    // Use a 256-byte fake binary body (above the size threshold)
    const fakeTsr = Buffer.alloc(256, 0xab);
    const r = await timestampManifest({
      outDir: tmp,
      tsaUrl: 'http://fake.tsa.example/tsr',
      httpPost: async (_url, body, ct) => {
        expect(ct).toBe('application/timestamp-query');
        expect(body.length).toBeGreaterThan(0); // openssl produced a real TSQ
        return { status: 200, body: fakeTsr, contentType: 'application/timestamp-reply' };
      },
    });
    expect(r.obtained, r.reason).toBe(true);
    expect(r.manifest_sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(existsSync(resolve(tmp, TSA_REQUEST_FILE))).toBe(true);
    expect(existsSync(resolve(tmp, TSA_RESPONSE_FILE))).toBe(true);
    const meta = JSON.parse(readFileSync(resolve(tmp, TSA_META_FILE), 'utf8'));
    expect(meta.obtained).toBe(true);
    expect(meta.tsa_url).toBe('http://fake.tsa.example/tsr');
  });
});

describe('verifyTimestamp', () => {
  it('returns valid=false with helpful reason when no TSR is present', () => {
    writeManifest();
    const r = verifyTimestamp(tmp);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/manifest.tsr missing/);
  });

  it('detects manifest tampering even when TSR exists', async () => {
    writeManifest({ a: 1 });
    // Stamp with a fake TSA
    await timestampManifest({
      outDir: tmp,
      tsaUrl: 'http://fake.tsa.example/',
      httpPost: async () => ({ status: 200, body: Buffer.alloc(256, 0xcd), contentType: 'application/timestamp-reply' }),
    });
    // Tamper: change the manifest after stamping
    writeFileSync(resolve(tmp, 'manifest.json'), JSON.stringify({ a: 2 }));
    const r = verifyTimestamp(tmp);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/hash changed since stamping/);
    expect(r.manifest_sha256_at_verify).not.toBe(r.manifest_sha256_at_stamp);
  });

  it('returns valid=false with helpful reason when TSR is fake (openssl rejects)', async () => {
    writeManifest({ a: 1 });
    await timestampManifest({
      outDir: tmp,
      tsaUrl: 'http://fake.tsa.example/',
      httpPost: async () => ({ status: 200, body: Buffer.alloc(256, 0xcd), contentType: 'application/timestamp-reply' }),
    });
    const r = verifyTimestamp(tmp);
    expect(r.valid).toBe(false);
    // The reason depends on whether openssl is on PATH; both messages are acceptable
    expect(r.reason ?? '').toMatch(/openssl|verify/i);
  });
});
