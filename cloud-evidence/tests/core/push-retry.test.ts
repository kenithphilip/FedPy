/**
 * Tests for the retry + URL-in-error hardening added to paramify-push.ts and
 * tracker-push.ts (Batch 2 error-handling audit).
 *
 * Both adapters read KSI-*.json evidence files from a directory and POST/PATCH
 * them via the global `fetch`. We stub `globalThis.fetch` to simulate transient
 * 5xx responses, network errors, and success.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { pushAllToParamify } from '../../core/paramify-push.ts';
import { pushAllToTracker } from '../../core/tracker-push.ts';

let outDir: string;
const realFetch = globalThis.fetch;

function writeEvidence(dir: string, ksiId = 'KSI-IAM-MFA'): void {
  const ev = {
    ksi_id: ksiId,
    ksi_name: 'Multi-Factor Authentication',
    ksi_statement: 'x',
    scope: 'CLOUD',
    frmr_version: '2025-06.r1',
    run_id: 'run-123',
    collected_at: '2026-05-27T12:00:00Z',
    providers: [{ provider: 'aws', account_id: '111122223333', evidence: [], findings: [] }],
    rollup: { pass: true, passing_findings: 1, failing_findings: 0, warnings: [], missing_evidence: [], alternatives_in_play: 0 },
    nist_controls: ['IA-2'],
  };
  writeFileSync(resolve(dir, `${ksiId}.json`), JSON.stringify(ev));
}

beforeEach(() => {
  outDir = mkdtempSync(resolve(tmpdir(), 'cev-pushretry-'));
  writeEvidence(outDir);
});

afterEach(() => {
  globalThis.fetch = realFetch;
  rmSync(outDir, { recursive: true, force: true });
});

describe('pushAllToParamify retry', () => {
  it('retries a 503 then succeeds on the second attempt', async () => {
    let calls = 0;
    globalThis.fetch = vi.fn(async () => {
      calls++;
      if (calls === 1) return new Response('upstream down', { status: 503 });
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    }) as any;

    const results = await pushAllToParamify(outDir, { apiToken: 't' });
    expect(results).toHaveLength(1);
    expect(results[0]!.status).toBe('sent');
    expect(calls).toBe(2);  // first 503 retried
  });

  it('reports an error including the URL after exhausting retries', async () => {
    globalThis.fetch = vi.fn(async () => new Response('still down', { status: 500 })) as any;
    const results = await pushAllToParamify(outDir, { apiToken: 't', apiBase: 'https://api.example.com/v1' });
    expect(results[0]!.status).toBe('error');
    expect(results[0]!.error).toContain('https://api.example.com/v1/ksi-evidence');
  });

  it('does NOT retry a 400 (non-transient) and surfaces the body', async () => {
    let calls = 0;
    globalThis.fetch = vi.fn(async () => { calls++; return new Response('bad request', { status: 400 }); }) as any;
    const results = await pushAllToParamify(outDir, { apiToken: 't' });
    expect(results[0]!.status).toBe('error');
    expect(calls).toBe(1);  // 400 is not retried
  });

  it('surfaces a network error (fetch throws) with the URL', async () => {
    globalThis.fetch = vi.fn(async () => { throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } }); }) as any;
    const results = await pushAllToParamify(outDir, { apiToken: 't' });
    expect(results[0]!.status).toBe('error');
    expect(results[0]!.error).toMatch(/failed after retries/);
  });
});

describe('pushAllToTracker retry', () => {
  it('maps a 404 to unsupported_ksi without retrying', async () => {
    let calls = 0;
    globalThis.fetch = vi.fn(async () => { calls++; return new Response('no such indicator', { status: 404 }); }) as any;
    const results = await pushAllToTracker(outDir, { apiToken: 't' });
    expect(results[0]!.status).toBe('unsupported_ksi');
    expect(calls).toBe(1);
  });

  it('retries a 502 then succeeds', async () => {
    let calls = 0;
    globalThis.fetch = vi.fn(async () => {
      calls++;
      if (calls === 1) return new Response('bad gateway', { status: 502 });
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    }) as any;
    const results = await pushAllToTracker(outDir, { apiToken: 't' });
    expect(results[0]!.status).toBe('sent');
    expect(calls).toBe(2);
  });
});
