/**
 * Tests for core/webhook-push.ts — HMAC signing + sender + verifier.
 */
import { describe, it, expect } from 'vitest';
import { signPayload, verifySignature, sendWebhook, sendFailingFindings, sendRunSummary } from '../../core/webhook-push.ts';
import type { Finding, EvidenceFile } from '../../core/envelope.ts';

describe('signPayload / verifySignature roundtrip', () => {
  it('signed body verifies with the same secret', () => {
    const { signature, timestamp } = signPayload('{"x":1}', 'shh');
    expect(verifySignature('{"x":1}', 'shh', signature, String(timestamp))).toBe(true);
  });

  it('verify fails with wrong secret', () => {
    const { signature, timestamp } = signPayload('{"x":1}', 'shh');
    expect(verifySignature('{"x":1}', 'wrong', signature, String(timestamp))).toBe(false);
  });

  it('verify fails when body has been tampered with', () => {
    const { signature, timestamp } = signPayload('{"x":1}', 'shh');
    expect(verifySignature('{"x":2}', 'shh', signature, String(timestamp))).toBe(false);
  });

  it('verify fails when timestamp is too old', () => {
    const tenMinAgo = Math.floor(Date.now() / 1000) - 600;
    const { signature } = signPayload('{"x":1}', 'shh', tenMinAgo);
    expect(verifySignature('{"x":1}', 'shh', signature, String(tenMinAgo), 300)).toBe(false);
  });
});

describe('sendWebhook', () => {
  it('attaches the X-CloudEvidence-Signature + X-CloudEvidence-Timestamp headers', async () => {
    let captured = { headers: {} as any, body: '' };
    const httpPost = async (_u: any, headers: any, body: string) => {
      captured = { headers, body };
      return { status: 200, body: 'ok' };
    };
    await sendWebhook({ url: 'https://hook.example/in', secret: 'shh', httpPost }, { hello: 'world' });
    expect(captured.headers['X-CloudEvidence-Signature']).toMatch(/^sha256=[a-f0-9]{64}$/);
    expect(Number(captured.headers['X-CloudEvidence-Timestamp'])).toBeGreaterThan(0);
    expect(captured.body).toBe(JSON.stringify({ hello: 'world' }));
  });

  it('returns ok=false with reason on non-2xx', async () => {
    const httpPost = async () => ({ status: 503, body: 'try later' });
    const r = await sendWebhook({ url: 'https://x', secret: 'shh', httpPost }, { a: 1 });
    expect(r.ok).toBe(false);
    expect(r.status).toBe(503);
    expect(r.reason).toMatch(/HTTP 503/);
  });

  it('merges extraHeaders without overwriting the signature', async () => {
    let captured: any = {};
    const httpPost = async (_u: any, headers: any) => {
      captured = headers;
      return { status: 200, body: 'ok' };
    };
    await sendWebhook({
      url: 'https://x',
      secret: 'shh',
      httpPost,
      extraHeaders: { 'X-API-Token': 'abc', authorization: 'Bearer token' },
    }, { foo: 1 });
    expect(captured['X-API-Token']).toBe('abc');
    expect(captured.authorization).toBe('Bearer token');
    expect(captured['X-CloudEvidence-Signature']).toBeTruthy();
  });
});

describe('sendFailingFindings', () => {
  function mkFinding(rule: string, passed: boolean): Finding {
    return {
      rule, passed, severity: 'high',
      current_state: { summary: 'x', observations: null },
      target_state: { summary: 'x', rationale: 'x' },
      ...(passed ? {} : {
        gap: { description: 'x', affected_resources: [] },
        remediation: { summary: 'x', options: [{ approach: 'x', mechanism: 'cli', steps: ['x'] }] },
      }),
    };
  }
  function mkEvidence(findings: Finding[]): EvidenceFile {
    return {
      ksi_id: 'KSI-IAM-MFA', ksi_name: 'MFA', ksi_statement: 'x', scope: 'CLOUD',
      frmr_version: '2025-06.r1', run_id: 'r', collected_at: '2026-05-27T12:00:00Z',
      providers: [{ provider: 'aws', account_id: '111', evidence: [], findings }],
      rollup: { pass: false, passing_findings: 0, failing_findings: 1, warnings: [], missing_evidence: [], alternatives_in_play: 0 },
    };
  }

  it('only emits a webhook for failing findings', async () => {
    let n = 0;
    const httpPost = async () => { n++; return { status: 200, body: 'ok' }; };
    const ev = mkEvidence([mkFinding('a', true), mkFinding('b', false), mkFinding('c', false)]);
    const results = await sendFailingFindings({ url: 'https://x', secret: 'shh', httpPost }, ev);
    expect(n).toBe(2);
    expect(results).toHaveLength(2);
    expect(results.every((r) => r.ok)).toBe(true);
  });
});

describe('sendRunSummary', () => {
  it('wraps the summary in an event envelope', async () => {
    let body = '';
    const httpPost = async (_u: any, _h: any, b: string) => { body = b; return { status: 200, body: 'ok' }; };
    await sendRunSummary({ url: 'https://x', secret: 'shh', httpPost }, { total: 10, passed: 8 });
    const parsed = JSON.parse(body);
    expect(parsed.event).toBe('cloud_evidence.run_summary');
    expect(parsed.payload.total).toBe(10);
  });
});

describe('sendWebhook network-error differentiation', () => {
  it('surfaces ECONNREFUSED in the failure reason (receiver down)', async () => {
    const httpPost = async () => { throw Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }); };
    const r = await sendWebhook({ url: 'https://x', secret: 'shh', httpPost }, { a: 1 });
    expect(r.ok).toBe(false);
    expect(r.reason).toContain('ECONNREFUSED');
  });

  it('surfaces a fetch-style cause code (ETIMEDOUT)', async () => {
    const httpPost = async () => { throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ETIMEDOUT' } }); };
    const r = await sendWebhook({ url: 'https://x', secret: 'shh', httpPost }, { a: 1 });
    expect(r.ok).toBe(false);
    expect(r.reason).toContain('ETIMEDOUT');
  });
});
