/**
 * Generic outbound webhook with HMAC-SHA256 signing.
 *
 * The dedicated integrations we ship (Paramify, tracker, Slack/PagerDuty,
 * Jira/ServiceNow/GitHub, SIEM OCSF) cover most cases, but some users will
 * want to push to a system we don't directly support — n8n, Zapier, custom
 * Slack workflows, internal queues, etc.
 *
 * This module provides a generic POST-with-signature mechanism that mirrors
 * the way GitHub, Slack, and Stripe sign their webhooks:
 *
 *   - The payload is JSON.
 *   - We compute HMAC-SHA256 over the body using the shared secret.
 *   - The signature is sent as `X-CloudEvidence-Signature: sha256=<hex>`.
 *   - We also send `X-CloudEvidence-Timestamp: <unix-sec>` so the receiver
 *     can reject replays (e.g. accept only timestamps within 5 minutes).
 *   - The signature actually covers `<timestamp>.<body>` (Stripe-style) so
 *     the receiver can't be tricked by a replayed payload with a fresh body.
 *
 * Two payload shapes are supported:
 *   - "run": one webhook per run, body = pva-run-summary.json
 *   - "finding": one webhook per failing finding (similar to ticket-push,
 *      but you wire your own consumer)
 *
 * The caller chooses which mode (or both) via the SIEM/ticket-style options.
 *
 * Failure handling:
 *   - Each call is retried up to 3 times via core/retry.ts.
 *   - Failures are recorded in the result, not thrown.
 */
import { createHmac, timingSafeEqual } from 'node:crypto';
import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';
import type { Finding, EvidenceFile } from './envelope.ts';
import { withRetry } from './retry.ts';
import { log } from './log.ts';

export interface WebhookOptions {
  /** Webhook URL. */
  url: string;
  /** Shared secret used to compute HMAC-SHA256 over `<timestamp>.<body>`. */
  secret: string;
  /** Additional headers to send (e.g. an auth token if the receiver requires one). */
  extraHeaders?: Record<string, string>;
  /** Skew tolerance the SERVER will apply (we just send a timestamp; receiver decides). */
  /** Override the HTTP function for tests. */
  httpPost?: (url: string, headers: Record<string, string>, body: string) => Promise<{ status: number; body: string }>;
}

const SIG_HEADER = 'X-CloudEvidence-Signature';
const TS_HEADER = 'X-CloudEvidence-Timestamp';

/** Compute the HMAC signature over `<timestamp>.<body>`. */
export function signPayload(body: string, secret: string, tsSec: number = Math.floor(Date.now() / 1000)): { signature: string; timestamp: number } {
  const mac = createHmac('sha256', secret).update(`${tsSec}.${body}`).digest('hex');
  return { signature: `sha256=${mac}`, timestamp: tsSec };
}

/**
 * Receiver-side verification helper. Use this in your downstream consumer
 * (or in tests). Returns true if signature matches and timestamp is within
 * the tolerance window.
 */
export function verifySignature(body: string, secret: string, signatureHeader: string, timestampHeader: string, maxSkewSec = 300): boolean {
  const ts = Number(timestampHeader);
  if (!Number.isFinite(ts)) return false;
  if (Math.abs(Math.floor(Date.now() / 1000) - ts) > maxSkewSec) return false;
  const expected = createHmac('sha256', secret).update(`${ts}.${body}`).digest('hex');
  const expectedHeader = `sha256=${expected}`;
  if (signatureHeader.length !== expectedHeader.length) return false;
  return timingSafeEqual(Buffer.from(signatureHeader), Buffer.from(expectedHeader));
}

function defaultHttp(url: string, headers: Record<string, string>, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === 'https:' ? httpsRequest : httpRequest;
    const req = lib({
      method: 'POST',
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search,
      headers: { ...headers, 'content-length': Buffer.byteLength(body) },
      timeout: 15_000,
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(new Error('webhook request timed out')); });
    req.write(body);
    req.end();
  });
}

export interface WebhookSendResult {
  url: string;
  status?: number;
  ok: boolean;
  reason?: string;
}

/**
 * Send a single signed payload. Returns gracefully on failure.
 */
export async function sendWebhook(opts: WebhookOptions, body: unknown): Promise<WebhookSendResult> {
  const bodyStr = JSON.stringify(body);
  const { signature, timestamp } = signPayload(bodyStr, opts.secret);
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    [SIG_HEADER]: signature,
    [TS_HEADER]: String(timestamp),
    ...(opts.extraHeaders ?? {}),
  };
  const post = opts.httpPost ?? defaultHttp;
  try {
    const res = await withRetry(() => post(opts.url, headers, bodyStr), { attempts: 3, baseDelayMs: 200, maxDelayMs: 2000 });
    if (res.status >= 200 && res.status < 300) {
      log.info({ event: 'webhook.sent', url: opts.url, status: res.status });
      return { url: opts.url, status: res.status, ok: true };
    }
    log.warn({ event: 'webhook.bad_status', url: opts.url, status: res.status });
    return { url: opts.url, status: res.status, ok: false, reason: `HTTP ${res.status}: ${res.body.slice(0, 200)}` };
  } catch (e: any) {
    // Surface the underlying network code (ECONNREFUSED vs ETIMEDOUT vs ENOTFOUND)
    // so the operator can tell "wrong URL" from "receiver down" from "DNS".
    const code = e?.code ?? e?.cause?.code;
    log.warn({ event: 'webhook.exception', url: opts.url, err_code: code, err_message: e?.message });
    return { url: opts.url, ok: false, reason: code ? `${code}: ${e?.message ?? ''}`.trim() : (e?.message ?? String(e)) };
  }
}

/**
 * Convenience: send the run-summary to a webhook.
 */
export async function sendRunSummary(opts: WebhookOptions, runSummary: unknown): Promise<WebhookSendResult> {
  return sendWebhook(opts, { event: 'cloud_evidence.run_summary', payload: runSummary });
}

/**
 * Convenience: send one webhook per failing finding. Useful when the
 * downstream wants to create alerts / notifications per finding.
 */
export async function sendFailingFindings(opts: WebhookOptions, evidence: EvidenceFile): Promise<WebhookSendResult[]> {
  const results: WebhookSendResult[] = [];
  for (const p of evidence.providers) {
    const scopeId = p.account_id ?? p.project_id ?? null;
    for (const f of p.findings) {
      if (f.passed) continue;
      const body = {
        event: 'cloud_evidence.failing_finding',
        ksi_id: evidence.ksi_id,
        ksi_name: evidence.ksi_name,
        run_id: evidence.run_id,
        collected_at: evidence.collected_at,
        provider: p.provider,
        scope_id: scopeId,
        finding: f,
      };
      results.push(await sendWebhook(opts, body));
    }
  }
  return results;
}
