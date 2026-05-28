/**
 * Paramify push adapter.
 *
 * Pushes per-KSI status + evidence pointer into Paramify via REST API.
 * Idempotent: uses external_id = ksi_id + run_id so re-runs don't duplicate.
 *
 * Auth: PARAMIFY_API_TOKEN env var (required when --push-paramify is set).
 * Endpoint: PARAMIFY_API_BASE env var (defaults to https://api.paramify.com/v1).
 *
 * The Paramify REST API contract varies by tenant. The default payload shape
 * here follows the common KSI-update pattern; users with bespoke endpoints can
 * override via a small adapter module passed in.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { EvidenceFile } from './envelope.ts';
import { withRetry, isTransientError } from './retry.ts';

/**
 * A `fetch` network failure throws a TypeError whose `.cause` carries the real
 * Node error (ECONNREFUSED, ETIMEDOUT, …). Unwrap one level so the retry
 * classifier can see the underlying transient code.
 */
function fetchTransient(err: unknown): boolean {
  if (isTransientError(err)) return true;
  const cause = (err as any)?.cause;
  return cause ? isTransientError(cause) : false;
}

/** Marker thrown so withRetry treats a 5xx/429 HTTP response as retryable. */
function retryableStatus(status: number): boolean {
  return status === 429 || (status >= 500 && status < 600);
}

export interface ParamifyConfig {
  apiBase?: string;
  apiToken: string;
  evidenceUrlBase?: string;   // public URL prefix for evidence JSON files (CI artifact URL, S3, etc.)
  dryRun?: boolean;
}

export interface ParamifyResult {
  ksi_id: string;
  status: 'sent' | 'dry_run' | 'error';
  http_status?: number;
  error?: string;
}

export async function pushAllToParamify(outDir: string, cfg: ParamifyConfig): Promise<ParamifyResult[]> {
  const base = (cfg.apiBase ?? process.env.PARAMIFY_API_BASE ?? 'https://api.paramify.com/v1').replace(/\/$/, '');
  const results: ParamifyResult[] = [];

  for (const f of readdirSync(outDir)) {
    if (!f.startsWith('KSI-') || !f.endsWith('.json')) continue;
    if (f === 'KSI-CSX-SUM-input.json') continue;
    let data: EvidenceFile;
    try { data = JSON.parse(readFileSync(join(outDir, f), 'utf8')); } catch (e: any) {
      results.push({ ksi_id: f, status: 'error', error: `parse: ${e.message}` });
      continue;
    }

    const evidenceUrl = cfg.evidenceUrlBase ? `${cfg.evidenceUrlBase.replace(/\/$/, '')}/${f}` : `file://${join(outDir, f)}`;
    const failingFindings = data.providers.flatMap((p) => p.findings.filter((x) => !x.passed));

    // Default payload shape (override by editing this adapter for your Paramify tenant).
    const payload = {
      external_id: `${data.ksi_id}__${data.run_id}`,
      ksi_id: data.ksi_id,
      ksi_name: data.ksi_name,
      satisfied: data.rollup.pass,
      narrative: data.summary_for_llm ?? `Run ${data.run_id} at ${data.collected_at}.`,
      nist_controls: data.nist_controls ?? [],
      evidence_url: evidenceUrl,
      evidence_collected_at: data.collected_at,
      failing_findings: failingFindings.map((x) => ({
        rule: x.rule,
        severity: x.severity,
        current: x.current_state.summary,
        target: x.target_state.summary,
      })),
      process_artifacts_required: data.process_artifacts_required ?? [],
    };

    if (cfg.dryRun) {
      results.push({ ksi_id: data.ksi_id, status: 'dry_run' });
      continue;
    }

    const url = `${base}/ksi-evidence`;
    try {
      // Idempotent (external_id de-dupes) → safe to retry transient/5xx failures.
      const r = await withRetry(
        async () => {
          const resp = await fetch(url, {
            method: 'POST',
            headers: {
              'authorization': `Bearer ${cfg.apiToken}`,
              'content-type': 'application/json',
              'accept': 'application/json',
            },
            body: JSON.stringify(payload),
          });
          if (retryableStatus(resp.status)) {
            const t = await resp.text().catch(() => '');
            throw Object.assign(new Error(`HTTP ${resp.status}: ${t.slice(0, 200)}`), { $metadata: { httpStatusCode: resp.status } });
          }
          return resp;
        },
        { attempts: 3, baseDelayMs: 300, maxDelayMs: 3000, isTransient: fetchTransient },
      );
      if (!r.ok) {
        const text = await r.text().catch(() => '');
        results.push({ ksi_id: data.ksi_id, status: 'error', http_status: r.status, error: `POST ${url} → ${text.slice(0, 200)}` });
      } else {
        results.push({ ksi_id: data.ksi_id, status: 'sent', http_status: r.status });
      }
    } catch (e: any) {
      results.push({ ksi_id: data.ksi_id, status: 'error', error: `POST ${url} failed after retries: ${e?.message ?? String(e)}` });
    }
  }

  return results;
}
