/**
 * Tracker push adapter.
 *
 * For each KSI evidence file, PATCHes the local tracker indicator row with:
 *   - status: met / in_progress / blocked
 *   - notes: failing-finding summary + run ID
 *   - evidence_url: link to the JSON evidence file
 *   - last_reviewed: today
 *
 * Also POSTs run telemetry to /api/collector-runs for the tracker dashboard.
 *
 * Auth: tracker API token (Bearer) via TRACKER_API_TOKEN env var.
 * Endpoint: tracker base URL via TRACKER_BASE_URL env var (default http://localhost:4000).
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { EvidenceFile } from './envelope.ts';
import { withRetry, isTransientError } from './retry.ts';

/** Unwrap a `fetch` TypeError's `.cause` so the retry classifier sees the real code. */
function fetchTransient(err: unknown): boolean {
  if (isTransientError(err)) return true;
  const cause = (err as any)?.cause;
  return cause ? isTransientError(cause) : false;
}

function retryableStatus(status: number): boolean {
  return status === 429 || (status >= 500 && status < 600);
}

export interface TrackerConfig {
  baseUrl?: string;
  apiToken: string;
  evidenceUrlBase?: string;
  dryRun?: boolean;
}

export interface TrackerResult {
  ksi_id: string;
  status: 'sent' | 'dry_run' | 'error' | 'unsupported_ksi';
  http_status?: number;
  error?: string;
}

const DEFAULT_BASE = 'http://localhost:4000';

function pickStatus(passed: boolean, hasBlockingDrift: boolean): 'met' | 'in_progress' | 'blocked' {
  if (hasBlockingDrift) return 'blocked';
  return passed ? 'met' : 'in_progress';
}

function buildNotes(data: EvidenceFile): string {
  const lines: string[] = [];
  lines.push(`cloud-evidence run ${data.run_id} at ${data.collected_at}`);
  lines.push(`Rollup: ${data.rollup.pass ? 'PASS' : 'FAIL'} (${data.rollup.passing_findings} passing, ${data.rollup.failing_findings} failing)`);
  const failing = data.providers.flatMap((p) => p.findings.filter((x) => !x.passed));
  if (failing.length > 0) {
    lines.push('Failing findings:');
    for (const f of failing.slice(0, 10)) {
      lines.push(`  - [${f.severity}] ${f.rule}: ${f.current_state.summary}`);
    }
    if (failing.length > 10) lines.push(`  …and ${failing.length - 10} more`);
  }
  if (data.summary_for_llm) {
    lines.push('');
    lines.push(`Summary: ${data.summary_for_llm}`);
  }
  return lines.join('\n');
}

export async function pushAllToTracker(outDir: string, cfg: TrackerConfig): Promise<TrackerResult[]> {
  const base = (cfg.baseUrl ?? process.env.TRACKER_BASE_URL ?? DEFAULT_BASE).replace(/\/$/, '');
  const results: TrackerResult[] = [];

  for (const f of readdirSync(outDir)) {
    if (!f.startsWith('KSI-') || !f.endsWith('.json')) continue;
    if (f === 'KSI-CSX-SUM-input.json') continue;
    let data: EvidenceFile;
    try { data = JSON.parse(readFileSync(join(outDir, f), 'utf8')); } catch (e: any) {
      results.push({ ksi_id: f, status: 'error', error: `parse: ${e.message}` });
      continue;
    }

    const evidenceUrl = cfg.evidenceUrlBase
      ? `${cfg.evidenceUrlBase.replace(/\/$/, '')}/${f}`
      : `file://${join(outDir, f)}`;
    const status = pickStatus(data.rollup.pass, false);  // future: pass drift signal in
    const payload = {
      status,
      notes: buildNotes(data),
      evidence_url: evidenceUrl,
      last_reviewed: new Date().toISOString().slice(0, 10),
    };

    if (cfg.dryRun) {
      results.push({ ksi_id: data.ksi_id, status: 'dry_run' });
      continue;
    }

    const url = `${base}/api/items/indicator/${encodeURIComponent(data.ksi_id)}`;
    try {
      // PATCH is idempotent → safe to retry transient/5xx failures.
      const r = await withRetry(
        async () => {
          const resp = await fetch(url, {
            method: 'PATCH',
            headers: {
              'authorization': `Bearer ${cfg.apiToken}`,
              'content-type': 'application/json',
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
      if (r.status === 404) {
        results.push({ ksi_id: data.ksi_id, status: 'unsupported_ksi' });
      } else if (!r.ok) {
        const text = await r.text().catch(() => '');
        results.push({ ksi_id: data.ksi_id, status: 'error', http_status: r.status, error: `PATCH ${url} → ${text.slice(0, 200)}` });
      } else {
        results.push({ ksi_id: data.ksi_id, status: 'sent', http_status: r.status });
      }
    } catch (e: any) {
      results.push({ ksi_id: data.ksi_id, status: 'error', error: `PATCH ${url} failed after retries: ${e?.message ?? String(e)}` });
    }
  }

  return results;
}

/** Push a run-telemetry record to /api/collector-runs for the tracker dashboard. */
export async function pushRunTelemetry(
  outDir: string,
  cfg: TrackerConfig,
  runMeta: { run_id: string; started_at: string; finished_at: string; frmr_version: string; total_ksis: number; passed_ksis: number; failed_ksis: number; drift_events: number; negative_drift: number; summary?: unknown },
): Promise<{ status: 'sent' | 'dry_run' | 'error'; http_status?: number; error?: string }> {
  const base = (cfg.baseUrl ?? process.env.TRACKER_BASE_URL ?? DEFAULT_BASE).replace(/\/$/, '');
  if (cfg.dryRun) return { status: 'dry_run' };
  const url = `${base}/api/collector-runs`;
  try {
    const r = await withRetry(
      async () => {
        const resp = await fetch(url, {
          method: 'POST',
          headers: { 'authorization': `Bearer ${cfg.apiToken}`, 'content-type': 'application/json' },
          body: JSON.stringify({
            run_id: runMeta.run_id,
            started_at: runMeta.started_at,
            finished_at: runMeta.finished_at,
            frmr_version: runMeta.frmr_version,
            total_ksis: runMeta.total_ksis,
            passed_ksis: runMeta.passed_ksis,
            failed_ksis: runMeta.failed_ksis,
            drift_events: runMeta.drift_events,
            negative_drift: runMeta.negative_drift,
            summary_json: runMeta.summary ?? null,
          }),
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
      return { status: 'error', http_status: r.status, error: `POST ${url} → ${text.slice(0, 200)}` };
    }
    return { status: 'sent', http_status: r.status };
  } catch (e: any) {
    return { status: 'error', error: `POST ${url} failed after retries: ${e?.message ?? String(e)}` };
  }
}
