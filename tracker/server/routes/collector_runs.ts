/**
 * Collector-run telemetry endpoint.
 * Receives PVA run summaries from cloud-evidence after each run.
 * Authenticated via either session cookie OR API token.
 */
import { Hono } from 'hono';
import { db } from '../db.ts';
import { requireAuth } from '../auth.ts';

export const collectorRunRoutes = new Hono();
collectorRunRoutes.use('*', requireAuth);

interface PushPayload {
  run_id: string;
  started_at: string;
  finished_at?: string;
  frmr_version?: string;
  total_ksis?: number;
  passed_ksis?: number;
  failed_ksis?: number;
  drift_events?: number;
  negative_drift?: number;
  summary_json?: any;
}

/** Coerce a value to a non-negative integer, clamping garbage/negatives to 0. */
function nonNegInt(v: unknown): number {
  const n = typeof v === 'number' ? v : Number(v);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.floor(n);
}

/** Accept only a parseable timestamp; return the normalized ISO string or null. */
function isoOrNull(v: unknown): string | null {
  if (typeof v !== 'string' || v === '') return null;
  const t = Date.parse(v);
  return Number.isNaN(t) ? null : new Date(t).toISOString();
}

collectorRunRoutes.post('/collector-runs', async (c) => {
  let body: PushPayload;
  try {
    body = await c.req.json<PushPayload>();
  } catch {
    return c.json({ error: 'invalid JSON body' }, 400);
  }
  if (!body.run_id || typeof body.run_id !== 'string') return c.json({ error: 'run_id (string) required' }, 400);
  if (body.run_id.length > 200) return c.json({ error: 'run_id too long (max 200 chars)' }, 400);
  const startedAt = isoOrNull(body.started_at);
  if (!startedAt) return c.json({ error: 'started_at must be a valid ISO datetime' }, 400);
  const finishedAt = isoOrNull(body.finished_at);
  if (body.finished_at != null && !finishedAt) return c.json({ error: 'finished_at must be a valid ISO datetime' }, 400);
  if (body.frmr_version != null && typeof body.frmr_version !== 'string') return c.json({ error: 'frmr_version must be a string' }, 400);

  const user = c.get('user');
  const apiToken = c.get('apiToken');
  const pushedBy = apiToken ? null : user.id;
  const sourceTokenId = apiToken ? apiToken.id : null;

  db().prepare(`
    INSERT INTO collector_runs (
      run_id, started_at, finished_at, frmr_version,
      total_ksis, passed_ksis, failed_ksis, drift_events, negative_drift,
      pushed_by, source_token_id, summary_json
    ) VALUES (
      @run_id, @started_at, @finished_at, @frmr_version,
      @total, @passed, @failed, @drift, @neg,
      @pushed_by, @source_token_id, @summary_json
    )
    ON CONFLICT(run_id) DO UPDATE SET
      finished_at = excluded.finished_at,
      total_ksis = excluded.total_ksis,
      passed_ksis = excluded.passed_ksis,
      failed_ksis = excluded.failed_ksis,
      drift_events = excluded.drift_events,
      negative_drift = excluded.negative_drift,
      summary_json = excluded.summary_json
  `).run({
    run_id: body.run_id,
    started_at: startedAt,
    finished_at: finishedAt,
    frmr_version: body.frmr_version ?? null,
    total: nonNegInt(body.total_ksis),
    passed: nonNegInt(body.passed_ksis),
    failed: nonNegInt(body.failed_ksis),
    drift: nonNegInt(body.drift_events),
    neg: nonNegInt(body.negative_drift),
    pushed_by: pushedBy,
    source_token_id: sourceTokenId,
    summary_json: body.summary_json ? JSON.stringify(body.summary_json) : null,
  });

  return c.json({ ok: true });
});

collectorRunRoutes.get('/collector-runs', (c) => {
  const rows = db().prepare(`
    SELECT r.*, u.name AS pushed_by_name, t.name AS token_name
    FROM collector_runs r
    LEFT JOIN users u ON u.id = r.pushed_by
    LEFT JOIN api_tokens t ON t.id = r.source_token_id
    ORDER BY r.started_at DESC
    LIMIT 50
  `).all();
  return c.json({ runs: rows });
});

collectorRunRoutes.get('/collector-runs/latest', (c) => {
  const row = db().prepare(`
    SELECT r.*, u.name AS pushed_by_name, t.name AS token_name
    FROM collector_runs r
    LEFT JOIN users u ON u.id = r.pushed_by
    LEFT JOIN api_tokens t ON t.id = r.source_token_id
    ORDER BY r.started_at DESC
    LIMIT 1
  `).get();
  if (!row) return c.json({ run: null });
  return c.json({ run: row });
});
