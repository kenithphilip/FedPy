/**
 * Tests for server/routes/collector_runs.ts — the input validation hardening
 * added in the Batch 3 audit: datetime validation, integer coercion, and
 * invalid-JSON / missing-field rejection.
 */
import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { Hono } from 'hono';

let tmpDir: string;

vi.mock('../auth.ts', async () => {
  const real = await vi.importActual<any>('../auth.ts');
  return {
    ...real,
    requireAuth: async (c: any, next: any) => {
      c.set('user', { id: 1, email: 'admin@example.com', name: 'Admin', role: 'admin' });
      c.set('apiToken', null);
      return next();
    },
  };
});

beforeAll(async () => {
  tmpDir = mkdtempSync(resolve(tmpdir(), 'tracker-cr-'));
  process.env.DB_PATH = resolve(tmpDir, 'cr-test.db');
});

afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

async function mkApp() {
  const { db } = await import('../db.ts');
  db().prepare('DELETE FROM collector_runs').run();
  // Seed the acting user (id=1) so the pushed_by FK on collector_runs resolves.
  db().prepare(`INSERT OR IGNORE INTO users (id, email, name, password_hash, role) VALUES (?, ?, ?, ?, ?)`)
    .run(1, 'admin@example.com', 'Admin', 'x', 'admin');
  const { collectorRunRoutes } = await import('./collector_runs.ts');
  const app = new Hono();
  app.route('/', collectorRunRoutes);
  return app;
}

async function post(app: Hono, body: string): Promise<{ status: number; body: any }> {
  const res = await app.fetch(new Request('http://localhost/collector-runs', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body,
  }));
  return { status: res.status, body: await res.json().catch(() => null) };
}

describe('POST /collector-runs validation', () => {
  it('rejects invalid JSON with 400', async () => {
    const app = await mkApp();
    const r = await post(app, '{ not json');
    expect(r.status).toBe(400);
    expect(r.body.error).toBe('invalid JSON body');
  });

  it('requires run_id', async () => {
    const app = await mkApp();
    const r = await post(app, JSON.stringify({ started_at: '2026-05-27T12:00:00Z' }));
    expect(r.status).toBe(400);
  });

  it('rejects a non-datetime started_at', async () => {
    const app = await mkApp();
    const r = await post(app, JSON.stringify({ run_id: 'r1', started_at: 'not-a-date' }));
    expect(r.status).toBe(400);
    expect(r.body.error).toMatch(/started_at/);
  });

  it('rejects a non-datetime finished_at when provided', async () => {
    const app = await mkApp();
    const r = await post(app, JSON.stringify({ run_id: 'r1', started_at: '2026-05-27T12:00:00Z', finished_at: 'garbage' }));
    expect(r.status).toBe(400);
    expect(r.body.error).toMatch(/finished_at/);
  });

  it('accepts a valid payload and coerces garbage integer fields to 0', async () => {
    const app = await mkApp();
    const r = await post(app, JSON.stringify({
      run_id: 'r-ok',
      started_at: '2026-05-27T12:00:00Z',
      total_ksis: 'abc',     // garbage → 0
      passed_ksis: -5,       // negative → 0
      failed_ksis: 3.9,      // float → floored to 3
    }));
    expect(r.status).toBe(200);

    const { db } = await import('../db.ts');
    const row = db().prepare(`SELECT total_ksis, passed_ksis, failed_ksis FROM collector_runs WHERE run_id = 'r-ok'`).get() as any;
    expect(row.total_ksis).toBe(0);
    expect(row.passed_ksis).toBe(0);
    expect(row.failed_ksis).toBe(3);
  });

  it('rejects an over-long run_id', async () => {
    const app = await mkApp();
    const r = await post(app, JSON.stringify({ run_id: 'x'.repeat(201), started_at: '2026-05-27T12:00:00Z' }));
    expect(r.status).toBe(400);
  });
});
