/**
 * Tests for server/db.ts — the production-readiness hardening from the Batch 3
 * audit: busy_timeout pragma, a startup health check, and an actionable error
 * when the database file can't be opened.
 *
 * NOTE: db.ts reads DB_PATH + TRACKER_DB_BUSY_TIMEOUT_MS at module-load time,
 * so each scenario sets the env vars then uses `vi.resetModules()` +
 * dynamic import to get a fresh module instance.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';

const created: string[] = [];

afterEach(() => {
  vi.resetModules();
  for (const d of created.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe('db() initialization', () => {
  it('applies the configured busy_timeout and passes the health check', async () => {
    const dir = mkdtempSync(resolve(tmpdir(), 'tracker-dbinit-'));
    created.push(dir);
    process.env.DB_PATH = resolve(dir, 'ok.db');
    process.env.TRACKER_DB_BUSY_TIMEOUT_MS = '7000';
    vi.resetModules();

    const { db, closeDb } = await import('./db.ts');
    const conn = db();
    const bt = conn.pragma('busy_timeout', { simple: true });
    expect(Number(bt)).toBe(7000);
    // Health check query the module runs on open should also work for us.
    expect((conn.prepare('SELECT 1 AS ok').get() as any).ok).toBe(1);
    closeDb();
  });

  it('throws an actionable error when the DB file cannot be opened', async () => {
    process.env.DB_PATH = '/this/path/surely/does/not/exist/tracker.db';
    delete process.env.TRACKER_DB_BUSY_TIMEOUT_MS;
    vi.resetModules();

    const { db } = await import('./db.ts');
    expect(() => db()).toThrowError(/Failed to open tracker database/);
  });
});
