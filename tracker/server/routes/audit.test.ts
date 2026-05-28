/**
 * Tests for server/routes/audit.ts — search/filter/CSV endpoints.
 *
 * This test exercises the REAL `auditRoutes` Hono module. We mock the auth +
 * permission middleware by intercepting `lookupSession` so it returns an
 * authorized auditor, then mount `auditRoutes` and issue in-memory requests.
 * Replacement of the inline-SQL stub that previously shadowed the real route
 * (caught by the 2026-05 audit).
 */
import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { Hono } from 'hono';

let tmpDir: string;
let app: Hono;

// Stub: act as if the request carries a valid auditor session cookie.
vi.mock('../auth.ts', async () => {
  const real = await vi.importActual<any>('../auth.ts');
  return {
    ...real,
    requireAuth: async (c: any, next: any) => {
      c.set('user', { id: 99, email: 'auditor@example.com', name: 'Auditor', role: 'auditor' });
      return next();
    },
  };
});

beforeAll(async () => {
  tmpDir = mkdtempSync(resolve(tmpdir(), 'tracker-audit-'));
  process.env.DB_PATH = resolve(tmpDir, 'audit-test.db');

  const { db } = await import('../db.ts');
  const conn = db();

  // Seed users (using roles allowed by the relaxed CHECK)
  conn.prepare(`INSERT OR IGNORE INTO users (id, email, name, password_hash, role) VALUES (?, ?, ?, ?, ?)`)
    .run(1, 'admin@example.com', 'Admin', 'x', 'admin');
  conn.prepare(`INSERT OR IGNORE INTO users (id, email, name, password_hash, role) VALUES (?, ?, ?, ?, ?)`)
    .run(2, 'alice@example.com', 'Alice', 'x', 'contributor');

  // Seed audit events with diverse fields/timestamps
  const insert = conn.prepare(
    `INSERT INTO audit_log (user_id, item_id, item_type, field, old_value, new_value, changed_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  );
  insert.run(1, 'KSI-IAM-MFA', 'indicator', 'status', 'not_started', 'in_progress', '2026-05-01T12:00:00');
  insert.run(2, 'KSI-IAM-MFA', 'indicator', 'notes', null, 'updating', '2026-05-02T12:00:00');
  insert.run(1, 'user:2', 'rbac', 'role', 'member', 'contributor', '2026-05-03T12:00:00');
  insert.run(1, 'KSI-MLA-EVC', 'indicator', 'status', 'in_progress', 'met', '2026-05-04T12:00:00');
  insert.run(null, 'KSI-MLA-EVC', 'indicator', 'status', 'met', 'in_progress', '2026-05-05T12:00:00'); // system actor

  // Mount the REAL auditRoutes module. Auth + permission middleware run, but
  // requireAuth above seeds an auditor user so requirePermission('read:audit_log')
  // succeeds.
  const { auditRoutes } = await import('./audit.ts');
  app = new Hono();
  app.route('/', auditRoutes);
});

afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

async function get(path: string): Promise<{ status: number; json: any; bodyText?: string; headers: Headers }> {
  const res = await app.fetch(new Request(`http://localhost${path}`));
  const headers = res.headers;
  const ct = headers.get('content-type') ?? '';
  if (ct.includes('application/json')) {
    return { status: res.status, json: await res.json(), headers };
  }
  return { status: res.status, json: null, bodyText: await res.text(), headers };
}

describe('audit log search (REAL auditRoutes module)', () => {
  it('returns all rows when no filters', async () => {
    const r = await get('/');
    expect(r.status).toBe(200);
    expect(r.json.total).toBe(5);
    expect(r.json.rows.length).toBe(5);
  });

  it('filters by actor user_id', async () => {
    const r = await get('/?actor=1');
    expect(r.json.total).toBe(3);
  });

  it('filters by null actor (system / api token)', async () => {
    const r = await get('/?actor=');
    expect(r.json.total).toBe(1);
  });

  it('filters by field/action', async () => {
    const r = await get('/?action=status');
    expect(r.json.total).toBe(3);
  });

  it('filters by item substring', async () => {
    const r = await get('/?item=IAM-MFA');
    expect(r.json.total).toBe(2);
  });

  it('filters by item_type', async () => {
    const r = await get('/?item_type=rbac');
    expect(r.json.total).toBe(1);
  });

  it('filters by date range', async () => {
    const r = await get('/?from=2026-05-02T00:00:00&to=2026-05-04T23:59:59');
    expect(r.json.total).toBe(3);
  });

  it('honors limit', async () => {
    const r = await get('/?limit=2');
    expect(r.json.total).toBe(5);
    expect(r.json.rows.length).toBe(2);
  });

  it('combines filters with AND', async () => {
    const r = await get('/?actor=1&action=status');
    expect(r.json.total).toBe(2);  // user_id=1 + field=status
  });

  it('includes joined user email/name on each row', async () => {
    const r = await get('/?action=role');
    expect(r.json.total).toBe(1);
    expect(r.json.rows[0].user_email).toBe('admin@example.com');
    expect(r.json.rows[0].user_name).toBe('Admin');
  });

  it('exposes pagination offset', async () => {
    const r = await get('/?limit=2&offset=2');
    expect(r.json.limit).toBe(2);
    expect(r.json.offset).toBe(2);
    expect(r.json.rows.length).toBe(2);
  });
});

describe('audit log facets (REAL auditRoutes module)', () => {
  it('returns distinct actions, item_types, and actors', async () => {
    const r = await get('/facets');
    expect(r.status).toBe(200);
    expect(r.json.actions).toEqual(expect.arrayContaining(['status', 'notes', 'role']));
    expect(r.json.item_types).toEqual(expect.arrayContaining(['indicator', 'rbac']));
    expect(r.json.actors.length).toBeGreaterThanOrEqual(1);
  });
});

describe('audit log CSV export (REAL auditRoutes module)', () => {
  it('returns text/csv with a header row + per-event rows', async () => {
    const r = await get('/csv');
    expect(r.status).toBe(200);
    expect(r.headers.get('content-type')).toMatch(/text\/csv/);
    expect(r.headers.get('content-disposition')).toMatch(/attachment.*audit-log-/);
    const lines = (r.bodyText ?? '').split('\n');
    expect(lines[0]).toMatch(/^changed_at,user_email,user_name,/);
    expect(lines.length).toBeGreaterThan(1);
  });

  it('CSV-escapes values containing commas / quotes / newlines', async () => {
    const { db } = await import('../db.ts');
    db().prepare(
      `INSERT INTO audit_log (user_id, item_id, item_type, field, old_value, new_value, changed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(1, 'KSI-TEST-CSV', 'indicator', 'notes', 'old, val', 'has "quotes"', '2026-05-06T12:00:00');
    const r = await get('/csv?item=KSI-TEST-CSV');
    expect(r.bodyText).toContain('"old, val"');
    expect(r.bodyText).toContain('"has ""quotes"""');
  });
});
