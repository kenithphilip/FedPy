/**
 * LOOP-B.B3 — Verify the additive migration on an EXISTING tracker DB.
 *
 * The B.B3 role expansion (adding iso/ao/assessor to users.role CHECK) must widen
 * a pre-existing database WITHOUT losing user data. This seeds a DB carrying the
 * pre-B.B3 6-role CHECK + real rows, opens it through the real db() layer (which
 * runs migrate()), and asserts: (1) prior rows survive, (2) the new roles are now
 * insertable, (3) the B.B3 tables exist.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Database from 'better-sqlite3';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';

let tmpDir: string;
let dbPath: string;

beforeAll(() => {
  tmpDir = mkdtempSync(resolve(tmpdir(), 'tracker-ramig-'));
  dbPath = resolve(tmpDir, 'existing.db');
  // Simulate a pre-B.B3 existing DB: users with the old 6-role CHECK + real data.
  const d = new Database(dbPath);
  d.exec(`CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('viewer','contributor','ksi-owner','auditor','admin','member')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    totp_secret_b32 TEXT, totp_enrolled_at TEXT, totp_backup_codes TEXT, require_2fa INTEGER NOT NULL DEFAULT 0
  );`);
  d.prepare(`INSERT INTO users (id, email, name, password_hash, role) VALUES (1, 'keep@x', 'Keep', 'hash-preserved', 'admin')`).run();
  d.close();
  process.env.DB_PATH = dbPath;
});

afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

describe('B.B3 migration on an existing DB', () => {
  it('widens the role CHECK to iso/ao/assessor, preserves data, and creates the new tables', async () => {
    const { db } = await import('./db.ts');
    const conn = db();

    // 1. Prior data survives the users-table rebuild.
    const kept = conn.prepare(`SELECT email, role, password_hash FROM users WHERE id = 1`).get() as any;
    expect(kept.email).toBe('keep@x');
    expect(kept.role).toBe('admin');
    expect(kept.password_hash).toBe('hash-preserved');

    // 2. The B.B3 separation-of-duties roles are now insertable.
    expect(() => conn.prepare(`INSERT INTO users (email,name,password_hash,role) VALUES ('ao@x','AO','h','ao')`).run()).not.toThrow();
    expect(() => conn.prepare(`INSERT INTO users (email,name,password_hash,role) VALUES ('iso@x','ISO','h','iso')`).run()).not.toThrow();
    expect(() => conn.prepare(`INSERT INTO users (email,name,password_hash,role) VALUES ('as@x','AS','h','assessor')`).run()).not.toThrow();

    // 3. The B.B3 tables exist.
    const tables = (conn.prepare(
      `SELECT name FROM sqlite_master WHERE type='table' AND name IN ('risk_acceptances','risk_acceptance_compensating_links','signing_keys')`,
    ).all() as Array<{ name: string }>).map((r) => r.name).sort();
    expect(tables).toEqual(['risk_acceptance_compensating_links', 'risk_acceptances', 'signing_keys']);
  });
});
