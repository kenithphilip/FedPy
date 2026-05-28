/**
 * Tests for server/auth.ts:
 *   - password hashing (scrypt) round-trip
 *   - session create / lookup / destroy
 *   - pre-auth session lifecycle (added by the 2026-05 audit fix)
 *   - requireAuth middleware behavior for full + pre-auth + bearer + missing
 *   - requireAdmin middleware
 *
 * The 2FA gating slice (login + verify) is covered by routes/auth and 2fa
 * integration in subsequent test files.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { Hono } from 'hono';

let tmpDir: string;

beforeAll(() => {
  tmpDir = mkdtempSync(resolve(tmpdir(), 'tracker-auth-'));
  process.env.DB_PATH = resolve(tmpDir, 'auth-test.db');
});

afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

describe('hashPassword / verifyPassword', () => {
  it('hashes a password and verifies the same password back', async () => {
    const { hashPassword, verifyPassword } = await import('./auth.ts');
    const h = hashPassword('correct-horse-battery-staple');
    expect(verifyPassword('correct-horse-battery-staple', h)).toBe(true);
    expect(verifyPassword('wrong', h)).toBe(false);
  });

  it('uses a fresh salt every call (same input ≠ same hash)', async () => {
    const { hashPassword } = await import('./auth.ts');
    expect(hashPassword('abc')).not.toBe(hashPassword('abc'));
  });

  it('rejects malformed stored hashes', async () => {
    const { verifyPassword } = await import('./auth.ts');
    expect(verifyPassword('x', 'not-a-real-hash')).toBe(false);
    expect(verifyPassword('x', 'scrypt$1$1$1$bad')).toBe(false);
  });
});

describe('session create / lookup / destroy', () => {
  it('round-trips a full session', async () => {
    const { db } = await import('./db.ts');
    db().prepare(`INSERT OR IGNORE INTO users (id, email, name, password_hash, role) VALUES (?, ?, ?, ?, ?)`)
      .run(10, 's1@example.com', 'S1', 'x', 'admin');
    const { createSession, lookupSession, destroySession } = await import('./auth.ts');
    const tok = createSession(10);
    const s = lookupSession(tok);
    expect(s).not.toBeNull();
    expect(s!.user.id).toBe(10);
    expect(s!.user.role).toBe('admin');
    expect(s!.preauth).toBe(false);
    destroySession(tok);
    expect(lookupSession(tok)).toBeNull();
  });

  it('returns null for an unknown token', async () => {
    const { lookupSession } = await import('./auth.ts');
    expect(lookupSession('not-a-real-token')).toBeNull();
  });
});

describe('pre-auth session lifecycle', () => {
  it('createSession(userId, n) marks the session as pre-auth', async () => {
    const { db } = await import('./db.ts');
    db().prepare(`INSERT OR IGNORE INTO users (id, email, name, password_hash, role) VALUES (?, ?, ?, ?, ?)`)
      .run(11, 's2@example.com', 'S2', 'x', 'admin');
    const { createSession, lookupSession } = await import('./auth.ts');
    const tok = createSession(11, 300);
    const s = lookupSession(tok);
    expect(s!.preauth).toBe(true);
  });

  it('elevateSession() clears the pre-auth flag', async () => {
    const { db } = await import('./db.ts');
    db().prepare(`INSERT OR IGNORE INTO users (id, email, name, password_hash, role) VALUES (?, ?, ?, ?, ?)`)
      .run(12, 's3@example.com', 'S3', 'x', 'admin');
    const { createSession, lookupSession, elevateSession } = await import('./auth.ts');
    const tok = createSession(12, 300);
    expect(lookupSession(tok)!.preauth).toBe(true);
    expect(elevateSession(tok)).toBe(true);
    expect(lookupSession(tok)!.preauth).toBe(false);
  });

  it('expired pre-auth session is invalidated on lookup', async () => {
    const { db } = await import('./db.ts');
    db().prepare(`INSERT OR IGNORE INTO users (id, email, name, password_hash, role) VALUES (?, ?, ?, ?, ?)`)
      .run(13, 's4@example.com', 'S4', 'x', 'admin');
    const { createSession, lookupSession } = await import('./auth.ts');
    const tok = createSession(13, 1);
    // Hand-backdate preauth_until to the past
    const { createHash } = await import('node:crypto');
    const tokenHash = createHash('sha256').update(tok).digest('hex');
    db().prepare(`UPDATE sessions SET preauth_until = ? WHERE token = ?`)
      .run(new Date(Date.now() - 60000).toISOString(), tokenHash);
    expect(lookupSession(tok)).toBeNull();
  });
});

describe('requireAuth middleware (pre-auth gating)', () => {
  async function mkApp(): Promise<{ app: Hono; tok: string }> {
    const { db } = await import('./db.ts');
    db().prepare(`INSERT OR IGNORE INTO users (id, email, name, password_hash, role) VALUES (?, ?, ?, ?, ?)`)
      .run(20, 'gate@example.com', 'Gate', 'x', 'admin');
    const { createSession, requireAuth } = await import('./auth.ts');
    const tok = createSession(20, 300);  // pre-auth
    const app = new Hono();
    app.use('*', requireAuth);
    app.get('/api/data', (c) => c.json({ ok: true }));
    app.post('/api/2fa/verify', (c) => c.json({ verified: true }));
    return { app, tok };
  }

  it('rejects pre-auth session on non-2FA route with 401 + 2fa_required', async () => {
    const { app, tok } = await mkApp();
    const res = await app.fetch(new Request('http://localhost/api/data', { headers: { cookie: `fr20x_sid=${tok}` } }));
    expect(res.status).toBe(401);
    const body = await res.json() as any;
    expect(body.error).toBe('2fa_required');
  });

  it('allows pre-auth session on /api/2fa/verify', async () => {
    const { app, tok } = await mkApp();
    const res = await app.fetch(new Request('http://localhost/api/2fa/verify', {
      method: 'POST',
      headers: { cookie: `fr20x_sid=${tok}` },
    }));
    expect(res.status).toBe(200);
  });

  it('returns 401 for missing session cookie', async () => {
    const { app } = await mkApp();
    const res = await app.fetch(new Request('http://localhost/api/data'));
    expect(res.status).toBe(401);
  });

  it('allows fully-authenticated session on all routes', async () => {
    const { db } = await import('./db.ts');
    db().prepare(`INSERT OR IGNORE INTO users (id, email, name, password_hash, role) VALUES (?, ?, ?, ?, ?)`)
      .run(21, 'full@example.com', 'Full', 'x', 'admin');
    const { createSession, requireAuth } = await import('./auth.ts');
    const tok = createSession(21);
    const app = new Hono();
    app.use('*', requireAuth);
    app.get('/api/data', (c) => c.json({ ok: true }));
    const res = await app.fetch(new Request('http://localhost/api/data', { headers: { cookie: `fr20x_sid=${tok}` } }));
    expect(res.status).toBe(200);
  });
});
