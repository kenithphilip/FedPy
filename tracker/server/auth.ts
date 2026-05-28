import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import type { Context, MiddlewareHandler } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { db } from './db.ts';

const SESSION_COOKIE = 'fr20x_sid';
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 14; // 14 days

// ---- Password hashing (scrypt; no native deps) ----
const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LEN = 64;

export function hashPassword(password: string): string {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, KEY_LEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P });
  return `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString('hex')}$${hash.toString('hex')}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const N = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  const salt = Buffer.from(parts[4]!, 'hex');
  const expected = Buffer.from(parts[5]!, 'hex');
  const actual = scryptSync(password, salt, expected.length, { N, r, p });
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

// ---- Sessions ----
export interface SessionUser {
  id: number;
  email: string;
  name: string;
  role: 'admin' | 'member';
}

function newToken(): string {
  return randomBytes(32).toString('base64url');
}

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

/** Default pre-auth window for sessions awaiting 2FA verification. */
const PREAUTH_WINDOW_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Create a session. When `preauthSeconds` is provided, the session is marked
 * pre-auth and only the 2FA verify route (and logout) will accept it. The
 * /api/2fa/verify handler is expected to call elevateSession() on success.
 */
export function createSession(userId: number, preauthSeconds?: number): string {
  const token = newToken();
  const tokenHash = hashToken(token);
  const expires = new Date(Date.now() + SESSION_TTL_MS).toISOString();
  const preauthUntil = preauthSeconds
    ? new Date(Date.now() + preauthSeconds * 1000).toISOString()
    : null;
  db().prepare(
    `INSERT INTO sessions (token, user_id, expires_at, preauth_until) VALUES (?, ?, ?, ?)`
  ).run(tokenHash, userId, expires, preauthUntil);
  return token;
}

/** Upgrade a pre-auth session to a fully-authenticated session. */
export function elevateSession(token: string): boolean {
  const info = db().prepare(`UPDATE sessions SET preauth_until = NULL WHERE token = ?`).run(hashToken(token));
  return info.changes > 0;
}

export function destroySession(token: string): void {
  db().prepare(`DELETE FROM sessions WHERE token = ?`).run(hashToken(token));
}

export interface LookupResult {
  user: SessionUser;
  preauth: boolean;
}

export function lookupSession(token: string): LookupResult | null {
  const row = db().prepare(`
    SELECT u.id, u.email, u.name, u.role, s.expires_at, s.preauth_until
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token = ?
  `).get(hashToken(token)) as any;
  if (!row) return null;
  const now = Date.now();
  if (new Date(row.expires_at).getTime() < now) {
    db().prepare(`DELETE FROM sessions WHERE token = ?`).run(hashToken(token));
    return null;
  }
  // Pre-auth window expired before 2FA verify? Invalidate the session.
  if (row.preauth_until && new Date(row.preauth_until).getTime() < now) {
    db().prepare(`DELETE FROM sessions WHERE token = ?`).run(hashToken(token));
    return null;
  }
  return {
    user: { id: row.id, email: row.email, name: row.name, role: row.role },
    preauth: row.preauth_until != null,
  };
}

/** Constant: how long pre-auth sessions stay valid before requiring re-login. */
export const PREAUTH_WINDOW_SEC = Math.floor(PREAUTH_WINDOW_MS / 1000);

// ---- User CRUD helpers ----
export function userCount(): number {
  return (db().prepare(`SELECT COUNT(*) AS c FROM users`).get() as any).c;
}

export function createUser(email: string, name: string, password: string, role: 'admin' | 'member' = 'member'): SessionUser {
  const hash = hashPassword(password);
  const info = db().prepare(
    `INSERT INTO users (email, name, password_hash, role) VALUES (?, ?, ?, ?)`
  ).run(email.toLowerCase().trim(), name.trim(), hash, role);
  const id = Number(info.lastInsertRowid);
  return { id, email: email.toLowerCase().trim(), name: name.trim(), role };
}

export function findUserByEmail(email: string): { id: number; email: string; name: string; password_hash: string; role: 'admin' | 'member' } | null {
  const row = db().prepare(
    `SELECT id, email, name, password_hash, role FROM users WHERE email = ?`
  ).get(email.toLowerCase().trim()) as any;
  return row ?? null;
}

// ---- Cookie helpers ----
export function setSessionCookie(c: Context, token: string): void {
  setCookie(c, SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: 'Strict',
    path: '/',
    secure: process.env.NODE_ENV === 'production',
    maxAge: SESSION_TTL_MS / 1000,
  });
}

export function clearSessionCookie(c: Context): void {
  deleteCookie(c, SESSION_COOKIE, { path: '/' });
}

export function readSessionToken(c: Context): string | undefined {
  return getCookie(c, SESSION_COOKIE);
}

// ---- Middleware ----
declare module 'hono' {
  interface ContextVariableMap {
    user: SessionUser;
  }
}

// ---- API tokens (for headless integrations) ----

export interface ApiTokenInfo {
  id: number;
  name: string;
  scope: 'patch:indicators' | 'patch:all' | 'read:all';
}

export function createApiToken(name: string, scope: ApiTokenInfo['scope'], createdBy: number, ttlDays?: number): { id: number; rawToken: string } {
  const raw = `cev_${randomBytes(24).toString('base64url')}`;
  const hashed = hashToken(raw);
  const expires = ttlDays ? new Date(Date.now() + ttlDays * 86400_000).toISOString() : null;
  const info = db().prepare(
    `INSERT INTO api_tokens (token_hash, name, scope, created_by, expires_at) VALUES (?, ?, ?, ?, ?)`
  ).run(hashed, name, scope, createdBy, expires);
  return { id: Number(info.lastInsertRowid), rawToken: raw };
}

export function lookupApiToken(raw: string): ApiTokenInfo | null {
  const hashed = hashToken(raw);
  const row = db().prepare(
    `SELECT id, name, scope, expires_at, revoked_at FROM api_tokens WHERE token_hash = ?`
  ).get(hashed) as any;
  if (!row) return null;
  if (row.revoked_at) return null;
  if (row.expires_at && new Date(row.expires_at).getTime() < Date.now()) return null;
  db().prepare(`UPDATE api_tokens SET last_used = datetime('now') WHERE id = ?`).run(row.id);
  return { id: row.id, name: row.name, scope: row.scope };
}

declare module 'hono' {
  interface ContextVariableMap {
    apiToken: ApiTokenInfo;
  }
}

/**
 * Routes that accept pre-auth sessions (sessions awaiting 2FA verification).
 * Pre-auth sessions are otherwise treated as unauthenticated.
 */
const PREAUTH_ALLOWED_PATHS = new Set([
  '/api/2fa/verify',
  '/api/2fa/status',
  '/api/auth/logout',
  '/api/auth/me',
]);

export const requireAuth: MiddlewareHandler = async (c, next) => {
  // Try Bearer-token auth first (for headless integrations)
  const authHeader = c.req.header('authorization') ?? c.req.header('Authorization');
  if (authHeader?.startsWith('Bearer ')) {
    const raw = authHeader.slice('Bearer '.length).trim();
    const info = lookupApiToken(raw);
    if (info) {
      c.set('apiToken', info);
      // For middleware-compatibility, also synthesize a minimal user object.
      c.set('user', { id: 0, email: `api-token:${info.id}`, name: info.name, role: 'member' });
      return await next();
    }
    return c.json({ error: 'invalid api token' }, 401);
  }
  // Fall back to session-cookie auth
  const token = readSessionToken(c);
  const session = token ? lookupSession(token) : null;
  if (!session) return c.json({ error: 'unauthorized' }, 401);

  // Pre-auth sessions can only reach the small allowlist of 2FA / logout routes.
  if (session.preauth) {
    const path = new URL(c.req.url).pathname;
    if (!PREAUTH_ALLOWED_PATHS.has(path)) {
      return c.json({ error: '2fa_required', message: '2FA verification required to complete login.' }, 401);
    }
  }
  c.set('user', session.user);
  await next();
};

export const requireAdmin: MiddlewareHandler = async (c, next) => {
  const token = readSessionToken(c);
  const session = token ? lookupSession(token) : null;
  if (!session) return c.json({ error: 'unauthorized' }, 401);
  if (session.preauth) return c.json({ error: '2fa_required' }, 401);
  if (session.user.role !== 'admin') return c.json({ error: 'forbidden' }, 403);
  c.set('user', session.user);
  await next();
};
