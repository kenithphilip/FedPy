import { Hono } from 'hono';
import {
  clearSessionCookie,
  createSession,
  createUser,
  destroySession,
  findUserByEmail,
  lookupSession,
  PREAUTH_WINDOW_SEC,
  readSessionToken,
  requireAuth,
  setSessionCookie,
  userCount,
  verifyPassword,
} from '../auth.ts';
import { db } from '../db.ts';
import { rateLimit, RL } from '../rate-limit.ts';
import { generateCsrfToken, setCsrfCookie, clearCsrfCookie } from '../csrf.ts';

export const authRoutes = new Hono();

// First-user bootstrap: anyone can sign up if no users exist; they become admin.
// After that, signup is admin-gated.
authRoutes.get('/bootstrap', (c) => {
  return c.json({ needsBootstrap: userCount() === 0 });
});

authRoutes.post('/signup', rateLimit(RL.LOGIN_PER_HOUR), async (c) => {
  let email: string | undefined, name: string | undefined, password: string | undefined;
  try {
    ({ email, name, password } = await c.req.json<{ email?: string; name?: string; password?: string }>());
  } catch {
    return c.json({ error: 'invalid JSON body' }, 400);
  }
  if (!email || !name || !password) return c.json({ error: 'email, name, password required' }, 400);
  if (password.length < 8) return c.json({ error: 'password must be at least 8 characters' }, 400);
  // Upper bound: scryptSync cost scales with input length, so an unbounded
  // password is a CPU-exhaustion vector. 1024 chars is well beyond any real
  // passphrase.
  if (password.length > 1024) return c.json({ error: 'password too long (max 1024 characters)' }, 400);
  if (name.length > 200) return c.json({ error: 'name too long (max 200 characters)' }, 400);
  if (email.length > 320) return c.json({ error: 'email too long (max 320 characters)' }, 400);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return c.json({ error: 'invalid email' }, 400);

  const firstUser = userCount() === 0;
  if (!firstUser) {
    // Require admin auth
    const token = readSessionToken(c);
    const session = token ? lookupSession(token) : null;
    if (!session || session.preauth || session.user.role !== 'admin') return c.json({ error: 'admin required to add users' }, 403);
  }

  if (findUserByEmail(email)) return c.json({ error: 'email already registered' }, 409);

  const user = createUser(email, name, password, firstUser ? 'admin' : 'member');

  if (firstUser) {
    const token = createSession(user.id);
    setSessionCookie(c, token);
    setCsrfCookie(c, generateCsrfToken());
  }
  return c.json({ user });
});

authRoutes.post('/login', rateLimit(RL.LOGIN_PER_MIN), rateLimit(RL.LOGIN_PER_HOUR), async (c) => {
  let email: string | undefined, password: string | undefined;
  try {
    ({ email, password } = await c.req.json<{ email?: string; password?: string }>());
  } catch {
    return c.json({ error: 'invalid JSON body' }, 400);
  }
  if (!email || !password) return c.json({ error: 'email and password required' }, 400);
  // Reject implausibly long passwords before hitting scryptSync (CPU-DoS guard).
  if (password.length > 1024) return c.json({ error: 'invalid credentials' }, 401);
  const row = findUserByEmail(email);
  if (!row || !verifyPassword(password, row.password_hash)) {
    return c.json({ error: 'invalid credentials' }, 401);
  }
  // If 2FA is enrolled on this user, issue a SHORT-lived pre-auth session.
  // The client must call /api/2fa/verify within the window to elevate to a
  // full session; otherwise the session is invalid.
  const enrolledRow = db().prepare(`SELECT totp_enrolled_at FROM users WHERE id = ?`).get(row.id) as { totp_enrolled_at?: string } | undefined;
  const requires_2fa = !!enrolledRow?.totp_enrolled_at;

  const token = requires_2fa
    ? createSession(row.id, PREAUTH_WINDOW_SEC)
    : createSession(row.id);
  setSessionCookie(c, token);
  // Issue a fresh CSRF token bound to this session. Rotated on each login
  // so an old (possibly leaked) token cannot be used after logout/login.
  setCsrfCookie(c, generateCsrfToken());

  return c.json({
    user: { id: row.id, email: row.email, name: row.name, role: row.role },
    requires_2fa,
  });
});

authRoutes.post('/logout', requireAuth, async (c) => {
  const token = readSessionToken(c);
  if (token) destroySession(token);
  clearSessionCookie(c);
  clearCsrfCookie(c);
  return c.json({ ok: true });
});

authRoutes.get('/me', requireAuth, (c) => {
  return c.json({ user: c.get('user') });
});
