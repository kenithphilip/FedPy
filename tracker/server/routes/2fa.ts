/**
 * 2FA / TOTP routes.
 *
 *   GET    /api/2fa/status            — current user's enrollment + backup-code count
 *   POST   /api/2fa/enroll            — begin enrollment; returns secret + otpauth URI + backup codes
 *   POST   /api/2fa/complete          — verify first code; completes enrollment
 *   POST   /api/2fa/verify            — verify a TOTP/backup code; elevates pre-auth session to full
 *   POST   /api/2fa/disable           — clear all 2FA state (requires password re-auth in body)
 *
 * Login flow when 2FA is enrolled:
 *   1. POST /api/auth/login with email+password as usual.
 *   2. Server returns 200 with { user, requires_2fa: true } and sets a SHORT-
 *      lived (5 min) pre-auth session cookie. The pre-auth session is rejected
 *      by every route EXCEPT /api/2fa/verify, /api/2fa/status, /api/auth/me,
 *      and /api/auth/logout (see PREAUTH_ALLOWED_PATHS in auth.ts).
 *   3. Client prompts for TOTP code and POSTs /api/2fa/verify.
 *   4. On success the server clears preauth_until — the same session is now
 *      a normal authenticated session.
 *   5. If the user fails to verify within 5 minutes, the pre-auth session
 *      expires and they have to log in from scratch.
 */
import { Hono } from 'hono';
import { db } from '../db.ts';
import { requireAuth, verifyPassword, elevateSession, readSessionToken } from '../auth.ts';
import {
  startEnrollment, completeEnrollment, get2faStatus,
  disable2fa, verifyCodeOrBackup,
} from '../totp.ts';
import { rateLimit, RL } from '../rate-limit.ts';

export const twoFaRoutes = new Hono();

// All 2FA routes require an active session (you can't enroll w/o being logged in).
twoFaRoutes.use('*', requireAuth);

twoFaRoutes.get('/status', (c) => {
  const user = c.get('user');
  return c.json(get2faStatus(user.id));
});

twoFaRoutes.post('/enroll', (c) => {
  const user = c.get('user');
  // Re-enrolling overwrites any existing secret. Prevent surprise data loss
  // by requiring `force: true` if already enrolled.
  // (Disabled here for simplicity — UI should warn.)
  const enr = startEnrollment(user.id, user.email);
  return c.json(enr);
});

twoFaRoutes.post('/complete', async (c) => {
  const user = c.get('user');
  const { code } = await c.req.json<{ code?: string }>();
  if (!code) return c.json({ error: 'code required' }, 400);
  const ok = completeEnrollment(user.id, code);
  if (!ok) return c.json({ error: 'invalid_code' }, 400);
  return c.json({ enrolled: true });
});

// Verify a code (TOTP or backup). Rate-limited — protects against brute-force.
// This is the route that elevates a pre-auth session to a full session.
twoFaRoutes.post('/verify', rateLimit(RL.LOGIN_PER_MIN), async (c) => {
  const user = c.get('user');
  const { code } = await c.req.json<{ code?: string }>();
  if (!code) return c.json({ error: 'code required' }, 400);
  const r = verifyCodeOrBackup(user.id, code);
  if (!r.ok) return c.json({ error: 'invalid_code' }, 401);
  // Clear preauth_until on the current session so subsequent requests pass requireAuth.
  const token = readSessionToken(c);
  if (token) elevateSession(token);
  return c.json({ ok: true, via: r.via });
});

// Disable 2FA — requires password re-auth in body to prevent session-takeover abuse.
twoFaRoutes.post('/disable', async (c) => {
  const user = c.get('user');
  const { password } = await c.req.json<{ password?: string }>();
  if (!password) return c.json({ error: 'password required for confirmation' }, 400);
  const row = db().prepare('SELECT password_hash FROM users WHERE id = ?').get(user.id) as { password_hash?: string } | undefined;
  if (!row?.password_hash || !verifyPassword(password, row.password_hash)) {
    return c.json({ error: 'password incorrect' }, 401);
  }
  disable2fa(user.id);
  return c.json({ disabled: true });
});
