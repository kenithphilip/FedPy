/**
 * CSRF protection (double-submit cookie pattern).
 *
 * Why CSRF matters here:
 *   The session cookie uses SameSite=Strict, which already prevents most
 *   cross-site form posts in modern browsers. SameSite=Strict is NOT a
 *   complete defense though:
 *     - Subdomain attacks: an XSS on a different subdomain of the same site
 *       can still POST with the cookie attached.
 *     - Legacy browsers (IE <11) ignore SameSite entirely.
 *     - Some CDN / reverse-proxy configurations strip SameSite on rewrite.
 *   So we add belt-and-suspenders: a CSRF token bound to the session.
 *
 * Algorithm (double-submit cookie):
 *   1. On session creation we issue a long random `csrf` cookie alongside
 *      the session cookie. The cookie is NOT HttpOnly (the client must read
 *      it).
 *   2. The client must include the cookie value in the `X-CSRF-Token` header
 *      on every state-changing request (POST/PUT/PATCH/DELETE).
 *   3. The server checks that the header matches the cookie. Since an
 *      attacker on a different origin cannot read the cookie value (same-
 *      origin policy), they cannot forge the header — even if the cookie is
 *      auto-attached.
 *
 * Notes:
 *   - GET / HEAD / OPTIONS are skipped (per RFC 9110, these MUST be safe).
 *   - API-token auth (Bearer header) skips CSRF — those are not browser-
 *     mediated and never carry an auto-attached session cookie.
 *   - The CSRF cookie is rotated on each login so a logout/login pair
 *     invalidates the old token.
 */
import type { Context, MiddlewareHandler } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { randomBytes, timingSafeEqual } from 'node:crypto';

const CSRF_COOKIE = 'fr20x_csrf';
const CSRF_HEADER = 'X-CSRF-Token';
const CSRF_TTL_SEC = 60 * 60 * 24 * 14; // 14 days; same as session

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export function generateCsrfToken(): string {
  return randomBytes(32).toString('base64url');
}

export function setCsrfCookie(c: Context, token: string): void {
  setCookie(c, CSRF_COOKIE, token, {
    httpOnly: false,           // client must read it
    sameSite: 'Strict',
    path: '/',
    secure: process.env.NODE_ENV === 'production',
    maxAge: CSRF_TTL_SEC,
  });
}

export function clearCsrfCookie(c: Context): void {
  deleteCookie(c, CSRF_COOKIE, { path: '/' });
}

export function readCsrfCookie(c: Context): string | undefined {
  return getCookie(c, CSRF_COOKIE);
}

/**
 * Middleware: enforce CSRF on state-changing requests.
 *
 * Skipped automatically for:
 *   - Safe methods (GET/HEAD/OPTIONS)
 *   - Bearer-token requests (auth header starts with "Bearer ")
 *   - Optional skip routes (e.g. /api/auth/login itself, where there's no
 *     session yet)
 */
export interface CsrfOptions {
  /** Path prefixes where CSRF check is skipped (e.g. ['/api/auth/login']). */
  skipPaths?: string[];
}

export function csrfMiddleware(opts: CsrfOptions = {}): MiddlewareHandler {
  const skipPaths = opts.skipPaths ?? [];
  return async (c, next) => {
    const method = c.req.method.toUpperCase();
    if (SAFE_METHODS.has(method)) return next();
    // Bearer-token requests are exempt — they're not browser-mediated.
    const authHeader = c.req.header('authorization') ?? c.req.header('Authorization');
    if (authHeader?.startsWith('Bearer ')) return next();

    const path = new URL(c.req.url).pathname;
    for (const p of skipPaths) {
      if (path === p || path.startsWith(p + '/')) return next();
    }

    const cookieToken = readCsrfCookie(c);
    const headerToken = c.req.header(CSRF_HEADER) ?? c.req.header(CSRF_HEADER.toLowerCase());
    if (!cookieToken || !headerToken) {
      return c.json({ error: 'csrf_missing', message: 'CSRF token cookie + header are required for this request.' }, 403);
    }
    // If a client or proxy sends X-CSRF-Token more than once, Node joins the
    // values with ", ". Reject explicitly rather than letting the comma-joined
    // value fail the constant-time compare with a confusing "mismatch".
    if (headerToken.includes(',')) {
      return c.json({ error: 'csrf_duplicate', message: 'Multiple X-CSRF-Token headers received; send exactly one.' }, 403);
    }
    const a = Buffer.from(cookieToken);
    const b = Buffer.from(headerToken);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      return c.json({ error: 'csrf_mismatch', message: 'CSRF token header does not match cookie.' }, 403);
    }
    return next();
  };
}

/**
 * Endpoint that returns a fresh CSRF token. Useful for SPAs that need to
 * obtain the token after a soft page reload.
 */
export function csrfTokenEndpoint(c: Context): Response {
  // If no cookie present, mint one.
  let token = readCsrfCookie(c);
  if (!token) {
    token = generateCsrfToken();
    setCsrfCookie(c, token);
  }
  return c.json({ csrf_token: token });
}
