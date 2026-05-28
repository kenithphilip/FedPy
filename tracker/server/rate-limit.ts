/**
 * Per-IP / per-key rate limiting.
 *
 * Why SQLite-backed and not in-memory:
 *   - The tracker can run behind a process supervisor that restarts on
 *     OOM / deploys. In-memory state vanishes on restart, opening a
 *     re-attack window. SQLite persists across restarts.
 *   - The tracker is local-multi-user — single process — so we don't need
 *     distributed coordination. SQLite is the right scope.
 *
 * Algorithm: fixed-window with a tail-overlap correction (i.e. count this
 * window's hits + a prorated share of the previous window's hits, scaled
 * by how far into this window we are). This gives near-sliding-window
 * accuracy without per-request cost.
 *
 * Usage:
 *   import { rateLimit, RL } from '../rate-limit.ts';
 *   app.post('/login', rateLimit(RL.LOGIN), async (c) => { ... });
 *
 * Configure thresholds via env:
 *   RL_LOGIN_PER_MIN          (default 5)
 *   RL_LOGIN_PER_HOUR         (default 30)
 *   RL_TOKEN_CREATE_PER_HOUR  (default 10)
 *   RL_API_TOKEN_PER_MIN      (default 60)
 */
import type { Context, MiddlewareHandler } from 'hono';
import { db } from './db.ts';

export interface RateLimitPolicy {
  name: string;
  /** Identifier the bucket is keyed by ("ip" | "user" | "api-token"). */
  key: 'ip' | 'user' | 'api-token';
  /** Window length in seconds (e.g. 60 = 1 min, 3600 = 1 hour). */
  windowSec: number;
  /** Max hits allowed in that window. */
  limit: number;
}

/** Pre-defined policies. */
export const RL = {
  LOGIN_PER_MIN: { name: 'login:1m', key: 'ip', windowSec: 60, limit: Number(process.env.RL_LOGIN_PER_MIN ?? 5) } as RateLimitPolicy,
  LOGIN_PER_HOUR: { name: 'login:1h', key: 'ip', windowSec: 3600, limit: Number(process.env.RL_LOGIN_PER_HOUR ?? 30) } as RateLimitPolicy,
  PASSWORD_RESET: { name: 'pwreset:1h', key: 'ip', windowSec: 3600, limit: Number(process.env.RL_PASSWORD_RESET_PER_HOUR ?? 5) } as RateLimitPolicy,
  TOKEN_CREATE: { name: 'tokcreate:1h', key: 'user', windowSec: 3600, limit: Number(process.env.RL_TOKEN_CREATE_PER_HOUR ?? 10) } as RateLimitPolicy,
  API_TOKEN_USE: { name: 'apitok:1m', key: 'api-token', windowSec: 60, limit: Number(process.env.RL_API_TOKEN_PER_MIN ?? 60) } as RateLimitPolicy,
};

export function clientIp(c: Context): string {
  const xff = c.req.header('x-forwarded-for');
  if (xff) {
    const first = (xff.split(',')[0] ?? xff).trim();
    if (first) return first;
  }
  const realIp = c.req.header('x-real-ip');
  if (realIp) return realIp.trim();
  // No proxy headers (direct connection): fall back to the TCP peer address
  // from @hono/node-server so every direct client doesn't share one bucket.
  const remote = (c.env as any)?.incoming?.socket?.remoteAddress
    ?? (c.env as any)?.incoming?.connection?.remoteAddress;
  if (typeof remote === 'string' && remote) return remote;
  return 'unknown';
}

function subject(c: Context, key: RateLimitPolicy['key']): string {
  if (key === 'ip') return clientIp(c);
  if (key === 'user') {
    // Optional: per-user limits when authenticated. Falls back to IP.
    const userId = (c.get as any)('userId') ?? null;
    return userId ? `u:${userId}` : `ip:${clientIp(c)}`;
  }
  if (key === 'api-token') {
    // Tokens are identified by header value's hash, set upstream by auth middleware.
    const tokId = (c.get as any)('apiTokenId') ?? null;
    return tokId ? `t:${tokId}` : `ip:${clientIp(c)}`;
  }
  return 'unknown';
}

/**
 * Check-and-increment. Returns true if allowed, false if over the limit.
 * Uses a single SQL transaction so concurrent requests can't race past
 * the limit by exactly N (the classic fixed-window race).
 */
export function checkAndHit(policy: RateLimitPolicy, subjectKey: string): { allowed: boolean; remaining: number; retryAfterSec: number } {
  const now = Math.floor(Date.now() / 1000);
  const currentWindow = now - (now % policy.windowSec);
  const prevWindow = currentWindow - policy.windowSec;
  const elapsedInWindow = now - currentWindow;
  const overlapWeight = (policy.windowSec - elapsedInWindow) / policy.windowSec;

  const key = `${policy.name}|${subjectKey}`;

  const conn = db();
  const result = conn.transaction(() => {
    // Read previous and current window hit counts
    const cur = conn.prepare<[string, number], { hits: number }>(
      'SELECT hits FROM rate_limits WHERE key = ? AND window_sec = ?',
    ).get(key, currentWindow);
    const prev = conn.prepare<[string, number], { hits: number }>(
      'SELECT hits FROM rate_limits WHERE key = ? AND window_sec = ?',
    ).get(key, prevWindow);

    const curHits = cur?.hits ?? 0;
    const prevHits = prev?.hits ?? 0;
    const weighted = curHits + Math.floor(prevHits * overlapWeight);

    if (weighted >= policy.limit) {
      return { allowed: false, remaining: 0, retryAfterSec: policy.windowSec - elapsedInWindow };
    }

    // Hit
    conn.prepare(
      `INSERT INTO rate_limits (key, window_sec, hits) VALUES (?, ?, 1)
       ON CONFLICT(key, window_sec) DO UPDATE SET hits = hits + 1`,
    ).run(key, currentWindow);

    // Opportunistically prune ancient buckets (older than 24h)
    if (Math.random() < 0.01) {
      conn.prepare('DELETE FROM rate_limits WHERE window_sec < ?').run(now - 86_400);
    }

    return { allowed: true, remaining: policy.limit - weighted - 1, retryAfterSec: 0 };
  })();

  return result;
}

/**
 * Hono middleware. Returns 429 with Retry-After + JSON body on rejection.
 */
export function rateLimit(policy: RateLimitPolicy): MiddlewareHandler {
  return async (c, next) => {
    const subj = subject(c, policy.key);
    const r = checkAndHit(policy, subj);
    c.header('X-RateLimit-Limit', String(policy.limit));
    c.header('X-RateLimit-Remaining', String(Math.max(0, r.remaining)));
    if (!r.allowed) {
      c.header('Retry-After', String(r.retryAfterSec));
      return c.json({
        error: 'rate_limited',
        message: `Too many requests. Retry in ${r.retryAfterSec}s.`,
        policy: policy.name,
      }, 429);
    }
    return next();
  };
}

/**
 * Manual call site (for places where the request hasn't gone through the
 * middleware — e.g. checking before consuming an API token).
 */
export function consume(policy: RateLimitPolicy, subjectKey: string): { allowed: boolean; retryAfterSec: number } {
  const r = checkAndHit(policy, subjectKey);
  return { allowed: r.allowed, retryAfterSec: r.retryAfterSec };
}
