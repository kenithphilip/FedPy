/**
 * Rate control + in-run memoization for production-load resilience.
 *
 * Cloud APIs throttle aggressively at scale (thousands of resources across many
 * accounts/regions). This module provides:
 *
 *   - TokenBucket: proactive client-side rate limiting per service so we don't
 *     trip provider throttles in the first place.
 *   - AdaptiveLimiter: a per-service concurrency ceiling that HALVES on a throttle
 *     signal and recovers slowly — additive-increase / multiplicative-decrease,
 *     the classic congestion-control shape — so a throttling service self-heals.
 *   - memoizeAsync: bounded in-run cache (TTL) for shared describe calls (e.g.
 *     STS whoAmI, account status) so we don't refetch the same data N times and
 *     so every cached value carries the timestamp it was fetched (no stale reuse
 *     across runs — the cache is per-process and TTL-bounded).
 *
 * Pure + deterministic given an injectable clock; no I/O.
 */

export type Clock = () => number;
const realClock: Clock = () => Date.now();

/** Classic token bucket. capacity tokens, refilled at refillPerSec. */
export class TokenBucket {
  private tokens: number;
  private last: number;
  constructor(
    private readonly capacity: number,
    private readonly refillPerSec: number,
    private readonly clock: Clock = realClock,
  ) {
    this.tokens = capacity;
    this.last = clock();
  }
  private refill(): void {
    const now = this.clock();
    const elapsedSec = (now - this.last) / 1000;
    if (elapsedSec > 0) {
      this.tokens = Math.min(this.capacity, this.tokens + elapsedSec * this.refillPerSec);
      this.last = now;
    }
  }
  /** Try to take n tokens without waiting. Returns true if granted. */
  tryTake(n = 1): boolean {
    this.refill();
    if (this.tokens >= n) { this.tokens -= n; return true; }
    return false;
  }
  /** Milliseconds until n tokens would be available (0 if available now). */
  waitMs(n = 1): number {
    this.refill();
    if (this.tokens >= n) return 0;
    return Math.ceil(((n - this.tokens) / this.refillPerSec) * 1000);
  }
  available(): number { this.refill(); return Math.floor(this.tokens); }
}

/**
 * Additive-increase / multiplicative-decrease concurrency ceiling per key.
 * Start at `start`, halve (floor `min`) on throttle, +1 (cap `max`) on success.
 */
export class AdaptiveLimiter {
  private limits = new Map<string, number>();
  private throttles = new Map<string, number>();
  constructor(
    private readonly start = 8,
    private readonly min = 1,
    private readonly max = 32,
  ) {}
  current(key: string): number {
    return this.limits.get(key) ?? this.start;
  }
  /** A throttle was observed for this key → multiplicative decrease. */
  onThrottle(key: string): number {
    const next = Math.max(this.min, Math.floor(this.current(key) / 2));
    this.limits.set(key, next);
    this.throttles.set(key, (this.throttles.get(key) ?? 0) + 1);
    return next;
  }
  /** A call succeeded for this key → additive increase. */
  onSuccess(key: string): number {
    const next = Math.min(this.max, this.current(key) + 1);
    this.limits.set(key, next);
    return next;
  }
  throttleCount(key: string): number { return this.throttles.get(key) ?? 0; }
  /** Snapshot of all per-key throttle counts (for the run ledger/summary). */
  throttleSnapshot(): Record<string, number> {
    return Object.fromEntries(this.throttles);
  }
}

interface CacheRec<T> { value: Promise<T>; at: number }

/**
 * Wrap an async function so identical-key calls within `ttlMs` reuse the same
 * in-flight/settled promise. Per-process, TTL-bounded — never serves data older
 * than ttlMs, so no cross-run staleness.
 */
export function memoizeAsync<TArgs extends unknown[], T>(
  fn: (...args: TArgs) => Promise<T>,
  opts: { ttlMs: number; keyFn?: (...args: TArgs) => string; clock?: Clock } = { ttlMs: 60_000 },
): (...args: TArgs) => Promise<T> {
  const clock = opts.clock ?? realClock;
  const keyFn = opts.keyFn ?? ((...a: TArgs) => JSON.stringify(a));
  const cache = new Map<string, CacheRec<T>>();
  return (...args: TArgs): Promise<T> => {
    const key = keyFn(...args);
    const now = clock();
    const hit = cache.get(key);
    if (hit && now - hit.at < opts.ttlMs) return hit.value;
    const value = fn(...args).catch((e) => { cache.delete(key); throw e; }); // don't cache failures
    cache.set(key, { value, at: now });
    return value;
  };
}
