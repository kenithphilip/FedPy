/**
 * Tests for server/rate-limit.ts — sliding-window counter behavior.
 *
 * Uses a tmp DB path so the production DB isn't touched. Tests run sequentially.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';

let tmpDir: string;

beforeAll(() => {
  tmpDir = mkdtempSync(resolve(tmpdir(), 'tracker-rl-'));
  process.env.DB_PATH = resolve(tmpDir, 'rl-test.db');
});

afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

describe('rate-limit: checkAndHit', () => {
  it('allows hits up to the limit', async () => {
    const { checkAndHit } = await import('./rate-limit.ts');
    const policy = { name: 'test:basic', key: 'ip' as const, windowSec: 60, limit: 3 };
    for (let i = 0; i < 3; i++) {
      const r = checkAndHit(policy, 'ip-1');
      expect(r.allowed, `hit ${i + 1} should be allowed`).toBe(true);
    }
  });

  it('blocks the (limit+1)th hit with retry-after', async () => {
    const { checkAndHit } = await import('./rate-limit.ts');
    const policy = { name: 'test:block', key: 'ip' as const, windowSec: 60, limit: 2 };
    expect(checkAndHit(policy, 'ip-X').allowed).toBe(true);
    expect(checkAndHit(policy, 'ip-X').allowed).toBe(true);
    const blocked = checkAndHit(policy, 'ip-X');
    expect(blocked.allowed).toBe(false);
    expect(blocked.retryAfterSec).toBeGreaterThan(0);
    expect(blocked.retryAfterSec).toBeLessThanOrEqual(60);
  });

  it('is per-subject (different IPs do not share buckets)', async () => {
    const { checkAndHit } = await import('./rate-limit.ts');
    const policy = { name: 'test:isolation', key: 'ip' as const, windowSec: 60, limit: 1 };
    expect(checkAndHit(policy, 'subj-A').allowed).toBe(true);
    expect(checkAndHit(policy, 'subj-A').allowed).toBe(false);
    expect(checkAndHit(policy, 'subj-B').allowed).toBe(true);
  });

  it('decrements remaining correctly', async () => {
    const { checkAndHit } = await import('./rate-limit.ts');
    const policy = { name: 'test:remaining', key: 'ip' as const, windowSec: 60, limit: 5 };
    const r1 = checkAndHit(policy, 'rem-1');
    expect(r1.remaining).toBe(4);
    const r2 = checkAndHit(policy, 'rem-1');
    expect(r2.remaining).toBe(3);
  });
});

describe('rate-limit: clientIp resolution', () => {
  // Build a minimal fake Hono Context with just header() + env.
  function fakeCtx(headers: Record<string, string>, remoteAddress?: string): any {
    return {
      req: { header: (name: string) => headers[name.toLowerCase()] },
      env: remoteAddress ? { incoming: { socket: { remoteAddress } } } : {},
    };
  }

  it('prefers the first x-forwarded-for hop', async () => {
    const { clientIp } = await import('./rate-limit.ts');
    expect(clientIp(fakeCtx({ 'x-forwarded-for': '203.0.113.7, 10.0.0.1' }))).toBe('203.0.113.7');
  });

  it('falls back to x-real-ip when no XFF', async () => {
    const { clientIp } = await import('./rate-limit.ts');
    expect(clientIp(fakeCtx({ 'x-real-ip': '198.51.100.9' }))).toBe('198.51.100.9');
  });

  it('falls back to the TCP peer address when no proxy headers (no shared bucket)', async () => {
    const { clientIp } = await import('./rate-limit.ts');
    expect(clientIp(fakeCtx({}, '192.0.2.55'))).toBe('192.0.2.55');
  });

  it('returns "unknown" only when there is no header and no socket address', async () => {
    const { clientIp } = await import('./rate-limit.ts');
    expect(clientIp(fakeCtx({}))).toBe('unknown');
  });
});
