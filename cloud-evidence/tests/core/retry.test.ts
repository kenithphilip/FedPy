/**
 * Tests for core/retry.ts — transient classifier + withRetry loop.
 */
import { describe, it, expect, vi } from 'vitest';
import { withRetry, isTransientError, nextBackoff } from '../../core/retry.ts';

describe('isTransientError classifier', () => {
  it('flags AWS SDK 5xx as transient', () => {
    const e = { $metadata: { httpStatusCode: 503 }, name: 'InternalFailure' };
    expect(isTransientError(e)).toBe(true);
  });

  it('flags AWS SDK 429 as transient', () => {
    expect(isTransientError({ $metadata: { httpStatusCode: 429 } })).toBe(true);
  });

  it('flags AWS SDK throttling exceptions as transient', () => {
    expect(isTransientError({ name: 'ThrottlingException' })).toBe(true);
    expect(isTransientError({ $retryable: { throttling: true } })).toBe(true);
  });

  it('flags GCP gRPC UNAVAILABLE (14) as transient', () => {
    expect(isTransientError({ code: 14, message: 'UNAVAILABLE' })).toBe(true);
  });

  it('flags Node ECONNRESET as transient', () => {
    expect(isTransientError({ code: 'ECONNRESET', message: 'connection reset' })).toBe(true);
  });

  it('does NOT flag a 403 AccessDenied as transient', () => {
    expect(isTransientError({ $metadata: { httpStatusCode: 403 }, name: 'AccessDeniedException' })).toBe(false);
  });

  it('does NOT flag a NoSuchEntityException as transient', () => {
    expect(isTransientError({ name: 'NoSuchEntityException' })).toBe(false);
  });
});

describe('nextBackoff', () => {
  it('returns a value between base and 3*max(base,prev), capped at cap', () => {
    for (let i = 0; i < 100; i++) {
      const v = nextBackoff(500, 100, 5000);
      expect(v).toBeGreaterThanOrEqual(100);
      expect(v).toBeLessThanOrEqual(5000);
    }
  });

  it('respects the cap', () => {
    for (let i = 0; i < 100; i++) {
      const v = nextBackoff(99999, 100, 800);
      expect(v).toBeLessThanOrEqual(800);
    }
  });
});

describe('withRetry', () => {
  it('returns the value on first success', async () => {
    const fn = vi.fn(async () => 42);
    const out = await withRetry(fn);
    expect(out).toBe(42);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('retries transient errors and eventually succeeds', async () => {
    let calls = 0;
    const fn = vi.fn(async () => {
      calls++;
      if (calls < 3) throw { $metadata: { httpStatusCode: 503 }, name: 'InternalFailure' };
      return 'ok';
    });
    const out = await withRetry(fn, { baseDelayMs: 1, maxDelayMs: 5 });
    expect(out).toBe('ok');
    expect(fn).toHaveBeenCalledTimes(3);
  });

  it('does NOT retry non-transient errors', async () => {
    const fn = vi.fn(async () => {
      throw { $metadata: { httpStatusCode: 403 }, name: 'AccessDeniedException', message: 'denied' };
    });
    await expect(withRetry(fn, { baseDelayMs: 1 })).rejects.toMatchObject({ name: 'AccessDeniedException' });
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('gives up after `attempts` and throws the last error', async () => {
    const err = { code: 'ECONNRESET', message: 'reset' };
    const fn = vi.fn(async () => { throw err; });
    await expect(withRetry(fn, { attempts: 3, baseDelayMs: 1, maxDelayMs: 2 })).rejects.toBe(err);
    expect(fn).toHaveBeenCalledTimes(3);
  });

  it('honors an AbortSignal between attempts', async () => {
    const ac = new AbortController();
    let calls = 0;
    const fn = vi.fn(async () => {
      calls++;
      if (calls === 1) {
        // abort immediately after the first failure
        setTimeout(() => ac.abort(), 0);
        throw { $metadata: { httpStatusCode: 503 } };
      }
      return 'should not reach';
    });
    await expect(
      withRetry(fn, { attempts: 5, baseDelayMs: 20, maxDelayMs: 100, signal: ac.signal }),
    ).rejects.toThrow(/aborted/);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('fires onRetry with attempt index, error, and delay', async () => {
    let calls = 0;
    const onRetry = vi.fn();
    await withRetry(
      async () => {
        calls++;
        if (calls < 2) throw { $metadata: { httpStatusCode: 503 } };
        return 'ok';
      },
      { baseDelayMs: 1, maxDelayMs: 2, onRetry },
    );
    expect(onRetry).toHaveBeenCalledTimes(1);
    const [attempt, _err, delay] = onRetry.mock.calls[0];
    expect(attempt).toBe(1);
    expect(delay).toBeGreaterThanOrEqual(1);
  });
});
