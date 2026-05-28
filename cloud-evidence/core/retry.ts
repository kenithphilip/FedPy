/**
 * Retry + backoff helper for SDK calls.
 *
 * The AWS SDK v3 has its own internal retry strategy (3 attempts, jittered
 * standard backoff) for transient errors and throttling. This module covers
 * the gaps:
 *
 *   1. GCP libraries: some have retry built-in, some don't. We wrap every
 *      GCP call site that we want to be resilient.
 *   2. Collector-level fan-out: e.g. iterating per-user `ListMFADevices`
 *      across thousands of users. AWS may rate-limit between calls; we want
 *      to back off harder than the SDK does on its own.
 *   3. Network-level failures (DNS, TCP) that the SDK sometimes propagates
 *      as-is.
 *
 * Design:
 *   - Default 4 attempts with exponential backoff + decorrelated jitter.
 *   - Only retries errors classified as transient (5xx, throttling,
 *     network errors, AbortError on a non-user signal).
 *   - Honors an optional AbortSignal so callers can cancel long-running
 *     fan-outs (e.g. on Ctrl-C).
 *   - Returns whatever the inner function returns; throws the last error
 *     after exhausting retries.
 *
 * NOT a circuit breaker — that's a separate concern and would belong at
 * the collector level if we ever see cascading failures.
 */

export interface RetryOptions {
  /** Total attempts including the first call. Default 4. */
  attempts?: number;
  /** Initial backoff in ms. Default 200. */
  baseDelayMs?: number;
  /** Cap on a single backoff. Default 5000. */
  maxDelayMs?: number;
  /** AbortSignal to cancel before the next attempt. */
  signal?: AbortSignal;
  /** Optional callback for diagnostics. */
  onRetry?: (attempt: number, error: unknown, delayMs: number) => void;
  /**
   * Override classifier. Return true if the error is worth retrying.
   * Default: see `isTransientError` below.
   */
  isTransient?: (error: unknown) => boolean;
}

/**
 * Classifies an error as transient (worth retrying) or not.
 *
 * Recognizes:
 *   - AWS SDK errors with $metadata.httpStatusCode in {429,500,502,503,504}
 *   - AWS SDK errors with $retryable.throttling === true
 *   - GCP errors with `.code` in transient set (UNAVAILABLE=14, DEADLINE_EXCEEDED=4, INTERNAL=13, ABORTED=10)
 *   - Node network errors: ECONNRESET, ETIMEDOUT, ENOTFOUND, EAI_AGAIN
 *   - Errors with name "TimeoutError", "NetworkingError", or message containing "rate exceeded"/"throttl"
 */
export function isTransientError(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const e = err as any;

  // AWS SDK v3 shape
  const status = e?.$metadata?.httpStatusCode;
  if (typeof status === 'number') {
    if (status === 429 || (status >= 500 && status < 600)) return true;
  }
  if (e?.$retryable?.throttling === true) return true;
  if (e?.name === 'ThrottlingException') return true;

  // GCP gRPC error codes (status.code or .code)
  const gcpCode = e?.code ?? e?.status?.code;
  if (typeof gcpCode === 'number') {
    if ([4, 10, 13, 14].includes(gcpCode)) return true;
  }

  // GCP googleapis omnibus (HTTP REST): err.code may be the HTTP status
  if (typeof e?.code === 'number' && (e.code === 429 || (e.code >= 500 && e.code < 600))) return true;

  // Node network errors
  const sysCode = e?.code;
  if (typeof sysCode === 'string') {
    if (['ECONNRESET', 'ETIMEDOUT', 'ENOTFOUND', 'EAI_AGAIN', 'EPIPE', 'EHOSTUNREACH'].includes(sysCode)) {
      return true;
    }
  }

  // Name-based hints
  const name = String(e?.name ?? '');
  if (['TimeoutError', 'NetworkingError', 'AbortError'].includes(name)) {
    // AbortError is transient ONLY if not from the caller's signal — caller
    // checks the signal in the retry loop, so by the time we see AbortError
    // without their signal being aborted, it's a fetch-level timeout.
    return name !== 'AbortError'; // be conservative; treat as non-transient
  }

  const msg = String(e?.message ?? '').toLowerCase();
  if (msg.includes('rate exceeded') || msg.includes('throttl') || msg.includes('too many requests')) {
    return true;
  }

  return false;
}

/**
 * Compute the backoff delay for the next attempt using decorrelated jitter.
 * See https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
 *
 * `prevDelay` is the previous backoff (0 if first retry).
 */
export function nextBackoff(prevDelay: number, base: number, cap: number): number {
  // decorrelated jitter: random between base and min(cap, prevDelay * 3)
  const upper = Math.min(cap, Math.max(base, prevDelay) * 3);
  return Math.floor(base + Math.random() * (upper - base));
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new Error('aborted'));
    const t = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(t);
      reject(new Error('aborted'));
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/**
 * Invoke `fn` with retry. Each attempt awaits the previous; failures that
 * pass the transient classifier trigger backoff. Returns whatever `fn`
 * returns; throws the last error if all attempts fail.
 *
 * Example:
 *   const out = await withRetry(() => client.send(new ListUsersCommand({})));
 */
export async function withRetry<T>(fn: () => Promise<T>, opts: RetryOptions = {}): Promise<T> {
  const attempts = Math.max(1, opts.attempts ?? 4);
  const base = Math.max(1, opts.baseDelayMs ?? 200);
  const cap = Math.max(base, opts.maxDelayMs ?? 5000);
  const isTransient = opts.isTransient ?? isTransientError;
  const signal = opts.signal;

  let lastErr: unknown;
  let delay = 0;
  for (let i = 1; i <= attempts; i++) {
    if (signal?.aborted) throw new Error('aborted');
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (i >= attempts || !isTransient(err)) throw err;
      delay = nextBackoff(delay, base, cap);
      opts.onRetry?.(i, err, delay);
      await sleep(delay, signal);
    }
  }
  throw lastErr;
}

/**
 * Convenience wrapper for "guard a single SDK call without thinking about it".
 *
 * Usage:
 *   const out = await retryable(client.send.bind(client))(new ListUsersCommand({}));
 *
 * The returned function has the same signature as the original SDK send().
 */
export function retryable<TArgs extends any[], TOut>(
  fn: (...args: TArgs) => Promise<TOut>,
  opts: RetryOptions = {},
): (...args: TArgs) => Promise<TOut> {
  return (...args: TArgs) => withRetry(() => fn(...args), opts);
}
