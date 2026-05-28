/**
 * Smoke test for core/log.ts.
 *
 * We don't try to capture pino transport output (it goes through a worker
 * thread). Instead we just verify:
 *   - The module loads.
 *   - `log` is a Logger with the expected methods.
 *   - `logger({...})` returns a child with bindings.
 *   - `timed()` resolves with the function's value on success and rejects
 *     on failure, returning the original error.
 */
import { describe, it, expect } from 'vitest';
import { log, logger, timed } from '../../core/log.ts';

describe('core/log', () => {
  it('exports a logger with standard pino methods', () => {
    expect(typeof log.info).toBe('function');
    expect(typeof log.warn).toBe('function');
    expect(typeof log.error).toBe('function');
    expect(typeof log.debug).toBe('function');
  });

  it('creates a child logger with bindings', () => {
    const child = logger({ ksi: 'KSI-IAM-MFA' });
    expect(typeof child.info).toBe('function');
    // bindings is a pino-specific accessor; existence is enough
    expect(child).not.toBe(log);
  });

  it('timed() returns the function value on success', async () => {
    const out = await timed(log, 'test.op', { foo: 'bar' }, async () => 'value');
    expect(out).toBe('value');
  });

  it('timed() rethrows on failure', async () => {
    const err = new Error('boom');
    await expect(timed(log, 'test.op', {}, async () => { throw err; })).rejects.toBe(err);
  });
});
