/**
 * Tests for the production-hardening layer (PC):
 *   - run-ledger: append-only JSONL persistence + timed actions
 *   - run-lock: overlap prevention, stale-lock stealing, release
 *   - rate-control: token bucket, adaptive concurrency, in-run memoization
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { createRunLedger, ledgerTimed, nullLedger } from '../../core/run-ledger.ts';
import { acquireRunLock, RunLockHeldError } from '../../core/run-lock.ts';
import { TokenBucket, AdaptiveLimiter, memoizeAsync } from '../../core/rate-control.ts';

let dir: string;
beforeEach(() => { dir = mkdtempSync(resolve(tmpdir(), 'cev-harden-')); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

describe('run-ledger', () => {
  it('appends one JSON line per record (durable, survives crash)', () => {
    const path = resolve(dir, 'run-ledger.jsonl');
    const l = createRunLedger(path, 'run-1');
    l.record('ksi.complete', { ksi_id: 'KSI-IAM-MFA', status: 'ok', duration_ms: 12 });
    l.record('ksi.complete', { ksi_id: 'KSI-IAM-ELP', status: 'fail' });
    const lines = readFileSync(path, 'utf8').trim().split('\n').map((x) => JSON.parse(x));
    expect(lines[0].event).toBe('run.ledger_open'); // written on open
    expect(lines.length).toBe(3);
    expect(lines.every((x) => x.run_id === 'run-1')).toBe(true);
    expect(lines[1].ksi_id).toBe('KSI-IAM-MFA');
    expect(l.count()).toBe(3);
  });

  it('ledgerTimed records start + ok with a duration', async () => {
    const path = resolve(dir, 'l.jsonl');
    const l = createRunLedger(path, 'r');
    const r = await ledgerTimed(l, 'collector.run', { ksi_id: 'X' }, async () => 42);
    expect(r).toBe(42);
    const lines = readFileSync(path, 'utf8').trim().split('\n').map((x) => JSON.parse(x));
    expect(lines.some((x) => x.status === 'start')).toBe(true);
    expect(lines.some((x) => x.status === 'ok' && typeof x.duration_ms === 'number')).toBe(true);
  });

  it('records fail (and rethrows) on action error; null ledger is a no-op', async () => {
    const l = createRunLedger(resolve(dir, 'f.jsonl'), 'r');
    await expect(ledgerTimed(l, 'x', {}, async () => { throw new Error('boom'); })).rejects.toThrow('boom');
    expect(nullLedger().count()).toBe(0);
  });
});

describe('run-lock', () => {
  it('acquires, blocks a second acquire, and releases', () => {
    const a = acquireRunLock(dir, 'run-A');
    expect(() => acquireRunLock(dir, 'run-B')).toThrow(RunLockHeldError);
    a.release();
    const b = acquireRunLock(dir, 'run-B'); // now free
    expect(b.info.run_id).toBe('run-B');
    b.release();
  });

  it('steals a stale lock (past TTL)', () => {
    const a = acquireRunLock(dir, 'run-old');
    // Backdate the lock far past the TTL.
    const lockPath = resolve(dir, '.run-lock.json');
    const info = JSON.parse(readFileSync(lockPath, 'utf8'));
    info.acquired_at = new Date(Date.now() - 48 * 3600 * 1000).toISOString();
    writeFileSync(lockPath, JSON.stringify(info));
    const b = acquireRunLock(dir, 'run-new', { ttlMs: 1000 }); // should steal
    expect(b.info.run_id).toBe('run-new');
    b.release();
    a.release();
  });

  it('release only removes a lock we still own', () => {
    const a = acquireRunLock(dir, 'run-A');
    const lockPath = resolve(dir, '.run-lock.json');
    // Simulate a later run stealing the lock.
    writeFileSync(lockPath, JSON.stringify({ pid: 999999, run_id: 'run-C', host: 'other', acquired_at: new Date().toISOString() }));
    a.release(); // must NOT delete run-C's lock
    expect(existsSync(lockPath)).toBe(true);
  });
});

describe('rate-control', () => {
  it('TokenBucket grants up to capacity then refills over time', () => {
    let t = 0; const clock = () => t;
    const tb = new TokenBucket(2, 1, clock); // 2 tokens, 1/sec
    expect(tb.tryTake()).toBe(true);
    expect(tb.tryTake()).toBe(true);
    expect(tb.tryTake()).toBe(false);     // empty
    expect(tb.waitMs()).toBe(1000);        // 1s to refill 1
    t = 1000;
    expect(tb.tryTake()).toBe(true);       // refilled
  });

  it('AdaptiveLimiter halves on throttle and recovers on success', () => {
    const a = new AdaptiveLimiter(8, 1, 32);
    expect(a.current('aws')).toBe(8);
    expect(a.onThrottle('aws')).toBe(4);
    expect(a.onThrottle('aws')).toBe(2);
    expect(a.onSuccess('aws')).toBe(3);
    expect(a.throttleCount('aws')).toBe(2);
    expect(a.throttleSnapshot()).toEqual({ aws: 2 });
  });

  it('memoizeAsync caches within TTL, expires after, never caches failures', async () => {
    let calls = 0; let t = 0; const clock = () => t;
    const fn = memoizeAsync(async (x: number) => { calls++; return x * 2; }, { ttlMs: 1000, clock });
    expect(await fn(5)).toBe(10);
    expect(await fn(5)).toBe(10);
    expect(calls).toBe(1);            // cached
    t = 2000;
    expect(await fn(5)).toBe(10);
    expect(calls).toBe(2);            // expired → recomputed

    let failCalls = 0;
    const bad = memoizeAsync(async () => { failCalls++; throw new Error('x'); }, { ttlMs: 1000, clock });
    await expect(bad()).rejects.toThrow('x');
    await expect(bad()).rejects.toThrow('x');
    expect(failCalls).toBe(2);        // failures not cached
  });
});
