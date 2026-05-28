/**
 * Run lock — prevents two collector runs from writing the same output directory
 * concurrently (which would interleave/clobber evidence files and produce
 * conflicting or stale results).
 *
 * Mechanism: a lock file `<outDir>/.run-lock.json` holding { pid, run_id, host,
 * acquired_at }. On acquire:
 *   - No lock           → take it.
 *   - Lock is stale     → (older than ttlMs, OR the owning PID is dead) → steal it.
 *   - Lock is fresh+live → throw an actionable error naming the owner.
 *
 * release() removes the lock. Always call it in a finally so a crash doesn't
 * strand the lock (and the TTL/PID-liveness check recovers it anyway).
 *
 * Read/write a single small JSON file; no external deps.
 */
import { readFileSync, writeFileSync, existsSync, unlinkSync } from 'node:fs';
import { resolve } from 'node:path';
import { hostname } from 'node:os';

const LOCK_NAME = '.run-lock.json';
/** A run holding the lock longer than this (without refreshing) is considered stale. */
const DEFAULT_TTL_MS = Number(process.env.CLOUD_EVIDENCE_RUN_LOCK_TTL_MS ?? 6 * 60 * 60 * 1000); // 6h

export interface RunLockInfo {
  pid: number;
  run_id: string;
  host: string;
  acquired_at: string;
}

export interface RunLock {
  release(): void;
  info: RunLockInfo;
}

export class RunLockHeldError extends Error {
  constructor(public readonly owner: RunLockInfo, lockPath: string) {
    super(
      `Another cloud-evidence run holds the lock on this output directory ` +
      `(run ${owner.run_id}, pid ${owner.pid} on ${owner.host}, since ${owner.acquired_at}). ` +
      `Wait for it to finish, use a different --out, or remove ${lockPath} if you are sure it is stale.`,
    );
    this.name = 'RunLockHeldError';
  }
}

/** Is a process with this pid alive on THIS host? (Cross-host can't be checked — rely on TTL.) */
function pidAlive(pid: number, host: string): boolean {
  if (host !== hostname()) return true; // can't check a remote pid; assume alive until TTL
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0); // signal 0 = liveness probe, doesn't actually signal
    return true;
  } catch (e: any) {
    return e?.code === 'EPERM'; // exists but not ours → alive
  }
}

/**
 * Acquire the run lock for `outDir`. Throws RunLockHeldError if a fresh, live
 * run already holds it. Returns a handle whose release() frees the lock.
 */
export function acquireRunLock(outDir: string, runId: string, opts: { ttlMs?: number } = {}): RunLock {
  const lockPath = resolve(outDir, LOCK_NAME);
  const ttl = opts.ttlMs ?? DEFAULT_TTL_MS;

  if (existsSync(lockPath)) {
    let existing: RunLockInfo | null = null;
    try { existing = JSON.parse(readFileSync(lockPath, 'utf8')); } catch { existing = null; }
    if (existing && existing.pid) {
      const ageMs = Date.now() - new Date(existing.acquired_at).getTime();
      const stale = !Number.isFinite(ageMs) || ageMs > ttl || !pidAlive(existing.pid, existing.host);
      if (!stale) throw new RunLockHeldError(existing, lockPath);
      // else: stale lock → fall through and steal it.
    }
  }

  const info: RunLockInfo = { pid: process.pid, run_id: runId, host: hostname(), acquired_at: new Date().toISOString() };
  writeFileSync(lockPath, JSON.stringify(info, null, 2));

  let released = false;
  return {
    info,
    release() {
      if (released) return;
      released = true;
      try {
        // Only remove if WE still own it (avoid deleting a lock a later run stole after our TTL).
        if (existsSync(lockPath)) {
          const cur: RunLockInfo = JSON.parse(readFileSync(lockPath, 'utf8'));
          if (cur.run_id === runId && cur.pid === process.pid) unlinkSync(lockPath);
        }
      } catch { /* best-effort */ }
    },
  };
}
