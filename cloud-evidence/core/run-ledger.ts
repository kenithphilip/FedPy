/**
 * Append-only run ledger.
 *
 * FedRAMP evidence collection must be auditable: "every action / report / log
 * must be stored and saved." This module writes a durable, append-only JSONL
 * record of every collector action + outcome + timing to `out/run-ledger.jsonl`.
 *
 * Why append-per-record (not buffer-then-flush): if the process crashes mid-run
 * (OOM, killed, SDK hang), every action recorded up to that point is already on
 * disk — the ledger is the forensic trail of exactly what ran and what happened.
 *
 * Each line is one JSON object:
 *   { ts, run_id, seq, event, ksi_id?, provider?, action?, status?, duration_ms?, err_class?, err_message? }
 *
 * Failures to write the ledger never abort the run — they downgrade to a pino
 * warning (losing the audit line is bad, but crashing a compliance run is worse).
 */
import { appendFileSync } from 'node:fs';
import { log } from './log.ts';

export type LedgerStatus = 'start' | 'ok' | 'fail' | 'skip' | 'info';

export interface LedgerFields {
  ksi_id?: string;
  provider?: string;
  account_id?: string | null;
  project_id?: string | null;
  action?: string;
  status?: LedgerStatus;
  duration_ms?: number;
  err_class?: string;
  err_message?: string;
  [k: string]: unknown;
}

export interface RunLedger {
  readonly path: string;
  /** Record one event. Never throws. */
  record(event: string, fields?: LedgerFields): void;
  /** Number of records written (incl. any that failed to flush). */
  count(): number;
  /** Number of records that could not be persisted to disk. */
  writeFailures(): number;
}

/**
 * Create an append-only run ledger at `path`. Writes a `run.ledger_open` line
 * immediately so an empty ledger still proves the run started.
 */
export function createRunLedger(path: string, runId: string): RunLedger {
  let seq = 0;
  let failures = 0;

  function record(event: string, fields: LedgerFields = {}): void {
    seq += 1;
    const entry = { ts: new Date().toISOString(), run_id: runId, seq, event, ...fields };
    try {
      appendFileSync(path, JSON.stringify(entry) + '\n');
    } catch (e: any) {
      failures += 1;
      // Don't let an audit-line write failure kill a compliance run.
      log.warn({ event: 'run_ledger.write_failed', path, err_code: e?.code, err_message: e?.message });
    }
  }

  const ledger: RunLedger = {
    path,
    record,
    count: () => seq,
    writeFailures: () => failures,
  };
  ledger.record('run.ledger_open', { status: 'info' });
  return ledger;
}

/** A no-op ledger (for code paths / tests that don't want to persist). */
export function nullLedger(): RunLedger {
  return { path: '', record: () => {}, count: () => 0, writeFailures: () => 0 };
}

/**
 * Time an async action and record start + ok/fail to the ledger. Returns the
 * action's result (or rethrows). Centralizes the "log every action + timing"
 * pattern so collectors/orchestrator stay legible.
 */
export async function ledgerTimed<T>(
  ledger: RunLedger,
  event: string,
  fields: LedgerFields,
  fn: () => Promise<T>,
): Promise<T> {
  const started = Date.now();
  ledger.record(event, { ...fields, status: 'start' });
  try {
    const out = await fn();
    ledger.record(event, { ...fields, status: 'ok', duration_ms: Date.now() - started });
    return out;
  } catch (e: any) {
    ledger.record(event, { ...fields, status: 'fail', duration_ms: Date.now() - started, err_message: e?.message });
    throw e;
  }
}
