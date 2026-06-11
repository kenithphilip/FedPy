/**
 * Monthly POA&M ledger — LOOP-E.E2.
 *
 * An append-only JSONL ledger (`out/poam-ledger.jsonl`) recording one line per
 * monthly POA&M emission, plus the on-disk archive of each month's document
 * (`out/archive/poam-<YYYY-MM>.json`). Together they let the monthly workflow
 * (core/poam-monthly.ts) reconstruct the prior month's POA&M so it can:
 *   - thread `metadata.revisions[]` forward (chain-of-custody for a 3PAO), and
 *   - compute a month-over-month delta (items opened / closed / status flips).
 *
 * Why a ledger + archive (not just re-reading poam.json):
 *   `out/poam.json` is overwritten every run. Without a durable record of each
 *   month's exact bytes, the version chain breaks the moment a new run lands. The
 *   ledger pins {run_id, report_month, version, last-modified, sha256, path}; the
 *   archive holds the immutable document the sha256 covers.
 *
 * REO compliance (cloud-evidence/CLAUDE.md):
 *   - Append-only: a prior ledger line is NEVER mutated. Re-emitting the same
 *     (run_id, report_month) is idempotent — no duplicate line is written.
 *   - No silent fallback: a corrupt ledger line raises PoamLedgerCorruptError
 *     (naming the offending line number); a sha256 mismatch between the ledger
 *     and the on-disk archive raises PoamArchiveTamperedError (naming the path);
 *     a structurally-broken archive raises PriorPoamCorruptError. None of these
 *     are ever treated as "no prior month".
 *   - Every value is real: sha256 is computed from the archived bytes; counts
 *     are read from the document; timestamps come from the document metadata.
 */
import { appendFileSync, readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import type { OscalPoam, OscalPoamDocument } from './oscal-poam.ts';

/** Append-only ledger file name (relative to outDir). */
export const POAM_LEDGER_FILENAME = 'poam-ledger.jsonl';
/** Sub-directory under outDir holding the immutable monthly POA&M snapshots. */
export const POAM_ARCHIVE_DIR = 'archive';

/** Strict YYYY-MM (01..12). */
const MONTH_RE = /^\d{4}-(0[1-9]|1[0-2])$/;

/** Relative archive path for a given report month (e.g. `archive/poam-2026-06.json`). */
export function poamArchiveRelPath(month: string): string {
  return `${POAM_ARCHIVE_DIR}/poam-${month}.json`;
}

/** One line of out/poam-ledger.jsonl. */
export interface PoamLedgerEntry {
  /** Orchestrator run id that emitted this month's POA&M. */
  run_id: string;
  /** Report month, "YYYY-MM". */
  report_month: string;
  /** metadata.last-modified of the archived document (ISO 8601, Z-suffixed). */
  last_modified: string;
  /** metadata.version of the archived document. */
  version: string;
  /** metadata.oscal-version of the archived document. */
  oscal_version: string;
  /** Hex SHA-256 of the archived poam.json bytes. */
  sha256: string;
  /** Archive path relative to outDir, e.g. "archive/poam-2026-06.json". */
  path: string;
  /** poam-items.length in the archived document. */
  item_count: number;
  /** Count of poam-items whose resolved risk status is NOT "closed". */
  open_count: number;
  /** Count of poam-items whose resolved risk status IS "closed". */
  closed_count: number;
  /** ISO 8601 (Z-suffixed) time this ledger line was written. */
  appended_at: string;
}

/** Raised when a JSONL line in the ledger cannot be parsed. */
export class PoamLedgerCorruptError extends Error {
  constructor(public readonly lineNumber: number, public readonly line: string, cause?: unknown) {
    super(
      `poam-ledger.jsonl: malformed JSON on line ${lineNumber}: ${line.slice(0, 120)}` +
        (cause ? ` (${String((cause as any)?.message ?? cause)})` : ''),
    );
    this.name = 'PoamLedgerCorruptError';
  }
}

/** Raised when the on-disk archive's sha256 does not match its ledger entry. */
export class PoamArchiveTamperedError extends Error {
  constructor(public readonly path: string, public readonly expected: string, public readonly actual: string) {
    super(
      `POA&M archive ${path} sha256 mismatch: ledger recorded ${expected.slice(0, 12)}…, ` +
        `on-disk file hashes to ${actual.slice(0, 12)}…. The archive was altered after it was recorded — refusing to use it.`,
    );
    this.name = 'PoamArchiveTamperedError';
  }
}

/** Raised when an archived POA&M file is present but is not a valid OSCAL POA&M document. */
export class PriorPoamCorruptError extends Error {
  constructor(public readonly path: string, cause?: unknown) {
    super(
      `Prior POA&M archive ${path} is not a valid OSCAL POA&M document` +
        (cause ? `: ${String((cause as any)?.message ?? cause)}` : '.'),
    );
    this.name = 'PriorPoamCorruptError';
  }
}

export function sha256Hex(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

/**
 * Append one entry to out/poam-ledger.jsonl. Idempotent by (run_id, report_month):
 * if a line with the same pair already exists, this is a no-op (the ledger is
 * append-only and never grows on a re-run of the same month/run).
 */
export function appendPoamLedger(outDir: string, entry: PoamLedgerEntry): void {
  const existing = readPoamLedger(outDir);
  if (existing.some((e) => e.run_id === entry.run_id && e.report_month === entry.report_month)) return;
  appendFileSync(resolve(outDir, POAM_LEDGER_FILENAME), JSON.stringify(entry) + '\n');
}

/**
 * Read + parse every line of out/poam-ledger.jsonl in insertion order. Empty /
 * whitespace-only lines (trailing newlines) are skipped. A malformed line raises
 * PoamLedgerCorruptError naming the 1-based line number.
 */
export function readPoamLedger(outDir: string): PoamLedgerEntry[] {
  const p = resolve(outDir, POAM_LEDGER_FILENAME);
  if (!existsSync(p)) return [];
  const raw = readFileSync(p, 'utf8');
  const lines = raw.split('\n');
  const out: PoamLedgerEntry[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim();
    if (line === '') continue;
    try {
      out.push(JSON.parse(line) as PoamLedgerEntry);
    } catch (e) {
      throw new PoamLedgerCorruptError(i + 1, line, e);
    }
  }
  return out;
}

/**
 * Load the most-recent POA&M strictly before `currentMonth` from the archive.
 * Returns `{ doc, entry }`, or `null` when there is no prior month (first month
 * of operation). Verifies the archived file's sha256 against the ledger entry
 * (PoamArchiveTamperedError on mismatch) and that it parses as an OSCAL POA&M
 * document (PriorPoamCorruptError otherwise). Never silently returns null on a
 * present-but-broken archive.
 */
export function loadPriorMonthPoam(
  outDir: string,
  currentMonth: string,
): { doc: OscalPoam; entry: PoamLedgerEntry } | null {
  if (!MONTH_RE.test(currentMonth)) {
    throw new Error(`loadPriorMonthPoam: currentMonth "${currentMonth}" is not strict YYYY-MM.`);
  }
  const candidates = readPoamLedger(outDir).filter((e) => e.report_month < currentMonth);
  if (candidates.length === 0) return null;
  // Most recent month wins; on a tie (same month re-emitted), the last-appended
  // line wins because its sha256 matches the current on-disk archive.
  let best = candidates[0]!;
  for (const e of candidates) if (e.report_month >= best.report_month) best = e;

  const archiveAbs = resolve(outDir, best.path);
  if (!existsSync(archiveAbs)) {
    throw new PriorPoamCorruptError(best.path, new Error('archive file referenced by the ledger is missing'));
  }
  const buf = readFileSync(archiveAbs);
  const actual = sha256Hex(buf);
  if (actual !== best.sha256) throw new PoamArchiveTamperedError(best.path, best.sha256, actual);

  let parsed: OscalPoamDocument;
  try {
    parsed = JSON.parse(buf.toString('utf8')) as OscalPoamDocument;
  } catch (e) {
    throw new PriorPoamCorruptError(best.path, e);
  }
  const doc = parsed['plan-of-action-and-milestones'];
  if (!doc || !doc.metadata || !Array.isArray(doc['poam-items'])) {
    throw new PriorPoamCorruptError(best.path, new Error('missing plan-of-action-and-milestones / metadata / poam-items'));
  }
  return { doc, entry: best };
}
