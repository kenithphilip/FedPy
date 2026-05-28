/**
 * VDR ledger summarizer.
 *
 * Rolls an enriched ledger (see core/vdr-ledger.ts) into the headline numbers
 * the orchestrator surfaces for the VDR family: total findings, KEV count,
 * overdue count, severity breakdown, oldest-open age, and the explicit list of
 * SLA-breaching entries (VDR-TFR-* timeframe violations). Feeds the report
 * builders described in vdr.md (VDR-RPT-AVI / VDR-RPT-VDT / VDR-TFR-MHR).
 *
 * READ-ONLY and PURE: no I/O, no cloud calls, deterministic given the ledger +
 * `now`. Date math delegates to core/bizdays.ts.
 */
import { calendarDaysBetween } from './bizdays.ts';
import type { LedgerEntry, Severity, LifecycleState } from './vdr-ledger.ts';

export interface VdrSummary {
  /** Total entries in the ledger. */
  total: number;
  /** Entries whose CVE is in the CISA KEV catalog. */
  kev_count: number;
  /** Entries whose binding SLA is overdue. */
  overdue: number;
  /** Count of entries per severity. */
  by_severity: Record<Severity, number>;
  /** Age (calendar days) of the oldest open (non-terminal) finding; 0 if none. */
  oldest_open_days: number;
  /** The actual entries in SLA breach (overdue), for drill-down / reporting. */
  sla_breaches: LedgerEntry[];
  /** Entries whose SLA could not be computed for lack of inputs (missing_evidence). */
  indeterminate: number;
}

const TERMINAL_STATES: ReadonlySet<LifecycleState> = new Set([
  'remediated',
  'accepted',
  'false_positive',
]);

function emptySeverity(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

/**
 * Summarize an enriched ledger.
 *
 * `now` (ISO) controls oldest-open age math for determinism; defaults to real
 * now. Overdue/breach classification uses the `sla` already computed by
 * buildLedger, so the same `now` should be passed to both for consistency.
 */
export function summarizeVdr(
  ledger: LedgerEntry[],
  now: string = new Date().toISOString(),
): VdrSummary {
  const nowDate = new Date(now);
  const by_severity = emptySeverity();
  const sla_breaches: LedgerEntry[] = [];

  let kev_count = 0;
  let overdue = 0;
  let indeterminate = 0;
  let oldest_open_days = 0;

  for (const e of ledger) {
    by_severity[e.severity] = (by_severity[e.severity] ?? 0) + 1;

    if (e.kev) kev_count++;

    const sla = e.sla;
    if (sla?.indeterminate) indeterminate++;
    if (sla?.overdue) {
      overdue++;
      sla_breaches.push(e);
    }

    const state = e.state ?? 'detected';
    if (!TERMINAL_STATES.has(state)) {
      const age = calendarDaysBetween(new Date(e.first_seen), nowDate);
      if (age > oldest_open_days) oldest_open_days = age;
    }
  }

  return {
    total: ledger.length,
    kev_count,
    overdue,
    by_severity,
    oldest_open_days,
    sla_breaches,
    indeterminate,
  };
}
