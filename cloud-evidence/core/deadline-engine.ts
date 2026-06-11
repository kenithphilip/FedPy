/**
 * Remediation deadline engine (LOOP-B.B2).
 *
 * Replaces the LOOP-A.A1 single `Severity → days` map with a priority-cascading
 * `computeDeadline()` that honours, in order:
 *
 *   1. Operator override  — a signed B.B3 risk-acceptance deadline (when present),
 *      EXCEPT a CISA KEV federal mandate caps it: an override may make a deadline
 *      stricter but never extend it past the KEV dueDate (open-question Q1).
 *   2. CISA KEV match      — BOD 22-01 requires remediation by the catalog's
 *      per-entry `dueDate` (read VERBATIM; earliest when several CVEs match).
 *   3. PAIN / IRV / LEV    — when composite_score ≥ threshold (default 9.0) AND
 *      IRV (internet-reachable) AND LEV (likely-exploitable), treat as
 *      critical-equivalent: FEDRAMP_CMP_DEADLINES.critical days (Q2 — derive from
 *      the table so it tracks future updates).
 *   4. FedRAMP CMP table   — FEDRAMP_CMP_DEADLINES[severity] days from collected.
 *   5. Severity fallback    — only if the CMP table lacks the severity (should
 *      never happen with a typed Record); reports `source: 'severity-fallback'`
 *      so `--strict-risk` can reject it. Observable, never silent.
 *
 * Every result carries a `source` + `rationale` so a 3PAO can audit WHICH table
 * drove each deadline.
 *
 * REO: KEV dueDate is read verbatim (no synthetic +21d). FedRAMP CMP values are
 * the published constants in deadline-table.ts. Severity-fallback is surfaced,
 * not hidden.
 */
import type { Finding, Severity } from './envelope.ts';
import type { KevEntry } from './kev-feed.ts';
import { collectCveIds } from './risk-score.ts';
import { FEDRAMP_CMP_DEADLINES, SEVERITY_FALLBACK_DEADLINES } from './deadline-table.ts';

export type DeadlineSource =
  | 'kev'
  | 'fedramp-cmp'
  | 'pain-irv-lev'
  | 'operator-override'
  | 'severity-fallback';

export interface DeadlineResult {
  /** ISO datetime the finding must be remediated by. */
  deadline: string;
  source: DeadlineSource;
  /** Days from collected_at (0 for operator-override / verbatim KEV dueDate). */
  days_from_collected: number;
  /** Human-readable WHY. */
  rationale: string;
  kev_entry?: { cveID: string; dueDate: string; dateAdded: string };
  pain_irv_lev?: { pain?: number; irv?: boolean; lev?: boolean; composite_score?: number };
  operator_override?: { uuid: string };
}

export interface DeadlineContext {
  /** CISA KEV index (CVE-ID upper-case → entry), from core/kev-feed.ts. */
  kevIndex?: Map<string, KevEntry>;
  /** FedRAMP CMP severity → days. Defaults to FEDRAMP_CMP_DEADLINES. */
  cmpTable?: Partial<Record<Severity, number>>;
  /** PAIN/IRV/LEV composite threshold (default 9.0; operator-tunable via B.B1 risk-config). */
  painIrvLevThreshold?: number;
  /** Active operator risk-acceptance override (from B.B3) for this finding. */
  acceptanceOverride?: { deadline: string; uuid: string };
  /** Injectable clock for deterministic tests; defaults to new Date(). */
  now?: () => Date;
}

const DAY_MS = 24 * 60 * 60 * 1000;

/** Parse an ISO date/datetime to epoch ms; NaN-safe with a now() fallback. */
function parseCollected(collectedAt: string, now: () => Date): { ms: number; fellBack: boolean } {
  const t = new Date(collectedAt).getTime();
  if (Number.isNaN(t)) return { ms: now().getTime(), fellBack: true };
  return { ms: t, fellBack: false };
}

function addDays(baseMs: number, days: number): string {
  return new Date(baseMs + days * DAY_MS).toISOString();
}

/** Normalize a KEV date-only `YYYY-MM-DD` dueDate to an ISO datetime. */
function kevDueToIso(dueDate: string): string {
  return /^\d{4}-\d{2}-\d{2}$/.test(dueDate) ? `${dueDate}T00:00:00.000Z` : new Date(dueDate).toISOString();
}

/** True when the finding is likely-exploitable (LEV): explicit flag, KEV membership, or EPSS ≥ 0.95. */
function isLev(finding: Finding, kevMatched: boolean): boolean {
  if (finding.lev === true) return true;
  if (kevMatched) return true;
  const pct = finding.risk_score?.epss?.percentile;
  return typeof pct === 'number' && pct >= 0.95;
}

/**
 * Compute the remediation deadline for a finding via the documented cascade.
 * `collectedAt` is the evidence envelope's collected_at (the deadline anchor).
 */
export function computeDeadline(finding: Finding, ctx: DeadlineContext, collectedAt: string): DeadlineResult {
  const now = ctx.now ?? (() => new Date());
  const cmpTable = ctx.cmpTable ?? FEDRAMP_CMP_DEADLINES;
  const threshold = ctx.painIrvLevThreshold ?? 9.0;
  const { ms: collectedMs, fellBack } = parseCollected(collectedAt, now);
  const fallbackNote = fellBack
    ? ' (collected_at was unparseable; anchored at current time)'
    : '';

  // Earliest KEV match across all CVE ids the finding cites.
  const cveIds = collectCveIds(finding).map((c) => c.toUpperCase());
  let kevEntry: KevEntry | undefined;
  if (ctx.kevIndex) {
    for (const cve of cveIds) {
      const e = ctx.kevIndex.get(cve);
      if (!e || !e.dueDate) continue;
      if (!kevEntry || new Date(e.dueDate).getTime() < new Date(kevEntry.dueDate).getTime()) kevEntry = e;
    }
  }
  const kevMatched = Boolean(kevEntry);

  // 1. Operator override — capped by a KEV federal mandate (Q1).
  if (ctx.acceptanceOverride) {
    const opMs = new Date(ctx.acceptanceOverride.deadline).getTime();
    if (kevEntry) {
      const kevMs = new Date(kevEntry.dueDate).getTime();
      if (!Number.isNaN(kevMs) && kevMs < opMs) {
        return {
          deadline: kevDueToIso(kevEntry.dueDate),
          source: 'kev',
          days_from_collected: Math.round((kevMs - collectedMs) / DAY_MS),
          rationale:
            `Operator override ${ctx.acceptanceOverride.uuid} (${ctx.acceptanceOverride.deadline}) capped by CISA KEV ` +
            `${kevEntry.cveID} BOD 22-01 dueDate ${kevEntry.dueDate} — a federal mandate cannot be extended.`,
          kev_entry: { cveID: kevEntry.cveID, dueDate: kevEntry.dueDate, dateAdded: kevEntry.dateAdded },
        };
      }
    }
    return {
      deadline: ctx.acceptanceOverride.deadline,
      source: 'operator-override',
      days_from_collected: Number.isNaN(opMs) ? 0 : Math.round((opMs - collectedMs) / DAY_MS),
      rationale: `Active risk acceptance ${ctx.acceptanceOverride.uuid} extends the deadline to ${ctx.acceptanceOverride.deadline}.`,
      operator_override: { uuid: ctx.acceptanceOverride.uuid },
    };
  }

  // 2. KEV match — dueDate verbatim.
  if (kevEntry) {
    const kevMs = new Date(kevEntry.dueDate).getTime();
    return {
      deadline: kevDueToIso(kevEntry.dueDate),
      source: 'kev',
      days_from_collected: Number.isNaN(kevMs) ? 0 : Math.round((kevMs - collectedMs) / DAY_MS),
      rationale: `CVE ${kevEntry.cveID} in CISA KEV catalog; BOD 22-01 dueDate ${kevEntry.dueDate} (added ${kevEntry.dateAdded}).`,
      kev_entry: { cveID: kevEntry.cveID, dueDate: kevEntry.dueDate, dateAdded: kevEntry.dateAdded },
    };
  }

  // 3. PAIN / IRV / LEV override.
  const composite = finding.risk_score?.composite_score ?? 0;
  const irv = finding.irv === true;
  const lev = isLev(finding, kevMatched);
  if (composite >= threshold && irv && lev) {
    const days = cmpTable.critical ?? FEDRAMP_CMP_DEADLINES.critical;
    return {
      deadline: addDays(collectedMs, days),
      source: 'pain-irv-lev',
      days_from_collected: days,
      rationale:
        `Composite ${composite.toFixed(2)} ≥ ${threshold}, IRV=true, LEV=true; treated as critical-equivalent ` +
        `(FedRAMP CMP critical = ${days}d)${fallbackNote}.`,
      pain_irv_lev: { pain: finding.pain, irv, lev, composite_score: composite },
    };
  }

  // 4. FedRAMP CMP table.
  const cmpDays = cmpTable[finding.severity];
  if (typeof cmpDays === 'number') {
    return {
      deadline: addDays(collectedMs, cmpDays),
      source: 'fedramp-cmp',
      days_from_collected: cmpDays,
      rationale: `FedRAMP ConMon Strategy & Guide severity ${finding.severity} → ${cmpDays} days${fallbackNote}.`,
    };
  }

  // 5. Severity fallback (observable).
  const fbDays = SEVERITY_FALLBACK_DEADLINES[finding.severity] ?? 90;
  return {
    deadline: addDays(collectedMs, fbDays),
    source: 'severity-fallback',
    days_from_collected: fbDays,
    rationale:
      `REQUIRES-OPERATOR-INPUT: FedRAMP CMP table missing severity ${finding.severity} — ` +
      `re-download docs/sources/fedramp-conmon-strategy-guide.pdf and confirm the table. ` +
      `Fell back to ${fbDays} days${fallbackNote}.`,
  };
}
