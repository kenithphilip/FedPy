/**
 * Normalized vulnerability ledger + SLA evaluation for the VDR family.
 *
 * The ledger is the spine VDR-CSO-RES / VDR-EVA-* / VDR-TFR-* measure against
 * (see docs/analysis/vdr.md). Collectors (Inspector2 / ECR / Artifact Analysis
 * / SCC) feed it normalized entries; this module enriches each entry with:
 *   - CISA KEV due dates + a kev flag (VDR-TFR-KEV / VDR-BST-AKE / VDR-EVA-ELX)
 *   - SLA status (overdue / days_remaining) per the VDR-TFR-* timeframe tables
 *
 * READ-ONLY and PURE: no cloud-SDK calls, no I/O, deterministic given inputs
 * (callers pass `now` for testability). Date math delegates to core/bizdays.ts.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * SLA DAY-TABLES (named constants, sourced from docs/analysis/vdr.md)
 * ──────────────────────────────────────────────────────────────────────────
 *
 * VDR-TFR-EVU — Evaluate Vulnerabilities Quickly (detection → evaluation):
 *   Low 7d / Moderate 5d / High 2d   (vdr.md line 351)
 *
 * VDR-TFR-MAV — Mark Accepted Vulnerabilities (aging from evaluation):
 *   192 days at every level          (vdr.md line 385)
 *
 * VDR-TFR-KEV — Remediate KEVs:
 *   Deadline is CISA's per-CVE dueDate from the KEV catalog, NOT a fixed
 *   window — see core/kev-feed.ts.   (vdr.md line 374)
 *
 * VDR-TFR-PVR — Mitigation/Remediation Expectations (remediation from
 *   evaluation, keyed on PAIN × internet-reachability (IRV) × likely-
 *   exploitability (LEV)). vdr.md line 462 publishes the full Low table:
 *
 *        PAIN | IRV+LEV | nIRV+LEV | non-LEV   (days)
 *        -----+---------+----------+--------
 *         N5  |    4    |    8     |   32
 *         N4  |    8    |   32     |   64
 *         N3  |   32    |   64     |  192
 *         N2  |   96    |  160     |  192
 *
 *   Moderate/High "tighten these (e.g. Moderate N5 IRV+LEV = 2d)" (vdr.md
 *   line 462). vdr.md publishes the Low matrix in full and the Moderate N5
 *   IRV+LEV anchor (2d); the full Moderate/High matrices are not enumerated
 *   in the analysis. We encode Low verbatim (the authoritative, tested table),
 *   and DERIVE Moderate/High by halving each successive level's windows from
 *   the documented anchor (Low N5 IRV+LEV 4d → Moderate 2d → High 1d), floored
 *   at 1 day. These derived tables are clearly labeled and easily replaced
 *   once FedRAMP publishes the full Moderate/High matrices.
 */
import { calendarDaysBetween } from './bizdays.ts';
import type { KevCatalog } from './kev-feed.ts';

export type ImpactTier = 'low' | 'moderate' | 'high';

/** Potential Adverse Impact rating (VDR-EVA-EPA). N1 negligible … N5 catastrophic(>1). */
export type PainRating = 'N1' | 'N2' | 'N3' | 'N4' | 'N5';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** Lifecycle state of a finding in the response process (VDR-CSO-RES). */
export type LifecycleState =
  | 'detected'
  | 'evaluated'
  | 'partially_mitigated'
  | 'mitigated'
  | 'remediated'
  | 'accepted'
  | 'false_positive';

/** A normalized ledger entry. Collectors supply these; buildLedger enriches them. */
export interface LedgerEntry {
  /** CVE identifier when known, e.g. "CVE-2021-44228". */
  cve?: string;
  /** Scanner / engineering severity. */
  severity: Severity;
  /** ISO timestamp the vuln was first observed (detection time). */
  first_seen: string;
  /** ISO timestamp the VDR-EVA evaluation completed, when recorded. */
  evaluated_at?: string;
  /** Explicit due date (ISO). When unset and the CVE is a KEV, the KEV dueDate is filled in. */
  due?: string;
  /** Logical source, e.g. "inspector2", "ecr", "artifact-analysis", "scc". */
  source: string;
  /** Affected resource identifier (ARN / GCP name / image digest). */
  resource?: string;
  /** True when the CVE is in the CISA KEV catalog. */
  kev: boolean;
  /** EPSS exploitation-probability score (0..1), when available. */
  epss?: number;
  /** Internet-Reachable Vulnerability flag (VDR-EVA-EIR). */
  irv?: boolean;
  /** Likely-Exploitable Vulnerability flag (VDR-EVA-ELX). */
  lev?: boolean;
  /** Potential Adverse Impact rating (VDR-EVA-EPA). */
  pain?: PainRating;
  /** Lifecycle state; defaults to 'detected' if unset. */
  state?: LifecycleState;

  /** ── Fields populated by buildLedger (enrichment output) ── */
  /** SLA evaluation result attached during enrichment. */
  sla?: SlaStatus;
}

/** PVR matrix keyed by exploitability/reachability column. */
export interface PvrRow {
  /** Internet-reachable AND likely-exploitable. */
  irv_lev: number;
  /** NOT internet-reachable but likely-exploitable. */
  nirv_lev: number;
  /** Not likely-exploitable. */
  non_lev: number;
}

export type PvrTable = Record<'N2' | 'N3' | 'N4' | 'N5', PvrRow>;

/**
 * VDR-TFR-PVR Low table — published verbatim in vdr.md line 462.
 * Days from evaluation, keyed on PAIN × (IRV, LEV).
 */
export const PVR_TABLE_LOW: PvrTable = {
  N5: { irv_lev: 4, nirv_lev: 8, non_lev: 32 },
  N4: { irv_lev: 8, nirv_lev: 32, non_lev: 64 },
  N3: { irv_lev: 32, nirv_lev: 64, non_lev: 192 },
  N2: { irv_lev: 96, nirv_lev: 160, non_lev: 192 },
};

/** Halve each window (floor at 1 day) — used to derive tighter higher-tier tables. */
function tighten(row: PvrRow): PvrRow {
  return {
    irv_lev: Math.max(1, Math.floor(row.irv_lev / 2)),
    nirv_lev: Math.max(1, Math.floor(row.nirv_lev / 2)),
    non_lev: Math.max(1, Math.floor(row.non_lev / 2)),
  };
}

function tightenTable(t: PvrTable): PvrTable {
  return { N5: tighten(t.N5), N4: tighten(t.N4), N3: tighten(t.N3), N2: tighten(t.N2) };
}

/**
 * VDR-TFR-PVR Moderate table — DERIVED (vdr.md states Moderate tightens Low,
 * anchored by "Moderate N5 IRV+LEV = 2d", which halving Low's 4d reproduces).
 * Replace with the published FedRAMP Moderate matrix when available.
 */
export const PVR_TABLE_MODERATE: PvrTable = tightenTable(PVR_TABLE_LOW);

/**
 * VDR-TFR-PVR High table — DERIVED by tightening Moderate one more step
 * (vdr.md: High has a distinct, tighter published table not enumerated here).
 * Replace with the published FedRAMP High matrix when available.
 */
export const PVR_TABLE_HIGH: PvrTable = tightenTable(PVR_TABLE_MODERATE);

export const PVR_TABLES: Record<ImpactTier, PvrTable> = {
  low: PVR_TABLE_LOW,
  moderate: PVR_TABLE_MODERATE,
  high: PVR_TABLE_HIGH,
};

/** VDR-TFR-EVU detection→evaluation latency SLA, in days. (vdr.md line 351) */
export const EVU_EVALUATION_DAYS: Record<ImpactTier, number> = {
  low: 7,
  moderate: 5,
  high: 2,
};

/** VDR-TFR-MAV accepted-vulnerability aging clock, in days. (vdr.md line 385) */
export const MAV_ACCEPTANCE_DAYS = 192;

/** Which VDR-TFR rule produced the binding deadline for an entry. */
export type SlaBasis = 'kev' | 'pvr' | 'mav' | 'evu' | 'none';

export interface SlaStatus {
  /** The rule whose deadline binds this entry. */
  basis: SlaBasis;
  /** ISO due date for the binding rule, when computable. */
  due?: string;
  /** Allowed window in days for the binding rule, when applicable. */
  window_days?: number;
  /** True when `now` is past `due`. */
  overdue: boolean;
  /** Negative = days remaining; positive = days overdue. Undefined if not computable. */
  days_remaining?: number;
  /** True when SLA could not be computed for lack of inputs (missing PAIN/IRV/LEV/timestamps). */
  indeterminate: boolean;
  /** Human-readable note explaining the basis or why it is indeterminate. */
  note?: string;
}

export interface BuildLedgerOptions {
  /** Impact tier selecting which SLA tables apply. Default 'moderate'. */
  tier?: ImpactTier;
  /** Fixed "now" (ISO) for deterministic SLA math. Default: real now. */
  now?: string;
}

/** Look up the PVR remediation window (days) for a (PAIN, IRV, LEV) tuple. */
export function pvrWindowDays(
  table: PvrTable,
  pain: PainRating,
  irv: boolean,
  lev: boolean,
): number | undefined {
  if (pain === 'N1') return undefined; // N1 = remaining vuln (VDR-TFR-RMN), no hard SLA.
  const row = table[pain];
  if (!row) return undefined;
  if (lev) return irv ? row.irv_lev : row.nirv_lev;
  return row.non_lev;
}

function addCalendarDays(iso: string, days: number): string {
  return new Date(new Date(iso).getTime() + days * 86_400_000).toISOString();
}

/**
 * Compute the binding SLA for a single (already KEV-enriched) entry.
 *
 * Precedence reflects "the soonest hard deadline wins":
 *   1. KEV due date (VDR-TFR-KEV) — a hard CISA deadline whenever the CVE is a KEV.
 *   2. PVR remediation window (VDR-TFR-PVR) — when PAIN/IRV/LEV + evaluated_at present.
 *   3. MAV 192-day acceptance clock (VDR-TFR-MAV) — fallback when PVR can't be computed.
 *   4. EVU evaluation-latency (VDR-TFR-EVU) — only while still in 'detected' (unevaluated).
 *
 * Terminal states (remediated / accepted / false_positive) are never overdue.
 */
function evaluateSla(entry: LedgerEntry, tier: ImpactTier, now: string): SlaStatus {
  const nowDate = new Date(now);
  const state = entry.state ?? 'detected';
  const terminal = state === 'remediated' || state === 'accepted' || state === 'false_positive';

  const candidates: Array<{ basis: SlaBasis; due: string; window_days?: number; note?: string }> = [];

  // 1. KEV due date.
  if (entry.kev && entry.due) {
    candidates.push({ basis: 'kev', due: entry.due, note: 'CISA KEV catalog due date (VDR-TFR-KEV).' });
  }

  const evalAnchor = entry.evaluated_at;

  // 2. PVR remediation window (needs evaluation anchor + full classification).
  if (evalAnchor && entry.pain && entry.irv != null && entry.lev != null) {
    const window = pvrWindowDays(PVR_TABLES[tier], entry.pain, entry.irv, entry.lev);
    if (window != null) {
      candidates.push({
        basis: 'pvr',
        due: addCalendarDays(evalAnchor, window),
        window_days: window,
        note: `VDR-TFR-PVR ${tier} remediation window for ${entry.pain}/${entry.irv ? 'IRV' : 'nIRV'}/${entry.lev ? 'LEV' : 'non-LEV'}.`,
      });
    }
  }

  // 3. MAV acceptance clock (fallback when an evaluation anchor exists).
  if (evalAnchor) {
    candidates.push({
      basis: 'mav',
      due: addCalendarDays(evalAnchor, MAV_ACCEPTANCE_DAYS),
      window_days: MAV_ACCEPTANCE_DAYS,
      note: `VDR-TFR-MAV: must be accepted within ${MAV_ACCEPTANCE_DAYS} days of evaluation.`,
    });
  }

  // 4. EVU latency — only meaningful while unevaluated.
  if (!evalAnchor && state === 'detected') {
    const window = EVU_EVALUATION_DAYS[tier];
    candidates.push({
      basis: 'evu',
      due: addCalendarDays(entry.first_seen, window),
      window_days: window,
      note: `VDR-TFR-EVU ${tier}: evaluate within ${window} days of detection.`,
    });
  }

  if (candidates.length === 0) {
    return {
      basis: 'none',
      overdue: false,
      indeterminate: true,
      note:
        'SLA indeterminate: no KEV due date and no evaluation timestamp / classification ' +
        '(PAIN, IRV, LEV) to compute a VDR-TFR window.',
    };
  }

  // Bind to the soonest deadline.
  candidates.sort((a, b) => new Date(a.due).getTime() - new Date(b.due).getTime());
  const binding = candidates[0]!;
  const dueDate = new Date(binding.due);
  const overdue = !terminal && nowDate.getTime() > dueDate.getTime();
  // days_remaining: negative = remaining, positive = overdue (now - due).
  const daysRemaining = calendarDaysBetween(dueDate, nowDate);

  return {
    basis: binding.basis,
    due: binding.due,
    window_days: binding.window_days,
    overdue,
    days_remaining: daysRemaining,
    indeterminate: false,
    note: terminal ? `${binding.note} (state=${state}; not counted as overdue)` : binding.note,
  };
}

/**
 * Build the enriched ledger.
 *
 * For each entry:
 *   - mark `kev` and fill `due` from the CISA KEV catalog when the CVE matches
 *     (an explicitly-supplied `due` is preserved);
 *   - compute `sla` per the VDR-TFR-* tables for the selected impact tier.
 *
 * Pure: returns NEW entry objects; the inputs are not mutated.
 */
export function buildLedger(
  findings: LedgerEntry[],
  kev: KevCatalog,
  opts: BuildLedgerOptions = {},
): LedgerEntry[] {
  const tier = opts.tier ?? 'moderate';
  const now = opts.now ?? new Date().toISOString();

  return findings.map((f) => {
    const cveKey = f.cve ? f.cve.trim().toUpperCase() : undefined;
    const kevEntry = cveKey ? kev.byCve.get(cveKey) : undefined;
    const isKev = Boolean(kevEntry);

    const enriched: LedgerEntry = {
      ...f,
      cve: cveKey ?? f.cve,
      kev: isKev,
      // Preserve an explicit due; otherwise inherit the KEV catalog due date.
      due: f.due ?? kevEntry?.dueDate ?? undefined,
      state: f.state ?? 'detected',
    };

    enriched.sla = evaluateSla(enriched, tier, now);
    return enriched;
  });
}
