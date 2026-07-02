/**
 * SSDF annual re-attestation cadence policy engine (LOOP-T.T4).
 *
 * Why this exists:
 *   OMB M-22-18 (Sep 14 2022) as amended by M-23-16 (Jun 9 2023) requires a
 *   software producer to keep its CISA Common Form attestation (T.T3) current on
 *   an annual cadence, "or upon material change". OMB M-26-05 (Jan 23 2026)
 *   rescinded the *mandatory* collection but agencies may continue to require the
 *   Common Form on a tailored, risk-based basis, and legacy contract flow-downs
 *   still bind (LOOP-T-RISKS T-X19). This module is the deterministic, regime-aware
 *   cadence engine that computes the producer's INTERNAL next-review date per
 *   (product × regime); it never treats that date as an expiry — the M-23-16
 *   binding clause keeps an attestation in force until the producer notifies the
 *   agency (LOOP-T-RISKS T.T4-R1). The actual binding-clause trigger is the
 *   material-change detector (core/ssdf-material-change-detector.ts), not this
 *   engine.
 *
 * REO posture:
 *   - The four regimes + their cadence day-counts are published OMB timelines
 *     (M-22-18 §III / M-23-16 §III / M-26-05), not invented values (Rule 3).
 *   - The regime is operator-supplied (config.yaml `ssdf.products[].regime`,
 *     REO Rule 4); an absent or unrecognised regime throws `InvalidRegimeError`
 *     rather than silently defaulting to a mandatory cadence.
 *   - Pure module: no clock, no I/O. `as-of` timestamps are injected by the
 *     caller so behaviour is fully deterministic + testable.
 */

// ─── Regime enum (operator-supplied; published OMB memoranda) ─────────────────

export type SsdfRegime =
  | 'm-22-18-mandatory'
  | 'm-23-16-extended'
  | 'm-26-05-tailored'
  | 'post-m-26-05-future';

export const ALL_REGIMES: SsdfRegime[] = [
  'm-22-18-mandatory',
  'm-23-16-extended',
  'm-26-05-tailored',
  'post-m-26-05-future',
];

export function isRegime(x: unknown): x is SsdfRegime {
  return typeof x === 'string' && (ALL_REGIMES as string[]).includes(x);
}

// ─── Cadence policy table (per-slice doc §6 Step 1) ───────────────────────────

export interface CadencePolicy {
  regime: SsdfRegime;
  /** Annual internal-review cadence for non-critical software (days). */
  base_cadence_days: number;
  /** Shorter cadence when the product is EO-critical software (M-22-18 §III: 270-day critical-software collection window). */
  critical_software_cadence_days: number;
  /** Days subtracted from the base for continuous-delivery products (0 = no modifier). */
  continuous_delivery_modifier_days: number;
}

/**
 * The four regimes' cadence day-counts. M-22-18 / M-23-16 set 365 days for
 * general software and 270 days for critical software (the two memos' §III
 * collection windows); under the M-26-05 tailored / post-M-26-05 regimes the
 * cadence is the operator's internal 365-day review baseline (no
 * critical-software acceleration is federally mandated once the collection is
 * voluntary). Values are published OMB timelines (REO Rule 3).
 */
export const CADENCE_TABLE: Record<SsdfRegime, CadencePolicy> = {
  'm-22-18-mandatory': { regime: 'm-22-18-mandatory', base_cadence_days: 365, critical_software_cadence_days: 270, continuous_delivery_modifier_days: 0 },
  'm-23-16-extended': { regime: 'm-23-16-extended', base_cadence_days: 365, critical_software_cadence_days: 270, continuous_delivery_modifier_days: 0 },
  'm-26-05-tailored': { regime: 'm-26-05-tailored', base_cadence_days: 365, critical_software_cadence_days: 365, continuous_delivery_modifier_days: 0 },
  'post-m-26-05-future': { regime: 'post-m-26-05-future', base_cadence_days: 365, critical_software_cadence_days: 365, continuous_delivery_modifier_days: 0 },
};

// ─── Typed errors (REO — never silently default) ──────────────────────────────

/** Thrown when a product's `regime` is absent or not one of the four published regimes. */
export class InvalidRegimeError extends Error {
  readonly regime: string;
  constructor(regime: string) {
    super(
      `Unknown SSDF attestation regime "${regime}"; ` +
        `config.yaml ssdf.products[].regime must be one of: ${ALL_REGIMES.join(', ')} ` +
        `(REO Rule 4 — the regime is operator-supplied and is never defaulted).`,
    );
    this.name = 'InvalidRegimeError';
    this.regime = regime;
  }
}

/** Thrown when `cadence_override_days` is present but not a positive integer (Q-T.T4-5). */
export class InvalidCadenceOverrideError extends Error {
  readonly value: number;
  constructor(value: number) {
    super(`cadence_override_days must be a positive integer when set; got ${value}.`);
    this.name = 'InvalidCadenceOverrideError';
    this.value = value;
  }
}

// ─── Cadence resolution ───────────────────────────────────────────────────────

export interface CadenceProductInput {
  /** Operator-supplied regime; validated against the four published regimes. */
  regime: string;
  critical_software: boolean;
  continuous_delivery?: boolean;
  /** Non-null operator override wins over the regime default; must be > 0. */
  cadence_override_days: number | null;
}

export type CadenceBasis = 'override' | 'critical-software' | 'base';

export interface ResolvedCadence {
  days: number;
  basis: CadenceBasis;
  policy: CadencePolicy;
}

/**
 * Resolve the cadence day-count for a product (per-slice doc §6 Step 1):
 *   1. `cadence_override_days` if non-null (operator over-ride; must be > 0).
 *   2. else `critical_software_cadence_days` if `critical_software === true`.
 *   3. else `base_cadence_days`.
 * A continuous-delivery product subtracts `continuous_delivery_modifier_days`
 * (floored at 1 day) — currently 0 for every published regime.
 */
export function resolveCadence(product: CadenceProductInput): ResolvedCadence {
  if (!isRegime(product.regime)) throw new InvalidRegimeError(product.regime);
  const policy = CADENCE_TABLE[product.regime];

  if (product.cadence_override_days !== null && product.cadence_override_days !== undefined) {
    const d = product.cadence_override_days;
    if (!Number.isInteger(d) || d <= 0) throw new InvalidCadenceOverrideError(d);
    return { days: d, basis: 'override', policy };
  }

  const baseDays = product.critical_software ? policy.critical_software_cadence_days : policy.base_cadence_days;
  const basis: CadenceBasis = product.critical_software ? 'critical-software' : 'base';
  const days = product.continuous_delivery
    ? Math.max(1, baseDays - policy.continuous_delivery_modifier_days)
    : baseDays;
  return { days, basis, policy };
}

// ─── UTC calendar-day helpers (deterministic; DST-free) ───────────────────────

const MS_PER_DAY = 86_400_000;

/** Parse an ISO-8601 timestamp to epoch ms; throws on an unparseable value. */
function epochMs(iso: string): number {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) throw new Error(`invalid ISO-8601 timestamp: "${iso}"`);
  return t;
}

/** `iso + days` as an ISO-8601 UTC timestamp. Pure UTC arithmetic (no DST). */
export function addDaysUtc(iso: string, days: number): string {
  return new Date(epochMs(iso) + days * MS_PER_DAY).toISOString();
}

/** Whole UTC days from `a` to `b` (floored). Positive when `b` is after `a`. */
export function diffDaysUtc(a: string, b: string): number {
  return Math.floor((epochMs(b) - epochMs(a)) / MS_PER_DAY);
}

// ─── Next-due computation ─────────────────────────────────────────────────────

export interface AttestationSubmissionRef {
  /** ISO-8601 UTC timestamp the attestation was (or would be) submitted. */
  submitted_at: string;
}

/**
 * Compute the INTERNAL next-review date for a submission:
 * `submitted_at + resolveCadence(product).days`, as an ISO-8601 UTC timestamp.
 * NOT an expiry (LOOP-T-RISKS T.T4-R1) — the M-23-16 binding clause keeps the
 * attestation in force until the producer notifies the agency; this is the
 * producer's proactive-review deadline.
 */
export function computeNextDueAt(product: CadenceProductInput, submission: AttestationSubmissionRef): string {
  const { days } = resolveCadence(product);
  return addDaysUtc(submission.submitted_at, days);
}

// ─── Due-state classification ─────────────────────────────────────────────────

export type DueState = 'current' | 'due_soon' | 'due_now' | 'overdue' | 'never_submitted';

/** Products land in `due_soon` this many days before `next_due_at`. */
export const DUE_SOON_WINDOW_DAYS = 60;

/**
 * Classify a status row's `due_state` from its `next_due_at` and an as-of date:
 *   - null `next_due_at`         → `never_submitted`
 *   - as-of after next_due_at    → `overdue`
 *   - as-of on next_due_at (day) → `due_now`
 *   - within DUE_SOON_WINDOW_DAYS → `due_soon`
 *   - otherwise                  → `current`
 */
export function computeDueState(nextDueAt: string | null, asOf: string): DueState {
  if (nextDueAt === null) return 'never_submitted';
  const daysUntil = diffDaysUtc(asOf, nextDueAt);
  if (daysUntil < 0) return 'overdue';
  if (daysUntil === 0) return 'due_now';
  if (daysUntil <= DUE_SOON_WINDOW_DAYS) return 'due_soon';
  return 'current';
}
