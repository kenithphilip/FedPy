/**
 * LOOP-T.T4 — SSDF annual re-attestation cadence policy engine tests.
 *
 * Covers per-slice doc §8 rows T01–T05 (cadence resolution + regime validation)
 * and T16–T17 (due-state classification), plus the UTC date helpers. Pure
 * module: no clock, no I/O — every `as-of` timestamp is injected so the tests are
 * fully deterministic.
 */
import { describe, it, expect } from 'vitest';
import {
  CADENCE_TABLE,
  ALL_REGIMES,
  isRegime,
  resolveCadence,
  computeNextDueAt,
  computeDueState,
  addDaysUtc,
  diffDaysUtc,
  DUE_SOON_WINDOW_DAYS,
  InvalidRegimeError,
  InvalidCadenceOverrideError,
  type CadenceProductInput,
} from '../../core/ssdf-annual-attestation.ts';

function product(over: Partial<CadenceProductInput> = {}): CadenceProductInput {
  return {
    regime: 'm-22-18-mandatory',
    critical_software: false,
    continuous_delivery: false,
    cadence_override_days: null,
    ...over,
  };
}

describe('LOOP-T.T4 cadence policy engine', () => {
  // T.T4-T01
  it('M-22-18 non-critical software → 365-day next_due_at', () => {
    const r = resolveCadence(product());
    expect(r.days).toBe(365);
    expect(r.basis).toBe('base');
    expect(computeNextDueAt(product(), { submitted_at: '2026-01-01T00:00:00.000Z' })).toBe('2027-01-01T00:00:00.000Z');
  });

  // T.T4-T02
  it('M-22-18 critical software → 270-day next_due_at', () => {
    const p = product({ critical_software: true });
    const r = resolveCadence(p);
    expect(r.days).toBe(270);
    expect(r.basis).toBe('critical-software');
    expect(computeNextDueAt(p, { submitted_at: '2026-01-01T00:00:00.000Z' })).toBe(addDaysUtc('2026-01-01T00:00:00.000Z', 270));
  });

  // T.T4-T03
  it('operator override wins over the regime default', () => {
    const p = product({ critical_software: true, cadence_override_days: 180 });
    const r = resolveCadence(p);
    expect(r.days).toBe(180);
    expect(r.basis).toBe('override');
    expect(computeNextDueAt(p, { submitted_at: '2026-01-01T00:00:00.000Z' })).toBe(addDaysUtc('2026-01-01T00:00:00.000Z', 180));
  });

  // T.T4-T04
  it('M-26-05 tailored → 365-day default even for critical software', () => {
    const p = product({ regime: 'm-26-05-tailored', critical_software: true });
    const r = resolveCadence(p);
    expect(r.days).toBe(365);
    expect(CADENCE_TABLE['m-26-05-tailored'].critical_software_cadence_days).toBe(365);
  });

  // T.T4-T05
  it('unknown regime → InvalidRegimeError', () => {
    expect(() => resolveCadence(product({ regime: 'not-a-regime' }))).toThrow(InvalidRegimeError);
    expect(() => computeNextDueAt(product({ regime: '' }), { submitted_at: '2026-01-01T00:00:00.000Z' })).toThrow(InvalidRegimeError);
  });

  it('non-positive cadence_override_days → InvalidCadenceOverrideError (Q-T.T4-5)', () => {
    expect(() => resolveCadence(product({ cadence_override_days: 0 }))).toThrow(InvalidCadenceOverrideError);
    expect(() => resolveCadence(product({ cadence_override_days: -30 }))).toThrow(InvalidCadenceOverrideError);
  });

  it('isRegime accepts the four published regimes and rejects others', () => {
    for (const r of ALL_REGIMES) expect(isRegime(r)).toBe(true);
    expect(ALL_REGIMES).toHaveLength(4);
    expect(isRegime('m-99')).toBe(false);
    expect(isRegime(undefined)).toBe(false);
    expect(isRegime(365)).toBe(false);
  });

  it('continuous-delivery modifier is 0 for every published regime (no acceleration)', () => {
    for (const r of ALL_REGIMES) expect(CADENCE_TABLE[r].continuous_delivery_modifier_days).toBe(0);
    const p = product({ continuous_delivery: true });
    expect(resolveCadence(p).days).toBe(365);
  });
});

describe('LOOP-T.T4 due-state classification', () => {
  // T.T4-T16
  it('due_soon when within 60 days of next_due_at', () => {
    // submitted 2026-02-25 + 365d = 2027-02-25; as-of 2027-01-01 → 55 days out.
    const nextDue = computeNextDueAt(product(), { submitted_at: '2026-02-25T00:00:00.000Z' });
    expect(diffDaysUtc('2027-01-01T00:00:00.000Z', nextDue)).toBe(55);
    expect(computeDueState(nextDue, '2027-01-01T00:00:00.000Z')).toBe('due_soon');
    expect(DUE_SOON_WINDOW_DAYS).toBe(60);
  });

  // T.T4-T17
  it('overdue when past next_due_at', () => {
    const nextDue = computeNextDueAt(product(), { submitted_at: '2025-11-01T00:00:00.000Z' });
    expect(computeDueState(nextDue, '2027-01-01T00:00:00.000Z')).toBe('overdue');
  });

  it('due_now on the due day, current far out, never_submitted for null', () => {
    const dueNow = computeNextDueAt(product(), { submitted_at: '2026-01-01T00:00:00.000Z' });
    expect(computeDueState(dueNow, '2027-01-01T00:00:00.000Z')).toBe('due_now');
    const current = computeNextDueAt(product(), { submitted_at: '2026-12-01T00:00:00.000Z' });
    expect(computeDueState(current, '2027-01-01T00:00:00.000Z')).toBe('current');
    expect(computeDueState(null, '2027-01-01T00:00:00.000Z')).toBe('never_submitted');
  });

  it('addDaysUtc / diffDaysUtc are exact UTC calendar arithmetic', () => {
    expect(addDaysUtc('2026-01-01T00:00:00.000Z', 365)).toBe('2027-01-01T00:00:00.000Z');
    expect(diffDaysUtc('2026-01-01T00:00:00.000Z', '2027-01-01T00:00:00.000Z')).toBe(365);
    expect(diffDaysUtc('2027-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')).toBe(-365);
  });
});
