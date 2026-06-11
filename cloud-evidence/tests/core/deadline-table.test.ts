/**
 * Pinning tests for the FedRAMP CMP deadline table (LOOP-B.B2). These values are
 * FedRAMP-published constants; if the source PDF cadence changes, update
 * core/deadline-table.ts AND this test atomically.
 */
import { describe, it, expect } from 'vitest';
import { FEDRAMP_CMP_DEADLINES, SEVERITY_FALLBACK_DEADLINES } from '../../core/deadline-table.ts';

describe('FEDRAMP_CMP_DEADLINES', () => {
  it('pins the published FedRAMP ConMon Strategy & Guide severity → days cadence', () => {
    expect(FEDRAMP_CMP_DEADLINES).toEqual({
      critical: 15,
      high: 30,
      medium: 90,
      low: 180,
      info: 365,
    });
  });

  it('has High = 30 days (NOT LOOP-A.A1’s 60) — the FedRAMP CMP divergence B.B2 fixes', () => {
    expect(FEDRAMP_CMP_DEADLINES.high).toBe(30);
    expect(FEDRAMP_CMP_DEADLINES.high).not.toBe(SEVERITY_FALLBACK_DEADLINES.high);
  });

  it('retains LOOP-A.A1 values as the observable severity-fallback table', () => {
    expect(SEVERITY_FALLBACK_DEADLINES).toEqual({
      critical: 30,
      high: 60,
      medium: 90,
      low: 180,
      info: 365,
    });
  });
});
