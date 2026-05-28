/**
 * Tests for core/family-rollup.ts (P4c) — pure per-family aggregation.
 */
import { describe, it, expect } from 'vitest';
import { rollupFromEvidence } from '../../core/family-rollup.ts';

function ev(ksi_id: string, pass: boolean, opts: { family?: string; category?: any; awareness_only?: boolean; impact_level?: any } = {}) {
  return {
    ksi_id,
    family: opts.family,
    category: opts.category,
    awareness_only: opts.awareness_only,
    impact_level: opts.impact_level,
    rollup: { pass, passing_findings: pass ? 1 : 0, failing_findings: pass ? 0 : 1, warnings: [], missing_evidence: [], alternatives_in_play: 0 },
  };
}

describe('rollupFromEvidence', () => {
  it('groups by family and computes pass rate excluding awareness items', () => {
    const r = rollupFromEvidence([
      ev('KSI-IAM-MFA', true, { family: 'IAM', category: 'ksi-indicator', impact_level: 'moderate' }),
      ev('KSI-IAM-ELP', false, { family: 'IAM', category: 'ksi-indicator' }),
      ev('VDR-CSO-DET', false, { family: 'VDR', category: 'frr-requirement' }),
      ev('VDR-AGM-MAP', true, { family: 'VDR', category: 'frr-requirement', awareness_only: true }),
    ]);
    expect(r.impact_level).toBe('moderate');
    const iam = r.families.find((f) => f.family === 'IAM')!;
    expect(iam.total).toBe(2);
    expect(iam.passed).toBe(1);
    expect(iam.failed).toBe(1);
    expect(iam.pass_rate).toBe(0.5);
    const vdr = r.families.find((f) => f.family === 'VDR')!;
    expect(vdr.total).toBe(2);
    expect(vdr.awareness).toBe(1);     // VDR-AGM-MAP is awareness-only
    expect(vdr.failed).toBe(1);
    expect(vdr.passed).toBe(0);
    expect(vdr.pass_rate).toBe(0);     // 0 of 1 provider-scoped passed
  });

  it('derives family from the id when family field is absent', () => {
    const r = rollupFromEvidence([ev('KSI-CMT-RVP', true), ev('KSI-CMT-LMC', false)]);
    const cmt = r.families.find((f) => f.family === 'CMT')!;
    expect(cmt.total).toBe(2);
    expect(cmt.passed).toBe(1);
  });

  it('totals exclude awareness from pass/fail', () => {
    const r = rollupFromEvidence([
      ev('A-X-Y', true, { family: 'A' }),
      ev('B-X-Y', true, { family: 'B', awareness_only: true }),
    ]);
    expect(r.totals.total).toBe(2);
    expect(r.totals.passed).toBe(1);
    expect(r.totals.awareness).toBe(1);
    expect(r.totals.pass_rate).toBe(1);
  });
});
