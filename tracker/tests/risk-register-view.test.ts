/**
 * Tests for client/src/lib/risk-register-view.ts — the pure logic behind the
 * Central Risk Register React pages (form validation + the deterministic NIST
 * 800-30 inherent hint + role-gated CTAs + inherent-descending sort). These stand
 * in for DOM-render tests: the tracker has no jsdom/@testing-library and vitest
 * only collects server/** + tests/** (same posture as B.B3/B.B4).
 */
import { describe, it, expect } from 'vitest';
import {
  validateOrganisationalRiskForm,
  canSubmitOrganisationalRiskForm,
  descriptionRemaining,
  suggestedInherent,
  combineInherent,
  sortByInherentDescending,
  canCreateOrganisationalRisk,
  canCloseOrganisationalRisk,
  canViewRiskRegister,
  RISK_BANDS, RISK_CATEGORIES, RISK_TREATMENTS,
  type OrganisationalRiskFormState,
} from '../client/src/lib/risk-register-view.ts';

const NOW = new Date('2026-07-02T12:00:00.000Z');
const future = (days: number) => new Date(NOW.getTime() + days * 86_400_000).toISOString();

function form(over: Partial<OrganisationalRiskFormState> = {}): OrganisationalRiskFormState {
  return {
    title: 'Key subprocessor bankruptcy',
    description: 'd'.repeat(140),
    category: 'third-party',
    likelihood: 'high',
    impact: 'very-high',
    residual_risk: 'moderate',
    treatment: 'mitigate',
    review_date: future(60),
    ...over,
  };
}

describe('validateOrganisationalRiskForm / canSubmit', () => {
  it('accepts a fully valid form', () => {
    expect(validateOrganisationalRiskForm(form(), NOW)).toEqual([]);
    expect(canSubmitOrganisationalRiskForm(form(), NOW)).toBe(true);
  });

  it('requires a ≥100 char description', () => {
    const s = form({ description: 'short' });
    expect(canSubmitOrganisationalRiskForm(s, NOW)).toBe(false);
    expect(validateOrganisationalRiskForm(s, NOW).some((e) => e.includes('100'))).toBe(true);
    expect(descriptionRemaining('short')).toBe(95);
    expect(descriptionRemaining('d'.repeat(100))).toBe(0);
  });

  it('requires NIST 800-30 bands, a category, and a treatment', () => {
    expect(canSubmitOrganisationalRiskForm(form({ likelihood: '' }), NOW)).toBe(false);
    expect(canSubmitOrganisationalRiskForm(form({ category: '' }), NOW)).toBe(false);
    expect(canSubmitOrganisationalRiskForm(form({ treatment: '' }), NOW)).toBe(false);
    // The dropdown option sets are the NIST/ISO enums.
    expect(RISK_BANDS).toEqual(['very-low', 'low', 'moderate', 'high', 'very-high']);
    expect(RISK_TREATMENTS).toEqual(['accept', 'mitigate', 'transfer', 'avoid']);
    expect(RISK_CATEGORIES).toContain('supply-chain');
  });

  it('requires a review date at least 30 days out', () => {
    expect(canSubmitOrganisationalRiskForm(form({ review_date: future(10) }), NOW)).toBe(false);
    expect(validateOrganisationalRiskForm(form({ review_date: future(10) }), NOW).some((e) => e.includes('30 days'))).toBe(true);
  });
});

describe('deterministic inherent hint (NIST 800-30 Table I-2, Q5)', () => {
  it('combines likelihood × impact per the published table', () => {
    expect(combineInherent('very-high', 'very-high')).toBe('very-high');
    expect(combineInherent('moderate', 'high')).toBe('moderate');
    expect(combineInherent('low', 'low')).toBe('low');
    expect(combineInherent('very-low', 'very-low')).toBe('very-low');
  });

  it('suggestedInherent is empty until both bands are set, then matches the matrix', () => {
    expect(suggestedInherent(form({ likelihood: '', impact: '' }))).toBe('');
    expect(suggestedInherent(form({ likelihood: 'high', impact: 'very-high' }))).toBe('very-high');
  });
});

describe('role-gated CTAs + sort', () => {
  it('shows create/close only to iso/ao/admin', () => {
    expect(canCreateOrganisationalRisk('iso')).toBe(true);
    expect(canCreateOrganisationalRisk('ao')).toBe(true);
    expect(canCreateOrganisationalRisk('admin')).toBe(true);
    expect(canCreateOrganisationalRisk('assessor')).toBe(false);
    expect(canCloseOrganisationalRisk('iso', 'open')).toBe(true);
    expect(canCloseOrganisationalRisk('iso', 'closed')).toBe(false);
    expect(canCloseOrganisationalRisk('viewer', 'open')).toBe(false);
  });

  it('shows the register nav link to every authenticated role', () => {
    expect(canViewRiskRegister('assessor')).toBe(true);
    expect(canViewRiskRegister('viewer')).toBe(true);
  });

  it('sorts entries by inherent risk descending (very-high first, marker last)', () => {
    const entries = [
      { inherent_risk: 'low' as const },
      { inherent_risk: 'very-high' as const },
      { inherent_risk: 'REQUIRES-OPERATOR-INPUT' as const },
      { inherent_risk: 'moderate' as const },
    ];
    expect(sortByInherentDescending(entries).map((e) => e.inherent_risk))
      .toEqual(['very-high', 'moderate', 'low', 'REQUIRES-OPERATOR-INPUT']);
  });
});
