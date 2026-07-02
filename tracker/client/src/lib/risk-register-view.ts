/**
 * LOOP-B.B5 — Pure view-logic for the Central Risk Register UI.
 *
 * The tracker toolchain has no jsdom / @testing-library, and vitest only collects
 * `server/**` + `tests/**` — so the React pages can't be unit-rendered. Their
 * decision logic (form validation, the deterministic inherent-band hint, role-gated
 * CTAs, inherent-descending sort) lives here as pure functions and is unit-tested in
 * `tracker/tests/risk-register-view.test.ts`. The pages import these helpers, so the
 * tested rules ARE the rendered behaviour (same pattern as B.B3/B.B4 view libs).
 */

export type RiskBand = 'very-low' | 'low' | 'moderate' | 'high' | 'very-high';
export type RiskBandOrMarker = RiskBand | 'REQUIRES-OPERATOR-INPUT';
export type RiskTreatment = 'accept' | 'mitigate' | 'transfer' | 'avoid';
export type OrganisationalRiskCategory =
  | 'third-party' | 'supply-chain' | 'environmental' | 'contractual'
  | 'operational' | 'organisational' | 'other';

export const RISK_BANDS: RiskBand[] = ['very-low', 'low', 'moderate', 'high', 'very-high'];
export const RISK_CATEGORIES: OrganisationalRiskCategory[] =
  ['third-party', 'supply-chain', 'environmental', 'contractual', 'operational', 'organisational', 'other'];
export const RISK_TREATMENTS: RiskTreatment[] = ['accept', 'mitigate', 'transfer', 'avoid'];

export const MIN_TITLE = 5;
export const MAX_TITLE = 200;
export const MIN_DESCRIPTION = 100;
export const MIN_CLOSURE_REASON = 20;
export const MIN_REVIEW_DAYS = 30;

/**
 * NIST SP 800-30 Rev 1 Table I-2 — inherent = combine(likelihood, impact).
 * Byte-identical to the server (routes/risk-register.ts) + cloud-evidence
 * (core/risk-register.ts) so the UI's "Suggested inherent" hint matches what the
 * server computes on POST (Q5).
 */
const INHERENT_MATRIX: Record<RiskBand, Record<RiskBand, RiskBand>> = {
  'very-high': { 'very-low': 'very-low', 'low': 'low', 'moderate': 'moderate', 'high': 'high', 'very-high': 'very-high' },
  'high':      { 'very-low': 'very-low', 'low': 'low', 'moderate': 'moderate', 'high': 'high', 'very-high': 'very-high' },
  'moderate':  { 'very-low': 'very-low', 'low': 'low', 'moderate': 'moderate', 'high': 'moderate', 'very-high': 'high' },
  'low':       { 'very-low': 'very-low', 'low': 'low', 'moderate': 'low', 'high': 'low', 'very-high': 'moderate' },
  'very-low':  { 'very-low': 'very-low', 'low': 'very-low', 'moderate': 'very-low', 'high': 'low', 'very-high': 'low' },
};
export function combineInherent(likelihood: RiskBand, impact: RiskBand): RiskBand {
  return INHERENT_MATRIX[likelihood][impact];
}

export interface OrganisationalRiskFormState {
  title: string;
  description: string;
  category: OrganisationalRiskCategory | '';
  likelihood: RiskBand | '';
  impact: RiskBand | '';
  residual_risk: RiskBand | '';
  treatment: RiskTreatment | '';
  review_date: string;   // ISO date (yyyy-mm-dd or full ISO)
}

/** Validate the create/edit form; returns human-readable problems (empty = OK). */
export function validateOrganisationalRiskForm(s: OrganisationalRiskFormState, now = new Date()): string[] {
  const errs: string[] = [];
  const title = s.title.trim();
  if (title.length < MIN_TITLE || title.length > MAX_TITLE) {
    errs.push(`Title must be ${MIN_TITLE}-${MAX_TITLE} characters (currently ${title.length}).`);
  }
  if (s.description.length < MIN_DESCRIPTION) {
    errs.push(`Description must be at least ${MIN_DESCRIPTION} characters (currently ${s.description.length}).`);
  }
  if (!(RISK_CATEGORIES as string[]).includes(s.category)) errs.push('A risk category is required.');
  if (!(RISK_BANDS as string[]).includes(s.likelihood)) errs.push('A likelihood band is required.');
  if (!(RISK_BANDS as string[]).includes(s.impact)) errs.push('An impact band is required.');
  if (!(RISK_BANDS as string[]).includes(s.residual_risk)) errs.push('A residual-risk band is required.');
  if (!(RISK_TREATMENTS as string[]).includes(s.treatment)) errs.push('A treatment option is required.');
  if (!s.review_date) {
    errs.push('A review date is required.');
  } else {
    const ms = Date.parse(s.review_date);
    if (!Number.isFinite(ms)) errs.push('Review date must be a valid date.');
    else if (ms < now.getTime() + MIN_REVIEW_DAYS * 86_400_000) errs.push(`Review date must be at least ${MIN_REVIEW_DAYS} days in the future.`);
  }
  return errs;
}

export function canSubmitOrganisationalRiskForm(s: OrganisationalRiskFormState, now = new Date()): boolean {
  return validateOrganisationalRiskForm(s, now).length === 0;
}

export function descriptionRemaining(text: string): number {
  return Math.max(0, MIN_DESCRIPTION - text.length);
}

/** The deterministic inherent-band hint (empty until both likelihood + impact are set). */
export function suggestedInherent(s: OrganisationalRiskFormState): RiskBand | '' {
  if (!(RISK_BANDS as string[]).includes(s.likelihood) || !(RISK_BANDS as string[]).includes(s.impact)) return '';
  return combineInherent(s.likelihood as RiskBand, s.impact as RiskBand);
}

// ─── Role-gated CTAs (mirror the server's rbac.ts permission model) ───────────
/** "New organisational risk" + edit CTA — iso/ao/admin. */
export function canCreateOrganisationalRisk(role: string): boolean {
  return role === 'iso' || role === 'ao' || role === 'admin';
}
/** "Close" CTA — iso/ao/admin, and only for an open risk. */
export function canCloseOrganisationalRisk(role: string, status: string): boolean {
  return (role === 'iso' || role === 'ao' || role === 'admin') && status === 'open';
}
/** Whether the "Risk Register" nav link should be shown for this role. */
export function canViewRiskRegister(role: string): boolean {
  return ['viewer', 'contributor', 'ksi-owner', 'auditor', 'iso', 'ao', 'assessor', 'admin'].includes(role);
}

const BAND_RANK: Record<RiskBandOrMarker, number> = {
  'very-high': 5, 'high': 4, 'moderate': 3, 'low': 2, 'very-low': 1, 'REQUIRES-OPERATOR-INPUT': 0,
};

/** Stable sort of register entries by inherent risk, very-high first. */
export function sortByInherentDescending<T extends { inherent_risk: RiskBandOrMarker }>(entries: T[]): T[] {
  return [...entries].sort((a, b) => (BAND_RANK[b.inherent_risk] ?? 0) - (BAND_RANK[a.inherent_risk] ?? 0));
}
