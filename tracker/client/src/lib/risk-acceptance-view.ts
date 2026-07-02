/**
 * LOOP-B.B3 — Pure view-logic for the risk-acceptance UI.
 *
 * The tracker toolchain has no jsdom / @testing-library, and vitest only collects
 * `server/**` + `tests/**` test files — so the React components can't be
 * unit-rendered in this repo. Instead the components' decision logic (form
 * validation, submit-enable, role-gated CTAs) lives here as pure functions and is
 * unit-tested directly in `tracker/tests/risk-acceptance-view.test.ts`. The
 * components import these helpers so the tested rules ARE the rendered behaviour.
 */

export type AcceptanceType = 'deviation-request' | 'risk-adjustment' | 'false-positive' | 'operational-requirement';
export type AcceptanceStatus = 'pending' | 'approved' | 'expired' | 'revoked';

export const ACCEPTANCE_TYPES: AcceptanceType[] = ['deviation-request', 'risk-adjustment', 'false-positive', 'operational-requirement'];

export const MIN_JUSTIFICATION = 100;
export const MIN_DAYS = 7;
export const MAX_DAYS = 365;
const DAY_MS = 86_400_000;

export interface CreateFormState {
  finding_uuid: string;
  poam_item_uuid: string;
  ksi_id: string;
  rule: string;
  provider: string;
  expiration_date: string;         // ISO date (yyyy-mm-dd) or datetime
  business_justification: string;
  acceptance_type: AcceptanceType;
  compensating_control_uuids: string[];
}

/** Validate the create form; returns the list of human-readable problems (empty = OK). */
export function validateCreateForm(s: CreateFormState, now: number = Date.now()): string[] {
  const errs: string[] = [];
  if (!s.finding_uuid.trim()) errs.push('Finding is required.');
  if (!s.poam_item_uuid.trim()) errs.push('POA&M item is required.');
  if (!s.ksi_id.trim()) errs.push('KSI is required.');
  if (!s.rule.trim()) errs.push('Rule is required.');
  if (!s.provider.trim()) errs.push('Provider is required.');
  if (s.business_justification.length < MIN_JUSTIFICATION) {
    errs.push(`Justification must be at least ${MIN_JUSTIFICATION} characters (currently ${s.business_justification.length}).`);
  }
  const expMs = Date.parse(s.expiration_date);
  if (!Number.isFinite(expMs)) {
    errs.push('Expiration date is required.');
  } else {
    if (expMs < now + MIN_DAYS * DAY_MS) errs.push(`Expiration must be at least ${MIN_DAYS} days out.`);
    if (expMs > now + MAX_DAYS * DAY_MS) errs.push(`Expiration must be within ${MAX_DAYS} days (annual review).`);
  }
  if (s.acceptance_type === 'deviation-request' && s.compensating_control_uuids.length === 0) {
    errs.push('A deviation-request requires at least one compensating control.');
  }
  return errs;
}

/** Submit is enabled only when the form has zero validation problems. */
export function canSubmitCreateForm(s: CreateFormState, now: number = Date.now()): boolean {
  return validateCreateForm(s, now).length === 0;
}

// ─── Role-gated CTAs (mirror the server's rbac.ts permission model) ───────────
export function canCreateAcceptance(role: string): boolean {
  return role === 'iso' || role === 'admin';
}
export function canApproveAcceptance(role: string, status: AcceptanceStatus): boolean {
  return (role === 'ao' || role === 'admin') && status === 'pending';
}
export function canRevokeAcceptance(role: string, status: AcceptanceStatus): boolean {
  return (role === 'iso' || role === 'ao' || role === 'admin') && (status === 'pending' || status === 'approved');
}
/** Whether the "Risk Acceptances" nav link should be shown for this role. */
export function canViewRiskAcceptances(role: string): boolean {
  return ['viewer', 'contributor', 'ksi-owner', 'auditor', 'iso', 'ao', 'assessor', 'admin'].includes(role);
}

/** Character-count helper for the justification textarea (drives the red-tint). */
export function justificationRemaining(text: string): number {
  return Math.max(0, MIN_JUSTIFICATION - text.length);
}
