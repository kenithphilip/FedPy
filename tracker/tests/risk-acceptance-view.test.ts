/**
 * Tests for client/src/lib/risk-acceptance-view.ts — the pure logic behind the
 * risk-acceptance React pages (form validation + role-gated CTAs). These stand in
 * for DOM-render tests: the tracker has no jsdom/@testing-library and vitest only
 * collects server/** + tests/**, so we test the components' decision rules directly.
 */
import { describe, it, expect } from 'vitest';
import {
  validateCreateForm,
  canSubmitCreateForm,
  canCreateAcceptance,
  canApproveAcceptance,
  canRevokeAcceptance,
  canViewRiskAcceptances,
  justificationRemaining,
  type CreateFormState,
} from '../client/src/lib/risk-acceptance-view.ts';

const NOW = Date.parse('2026-07-02T00:00:00.000Z');
const inDays = (d: number) => new Date(NOW + d * 86_400_000).toISOString();

function form(over: Partial<CreateFormState> = {}): CreateFormState {
  return {
    finding_uuid: 'f-1',
    poam_item_uuid: 'p-1',
    ksi_id: 'KSI-IAM-MFA',
    rule: 'iam-mfa-aws-root',
    provider: 'aws',
    expiration_date: inDays(90),
    business_justification: 'j'.repeat(120),
    acceptance_type: 'risk-adjustment',
    compensating_control_uuids: [],
    ...over,
  };
}

describe('validateCreateForm / canSubmitCreateForm', () => {
  it('renders a submittable form when all required fields are valid', () => {
    expect(validateCreateForm(form(), NOW)).toEqual([]);
    expect(canSubmitCreateForm(form(), NOW)).toBe(true);
  });

  it('disables submit until justification >= 100 chars', () => {
    const s = form({ business_justification: 'too short' });
    expect(canSubmitCreateForm(s, NOW)).toBe(false);
    expect(validateCreateForm(s, NOW).some((e) => e.includes('100 characters'))).toBe(true);
    expect(justificationRemaining('too short')).toBe(91);
    expect(justificationRemaining('j'.repeat(100))).toBe(0);
  });

  it('rejects expiration windows outside 7..365 days', () => {
    expect(canSubmitCreateForm(form({ expiration_date: inDays(3) }), NOW)).toBe(false);
    expect(canSubmitCreateForm(form({ expiration_date: inDays(400) }), NOW)).toBe(false);
  });

  it('requires a compensating control for deviation-request', () => {
    expect(canSubmitCreateForm(form({ acceptance_type: 'deviation-request', compensating_control_uuids: [] }), NOW)).toBe(false);
    expect(canSubmitCreateForm(form({ acceptance_type: 'deviation-request', compensating_control_uuids: ['cc-1'] }), NOW)).toBe(true);
  });
});

describe('role-gated CTAs', () => {
  it('shows the "New Acceptance" CTA only to iso/admin', () => {
    expect(canCreateAcceptance('iso')).toBe(true);
    expect(canCreateAcceptance('admin')).toBe(true);
    expect(canCreateAcceptance('ao')).toBe(false);
    expect(canCreateAcceptance('assessor')).toBe(false);
    expect(canCreateAcceptance('viewer')).toBe(false);
  });

  it('hides the Approve CTA from non-ao users and non-pending rows', () => {
    expect(canApproveAcceptance('ao', 'pending')).toBe(true);
    expect(canApproveAcceptance('admin', 'pending')).toBe(true);
    expect(canApproveAcceptance('iso', 'pending')).toBe(false);
    expect(canApproveAcceptance('ao', 'approved')).toBe(false);
  });

  it('shows Revoke to iso/ao/admin for active rows only', () => {
    expect(canRevokeAcceptance('iso', 'approved')).toBe(true);
    expect(canRevokeAcceptance('ao', 'pending')).toBe(true);
    expect(canRevokeAcceptance('assessor', 'approved')).toBe(false);
    expect(canRevokeAcceptance('iso', 'revoked')).toBe(false);
    expect(canRevokeAcceptance('iso', 'expired')).toBe(false);
  });

  it('shows the nav link to all authenticated roles', () => {
    expect(canViewRiskAcceptances('assessor')).toBe(true);
    expect(canViewRiskAcceptances('viewer')).toBe(true);
  });
});
