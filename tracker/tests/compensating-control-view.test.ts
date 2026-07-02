/**
 * Tests for client/src/lib/compensating-control-view.ts — the pure logic behind the
 * compensating-controls React pages (form validation + role-gated CTAs + NIST-id
 * normalisation + autocomplete filtering). These stand in for DOM-render tests: the
 * tracker has no jsdom/@testing-library and vitest only collects server/** + tests/**.
 */
import { describe, it, expect } from 'vitest';
import {
  validateControlForm,
  canSubmitControlForm,
  descriptionRemaining,
  normalizeControlId,
  filterControlSuggestions,
  canCreateControl,
  canActivateControl,
  canRetireControl,
  canViewCompensatingControls,
  type CompensatingControlFormState,
  type ControlCatalogEntry,
} from '../client/src/lib/compensating-control-view.ts';

function form(over: Partial<CompensatingControlFormState> = {}): CompensatingControlFormState {
  return {
    title: 'MFA break-glass vault',
    description: 'd'.repeat(220),
    nist_control_ids: ['AC-2', 'SC-7'],
    evidence_url: '',
    expiration_date: '',
    ...over,
  };
}

describe('validateControlForm / canSubmitControlForm', () => {
  it('renders a submittable form when all required fields are valid', () => {
    expect(validateControlForm(form())).toEqual([]);
    expect(canSubmitControlForm(form())).toBe(true);
  });

  it('disables submit until the description reaches 200 chars', () => {
    const s = form({ description: 'short' });
    expect(canSubmitControlForm(s)).toBe(false);
    expect(validateControlForm(s).some((e) => e.includes('200'))).toBe(true);
    expect(descriptionRemaining('short')).toBe(195);
    expect(descriptionRemaining('d'.repeat(200))).toBe(0);
  });

  it('requires a title of 5..200 chars and at least one NIST control id', () => {
    expect(canSubmitControlForm(form({ title: 'AB' }))).toBe(false);
    expect(canSubmitControlForm(form({ title: 'x'.repeat(201) }))).toBe(false);
    expect(canSubmitControlForm(form({ nist_control_ids: [] }))).toBe(false);
  });
});

describe('normalizeControlId + filterControlSuggestions', () => {
  const catalog: ControlCatalogEntry[] = [
    { id: 'AC-2', name: 'Account Management' },
    { id: 'AC-2(3)', name: 'Disable Accounts' },
    { id: 'SC-7', name: 'Boundary Protection' },
  ];

  it('normalises enhancement notation AC-2(3) -> ac-2.3', () => {
    expect(normalizeControlId('AC-2(3)')).toBe('ac-2.3');
    expect(normalizeControlId(' ac-2 ')).toBe('ac-2');
  });

  it('suggests catalog entries by id or title and returns [] for a blank query', () => {
    expect(filterControlSuggestions('', catalog)).toEqual([]);
    expect(filterControlSuggestions('ac-2', catalog).map((e) => e.id)).toEqual(['AC-2', 'AC-2(3)']);
    expect(filterControlSuggestions('boundary', catalog).map((e) => e.id)).toEqual(['SC-7']);
    expect(filterControlSuggestions('AC-2(3)', catalog).map((e) => e.id)).toEqual(['AC-2(3)']);
  });
});

describe('role-gated CTAs', () => {
  it('shows the "New Control" CTA only to iso/admin', () => {
    expect(canCreateControl('iso')).toBe(true);
    expect(canCreateControl('admin')).toBe(true);
    expect(canCreateControl('ao')).toBe(false);
    expect(canCreateControl('assessor')).toBe(false);
  });

  it('shows Activate only to ao/admin and only for a draft', () => {
    expect(canActivateControl('ao', 'draft')).toBe(true);
    expect(canActivateControl('admin', 'draft')).toBe(true);
    expect(canActivateControl('iso', 'draft')).toBe(false);
    expect(canActivateControl('ao', 'active')).toBe(false);
  });

  it('shows Retire to iso/ao/admin for active controls only', () => {
    expect(canRetireControl('iso', 'active')).toBe(true);
    expect(canRetireControl('ao', 'active')).toBe(true);
    expect(canRetireControl('assessor', 'active')).toBe(false);
    expect(canRetireControl('iso', 'draft')).toBe(false);
    expect(canRetireControl('iso', 'retired')).toBe(false);
  });

  it('shows the nav link to all authenticated roles', () => {
    expect(canViewCompensatingControls('assessor')).toBe(true);
    expect(canViewCompensatingControls('viewer')).toBe(true);
  });
});
