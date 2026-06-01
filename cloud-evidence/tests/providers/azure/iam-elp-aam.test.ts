/**
 * Tests for providers/azure/iam.ts → collectIamElp + collectIamAam.
 *
 * Same path-substring routing pattern as iam-mfa.test.ts.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { validateEvidenceFile } from '../../../core/schema.ts';

const _state = vi.hoisted(() => ({
  fetchAll: [] as Array<{ match: string; items: any[]; warnings?: string[] }>,
  fetchOne: [] as Array<{ match: string; data: any; warnings?: string[] }>,
}));

vi.mock('../../../core/auth/azure-graph.ts', () => ({
  async graphFetchAll(path: string) {
    const r = _state.fetchAll.find((x) => path.includes(x.match));
    return { items: r?.items ?? [], warnings: r?.warnings ?? [] };
  },
  async graphFetchOne(path: string) {
    const r = _state.fetchOne.find((x) => path.includes(x.match));
    return { data: r?.data ?? null, warnings: r?.warnings ?? [] };
  },
  _resetTokenCache: () => { /* noop */ },
}));

import { collectIamElp, collectIamAam } from '../../../providers/azure/iam.ts';

const GLOBAL_ADMIN_TEMPLATE = '62e90394-69f5-4237-9190-012177145e10';

function assertSchemaValid(block: any, ksiId: string): void {
  const envelope: any = {
    ksi_id: ksiId, ksi_name: ksiId, ksi_statement: 'smoke', scope: 'CLOUD',
    frmr_version: 'test', run_id: '00000000-0000-0000-0000-000000000000',
    collected_at: '2026-06-01T00:00:00.000Z',
    providers: [block],
    rollup: {
      pass: block.findings.every((f: any) => f.passed),
      passing_findings: block.findings.filter((f: any) => f.passed).length,
      failing_findings: block.findings.filter((f: any) => !f.passed).length,
      warnings: block.warnings ?? [],
      missing_evidence: [], alternatives_in_play: 0,
    },
  };
  const r = validateEvidenceFile(JSON.parse(JSON.stringify(envelope)));
  if (!r.valid) throw new Error(`schema invalid: ${(r.errors[0] as any)?.instancePath} ${(r.errors[0] as any)?.message}`);
}

// =====================================================================
// KSI-IAM-ELP
// =====================================================================
describe('collectIamElp (KSI-IAM-ELP Azure)', () => {
  beforeEach(() => { _state.fetchAll = []; _state.fetchOne = []; });

  function setRoles(globalAdminMemberCount: number, pimEligibleAdminCount: number): void {
    _state.fetchAll = [
      { match: '/directoryRoles/role-ga/members', items: Array.from({ length: globalAdminMemberCount }, (_, i) => ({ id: `user-${i}` })) },
      { match: '/directoryRoles', items: [{ id: 'role-ga', displayName: 'Global Administrator', roleTemplateId: GLOBAL_ADMIN_TEMPLATE }] },
      { match: 'roleEligibilitySchedules', items: Array.from({ length: pimEligibleAdminCount }, (_, i) => ({ id: `e-${i}`, principalId: `p-${i}`, roleDefinitionId: GLOBAL_ADMIN_TEMPLATE })) },
    ];
  }

  it('PASSES global-admin-count finding when count ≤ 5', async () => {
    setRoles(3, 2);
    const block = await collectIamElp({ azure: { tenant_id: 't', subscription_id: null } });
    const f = block.findings.find((x) => x.rule === 'aad.global_admin_count_within_threshold')!;
    expect(f.passed).toBe(true);
    expect(f.current_state.summary).toContain('3');
    assertSchemaValid(block, 'KSI-IAM-ELP');
  });

  it('FAILS global-admin-count finding when count > 5', async () => {
    setRoles(8, 0);
    const block = await collectIamElp({ azure: { tenant_id: 't', subscription_id: null } });
    const f = block.findings.find((x) => x.rule === 'aad.global_admin_count_within_threshold')!;
    expect(f.passed).toBe(false);
    expect(f.severity).toBe('high');
    expect(f.gap?.affected_resources[0]?.attributes?.count).toBe(8);
  });

  it('PASSES PIM-eligibility finding when at least one admin role is PIM-eligible', async () => {
    setRoles(3, 1);
    const block = await collectIamElp({ azure: { tenant_id: 't', subscription_id: null } });
    const f = block.findings.find((x) => x.rule === 'aad.pim_eligible_for_admin_roles')!;
    expect(f.passed).toBe(true);
  });

  it('FAILS PIM-eligibility finding when no eligible admin assignments exist', async () => {
    setRoles(3, 0);
    const block = await collectIamElp({ azure: { tenant_id: 't', subscription_id: null } });
    const f = block.findings.find((x) => x.rule === 'aad.pim_eligible_for_admin_roles')!;
    expect(f.passed).toBe(false);
  });

  it('warns + still emits findings when Global Admin role is not activated', async () => {
    _state.fetchAll = [
      { match: '/directoryRoles', items: [] },                              // no roles activated yet
      { match: 'roleEligibilitySchedules', items: [] },
    ];
    const block = await collectIamElp({ azure: { tenant_id: 't', subscription_id: null } });
    expect(block.warnings?.some((w) => /Global Administrator/.test(w))).toBe(true);
    expect(block.findings).toHaveLength(2);
    assertSchemaValid(block, 'KSI-IAM-ELP');
  });

  it('IGNORES eligibility entries whose roleDefinitionId is not a privileged role', async () => {
    _state.fetchAll = [
      { match: '/directoryRoles', items: [{ id: 'role-ga', roleTemplateId: GLOBAL_ADMIN_TEMPLATE }] },
      { match: '/directoryRoles/role-ga/members', items: [{ id: 'u1' }] },
      { match: 'roleEligibilitySchedules', items: [
        { id: 'e1', principalId: 'p1', roleDefinitionId: 'some-non-admin-role' },
      ] },
    ];
    const block = await collectIamElp({ azure: { tenant_id: 't', subscription_id: null } });
    const pim = block.findings.find((x) => x.rule === 'aad.pim_eligible_for_admin_roles')!;
    expect(pim.passed).toBe(false);   // no eligible *admin* assignment
  });
});

// =====================================================================
// KSI-IAM-AAM
// =====================================================================
describe('collectIamAam (KSI-IAM-AAM Azure)', () => {
  beforeEach(() => { _state.fetchAll = []; _state.fetchOne = []; });

  /** ISO date `d` days ago. */
  function daysAgo(d: number): string {
    return new Date(Date.now() - d * 86_400_000).toISOString();
  }

  it('PASSES both findings when every enabled member has signed in within 90 days', async () => {
    _state.fetchAll = [
      { match: '/users', items: [
        { id: 'u1', userPrincipalName: 'a@x', accountEnabled: true, signInActivity: { lastSignInDateTime: daysAgo(5) } },
        { id: 'u2', userPrincipalName: 'b@x', accountEnabled: true, signInActivity: { lastSignInDateTime: daysAgo(45) } },
      ] },
    ];
    const block = await collectIamAam({ azure: { tenant_id: 't', subscription_id: null } });
    const dormant = block.findings.find((f) => f.rule === 'aad.no_dormant_enabled_accounts')!;
    const severe = block.findings.find((f) => f.rule === 'aad.no_severely_dormant_accounts')!;
    expect(dormant.passed).toBe(true);
    expect(severe.passed).toBe(true);
    assertSchemaValid(block, 'KSI-IAM-AAM');
  });

  it('FAILS dormant finding when an enabled member has been silent > 90 days', async () => {
    _state.fetchAll = [
      { match: '/users', items: [
        { id: 'u1', userPrincipalName: 'fresh@x', accountEnabled: true, signInActivity: { lastSignInDateTime: daysAgo(5) } },
        { id: 'u2', userPrincipalName: 'stale@x', accountEnabled: true, signInActivity: { lastSignInDateTime: daysAgo(120) } },
      ] },
    ];
    const block = await collectIamAam({ azure: { tenant_id: 't', subscription_id: null } });
    const f = block.findings.find((x) => x.rule === 'aad.no_dormant_enabled_accounts')!;
    expect(f.passed).toBe(false);
    expect(f.gap?.affected_resources.some((r) => r.identifier === 'stale@x')).toBe(true);
    expect(f.gap?.affected_resources.some((r) => r.identifier === 'fresh@x')).toBe(false);
  });

  it('FAILS severe-dormant finding (critical) when an enabled member has been silent > 365 days', async () => {
    _state.fetchAll = [
      { match: '/users', items: [
        { id: 'u', userPrincipalName: 'ancient@x', accountEnabled: true, signInActivity: { lastSignInDateTime: daysAgo(400) } },
      ] },
    ];
    const block = await collectIamAam({ azure: { tenant_id: 't', subscription_id: null } });
    const f = block.findings.find((x) => x.rule === 'aad.no_severely_dormant_accounts')!;
    expect(f.passed).toBe(false);
    expect(f.severity).toBe('critical');
  });

  it('IGNORES guest users (userType="Guest") for dormancy', async () => {
    _state.fetchAll = [
      { match: '/users', items: [
        { id: 'g', userPrincipalName: 'guest@x', accountEnabled: true, userType: 'Guest', signInActivity: { lastSignInDateTime: daysAgo(400) } },
      ] },
    ];
    const block = await collectIamAam({ azure: { tenant_id: 't', subscription_id: null } });
    const f = block.findings.find((x) => x.rule === 'aad.no_dormant_enabled_accounts')!;
    expect(f.passed).toBe(true);
  });

  it('IGNORES disabled accounts (accountEnabled=false) for dormancy', async () => {
    _state.fetchAll = [
      { match: '/users', items: [
        { id: 'd', userPrincipalName: 'off@x', accountEnabled: false, signInActivity: { lastSignInDateTime: daysAgo(500) } },
      ] },
    ];
    const block = await collectIamAam({ azure: { tenant_id: 't', subscription_id: null } });
    const f = block.findings.find((x) => x.rule === 'aad.no_dormant_enabled_accounts')!;
    expect(f.passed).toBe(true);
  });

  it('degrades to "data-missing" mode (warning + fail) when signInActivity is absent on every user', async () => {
    _state.fetchAll = [
      { match: '/users', items: [
        { id: 'u1', userPrincipalName: 'a@x', accountEnabled: true /* no signInActivity */ },
        { id: 'u2', userPrincipalName: 'b@x', accountEnabled: true },
      ] },
    ];
    const block = await collectIamAam({ azure: { tenant_id: 't', subscription_id: null } });
    expect(block.warnings?.some((w) => /AuditLog\.Read\.All/i.test(w))).toBe(true);
    const f = block.findings.find((x) => x.rule === 'aad.no_dormant_enabled_accounts')!;
    expect(f.passed).toBe(false);
    expect(f.current_state.summary).toMatch(/Unable to verify/);
  });

  it('handles an empty tenant gracefully', async () => {
    _state.fetchAll = [{ match: '/users', items: [] }];
    const block = await collectIamAam({ azure: { tenant_id: 't', subscription_id: null } });
    // With no enabled members, both findings pass (allMissing is false because total=0).
    expect(block.findings.every((f) => f.passed)).toBe(true);
    assertSchemaValid(block, 'KSI-IAM-AAM');
  });
});
