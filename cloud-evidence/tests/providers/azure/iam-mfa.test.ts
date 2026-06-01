/**
 * Tests for providers/azure/iam.ts → collectIamMfa (AZ-IAM-MFA).
 *
 * Mocks core/auth/azure-graph.ts (no Microsoft Graph access). Each test seeds
 * canned `graphFetchAll` / `graphFetchOne` responses (routed by path substring)
 * and asserts the two findings classify correctly + the ProviderBlock is
 * schema-valid.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { validateEvidenceFile } from '../../../core/schema.ts';

const _state = vi.hoisted(() => ({
  // Path-substring routing: first matching key wins.
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

import { collectIamMfa } from '../../../providers/azure/iam.ts';

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

describe('collectIamMfa (KSI-IAM-MFA Azure)', () => {
  beforeEach(() => { _state.fetchAll = []; _state.fetchOne = []; });

  it('PASSES finding 1 when Security Defaults are enabled (no CA needed)', async () => {
    _state.fetchOne = [{ match: 'identitySecurityDefaultsEnforcementPolicy', data: { isEnabled: true } }];
    _state.fetchAll = [{ match: 'conditionalAccess/policies', items: [] }];
    const block = await collectIamMfa({ azure: { tenant_id: 't', subscription_id: null } });
    expect(block.provider).toBe('azure');
    const f1 = block.findings.find((f) => f.rule === 'aad.security_defaults_or_ca_mfa_for_all_users')!;
    expect(f1.passed).toBe(true);
    expect(f1.current_state.summary).toMatch(/Security Defaults/);
    assertSchemaValid(block, 'KSI-IAM-MFA');
  });

  it('PASSES finding 1 when an enabled CA policy covers all users with MFA', async () => {
    _state.fetchOne = [{ match: 'identitySecurityDefaultsEnforcementPolicy', data: { isEnabled: false } }];
    _state.fetchAll = [{ match: 'conditionalAccess/policies', items: [
      { id: 'p1', displayName: 'MFA — all users', state: 'enabled',
        conditions: { users: { includeUsers: ['All'] } },
        grantControls: { builtInControls: ['mfa'] } },
    ] }];
    const block = await collectIamMfa({ azure: { tenant_id: 't', subscription_id: null } });
    const f1 = block.findings.find((f) => f.rule === 'aad.security_defaults_or_ca_mfa_for_all_users')!;
    expect(f1.passed).toBe(true);
    expect(f1.current_state.summary).toMatch(/all users/i);
  });

  it('FAILS finding 1 when neither Security Defaults nor an all-users MFA policy is enabled', async () => {
    _state.fetchOne = [{ match: 'identitySecurityDefaultsEnforcementPolicy', data: { isEnabled: false } }];
    _state.fetchAll = [{ match: 'conditionalAccess/policies', items: [
      { id: 'p1', displayName: 'MFA — admins only', state: 'enabled',
        conditions: { users: { includeRoles: [GLOBAL_ADMIN_TEMPLATE] } },
        grantControls: { builtInControls: ['mfa'] } },
    ] }];
    const block = await collectIamMfa({ azure: { tenant_id: 't', subscription_id: null } });
    const f1 = block.findings.find((f) => f.rule === 'aad.security_defaults_or_ca_mfa_for_all_users')!;
    expect(f1.passed).toBe(false);
    expect(f1.severity).toBe('high');
    expect(f1.gap?.description).toBeTruthy();
    expect(f1.remediation?.options.length ?? 0).toBeGreaterThan(0);
  });

  it('PASSES finding 2 when a CA policy targets an admin directory-role template with MFA', async () => {
    _state.fetchOne = [{ match: 'identitySecurityDefaultsEnforcementPolicy', data: { isEnabled: false } }];
    _state.fetchAll = [{ match: 'conditionalAccess/policies', items: [
      { id: 'p1', displayName: 'MFA — Global Admins', state: 'enabled',
        conditions: { users: { includeRoles: [GLOBAL_ADMIN_TEMPLATE] } },
        grantControls: { builtInControls: ['mfa'] } },
    ] }];
    const block = await collectIamMfa({ azure: { tenant_id: 't', subscription_id: null } });
    const f2 = block.findings.find((f) => f.rule === 'aad.ca_mfa_for_admin_roles')!;
    expect(f2.passed).toBe(true);
    expect(f2.severity).toBe('critical');
  });

  it('FAILS finding 2 when no CA policy targets admin roles', async () => {
    _state.fetchOne = [{ match: 'identitySecurityDefaultsEnforcementPolicy', data: { isEnabled: false } }];
    _state.fetchAll = [{ match: 'conditionalAccess/policies', items: [
      { id: 'p1', displayName: 'MFA — all users', state: 'enabled',
        conditions: { users: { includeUsers: ['All'] } },
        grantControls: { builtInControls: ['mfa'] } },
    ] }];
    const block = await collectIamMfa({ azure: { tenant_id: 't', subscription_id: null } });
    const f2 = block.findings.find((f) => f.rule === 'aad.ca_mfa_for_admin_roles')!;
    expect(f2.passed).toBe(false);
    expect(f2.severity).toBe('critical');
  });

  it('IGNORES disabled CA policies (state != enabled)', async () => {
    _state.fetchOne = [{ match: 'identitySecurityDefaultsEnforcementPolicy', data: { isEnabled: false } }];
    _state.fetchAll = [{ match: 'conditionalAccess/policies', items: [
      { id: 'p1', displayName: 'MFA — admins (DISABLED)', state: 'disabled',
        conditions: { users: { includeRoles: [GLOBAL_ADMIN_TEMPLATE] } },
        grantControls: { builtInControls: ['mfa'] } },
    ] }];
    const block = await collectIamMfa({ azure: { tenant_id: 't', subscription_id: null } });
    const f2 = block.findings.find((f) => f.rule === 'aad.ca_mfa_for_admin_roles')!;
    expect(f2.passed).toBe(false);
  });

  it('treats authenticationStrength references as MFA-equivalent', async () => {
    _state.fetchOne = [{ match: 'identitySecurityDefaultsEnforcementPolicy', data: { isEnabled: false } }];
    _state.fetchAll = [{ match: 'conditionalAccess/policies', items: [
      { id: 'p1', displayName: 'Phishing-resistant strength', state: 'enabled',
        conditions: { users: { includeUsers: ['All'] } },
        grantControls: { authenticationStrength: { id: 'strength-1' } } },
    ] }];
    const block = await collectIamMfa({ azure: { tenant_id: 't', subscription_id: null } });
    const f1 = block.findings.find((f) => f.rule === 'aad.security_defaults_or_ca_mfa_for_all_users')!;
    expect(f1.passed).toBe(true);
  });

  it('captures Graph errors as warnings instead of throwing', async () => {
    _state.fetchOne = [{ match: 'identitySecurityDefaultsEnforcementPolicy', data: null, warnings: ['403 Forbidden'] }];
    _state.fetchAll = [{ match: 'conditionalAccess/policies', items: [], warnings: ['403 Forbidden'] }];
    const block = await collectIamMfa({ azure: { tenant_id: 't', subscription_id: null } });
    expect(block.warnings?.length ?? 0).toBeGreaterThanOrEqual(2);
    expect(block.findings).toHaveLength(2);   // still emits findings (failing, with the warning context)
    assertSchemaValid(block, 'KSI-IAM-MFA');
  });

  it('emits the external-IdP alternative-satisfier as awareness', async () => {
    _state.fetchOne = [{ match: 'identitySecurityDefaultsEnforcementPolicy', data: { isEnabled: true } }];
    _state.fetchAll = [{ match: 'conditionalAccess/policies', items: [] }];
    const block = await collectIamMfa({ azure: { tenant_id: 't', subscription_id: null } });
    expect((block.ksi_level_alternatives ?? []).some((a) => /External SAML/i.test(a.via))).toBe(true);
  });
});
