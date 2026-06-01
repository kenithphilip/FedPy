/**
 * Tests for the remaining 4 Azure IAM collectors (APM / SNU / JIT / SUS).
 * Same path-substring routing pattern as iam-mfa.test.ts + iam-elp-aam.test.ts.
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

import { collectIamApm, collectIamSnu, collectIamJit, collectIamSus } from '../../../providers/azure/iam.ts';

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

const ctx = { azure: { tenant_id: 't', subscription_id: null } };
function daysAgo(d: number): string { return new Date(Date.now() - d * 86_400_000).toISOString(); }
function daysAhead(d: number): string { return new Date(Date.now() + d * 86_400_000).toISOString(); }

// =====================================================================
// KSI-IAM-APM
// =====================================================================
describe('collectIamApm (KSI-IAM-APM Azure)', () => {
  beforeEach(() => { _state.fetchAll = []; _state.fetchOne = []; });

  it('PASSES both findings when an admin-scoped CA policy uses authenticationStrength', async () => {
    _state.fetchAll = [{ match: 'conditionalAccess/policies', items: [
      { id: 'p', displayName: 'Phishing-resistant for admins', state: 'enabled',
        conditions: { users: { includeRoles: [GLOBAL_ADMIN_TEMPLATE] } },
        grantControls: { authenticationStrength: { id: 'strength-1' } } },
    ] }];
    const block = await collectIamApm(ctx);
    expect(block.findings.find((f) => f.rule === 'aad.ca_uses_authentication_strength')!.passed).toBe(true);
    expect(block.findings.find((f) => f.rule === 'aad.ca_authentication_strength_for_admins')!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-IAM-APM');
  });

  it('PASSES the any-strength finding but FAILS the admin-strength finding when the strong policy targets only regular users', async () => {
    _state.fetchAll = [{ match: 'conditionalAccess/policies', items: [
      { id: 'p', state: 'enabled', conditions: { users: { includeUsers: ['All'] } }, grantControls: { authenticationStrength: { id: 's' } } },
    ] }];
    const block = await collectIamApm(ctx);
    expect(block.findings.find((f) => f.rule === 'aad.ca_uses_authentication_strength')!.passed).toBe(true);
    expect(block.findings.find((f) => f.rule === 'aad.ca_authentication_strength_for_admins')!.passed).toBe(false);
  });

  it('FAILS both findings when no policy uses authenticationStrength', async () => {
    _state.fetchAll = [{ match: 'conditionalAccess/policies', items: [
      { id: 'p', state: 'enabled', conditions: { users: { includeUsers: ['All'] } }, grantControls: { builtInControls: ['mfa'] } },
    ] }];
    const block = await collectIamApm(ctx);
    expect(block.findings.every((f) => !f.passed)).toBe(true);
  });

  it('IGNORES disabled policies even when they use authenticationStrength', async () => {
    _state.fetchAll = [{ match: 'conditionalAccess/policies', items: [
      { id: 'p', state: 'disabled', conditions: { users: { includeRoles: [GLOBAL_ADMIN_TEMPLATE] } }, grantControls: { authenticationStrength: { id: 's' } } },
    ] }];
    const block = await collectIamApm(ctx);
    expect(block.findings.every((f) => !f.passed)).toBe(true);
  });
});

// =====================================================================
// KSI-IAM-SNU
// =====================================================================
describe('collectIamSnu (KSI-IAM-SNU Azure)', () => {
  beforeEach(() => { _state.fetchAll = []; _state.fetchOne = []; });

  it('PASSES both findings when every credential is current and rotated within a year', async () => {
    _state.fetchAll = [{ match: '/applications', items: [
      { id: 'a1', displayName: 'App 1',
        passwordCredentials: [{ keyId: 'k1', startDateTime: daysAgo(30), endDateTime: daysAhead(60) }],
        keyCredentials: [] },
    ] }];
    const block = await collectIamSnu(ctx);
    expect(block.findings.every((f) => f.passed)).toBe(true);
    assertSchemaValid(block, 'KSI-IAM-SNU');
  });

  it('FAILS the expired-credentials finding when an app has a credential past endDateTime', async () => {
    _state.fetchAll = [{ match: '/applications', items: [
      { id: 'a1', displayName: 'App Expired',
        passwordCredentials: [{ keyId: 'k1', startDateTime: daysAgo(400), endDateTime: daysAgo(10) }],
        keyCredentials: [] },
    ] }];
    const block = await collectIamSnu(ctx);
    const expired = block.findings.find((f) => f.rule === 'aad.sp_no_expired_credentials')!;
    expect(expired.passed).toBe(false);
    expect(expired.gap?.affected_resources[0]?.identifier).toContain('App Expired');
  });

  it('FAILS the rotation finding when a credential is older than 365 days (even if still in date)', async () => {
    _state.fetchAll = [{ match: '/applications', items: [
      { id: 'a1', displayName: 'App Long-Lived',
        passwordCredentials: [{ keyId: 'k', startDateTime: daysAgo(400), endDateTime: daysAhead(60) }],
        keyCredentials: [] },
    ] }];
    const block = await collectIamSnu(ctx);
    expect(block.findings.find((f) => f.rule === 'aad.sp_credentials_rotated_within_year')!.passed).toBe(false);
  });

  it('flags BOTH password and key (certificate) credentials', async () => {
    _state.fetchAll = [{ match: '/applications', items: [
      { id: 'a1', displayName: 'A',
        passwordCredentials: [],
        keyCredentials: [{ keyId: 'kc', startDateTime: daysAgo(800), endDateTime: daysAgo(5) }] },
    ] }];
    const block = await collectIamSnu(ctx);
    const expired = block.findings.find((f) => f.rule === 'aad.sp_no_expired_credentials')!;
    expect(expired.passed).toBe(false);
    expect(expired.gap?.affected_resources[0]?.identifier).toContain('cert');
  });

  it('handles a tenant with no applications gracefully', async () => {
    _state.fetchAll = [{ match: '/applications', items: [] }];
    const block = await collectIamSnu(ctx);
    expect(block.findings.every((f) => f.passed)).toBe(true);
  });
});

// =====================================================================
// KSI-IAM-JIT
// =====================================================================
describe('collectIamJit (KSI-IAM-JIT Azure)', () => {
  beforeEach(() => { _state.fetchAll = []; _state.fetchOne = []; });

  it('PASSES when a granted PIM self-activation for Global Admin occurred in the last 30 days', async () => {
    _state.fetchAll = [{ match: 'roleAssignmentScheduleRequests', items: [
      { id: 'r1', action: 'selfActivate', status: 'Granted', roleDefinitionId: GLOBAL_ADMIN_TEMPLATE,
        principalId: 'u', createdDateTime: daysAgo(5) },
    ] }];
    const block = await collectIamJit(ctx);
    expect(block.findings[0]!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-IAM-JIT');
  });

  it('FAILS when no admin activations in window (only old activations exist)', async () => {
    _state.fetchAll = [{ match: 'roleAssignmentScheduleRequests', items: [
      { id: 'r1', action: 'selfActivate', status: 'Granted', roleDefinitionId: GLOBAL_ADMIN_TEMPLATE,
        principalId: 'u', createdDateTime: daysAgo(60) },
    ] }];
    const block = await collectIamJit(ctx);
    expect(block.findings[0]!.passed).toBe(false);
  });

  it('IGNORES activations for non-admin roles', async () => {
    _state.fetchAll = [{ match: 'roleAssignmentScheduleRequests', items: [
      { id: 'r1', action: 'selfActivate', status: 'Granted', roleDefinitionId: 'random-non-admin-role',
        principalId: 'u', createdDateTime: daysAgo(5) },
    ] }];
    const block = await collectIamJit(ctx);
    expect(block.findings[0]!.passed).toBe(false);
  });

  it('IGNORES denied / non-granted requests', async () => {
    _state.fetchAll = [{ match: 'roleAssignmentScheduleRequests', items: [
      { id: 'r1', action: 'selfActivate', status: 'Denied', roleDefinitionId: GLOBAL_ADMIN_TEMPLATE,
        principalId: 'u', createdDateTime: daysAgo(5) },
    ] }];
    const block = await collectIamJit(ctx);
    expect(block.findings[0]!.passed).toBe(false);
  });
});

// =====================================================================
// KSI-IAM-SUS
// =====================================================================
describe('collectIamSus (KSI-IAM-SUS Azure)', () => {
  beforeEach(() => { _state.fetchAll = []; _state.fetchOne = []; });

  it('PASSES when an enabled CA policy uses signInRiskLevels', async () => {
    _state.fetchAll = [{ match: 'conditionalAccess/policies', items: [
      { id: 'p', state: 'enabled', conditions: { signInRiskLevels: ['high'], users: { includeUsers: ['All'] } },
        grantControls: { builtInControls: ['block'] } },
    ] }];
    const block = await collectIamSus(ctx);
    expect(block.findings[0]!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-IAM-SUS');
  });

  it('PASSES when an enabled CA policy uses userRiskLevels', async () => {
    _state.fetchAll = [{ match: 'conditionalAccess/policies', items: [
      { id: 'p', state: 'enabled', conditions: { userRiskLevels: ['high', 'medium'], users: { includeUsers: ['All'] } },
        grantControls: { builtInControls: ['passwordChange'] } },
    ] }];
    const block = await collectIamSus(ctx);
    expect(block.findings[0]!.passed).toBe(true);
  });

  it('FAILS when no CA policy uses risk conditions', async () => {
    _state.fetchAll = [{ match: 'conditionalAccess/policies', items: [
      { id: 'p', state: 'enabled', conditions: { users: { includeUsers: ['All'] } }, grantControls: { builtInControls: ['mfa'] } },
    ] }];
    const block = await collectIamSus(ctx);
    expect(block.findings[0]!.passed).toBe(false);
  });

  it('IGNORES disabled risk policies', async () => {
    _state.fetchAll = [{ match: 'conditionalAccess/policies', items: [
      { id: 'p', state: 'disabled', conditions: { signInRiskLevels: ['high'] }, grantControls: { builtInControls: ['block'] } },
    ] }];
    const block = await collectIamSus(ctx);
    expect(block.findings[0]!.passed).toBe(false);
  });

  it('captures Graph warnings on listing failure', async () => {
    _state.fetchAll = [{ match: 'conditionalAccess/policies', items: [], warnings: ['403 Forbidden — Policy.Read.All missing'] }];
    const block = await collectIamSus(ctx);
    expect(block.warnings).toBeDefined();
    expect(block.warnings!.some((w) => /403/.test(w))).toBe(true);
    expect(block.findings).toHaveLength(1);
  });
});
