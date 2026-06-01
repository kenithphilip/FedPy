/**
 * Tests for providers/azure/secrets.ts → collectSvcAsm.
 * Substring-routed Resource Graph mock, same shape as the other Azure tests.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { validateEvidenceFile } from '../../../core/schema.ts';

const _state = vi.hoisted(() => ({
  routes: [] as Array<{ match: string; rows: any[] }>,
  queries: [] as string[],
}));

vi.mock('../../../core/auth/azure.ts', () => ({
  whoAmIAzure: async () => ({ principal: 'test', tenantId: null, appId: null }),
  guardAzure: <T extends object>(c: T) => c,
  resourceGraph: () => ({
    async resources(req: any) {
      _state.queries.push(req.query);
      const route = _state.routes.find((r) => req.query.includes(r.match));
      return { data: route?.rows ?? [] };
    },
  }),
  resources: (_id: string) => ({}),
}));

import { collectSvcAsm } from '../../../providers/azure/secrets.ts';

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

const ctx = (subs: string[] = ['sub-1']) => ({ azure: { tenant_id: 't', subscription_id: subs[0] ?? null, subscription_ids: subs } });

describe('collectSvcAsm (KSI-SVC-ASM Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES all three findings for a vault with soft-delete + RBAC + purge protection', async () => {
    _state.routes = [{ match: 'microsoft.keyvault/vaults', rows: [
      { id: '/kv/1', name: 'kv-prod', subscriptionId: 'sub-1', location: 'eastus', soft: true, purge: true, rbac: true },
    ] }];
    const block = await collectSvcAsm(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.svc.asm.key_vault_present')!.passed).toBe(true);
    expect(block.findings.find((f) => f.rule === 'azure.svc.asm.key_vault_soft_delete_enabled')!.passed).toBe(true);
    expect(block.findings.find((f) => f.rule === 'azure.svc.asm.key_vault_rbac_or_purge_protection')!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-SVC-ASM');
  });

  it('PASSES the RBAC-or-purge finding when only purge protection is on (legacy access policies)', async () => {
    _state.routes = [{ match: 'microsoft.keyvault/vaults', rows: [
      { id: '/kv/legacy', name: 'kv-legacy', subscriptionId: 'sub-1', soft: true, purge: true, rbac: false },
    ] }];
    const block = await collectSvcAsm(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.svc.asm.key_vault_rbac_or_purge_protection')!.passed).toBe(true);
  });

  it('PASSES the RBAC-or-purge finding when only RBAC is on (no purge protection)', async () => {
    _state.routes = [{ match: 'microsoft.keyvault/vaults', rows: [
      { id: '/kv/rbac', name: 'kv-rbac', subscriptionId: 'sub-1', soft: true, purge: false, rbac: true },
    ] }];
    const block = await collectSvcAsm(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.svc.asm.key_vault_rbac_or_purge_protection')!.passed).toBe(true);
  });

  it('FAILS the presence finding when no Key Vaults exist', async () => {
    _state.routes = [{ match: 'microsoft.keyvault/vaults', rows: [] }];
    const block = await collectSvcAsm(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.svc.asm.key_vault_present')!.passed).toBe(false);
    // The soft-delete + RBAC findings pass vacuously when there are no vaults.
    expect(block.findings.find((f) => f.rule === 'azure.svc.asm.key_vault_soft_delete_enabled')!.passed).toBe(true);
    expect(block.findings.find((f) => f.rule === 'azure.svc.asm.key_vault_rbac_or_purge_protection')!.passed).toBe(true);
  });

  it('FAILS the soft-delete finding when at least one vault has soft-delete explicitly off', async () => {
    _state.routes = [{ match: 'microsoft.keyvault/vaults', rows: [
      { id: '/kv/good', name: 'kv-good', soft: true, purge: true, rbac: true },
      { id: '/kv/bad', name: 'kv-bad', soft: false, purge: true, rbac: true },
    ] }];
    const block = await collectSvcAsm(ctx());
    const f = block.findings.find((x) => x.rule === 'azure.svc.asm.key_vault_soft_delete_enabled')!;
    expect(f.passed).toBe(false);
    expect(f.gap?.affected_resources[0]?.identifier).toBe('/kv/bad');
  });

  it('FAILS the RBAC-or-purge finding when a legacy vault has neither', async () => {
    _state.routes = [{ match: 'microsoft.keyvault/vaults', rows: [
      { id: '/kv/legacy-unprotected', name: 'legacy', soft: true, purge: false, rbac: false },
    ] }];
    const block = await collectSvcAsm(ctx());
    const f = block.findings.find((x) => x.rule === 'azure.svc.asm.key_vault_rbac_or_purge_protection')!;
    expect(f.passed).toBe(false);
    expect(f.gap?.affected_resources[0]?.identifier).toBe('/kv/legacy-unprotected');
  });

  it('treats undefined soft-delete as enabled (defensive default for older API shapes)', async () => {
    _state.routes = [{ match: 'microsoft.keyvault/vaults', rows: [
      { id: '/kv/null-soft', name: 'kv', soft: null, purge: true, rbac: true },
    ] }];
    const block = await collectSvcAsm(ctx());
    // null !== false, so the soft-delete finding passes.
    expect(block.findings.find((f) => f.rule === 'azure.svc.asm.key_vault_soft_delete_enabled')!.passed).toBe(true);
  });
});
