/**
 * Tests for providers/azure/crypto.ts → collectUcm (KSI-AFR-UCM).
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

import { collectUcm } from '../../../providers/azure/crypto.ts';

function assertSchemaValid(block: any, ksiId: string): void {
  const envelope: any = {
    ksi_id: ksiId, ksi_name: ksiId, ksi_statement: 'smoke', scope: 'HYBRID',
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

describe('collectUcm (KSI-AFR-UCM Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES when at least one Key Vault key is enabled', async () => {
    _state.routes = [
      { match: 'microsoft.keyvault/vaults/keys', rows: [{ id: '/kv/k1', name: 'data-kek', subscriptionId: 'sub-1', kty: 'RSA', enabled: true }] },
      { match: 'microsoft.network/applicationgateways', rows: [] },
      { match: 'microsoft.storage/storageaccounts', rows: [] },
    ];
    const block = await collectUcm(ctx());
    expect(block.findings[0]!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-AFR-UCM');
  });

  it('PASSES when an AGW uses a modern TLS-1.2-min predefined SSL policy', async () => {
    _state.routes = [
      { match: 'microsoft.keyvault/vaults/keys', rows: [] },
      { match: 'microsoft.network/applicationgateways', rows: [{ id: '/agw/1', subscriptionId: 'sub-1', policyName: 'appgwsslpolicy20220101', minProto: '' }] },
      { match: 'microsoft.storage/storageaccounts', rows: [] },
    ];
    const block = await collectUcm(ctx());
    expect(block.findings[0]!.passed).toBe(true);
  });

  it('PASSES when an AGW custom policy declares minProtocolVersion TLSv1_2', async () => {
    _state.routes = [
      { match: 'microsoft.keyvault/vaults/keys', rows: [] },
      { match: 'microsoft.network/applicationgateways', rows: [{ id: '/agw/2', policyName: '', minProto: 'TLSv1_2' }] },
      { match: 'microsoft.storage/storageaccounts', rows: [] },
    ];
    const block = await collectUcm(ctx());
    expect(block.findings[0]!.passed).toBe(true);
  });

  it('PASSES when a storage account uses infrastructure-encryption (double encrypt)', async () => {
    _state.routes = [
      { match: 'microsoft.keyvault/vaults/keys', rows: [] },
      { match: 'microsoft.network/applicationgateways', rows: [] },
      { match: 'microsoft.storage/storageaccounts', rows: [{ id: '/sa/1', name: 'sec', infraEnc: true }] },
    ];
    const block = await collectUcm(ctx());
    expect(block.findings[0]!.passed).toBe(true);
    expect((block.findings[0]!.current_state.observations as any).storage_with_infrastructure_encryption).toBe(1);
  });

  it('FAILS when no Key Vault keys, no modern-TLS AGWs, and no infra-encrypted storage', async () => {
    _state.routes = [
      { match: 'microsoft.keyvault/vaults/keys', rows: [{ id: '/kv/disabled', enabled: false }] },
      { match: 'microsoft.network/applicationgateways', rows: [{ id: '/agw/legacy', policyName: 'legacypolicy', minProto: 'TLSv1_0' }] },
      { match: 'microsoft.storage/storageaccounts', rows: [{ id: '/sa/basic', infraEnc: false }] },
    ];
    const block = await collectUcm(ctx());
    expect(block.findings[0]!.passed).toBe(false);
  });

  it('exposes the external-HSM alternative satisfier at KSI level', async () => {
    _state.routes = [
      { match: 'microsoft.keyvault/vaults/keys', rows: [] },
      { match: 'microsoft.network/applicationgateways', rows: [] },
      { match: 'microsoft.storage/storageaccounts', rows: [] },
    ];
    const block = await collectUcm(ctx());
    expect(block.ksi_level_alternatives?.[0]?.via).toContain('External HSM');
    expect(block.ksi_level_alternatives?.[0]?.detected).toBe(false);
  });
});
