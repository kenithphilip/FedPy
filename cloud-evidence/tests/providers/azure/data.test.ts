/**
 * Tests for providers/azure/data.ts → collectSvcRud + collectSvcVcm + collectSvcVri.
 * Substring-routed Resource Graph mock; same shape as the other Azure tests.
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

import { collectSvcRud, collectSvcVcm, collectSvcVri } from '../../../providers/azure/data.ts';

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

// =====================================================================
// KSI-SVC-RUD
// =====================================================================
describe('collectSvcRud (KSI-SVC-RUD Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES both findings when soft-delete is on with finite retention and a lifecycle policy is attached', async () => {
    _state.routes = [
      { match: 'microsoft.storage/storageaccounts"', rows: [
        { id: '/sa/1', name: 'sa-1', subscriptionId: 'sub-1', sdEnabled: true, sdDays: 30 },
      ] },
      { match: 'managementpolicies', rows: [
        { id: '/sa/1/policy', name: 'default', subscriptionId: 'sub-1' },
      ] },
    ];
    const block = await collectSvcRud(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.svc.rud.blob_soft_delete_finite_window')!.passed).toBe(true);
    expect(block.findings.find((f) => f.rule === 'azure.svc.rud.lifecycle_management_present')!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-SVC-RUD');
  });

  it('FAILS the soft-delete finding when at least one account has soft-delete disabled', async () => {
    _state.routes = [
      { match: 'microsoft.storage/storageaccounts"', rows: [
        { id: '/sa/good', sdEnabled: true, sdDays: 30 },
        { id: '/sa/bad', sdEnabled: false, sdDays: 0 },
      ] },
      { match: 'managementpolicies', rows: [{ id: '/sa/good/p' }] },
    ];
    const block = await collectSvcRud(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.svc.rud.blob_soft_delete_finite_window')!.passed).toBe(false);
  });

  it('FAILS the soft-delete finding when retention is excessively long (> 90 days)', async () => {
    _state.routes = [
      { match: 'microsoft.storage/storageaccounts"', rows: [
        { id: '/sa/long', sdEnabled: true, sdDays: 365 },
      ] },
      { match: 'managementpolicies', rows: [{ id: '/sa/long/p' }] },
    ];
    const block = await collectSvcRud(ctx());
    const f = block.findings.find((x) => x.rule === 'azure.svc.rud.blob_soft_delete_finite_window')!;
    expect(f.passed).toBe(false);
    expect((f.current_state.observations as any).overly_long_retention).toBe(1);
  });

  it('FAILS the lifecycle finding when storage accounts exist but no policies are attached', async () => {
    _state.routes = [
      { match: 'microsoft.storage/storageaccounts"', rows: [
        { id: '/sa/1', sdEnabled: true, sdDays: 30 },
      ] },
      { match: 'managementpolicies', rows: [] },
    ];
    const block = await collectSvcRud(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.svc.rud.lifecycle_management_present')!.passed).toBe(false);
  });

  it('PASSES both findings vacuously when no storage accounts exist', async () => {
    _state.routes = [
      { match: 'microsoft.storage/storageaccounts"', rows: [] },
      { match: 'managementpolicies', rows: [] },
    ];
    const block = await collectSvcRud(ctx());
    expect(block.findings.every((f) => f.passed)).toBe(true);
  });
});

// =====================================================================
// KSI-SVC-VCM
// =====================================================================
describe('collectSvcVcm (KSI-SVC-VCM Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES when an Application Gateway has at least one SSL profile (mTLS)', async () => {
    _state.routes = [
      { match: 'microsoft.network/applicationgateways', rows: [
        { id: '/agw/1', name: 'agw-prod', subscriptionId: 'sub-1', mtlsProfiles: 2 },
      ] },
      { match: 'microsoft.apimanagement/service', rows: [] },
      { match: 'microsoft.containerservice/managedclusters', rows: [] },
    ];
    const block = await collectSvcVcm(ctx());
    expect(block.findings[0]!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-SVC-VCM');
  });

  it('PASSES when API Management has a hostnameConfiguration with negotiateClientCertificate=true', async () => {
    _state.routes = [
      { match: 'microsoft.network/applicationgateways', rows: [] },
      { match: 'microsoft.apimanagement/service', rows: [
        { id: '/apim/1', subscriptionId: 'sub-1', hcs: [{ type: 'Proxy', negotiateClientCertificate: true }] },
      ] },
      { match: 'microsoft.containerservice/managedclusters', rows: [] },
    ];
    const block = await collectSvcVcm(ctx());
    expect(block.findings[0]!.passed).toBe(true);
  });

  it('PASSES when an AKS cluster has Istio service-mesh add-on enabled', async () => {
    _state.routes = [
      { match: 'microsoft.network/applicationgateways', rows: [] },
      { match: 'microsoft.apimanagement/service', rows: [] },
      { match: 'microsoft.containerservice/managedclusters', rows: [
        { id: '/aks/1', subscriptionId: 'sub-1', meshMode: 'Istio' },
      ] },
    ];
    const block = await collectSvcVcm(ctx());
    expect(block.findings[0]!.passed).toBe(true);
    expect((block.findings[0]!.current_state.observations as any).aks_with_istio_mesh).toBe(1);
  });

  it('FAILS when no AGW mTLS, APIM client-cert, or AKS Istio is detected', async () => {
    _state.routes = [
      { match: 'microsoft.network/applicationgateways', rows: [
        { id: '/agw/no-mtls', mtlsProfiles: 0 },
      ] },
      { match: 'microsoft.apimanagement/service', rows: [
        { id: '/apim/no-cert', hcs: [{ type: 'Proxy', negotiateClientCertificate: false }] },
      ] },
      { match: 'microsoft.containerservice/managedclusters', rows: [
        { id: '/aks/no-mesh', meshMode: '' },
      ] },
    ];
    const block = await collectSvcVcm(ctx());
    expect(block.findings[0]!.passed).toBe(false);
  });

  it('exposes external service-mesh + code-level mTLS alternative satisfiers at KSI level', async () => {
    _state.routes = [
      { match: 'microsoft.network/applicationgateways', rows: [] },
      { match: 'microsoft.apimanagement/service', rows: [] },
      { match: 'microsoft.containerservice/managedclusters', rows: [] },
    ];
    const block = await collectSvcVcm(ctx());
    const labels = block.ksi_level_alternatives?.map((a) => a.via) ?? [];
    expect(labels.some((l) => l.includes('External service mesh'))).toBe(true);
    expect(labels.some((l) => l.includes('Code-level mTLS'))).toBe(true);
  });
});

// =====================================================================
// KSI-SVC-VRI
// =====================================================================
describe('collectSvcVri (KSI-SVC-VRI Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES when every storage account has blob versioning enabled', async () => {
    _state.routes = [
      { match: 'microsoft.storage/storageaccounts"', rows: [
        { id: '/sa/1', name: 'sa-1', subscriptionId: 'sub-1', versioning: true },
      ] },
      { match: 'immutabilitypolicies', rows: [] },
    ];
    const block = await collectSvcVri(ctx());
    expect(block.findings[0]!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-SVC-VRI');
  });

  it('PASSES when an immutability policy covers an otherwise-unversioned account', async () => {
    _state.routes = [
      { match: 'microsoft.storage/storageaccounts"', rows: [
        { id: '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa-1', name: 'sa-1', versioning: false },
      ] },
      { match: 'immutabilitypolicies', rows: [
        { id: '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa-1/blobServices/default/containers/c1/immutabilityPolicies/default' },
      ] },
    ];
    const block = await collectSvcVri(ctx());
    expect(block.findings[0]!.passed).toBe(true);
  });

  it('FAILS when a storage account has neither versioning nor an immutability policy', async () => {
    _state.routes = [
      { match: 'microsoft.storage/storageaccounts"', rows: [
        { id: '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/unprotected', name: 'unprotected', versioning: false },
      ] },
      { match: 'immutabilitypolicies', rows: [] },
    ];
    const block = await collectSvcVri(ctx());
    expect(block.findings[0]!.passed).toBe(false);
  });

  it('PASSES vacuously when no storage accounts exist', async () => {
    _state.routes = [
      { match: 'microsoft.storage/storageaccounts"', rows: [] },
      { match: 'immutabilitypolicies', rows: [] },
    ];
    const block = await collectSvcVri(ctx());
    expect(block.findings[0]!.passed).toBe(true);
  });

  it('exposes Confidential Compute alt satisfier at KSI level', async () => {
    _state.routes = [
      { match: 'microsoft.storage/storageaccounts"', rows: [] },
      { match: 'immutabilitypolicies', rows: [] },
    ];
    const block = await collectSvcVri(ctx());
    expect(block.ksi_level_alternatives?.[0]?.via).toContain('Confidential Compute');
  });
});
