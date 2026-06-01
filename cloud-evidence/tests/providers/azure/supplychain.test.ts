/**
 * Tests for providers/azure/supplychain.ts → collectCmtRmv + collectCmtVtd.
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

import { collectCmtRmv, collectCmtVtd } from '../../../providers/azure/supplychain.ts';

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
// KSI-CMT-RMV
// =====================================================================
describe('collectCmtRmv (KSI-CMT-RMV Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES both findings when an ACR exists with admin user disabled', async () => {
    _state.routes = [{ match: 'microsoft.containerregistry/registries', rows: [
      { id: '/acr/1', name: 'acrprod', subscriptionId: 'sub-1', admin: false, anonPull: false, softDelete: 'enabled', trust: 'enabled' },
    ] }];
    const block = await collectCmtRmv(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.cmt.rmv.acr_present')!.passed).toBe(true);
    expect(block.findings.find((f) => f.rule === 'azure.cmt.rmv.acr_admin_user_disabled')!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-CMT-RMV');
  });

  it('FAILS the presence finding when no ACRs exist; admin-disabled finding passes vacuously', async () => {
    _state.routes = [{ match: 'microsoft.containerregistry/registries', rows: [] }];
    const block = await collectCmtRmv(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.cmt.rmv.acr_present')!.passed).toBe(false);
    expect(block.findings.find((f) => f.rule === 'azure.cmt.rmv.acr_admin_user_disabled')!.passed).toBe(true);
  });

  it('FAILS the admin-disabled finding when at least one ACR has admin user enabled', async () => {
    _state.routes = [{ match: 'microsoft.containerregistry/registries', rows: [
      { id: '/acr/good', name: 'good', admin: false },
      { id: '/acr/bad', name: 'bad', admin: true },
    ] }];
    const block = await collectCmtRmv(ctx());
    const f = block.findings.find((x) => x.rule === 'azure.cmt.rmv.acr_admin_user_disabled')!;
    expect(f.passed).toBe(false);
    expect(f.gap?.affected_resources[0]?.identifier).toBe('/acr/bad');
  });

  it('treats null adminUserEnabled as disabled (defensive default — ACR ships with admin off)', async () => {
    _state.routes = [{ match: 'microsoft.containerregistry/registries', rows: [
      { id: '/acr/default', name: 'default', admin: null },
    ] }];
    const block = await collectCmtRmv(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.cmt.rmv.acr_admin_user_disabled')!.passed).toBe(true);
  });

  it('exposes the off-Azure-registry alternative satisfier at KSI level', async () => {
    _state.routes = [{ match: 'microsoft.containerregistry/registries', rows: [] }];
    const block = await collectCmtRmv(ctx());
    expect(block.ksi_level_alternatives?.[0]?.via).toContain('Off-Azure registry');
    expect(block.ksi_level_alternatives?.[0]?.detected).toBe(false);
  });
});

// =====================================================================
// KSI-CMT-VTD
// =====================================================================
describe('collectCmtVtd (KSI-CMT-VTD Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES both findings when a DevOps connector exists and Defender for Containers is Standard', async () => {
    _state.routes = [
      { match: 'securityconnectors', rows: [
        { id: '/conn/gh', name: 'github-prod', subscriptionId: 'sub-1', env: 'GitHub' },
      ] },
      { match: 'microsoft.security/pricings', rows: [
        { id: '/p/containers', name: 'Containers', subscriptionId: 'sub-1', planName: 'Containers', tier: 'Standard' },
      ] },
    ];
    const block = await collectCmtVtd(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.cmt.vtd.defender_devops_connector_present')!.passed).toBe(true);
    expect(block.findings.find((f) => f.rule === 'azure.cmt.vtd.defender_for_containers_enabled')!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-CMT-VTD');
  });

  it('ACCEPTS Azure DevOps, GitHub, or GitLab connector environments', async () => {
    _state.routes = [
      { match: 'securityconnectors', rows: [
        { id: '/conn/ado', env: 'AzureDevOps' },
      ] },
      { match: 'microsoft.security/pricings', rows: [
        { id: '/p/c', name: 'Containers', subscriptionId: 'sub-1', planName: 'Containers', tier: 'Standard' },
      ] },
    ];
    const block = await collectCmtVtd(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.cmt.vtd.defender_devops_connector_present')!.passed).toBe(true);
  });

  it('FAILS the DevOps-connector finding when no connectors of an accepted env type exist', async () => {
    _state.routes = [
      { match: 'securityconnectors', rows: [
        { id: '/conn/other', env: 'AWS' }, // non-DevOps env — should not count
      ] },
      { match: 'microsoft.security/pricings', rows: [] },
    ];
    const block = await collectCmtVtd(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.cmt.vtd.defender_devops_connector_present')!.passed).toBe(false);
  });

  it('FAILS the containers-pricing finding when no Standard tier subscription exists', async () => {
    _state.routes = [
      { match: 'securityconnectors', rows: [{ id: '/conn/gh', env: 'GitHub' }] },
      { match: 'microsoft.security/pricings', rows: [
        { id: '/p/c', name: 'Containers', subscriptionId: 'sub-1', planName: 'Containers', tier: 'Free' },
      ] },
    ];
    const block = await collectCmtVtd(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.cmt.vtd.defender_for_containers_enabled')!.passed).toBe(false);
  });

  it('FAILS the containers-pricing finding when no pricing row exists at all (Security Reader missing or plan off)', async () => {
    _state.routes = [
      { match: 'securityconnectors', rows: [{ id: '/conn/gh', env: 'GitHub' }] },
      { match: 'microsoft.security/pricings', rows: [] },
    ];
    const block = await collectCmtVtd(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.cmt.vtd.defender_for_containers_enabled')!.passed).toBe(false);
  });

  it('exposes 3rd-party CI gate + GitHub Advanced Security alt satisfiers at KSI level', async () => {
    _state.routes = [
      { match: 'securityconnectors', rows: [] },
      { match: 'microsoft.security/pricings', rows: [] },
    ];
    const block = await collectCmtVtd(ctx());
    const labels = block.ksi_level_alternatives?.map((a) => a.via) ?? [];
    expect(labels.some((l) => l.includes('GitHub Advanced Security'))).toBe(true);
    expect(labels.some((l) => l.includes('3rd-party CI gates'))).toBe(true);
  });
});
