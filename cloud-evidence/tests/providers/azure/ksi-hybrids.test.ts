/**
 * Tests for providers/azure/ksi-hybrids.ts → collectCmtRvp / collectInrAar /
 * collectInrRpi / collectScrMit / collectSvcPrr.
 *
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

import { collectCmtRvp, collectInrAar, collectInrRpi, collectScrMit, collectSvcPrr } from '../../../providers/azure/ksi-hybrids.ts';

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

describe('collectCmtRvp (KSI-CMT-RVP Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES when policy assignments + policy states are present', async () => {
    _state.routes = [
      { match: 'policyassignments', rows: [{ id: '/pa/1', name: 'mcsb', subscriptionId: 'sub-1' }] },
      { match: 'policystates', rows: [{ subscriptionId: 'sub-1', n: 100 }] },
    ];
    const block = await collectCmtRvp(ctx());
    expect(block.findings[0]!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-CMT-RVP');
  });

  it('FAILS when assignments exist but no policy-state evaluations are running', async () => {
    _state.routes = [
      { match: 'policyassignments', rows: [{ id: '/pa/1' }] },
      { match: 'policystates', rows: [] },
    ];
    const block = await collectCmtRvp(ctx());
    expect(block.findings[0]!.passed).toBe(false);
  });

  it('FAILS when no assignments exist at all', async () => {
    _state.routes = [
      { match: 'policyassignments', rows: [] },
      { match: 'policystates', rows: [] },
    ];
    const block = await collectCmtRvp(ctx());
    expect(block.findings[0]!.passed).toBe(false);
  });
});

describe('collectInrAar (KSI-INR-AAR Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES when a Sentinel automation rule exists', async () => {
    _state.routes = [
      { match: 'automationrules', rows: [{ id: '/auto/1', name: 'p1-handler', subscriptionId: 'sub-1' }] },
      { match: 'microsoft.insights/activitylogalerts', rows: [] },
    ];
    const block = await collectInrAar(ctx());
    expect(block.findings[0]!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-INR-AAR');
  });

  it('PASSES when a Monitor alert rule exists (without Sentinel)', async () => {
    _state.routes = [
      { match: 'automationrules', rows: [] },
      { match: 'microsoft.insights/activitylogalerts', rows: [{ id: '/al/1', name: 'crit', type: 'microsoft.insights/activitylogalerts' }] },
    ];
    const block = await collectInrAar(ctx());
    expect(block.findings[0]!.passed).toBe(true);
  });

  it('FAILS when neither Sentinel nor Monitor alert rules exist', async () => {
    _state.routes = [
      { match: 'automationrules', rows: [] },
      { match: 'microsoft.insights/activitylogalerts', rows: [] },
    ];
    const block = await collectInrAar(ctx());
    expect(block.findings[0]!.passed).toBe(false);
  });
});

describe('collectInrRpi (KSI-INR-RPI Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES when at least one workspace has retention >= 90 days', async () => {
    _state.routes = [{ match: 'operationalinsights/workspaces', rows: [
      { id: '/w/1', name: 'logs-prod', subscriptionId: 'sub-1', retention: 365 },
    ] }];
    const block = await collectInrRpi(ctx());
    expect(block.findings[0]!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-INR-RPI');
  });

  it('FAILS when all workspaces have retention < 90 days', async () => {
    _state.routes = [{ match: 'operationalinsights/workspaces', rows: [
      { id: '/w/short', retention: 30 },
    ] }];
    const block = await collectInrRpi(ctx());
    expect(block.findings[0]!.passed).toBe(false);
  });

  it('PASSES vacuously when no workspaces exist (downstream KSIs flag the absence)', async () => {
    _state.routes = [{ match: 'operationalinsights/workspaces', rows: [] }];
    const block = await collectInrRpi(ctx());
    expect(block.findings[0]!.passed).toBe(true);
  });
});

describe('collectScrMit (KSI-SCR-MIT Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES when an ACR has content trust enabled', async () => {
    _state.routes = [
      { match: 'microsoft.containerregistry/registries', rows: [
        { id: '/acr/1', name: 'prod', subscriptionId: 'sub-1', trust: 'enabled' },
      ] },
      { match: 'microsoft.security/pricings', rows: [] },
    ];
    const block = await collectScrMit(ctx());
    expect(block.findings[0]!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-SCR-MIT');
  });

  it('PASSES when Defender for Containers is Standard tier (even without ACR policies)', async () => {
    _state.routes = [
      { match: 'microsoft.containerregistry/registries', rows: [] },
      { match: 'microsoft.security/pricings', rows: [{ id: '/p', name: 'Containers', subscriptionId: 'sub-1', tier: 'Standard' }] },
    ];
    const block = await collectScrMit(ctx());
    expect(block.findings[0]!.passed).toBe(true);
  });

  it('FAILS when neither ACR policies nor Defender Standard tier is present', async () => {
    _state.routes = [
      { match: 'microsoft.containerregistry/registries', rows: [{ id: '/acr/empty', trust: 'disabled', quarantine: 'disabled' }] },
      { match: 'microsoft.security/pricings', rows: [{ id: '/p', name: 'Containers', tier: 'Free' }] },
    ];
    const block = await collectScrMit(ctx());
    expect(block.findings[0]!.passed).toBe(false);
  });
});

describe('collectSvcPrr (KSI-SVC-PRR Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES when every storage account denies public network + anonymous blob access', async () => {
    _state.routes = [{ match: 'microsoft.storage/storageaccounts', rows: [
      { id: '/sa/safe', name: 'safe', subscriptionId: 'sub-1', pubAccess: 'Disabled', allowBlobAnon: false },
    ] }];
    const block = await collectSvcPrr(ctx());
    expect(block.findings[0]!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-SVC-PRR');
  });

  it('FAILS when a storage account has publicNetworkAccess=Enabled', async () => {
    _state.routes = [{ match: 'microsoft.storage/storageaccounts', rows: [
      { id: '/sa/open', name: 'open', pubAccess: 'Enabled', allowBlobAnon: false },
    ] }];
    const block = await collectSvcPrr(ctx());
    expect(block.findings[0]!.passed).toBe(false);
    expect(block.findings[0]!.gap?.affected_resources[0]?.identifier).toBe('/sa/open');
  });

  it('FAILS when allowBlobPublicAccess=true even with publicNetworkAccess=Disabled', async () => {
    _state.routes = [{ match: 'microsoft.storage/storageaccounts', rows: [
      { id: '/sa/blob', pubAccess: 'Disabled', allowBlobAnon: true },
    ] }];
    const block = await collectSvcPrr(ctx());
    expect(block.findings[0]!.passed).toBe(false);
  });

  it('PASSES vacuously when no storage accounts exist', async () => {
    _state.routes = [{ match: 'microsoft.storage/storageaccounts', rows: [] }];
    const block = await collectSvcPrr(ctx());
    expect(block.findings[0]!.passed).toBe(true);
  });
});
