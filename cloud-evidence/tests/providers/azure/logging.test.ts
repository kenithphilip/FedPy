/**
 * Tests for providers/azure/logging.ts → collectMlaLet + collectMlaOsm.
 *
 * Mocks core/auth/azure.ts::resourceGraph with a substring-routed stub:
 * each KQL fragment maps to a canned response. Same shape used in the
 * Azure reference-arch test.
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

import { collectMlaLet, collectMlaOsm } from '../../../providers/azure/logging.ts';

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
// KSI-MLA-LET
// =====================================================================
describe('collectMlaLet (KSI-MLA-LET Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES both findings when diag settings + workspaces are present', async () => {
    _state.routes = [
      { match: 'diagnosticsettings', rows: [{ total: 42, bySub: ['sub-1', 'sub-2'] }] },
      { match: 'operationalinsights/workspaces', rows: [{ subscriptionId: 'sub-1', name: 'ws1', id: '/sub-1/ws1', retention: 90, sku: 'PerGB2018' }] },
    ];
    const block = await collectMlaLet(ctx(['sub-1', 'sub-2']));
    expect(block.findings.find((f) => f.rule === 'azure.diagnostic_settings_present')!.passed).toBe(true);
    expect(block.findings.find((f) => f.rule === 'azure.log_analytics_workspace_present')!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-MLA-LET');
  });

  it('FAILS the diag-settings finding when none exist (count=0)', async () => {
    _state.routes = [
      { match: 'diagnosticsettings', rows: [{ total: 0, bySub: [] }] },
      { match: 'operationalinsights/workspaces', rows: [{ subscriptionId: 'sub-1', name: 'ws1', id: 'x', retention: 90 }] },
    ];
    const block = await collectMlaLet(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.diagnostic_settings_present')!.passed).toBe(false);
  });

  it('FAILS the workspace finding when no Log Analytics workspace exists', async () => {
    _state.routes = [
      { match: 'diagnosticsettings', rows: [{ total: 5 }] },
      { match: 'operationalinsights/workspaces', rows: [] },
    ];
    const block = await collectMlaLet(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.log_analytics_workspace_present')!.passed).toBe(false);
  });

  it('warns + emits findings (still schema-valid) when no subscriptions are configured', async () => {
    const block = await collectMlaLet({ azure: { tenant_id: null, subscription_id: null, subscription_ids: [] } });
    expect(block.warnings?.some((w) => /No subscriptions/.test(w))).toBe(true);
    expect(block.findings).toHaveLength(2);
    assertSchemaValid(block, 'KSI-MLA-LET');
  });

  it('falls back to subscription_id when subscription_ids is missing (backward compat)', async () => {
    _state.routes = [
      { match: 'diagnosticsettings', rows: [{ total: 3 }] },
      { match: 'operationalinsights/workspaces', rows: [{ name: 'ws1' }] },
    ];
    const block = await collectMlaLet({ azure: { tenant_id: null, subscription_id: 'sub-only', subscription_ids: undefined } });
    expect(block.warnings).toEqual([]);
    expect(block.findings.every((f) => f.passed)).toBe(true);
  });
});

// =====================================================================
// KSI-MLA-OSM
// =====================================================================
describe('collectMlaOsm (KSI-MLA-OSM Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES both findings when workspace + Sentinel are both present (legacy solutions path)', async () => {
    _state.routes = [
      { match: 'operationalinsights/workspaces', rows: [{ id: '/w1', name: 'ws1' }] },
      { match: 'operationsmanagement/solutions', rows: [{ id: '/s1', name: 'SecurityInsights(ws1)' }] },
      { match: 'securityinsights/onboardingstates', rows: [] },
    ];
    const block = await collectMlaOsm(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.siem.workspace_substrate_present')!.passed).toBe(true);
    expect(block.findings.find((f) => f.rule === 'azure.siem.sentinel_deployed')!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-MLA-OSM');
  });

  it('PASSES the Sentinel finding via the newer onboardingstates path', async () => {
    _state.routes = [
      { match: 'operationalinsights/workspaces', rows: [{ id: '/w1', name: 'ws1' }] },
      { match: 'operationsmanagement/solutions', rows: [] },
      { match: 'securityinsights/onboardingstates', rows: [{ id: '/o1', name: 'default' }] },
    ];
    const block = await collectMlaOsm(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.siem.sentinel_deployed')!.passed).toBe(true);
  });

  it('FAILS both findings when no workspace and no Sentinel exist', async () => {
    _state.routes = [
      { match: 'operationalinsights/workspaces', rows: [] },
      { match: 'operationsmanagement/solutions', rows: [] },
      { match: 'securityinsights/onboardingstates', rows: [] },
    ];
    const block = await collectMlaOsm(ctx());
    expect(block.findings.every((f) => !f.passed)).toBe(true);
  });

  it('PASSES the workspace finding but FAILS Sentinel when SIEM not onboarded', async () => {
    _state.routes = [
      { match: 'operationalinsights/workspaces', rows: [{ id: '/w', name: 'ws' }] },
      { match: 'operationsmanagement/solutions', rows: [] },
      { match: 'securityinsights/onboardingstates', rows: [] },
    ];
    const block = await collectMlaOsm(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.siem.workspace_substrate_present')!.passed).toBe(true);
    expect(block.findings.find((f) => f.rule === 'azure.siem.sentinel_deployed')!.passed).toBe(false);
  });

  it('emits the 3rd-party SIEM alternative-satisfier as an awareness entry', async () => {
    _state.routes = [
      { match: 'operationalinsights/workspaces', rows: [] },
      { match: 'operationsmanagement/solutions', rows: [] },
      { match: 'securityinsights/onboardingstates', rows: [] },
    ];
    const block = await collectMlaOsm(ctx());
    expect((block.ksi_level_alternatives ?? []).some((a) => /3rd-party SIEM/i.test(a.via))).toBe(true);
  });
});
