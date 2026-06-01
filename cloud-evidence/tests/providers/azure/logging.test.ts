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

import { collectMlaLet, collectMlaOsm, collectMlaAla, collectMlaRvl, collectCmtLmc, collectMlaEvc, collectInrRir } from '../../../providers/azure/logging.ts';

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

// =====================================================================
// KSI-MLA-ALA
// =====================================================================
const LAR = '73c42c96-874c-492b-b04d-ab87d138a893';
const OWNER = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635';
const CONTRIB = 'b24988ac-6180-42a0-ab88-20f7382dd24c';

describe('collectMlaAla (KSI-MLA-ALA Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES the Log Analytics Reader finding when a Reader assignment exists at workspace scope', async () => {
    _state.routes = [{ match: 'authorizationresources', rows: [
      { id: '/ra/1', scope: '/subscriptions/sub-1/.../microsoft.operationalinsights/workspaces/ws1', roleDef: `/providers/Microsoft.Authorization/roleDefinitions/${LAR}`, principalId: 'p1' },
    ] }];
    const block = await collectMlaAla(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.mla.ala.log_analytics_reader_assigned')!.passed).toBe(true);
    expect(block.findings.find((f) => f.rule === 'azure.mla.ala.no_broad_workspace_admins')!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-MLA-ALA');
  });

  it('FAILS the broad-admin finding when an Owner is scoped at a workspace', async () => {
    _state.routes = [{ match: 'authorizationresources', rows: [
      { id: '/ra/1', scope: '/subscriptions/sub-1/.../microsoft.operationalinsights/workspaces/ws1', roleDef: `/providers/Microsoft.Authorization/roleDefinitions/${OWNER}` },
      { id: '/ra/2', scope: '/subscriptions/sub-1/.../microsoft.operationalinsights/workspaces/ws1', roleDef: `/providers/Microsoft.Authorization/roleDefinitions/${LAR}` },
    ] }];
    const block = await collectMlaAla(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.mla.ala.no_broad_workspace_admins')!.passed).toBe(false);
    expect(block.findings.find((f) => f.rule === 'azure.mla.ala.log_analytics_reader_assigned')!.passed).toBe(true);
  });

  it('FAILS both findings when there are zero workspace-scoped role assignments', async () => {
    _state.routes = [{ match: 'authorizationresources', rows: [] }];
    const block = await collectMlaAla(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.mla.ala.log_analytics_reader_assigned')!.passed).toBe(false);
    // no_broad_workspace_admins passes because there are no broad assignments either; only the Reader-not-present finding fails.
    expect(block.findings.find((f) => f.rule === 'azure.mla.ala.no_broad_workspace_admins')!.passed).toBe(true);
  });

  it('IGNORES Contributor role-defs that don\'t live under the role-definitions path', async () => {
    _state.routes = [{ match: 'authorizationresources', rows: [
      // Bogus roleDef that doesn't end with `/${CONTRIB}` — should be ignored by the substring check.
      { id: '/ra/1', scope: '/subscriptions/sub-1/.../microsoft.operationalinsights/workspaces/ws1', roleDef: `/CustomRoleDefs/${CONTRIB}-suffixed` },
      { id: '/ra/2', scope: '/subscriptions/sub-1/.../microsoft.operationalinsights/workspaces/ws1', roleDef: `/providers/Microsoft.Authorization/roleDefinitions/${LAR}` },
    ] }];
    const block = await collectMlaAla(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.mla.ala.no_broad_workspace_admins')!.passed).toBe(true);
  });
});

// =====================================================================
// KSI-MLA-RVL
// =====================================================================
describe('collectMlaRvl (KSI-MLA-RVL Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES both findings when at least one workspace meets the retention floor and at least one alert rule exists', async () => {
    _state.routes = [
      { match: 'operationalinsights/workspaces', rows: [{ id: '/w1', retention: 365 }] },
      { match: 'insights/scheduledqueryrules', rows: [{ id: '/r1', name: 'rule1' }] },
      { match: 'securityinsights/alertrules', rows: [] },
    ];
    const block = await collectMlaRvl(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.mla.rvl.workspace_retention_at_floor')!.passed).toBe(true);
    expect(block.findings.find((f) => f.rule === 'azure.mla.rvl.alert_rules_present')!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-MLA-RVL');
  });

  it('FAILS the retention finding when all workspaces are below the 90-day floor', async () => {
    _state.routes = [
      { match: 'operationalinsights/workspaces', rows: [{ id: '/w', retention: 30 }] },
      { match: 'insights/scheduledqueryrules', rows: [{ id: '/r' }] },
      { match: 'securityinsights/alertrules', rows: [] },
    ];
    const block = await collectMlaRvl(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.mla.rvl.workspace_retention_at_floor')!.passed).toBe(false);
  });

  it('PASSES the alert-rules finding via Sentinel-only path', async () => {
    _state.routes = [
      { match: 'operationalinsights/workspaces', rows: [{ id: '/w', retention: 90 }] },
      { match: 'insights/scheduledqueryrules', rows: [] },
      { match: 'securityinsights/alertrules', rows: [{ id: '/r' }, { id: '/r2' }] },
    ];
    const block = await collectMlaRvl(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.mla.rvl.alert_rules_present')!.passed).toBe(true);
  });

  it('FAILS both findings when there are no workspaces and no alert rules', async () => {
    _state.routes = [
      { match: 'operationalinsights/workspaces', rows: [] },
      { match: 'insights/scheduledqueryrules', rows: [] },
      { match: 'securityinsights/alertrules', rows: [] },
    ];
    const block = await collectMlaRvl(ctx());
    expect(block.findings.every((f) => !f.passed)).toBe(true);
  });
});

// =====================================================================
// KSI-CMT-LMC
// =====================================================================
describe('collectCmtLmc (KSI-CMT-LMC Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES activity-log finding when every subscription has a sub-scope diagnostic setting', async () => {
    _state.routes = [
      { match: 'diagnosticsettings', rows: [
        { id: '/subscriptions/sub-1/providers/microsoft.insights/diagnosticsettings/ds-1', subscriptionId: 'sub-1', name: 'ds-1', workspaceId: '/ws', storageId: '' },
        { id: '/subscriptions/sub-2/providers/microsoft.insights/diagnosticsettings/ds-2', subscriptionId: 'sub-2', name: 'ds-2', workspaceId: '/ws', storageId: '' },
      ] },
      { match: 'operationsmanagement/solutions', rows: [{ id: '/s/ChangeTracking(ws)', name: 'ChangeTracking(ws)' }] },
    ];
    const block = await collectCmtLmc(ctx(['sub-1', 'sub-2']));
    expect(block.findings.find((f) => f.rule === 'azure.cmt.lmc.activity_log_exported')!.passed).toBe(true);
    expect(block.findings.find((f) => f.rule === 'azure.cmt.lmc.change_tracking_enabled')!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-CMT-LMC');
  });

  it('FAILS activity-log finding when one subscription is missing its sub-scope diagnostic setting', async () => {
    _state.routes = [
      { match: 'diagnosticsettings', rows: [
        { id: '/subscriptions/sub-1/providers/microsoft.insights/diagnosticsettings/ds-1', subscriptionId: 'sub-1' },
      ] },
      { match: 'operationsmanagement/solutions', rows: [] },
    ];
    const block = await collectCmtLmc(ctx(['sub-1', 'sub-2']));
    const f = block.findings.find((x) => x.rule === 'azure.cmt.lmc.activity_log_exported')!;
    expect(f.passed).toBe(false);
    expect(f.gap?.affected_resources.some((r) => r.identifier === 'sub-2')).toBe(true);
  });

  it('FAILS activity-log finding when no subscriptions are configured', async () => {
    _state.routes = [{ match: 'diagnosticsettings', rows: [] }, { match: 'operationsmanagement/solutions', rows: [] }];
    const block = await collectCmtLmc(ctx([]));
    expect(block.findings.find((f) => f.rule === 'azure.cmt.lmc.activity_log_exported')!.passed).toBe(false);
  });

  it('FAILS change-tracking finding when no ChangeTracking solution is deployed', async () => {
    _state.routes = [
      { match: 'diagnosticsettings', rows: [
        { id: '/subscriptions/sub-1/providers/microsoft.insights/diagnosticsettings/ds', subscriptionId: 'sub-1' },
      ] },
      { match: 'operationsmanagement/solutions', rows: [] },
    ];
    const block = await collectCmtLmc(ctx(['sub-1']));
    expect(block.findings.find((f) => f.rule === 'azure.cmt.lmc.change_tracking_enabled')!.passed).toBe(false);
  });

  it('IGNORES diagnostic settings at non-subscription scopes (e.g. child of a resource)', async () => {
    _state.routes = [
      { match: 'diagnosticsettings', rows: [
        { id: '/subscriptions/sub-1/resourceGroups/rg/providers/microsoft.storage/storageaccounts/sa/providers/microsoft.insights/diagnosticsettings/ds', subscriptionId: 'sub-1' },
      ] },
      { match: 'operationsmanagement/solutions', rows: [] },
    ];
    const block = await collectCmtLmc(ctx(['sub-1']));
    // Resource-scope diag settings don't count as sub-scope; activity-log export is not configured for this sub.
    expect(block.findings.find((f) => f.rule === 'azure.cmt.lmc.activity_log_exported')!.passed).toBe(false);
  });
});

// =====================================================================
// KSI-MLA-EVC
// =====================================================================
describe('collectMlaEvc (KSI-MLA-EVC Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES when Defender assessments exist (any subscription)', async () => {
    _state.routes = [{ match: 'security/assessments', rows: [
      { subscriptionId: 'sub-1', total: 200, unhealthy: 25, healthy: 175 },
    ] }];
    const block = await collectMlaEvc(ctx());
    expect(block.findings[0]!.passed).toBe(true);
    const obs = block.findings[0]!.current_state.observations as any;
    expect(obs.total).toBe(200);
    expect(obs.unhealthy).toBe(25);
    expect(obs.healthy).toBe(175);
    assertSchemaValid(block, 'KSI-MLA-EVC');
  });

  it('SUMS across multiple subscriptions', async () => {
    _state.routes = [{ match: 'security/assessments', rows: [
      { subscriptionId: 'sub-1', total: 100, unhealthy: 10, healthy: 90 },
      { subscriptionId: 'sub-2', total: 50, unhealthy: 5, healthy: 45 },
    ] }];
    const block = await collectMlaEvc(ctx(['sub-1', 'sub-2']));
    const obs = block.findings[0]!.current_state.observations as any;
    expect(obs.total).toBe(150);
    expect(obs.unhealthy).toBe(15);
    expect(obs.healthy).toBe(135);
  });

  it('FAILS when no Defender assessments exist', async () => {
    _state.routes = [{ match: 'security/assessments', rows: [] }];
    const block = await collectMlaEvc(ctx());
    expect(block.findings[0]!.passed).toBe(false);
  });
});

// =====================================================================
// KSI-INR-RIR
// =====================================================================
describe('collectInrRir (KSI-INR-RIR Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES when at least one Action Group has a populated receiver', async () => {
    _state.routes = [
      { match: 'microsoft.insights/actiongroups', rows: [
        { id: '/ag/1', name: 'ag-prod', subscriptionId: 'sub-1', location: 'global',
          email_count: 2, sms_count: 0, webhook_count: 1, logic_app_count: 0, function_count: 0, eventhub_count: 0 },
      ] },
      { match: 'microsoft.securityinsights/automationrules', rows: [] },
    ];
    const block = await collectInrRir(ctx());
    expect(block.findings[0]!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-INR-RIR');
  });

  it('PASSES on a Sentinel automation rule even without Action Groups', async () => {
    _state.routes = [
      { match: 'microsoft.insights/actiongroups', rows: [] },
      { match: 'microsoft.securityinsights/automationrules', rows: [
        { id: '/auto/1', name: 'pager-on-incident', subscriptionId: 'sub-1' },
      ] },
    ];
    const block = await collectInrRir(ctx());
    expect(block.findings[0]!.passed).toBe(true);
    // Detected signal reflected in the alt satisfier list.
    const sentinelAlt = block.ksi_level_alternatives!.find((a) => a.via.includes('Sentinel'));
    expect(sentinelAlt?.detected).toBe(true);
  });

  it('FAILS when Action Groups exist but every one is empty (plumbing without routing)', async () => {
    _state.routes = [
      { match: 'microsoft.insights/actiongroups', rows: [
        { id: '/ag/empty', name: 'empty', email_count: 0, sms_count: 0, webhook_count: 0, logic_app_count: 0, function_count: 0, eventhub_count: 0 },
      ] },
      { match: 'microsoft.securityinsights/automationrules', rows: [] },
    ];
    const block = await collectInrRir(ctx());
    expect(block.findings[0]!.passed).toBe(false);
    expect(block.findings[0]!.current_state.summary).toContain('plumbing without routing');
  });

  it('FAILS when neither Action Groups nor automation rules exist', async () => {
    _state.routes = [
      { match: 'microsoft.insights/actiongroups', rows: [] },
      { match: 'microsoft.securityinsights/automationrules', rows: [] },
    ];
    const block = await collectInrRir(ctx());
    expect(block.findings[0]!.passed).toBe(false);
  });

  it('exposes PagerDuty / OpsGenie alternative satisfier at KSI level', async () => {
    _state.routes = [
      { match: 'microsoft.insights/actiongroups', rows: [] },
      { match: 'microsoft.securityinsights/automationrules', rows: [] },
    ];
    const block = await collectInrRir(ctx());
    const pdAlt = block.ksi_level_alternatives!.find((a) => a.via.includes('PagerDuty'));
    expect(pdAlt).toBeDefined();
    expect(pdAlt?.detected).toBe(false);
  });
});
