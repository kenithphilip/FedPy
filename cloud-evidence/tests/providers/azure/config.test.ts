/**
 * Tests for providers/azure/config.ts → collectCnaEis + collectCnaIbp.
 * Same substring-routed Resource Graph mock as the other Azure test files.
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

import { collectCnaEis, collectCnaIbp, collectCnaDfp, collectSvcAcm, collectSvcEis } from '../../../providers/azure/config.ts';

// Substring used to route mock queries to the MCSB-specific route. The
// collector embeds the (mixed-case) MCSB initiative id literally in the KQL,
// so the route only needs to look for the unique GUID tail to disambiguate
// the MCSB query from the broader regulatory-initiative query.
const MCSB_ROUTE_KEY = '1f3afdf9-d0c9-4c3d-847f-89da613e70a8';

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
// KSI-CNA-EIS
// =====================================================================
describe('collectCnaEis (KSI-CNA-EIS Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES both findings when assignments + state rows are non-empty', async () => {
    _state.routes = [
      { match: 'policyassignments', rows: [
        { id: '/pa/1', name: 'pa-1', subscriptionId: 'sub-1', displayName: 'MCSB', scope: '/subscriptions/sub-1' },
      ] },
      { match: 'policystates', rows: [
        { subscriptionId: 'sub-1', total: 50, nonCompliant: 5 },
      ] },
    ];
    const block = await collectCnaEis(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.cna.eis.policy_assignments_present')!.passed).toBe(true);
    expect(block.findings.find((f) => f.rule === 'azure.cna.eis.policy_evaluations_running')!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-CNA-EIS');
  });

  it('FAILS both findings when nothing is configured', async () => {
    _state.routes = [
      { match: 'policyassignments', rows: [] },
      { match: 'policystates', rows: [] },
    ];
    const block = await collectCnaEis(ctx());
    expect(block.findings.every((f) => !f.passed)).toBe(true);
  });

  it('FAILS the evaluation finding when assignments exist but no state rows are present', async () => {
    _state.routes = [
      { match: 'policyassignments', rows: [{ id: '/pa', name: 'pa' }] },
      { match: 'policystates', rows: [] },
    ];
    const block = await collectCnaEis(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.cna.eis.policy_assignments_present')!.passed).toBe(true);
    expect(block.findings.find((f) => f.rule === 'azure.cna.eis.policy_evaluations_running')!.passed).toBe(false);
  });

  it('reports total + non-compliant counts in observations', async () => {
    _state.routes = [
      { match: 'policyassignments', rows: [{ id: '/pa' }] },
      { match: 'policystates', rows: [
        { subscriptionId: 'sub-1', total: 100, nonCompliant: 12 },
        { subscriptionId: 'sub-2', total: 50, nonCompliant: 3 },
      ] },
    ];
    const block = await collectCnaEis(ctx(['sub-1', 'sub-2']));
    const f = block.findings.find((x) => x.rule === 'azure.cna.eis.policy_evaluations_running')!;
    expect((f.current_state.observations as any).total).toBe(150);
    expect((f.current_state.observations as any).non_compliant).toBe(15);
  });
});

// =====================================================================
// KSI-CNA-IBP
// =====================================================================
describe('collectCnaIbp (KSI-CNA-IBP Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES MCSB finding when an MCSB assignment exists (case-insensitive match)', async () => {
    _state.routes = [
      // First query (MCSB-id filter) returns the matching assignment.
      { match: MCSB_ROUTE_KEY, rows: [{ id: '/pa/1', subscriptionId: 'sub-1', name: 'mcsb-assignment', displayName: 'MCSB', scope: '/managementGroups/root' }] },
      // Second query (no id filter) — return empty so we isolate this test to MCSB only.
      { match: 'policyassignments', rows: [] },
    ];
    const block = await collectCnaIbp(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.cna.ibp.mcsb_assigned')!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-CNA-IBP');
  });

  it('FAILS MCSB finding when no MCSB assignment exists', async () => {
    _state.routes = [
      { match: MCSB_ROUTE_KEY, rows: [] },
      { match: 'policyassignments', rows: [] },
    ];
    const block = await collectCnaIbp(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.cna.ibp.mcsb_assigned')!.passed).toBe(false);
  });

  it('PASSES regulatory-initiative finding via displayName-pattern match (FedRAMP)', async () => {
    _state.routes = [
      { match: MCSB_ROUTE_KEY, rows: [] },
      { match: 'policyassignments', rows: [
        { id: '/pa', subscriptionId: 'sub-1', name: 'fedramp-mod', dn: 'FedRAMP Moderate', defId: '/sets/some' },
      ] },
    ];
    const block = await collectCnaIbp(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.cna.ibp.regulatory_initiative_assigned')!.passed).toBe(true);
  });

  it('PASSES regulatory-initiative finding via defId-pattern match (NIST 800-53)', async () => {
    _state.routes = [
      { match: MCSB_ROUTE_KEY, rows: [] },
      { match: 'policyassignments', rows: [
        { id: '/pa', subscriptionId: 'sub-1', name: 'nist-mod', dn: 'Compliance baseline', defId: '/providers/Microsoft.Authorization/policySetDefinitions/NIST-SP-800-53-Rev5' },
      ] },
    ];
    const block = await collectCnaIbp(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.cna.ibp.regulatory_initiative_assigned')!.passed).toBe(true);
  });

  it('FAILS regulatory-initiative finding when no FedRAMP / NIST pattern is matched', async () => {
    _state.routes = [
      { match: MCSB_ROUTE_KEY, rows: [] },
      { match: 'policyassignments', rows: [
        { id: '/pa', subscriptionId: 'sub-1', name: 'random', dn: 'Custom unrelated policy', defId: '/providers/Microsoft.Authorization/policySetDefinitions/Other' },
      ] },
    ];
    const block = await collectCnaIbp(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.cna.ibp.regulatory_initiative_assigned')!.passed).toBe(false);
  });
});

// =====================================================================
// KSI-CNA-DFP
// =====================================================================
describe('collectCnaDfp (KSI-CNA-DFP Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES when at least one custom RBAC role definition exists', async () => {
    _state.routes = [{ match: 'roledefinitions', rows: [
      { id: '/rd/1', name: 'custom-1', roleName: 'Workload Reader', subscriptionId: 'sub-1' },
    ] }];
    const block = await collectCnaDfp(ctx());
    expect(block.findings[0]!.passed).toBe(true);
    expect((block.findings[0]!.current_state.observations as any).sample).toContain('Workload Reader');
    assertSchemaValid(block, 'KSI-CNA-DFP');
  });

  it('FAILS when no custom role definitions exist', async () => {
    _state.routes = [{ match: 'roledefinitions', rows: [] }];
    const block = await collectCnaDfp(ctx());
    expect(block.findings[0]!.passed).toBe(false);
  });
});

// =====================================================================
// KSI-SVC-ACM — Automating Configuration Management
// =====================================================================
const nowIso = () => new Date().toISOString();
const staleIso = () => new Date(Date.now() - 200 * 86400_000).toISOString();

describe('collectSvcAcm (KSI-SVC-ACM Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES both findings when recent deployments exist AND compliance ratio >= 80%', async () => {
    _state.routes = [
      { match: 'microsoft.resources/deployments', rows: [
        { id: '/dep/1', name: 'recent', subscriptionId: 'sub-1', ts: nowIso(), state: 'Succeeded' },
      ] },
      { match: 'policystates', rows: [
        { subscriptionId: 'sub-1', compliant: 90, non_compliant: 10, total: 100 },
      ] },
    ];
    const block = await collectSvcAcm(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.svc.acm.deployment_history_present')!.passed).toBe(true);
    expect(block.findings.find((f) => f.rule === 'azure.svc.acm.policy_compliance_acceptable')!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-SVC-ACM');
  });

  it('FAILS the deployment-history finding when only stale (>90d) deployments exist', async () => {
    _state.routes = [
      { match: 'microsoft.resources/deployments', rows: [
        { id: '/dep/old', subscriptionId: 'sub-1', ts: staleIso(), state: 'Succeeded' },
      ] },
      { match: 'policystates', rows: [
        { subscriptionId: 'sub-1', compliant: 90, non_compliant: 10, total: 100 },
      ] },
    ];
    const block = await collectSvcAcm(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.svc.acm.deployment_history_present')!.passed).toBe(false);
  });

  it('FAILS the compliance finding when ratio < 80%', async () => {
    _state.routes = [
      { match: 'microsoft.resources/deployments', rows: [{ id: '/dep', subscriptionId: 'sub-1', ts: nowIso() }] },
      { match: 'policystates', rows: [
        { subscriptionId: 'sub-1', compliant: 30, non_compliant: 70, total: 100 },
      ] },
    ];
    const block = await collectSvcAcm(ctx());
    const f = block.findings.find((x) => x.rule === 'azure.svc.acm.policy_compliance_acceptable')!;
    expect(f.passed).toBe(false);
    expect((f.current_state.observations as any).ratio).toBeCloseTo(0.3, 5);
  });

  it('PASSES the compliance finding vacuously when no policy-state rows exist (CNA-EIS would already flag this)', async () => {
    _state.routes = [
      { match: 'microsoft.resources/deployments', rows: [{ id: '/dep', subscriptionId: 'sub-1', ts: nowIso() }] },
      { match: 'policystates', rows: [] },
    ];
    const block = await collectSvcAcm(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.svc.acm.policy_compliance_acceptable')!.passed).toBe(true);
  });

  it('exposes Terraform-Cloud alternative satisfier at KSI level', async () => {
    _state.routes = [
      { match: 'microsoft.resources/deployments', rows: [] },
      { match: 'policystates', rows: [] },
    ];
    const block = await collectSvcAcm(ctx());
    const alt = block.ksi_level_alternatives?.[0];
    expect(alt?.via).toContain('Terraform Cloud');
    expect(alt?.detected).toBe(false);
  });

  it('SUMS compliance numerators across multiple subscriptions', async () => {
    _state.routes = [
      { match: 'microsoft.resources/deployments', rows: [{ id: '/dep', subscriptionId: 'sub-1', ts: nowIso() }] },
      { match: 'policystates', rows: [
        { subscriptionId: 'sub-1', compliant: 40, non_compliant: 10, total: 50 },
        { subscriptionId: 'sub-2', compliant: 80, non_compliant: 20, total: 100 },
      ] },
    ];
    const block = await collectSvcAcm(ctx(['sub-1', 'sub-2']));
    const obs = block.findings.find((f) => f.rule === 'azure.svc.acm.policy_compliance_acceptable')!.current_state.observations as any;
    expect(obs.compliant).toBe(120);
    expect(obs.non_compliant).toBe(30);
    expect(obs.total).toBe(150);
    expect(obs.ratio).toBeCloseTo(120 / 150, 5);
  });
});

// =====================================================================
// KSI-SVC-EIS — Evaluating and Improving Security (HYBRID)
// =====================================================================
describe('collectSvcEis (KSI-SVC-EIS Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES both findings when secure-score is present and ratio >= 50%', async () => {
    _state.routes = [{ match: 'microsoft.security/securescores', rows: [
      { id: '/score/sub-1', name: 'score', subscriptionId: 'sub-1', current: 70, maxv: 100, weight: 1 },
    ] }];
    const block = await collectSvcEis(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.svc.eis.defender_secure_score_present')!.passed).toBe(true);
    expect(block.findings.find((f) => f.rule === 'azure.svc.eis.defender_secure_score_acceptable')!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-SVC-EIS');
  });

  it('FAILS the presence finding when no secure-score rows exist', async () => {
    _state.routes = [{ match: 'microsoft.security/securescores', rows: [] }];
    const block = await collectSvcEis(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.svc.eis.defender_secure_score_present')!.passed).toBe(false);
    // Vacuously OK when there's no signal — presence finding does the talking.
    expect(block.findings.find((f) => f.rule === 'azure.svc.eis.defender_secure_score_acceptable')!.passed).toBe(true);
  });

  it('FAILS the acceptable finding when ratio < 50%', async () => {
    _state.routes = [{ match: 'microsoft.security/securescores', rows: [
      { id: '/score/sub-1', subscriptionId: 'sub-1', current: 30, maxv: 100, weight: 1 },
    ] }];
    const block = await collectSvcEis(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.svc.eis.defender_secure_score_acceptable')!.passed).toBe(false);
  });

  it('AGGREGATES secure-score across subscriptions', async () => {
    _state.routes = [{ match: 'microsoft.security/securescores', rows: [
      { id: '/s/1', subscriptionId: 'sub-1', current: 40, maxv: 100, weight: 1 },
      { id: '/s/2', subscriptionId: 'sub-2', current: 80, maxv: 100, weight: 1 },
    ] }];
    const block = await collectSvcEis(ctx(['sub-1', 'sub-2']));
    const obs = block.findings.find((f) => f.rule === 'azure.svc.eis.defender_secure_score_acceptable')!.current_state.observations as any;
    expect(obs.aggregate_current).toBe(120);
    expect(obs.aggregate_max).toBe(200);
    expect(obs.ratio).toBeCloseTo(0.6, 5);
    // 60% > 50% threshold → passes.
    expect(block.findings.find((f) => f.rule === 'azure.svc.eis.defender_secure_score_acceptable')!.passed).toBe(true);
  });

  it('exposes 3rd-party CSPM alternative satisfier at KSI level (detected=false)', async () => {
    _state.routes = [{ match: 'microsoft.security/securescores', rows: [] }];
    const block = await collectSvcEis(ctx());
    expect(block.ksi_level_alternatives?.[0]?.via).toContain('CSPM');
    expect(block.ksi_level_alternatives?.[0]?.detected).toBe(false);
  });
});
