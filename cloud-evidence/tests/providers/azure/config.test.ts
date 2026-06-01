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

import { collectCnaEis, collectCnaIbp } from '../../../providers/azure/config.ts';

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
