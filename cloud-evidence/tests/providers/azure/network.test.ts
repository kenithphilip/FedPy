/**
 * Tests for providers/azure/network.ts → collectCnaUln + collectCnaRvp + collectSvcSnt.
 * Same substring-routed Resource Graph mock as the logging tests.
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

import { collectCnaUln, collectCnaRvp, collectSvcSnt } from '../../../providers/azure/network.ts';

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
// KSI-CNA-ULN
// =====================================================================
describe('collectCnaUln (KSI-CNA-ULN Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES when at least one enabled NSG flow log exists', async () => {
    _state.routes = [{ match: 'networkwatchers/flowlogs', rows: [
      { id: '/fl/1', name: 'fl-1', subscriptionId: 'sub-1', enabled: true, targetId: '/nsg', workspaceId: '/ws' },
    ] }];
    const block = await collectCnaUln(ctx());
    expect(block.findings[0]!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-CNA-ULN');
  });

  it('FAILS when flow logs exist but none are enabled', async () => {
    _state.routes = [{ match: 'networkwatchers/flowlogs', rows: [
      { id: '/fl/1', name: 'fl-disabled', enabled: false, workspaceId: '/ws' },
    ] }];
    const block = await collectCnaUln(ctx());
    expect(block.findings[0]!.passed).toBe(false);
  });

  it('FAILS when no flow logs exist at all', async () => {
    _state.routes = [{ match: 'networkwatchers/flowlogs', rows: [] }];
    const block = await collectCnaUln(ctx());
    expect(block.findings[0]!.passed).toBe(false);
  });

  it('reports the "with workspace" sub-count in the observations', async () => {
    _state.routes = [{ match: 'networkwatchers/flowlogs', rows: [
      { id: '/fl/1', enabled: true, workspaceId: '/ws' },
      { id: '/fl/2', enabled: true, workspaceId: '' },
    ] }];
    const block = await collectCnaUln(ctx());
    const f = block.findings[0]!;
    expect((f.current_state.observations as any).with_workspace).toBe(1);
    expect((f.current_state.observations as any).enabled).toBe(2);
  });
});

// =====================================================================
// KSI-CNA-RVP
// =====================================================================
describe('collectCnaRvp (KSI-CNA-RVP Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES via an Application Gateway WAF policy in Enabled state', async () => {
    _state.routes = [
      { match: 'applicationgatewaywebapplicationfirewallpolicies', rows: [
        { id: '/p', name: 'agw-waf', subscriptionId: 'sub-1', policyState: 'Enabled', mode: 'Prevention' },
      ] },
      { match: 'frontdoorwebapplicationfirewallpolicies', rows: [] },
    ];
    const block = await collectCnaRvp(ctx());
    expect(block.findings[0]!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-CNA-RVP');
  });

  it('PASSES via a Front Door WAF policy in Enabled state', async () => {
    _state.routes = [
      { match: 'applicationgatewaywebapplicationfirewallpolicies', rows: [] },
      { match: 'frontdoorwebapplicationfirewallpolicies', rows: [
        { id: '/p', name: 'fd-waf', subscriptionId: 'sub-1', policyState: 'Enabled', mode: 'Prevention' },
      ] },
    ];
    const block = await collectCnaRvp(ctx());
    expect(block.findings[0]!.passed).toBe(true);
  });

  it('FAILS when WAF policies exist but are all Disabled', async () => {
    _state.routes = [
      { match: 'applicationgatewaywebapplicationfirewallpolicies', rows: [
        { id: '/p', name: 'agw-waf', policyState: 'Disabled', mode: 'Detection' },
      ] },
      { match: 'frontdoorwebapplicationfirewallpolicies', rows: [] },
    ];
    const block = await collectCnaRvp(ctx());
    expect(block.findings[0]!.passed).toBe(false);
  });

  it('FAILS when no WAF policies exist anywhere', async () => {
    _state.routes = [
      { match: 'applicationgatewaywebapplicationfirewallpolicies', rows: [] },
      { match: 'frontdoorwebapplicationfirewallpolicies', rows: [] },
    ];
    const block = await collectCnaRvp(ctx());
    expect(block.findings[0]!.passed).toBe(false);
  });
});

// =====================================================================
// KSI-SVC-SNT
// =====================================================================
describe('collectSvcSnt (KSI-SVC-SNT Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES both findings when every AGW listener is HTTPS and every storage account is HTTPS-only', async () => {
    _state.routes = [
      { match: 'microsoft.network/applicationgateways', rows: [
        { subscriptionId: 'sub-1', id: '/agw1', agwName: 'agw1', listenerName: 'L1', protocol: 'Https' },
      ] },
      { match: 'microsoft.storage/storageaccounts', rows: [
        { id: '/sa1', name: 'sa1', subscriptionId: 'sub-1', https: true, tls: 'TLS1_2' },
      ] },
    ];
    const block = await collectSvcSnt(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.svc.snt.appgateway_https_only')!.passed).toBe(true);
    expect(block.findings.find((f) => f.rule === 'azure.svc.snt.storage_https_only')!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-SVC-SNT');
  });

  it('FAILS the AGW finding when any listener uses plaintext Http', async () => {
    _state.routes = [
      { match: 'microsoft.network/applicationgateways', rows: [
        { subscriptionId: 'sub-1', id: '/agw1', agwName: 'agw1', listenerName: 'L-http', protocol: 'Http' },
        { subscriptionId: 'sub-1', id: '/agw1', agwName: 'agw1', listenerName: 'L-https', protocol: 'Https' },
      ] },
      { match: 'microsoft.storage/storageaccounts', rows: [{ id: '/sa', https: true }] },
    ];
    const block = await collectSvcSnt(ctx());
    const f = block.findings.find((x) => x.rule === 'azure.svc.snt.appgateway_https_only')!;
    expect(f.passed).toBe(false);
    expect(f.gap?.affected_resources[0]?.identifier).toContain('L-http');
  });

  it('FAILS the storage finding when supportsHttpsTrafficOnly is false on any account', async () => {
    _state.routes = [
      { match: 'microsoft.network/applicationgateways', rows: [] },
      { match: 'microsoft.storage/storageaccounts', rows: [
        { id: '/sa-bad', name: 'sa-bad', https: false, tls: 'TLS1_0' },
        { id: '/sa-good', name: 'sa-good', https: true, tls: 'TLS1_2' },
      ] },
    ];
    const block = await collectSvcSnt(ctx());
    const f = block.findings.find((x) => x.rule === 'azure.svc.snt.storage_https_only')!;
    expect(f.passed).toBe(false);
    expect(f.gap?.affected_resources[0]?.identifier).toBe('/sa-bad');
  });

  it('PASSES the storage finding vacuously when no storage accounts exist', async () => {
    _state.routes = [
      { match: 'microsoft.network/applicationgateways', rows: [] },
      { match: 'microsoft.storage/storageaccounts', rows: [] },
    ];
    const block = await collectSvcSnt(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.svc.snt.storage_https_only')!.passed).toBe(true);
    expect(block.findings.find((f) => f.rule === 'azure.svc.snt.appgateway_https_only')!.passed).toBe(true);
  });
});
