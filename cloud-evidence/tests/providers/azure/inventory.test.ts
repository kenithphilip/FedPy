/**
 * Tests for providers/azure/inventory.ts → collectPiyGiv.
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

import { collectPiyGiv } from '../../../providers/azure/inventory.ts';

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

describe('collectPiyGiv (KSI-PIY-GIV Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES when Resource Graph returns a non-zero inventory across multiple types', async () => {
    _state.routes = [{ match: 'summarize count', rows: [
      { type: 'microsoft.compute/virtualmachines', count: 42 },
      { type: 'microsoft.storage/storageaccounts', count: 18 },
      { type: 'microsoft.keyvault/vaults', count: 5 },
    ] }];
    const block = await collectPiyGiv(ctx());
    expect(block.findings[0]!.passed).toBe(true);
    const obs = block.findings[0]!.current_state.observations as any;
    expect(obs.total_resources).toBe(65);
    expect(obs.distinct_types).toBe(3);
    assertSchemaValid(block, 'KSI-PIY-GIV');
  });

  it('FAILS when Resource Graph returns zero rows (likely missing Reader or empty sub)', async () => {
    _state.routes = [{ match: 'summarize count', rows: [] }];
    const block = await collectPiyGiv(ctx());
    expect(block.findings[0]!.passed).toBe(false);
  });

  it('aggregates total across many type rows and exposes the top 20 in observations', async () => {
    const rows = Array.from({ length: 30 }).map((_, i) => ({ type: `t-${i}`, count: i + 1 }));
    _state.routes = [{ match: 'summarize count', rows }];
    const block = await collectPiyGiv(ctx(['sub-1', 'sub-2']));
    const obs = block.findings[0]!.current_state.observations as any;
    // 1 + 2 + ... + 30 = 465
    expect(obs.total_resources).toBe(465);
    expect(obs.distinct_types).toBe(30);
    expect(obs.top_types).toHaveLength(20);
    expect(obs.subscriptions).toBe(2);
  });

  it('emits a warning when no subscriptions are configured', async () => {
    const block = await collectPiyGiv({ azure: { tenant_id: 't', subscription_ids: [] } });
    expect(block.findings[0]!.passed).toBe(false);
    expect((block.warnings ?? []).some((w) => w.includes('No subscriptions configured'))).toBe(true);
  });
});
