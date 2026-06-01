/**
 * Tests for providers/azure/backup.ts → collectCnaOfa.
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

import { collectCnaOfa } from '../../../providers/azure/backup.ts';

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

describe('collectCnaOfa (KSI-CNA-OFA Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES both findings when VMs span 2+ zones and storage uses ZRS/GRS', async () => {
    _state.routes = [
      { match: 'microsoft.compute/virtualmachines', rows: [
        { id: '/vm/1', name: 'vm-1', subscriptionId: 'sub-1', zone: '1' },
        { id: '/vm/2', name: 'vm-2', subscriptionId: 'sub-1', zone: '2' },
      ] },
      { match: 'microsoft.storage/storageaccounts', rows: [
        { id: '/sa/1', name: 'sa-1', subscriptionId: 'sub-1', sku: 'Standard_ZRS' },
      ] },
    ];
    const block = await collectCnaOfa(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.cna.ofa.vms_use_availability_zones')!.passed).toBe(true);
    expect(block.findings.find((f) => f.rule === 'azure.cna.ofa.storage_redundant_replication')!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-CNA-OFA');
  });

  it('FAILS the VM-zone finding when VMs are not zone-pinned', async () => {
    _state.routes = [
      { match: 'microsoft.compute/virtualmachines', rows: [
        { id: '/vm/1', name: 'no-zone', subscriptionId: 'sub-1', zone: '' },
      ] },
      { match: 'microsoft.storage/storageaccounts', rows: [] },
    ];
    const block = await collectCnaOfa(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.cna.ofa.vms_use_availability_zones')!.passed).toBe(false);
  });

  it('FAILS the VM-zone finding when every VM is in the same single zone', async () => {
    _state.routes = [
      { match: 'microsoft.compute/virtualmachines', rows: [
        { id: '/vm/1', zone: '1' },
        { id: '/vm/2', zone: '1' },
      ] },
      { match: 'microsoft.storage/storageaccounts', rows: [] },
    ];
    const block = await collectCnaOfa(ctx());
    // Single-zone is better than no-zone but still fails the "≥ 2 zones" requirement.
    expect(block.findings.find((f) => f.rule === 'azure.cna.ofa.vms_use_availability_zones')!.passed).toBe(false);
  });

  it('FAILS the storage finding when at least one account uses Standard_LRS', async () => {
    _state.routes = [
      { match: 'microsoft.compute/virtualmachines', rows: [] },
      { match: 'microsoft.storage/storageaccounts', rows: [
        { id: '/sa-lrs', name: 'sa-lrs', sku: 'Standard_LRS' },
        { id: '/sa-zrs', name: 'sa-zrs', sku: 'Standard_ZRS' },
      ] },
    ];
    const block = await collectCnaOfa(ctx());
    const f = block.findings.find((x) => x.rule === 'azure.cna.ofa.storage_redundant_replication')!;
    expect(f.passed).toBe(false);
    expect(f.gap?.affected_resources[0]?.identifier).toBe('/sa-lrs');
  });

  it('FAILS the storage finding for Premium_LRS too', async () => {
    _state.routes = [
      { match: 'microsoft.compute/virtualmachines', rows: [] },
      { match: 'microsoft.storage/storageaccounts', rows: [
        { id: '/sa-plrs', name: 'sa-plrs', sku: 'Premium_LRS' },
      ] },
    ];
    const block = await collectCnaOfa(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.cna.ofa.storage_redundant_replication')!.passed).toBe(false);
  });

  it('PASSES vacuously when no VMs and no storage accounts exist', async () => {
    _state.routes = [
      { match: 'microsoft.compute/virtualmachines', rows: [] },
      { match: 'microsoft.storage/storageaccounts', rows: [] },
    ];
    const block = await collectCnaOfa(ctx());
    expect(block.findings.every((f) => f.passed)).toBe(true);
    assertSchemaValid(block, 'KSI-CNA-OFA');
  });
});
