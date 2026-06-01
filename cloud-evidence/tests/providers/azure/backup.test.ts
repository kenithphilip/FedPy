/**
 * Tests for providers/azure/backup.ts → collectCnaOfa + collectRplAbo + collectRplTrc.
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

import { collectCnaOfa, collectRplAbo, collectRplTrc } from '../../../providers/azure/backup.ts';

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

// =====================================================================
// KSI-RPL-ABO
// =====================================================================
const nowIso = () => new Date().toISOString();

describe('collectRplAbo (KSI-RPL-ABO Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES all three findings when vaults, protected items, and clean recent jobs are present', async () => {
    _state.routes = [
      { match: 'microsoft.recoveryservices/vaults"', rows: [
        { id: '/rsv/1', name: 'rsv-1', type: 'microsoft.recoveryservices/vaults', subscriptionId: 'sub-1', location: 'eastus' },
      ] },
      { match: 'backupprotecteditems', rows: [
        { id: '/rsv/1/items/vm-1', name: 'vm-1', subscriptionId: 'sub-1' },
        { id: '/rsv/1/items/vm-2', name: 'vm-2', subscriptionId: 'sub-1' },
      ] },
      { match: 'backupjobs', rows: [
        { id: '/job/1', name: 'job-1', op: 'Backup', status: 'Completed', startTime: nowIso() },
        { id: '/job/2', name: 'job-2', op: 'Backup', status: 'Completed', startTime: nowIso() },
      ] },
    ];
    const block = await collectRplAbo(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.rpl.abo.recovery_vault_present')!.passed).toBe(true);
    expect(block.findings.find((f) => f.rule === 'azure.rpl.abo.protected_items_present')!.passed).toBe(true);
    expect(block.findings.find((f) => f.rule === 'azure.rpl.abo.recent_backup_jobs_clean')!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-RPL-ABO');
  });

  it('FAILS the vault finding (and downstream items finding is vacuously OK) when no vault exists', async () => {
    _state.routes = [
      { match: 'microsoft.recoveryservices/vaults"', rows: [] },
      { match: 'backupprotecteditems', rows: [] },
      { match: 'backupjobs', rows: [] },
    ];
    const block = await collectRplAbo(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.rpl.abo.recovery_vault_present')!.passed).toBe(false);
    // Items + jobs are vacuously passing when there is nothing to back up.
    expect(block.findings.find((f) => f.rule === 'azure.rpl.abo.protected_items_present')!.passed).toBe(true);
    expect(block.findings.find((f) => f.rule === 'azure.rpl.abo.recent_backup_jobs_clean')!.passed).toBe(true);
  });

  it('FAILS the protected-items finding when vault exists but nothing is protected', async () => {
    _state.routes = [
      { match: 'microsoft.recoveryservices/vaults"', rows: [{ id: '/rsv/empty', name: 'empty', type: 'microsoft.recoveryservices/vaults' }] },
      { match: 'backupprotecteditems', rows: [] },
      { match: 'backupjobs', rows: [] },
    ];
    const block = await collectRplAbo(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.rpl.abo.recovery_vault_present')!.passed).toBe(true);
    expect(block.findings.find((f) => f.rule === 'azure.rpl.abo.protected_items_present')!.passed).toBe(false);
  });

  it('FAILS the recent-jobs finding when a Failed job sits inside the 30-day window', async () => {
    _state.routes = [
      { match: 'microsoft.recoveryservices/vaults"', rows: [{ id: '/rsv/1', name: 'rsv-1', type: 'microsoft.recoveryservices/vaults' }] },
      { match: 'backupprotecteditems', rows: [{ id: '/item/1', name: 'vm-1' }] },
      { match: 'backupjobs', rows: [
        { id: '/job/1', name: 'job-1', op: 'Backup', status: 'Completed', startTime: nowIso() },
        { id: '/job/2', name: 'job-2', op: 'Backup', status: 'Failed', startTime: nowIso() },
      ] },
    ];
    const block = await collectRplAbo(ctx());
    const jobsFinding = block.findings.find((f) => f.rule === 'azure.rpl.abo.recent_backup_jobs_clean')!;
    expect(jobsFinding.passed).toBe(false);
    expect((jobsFinding.current_state.observations as any).failed).toBe(1);
  });

  it('FAILS the recent-jobs finding when no jobs ran in the 30-day window (zero successes)', async () => {
    _state.routes = [
      { match: 'microsoft.recoveryservices/vaults"', rows: [{ id: '/rsv/1', name: 'rsv-1', type: 'microsoft.recoveryservices/vaults' }] },
      { match: 'backupprotecteditems', rows: [{ id: '/item/1', name: 'vm-1' }] },
      { match: 'backupjobs', rows: [] },
    ];
    const block = await collectRplAbo(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.rpl.abo.recent_backup_jobs_clean')!.passed).toBe(false);
  });

  it('recognises the newer microsoft.dataprotection/backupvaults type as a vault too', async () => {
    _state.routes = [
      { match: 'microsoft.dataprotection/backupvaults', rows: [
        { id: '/bv/1', name: 'bv-1', type: 'microsoft.dataprotection/backupvaults', subscriptionId: 'sub-1' },
      ] },
      { match: 'backupprotecteditems', rows: [{ id: '/item/1', name: 'vm-1' }] },
      { match: 'backupjobs', rows: [{ id: '/job/1', op: 'Backup', status: 'Completed', startTime: nowIso() }] },
    ];
    const block = await collectRplAbo(ctx());
    expect(block.findings.find((f) => f.rule === 'azure.rpl.abo.recovery_vault_present')!.passed).toBe(true);
  });
});

// =====================================================================
// KSI-RPL-TRC
// =====================================================================
describe('collectRplTrc (KSI-RPL-TRC Azure)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('PASSES when at least one Completed Restore job exists in the last 90 days', async () => {
    _state.routes = [{ match: 'backupjobs', rows: [
      { id: '/job/r1', name: 'restore-1', op: 'Restore', status: 'Completed', startTime: nowIso() },
    ] }];
    const block = await collectRplTrc(ctx());
    expect(block.findings[0]!.passed).toBe(true);
    expect((block.findings[0]!.current_state.observations as any).successful).toBe(1);
    assertSchemaValid(block, 'KSI-RPL-TRC');
  });

  it('FAILS when no Restore jobs exist in the last 90 days', async () => {
    _state.routes = [{ match: 'backupjobs', rows: [] }];
    const block = await collectRplTrc(ctx());
    expect(block.findings[0]!.passed).toBe(false);
  });

  it('FAILS when Restore jobs exist but none completed successfully', async () => {
    _state.routes = [{ match: 'backupjobs', rows: [
      { id: '/job/r1', op: 'Restore', status: 'Failed', startTime: nowIso() },
      { id: '/job/r2', op: 'Restore', status: 'InProgress', startTime: nowIso() },
    ] }];
    const block = await collectRplTrc(ctx());
    expect(block.findings[0]!.passed).toBe(false);
  });

  it('exposes the gameday/AAR alternative satisfier at KSI level (detected=false)', async () => {
    _state.routes = [{ match: 'backupjobs', rows: [] }];
    const block = await collectRplTrc(ctx());
    expect(block.ksi_level_alternatives?.length ?? 0).toBeGreaterThan(0);
    expect(block.ksi_level_alternatives?.[0]?.detected).toBe(false);
  });

  it('ignores stale (>90d) Restore jobs even if Completed', async () => {
    const stale = new Date(Date.now() - 120 * 86400_000).toISOString();
    _state.routes = [{ match: 'backupjobs', rows: [
      { id: '/job/old', op: 'Restore', status: 'Completed', startTime: stale },
    ] }];
    const block = await collectRplTrc(ctx());
    expect(block.findings[0]!.passed).toBe(false);
  });
});
