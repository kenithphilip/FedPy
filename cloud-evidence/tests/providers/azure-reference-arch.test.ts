/**
 * Tests for providers/azure/reference-arch.ts (AZ-CHK).
 *
 * Mocks core/auth/azure.ts so no real Azure SDK is loaded and no network is hit.
 * The Resource Graph stub routes each KQL query to a canned response by
 * substring match (keyed on a unique fragment per check) so the assertions
 * don't depend on the order in which the module fires the queries.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { validateEvidenceFile } from '../../core/schema.ts';

// Per-query routing: keyed by a substring that appears in the KQL for one check.
const _state = vi.hoisted(() => ({
  routes: [] as Array<{ match: string; rows: any[] }>,
  /** Captured query strings for debugging / negative assertions. */
  queries: [] as string[],
}));

vi.mock('../../core/auth/azure.ts', () => ({
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

import { collectAzureReferenceArch } from '../../providers/azure/reference-arch.ts';

const CTX = { runId: '00000000-0000-0000-0000-000000000000', frmrVersion: 'test' };

function passingRoutes(): typeof _state.routes {
  return [
    // 1) Defender: at least one Standard plan per subscription
    { match: 'securityresources', rows: [{ subscriptionId: 'sub-1', standardPlans: 5, totalPlans: 6 }] },
    // 2) FedRAMP policy assignment
    { match: 'policyresources', rows: [{ subscriptionId: 'sub-1', name: 'fedramp-mod', displayName: 'FedRAMP Moderate', policyDefinitionId: '/providers/Microsoft.Authorization/policySetDefinitions/FedRAMP-Moderate' }] },
    // 3) Storage no-public-blob
    { match: 'allowBlobPublicAccess', rows: [{ subscriptionId: 'sub-1', name: 'sa1', id: '/sub-1/sa1', pb: false }] },
    // 4) Storage HTTPS + TLS
    { match: 'supportsHttpsTrafficOnly', rows: [{ subscriptionId: 'sub-1', name: 'sa1', id: '/sub-1/sa1', https: true, tls: 'TLS1_2' }] },
    // 5) Storage public-network-access
    { match: 'publicNetworkAccess', rows: [{ subscriptionId: 'sub-1', name: 'sa1', id: '/sub-1/sa1', pna: 'Disabled', defAct: 'Deny' }] },
    // 7a) CMEK Key Vault keys (queried before storage CMK in module — narrower match first)
    { match: 'microsoft.keyvault/vaults/keys', rows: [{ subscriptionId: 'sub-1', count_: 3 }] },
    // 6) Key Vault hardening
    { match: 'microsoft.keyvault/vaults', rows: [{ subscriptionId: 'sub-1', name: 'kv1', id: '/sub-1/kv1', sd: true, pp: true, rbac: true }] },
    // 7b) CMK-bound storage accounts
    { match: 'Microsoft.Keyvault', rows: [{ subscriptionId: 'sub-1', count_: 2 }] },
    // 8) Disk encryption
    { match: 'microsoft.compute/disks', rows: [{ subscriptionId: 'sub-1', name: 'd1', id: '/sub-1/d1', encType: 'EncryptionAtRestWithCustomerKey' }] },
    // 9) NSG open admin
    { match: 'networksecuritygroups', rows: [] },
    // 10) Public IPs attached to NICs
    { match: 'publicipaddresses', rows: [] },
    // 11) Workspace retention
    { match: 'operationalinsights/workspaces', rows: [{ subscriptionId: 'sub-1', name: 'ws1', id: '/sub-1/ws1', retention: 90 }] },
  ];
}

function assertSchemaValid(ev: any): void {
  const r = validateEvidenceFile(JSON.parse(JSON.stringify(ev)));
  if (!r.valid) throw new Error(`schema invalid: ${(r.errors[0] as any)?.instancePath} ${(r.errors[0] as any)?.message}`);
}

describe('collectAzureReferenceArch (AUDIT-REFARCH-AZURE)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('passes every check in a fully-hardened environment', async () => {
    _state.routes = passingRoutes();
    const ev = await collectAzureReferenceArch(['sub-1'], CTX);

    expect(ev.ksi_id).toBe('AUDIT-REFARCH-AZURE');
    expect(ev.scope).toBe('CLOUD');
    expect(ev.providers[0]?.provider).toBe('azure');
    expect(ev.providers[0]?.account_id).toBe('sub-1');

    const byRule = Object.fromEntries(ev.providers[0]!.findings.map((f) => [f.rule, f.passed]));
    expect(byRule['azure.defender.enabled']).toBe(true);
    expect(byRule['azure.policy.fedramp_initiative']).toBe(true);
    expect(byRule['azure.storage.no_public_blob']).toBe(true);
    expect(byRule['azure.storage.https_only']).toBe(true);
    expect(byRule['azure.storage.network_restricted']).toBe(true);
    expect(byRule['azure.keyvault.soft_delete_purge_rbac']).toBe(true);
    expect(byRule['azure.cmek.in_use']).toBe(true);
    expect(byRule['azure.compute.disk_encryption']).toBe(true);
    expect(byRule['azure.network.no_open_admin_ports']).toBe(true);
    expect(byRule['azure.network.no_vm_public_ip']).toBe(true);
    expect(byRule['azure.logging.workspace_retention']).toBe(true);
    expect(ev.rollup.failing_findings).toBe(0);
    assertSchemaValid(ev);
  });

  it('fails-open (no throw, schema valid) on an empty Resource Graph', async () => {
    _state.routes = [];   // every query returns empty
    const ev = await collectAzureReferenceArch(['sub-1'], CTX);
    expect(ev.ksi_id).toBe('AUDIT-REFARCH-AZURE');
    expect(ev.providers[0]!.findings.length).toBe(11);

    // Defender / Policy / CMEK / Workspace fail on empty; storage / disk / NSG / public-IP /
    // Key Vault checks pass because their universes are empty (vacuously safe).
    const byRule = Object.fromEntries(ev.providers[0]!.findings.map((f) => [f.rule, f.passed]));
    expect(byRule['azure.defender.enabled']).toBe(false);
    expect(byRule['azure.policy.fedramp_initiative']).toBe(false);
    expect(byRule['azure.cmek.in_use']).toBe(false);
    expect(byRule['azure.logging.workspace_retention']).toBe(false);
    assertSchemaValid(ev);
  });

  it('flags storage accounts with allowBlobPublicAccess = true', async () => {
    _state.routes = [
      ...passingRoutes().filter((r) => r.match !== 'allowBlobPublicAccess'),
      { match: 'allowBlobPublicAccess', rows: [
        { subscriptionId: 'sub-1', name: 'sa-bad', id: '/sub-1/sa-bad', pb: true },
        { subscriptionId: 'sub-1', name: 'sa-good', id: '/sub-1/sa-good', pb: false },
      ] },
    ];
    const ev = await collectAzureReferenceArch(['sub-1'], CTX);
    const f = ev.providers[0]!.findings.find((x) => x.rule === 'azure.storage.no_public_blob')!;
    expect(f.passed).toBe(false);
    expect(f.gap?.affected_resources.some((r) => r.identifier === '/sub-1/sa-bad')).toBe(true);
    expect(f.gap?.affected_resources.some((r) => r.identifier === '/sub-1/sa-good')).toBe(false);
    assertSchemaValid(ev);
  });

  it('flags NSG rules allowing SSH/RDP from the Internet', async () => {
    _state.routes = [
      ...passingRoutes().filter((r) => r.match !== 'networksecuritygroups'),
      { match: 'networksecuritygroups', rows: [
        { subscriptionId: 'sub-1', nsg: 'nsg-1', id: '/sub-1/nsg-1', ruleName: 'allow-ssh-any', srcPrefix: '*', dstPort: '22' },
      ] },
    ];
    const ev = await collectAzureReferenceArch(['sub-1'], CTX);
    const f = ev.providers[0]!.findings.find((x) => x.rule === 'azure.network.no_open_admin_ports')!;
    expect(f.passed).toBe(false);
    expect(f.gap?.affected_resources[0]?.identifier).toContain('allow-ssh-any');
    assertSchemaValid(ev);
  });

  it('warns (not fails) when no subscriptions are configured', async () => {
    const ev = await collectAzureReferenceArch([], CTX);
    expect(ev.providers[0]!.warnings!.length).toBeGreaterThan(0);
    expect(ev.providers[0]!.warnings![0]).toMatch(/no subscriptions/i);
    assertSchemaValid(ev);
  });
});
