/**
 * Tests for providers/azure/discover.ts + providers/azure/inventory-assets.ts.
 *
 * Mocks core/auth/azure.ts so no real Azure SDK is loaded and no network is hit.
 * The discover module is driven by a stub ResourceGraphClient whose `resources()`
 * returns canned rows; we assert pagination + row → CloudAsset mapping shape.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

// Stub the @azure/identity / arm-resources / arm-resourcegraph deps via the auth module mock.
// The mock provides a configurable ResourceGraphClient whose `resources(query)`
// returns whatever we pre-load into `_routes`.
const _state = vi.hoisted(() => ({
  /** Array of pages to return in order from `resources()` calls. */
  pages: [] as Array<{ data: any[]; skipToken?: string; '$skipToken'?: string }>,
  /** Captured request payloads for assertion. */
  calls: [] as Array<{ subscriptions: string[]; query: string; options?: any }>,
}));

vi.mock('../../core/auth/azure.ts', () => ({
  whoAmIAzure: async () => ({ principal: 'test@example.com', tenantId: 't', appId: null }),
  guardAzure: <T extends object>(c: T) => c,
  resourceGraph: () => ({
    async resources(req: any) {
      _state.calls.push(req);
      return _state.pages.shift() ?? { data: [] };
    },
  }),
  resources: (_id: string) => ({}),
}));

import { discoverAzureAssets, rowToAsset } from '../../providers/azure/discover.ts';

describe('rowToAsset', () => {
  it('maps a Resource Graph row to a CloudAsset with the right provider + projection', () => {
    const a = rowToAsset({
      id: '/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/sa1',
      name: 'sa1', type: 'microsoft.storage/storageaccounts', kind: 'StorageV2',
      location: 'eastus', resourceGroup: 'rg-1', subscriptionId: 'sub-1',
      tags: { env: 'prod', owner: 'sec' },
      properties: { publicNetworkAccess: 'Disabled', encryption: { keyVaultProperties: { keyIdentifier: 'https://kv1.vault.azure.net/keys/k/v' } } },
    });
    expect(a.provider).toBe('azure');
    expect(a.uniqueId).toContain('storageAccounts/sa1');
    expect(a.resourceType).toBe('microsoft.storage/storageaccounts');
    expect(a.assetType).toBe('storageaccounts');
    expect(a.accountId).toBe('sub-1');
    expect(a.location).toBe('eastus');
    expect(a.publicFacing).toBe(false);
    expect(a.encryptionAtRest).toBe(true);
    expect(a.kmsKeyId).toMatch(/keys\/k\/v$/);
    expect(a.tags).toEqual({ env: 'prod', owner: 'sec' });
  });

  it('returns publicFacing=undefined when publicNetworkAccess is not in properties', () => {
    const a = rowToAsset({ id: 'x', name: 'x', type: 'microsoft.compute/virtualmachines', subscriptionId: 's', properties: {} });
    expect(a.publicFacing).toBeUndefined();
  });
});

describe('discoverAzureAssets', () => {
  beforeEach(() => { _state.pages = []; _state.calls = []; });

  it('returns a no-op + warning when no subscriptions are configured', async () => {
    const r = await discoverAzureAssets([]);
    expect(r.assets).toEqual([]);
    expect(r.warnings.length).toBeGreaterThan(0);
    expect(_state.calls.length).toBe(0);
  });

  it('paginates via $skipToken and aggregates rows across pages', async () => {
    _state.pages = [
      { data: [{ id: '/r/1', name: 'r1', type: 'microsoft.compute/virtualmachines', subscriptionId: 'sub-1' }], $skipToken: 'PAGE2' },
      { data: [{ id: '/r/2', name: 'r2', type: 'microsoft.storage/storageaccounts', subscriptionId: 'sub-1' }] },
    ];
    const r = await discoverAzureAssets(['sub-1']);
    expect(r.warnings).toEqual([]);
    expect(r.assets.map((a) => a.uniqueId)).toEqual(['/r/1', '/r/2']);
    expect(_state.calls.length).toBe(2);
    expect(_state.calls[0]!.subscriptions).toEqual(['sub-1']);
    expect(_state.calls[1]!.options.$skipToken).toBe('PAGE2');
  });

  it('records a warning and stops on query error (does not throw)', async () => {
    _state.pages = [];
    // Trigger error path: replace the mock resources() with one that throws once.
    const ag = await import('../../core/auth/azure.ts');
    const origRG = (ag as any).resourceGraph;
    (ag as any).resourceGraph = () => ({ async resources(_req: any) { throw new Error('boom'); } });
    try {
      const r = await discoverAzureAssets(['sub-1']);
      expect(r.assets).toEqual([]);
      expect(r.warnings.some((w) => /boom/.test(w))).toBe(true);
    } finally {
      (ag as any).resourceGraph = origRG;
    }
  });
});

// `collectAzureAssets` depth-enricher tests live in
// `tests/providers/azure/inventory-assets.test.ts` (INV-S2).
// That file uses the modern substring-routed Resource Graph mock so the
// 13 parallel + sequential KQL queries the depth enrichers issue can be
// routed by table-name match rather than by call-order. The remaining
// tests in this file exercise `discoverAzureAssets` + `rowToAsset` only.
