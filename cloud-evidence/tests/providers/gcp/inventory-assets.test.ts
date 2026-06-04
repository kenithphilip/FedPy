/**
 * Tests for providers/gcp/inventory-assets.ts → collectGcpAssets (INV-S3).
 *
 * Mocks core/auth/gcp.ts so the test never touches real GCP credentials.
 * Exercises:
 *   - the CAI `assets.list` path with the Compute Instance mapping
 *     (NIC IPs, MAC addresses, machineType → HW Make/Model, network/subnet);
 *   - the OS Config inventory enrichment that fans osNameVersion +
 *     netbiosName + patchLevel onto Instance assets (column F + K + R).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

const _state = vi.hoisted(() => ({
  // Mock googleapis clients are constructed per-test via `setClients`.
  cloudasset: null as any,
  osconfig: null as any,
}));

vi.mock('../../../core/auth/gcp.ts', () => ({
  googleClient: async (service: string) => {
    if (service === 'cloudasset') return _state.cloudasset;
    if (service === 'osconfig') return _state.osconfig;
    throw new Error(`unknown service: ${service}`);
  },
}));

import { collectGcpAssets } from '../../../providers/gcp/inventory-assets.ts';

describe('collectGcpAssets — CAI + OS Config inventory enrichment', () => {
  beforeEach(() => {
    _state.cloudasset = null;
    _state.osconfig = null;
  });

  function mockCai(assets: Array<{ name: string; assetType: string; resource: { data?: any; location?: string | null } }>): void {
    _state.cloudasset = {
      assets: {
        list: async () => ({ data: { assets } }),
      },
    };
  }

  function mockOsConfig(inventoriesByZone: Record<string, any[]>): void {
    _state.osconfig = {
      projects: { locations: { instances: { inventories: { list: async (args: any) => {
        // parent = projects/<p>/locations/<zone>/instances/-
        const m = String(args.parent ?? '').match(/locations\/([^/]+)\/instances/);
        const zone = m?.[1] ?? '';
        return { data: { inventories: inventoriesByZone[zone] ?? [] } };
      } } } } },
    };
  }

  it('extracts NIC MAC addresses (column G) for Compute Instances', async () => {
    mockCai([{
      name: '//compute.googleapis.com/projects/p/zones/us-central1-a/instances/vm-1',
      assetType: 'compute.googleapis.com/Instance',
      resource: {
        location: 'us-central1-a',
        data: {
          name: 'vm-1',
          zone: 'projects/p/zones/us-central1-a',
          machineType: 'projects/p/zones/us-central1-a/machineTypes/e2-standard-4',
          networkInterfaces: [{
            networkIP: '10.0.0.5',
            macAddress: '42:01:0a:00:00:05',
            accessConfigs: [{ natIP: '203.0.113.10' }],
            network: 'projects/p/global/networks/default',
            subnetwork: 'projects/p/regions/us-central1/subnetworks/web',
          }],
        },
      },
    }]);
    // No OS Config client → enrichment skipped silently.
    _state.osconfig = null;

    const r = await collectGcpAssets('p');
    expect(r.assets).toHaveLength(1);
    const vm = r.assets[0]!;
    expect(vm.ips).toEqual(['10.0.0.5', '203.0.113.10']);
    expect(vm.macs).toEqual(['42:01:0a:00:00:05']);
    expect(vm.hardwareMakeModel).toBe('GCP e2-standard-4');
    expect(vm.vlanNetworkId).toBe('default/web');
    expect(vm.publicFacing).toBe(true);
  });

  it('OS Config enrichment fills osNameVersion + patchLevel for matched instances', async () => {
    mockCai([{
      name: '//compute.googleapis.com/projects/p/zones/us-central1-a/instances/vm-42',
      assetType: 'compute.googleapis.com/Instance',
      resource: { location: 'us-central1-a', data: { name: 'vm-42', zone: 'projects/p/zones/us-central1-a' } },
    }]);
    mockOsConfig({
      'us-central1-a': [{
        name: 'projects/p/locations/us-central1-a/instances/vm-42/inventory',
        osInfo: { shortName: 'debian', version: '12', hostname: 'vm-42' },
        items: {
          a: { type: 'INSTALLED_PACKAGE' },
          b: { type: 'INSTALLED_PACKAGE' },
          c: { type: 'INSTALLED_PACKAGE' },
          d: { type: 'AVAILABLE_PACKAGE' },
        },
      }],
    });
    const r = await collectGcpAssets('p');
    expect(r.warnings).toEqual([]);
    const vm = r.assets[0]!;
    expect(vm.osNameVersion).toBe('debian 12');
    expect(vm.patchLevel).toContain('1 update');
    expect(vm.sourceApi).toContain('osconfig');
  });

  it('extracts netbiosName from OS Config hostname only when shortName is Windows', async () => {
    mockCai([
      { name: '//compute.googleapis.com/projects/p/zones/us-central1-a/instances/win-1',
        assetType: 'compute.googleapis.com/Instance',
        resource: { location: 'us-central1-a', data: { name: 'win-1' } } },
      { name: '//compute.googleapis.com/projects/p/zones/us-central1-a/instances/linux-1',
        assetType: 'compute.googleapis.com/Instance',
        resource: { location: 'us-central1-a', data: { name: 'linux-1' } } },
    ]);
    mockOsConfig({
      'us-central1-a': [
        { name: 'projects/p/locations/us-central1-a/instances/win-1/inventory',
          osInfo: { shortName: 'windows', version: '2022', hostname: 'WIN-PROD-01' }, items: {} },
        { name: 'projects/p/locations/us-central1-a/instances/linux-1/inventory',
          osInfo: { shortName: 'ubuntu', version: '22.04', hostname: 'linux-prod-01' }, items: {} },
      ],
    });
    const r = await collectGcpAssets('p');
    const win = r.assets.find((a) => a.uniqueId.endsWith('/win-1'))! as any;
    const lin = r.assets.find((a) => a.uniqueId.endsWith('/linux-1'))! as any;
    expect(win.netbiosName).toBe('WIN-PROD-01');
    expect(lin.netbiosName).toBeUndefined();
  });

  it('reports "Current" patchLevel when no available packages remain', async () => {
    mockCai([{
      name: '//compute.googleapis.com/projects/p/zones/us-east1-b/instances/clean-vm',
      assetType: 'compute.googleapis.com/Instance',
      resource: { location: 'us-east1-b', data: { name: 'clean-vm' } },
    }]);
    mockOsConfig({
      'us-east1-b': [{
        name: 'projects/p/locations/us-east1-b/instances/clean-vm/inventory',
        osInfo: { shortName: 'cos', version: '109' },
        items: { p1: { type: 'INSTALLED_PACKAGE' }, p2: { type: 'INSTALLED_PACKAGE' } },
      }],
    });
    const r = await collectGcpAssets('p');
    expect(r.assets[0]!.patchLevel).toContain('Current');
  });

  it('degrades gracefully (single warning, no throw) when OS Config client is missing or older than expected', async () => {
    mockCai([{
      name: '//compute.googleapis.com/projects/p/zones/us-central1-a/instances/vm-1',
      assetType: 'compute.googleapis.com/Instance',
      resource: { location: 'us-central1-a', data: { name: 'vm-1' } },
    }]);
    // Provide an osconfig client that lacks the inventories namespace.
    _state.osconfig = { projects: { locations: { instances: { /* no inventories */ } } } };
    const r = await collectGcpAssets('p');
    expect(r.assets).toHaveLength(1);
    expect(r.warnings.some((w) => w.includes('OS Config inventory'))).toBe(true);
  });

  it('skips OS Config entirely when no Compute Instances are found (no spurious permission warning)', async () => {
    mockCai([{
      name: '//storage.googleapis.com/projects/p/buckets/b',
      assetType: 'storage.googleapis.com/Bucket',
      resource: { location: 'US', data: { location: 'US', name: 'b' } },
    }]);
    _state.osconfig = null; // would throw if called.
    const r = await collectGcpAssets('p');
    expect(r.assets).toHaveLength(1);
    expect(r.warnings.filter((w) => /osconfig/i.test(w))).toHaveLength(0);
  });
});
