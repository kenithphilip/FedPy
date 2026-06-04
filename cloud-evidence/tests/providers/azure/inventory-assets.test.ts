/**
 * Tests for providers/azure/inventory-assets.ts → collectAzureAssets (INV-S2).
 *
 * These tests pin the cell-fill plan for each Azure enricher: each one must
 * produce a CloudAsset with the fields the FedRAMP Appendix M workbook needs
 * (DNS, IPs, MAC, HW Make/Model, SW Vendor/Version, VLAN/Network, etc.).
 * Substring-routed Resource Graph mock; same shape as the rest of the
 * Azure provider tests.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

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

import { collectAzureAssets } from '../../../providers/azure/inventory-assets.ts';

describe('collectAzureAssets (INV-S2 depth enrichers)', () => {
  beforeEach(() => { _state.routes = []; _state.queries = []; });

  it('VM enricher fans out NIC IPs + MAC + VLAN path onto the VM asset', async () => {
    _state.routes = [
      { match: 'microsoft.network/networkinterfaces', rows: [
        { vmId: '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1',
          mac: '00-AA-BB-CC-DD-EE',
          subnetId: '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet-prod/subnets/web',
          ipConfigs: [{ properties: { privateIPAddress: '10.0.0.5', publicIPAddress: { id: '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/pip-1' } } }],
        },
      ] },
      { match: 'microsoft.network/publicipaddresses', rows: [
        { id: '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/pip-1', ip: '203.0.113.5' },
      ] },
      { match: 'microsoft.compute/virtualmachines', rows: [
        { id: '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1',
          name: 'vm-1', location: 'eastus', subscriptionId: 'sub-1',
          vmSize: 'Standard_D2s_v3',
          imagePublisher: 'MicrosoftWindowsServer', imageOffer: 'WindowsServer', imageSku: '2022-Datacenter', imageVersion: 'latest',
          provisioning: 'Succeeded',
        },
      ] },
    ];
    const r = await collectAzureAssets(['sub-1']);
    const vm = r.assets.find((a) => a.resourceType === 'microsoft.compute/virtualmachines')!;
    expect(vm).toBeDefined();
    expect(vm.ips).toEqual(['10.0.0.5', '203.0.113.5']);
    expect(vm.macs).toEqual(['00-AA-BB-CC-DD-EE']);
    expect(vm.publicFacing).toBe(true);
    expect(vm.vlanNetworkId).toBe('vnet-prod/web');
    expect(vm.hardwareMakeModel).toBe('Standard_D2s_v3');
    expect(vm.osNameVersion).toContain('WindowsServer');
  });

  it('Azure SQL Server enricher fills DNS + vendor + version + publicFacing', async () => {
    _state.routes = [
      { match: 'microsoft.sql/servers"', rows: [
        { id: '/sql/srv-1', name: 'srv-prod', subscriptionId: 'sub-1', version: '12.0', fqdn: 'srv-prod.database.windows.net', publicAccess: 'Enabled' },
      ] },
      { match: 'microsoft.sql/servers/databases', rows: [] },
    ];
    const r = await collectAzureAssets(['sub-1']);
    const srv = r.assets.find((a) => a.resourceType === 'microsoft.sql/servers')!;
    expect(srv.softwareDatabaseVendor).toContain('Azure SQL');
    expect(srv.softwareDatabaseNameVersion).toContain('12.0');
    expect(srv.dns).toBe('srv-prod.database.windows.net');
    expect(srv.publicFacing).toBe(true);
  });

  it('Cosmos DB enricher fills vendor/version + DNS + publicFacing', async () => {
    _state.routes = [{ match: 'microsoft.documentdb/databaseaccounts', rows: [
      { id: '/cosmos/1', name: 'cdb', subscriptionId: 'sub-1', kind: 'MongoDB', endpoint: 'https://cdb.documents.azure.com:443/', publicAccess: 'Enabled' },
    ] }];
    const r = await collectAzureAssets(['sub-1']);
    const c = r.assets.find((a) => a.resourceType === 'microsoft.documentdb/databaseaccounts')!;
    expect(c.softwareDatabaseVendor).toContain('Cosmos DB');
    expect(c.softwareDatabaseNameVersion).toContain('MongoDB');
    expect(c.dns).toContain('documents.azure.com');
    expect(c.publicFacing).toBe(true);
  });

  it('AKS enricher fills vendor + Kubernetes version + node sizes + DNS', async () => {
    _state.routes = [{ match: 'microsoft.containerservice/managedclusters', rows: [
      { id: '/aks/1', name: 'aks-prod', subscriptionId: 'sub-1',
        k8sVersion: '1.29.4', fqdn: 'aks-prod-abc.hcp.eastus.azmk8s.io',
        apiPublic: 'false', nodePools: [{ vmSize: 'Standard_D4s_v3' }, { vmSize: 'Standard_D8s_v3' }],
      },
    ] }];
    const r = await collectAzureAssets(['sub-1']);
    const aks = r.assets.find((a) => a.resourceType === 'microsoft.containerservice/managedclusters')!;
    expect(aks.softwareDatabaseVendor).toContain('Kubernetes');
    expect(aks.softwareDatabaseNameVersion).toContain('1.29.4');
    expect(aks.hardwareMakeModel).toContain('Standard_D4s_v3');
    expect(aks.dns).toContain('azmk8s.io');
  });

  it('App Service / Function App enricher derives variety from kind + fills DNS', async () => {
    _state.routes = [{ match: 'microsoft.web/sites', rows: [
      { id: '/web/api', name: 'api', subscriptionId: 'sub-1', kind: 'app,linux', host: 'api-xy.azurewebsites.net', state: 'Running', publicAccess: 'Enabled' },
      { id: '/web/fn', name: 'fn', subscriptionId: 'sub-1', kind: 'functionapp,linux', host: 'fn-xy.azurewebsites.net', state: 'Running', publicAccess: 'Enabled' },
    ] }];
    const r = await collectAzureAssets(['sub-1']);
    const api = r.assets.find((a) => a.uniqueId === '/web/api')!;
    const fn = r.assets.find((a) => a.uniqueId === '/web/fn')!;
    expect(api.assetType).toBe('app-service');
    expect(api.dns).toBe('https://api-xy.azurewebsites.net');
    expect(api.publicFacing).toBe(true);
    expect(fn.assetType).toBe('function-app');
  });

  it('Application Gateway enricher reports HW tier + publicFacing when a public frontend exists', async () => {
    _state.routes = [{ match: 'microsoft.network/applicationgateways', rows: [
      { id: '/agw/1', name: 'agw', subscriptionId: 'sub-1', tier: 'WAF_v2', sslPolicy: 'AppGwSslPolicy20220101',
        frontendIPs: [{ properties: { publicIPAddress: { id: '/pip/x' } } }],
      },
    ] }];
    const r = await collectAzureAssets(['sub-1']);
    const agw = r.assets.find((a) => a.resourceType === 'microsoft.network/applicationgateways')!;
    expect(agw.hardwareMakeModel).toContain('WAF_v2');
    expect(agw.softwareDatabaseNameVersion).toContain('AppGwSslPolicy20220101');
    expect(agw.publicFacing).toBe(true);
  });

  it('Load Balancer enricher detects publicFacing from frontend public IPs', async () => {
    _state.routes = [{ match: 'microsoft.network/loadbalancers', rows: [
      { id: '/lb/1', subscriptionId: 'sub-1', skuName: 'Standard', tier: 'Regional',
        frontendIPs: [{ properties: { publicIPAddress: { id: '/pip/x' } } }],
      },
      { id: '/lb/internal', subscriptionId: 'sub-1', skuName: 'Standard', tier: 'Regional',
        frontendIPs: [{ properties: { privateIPAddress: '10.0.0.4' } }],
      },
    ] }];
    const r = await collectAzureAssets(['sub-1']);
    const lbs = r.assets.filter((a) => a.resourceType === 'microsoft.network/loadbalancers');
    expect(lbs.find((l) => l.uniqueId === '/lb/1')!.publicFacing).toBe(true);
    expect(lbs.find((l) => l.uniqueId === '/lb/internal')!.publicFacing).toBe(false);
  });

  it('Managed Disk enricher fills sizeGb + state + encryptionAtRest', async () => {
    _state.routes = [{ match: 'microsoft.compute/disks', rows: [
      { id: '/disk/1', name: 'disk-1', subscriptionId: 'sub-1', sizeGB: 256, tier: 'Premium_LRS', state: 'Attached', encType: 'EncryptionAtRestWithPlatformKey' },
    ] }];
    const r = await collectAzureAssets(['sub-1']);
    const disk = r.assets.find((a) => a.resourceType === 'microsoft.compute/disks')!;
    expect(disk.sizeGb).toBe(256);
    expect(disk.state).toBe('Attached');
    expect(disk.encryptionAtRest).toBe(true);
  });

  it('ACR enricher fills DNS (loginServer) + vendor', async () => {
    _state.routes = [{ match: 'microsoft.containerregistry/registries', rows: [
      { id: '/acr/1', name: 'acrprod', subscriptionId: 'sub-1', sku: 'Premium', loginServer: 'acrprod.azurecr.io', publicAccess: 'Enabled' },
    ] }];
    const r = await collectAzureAssets(['sub-1']);
    const acr = r.assets.find((a) => a.resourceType === 'microsoft.containerregistry/registries')!;
    expect(acr.dns).toBe('https://acrprod.azurecr.io');
    expect(acr.softwareDatabaseVendor).toContain('Container Registry');
    expect(acr.publicFacing).toBe(true);
  });

  it('Key Vault enricher fills DNS (vaultUri) + sku', async () => {
    _state.routes = [{ match: 'microsoft.keyvault/vaults', rows: [
      { id: '/kv/1', name: 'kv-prod', subscriptionId: 'sub-1', uri: 'https://kv-prod.vault.azure.net/', sku: 'premium', publicAccess: 'Disabled' },
    ] }];
    const r = await collectAzureAssets(['sub-1']);
    const kv = r.assets.find((a) => a.resourceType === 'microsoft.keyvault/vaults')!;
    expect(kv.dns).toBe('https://kv-prod.vault.azure.net/');
    expect(kv.softwareDatabaseNameVersion).toContain('Key Vault');
    expect(kv.publicFacing).toBe(false);
  });

  it('emits a warning when no subscriptions are configured', async () => {
    const r = await collectAzureAssets([]);
    expect(r.assets).toEqual([]);
    expect(r.warnings.some((w) => w.includes('no subscriptions configured'))).toBe(true);
  });

  // INV-S4
  it('VM enricher fills netbiosName (column F) from osProfile.computerName', async () => {
    _state.routes = [
      { match: 'microsoft.compute/virtualmachines', rows: [
        { id: '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/win-1',
          name: 'win-1', location: 'eastus', subscriptionId: 'sub-1',
          vmSize: 'Standard_D2s_v3', osType: 'Windows',
          computerName: 'WIN-PROD-01',
          imagePublisher: 'MicrosoftWindowsServer', imageOffer: 'WindowsServer', imageSku: '2022-Datacenter', imageVersion: 'latest',
        },
      ] },
    ];
    const r = await collectAzureAssets(['sub-1']);
    const vm = r.assets.find((a) => a.resourceType === 'microsoft.compute/virtualmachines') as any;
    expect(vm.netbiosName).toBe('WIN-PROD-01');
  });

  // INV-S4
  it('patchassessmentresults enrichment upgrades osNameVersion + patchLevel on VMs', async () => {
    _state.routes = [
      { match: 'patchassessmentresources', rows: [
        { vmId: '/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.compute/virtualmachines/srv-1/patchassessmentresults/latest',
          osName: 'Red Hat Enterprise Linux', osVersion: '9.4',
          assessmentResult: 'Succeeded', patchCount: 3 },
      ] },
      { match: 'microsoft.compute/virtualmachines', rows: [
        { id: '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/srv-1',
          name: 'srv-1', subscriptionId: 'sub-1',
          vmSize: 'Standard_D4s_v3', osType: 'Linux',
          // Image-only OS would have said "RedHat RHEL 9_4 latest" — patch assessment supersedes.
          imagePublisher: 'RedHat', imageOffer: 'RHEL', imageSku: '9_4', imageVersion: 'latest',
        },
      ] },
    ];
    const r = await collectAzureAssets(['sub-1']);
    const vm = r.assets.find((a) => a.resourceType === 'microsoft.compute/virtualmachines')!;
    expect(vm.osNameVersion).toBe('Red Hat Enterprise Linux 9.4');
    expect(vm.patchLevel).toContain('Succeeded');
    expect(vm.patchLevel).toContain('3 missing patch');
  });

  it('falls back to image-reference OS when no patchassessmentresult exists', async () => {
    _state.routes = [
      { match: 'patchassessmentresources', rows: [] }, // empty
      { match: 'microsoft.compute/virtualmachines', rows: [
        { id: '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/no-assessment',
          name: 'no-assessment', subscriptionId: 'sub-1',
          vmSize: 'Standard_D2s_v3', osType: 'Linux',
          imagePublisher: 'Canonical', imageOffer: 'UbuntuServer', imageSku: '22_04-lts', imageVersion: 'latest',
        },
      ] },
    ];
    const r = await collectAzureAssets(['sub-1']);
    const vm = r.assets.find((a) => a.resourceType === 'microsoft.compute/virtualmachines')!;
    // Falls back to image string.
    expect(vm.osNameVersion).toContain('Canonical');
    // patchLevel stays undefined when no assessment exists.
    expect(vm.patchLevel).toBeUndefined();
  });
});
