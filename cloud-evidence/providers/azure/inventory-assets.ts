/**
 * Azure inventory depth enricher (AZ-1).
 *
 * Resource Graph (`providers/azure/discover.ts`) already returns one CloudAsset
 * per resource with the generic fields. This module adds TYPE-SPECIFIC depth
 * — storage accounts (public blob access + encryption mode), VMs (OS family /
 * size / NIC IPs) — that the workbook + governance need but the generic
 * projection doesn't carry by default.
 *
 * Both queries are KQL against Resource Graph; the wrapper guardrail enforces
 * read-only. Merged with `discover.ts` rows via `dedupeAssets` in the orchestrator.
 */
import * as azure from '../../core/auth/azure.ts';
import type { CloudAsset } from '../../core/inventory-workbook.ts';

const PAGE_SIZE = 1000;
const MAX_PAGES = 100;

export interface AzureInventoryResult { assets: CloudAsset[]; warnings: string[]; }

async function runQuery(subscriptionIds: string[], query: string, warnings: string[]): Promise<any[]> {
  const rows: any[] = [];
  let client: any;
  try { client = azure.resourceGraph(); }
  catch (e: any) { warnings.push(`Azure Resource Graph client construction failed: ${e.message ?? e}`); return rows; }
  let skipToken: string | undefined;
  let pages = 0;
  do {
    try {
      const r = await client.resources({
        subscriptions: subscriptionIds, query,
        options: { top: PAGE_SIZE, resultFormat: 'objectArray', ...(skipToken ? { $skipToken: skipToken } : {}) },
      });
      const data = Array.isArray(r?.data) ? r.data : [];
      rows.push(...data);
      skipToken = r?.$skipToken ?? r?.skipToken ?? undefined;
    } catch (e: any) {
      warnings.push(`Azure inventory query failed (${query.slice(0, 60)}…): ${e?.message ?? e}`);
      break;
    }
  } while (skipToken && ++pages < MAX_PAGES);
  return rows;
}

function commonFields(row: any): Pick<CloudAsset, 'provider' | 'accountId' | 'location' | 'function' | 'tags' | 'sourceApi'> {
  const tags = (row.tags && typeof row.tags === 'object' && Object.keys(row.tags).length) ? row.tags as Record<string, string> : undefined;
  return {
    provider: 'azure',
    accountId: row.subscriptionId ?? null,
    location: row.location ?? null,
    function: row.name ?? null,
    tags,
    sourceApi: 'azure-inventory-assets',
  };
}

/** Storage accounts → CloudAsset with public-access + encryption depth. */
async function storageAccounts(subs: string[], warnings: string[]): Promise<CloudAsset[]> {
  const rows = await runQuery(subs,
    'Resources | where type =~ "microsoft.storage/storageaccounts" | project ' +
    'id, name, location, resourceGroup, subscriptionId, tags, sku, kind, ' +
    'publicNetworkAccess=properties.publicNetworkAccess, ' +
    'allowBlobPublicAccess=properties.allowBlobPublicAccess, ' +
    'minTls=properties.minimumTlsVersion, ' +
    'encKeySource=properties.encryption.keySource, ' +
    'cmkKey=properties.encryption.keyVaultProperties.keyVaultUri',
    warnings,
  );
  return rows.map((r): CloudAsset => ({
    ...commonFields(r),
    uniqueId: r.id ?? r.name ?? '',
    resourceType: 'microsoft.storage/storageaccounts',
    assetType: 'storage-account',
    publicFacing: r.allowBlobPublicAccess === true || /enabled/i.test(String(r.publicNetworkAccess ?? '')),
    encryptionAtRest: true,                            // ASA always encrypts at rest; cmkKey tells you with what
    kmsKeyId: r.cmkKey ?? null,
    raw: {
      resourceGroup: r.resourceGroup, sku: r.sku, kind: r.kind,
      minimumTlsVersion: r.minTls, encryptionKeySource: r.encKeySource,
      publicNetworkAccess: r.publicNetworkAccess, allowBlobPublicAccess: r.allowBlobPublicAccess,
    },
  }));
}

/** Virtual machines → CloudAsset with OS + size depth. */
async function virtualMachines(subs: string[], warnings: string[]): Promise<CloudAsset[]> {
  const rows = await runQuery(subs,
    'Resources | where type =~ "microsoft.compute/virtualmachines" | project ' +
    'id, name, location, resourceGroup, subscriptionId, tags, ' +
    'vmSize=properties.hardwareProfile.vmSize, ' +
    'osType=properties.storageProfile.osDisk.osType, ' +
    'imagePublisher=properties.storageProfile.imageReference.publisher, ' +
    'imageOffer=properties.storageProfile.imageReference.offer, ' +
    'imageSku=properties.storageProfile.imageReference.sku, ' +
    'imageVersion=properties.storageProfile.imageReference.version, ' +
    'provisioning=properties.provisioningState',
    warnings,
  );
  return rows.map((r): CloudAsset => ({
    ...commonFields(r),
    uniqueId: r.id ?? r.name ?? '',
    resourceType: 'microsoft.compute/virtualmachines',
    assetType: 'virtual-machine',
    osNameVersion: [r.imagePublisher, r.imageOffer, r.imageSku, r.imageVersion].filter(Boolean).join(' ') || null,
    hardwareMakeModel: r.vmSize ?? null,
    state: r.provisioning ?? null,
    raw: { resourceGroup: r.resourceGroup, osType: r.osType, imageReference: { publisher: r.imagePublisher, offer: r.imageOffer, sku: r.imageSku, version: r.imageVersion } },
  }));
}

/**
 * Network interfaces → VM NIC IP + MAC fan-out (INV-S2).
 * Closes columns C (IPv4/IPv6) and G (MAC) for Azure VMs. Resource Graph
 * exposes NICs as their own resource; we project each NIC's IPs + MAC and
 * attach them to its parent VM via the `properties.virtualMachine.id` link.
 */
async function networkInterfaces(subs: string[], warnings: string[]): Promise<Map<string, { ips: string[]; macs: string[]; publicIpIds: string[] }>> {
  const byVmId = new Map<string, { ips: string[]; macs: string[]; publicIpIds: string[] }>();
  const rows = await runQuery(subs,
    'Resources | where type =~ "microsoft.network/networkinterfaces" | project ' +
    'vmId=tostring(properties.virtualMachine.id), ' +
    'mac=tostring(properties.macAddress), ' +
    'ipConfigs=properties.ipConfigurations',
    warnings,
  );
  for (const r of rows) {
    if (!r.vmId) continue;
    const ips: string[] = []; const publicIpIds: string[] = [];
    for (const c of (Array.isArray(r.ipConfigs) ? r.ipConfigs : []) as Array<any>) {
      const priv = c?.properties?.privateIPAddress;
      if (typeof priv === 'string' && priv) ips.push(priv);
      const pubId = c?.properties?.publicIPAddress?.id;
      if (typeof pubId === 'string' && pubId) publicIpIds.push(pubId);
    }
    const key = String(r.vmId);
    const cur = byVmId.get(key) ?? { ips: [], macs: [], publicIpIds: [] };
    cur.ips.push(...ips);
    if (r.mac) cur.macs.push(String(r.mac));
    cur.publicIpIds.push(...publicIpIds);
    byVmId.set(key, cur);
  }
  return byVmId;
}

/** Resolve `microsoft.network/publicipaddresses` ids → their IP values. */
async function publicIpMap(subs: string[], warnings: string[]): Promise<Map<string, string>> {
  const m = new Map<string, string>();
  const rows = await runQuery(subs,
    'Resources | where type =~ "microsoft.network/publicipaddresses" | project ' +
    'id, ip=tostring(properties.ipAddress)',
    warnings,
  );
  for (const r of rows) {
    if (typeof r.id === 'string' && typeof r.ip === 'string' && r.ip) m.set(r.id, r.ip);
  }
  return m;
}

/**
 * Azure SQL Server + Database → CloudAsset with vendor/version (columns P + Q).
 * Server carries firewall + version metadata; databases inherit server + add
 * their own service tier (HW Make/Model → column N).
 */
async function azureSql(subs: string[], warnings: string[]): Promise<CloudAsset[]> {
  const servers = await runQuery(subs,
    'Resources | where type =~ "microsoft.sql/servers" | project ' +
    'id, name, location, resourceGroup, subscriptionId, tags, ' +
    'version=tostring(properties.version), ' +
    'fqdn=tostring(properties.fullyQualifiedDomainName), ' +
    'publicAccess=tostring(properties.publicNetworkAccess)',
    warnings,
  );
  const dbs = await runQuery(subs,
    'Resources | where type =~ "microsoft.sql/servers/databases" | project ' +
    'id, name, location, resourceGroup, subscriptionId, tags, ' +
    'tier=tostring(sku.tier), capacity=tostring(sku.capacity), ' +
    'collation=tostring(properties.collation)',
    warnings,
  );
  const out: CloudAsset[] = [];
  for (const r of servers) {
    out.push({
      ...commonFields(r),
      uniqueId: r.id ?? r.name ?? '',
      resourceType: 'microsoft.sql/servers',
      assetType: 'azure-sql-server',
      softwareDatabaseVendor: 'Microsoft Azure SQL',
      softwareDatabaseNameVersion: r.version ? `Azure SQL Server ${r.version}` : 'Azure SQL Server',
      dns: r.fqdn ?? null,
      publicFacing: /enabled/i.test(String(r.publicAccess ?? '')),
    });
  }
  for (const r of dbs) {
    out.push({
      ...commonFields(r),
      uniqueId: r.id ?? r.name ?? '',
      resourceType: 'microsoft.sql/servers/databases',
      assetType: 'azure-sql-database',
      softwareDatabaseVendor: 'Microsoft Azure SQL',
      softwareDatabaseNameVersion: 'Azure SQL Database',
      hardwareMakeModel: [r.tier, r.capacity].filter(Boolean).join(' ') || null,
    });
  }
  return out;
}

/** Cosmos DB accounts → CloudAsset (column P/Q + DNS). */
async function cosmosDb(subs: string[], warnings: string[]): Promise<CloudAsset[]> {
  const rows = await runQuery(subs,
    'Resources | where type =~ "microsoft.documentdb/databaseaccounts" | project ' +
    'id, name, location, resourceGroup, subscriptionId, tags, kind, ' +
    'endpoint=tostring(properties.documentEndpoint), ' +
    'publicAccess=tostring(properties.publicNetworkAccess), ' +
    'apiKind=tostring(properties.databaseAccountOfferType)',
    warnings,
  );
  return rows.map((r): CloudAsset => ({
    ...commonFields(r),
    uniqueId: r.id ?? r.name ?? '',
    resourceType: 'microsoft.documentdb/databaseaccounts',
    assetType: 'cosmos-db-account',
    softwareDatabaseVendor: 'Microsoft Azure Cosmos DB',
    softwareDatabaseNameVersion: r.kind ? `Cosmos DB (${r.kind})` : 'Cosmos DB',
    dns: r.endpoint ?? null,
    publicFacing: /enabled/i.test(String(r.publicAccess ?? '')),
  }));
}

/** AKS managed clusters → CloudAsset with Kubernetes version + node sizes. */
async function aksClusters(subs: string[], warnings: string[]): Promise<CloudAsset[]> {
  const rows = await runQuery(subs,
    'Resources | where type =~ "microsoft.containerservice/managedclusters" | project ' +
    'id, name, location, resourceGroup, subscriptionId, tags, ' +
    'k8sVersion=tostring(properties.kubernetesVersion), ' +
    'fqdn=tostring(properties.fqdn), ' +
    'apiPublic=tostring(properties.apiServerAccessProfile.enablePrivateCluster), ' +
    'nodePools=properties.agentPoolProfiles',
    warnings,
  );
  return rows.map((r): CloudAsset => {
    const np = Array.isArray(r.nodePools) ? r.nodePools : [];
    const sizes = np.map((p: any) => p?.vmSize).filter(Boolean).join(',');
    return {
      ...commonFields(r),
      uniqueId: r.id ?? r.name ?? '',
      resourceType: 'microsoft.containerservice/managedclusters',
      assetType: 'kubernetes-cluster',
      softwareDatabaseVendor: 'Microsoft Azure Kubernetes Service',
      softwareDatabaseNameVersion: r.k8sVersion ? `Kubernetes ${r.k8sVersion}` : 'AKS',
      hardwareMakeModel: sizes || null,
      dns: r.fqdn ?? null,
      // apiServerAccessProfile.enablePrivateCluster=true → API server NOT public.
      // Bools come back stringly in KQL; treat truthy as private.
      publicFacing: !(String(r.apiPublic ?? '').toLowerCase() === 'true'),
    };
  });
}

/** App Service / Function Apps / Logic Apps → CloudAsset (columns H + Q). */
async function appServices(subs: string[], warnings: string[]): Promise<CloudAsset[]> {
  const rows = await runQuery(subs,
    'Resources | where type =~ "microsoft.web/sites" | project ' +
    'id, name, location, resourceGroup, subscriptionId, tags, kind, ' +
    'host=tostring(properties.defaultHostName), ' +
    'state=tostring(properties.state), ' +
    'publicAccess=tostring(properties.publicNetworkAccess), ' +
    'runtime=tostring(properties.siteProperties.properties[0].value)',
    warnings,
  );
  return rows.map((r): CloudAsset => {
    const kind = String(r.kind ?? '').toLowerCase();
    const variety = kind.includes('functionapp') ? 'function-app'
      : kind.includes('workflowapp') ? 'logic-app'
      : kind.includes('container') ? 'app-service-container'
      : 'app-service';
    return {
      ...commonFields(r),
      uniqueId: r.id ?? r.name ?? '',
      resourceType: 'microsoft.web/sites',
      assetType: variety,
      dns: r.host ? `https://${r.host}` : null,
      softwareDatabaseVendor: 'Microsoft Azure App Service',
      softwareDatabaseNameVersion: r.runtime ? `App Service runtime: ${r.runtime}` : 'Azure App Service',
      state: r.state ?? null,
      publicFacing: /enabled/i.test(String(r.publicAccess ?? '')),
    };
  });
}

/** Application Gateways → CloudAsset with frontend FQDN + SSL policy (columns H + Q). */
async function applicationGateways(subs: string[], warnings: string[]): Promise<CloudAsset[]> {
  const rows = await runQuery(subs,
    'Resources | where type =~ "microsoft.network/applicationgateways" | project ' +
    'id, name, location, resourceGroup, subscriptionId, tags, ' +
    'sslPolicy=tostring(properties.sslPolicy.policyName), ' +
    'tier=tostring(sku.tier), ' +
    'frontendIPs=properties.frontendIPConfigurations',
    warnings,
  );
  return rows.map((r): CloudAsset => {
    const fes = Array.isArray(r.frontendIPs) ? r.frontendIPs : [];
    const publicFe = fes.find((f: any) => f?.properties?.publicIPAddress);
    return {
      ...commonFields(r),
      uniqueId: r.id ?? r.name ?? '',
      resourceType: 'microsoft.network/applicationgateways',
      assetType: 'application-gateway',
      hardwareMakeModel: r.tier ? `Application Gateway ${r.tier}` : 'Application Gateway',
      softwareDatabaseVendor: 'Microsoft Azure Application Gateway',
      softwareDatabaseNameVersion: r.sslPolicy ? `AGW SSL policy: ${r.sslPolicy}` : 'AGW',
      publicFacing: Boolean(publicFe),
    };
  });
}

/** Load Balancers → CloudAsset (column H + N). */
async function loadBalancers(subs: string[], warnings: string[]): Promise<CloudAsset[]> {
  const rows = await runQuery(subs,
    'Resources | where type =~ "microsoft.network/loadbalancers" | project ' +
    'id, name, location, resourceGroup, subscriptionId, tags, ' +
    'tier=tostring(sku.tier), skuName=tostring(sku.name), ' +
    'frontendIPs=properties.frontendIPConfigurations',
    warnings,
  );
  return rows.map((r): CloudAsset => {
    const fes = Array.isArray(r.frontendIPs) ? r.frontendIPs : [];
    const hasPublic = fes.some((f: any) => f?.properties?.publicIPAddress);
    return {
      ...commonFields(r),
      uniqueId: r.id ?? r.name ?? '',
      resourceType: 'microsoft.network/loadbalancers',
      assetType: 'load-balancer',
      hardwareMakeModel: [r.skuName, r.tier].filter(Boolean).join(' ') || null,
      publicFacing: hasPublic,
    };
  });
}

/** Managed Disks → CloudAsset (column N + V via tags). */
async function managedDisks(subs: string[], warnings: string[]): Promise<CloudAsset[]> {
  const rows = await runQuery(subs,
    'Resources | where type =~ "microsoft.compute/disks" | project ' +
    'id, name, location, resourceGroup, subscriptionId, tags, ' +
    'sizeGB=toint(properties.diskSizeGB), ' +
    'tier=tostring(sku.name), ' +
    'state=tostring(properties.diskState), ' +
    'encType=tostring(properties.encryption.type)',
    warnings,
  );
  return rows.map((r): CloudAsset => ({
    ...commonFields(r),
    uniqueId: r.id ?? r.name ?? '',
    resourceType: 'microsoft.compute/disks',
    assetType: 'managed-disk',
    hardwareMakeModel: r.tier ? `Azure Managed Disk ${r.tier}` : 'Azure Managed Disk',
    sizeGb: typeof r.sizeGB === 'number' ? r.sizeGB : null,
    state: r.state ?? null,
    encryptionAtRest: true,
    raw: { encryptionType: r.encType, resourceGroup: r.resourceGroup },
  }));
}

/** ACR registries → CloudAsset (column H + Q). */
async function containerRegistries(subs: string[], warnings: string[]): Promise<CloudAsset[]> {
  const rows = await runQuery(subs,
    'Resources | where type =~ "microsoft.containerregistry/registries" | project ' +
    'id, name, location, resourceGroup, subscriptionId, tags, ' +
    'sku=tostring(sku.tier), ' +
    'loginServer=tostring(properties.loginServer), ' +
    'publicAccess=tostring(properties.publicNetworkAccess)',
    warnings,
  );
  return rows.map((r): CloudAsset => ({
    ...commonFields(r),
    uniqueId: r.id ?? r.name ?? '',
    resourceType: 'microsoft.containerregistry/registries',
    assetType: 'container-registry',
    softwareDatabaseVendor: 'Microsoft Azure Container Registry',
    softwareDatabaseNameVersion: r.sku ? `ACR ${r.sku}` : 'ACR',
    dns: r.loginServer ? `https://${r.loginServer}` : null,
    publicFacing: /enabled/i.test(String(r.publicAccess ?? '')),
  }));
}

/** Key Vaults → CloudAsset (column H). */
async function keyVaults(subs: string[], warnings: string[]): Promise<CloudAsset[]> {
  const rows = await runQuery(subs,
    'Resources | where type =~ "microsoft.keyvault/vaults" | project ' +
    'id, name, location, resourceGroup, subscriptionId, tags, ' +
    'uri=tostring(properties.vaultUri), ' +
    'sku=tostring(properties.sku.name), ' +
    'publicAccess=tostring(properties.publicNetworkAccess)',
    warnings,
  );
  return rows.map((r): CloudAsset => ({
    ...commonFields(r),
    uniqueId: r.id ?? r.name ?? '',
    resourceType: 'microsoft.keyvault/vaults',
    assetType: 'key-vault',
    softwareDatabaseVendor: 'Microsoft Azure Key Vault',
    softwareDatabaseNameVersion: r.sku ? `Key Vault ${r.sku}` : 'Azure Key Vault',
    dns: r.uri ?? null,
    publicFacing: /enabled/i.test(String(r.publicAccess ?? '')),
  }));
}

/** Resolve VM `properties.networkProfile.networkInterfaces[].id` → subnet path. */
async function vmSubnetMap(subs: string[], warnings: string[]): Promise<Map<string, string>> {
  // Returns a map of VM id → "<vnet>/<subnet>" derived from NIC ipConfigurations.
  // Pure read-only KQL.
  const m = new Map<string, string>();
  const rows = await runQuery(subs,
    'Resources | where type =~ "microsoft.network/networkinterfaces" | project ' +
    'vmId=tostring(properties.virtualMachine.id), ' +
    'subnetId=tostring(properties.ipConfigurations[0].properties.subnet.id)',
    warnings,
  );
  for (const r of rows) {
    if (!r.vmId || !r.subnetId) continue;
    // subnetId is like /.../virtualNetworks/<vnet>/subnets/<subnet>.
    const match = String(r.subnetId).match(/virtualNetworks\/([^/]+)\/subnets\/([^/]+)/i);
    if (match) m.set(String(r.vmId), `${match[1]}/${match[2]}`);
  }
  return m;
}

/** Run all depth enrichers; aggregate. */
export async function collectAzureAssets(subscriptionIds: string[]): Promise<AzureInventoryResult> {
  const assets: CloudAsset[] = [];
  const warnings: string[] = [];
  if (subscriptionIds.length === 0) {
    warnings.push('Azure inventory: no subscriptions configured.');
    return { assets, warnings };
  }
  // Run NIC + public-IP + VM-subnet lookups first; the VM enricher uses them.
  const [nicByVm, pubIpById, subnetByVm] = await Promise.all([
    networkInterfaces(subscriptionIds, warnings),
    publicIpMap(subscriptionIds, warnings),
    vmSubnetMap(subscriptionIds, warnings),
  ]);
  for (const fn of [
    storageAccounts, virtualMachines, azureSql, cosmosDb, aksClusters,
    appServices, applicationGateways, loadBalancers, managedDisks,
    containerRegistries, keyVaults,
  ]) {
    try {
      const r = await fn(subscriptionIds, warnings);
      // After VMs return, fan out their NIC IPs + MACs + subnet path.
      if (fn === virtualMachines) {
        for (const a of r) {
          const idLc = a.uniqueId.toLowerCase();
          // Resource Graph stores ids in lowercase; ensure consistent lookup.
          let entry = nicByVm.get(idLc);
          if (!entry) {
            // Try title-case match — Resource Graph returns ids with mixed case.
            for (const [k, v] of nicByVm) { if (k.toLowerCase() === idLc) { entry = v; break; } }
          }
          if (entry) {
            const allIps = [...entry.ips];
            for (const pid of entry.publicIpIds) {
              const pip = pubIpById.get(pid) ?? Array.from(pubIpById.entries()).find(([k]) => k.toLowerCase() === pid.toLowerCase())?.[1];
              if (pip) allIps.push(pip);
            }
            if (allIps.length) a.ips = allIps;
            if (entry.macs.length) a.macs = entry.macs;
            if (entry.publicIpIds.length > 0) a.publicFacing = true;
          }
          const subnet = subnetByVm.get(idLc) ?? Array.from(subnetByVm.entries()).find(([k]) => k.toLowerCase() === idLc)?.[1];
          if (subnet) a.vlanNetworkId = subnet;
        }
      }
      assets.push(...r);
    } catch (e: any) { warnings.push(`Azure inventory enricher ${fn.name} failed: ${e?.message ?? e}`); }
  }
  return { assets, warnings };
}
