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

/** Run all depth enrichers; aggregate. */
export async function collectAzureAssets(subscriptionIds: string[]): Promise<AzureInventoryResult> {
  const assets: CloudAsset[] = [];
  const warnings: string[] = [];
  if (subscriptionIds.length === 0) {
    warnings.push('Azure inventory: no subscriptions configured.');
    return { assets, warnings };
  }
  for (const fn of [storageAccounts, virtualMachines]) {
    try { assets.push(...await fn(subscriptionIds, warnings)); }
    catch (e: any) { warnings.push(`Azure inventory enricher ${fn.name} failed: ${e?.message ?? e}`); }
  }
  return { assets, warnings };
}
