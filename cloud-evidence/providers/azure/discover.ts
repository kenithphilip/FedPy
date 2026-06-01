/**
 * Azure generic resource-discovery backbone for the inventory (AZ-1).
 *
 * BREADTH via Azure Resource Graph (the Azure analog of AWS Config Advanced Query
 * and GCP CAI `searchAllResources`). A single KQL query against the runner's
 * accessible subscriptions returns *every* resource type, populated with the
 * fields the inventory workbook needs. Combined with the per-type DEPTH enricher
 * in `inventory-assets.ts` via `dedupeAssets`.
 *
 * Read-only via the Azure Proxy guardrail. Pure mapper exported for tests.
 */
import * as azure from '../../core/auth/azure.ts';
import type { CloudAsset } from '../../core/inventory-workbook.ts';

const PAGE_SIZE = 1000;
const MAX_PAGES = 100;

export interface AzureDiscoverResult { assets: CloudAsset[]; warnings: string[]; }

/**
 * Map one Azure Resource Graph row → CloudAsset.
 *
 * Resource Graph rows have shape:
 *   { id, name, type, kind, location, resourceGroup, subscriptionId, tags, properties }
 * with `properties` carrying the type-specific bag (encryption, SKU, …).
 */
export function rowToAsset(row: Record<string, any>): CloudAsset {
  const type: string | null = row.type ?? null;
  const friendly = type ? type.split('/').pop() ?? null : null;
  const tags = (row.tags && typeof row.tags === 'object' && Object.keys(row.tags).length) ? row.tags as Record<string, string> : undefined;
  const props = (row.properties && typeof row.properties === 'object') ? row.properties as Record<string, any> : {};
  return {
    provider: 'azure',
    uniqueId: row.id ?? row.name ?? '',
    resourceType: type,
    assetType: friendly,
    location: row.location ?? null,
    accountId: row.subscriptionId ?? null,            // Azure "account" ≈ subscription
    function: row.name ?? null,
    kmsKeyId: props.encryption?.keyVaultProperties?.keyIdentifier ?? props.kmsKeyId ?? null,
    encryptionAtRest: typeof props.encryption !== 'undefined' || typeof props.diskEncryptionSetId !== 'undefined' ? true : null,
    state: props.provisioningState ?? null,
    createdAt: row.createdTime ?? null,
    lastModifiedAt: row.changedTime ?? null,
    publicFacing: typeof props.publicNetworkAccess === 'string' ? /enabled/i.test(props.publicNetworkAccess) : undefined,
    virtual: true,
    tags,
    raw: { resourceGroup: row.resourceGroup, kind: row.kind, sku: row.sku },
    sourceApi: 'azure-resource-graph',
  };
}

/**
 * Discover all Azure resources across the given subscriptions via Resource Graph.
 * The projection includes the fields needed by the inventory workbook + tag governance.
 */
export async function discoverAzureAssets(subscriptionIds: string[]): Promise<AzureDiscoverResult> {
  const assets: CloudAsset[] = [];
  const warnings: string[] = [];
  if (subscriptionIds.length === 0) {
    warnings.push('Azure discover: no subscriptions configured in config.azure.subscriptions.');
    return { assets, warnings };
  }
  let client: any;
  try { client = azure.resourceGraph(); }
  catch (e: any) { warnings.push(`Azure Resource Graph client construction failed: ${e.message ?? e}`); return { assets, warnings }; }

  const query =
    'Resources | project id, name, type, kind, location, resourceGroup, subscriptionId, ' +
    'tags, sku, createdTime=properties.createdTime, changedTime=properties.changedTime, properties | order by id asc';

  let skipToken: string | undefined;
  let pages = 0;
  do {
    try {
      const r = await client.resources({
        subscriptions: subscriptionIds,
        query,
        options: { top: PAGE_SIZE, resultFormat: 'objectArray', ...(skipToken ? { $skipToken: skipToken } : {}) },
      });
      const rows = Array.isArray(r?.data) ? r.data : [];
      for (const row of rows) {
        if (!row || (!row.id && !row.name)) continue;
        assets.push(rowToAsset(row));
      }
      skipToken = r?.$skipToken ?? r?.skipToken ?? undefined;
    } catch (e: any) {
      warnings.push(`Azure Resource Graph query failed: ${e?.message ?? e}`);
      break;
    }
  } while (skipToken && ++pages < MAX_PAGES);

  return { assets, warnings };
}
