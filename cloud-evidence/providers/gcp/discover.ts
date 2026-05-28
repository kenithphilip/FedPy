/**
 * GCP generic resource-discovery backbone for the inventory (INV-8).
 *
 * BREADTH via Cloud Asset Inventory `searchAllResources` — returns *every*
 * resource type in the project (broader than the curated `assets.list` set in
 * `inventory-assets.ts`, which stays for depth on compute/SQL/etc.). `dedupeAssets`
 * merges the shallow-broad rows with the deep-narrow ones. Read-only via the GCP
 * Proxy guardrail. Pure mapper exported for tests.
 */
import * as gcpAuth from '../../core/auth/gcp.ts';
import { diagnoseGcpError } from '../../core/error-diagnostics.ts';
import type { CloudAsset } from '../../core/inventory-workbook.ts';

const MAX_PAGES = 400;

export interface GcpDiscoverResult { assets: CloudAsset[]; warnings: string[]; }

/** Map a CAI `searchAllResources` result → CloudAsset. */
export function searchResultToAsset(r: any, project: string): CloudAsset {
  const labels = (r.labels && typeof r.labels === 'object') ? r.labels as Record<string, string> : undefined;
  const friendly = (r.assetType ? String(r.assetType).split('/').pop() : null) ?? null;
  return {
    provider: 'gcp',
    uniqueId: r.name,
    resourceType: r.assetType ?? null,
    assetType: friendly,
    location: r.location ?? null,
    createdAt: r.createTime ?? null,
    lastModifiedAt: r.updateTime ?? null,
    state: r.state ?? null,
    kmsKeyId: r.kmsKey ?? (Array.isArray(r.kmsKeys) ? r.kmsKeys[0] : null) ?? null,
    function: r.displayName ?? null,
    accountId: r.project ? String(r.project).replace(/^projects\//, '') : project,
    virtual: true,
    tags: labels && Object.keys(labels).length ? labels : undefined,
    sourceApi: 'gcp-cai-search',
  };
}

/** Discover all GCP resources in a project via CAI searchAllResources. */
export async function discoverGcpAssets(project: string): Promise<GcpDiscoverResult> {
  const assets: CloudAsset[] = [];
  const warnings: string[] = [];
  try {
    const ca = await gcpAuth.googleClient<any>('cloudasset', 'v1');
    if (!ca.v1?.searchAllResources) {
      warnings.push('Cloud Asset Inventory searchAllResources not available in this client version.');
      return { assets, warnings };
    }
    let pageToken: string | undefined; let pages = 0;
    do {
      const r = await ca.v1.searchAllResources({ scope: `projects/${project}`, pageSize: 500, pageToken });
      for (const res of r.data.results ?? []) {
        if (!res.name) continue;
        assets.push(searchResultToAsset(res, project));
      }
      pageToken = r.data.nextPageToken || undefined;
    } while (pageToken && ++pages < MAX_PAGES);
  } catch (e) {
    warnings.push(diagnoseGcpError(e, 'cloudasset.v1.searchAllResources (inventory backbone)', 'cloudasset.assets.searchAllResources (roles/cloudasset.viewer)'));
  }
  return { assets, warnings };
}
