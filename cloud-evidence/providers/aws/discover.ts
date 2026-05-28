/**
 * AWS generic resource-discovery backbone for the inventory (INV-7).
 *
 * Gives BREADTH — every resource type, not a hand-written list — by riding the
 * account's resource-graph APIs, in preference order:
 *   1. **AWS Config Advanced Query** (`SelectResourceConfig`) — SQL over every
 *      Config-recorded type; the richest generic source.
 *   2. **Resource Explorer** (`Search`) — fallback when Config isn't recording;
 *      no query language, but capped at 1,000 results per query.
 *   3. **Resource Groups Tagging API** (`GetResources`) — merged in to fill tags.
 *
 * Each returns a *baseline* `CloudAsset` (id/type/name/region/tags/created); the
 * per-service depth enrichers in `inventory-assets.ts` then upgrade high-value
 * types, and `dedupeAssets` merges the two. Read-only (guardrail-wrapped clients).
 * Pure mappers are exported for unit testing.
 */
import { SelectResourceConfigCommand } from '@aws-sdk/client-config-service';
import { SearchCommand } from '@aws-sdk/client-resource-explorer-2';
import { GetResourcesCommand } from '@aws-sdk/client-resource-groups-tagging-api';
import * as aws from '../../core/auth/aws.ts';
import type { CloudAsset } from '../../core/inventory-workbook.ts';

const MAX_PAGES = 200;

export interface AwsDiscoverResult { assets: CloudAsset[]; warnings: string[]; method: 'config' | 'resource-explorer' | 'none'; }

/** "AWS::EC2::Instance" → "Instance" (friendly fallback assetType). */
export function friendlyAwsType(awsType: string | undefined): string | null {
  if (!awsType) return null;
  const seg = awsType.split('::').pop() ?? awsType;
  // CamelCase → spaced words
  return seg.replace(/([a-z0-9])([A-Z])/g, '$1 $2');
}

/** Parse one AWS Config `SelectResourceConfig` JSON result row → CloudAsset. */
export function configRowToAsset(row: any, account: string | null): CloudAsset | null {
  if (!row || (!row.arn && !row.resourceId)) return null;
  const tags: Record<string, string> = {};
  for (const t of row.tags ?? []) if (t?.key || t?.tag) tags[t.key ?? t.tag] = t.value ?? '';
  return {
    provider: 'aws',
    uniqueId: row.arn ?? `${row.resourceType}/${row.resourceId}`,
    resourceType: row.resourceType ?? null,
    assetType: friendlyAwsType(row.resourceType),
    location: row.availabilityZone ?? row.awsRegion ?? null,
    createdAt: row.resourceCreationTime ?? null,
    function: row.resourceName ?? null,
    accountId: account,
    virtual: true,
    tags: Object.keys(tags).length ? tags : undefined,
    sourceApi: 'aws-config-advanced-query',
  };
}

/** Map one Resource Explorer search result → CloudAsset. */
export function resourceExplorerToAsset(r: any): CloudAsset | null {
  if (!r?.Arn) return null;
  return {
    provider: 'aws',
    uniqueId: r.Arn,
    resourceType: r.ResourceType ?? null,
    assetType: friendlyAwsType(r.ResourceType),
    location: r.Region ?? null,
    accountId: r.OwningAccountId ?? null,
    virtual: true,
    sourceApi: 'aws-resource-explorer',
  };
}

/**
 * Discover all AWS resources for one region via the backbone (Config → Resource
 * Explorer), then merge in tags from the Tagging API. Best-effort: any source
 * that isn't enabled/permitted degrades to a warning.
 */
export async function discoverAwsAssets(auth: aws.AwsAuth, account: string | null): Promise<AwsDiscoverResult> {
  const warnings: string[] = [];
  let assets: CloudAsset[] = [];
  let method: AwsDiscoverResult['method'] = 'none';

  // 1) AWS Config Advanced Query
  try {
    const cfg = aws.configService(auth);
    const expr = 'SELECT resourceId, resourceName, resourceType, awsRegion, availabilityZone, arn, resourceCreationTime, tags';
    let token: string | undefined; let pages = 0;
    do {
      const r = await cfg.send(new SelectResourceConfigCommand({ Expression: expr, Limit: 100, NextToken: token }));
      for (const s of r.Results ?? []) {
        try { const a = configRowToAsset(JSON.parse(s), account); if (a) assets.push(a); } catch { /* skip bad row */ }
      }
      token = r.NextToken && r.NextToken !== token ? r.NextToken : undefined;
    } while (token && ++pages < MAX_PAGES);
    if (assets.length > 0) method = 'config';
  } catch (e: any) {
    warnings.push(`Config advanced query (config:SelectResourceConfig): ${e.message}`);
  }

  // 2) Resource Explorer fallback (only if Config produced nothing)
  if (assets.length === 0) {
    try {
      const rex = aws.resourceExplorer(auth);
      let token: string | undefined; let pages = 0;
      do {
        const r = await rex.send(new SearchCommand({ QueryString: '*', MaxResults: 100, NextToken: token }));
        for (const res of r.Resources ?? []) { const a = resourceExplorerToAsset(res); if (a) assets.push(a); }
        token = r.NextToken && r.NextToken !== token ? r.NextToken : undefined;
      } while (token && ++pages < MAX_PAGES);
      if (assets.length > 0) method = 'resource-explorer';
    } catch (e: any) {
      warnings.push(`Resource Explorer (resource-explorer-2:Search): ${e.message}`);
    }
  }

  // 3) Merge tags from the Tagging API (best-effort) onto assets that lack them.
  if (assets.length > 0) {
    try {
      const tagApi = aws.taggingApi(auth);
      const byArn = new Map(assets.map((a) => [a.uniqueId, a]));
      let token: string | undefined; let pages = 0;
      do {
        const r = await tagApi.send(new GetResourcesCommand({ PaginationToken: token, ResourcesPerPage: 100 }));
        for (const m of r.ResourceTagMappingList ?? []) {
          const a = m.ResourceARN ? byArn.get(m.ResourceARN) : undefined;
          if (!a || a.tags) continue;
          const tags: Record<string, string> = {};
          for (const t of m.Tags ?? []) if (t.Key) tags[t.Key] = t.Value ?? '';
          if (Object.keys(tags).length) a.tags = tags;
        }
        token = r.PaginationToken && r.PaginationToken !== token ? r.PaginationToken : undefined;
      } while (token && ++pages < MAX_PAGES);
    } catch (e: any) {
      warnings.push(`Tagging API (tag:GetResources): ${e.message}`);
    }
  }

  const now = new Date().toISOString();
  for (const a of assets) { a.collectedAt ??= now; a.accountId ??= account; }
  return { assets, warnings, method };
}
