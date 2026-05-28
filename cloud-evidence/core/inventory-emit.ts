/**
 * Inventory emitters + change-tracking (INV-18/19/21).
 *
 * The rich `InventorySnapshot` from `inventory-workbook.ts` is the source of
 * truth; these turn it into additional consumer formats and a run-over-run diff:
 *   - OSCAL `system-implementation` inventory-items (feeds the SSP pipeline)
 *   - ServiceNow-CMDB / CSDM-style CI records (enterprise CMDB ingest)
 *   - inventory-diff.json (added / removed / changed vs the previous run)
 *
 * Pure transforms + small fs read/write helpers. Read-only w.r.t. the cloud.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import type { CloudAsset, InventorySnapshot } from './inventory-workbook.ts';

// ---- INV-18: change tracking (diff vs previous run) ----

export interface InventoryDiff {
  generated_at: string;
  previous_count: number;
  current_count: number;
  added: string[];
  removed: string[];
  changed: Array<{ id: string; fields: string[] }>;
}

/** Scalar fields worth diffing for "changed" detection. */
const DIFF_FIELDS: Array<keyof CloudAsset> = [
  'state', 'publicFacing', 'osNameVersion', 'encryptionAtRest', 'kmsKeyId',
  'softwareDatabaseNameVersion', 'sizeGb', 'environment', 'systemOwner', 'endOfLife',
];

/** Diff two asset lists by uniqueId → added / removed / changed-field sets. */
export function diffInventory(prev: CloudAsset[], curr: CloudAsset[]): InventoryDiff {
  const prevById = new Map(prev.map((a) => [a.uniqueId, a]));
  const currById = new Map(curr.map((a) => [a.uniqueId, a]));
  const added: string[] = [];
  const removed: string[] = [];
  const changed: Array<{ id: string; fields: string[] }> = [];
  for (const id of currById.keys()) if (!prevById.has(id)) added.push(id);
  for (const id of prevById.keys()) if (!currById.has(id)) removed.push(id);
  for (const [id, c] of currById) {
    const p = prevById.get(id);
    if (!p) continue;
    const fields = DIFF_FIELDS.filter((f) => JSON.stringify(p[f] ?? null) !== JSON.stringify(c[f] ?? null));
    if (fields.length) changed.push({ id, fields: fields as string[] });
  }
  return {
    generated_at: new Date().toISOString(),
    previous_count: prev.length,
    current_count: curr.length,
    added: added.sort(),
    removed: removed.sort(),
    changed: changed.sort((a, b) => a.id.localeCompare(b.id)),
  };
}

/** Load the assets from a previous inventory.json snapshot (null if absent/bad). */
export function readPreviousInventory(path: string): CloudAsset[] | null {
  if (!existsSync(path)) return null;
  try {
    const snap = JSON.parse(readFileSync(path, 'utf8')) as InventorySnapshot;
    return Array.isArray(snap.assets) ? snap.assets : null;
  } catch { return null; }
}

// ---- INV-19: OSCAL system-implementation inventory-items ----

function stableUuid(seed: string): string {
  const h = createHash('sha256').update(seed).digest('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

export interface OscalInventoryItem {
  uuid: string;
  description: string;
  props: Array<{ name: string; value: string; ns?: string }>;
  'responsible-parties'?: Array<{ 'role-id': string; remarks?: string }>;
}

/** Project the inventory into OSCAL `inventory-item` objects (one per asset). */
export function assetsToOscalInventory(assets: CloudAsset[]): OscalInventoryItem[] {
  return assets.map((a) => {
    const props: OscalInventoryItem['props'] = [
      { name: 'asset-id', value: a.uniqueId },
      { name: 'asset-type', value: a.assetType ?? a.resourceType ?? 'unknown' },
      { name: 'cloud-provider', value: a.provider },
    ];
    if (a.resourceType) props.push({ name: 'resource-type', value: a.resourceType });
    if (a.accountId) props.push({ name: 'account', value: a.accountId });
    if (a.location) props.push({ name: 'location', value: a.location });
    if (a.ips?.length) props.push({ name: 'ipv4-address', value: a.ips[0]! });
    if (a.osNameVersion) props.push({ name: 'software-name', value: a.osNameVersion });
    if (a.publicFacing != null) props.push({ name: 'public', value: a.publicFacing ? 'yes' : 'no' });
    if (a.environment) props.push({ name: 'environment', value: a.environment });
    if (a.endOfLife) props.push({ name: 'end-of-life', value: a.endOfLife });
    const item: OscalInventoryItem = {
      uuid: stableUuid(a.uniqueId),
      description: `${a.assetType ?? a.resourceType ?? 'Cloud resource'}: ${a.function ?? a.uniqueId}`,
      props,
    };
    if (a.systemOwner) item['responsible-parties'] = [{ 'role-id': 'asset-owner', remarks: a.systemOwner }];
    return item;
  });
}

// ---- INV-21: ServiceNow CMDB / CSDM-style CI records ----

/** Map a cloud asset type to a ServiceNow CMDB CI class (CSDM-ish, best-effort). */
function cmdbClass(a: CloudAsset): string {
  const t = (a.assetType ?? a.resourceType ?? '').toLowerCase();
  if (/instance|compute|vm/.test(t)) return 'cmdb_ci_vm_instance';
  if (/bucket|storage|volume|disk/.test(t)) return 'cmdb_ci_storage_volume';
  if (/database|sql|dynamodb|table/.test(t)) return 'cmdb_ci_database';
  if (/load balancer|cdn|distribution/.test(t)) return 'cmdb_ci_lb';
  if (/cluster|kubernetes/.test(t)) return 'cmdb_ci_kubernetes_cluster';
  if (/function|serverless/.test(t)) return 'cmdb_ci_cloud_function';
  return 'cmdb_ci_cloud_resource';
}

export interface CmdbRecord {
  sys_class_name: string;
  name: string;
  object_id: string;
  ip_address?: string;
  fqdn?: string;
  cloud_provider: string;
  location?: string;
  environment?: string;
  owned_by?: string;
  install_status?: string;
  u_end_of_life?: string;
  discovery_source: string;
}

/** Project the inventory into ServiceNow-CMDB-ingestable CI records. */
export function assetsToCmdbRecords(assets: CloudAsset[]): CmdbRecord[] {
  return assets.map((a) => {
    const r: CmdbRecord = {
      sys_class_name: cmdbClass(a),
      name: a.function ?? a.uniqueId,
      object_id: a.uniqueId,
      cloud_provider: a.provider,
      discovery_source: 'FedPy cloud-evidence',
    };
    if (a.ips?.length) r.ip_address = a.ips[0]!;
    if (a.dns) r.fqdn = a.dns;
    if (a.location) r.location = a.location;
    if (a.environment) r.environment = a.environment;
    if (a.systemOwner) r.owned_by = a.systemOwner;
    if (a.state) r.install_status = a.state;
    if (a.endOfLife) r.u_end_of_life = a.endOfLife;
    return r;
  });
}

// ---- writers ----

export function writeInventoryOscal(snapshot: InventorySnapshot, path: string): number {
  const items = assetsToOscalInventory(snapshot.assets);
  writeFileSync(path, JSON.stringify({
    'inventory-items': items,
    metadata: { generated_at: snapshot.generated_at, asset_count: items.length, tool: 'fedramp-20x-cloud-evidence' },
  }, null, 2));
  return items.length;
}

export function writeInventoryCmdb(snapshot: InventorySnapshot, path: string): number {
  const records = assetsToCmdbRecords(snapshot.assets);
  writeFileSync(path, JSON.stringify({ records, generated_at: snapshot.generated_at, source: 'FedPy cloud-evidence' }, null, 2));
  return records.length;
}

export function writeInventoryDiff(diff: InventoryDiff, path: string): void {
  writeFileSync(path, JSON.stringify(diff, null, 2));
}
