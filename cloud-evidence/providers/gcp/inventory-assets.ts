/**
 * GCP asset enumeration for the FedRAMP Integrated Inventory Workbook.
 *
 * Read-only: uses Cloud Asset Inventory (`cloudasset.assets.list`, contentType
 * RESOURCE) — one API that returns every in-scope resource with metadata — and
 * normalizes a curated set of asset types to `CloudAsset` rows for
 * `core/inventory-workbook.ts`. Distinct from `inventory.ts` (KSI-PIY-GIV), which
 * only checks that the inventory *mechanism* (CAI) is reachable.
 *
 * Field mapping is clean-room, informed by the Apache-2.0 reference design
 * `google/asset-inventory-worksheet` (see research report 06 / 00-INDEX).
 * The googleapis client is wrapped by the GCP read-only Proxy guardrail.
 */
import * as gcpAuth from '../../core/auth/gcp.ts';
import { diagnoseGcpError } from '../../core/error-diagnostics.ts';
import type { CloudAsset } from '../../core/inventory-workbook.ts';

const MAX_PAGES = 200;

/** Curated CAI asset types worth putting in an inventory workbook. */
const ASSET_TYPES = [
  'compute.googleapis.com/Instance',
  'compute.googleapis.com/Disk',
  'compute.googleapis.com/ForwardingRule',
  'compute.googleapis.com/Address',
  'storage.googleapis.com/Bucket',
  'sqladmin.googleapis.com/Instance',
  'run.googleapis.com/Service',
  'container.googleapis.com/Cluster',
  'cloudfunctions.googleapis.com/Function',
];

const FRIENDLY: Record<string, string> = {
  'compute.googleapis.com/Instance': 'Compute Instance',
  'compute.googleapis.com/Disk': 'Storage Volume',
  'compute.googleapis.com/ForwardingRule': 'Load Balancer',
  'compute.googleapis.com/Address': 'IP Address',
  'storage.googleapis.com/Bucket': 'Object Storage Bucket',
  'sqladmin.googleapis.com/Instance': 'Database',
  'run.googleapis.com/Service': 'Serverless Service',
  'container.googleapis.com/Cluster': 'Kubernetes Cluster',
  'cloudfunctions.googleapis.com/Function': 'Serverless Function',
};

export interface GcpAssetResult { assets: CloudAsset[]; warnings: string[]; }

/** Last path segment of a GCP resource URL (e.g. machineType, zone). */
function tail(url: string | undefined | null): string | null {
  if (!url) return null;
  const s = String(url);
  const i = s.lastIndexOf('/');
  return i >= 0 ? s.slice(i + 1) : s;
}

function mapAsset(assetType: string, name: string, data: any, resourceLocation: string | null): CloudAsset {
  const base: CloudAsset = {
    provider: 'gcp',
    uniqueId: name,
    resourceType: assetType,
    virtual: true,
    assetType: FRIENDLY[assetType] ?? (tail(assetType) ?? assetType),
    location: resourceLocation,
  };
  if (!data || typeof data !== 'object') return base;

  if (assetType === 'compute.googleapis.com/Instance') {
    const ips: string[] = [];
    let publicFacing = false;
    for (const ni of data.networkInterfaces ?? []) {
      if (ni.networkIP) ips.push(ni.networkIP);
      for (const ac of ni.accessConfigs ?? []) if (ac.natIP) { ips.push(ac.natIP); publicFacing = true; }
    }
    const ni0 = (data.networkInterfaces ?? [])[0] ?? {};
    return {
      ...base,
      ips,
      publicFacing,
      location: tail(data.zone) ?? resourceLocation,
      hardwareMakeModel: `GCP ${tail(data.machineType) ?? ''}`.trim(),
      vlanNetworkId: [tail(data.networkInterfaces?.[0]?.network), tail(ni0.subnetwork)].filter(Boolean).join('/') || null,
      function: data.name ?? null,
    };
  }
  if (assetType === 'compute.googleapis.com/Disk') {
    return { ...base, location: tail(data.zone) ?? resourceLocation, hardwareMakeModel: `GCP ${tail(data.type) ?? 'PersistentDisk'}`, function: data.name ?? null };
  }
  if (assetType === 'storage.googleapis.com/Bucket') {
    return { ...base, location: (data.location ?? resourceLocation ?? null), function: data.name ?? null };
  }
  if (assetType === 'sqladmin.googleapis.com/Instance') {
    const ips = (data.ipAddresses ?? []).map((a: any) => a.ipAddress).filter(Boolean);
    return {
      ...base,
      ips,
      publicFacing: (data.settings?.ipConfiguration?.ipv4Enabled === true),
      location: data.region ?? resourceLocation,
      softwareDatabaseVendor: 'Google Cloud SQL',
      softwareDatabaseNameVersion: data.databaseVersion ?? null,
      function: data.name ?? null,
    };
  }
  if (assetType === 'run.googleapis.com/Service' || assetType === 'cloudfunctions.googleapis.com/Function') {
    return { ...base, dns: data.uri ?? null, publicFacing: Boolean(data.uri), location: resourceLocation, function: tail(name) };
  }
  if (assetType === 'container.googleapis.com/Cluster') {
    return { ...base, dns: data.endpoint ?? null, location: data.location ?? resourceLocation, softwareDatabaseNameVersion: data.currentMasterVersion ?? null, function: data.name ?? null };
  }
  if (assetType === 'compute.googleapis.com/ForwardingRule') {
    return { ...base, ips: data.IPAddress ? [data.IPAddress] : undefined, publicFacing: data.loadBalancingScheme === 'EXTERNAL' || data.loadBalancingScheme === 'EXTERNAL_MANAGED', location: tail(data.region) ?? resourceLocation, function: data.name ?? null };
  }
  if (assetType === 'compute.googleapis.com/Address') {
    return { ...base, ips: data.address ? [data.address] : undefined, publicFacing: data.addressType === 'EXTERNAL', location: tail(data.region) ?? resourceLocation, function: data.name ?? null };
  }
  return base;
}

/** Enumerate GCP assets for a project via Cloud Asset Inventory. */
export async function collectGcpAssets(project: string): Promise<GcpAssetResult> {
  const assets: CloudAsset[] = [];
  const warnings: string[] = [];
  try {
    const ca = await gcpAuth.googleClient<any>('cloudasset', 'v1');
    let pageToken: string | undefined; let pages = 0;
    do {
      const r = await ca.assets.list({
        parent: `projects/${project}`,
        contentType: 'RESOURCE',
        assetTypes: ASSET_TYPES,
        pageSize: 500,
        pageToken,
      });
      for (const a of r.data.assets ?? []) {
        if (!a.name || !a.assetType) continue;
        const asset = mapAsset(a.assetType, a.name, a.resource?.data, a.resource?.location ?? null);
        asset.accountId = project;
        asset.collectedAt = new Date().toISOString();
        asset.sourceApi = 'gcp-cloudasset';
        assets.push(asset);
      }
      pageToken = r.data.nextPageToken || undefined;
    } while (pageToken && ++pages < MAX_PAGES);
  } catch (e) {
    warnings.push(diagnoseGcpError(e, 'cloudasset.assets.list (inventory workbook)', 'cloudasset.assets.list (roles/cloudasset.viewer)'));
  }
  return { assets, warnings };
}
