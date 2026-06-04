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
    const macs: string[] = [];
    let publicFacing = false;
    for (const ni of data.networkInterfaces ?? []) {
      if (ni.networkIP) ips.push(ni.networkIP);
      // INV-S3: extract NIC MAC address (column G of the workbook). The
      // Compute Instance resource exposes it under `networkInterfaces[].macAddress`
      // and Cloud Asset Inventory passes it through verbatim.
      if (ni.macAddress) macs.push(ni.macAddress);
      for (const ac of ni.accessConfigs ?? []) if (ac.natIP) { ips.push(ac.natIP); publicFacing = true; }
    }
    const ni0 = (data.networkInterfaces ?? [])[0] ?? {};
    return {
      ...base,
      ips,
      macs: macs.length ? macs : undefined,
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

/**
 * INV-S3: OS Config inventory enrichment for Compute Engine instances.
 *
 * Closes columns F (NetBIOS Name for Windows hosts), K (OS Name and
 * Version), R (Patch Level). The OS Config API exposes a guest-OS
 * inventory per Compute instance with the kind of detail SSM Inventory
 * gives us on AWS: shortName + version + hostname + installed packages.
 *
 * Pattern: list inventories per zone, index by instance "name" (the bare
 * trailing path component), then fan out onto every Compute Instance
 * CloudAsset whose uniqueId tail matches.
 *
 * Required IAM: `roles/osconfig.inventoryViewer` (granular) or
 * `roles/compute.viewer` (broad).
 */
async function enrichWithOsConfig(project: string, assets: CloudAsset[], warnings: string[]): Promise<void> {
  // Skip the work entirely if no Compute instances were found — saves the
  // operator a permission-friction warning when their project doesn't use GCE.
  const instances = assets.filter((a) => a.resourceType === 'compute.googleapis.com/Instance');
  if (instances.length === 0) return;
  let osconfig: any;
  try {
    osconfig = await gcpAuth.googleClient<any>('osconfig', 'v1');
  } catch (e) {
    warnings.push(diagnoseGcpError(e, 'osconfig.client (OS inventory enrichment)', 'osconfig (roles/osconfig.inventoryViewer)'));
    return;
  }
  if (!osconfig?.projects?.locations?.instances?.inventories?.list) {
    // Older client builds: skip cleanly with a single warning instead of throwing.
    warnings.push('OS Config inventory: `osconfig.projects.locations.instances.inventories.list` not available in this client version; OS name/patch level cells stay blank.');
    return;
  }

  // OS Config inventories are listed per (project, location, instance) — but
  // the API accepts the wildcard `instances/-` to return every instance in
  // a location. Group instance assets by zone, then call once per zone.
  const byZone = new Map<string, CloudAsset[]>();
  for (const a of instances) {
    const zone = a.location ?? '-';
    if (!byZone.has(zone)) byZone.set(zone, []);
    byZone.get(zone)!.push(a);
  }

  for (const [zone, _zoneAssets] of byZone) {
    let pageToken: string | undefined; let pages = 0;
    try {
      do {
        const r = await osconfig.projects.locations.instances.inventories.list({
          parent: `projects/${project}/locations/${zone}/instances/-`,
          view: 'FULL',
          pageSize: 500,
          pageToken,
        });
        for (const inv of (r.data.inventories ?? []) as Array<any>) {
          // inv.name looks like
          //   projects/<num>/locations/<zone>/instances/<id>/inventory
          // We need the INSTANCE id to join to the asset; CAI's `name`
          // for compute instances is
          //   //compute.googleapis.com/projects/<num>/zones/<zone>/instances/<name>
          // and self-links also reference the id. Match on the tail of the
          // OS Config name (which is the instance numeric id) against the
          // CAI asset's `name` substring.
          const trail = String(inv.name ?? '').match(/instances\/([^/]+)\/inventory/);
          const instanceId = trail?.[1];
          if (!instanceId) continue;
          const target = instances.find((a) => a.uniqueId.includes(`/instances/${instanceId}`));
          if (!target) continue;
          const os = inv.osInfo ?? {};
          if (os.shortName || os.version) {
            target.osNameVersion = [os.shortName, os.version].filter(Boolean).join(' ').trim() || target.osNameVersion;
          }
          if (os.hostname && /windows/i.test(String(os.shortName ?? ''))) {
            // Column F (NetBIOS Name) — only meaningful for Windows hosts.
            (target as any).netbiosName = String(os.hostname);
          }
          // Patch-level proxy: count packages with available updates. If the
          // API reports "0 available", the box is current (Patch Level = "Current");
          // otherwise list the count so the operator sees the magnitude.
          const items = (inv.items ?? {}) as Record<string, any>;
          let pkgInstalled = 0; let pkgAvailable = 0;
          for (const it of Object.values(items)) {
            if (it?.type === 'INSTALLED_PACKAGE') pkgInstalled++;
            else if (it?.type === 'AVAILABLE_PACKAGE') pkgAvailable++;
          }
          if (pkgInstalled > 0 || pkgAvailable > 0) {
            target.patchLevel = pkgAvailable === 0
              ? `Current (${pkgInstalled} packages installed)`
              : `${pkgAvailable} update(s) available · ${pkgInstalled} packages installed`;
          }
          target.sourceApi = `${target.sourceApi ?? 'gcp-cloudasset'}+osconfig`;
        }
        pageToken = r.data.nextPageToken || undefined;
      } while (pageToken && ++pages < MAX_PAGES);
    } catch (e) {
      warnings.push(diagnoseGcpError(e, `osconfig.inventories.list ${zone}`, 'osconfig.inventories.list (roles/osconfig.inventoryViewer)'));
      // Continue with other zones rather than aborting the whole enrichment.
    }
  }
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
  // INV-S3: enrich Compute Instances with OS Config guest-inventory data.
  // Best-effort: any missing role / disabled service degrades to a warning,
  // not a hard failure.
  await enrichWithOsConfig(project, assets, warnings);
  return { assets, warnings };
}
