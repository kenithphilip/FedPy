/**
 * FedRAMP Integrated Inventory Workbook coverage contract.
 *
 * The structural fix to a real failure mode: a column quietly stops being
 * populated for one cloud (a provider rewrite, a new asset type, a renamed
 * field) and nobody notices because "blank" looks correct. This registry
 * makes every cell's fill source explicit, per cloud, and the runtime
 * report + tests assert against the registry — so a regression is loud.
 *
 * Each entry documents:
 *   - the FedRAMP column header (exact, matching Appendix M template);
 *   - the `CloudAsset` field that backs it (in `core/inventory-workbook.ts`);
 *   - the per-provider data source for that field (the API + property path);
 *   - the fill status today (filled / partial / not-yet / operator-only);
 *   - a `blank_reason` IFF the cell is intentionally left blank.
 *
 * Per-run, `inventory-coverage-report.ts` projects the actual snapshot
 * against this registry and emits `out/inventory-coverage.json` so the
 * operator + CI see exactly which cells filled, for which asset types,
 * with which proportion. CI may assert "no cell that was previously
 * filled is now blank" to catch silent regressions.
 *
 * THIS FILE IS THE SOURCE OF TRUTH FOR THE ANSWER TO
 * "is column X populated for cloud Y, and from what API?"
 */
import type { CloudAsset } from './inventory-workbook.ts';
import { APPENDIX_M_COLUMNS } from './inventory-workbook.ts';

export type CoverageStatus =
  | 'filled'           // populated from a cloud API for every (or nearly every) asset of the relevant kind
  | 'partial'          // populated for some asset kinds; some leave blank
  | 'tag-based'        // filled from a resource tag (`owner`, `eol_date`, etc.) — only when operator has tagged
  | 'operator-only'    // FedRAMP-defined as operator-supplied; we do NOT auto-fill (or only via explicit tag override)
  | 'not-yet';         // we know how to fill it but haven't shipped the enricher yet — slice tracked below

export interface ColumnSource {
  /** Brief human description of the API + property path. */
  description: string;
  /** Read-only API endpoint or KQL/SQL table the source rides. */
  api: string;
  /** Hard-line status. */
  status: CoverageStatus;
  /** The slice id that is intended to (or did) make this 'filled'. */
  shippedIn?: string;
}

export interface CoverageEntry {
  /** Column header text exactly as it appears on the FedRAMP template. */
  column: string;
  /** Key on `CloudAsset` (in `inventory-workbook.ts`) that backs this cell. */
  assetField: keyof CloudAsset | '(synthetic)';
  /** When non-null, the cell is intentionally blank — the reason is operator-discretion / template-design. */
  blankReason: string | null;
  /** Per-provider fill plan + status. */
  sources: {
    aws: ColumnSource;
    gcp: ColumnSource;
    azure: ColumnSource;
  };
}

const filled = (description: string, api: string, shippedIn?: string): ColumnSource =>
  ({ description, api, status: 'filled', shippedIn });
const partial = (description: string, api: string, shippedIn?: string): ColumnSource =>
  ({ description, api, status: 'partial', shippedIn });
const tagBased = (description: string, api: string): ColumnSource =>
  ({ description, api, status: 'tag-based' });
const notYet = (description: string, api: string, plannedIn: string): ColumnSource =>
  ({ description, api, status: 'not-yet', shippedIn: plannedIn });
const operatorOnly = (description: string): ColumnSource =>
  ({ description, api: '(none)', status: 'operator-only' });

/**
 * The 25-column registry. Order matches APPENDIX_M_COLUMNS exactly; a
 * runtime check below asserts that invariant so a column-order edit in
 * `inventory-workbook.ts` can never silently mis-align the contract.
 */
export const COVERAGE_REGISTRY: readonly CoverageEntry[] = [
  {
    column: 'Unique Asset Identifier', assetField: 'uniqueId', blankReason: null,
    sources: {
      aws:   filled('ARN', 'sts:GetCallerIdentity + per-service ARN', 'INV-1..4'),
      gcp:   filled('resource self-link (`name`)', 'cloudasset.assets.list', 'INV-1..4'),
      azure: filled('resource id', 'Azure Resource Graph `Resources` table', 'AZ-1'),
    },
  },
  {
    column: 'IPv4 or IPv6 Address', assetField: 'ips', blankReason: null,
    sources: {
      aws:   filled('EC2 NetworkInterfaces + ELB / RDS endpoint IPs', 'ec2:DescribeInstances + rds:DescribeDBInstances', 'INV-1..4'),
      gcp:   filled('Instance.networkInterfaces + SQL ipAddresses', 'cloudasset.assets.list', 'INV-1..4'),
      azure: filled('VM NIC private IPs + public-IP resource lookup + LB/AGW frontend IPs', 'Azure Resource Graph KQL (`microsoft.network/networkinterfaces`, `publicipaddresses`)', 'INV-S2'),
    },
  },
  {
    column: 'Virtual', assetField: 'virtual', blankReason: null,
    sources: {
      aws:   filled('hardcoded true (all cloud assets are virtual)', '(none)', 'INV-1..4'),
      gcp:   filled('hardcoded true', '(none)', 'INV-1..4'),
      azure: filled('hardcoded true', '(none)', 'AZ-1'),
    },
  },
  {
    column: 'Public', assetField: 'publicFacing', blankReason: null,
    sources: {
      aws:   filled('S3 PublicAccessBlock + security-group ingress 0.0.0.0/0 + CloudFront/ELB scheme', 's3:GetPublicAccessBlock + ec2:DescribeSecurityGroups', 'INV-1..4'),
      gcp:   filled('Instance external IP + LB scheme EXTERNAL', 'cloudasset.assets.list (Instance.networkInterfaces.accessConfigs)', 'INV-1..4'),
      azure: filled('Resource Graph `properties.publicNetworkAccess` + storage `allowBlobPublicAccess`', 'Azure Resource Graph KQL', 'AZ-1'),
    },
  },
  {
    column: 'DNS Name or URL', assetField: 'dns', blankReason: null,
    sources: {
      aws:   filled('ELB DNSName, CloudFront DomainName, API Gateway invoke URL', 'elbv2:DescribeLoadBalancers + cloudfront:ListDistributions', 'INV-1..4'),
      gcp:   filled('Cloud Run uri, GKE endpoint, Cloud Functions uri', 'cloudasset.assets.list', 'INV-1..4'),
      azure: filled('Application Gateway frontend, App Service `defaultHostName`, Function Apps, AKS fqdn, Cosmos endpoint, ACR loginServer, Key Vault vaultUri, Azure SQL fqdn', 'Azure Resource Graph KQL per type', 'INV-S2'),
    },
  },
  {
    column: 'NetBIOS Name', assetField: 'netbiosName', blankReason: null,
    sources: {
      aws:   notYet('SSM Inventory `AWS:InstanceInformation.ComputerName` (Windows hosts)', 'ssm:GetInventory', 'INV-S3-aws-supplement'),
      gcp:   filled('OS Config inventory `osInfo.hostname` (Windows hosts)', 'osconfig.inventories.list', 'INV-S3'),
      azure: filled('Resource Graph `properties.osProfile.computerName` (Windows VMs; Linux hostname best-effort)', 'Azure Resource Graph KQL', 'INV-S4'),
    },
  },
  {
    column: 'MAC Address', assetField: 'macs', blankReason: null,
    sources: {
      aws:   filled('EC2 NetworkInterfaces.MacAddress', 'ec2:DescribeInstances', 'INV-1..4'),
      gcp:   filled('Instance.networkInterfaces[].macAddress passed through by Cloud Asset Inventory', 'cloudasset.assets.list', 'INV-S3'),
      azure: filled('Resource Graph `microsoft.network/networkinterfaces.macAddress`', 'Azure Resource Graph KQL', 'INV-S2'),
    },
  },
  {
    column: 'Authenticated Scan', assetField: 'authenticatedScan', blankReason: null,
    sources: {
      aws:   filled('Inspector v2 findings (always authenticated/agent-based)', 'inspector2:ListFindings', 'P5a'),
      gcp:   filled('Container Analysis occurrences + GCE OS scanning', 'containeranalysis.occurrences.list', 'P5a'),
      azure: filled('Defender for Cloud assessments (agent-based via Azure Monitor Agent), surfaced via `assessed_resource_ids` evidence and reconciled by `core/inventory-workbook.ts:reconcileScans`', 'Azure Resource Graph `securityresources`', 'INV-S5'),
    },
  },
  {
    column: 'Baseline Configuration Name', assetField: 'baselineConfig', blankReason: null,
    sources: {
      aws:   tagBased('Resource tag `baseline` / `baseline_config` / `stig`', 'tag:GetResources'),
      gcp:   tagBased('Resource label `baseline`', 'cloudasset.assets.list'),
      azure: tagBased('Resource Graph `tags.baseline`', 'Azure Resource Graph KQL'),
    },
  },
  {
    column: 'OS Name and Version', assetField: 'osNameVersion', blankReason: null,
    sources: {
      aws:   filled('SSM Inventory `AWS:InstanceInformation.PlatformName + PlatformVersion`', 'ssm:GetInventory', 'INV-1..4'),
      gcp:   filled('OS Config inventory `osInfo.shortName + osInfo.version`', 'osconfig.inventories.list', 'INV-S3'),
      azure: filled('Resource Graph `patchassessmentresources.osName + osVersion` (live assessed OS) with fallback to `imageReference.{publisher,offer,sku,version}` for VMs without active assessment', 'Azure Resource Graph KQL', 'INV-S4'),
    },
  },
  {
    column: 'Location', assetField: 'location', blankReason: null,
    sources: {
      aws:   filled('region or availability zone', 'all AWS APIs', 'INV-1..4'),
      gcp:   filled('zone/region from CAI `resource.location`', 'cloudasset.assets.list', 'INV-1..4'),
      azure: filled('Resource Graph `location`', 'Azure Resource Graph', 'AZ-1'),
    },
  },
  {
    column: 'Asset Type', assetField: 'assetType', blankReason: null,
    sources: {
      aws:   filled('friendly name derived from resource type (e.g. "Instance")', 'core/inventory-workbook.ts mapping', 'INV-1..4'),
      gcp:   filled('friendly name from CAI assetType', 'core/inventory-workbook.ts mapping', 'INV-1..4'),
      azure: filled('friendly name from Resource Graph `type`', 'core/inventory-workbook.ts mapping', 'AZ-1'),
    },
  },
  {
    column: 'Hardware Make/Model', assetField: 'hardwareMakeModel', blankReason: null,
    sources: {
      aws:   filled('EC2 InstanceType (e.g. "t3.large")', 'ec2:DescribeInstances', 'INV-1..4'),
      gcp:   filled('Instance.machineType', 'cloudasset.assets.list', 'INV-1..4'),
      azure: filled('VM vmSize, AKS node-pool sizes, SQL Database tier+capacity, Application Gateway tier, Load Balancer SKU, Managed Disk tier', 'Azure Resource Graph KQL per type', 'INV-S2'),
    },
  },
  {
    column: 'In Latest Scan', assetField: 'inLatestScan', blankReason: null,
    sources: {
      aws:   filled('VDR scan reconcile via `reconcileScans()`', 'inspector2:ListFindings', 'P5a'),
      gcp:   filled('VDR scan reconcile via `reconcileScans()`', 'containeranalysis.occurrences.list', 'P5a'),
      azure: filled('Defender assessment id → assessed resource id reconcile via `assessed_resource_ids` evidence + `reconcileScans`', 'Azure Resource Graph `securityresources`', 'INV-S5'),
    },
  },
  {
    column: 'Software/Database Vendor', assetField: 'softwareDatabaseVendor', blankReason: null,
    sources: {
      aws:   filled('RDS engine vendor (e.g. "Amazon", "PostgreSQL")', 'rds:DescribeDBInstances', 'INV-1..4'),
      gcp:   filled('Cloud SQL databaseVersion → vendor', 'cloudasset.assets.list', 'INV-1..4'),
      azure: filled('Azure SQL, Cosmos DB, AKS, App Service, ACR, Key Vault → vendor strings', 'Azure Resource Graph KQL per type', 'INV-S2'),
    },
  },
  {
    column: 'Software/Database Name & Version', assetField: 'softwareDatabaseNameVersion', blankReason: null,
    sources: {
      aws:   filled('RDS engine + engineVersion', 'rds:DescribeDBInstances', 'INV-1..4'),
      gcp:   filled('Cloud SQL databaseVersion', 'cloudasset.assets.list', 'INV-1..4'),
      azure: filled('Azure SQL version, Cosmos kind, AKS k8s version, App Service runtime, ACR sku, Key Vault sku, AGW SSL policy', 'Azure Resource Graph KQL per type', 'INV-S2'),
    },
  },
  {
    column: 'Patch Level', assetField: 'patchLevel', blankReason: null,
    sources: {
      aws:   filled('SSM Patch Manager patch-baseline + missing-patch count', 'ssm:GetInventory', 'INV-1..4'),
      gcp:   filled('OS Config inventory installed/available package counts → "Current" or "<N> updates available"', 'osconfig.inventories.list', 'INV-S3'),
      azure: filled('Resource Graph `patchassessmentresources.lastAssessmentResult` + missing-patch count', 'Azure Resource Graph KQL', 'INV-S4'),
    },
  },
  {
    column: 'Diagram Label', assetField: 'diagramLabel', blankReason: null,
    sources: {
      aws:   filled('Auto-synthesized as `<friendly-type>-<name>@<location>`; overridden by tag `diagram_label` / `DiagramLabel` / `inventory_label` / `fedramp_label`', 'core/inventory-workbook.ts:applyDiagramLabelAndComments', 'INV-S6'),
      gcp:   filled('Auto-synthesized as `<friendly-type>-<name>@<location>`; overridden by label `diagram_label`', 'core/inventory-workbook.ts:applyDiagramLabelAndComments', 'INV-S6'),
      azure: filled('Auto-synthesized as `<friendly-type>-<name>@<location>`; overridden by tag `diagram_label`', 'core/inventory-workbook.ts:applyDiagramLabelAndComments', 'INV-S6'),
    },
  },
  {
    column: 'Comments', assetField: 'comments',
    blankReason: 'FedRAMP Appendix M defines Comments as operator-supplied free-text. We populate ONLY when the operator sets an `inventory_comments` tag/label — otherwise the cell stays blank (the operator fills it in the SSP package).',
    sources: {
      aws:   operatorOnly('Tag `inventory_comments` (set by operator) — otherwise intentionally blank'),
      gcp:   operatorOnly('Label `inventory_comments` (set by operator) — otherwise intentionally blank'),
      azure: operatorOnly('Tag `inventory_comments` (set by operator) — otherwise intentionally blank'),
    },
  },
  {
    column: 'Serial #/Asset Tag#', assetField: 'uniqueId', blankReason: null,
    sources: {
      aws:   filled('ARN (reused from Unique Asset Identifier per template guidance)', '(reused)', 'INV-1..4'),
      gcp:   filled('self-link (reused)', '(reused)', 'INV-1..4'),
      azure: filled('resource id (reused)', '(reused)', 'AZ-1'),
    },
  },
  {
    column: 'VLAN/Network ID', assetField: 'vlanNetworkId', blankReason: null,
    sources: {
      aws:   filled('VPC id + Subnet id', 'ec2:DescribeInstances + ec2:DescribeVpcs', 'INV-1..4'),
      gcp:   filled('network + subnetwork', 'cloudasset.assets.list', 'INV-1..4'),
      azure: filled('vnet/subnet path resolved from each VM\'s NIC ipConfigurations[0].subnet.id', 'Azure Resource Graph KQL', 'INV-S2'),
    },
  },
  {
    column: 'System Administrator/Owner', assetField: 'systemOwner', blankReason: null,
    sources: {
      aws:   tagBased('Tag `owner` / `system_admin` / `sys_admin`', 'tag:GetResources'),
      gcp:   tagBased('Label `owner`', 'cloudasset.assets.list'),
      azure: tagBased('Tag `owner`', 'Azure Resource Graph'),
    },
  },
  {
    column: 'Application Administrator/Owner', assetField: 'applicationOwner', blankReason: null,
    sources: {
      aws:   tagBased('Tag `app_owner` / `application_owner`', 'tag:GetResources'),
      gcp:   tagBased('Label `app_owner`', 'cloudasset.assets.list'),
      azure: tagBased('Tag `app_owner`', 'Azure Resource Graph'),
    },
  },
  {
    column: 'Function', assetField: 'function', blankReason: null,
    sources: {
      aws:   filled('Name tag or resource name', 'all AWS APIs', 'INV-1..4'),
      gcp:   filled('resource displayName / name', 'cloudasset.assets.list', 'INV-1..4'),
      azure: filled('resource name from Resource Graph', 'Azure Resource Graph', 'AZ-1'),
    },
  },
  {
    column: 'End-of-Life', assetField: 'endOfLife', blankReason: null,
    sources: {
      aws:   tagBased('Tag `eol_date` (operator-supplied per asset)', 'tag:GetResources'),
      gcp:   tagBased('Label `eol_date`', 'cloudasset.assets.list'),
      azure: tagBased('Tag `eol_date`', 'Azure Resource Graph'),
    },
  },
] as const;

// ---------------------------------------------------------------------------
// Invariants — these run at module load to make a mis-aligned registry fail
// loudly in `import` (no need for a separate "is the registry sane" test).
// ---------------------------------------------------------------------------
if (COVERAGE_REGISTRY.length !== APPENDIX_M_COLUMNS.length) {
  throw new Error(
    `inventory-coverage: registry has ${COVERAGE_REGISTRY.length} entries but APPENDIX_M_COLUMNS has ${APPENDIX_M_COLUMNS.length}`,
  );
}
for (let i = 0; i < COVERAGE_REGISTRY.length; i++) {
  const reg = COVERAGE_REGISTRY[i]!;
  const col = APPENDIX_M_COLUMNS[i]!;
  if (reg.column !== col.header) {
    throw new Error(`inventory-coverage: order mismatch at index ${i}: registry="${reg.column}" vs columns="${col.header}"`);
  }
}

// ---------------------------------------------------------------------------
// Helpers for the per-run report.
// ---------------------------------------------------------------------------

export type Provider = 'aws' | 'gcp' | 'azure';

/**
 * Detects whether a `CloudAsset` field is populated for a given asset.
 * Treats undefined / null / "" / [] as blank; everything else as filled.
 * Synthetic fields (Diagram Label, NetBIOS Name pre-S3) report blank until
 * the slice that fills them lands.
 */
export function isCellFilled(asset: CloudAsset, entry: CoverageEntry): boolean {
  const f = entry.assetField;
  if (f === '(synthetic)') {
    // Synthetic fields are not on CloudAsset yet; treat as blank for now.
    // S6 introduces `diagramLabel` and S3/S4 introduce `netbiosName` on CloudAsset.
    // Until then, the registry status drives the report; we don't auto-fill.
    return false;
  }
  const v = (asset as unknown as Record<string, unknown>)[f];
  if (v === undefined || v === null) return false;
  if (typeof v === 'string' && v.trim() === '') return false;
  if (Array.isArray(v) && v.length === 0) return false;
  return true;
}

export interface ColumnCoverage {
  column: string;
  /** Total assets per cloud. */
  total: Record<Provider, number>;
  /** Filled count per cloud. */
  filled: Record<Provider, number>;
  /** % filled per cloud (0–1). 1.0 = every asset of this cloud has the cell populated. */
  fillRate: Record<Provider, number>;
  /** Registry status per cloud. */
  status: Record<Provider, CoverageStatus>;
  /** When the cell is intentionally blank. */
  blankReason: string | null;
}

export interface CoverageReport {
  generated_at: string;
  schema_version: 1;
  /** One entry per Appendix M column, in template order. */
  columns: ColumnCoverage[];
  /** Roll-up: count of cells filled per provider across all 25 columns × assets. */
  totals: Record<Provider, { assets: number; filled_cells: number; total_cells: number; fill_rate: number }>;
  /** Prohibited-vendor catalog contribution (LOOP-W.W1), present only when that emitter ran. */
  prohibited_vendors_catalog_entity_count?: number;
  prohibited_vendors_catalog_source_count?: number;
  /** Prohibited-vendor screen contribution (LOOP-W.W2), present only when the screen ran. */
  prohibited_vendor_screen_coverage?: ProhibitedVendorScreenCoverage;
}

/** Per-run prohibited-vendor screen coverage (LOOP-W.W2). Sibling field — never a G2 fillRate cell. */
export interface ProhibitedVendorScreenCoverage {
  surfaces_walked: number;
  subprocessor_rows_screened: number;
  sbom_packages_screened: number;
  oci_images_screened: number;
  inventory_assets_screened: number;
  total_matches: number;
  catalog_age_hours: number;
}

/**
 * Augment an inventory-coverage report (or any object) with the LOOP-W.W1
 * prohibited-vendor catalog counts as sibling top-level fields. These are NOT
 * Appendix-M `columns[].fillRate` cells — the coverage-regression guardrail (G2)
 * only compares fillRate, so adding these siblings can never trigger a
 * regression. Pure function: returns a new object, does not mutate the input.
 */
export function augmentCoverageWithProhibitedVendors<T extends Record<string, unknown>>(
  report: T,
  counts: { entityCount: number; sourceCount: number },
): T & { prohibited_vendors_catalog_entity_count: number; prohibited_vendors_catalog_source_count: number } {
  return {
    ...report,
    prohibited_vendors_catalog_entity_count: counts.entityCount,
    prohibited_vendors_catalog_source_count: counts.sourceCount,
  };
}

/**
 * Augment a coverage report with the LOOP-W.W2 prohibited-vendor screen coverage
 * as a sibling top-level field. Like its W.W1 counterpart this is NOT an
 * Appendix-M `columns[].fillRate` cell, so the G2 coverage-regression guardrail
 * (which only compares fillRate) can never flag it. Pure: returns a new object.
 */
export function augmentCoverageWithProhibitedVendorScreen<T extends Record<string, unknown>>(
  report: T,
  coverage: ProhibitedVendorScreenCoverage,
): T & { prohibited_vendor_screen_coverage: ProhibitedVendorScreenCoverage } {
  return { ...report, prohibited_vendor_screen_coverage: coverage };
}

/** Per-product CISA Common Form fill-rate (LOOP-T.T3). Sibling field — never a G2 fillRate cell. */
export interface SsdfCommonFormFillRate {
  id: string;
  name: string;
  required_fields: number;
  populated_fields: number;
  /** populated / required, in [0, 1]. */
  fill_rate: number;
}

/**
 * Augment a coverage report with the LOOP-T.T3 CISA Common Form per-product
 * fill-rate as a sibling top-level array (`ssdf_common_form_fill_rate`). Like the
 * W.W1/W.W2 siblings this is NOT an Appendix-M `columns[].fillRate` cell, so the
 * G2 coverage-regression guardrail (which only compares fillRate) can never flag
 * it. Pure: returns a new object, does not mutate the input.
 */
export function augmentCoverageWithSsdfCommonForm<T extends Record<string, unknown>>(
  report: T,
  products: SsdfCommonFormFillRate[],
): T & { ssdf_common_form_fill_rate: SsdfCommonFormFillRate[] } {
  return { ...report, ssdf_common_form_fill_rate: products.map((p) => ({ ...p })) };
}
