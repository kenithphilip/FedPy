/**
 * FedRAMP Integrated Inventory Workbook generator (SSP Appendix M, ex-A-13).
 *
 * Re-projects enumerated cloud resources into the official FedRAMP inventory
 * spreadsheet format and emits it as CSV and/or a real `.xlsx`.
 *
 * The 25-column contract comes from the live FedRAMP template
 * (`SSP-Appendix-M-Integrated-Inventory-Workbook-Template.xlsx`, the `Inventory`
 * sheet header row); see `research/reports/06-fedramp-inventory-workbook.md`.
 * The resource→column field mapping is clean-room, informed by the Apache-2.0
 * analogs `aws-samples/fedramp-integrated-inventory-workbook` and
 * `google/asset-inventory-worksheet` (NOT the GPL-3.0 `manywho/awsinventory`,
 * which is reference-only — see report 05 / the licensing decision in 00-INDEX).
 *
 * Pure + dependency-free: the `.xlsx` is produced with a minimal store-only ZIP
 * writer (Node `zlib.crc32`) + inline-string OOXML, to avoid pulling a heavy
 * spreadsheet dependency into a tool that prizes a lean, auditable tree.
 *
 * Read-only: this module only formats data; collection lives in the providers.
 */
import { writeFileSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { xmlEscape, zipStore } from './zip.ts';

// ---- The Appendix M column contract (Inventory sheet, header row 2) ----

export type InvGroup = 'all' | 'os' | 'sw' | 'any';
export interface InvColumn {
  /** Stable key used in code + CSV-debug. */
  key: string;
  /** Exact header text as it appears in the official template. */
  header: string;
  /** The row-1 banner group the column falls under. */
  group: InvGroup;
}

/** The 25 data columns (B–Z) of the FedRAMP Appendix M Integrated Inventory Workbook. */
export const APPENDIX_M_COLUMNS: readonly InvColumn[] = [
  { key: 'unique_asset_identifier', header: 'Unique Asset Identifier', group: 'all' },
  { key: 'ip_address', header: 'IPv4 or IPv6 Address', group: 'all' },
  { key: 'virtual', header: 'Virtual', group: 'all' },
  { key: 'public', header: 'Public', group: 'all' },
  { key: 'dns_name_or_url', header: 'DNS Name or URL', group: 'all' },
  { key: 'netbios_name', header: 'NetBIOS Name', group: 'os' },
  { key: 'mac_address', header: 'MAC Address', group: 'os' },
  { key: 'authenticated_scan', header: 'Authenticated Scan', group: 'os' },
  { key: 'baseline_configuration_name', header: 'Baseline Configuration Name', group: 'os' },
  { key: 'os_name_and_version', header: 'OS Name and Version', group: 'os' },
  { key: 'location', header: 'Location', group: 'os' },
  { key: 'asset_type', header: 'Asset Type', group: 'os' },
  { key: 'hardware_make_model', header: 'Hardware Make/Model', group: 'os' },
  { key: 'in_latest_scan', header: 'In Latest Scan', group: 'os' },
  { key: 'software_database_vendor', header: 'Software/Database Vendor', group: 'sw' },
  { key: 'software_database_name_version', header: 'Software/Database Name & Version', group: 'sw' },
  { key: 'patch_level', header: 'Patch Level', group: 'sw' },
  { key: 'diagram_label', header: 'Diagram Label', group: 'any' },
  { key: 'comments', header: 'Comments', group: 'any' },
  { key: 'serial_asset_tag', header: 'Serial #/Asset Tag#', group: 'any' },
  { key: 'vlan_network_id', header: 'VLAN/Network ID', group: 'any' },
  { key: 'system_administrator_owner', header: 'System Administrator/Owner', group: 'any' },
  { key: 'application_administrator_owner', header: 'Application Administrator/Owner', group: 'any' },
  { key: 'function', header: 'Function', group: 'any' },
  { key: 'end_of_life', header: 'End-of-Life', group: 'any' },
] as const;

// ---- Normalized cloud asset (what providers produce) ----

/**
 * One discovered cloud resource, normalized across providers. Providers fill what
 * read-only APIs expose; everything optional falls back to a blank cell so the
 * output is honestly partial rather than fabricated.
 */
export interface CloudAsset {
  provider: 'aws' | 'gcp' | 'azure';
  /** ARN / GCP self-link / resource id — fills Unique Asset Identifier + Serial/Asset Tag. */
  uniqueId: string;
  /** One or more IPs; >1 fans out into one workbook row per IP (per template guidance). */
  ips?: string[];
  /** MACs aligned by index with `ips` where known. */
  macs?: string[];
  /**
   * Windows guest hostname (used as the NetBIOS Name in column F of the
   * FedRAMP Appendix M workbook). Populated by the OS-level enrichers
   * (SSM Inventory on AWS, OS Config on GCP, osProfile/Update Mgmt on
   * Azure) for Windows hosts only — Linux + container assets leave it
   * blank (no NetBIOS concept).
   */
  netbiosName?: string | null;
  /** Default true for cloud-managed assets. */
  virtual?: boolean;
  /** True = internet-facing / outside the boundary. undefined = unknown (blank). */
  publicFacing?: boolean;
  dns?: string | null;
  osNameVersion?: string | null;
  /** STIG/CIS hardening benchmark name applied. */
  baselineConfig?: string | null;
  /** region / zone / data-center identifier. */
  location?: string | null;
  /** Plain function description, no vendor/product names (e.g. "Compute Instance"). */
  assetType?: string | null;
  /** e.g. "AWS EC2 t3.large" / "GCP e2-standard-4". */
  hardwareMakeModel?: string | null;
  softwareDatabaseVendor?: string | null;
  softwareDatabaseNameVersion?: string | null;
  patchLevel?: string | null;
  /** VPC/subnet id or GCP network. */
  vlanNetworkId?: string | null;
  systemOwner?: string | null;
  applicationOwner?: string | null;
  /** The function the component provides for the system. */
  function?: string | null;
  endOfLife?: string | null;
  /**
   * Diagram Label (column S). Auto-synthesized by `applyDiagramLabelAndComments`
   * as `<friendlyType>-<name>@<location>` when blank; operator override via the
   * `diagram_label` / `DiagramLabel` / `inventory_label` / `fedramp_label` tag.
   */
  diagramLabel?: string | null;
  comments?: string | null;
  /** Raw resource tags/labels — drive tag→column enrichment (owner/function/baseline). */
  tags?: Record<string, string>;
  /** Column O — set by scan reconciliation against our own VDR/Inspector evidence. */
  inLatestScan?: boolean;
  /** Column I — Inspector/agent scans are authenticated. */
  authenticatedScan?: boolean;

  // ---- Rich superset fields (surfaced in inventory.json; the workbook is a
  //      lossy 25-column projection of this). All optional + honest-blank. ----
  /** Owning account / project / subscription id. */
  accountId?: string | null;
  /** Provider-native resource type, e.g. "AWS::EC2::Instance" / CAI assetType. */
  resourceType?: string | null;
  // Lifecycle
  createdAt?: string | null;
  lastModifiedAt?: string | null;
  /** Last activity/usage (idle-resource detection). */
  lastUsedAt?: string | null;
  /** running / stopped / available / … */
  state?: string | null;
  // Compute / capacity
  sizeGb?: number | null;
  vcpu?: number | null;
  memoryMb?: number | null;
  imageId?: string | null;
  architecture?: string | null;
  // Security / data
  kmsKeyId?: string | null;
  encryptionAtRest?: boolean | null;
  /** Ports/ranges open to the internet (network-exposure analysis). */
  openPorts?: string[];
  dataClassification?: string | null;
  // Ownership / org (tag-derived)
  environment?: string | null;
  criticality?: string | null;
  costCenter?: string | null;
  application?: string | null;
  // Cost
  monthlyCostEstimate?: number | null;
  pricingModel?: string | null;
  // Governance
  /** Required tags that are missing on this asset (tag-governance). */
  missingRequiredTags?: string[];
  // Provenance
  collectedAt?: string | null;
  /** Which discovery/enrich pass produced or last touched this asset. */
  sourceApi?: string | null;
  /** Raw provider config for long-tail types with no dedicated enricher. */
  raw?: unknown;
}

/** A directed relationship between two assets (topology / blast-radius graph). */
export interface InventoryEdge {
  /** Source asset uniqueId. */
  from: string;
  /** Target asset uniqueId. */
  to: string;
  /** Edge kind, e.g. "attached-volume", "in-vpc", "lb-target", "uses-kms-key". */
  type: string;
}

/** The full normalized inventory snapshot — the source of truth all emitters read. */
export interface InventorySnapshot {
  generated_at: string;
  asset_count: number;
  edge_count: number;
  by_provider: Record<string, number>;
  by_type: Record<string, number>;
  assets: CloudAsset[];
  edges: InventoryEdge[];
}

const yn = (b: boolean | undefined): string => (b === true ? 'Yes' : b === false ? 'No' : '');

/**
 * Map one normalized asset to one or more workbook rows (keyed by column header).
 * Multi-IP assets fan out into one row per IP (template guidance for column C).
 */
export function assetToRows(a: CloudAsset): Array<Record<string, string>> {
  const ips = a.ips && a.ips.length > 0 ? a.ips : [''];
  return ips.map((ip, i) => ({
    'Unique Asset Identifier': a.uniqueId,
    'IPv4 or IPv6 Address': ip,
    'Virtual': yn(a.virtual ?? true),
    'Public': yn(a.publicFacing),
    'DNS Name or URL': a.dns ?? '',
    'NetBIOS Name': a.netbiosName ?? '',
    'MAC Address': a.macs?.[i] ?? '',
    'Authenticated Scan': yn(a.authenticatedScan),
    'Baseline Configuration Name': a.baselineConfig ?? '',
    'OS Name and Version': a.osNameVersion ?? '',
    'Location': a.location ?? '',
    'Asset Type': a.assetType ?? '',
    'Hardware Make/Model': a.hardwareMakeModel ?? '',
    'In Latest Scan': yn(a.inLatestScan),
    'Software/Database Vendor': a.softwareDatabaseVendor ?? '',
    'Software/Database Name & Version': a.softwareDatabaseNameVersion ?? '',
    'Patch Level': a.patchLevel ?? '',
    'Diagram Label': a.diagramLabel ?? '',
    'Comments': a.comments ?? '',
    'Serial #/Asset Tag#': a.uniqueId,
    'VLAN/Network ID': a.vlanNetworkId ?? '',
    'System Administrator/Owner': a.systemOwner ?? '',
    'Application Administrator/Owner': a.applicationOwner ?? '',
    'Function': a.function ?? '',
    'End-of-Life': a.endOfLife ?? '',
  }));
}

/** Flatten many assets into workbook rows. */
export function assetsToRows(assets: CloudAsset[]): Array<Record<string, string>> {
  return assets.flatMap(assetToRows);
}

// ---- CSV output ----

function csvEscape(v: string): string {
  return /[",\r\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
}

/** Render rows as CSV with the exact Appendix M header order. */
export function rowsToCsv(rows: Array<Record<string, string>>): string {
  const headers = APPENDIX_M_COLUMNS.map((c) => c.header);
  const lines = [headers.map(csvEscape).join(',')];
  for (const r of rows) lines.push(headers.map((h) => csvEscape(r[h] ?? '')).join(','));
  return lines.join('\r\n') + '\r\n';
}

// ---- Minimal store-only XLSX writer (no external dependency) ----

/** Column letter for a 1-based index (1→A, 26→Z, 27→AA). */
function colLetter(n: number): string {
  let s = '';
  while (n > 0) { const m = (n - 1) % 26; s = String.fromCharCode(65 + m) + s; n = Math.floor((n - 1) / 26); }
  return s;
}

function sheetXml(rows: Array<Record<string, string>>): string {
  const headers = APPENDIX_M_COLUMNS.map((c) => c.header);
  const allRows = [headers, ...rows.map((r) => headers.map((h) => r[h] ?? ''))];
  const xmlRows = allRows.map((cells, ri) => {
    const r = ri + 1;
    const xmlCells = cells.map((val, ci) => {
      if (val === '') return '';
      const ref = `${colLetter(ci + 1)}${r}`;
      return `<c r="${ref}" t="inlineStr"><is><t xml:space="preserve">${xmlEscape(val)}</t></is></c>`;
    }).join('');
    return `<row r="${r}">${xmlCells}</row>`;
  }).join('');
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>${xmlRows}</sheetData></worksheet>`;
}

/** Produce a minimal valid `.xlsx` (single "Inventory" sheet, inline strings). */
export function rowsToXlsx(rows: Array<Record<string, string>>): Buffer {
  const files: Array<{ name: string; data: Buffer }> = [
    { name: '[Content_Types].xml', data: Buffer.from(
      `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
      `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
      `<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
      `<Default Extension="xml" ContentType="application/xml"/>` +
      `<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
      `<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>` +
      `</Types>`, 'utf8') },
    { name: '_rels/.rels', data: Buffer.from(
      `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
      `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
      `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>` +
      `</Relationships>`, 'utf8') },
    { name: 'xl/workbook.xml', data: Buffer.from(
      `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
      `<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">` +
      `<sheets><sheet name="Inventory" sheetId="1" r:id="rId1"/></sheets></workbook>`, 'utf8') },
    { name: 'xl/_rels/workbook.xml.rels', data: Buffer.from(
      `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
      `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
      `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>` +
      `</Relationships>`, 'utf8') },
    { name: 'xl/worksheets/sheet1.xml', data: Buffer.from(sheetXml(rows), 'utf8') },
  ];
  return zipStore(files);
}

// ---- FedPy-native enrichment (our own mechanics on top of the base inventory) ----

/** Which resource tags map to which inventory columns. Config-overridable. */
export interface TagColumnMap {
  systemOwner: string[];
  applicationOwner: string[];
  function: string[];
  baselineConfig: string[];
}

export const DEFAULT_TAG_MAP: TagColumnMap = {
  systemOwner: ['Owner', 'owner', 'SystemOwner', 'system_owner', 'team'],
  applicationOwner: ['AppOwner', 'ApplicationOwner', 'app_owner', 'application_owner'],
  function: ['Function', 'function', 'Role', 'role', 'Name', 'service'],
  baselineConfig: ['Baseline', 'BaselineConfig', 'STIG', 'CIS', 'HardeningBaseline', 'baseline'],
};

// INV-S6: Tags the operator can set to override the auto-synthesized Diagram
// Label (column S) and to populate the Comments (column T) cell. Comments
// stays blank by default per the FedRAMP template — the tag is the operator's
// override hook for asset-specific notes that should travel into the workbook.
const DIAGRAM_LABEL_TAGS = ['diagram_label', 'DiagramLabel', 'inventory_label', 'fedramp_label'];
const COMMENTS_TAGS = ['inventory_comments', 'fedramp_comments', 'comments'];

/**
 * Derive the auto-synthesized Diagram Label for an asset. Used when no
 * explicit `diagramLabel` (or override tag) is present. Format:
 *   <friendlyType>-<name>             (when location is "global" / absent)
 *   <friendlyType>-<name>@<location>  (otherwise)
 * Spaces are converted to hyphens and the whole string is lower-cased so the
 * output is diagram-friendly (no whitespace, predictable casing).
 */
export function synthesizeDiagramLabel(asset: CloudAsset): string {
  const type = (asset.assetType ?? 'asset').toString().trim();
  // Prefer the explicit `function` (usually the resource name) over the tail
  // of the uniqueId — the workbook's reader will recognize names.
  const nameSrc = (asset.function ?? asset.uniqueId.split(/[/:]/).filter(Boolean).pop() ?? 'unnamed').toString().trim();
  const loc = (asset.location ?? '').toString().trim().toLowerCase();
  const base = `${type}-${nameSrc}`.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9._@/-]/g, '');
  if (!loc || loc === 'global') return base;
  return `${base}@${loc.replace(/\s+/g, '-')}`;
}

/**
 * Apply the diagram-label + comments tag overrides + synthesis (INV-S6).
 *
 * Rules:
 *   1. If a `diagram_label` (or alias) tag is set, use that verbatim.
 *   2. Otherwise auto-synthesize a default label (see `synthesizeDiagramLabel`).
 *   3. Operators can override the result by passing `--diagram-label-blank`
 *      via the orchestrator (not implemented here — this function just sets
 *      a sensible default that downstream code can clear if requested).
 *   4. For Comments: an `inventory_comments` tag is passed through verbatim;
 *      no synthesis (FedRAMP defines column T as operator-supplied free text).
 *
 * Mutates and returns the asset.
 */
export function applyDiagramLabelAndComments(asset: CloudAsset): CloudAsset {
  // Diagram Label.
  const explicitLabel = firstTag(asset.tags, DIAGRAM_LABEL_TAGS);
  if (explicitLabel) {
    asset.diagramLabel = explicitLabel;
  } else if (asset.diagramLabel == null) {
    asset.diagramLabel = synthesizeDiagramLabel(asset);
  }
  // Comments — only populated when the operator has tagged the asset.
  const explicitComments = firstTag(asset.tags, COMMENTS_TAGS);
  if (explicitComments && (asset.comments == null || asset.comments === '')) {
    asset.comments = explicitComments;
  }
  return asset;
}

function firstTag(tags: Record<string, string> | undefined, keys: string[]): string | undefined {
  if (!tags) return undefined;
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(tags)) lower[k.toLowerCase()] = v;
  for (const k of keys) { const v = lower[k.toLowerCase()]; if (v) return v; }
  return undefined;
}

/**
 * Fill owner / application-owner / function / baseline columns from resource tags
 * (only where not already set by the collector). Mutates and returns the asset.
 */
export function enrichFromTags(asset: CloudAsset, map: TagColumnMap = DEFAULT_TAG_MAP): CloudAsset {
  asset.systemOwner ??= firstTag(asset.tags, map.systemOwner) ?? null;
  asset.applicationOwner ??= firstTag(asset.tags, map.applicationOwner) ?? null;
  asset.function ??= firstTag(asset.tags, map.function) ?? null;
  asset.baselineConfig ??= firstTag(asset.tags, map.baselineConfig) ?? null;
  return asset;
}

/** Meaningful match tokens for a resource identifier (full + last segment, len ≥ 6). */
export function idTokens(id: string): Set<string> {
  const out = new Set<string>();
  const full = id.toLowerCase().trim();
  if (full.length >= 6) out.add(full);
  const seg = full.split(/[/:]/).filter(Boolean).pop();
  if (seg && seg.length >= 6) out.add(seg);
  return out;
}

/** True if two identifiers share a meaningful token (ARN-equality or resource-id match). */
export function identifiersMatch(a: string, b: string): boolean {
  const ta = idTokens(a); const tb = idTokens(b);
  for (const t of ta) if (tb.has(t)) return true;
  return false;
}

/**
 * Scan reconciliation (column O + I) — our twist: cross-reference each asset
 * against identifiers that appeared in OUR vulnerability-scan evidence (Inspector
 * / ECR / VDR). A match ⇒ the asset is in the latest scan, authenticated.
 * Returns the number of assets matched. Mutates assets.
 */
export function reconcileScans(assets: CloudAsset[], scannedIdentifiers: Iterable<string>): number {
  const scanned = [...scannedIdentifiers];
  let matched = 0;
  for (const a of assets) {
    if (scanned.some((s) => identifiersMatch(a.uniqueId, s))) {
      a.inLatestScan = true;
      a.authenticatedScan = true;
      matched++;
    }
  }
  return matched;
}

export interface FindingRef { identifier: string; ksiId: string; rule: string; passed: boolean; }

/**
 * KSI cross-linking — our twist: annotate each asset's Comments with the
 * compliance findings (from this run's evidence) whose affected resource matches
 * it, so the inventory doubles as a posture map. Failing findings are listed
 * first. Mutates assets; returns the number of assets annotated.
 */
export function annotateWithFindings(assets: CloudAsset[], findings: FindingRef[]): number {
  let annotated = 0;
  for (const a of assets) {
    const hits = findings.filter((f) => identifiersMatch(a.uniqueId, f.identifier));
    if (hits.length === 0) continue;
    const fails = [...new Set(hits.filter((h) => !h.passed).map((h) => `${h.ksiId}/${h.rule}`))];
    const passes = [...new Set(hits.filter((h) => h.passed).map((h) => h.ksiId))];
    const parts: string[] = [];
    if (fails.length) parts.push(`failing KSI findings: ${fails.slice(0, 8).join(', ')}${fails.length > 8 ? ` (+${fails.length - 8} more)` : ''}`);
    if (passes.length) parts.push(`passing: ${[...new Set(passes)].slice(0, 8).join(', ')}`);
    const note = `FedPy ${parts.join('; ')}`;
    a.comments = a.comments ? `${a.comments} | ${note}` : note;
    annotated++;
  }
  return annotated;
}

// ---- INV-11: End-of-life derivation (maintained static map) ----

/**
 * Known end-of-life / end-of-support dates for common runtimes/engines, keyed by
 * a lowercase substring matched against an asset's software/OS string. Maintained
 * by hand (these dates move slowly); unknowns return null rather than guessing.
 */
export const EOL_MAP: Record<string, string> = {
  // AWS Lambda runtimes (deprecation dates)
  'nodejs14.x': '2023-12-04', 'nodejs16.x': '2024-06-12', 'nodejs18.x': '2025-09-01',
  'python3.7': '2023-12-04', 'python3.8': '2024-10-14', 'python3.9': '2025-12-15',
  'go1.x': '2024-01-08', 'ruby2.7': '2024-01-08', 'dotnet6': '2024-12-20', 'java8': '2024-01-08',
  // Database engines (major-version EOL, approximate community/RDS dates)
  'mysql 5.7': '2024-02-29', 'mysql 8.0': '2026-04-30',
  'postgres 11': '2024-02-29', 'postgres 12': '2024-11-14', 'postgres 13': '2025-11-13',
  'mariadb 10.4': '2024-06-18', 'mariadb 10.5': '2025-06-24',
  // Kubernetes (EKS/GKE) minor versions (EKS end-of-standard-support, approximate)
  'eks 1.23': '2024-10-11', 'eks 1.24': '2025-01-31', 'eks 1.25': '2025-05-01',
  'eks 1.26': '2025-06-01', 'eks 1.27': '2025-07-01', 'eks 1.28': '2025-11-01',
  // Operating systems
  'amazon linux': '2025-06-30', 'amazon linux 2': '2026-06-30',
  'ubuntu 18.04': '2023-05-31', 'ubuntu 20.04': '2025-05-31',
  'windows server 2012': '2023-10-10', 'windows server 2016': '2027-01-12',
};

/** Derive an end-of-life date from an asset's software/OS strings, if known. */
export function deriveEol(asset: CloudAsset): string | null {
  if (asset.endOfLife) return asset.endOfLife;
  const hay = `${asset.softwareDatabaseNameVersion ?? ''} ${asset.osNameVersion ?? ''}`.toLowerCase();
  for (const [needle, date] of Object.entries(EOL_MAP)) {
    if (hay.includes(needle)) return date;
  }
  return null;
}

// ---- INV-14: Tag governance (ownership columns + required-tag compliance) ----

/** Default required-tag policy for an org inventory (override via config). */
export const DEFAULT_REQUIRED_TAGS = ['Owner', 'Environment', 'CostCenter', 'DataClassification'];

const ENV_KEYS = ['Environment', 'environment', 'Env', 'env', 'stage', 'tier'];
const CRIT_KEYS = ['Criticality', 'criticality', 'severity', 'tier'];
const COST_KEYS = ['CostCenter', 'cost_center', 'costcenter', 'BillingCode', 'billing'];
const APP_KEYS = ['Application', 'application', 'App', 'app', 'service', 'Service', 'project'];
const CLASS_KEYS = ['DataClassification', 'data_classification', 'classification', 'sensitivity'];

/**
 * Fill ownership/governance columns from tags and record any required tags that
 * are missing (tag-governance). Mutates and returns the asset.
 */
export function applyTagGovernance(asset: CloudAsset, requiredTags: string[] = DEFAULT_REQUIRED_TAGS): CloudAsset {
  asset.environment ??= firstTag(asset.tags, ENV_KEYS) ?? null;
  asset.criticality ??= firstTag(asset.tags, CRIT_KEYS) ?? null;
  asset.costCenter ??= firstTag(asset.tags, COST_KEYS) ?? null;
  asset.application ??= firstTag(asset.tags, APP_KEYS) ?? null;
  asset.dataClassification ??= firstTag(asset.tags, CLASS_KEYS) ?? null;
  const present = new Set(Object.keys(asset.tags ?? {}).map((k) => k.toLowerCase()));
  asset.missingRequiredTags = requiredTags.filter((t) => !present.has(t.toLowerCase()));
  return asset;
}

// ---- INV-17: data classification from a detector (e.g. AWS Macie) ----

/**
 * Mark S3-bucket assets whose bucket name is in `sensitiveBucketNames` with a
 * data-classification label (only where not already tag-classified). Returns the
 * number labeled. Pure.
 */
export function applyDataClassification(
  assets: CloudAsset[],
  sensitiveBucketNames: Set<string>,
  label = 'Sensitive (Macie)',
): number {
  if (sensitiveBucketNames.size === 0) return 0;
  let n = 0;
  for (const a of assets) {
    if (a.dataClassification) continue;
    const name = a.uniqueId.startsWith('arn:aws:s3:::') ? a.uniqueId.slice('arn:aws:s3:::'.length) : null;
    if (name && sensitiveBucketNames.has(name)) { a.dataClassification = label; n++; }
  }
  return n;
}

// ---- INV-13: Relationship graph (topology / blast-radius) ----

/**
 * Derive directed edges from the fields we hold: each asset → its VPC/network and
 * → its KMS key. Targets may be implicit graph nodes (not themselves listed
 * assets). Extensible — richer edges (instance→volume, lb→target) need attachment
 * data the depth enrichers can add later.
 */
export function deriveEdges(assets: CloudAsset[]): InventoryEdge[] {
  const edges: InventoryEdge[] = [];
  const seen = new Set<string>();
  const add = (from: string, to: string, type: string) => {
    const k = `${from}|${to}|${type}`;
    if (to && !seen.has(k)) { seen.add(k); edges.push({ from, to, type }); }
  };
  for (const a of assets) {
    if (a.vlanNetworkId) for (const net of a.vlanNetworkId.split('/').filter(Boolean)) add(a.uniqueId, net, 'in-network');
    if (a.kmsKeyId) add(a.uniqueId, a.kmsKeyId, 'uses-kms-key');
  }
  return edges;
}

/**
 * Merge assets that share a uniqueId (e.g. one from the discovery backbone, one
 * from a depth-enricher; or the same global resource seen in two region passes).
 * Later non-null/non-empty values win field-by-field; ips/macs/openPorts unions.
 */
export function dedupeAssets(assets: CloudAsset[]): CloudAsset[] {
  const byId = new Map<string, CloudAsset>();
  for (const a of assets) {
    const existing = byId.get(a.uniqueId);
    if (!existing) { byId.set(a.uniqueId, { ...a }); continue; }
    for (const [k, v] of Object.entries(a) as Array<[keyof CloudAsset, unknown]>) {
      if (v == null) continue;
      if (Array.isArray(v)) {
        const prev = (existing[k] as unknown[] | undefined) ?? [];
        (existing as any)[k] = [...new Set([...prev, ...v])];
      } else if (typeof v === 'object') {
        (existing as any)[k] = { ...(existing[k] as object ?? {}), ...(v as object) };
      } else if (existing[k] == null || existing[k] === '' || existing[k] === false) {
        (existing as any)[k] = v;
      }
    }
  }
  return [...byId.values()];
}

/** Build the full normalized inventory snapshot (the source of truth for emitters). */
export function buildInventorySnapshot(assets: CloudAsset[], edges: InventoryEdge[] = []): InventorySnapshot {
  const byProvider: Record<string, number> = {};
  const byType: Record<string, number> = {};
  for (const a of assets) {
    byProvider[a.provider] = (byProvider[a.provider] ?? 0) + 1;
    const t = a.resourceType ?? a.assetType ?? 'unknown';
    byType[t] = (byType[t] ?? 0) + 1;
  }
  return {
    generated_at: new Date().toISOString(),
    asset_count: assets.length,
    edge_count: edges.length,
    by_provider: byProvider,
    by_type: byType,
    assets,
    edges,
  };
}

/** Write the rich inventory snapshot as JSON (the superset; CSV/XLSX are projections). */
export function writeInventoryJson(snapshot: InventorySnapshot, path: string): void {
  writeFileSync(path, JSON.stringify(snapshot, null, 2));
}

// ---- Top-level writer ----

export interface InventoryWorkbookResult {
  asset_count: number;
  row_count: number;
  csv_path?: string;
  xlsx_path?: string;
}

/** VDR / vulnerability-scan KSIs whose affected resources count as "scanned". */
const SCAN_KSI = /VDR|SVC-VRI|SCR-MON|SCR-MIT/i;

const SKIP_FILES = new Set([
  'pva-run-summary.json', 'manifest.json', 'coverage-report.json', 'family-rollup.json',
  'vdr-report.json', 'crosswalk-report.json', 'diff-report.json', 'anomaly-report.json',
  'sbom-report.json', 'llm-prs.json', 'control-benchmark.json', 'assessment-results.json',
]);

export interface InventoryContext { findings: FindingRef[]; scannedIdentifiers: Set<string>; }

/**
 * Read this run's evidence files from `outDir` and extract (a) every finding's
 * affected-resource identifiers (for KSI cross-linking) and (b) the subset that
 * came from vulnerability-scan KSIs (for scan reconciliation). Read-only.
 */
export function readInventoryContext(outDir: string): InventoryContext {
  const findings: FindingRef[] = [];
  const scannedIdentifiers = new Set<string>();
  let names: string[] = [];
  try { names = readdirSync(outDir); } catch { return { findings, scannedIdentifiers }; }
  for (const name of names) {
    if (!name.endsWith('.json') || SKIP_FILES.has(name)) continue;
    let data: any;
    try { data = JSON.parse(readFileSync(join(outDir, name), 'utf8')); } catch { continue; }
    if (!data || typeof data !== 'object' || !data.ksi_id || !Array.isArray(data.providers)) continue;
    const isScanKsi = SCAN_KSI.test(String(data.ksi_id));
    for (const p of data.providers) {
      for (const f of p.findings ?? []) {
        for (const r of f.gap?.affected_resources ?? []) {
          if (!r?.identifier || r.identifier === 'none') continue;
          findings.push({ identifier: r.identifier, ksiId: data.ksi_id, rule: f.rule, passed: f.passed });
          if (isScanKsi) scannedIdentifiers.add(r.identifier);
        }
      }
      // INV-S5: ALSO pick up "assessed_resource_ids" arrays from VDR-style
      // evidence entries (e.g. Defender for Cloud assessments on Azure).
      // The gap.affected_resources path only captures FAILING assets — but the
      // FedRAMP workbook columns I ("Authenticated Scan") + O ("In Latest
      // Scan") ask whether the asset was scanned AT ALL, regardless of result.
      // Providers can publish their scanned-id set on any evidence entry as
      // `data.assessed_resource_ids: string[]` and we surface them into the
      // scannedIdentifiers set when the KSI is a VDR/SCR/SVC-VRI class.
      if (!isScanKsi) continue;
      for (const e of p.evidence ?? []) {
        const ids = (e?.data as { assessed_resource_ids?: unknown })?.assessed_resource_ids;
        if (!Array.isArray(ids)) continue;
        for (const id of ids) {
          if (typeof id === 'string' && id.trim() && id !== 'none') scannedIdentifiers.add(id);
        }
      }
    }
  }
  return { findings, scannedIdentifiers };
}

/**
 * Write the inventory workbook from normalized assets. Emits CSV and/or XLSX
 * depending on which paths are provided.
 */
export function writeInventoryWorkbook(
  assets: CloudAsset[],
  opts: { csvPath?: string; xlsxPath?: string },
): InventoryWorkbookResult {
  const rows = assetsToRows(assets);
  const res: InventoryWorkbookResult = { asset_count: assets.length, row_count: rows.length };
  if (opts.csvPath) { writeFileSync(opts.csvPath, rowsToCsv(rows)); res.csv_path = opts.csvPath; }
  if (opts.xlsxPath) { writeFileSync(opts.xlsxPath, rowsToXlsx(rows)); res.xlsx_path = opts.xlsxPath; }
  return res;
}
