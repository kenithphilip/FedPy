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
import { writeFileSync } from 'node:fs';
import { crc32 } from 'node:zlib';

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
  provider: 'aws' | 'gcp';
  /** ARN / GCP self-link / resource id — fills Unique Asset Identifier + Serial/Asset Tag. */
  uniqueId: string;
  /** One or more IPs; >1 fans out into one workbook row per IP (per template guidance). */
  ips?: string[];
  /** MACs aligned by index with `ips` where known. */
  macs?: string[];
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
  comments?: string | null;
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
    'NetBIOS Name': '',
    'MAC Address': a.macs?.[i] ?? '',
    'Authenticated Scan': '',
    'Baseline Configuration Name': a.baselineConfig ?? '',
    'OS Name and Version': a.osNameVersion ?? '',
    'Location': a.location ?? '',
    'Asset Type': a.assetType ?? '',
    'Hardware Make/Model': a.hardwareMakeModel ?? '',
    'In Latest Scan': '',
    'Software/Database Vendor': a.softwareDatabaseVendor ?? '',
    'Software/Database Name & Version': a.softwareDatabaseNameVersion ?? '',
    'Patch Level': a.patchLevel ?? '',
    'Diagram Label': '',
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

function xmlEscape(v: string): string {
  return v.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

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

/** Build a store-only (uncompressed) ZIP from named buffers — valid for .xlsx. */
function zipStore(files: Array<{ name: string; data: Buffer }>): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const f of files) {
    const nameBuf = Buffer.from(f.name, 'utf8');
    const cr = crc32(f.data) >>> 0;
    const size = f.data.length;
    const local = Buffer.alloc(30 + nameBuf.length);
    local.writeUInt32LE(0x04034b50, 0); // local file header sig
    local.writeUInt16LE(20, 4);          // version needed
    local.writeUInt16LE(0, 6);           // flags
    local.writeUInt16LE(0, 8);           // method 0 = store
    local.writeUInt16LE(0, 10);          // mod time
    local.writeUInt16LE(0x21, 12);       // mod date (1980-01-01)
    local.writeUInt32LE(cr, 14);         // crc32
    local.writeUInt32LE(size, 18);       // compressed size
    local.writeUInt32LE(size, 22);       // uncompressed size
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28);          // extra len
    nameBuf.copy(local, 30);
    locals.push(local, f.data);

    const central = Buffer.alloc(46 + nameBuf.length);
    central.writeUInt32LE(0x02014b50, 0); // central dir sig
    central.writeUInt16LE(20, 4);         // version made by
    central.writeUInt16LE(20, 6);         // version needed
    central.writeUInt16LE(0, 8);          // flags
    central.writeUInt16LE(0, 10);         // method
    central.writeUInt16LE(0, 12);         // mod time
    central.writeUInt16LE(0x21, 14);      // mod date
    central.writeUInt32LE(cr, 16);
    central.writeUInt32LE(size, 20);
    central.writeUInt32LE(size, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt16LE(0, 30);         // extra len
    central.writeUInt16LE(0, 32);         // comment len
    central.writeUInt16LE(0, 34);         // disk #
    central.writeUInt16LE(0, 36);         // internal attrs
    central.writeUInt32LE(0, 38);         // external attrs
    central.writeUInt32LE(offset, 42);    // local header offset
    nameBuf.copy(central, 46);
    centrals.push(central);
    offset += local.length + f.data.length;
  }
  const centralStart = offset;
  const centralBuf = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);          // EOCD sig
  eocd.writeUInt16LE(0, 4);                    // disk #
  eocd.writeUInt16LE(0, 6);                    // disk w/ central dir
  eocd.writeUInt16LE(files.length, 8);         // entries on disk
  eocd.writeUInt16LE(files.length, 10);        // total entries
  eocd.writeUInt32LE(centralBuf.length, 12);   // central dir size
  eocd.writeUInt32LE(centralStart, 16);        // central dir offset
  eocd.writeUInt16LE(0, 20);                   // comment len
  return Buffer.concat([...locals, centralBuf, eocd]);
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

// ---- Top-level writer ----

export interface InventoryWorkbookResult {
  asset_count: number;
  row_count: number;
  csv_path?: string;
  xlsx_path?: string;
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
