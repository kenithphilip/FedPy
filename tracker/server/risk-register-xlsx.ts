/**
 * LOOP-B.B5 — Risk Register XLSX renderer (tracker side).
 *
 * The tracker is a separate npm workspace from cloud-evidence, so it cannot
 * import `cloud-evidence/core/risk-register-xlsx.ts`. This is a self-contained
 * copy of that renderer (same 20-column layout, frozen header pane, and
 * conditional formatting) built on a minimal dependency-free store-only ZIP
 * writer — the tracker's `GET /api/risk-register/export.xlsx` streams its output.
 *
 * Keep this byte-compatible in structure with the cloud-evidence renderer; a
 * future column change MUST be applied to both (tracked as LOOP-B-RISKS B.B5-12).
 */
import { crc32 } from 'node:zlib';

export type RiskBandLike = 'very-low' | 'low' | 'moderate' | 'high' | 'very-high' | 'REQUIRES-OPERATOR-INPUT';

export interface RegisterRow {
  uuid: string;
  source: string;
  title: string;
  category: string;
  likelihood: RiskBandLike;
  impact: RiskBandLike;
  inherent_risk: RiskBandLike;
  residual_risk: RiskBandLike;
  treatment: string;
  owner: string;
  review_date: string;
  status: string;
  poam_item_uuid?: string | null;
  acceptance_uuid?: string | null;
  compensating_control_uuids?: string[] | null;
  nist_control_ids?: string[] | null;
  cvss_base?: number | null;
  epss_score?: number | null;
  epss_percentile?: number | null;
  description: string;
}

export const RISK_REGISTER_COLUMNS: readonly string[] = [
  'Risk ID', 'Source', 'Title', 'Category', 'Likelihood', 'Impact',
  'Inherent Risk', 'Residual Risk', 'Treatment', 'Owner', 'Review Date',
  'Status', 'Linked POA&M Item', 'Linked Acceptance', 'Compensating Controls',
  'NIST Controls', 'CVSS Base', 'EPSS Score', 'EPSS Percentile', 'Description',
] as const;

const S_DEFAULT = 0, S_RED_FILL = 1, S_BOLD_RED = 2, S_WRAP = 3;

function num(n: number | null | undefined): string {
  return typeof n === 'number' && Number.isFinite(n) ? String(n) : '';
}

export function rowToCells(r: RegisterRow): string[] {
  return [
    r.uuid, r.source, r.title, r.category, r.likelihood, r.impact,
    r.inherent_risk, r.residual_risk, r.treatment, r.owner, r.review_date, r.status,
    r.poam_item_uuid ?? '', r.acceptance_uuid ?? '',
    (r.compensating_control_uuids ?? []).join(';'), (r.nist_control_ids ?? []).join(';'),
    num(r.cvss_base), num(r.epss_score), num(r.epss_percentile), r.description,
  ];
}

function styleForCell(colIdx: number, r: RegisterRow): number {
  if (colIdx === 6 && (r.inherent_risk === 'high' || r.inherent_risk === 'very-high')) return S_RED_FILL;
  if (colIdx === 7 && r.residual_risk === 'very-high') return S_BOLD_RED;
  if (colIdx === 19) return S_WRAP;
  return S_DEFAULT;
}

function xmlEscape(v: string): string {
  return v.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function colLetter(n: number): string {
  let s = '';
  while (n > 0) { const m = (n - 1) % 26; s = String.fromCharCode(65 + m) + s; n = Math.floor((n - 1) / 26); }
  return s;
}

function cellXml(ref: string, value: string, style: number): string {
  if (value === '' && style === S_DEFAULT) return '';
  const sAttr = style !== S_DEFAULT ? ` s="${style}"` : '';
  if (value === '') return `<c r="${ref}"${sAttr}/>`;
  return `<c r="${ref}"${sAttr} t="inlineStr"><is><t xml:space="preserve">${xmlEscape(value)}</t></is></c>`;
}

function sheetXml(rows: RegisterRow[]): string {
  const headerCells = RISK_REGISTER_COLUMNS.map((h, ci) => cellXml(`${colLetter(ci + 1)}1`, h, S_DEFAULT)).join('');
  const out: string[] = [`<row r="1">${headerCells}</row>`];
  for (let ri = 0; ri < rows.length; ri++) {
    const r = rows[ri]!;
    const rn = ri + 2;
    const cells = rowToCells(r).map((v, ci) => cellXml(`${colLetter(ci + 1)}${rn}`, v, styleForCell(ci, r))).join('');
    out.push(`<row r="${rn}">${cells}</row>`);
  }
  const pane = `<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>`;
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">` +
    `${pane}<sheetData>${out.join('')}</sheetData></worksheet>`;
}

function stylesXml(): string {
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">` +
    `<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>` +
    `<font><b/><color rgb="FF9C0006"/><sz val="11"/><name val="Calibri"/></font></fonts>` +
    `<fills count="3"><fill><patternFill patternType="none"/></fill>` +
    `<fill><patternFill patternType="gray125"/></fill>` +
    `<fill><patternFill patternType="solid"><fgColor rgb="FFFFC7CE"/><bgColor indexed="64"/></patternFill></fill></fills>` +
    `<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>` +
    `<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>` +
    `<cellXfs count="4">` +
    `<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>` +
    `<xf numFmtId="0" fontId="0" fillId="2" borderId="0" xfId="0" applyFill="1"/>` +
    `<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/>` +
    `<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment wrapText="1"/></xf>` +
    `</cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>`;
}

function zipStore(files: Array<{ name: string; data: Buffer }>): Buffer {
  const locals: Buffer[] = [], centrals: Buffer[] = [];
  let offset = 0;
  for (const f of files) {
    const nameBuf = Buffer.from(f.name, 'utf8');
    const cr = crc32(f.data) >>> 0;
    const size = f.data.length;
    const local = Buffer.alloc(30 + nameBuf.length);
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(0, 6);
    local.writeUInt16LE(0, 8); local.writeUInt16LE(0, 10); local.writeUInt16LE(0x21, 12);
    local.writeUInt32LE(cr, 14); local.writeUInt32LE(size, 18); local.writeUInt32LE(size, 22);
    local.writeUInt16LE(nameBuf.length, 26); local.writeUInt16LE(0, 28); nameBuf.copy(local, 30);
    locals.push(local, f.data);
    const central = Buffer.alloc(46 + nameBuf.length);
    central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8); central.writeUInt16LE(0, 10); central.writeUInt16LE(0, 12);
    central.writeUInt16LE(0x21, 14); central.writeUInt32LE(cr, 16); central.writeUInt32LE(size, 20);
    central.writeUInt32LE(size, 24); central.writeUInt16LE(nameBuf.length, 28); central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32); central.writeUInt16LE(0, 34); central.writeUInt16LE(0, 36);
    central.writeUInt32LE(0, 38); central.writeUInt32LE(offset, 42); nameBuf.copy(central, 46);
    centrals.push(central);
    offset += local.length + f.data.length;
  }
  const centralBuf = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(0, 4); eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(files.length, 8); eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(centralBuf.length, 12); eocd.writeUInt32LE(offset, 16); eocd.writeUInt16LE(0, 20);
  return Buffer.concat([...locals, centralBuf, eocd]);
}

/** Produce a valid single-sheet `.xlsx` (Risk Register) for the given rows. */
export function renderRiskRegisterXlsx(rows: RegisterRow[]): Buffer {
  return zipStore([
    { name: '[Content_Types].xml', data: Buffer.from(
      `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
      `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
      `<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
      `<Default Extension="xml" ContentType="application/xml"/>` +
      `<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
      `<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>` +
      `<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>` +
      `</Types>`, 'utf8') },
    { name: '_rels/.rels', data: Buffer.from(
      `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
      `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
      `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>` +
      `</Relationships>`, 'utf8') },
    { name: 'xl/workbook.xml', data: Buffer.from(
      `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
      `<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">` +
      `<sheets><sheet name="Risk Register" sheetId="1" r:id="rId1"/></sheets></workbook>`, 'utf8') },
    { name: 'xl/_rels/workbook.xml.rels', data: Buffer.from(
      `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
      `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
      `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>` +
      `<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>` +
      `</Relationships>`, 'utf8') },
    { name: 'xl/styles.xml', data: Buffer.from(stylesXml(), 'utf8') },
    { name: 'xl/worksheets/sheet1.xml', data: Buffer.from(sheetXml(rows), 'utf8') },
  ]);
}
