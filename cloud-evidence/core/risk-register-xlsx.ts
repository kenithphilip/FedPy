/**
 * LOOP-B.B5 — Risk Register XLSX renderer.
 *
 * Renders the aggregated RiskRegisterEntry[] into a single-sheet `.xlsx`
 * ("Risk Register") using the repo's dependency-free store-only OOXML writer
 * (core/zip.ts) — the same pattern as core/inventory-workbook.ts. No SheetJS.
 *
 * Layout (per-slice doc §"XLSX structure"): 20 columns A..T, header row 1,
 * one data row per entry from row 2. A frozen header pane (Q7) keeps the header
 * visible on scroll. Conditional formatting is applied at emit time:
 *   - column G (Inherent Risk) gets a red fill when the band is high / very-high;
 *   - column H (Residual Risk) gets a bold-red fill when the band is very-high;
 *   - column T (Description) wraps long text.
 *
 * The output is OOXML-spec-compliant and round-trips through the repo's zip
 * reader (tests inflate/parse it directly — the tracker toolchain and this
 * package ship no SheetJS dependency, so "SheetJS round-trip" from the spec is
 * realised as "valid-OOXML round-trip", tracked as LOOP-B-RISKS B.B5-11).
 */
import { xmlEscape, zipStore } from './zip.ts';
import type { RiskRegisterEntry } from './risk-register.ts';

/** The 20 columns A..T in order. */
export const RISK_REGISTER_COLUMNS: readonly string[] = [
  'Risk ID', 'Source', 'Title', 'Category', 'Likelihood', 'Impact',
  'Inherent Risk', 'Residual Risk', 'Treatment', 'Owner', 'Review Date',
  'Status', 'Linked POA&M Item', 'Linked Acceptance', 'Compensating Controls',
  'NIST Controls', 'CVSS Base', 'EPSS Score', 'EPSS Percentile', 'Description',
] as const;

// Style indices into cellXfs (see stylesXml below).
const S_DEFAULT = 0;
const S_RED_FILL = 1;   // high/very-high inherent
const S_BOLD_RED = 2;   // very-high residual
const S_WRAP = 3;       // description column

/** Map a register entry to its 20 ordered cell values (all strings). */
export function entryToRow(e: RiskRegisterEntry): string[] {
  const num = (n: number | undefined): string => (typeof n === 'number' && Number.isFinite(n) ? String(n) : '');
  return [
    e.uuid,
    e.source,
    e.title,
    e.category,
    e.likelihood,
    e.impact,
    e.inherent_risk,
    e.residual_risk,
    e.treatment,
    e.owner,
    e.review_date,
    e.status,
    e.references.poam_item_uuid ?? '',
    e.references.acceptance_uuid ?? '',
    (e.references.compensating_control_uuids ?? []).join(';'),
    (e.references.nist_control_ids ?? []).join(';'),
    num(e.references.cvss_base),
    num(e.references.epss_score),
    num(e.references.epss_percentile),
    e.description,
  ];
}

/** Per-cell style index for a data row (conditional formatting at emit time). */
function styleForCell(colIdx: number, entry: RiskRegisterEntry): number {
  if (colIdx === 6 && (entry.inherent_risk === 'high' || entry.inherent_risk === 'very-high')) return S_RED_FILL;
  if (colIdx === 7 && entry.residual_risk === 'very-high') return S_BOLD_RED;
  if (colIdx === 19) return S_WRAP;
  return S_DEFAULT;
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

function sheetXml(entries: RiskRegisterEntry[]): string {
  const headers = RISK_REGISTER_COLUMNS;
  // Header row (row 1) — no per-cell style.
  const headerCells = headers.map((h, ci) => cellXml(`${colLetter(ci + 1)}1`, h, S_DEFAULT)).join('');
  const rows: string[] = [`<row r="1">${headerCells}</row>`];
  for (let ri = 0; ri < entries.length; ri++) {
    const e = entries[ri]!;
    const r = ri + 2;
    const values = entryToRow(e);
    const cells = values.map((v, ci) => cellXml(`${colLetter(ci + 1)}${r}`, v, styleForCell(ci, e))).join('');
    rows.push(`<row r="${r}">${cells}</row>`);
  }
  // Frozen header pane (Q7): split below row 1.
  const pane = `<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>`;
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">` +
    `${pane}<sheetData>${rows.join('')}</sheetData></worksheet>`;
}

function stylesXml(): string {
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">` +
    `<fonts count="2">` +
      `<font><sz val="11"/><name val="Calibri"/></font>` +
      `<font><b/><color rgb="FF9C0006"/><sz val="11"/><name val="Calibri"/></font>` +
    `</fonts>` +
    `<fills count="3">` +
      `<fill><patternFill patternType="none"/></fill>` +
      `<fill><patternFill patternType="gray125"/></fill>` +
      `<fill><patternFill patternType="solid"><fgColor rgb="FFFFC7CE"/><bgColor indexed="64"/></patternFill></fill>` +
    `</fills>` +
    `<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>` +
    `<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>` +
    `<cellXfs count="4">` +
      `<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>` +
      `<xf numFmtId="0" fontId="0" fillId="2" borderId="0" xfId="0" applyFill="1"/>` +
      `<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/>` +
      `<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment wrapText="1"/></xf>` +
    `</cellXfs>` +
    `<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>` +
    `</styleSheet>`;
}

/** Produce a valid single-sheet `.xlsx` for the risk register. */
export function renderRiskRegisterXlsx(entries: RiskRegisterEntry[]): Buffer {
  const files: Array<{ name: string; data: Buffer }> = [
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
    { name: 'xl/worksheets/sheet1.xml', data: Buffer.from(sheetXml(entries), 'utf8') },
  ];
  return zipStore(files);
}
