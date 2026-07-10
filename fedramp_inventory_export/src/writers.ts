/**
 * Dependency-free CSV + presentation-quality multi-sheet XLSX writer.
 *
 * Produces a stakeholder-ready workbook: an Executive Summary dashboard (KPI
 * tiles + posture + top remediation levers), a security-lever Remediation Plan,
 * family + cluster segmentation, and detailed inventory/compliance sheets — all
 * with title bands, sized columns, banded rows, severity colour-coding, frozen
 * headers, and autofilters. Built on the store-only ZIP primitive FedPy already
 * uses (`core/zip.ts`), so it pulls in NO spreadsheet dependency.
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { xmlEscape, zipStore } from '../../cloud-evidence/core/zip.ts';
import type { ReportTable } from './tables.ts';
import type { ComplianceSummary } from './join.ts';
import type { DashboardModel, Kpi } from './dashboard.ts';
import { COLUMN_META, STATUS_RISK } from './columns.ts';

// --------------------------------------------------------------------------- #
// CSV
// --------------------------------------------------------------------------- #

function csvEscape(v: string): string {
  return /[",\r\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
}

export function tableToCsv(table: ReportTable): string {
  const lines = [table.columns.map(csvEscape).join(',')];
  for (const r of table.rows) lines.push(table.columns.map((c) => csvEscape(r[c] ?? '')).join(','));
  return lines.join('\r\n') + '\r\n';
}

export function writeCsvs(tables: ReportTable[], outDir: string): string[] {
  mkdirSync(outDir, { recursive: true });
  const paths: string[] = [];
  for (const t of tables) {
    const p = join(outDir, `${t.name}.csv`);
    writeFileSync(p, tableToCsv(t));
    paths.push(p);
  }
  return paths;
}

// --------------------------------------------------------------------------- #
// XLSX — style catalogue (index into <cellXfs> below)
// --------------------------------------------------------------------------- #

const S = {
  DEFAULT: 0,
  HEADER: 1,          // table header: bold white on navy
  TITLE: 2,           // big title band
  SUBTITLE: 3,        // italic grey subtitle
  BADBG: 4, AMBERBG: 5, GOODBG: 6, GREYBG: 7,   // status fills (dark text)
  LABEL: 8,           // bold label
  BAND: 9,            // banded (zebra) row fill
  SECTION: 10,        // section header band (white on slate)
  KPI_NUM: 11,        // large KPI number
  KPI_LABEL: 12,      // KPI caption
  KPI_GOOD: 13, KPI_WARN: 14, KPI_BAD: 15, KPI_NEUTRAL: 16, // KPI tile fills (big number)
  NOTE: 17,           // small wrapped note
  BADTX: 18, AMBERTX: 19, GOODTX: 20, // colored TEXT (no fill) for severity words
} as const;

/** Column letter for a 1-based index (1→A, 27→AA). */
function colLetter(n: number): string {
  let str = '';
  while (n > 0) { const m = (n - 1) % 26; str = String.fromCharCode(65 + m) + str; n = Math.floor((n - 1) / 26); }
  return str;
}


class SharedStrings {
  private readonly map = new Map<string, number>();
  readonly list: string[] = [];
  intern(v: string): number {
    let i = this.map.get(v);
    if (i === undefined) { i = this.list.length; this.map.set(v, i); this.list.push(v); }
    return i;
  }
  xml(): string {
    const items = this.list.map((s) => `<si><t xml:space="preserve">${xmlEscape(s)}</t></si>`).join('');
    return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
      `<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="${this.list.length}" uniqueCount="${this.list.length}">${items}</sst>`;
  }
}

function stylesXml(): string {
  // Palette
  const NAVY = 'FF1F3864', SLATE = 'FF44546A', HEADER = 'FF2E5496';
  const RED = 'FFC00000', REDBG = 'FFF4CCCC', AMBERBG = 'FFFFF2CC', GREENBG = 'FFD9EAD3', GREYBG = 'FFEDEDED';
  const BAND = 'FFF5F8FC';
  const GOODK = 'FF548235', WARNK = 'FFBF8F00', BADK = 'FFC00000', NEUK = 'FF2E5496';
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">` +
    `<fonts count="12">` +
      `<font><sz val="10"/><name val="Calibri"/></font>` +                                            // 0 base
      `<font><b/><color rgb="FFFFFFFF"/><sz val="10"/><name val="Calibri"/></font>` +                 // 1 white bold
      `<font><b/><sz val="18"/><color rgb="${NAVY}"/><name val="Calibri"/></font>` +                  // 2 title
      `<font><i/><sz val="11"/><color rgb="FF808080"/><name val="Calibri"/></font>` +                 // 3 subtitle grey
      `<font><b/><sz val="10"/><name val="Calibri"/></font>` +                                        // 4 bold
      `<font><b/><sz val="28"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>` +                 // 5 KPI number white
      `<font><b/><sz val="9"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>` +                  // 6 KPI caption white
      `<font><sz val="9"/><color rgb="FF808080"/><name val="Calibri"/></font>` +                      // 7 note grey
      `<font><b/><color rgb="${RED}"/><sz val="10"/><name val="Calibri"/></font>` +                   // 8 red bold text
      `<font><b/><color rgb="${WARNK}"/><sz val="10"/><name val="Calibri"/></font>` +                 // 9 amber bold text
      `<font><b/><color rgb="${GOODK}"/><sz val="10"/><name val="Calibri"/></font>` +                 // 10 green bold text
      `<font><b/><color rgb="FFFFFFFF"/><sz val="11"/><name val="Calibri"/></font>` +                 // 11 section white bold 11
    `</fonts>` +
    `<fills count="14">` +
      `<fill><patternFill patternType="none"/></fill>` +           // 0
      `<fill><patternFill patternType="gray125"/></fill>` +        // 1
      `<fill><patternFill patternType="solid"><fgColor rgb="${HEADER}"/></patternFill></fill>` +  // 2 header
      `<fill><patternFill patternType="solid"><fgColor rgb="${REDBG}"/></patternFill></fill>` +   // 3 red bg
      `<fill><patternFill patternType="solid"><fgColor rgb="${AMBERBG}"/></patternFill></fill>` + // 4 amber bg
      `<fill><patternFill patternType="solid"><fgColor rgb="${GREENBG}"/></patternFill></fill>` + // 5 green bg
      `<fill><patternFill patternType="solid"><fgColor rgb="${GREYBG}"/></patternFill></fill>` +  // 6 grey bg
      `<fill><patternFill patternType="solid"><fgColor rgb="${BAND}"/></patternFill></fill>` +    // 7 band
      `<fill><patternFill patternType="solid"><fgColor rgb="${SLATE}"/></patternFill></fill>` +   // 8 section slate
      `<fill><patternFill patternType="solid"><fgColor rgb="${GOODK}"/></patternFill></fill>` +   // 9 KPI good
      `<fill><patternFill patternType="solid"><fgColor rgb="${WARNK}"/></patternFill></fill>` +   // 10 KPI warn
      `<fill><patternFill patternType="solid"><fgColor rgb="${BADK}"/></patternFill></fill>` +    // 11 KPI bad
      `<fill><patternFill patternType="solid"><fgColor rgb="${NEUK}"/></patternFill></fill>` +    // 12 KPI neutral
      `<fill><patternFill patternType="solid"><fgColor rgb="FFFFFFFF"/></patternFill></fill>` +   // 13 white
    `</fills>` +
    `<borders count="2">` +
      `<border><left/><right/><top/><bottom/><diagonal/></border>` +                              // 0 none
      `<border><left style="thin"><color rgb="FFD9D9D9"/></left><right style="thin"><color rgb="FFD9D9D9"/></right><top style="thin"><color rgb="FFD9D9D9"/></top><bottom style="thin"><color rgb="FFD9D9D9"/></bottom></border>` + // 1 thin grey
    `</borders>` +
    `<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>` +
    `<cellXfs count="21">` +
      `<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1"><alignment vertical="center" wrapText="1"/></xf>` + // 0 default (wrap+border)
      `<xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"><alignment vertical="center" wrapText="1"/></xf>` + // 1 header
      `<xf numFmtId="0" fontId="2" fillId="0" borderId="0" xfId="0" applyFont="1"><alignment vertical="center"/></xf>` +   // 2 title
      `<xf numFmtId="0" fontId="3" fillId="0" borderId="0" xfId="0" applyFont="1"/>` +                                     // 3 subtitle
      `<xf numFmtId="0" fontId="0" fillId="3" borderId="1" xfId="0" applyFill="1" applyBorder="1"><alignment vertical="center" wrapText="1"/></xf>` + // 4 red bg
      `<xf numFmtId="0" fontId="0" fillId="4" borderId="1" xfId="0" applyFill="1" applyBorder="1"><alignment vertical="center" wrapText="1"/></xf>` + // 5 amber bg
      `<xf numFmtId="0" fontId="0" fillId="5" borderId="1" xfId="0" applyFill="1" applyBorder="1"><alignment vertical="center" wrapText="1"/></xf>` + // 6 green bg
      `<xf numFmtId="0" fontId="0" fillId="6" borderId="1" xfId="0" applyFill="1" applyBorder="1"><alignment vertical="center" wrapText="1"/></xf>` + // 7 grey bg
      `<xf numFmtId="0" fontId="4" fillId="0" borderId="0" xfId="0" applyFont="1"><alignment vertical="center"/></xf>` +   // 8 label bold
      `<xf numFmtId="0" fontId="0" fillId="7" borderId="1" xfId="0" applyFill="1" applyBorder="1"><alignment vertical="center" wrapText="1"/></xf>` + // 9 band
      `<xf numFmtId="0" fontId="11" fillId="8" borderId="0" xfId="0" applyFont="1" applyFill="1"><alignment vertical="center"/></xf>` + // 10 section band
      `<xf numFmtId="0" fontId="5" fillId="0" borderId="0" xfId="0" applyFont="1"><alignment horizontal="center" vertical="center"/></xf>` + // 11 KPI number (fill set per-tile)
      `<xf numFmtId="0" fontId="6" fillId="0" borderId="0" xfId="0" applyFont="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf>` + // 12 KPI caption
      `<xf numFmtId="0" fontId="5" fillId="9" borderId="0" xfId="0" applyFont="1" applyFill="1"><alignment horizontal="center" vertical="center"/></xf>` +  // 13 KPI good
      `<xf numFmtId="0" fontId="5" fillId="10" borderId="0" xfId="0" applyFont="1" applyFill="1"><alignment horizontal="center" vertical="center"/></xf>` + // 14 KPI warn
      `<xf numFmtId="0" fontId="5" fillId="11" borderId="0" xfId="0" applyFont="1" applyFill="1"><alignment horizontal="center" vertical="center"/></xf>` + // 15 KPI bad
      `<xf numFmtId="0" fontId="5" fillId="12" borderId="0" xfId="0" applyFont="1" applyFill="1"><alignment horizontal="center" vertical="center"/></xf>` + // 16 KPI neutral
      `<xf numFmtId="0" fontId="7" fillId="0" borderId="0" xfId="0" applyFont="1"><alignment vertical="top" wrapText="1"/></xf>` + // 17 note
      `<xf numFmtId="0" fontId="8" fillId="0" borderId="1" xfId="0" applyFont="1" applyBorder="1"><alignment vertical="center"/></xf>` + // 18 red text
      `<xf numFmtId="0" fontId="9" fillId="0" borderId="1" xfId="0" applyFont="1" applyBorder="1"><alignment vertical="center"/></xf>` + // 19 amber text
      `<xf numFmtId="0" fontId="10" fillId="0" borderId="1" xfId="0" applyFont="1" applyBorder="1"><alignment vertical="center"/></xf>` + // 20 green text
    `</cellXfs>` +
    `<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>` +
    `</styleSheet>`;
}

interface Cell { v: string; s: number }
interface Merge { r1: number; c1: number; r2: number; c2: number } // 0-based inclusive
interface SheetSpec {
  title: string;
  matrix: Cell[][];
  freezeRow: number;      // rows to freeze at top (0 = none)
  autofilterRow: number;  // 1-based header row for autofilter (0 = none)
  cols: Array<{ min: number; max: number; width: number }>;
  merges: Merge[];
  hideGridlines?: boolean;  // clean look for dashboard / summary layouts
}

function cell(v: string, s: number = S.DEFAULT): Cell { return { v, s }; }

function sheetXml(spec: SheetSpec, ss: SharedStrings): string {
  const nCols = Math.max(1, spec.matrix.reduce((m, r) => Math.max(m, r.length), 0));
  const rowsXml = spec.matrix.map((cells, ri) => {
    const r = ri + 1;
    const cellsXml = cells.map((c, ci) => {
      const ref = `${colLetter(ci + 1)}${r}`;
      const sAttr = c.s ? ` s="${c.s}"` : '';
      if (c.v === '') return `<c r="${ref}"${sAttr}/>`;
      return `<c r="${ref}"${sAttr} t="s"><v>${ss.intern(c.v)}</v></c>`;
    }).join('');
    return `<row r="${r}">${cellsXml}</row>`;
  }).join('');

  const colsXml = spec.cols.length
    ? `<cols>${spec.cols.map((c) => `<col min="${c.min}" max="${c.max}" width="${c.width}" customWidth="1"/>`).join('')}</cols>`
    : '';
  const gl = spec.hideGridlines ? ' showGridLines="0"' : '';
  const pane = spec.freezeRow > 0
    ? `<sheetViews><sheetView${gl} workbookViewId="0"><pane ySplit="${spec.freezeRow}" topLeftCell="A${spec.freezeRow + 1}" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>`
    : `<sheetViews><sheetView${gl} workbookViewId="0"/></sheetViews>`;
  const filter = spec.autofilterRow > 0 && spec.matrix.length > spec.autofilterRow
    ? `<autoFilter ref="A${spec.autofilterRow}:${colLetter(nCols)}${spec.matrix.length}"/>`
    : '';
  const merges = spec.merges.length
    ? `<mergeCells count="${spec.merges.length}">${spec.merges.map((m) => `<mergeCell ref="${colLetter(m.c1 + 1)}${m.r1 + 1}:${colLetter(m.c2 + 1)}${m.r2 + 1}"/>`).join('')}</mergeCells>`
    : '';

  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">` +
    `<dimension ref="A1:${colLetter(nCols)}${Math.max(1, spec.matrix.length)}"/>` +
    pane + colsXml +
    `<sheetData>${rowsXml}</sheetData>` +
    filter + merges +
    `</worksheet>`;
}

// --------------------------------------------------------------------------- #
// Table → styled sheet (title band, header, banded rows, status colour)
// --------------------------------------------------------------------------- #

/**
 * Per-column widths: use the curated metadata when known, else estimate from
 * header + sampled cell lengths (capped). Metadata gives ARNs/detail room and
 * keeps narrow flags narrow — cleaner than pure autosize.
 */
function columnWidths(table: ReportTable): Array<{ min: number; max: number; width: number }> {
  return table.columns.map((col, i) => {
    const meta = COLUMN_META[col];
    if (meta) return { min: i + 1, max: i + 1, width: meta.width };
    let w = col.length;
    const sample = table.rows.length > 400 ? table.rows.slice(0, 400) : table.rows;
    for (const r of sample) w = Math.max(w, (r[col] ?? '').length);
    return { min: i + 1, max: i + 1, width: Math.min(Math.max(w + 2, 9), 50) };
  });
}

/** Fill index for a status/risk tone. */
function toneFill(tone: 'red' | 'amber' | 'good' | 'grey'): number {
  return tone === 'red' ? S.BADBG : tone === 'amber' ? S.AMBERBG : tone === 'good' ? S.GOODBG : S.GREYBG;
}

function tableSheet(table: ReportTable): SheetSpec {
  const matrix: Cell[][] = [];
  // Title band (row 1).
  matrix.push([cell(table.title, S.TITLE)]);
  const headerRowIdx = 2;
  matrix.push(table.columns.map((c) => cell(c, S.HEADER)));

  // Precompute per-column risk rules + status-word rules. (All data styles wrap
  // long text already, so no separate wrap handling is needed here.)
  const colRisk = table.columns.map((c) => COLUMN_META[c]?.risk);
  const colStatus = table.columns.map((c) => STATUS_RISK[c]);

  table.rows.forEach((row, ri) => {
    const band = ri % 2 === 1;
    const cells = table.columns.map((c) => cell(row[c] ?? '', band ? S.BAND : S.DEFAULT));
    cells.forEach((cc, i) => {
      if (!cc.v) return;
      // 1) Compliance/finding status words (Status/Result/Priority/Severity).
      const sr = colStatus[i];
      if (sr) { const t = sr(cc.v); if (t) { cc.s = toneFill(t); return; } }
      // 2) Inventory control cells (Encryption=No, Public=Yes, MFA=No, ...).
      const rr = colRisk[i];
      if (rr && rr.when(cc.v)) { cc.s = toneFill(rr.tone); }
    });
    matrix.push(cells);
  });
  return {
    title: table.title,
    matrix,
    freezeRow: headerRowIdx,
    autofilterRow: headerRowIdx,
    cols: columnWidths(table),
    merges: [{ r1: 0, c1: 0, r2: 0, c2: Math.max(0, table.columns.length - 1) }],
  };
}

// --------------------------------------------------------------------------- #
// Executive dashboard sheet (bespoke layout)
// --------------------------------------------------------------------------- #

const KPI_TONE: Record<Kpi['tone'], number> = { good: S.KPI_GOOD, warn: S.KPI_WARN, bad: S.KPI_BAD, neutral: S.KPI_NEUTRAL };

function dashboardSheet(d: DashboardModel): SheetSpec {
  const WIDTH = 12; // grid columns
  const matrix: Cell[][] = [];
  const merges: Merge[] = [];
  const blank = () => Array.from({ length: WIDTH }, () => cell(''));
  const rowIdx = () => matrix.length; // 0-based index of the row we're about to push

  // Title + subtitle.
  let r = rowIdx(); matrix.push([cell(d.title, S.TITLE), ...Array.from({ length: WIDTH - 1 }, () => cell(''))]);
  merges.push({ r1: r, c1: 0, r2: r, c2: WIDTH - 1 });
  r = rowIdx(); matrix.push([cell(d.subtitle, S.SUBTITLE), ...Array.from({ length: WIDTH - 1 }, () => cell(''))]);
  merges.push({ r1: r, c1: 0, r2: r, c2: WIDTH - 1 });
  r = rowIdx(); matrix.push([cell(`Account ${d.account}   ·   Generated ${d.generatedAt}`, S.SUBTITLE), ...Array.from({ length: WIDTH - 1 }, () => cell(''))]);
  merges.push({ r1: r, c1: 0, r2: r, c2: WIDTH - 1 });
  matrix.push(blank());

  // Section: KPIs — 3 tiles per band (number row + caption row), each tile 4 cols wide.
  const section = (label: string) => {
    const rr = rowIdx();
    matrix.push([cell(label, S.SECTION), ...Array.from({ length: WIDTH - 1 }, () => cell(''))]);
    merges.push({ r1: rr, c1: 0, r2: rr, c2: WIDTH - 1 });
  };
  section('Key Posture Indicators');
  const perRow = 3, tileW = WIDTH / perRow; // 4
  for (let i = 0; i < d.kpis.length; i += perRow) {
    const group = d.kpis.slice(i, i + perRow);
    // number row
    const numRow = blank(); const capRow = blank(); const noteRow = blank();
    group.forEach((k, gi) => {
      const c0 = gi * tileW;
      numRow[c0] = cell(k.value, KPI_TONE[k.tone]);
      capRow[c0] = cell(k.label, S.KPI_LABEL);
      noteRow[c0] = cell(k.note ?? '', S.NOTE);
    });
    const rn = rowIdx(); matrix.push(numRow);
    group.forEach((_, gi) => merges.push({ r1: rn, c1: gi * tileW, r2: rn, c2: gi * tileW + tileW - 1 }));
    const rc = rowIdx(); matrix.push(capRow);
    group.forEach((_, gi) => merges.push({ r1: rc, c1: gi * tileW, r2: rc, c2: gi * tileW + tileW - 1 }));
    const rnote = rowIdx(); matrix.push(noteRow);
    group.forEach((_, gi) => merges.push({ r1: rnote, c1: gi * tileW, r2: rnote, c2: gi * tileW + tileW - 1 }));
    matrix.push(blank());
  }

  // Section: Control posture table.
  section('Control Posture (NIST 800-53)');
  const postHeader = ['Framework', 'In Scope', 'Satisfied', 'Partial', 'Not Satisfied', 'Not Assessed', 'Assessed Pass'];
  const ph = blank(); postHeader.forEach((h, i) => ph[i] = cell(h, S.HEADER)); matrix.push(ph);
  for (const p of d.controlPosture) {
    const row = blank();
    row[0] = cell(p.framework, S.DEFAULT);
    row[1] = cell(String(p.inScope), S.DEFAULT);
    row[2] = cell(String(p.satisfied), S.GOODBG);
    row[3] = cell(String(p.partial), S.AMBERBG);
    row[4] = cell(String(p.notSatisfied), S.BADBG);
    row[5] = cell(String(p.notAssessed), S.GREYBG);
    row[6] = cell(`${(p.assessedPassRate * 100).toFixed(0)}%`, S.DEFAULT);
    matrix.push(row);
  }
  matrix.push(blank());

  // Section: open findings by severity.
  section('Open Findings by Severity');
  const sevH = blank(); ['Critical', 'High', 'Medium', 'Low'].forEach((h, i) => sevH[i] = cell(h, S.HEADER)); matrix.push(sevH);
  const sevRow = blank();
  sevRow[0] = cell(String(d.severity.critical), S.BADBG);
  sevRow[1] = cell(String(d.severity.high), S.BADBG);
  sevRow[2] = cell(String(d.severity.medium), S.AMBERBG);
  sevRow[3] = cell(String(d.severity.low), S.GREYBG);
  matrix.push(sevRow);
  matrix.push(blank());

  // Section: top remediation levers.
  section('Top Remediation Levers (deploy priorities)');
  const levH = blank(); ['Security Lever', '', '', '', 'Findings', 'Critical', 'High', 'Suggested Owner'].forEach((h, i) => levH[i] = cell(h, S.HEADER));
  merges.push({ r1: rowIdx(), c1: 0, r2: rowIdx(), c2: 3 });
  merges.push({ r1: rowIdx(), c1: 7, r2: rowIdx(), c2: WIDTH - 1 });
  matrix.push(levH);
  for (const l of d.topLevers) {
    const rr = rowIdx();
    const row = blank();
    row[0] = cell(l.lever, S.DEFAULT);
    row[4] = cell(String(l.findings), S.DEFAULT);
    row[5] = cell(String(l.critical), l.critical > 0 ? S.BADBG : S.DEFAULT);
    row[6] = cell(String(l.high), l.high > 0 ? S.AMBERBG : S.DEFAULT);
    row[7] = cell(l.owner, S.DEFAULT);
    matrix.push(row);
    merges.push({ r1: rr, c1: 0, r2: rr, c2: 3 });
    merges.push({ r1: rr, c1: 7, r2: rr, c2: WIDTH - 1 });
  }
  matrix.push(blank());

  // Section: family posture (top non-compliant).
  section('Posture by Resource Family');
  const famH = blank(); ['Family', '', 'Assets', 'Non-Compliant'].forEach((h, i) => famH[i] = cell(h, S.HEADER));
  merges.push({ r1: rowIdx(), c1: 0, r2: rowIdx(), c2: 1 });
  matrix.push(famH);
  for (const f of d.familyPosture) {
    const rr = rowIdx();
    const row = blank();
    row[0] = cell(f.family, S.DEFAULT);
    row[2] = cell(String(f.assets), S.DEFAULT);
    row[3] = cell(String(f.nonCompliant), f.nonCompliant > 0 ? S.BADBG : S.GOODBG);
    matrix.push(row);
    merges.push({ r1: rr, c1: 0, r2: rr, c2: 1 });
  }
  matrix.push(blank());

  // Section: how to read.
  section('How to Read This Workbook');
  for (const n of d.notes) {
    const rr = rowIdx();
    matrix.push([cell('•  ' + n, S.NOTE), ...Array.from({ length: WIDTH - 1 }, () => cell(''))]);
    merges.push({ r1: rr, c1: 0, r2: rr, c2: WIDTH - 1 });
  }

  return {
    title: 'Executive Summary',
    matrix,
    freezeRow: 0,
    autofilterRow: 0,
    cols: Array.from({ length: WIDTH }, (_, i) => ({ min: i + 1, max: i + 1, width: i === 0 ? 26 : 13 })),
    merges,
    hideGridlines: true,
  };
}

// --------------------------------------------------------------------------- #
// Workbook assembly
// --------------------------------------------------------------------------- #

export interface WorkbookMeta {
  title: string;
  subtitle: string;
  coverFacts: Array<[string, string]>;
  dashboard?: DashboardModel;
}

function safeSheetName(title: string, used: Set<string>): string {
  let n = title.replace(/[:\\/?*\[\]]/g, '-').slice(0, 31).trim() || 'Sheet';
  if (used.has(n.toLowerCase())) {
    const base = n.slice(0, 28);
    let i = 2;
    while (used.has(`${base}-${i}`.toLowerCase())) i++;
    n = `${base}-${i}`;
  }
  used.add(n.toLowerCase());
  return n;
}

/** Produce a multi-sheet `.xlsx`: [Executive Summary] + one sheet per table. */
export function buildWorkbook(tables: ReportTable[], meta: WorkbookMeta): Buffer {
  const ss = new SharedStrings();
  const usedNames = new Set<string>();
  const specs: SheetSpec[] = [];
  if (meta.dashboard) {
    const d = dashboardSheet(meta.dashboard);
    d.title = safeSheetName('Executive Summary', usedNames);
    specs.push(d);
  }
  for (const t of tables) {
    const s = tableSheet(t);
    s.title = safeSheetName(t.title, usedNames);
    specs.push(s);
  }

  const sheetXmls = specs.map((spec) => sheetXml(spec, ss));
  const sheetEntries = specs.map((s, i) => ({ name: `xl/worksheets/sheet${i + 1}.xml`, data: Buffer.from(sheetXmls[i]!, 'utf8') }));

  const contentTypes =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
    `<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
    `<Default Extension="xml" ContentType="application/xml"/>` +
    `<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
    specs.map((_, i) => `<Override PartName="/xl/worksheets/sheet${i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`).join('') +
    `<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>` +
    `<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>` +
    `</Types>`;

  const rootRels =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
    `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>` +
    `</Relationships>`;

  const workbookXml =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">` +
    `<sheets>` +
    specs.map((s, i) => `<sheet name="${xmlEscape(s.title)}" sheetId="${i + 1}" r:id="rId${i + 1}"/>`).join('') +
    `</sheets></workbook>`;

  const sheetRelParts = specs.map((_, i) => `<Relationship Id="rId${i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${i + 1}.xml"/>`).join('');
  const stylesRid = specs.length + 1;
  const ssRid = specs.length + 2;
  const workbookRels =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
    sheetRelParts +
    `<Relationship Id="rId${stylesRid}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>` +
    `<Relationship Id="rId${ssRid}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>` +
    `</Relationships>`;

  const files: Array<{ name: string; data: Buffer }> = [
    { name: '[Content_Types].xml', data: Buffer.from(contentTypes, 'utf8') },
    { name: '_rels/.rels', data: Buffer.from(rootRels, 'utf8') },
    { name: 'xl/workbook.xml', data: Buffer.from(workbookXml, 'utf8') },
    { name: 'xl/_rels/workbook.xml.rels', data: Buffer.from(workbookRels, 'utf8') },
    { name: 'xl/styles.xml', data: Buffer.from(stylesXml(), 'utf8') },
    ...sheetEntries,
    { name: 'xl/sharedStrings.xml', data: Buffer.from(ss.xml(), 'utf8') },
  ];
  return zipStore(files);
}

export function writeWorkbook(tables: ReportTable[], meta: WorkbookMeta, path: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, buildWorkbook(tables, meta));
}

/** Cover facts (kept for back-compat / callers that don't build a dashboard). */
export function summaryCoverFacts(summary: ComplianceSummary): Array<[string, string]> {
  const p = (n: number) => `${(n * 100).toFixed(1)}%`;
  return [
    ['Impact level', 'Moderate'],
    ['Frameworks', 'FedRAMP 20x + NIST 800-53 Rev5'],
    ['Assets — total', String(summary.assetCount)],
    ['  non-compliant', String(summary.assetsNonCompliant)],
    ['  not-assessed', String(summary.assetsNotAssessed)],
    ['Requirements — not met / partial / met', `${summary.requirementsNotMet} / ${summary.requirementsPartial} / ${summary.requirementsMet}`],
    ['Findings — failing / total', `${summary.findingsFailing} / ${summary.findingsTotal}`],
    ['Rev5 assessed pass rate', p(summary.rev5.assessedPassRate)],
    ['20x assessed pass rate', p(summary.twentyX.assessedPassRate)],
  ];
}
