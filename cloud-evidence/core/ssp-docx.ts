/**
 * OSCAL System Security Plan → FedRAMP Word (.docx) renderer — SSP-2.
 *
 * Renders the draft OSCAL SSP we emit (SSP-1, core/oscal-ssp.ts) into a
 * human-readable Word document so a system owner can review, complete, and
 * circulate it without first loading the JSON into a GRC tool.
 *
 * Dependency-free: a `.docx` is a ZIP of WordprocessingML (OOXML) XML parts, so
 * we build the parts as strings and pack them with the same store-only ZIP writer
 * used for the inventory `.xlsx` (core/zip.ts) — no python-docx, no `docx` npm
 * package, no runtime network. The idea (OSCAL → FedRAMP template prose) is drawn
 * clean-room from the CC0 GoComply/fedramp tool (research report 09); no code copied.
 *
 * Pure renderer (`renderSspDocx`) + a disk reader/emitter (`emitSspDocx`).
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { xmlEscape, zipStore } from './zip.ts';
import { log } from './log.ts';

const W_NS = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main';

// ─────────────────────────── OOXML building blocks ───────────────────────────

/** A paragraph in the given style (Normal when omitted). Empty text → spacer. */
function para(text: string, style?: string): string {
  const pPr = style ? `<w:pPr><w:pStyle w:val="${style}"/></w:pPr>` : '';
  if (text === '') return `<w:p>${pPr}</w:p>`;
  // Preserve hard line breaks within a single logical paragraph.
  const runs = text.split('\n').map((line, i) =>
    `${i > 0 ? '<w:br/>' : ''}<w:t xml:space="preserve">${xmlEscape(line)}</w:t>`,
  ).join('');
  return `<w:p>${pPr}<w:r>${runs}</w:r></w:p>`;
}

function heading(text: string, level: 1 | 2 | 3): string {
  return para(text, `Heading${level}`);
}

/** A 2-column field/value table. */
function fieldTable(rows: Array<[string, string]>): string {
  return table(['Field', 'Value'], rows.map(([k, v]) => [k, v]), [2400, 6600], { headerRow: false });
}

interface TableOpts { headerRow?: boolean; widthsDxa?: number[] }

/** A bordered table. `widths` are column widths in twips (dxa); 1 inch = 1440. */
function table(headers: string[], rows: string[][], widths: number[], opts: TableOpts = {}): string {
  const headerRow = opts.headerRow ?? true;
  const grid = `<w:tblGrid>${widths.map((w) => `<w:gridCol w:w="${w}"/>`).join('')}</w:tblGrid>`;
  const border = '<w:top w:val="single" w:sz="4" w:space="0" w:color="999999"/>' +
    '<w:left w:val="single" w:sz="4" w:space="0" w:color="999999"/>' +
    '<w:bottom w:val="single" w:sz="4" w:space="0" w:color="999999"/>' +
    '<w:right w:val="single" w:sz="4" w:space="0" w:color="999999"/>' +
    '<w:insideH w:val="single" w:sz="4" w:space="0" w:color="999999"/>' +
    '<w:insideV w:val="single" w:sz="4" w:space="0" w:color="999999"/>';
  const tblPr = `<w:tblPr><w:tblW w:w="0" w:type="auto"/><w:tblBorders>${border}</w:tblBorders></w:tblPr>`;

  const cell = (text: string, w: number, bold: boolean, shade: boolean): string => {
    const shadeXml = shade ? '<w:shd w:val="clear" w:color="auto" w:fill="E7E6E6"/>' : '';
    const runPr = bold ? '<w:rPr><w:b/></w:rPr>' : '';
    const runs = text.split('\n').map((line, i) =>
      `${i > 0 ? '<w:br/>' : ''}<w:t xml:space="preserve">${xmlEscape(line)}</w:t>`,
    ).join('');
    return `<w:tc><w:tcPr><w:tcW w:w="${w}" w:type="dxa"/>${shadeXml}</w:tcPr>` +
      `<w:p><w:r>${runPr}${runs}</w:r></w:p></w:tc>`;
  };

  const tr = (cells: string[], bold: boolean, shade: boolean): string =>
    `<w:tr>${cells.map((c, i) => cell(c, widths[i] ?? 2000, bold, shade)).join('')}</w:tr>`;

  const body: string[] = [];
  if (headerRow) body.push(tr(headers, true, true));
  for (const r of rows) body.push(tr(r, false, false));
  return `<w:tbl>${tblPr}${grid}${body.join('')}</w:tbl>`;
}

// ───────────────────────────── document assembly ─────────────────────────────

function get<T = any>(o: any, path: string, dflt: T): T {
  let cur = o;
  for (const k of path.split('.')) { if (cur == null) return dflt; cur = cur[k]; }
  return (cur ?? dflt) as T;
}

const STATUS_LABEL: Record<string, string> = {
  implemented: 'Implemented',
  partial: 'Partially Implemented',
  planned: 'Planned',
  alternative: 'Alternative Implementation',
  'not-applicable': 'Not Applicable',
};

function bodyXml(ssp: any): { xml: string; controlCount: number } {
  const sc = ssp['system-characteristics'] ?? {};
  const si = ssp['system-implementation'] ?? {};
  const ci = ssp['control-implementation'] ?? {};
  const meta = ssp.metadata ?? {};
  const level = get<string>(sc, 'security-sensitivity-level', 'moderate');
  const systemName = get<string>(sc, 'system-name', 'Cloud System');
  const parts: string[] = [];

  // ── Title block ──
  parts.push(para(systemName, 'Title'));
  parts.push(para(`System Security Plan — FedRAMP ${level} (DRAFT)`, 'Subtitle'));
  if (meta.remarks) parts.push(para(meta.remarks, 'Disclaimer'));
  parts.push(para(''));

  // ── 1. Document metadata ──
  parts.push(heading('1. Document Information', 1));
  const orgName = (meta.parties ?? []).find((p: any) => p.type === 'organization')?.name;
  const tool = (meta.props ?? []).find((p: any) => p.name === 'tool')?.value;
  const frmr = (meta.props ?? []).find((p: any) => p.name === 'frmr-version')?.value;
  parts.push(fieldTable([
    ['Document Title', String(meta.title ?? '')],
    ['Version', String(meta.version ?? '')],
    ['OSCAL Version', String(meta['oscal-version'] ?? '')],
    ['Last Modified', String(meta['last-modified'] ?? '')],
    ...(orgName ? [['Organization', orgName] as [string, string]] : []),
    ...(tool ? [['Generated By', tool] as [string, string]] : []),
    ...(frmr ? [['FRMR Version', frmr] as [string, string]] : []),
    ['Imports Profile', String(get(ssp, 'import-profile.href', ''))],
  ]));
  parts.push(para(''));

  // ── 2. System characteristics ──
  parts.push(heading('2. System Characteristics', 1));
  const sysId = (sc['system-ids'] ?? [])[0]?.id ?? '';
  parts.push(fieldTable([
    ['System Name', systemName],
    ['System ID', String(sysId)],
    ['Security Sensitivity Level', String(level)],
    ['Operational Status', String(get(sc, 'status.state', ''))],
  ]));
  parts.push(heading('2.1 System Description', 2));
  parts.push(para(String(sc.description ?? '')));

  const sil = sc['security-impact-level'];
  if (sil) {
    parts.push(heading('2.2 Security Impact Level (FIPS-199)', 2));
    parts.push(table(
      ['Security Objective', 'Impact'],
      [
        ['Confidentiality', String(sil['security-objective-confidentiality'] ?? '')],
        ['Integrity', String(sil['security-objective-integrity'] ?? '')],
        ['Availability', String(sil['security-objective-availability'] ?? '')],
      ],
      [4500, 4500],
    ));
  }

  const its: any[] = get(sc, 'system-information.information-types', []);
  if (its.length) {
    parts.push(heading('2.3 Information Types', 2));
    parts.push(table(
      ['Information Type', 'Description'],
      its.map((it) => [String(it.title ?? ''), String(it.description ?? '')]),
      [2700, 6300],
    ));
  }

  parts.push(heading('2.4 Authorization Boundary', 2));
  parts.push(para(String(get(sc, 'authorization-boundary.description', ''))));
  parts.push(para(''));

  // ── 3. System implementation ──
  parts.push(heading('3. System Implementation', 1));
  const components: any[] = si.components ?? [];
  if (components.length) {
    parts.push(heading('3.1 Components', 2));
    parts.push(table(
      ['Title', 'Type', 'Status', 'Description'],
      components.map((c) => [
        String(c.title ?? ''), String(c.type ?? ''),
        String(get(c, 'status.state', '')), String(c.description ?? ''),
      ]),
      [2200, 1400, 1400, 4000],
    ));
  }
  const users: any[] = si.users ?? [];
  if (users.length) {
    parts.push(heading('3.2 Users', 2));
    parts.push(table(
      ['Title', 'Roles', 'Description'],
      users.map((u) => [
        String(u.title ?? ''), (u['role-ids'] ?? []).join(', '), String(u.description ?? ''),
      ]),
      [2400, 2200, 4400],
    ));
  }
  parts.push(para(''));

  // ── 4. Control implementation ──
  parts.push(heading('4. Control Implementation', 1));
  if (ci.description) parts.push(para(String(ci.description)));
  const irs: any[] = ci['implemented-requirements'] ?? [];

  // Status summary.
  const counts: Record<string, number> = {};
  for (const ir of irs) {
    const st = get<string>(ir, 'by-components.0.implementation-status.state', 'planned');
    counts[st] = (counts[st] ?? 0) + 1;
  }
  parts.push(heading('4.1 Implementation Status Summary', 2));
  parts.push(table(
    ['Status', 'Controls'],
    Object.keys(STATUS_LABEL)
      .filter((k) => counts[k])
      .map((k) => [STATUS_LABEL[k]!, String(counts[k])]),
    [4500, 4500],
  ));

  // Per-control implementation table.
  parts.push(heading('4.2 Controls', 2));
  parts.push(table(
    ['Control', 'Status', 'Implementation Statement'],
    irs.map((ir) => {
      const id = String(ir['control-id'] ?? '').toUpperCase();
      const name = (ir.props ?? []).find((p: any) => p.name === 'control-name')?.value ?? '';
      const st = get<string>(ir, 'by-components.0.implementation-status.state', 'planned');
      const desc = get<string>(ir, 'by-components.0.description', '');
      return [name ? `${id}\n${name}` : id, STATUS_LABEL[st] ?? st, desc];
    }),
    [1700, 1600, 5700],
  ));

  // ── Page geometry (US Letter) ──
  const sectPr = '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/>' +
    '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr>';

  const xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<w:document xmlns:w="${W_NS}"><w:body>${parts.join('')}${sectPr}</w:body></w:document>`;
  return { xml, controlCount: irs.length };
}

function stylesXml(): string {
  const style = (id: string, name: string, opts: { size?: number; bold?: boolean; color?: string; italic?: boolean; spacingBefore?: number; basedOn?: string }) => {
    const rPr = `<w:rPr>${opts.bold ? '<w:b/>' : ''}${opts.italic ? '<w:i/>' : ''}` +
      `${opts.color ? `<w:color w:val="${opts.color}"/>` : ''}` +
      `${opts.size ? `<w:sz w:val="${opts.size}"/>` : ''}</w:rPr>`;
    const pPr = opts.spacingBefore ? `<w:pPr><w:spacing w:before="${opts.spacingBefore}" w:after="120"/></w:pPr>` : '<w:pPr><w:spacing w:after="120"/></w:pPr>';
    return `<w:style w:type="paragraph" w:styleId="${id}"><w:name w:val="${name}"/>` +
      `${opts.basedOn ? `<w:basedOn w:val="${opts.basedOn}"/>` : ''}${pPr}${rPr}</w:style>`;
  };
  const docDefaults = '<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="22"/></w:rPr></w:rPrDefault></w:docDefaults>';
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<w:styles xmlns:w="${W_NS}">${docDefaults}` +
    `<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>` +
    style('Title', 'Title', { size: 56, bold: true, color: '1F3864' }) +
    style('Subtitle', 'Subtitle', { size: 30, color: '2E74B5' }) +
    style('Disclaimer', 'Disclaimer', { size: 18, italic: true, color: 'C00000' }) +
    style('Heading1', 'heading 1', { size: 32, bold: true, color: '1F3864', spacingBefore: 360 }) +
    style('Heading2', 'heading 2', { size: 26, bold: true, color: '2E74B5', spacingBefore: 240 }) +
    style('Heading3', 'heading 3', { size: 24, bold: true, color: '1F4E79', spacingBefore: 160 }) +
    `</w:styles>`;
}

const CONTENT_TYPES = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
  `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
  `<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
  `<Default Extension="xml" ContentType="application/xml"/>` +
  `<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
  `<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>` +
  `</Types>`;

const ROOT_RELS = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
  `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
  `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
  `</Relationships>`;

const DOC_RELS = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
  `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
  `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>` +
  `</Relationships>`;

/** Pure: render an OSCAL SSP (wrapped or unwrapped) to a .docx Buffer. */
export function renderSspDocx(sspDoc: any): { buffer: Buffer; controlCount: number } {
  const ssp = sspDoc?.['system-security-plan'] ?? sspDoc;
  const { xml, controlCount } = bodyXml(ssp);
  const b = (s: string) => Buffer.from(s, 'utf8');
  const buffer = zipStore([
    { name: '[Content_Types].xml', data: b(CONTENT_TYPES) },
    { name: '_rels/.rels', data: b(ROOT_RELS) },
    { name: 'word/document.xml', data: b(xml) },
    { name: 'word/styles.xml', data: b(stylesXml()) },
    { name: 'word/_rels/document.xml.rels', data: b(DOC_RELS) },
  ]);
  return { buffer, controlCount };
}

export interface SspDocxResult { path: string; bytes: number; control_count: number }

export interface SspDocxEmitOptions {
  outDir: string;
  /** In-memory SSP doc (preferred — avoids a re-read). */
  ssp?: any;
  /** Path to ssp.json (default: <outDir>/ssp.json) when `ssp` is not provided. */
  sspPath?: string;
  /** Output path (default: <outDir>/ssp.docx). */
  outPath?: string;
}

/** Read the SSP (or use the provided doc), render it, and write ssp.docx. */
export function emitSspDocx(opts: SspDocxEmitOptions): SspDocxResult {
  let sspDoc = opts.ssp;
  if (!sspDoc) {
    const p = opts.sspPath ?? resolve(opts.outDir, 'ssp.json');
    sspDoc = JSON.parse(readFileSync(p, 'utf8'));
  }
  const { buffer, controlCount } = renderSspDocx(sspDoc);
  const outPath = opts.outPath ?? resolve(opts.outDir, 'ssp.docx');
  writeFileSync(outPath, buffer);
  log.info({ event: 'ssp_docx.emitted', path: outPath, bytes: buffer.length, control_count: controlCount });
  return { path: outPath, bytes: buffer.length, control_count: controlCount };
}
