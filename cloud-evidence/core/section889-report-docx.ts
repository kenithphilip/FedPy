/**
 * OOXML/zip-store `.docx` renderer for the FAR 52.204-25(d) 1-business-day
 * report (LOOP-W.W3).
 *
 * Composes the public OOXML primitives from `core/zip.ts` (`xmlEscape`,
 * `zipStore`) into a WordprocessingML document the operator attaches to the
 * Contracting Officer email (civilian) or DIBNet upload (DoD). The layout
 * follows W.W3 §5.2: cover page, summary table, one per-finding section quoting
 * the operative FAR 52.204-25(a) + NDAA §889(f)(2) (or NDAA §1634 + DHS BOD
 * 17-01) text verbatim, a remediation-status block, and an attestation block
 * with a reserved signature region (a bookmark the operator fills with a wet
 * signature image or the Ed25519 signature receipt id).
 *
 * The statutory quotations are published law / regulation (REO Rule 3 allowed
 * fixed data) reproduced verbatim from acquisition.gov / congress.gov /
 * cisa.gov — they are NOT invented and NOT paraphrased.
 *
 * Pure: returns a Buffer; no disk I/O.
 */
import { xmlEscape, zipStore } from './zip.ts';
import type { Section8891bdReport, StatutoryBasis } from './section889-report-json.ts';

const W_NS = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main';

/** Verbatim statutory / regulatory text keyed by the report's statutory_basis. */
const STATUTORY_TEXT: Record<StatutoryBasis, string> = {
  'far-52.204-25-a-1':
    'FAR 52.204-25(a): "Covered telecommunications equipment or services means— (1) Telecommunications equipment produced by Huawei Technologies Company or ZTE Corporation (or any subsidiary or affiliate of such entities)."',
  'far-52.204-25-a-2':
    'FAR 52.204-25(a): "Covered telecommunications equipment or services means— (2) For the purpose of public safety, security of Government facilities, physical security surveillance of critical infrastructure, and other national security purposes, video surveillance and telecommunications equipment produced by Hytera Communications Corporation, Hangzhou Hikvision Digital Technology Company, or Dahua Technology Company (or any subsidiary or affiliate of such entities)."',
  'far-52.204-25-a-3':
    'FAR 52.204-25(a): "Covered telecommunications equipment or services means— (3) Telecommunications or video surveillance services provided by such entities or using such equipment."',
  'far-52.204-25-a-4':
    'FAR 52.204-25(a): "Covered telecommunications equipment or services means— (4) Telecommunications or video surveillance equipment or services produced or provided by an entity that the Secretary of Defense, in consultation with the Director of the National Intelligence or the Director of the Federal Bureau of Investigation, reasonably believes to be an entity owned or controlled by, or otherwise connected to, the government of a covered foreign country."',
  'ndaa-2019-sec-889-f-2-A':
    'NDAA FY2019 §889(f)(2)(A): "Telecommunications equipment produced by Huawei Technologies Company or ZTE Corporation (or any subsidiary or affiliate of such entities)."',
  'ndaa-2019-sec-889-f-2-B':
    'NDAA FY2019 §889(f)(2)(B): "For the purpose of public safety, security of Government facilities, physical security surveillance of critical infrastructure, and other national security purposes, video surveillance and telecommunications equipment produced by Hytera Communications Corporation, Hangzhou Hikvision Digital Technology Company, or Dahua Technology Company (or any subsidiary or affiliate of such entities)."',
  'ndaa-2019-sec-889-f-2-C':
    'NDAA FY2019 §889(f)(2)(C): "Telecommunications or video surveillance services provided by such entities or using such equipment."',
  'ndaa-2019-sec-889-f-2-D':
    'NDAA FY2019 §889(f)(2)(D): "Telecommunications or video surveillance equipment or services produced or provided by an entity that the Secretary of Defense, in consultation with the Director of National Intelligence or the Director of the Federal Bureau of Investigation, reasonably believes to be an entity owned or controlled by, or otherwise connected to, the government of a covered foreign country." §889(f)(3): "The term ‘covered foreign country’ means the People’s Republic of China."',
  'ndaa-2018-sec-1634':
    'NDAA FY2018 §1634(a): "No department, agency, organization, or other element of the Federal Government shall use, whether directly or through work with or on behalf of another department, agency, organization, or element of the Federal Government, any hardware, software, or services developed or provided, in whole or in part, by— (1) Kaspersky Lab (or any successor entity); (2) any entity that controls, is controlled by, or is under common control with Kaspersky Lab; or (3) any entity of which Kaspersky Lab has a majority ownership."',
  'dhs-bod-17-01':
    'DHS Binding Operational Directive 17-01: directs Federal Executive Branch departments and agencies to identify any use or presence of Kaspersky-branded products on their information systems, to develop and furnish to DHS a detailed plan of action to remove and discontinue present and future use of all Kaspersky-branded products, and to begin to implement the plan.',
  'operator-addition':
    'Operator-supplied prohibited-vendor addition (cloud-evidence prohibited-vendors-overrides.yaml manual_additions): the operator has designated this entity as prohibited; see the cited justification in the catalog provenance.',
};

const REPORTING_CLAUSE =
  'FAR 52.204-25(d)(2)(i): "Within one business day from the date of such identification or notification: The contract number; the order number(s), if applicable; supplier name; supplier unique entity identifier (if known); supplier Commercial and Government Entity (CAGE) code (if known); brand; model number (original equipment manufacturer number, manufacturer part number, or wholesaler number); item description; and any readily available information about mitigation actions undertaken or recommended."';

const FOLLOWUP_CLAUSE =
  'FAR 52.204-25(d)(2)(ii): "Within 10 business days of submitting the information in paragraph (d)(2)(i) of this clause: Any further available information about mitigation actions undertaken or recommended. In addition, the Contractor shall describe the efforts it undertook to prevent use or submission of covered telecommunications equipment or services, and any additional efforts that will be incorporated to prevent future use or submission of covered telecommunications equipment or services."';

// ─── OOXML building blocks (local, on top of zip.ts — the ssp-docx.ts idiom) ──

function para(text: string, style?: string): string {
  const pPr = style ? `<w:pPr><w:pStyle w:val="${style}"/></w:pPr>` : '';
  if (text === '') return `<w:p>${pPr}</w:p>`;
  const runs = text.split('\n').map((line, i) =>
    `${i > 0 ? '<w:br/>' : ''}<w:t xml:space="preserve">${xmlEscape(line)}</w:t>`,
  ).join('');
  return `<w:p>${pPr}<w:r>${runs}</w:r></w:p>`;
}

function heading(text: string, level: 1 | 2 | 3): string {
  return para(text, `Heading${level}`);
}

function table(headers: string[], rows: string[][], widths: number[], headerRow = true): string {
  const grid = `<w:tblGrid>${widths.map((w) => `<w:gridCol w:w="${w}"/>`).join('')}</w:tblGrid>`;
  const border = ['top', 'left', 'bottom', 'right', 'insideH', 'insideV']
    .map((s) => `<w:${s} w:val="single" w:sz="4" w:space="0" w:color="999999"/>`).join('');
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

/** A reserved, fillable signature region (operator inserts a wet signature). */
function signatureRegion(): string {
  return `<w:p><w:bookmarkStart w:id="0" w:name="signature-block"/>` +
    `<w:r><w:t xml:space="preserve">Signature: ____________________________</w:t></w:r>` +
    `<w:bookmarkEnd w:id="0"/></w:p>`;
}

// ─── Document assembly ────────────────────────────────────────────────────────

const STATUS_TZ = (env: Section8891bdReport) => env.federal_business_hours_tz;

function bodyXml(env: Section8891bdReport): string {
  const parts: string[] = [];
  const kindLabel = env.report_kind === 'follow-up-10bd'
    ? 'FAR 52.204-25(d)(2)(ii) 10-Business-Day Follow-up Report'
    : 'FAR 52.204-25(d) Initial 1-Business-Day Report';

  // Cover page.
  parts.push(para(kindLabel, 'Title'));
  parts.push(para('Prohibition on Contracting for Certain Telecommunications and Video Surveillance Services or Equipment', 'Subtitle'));
  parts.push(table(['Field', 'Value'], [
    ['Contractor (CSP)', env.csp_name],
    ['CSP Unique Entity Identifier (UEI)', env.csp_uei],
    ['CSP CAGE Code', env.csp_cage_code],
    ['Contract number', env.far_d_2_i.contract_number],
    ['Endpoint', env.endpoint_type === 'dod-dibnet' ? `DoD DIBNet (${env.dibnet_url})` : `Contracting Officer (${env.contracting_officer_email ?? 'REQUIRES-OPERATOR-INPUT'})`],
    ['Discovery date', env.discovered_at],
    ['Reporting deadline', `${env.deadline_at}  (${STATUS_TZ(env)} business day)`],
    ['Report id', env.report_id],
  ], [3200, 5800], false));
  parts.push(para(''));
  parts.push(para(REPORTING_CLAUSE));
  if (env.report_kind === 'follow-up-10bd') parts.push(para(FOLLOWUP_CLAUSE));

  // Summary table.
  parts.push(heading('1. Summary of identified covered item', 1));
  const far = env.far_d_2_i;
  parts.push(table(['Field', 'Value'], [
    ['Supplier name', far.supplier_name],
    ['Supplier UEI', far.supplier_uei],
    ['Supplier CAGE code', far.supplier_cage_code],
    ['Brand', far.brand],
    ['Model number', far.model_number],
    ['Item description', far.item_description],
    ['Order number(s)', far.order_numbers.length ? far.order_numbers.join(', ') : '(none)'],
  ], [3200, 5800], false));

  // Per-finding statutory section.
  parts.push(heading('2. Statutory and regulatory basis', 1));
  for (const basis of env.statutory_basis) {
    parts.push(para(STATUTORY_TEXT[basis] ?? basis));
    parts.push(para(''));
  }
  parts.push(para(`Detection surface / evidence path: ${env.source_match_id} (W.W2 screen run ${env.source_screen_envelope_ref.run_id}).`));
  parts.push(para(`Catalog snapshot: ${env.catalog_snapshot_ref.path} (sha256 ${env.catalog_snapshot_ref.sha256.slice(0, 16)}…, generated ${env.catalog_snapshot_ref.generated_at}).`));

  // Remediation status block.
  parts.push(heading('3. Mitigation actions', 1));
  parts.push(para(`Mitigation actions undertaken or recommended: ${far.mitigation_actions}`));
  if (env.far_d_2_ii) {
    parts.push(para(`Additional mitigation actions: ${env.far_d_2_ii.additional_mitigation_actions}`));
    parts.push(para(`Efforts undertaken to prevent use/submission: ${env.far_d_2_ii.prevention_efforts_undertaken}`));
    parts.push(para(`Future prevention efforts: ${env.far_d_2_ii.future_prevention_efforts}`));
  }
  if (env.waiver_id) parts.push(para(`Active waiver (FAR 4.2104): ${env.waiver_id}`));

  // Attestation block + signature region.
  parts.push(heading('4. Attestation', 1));
  parts.push(para('I attest under penalty of 18 U.S.C. §1001 that the information in this report is, to the best of my knowledge, accurate and complete as of the date below.'));
  parts.push(para(''));
  parts.push(signatureRegion());
  parts.push(para(`Printed name: ${env.signing_officer.name}`));
  parts.push(para(`Title: ${env.signing_officer.title}`));
  parts.push(para(`Date: ${env.emitted_at}`));
  parts.push(para(''));
  parts.push(para(`Ed25519 signature key id: ${env.signing_officer.key_id} (version ${env.signing_officer.key_version}). The machine-readable signed JSON envelope (${env.report_id}.json) is the authoritative record; this document is its human-readable rendering.`, 'Disclaimer'));

  const sectPr = '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/>' +
    '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr>';
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<w:document xmlns:w="${W_NS}"><w:body>${parts.join('')}${sectPr}</w:body></w:document>`;
}

function stylesXml(): string {
  const docDefaults = '<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="22"/></w:rPr></w:rPrDefault></w:docDefaults>';
  const style = (id: string, name: string, opts: { size?: number; bold?: boolean; color?: string; italic?: boolean }) => {
    const rPr = `<w:rPr>${opts.bold ? '<w:b/>' : ''}${opts.italic ? '<w:i/>' : ''}` +
      `${opts.color ? `<w:color w:val="${opts.color}"/>` : ''}${opts.size ? `<w:sz w:val="${opts.size}"/>` : ''}</w:rPr>`;
    return `<w:style w:type="paragraph" w:styleId="${id}"><w:name w:val="${name}"/><w:pPr><w:spacing w:after="120"/></w:pPr>${rPr}</w:style>`;
  };
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<w:styles xmlns:w="${W_NS}">${docDefaults}` +
    `<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>` +
    style('Title', 'Title', { size: 48, bold: true, color: '1F3864' }) +
    style('Subtitle', 'Subtitle', { size: 26, color: '2E74B5' }) +
    style('Disclaimer', 'Disclaimer', { size: 18, italic: true, color: 'C00000' }) +
    style('Heading1', 'heading 1', { size: 30, bold: true, color: '1F3864' }) +
    style('Heading2', 'heading 2', { size: 26, bold: true, color: '2E74B5' }) +
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

/** Pure: render a FAR 52.204-25(d) report envelope to a `.docx` Buffer. */
export function renderSection889ReportDocx(env: Section8891bdReport): Buffer {
  const b = (s: string) => Buffer.from(s, 'utf8');
  return zipStore([
    { name: '[Content_Types].xml', data: b(CONTENT_TYPES) },
    { name: '_rels/.rels', data: b(ROOT_RELS) },
    { name: 'word/document.xml', data: b(bodyXml(env)) },
    { name: 'word/styles.xml', data: b(stylesXml()) },
    { name: 'word/_rels/document.xml.rels', data: b(DOC_RELS) },
  ]);
}
