/**
 * OOXML/zip-store `.docx` renderer for the FAR 52.204-26 Section 889 annual
 * representation (LOOP-W.W4).
 *
 * Composes the public OOXML primitives from `core/zip.ts` (`xmlEscape`,
 * `zipStore`) into a WordprocessingML document the operator prints, the
 * authorized officer signs, and the operator carries to SAM.gov to enter the
 * two FAR 52.204-26(c) checkbox answers. The layout follows W.W4 §5.2: header
 * (offeror identity), title, verbatim FAR 52.204-26(a) Definitions + (b)
 * Procedures recital, the two (c)(1)/(c)(2) representations with the
 * screen-driven checkbox marked (■) and the alternative left unmarked (□), the
 * computed rationale narrative under each, the FAR 52.204-25(a) "Reasonable
 * inquiry" definition + operator methodology summary, the SAM-review footer, an
 * optional linked-incident annex, an optional NDAA §1634 Kaspersky supplement
 * annex, and the officer signature block.
 *
 * The statutory quotations are published law / regulation (REO Rule 3 allowed
 * fixed data) reproduced verbatim from acquisition.gov — they are NOT invented
 * and NOT paraphrased. Every computed value (the checkbox, the rationale, the
 * inquiry scope counts, the snapshot hash) flows from the signed envelope.
 *
 * Pure: returns a Buffer; no disk I/O. Zip-store (no compression) + pinned
 * timestamps keep the byte-stream reproducible for the 3PAO hash-verification
 * chain (W.W4.md R4).
 */
import { xmlEscape, zipStore } from './zip.ts';
import type { Section889AnnualRepEnvelope } from './section889-annual-rep.ts';

const W_NS = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main';

const CHECKED = '■';   // ■ BLACK SQUARE
const UNCHECKED = '□'; // □ WHITE SQUARE

// ─── Verbatim FAR text (published regulation; acquisition.gov, accessed 2026-06-07) ──

const FAR_52_204_26_A =
  'FAR 52.204-26(a) Definitions: "Covered telecommunications equipment or services" and "reasonable inquiry" have the meaning provided in the clause 52.204-25, Prohibition on Contracting for Certain Telecommunications and Video Surveillance Services or Equipment.';

const FAR_52_204_26_B =
  'FAR 52.204-26(b) Procedures: The Offeror shall review the list of excluded parties in the System for Award Management (SAM) (https://www.sam.gov) for entities excluded from receiving federal awards for "covered telecommunications equipment or services".';

const FAR_52_204_26_C1 =
  '(1) The Offeror represents that it [ ] does, [ ] does not provide covered telecommunications equipment or services as a part of its offered products or services to the Government in the performance of any contract, subcontract, or other contractual instrument.';

const FAR_52_204_26_C2 =
  '(2) After conducting a reasonable inquiry for purposes of this representation, the offeror represents that it [ ] does, [ ] does not use covered telecommunications equipment or services, or any equipment, system, or service that uses covered telecommunications equipment or services.';

// FAR 52.204-25(a) "Reasonable inquiry" definition (verbatim, acquisition.gov/far/52.204-25).
const FAR_52_204_25_REASONABLE_INQUIRY =
  'FAR 52.204-25(a): "Reasonable inquiry means an inquiry designed to uncover any information in the entity\'s possession about the identity of the producer or provider of covered telecommunications equipment or services used by the entity that excludes the need to include an internal or third-party audit."';

// FAR 52.204-25(a) "Covered telecommunications equipment or services" definition (verbatim).
const FAR_52_204_25_COVERED =
  'FAR 52.204-25(a): "Covered telecommunications equipment or services means— (1) Telecommunications equipment produced by Huawei Technologies Company or ZTE Corporation (or any subsidiary or affiliate of such entities); (2) For the purpose of public safety, security of Government facilities, physical security surveillance of critical infrastructure, and other national security purposes, video surveillance and telecommunications equipment produced by Hytera Communications Corporation, Hangzhou Hikvision Digital Technology Company, or Dahua Technology Company (or any subsidiary or affiliate of such entities); (3) Telecommunications or video surveillance services provided by such entities or using such equipment; or (4) Telecommunications or video surveillance equipment or services produced or provided by an entity that the Secretary of Defense, in consultation with the Director of the National Intelligence or the Director of the Federal Bureau of Investigation, reasonably believes to be an entity owned or controlled by, or otherwise connected to, the government of a covered foreign country." "Covered foreign country means The People\'s Republic of China."';

// ─── OOXML building blocks (local, on top of zip.ts — the section889-report-docx idiom) ──

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

/** A reserved, fillable signature region (the officer inserts a wet signature). */
function signatureRegion(): string {
  return `<w:p><w:bookmarkStart w:id="0" w:name="signature-block"/>` +
    `<w:r><w:t xml:space="preserve">Signature: ____________________________</w:t></w:r>` +
    `<w:bookmarkEnd w:id="0"/></w:p>`;
}

/** Render the two-option representation line with the screen-driven box marked. */
function checkboxLine(answer: 'does' | 'does not', subject: string): string {
  const doesBox = answer === 'does' ? CHECKED : UNCHECKED;
  const doesNotBox = answer === 'does not' ? CHECKED : UNCHECKED;
  return para(`The offeror represents that it ${doesBox} does, ${doesNotBox} does not ${subject}`);
}

// ─── Document assembly ────────────────────────────────────────────────────────

function bodyXml(env: Section889AnnualRepEnvelope): string {
  const parts: string[] = [];
  const rep = env.representation;

  // Title.
  parts.push(para('Representation Pursuant to FAR 52.204-26 — Covered Telecommunications Equipment or Services', 'Title'));
  parts.push(para('Section 889 Part B Annual Representation', 'Subtitle'));

  // Header — offeror identity.
  const a = env.offeror.physical_address;
  const addr = [a.street1, a.street2, `${a.city}, ${a.state} ${a.zip}`, a.country].filter(Boolean).join('\n');
  parts.push(table(['Field', 'Value'], [
    ['Offeror (legal name)', env.offeror.legal_name],
    ['Unique Entity Identifier (UEI)', env.offeror.unique_entity_id],
    ['CAGE code', env.offeror.cage_code ?? '(none)'],
    ['Physical address', addr],
    ['Representation signed', env.signed_at],
    ['Valid until (FAR 52.204-8(d))', env.valid_until],
    ['Envelope id', env.envelope_uuid],
  ], [3200, 5800], false));
  parts.push(para(''));

  // Recital — verbatim FAR 52.204-26(a) + (b).
  parts.push(heading('1. Definitions and Procedures', 1));
  parts.push(para(FAR_52_204_26_A, 'Recital'));
  parts.push(para(FAR_52_204_26_B, 'Recital'));
  parts.push(para(FAR_52_204_25_COVERED, 'Recital'));

  // Representation (c)(1).
  parts.push(heading('2. Representation — FAR 52.204-26(c)(1) (provision to the Government)', 1));
  parts.push(para(FAR_52_204_26_C1, 'Recital'));
  parts.push(checkboxLine(rep.provides_covered_equipment_or_services, 'provide covered telecommunications equipment or services as a part of its offered products or services to the Government in the performance of any contract, subcontract, or other contractual instrument.'));
  parts.push(para(`Basis: ${rep.rationale.provides_basis}`));

  // Representation (c)(2).
  parts.push(heading('3. Representation — FAR 52.204-26(c)(2) (use)', 1));
  parts.push(para(FAR_52_204_26_C2, 'Recital'));
  parts.push(checkboxLine(rep.uses_covered_equipment_or_services, 'use covered telecommunications equipment or services, or any equipment, system, or service that uses covered telecommunications equipment or services.'));
  parts.push(para(`Basis: ${rep.rationale.uses_basis}`));

  // Reasonable-inquiry methodology.
  parts.push(heading('4. Reasonable inquiry', 1));
  parts.push(para(FAR_52_204_25_REASONABLE_INQUIRY, 'Recital'));
  parts.push(table(['Inquiry surface', 'Entries screened'], [
    ['Subprocessor sheet', String(env.reasonable_inquiry.inquiry_scope.subprocessor_count)],
    ['SBOM packages (transitive)', String(env.reasonable_inquiry.inquiry_scope.sbom_package_count)],
    ['OCI image publishers', String(env.reasonable_inquiry.inquiry_scope.oci_image_count)],
    ['Inventory provider-tag / SKU', String(env.reasonable_inquiry.inquiry_scope.inventory_asset_count)],
  ], [5000, 4000], true));
  parts.push(para(`Methodology document: ${env.reasonable_inquiry.methodology_path} (SHA-256 ${env.reasonable_inquiry.methodology_sha256.slice(0, 16)}…). Inquiry completed ${env.reasonable_inquiry.inquiry_completed_at}.`));

  // SAM-review footer.
  parts.push(heading('5. SAM excluded-parties review', 1));
  parts.push(para(`This representation was informed by a review of the SAM Excluded Parties List as of ${env.sam_review.excluded_parties_review_date}, snapshot ${env.sam_review.excluded_parties_snapshot_id} SHA-256 ${env.sam_review.excluded_parties_snapshot_sha256.slice(0, 16)}….`));

  // Linked-incident annex (only when there is at least one unsuppressed match driving a filed report).
  if (rep.linked_incidents.length > 0) {
    parts.push(heading('Annex A — Linked FAR 52.204-25(d) incidents', 1));
    parts.push(table(['Incident id', 'Reported at', 'Contract', 'Status'],
      rep.linked_incidents.map((i) => [i.incident_id, i.reported_at, i.contract_number || '(none)', i.status]),
      [3400, 2600, 2000, 1000], true));
  }

  // Kaspersky supplement annex (only when opted in).
  if (env.kaspersky_supplement) {
    parts.push(heading('Annex B — NDAA FY2018 §1634 / DHS BOD 17-01 supplement', 1));
    parts.push(para(env.kaspersky_supplement.representation_text, 'Recital'));
  }

  // SR-family control cross-reference.
  parts.push(heading('6. Controls evidenced', 1));
  parts.push(para(`This representation provides evidence under NIST SP 800-53 Rev 5 supply-chain controls: ${env.controls_evidenced.join(', ')}.`));

  // Signature block.
  parts.push(heading('7. Authorized officer attestation', 1));
  parts.push(para('I attest under penalty of 18 U.S.C. §1001 that the representations above are, to the best of my knowledge after a reasonable inquiry, accurate and complete as of the date below.'));
  parts.push(para(''));
  parts.push(signatureRegion());
  parts.push(para(`Printed name: ${env.authorized_officer.full_name}`));
  parts.push(para(`Title: ${env.authorized_officer.title}`));
  parts.push(para(`Email: ${env.authorized_officer.email}`));
  parts.push(para(`Officer signing-key id: ${env.authorized_officer.signing_key_id}`));
  parts.push(para(`Date signed: ${env.signed_at}`));
  parts.push(para(''));
  parts.push(para(`Ed25519 envelope signature key id: ${env.provenance.signingKeyId}. The machine-readable signed JSON envelope (${env.envelope_uuid}) is the authoritative record; this document is its human-readable rendering for SAM.gov submission and officer signature.`, 'Disclaimer'));

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
    style('Recital', 'Recital', { size: 20, italic: true, color: '44546A' }) +
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

/** The OOXML part names the renderer emits, in archive order (for tests + tooling). */
export const ANNUAL_REP_DOCX_PARTS = [
  '[Content_Types].xml',
  '_rels/.rels',
  'word/document.xml',
  'word/styles.xml',
  'word/_rels/document.xml.rels',
] as const;

/** Pure: render a FAR 52.204-26 annual representation envelope to a `.docx` Buffer. */
export function renderSection889AnnualRepDocx(env: Section889AnnualRepEnvelope): Buffer {
  const b = (s: string) => Buffer.from(s, 'utf8');
  return zipStore([
    { name: '[Content_Types].xml', data: b(CONTENT_TYPES) },
    { name: '_rels/.rels', data: b(ROOT_RELS) },
    { name: 'word/document.xml', data: b(bodyXml(env)) },
    { name: 'word/styles.xml', data: b(stylesXml()) },
    { name: 'word/_rels/document.xml.rels', data: b(DOC_RELS) },
  ]);
}
