/**
 * Deterministic PDF renderer for the CISA Secure Software Development Attestation
 * Common Form (OMB 1670-0052) — LOOP-T.T3.
 *
 * The structural PDF object/xref/trailer assembly is adapted from the proven,
 * dependency-free pattern in core/conmon-pdf.ts (LOOP-E.E1); the text-escaping +
 * word-wrap primitives are COMPOSED from that module (REO: never re-implement a
 * working primitive). On top of that base this renderer adds the three things the
 * Common Form needs and conmon-pdf does not:
 *   - one forced physical page per form Section (I / II / III / Appendix A[/B]);
 *   - an OMB-control-number footer stamped on every page;
 *   - a deterministic `/Info` (CreationDate / ModDate from the form's frozen
 *     emittedAt) + a `/ID` array seeded from the canonical-JSON digest, so two
 *     runs with identical inputs yield byte-identical output (test T3 determinism).
 *
 * Determinism: renderCommonFormPdf() is a pure function of (form, docId). It calls
 * neither Date.now() nor any RNG. zlib.deflateSync is deterministic for identical
 * input (the property core/conmon-pdf.ts already relies on).
 */
import { deflateSync } from 'node:zlib';
import { escapePdfText, wrapText } from './conmon-pdf.ts';
import {
  type CisaCommonFormCanonical,
  type PracticeBox,
  OMB_CONTROL_NUMBER,
  FORM_EXPIRATION_DATE,
  FORM_TITLE,
} from './ssdf-common-form.ts';

// ─── Page + typography geometry (US Letter, 72 dpi) ───────────────────────────

const PAGE_WIDTH = 612; // 8.5in * 72
const PAGE_HEIGHT = 792; // 11in * 72
const MARGIN_X = 54; // 0.75in
const MARGIN_TOP = 54;
const MARGIN_BOTTOM = 54;
const FOOTER_Y = 30; // footer baseline, below the bottom content margin
const CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN_X; // 504

const F_BODY = 'F1'; // Helvetica
const F_MONO = 'F2'; // Courier
const F_BOLD = 'F3'; // Helvetica-Bold

const PROSE_ADVANCE = 0.52; // conservative Helvetica average glyph width (em)
const MONO_ADVANCE = 0.6; // Courier advance (exact, em)

// ─── Low-level draw model ─────────────────────────────────────────────────────

interface PageOps {
  ops: string[];
}

class FormLayout {
  pages: PageOps[] = [];
  private cur!: PageOps;
  private y = 0;

  constructor() {
    this.page();
  }

  /** Start a fresh physical page (used at the top of every form Section). */
  page(): void {
    this.cur = { ops: ['0.5 w'] };
    this.pages.push(this.cur);
    this.y = PAGE_HEIGHT - MARGIN_TOP;
  }

  private ensure(height: number): void {
    if (this.y - height < MARGIN_BOTTOM) this.page();
  }

  private text(font: string, size: number, x: number, baselineY: number, s: string): void {
    this.cur.ops.push(
      `BT /${font} ${size} Tf 1 0 0 1 ${x.toFixed(2)} ${baselineY.toFixed(2)} Tm (${escapePdfText(s)}) Tj ET`,
    );
  }

  private rule(x1: number, y1: number, x2: number, y2: number): void {
    this.cur.ops.push(`${x1.toFixed(2)} ${y1.toFixed(2)} m ${x2.toFixed(2)} ${y2.toFixed(2)} l S`);
  }

  gap(h: number): void {
    this.y -= h;
  }

  /** A heading line (bold). */
  heading(text: string, size = 13): void {
    this.ensure(size + 8);
    this.y -= size;
    this.text(F_BOLD, size, MARGIN_X, this.y, text);
    this.y -= 6;
  }

  /** A label: value line; the label is bold, the value plain, on one row. */
  field(label: string, value: string, size = 10): void {
    const lead = size + 3;
    const max = maxChars(size, PROSE_ADVANCE, CONTENT_WIDTH - 130);
    const valueLines = wrapText(value || '—', max);
    this.ensure(lead * valueLines.length);
    this.y -= size;
    this.text(F_BOLD, size, MARGIN_X, this.y, label);
    this.text(F_BODY, size, MARGIN_X + 130, this.y, valueLines[0] ?? '');
    for (let i = 1; i < valueLines.length; i++) {
      this.y -= lead;
      this.text(F_BODY, size, MARGIN_X + 130, this.y, valueLines[i] ?? '');
    }
    this.y -= lead - size;
  }

  /** A wrapped prose paragraph at the given indent. */
  paragraph(text: string, size = 9, indent = 0): void {
    const lead = size + 2;
    const max = maxChars(size, PROSE_ADVANCE, CONTENT_WIDTH - indent);
    for (const ln of wrapText(text, max)) {
      this.ensure(lead);
      this.y -= size;
      this.text(F_BODY, size, MARGIN_X + indent, this.y, ln);
      this.y -= lead - size;
    }
  }

  /** A bold prose line at the given indent (used for selection markers). */
  boldLine(text: string, size = 9, indent = 0): void {
    const lead = size + 2;
    const max = maxChars(size, PROSE_ADVANCE, CONTENT_WIDTH - indent);
    for (const ln of wrapText(text, max)) {
      this.ensure(lead);
      this.y -= size;
      this.text(F_BOLD, size, MARGIN_X + indent, this.y, ln);
      this.y -= lead - size;
    }
  }

  /** A fixed-width-cell table (Courier) with header + borders. */
  table(columns: string[], rows: string[][]): void {
    const nCols = columns.length;
    if (nCols === 0) return;
    const colWidth = CONTENT_WIDTH / nCols;
    const size = 8;
    const rowHeight = 12;
    const cellChars = Math.max(1, Math.floor((colWidth - 6) / (size * MONO_ADVANCE)));
    const drawRow = (cells: string[], bold: boolean): void => {
      const wrapped = cells.map((c) => wrapText(c ?? '', cellChars));
      const linesInRow = Math.max(1, ...wrapped.map((w) => w.length));
      const rowH = linesInRow * rowHeight + 4;
      this.ensure(rowH);
      const top = this.y;
      const bottom = this.y - rowH;
      for (let li = 0; li < linesInRow; li++) {
        const baseY = top - size - li * rowHeight - 2;
        for (let ci = 0; ci < nCols; ci++) {
          const cellLine = wrapped[ci]?.[li];
          if (cellLine === undefined) continue;
          const x = MARGIN_X + ci * colWidth + 3;
          this.cur.ops.push(
            `BT /${bold ? F_BOLD : F_MONO} ${size} Tf 1 0 0 1 ${x.toFixed(2)} ${baseY.toFixed(2)} Tm (${escapePdfText(cellLine)}) Tj ET`,
          );
        }
      }
      for (let ci = 0; ci <= nCols; ci++) {
        const x = MARGIN_X + ci * colWidth;
        this.rule(x, top, x, bottom);
      }
      this.rule(MARGIN_X, bottom, MARGIN_X + CONTENT_WIDTH, bottom);
      if (bold) this.rule(MARGIN_X, top, MARGIN_X + CONTENT_WIDTH, top);
      this.y = bottom;
    };
    drawRow(columns, true);
    for (const r of rows) drawRow(r, false);
    this.y -= 6;
  }

  /** Stamp the OMB-control footer on every page once the page count is known. */
  finalizeFooters(): void {
    const n = this.pages.length;
    const size = 8;
    for (let p = 0; p < n; p++) {
      const footer =
        `OMB Control No. ${OMB_CONTROL_NUMBER} — Expiration Date ${FORM_EXPIRATION_DATE} — Page ${p + 1} of ${n}`;
      this.pages[p]!.ops.push(`0.5 w`);
      this.pages[p]!.ops.push(
        `${MARGIN_X} ${(FOOTER_Y + 10).toFixed(2)} m ${(MARGIN_X + CONTENT_WIDTH).toFixed(2)} ${(FOOTER_Y + 10).toFixed(2)} l S`,
      );
      this.pages[p]!.ops.push(
        `BT /${F_BODY} ${size} Tf 1 0 0 1 ${MARGIN_X} ${FOOTER_Y} Tm (${escapePdfText(footer)}) Tj ET`,
      );
    }
  }
}

function maxChars(size: number, advance: number, width: number): number {
  return Math.max(1, Math.floor(width / (size * advance)));
}

// ─── Selection rendering ──────────────────────────────────────────────────────

function selectionLine(box: PracticeBox): string {
  switch (box.selection) {
    case 'comply':
      return '[X] The company complies with this attestation.';
    case 'comply-with-conditions':
      return '[X] The company complies with conditions (POA&M attached for the remaining items).';
    case 'cannot-comply':
      return '[X] The company cannot comply with this attestation (POA&M item identifiers listed below).';
    case 'not-yet-determined':
      return '[ ] REQUIRES OPERATOR INPUT — one or more underlying SSDF tasks were not assessed.';
  }
}

// ─── Deterministic PDF date ───────────────────────────────────────────────────

/** PDF date string `D:YYYYMMDDHHmmSSZ` derived from a frozen ISO-8601 timestamp. */
export function pdfDate(iso: string): string {
  const d = new Date(iso);
  const ms = d.getTime();
  if (Number.isNaN(ms)) return "D:19700101000000Z";
  const p = (n: number, w = 2) => String(n).padStart(w, '0');
  return (
    'D:' +
    p(d.getUTCFullYear(), 4) +
    p(d.getUTCMonth() + 1) +
    p(d.getUTCDate()) +
    p(d.getUTCHours()) +
    p(d.getUTCMinutes()) +
    p(d.getUTCSeconds()) +
    'Z'
  );
}

// ─── PDF object assembly (adapted from core/conmon-pdf.ts) ─────────────────────

function obj(num: number, body: string): Buffer {
  return Buffer.from(`${num} 0 obj\n${body}\nendobj\n`, 'latin1');
}

function streamObj(num: number, raw: Buffer): Buffer {
  const compressed = deflateSync(raw);
  const head = Buffer.from(
    `${num} 0 obj\n<< /Length ${compressed.length} /Filter /FlateDecode >>\nstream\n`,
    'latin1',
  );
  const tail = Buffer.from('\nendstream\nendobj\n', 'latin1');
  return Buffer.concat([head, compressed, tail]);
}

export interface RenderCommonFormPdfOptions {
  /** Hex digest of the canonical JSON — seeds the deterministic `/ID` array. */
  docId: string;
}

/** Render the canonical Common Form to a complete, deterministic PDF 1.4 Buffer. */
export function renderCommonFormPdf(
  form: CisaCommonFormCanonical,
  opts: RenderCommonFormPdfOptions,
): Buffer {
  const L = new FormLayout();

  // ── Title (page 1) ──
  L.heading(FORM_TITLE, 14);
  L.paragraph(`OMB Control Number ${OMB_CONTROL_NUMBER} — Expiration Date ${FORM_EXPIRATION_DATE}`, 9);
  L.paragraph(form.regime_note, 8);
  L.gap(6);

  // ── Section I — Producer Information ──
  L.heading('Section I — Software Producer Information', 12);
  L.field('Legal name:', form.producer.legal_name);
  if (form.producer.dba_name) L.field('DBA:', form.producer.dba_name);
  const a = form.producer.address;
  L.field('Address:', `${a.street}, ${a.city}, ${a.state} ${a.postal_code}, ${a.country}`);
  const poc = form.producer.point_of_contact;
  L.field('Point of contact:', `${poc.name}, ${poc.title}`);
  L.field('Contact email:', poc.email);
  L.field('Contact phone:', poc.phone);
  L.gap(4);
  L.boldLine('Scope of attestation (covered software):', 10);
  L.gap(2);
  L.table(
    ['Product', 'Version', 'CPE 2.3'],
    form.producer.scope_of_attestation.products.map((p) => [p.name, p.version, p.cpe ?? '—']),
  );

  // ── Section II — Attestation (own page) ──
  L.page();
  L.heading('Section II — Attestation', 12);
  L.paragraph(
    'For each of the following practices, the box indicates the selection derived from the run\'s ' +
      'SSDF (NIST SP 800-218 v1.1) per-practice satisfaction matrix (LOOP-T.T2).',
    8,
  );
  L.gap(2);
  const boxes: PracticeBox[] = [
    form.attestations.practice_1_secure_environments,
    form.attestations.practice_2_trusted_supply_chains,
    form.attestations.practice_3_data_provenance,
    form.attestations.practice_4_automated_vulnerability_tools,
  ];
  for (const box of boxes) {
    L.boldLine(`Practice ${box.cisa_practice} — ${box.heading}`, 10);
    L.paragraph(box.statement, 9);
    for (const sub of box.sub_actions) L.paragraph(`(${sub.id}) ${sub.text}`, 8, 14);
    L.boldLine(selectionLine(box), 9);
    if (box.ssdf_v1_1_ids.length > 0) {
      L.paragraph(`SSDF v1.1 tasks: ${box.ssdf_v1_1_ids.join(', ')}`, 8, 14);
    }
    if (box.poam_item_uuids.length > 0) {
      L.paragraph(`POA&M item identifiers: ${box.poam_item_uuids.join(', ')}`, 8, 14);
    }
    L.gap(3);
  }

  // ── Section III — Signatory (own page) ──
  L.page();
  L.heading('Section III — Signature of Authorized Person', 12);
  L.paragraph(form.signatory_attestation_text, 9);
  L.gap(10);
  L.field('Signatory name:', form.producer.signatory.name);
  L.field('Signatory title:', form.producer.signatory.title);
  L.gap(14);
  L.boldLine('Signature: __________________________________________', 10);
  L.gap(10);
  L.boldLine('Date: ____________________', 10);

  // ── Appendix A — SSDF coverage roll-up (own page) ──
  L.page();
  L.heading('Appendix A — SSDF v1.1 Practice Coverage Roll-up', 12);
  L.paragraph(
    'Per CISA practice, the count of underlying SSDF v1.1 tasks by satisfaction status, ' +
      'from the signed T.T2 matrix. Informational support for the Section II selections.',
    8,
  );
  L.gap(2);
  L.table(
    ['CISA Practice', 'SSDF v1.1 tasks', 'Satisfied', 'Partial', 'Not satisfied', 'Not assessed', 'Needs input'],
    form.ssdf_coverage_rollup.map((r) => [
      r.cisa_practice,
      r.ssdf_v1_1_ids.join(', ') || '—',
      String(r.satisfied),
      String(r.partially_satisfied),
      String(r.not_satisfied),
      String(r.not_assessed),
      String(r.requires_operator_input),
    ]),
  );

  // ── Appendix B — SP 800-218A AI Profile (own page, optional) ──
  if (form.ai_profile_appendix?.enabled) {
    L.page();
    L.heading('Appendix B — NIST SP 800-218A AI Community Profile', 12);
    L.paragraph(form.ai_profile_appendix.note, 9);
    L.gap(2);
    L.table(
      ['SP 800-218A Practice', 'Status'],
      form.ai_profile_appendix.sp_800_218a_practices.map((p) => [p.id, p.status]),
    );
  }

  L.finalizeFooters();

  // ── Object assembly ──
  const pages = L.pages;
  const nPages = pages.length;

  const objects: Buffer[] = [];
  const FIRST_PAGE_OBJ = 7; // 1 Catalog, 2 Pages, 3-5 fonts, 6 Info
  const pageObjNums: number[] = [];
  for (let p = 0; p < nPages; p++) pageObjNums.push(FIRST_PAGE_OBJ + p * 2);

  objects.push(obj(1, '<< /Type /Catalog /Pages 2 0 R >>'));
  objects.push(
    obj(2, `<< /Type /Pages /Kids [${pageObjNums.map((n) => `${n} 0 R`).join(' ')}] /Count ${nPages} >>`),
  );
  objects.push(obj(3, '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>'));
  objects.push(obj(4, '<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>'));
  objects.push(obj(5, '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>'));
  const created = pdfDate(form.emittedAt);
  objects.push(
    obj(
      6,
      `<< /Title (${escapePdfText(FORM_TITLE)}) /Producer (FedPy ssdf-common-form ${escapePdfText(OMB_CONTROL_NUMBER)}) ` +
        `/CreationDate (${created}) /ModDate (${created}) >>`,
    ),
  );
  for (let p = 0; p < nPages; p++) {
    const pageNum = FIRST_PAGE_OBJ + p * 2;
    const contentNum = pageNum + 1;
    const resources = `<< /Font << /${F_BODY} 3 0 R /${F_MONO} 4 0 R /${F_BOLD} 5 0 R >> >>`;
    objects.push(
      obj(
        pageNum,
        `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_WIDTH} ${PAGE_HEIGHT}] ` +
          `/Resources ${resources} /Contents ${contentNum} 0 R >>`,
      ),
    );
    objects.push(streamObj(contentNum, Buffer.from(pages[p]!.ops.join('\n') + '\n', 'latin1')));
  }

  const header = Buffer.from('%PDF-1.4\n%\xE2\xE3\xCF\xD3\n', 'latin1');
  const chunks: Buffer[] = [header];
  let offset = header.length;
  const offsets: number[] = [];
  for (const o of objects) {
    offsets.push(offset);
    chunks.push(o);
    offset += o.length;
  }

  const objCount = objects.length;
  const xrefStart = offset;
  const id = (opts.docId || '0').replace(/[^0-9a-fA-F]/g, '').padEnd(32, '0').slice(0, 64);
  let xref = `xref\n0 ${objCount + 1}\n`;
  xref += '0000000000 65535 f \n';
  for (let i = 0; i < objCount; i++) {
    xref += `${String(offsets[i]).padStart(10, '0')} 00000 n \n`;
  }
  xref +=
    `trailer\n<< /Size ${objCount + 1} /Root 1 0 R /Info 6 0 R /ID [<${id}> <${id}>] >>\n` +
    `startxref\n${xrefStart}\n%%EOF\n`;
  chunks.push(Buffer.from(xref, 'latin1'));

  return Buffer.concat(chunks);
}
