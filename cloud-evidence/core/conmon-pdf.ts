/**
 * Minimal, dependency-free PDF 1.4 generator (LOOP-E.E1).
 *
 * Why this exists:
 *   The monthly ConMon analysis report (core/conmon-report.ts) is uploaded to
 *   the FedRAMP secure repository (USDA Connect.gov) alongside the POA&M +
 *   inventory + scan files. Agency POCs commonly expect a PDF. We refuse to
 *   pull in `pdfkit` / `pdfmake` (heavy, non-deterministic byte output, large
 *   transitive trees) — the same dependency-free stance taken by
 *   core/submission-bundle.ts (POSIX ustar) and core/roe-emit.ts (OOXML zip).
 *
 * What it produces:
 *   A valid PDF 1.4 file (ISO 32000-1:2008 ASCII subset) with:
 *     - a Catalog -> Pages -> Page(s) object chain,
 *     - Helvetica (/F1) for prose + Courier (/F2) for table cells,
 *     - FlateDecode-compressed content streams (Node `zlib`),
 *     - a byte-accurate cross-reference (xref) table + trailer,
 *     - automatic pagination when content overflows a US-Letter page.
 *
 * Determinism:
 *   renderPdf() is a pure function of its `sections` input. It calls neither
 *   Date.now() nor any RNG, so identical input yields byte-identical output —
 *   the property LOOP-E CC-4 (determinism) requires and the slice tests assert.
 *
 * Layout model:
 *   PDF user space has its origin at the bottom-left; y grows upward. We track
 *   a downward cursor and convert to PDF coordinates at draw time. Tables are
 *   rendered with Courier (fixed-width metrics) so column widths are exact;
 *   prose is wrapped against a conservative average-glyph-width estimate.
 */
import { deflateSync } from 'node:zlib';

// ─── Public section model ─────────────────────────────────────────────────────

export type PdfSection =
  | { kind: 'heading'; text: string; level?: 1 | 2 }
  | { kind: 'paragraph'; text: string }
  | { kind: 'table'; columns: string[]; rows: string[][] };

export interface RenderPdfOptions {
  /** Document title — drawn as the first level-1 heading when provided. */
  title?: string;
}

// ─── Page + typography geometry (US Letter, 72 dpi) ───────────────────────────

const PAGE_WIDTH = 612;   // 8.5in * 72
const PAGE_HEIGHT = 792;  // 11in * 72
const MARGIN_X = 54;      // 0.75in
const MARGIN_TOP = 54;
const MARGIN_BOTTOM = 54;
const CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN_X; // 504

const FONT_PROSE = 'F1';   // Helvetica
const FONT_MONO = 'F2';    // Courier

const SIZE_H1 = 16;
const SIZE_H2 = 12;
const SIZE_BODY = 10;
const SIZE_TABLE = 8;

const LEAD_H1 = 26;
const LEAD_H2 = 20;
const LEAD_BODY = 13;
const ROW_HEIGHT = 13;

// Courier advance width is exactly 0.6 em. Helvetica varies; 0.52 em is a
// conservative average that keeps wrapped prose inside the content box.
const MONO_ADVANCE = 0.6;
const PROSE_ADVANCE = 0.52;

// ─── Text helpers ─────────────────────────────────────────────────────────────

/**
 * Escape a string for use inside a PDF literal-string `( ... )`. Backslash and
 * the parenthesis pair are the structural metacharacters; control bytes and
 * non-ASCII are mapped to a visible substitute so the output stays inside the
 * PDF 1.4 ASCII subset (no encoding object required).
 */
export function escapePdfText(s: string): string {
  let out = '';
  for (const ch of String(s)) {
    const code = ch.codePointAt(0)!;
    if (ch === '\\') out += '\\\\';
    else if (ch === '(') out += '\\(';
    else if (ch === ')') out += '\\)';
    else if (code === 0x0a) out += '\\n';
    else if (code === 0x0d) out += '\\r';
    else if (code === 0x09) out += '    ';
    else if (code >= 0x20 && code <= 0x7e) out += ch;
    else out += '?';
  }
  return out;
}

/** Max characters that fit on one line for a font size + average glyph advance. */
function maxCharsFor(size: number, advance: number, width = CONTENT_WIDTH): number {
  return Math.max(1, Math.floor(width / (size * advance)));
}

/** Greedy word-wrap. Words longer than the line budget are hard-split. */
export function wrapText(text: string, maxChars: number): string[] {
  const words = String(text).replace(/\s+/g, ' ').trim().split(' ');
  if (words.length === 0 || (words.length === 1 && words[0] === '')) return [''];
  const lines: string[] = [];
  let cur = '';
  for (let word of words) {
    while (word.length > maxChars) {
      if (cur) { lines.push(cur); cur = ''; }
      lines.push(word.slice(0, maxChars));
      word = word.slice(maxChars);
    }
    if (!cur) cur = word;
    else if (cur.length + 1 + word.length <= maxChars) cur += ' ' + word;
    else { lines.push(cur); cur = word; }
  }
  if (cur) lines.push(cur);
  return lines.length ? lines : [''];
}

// ─── Internal draw model ──────────────────────────────────────────────────────

interface PageOps {
  ops: string[];
}

class Layout {
  pages: PageOps[] = [];
  private cur!: PageOps;
  private y = 0;

  constructor() {
    this.newPage();
  }

  private newPage(): void {
    this.cur = { ops: ['0.5 w'] }; // default line width for borders
    this.pages.push(this.cur);
    this.y = PAGE_HEIGHT - MARGIN_TOP;
  }

  private ensure(height: number): void {
    if (this.y - height < MARGIN_BOTTOM) this.newPage();
  }

  private textLine(font: string, size: number, x: number, baselineY: number, text: string): void {
    this.cur.ops.push(
      `BT /${font} ${size} Tf 1 0 0 1 ${x.toFixed(2)} ${baselineY.toFixed(2)} Tm (${escapePdfText(text)}) Tj ET`,
    );
  }

  private line(x1: number, y1: number, x2: number, y2: number): void {
    this.cur.ops.push(`${x1.toFixed(2)} ${y1.toFixed(2)} m ${x2.toFixed(2)} ${y2.toFixed(2)} l S`);
  }

  heading(text: string, level: 1 | 2): void {
    const size = level === 1 ? SIZE_H1 : SIZE_H2;
    const lead = level === 1 ? LEAD_H1 : LEAD_H2;
    this.ensure(lead);
    this.y -= size;
    this.textLine(FONT_PROSE, size, MARGIN_X, this.y, text);
    this.y -= lead - size;
  }

  paragraph(text: string): void {
    const max = maxCharsFor(SIZE_BODY, PROSE_ADVANCE);
    for (const ln of wrapText(text, max)) {
      this.ensure(LEAD_BODY);
      this.y -= SIZE_BODY;
      this.textLine(FONT_PROSE, SIZE_BODY, MARGIN_X, this.y, ln);
      this.y -= LEAD_BODY - SIZE_BODY;
    }
    this.y -= 4; // paragraph gap
  }

  table(columns: string[], rows: string[][]): void {
    const nCols = columns.length;
    if (nCols === 0) return;
    const colWidth = CONTENT_WIDTH / nCols;
    const cellChars = Math.max(1, Math.floor((colWidth - 6) / (SIZE_TABLE * MONO_ADVANCE)));

    const drawRow = (cells: string[], bold: boolean): void => {
      // Pre-wrap each cell, row height = tallest cell.
      const wrapped = cells.map((c) => wrapText(c ?? '', cellChars));
      const linesInRow = Math.max(1, ...wrapped.map((w) => w.length));
      const rowH = linesInRow * ROW_HEIGHT + 4;
      this.ensure(rowH);
      const top = this.y;
      const bottom = this.y - rowH;
      for (let li = 0; li < linesInRow; li++) {
        const baseY = top - SIZE_TABLE - li * ROW_HEIGHT - 2;
        for (let ci = 0; ci < nCols; ci++) {
          const cellLine = wrapped[ci]?.[li];
          if (cellLine === undefined) continue;
          const x = MARGIN_X + ci * colWidth + 3;
          const text = bold ? cellLine.toUpperCase() : cellLine;
          this.textLine(FONT_MONO, SIZE_TABLE, x, baseY, text);
        }
      }
      // Cell borders: vertical separators + bottom rule.
      for (let ci = 0; ci <= nCols; ci++) {
        const x = MARGIN_X + ci * colWidth;
        this.line(x, top, x, bottom);
      }
      this.line(MARGIN_X, bottom, MARGIN_X + CONTENT_WIDTH, bottom);
      if (bold) this.line(MARGIN_X, top, MARGIN_X + CONTENT_WIDTH, top);
      this.y = bottom;
    };

    drawRow(columns, true);
    for (const r of rows) drawRow(r, false);
    this.y -= 6; // gap after table
  }
}

// ─── PDF object assembly ──────────────────────────────────────────────────────

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

/**
 * Render a list of sections to a complete PDF 1.4 document.
 * Object layout: 1=Catalog, 2=Pages, 3=Helvetica, 4=Courier, then for each
 * page p (0-based): (5 + 2p)=Page, (6 + 2p)=Contents stream.
 */
export function renderPdf(sections: PdfSection[], opts: RenderPdfOptions = {}): Buffer {
  const layout = new Layout();
  if (opts.title) layout.heading(opts.title, 1);
  for (const s of sections) {
    if (s.kind === 'heading') layout.heading(s.text, s.level ?? 2);
    else if (s.kind === 'paragraph') layout.paragraph(s.text);
    else if (s.kind === 'table') layout.table(s.columns, s.rows);
  }

  const pages = layout.pages;
  const nPages = pages.length;

  const objects: Buffer[] = [];
  const pageObjNums: number[] = [];
  for (let p = 0; p < nPages; p++) pageObjNums.push(5 + p * 2);

  // 1: Catalog
  objects.push(obj(1, '<< /Type /Catalog /Pages 2 0 R >>'));
  // 2: Pages
  objects.push(
    obj(2, `<< /Type /Pages /Kids [${pageObjNums.map((n) => `${n} 0 R`).join(' ')}] /Count ${nPages} >>`),
  );
  // 3,4: Fonts
  objects.push(obj(3, '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>'));
  objects.push(obj(4, '<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>'));
  // Pages + content streams
  for (let p = 0; p < nPages; p++) {
    const pageNum = 5 + p * 2;
    const contentNum = 6 + p * 2;
    const resources = `<< /Font << /${FONT_PROSE} 3 0 R /${FONT_MONO} 4 0 R >> >>`;
    objects.push(
      obj(
        pageNum,
        `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_WIDTH} ${PAGE_HEIGHT}] ` +
          `/Resources ${resources} /Contents ${contentNum} 0 R >>`,
      ),
    );
    objects.push(streamObj(contentNum, Buffer.from(pages[p]!.ops.join('\n') + '\n', 'latin1')));
  }

  // Header. A binary comment line right after the version marks the file as
  // containing 8-bit data (PDF convention) and keeps naive readers honest.
  const header = Buffer.from('%PDF-1.4\n%\xE2\xE3\xCF\xD3\n', 'latin1');

  // Concatenate, recording each object's byte offset (objects are numbered
  // 1..maxObj in emission order).
  const chunks: Buffer[] = [header];
  let offset = header.length;
  const offsets: number[] = []; // offsets[i] = byte offset of object (i+1)
  for (const o of objects) {
    offsets.push(offset);
    chunks.push(o);
    offset += o.length;
  }

  const objCount = objects.length; // == maxObjNum (1..objCount, contiguous)
  const xrefStart = offset;

  // xref table — every entry is exactly 20 bytes.
  let xref = `xref\n0 ${objCount + 1}\n`;
  xref += '0000000000 65535 f \n';
  for (let i = 0; i < objCount; i++) {
    xref += `${String(offsets[i]).padStart(10, '0')} 00000 n \n`;
  }
  xref += `trailer\n<< /Size ${objCount + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF\n`;
  chunks.push(Buffer.from(xref, 'latin1'));

  return Buffer.concat(chunks);
}
