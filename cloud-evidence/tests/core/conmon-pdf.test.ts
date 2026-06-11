/**
 * Tests for core/conmon-pdf.ts — the dependency-free PDF 1.4 generator (LOOP-E.E1).
 *
 * Covers per-slice doc §8 tests 14-23: xref offset accuracy, stream-length
 * correctness, prose wrapping, table borders, special-character escaping,
 * determinism, page-per-logical-page, page-count growth, FlateDecode
 * round-trip, and the Catalog -> Pages -> Page object chain.
 *
 * The PDF is validated by re-parsing the bytes (xref + objects) and inflating
 * the FlateDecode content streams with Node `zlib` — no third-party PDF reader,
 * so the assertions are exact and deterministic.
 */
import { describe, it, expect } from 'vitest';
import { inflateSync, deflateSync } from 'node:zlib';
import { renderPdf, wrapText, escapePdfText, type PdfSection } from '../../core/conmon-pdf.ts';

// ─── Re-parsing helpers ───────────────────────────────────────────────────────

function latin1(buf: Buffer): string {
  return buf.toString('latin1');
}

interface ParsedStream {
  declaredLength: number;
  compressed: Buffer;
  inflated: string;
}

function extractStreams(buf: Buffer): ParsedStream[] {
  const s = latin1(buf);
  const out: ParsedStream[] = [];
  const re = /<< \/Length (\d+) \/Filter \/FlateDecode >>\nstream\n/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) {
    const len = Number(m[1]);
    const start = m.index + m[0].length;
    const compressed = buf.subarray(start, start + len);
    out.push({ declaredLength: len, compressed, inflated: inflateSync(compressed).toString('latin1') });
  }
  return out;
}

function parseXref(buf: Buffer): { objCount: number; offsets: number[]; xrefStart: number } {
  const s = latin1(buf);
  const m = s.match(/startxref\n(\d+)\n%%EOF\s*$/);
  if (!m) throw new Error('no startxref/%%EOF trailer');
  const xrefStart = Number(m[1]);
  const block = s.slice(xrefStart);
  const lines = block.split('\n');
  const objCount = Number(lines[1]!.split(' ')[1]) - 1; // "0 N+1"
  // lines[2] is the free object-0 entry; object i lives at lines[2 + i].
  const offsets: number[] = [];
  for (let i = 1; i <= objCount; i++) offsets.push(Number(lines[2 + i]!.slice(0, 10)));
  return { objCount, offsets, xrefStart };
}

const SAMPLE: PdfSection[] = [
  { kind: 'heading', text: 'Section One', level: 1 },
  { kind: 'paragraph', text: 'A concise paragraph of prose for the report body.' },
  { kind: 'table', columns: ['Alpha', 'Bravo', 'Charlie'], rows: [['1', '2', '3'], ['x', 'y', 'z']] },
];

function bigDoc(nParas: number): PdfSection[] {
  const out: PdfSection[] = [{ kind: 'heading', text: 'Big', level: 1 }];
  for (let i = 0; i < nParas; i++) out.push({ kind: 'paragraph', text: `Paragraph ${i}: ${'filler word '.repeat(8)}` });
  return out;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('conmon-pdf', () => {
  it('PDF xref offsets resolve correctly', () => {
    const buf = renderPdf(SAMPLE, { title: 'Report' });
    const s = latin1(buf);
    const { objCount, offsets } = parseXref(buf);
    expect(objCount).toBeGreaterThanOrEqual(6); // catalog+pages+2 fonts+>=1 page+content
    for (let i = 0; i < objCount; i++) {
      const at = s.slice(offsets[i]!, offsets[i]! + 16);
      expect(at.startsWith(`${i + 1} 0 obj`)).toBe(true);
    }
  });

  it('PDF stream lengths match /Length entries', () => {
    const buf = renderPdf(SAMPLE, { title: 'Report' });
    const s = latin1(buf);
    const re = /<< \/Length (\d+) \/Filter \/FlateDecode >>\nstream\n/g;
    let m: RegExpExecArray | null;
    let n = 0;
    while ((m = re.exec(s))) {
      n++;
      const len = Number(m[1]);
      const start = m.index + m[0].length;
      expect(s.slice(start + len, start + len + 11)).toBe('\nendstream\n');
    }
    expect(n).toBeGreaterThanOrEqual(1);
  });

  it('PDF wraps prose at the right column position', () => {
    // Unit: the wrapper never exceeds the budget and splits over-long words.
    const wrapped = wrapText(`${'word '.repeat(60)}${'z'.repeat(200)}`, 40);
    expect(wrapped.length).toBeGreaterThan(1);
    for (const ln of wrapped) expect(ln.length).toBeLessThanOrEqual(40);
    // Render-level: a long paragraph produces multiple text-show operators.
    const streams = extractStreams(renderPdf([{ kind: 'paragraph', text: 'lorem-free '.repeat(120) }]));
    const tjCount = (streams.map((x) => x.inflated).join('').match(/\) Tj/g) ?? []).length;
    expect(tjCount).toBeGreaterThan(3);
  });

  it('PDF renders a 3-column table with borders', () => {
    const streams = extractStreams(renderPdf([{ kind: 'table', columns: ['Alpha', 'Bravo', 'Charlie'], rows: [['1', '2', '3']] }]));
    const content = streams.map((x) => x.inflated).join('\n');
    // Column header text (bold rows are upper-cased in the renderer).
    expect(content).toContain('(ALPHA)');
    expect(content).toContain('(BRAVO)');
    expect(content).toContain('(CHARLIE)');
    // Border line operators (move + line + stroke).
    expect(content).toMatch(/\d+\.\d+ \d+\.\d+ m \d+\.\d+ \d+\.\d+ l S/);
  });

  it('PDF handles XML/PDF special chars in user text (parens, backslashes)', () => {
    expect(escapePdfText('a(b)c\\d')).toBe('a\\(b\\)c\\\\d');
    const buf = renderPdf([{ kind: 'paragraph', text: 'risky (value) with \\ backslash' }]);
    const content = extractStreams(buf).map((x) => x.inflated).join('');
    expect(content).toContain('\\(value\\)');
    expect(content).toContain('\\\\');
    // The escaped output must still parse: xref offsets resolve.
    const { objCount, offsets } = parseXref(buf);
    const s = latin1(buf);
    for (let i = 0; i < objCount; i++) expect(s.slice(offsets[i]!, offsets[i]! + 7)).toBe(`${i + 1} 0 obj`);
  });

  it('PDF is deterministic on same input', () => {
    const a = renderPdf(SAMPLE, { title: 'Report' });
    const b = renderPdf(SAMPLE, { title: 'Report' });
    expect(Buffer.compare(a, b)).toBe(0);
  });

  it('PDF emits one Page per logical page', () => {
    const buf = renderPdf([{ kind: 'heading', text: 'Hi', level: 1 }, { kind: 'paragraph', text: 'short body' }]);
    const s = latin1(buf);
    const count = Number(s.match(/\/Type \/Pages \/Kids \[([^\]]*)\] \/Count (\d+)/)![2]);
    const kids = s.match(/\/Kids \[([^\]]*)\]/)![1]!.trim().match(/\d+ 0 R/g) ?? [];
    expect(count).toBe(1);
    expect(kids.length).toBe(1);
  });

  it('PDF page count grows with content', () => {
    const small = Number(latin1(renderPdf(bigDoc(2))).match(/\/Count (\d+)/)![1]);
    const large = Number(latin1(renderPdf(bigDoc(120))).match(/\/Count (\d+)/)![1]);
    expect(small).toBe(1);
    expect(large).toBeGreaterThan(small);
  });

  it('PDF FlateDecode round-trips', () => {
    const streams = extractStreams(renderPdf(SAMPLE, { title: 'Report' }));
    expect(streams.length).toBeGreaterThan(0);
    for (const st of streams) {
      expect(st.inflated).toContain('BT'); // begin-text operator present
      // re-deflate then re-inflate is identity on the content bytes
      const round = inflateSync(deflateSync(Buffer.from(st.inflated, 'latin1'))).toString('latin1');
      expect(round).toBe(st.inflated);
    }
  });

  it('PDF Catalog -> Pages -> Page chain resolves', () => {
    const buf = renderPdf(bigDoc(60));
    const s = latin1(buf);
    // Catalog references Pages 2 0 R.
    expect(s).toMatch(/1 0 obj\n<< \/Type \/Catalog \/Pages 2 0 R >>/);
    // Pages enumerates Kids; each kid object is a /Type /Page.
    const kids = s.match(/2 0 obj\n<< \/Type \/Pages \/Kids \[([^\]]*)\]/)![1]!.trim().match(/(\d+) 0 R/g)!;
    expect(kids.length).toBeGreaterThan(1);
    for (const k of kids) {
      const num = k.split(' ')[0];
      expect(s).toContain(`${num} 0 obj\n<< /Type /Page /Parent 2 0 R`);
    }
  });
});
