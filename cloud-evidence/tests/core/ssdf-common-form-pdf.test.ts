/**
 * LOOP-T.T3 — deterministic CISA Common Form PDF renderer tests.
 *
 * The PDF is validated by re-parsing the bytes (xref + /Count + MediaBox) and
 * inflating the FlateDecode content streams with Node `zlib` — no third-party PDF
 * reader, so the assertions are exact and deterministic (the same approach as
 * tests/core/conmon-pdf.test.ts).
 */
import { describe, it, expect, afterEach } from 'vitest';
import { inflateSync } from 'node:zlib';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { emptyStatusTally, type SsdfSatisfactionMatrix, type SsdfTaskRow } from '../../core/ssdf-satisfaction-matrix.ts';
import type { CommonFormSection } from '../../core/ssdf-practices-catalog.ts';
import { emitSsdfCommonForm, type CisaCommonFormCanonical } from '../../core/ssdf-common-form.ts';
import { renderCommonFormPdf, pdfDate } from '../../core/ssdf-common-form-pdf.ts';

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-t3pdf-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* ignore */ }
  }
});

// ─── PDF re-parsing helpers (mirrors conmon-pdf.test.ts) ──────────────────────

function latin1(buf: Buffer): string {
  return buf.toString('latin1');
}
function inflatedStreams(buf: Buffer): string[] {
  const s = latin1(buf);
  const out: string[] = [];
  const re = /<< \/Length (\d+) \/Filter \/FlateDecode >>\nstream\n/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) {
    const len = Number(m[1]);
    const start = m.index + m[0].length;
    out.push(inflateSync(buf.subarray(start, start + len)).toString('latin1'));
  }
  return out;
}

/**
 * Reconstruct the visible text of a page's content stream: pull every `( ... ) Tj`
 * literal, unescape the PDF metacharacters, and join with single spaces. This
 * de-wraps lines the renderer broke for layout, so a verbatim sentence split
 * across two display lines is matchable as one contiguous string.
 */
function pageText(stream: string): string {
  const parts: string[] = [];
  const re = /\(((?:\\.|[^\\()])*)\)\s*Tj/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(stream))) {
    parts.push(m[1]!.replace(/\\\(/g, '(').replace(/\\\)/g, ')').replace(/\\\\/g, '\\'));
  }
  return parts.join(' ').replace(/\s+/g, ' ');
}

// ─── Fixture (a compact comply-everywhere form, optionally with AI) ───────────

function task(id: string, sections: CommonFormSection[]): SsdfTaskRow {
  return {
    id,
    statement: `Task ${id}`,
    status: 'satisfied',
    nist_800_53_r5_controls: [],
    crosswalk_ksi: [],
    common_form_section_ref: sections,
    evidence_pointers: [{ kind: 'oscal-observation', observation_uuid: `o-${id}`, control_id: 'sa-15', source_path: 'out/KSI-x.json' }],
    open_risk_score: null,
    diagnostics: [],
  };
}

function matrix(): SsdfSatisfactionMatrix {
  const tasks = [task('PO.5.1', ['§IV(1)']), task('PW.4.1', ['§IV(2)']), task('PS.3.2', ['§IV(3)']), task('PW.7.1', ['§IV(4)'])];
  const tally = emptyStatusTally();
  tally['satisfied'] = tasks.length;
  return {
    schema_version: '1.0',
    matrix_id: 'm-acme',
    generated_at: '2026-06-20T00:00:00.000Z',
    csp_name: 'Acme CSP, Inc.',
    product: { id: 'acme-cep', name: 'Acme Cloud Evidence Platform', ai_enabled: false, critical_software: false },
    regime: 'test',
    catalogue_source: { sp: '800-218', version: 'v1.1', publication_date: '2022-02', source_pdf_sha256: 'd' },
    totals: { practices: 1, tasks: tasks.length, practices_by_status: emptyStatusTally(), tasks_by_status: tally },
    practices: [{ id: 'PO.1', group: 'PO', name: 'Prepare', outcome: '', status: 'satisfied', open_risk_score: null, tasks_by_status: tally, tasks }],
    provenance: {
      emitter: 'core/ssdf-evidence-aggregator.ts', emitterVersion: '1', emittedAt: '2026-06-20T00:00:00.000Z',
      sourceCalls: ['fixture'], sourceDigests: [], signingKeyId: 'k', publicKeyPem: 'p', signatureEd25519: 's',
      timestampAuthority: null, coverageDiagnostics: [],
    },
  };
}

function producer(ai = false): Record<string, any> {
  return {
    legal_name: 'Acme CSP, Inc.',
    address: { street: '123 Main St', city: 'Reston', state: 'VA', postal_code: '20190', country: 'US' },
    point_of_contact: { name: 'Jane Doe', title: 'CISO', email: 'jane.doe@acme.example', phone: '+1-703-555-0100' },
    signatory: { name: 'John Smith', title: 'Chief Executive Officer' },
    scope_of_attestation: { products: [{ name: 'Acme Cloud Evidence Platform', version: '2026.6.1' }] },
    ai_profile: ai,
  };
}

function emitForm(ai = false): { form: CisaCommonFormCanonical; pdf: Buffer } {
  const dir = tmp();
  writeFileSync(resolve(dir, 'ssdf-satisfaction-matrix.json'), JSON.stringify(matrix(), null, 2));
  const res = emitSsdfCommonForm({
    outDir: dir,
    runId: 't3',
    producer: producer(ai),
    generatedAt: '2026-06-20T12:00:00.000Z',
    aiProfilePractices: ai ? [{ id: 'PW.A.1', status: 'satisfied' }] : undefined,
  });
  return {
    form: JSON.parse(readFileSync(res.json_path, 'utf8')) as CisaCommonFormCanonical,
    pdf: readFileSync(res.pdf_path),
  };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('ssdf-common-form-pdf', () => {
  it('T3-T10: render is byte-deterministic for identical (form, docId)', () => {
    const { form } = emitForm();
    const a = renderCommonFormPdf(form, { docId: 'abc123' });
    const b = renderCommonFormPdf(form, { docId: 'abc123' });
    expect(a.equals(b)).toBe(true);
  });

  it('T3-T11: emits a US-Letter (612x792) page', () => {
    const { pdf } = emitForm();
    expect(latin1(pdf)).toContain('/MediaBox [0 0 612 792]');
  });

  it('T3-T09/T3-T11: no-AI form is a 4-page document', () => {
    const { pdf } = emitForm(false);
    const count = Number(latin1(pdf).match(/\/Count (\d+)/)![1]);
    expect(count).toBe(4);
  });

  it('T3-T08: ai_profile form adds Appendix B (5 pages)', () => {
    const { pdf } = emitForm(true);
    const count = Number(latin1(pdf).match(/\/Count (\d+)/)![1]);
    expect(count).toBe(5);
  });

  it('T3-T12: the OMB Control Number 1670-0052 footer is on every page', () => {
    const { pdf } = emitForm(false);
    const streams = inflatedStreams(pdf);
    expect(streams.length).toBe(4);
    for (const s of streams) expect(s).toContain('1670-0052');
  });

  it('T3-T13: producer legal name appears on Section I (page 1)', () => {
    const { pdf } = emitForm();
    const streams = inflatedStreams(pdf);
    expect(pageText(streams[0]!)).toContain('Acme CSP, Inc.');
  });

  it('T3-T14: verbatim Practice 1.a text appears on Section II (page 2)', () => {
    const { pdf } = emitForm();
    const streams = inflatedStreams(pdf);
    expect(pageText(streams[1]!)).toContain('separating and protecting each environment involved in developing and building software');
  });

  it('T3-T15: verbatim Practice 4 statement appears on Section II (page 2)', () => {
    const { pdf } = emitForm();
    const streams = inflatedStreams(pdf);
    expect(pageText(streams[1]!)).toContain('The software producer employed automated tools or comparable processes that check for security vulnerabilities');
  });

  it('the signatory penalty-of-perjury attestation appears on Section III (page 3)', () => {
    const { pdf } = emitForm();
    const streams = inflatedStreams(pdf);
    expect(pageText(streams[2]!)).toContain('hereby attest under penalty of perjury');
  });

  it('a valid PDF header + EOF trailer + deterministic /Info date are present', () => {
    const { pdf } = emitForm();
    const s = latin1(pdf);
    expect(s.startsWith('%PDF-1.4')).toBe(true);
    expect(s.trimEnd().endsWith('%%EOF')).toBe(true);
    expect(s).toContain('/CreationDate (D:20260620120000Z)');
  });

  it('pdfDate derives a deterministic D:YYYYMMDDHHmmSSZ string', () => {
    expect(pdfDate('2026-06-20T12:00:00.000Z')).toBe('D:20260620120000Z');
    expect(pdfDate('not-a-date')).toBe('D:19700101000000Z');
  });
});
