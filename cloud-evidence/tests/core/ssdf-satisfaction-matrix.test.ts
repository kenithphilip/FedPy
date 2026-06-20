/**
 * LOOP-T.T2 — SSDF satisfaction-matrix typedefs + canonical serializer + `.xlsx`
 * renderer (`core/ssdf-satisfaction-matrix.ts`). The renderer composes the
 * store-only OOXML writer from core/supply-chain-risk.ts, so the produced
 * workbook is plaintext-inspectable (inline strings) — the repo's xlsx test
 * convention.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSsdfSatisfactionMatrix } from '../../core/ssdf-evidence-aggregator.ts';
import {
  satisfactionMatrixToXlsx,
  serializeUnsignedCanonical,
  uuidV5,
  deriveMatrixId,
  matrixJsonFilename,
  matrixXlsxFilename,
  SATISFACTION_MATRIX_FILENAME,
  SATISFACTION_MATRIX_XLSX_FILENAME,
} from '../../core/ssdf-satisfaction-matrix.ts';

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-t2x-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

function matrix() {
  return buildSsdfSatisfactionMatrix({
    outDir: tmp(),
    cspName: 'Acme CSP',
    product: { id: 'acme-platform', name: 'Acme Platform' },
    generatedAt: '2026-06-20T12:00:00.000Z',
  });
}

describe('T.T2 — satisfactionMatrixToXlsx', () => {
  it('T2-16a: produces a structurally valid store-only .xlsx with both named sheets', () => {
    const buf = satisfactionMatrixToXlsx(matrix());
    const s = buf.toString('latin1');
    expect(s).toContain('xl/worksheets/sheet1.xml');
    expect(s).toContain('xl/worksheets/sheet2.xml');
    expect(s).toContain('Per-Task Matrix');
    expect(s).toContain('Per-Practice Summary');
    expect(s).toContain('t="inlineStr"');
  });

  it('T2-16b: sheet 1 has 42 task rows + header; sheet 2 has 19 practice rows + header (63 rows total)', () => {
    const buf = satisfactionMatrixToXlsx(matrix());
    const s = buf.toString('latin1');
    const rowCount = (s.match(/<row r="/g) ?? []).length;
    expect(rowCount).toBe(43 + 20); // (1 header + 42 tasks) + (1 header + 19 practices)
  });

  it('T2-16c: per-task rows carry the verbatim task id + practice id', () => {
    const s = satisfactionMatrixToXlsx(matrix()).toString('latin1');
    expect(s).toContain('PO.1.1');
    expect(s).toContain('RV.3.4');
    expect(s).toContain('PW.4');
  });

  it('T2-17b: a satisfied/requires-operator-input status value is rendered into the workbook', () => {
    const s = satisfactionMatrixToXlsx(matrix()).toString('latin1');
    // With no evidence corpus every task is requires-operator-input.
    expect(s).toContain('requires-operator-input');
  });

  it('uuidV5 is deterministic and RFC 4122 version-5 shaped', () => {
    const a = uuidV5('hello');
    const b = uuidV5('hello');
    const c = uuidV5('world');
    expect(a).toBe(b);
    expect(a).not.toBe(c);
    expect(a).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });

  it('deriveMatrixId is stable for identical inputs and changes when a source digest changes', () => {
    const base = { productId: 'p', cataloguePdfSha256: 'a'.repeat(64), sourceDigests: [{ kind: 'ksi-envelope', path: 'KSI-X.json', sha256: 'b'.repeat(64) }] };
    const id1 = deriveMatrixId(base);
    const id2 = deriveMatrixId({ ...base, sourceDigests: [...base.sourceDigests] });
    const id3 = deriveMatrixId({ ...base, sourceDigests: [{ kind: 'ksi-envelope', path: 'KSI-X.json', sha256: 'c'.repeat(64) }] });
    expect(id1).toBe(id2);
    expect(id1).not.toBe(id3);
  });

  it('serializeUnsignedCanonical blanks signature fields and yields sorted-key canonical JSON', () => {
    const m = matrix();
    m.provenance.signingKeyId = 'KEY';
    m.provenance.signatureEd25519 = 'SIG';
    m.provenance.publicKeyPem = 'PEM';
    const canon = serializeUnsignedCanonical(m);
    expect(canon).not.toContain('"KEY"');
    expect(canon).not.toContain('"SIG"');
    // Canonical form sorts object keys: catalogue_source precedes csp_name precedes generated_at.
    expect(canon.indexOf('"catalogue_source"')).toBeLessThan(canon.indexOf('"csp_name"'));
    expect(canon.indexOf('"csp_name"')).toBeLessThan(canon.indexOf('"generated_at"'));
  });

  it('matrix filename helpers: first product owns the canonical name; others are slug-suffixed', () => {
    expect(matrixJsonFilename('acme', true)).toBe(SATISFACTION_MATRIX_FILENAME);
    expect(matrixXlsxFilename('acme', true)).toBe(SATISFACTION_MATRIX_XLSX_FILENAME);
    expect(matrixJsonFilename('Acme Platform 2', false)).toBe('ssdf-satisfaction-matrix.acme-platform-2.json');
    expect(matrixXlsxFilename('Acme Platform 2', false)).toBe('ssdf-satisfaction-matrix.acme-platform-2.xlsx');
  });
});
