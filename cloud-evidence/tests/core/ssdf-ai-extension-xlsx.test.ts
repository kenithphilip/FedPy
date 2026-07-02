/**
 * LOOP-T.T5 — XLSX renderer for the 800-218A SSDF-AI extension.
 *
 * Covers per-slice doc §8 T5-20 (one worksheet per in-scope product + Summary +
 * delta + statutory-lineage) and T5-21 (per-product worksheet column schema
 * A..O). The workbook is a dependency-free OOXML zip; we read it back with the
 * repo's zip reader to assert structure.
 */
import { describe, it, expect } from 'vitest';
import { loadAugmentationCatalogue, buildAiAugmentation, type ModelCard } from '../../core/ssdf-ai-extension.ts';
import { renderAiAugmentationXlsx } from '../../core/ssdf-ai-extension-xlsx.ts';
import type { SsdfSatisfactionMatrix, TaskStatus } from '../../core/ssdf-satisfaction-matrix.ts';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { inflateRawSync } from 'node:zlib';

const IPD_FIXTURE = fileURLToPath(new URL('../fixtures/ssdf-ai-extension/ipd-catalogue.json', import.meta.url));

function mkMatrixForXlsx(productId: string, tasks: Array<{ id: string; status: TaskStatus; withPointer?: boolean }>): SsdfSatisfactionMatrix {
  const zero = { 'satisfied': 0, 'partially-satisfied': 0, 'not-satisfied': 0, 'not-assessed': 0, 'requires-operator-input': 0 };
  return {
    schema_version: '1.0', matrix_id: 'm', generated_at: '2026-07-02T12:00:00.000Z', csp_name: 'CSP',
    product: { id: productId, name: productId, ai_enabled: true, critical_software: false }, regime: 'm-22-18-mandatory',
    catalogue_source: { sp: '800-218', version: '1.1', publication_date: '2022-02-01', source_pdf_sha256: 'x' },
    totals: { practices: 1, tasks: tasks.length, practices_by_status: { ...zero }, tasks_by_status: { ...zero } },
    practices: [{
      id: 'PO.1', group: 'PO', name: 'PO.1', outcome: 'o', status: 'partially-satisfied', open_risk_score: null, tasks_by_status: { ...zero },
      tasks: tasks.map((t) => ({ id: t.id, statement: `stmt ${t.id}`, status: t.status, nist_800_53_r5_controls: [], crosswalk_ksi: [], common_form_section_ref: [], evidence_pointers: t.withPointer ? [{ kind: 'ksi-envelope', ksi_id: 'K', envelope_sha256: 's', signing_key_id: 'k', signature_verified: true, source_path: 'K.json' }] : [], open_risk_score: null, diagnostics: [] })),
    }],
    provenance: { emitter: 'core/ssdf-evidence-aggregator.ts', emitterVersion: '1', emittedAt: '2026-07-02T12:00:00.000Z', sourceCalls: ['x'], sourceDigests: [], signingKeyId: 'k', publicKeyPem: 'p', signatureEd25519: 's', timestampAuthority: null, coverageDiagnostics: [] },
  };
}

function card(over: Partial<ModelCard> = {}): ModelCard {
  return {
    product_id: 'ai-one', model_id: 'm', ai_use_case: 'assistant', is_dual_use_foundation_model: false,
    training_data_provenance: { datasets: [], attestation_pointer: null },
    pre_deployment_evaluations: [{ id: 'e', report_path: 'r' }], post_deployment_evaluations: [], red_team_engagements: [],
    ...over,
  };
}

function build(cards: ModelCard[]) {
  const cat = loadAugmentationCatalogue(IPD_FIXTURE);
  const result = buildAiAugmentation({
    outDir: '/tmp', cspName: 'CSP', catalogue: cat, secondaryCatalogueVersion: 'final',
    matrix: mkMatrixForXlsx(cards[0].product_id, [{ id: 'PO.1.1', status: 'satisfied', withPointer: true }]),
    matrixSha256: 'm', modelCards: cards.map((c) => ({ card: c, path: `model-cards/${c.product_id}.json`, sha256: 's' })),
    aiKsiByAugmentation: new Map(), generatedAt: '2026-07-02T12:00:00.000Z',
  });
  const delta = JSON.parse(readFileSync(fileURLToPath(new URL('../../docs/sources/ssdf-800-218A-delta.json', import.meta.url)), 'utf8'));
  return { result, cat, delta };
}

/** Extract every worksheet's decompressed XML from an .xlsx zip buffer. */
function readSheetXmls(buf: Buffer): string[] {
  const sheets: Array<{ name: string; xml: string }> = [];
  let i = 0;
  while (i + 4 <= buf.length) {
    const sig = buf.readUInt32LE(i);
    if (sig !== 0x04034b50) break; // local file header
    const method = buf.readUInt16LE(i + 8);
    const compSize = buf.readUInt32LE(i + 18);
    const nameLen = buf.readUInt16LE(i + 26);
    const extraLen = buf.readUInt16LE(i + 28);
    const name = buf.toString('utf8', i + 30, i + 30 + nameLen);
    const dataStart = i + 30 + nameLen + extraLen;
    const raw = buf.subarray(dataStart, dataStart + compSize);
    const content = method === 8 ? inflateRawSync(raw) : raw;
    if (name.startsWith('xl/worksheets/sheet')) sheets.push({ name, xml: content.toString('utf8') });
    i = dataStart + compSize;
  }
  return sheets.sort((a, b) => a.name.localeCompare(b.name)).map((s) => s.xml);
}

describe('T.T5 xlsx renderer', () => {
  it('T5-20: writes Summary + one worksheet per in-scope product + delta + lineage', () => {
    const { result, cat, delta } = build([card({ product_id: 'ai-one' }), card({ product_id: 'ai-two' })]);
    const buf = renderAiAugmentationXlsx(result, cat, delta);
    const sheets = readSheetXmls(buf);
    // Summary + 2 products + IPD-vs-final delta + Statutory lineage = 5 worksheets.
    expect(sheets.length).toBe(5);
  });

  it('T5-21: each per-product worksheet carries the 15-column A..O header row', () => {
    const { result, cat, delta } = build([card({ product_id: 'ai-one' })]);
    const buf = renderAiAugmentationXlsx(result, cat, delta);
    const sheets = readSheetXmls(buf);
    // Worksheet 2 is the (single) product sheet; its header row 1 has 15 cells A1..O1.
    const productSheet = sheets[1];
    for (const col of ['A1', 'B1', 'C1', 'D1', 'E1', 'F1', 'G1', 'H1', 'I1', 'J1', 'K1', 'L1', 'M1', 'N1', 'O1']) {
      expect(productSheet).toContain(`r="${col}"`);
    }
    expect(productSheet).not.toContain('r="P1"'); // exactly 15 columns
  });

  it('T5-20b: a product worksheet contains the augmentation id and status cells', () => {
    const { result, cat, delta } = build([card({ product_id: 'ai-one' })]);
    const buf = renderAiAugmentationXlsx(result, cat, delta);
    const sheets = readSheetXmls(buf);
    const productSheet = sheets[1];
    expect(productSheet).toContain('PO.1.1.R1');
    expect(productSheet).toContain('satisfied');
  });

  it('T5-20c: the delta worksheet reflects the committed IPD-vs-final sidecar rows', () => {
    const { result, cat, delta } = build([card({ product_id: 'ai-one' })]);
    const buf = renderAiAugmentationXlsx(result, cat, delta);
    const sheets = readSheetXmls(buf);
    // The 2nd-to-last sheet is the delta; assert a diff class token appears.
    const deltaSheet = sheets[sheets.length - 2];
    expect(deltaSheet).toMatch(/restated|added|removed|renamed/);
  });
});
