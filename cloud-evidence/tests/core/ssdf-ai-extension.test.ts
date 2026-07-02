/**
 * LOOP-T.T5 — NIST SP 800-218A SSDF-AI extension.
 *
 * Covers per-slice doc §8 (T5-1..T5-25, reconciled to the real published
 * 800-218A structure: R/C/N item ids `<task>.R<n>` rather than the spec's
 * assumed `<task>.A<n>`; RFC 3161 coverage via the run-manifest TSR as with
 * T.T2, so the sign test asserts `.sig` + signature verification rather than a
 * per-file `.tsr`). Fixtures: two committed catalogue fixtures + the REAL
 * committed catalogues (data/ssdf-800-218A-final.json) + inline matrices /
 * model cards / AI KSI envelopes written to tmp dirs, so every join exercises
 * the real code path.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize, verifyDetached } from '../../core/sign.ts';
import type { SsdfSatisfactionMatrix, TaskStatus, SsdfEvidencePointer } from '../../core/ssdf-satisfaction-matrix.ts';
import {
  loadAugmentationCatalogue,
  loadModelCards,
  isModelCardInScope,
  deriveAugmentationStatus,
  buildAiAugmentation,
  buildAugmentedMatrix,
  emitSsdfAiAugmentation,
  SsdfAiCatalogueIntegrityError,
  MissingSatisfactionMatrixError,
  AI_AUGMENTATION_FILENAME,
  AUGMENTED_MATRIX_FILENAME,
  type SsdfAiAugmentation,
  type SsdfAiAugmentationCatalogue,
  type ModelCard,
} from '../../core/ssdf-ai-extension.ts';

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-t5-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

const GEN_AT = '2026-07-02T12:00:00.000Z';
const FIXTURE_DIR = fileURLToPath(new URL('../fixtures/ssdf-ai-extension/', import.meta.url));
const IPD_FIXTURE = join(FIXTURE_DIR, 'ipd-catalogue.json');
const MALFORMED_FIXTURE = join(FIXTURE_DIR, 'ipd-catalogue-malformed.json');
const REAL_FINAL_CATALOGUE = fileURLToPath(new URL('../../data/ssdf-800-218A-final.json', import.meta.url));
const REAL_IPD_CATALOGUE = fileURLToPath(new URL('../../data/ssdf-800-218A-ipd.json', import.meta.url));
const REAL_DELTA = fileURLToPath(new URL('../../docs/sources/ssdf-800-218A-delta.json', import.meta.url));
const CHECK_PROVENANCE = fileURLToPath(new URL('../../scripts/check-provenance.mjs', import.meta.url));
const CHECK_NO_SILENT_PASS = fileURLToPath(new URL('../../scripts/check-ssdf-no-silent-pass.mjs', import.meta.url));

// ─── Inline fixture builders ────────────────────────────────────────────────

function ksiPointer(sha: string): SsdfEvidencePointer {
  return { kind: 'ksi-envelope', ksi_id: 'KSI-AI-01', envelope_sha256: sha, signing_key_id: 'k', signature_verified: true, source_path: 'KSI-AI-01.json' };
}

/** Minimal but structurally real T.T2 satisfaction matrix. */
function mkMatrix(productId: string, tasks: Array<{ id: string; status: TaskStatus; withPointer?: boolean }>): SsdfSatisfactionMatrix {
  const byPractice = new Map<string, Array<{ id: string; status: TaskStatus; withPointer?: boolean }>>();
  for (const t of tasks) {
    const pid = t.id.split('.').slice(0, 2).join('.');
    if (!byPractice.has(pid)) byPractice.set(pid, []);
    byPractice.get(pid)!.push(t);
  }
  const practices = [...byPractice.entries()].map(([pid, ts]) => ({
    id: pid,
    group: pid.slice(0, 2) as 'PO' | 'PS' | 'PW' | 'RV',
    name: pid,
    outcome: 'outcome',
    status: 'partially-satisfied' as TaskStatus,
    open_risk_score: null,
    tasks_by_status: { 'satisfied': 0, 'partially-satisfied': 0, 'not-satisfied': 0, 'not-assessed': 0, 'requires-operator-input': 0 },
    tasks: ts.map((t) => ({
      id: t.id,
      statement: `statement for ${t.id}`,
      status: t.status,
      nist_800_53_r5_controls: [],
      crosswalk_ksi: [],
      common_form_section_ref: [],
      evidence_pointers: t.withPointer ? [ksiPointer(`sha-${t.id}`)] : [],
      open_risk_score: null,
      diagnostics: [],
    })),
  }));
  return {
    schema_version: '1.0',
    matrix_id: 'test-matrix',
    generated_at: GEN_AT,
    csp_name: 'Test CSP',
    product: { id: productId, name: productId, ai_enabled: true, critical_software: false },
    regime: 'm-22-18-mandatory',
    catalogue_source: { sp: '800-218', version: '1.1', publication_date: '2022-02-01', source_pdf_sha256: 'base-sha' },
    totals: { practices: practices.length, tasks: tasks.length, practices_by_status: { 'satisfied': 0, 'partially-satisfied': 0, 'not-satisfied': 0, 'not-assessed': 0, 'requires-operator-input': 0 }, tasks_by_status: { 'satisfied': 0, 'partially-satisfied': 0, 'not-satisfied': 0, 'not-assessed': 0, 'requires-operator-input': 0 } },
    practices,
    provenance: { emitter: 'core/ssdf-evidence-aggregator.ts', emitterVersion: '1.0.0', emittedAt: GEN_AT, sourceCalls: ['ssdf-catalog:data/ssdf-800-218-v1.1.json'], sourceDigests: [], signingKeyId: 'k', publicKeyPem: 'p', signatureEd25519: 's', timestampAuthority: null, coverageDiagnostics: [] },
  };
}

function mkCard(over: Partial<ModelCard> = {}): ModelCard {
  return {
    product_id: 'gen-ai-product',
    model_id: 'model-1',
    ai_use_case: 'summarization assistant',
    is_dual_use_foundation_model: false,
    model_family: { name: 'fam', version: '1', upstream_provider: null, parameter_count_estimate: null },
    training_data_provenance: { datasets: [], attestation_pointer: null },
    pre_deployment_evaluations: [],
    post_deployment_evaluations: [],
    red_team_engagements: [],
    ...over,
  };
}

function writeCard(outDir: string, card: ModelCard): void {
  const dir = join(outDir, 'model-cards');
  mkdirSync(dir, { recursive: true });
  // Real LOOP-O.O5 model cards carry their own provenance block (they are signed
  // O.O5 outputs); include one so the emitted out/ dir is G3-provenance-clean.
  const withProv = { ...card, provenance: { emitter: 'core/model-cards.ts', emittedAt: GEN_AT, sourceCalls: ['model-registry'], signingKeyId: 'o5-key' } };
  writeFileSync(join(dir, `${card.product_id}.json`), JSON.stringify(withProv, null, 2));
}

function writeMatrix(outDir: string, matrix: SsdfSatisfactionMatrix): void {
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, 'ssdf-satisfaction-matrix.json'), JSON.stringify(matrix, null, 2));
}

function aug(over: Partial<SsdfAiAugmentation> = {}): SsdfAiAugmentation {
  return {
    augmentation_id: 'PO.1.1.R1',
    parent_task_id: 'PO.1.1',
    item_type: 'R',
    statement: 'Include AI model development in the security requirements.',
    notes: '',
    informative_references: [],
    applies_to: ['both'],
    ...over,
  };
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('T.T5 — 800-218A catalogue load + integrity', () => {
  it('T5-1: loads a catalogue with non-empty practices', () => {
    const cat = loadAugmentationCatalogue(IPD_FIXTURE);
    expect(cat.practices.length).toBeGreaterThan(0);
    expect(cat.version).toBe('IPD');
  });

  it('T5-2: every augmentation parent_task_id resolves (real final catalogue joins base)', () => {
    const cat = loadAugmentationCatalogue(REAL_FINAL_CATALOGUE);
    expect(cat.practices.length).toBeGreaterThanOrEqual(4);
    // No throw ⇒ every base_task_present task exists in base + every aug parent matches its task.
    let augCount = 0;
    for (const p of cat.practices) for (const t of p.tasks) for (const a of t.augmentations) {
      expect(a.parent_task_id).toBe(t.task_id);
      augCount++;
    }
    expect(augCount).toBeGreaterThan(0);
  });

  it('T5-3: throws SsdfAiCatalogueIntegrityError naming the augmentation + parent on a malformed catalogue', () => {
    expect(() => loadAugmentationCatalogue(MALFORMED_FIXTURE)).toThrow(SsdfAiCatalogueIntegrityError);
    try {
      loadAugmentationCatalogue(MALFORMED_FIXTURE);
    } catch (e) {
      expect((e as Error).message).toContain('PO.1.1.R1');
      expect((e as Error).message).toContain('PO.99.99');
    }
  });

  it('T5-2b: re-adds PW.3 tasks (not-part-of-ssdf-1.1) with base_task_present=false', () => {
    const cat = loadAugmentationCatalogue(REAL_FINAL_CATALOGUE);
    const pw3 = cat.practices.find((p) => p.practice_id === 'PW.3');
    expect(pw3).toBeTruthy();
    const pw31 = pw3!.tasks.find((t) => t.task_id === 'PW.3.1');
    expect(pw31?.base_task_present).toBe(false);
    expect(pw31?.ssdf_1_1_tag).toBe('not-part-of-ssdf-1.1');
  });
});

describe('T.T5 — conditional gate (emit)', () => {
  it('T5-4: exits early when no model cards present', () => {
    const out = join(tmp(), 'out');
    writeMatrix(out, mkMatrix('p', [{ id: 'PO.1.1', status: 'satisfied', withPointer: true }]));
    const r = emitSsdfAiAugmentation({ outDir: out, runId: 'r', cspName: 'CSP', aiAugmentationEnabled: true, ipdCataloguePath: IPD_FIXTURE, finalCataloguePath: IPD_FIXTURE });
    expect(r).toEqual({ skipped: true, reason: 'no-model-cards' });
    expect(existsSync(join(out, AI_AUGMENTATION_FILENAME))).toBe(false);
  });

  it('T5-5: exits early when all model cards are out of AI scope', () => {
    const out = join(tmp(), 'out');
    writeMatrix(out, mkMatrix('p', [{ id: 'PO.1.1', status: 'satisfied', withPointer: true }]));
    writeCard(out, mkCard({ product_id: 'plain', ai_use_case: '', is_dual_use_foundation_model: false }));
    const r = emitSsdfAiAugmentation({ outDir: out, runId: 'r', cspName: 'CSP', aiAugmentationEnabled: true, ipdCataloguePath: IPD_FIXTURE, finalCataloguePath: IPD_FIXTURE });
    expect(r).toEqual({ skipped: true, reason: 'no-ai-products-in-scope' });
  });

  it('T5-23: exits early when ai_augmentation_enabled is false', () => {
    const out = join(tmp(), 'out');
    writeMatrix(out, mkMatrix('p', [{ id: 'PO.1.1', status: 'satisfied', withPointer: true }]));
    writeCard(out, mkCard());
    const r = emitSsdfAiAugmentation({ outDir: out, runId: 'r', cspName: 'CSP', aiAugmentationEnabled: false });
    expect(r).toEqual({ skipped: true, reason: 'ai-augmentation-disabled' });
  });

  it('T5-3b: throws MissingSatisfactionMatrixError when T.T2 matrix absent but scope present', () => {
    const out = join(tmp(), 'out');
    mkdirSync(out, { recursive: true });
    writeCard(out, mkCard());
    expect(() => emitSsdfAiAugmentation({ outDir: out, runId: 'r', cspName: 'CSP', aiAugmentationEnabled: true, ipdCataloguePath: IPD_FIXTURE, finalCataloguePath: IPD_FIXTURE })).toThrow(MissingSatisfactionMatrixError);
  });
});

describe('T.T5 — derivation function (pure)', () => {
  it('T5-7: satisfied when parent satisfied + AI evidence present', () => {
    const d = deriveAugmentationStatus({ augmentation: aug(), parentStatus: 'satisfied', mode: 'generative-ai', aiEvidencePresent: true });
    expect(d.status).toBe('satisfied');
    expect(d.derivation).toBe('ai-specific-evidence');
  });

  it('T5-8: partially-satisfied (inherits-parent) when parent satisfied but no AI evidence', () => {
    const d = deriveAugmentationStatus({ augmentation: aug(), parentStatus: 'satisfied', mode: 'generative-ai', aiEvidencePresent: false });
    expect(d.status).toBe('partially-satisfied');
    expect(d.derivation).toBe('inherits-parent');
  });

  it('T5-9: not-satisfied when parent not-satisfied + no AI evidence', () => {
    const d = deriveAugmentationStatus({ augmentation: aug(), parentStatus: 'not-satisfied', mode: 'generative-ai', aiEvidencePresent: false });
    expect(d.status).toBe('not-satisfied');
    expect(d.derivation).toBe('inherits-parent');
  });

  it('T5-10: not-assessed propagates from parent', () => {
    const d = deriveAugmentationStatus({ augmentation: aug(), parentStatus: 'not-assessed', mode: 'generative-ai', aiEvidencePresent: false });
    expect(d.status).toBe('not-assessed');
  });

  it('T5-11: applies_to filter yields not-applicable for a dual-use-only augmentation + generative-ai model', () => {
    const d = deriveAugmentationStatus({ augmentation: aug({ applies_to: ['dual-use-foundation-model'] }), parentStatus: 'satisfied', mode: 'generative-ai', aiEvidencePresent: true });
    expect(d.status).toBe('not-applicable');
    expect(d.explanation).toContain('applies_to');
  });

  it('T5-25: new 800-218A AI task (no base parent) with no AI evidence is requires-operator-input', () => {
    const d = deriveAugmentationStatus({ augmentation: aug({ augmentation_id: 'PW.3.1.R1', parent_task_id: 'PW.3.1' }), parentStatus: null, mode: 'generative-ai', aiEvidencePresent: false });
    expect(d.status).toBe('requires-operator-input');
    expect(d.derivation).toBe('requires-operator-input');
  });
});

describe('T.T5 — build (per-product join)', () => {
  function build(cards: ModelCard[], matrixTasks: Array<{ id: string; status: TaskStatus; withPointer?: boolean }>, over: Partial<Parameters<typeof buildAiAugmentation>[0]> = {}) {
    const cat = loadAugmentationCatalogue(IPD_FIXTURE);
    return buildAiAugmentation({
      outDir: tmp(),
      cspName: 'CSP',
      catalogue: cat,
      secondaryCatalogueVersion: 'final',
      matrix: mkMatrix(cards[0]?.product_id ?? 'p', matrixTasks),
      matrixSha256: 'msha',
      modelCards: cards.map((c) => ({ card: c, path: `model-cards/${c.product_id}.json`, sha256: `sha-${c.product_id}` })),
      aiKsiByAugmentation: new Map(),
      generatedAt: GEN_AT,
      ...over,
    });
  }

  it('T5-6: only in-scope products appear in products_in_scope; out-of-scope populated', () => {
    const r = build(
      [mkCard({ product_id: 'ai-one' }), mkCard({ product_id: 'plain', ai_use_case: '' })],
      [{ id: 'PO.1.1', status: 'satisfied', withPointer: true }],
    );
    expect(r.products_in_scope.map((p) => p.product_id)).toEqual(['ai-one']);
    expect(r.products_out_of_scope).toEqual([{ product_id: 'plain', reason: 'empty-ai-use-case' }]);
  });

  it('T5-12: attaches the model_card_pointer to every augmentation', () => {
    const r = build([mkCard({ product_id: 'ai-one' })], [{ id: 'PO.1.1', status: 'satisfied', withPointer: true }]);
    const entry = r.products_in_scope[0].practices.flatMap((p) => p.tasks).flatMap((t) => t.augmentations)[0];
    expect(entry.evidence_pointers.model_card_pointer).toBe('ai-one.json');
  });

  it('T5-13: attaches pre + post deployment evaluation pointers', () => {
    const r = build([mkCard({ product_id: 'ai-one', pre_deployment_evaluations: [{ id: 'e1', report_path: 'r1' }, { id: 'e2', report_path: 'r2' }], post_deployment_evaluations: [{ id: 'e3', report_path: 'r3' }] })], [{ id: 'PO.1.1', status: 'satisfied', withPointer: true }]);
    const entry = r.products_in_scope[0].practices.flatMap((p) => p.tasks).flatMap((t) => t.augmentations)[0];
    expect(entry.evidence_pointers.ai_evaluation_report_pointers).toEqual(['r1', 'r2', 'r3']);
    expect(entry.status).toBe('satisfied'); // parent satisfied + AI evidence
  });

  it('T5-14: attaches red_team engagement pointers', () => {
    const r = build([mkCard({ product_id: 'ai-one', red_team_engagements: [{ id: 'rt1', engagement_path: 'p1' }, { id: 'rt2', engagement_path: 'p2' }] })], [{ id: 'PO.1.1', status: 'satisfied', withPointer: true }]);
    const entry = r.products_in_scope[0].practices.flatMap((p) => p.tasks).flatMap((t) => t.augmentations)[0];
    expect(entry.evidence_pointers.red_team_engagement_pointers).toEqual(['p1', 'p2']);
  });

  it('T5-15: an AI KSI envelope referencing an augmentation id contributes its hash', () => {
    const cat = loadAugmentationCatalogue(IPD_FIXTURE);
    const r = buildAiAugmentation({
      outDir: tmp(), cspName: 'CSP', catalogue: cat, secondaryCatalogueVersion: 'final',
      matrix: mkMatrix('ai-one', [{ id: 'PO.1.1', status: 'satisfied', withPointer: true }]), matrixSha256: 'm',
      modelCards: [{ card: mkCard({ product_id: 'ai-one' }), path: 'model-cards/ai-one.json', sha256: 's' }],
      aiKsiByAugmentation: new Map([['PO.1.1.R1', ['envhash-1']]]), generatedAt: GEN_AT,
    });
    const entry = r.products_in_scope[0].practices.flatMap((p) => p.tasks).flatMap((t) => t.augmentations).find((a) => a.augmentation_id === 'PO.1.1.R1')!;
    expect(entry.evidence_pointers.ksi_envelope_hashes).toContain('envhash-1');
    expect(entry.derivation).toBe('ai-specific-evidence');
  });

  it('T5-17: rollup counts sum exactly to total_augmentations_evaluated', () => {
    const r = build([mkCard({ product_id: 'ai-one', is_dual_use_foundation_model: true })], [{ id: 'PO.1.1', status: 'satisfied', withPointer: true }, { id: 'PO.1.2', status: 'not-satisfied' }]);
    const { rollup } = r;
    const sum = rollup.satisfied + rollup.partially_satisfied + rollup.not_satisfied + rollup.not_assessed + rollup.requires_operator_input + rollup.not_applicable;
    expect(sum).toBe(rollup.total_augmentations_evaluated);
    expect(rollup.total_in_scope).toBe(1);
  });

  it('T5-16b: provenance block names emitter + carries non-empty sourceCalls', () => {
    const r = build([mkCard({ product_id: 'ai-one' })], [{ id: 'PO.1.1', status: 'satisfied', withPointer: true }], {
      sourceDigests: [{ kind: 'augmentation-catalogue', path: 'data/ssdf-800-218A-ipd.json', sha256: 'x' }],
    });
    expect(r.provenance.emitter).toBe('ssdf-ai-extension');
    expect(r.provenance.sourceCalls.length).toBeGreaterThan(0);
    expect(r.eo_lineage.length).toBeGreaterThan(0);
  });
});

describe('T.T5 — augmented matrix + end-to-end emit', () => {
  it('T5-18: augmented matrix interleaves augmentations under base tasks and appends new AI tasks', () => {
    const cat = loadAugmentationCatalogue(IPD_FIXTURE);
    const matrix = mkMatrix('ai-one', [{ id: 'PO.1.1', status: 'satisfied', withPointer: true }]);
    const built = buildAiAugmentation({
      outDir: tmp(), cspName: 'CSP', catalogue: cat, secondaryCatalogueVersion: 'final', matrix, matrixSha256: 'm',
      modelCards: [{ card: mkCard({ product_id: 'ai-one' }), path: 'model-cards/ai-one.json', sha256: 's' }],
      aiKsiByAugmentation: new Map(), generatedAt: GEN_AT,
    });
    const augMatrix = buildAugmentedMatrix(matrix, built.products_in_scope[0], cat);
    const po11 = augMatrix.practices.flatMap((p) => p.tasks).find((t: any) => t.id === 'PO.1.1') as any;
    expect(po11.statement).toBe('statement for PO.1.1'); // base field preserved (round-trip)
    expect(po11.ai_augmentations.length).toBe(1);
    // New AI task PW.3.1 appended as a guardrail-safe requires-operator-input row.
    const pw31 = augMatrix.practices.flatMap((p) => p.tasks).find((t: any) => t.id === 'PW.3.1') as any;
    expect(pw31).toBeTruthy();
    expect(pw31.status).toBe('requires-operator-input');
    expect(pw31.evidence_pointers.length).toBe(0);
  });

  it('T5-19: the committed IPD-vs-final delta sidecar is present and structured', () => {
    expect(existsSync(REAL_DELTA)).toBe(true);
    const delta = JSON.parse(readFileSync(REAL_DELTA, 'utf8'));
    for (const k of ['added', 'removed', 'restated', 'renamed']) expect(Array.isArray(delta[k])).toBe(true);
    expect(delta.ipd_augmentation_count).toBeGreaterThan(0);
    expect(delta.final_augmentation_count).toBeGreaterThan(0);
  });

  it('T5-22: end-to-end emit writes a signed JSON whose detached signature verifies', () => {
    const out = join(tmp(), 'out');
    writeMatrix(out, mkMatrix('ai-one', [{ id: 'PO.1.1', status: 'satisfied', withPointer: true }]));
    writeCard(out, mkCard({ product_id: 'ai-one', pre_deployment_evaluations: [{ id: 'e', report_path: 'r' }] }));
    const r = emitSsdfAiAugmentation({ outDir: out, runId: 'run-1', cspName: 'CSP', aiAugmentationEnabled: true, ipdCataloguePath: IPD_FIXTURE, finalCataloguePath: IPD_FIXTURE, generatedAt: GEN_AT });
    expect(r.skipped).toBe(false);
    const jsonPath = join(out, AI_AUGMENTATION_FILENAME);
    expect(existsSync(jsonPath)).toBe(true);
    expect(existsSync(`${jsonPath}.sig`)).toBe(true);
    const doc = JSON.parse(readFileSync(jsonPath, 'utf8'));
    const blanked = { ...doc, provenance: { ...doc.provenance, signingKeyId: '', publicKeyPem: '', signatureEd25519: '' } };
    const ok = verifyDetached(Buffer.from(canonicalize(JSON.parse(JSON.stringify(blanked))), 'utf8'), { publicKeyPem: doc.provenance.publicKeyPem, signatureBase64: doc.provenance.signatureEd25519 });
    expect(ok).toBe(true);
  });

  it('T5-16: emitted artefacts pass the G3 provenance guardrail', () => {
    const out = join(tmp(), 'out');
    writeMatrix(out, mkMatrix('ai-one', [{ id: 'PO.1.1', status: 'satisfied', withPointer: true }]));
    writeCard(out, mkCard({ product_id: 'ai-one', pre_deployment_evaluations: [{ id: 'e', report_path: 'r' }] }));
    emitSsdfAiAugmentation({ outDir: out, runId: 'run-1', cspName: 'CSP', aiAugmentationEnabled: true, ipdCataloguePath: IPD_FIXTURE, finalCataloguePath: IPD_FIXTURE, generatedAt: GEN_AT });
    const res = execFileSync('node', [CHECK_PROVENANCE, '--dir', out], { encoding: 'utf8' });
    expect(res).toMatch(/provenance|OK|pass/i);
  });

  it('T5-24: the augmented matrix passes the no-silent-pass guardrail', () => {
    const out = join(tmp(), 'out');
    // A matrix with a zero-pointer requires-operator-input base task + a satisfied one.
    writeMatrix(out, mkMatrix('ai-one', [
      { id: 'PO.1.1', status: 'satisfied', withPointer: true },
      { id: 'PO.1.2', status: 'requires-operator-input' },
    ]));
    writeCard(out, mkCard({ product_id: 'ai-one' }));
    emitSsdfAiAugmentation({ outDir: out, runId: 'run-1', cspName: 'CSP', aiAugmentationEnabled: true, ipdCataloguePath: IPD_FIXTURE, finalCataloguePath: IPD_FIXTURE, generatedAt: GEN_AT });
    expect(existsSync(join(out, AUGMENTED_MATRIX_FILENAME))).toBe(true);
    // exits 0 ⇒ no silent pass (a throw would fail the test).
    const res = execFileSync('node', [CHECK_NO_SILENT_PASS, '--dir', out], { encoding: 'utf8' });
    expect(res).toBeDefined();
  });

  it('T5-26: real committed final catalogue drives a full in-scope build with no throw', () => {
    const cat = loadAugmentationCatalogue(REAL_FINAL_CATALOGUE);
    const taskIds = cat.practices.flatMap((p) => p.tasks).filter((t) => t.base_task_present).slice(0, 5).map((t) => t.task_id);
    const r = buildAiAugmentation({
      outDir: tmp(), cspName: 'CSP', catalogue: cat, secondaryCatalogueVersion: 'IPD',
      matrix: mkMatrix('ai-one', taskIds.map((id) => ({ id, status: 'satisfied' as TaskStatus, withPointer: true }))), matrixSha256: 'm',
      modelCards: [{ card: mkCard({ product_id: 'ai-one', is_dual_use_foundation_model: true }), path: 'model-cards/ai-one.json', sha256: 's' }],
      aiKsiByAugmentation: new Map(), generatedAt: GEN_AT,
    });
    expect(r.products_in_scope.length).toBe(1);
    expect(r.rollup.total_augmentations_evaluated).toBeGreaterThan(0);
  });
});

describe('T.T5 — model-card helpers', () => {
  it('T5-27: isModelCardInScope true for non-empty ai_use_case OR dual-use foundation model', () => {
    expect(isModelCardInScope(mkCard({ ai_use_case: 'x' }))).toBe(true);
    expect(isModelCardInScope(mkCard({ ai_use_case: '', is_dual_use_foundation_model: true }))).toBe(true);
    expect(isModelCardInScope(mkCard({ ai_use_case: '  ', is_dual_use_foundation_model: false }))).toBe(false);
  });

  it('T5-28: loadModelCards returns [] when the model-cards dir is absent (graceful degradation)', () => {
    expect(loadModelCards(tmp())).toEqual([]);
  });
});
