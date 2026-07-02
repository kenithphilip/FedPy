/**
 * LOOP-T.T4 — SSDF material-change detector + annual-cadence ledger tests.
 *
 * Covers per-slice doc §8 rows T06–T15 (detector change kinds + idempotency +
 * status DTO) and the signed end-to-end emit (T14 provenance). Realizable-core
 * posture: the spec's tracker DB / REST / React surface (T15/T18–T20) is
 * deferred (LOOP-T-RISKS T.T4-21..24); the equivalent behaviour is exercised
 * here against the pure engines + the on-disk signed ledger. Fixtures are built
 * inline (repo convention); the emit test runs the real code path
 * (load → diff → sign → write JSON/.sig + coverage + ledger + snapshot).
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { verifyDetached, canonicalize } from '../../core/sign.ts';
import { addDaysUtc } from '../../core/ssdf-annual-attestation.ts';
import { emptyStatusTally, type SsdfSatisfactionMatrix, type PracticeStatus } from '../../core/ssdf-satisfaction-matrix.ts';
import {
  detectMaterialChange,
  computeStatusRows,
  deriveEventId,
  emitSsdfMaterialChanges,
  MissingMatrixError,
  ATTESTATION_LEDGER_FILENAME,
  ATTESTATION_SNAPSHOT_DIR,
  MATERIAL_CHANGE_EVENTS_FILENAME,
  type SsdfProduct,
  type DetectOptions,
} from '../../core/ssdf-material-change-detector.ts';

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-t4-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* ignore */ }
  }
});

// ─── Fixture builders ─────────────────────────────────────────────────────────

function matrix(
  productId: string,
  practices: Array<{ id: string; status: PracticeStatus; group?: 'PO' | 'PS' | 'PW' | 'RV' }>,
  opts: { generatedAt?: string; regime?: string; critical?: boolean } = {},
): SsdfSatisfactionMatrix {
  const at = opts.generatedAt ?? '2026-06-20T00:00:00.000Z';
  return {
    schema_version: '1.0',
    matrix_id: `m-${productId}-${practices.map((p) => p.status[0]).join('')}`,
    generated_at: at,
    csp_name: 'Acme CSP, Inc.',
    product: { id: productId, name: `Product ${productId}`, ai_enabled: false, critical_software: opts.critical ?? false },
    regime: opts.regime ?? 'test-label',
    catalogue_source: { sp: '800-218', version: 'v1.1', publication_date: '2022-02', source_pdf_sha256: 'deadbeef' },
    totals: { practices: practices.length, tasks: 0, practices_by_status: emptyStatusTally(), tasks_by_status: emptyStatusTally() },
    practices: practices.map((p) => ({
      id: p.id,
      group: p.group ?? 'PO',
      name: `Practice ${p.id}`,
      outcome: '',
      status: p.status,
      open_risk_score: null,
      tasks_by_status: emptyStatusTally(),
      tasks: [],
    })),
    provenance: {
      emitter: 'core/ssdf-evidence-aggregator.ts',
      emitterVersion: '1.0.0',
      emittedAt: at,
      sourceCalls: ['fixture'],
      sourceDigests: [],
      signingKeyId: 'k',
      publicKeyPem: 'p',
      signatureEd25519: 's',
      timestampAuthority: null,
      coverageDiagnostics: [],
    },
  };
}

function prod(over: Partial<SsdfProduct> = {}): SsdfProduct {
  return {
    id: 'prod-a',
    legal_name: 'Product A',
    regime: 'm-22-18-mandatory',
    critical_software: false,
    continuous_delivery: false,
    major_version_pattern: '^(\\d+)\\.0\\.0$',
    cadence_override_days: null,
    poam_extension_allowed: true,
    federal_agencies: [{ id: 'dot', name: 'U.S. Department of Transportation' }],
    ...over,
  };
}

const NOW = '2026-07-01T00:00:00.000Z';
function opts(over: Partial<DetectOptions> = {}): DetectOptions {
  return { currentDate: NOW, currentMatrixSha256: 'cur-sha', priorMatrixSha256: 'prior-sha', ...over };
}

// ─── Detector (pure) ──────────────────────────────────────────────────────────

describe('LOOP-T.T4 material-change detector', () => {
  // T.T4-T06
  it('practice_regression when satisfied → not-satisfied (triggers re-attestation, +14d)', () => {
    const prior = matrix('prod-a', [{ id: 'PO.1', status: 'satisfied' }]);
    const cur = matrix('prod-a', [{ id: 'PO.1', status: 'not-satisfied' }]);
    const events = detectMaterialChange(prior, cur, prod(), opts());
    expect(events).toHaveLength(1);
    expect(events[0]!.change_kind).toBe('practice_regression');
    expect(events[0]!.practice_ids).toEqual(['PO.1']);
    expect(events[0]!.triggers_reattestation).toBe(true);
    expect(events[0]!.notification_due_at).toBe(addDaysUtc(NOW, 14));
  });

  // T.T4-T07
  it('no event when the regression has an active POA&M-extension override', () => {
    const prior = matrix('prod-a', [{ id: 'PO.1', status: 'satisfied' }]);
    const cur = matrix('prod-a', [{ id: 'PO.1', status: 'not-satisfied' }]);
    const events = detectMaterialChange(prior, cur, prod(), opts({ activeOverridePracticeIds: new Set(['PO.1']) }));
    expect(events).toHaveLength(0);
  });

  // T.T4-R2 — satisfied → requires-operator-input is a coverage gap, not a regression.
  it('no regression when satisfied → requires-operator-input (coverage gap, not material)', () => {
    const prior = matrix('prod-a', [{ id: 'PO.1', status: 'satisfied' }]);
    const cur = matrix('prod-a', [{ id: 'PO.1', status: 'requires-operator-input' }]);
    expect(detectMaterialChange(prior, cur, prod(), opts())).toHaveLength(0);
  });

  // T.T4-T08
  it('new_untestable_practice when current introduces a not-satisfied practice', () => {
    const prior = matrix('prod-a', [{ id: 'PO.1', status: 'satisfied' }]);
    const cur = matrix('prod-a', [
      { id: 'PO.1', status: 'satisfied' },
      { id: 'PW.7', status: 'not-satisfied', group: 'PW' },
    ]);
    const events = detectMaterialChange(prior, cur, prod(), opts());
    expect(events).toHaveLength(1);
    expect(events[0]!.change_kind).toBe('new_untestable_practice');
    expect(events[0]!.practice_ids).toEqual(['PW.7']);
    expect(events[0]!.triggers_reattestation).toBe(true);
  });

  // T.T4-T09
  it('ai_augmentation_gap when only the AI-augmented view changes (does not trigger re-attestation)', () => {
    const prior = matrix('prod-a', [{ id: 'PO.1', status: 'satisfied' }]);
    const cur = matrix('prod-a', [{ id: 'PO.1', status: 'satisfied' }]);
    const events = detectMaterialChange(prior, cur, prod(), opts({ aiAugmentationGapPracticeIds: ['PW.A.1'] }));
    expect(events).toHaveLength(1);
    expect(events[0]!.change_kind).toBe('ai_augmentation_gap');
    expect(events[0]!.triggers_reattestation).toBe(false);
    expect(events[0]!.notification_due_at).toBe(addDaysUtc(NOW, 14));
  });

  // T.T4-T10
  it('major_version_bump when the SBOM version newly matches the major-version pattern (+30d)', () => {
    const prior = matrix('prod-a', [{ id: 'PO.1', status: 'satisfied' }]);
    const cur = matrix('prod-a', [{ id: 'PO.1', status: 'satisfied' }]);
    const events = detectMaterialChange(prior, cur, prod(), opts({ priorSbomVersion: '1.5.3', currentSbomVersion: '2.0.0' }));
    expect(events).toHaveLength(1);
    expect(events[0]!.change_kind).toBe('major_version_bump');
    expect(events[0]!.triggers_reattestation).toBe(true);
    expect(events[0]!.notification_due_at).toBe(addDaysUtc(NOW, 30));
  });

  it('no major_version_bump when both prior and current match the pattern', () => {
    const prior = matrix('prod-a', [{ id: 'PO.1', status: 'satisfied' }]);
    const cur = matrix('prod-a', [{ id: 'PO.1', status: 'satisfied' }]);
    expect(detectMaterialChange(prior, cur, prod(), opts({ priorSbomVersion: '2.0.0', currentSbomVersion: '3.0.0' }))).toHaveLength(0);
  });

  // T.T4-T11
  it('regime_change when the product regime differs from the prior submission (+30d)', () => {
    const prior = matrix('prod-a', [{ id: 'PO.1', status: 'satisfied' }]);
    const cur = matrix('prod-a', [{ id: 'PO.1', status: 'satisfied' }]);
    const events = detectMaterialChange(prior, cur, prod({ regime: 'm-26-05-tailored' }), opts({ priorRegime: 'm-23-16-extended' }));
    expect(events).toHaveLength(1);
    expect(events[0]!.change_kind).toBe('regime_change');
    expect(events[0]!.triggers_reattestation).toBe(true);
    expect(events[0]!.notification_due_at).toBe(addDaysUtc(NOW, 30));
  });

  // T.T4-T12
  it('agency_added when a new federal agency appears (informational, no notification clock)', () => {
    const prior = matrix('prod-a', [{ id: 'PO.1', status: 'satisfied' }]);
    const cur = matrix('prod-a', [{ id: 'PO.1', status: 'satisfied' }]);
    const p = prod({ federal_agencies: [{ id: 'dot', name: 'DOT' }, { id: 'doe', name: 'DOE' }] });
    const events = detectMaterialChange(prior, cur, p, opts({ priorAgencyIds: ['dot'] }));
    expect(events).toHaveLength(1);
    expect(events[0]!.change_kind).toBe('agency_added');
    expect(events[0]!.triggers_reattestation).toBe(false);
    expect(events[0]!.notification_due_at).toBeNull();
  });

  // T.T4-T13
  it('idempotent — identical inputs produce the same event id', () => {
    const prior = matrix('prod-a', [{ id: 'PO.1', status: 'satisfied' }]);
    const cur = matrix('prod-a', [{ id: 'PO.1', status: 'not-satisfied' }]);
    const a = detectMaterialChange(prior, cur, prod(), opts());
    const b = detectMaterialChange(prior, cur, prod(), opts());
    expect(a[0]!.id).toBe(b[0]!.id);
    expect(a[0]!.id).toBe(deriveEventId('prod-a', 'prior-sha', 'cur-sha', 'practice_regression'));
  });

  it('baseline run (no prior) emits no diff-based events', () => {
    const cur = matrix('prod-a', [{ id: 'PO.1', status: 'not-satisfied' }]);
    expect(detectMaterialChange(null, cur, prod(), opts({ priorMatrixSha256: null }))).toHaveLength(0);
  });
});

// ─── Status DTO (per-slice doc §5.4) ──────────────────────────────────────────

describe('LOOP-T.T4 cadence status rows', () => {
  // T.T4-T15
  it('never_submitted state for an agency without a prior submission', () => {
    const rows = computeStatusRows(prod(), { last_submission_id: null, last_submitted_at: null }, [], NOW);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.due_state).toBe('never_submitted');
    expect(rows[0]!.next_due_at).toBeNull();
    expect(rows[0]!.agency_id).toBe('dot');
  });

  it('one row per federal agency with computed next_due_at when submitted', () => {
    const p = prod({ federal_agencies: [{ id: 'dot', name: 'DOT' }, { id: 'doe', name: 'DOE' }] });
    const rows = computeStatusRows(p, { last_submission_id: 's1', last_submitted_at: '2026-01-01T00:00:00.000Z' }, ['ev-1'], NOW);
    expect(rows).toHaveLength(2);
    expect(rows.every((r) => r.next_due_at === '2027-01-01T00:00:00.000Z')).toBe(true);
    expect(rows[0]!.open_material_change_event_ids).toEqual(['ev-1']);
    expect(rows[0]!.due_state).toBe('current');
  });

  it('no rows when the product declares no federal agencies', () => {
    expect(computeStatusRows(prod({ federal_agencies: [] }), { last_submission_id: null, last_submitted_at: null }, [], NOW)).toHaveLength(0);
  });
});

// ─── End-to-end signed emit (real code path) ──────────────────────────────────

describe('LOOP-T.T4 emitSsdfMaterialChanges (end-to-end)', () => {
  function writeMatrix(dir: string, m: SsdfSatisfactionMatrix): void {
    writeFileSync(resolve(dir, 'ssdf-satisfaction-matrix.json'), JSON.stringify(m, null, 2));
  }

  it('throws MissingMatrixError when no T.T2 matrix is present', () => {
    expect(() => emitSsdfMaterialChanges({ outDir: tmp(), runId: 'r', cspName: 'Acme', products: [] })).toThrow(MissingMatrixError);
  });

  // T.T4-T14 — provenance block present + signing key id recorded + signature verifies.
  it('emits a signed report with provenance, baseline on first run, regression on the second', () => {
    const dir = tmp();
    writeMatrix(dir, matrix('prod-a', [{ id: 'PO.1', status: 'satisfied' }], { generatedAt: '2026-06-20T00:00:00.000Z' }));

    // Run 1 — baseline (no prior snapshot to diff).
    const r1 = emitSsdfMaterialChanges({ outDir: dir, runId: 'run-1', cspName: 'Acme CSP, Inc.', products: [prod()], generatedAt: NOW });
    expect(r1.events).toBe(0);
    expect(r1.baseline_products).toBe(1);
    expect(r1.status_rows).toBe(1);

    const report1 = JSON.parse(readFileSync(resolve(dir, MATERIAL_CHANGE_EVENTS_FILENAME), 'utf8'));
    expect(report1.provenance.emitter).toContain('ssdf-material-change-detector');
    expect(report1.provenance.signingKeyId).toBeTruthy();
    expect(report1.provenance.sourceCalls.length).toBeGreaterThan(0);
    // Signature verifies over the signature-blanked canonical bytes.
    const blanked = { ...report1, provenance: { ...report1.provenance, signingKeyId: '', signatureEd25519: '', publicKeyPem: '' } };
    const canonical = canonicalize(JSON.parse(JSON.stringify(blanked)));
    expect(verifyDetached(Buffer.from(canonical, 'utf8'), { publicKeyPem: report1.provenance.publicKeyPem, signatureBase64: report1.provenance.signatureEd25519 })).toBe(true);
    // Cadence row reflects the 365-day internal review date.
    expect(report1.status_rows[0].next_due_at).toBe('2027-06-20T00:00:00.000Z');
    expect(report1.status_rows[0].due_state).toBe('current');

    // Run 2 — regress PO.1 → a practice_regression event vs the run-1 snapshot.
    writeMatrix(dir, matrix('prod-a', [{ id: 'PO.1', status: 'not-satisfied' }], { generatedAt: '2026-06-20T00:00:00.000Z' }));
    const r2 = emitSsdfMaterialChanges({ outDir: dir, runId: 'run-2', cspName: 'Acme CSP, Inc.', products: [prod()], generatedAt: NOW });
    expect(r2.events).toBe(1);
    expect(r2.events_triggering_reattestation).toBe(1);
    expect(r2.baseline_products).toBe(0);
    const report2 = JSON.parse(readFileSync(resolve(dir, MATERIAL_CHANGE_EVENTS_FILENAME), 'utf8'));
    expect(report2.events[0].change_kind).toBe('practice_regression');

    // Ledger has two runs; two content-addressed snapshots exist.
    const ledgerLines = readFileSync(resolve(dir, ATTESTATION_LEDGER_FILENAME), 'utf8').trim().split('\n');
    expect(ledgerLines).toHaveLength(2);
    const snapDir = resolve(dir, ATTESTATION_SNAPSHOT_DIR, 'prod-a');
    expect(readdirSync(snapDir).filter((f) => f.endsWith('.json'))).toHaveLength(2);

    // Coverage sibling was written (not a fillRate cell — G2-safe).
    const cov = JSON.parse(readFileSync(resolve(dir, 'inventory-coverage.json'), 'utf8'));
    expect(cov.ssdf_material_change_coverage.products_tracked).toBe(1);
    expect(cov.ssdf_material_change_coverage.events_detected).toBe(1);
  });

  it('records a requires-operator-input diagnostic when a product regime is absent', () => {
    const dir = tmp();
    writeMatrix(dir, matrix('prod-x', [{ id: 'PO.1', status: 'satisfied' }]));
    // No config product → synthesized product carries the matrix free-text regime (not a valid enum).
    const r = emitSsdfMaterialChanges({ outDir: dir, runId: 'run-1', cspName: 'Acme', products: [], generatedAt: NOW });
    expect(r.products_tracked).toBe(1);
    const report = JSON.parse(readFileSync(resolve(dir, MATERIAL_CHANGE_EVENTS_FILENAME), 'utf8'));
    expect(report.provenance.coverageDiagnostics.some((d: string) => d.includes('requires-operator-input') && d.includes('regime'))).toBe(true);
    expect(report.products[0].next_due_at).toBeNull();
  });
});
