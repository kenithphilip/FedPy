/**
 * LOOP-T.T2 — SSDF per-practice evidence aggregator + satisfaction matrix.
 *
 * Covers per-slice doc §8 (T2-1..T2-24, reconciled to the committed T.T1
 * catalogue shape: 19 practices / 42 tasks; KSI + 800-53 crosswalks are
 * per-practice). Fixtures are built inline (the repo convention) using the REAL
 * committed catalogue (data/ssdf-800-218-v1.1.json) + inline KSI evidence
 * envelopes written to a tmp dir, so every join exercises the real code path.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { EvidenceFile, Finding } from '../../core/envelope.ts';
import { verifyDetached } from '../../core/sign.ts';
import { loadSsdfCatalog } from '../../core/ssdf-practices-catalog.ts';
import {
  buildSsdfSatisfactionMatrix,
  emitSsdfSatisfactionMatrix,
  computeTaskStatus,
  rollUpPracticeStatus,
  SsdfCatalogTamperError,
  EnvelopeSignatureError,
} from '../../core/ssdf-evidence-aggregator.ts';
import {
  serializeUnsignedCanonical,
  emptyStatusTally,
  SATISFACTION_MATRIX_FILENAME,
} from '../../core/ssdf-satisfaction-matrix.ts';

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-t2-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

const GEN_AT = '2026-06-20T12:00:00.000Z';
const CHECK_PROVENANCE = fileURLToPath(new URL('../../scripts/check-provenance.mjs', import.meta.url));
const CHECK_NO_SILENT_PASS = fileURLToPath(new URL('../../scripts/check-ssdf-no-silent-pass.mjs', import.meta.url));

function mkFinding(over: Partial<Finding> = {}): Finding {
  return {
    rule: 'aws.example.rule',
    passed: true,
    severity: 'low',
    current_state: { summary: 's', observations: {} },
    target_state: { summary: 't', rationale: 'r' },
    ...over,
  };
}

function writeEnvelope(outDir: string, ksiId: string, findings: Finding[]): string {
  const env: EvidenceFile = {
    ksi_id: ksiId,
    ksi_name: `${ksiId} name`,
    ksi_statement: 'verbatim FRMR statement',
    scope: 'CLOUD',
    frmr_version: '25.06A',
    run_id: 'run-test',
    collected_at: GEN_AT,
    providers: [
      {
        provider: 'aws',
        evidence: [{ source: 'iam.GetAccountSummary', captured_at: GEN_AT, data: {} }],
        findings,
      },
    ],
    rollup: {
      pass: findings.every((f) => f.passed),
      passing_findings: findings.filter((f) => f.passed).length,
      failing_findings: findings.filter((f) => !f.passed).length,
      warnings: [],
      missing_evidence: [],
      alternatives_in_play: 0,
    },
  };
  const p = resolve(outDir, `${ksiId}.json`);
  writeFileSync(p, JSON.stringify(env, null, 2));
  return p;
}

function baseOpts(outDir: string, extra: Record<string, unknown> = {}) {
  return {
    outDir,
    cspName: 'Acme CSP',
    product: { id: 'acme-platform', name: 'Acme Platform' },
    generatedAt: GEN_AT,
    ...extra,
  };
}

function taskById(matrix: ReturnType<typeof buildSsdfSatisfactionMatrix>, id: string) {
  for (const p of matrix.practices) {
    for (const t of p.tasks) if (t.id === id) return t;
  }
  throw new Error(`task ${id} not found`);
}
function practiceById(matrix: ReturnType<typeof buildSsdfSatisfactionMatrix>, id: string) {
  const p = matrix.practices.find((x) => x.id === id);
  if (!p) throw new Error(`practice ${id} not found`);
  return p;
}

describe('T.T2 — buildSsdfSatisfactionMatrix', () => {
  it('T2-1: loads the T.T1 catalogue and asserts published counts (19 practices / 42 tasks / 4 groups)', () => {
    const d = tmp();
    const m = buildSsdfSatisfactionMatrix(baseOpts(d));
    expect(m.totals.practices).toBe(19);
    expect(m.totals.tasks).toBe(42);
    expect(new Set(m.practices.map((p) => p.group))).toEqual(new Set(['PO', 'PS', 'PW', 'RV']));
    expect(m.catalogue_source.source_pdf_sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it('T2-2: rejects a catalogue whose source_pdf_sha256 does not match the pinned hash', () => {
    const d = tmp();
    const real = loadSsdfCatalog();
    const tampered = { ...real, source_pdf_sha256: 'deadbeef'.repeat(8) };
    expect(() => buildSsdfSatisfactionMatrix(baseOpts(d, { catalog: tampered, pinnedPdfSha256: real.source_pdf_sha256 })))
      .toThrow(SsdfCatalogTamperError);
  });

  it('T2-3: a task joined to one passing KSI envelope ⇒ status satisfied with exactly one ksi-envelope pointer', () => {
    const d = tmp();
    writeEnvelope(d, 'KSI-IAM-MFA', [mkFinding({ passed: true, severity: 'low' })]);
    const m = buildSsdfSatisfactionMatrix(baseOpts(d));
    const t = taskById(m, 'PO.5.1'); // PO.5 forward-maps KSI-IAM-MFA + KSI-MLA-ALA
    expect(t.status).toBe('satisfied');
    const ksiPtrs = t.evidence_pointers.filter((p) => p.kind === 'ksi-envelope');
    expect(ksiPtrs.length).toBe(1);
    expect((ksiPtrs[0] as any).ksi_id).toBe('KSI-IAM-MFA');
  });

  it('T2-4: a task whose KSI envelope carries a failing high-severity finding ⇒ status not-satisfied', () => {
    const d = tmp();
    writeEnvelope(d, 'KSI-CMT-VTD', [mkFinding({ passed: false, severity: 'high' })]);
    const m = buildSsdfSatisfactionMatrix(baseOpts(d));
    expect(taskById(m, 'PW.7.1').status).toBe('not-satisfied'); // PW.7 -> KSI-CMT-VTD
    expect(taskById(m, 'PW.8.1').status).toBe('not-satisfied'); // PW.8 -> KSI-CMT-VTD
  });

  it('T2-5: a task with an open OSCAL POA&M item referencing its control ⇒ partially-satisfied with a poam-item pointer', () => {
    const d = tmp();
    writeEnvelope(d, 'KSI-SCR-MON', [mkFinding({ passed: true })]); // RV.1 -> KSI-SCR-MON,KSI-INR-RIR
    // RV.1 controls include sa-10; an open POA&M item references SA-10.
    writeFileSync(resolve(d, 'poam.json'), JSON.stringify({
      'plan-of-action-and-milestones': {
        uuid: 'p-1',
        'poam-items': [{ uuid: 'pi-1', title: 'Remediate SA-10 gap', description: 'control SA-10 finding open' }],
        observations: [{ uuid: 'ob-1', title: 'SA-10 observation', description: 'sa-10' }],
      },
    }));
    const m = buildSsdfSatisfactionMatrix(baseOpts(d));
    const t = taskById(m, 'RV.1.1');
    expect(t.status).toBe('partially-satisfied');
    expect(t.evidence_pointers.some((p) => p.kind === 'oscal-poam-item')).toBe(true);
    expect(t.evidence_pointers.some((p) => p.kind === 'oscal-observation')).toBe(true);
  });

  it('T2-6: a task with no joined evidence ⇒ requires-operator-input (no silent pass)', () => {
    const d = tmp();
    const m = buildSsdfSatisfactionMatrix(baseOpts(d)); // no envelopes, no registers
    const t = taskById(m, 'PO.2.1'); // PO.2 has no KSI forward map + not in any ancillary set
    expect(t.status).toBe('requires-operator-input');
    expect(t.evidence_pointers.length).toBe(0);
    expect(t.diagnostics.join(' ')).toMatch(/requires-operator-input/);
  });

  it('T2-7: per-practice roll-up — any not-satisfied task ⇒ practice not-satisfied', () => {
    const d = tmp();
    writeEnvelope(d, 'KSI-CMT-VTD', [mkFinding({ passed: false, severity: 'critical' })]);
    const m = buildSsdfSatisfactionMatrix(baseOpts(d));
    expect(practiceById(m, 'PW.7').status).toBe('not-satisfied');
  });

  it('T2-8: roll-up logic — mixed tallies resolve to the documented worst-with-partial-overlay status', () => {
    // The catalogue joins evidence per practice, so this pins the pure roll-up
    // function (spec §6 step 8) across every mixed combination.
    const mixed = emptyStatusTally(); mixed['satisfied'] = 2; mixed['partially-satisfied'] = 1;
    expect(rollUpPracticeStatus(mixed)).toBe('partially-satisfied');
    const withNotSat = emptyStatusTally(); withNotSat['satisfied'] = 1; withNotSat['not-satisfied'] = 1; withNotSat['partially-satisfied'] = 1;
    expect(rollUpPracticeStatus(withNotSat)).toBe('not-satisfied');
    const withRoi = emptyStatusTally(); withRoi['satisfied'] = 1; withRoi['requires-operator-input'] = 1;
    expect(rollUpPracticeStatus(withRoi)).toBe('requires-operator-input');
    const allSat = emptyStatusTally(); allSat['satisfied'] = 3;
    expect(rollUpPracticeStatus(allSat)).toBe('satisfied');
  });

  it('T2-9: per-practice roll-up — all tasks satisfied ⇒ practice satisfied', () => {
    const d = tmp();
    writeEnvelope(d, 'KSI-SVC-VRI', [mkFinding({ passed: true })]); // PS.2 (single task PS.2.1) -> KSI-SVC-VRI
    const m = buildSsdfSatisfactionMatrix(baseOpts(d));
    const p = practiceById(m, 'PS.2');
    expect(p.status).toBe('satisfied');
    expect(p.tasks_by_status['satisfied']).toBe(1);
    expect(p.tasks_by_status['not-satisfied']).toBe(0);
  });

  it('T2-10: refuses to ingest an envelope whose on-disk hash does not match the run manifest ⇒ EnvelopeSignatureError', () => {
    const d = tmp();
    writeEnvelope(d, 'KSI-IAM-MFA', [mkFinding({ passed: true })]);
    // Manifest claims a different sha256 for the envelope ⇒ tamper.
    writeFileSync(resolve(d, 'manifest.json'), JSON.stringify({
      schema_version: 1, run_id: 'r', frmr_version: '25.06A', signed_at: GEN_AT,
      signer_public_key: '', files: [{ name: 'KSI-IAM-MFA.json', sha256: '00'.repeat(32), bytes: 1 }],
    }));
    expect(() => buildSsdfSatisfactionMatrix(baseOpts(d))).toThrow(EnvelopeSignatureError);
  });

  it('T2-11: attaches an SBOM pointer for release-integrity practices (PS.2) when sbom-report.json is present', () => {
    const d = tmp();
    writeEnvelope(d, 'KSI-SVC-VRI', [mkFinding({ passed: true })]);
    writeFileSync(resolve(d, 'sbom-report.json'), JSON.stringify({ format: 'cyclonedx', files: [] }));
    const m = buildSsdfSatisfactionMatrix(baseOpts(d));
    const t = taskById(m, 'PS.2.1');
    const sbom = t.evidence_pointers.find((p) => p.kind === 'sbom');
    expect(sbom).toBeTruthy();
    expect((sbom as any).sbom_format).toBe('cyclonedx');
    expect((sbom as any).sbom_sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it('T2-12: attaches subprocessor + supply-chain-register pointers for PW.4', () => {
    const d = tmp();
    writeEnvelope(d, 'KSI-SCR-MON', [mkFinding({ passed: true })]); // PW.4 -> KSI-SCR-MON, KSI-SCR-MIT
    writeFileSync(resolve(d, 'subprocessor-inventory.json'), JSON.stringify({ subprocessors: [{ id: 'sub-1', name: 'GitHub' }] }));
    writeFileSync(resolve(d, 'supply-chain-risk-register.json'), JSON.stringify({ entries: [{ id: 'scr-1', related_nist_controls: ['SR-3'] }] }));
    const m = buildSsdfSatisfactionMatrix(baseOpts(d));
    const t = taskById(m, 'PW.4.1');
    expect(t.evidence_pointers.some((p) => p.kind === 'subprocessor-inventory')).toBe(true);
    expect(t.evidence_pointers.some((p) => p.kind === 'supply-chain-risk-register-row')).toBe(true);
  });

  it('T2-13: emits a coverage:partial diagnostic when the LOOP-B risk register is absent; risk scores stay null', () => {
    const d = tmp();
    writeEnvelope(d, 'KSI-IAM-MFA', [mkFinding({ passed: true })]);
    const m = buildSsdfSatisfactionMatrix(baseOpts(d)); // no risk-scores.json
    expect(m.provenance.coverageDiagnostics.some((x) => /risk-scores\.json absent/.test(x))).toBe(true);
    expect(taskById(m, 'PO.5.1').open_risk_score).toBeNull();
  });

  it('T2-14: deterministic matrix_id (uuid v5 over canonical inputs) — identical inputs ⇒ identical id, independent of wall-clock', () => {
    const d = tmp();
    writeEnvelope(d, 'KSI-IAM-MFA', [mkFinding({ passed: true })]);
    const a = buildSsdfSatisfactionMatrix(baseOpts(d, { generatedAt: '2026-06-20T00:00:00.000Z' }));
    const b = buildSsdfSatisfactionMatrix(baseOpts(d, { generatedAt: '2027-01-01T00:00:00.000Z' }));
    expect(a.matrix_id).toBe(b.matrix_id);
    expect(a.matrix_id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });

  it('T2-15: the provenance block lists every source file read with a sha256 + non-empty sourceCalls', () => {
    const d = tmp();
    writeEnvelope(d, 'KSI-IAM-MFA', [mkFinding({ passed: true })]);
    const m = buildSsdfSatisfactionMatrix(baseOpts(d));
    expect(m.provenance.sourceCalls.length).toBeGreaterThan(0);
    expect(m.provenance.sourceDigests.length).toBeGreaterThan(0);
    for (const s of m.provenance.sourceDigests) expect(s.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(m.provenance.sourceCalls.some((c) => c.startsWith('ksi-envelope:KSI-IAM-MFA'))).toBe(true);
  });

  it('T2-17: per-task open_risk_score is read from risk-scores.json (max composite over the practice KSIs)', () => {
    const d = tmp();
    writeEnvelope(d, 'KSI-IAM-MFA', [mkFinding({ passed: true })]);
    writeFileSync(resolve(d, 'risk-scores.json'), JSON.stringify({
      findings: [
        { ksi_id: 'KSI-IAM-MFA', rule: 'r1', composite_score: 4.2 },
        { ksi_id: 'KSI-IAM-MFA', rule: 'r2', composite_score: 7.5 },
      ],
    }));
    const m = buildSsdfSatisfactionMatrix(baseOpts(d));
    expect(taskById(m, 'PO.5.1').open_risk_score).toBe(7.5);
    expect(practiceById(m, 'PO.5').open_risk_score).toBe(7.5);
  });

  it('T2-18: per-product scoping — ksi_to_product_map excludes a KSI for one product', () => {
    const d = tmp();
    writeEnvelope(d, 'KSI-IAM-MFA', [mkFinding({ passed: true })]); // PO.5 maps KSI-IAM-MFA + KSI-MLA-ALA
    const a = buildSsdfSatisfactionMatrix(baseOpts(d, {
      product: { id: 'prod-a', name: 'A' },
      ksiToProductMap: { 'KSI-IAM-MFA': ['prod-a'] },
    }));
    const b = buildSsdfSatisfactionMatrix(baseOpts(d, {
      product: { id: 'prod-b', name: 'B' },
      ksiToProductMap: { 'KSI-IAM-MFA': ['prod-a'] },
    }));
    const aHas = taskById(a, 'PO.5.1').evidence_pointers.some((p) => p.kind === 'ksi-envelope' && (p as any).ksi_id === 'KSI-IAM-MFA');
    const bHas = taskById(b, 'PO.5.1').evidence_pointers.some((p) => p.kind === 'ksi-envelope' && (p as any).ksi_id === 'KSI-IAM-MFA');
    expect(aHas).toBe(true);
    expect(bHas).toBe(false);
  });

  it('computeTaskStatus pins every branch of the per-task status function', () => {
    expect(computeTaskStatus({ pointers: [], failingHighCrit: false, hasOpenPoam: false, hasKsiEnvelope: false, openRiskScore: null })).toBe('requires-operator-input');
    const ksi = [{ kind: 'ksi-envelope' } as any];
    expect(computeTaskStatus({ pointers: ksi, failingHighCrit: true, hasOpenPoam: false, hasKsiEnvelope: true, openRiskScore: null })).toBe('not-satisfied');
    expect(computeTaskStatus({ pointers: ksi, failingHighCrit: false, hasOpenPoam: true, hasKsiEnvelope: true, openRiskScore: null })).toBe('partially-satisfied');
    expect(computeTaskStatus({ pointers: ksi, failingHighCrit: false, hasOpenPoam: false, hasKsiEnvelope: true, openRiskScore: null })).toBe('satisfied');
    const anc = [{ kind: 'sbom' } as any];
    expect(computeTaskStatus({ pointers: anc, failingHighCrit: false, hasOpenPoam: false, hasKsiEnvelope: false, openRiskScore: null })).toBe('not-assessed');
  });
});

describe('T.T2 — emitSsdfSatisfactionMatrix (sign + write + guardrails)', () => {
  it('T2-22: end-to-end emit writes a signed matrix JSON + .sig + .xlsx whose signature verifies', () => {
    const d = tmp();
    writeEnvelope(d, 'KSI-IAM-MFA', [mkFinding({ passed: true })]);
    const [res] = emitSsdfSatisfactionMatrix({ outDir: d, runId: 'run-1', cspName: 'Acme CSP', generatedAt: GEN_AT });
    expect(res.json_path.endsWith(SATISFACTION_MATRIX_FILENAME)).toBe(true);
    expect(existsSync(res.json_path)).toBe(true);
    expect(existsSync(res.sig_path)).toBe(true);
    expect(res.xlsx_path && existsSync(res.xlsx_path)).toBe(true);

    const matrix = JSON.parse(readFileSync(res.json_path, 'utf8'));
    expect(matrix.provenance.signingKeyId).toBeTruthy();
    const ok = verifyDetached(Buffer.from(serializeUnsignedCanonical(matrix), 'utf8'), {
      publicKeyPem: matrix.provenance.publicKeyPem,
      signatureBase64: matrix.provenance.signatureEd25519,
    });
    expect(ok).toBe(true);
  });

  it('emit honours config products and writes a per-product file for the second product', () => {
    const d = tmp();
    writeEnvelope(d, 'KSI-IAM-MFA', [mkFinding({ passed: true })]);
    const results = emitSsdfSatisfactionMatrix({
      outDir: d, runId: 'run-1', cspName: 'Acme CSP', generatedAt: GEN_AT,
      products: [{ id: 'prod-a', name: 'A' }, { id: 'prod-b', name: 'B' }],
    });
    expect(results.length).toBe(2);
    expect(results[0]!.json_path.endsWith('ssdf-satisfaction-matrix.json')).toBe(true);
    expect(results[1]!.json_path.endsWith('ssdf-satisfaction-matrix.prod-b.json')).toBe(true);
    expect(existsSync(results[1]!.json_path)).toBe(true);
  });

  it('the emitted matrix passes check:provenance (G3) and check:ssdf-no-silent-pass', () => {
    const d = tmp();
    writeEnvelope(d, 'KSI-IAM-MFA', [mkFinding({ passed: true })]);
    emitSsdfSatisfactionMatrix({ outDir: d, runId: 'run-1', cspName: 'Acme CSP', generatedAt: GEN_AT });
    // check:provenance over the dir (KSI envelope is structural; matrix has provenance).
    const prov = execFileSync(process.execPath, [CHECK_PROVENANCE, '--dir', d, '--json'], { encoding: 'utf8' });
    expect(JSON.parse(prov).issues).toEqual([]);
    // check:ssdf-no-silent-pass should be clean (every satisfied cell has pointers).
    const out = execFileSync(process.execPath, [CHECK_NO_SILENT_PASS, '--dir', d], { encoding: 'utf8' });
    expect(out).toMatch(/OK/);
  });

  it('T2-21: check:ssdf-no-silent-pass rejects a matrix whose satisfied task has zero pointers', () => {
    const d = tmp();
    const bad = {
      schema_version: '1.0', matrix_id: 'x', practices: [
        { id: 'PO.1', status: 'satisfied', tasks: [{ id: 'PO.1.1', status: 'satisfied', evidence_pointers: [] }] },
      ],
    };
    writeFileSync(resolve(d, 'ssdf-satisfaction-matrix.json'), JSON.stringify(bad));
    let code = 0;
    try {
      execFileSync(process.execPath, [CHECK_NO_SILENT_PASS, '--dir', d], { encoding: 'utf8' });
    } catch (e: any) {
      code = e.status;
    }
    expect(code).toBe(1);
  });
});
