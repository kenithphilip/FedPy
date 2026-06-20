/**
 * LOOP-T.T3 — CISA Secure Software Development Attestation Common Form
 * (OMB 1670-0052) aggregator + emit tests.
 *
 * Covers per-slice doc §8 (reconciled to the real T.T2 satisfaction-matrix input
 * + the catalogue's §IV(1..4) Common Form mapping; see core/ssdf-common-form.ts
 * docstring). Fixtures are built inline (repo convention): a real-shaped
 * SsdfSatisfactionMatrix is written to a tmp outDir and the emitter runs the
 * actual code path (validate → aggregate → sign → write JSON/PDF + coverage).
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { verifyDetached } from '../../core/sign.ts';
import { buildSubmissionIndex } from '../../core/submission-bundle.ts';
import type { CommonFormSection } from '../../core/ssdf-practices-catalog.ts';
import {
  emptyStatusTally,
  type SsdfSatisfactionMatrix,
  type SsdfPracticeRow,
  type SsdfTaskRow,
  type SsdfEvidencePointer,
  type TaskStatus,
} from '../../core/ssdf-satisfaction-matrix.ts';
import {
  emitSsdfCommonForm,
  buildCommonForm,
  validateProducer,
  computeSelection,
  loadMatrices,
  serializeUnsignedCanonical,
  MissingOperatorInputError,
  MissingPoamReferenceError,
  MissingMatrixError,
  ScopeMismatchError,
  OMB_CONTROL_NUMBER,
  type CisaCommonFormCanonical,
} from '../../core/ssdf-common-form.ts';

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-t3-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* ignore */ }
  }
});

// ─── Fixture builders ─────────────────────────────────────────────────────────

function obs(uuid: string): SsdfEvidencePointer {
  return { kind: 'oscal-observation', observation_uuid: uuid, control_id: 'sa-15', source_path: 'out/KSI-x.json' };
}
function poamPtr(uuid: string): SsdfEvidencePointer {
  return { kind: 'oscal-poam-item', poam_item_uuid: uuid, control_id: 'sa-11', source_path: 'out/poam.json' };
}
function task(
  id: string,
  status: TaskStatus,
  sections: CommonFormSection[],
  pointers: SsdfEvidencePointer[] = [],
): SsdfTaskRow {
  return {
    id,
    statement: `Task ${id}`,
    status,
    nist_800_53_r5_controls: [],
    crosswalk_ksi: [],
    common_form_section_ref: sections,
    evidence_pointers: pointers,
    open_risk_score: null,
    diagnostics: [],
  };
}

function buildMatrix(
  product: { id: string; name: string; ai_enabled?: boolean },
  tasks: SsdfTaskRow[],
): SsdfSatisfactionMatrix {
  const practice: SsdfPracticeRow = {
    id: 'PO.1',
    group: 'PO',
    name: 'Define Security Requirements',
    outcome: '',
    status: 'not-assessed',
    open_risk_score: null,
    tasks_by_status: emptyStatusTally(),
    tasks,
  };
  for (const t of tasks) practice.tasks_by_status[t.status] += 1;
  return {
    schema_version: '1.0',
    matrix_id: `m-${product.id}`,
    generated_at: '2026-06-20T00:00:00.000Z',
    csp_name: 'Acme CSP, Inc.',
    product: { id: product.id, name: product.name, ai_enabled: product.ai_enabled ?? false, critical_software: false },
    regime: 'test',
    catalogue_source: { sp: '800-218', version: 'v1.1', publication_date: '2022-02', source_pdf_sha256: 'deadbeef' },
    totals: {
      practices: 1,
      tasks: tasks.length,
      practices_by_status: emptyStatusTally(),
      tasks_by_status: emptyStatusTally(),
    },
    practices: [practice],
    provenance: {
      emitter: 'core/ssdf-evidence-aggregator.ts',
      emitterVersion: '1.0.0',
      emittedAt: '2026-06-20T00:00:00.000Z',
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

/** The "comply everywhere" task set: each §IV section has a satisfied, KSI-backed task. */
function complyTasks(): SsdfTaskRow[] {
  return [
    task('PO.5.1', 'satisfied', ['§IV(1)'], [obs('o-iv1')]),
    task('PW.4.1', 'satisfied', ['§IV(2)'], [obs('o-iv2')]),
    task('PS.3.2', 'satisfied', ['§IV(3)'], [obs('o-iv3')]),
    task('PW.7.1', 'satisfied', ['§IV(4)'], [obs('o-iv4')]),
  ];
}

function writeMatrix(dir: string, m: SsdfSatisfactionMatrix, suffix?: string): void {
  const name = suffix ? `ssdf-satisfaction-matrix.${suffix}.json` : 'ssdf-satisfaction-matrix.json';
  writeFileSync(resolve(dir, name), JSON.stringify(m, null, 2));
}

function producer(overrides: Record<string, any> = {}): Record<string, any> {
  return {
    legal_name: 'Acme CSP, Inc.',
    dba_name: 'Acme Cloud',
    address: { street: '123 Main St', city: 'Reston', state: 'VA', postal_code: '20190', country: 'US' },
    point_of_contact: { name: 'Jane Doe', title: 'CISO', email: 'jane.doe@acme.example', phone: '+1-703-555-0100' },
    signatory: { name: 'John Smith', title: 'Chief Executive Officer' },
    scope_of_attestation: { products: [{ name: 'Acme Cloud Evidence Platform', version: '2026.6.1', cpe: 'cpe:2.3:a:acme:cep:2026.6.1:*:*:*:*:*:*:*' }] },
    ai_profile: false,
    ...overrides,
  };
}

function emitMinimal(opts: { tasks?: SsdfTaskRow[]; prod?: Record<string, any>; aiPractices?: any } = {}): {
  dir: string;
  form: CisaCommonFormCanonical;
} {
  const dir = tmp();
  writeMatrix(dir, buildMatrix({ id: 'acme-cep', name: 'Acme Cloud Evidence Platform' }, opts.tasks ?? complyTasks()));
  const res = emitSsdfCommonForm({
    outDir: dir,
    runId: 't3-test',
    producer: opts.prod ?? producer(),
    generatedAt: '2026-06-20T12:00:00.000Z',
    aiProfilePractices: opts.aiPractices,
  });
  const form = JSON.parse(readFileSync(res.json_path, 'utf8')) as CisaCommonFormCanonical;
  return { dir, form };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('ssdf-common-form — validation', () => {
  it('T3-T04: throws MissingOperatorInputError listing ssdf.producer.legal_name when absent', () => {
    const p = producer();
    delete p.legal_name;
    expect(() => validateProducer(p)).toThrow(MissingOperatorInputError);
    try {
      validateProducer(p);
    } catch (e) {
      expect((e as MissingOperatorInputError).fields).toContain('ssdf.producer.legal_name');
    }
  });

  it('collects EVERY missing required field, not just the first', () => {
    try {
      validateProducer({ scope_of_attestation: { products: [] } });
      throw new Error('should have thrown');
    } catch (e) {
      const fields = (e as MissingOperatorInputError).fields;
      expect(fields).toContain('ssdf.producer.legal_name');
      expect(fields).toContain('ssdf.producer.address.street');
      expect(fields).toContain('ssdf.producer.point_of_contact.email');
      expect(fields).toContain('ssdf.producer.scope_of_attestation.products[] (>=1 required)');
      expect(fields.length).toBeGreaterThan(5);
    }
  });

  it('flags a malformed point-of-contact email', () => {
    const p = producer({ point_of_contact: { name: 'J', title: 'T', email: 'not-an-email', phone: '+1-703-555-0100' } });
    expect(() => validateProducer(p)).toThrow(/email \(invalid-format\)/);
  });

  it('defaults optional fields (dba_name null, country US, ai_profile false)', () => {
    const p = producer();
    delete p.dba_name;
    delete p.address.country;
    delete p.ai_profile;
    const v = validateProducer(p);
    expect(v.dba_name).toBeNull();
    expect(v.address.country).toBe('US');
    expect(v.ai_profile).toBe(false);
  });
});

describe('ssdf-common-form — selection reduction', () => {
  it('all satisfied → comply', () => {
    expect(computeSelection(['satisfied', 'satisfied'])).toBe('comply');
  });
  it('all not-satisfied → cannot-comply', () => {
    expect(computeSelection(['not-satisfied', 'not-satisfied'])).toBe('cannot-comply');
  });
  it('T3-T06: mixed satisfied + partially-satisfied → comply-with-conditions', () => {
    expect(computeSelection(['satisfied', 'partially-satisfied'])).toBe('comply-with-conditions');
  });
  it('T3-T07: any requires-operator-input → not-yet-determined (no silent promotion to comply)', () => {
    expect(computeSelection(['satisfied', 'requires-operator-input'])).toBe('not-yet-determined');
    expect(computeSelection(['satisfied', 'not-assessed'])).toBe('not-yet-determined');
  });
  it('empty (no mapped tasks) → not-yet-determined', () => {
    expect(computeSelection([])).toBe('not-yet-determined');
  });
});

describe('ssdf-common-form — canonical build', () => {
  it('T3-T01: all-comply config yields every Section IV selection = comply', () => {
    const { form } = emitMinimal();
    expect(form.attestations.practice_1_secure_environments.selection).toBe('comply');
    expect(form.attestations.practice_2_trusted_supply_chains.selection).toBe('comply');
    expect(form.attestations.practice_3_data_provenance.selection).toBe('comply');
    expect(form.attestations.practice_4_automated_vulnerability_tools.selection).toBe('comply');
  });

  it('T3-T21: omb_control_number is the constant "1670-0052"', () => {
    const { form } = emitMinimal();
    expect(form.omb_control_number).toBe(OMB_CONTROL_NUMBER);
    expect(form.omb_control_number).toBe('1670-0052');
  });

  it('T3-T05: roll-up counts mixed statuses for a section', () => {
    const tasks = [
      task('PO.5.1', 'satisfied', ['§IV(1)'], [obs('a')]),
      task('PO.5.2', 'partially-satisfied', ['§IV(1)'], [poamPtr('p1')]),
      task('PW.4.1', 'satisfied', ['§IV(2)'], [obs('b')]),
      task('PS.3.2', 'satisfied', ['§IV(3)'], [obs('c')]),
      task('PW.7.1', 'satisfied', ['§IV(4)'], [obs('d')]),
    ];
    const { form } = emitMinimal({ tasks });
    const row = form.ssdf_coverage_rollup.find((r) => r.cisa_practice === '1')!;
    expect(row.satisfied).toBe(1);
    expect(row.partially_satisfied).toBe(1);
    expect(row.not_satisfied).toBe(0);
    expect(form.attestations.practice_1_secure_environments.selection).toBe('comply-with-conditions');
  });

  it('T3-T02: cannot-comply Practice 4 surfaces the POA&M item uuids', () => {
    const tasks = [
      task('PO.5.1', 'satisfied', ['§IV(1)'], [obs('a')]),
      task('PW.4.1', 'satisfied', ['§IV(2)'], [obs('b')]),
      task('PS.3.2', 'satisfied', ['§IV(3)'], [obs('c')]),
      task('PW.7.1', 'not-satisfied', ['§IV(4)'], [poamPtr('uuid-1'), poamPtr('uuid-2')]),
    ];
    const { form } = emitMinimal({ tasks });
    expect(form.attestations.practice_4_automated_vulnerability_tools.selection).toBe('cannot-comply');
    const ref = form.poam_references.find((r) => r.cisa_practice === '4')!;
    expect(ref.poam_item_uuids).toEqual(['uuid-1', 'uuid-2']);
  });

  it('T3-T03: cannot-comply with no POA&M reference throws MissingPoamReferenceError', () => {
    const tasks = [
      task('PO.5.1', 'satisfied', ['§IV(1)'], [obs('a')]),
      task('PW.4.1', 'satisfied', ['§IV(2)'], [obs('b')]),
      task('PS.3.2', 'satisfied', ['§IV(3)'], [obs('c')]),
      task('PW.7.1', 'not-satisfied', ['§IV(4)'], [obs('failing-obs-no-poam')]),
    ];
    const dir = tmp();
    writeMatrix(dir, buildMatrix({ id: 'acme-cep', name: 'Acme Cloud Evidence Platform' }, tasks));
    expect(() =>
      emitSsdfCommonForm({ outDir: dir, runId: 'x', producer: producer(), generatedAt: '2026-06-20T12:00:00.000Z' }),
    ).toThrow(MissingPoamReferenceError);
  });

  it('honors a poam_reference_overrides entry to satisfy a cannot-comply citation', () => {
    const tasks = [
      task('PO.5.1', 'satisfied', ['§IV(1)'], [obs('a')]),
      task('PW.4.1', 'satisfied', ['§IV(2)'], [obs('b')]),
      task('PS.3.2', 'satisfied', ['§IV(3)'], [obs('c')]),
      task('PW.7.1', 'not-satisfied', ['§IV(4)'], [obs('failing')]),
    ];
    const { form } = emitMinimal({ tasks, prod: producer({ poam_reference_overrides: { '4': ['override-uuid'] } }) });
    expect(form.attestations.practice_4_automated_vulnerability_tools.selection).toBe('cannot-comply');
    expect(form.attestations.practice_4_automated_vulnerability_tools.poam_item_uuids).toEqual(['override-uuid']);
  });

  it('T3-T07: a not-assessed task forces not-yet-determined + REQUIRES-OPERATOR-INPUT source', () => {
    const tasks = [
      task('PO.5.1', 'requires-operator-input', ['§IV(1)'], []),
      task('PW.4.1', 'satisfied', ['§IV(2)'], [obs('b')]),
      task('PS.3.2', 'satisfied', ['§IV(3)'], [obs('c')]),
      task('PW.7.1', 'satisfied', ['§IV(4)'], [obs('d')]),
    ];
    const { form } = emitMinimal({ tasks });
    const box = form.attestations.practice_1_secure_environments;
    expect(box.selection).toBe('not-yet-determined');
    expect(box.source).toBe('REQUIRES-OPERATOR-INPUT');
  });

  it('T3-T08: ai_profile:true emits Appendix B with >=1 practice', () => {
    const { form } = emitMinimal({
      prod: producer({ ai_profile: true }),
      aiPractices: [{ id: 'PW.A.1', status: 'satisfied' }],
    });
    expect(form.ai_profile_appendix?.enabled).toBe(true);
    expect(form.ai_profile_appendix?.sp_800_218a_practices.length).toBeGreaterThan(0);
  });

  it('T3-T09: ai_profile:false omits the appendix', () => {
    const { form } = emitMinimal();
    expect(form.ai_profile_appendix).toBeUndefined();
  });
});

describe('ssdf-common-form — emit pipeline', () => {
  it('writes the PDF + JSON + sig to outDir', () => {
    const { dir } = emitMinimal();
    expect(existsSync(resolve(dir, 'cisa-common-form-1670-0052.pdf'))).toBe(true);
    expect(existsSync(resolve(dir, 'cisa-common-form-1670-0052.json'))).toBe(true);
    expect(existsSync(resolve(dir, 'cisa-common-form-1670-0052.json.sig'))).toBe(true);
  });

  it('T3-T19: provenance carries emitter/emittedAt/sourceCalls + signingKeyId + matrix digest', () => {
    const { form } = emitMinimal();
    const p = form.provenance;
    expect(p.emitter).toBe('core/ssdf-common-form.ts');
    expect(p.emittedAt).toBe('2026-06-20T12:00:00.000Z');
    expect(p.sourceCalls.length).toBeGreaterThan(0);
    expect(p.signingKeyId.length).toBeGreaterThan(0);
    expect(p.sourceDigests.some((d) => d.kind === 'ssdf-satisfaction-matrix')).toBe(true);
  });

  it('T3-T20: the detached signature verifies over the canonical signature-blanked bytes', () => {
    const { form } = emitMinimal();
    const canonical = serializeUnsignedCanonical(form);
    const ok = verifyDetached(Buffer.from(canonical, 'utf8'), {
      publicKeyPem: form.provenance.publicKeyPem,
      signatureBase64: form.provenance.signatureEd25519,
    });
    expect(ok).toBe(true);
  });

  it('T3-T16: serializeUnsignedCanonical is idempotent (RFC 8785 sorted-key, stable)', () => {
    const { form } = emitMinimal();
    const a = serializeUnsignedCanonical(form);
    const b = serializeUnsignedCanonical(JSON.parse(a) as CisaCommonFormCanonical);
    expect(b).toBe(a);
  });

  it('T3-T18: two products yield two ssdf_common_form_fill_rate entries, each in [0,1]', () => {
    const dir = tmp();
    writeMatrix(dir, buildMatrix({ id: 'p1', name: 'Acme Cloud Evidence Platform' }, complyTasks()));
    writeMatrix(dir, buildMatrix({ id: 'p2', name: 'Acme Cloud Tracker' }, complyTasks()), 'p2');
    emitSsdfCommonForm({
      outDir: dir,
      runId: 'x',
      generatedAt: '2026-06-20T12:00:00.000Z',
      producer: producer({
        scope_of_attestation: {
          products: [
            { name: 'Acme Cloud Evidence Platform', version: '2026.6.1' },
            { name: 'Acme Cloud Tracker', version: '1.4.0' },
          ],
        },
      }),
    });
    const cov = JSON.parse(readFileSync(resolve(dir, 'inventory-coverage.json'), 'utf8'));
    expect(Array.isArray(cov.ssdf_common_form_fill_rate)).toBe(true);
    expect(cov.ssdf_common_form_fill_rate.length).toBe(2);
    for (const e of cov.ssdf_common_form_fill_rate) {
      expect(e.fill_rate).toBeGreaterThanOrEqual(0);
      expect(e.fill_rate).toBeLessThanOrEqual(1);
    }
  });

  it('T3-T23: a scope product with no matching matrix throws ScopeMismatchError', () => {
    const dir = tmp();
    writeMatrix(dir, buildMatrix({ id: 'p1', name: 'Acme Cloud Evidence Platform' }, complyTasks()));
    writeMatrix(dir, buildMatrix({ id: 'p2', name: 'Acme Cloud Tracker' }, complyTasks()), 'p2');
    expect(() =>
      emitSsdfCommonForm({
        outDir: dir,
        runId: 'x',
        generatedAt: '2026-06-20T12:00:00.000Z',
        producer: producer({
          scope_of_attestation: { products: [{ name: 'Nonexistent Product', version: '9.9' }] },
        }),
      }),
    ).toThrow(ScopeMismatchError);
  });

  it('throws MissingMatrixError when no T.T2 matrix is present', () => {
    const dir = tmp();
    expect(() =>
      emitSsdfCommonForm({ outDir: dir, runId: 'x', producer: producer(), generatedAt: '2026-06-20T12:00:00.000Z' }),
    ).toThrow(MissingMatrixError);
  });

  it('loadMatrices discovers default + suffixed matrices', () => {
    const dir = tmp();
    writeMatrix(dir, buildMatrix({ id: 'p1', name: 'P One' }, complyTasks()));
    writeMatrix(dir, buildMatrix({ id: 'p2', name: 'P Two' }, complyTasks()), 'p2');
    const ms = loadMatrices(dir);
    expect(ms.length).toBe(2);
  });

  it('T3-T17: the submission bundle classifies the PDF + JSON with the LOOP-T.T3 roles', () => {
    const { dir } = emitMinimal();
    const { index } = buildSubmissionIndex(dir, { outDir: dir, runId: 't3-test', frmrVersion: '0.9.43-beta' } as any);
    const roles = index.artifacts.map((a) => a.role);
    expect(roles).toContain('ssdf-common-form-pdf');
    expect(roles).toContain('ssdf-common-form-json');
    const json = index.artifacts.find((a) => a.role === 'ssdf-common-form-json')!;
    expect(json.description).toMatch(/LOOP-T\.T3/);
  });
});
