/**
 * Tests for core/oscal-ssp.ts — the OSCAL System Security Plan emitter (SSP-1).
 *
 * Writes evidence files to a temp dir, injects a fixture NIST baseline via
 * NIST_BASELINES_PATH, emits the SSP, and asserts:
 *   1. The output validates against the committed NIST OSCAL 1.1.2 SSP schema.
 *   2. ControlStatus → implementation-status mapping is correct.
 *   3. Every baseline control gets exactly one implemented-requirement.
 *   4. Control ids and required SSP structure are present.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { emitOscalSsp, buildOscalSsp } from '../../core/oscal-ssp.ts';
import { benchmarkControls } from '../../core/control-benchmark.ts';
import { validateOscal, validateOscalFile } from '../../core/oscal-validate.ts';

function ev(ksi_id: string, findings: Array<{ rule: string; passed: boolean; nist_controls?: string[] }>): any {
  return { ksi_id, providers: [{ provider: 'aws', findings }], rollup: { pass: findings.every((f) => f.passed) } };
}

const FIXTURE_BASELINES = {
  low: ['ac-2', 'ra-5', 'au-6'],
  moderate: ['ac-2', 'ac-2.1', 'ra-5', 'ra-5.2', 'au-6'],
  high: ['ac-2', 'ac-2.1', 'ac-2.12', 'ra-5', 'au-6'],
};

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-ssp-'));
  dirs.push(d);
  return d;
}

let prevBaselines: string | undefined;
function injectBaselines(): string {
  const d = tmp();
  const p = join(d, 'baselines.json');
  writeFileSync(p, JSON.stringify(FIXTURE_BASELINES));
  prevBaselines = process.env.NIST_BASELINES_PATH;
  process.env.NIST_BASELINES_PATH = p;
  return d;
}

afterEach(() => {
  if (prevBaselines === undefined) delete process.env.NIST_BASELINES_PATH;
  else process.env.NIST_BASELINES_PATH = prevBaselines;
  prevBaselines = undefined;
  for (const d of dirs.splice(0)) { try { rmSync(d, { recursive: true, force: true }); } catch { /* */ } }
});

describe('emitOscalSsp (disk reader → schema-valid SSP)', () => {
  it('emits an SSP that validates against the NIST OSCAL 1.1.2 SSP schema', () => {
    injectBaselines();
    const out = tmp();
    writeFileSync(join(out, 'KSI-IAM-MFA.json'), JSON.stringify(
      ev('KSI-IAM-MFA', [{ rule: 'mfa_on', passed: true, nist_controls: ['ac-2'] }]),
    ));
    writeFileSync(join(out, 'KSI-SVC-VRI.json'), JSON.stringify(
      ev('KSI-SVC-VRI', [{ rule: 'scan', passed: false, nist_controls: ['ra-5'] }]),
    ));

    const r = emitOscalSsp({ outDir: out, runId: 'run-1', frmrVersion: '25.05', impactLevel: 'moderate', systemName: 'Test System', systemId: 'sys-test' });

    // 5 controls in the moderate fixture baseline.
    expect(r.control_count).toBe(FIXTURE_BASELINES.moderate.length);
    expect(r.implemented).toBe(1);            // ac-2 passing
    expect(r.partial).toBe(0);
    expect(r.planned).toBe(FIXTURE_BASELINES.moderate.length - 1);  // ra-5 fail + 3 not-assessed

    const v = validateOscalFile(r.path, 'ssp');
    if (!v.valid) throw new Error(`SSP schema invalid:\n${v.errors.slice(0, 8).join('\n')}`);
    expect(v.valid).toBe(true);
  });

  it('maps control status → implementation-status correctly', () => {
    injectBaselines();
    const out = tmp();
    writeFileSync(join(out, 'KSI-A.json'), JSON.stringify(
      ev('KSI-A', [{ rule: 'r1', passed: true, nist_controls: ['ac-2'] }]),
    ));
    writeFileSync(join(out, 'KSI-B.json'), JSON.stringify(
      ev('KSI-B', [
        { rule: 'r2', passed: true, nist_controls: ['ac-2.1'] },
        { rule: 'r3', passed: false, nist_controls: ['ac-2.1'] },   // mixed → partial
      ]),
    ));
    writeFileSync(join(out, 'KSI-C.json'), JSON.stringify(
      ev('KSI-C', [{ rule: 'r4', passed: false, nist_controls: ['ra-5'] }]),
    ));

    emitOscalSsp({ outDir: out, runId: 'run-2', frmrVersion: '25.05', impactLevel: 'moderate', systemId: 'sys-map' });
    const doc = JSON.parse(readFileSync(join(out, 'ssp.json'), 'utf8'));
    const irs: any[] = doc['system-security-plan']['control-implementation']['implemented-requirements'];
    const stateOf = (id: string) => {
      const ir = irs.find((x) => x['control-id'] === id);
      return ir?.['by-components']?.[0]?.['implementation-status']?.state;
    };
    expect(stateOf('ac-2')).toBe('implemented');     // all pass
    expect(stateOf('ac-2.1')).toBe('partial');       // mixed
    expect(stateOf('ra-5')).toBe('planned');         // all fail
    expect(stateOf('au-6')).toBe('planned');         // not-assessed
    // FedRAMP implementation-status prop mirrors the by-component state.
    const ac2 = irs.find((x) => x['control-id'] === 'ac-2');
    expect(ac2.props.some((p: any) => p.name === 'implementation-status' && p.value === 'implemented')).toBe(true);
  });
});

describe('buildOscalSsp (pure)', () => {
  it('produces required SSP structure and one implemented-requirement per control', () => {
    const benchmark = benchmarkControls(
      [ev('KSI-IAM-MFA', [{ rule: 'mfa', passed: true, nist_controls: ['ac-2'] }])],
      ['ac-2', 'ra-5'],
      'rev5',
      'low',
    );
    const { doc, result } = buildOscalSsp(benchmark, {
      outDir: '/tmp', runId: 'run-3', frmrVersion: '25.05', impactLevel: 'low',
      systemName: 'Acme', systemId: 'acme', organizationName: 'Acme Corp', providers: ['aws'],
    });
    const ssp = doc['system-security-plan'];
    expect(ssp.uuid).toMatch(/^[0-9a-f-]{36}$/);
    expect(ssp.metadata['oscal-version']).toBe('1.1.2');
    expect(ssp['import-profile'].href).toMatch(/FedRAMP_rev5_LOW-baseline/);
    expect(ssp['control-implementation']['implemented-requirements']).toHaveLength(2);
    expect(result.control_count).toBe(2);
    // this-system + one leveraged provider component.
    expect(ssp['system-implementation'].components.length).toBe(2);
    expect(ssp['system-implementation'].components[0]!.type).toBe('this-system');
    // by-component references the this-system component.
    const ir = ssp['control-implementation']['implemented-requirements'][0]!;
    expect(ir['by-components']![0]!['component-uuid']).toBe(ssp['system-implementation'].components[0]!.uuid);
    // The whole doc validates.
    const v = validateOscal(doc, 'ssp');
    if (!v.valid) throw new Error(`SSP schema invalid:\n${v.errors.slice(0, 8).join('\n')}`);
    expect(v.valid).toBe(true);
  });

  it('is deterministic: same inputs → identical document', () => {
    const benchmark = benchmarkControls([], ['ac-2'], 'rev5', 'low');
    const a = buildOscalSsp(benchmark, { outDir: '/tmp', runId: 'r', frmrVersion: 'v', impactLevel: 'low', systemId: 'x' });
    const b = buildOscalSsp(benchmark, { outDir: '/tmp', runId: 'r', frmrVersion: 'v', impactLevel: 'low', systemId: 'x' });
    // last-modified is the only volatile field; null it out before comparing.
    a.doc['system-security-plan'].metadata['last-modified'] = '';
    b.doc['system-security-plan'].metadata['last-modified'] = '';
    expect(JSON.stringify(a.doc)).toBe(JSON.stringify(b.doc));
  });

  // ── REO-0: operator-supplied SSP inputs ────────────────────────────────────
  // Per cloud-evidence/CLAUDE.md the SSP emitter never silently substitutes
  // placeholder data for the authorization-boundary narrative or the
  // system-implementation.users[] entries. When the operator supplies real
  // values, the emitter uses them verbatim; when omitted, a clearly-marked
  // REQUIRES-OPERATOR-INPUT diagnostic is emitted instead, so a 3PAO can
  // see at-a-glance that the gap exists rather than mistaking placeholder
  // text for a finalized narrative.
  describe('REO: authorization-boundary + userRoles', () => {
    it('emits REQUIRES-OPERATOR-INPUT marker when boundary description is omitted', () => {
      const benchmark = benchmarkControls([], ['ac-2'], 'rev5', 'low');
      const { doc } = buildOscalSsp(benchmark, {
        outDir: '/tmp', runId: 'r', frmrVersion: 'v', impactLevel: 'low', systemId: 'x',
      });
      const boundary = doc['system-security-plan']['system-characteristics']['authorization-boundary'];
      expect(boundary.description).toMatch(/^REQUIRES-OPERATOR-INPUT:/);
      // No "placeholder" wording allowed.
      expect(boundary.description.toLowerCase()).not.toContain('placeholder');
    });

    it('uses operator-supplied boundary description verbatim when provided', () => {
      const benchmark = benchmarkControls([], ['ac-2'], 'rev5', 'low');
      const real = 'Our boundary contains the ACME web tier (VPC vpc-abc), the data tier (RDS in vpc-abc), and the shared services VPC (peered).';
      const { doc } = buildOscalSsp(benchmark, {
        outDir: '/tmp', runId: 'r', frmrVersion: 'v', impactLevel: 'low', systemId: 'x',
        authorizationBoundaryDescription: real,
      });
      const boundary = doc['system-security-plan']['system-characteristics']['authorization-boundary'];
      expect(boundary.description).toBe(real);
      expect(boundary.description).not.toMatch(/^REQUIRES-OPERATOR-INPUT:/);
    });

    it('emits REQUIRES-OPERATOR-INPUT marker for users[] when userRoles is omitted', () => {
      const benchmark = benchmarkControls([], ['ac-2'], 'rev5', 'low');
      const { doc } = buildOscalSsp(benchmark, {
        outDir: '/tmp', runId: 'r', frmrVersion: 'v', impactLevel: 'low', systemId: 'x',
      });
      const users = doc['system-security-plan']['system-implementation'].users;
      expect(users).toHaveLength(1);
      expect(users[0]!.description).toMatch(/^REQUIRES-OPERATOR-INPUT:/);
      expect(users[0]!.description.toLowerCase()).not.toContain('placeholder');
    });

    it('uses operator-supplied userRoles[] verbatim when provided', () => {
      const benchmark = benchmarkControls([], ['ac-2'], 'rev5', 'low');
      const { doc } = buildOscalSsp(benchmark, {
        outDir: '/tmp', runId: 'r', frmrVersion: 'v', impactLevel: 'low', systemId: 'x',
        userRoles: [
          { title: 'Site Reliability Engineer', roleIds: ['admin'], description: 'On-call infrastructure operator with break-glass access.' },
          { title: 'Developer', roleIds: ['developer'], description: 'Read-only on production; full access in staging.' },
        ],
      });
      const users = doc['system-security-plan']['system-implementation'].users;
      expect(users).toHaveLength(2);
      expect(users[0]!.title).toBe('Site Reliability Engineer');
      expect(users[1]!.title).toBe('Developer');
      for (const u of users) {
        expect(u.description).not.toMatch(/^REQUIRES-OPERATOR-INPUT:/);
        expect(u.description.toLowerCase()).not.toContain('placeholder');
      }
    });
  });
});
