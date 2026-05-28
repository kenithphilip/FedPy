/**
 * Tests for core/control-benchmark.ts — the NIST 800-53 control benchmark.
 *
 * Pure-core (`benchmarkControls`, `inScopeControls`) tests use fixed inputs so
 * they never touch the network or the generated baseline file. The disk reader
 * (`buildControlBenchmark`) writes evidence files to a temp dir and points the
 * baseline loader at an injected fixture via NIST_BASELINES_PATH.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  benchmarkControls,
  inScopeControls,
  buildControlBenchmark,
  loadBaselines,
  type BenchmarkFramework,
} from '../../core/control-benchmark.ts';

/** Build a minimal EvidenceFile-shaped object. */
function ev(
  ksi_id: string,
  findings: Array<{ rule: string; passed: boolean; nist_controls?: string[] }>,
  opts: { nist_controls?: string[]; awareness_only?: boolean } = {},
): any {
  return {
    ksi_id,
    nist_controls: opts.nist_controls,
    awareness_only: opts.awareness_only,
    providers: [{ provider: 'aws', findings }],
  };
}

const FIXTURE_BASELINES = {
  low: ['ac-2', 'ra-5'],
  moderate: ['ac-2', 'ac-2.1', 'ra-5', 'ra-5.2', 'au-6'],
  high: ['ac-2', 'ac-2.1', 'ac-2.12', 'ra-5', 'ra-5.2', 'ra-5.4', 'au-6'],
};

describe('benchmarkControls (pure)', () => {
  it('marks a control satisfied when all mapping findings pass', () => {
    const files = [ev('KSI-IAM-MFA', [{ rule: 'mfa_on', passed: true, nist_controls: ['ac-2'] }])];
    const r = benchmarkControls(files, ['ac-2', 'ra-5'], '20x', 'moderate');
    const ac2 = r.controls.find((c) => c.id === 'ac-2')!;
    expect(ac2.status).toBe('satisfied');
    expect(ac2.addressed_by).toHaveLength(1);
    expect(ac2.addressed_by[0]!.requirement_id).toBe('KSI-IAM-MFA');
    // ra-5 has no evidence → not-assessed
    expect(r.controls.find((c) => c.id === 'ra-5')!.status).toBe('not-assessed');
  });

  it('marks a control not-satisfied when all mapping findings fail', () => {
    const files = [ev('KSI-SVC-VRI', [{ rule: 'scan', passed: false, nist_controls: ['ra-5'] }])];
    const r = benchmarkControls(files, ['ra-5'], '20x', 'low');
    expect(r.controls.find((c) => c.id === 'ra-5')!.status).toBe('not-satisfied');
  });

  it('marks a control partially-satisfied on mixed findings', () => {
    const files = [
      ev('KSI-A', [{ rule: 'r1', passed: true, nist_controls: ['ac-2'] }]),
      ev('KSI-B', [{ rule: 'r2', passed: false, nist_controls: ['ac-2'] }]),
    ];
    const r = benchmarkControls(files, ['ac-2'], '20x', 'low');
    const ac2 = r.controls.find((c) => c.id === 'ac-2')!;
    expect(ac2.status).toBe('partially-satisfied');
    expect(ac2.addressed_by).toHaveLength(2);
  });

  it('falls back to the file-level nist_controls when a finding has none', () => {
    const files = [ev('KSI-AU', [{ rule: 'logs', passed: true }], { nist_controls: ['au-6'] })];
    const r = benchmarkControls(files, ['au-6'], '20x', 'moderate');
    expect(r.controls.find((c) => c.id === 'au-6')!.status).toBe('satisfied');
  });

  it('prefers the finding-level controls over the file-level ones', () => {
    const files = [ev('KSI-X', [{ rule: 'r', passed: true, nist_controls: ['ra-5'] }], { nist_controls: ['ac-2'] })];
    const r = benchmarkControls(files, ['ac-2', 'ra-5'], '20x', 'low');
    expect(r.controls.find((c) => c.id === 'ra-5')!.status).toBe('satisfied');
    // ac-2 was the file-level fallback, not used because the finding had its own
    expect(r.controls.find((c) => c.id === 'ac-2')!.status).toBe('not-assessed');
  });

  it('awareness-only evidence does not satisfy a control on its own', () => {
    const files = [ev('FRR-CSX', [{ rule: 'attest', passed: true, nist_controls: ['ac-2'] }], { awareness_only: true })];
    const r = benchmarkControls(files, ['ac-2'], '20x', 'low');
    const ac2 = r.controls.find((c) => c.id === 'ac-2')!;
    expect(ac2.status).toBe('not-assessed');           // scoring excludes awareness
    expect(ac2.addressed_by).toHaveLength(1);           // …but it is still listed
    expect(ac2.addressed_by[0]!.awareness_only).toBe(true);
  });

  it('ignores controls that are out of scope for the chosen level', () => {
    const files = [ev('KSI', [{ rule: 'r', passed: true, nist_controls: ['ac-2.1'] }])];
    // ac-2.1 is NOT in the in-scope set → no contribution recorded
    const r = benchmarkControls(files, ['ac-2'], 'rev5', 'low');
    expect(r.totals.in_scope).toBe(1);
    expect(r.controls.find((c) => c.id === 'ac-2')!.status).toBe('not-assessed');
  });

  it('is case-insensitive on control ids', () => {
    const files = [ev('KSI', [{ rule: 'r', passed: true, nist_controls: ['AC-2'] }])];
    const r = benchmarkControls(files, ['Ac-2'], '20x', 'low');
    expect(r.controls.find((c) => c.id === 'ac-2')!.status).toBe('satisfied');
  });

  it('computes totals and the two rates correctly', () => {
    const files = [
      ev('KSI-1', [{ rule: 'a', passed: true, nist_controls: ['ac-2'] }]),  // satisfied
      ev('KSI-2', [{ rule: 'b', passed: false, nist_controls: ['ra-5'] }]), // not-satisfied
      ev('KSI-3', [{ rule: 'c1', passed: true, nist_controls: ['au-6'] }, { rule: 'c2', passed: false, nist_controls: ['au-6'] }]), // partial
      // ac-2.1 in scope but no evidence → not-assessed
    ];
    const r = benchmarkControls(files, ['ac-2', 'ra-5', 'au-6', 'ac-2.1'], 'rev5', 'moderate');
    const t = r.totals;
    expect(t.in_scope).toBe(4);
    expect(t.satisfied).toBe(1);
    expect(t.not_satisfied).toBe(1);
    expect(t.partially_satisfied).toBe(1);
    expect(t.not_assessed).toBe(1);
    // assessed = 4 - 1 = 3; satisfied / assessed = 1/3
    expect(t.assessed_pass_rate).toBeCloseTo(1 / 3, 5);
    // baseline_coverage = satisfied / in_scope = 1/4
    expect(t.baseline_coverage_rate).toBe(0.25);
  });

  it('records the framework, level, and a control_source label', () => {
    const r5 = benchmarkControls([], ['ac-2'], 'rev5', 'high');
    expect(r5.framework).toBe('rev5');
    expect(r5.impact_level).toBe('high');
    expect(r5.control_source).toMatch(/800-53B/);
    const x = benchmarkControls([], ['ac-2'], '20x', 'low');
    expect(x.control_source).toMatch(/20x/);
  });

  it('enriches controls with NIST names/families when known', () => {
    const r = benchmarkControls([], ['ra-5'], 'rev5', 'low');
    const ra5 = r.controls.find((c) => c.id === 'ra-5')!;
    // ships with the repo lookup; ra-5 is a well-known control
    expect(ra5.family).toBe('RA');
    expect(ra5.name).toBeTruthy();
  });

  it('returns controls sorted by id', () => {
    const r = benchmarkControls([], ['ra-5', 'ac-2', 'au-6'], 'rev5', 'low');
    expect(r.controls.map((c) => c.id)).toEqual(['ac-2', 'au-6', 'ra-5']);
  });

  it('skips files missing ksi_id or providers', () => {
    const files: any[] = [
      { providers: [{ findings: [{ rule: 'r', passed: true, nist_controls: ['ac-2'] }] }] }, // no ksi_id
      { ksi_id: 'KSI', providers: 'nope' },                                                   // bad providers
    ];
    const r = benchmarkControls(files, ['ac-2'], '20x', 'low');
    expect(r.controls.find((c) => c.id === 'ac-2')!.status).toBe('not-assessed');
  });
});

describe('inScopeControls', () => {
  it('rev5 returns the full baseline membership for the level', () => {
    expect(inScopeControls('rev5', 'low', [], FIXTURE_BASELINES)).toEqual(FIXTURE_BASELINES.low);
    expect(inScopeControls('rev5', 'high', [], FIXTURE_BASELINES)).toEqual(FIXTURE_BASELINES.high);
  });

  it('20x returns the sorted union of controls the evidence references', () => {
    const files = [
      ev('KSI-1', [{ rule: 'a', passed: true, nist_controls: ['ra-5', 'ac-2'] }]),
      ev('KSI-2', [{ rule: 'b', passed: false }], { nist_controls: ['au-6'] }),
      ev('KSI-3', [{ rule: 'c', passed: true, nist_controls: ['AC-2'] }]), // dup, different case
    ];
    expect(inScopeControls('20x', 'moderate', files, FIXTURE_BASELINES)).toEqual(['ac-2', 'au-6', 'ra-5']);
  });

  it('20x is independent of the level (driven by evidence, not the baseline)', () => {
    const files = [ev('KSI', [{ rule: 'a', passed: true, nist_controls: ['ra-5'] }])];
    expect(inScopeControls('20x', 'low', files, FIXTURE_BASELINES)).toEqual(['ra-5']);
    expect(inScopeControls('20x', 'high', files, FIXTURE_BASELINES)).toEqual(['ra-5']);
  });
});

describe('loadBaselines', () => {
  it('throws an actionable error when the baseline file is missing', () => {
    expect(() => loadBaselines('/nonexistent/path/baselines.json')).toThrow(/extract-nist-baselines/);
  });

  it('loads the committed baseline membership with the expected counts', () => {
    // The repo ships docs/nist-r5-baselines.generated.json (Low 149 / Mod 287 / High 370).
    const b = loadBaselines();
    expect(b.low.length).toBe(149);
    expect(b.moderate.length).toBe(287);
    expect(b.high.length).toBe(370);
    // nesting invariant: low ⊆ moderate ⊆ high
    const mod = new Set(b.moderate);
    const high = new Set(b.high);
    expect(b.low.every((c) => mod.has(c))).toBe(true);
    expect(b.moderate.every((c) => high.has(c))).toBe(true);
  });
});

describe('buildControlBenchmark (disk)', () => {
  let dir: string;
  let baselinePath: string;
  const prevEnv = process.env.NIST_BASELINES_PATH;

  afterEach(() => {
    if (prevEnv === undefined) delete process.env.NIST_BASELINES_PATH;
    else process.env.NIST_BASELINES_PATH = prevEnv;
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  function setup(): void {
    dir = mkdtempSync(join(tmpdir(), 'control-bench-'));
    baselinePath = join(dir, 'baselines.json');
    writeFileSync(baselinePath, JSON.stringify(FIXTURE_BASELINES));
    process.env.NIST_BASELINES_PATH = baselinePath;
    // Two evidence files + one report file that must be skipped.
    writeFileSync(join(dir, 'ksi-iam-mfa.json'), JSON.stringify(ev('KSI-IAM-MFA', [{ rule: 'mfa', passed: true, nist_controls: ['ac-2'] }])));
    writeFileSync(join(dir, 'ksi-svc-vri.json'), JSON.stringify(ev('KSI-SVC-VRI', [{ rule: 'scan', passed: false, nist_controls: ['ra-5'] }])));
    writeFileSync(join(dir, 'family-rollup.json'), JSON.stringify({ not: 'evidence' }));
    writeFileSync(join(dir, 'control-benchmark.json'), JSON.stringify({ stale: true }));
  }

  it('rev5: scores the whole level baseline, skipping report files', () => {
    setup();
    const b = buildControlBenchmark(dir, { framework: 'rev5', level: 'low' });
    expect(b.framework).toBe('rev5');
    expect(b.totals.in_scope).toBe(FIXTURE_BASELINES.low.length); // 2
    expect(b.controls.find((c) => c.id === 'ac-2')!.status).toBe('satisfied');
    expect(b.controls.find((c) => c.id === 'ra-5')!.status).toBe('not-satisfied');
  });

  it('20x: scores only the controls the evidence references', () => {
    setup();
    const b = buildControlBenchmark(dir, { framework: '20x', level: 'high' });
    expect(b.totals.in_scope).toBe(2); // ac-2, ra-5
    expect(b.controls.map((c) => c.id).sort()).toEqual(['ac-2', 'ra-5']);
  });

  it('handles an empty output directory without throwing', () => {
    dir = mkdtempSync(join(tmpdir(), 'control-bench-empty-'));
    baselinePath = join(dir, 'baselines.json');
    writeFileSync(baselinePath, JSON.stringify(FIXTURE_BASELINES));
    process.env.NIST_BASELINES_PATH = baselinePath;
    const b = buildControlBenchmark(dir, { framework: '20x', level: 'low' });
    expect(b.totals.in_scope).toBe(0);
    expect(b.controls).toHaveLength(0);
  });
});
