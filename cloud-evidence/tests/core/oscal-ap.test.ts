/**
 * Tests for core/oscal-ap.ts — the OSCAL Assessment Plan emitter (LOOP-A.A2).
 *
 * Verifies:
 *   1. Emitted AP validates against the committed OSCAL v1.1.2 AP schema.
 *   2. Schema-required structure: uuid + metadata.{title,last-modified,
 *      version,oscal-version} + import-ssp{href} + reviewed-controls.control-selections.
 *   3. reviewed-controls enumerates every control in the FedRAMP baseline
 *      for the impact tier (no synthetic IDs).
 *   4. local-definitions.activities[] has one entry per registered KSI
 *      (read from ksi-map.ts source — same trick the FRMR extractor uses).
 *   5. assessment-subjects derives from real inventory.json when present;
 *      falls back to a REQUIRES-OPERATOR-INPUT include-all subject when
 *      inventory is missing (per the REO rule, no fabricated subjects).
 *   6. Operator-supplied roeHref + samplingMethodologyHref produce real
 *      back-matter resources + populated terms-and-conditions prose;
 *      when omitted, REQUIRES-OPERATOR-INPUT markers are emitted.
 *   7. Tasks: operator-supplied dates produce timing.within-date-range;
 *      omitted dates produce REQUIRES-OPERATOR-INPUT remarks.
 *   8. Determinism: same inputs → identical document.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { emitOscalAp, buildOscalAp, type ApEmitOptions } from '../../core/oscal-ap.ts';
import { buildControlBenchmark } from '../../core/control-benchmark.ts';
import { validateOscal, validateOscalFile } from '../../core/oscal-validate.ts';

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-ap-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

function baseOpts(over: Partial<ApEmitOptions> = {}): ApEmitOptions {
  return {
    outDir: '/tmp', runId: 'r-ap-1', frmrVersion: '0.9.43-beta', impactLevel: 'low',
    systemId: 'acme-prod', systemName: 'Acme Prod',
    ...over,
  };
}

describe('OSCAL Assessment Plan emitter — buildOscalAp', () => {
  it('produces a schema-valid AP document at low impact', () => {
    const benchmark = buildControlBenchmark('/tmp', { framework: 'rev5', level: 'low' });
    const { doc, result } = buildOscalAp(benchmark, baseOpts());
    const v = validateOscal(doc, 'assessment-plan');
    if (!v.valid) throw new Error(`AP schema invalid:\n${v.errors.slice(0, 8).join('\n')}`);
    expect(v.valid).toBe(true);
    expect(result.reviewed_control_count).toBe(benchmark.controls.length);
    expect(result.task_count).toBe(4); // default 4-phase plan
    expect(result.activity_count).toBeGreaterThan(0);
  });

  it('produces a schema-valid AP document at moderate impact', () => {
    const benchmark = buildControlBenchmark('/tmp', { framework: 'rev5', level: 'moderate' });
    const { doc, result } = buildOscalAp(benchmark, baseOpts({ impactLevel: 'moderate' }));
    const v = validateOscal(doc, 'assessment-plan');
    if (!v.valid) throw new Error(`AP schema invalid:\n${v.errors.slice(0, 8).join('\n')}`);
    expect(v.valid).toBe(true);
    // Moderate baseline is larger than Low.
    expect(result.reviewed_control_count).toBeGreaterThan(150);
  });

  it('emits the schema-required metadata fields', () => {
    const benchmark = buildControlBenchmark('/tmp', { framework: 'rev5', level: 'low' });
    const { doc } = buildOscalAp(benchmark, baseOpts());
    const m = doc['assessment-plan'].metadata;
    expect(m.title).toBeTruthy();
    expect(m['last-modified']).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(m.version).toBe('r-ap-1');
    expect(m['oscal-version']).toBe('1.1.2');
  });

  it('emits import-ssp with the operator-provided sspHref', () => {
    const benchmark = buildControlBenchmark('/tmp', { framework: 'rev5', level: 'low' });
    const { doc } = buildOscalAp(benchmark, baseOpts({ sspHref: '#ssp-uuid-abc' }));
    expect(doc['assessment-plan']['import-ssp'].href).toBe('#ssp-uuid-abc');
  });

  it('defaults import-ssp.href to "ssp.json" when no sspHref supplied + emits remarks pointing operator to the flag', () => {
    const benchmark = buildControlBenchmark('/tmp', { framework: 'rev5', level: 'low' });
    const { doc } = buildOscalAp(benchmark, baseOpts());
    expect(doc['assessment-plan']['import-ssp'].href).toBe('ssp.json');
    expect(doc['assessment-plan']['import-ssp'].remarks).toMatch(/--ap-ssp-href/);
  });

  it('reviewed-controls enumerates every baseline control (no synthetic IDs)', () => {
    const benchmark = buildControlBenchmark('/tmp', { framework: 'rev5', level: 'low' });
    const { doc } = buildOscalAp(benchmark, baseOpts());
    const sel = doc['assessment-plan']['reviewed-controls']['control-selections'];
    expect(sel).toHaveLength(1);
    const ids = sel[0]!['include-controls']!.map((c) => c['control-id']).sort();
    const benchIds = benchmark.controls.map((c) => c.id).sort();
    expect(ids).toEqual(benchIds);
  });

  it('local-definitions.activities[] registers one activity per KSI (read from ksi-map.ts)', () => {
    const benchmark = buildControlBenchmark('/tmp', { framework: 'rev5', level: 'low' });
    const { doc, result } = buildOscalAp(benchmark, baseOpts());
    const activities = doc['assessment-plan']['local-definitions']?.activities;
    expect(activities).toBeDefined();
    expect(activities!.length).toBe(result.activity_count);
    // Each activity carries method=TEST + a ksi-id prop.
    for (const a of activities!) {
      const methodProp = a.props?.find((p) => p.name === 'method');
      const ksiProp = a.props?.find((p) => p.name === 'ksi-id');
      expect(methodProp?.value).toBe('TEST');
      expect(ksiProp?.value).toMatch(/^KSI-/);
    }
  });

  it('emits REQUIRES-OPERATOR-INPUT in terms-and-conditions when roeHref + samplingMethodologyHref are omitted', () => {
    const benchmark = buildControlBenchmark('/tmp', { framework: 'rev5', level: 'low' });
    const { doc } = buildOscalAp(benchmark, baseOpts());
    const parts = doc['assessment-plan']['terms-and-conditions']?.parts ?? [];
    const roe = parts.find((p) => p.name === 'rules-of-engagement')!;
    const sampling = parts.find((p) => p.name === 'sampling-methodology')!;
    expect(roe.prose).toMatch(/^REQUIRES-OPERATOR-INPUT:/);
    expect(sampling.prose).toMatch(/^REQUIRES-OPERATOR-INPUT:/);
  });

  it('uses operator-supplied roeHref + samplingMethodologyHref verbatim + emits matching back-matter resources', () => {
    const benchmark = buildControlBenchmark('/tmp', { framework: 'rev5', level: 'low' });
    const { doc } = buildOscalAp(benchmark, baseOpts({
      roeHref: 'https://example.com/roe.pdf',
      samplingMethodologyHref: 'https://example.com/sampling.json',
    }));
    const parts = doc['assessment-plan']['terms-and-conditions']?.parts ?? [];
    expect(parts.find((p) => p.name === 'rules-of-engagement')!.prose).toContain('https://example.com/roe.pdf');
    expect(parts.find((p) => p.name === 'sampling-methodology')!.prose).toContain('https://example.com/sampling.json');
    const bmHrefs = (doc['assessment-plan']['back-matter']?.resources ?? []).flatMap((r) => r.rlinks?.map((l) => l.href) ?? []);
    expect(bmHrefs).toContain('https://example.com/roe.pdf');
    expect(bmHrefs).toContain('https://example.com/sampling.json');
  });

  it('emits REQUIRES-OPERATOR-INPUT in task.remarks when no dates are supplied', () => {
    const benchmark = buildControlBenchmark('/tmp', { framework: 'rev5', level: 'low' });
    const { doc } = buildOscalAp(benchmark, baseOpts());
    const tasks = doc['assessment-plan'].tasks ?? [];
    expect(tasks.length).toBeGreaterThan(0);
    for (const t of tasks) {
      expect(t.timing).toBeUndefined();
      expect(t.remarks).toMatch(/^REQUIRES-OPERATOR-INPUT:/);
    }
  });

  it('uses operator-supplied task dates → timing.within-date-range', () => {
    const benchmark = buildControlBenchmark('/tmp', { framework: 'rev5', level: 'low' });
    const { doc } = buildOscalAp(benchmark, baseOpts({
      tasks: [
        { title: 'Scoping', description: 'desc', type: 'milestone', startDate: '2026-07-01', endDate: '2026-07-07' },
        { title: 'Testing', description: 'desc', startDate: '2026-07-15', endDate: '2026-08-15' },
      ],
    }));
    const tasks = doc['assessment-plan'].tasks ?? [];
    expect(tasks).toHaveLength(2);
    expect(tasks[0]!.timing?.['within-date-range']).toEqual({ start: '2026-07-01', end: '2026-07-07' });
    expect(tasks[0]!.remarks).toBeUndefined();
    expect(tasks[1]!.timing?.['within-date-range']).toEqual({ start: '2026-07-15', end: '2026-08-15' });
  });

  it('falls back to a REQUIRES-OPERATOR-INPUT subject when no inventory.json exists', () => {
    const benchmark = buildControlBenchmark('/tmp', { framework: 'rev5', level: 'low' });
    const { doc } = buildOscalAp(benchmark, baseOpts({ outDir: '/tmp/does-not-exist-cev-ap' }));
    const subjects = doc['assessment-plan']['assessment-subjects'] ?? [];
    expect(subjects.length).toBeGreaterThan(0);
    expect(subjects[0]!.description).toMatch(/^REQUIRES-OPERATOR-INPUT:/);
  });

  it('derives real assessment-subjects from inventory.json when present', () => {
    const d = tmp();
    writeFileSync(join(d, 'inventory.json'), JSON.stringify({
      assets: [
        { provider: 'aws', uniqueId: 'arn:aws:ec2:us-east-1:123:instance/i-1', assetType: 'Instance', name: 'web-1' },
        { provider: 'aws', uniqueId: 'arn:aws:ec2:us-east-1:123:instance/i-2', assetType: 'Instance', name: 'web-2' },
        { provider: 'gcp', uniqueId: 'projects/p/zones/us-c1/instances/g1', assetType: 'Instance', name: 'gcp-1' },
      ],
    }));
    const benchmark = buildControlBenchmark(d, { framework: 'rev5', level: 'low' });
    const { doc, result } = buildOscalAp(benchmark, baseOpts({ outDir: d }));
    const subjects = doc['assessment-plan']['assessment-subjects'] ?? [];
    expect(subjects.length).toBeGreaterThan(0);
    // Two component groups (aws:Instance, gcp:Instance) + three inventory-items.
    const componentSubjects = subjects.find((s) => s.type === 'component');
    expect(componentSubjects?.['include-subjects']?.length).toBe(2);
    const itemSubjects = subjects.find((s) => s.type === 'inventory-item');
    expect(itemSubjects?.['include-subjects']?.length).toBe(3);
    expect(result.assessment_subject_count).toBe(5);
  });

  it('is deterministic: same inputs → identical document', () => {
    const benchmark = buildControlBenchmark('/tmp', { framework: 'rev5', level: 'low' });
    const a = buildOscalAp(benchmark, baseOpts());
    const b = buildOscalAp(benchmark, baseOpts());
    // last-modified is the only volatile field.
    a.doc['assessment-plan'].metadata['last-modified'] = '';
    b.doc['assessment-plan'].metadata['last-modified'] = '';
    expect(JSON.stringify(a.doc)).toBe(JSON.stringify(b.doc));
  });
});

describe('OSCAL Assessment Plan emitter — emitOscalAp (disk)', () => {
  it('writes ap.json + ap.xml to outDir + validates against the schema', () => {
    const d = tmp();
    const r = emitOscalAp(baseOpts({ outDir: d }));
    expect(existsSync(r.path)).toBe(true);
    expect(r.xml_path).toBeDefined();
    expect(existsSync(r.xml_path!)).toBe(true);
    const v = validateOscalFile(r.path, 'assessment-plan');
    if (!v.valid) throw new Error(`AP file invalid:\n${v.errors.slice(0, 8).join('\n')}`);
    expect(v.valid).toBe(true);
    const xml = readFileSync(r.xml_path!, 'utf8');
    expect(xml).toContain('<assessment-plan');
  });

  it('respects CLOUD_EVIDENCE_DISABLE_OSCAL_XML=1', () => {
    const d = tmp();
    const prev = process.env.CLOUD_EVIDENCE_DISABLE_OSCAL_XML;
    process.env.CLOUD_EVIDENCE_DISABLE_OSCAL_XML = '1';
    try {
      const r = emitOscalAp(baseOpts({ outDir: d }));
      expect(r.xml_path).toBeUndefined();
    } finally {
      if (prev === undefined) delete process.env.CLOUD_EVIDENCE_DISABLE_OSCAL_XML;
      else process.env.CLOUD_EVIDENCE_DISABLE_OSCAL_XML = prev;
    }
  });

  it('writes to a custom outPath when provided', () => {
    const d = tmp();
    const customPath = join(d, 'custom-ap.json');
    const r = emitOscalAp(baseOpts({ outDir: d, outPath: customPath }));
    expect(r.path).toBe(customPath);
    expect(existsSync(customPath)).toBe(true);
  });
});
