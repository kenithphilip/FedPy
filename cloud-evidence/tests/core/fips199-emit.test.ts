/**
 * Tests for core/fips199-emit.ts — LOOP-C.C5 FIPS 199 categorization worksheet (RA-2).
 *
 * The 12 numbered tests below are the per-slice §8 contract; three extra tests
 * exercise the SP 800-60 V2 unknown-code warning, the sample fixture round-trip,
 * and the structured log event.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import {
  emitFips199Docx, renderFips199Docx, buildFips199BodyXml, computeOverallSC,
  validateInformationType, impactToken, overallSystemLevel, Fips199ImpactError,
  type Fips199EmitOptions, type InformationType,
} from '../../core/fips199-emit.ts';
import { log } from '../../core/log.ts';

const FIXTURE_DIR = resolve(import.meta.dirname ?? '', 'fixtures/fips199');

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-fips199-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  vi.restoreAllMocks();
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

const TYPES_MMM: InformationType[] = [
  { code: 'C.3.5.1', name: 'System Development', confidentiality: 'moderate', integrity: 'moderate', availability: 'low', rationale: 'dev pipelines' },
  { code: 'C.3.5.5', name: 'Information Security', confidentiality: 'moderate', integrity: 'moderate', availability: 'moderate', rationale: 'security config' },
  { code: 'C.3.5.8', name: 'System and Network Monitoring', confidentiality: 'low', integrity: 'moderate', availability: 'moderate', rationale: 'telemetry' },
];

function baseOpts(over: Partial<Fips199EmitOptions> = {}): Fips199EmitOptions {
  return { outDir: '/nonexistent-fips199-dir', runId: 'r-fips199-test', frmrVersion: '0.9.43-beta', ...over };
}

/** Every required-for-signature operator field supplied. */
function fullOpts(dir: string, over: Partial<Fips199EmitOptions> = {}): Fips199EmitOptions {
  return baseOpts({
    outDir: dir,
    systemName: 'Acme Platform', systemId: 'acme-prod-1', cspOrganization: 'Acme Corp',
    informationTypes: TYPES_MMM,
    overallConfidentialityRationale: 'Confidentiality is moderate.',
    overallIntegrityRationale: 'Integrity is moderate.',
    overallAvailabilityRationale: 'Availability is moderate.',
    categorizationApprover: { name: 'Alex AO', role: 'Authorizing Official', org: 'Agency', date: '2026-07-07' },
    ...over,
  });
}

/** Write an OSCAL SSP (real per-objective shape) into <dir>/ssp.json. */
function writeSsp(dir: string, level: 'low' | 'moderate' | 'high', objectives?: { c: string; i: string; a: string }): void {
  const obj = objectives ?? { c: level, i: level, a: level };
  writeFileSync(join(dir, 'ssp.json'), JSON.stringify({
    'system-security-plan': {
      'system-characteristics': {
        'security-sensitivity-level': `fips-199-${level}`,
        'security-impact-level': {
          'security-objective-confidentiality': `fips-199-${obj.c}`,
          'security-objective-integrity': `fips-199-${obj.i}`,
          'security-objective-availability': `fips-199-${obj.a}`,
        },
      },
    },
  }));
}

// ── Test 1 ──
it('emits 6 sections in order with FIPS 199 §3 verbatim quotes', () => {
  const { xml } = buildFips199BodyXml(fullOpts(tmp()));
  const idx = (s: string) => xml.indexOf(s);
  expect(idx('1. Introduction')).toBeGreaterThan(-1);
  expect(idx('2. Methodology')).toBeGreaterThan(idx('1. Introduction'));
  expect(idx('3. Information Types Identified')).toBeGreaterThan(idx('2. Methodology'));
  expect(idx('4. System Security Categorization')).toBeGreaterThan(idx('3. Information Types Identified'));
  expect(idx('5. Categorization Rationale')).toBeGreaterThan(idx('4. System Security Categorization'));
  expect(idx('6. Approval Signatures')).toBeGreaterThan(idx('5. Categorization Rationale'));
  // Verbatim FIPS 199 §3 impact definitions + loss definitions.
  expect(xml).toContain('could be expected to have a limited adverse effect on organizational operations');
  expect(xml).toContain('could be expected to have a serious adverse effect on organizational operations');
  expect(xml).toContain('could be expected to have a severe or catastrophic adverse effect on organizational operations');
  expect(xml).toContain('A loss of confidentiality is the unauthorized disclosure of information.');
});

// ── Test 2 ──
it('computeOverallSC takes the high-water-mark across all info types', () => {
  const sc = computeOverallSC(TYPES_MMM);
  expect(sc).toEqual({ c: 'moderate', i: 'moderate', a: 'moderate' });
  expect(overallSystemLevel(sc)).toBe('moderate');
  const withHigh = computeOverallSC([
    ...TYPES_MMM,
    { code: 'C.3.5.6', name: 'Record Retention', confidentiality: 'high', integrity: 'low', availability: 'low', rationale: 'r' },
  ]);
  expect(withHigh).toEqual({ c: 'high', i: 'moderate', a: 'moderate' });
  expect(overallSystemLevel(withHigh)).toBe('high');
});

// ── Test 3 ──
it('computeOverallSC handles c=n/a per FIPS 199 (only for confidentiality)', () => {
  const allNa: InformationType[] = [
    { code: 'C.2.8', name: 'General Government', confidentiality: 'n/a', integrity: 'low', availability: 'low', rationale: 'public data' },
    { code: 'C.2.6', name: 'Public Affairs', confidentiality: 'n/a', integrity: 'moderate', availability: 'low', rationale: 'public data' },
  ];
  const sc = computeOverallSC(allNa);
  expect(sc.c).toBe('n/a');
  expect(sc.i).toBe('moderate');
  expect(sc.a).toBe('low');
  // A mix: one n/a, one low → high-water-mark ignores the n/a.
  const mix = computeOverallSC([
    { code: 'C.2.8', name: 'General Government', confidentiality: 'n/a', integrity: 'low', availability: 'low', rationale: 'r' },
    { code: 'C.3.5.1', name: 'System Development', confidentiality: 'low', integrity: 'low', availability: 'low', rationale: 'r' },
  ]);
  expect(mix.c).toBe('low');
});

// ── Test 4 ──
it('SC formula displays as {(confidentiality, MODERATE), (integrity, LOW), (availability, LOW)} when computed', () => {
  const types: InformationType[] = [
    { code: 'C.3.5.1', name: 'System Development', confidentiality: 'moderate', integrity: 'low', availability: 'low', rationale: 'r' },
  ];
  const { xml } = buildFips199BodyXml(fullOpts(tmp(), { informationTypes: types }));
  expect(xml).toContain('(confidentiality, MODERATE), (integrity, LOW), (availability, LOW)');
});

// ── Test 5 ──
it('emits REQUIRES-OPERATOR-INPUT row + SP 800-60 V2 selection note when no information types supplied', () => {
  const { xml, stats } = buildFips199BodyXml(baseOpts({ informationTypes: [] }));
  expect(stats.information_type_count).toBe(0);
  expect(stats.overall_level).toBe('n/a');
  expect(xml).toContain('REQUIRES-OPERATOR-INPUT');
  expect(xml).toContain('NIST SP 800-60 Vol. 2 Rev. 1 catalogue');
  expect(stats.requires_operator_input).toContain('informationTypes (config.yaml: fips199.information_types[] or --fips199-info-type)');
});

// ── Test 6 ──
it('flags MISMATCH when SSP security-impact-level disagrees with worksheet overall SC', () => {
  const dir = tmp();
  writeSsp(dir, 'low'); // SSP says low; worksheet computes moderate
  const { xml, stats } = buildFips199BodyXml(fullOpts(dir));
  expect(stats.ssp_crossref).toBe('mismatch');
  expect(xml).toContain('MISMATCH');
});

// ── Test 7 ──
it('flags CONSISTENT when SSP matches', () => {
  const dir = tmp();
  writeSsp(dir, 'moderate'); // SSP objectives moderate/moderate/moderate == worksheet
  const { xml, stats } = buildFips199BodyXml(fullOpts(dir));
  expect(stats.ssp_crossref).toBe('consistent');
  expect(xml).toContain('CONSISTENT');
});

// ── Test 8 ──
it('rejects information type with C+I+A all "n/a" (invalid per FIPS 199)', () => {
  const bad = { code: 'C.2.8', name: 'General Government', confidentiality: 'n/a', integrity: 'n/a', availability: 'n/a', rationale: 'r' } as unknown as InformationType;
  expect(() => validateInformationType(bad)).toThrow(Fips199ImpactError);
  expect(() => computeOverallSC([bad])).toThrow(/integrity/);
});

// ── Test 9 ──
it('rejects unknown impact level value', () => {
  const bad = { code: 'C.3.5.1', name: 'System Development', confidentiality: 'critical', integrity: 'low', availability: 'low', rationale: 'r' } as unknown as InformationType;
  expect(() => validateInformationType(bad)).toThrow(Fips199ImpactError);
  expect(() => buildFips199BodyXml(baseOpts({ informationTypes: [bad] }))).toThrow(/invalid confidentiality/);
});

// ── Test 10 ──
it('writes to outPath when supplied', () => {
  const dir = tmp();
  const outPath = join(dir, 'custom-fips199.docx');
  const r = emitFips199Docx(fullOpts(dir, { outPath }));
  expect(r.path).toBe(outPath);
  expect(existsSync(outPath)).toBe(true);
  expect(r.bytes).toBeGreaterThan(0);
});

// ── Test 11 ──
it('deterministic output (same inputs → byte-identical .docx)', () => {
  const dir = tmp();
  const a = renderFips199Docx(fullOpts(dir));
  const b = renderFips199Docx(fullOpts(dir));
  expect(Buffer.compare(a.buffer, b.buffer)).toBe(0);
});

// ── Test 12 ──
it('ready_for_signature requires ≥1 info type + 3 rationales + approver', () => {
  const dir = tmp();
  expect(buildFips199BodyXml(fullOpts(dir)).stats.ready_for_signature).toBe(true);
  // Drop the approver → not ready.
  expect(buildFips199BodyXml(fullOpts(dir, { categorizationApprover: undefined })).stats.ready_for_signature).toBe(false);
  // Drop a rationale → not ready.
  expect(buildFips199BodyXml(fullOpts(dir, { overallIntegrityRationale: undefined })).stats.ready_for_signature).toBe(false);
  // Zero info types → not ready.
  expect(buildFips199BodyXml(fullOpts(dir, { informationTypes: [] })).stats.ready_for_signature).toBe(false);
});

// ── Extra 13: unknown SP 800-60 code → warn + accept (Q3) ──
it('warns (UNKNOWN-TYPE-CODE) but accepts a code outside the SP 800-60 V2 subset', () => {
  const types: InformationType[] = [
    { code: 'D.99.9', name: 'Some Mission Type', confidentiality: 'moderate', integrity: 'moderate', availability: 'low', rationale: 'agency mission data' },
  ];
  const { xml, stats } = buildFips199BodyXml(fullOpts(tmp(), { informationTypes: types }));
  expect(stats.unknown_type_codes).toEqual(['D.99.9']);
  expect(stats.information_type_count).toBe(1); // accepted, not dropped
  expect(xml).toContain('UNKNOWN-TYPE-CODE');
});

// ── Extra 14: the sample fixture maps to a ready-for-signature worksheet ──
it('the info-types.sample.yaml fixture maps to a ready-for-signature worksheet', () => {
  const parsed: any = parseYaml(readFileSync(join(FIXTURE_DIR, 'info-types.sample.yaml'), 'utf8'));
  const dir = tmp();
  writeSsp(dir, 'moderate');
  const stats = buildFips199BodyXml(fullOpts(dir, {
    informationTypes: parsed.information_types,
    overallConfidentialityRationale: parsed.c_rationale,
    overallIntegrityRationale: parsed.i_rationale,
    overallAvailabilityRationale: parsed.a_rationale,
    categorizationApprover: parsed.approver,
  })).stats;
  expect(stats.ready_for_signature).toBe(true);
  expect(stats.overall_level).toBe('moderate');
  expect(stats.ssp_crossref).toBe('consistent');
  expect(stats.unknown_type_codes).toEqual([]);
});

// ── Extra 15: emits a structured log event with counts ──
it('emits a structured log event with information_type_count + overall_level', () => {
  const dir = tmp();
  const spy = vi.spyOn(log, 'info').mockImplementation(() => {});
  emitFips199Docx(fullOpts(dir));
  const evt = spy.mock.calls.map((c) => c[0]).find((a: any) => a?.event === 'fips199.emitted');
  expect(evt).toBeTruthy();
  expect((evt as any).information_type_count).toBe(3);
  expect((evt as any).overall_level).toBe('moderate');
  expect(typeof (evt as any).bytes).toBe('number');
});

describe('impactToken', () => {
  it('renders NOT APPLICABLE for n/a and uppercase for levels', () => {
    expect(impactToken('n/a')).toBe('NOT APPLICABLE');
    expect(impactToken('low')).toBe('LOW');
    expect(impactToken('moderate')).toBe('MODERATE');
    expect(impactToken('high')).toBe('HIGH');
  });
});
