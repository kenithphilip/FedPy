/**
 * Tests for core/crosswalk.ts — NIST↔SOC2/ISO27001/HIPAA mapping.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { mapNistToFrameworks, buildCrosswalkReport, _internal } from '../../core/crosswalk.ts';
import type { EvidenceFile } from '../../core/envelope.ts';

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(resolve(tmpdir(), 'cev-xw-'));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

describe('mapNistToFrameworks', () => {
  it('returns SOC2 / ISO27001 / HIPAA refs for IA-2', () => {
    const m = mapNistToFrameworks('IA-2');
    expect(m.unmapped).toBe(false);
    const fws = m.refs.map((r) => r.framework).sort();
    expect(fws).toEqual(['HIPAA', 'ISO_27001', 'SOC2']);
  });

  it('falls back to parent control for unmapped enhancement', () => {
    // Set up: ensure a control enhancement only the parent has
    // AC-3 is in the catalog with mappings; AC-3(7) is not — should fall back to AC-3
    const m = mapNistToFrameworks('AC-3(7)');
    expect(m.unmapped).toBe(false);
    expect(m.refs.length).toBeGreaterThan(0);
  });

  it('returns unmapped=true for an unknown control', () => {
    const m = mapNistToFrameworks('XX-99');
    expect(m.unmapped).toBe(true);
    expect(m.refs).toHaveLength(0);
  });

  it('NIST_TO_FRAMEWORKS contains all expected control families', () => {
    const families = new Set(Object.keys(_internal.NIST_TO_FRAMEWORKS).map((k) => k.split('-')[0]));
    // At minimum, we need AC, AU, CM, CP, IA, IR, RA, SC, SI
    for (const fam of ['AC', 'AU', 'CM', 'CP', 'IA', 'IR', 'RA', 'SC', 'SI']) {
      expect(families.has(fam), `expected family ${fam} in crosswalk`).toBe(true);
    }
  });
});

function writeKsi(name: string, ef: Partial<EvidenceFile> & { ksi_id: string }): void {
  const full: EvidenceFile = {
    ksi_id: ef.ksi_id,
    ksi_name: ef.ksi_name ?? ef.ksi_id,
    ksi_statement: 'x',
    scope: 'CLOUD',
    frmr_version: '2025-06.r1',
    run_id: 'run-1',
    collected_at: '2026-05-27T12:00:00Z',
    providers: ef.providers ?? [],
    rollup: ef.rollup ?? { pass: true, passing_findings: 0, failing_findings: 0, warnings: [], missing_evidence: [], alternatives_in_play: 0 },
    nist_controls: ef.nist_controls,
  };
  writeFileSync(resolve(tmp, name), JSON.stringify(full));
}

describe('buildCrosswalkReport', () => {
  it('aggregates KSIs into per-framework summaries', () => {
    writeKsi('KSI-IAM-MFA.json', {
      ksi_id: 'KSI-IAM-MFA',
      nist_controls: ['IA-2', 'IA-2(1)'],
      providers: [{
        provider: 'aws', account_id: '111122223333',
        evidence: [],
        findings: [
          { rule: 'r1', passed: false, severity: 'critical',
            current_state: { summary: 'x', observations: null },
            target_state: { summary: 'x', rationale: 'x' },
            gap: { description: 'x', affected_resources: [] },
            remediation: { summary: 'x', options: [{ approach: 'x', mechanism: 'cli', steps: ['x'] }] },
            nist_controls: ['IA-2(2)'],
          },
        ],
      }],
    });
    writeKsi('KSI-MLA-EVC.json', {
      ksi_id: 'KSI-MLA-EVC',
      nist_controls: ['AU-2', 'AU-9'],
      providers: [{
        provider: 'aws', account_id: '111122223333',
        evidence: [],
        findings: [{ rule: 'r2', passed: true, severity: 'high',
          current_state: { summary: 'x', observations: null },
          target_state: { summary: 'x', rationale: 'x' },
        }],
      }],
    });

    const r = buildCrosswalkReport(tmp);
    expect(r.total_ksis_analyzed).toBe(2);
    const soc2 = r.framework_summaries.find((f) => f.framework === 'SOC2')!;
    expect(soc2).toBeTruthy();
    // CC6.1 should reference KSI-IAM-MFA (failing)
    const cc61 = soc2.controls_referenced.find((c) => c.control_id === 'CC6.1');
    expect(cc61?.ksis).toContain('KSI-IAM-MFA');
    expect(cc61?.failing_ksis).toContain('KSI-IAM-MFA');
    // CC7.2 should reference KSI-MLA-EVC (passing — no failing_ksis)
    const cc72 = soc2.controls_referenced.find((c) => c.control_id === 'CC7.2');
    expect(cc72?.ksis).toContain('KSI-MLA-EVC');
    expect(cc72?.failing_ksis).not.toContain('KSI-MLA-EVC');
  });

  it('tracks unmapped NIST controls', () => {
    writeKsi('KSI-FOO.json', {
      ksi_id: 'KSI-FOO',
      nist_controls: ['XX-99', 'IA-2'],
      providers: [],
    });
    const r = buildCrosswalkReport(tmp);
    expect(r.unmapped_nist_controls).toContain('XX-99');
  });

  it('tracks KSIs with no NIST mapping at all', () => {
    writeKsi('KSI-NOMAP.json', {
      ksi_id: 'KSI-NOMAP',
      providers: [],
    });
    const r = buildCrosswalkReport(tmp);
    expect(r.ksis_without_nist).toContain('KSI-NOMAP');
  });

  it('writes crosswalk-report.json to outDir', () => {
    writeKsi('KSI-IAM-MFA.json', {
      ksi_id: 'KSI-IAM-MFA',
      nist_controls: ['IA-2'],
      providers: [],
    });
    buildCrosswalkReport(tmp);
    const f = JSON.parse(readFileSync(resolve(tmp, 'crosswalk-report.json'), 'utf8'));
    expect(f.framework_summaries.length).toBeGreaterThan(0);
    expect(f.generated_at).toBeTruthy();
  });
});
