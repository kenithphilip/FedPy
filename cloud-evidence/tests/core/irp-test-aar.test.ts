/**
 * Tests for core/irp-test-aar.ts — LOOP-C.C3 Incident Response Test
 * After-Action Report (IR-3).
 *
 * Verifies (10 tests per C.C3.md §8):
 *   1. Produces the 7-section AAR structure with the 5-phase timing matrix.
 *   2. Timing-metrics table reflects detection→recovery elapsed time per scenario.
 *   3. Flags scenarios with outcome=fail in the §4 Outcomes summary.
 *   4. Lessons-learned of severity=high gets a POA&M footer note.
 *   5. Emits REQUIRES-OPERATOR-INPUT row when scenarios[] is empty.
 *   6. Renders participants verbatim.
 *   7. Sign-off block has 4 rows with REQUIRES-OPERATOR-INPUT signature/date cells.
 *   8. Rejects scenarios with a negative timing value.
 *   9. Writes to outPath when supplied.
 *  10. Deterministic output for identical inputs + a frozen testDate.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  emitIrpTestAarDocx, renderIrpTestAarDocx, buildIrpTestAarBodyXml,
  IrpAarValidationError,
  type IrpTestAarOptions, type IrpTestScenario,
} from '../../core/irp-test-aar.ts';
import { log } from '../../core/log.ts';

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-irp-aar-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  vi.restoreAllMocks();
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

function baseOpts(over: Partial<IrpTestAarOptions> = {}): IrpTestAarOptions {
  return { outDir: '/nonexistent-irp-aar-dir', runId: 'r-irp-aar-test', ...over };
}

function scenario(over: Partial<IrpTestScenario> = {}): IrpTestScenario {
  return {
    id: 'S1', description: 'Credential-stuffing against the authenticated surface', severity: 'high',
    detection_time_minutes: 12, response_time_minutes: 25, containment_time_minutes: 40,
    eradication_time_minutes: 70, recovery_time_minutes: 95,
    outcome: 'pass', ...over,
  };
}

/** Extract ordered Heading1 titles from document.xml. */
function heading1Titles(xml: string): string[] {
  return [...xml.matchAll(/<w:pStyle w:val="Heading1"\/><\/w:pPr><w:r><w:t xml:space="preserve">([^<]*)<\/w:t>/g)].map((m) => m[1]!);
}

describe('IRP AAR emitter — structure', () => {
  it('produces the 7-section AAR structure with the 5-phase timing matrix', () => {
    const { xml } = buildIrpTestAarBodyXml(baseOpts({ testDate: '2026-05-01', testType: 'tabletop', scenarios: [scenario()] }));
    const titles = heading1Titles(xml);
    for (let i = 0; i < 7; i++) expect(titles[i]!.startsWith(`${i + 1}.`)).toBe(true);
    expect(titles[0]).toContain('Test Overview');
    expect(titles[2]).toContain('Timing Metrics');
    expect(titles[6]).toContain('Sign-off');
    // 5-phase matrix header present.
    for (const phase of ['Detection (min)', 'Response (min)', 'Containment (min)', 'Eradication (min)', 'Recovery (min)']) {
      expect(xml).toContain(phase);
    }
  });
});

describe('IRP AAR emitter — timing + outcomes', () => {
  it('timing-metrics table reflects detection→recovery elapsed time per scenario', () => {
    const { xml, stats } = buildIrpTestAarBodyXml(baseOpts({
      scenarios: [scenario({ detection_time_minutes: 12, response_time_minutes: 25, containment_time_minutes: 40, eradication_time_minutes: 70, recovery_time_minutes: 95 })],
    }));
    expect(stats.scenario_count).toBe(1);
    for (const n of ['12', '25', '40', '70', '95']) expect(xml).toContain(`>${n}<`);
  });

  it('flags scenarios with outcome=fail in the §4 Outcomes summary', () => {
    const { xml, stats } = buildIrpTestAarBodyXml(baseOpts({
      scenarios: [scenario({ id: 'S9', outcome: 'fail' })],
    }));
    expect(stats.failed_scenario_count).toBe(1);
    expect(xml).toContain('FAILED scenarios requiring corrective action');
    expect(xml).toContain('S9');
  });

  it('emits a REQUIRES-OPERATOR-INPUT row when scenarios[] is empty', () => {
    const { xml, stats } = buildIrpTestAarBodyXml(baseOpts());
    expect(stats.scenario_count).toBe(0);
    expect(xml).toContain('Operator must populate scenarios[]');
    expect(xml).toContain('REQUIRES-OPERATOR-INPUT');
    expect(stats.requires_operator_input).toContain('scenarios');
  });
});

describe('IRP AAR emitter — lessons learned + POA&M', () => {
  it('lessons-learned of severity=high gets a POA&M footer note', () => {
    const { xml, stats } = buildIrpTestAarBodyXml(baseOpts({
      lessonsLearned: [{ id: 'L1', phase: 'respond', finding: 'On-call paging delayed', severity: 'high', recommendation: 'Tune escalation', owner: 'SRE', due_date: '2026-06-01' }],
    }));
    expect(stats.poam_candidate_count).toBe(1);
    expect(xml).toContain('MUST be filed as POA&amp;M');
    expect(xml).toContain('L1');
  });
});

describe('IRP AAR emitter — participants + sign-off', () => {
  it('renders participants verbatim', () => {
    const { xml } = buildIrpTestAarBodyXml(baseOpts({
      participants: [{ role: 'Incident Commander', name: 'Sam Okafor', org: 'Acme' }],
    }));
    expect(xml).toContain('Sam Okafor');
    expect(xml).toContain('Incident Commander');
  });

  it('sign-off block has 4 rows with REQUIRES-OPERATOR-INPUT signature/date cells', () => {
    const { xml } = buildIrpTestAarBodyXml(baseOpts());
    for (const role of ['Test Coordinator', 'IR Lead', 'System Owner', '3PAO Observer']) {
      expect(xml).toContain(role);
    }
    expect(xml).toContain('the toolkit never auto-signs a human');
    expect(xml).toContain('REQUIRES-OPERATOR-INPUT');
  });
});

describe('IRP AAR emitter — validation', () => {
  it('rejects scenarios with a negative timing value', () => {
    expect(() => buildIrpTestAarBodyXml(baseOpts({
      scenarios: [scenario({ containment_time_minutes: -1 })],
    }))).toThrow(IrpAarValidationError);
  });
});

describe('IRP AAR emitter — disk + determinism', () => {
  it('writes to outPath when supplied', () => {
    const d = tmp();
    const outPath = join(d, 'custom-irp-aar.docx');
    const spy = vi.spyOn(log, 'info').mockImplementation(() => log as any);
    const r = emitIrpTestAarDocx(baseOpts({ outDir: d, outPath, testDate: '2026-05-01', testType: 'functional', scenarios: [scenario()] }));
    expect(r.path).toBe(outPath);
    expect(existsSync(outPath)).toBe(true);
    expect(r.bytes).toBeGreaterThan(6000);
    expect(spy).toHaveBeenCalledWith(expect.objectContaining({ event: 'irp-test-aar.emitted', scenario_count: 1 }));
  });

  it('produces deterministic output for identical inputs + a frozen testDate', () => {
    const opts = baseOpts({ testDate: '2026-05-01', testType: 'red-team', scenarios: [scenario()] });
    const a = renderIrpTestAarDocx(opts);
    const b = renderIrpTestAarDocx(opts);
    expect(Buffer.compare(a.buffer, b.buffer)).toBe(0);
  });
});
