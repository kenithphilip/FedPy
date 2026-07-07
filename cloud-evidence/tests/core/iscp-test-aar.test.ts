/**
 * Tests for core/iscp-test-aar.ts — LOOP-C.C2 Contingency Plan Test
 * After-Action Report (CP-4).
 *
 * Verifies (10 tests per C.C2.md §8):
 *   1. Produces the 6-section AAR structure.
 *   2. Scenarios table reflects RTO/RPO target vs actual.
 *   3. Flags scenarios with outcome=fail in the §3 summary.
 *   4. Lessons-learned of severity=high gets a POA&M footer note.
 *   5. Emits REQUIRES-OPERATOR-INPUT row when scenarios[] is empty.
 *   6. Renders participants verbatim.
 *   7. Sign-off block has 4 rows with REQUIRES-OPERATOR-INPUT signature/date cells.
 *   8. Rejects scenarios with a negative RTO actual.
 *   9. Writes to outPath when supplied.
 *  10. Deterministic output for identical inputs + a frozen testDate.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  emitIscpTestAarDocx, renderIscpTestAarDocx, buildIscpTestAarBodyXml,
  IscpAarValidationError,
  type IscpTestAarOptions, type IscpTestScenario,
} from '../../core/iscp-test-aar.ts';
import { log } from '../../core/log.ts';

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-aar-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  vi.restoreAllMocks();
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

function baseOpts(over: Partial<IscpTestAarOptions> = {}): IscpTestAarOptions {
  return { outDir: '/nonexistent-aar-dir', runId: 'r-aar-test', ...over };
}

function scenario(over: Partial<IscpTestScenario> = {}): IscpTestScenario {
  return {
    id: 'S1', description: 'Primary region failover',
    rto_target_hours: 4, rto_actual_hours: 3,
    rpo_target_hours: 1, rpo_actual_hours: 1,
    outcome: 'pass', ...over,
  };
}

/** Extract ordered Heading1 titles from document.xml. */
function heading1Titles(xml: string): string[] {
  return [...xml.matchAll(/<w:pStyle w:val="Heading1"\/><\/w:pPr><w:r><w:t xml:space="preserve">([^<]*)<\/w:t>/g)].map((m) => m[1]!);
}

describe('AAR emitter — structure', () => {
  it('produces the 6-section AAR structure', () => {
    const { xml } = buildIscpTestAarBodyXml(baseOpts({ testDate: '2026-05-01', testType: 'tabletop' }));
    const titles = heading1Titles(xml);
    for (let i = 0; i < 6; i++) expect(titles[i]!.startsWith(`${i + 1}.`)).toBe(true);
    expect(titles[0]).toContain('Test Overview');
    expect(titles[1]).toContain('Scenarios Executed');
    expect(titles[5]).toContain('Sign-off');
  });
});

describe('AAR emitter — scenarios + results', () => {
  it('scenarios table reflects RTO/RPO target vs actual', () => {
    const { xml, stats } = buildIscpTestAarBodyXml(baseOpts({
      scenarios: [scenario({ rto_target_hours: 4, rto_actual_hours: 6, rpo_target_hours: 2, rpo_actual_hours: 1 })],
    }));
    expect(stats.scenario_count).toBe(1);
    expect(xml).toContain('Primary region failover');
    // target + actual columns present.
    for (const n of ['4', '6', '2', '1']) expect(xml).toContain(`>${n}<`);
  });

  it('flags scenarios with outcome=fail in the §3 summary', () => {
    const { xml, stats } = buildIscpTestAarBodyXml(baseOpts({
      scenarios: [scenario({ id: 'S9', outcome: 'fail' })],
    }));
    expect(stats.failed_scenario_count).toBe(1);
    expect(xml).toContain('FAILED scenarios requiring corrective action');
    expect(xml).toContain('S9');
  });

  it('emits a REQUIRES-OPERATOR-INPUT row when scenarios[] is empty', () => {
    const { xml, stats } = buildIscpTestAarBodyXml(baseOpts());
    expect(stats.scenario_count).toBe(0);
    expect(xml).toContain('Operator must populate scenarios[]');
    expect(xml).toContain('REQUIRES-OPERATOR-INPUT');
    expect(stats.requires_operator_input).toContain('scenarios');
  });
});

describe('AAR emitter — lessons learned + POA&M', () => {
  it('lessons-learned of severity=high gets a POA&M footer note', () => {
    const { xml, stats } = buildIscpTestAarBodyXml(baseOpts({
      lessonsLearned: [{ id: 'L1', finding: 'Failover runbook stale', severity: 'high', recommendation: 'Update runbook', owner: 'SRE', due_date: '2026-06-01' }],
    }));
    expect(stats.poam_candidate_count).toBe(1);
    // POA&M renders XML-escaped as "POA&amp;M".
    expect(xml).toContain('MUST be filed as POA&amp;M');
    expect(xml).toContain('L1');
  });
});

describe('AAR emitter — participants + sign-off', () => {
  it('renders participants verbatim', () => {
    const { xml } = buildIscpTestAarBodyXml(baseOpts({
      participants: [{ role: 'Incident Commander', name: 'Sam Okafor', org: 'Acme' }],
    }));
    expect(xml).toContain('Sam Okafor');
    expect(xml).toContain('Incident Commander');
  });

  it('sign-off block has 4 rows with REQUIRES-OPERATOR-INPUT signature/date cells', () => {
    const { xml } = buildIscpTestAarBodyXml(baseOpts());
    for (const role of ['Test Coordinator', 'IT Director', 'System Owner', '3PAO Observer']) {
      expect(xml).toContain(role);
    }
    // The sign-off narrative names the out-of-band signature handling (never auto-signed).
    expect(xml).toContain('the toolkit never auto-signs a human');
    expect(xml).toContain('REQUIRES-OPERATOR-INPUT');
  });
});

describe('AAR emitter — validation', () => {
  it('rejects scenarios with a negative RTO actual', () => {
    expect(() => buildIscpTestAarBodyXml(baseOpts({
      scenarios: [scenario({ rto_actual_hours: -1 })],
    }))).toThrow(IscpAarValidationError);
  });
});

describe('AAR emitter — disk + determinism', () => {
  it('writes to outPath when supplied', () => {
    const d = tmp();
    const outPath = join(d, 'custom-aar.docx');
    const spy = vi.spyOn(log, 'info').mockImplementation(() => log as any);
    const r = emitIscpTestAarDocx(baseOpts({ outDir: d, outPath, testDate: '2026-05-01', testType: 'functional', scenarios: [scenario()] }));
    expect(r.path).toBe(outPath);
    expect(existsSync(outPath)).toBe(true);
    expect(r.bytes).toBeGreaterThan(6000);
    expect(spy).toHaveBeenCalledWith(expect.objectContaining({ event: 'iscp-test-aar.emitted', scenario_count: 1 }));
  });

  it('produces deterministic output for identical inputs + a frozen testDate', () => {
    const opts = baseOpts({ testDate: '2026-05-01', testType: 'tabletop', scenarios: [scenario()] });
    const a = renderIscpTestAarDocx(opts);
    const b = renderIscpTestAarDocx(opts);
    expect(Buffer.compare(a.buffer, b.buffer)).toBe(0);
  });
});
