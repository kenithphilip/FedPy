/**
 * Tests for core/pva-collector.ts — focus on the run-summary enrichment added
 * in the Batch 2 audit: explicit failed_ksis + parse_error tracking.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { buildPvaEvidence } from '../../core/pva-collector.ts';

let dir: string;

function writeKsi(id: string, pass: boolean): void {
  const ev = {
    ksi_id: id,
    ksi_name: id,
    ksi_statement: 'x',
    scope: 'CLOUD',
    frmr_version: 'v',
    run_id: 'r',
    collected_at: '2026-05-27T12:00:00Z',
    providers: [{ provider: 'aws', account_id: '1', evidence: [], findings: [], warnings: [] }],
    rollup: { pass, passing_findings: pass ? 1 : 0, failing_findings: pass ? 0 : 1, warnings: [], missing_evidence: [], alternatives_in_play: 0 },
  };
  writeFileSync(resolve(dir, `${id}.json`), JSON.stringify(ev));
}

beforeEach(() => { dir = mkdtempSync(resolve(tmpdir(), 'cev-pva-')); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

describe('buildPvaEvidence run summary', () => {
  it('lists failing KSIs explicitly in failed_ksis', () => {
    writeKsi('KSI-IAM-MFA', true);
    writeKsi('KSI-IAM-AAM', false);
    writeKsi('KSI-CNA-EIS', false);

    const { runSummary } = buildPvaEvidence({ outDir: dir, runId: 'r', startedAt: 's', finishedAt: 'f', frmrVersion: 'v' });
    expect(runSummary.total_ksis).toBe(3);
    expect(runSummary.passed_ksis).toBe(1);
    expect(runSummary.failed_ksis.sort()).toEqual(['KSI-CNA-EIS', 'KSI-IAM-AAM']);
    expect(runSummary.parse_error_ksis).toEqual([]);
  });

  it('records an unparseable evidence file as a failed KSI with a parse error', () => {
    writeKsi('KSI-IAM-MFA', true);
    writeFileSync(resolve(dir, 'KSI-BROKEN.json'), '{ corrupt json');

    const { runSummary } = buildPvaEvidence({ outDir: dir, runId: 'r', startedAt: 's', finishedAt: 'f', frmrVersion: 'v' });
    expect(runSummary.failed_ksis).toContain('KSI-BROKEN');
    expect(runSummary.parse_error_ksis).toContain('KSI-BROKEN');
    const broken = runSummary.ksi_module_results.find((r: any) => r.ksi_id === 'KSI-BROKEN');
    expect(broken?.parse_error).toBeTruthy();
  });
});
