/**
 * Tests for core/anomaly.ts — anomaly detection vs rolling baseline.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { detectAnomalies } from '../../core/anomaly.ts';
import type { EvidenceFile, Finding } from '../../core/envelope.ts';

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(resolve(tmpdir(), 'cev-anom-'));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

function mkFinding(rule: string, passed: boolean): Finding {
  return {
    rule, passed, severity: passed ? 'info' : 'high',
    current_state: { summary: 'x', observations: null },
    target_state: { summary: 'x', rationale: 'x' },
    ...(passed ? {} : {
      gap: { description: 'x', affected_resources: [] },
      remediation: { summary: 'x', options: [{ approach: 'x', mechanism: 'cli', steps: ['x'] }] },
    }),
  };
}

function writeKsi(name: string, ksi_id: string, findings: Finding[]): void {
  const ef: EvidenceFile = {
    ksi_id, ksi_name: ksi_id, ksi_statement: 'x', scope: 'CLOUD',
    frmr_version: '2025-06.r1', run_id: 'r', collected_at: '2026-05-27T12:00:00Z',
    providers: [{ provider: 'aws', account_id: '111122223333', evidence: [], findings }],
    rollup: {
      pass: findings.every((f) => f.passed),
      passing_findings: findings.filter((f) => f.passed).length,
      failing_findings: findings.filter((f) => !f.passed).length,
      warnings: [], missing_evidence: [], alternatives_in_play: 0,
    },
  };
  writeFileSync(resolve(tmp, name), JSON.stringify(ef));
}

function appendHistoryLine(snap: any): void {
  const path = resolve(tmp, 'anomaly-history.jsonl');
  const existing = existsSync(path) ? readFileSync(path, 'utf8') : '';
  writeFileSync(path, existing + JSON.stringify(snap) + '\n');
}

describe('detectAnomalies', () => {
  it('returns no anomalies on a clean first run with no history', () => {
    writeKsi('KSI-IAM-MFA.json', 'KSI-IAM-MFA', [mkFinding('r1', true)]);
    const r = detectAnomalies({ outDir: tmp, runId: 'run-1', finishedAt: '2026-05-27T12:00:00Z' });
    // First run: every rule is "new" — so we DO see new_rule anomalies but no
    // regressions or spikes. Verify the type breakdown.
    expect(r.summary.by_type.new_rule).toBe(1);
    expect(r.summary.by_type.persistent_regression).toBeUndefined();
    expect(r.summary.by_type.spike).toBeUndefined();
  });

  it('detects persistent_regression (failing in current + at least 1 prior run)', () => {
    appendHistoryLine({
      run_id: 'prev', finished_at: '2026-05-26T12:00:00Z',
      findings: [{ ksi_id: 'KSI-IAM-MFA', rule: 'r1', passed: false, severity: 'high' }],
    });
    writeKsi('KSI-IAM-MFA.json', 'KSI-IAM-MFA', [mkFinding('r1', false)]);
    const r = detectAnomalies({ outDir: tmp, runId: 'curr', finishedAt: '2026-05-27T12:00:00Z' });
    const reg = r.anomalies.filter((a) => a.type === 'persistent_regression');
    expect(reg.length).toBe(1);
    expect(reg[0].rule).toBe('r1');
  });

  it('detects new_rule for a finding never seen in history', () => {
    appendHistoryLine({
      run_id: 'prev', finished_at: '2026-05-26T12:00:00Z',
      findings: [{ ksi_id: 'KSI-IAM-MFA', rule: 'old_rule', passed: true, severity: 'info' }],
    });
    writeKsi('KSI-IAM-MFA.json', 'KSI-IAM-MFA', [
      mkFinding('old_rule', true),
      mkFinding('brand_new_rule', false),
    ]);
    const r = detectAnomalies({ outDir: tmp, runId: 'curr', finishedAt: '2026-05-27T12:00:00Z' });
    const nuevo = r.anomalies.filter((a) => a.type === 'new_rule');
    expect(nuevo.length).toBe(1);
    expect(nuevo[0].rule).toBe('brand_new_rule');
  });

  it('detects spike when domain failing count exceeds window max + 1', () => {
    // Baseline: each prior run has 0-1 failing finding in IAM
    for (let i = 0; i < 5; i++) {
      appendHistoryLine({
        run_id: `prev-${i}`, finished_at: `2026-05-2${i}T12:00:00Z`,
        findings: [
          { ksi_id: 'KSI-IAM-MFA', rule: 'r1', passed: true, severity: 'info' },
        ],
      });
    }
    // Current: 3 failing findings across IAM (well above max+1 = 1)
    writeKsi('KSI-IAM-MFA.json', 'KSI-IAM-MFA', [mkFinding('r1', false), mkFinding('r2', false)]);
    writeKsi('KSI-IAM-AAM.json', 'KSI-IAM-AAM', [mkFinding('r3', false)]);
    const r = detectAnomalies({ outDir: tmp, runId: 'curr', finishedAt: '2026-05-27T12:00:00Z' });
    const spikes = r.anomalies.filter((a) => a.type === 'spike');
    expect(spikes.length).toBeGreaterThanOrEqual(1);
    expect(spikes[0].current_value).toBeGreaterThan(spikes[0].baseline_max!);
  });

  it('detects ksi_full_regression when KSI flips from all-pass to any-fail', () => {
    appendHistoryLine({
      run_id: 'prev', finished_at: '2026-05-26T12:00:00Z',
      findings: [
        { ksi_id: 'KSI-IAM-MFA', rule: 'r1', passed: true, severity: 'info' },
        { ksi_id: 'KSI-IAM-MFA', rule: 'r2', passed: true, severity: 'info' },
      ],
    });
    writeKsi('KSI-IAM-MFA.json', 'KSI-IAM-MFA', [
      mkFinding('r1', false),
      mkFinding('r2', true),
    ]);
    const r = detectAnomalies({ outDir: tmp, runId: 'curr', finishedAt: '2026-05-27T12:00:00Z' });
    const regressions = r.anomalies.filter((a) => a.type === 'ksi_full_regression');
    expect(regressions.length).toBe(1);
    expect(regressions[0].ksi_id).toBe('KSI-IAM-MFA');
  });

  it('appends current run to history so the next call has more context', () => {
    writeKsi('KSI-IAM-MFA.json', 'KSI-IAM-MFA', [mkFinding('r1', true)]);
    detectAnomalies({ outDir: tmp, runId: 'r1', finishedAt: '2026-05-27T12:00:00Z' });
    const before = readFileSync(resolve(tmp, 'anomaly-history.jsonl'), 'utf8').split('\n').filter(Boolean).length;
    detectAnomalies({ outDir: tmp, runId: 'r2', finishedAt: '2026-05-27T12:01:00Z' });
    const after = readFileSync(resolve(tmp, 'anomaly-history.jsonl'), 'utf8').split('\n').filter(Boolean).length;
    expect(after).toBe(before + 1);
  });

  it('writes anomaly-report.json with the summary', () => {
    writeKsi('KSI-IAM-MFA.json', 'KSI-IAM-MFA', [mkFinding('r1', false)]);
    detectAnomalies({ outDir: tmp, runId: 'r', finishedAt: '2026-05-27T12:00:00Z' });
    const report = JSON.parse(readFileSync(resolve(tmp, 'anomaly-report.json'), 'utf8'));
    expect(report.current_run_id).toBe('r');
    expect(report.anomalies).toBeDefined();
    expect(report.summary.total).toBeGreaterThanOrEqual(0);
  });
});
