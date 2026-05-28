/**
 * Tests for core/coverage-check.ts — verifies that silent failures get flagged.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { checkCoverage } from '../../core/coverage-check.ts';
import type { EvidenceFile } from '../../core/envelope.ts';

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(resolve(tmpdir(), 'cev-cov-'));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

function writeKsi(name: string, partial: Partial<EvidenceFile> & { ksi_id: string }): void {
  const ef: EvidenceFile = {
    ksi_id: partial.ksi_id,
    ksi_name: partial.ksi_name ?? partial.ksi_id,
    ksi_statement: 'x',
    scope: 'CLOUD',
    frmr_version: '2025-06.r1',
    run_id: 'run-1',
    collected_at: '2026-05-27T12:00:00Z',
    providers: partial.providers ?? [{
      provider: 'aws',
      account_id: '111122223333',
      region_set: ['us-east-1'],
      evidence: [],
      findings: [{
        rule: 'r1', passed: true, severity: 'info',
        current_state: { summary: 'x', observations: null },
        target_state: { summary: 'x', rationale: 'x' },
      }],
    }],
    rollup: { pass: true, passing_findings: 1, failing_findings: 0, warnings: [], missing_evidence: [], alternatives_in_play: 0 },
  };
  writeFileSync(resolve(tmp, name), JSON.stringify(ef));
}

describe('checkCoverage', () => {
  it('passes cleanly when account, projects, regions, and KSIs all match', () => {
    writeKsi('KSI-IAM-MFA.json', { ksi_id: 'KSI-IAM-MFA' });
    const r = checkCoverage(tmp, {
      awsAccount: '111122223333',
      gcpProjects: [],
      regions: ['us-east-1'],
      expectedKsis: ['KSI-IAM-MFA'],
    });
    expect(r.warnings).toHaveLength(0);
    expect(r.missing_aws).toBe(false);
    expect(r.missing_ksis).toEqual([]);
    expect(r.total_findings).toBe(1);
  });

  it('warns when expected AWS account is not present', () => {
    writeKsi('KSI-IAM-MFA.json', { ksi_id: 'KSI-IAM-MFA' });
    const r = checkCoverage(tmp, {
      awsAccount: '999999999999',
      gcpProjects: [],
    });
    expect(r.missing_aws).toBe(true);
    expect(r.warnings.some((w) => /999999999999/.test(w))).toBe(true);
  });

  it('warns when expected GCP project is not present', () => {
    writeKsi('KSI-IAM-MFA.json', {
      ksi_id: 'KSI-IAM-MFA',
      providers: [{ provider: 'gcp', project_id: 'project-a', evidence: [], findings: [] }],
    });
    const r = checkCoverage(tmp, {
      awsAccount: null,
      gcpProjects: ['project-a', 'project-b'],
    });
    expect(r.missing_gcp_projects).toEqual(['project-b']);
    expect(r.warnings.some((w) => /project-b/.test(w))).toBe(true);
  });

  it('warns when an expected KSI produced no evidence file', () => {
    writeKsi('KSI-IAM-MFA.json', { ksi_id: 'KSI-IAM-MFA' });
    const r = checkCoverage(tmp, {
      awsAccount: '111122223333',
      gcpProjects: [],
      expectedKsis: ['KSI-IAM-MFA', 'KSI-IAM-AAM'],
    });
    expect(r.missing_ksis).toEqual(['KSI-IAM-AAM']);
    expect(r.warnings.some((w) => /KSI-IAM-AAM/.test(w))).toBe(true);
  });

  it('warns when a KSI has zero findings', () => {
    writeKsi('KSI-IAM-MFA.json', {
      ksi_id: 'KSI-IAM-MFA',
      providers: [{
        provider: 'aws', account_id: '111122223333', region_set: ['us-east-1'],
        evidence: [], findings: [],
      }],
    });
    const r = checkCoverage(tmp, {
      awsAccount: '111122223333',
      gcpProjects: [],
    });
    expect(r.ksis_with_zero_findings).toContain('KSI-IAM-MFA');
    expect(r.warnings.some((w) => /0 findings/.test(w))).toBe(true);
  });

  it('warns when an expected region is absent from every region_set', () => {
    writeKsi('KSI-IAM-MFA.json', { ksi_id: 'KSI-IAM-MFA' }); // region_set: us-east-1
    const r = checkCoverage(tmp, {
      awsAccount: '111122223333',
      gcpProjects: [],
      regions: ['us-east-1', 'us-west-2'],
    });
    expect(r.missing_regions).toEqual(['us-west-2']);
    expect(r.warnings.some((w) => /us-west-2/.test(w))).toBe(true);
  });

  it('warns when a KSI has excess collector warnings', () => {
    writeKsi('KSI-IAM-MFA.json', {
      ksi_id: 'KSI-IAM-MFA',
      providers: [{
        provider: 'aws', account_id: '111122223333',
        evidence: [],
        findings: [],
        warnings: ['w1', 'w2', 'w3', 'w4', 'w5', 'w6'], // > threshold 5
      }],
    });
    const r = checkCoverage(tmp, {
      awsAccount: '111122223333',
      gcpProjects: [],
      warningThresholdPerKsi: 5,
    });
    expect(r.ksis_with_excess_warnings).toEqual([{ ksi: 'KSI-IAM-MFA', warnings: 6 }]);
    expect(r.warnings.some((w) => /6 collector warnings/.test(w))).toBe(true);
  });

  it('persists coverage-report.json to disk', () => {
    writeKsi('KSI-IAM-MFA.json', { ksi_id: 'KSI-IAM-MFA' });
    checkCoverage(tmp, { awsAccount: '111122223333', gcpProjects: [] });
    const reportPath = resolve(tmp, 'coverage-report.json');
    expect(existsSync(reportPath)).toBe(true);
    const r = JSON.parse(readFileSync(reportPath, 'utf8'));
    expect(r.total_evidence_files).toBe(1);
    expect(r.actual_aws_accounts).toEqual(['111122223333']);
  });

  it('handles unparseable evidence files with a warning, not a crash', () => {
    writeFileSync(resolve(tmp, 'KSI-IAM-MFA.json'), '{not valid json');
    const r = checkCoverage(tmp, { awsAccount: '111122223333', gcpProjects: [] });
    expect(r.warnings.some((w) => /corrupt|parse/i.test(w))).toBe(true);
    expect(r.total_evidence_files).toBe(1); // counted, but content unusable
  });
});
