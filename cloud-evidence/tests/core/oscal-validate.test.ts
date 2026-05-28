/**
 * Tests for core/oscal-validate.ts (OSC-1) — validating our emitted OSCAL against
 * the committed NIST schema (docs/oscal/, via scripts/extract-oscal-schemas.mjs).
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { emitOscalAssessmentResults } from '../../core/oscal.ts';
import { validateOscal, validateOscalFile, _resetOscalValidators } from '../../core/oscal-validate.ts';

let tmp: string;
beforeEach(() => { tmp = mkdtempSync(resolve(tmpdir(), 'cev-oscalv-')); _resetOscalValidators(); });
afterEach(() => { rmSync(tmp, { recursive: true, force: true }); });

const minimalEvidence = {
  ksi_id: 'KSI-IAM-MFA', ksi_name: 'MFA', ksi_statement: 'MFA enforced.', scope: 'CLOUD',
  frmr_version: '2025-06.r1', run_id: 'run-1', collected_at: '2026-05-27T12:00:00.000Z',
  providers: [{
    provider: 'aws', account_id: '111122223333', region_set: ['us-east-1'],
    evidence: [{ source: 'iam.GetAccountSummary', captured_at: '2026-05-27T12:00:01.000Z', data: { AccountMFAEnabled: 1 } }],
    findings: [{ rule: 'aws.iam.root_mfa_enabled', passed: true, severity: 'critical',
      current_state: { summary: 'on', observations: {} }, target_state: { summary: 'on', rationale: 'r' } }],
  }],
  rollup: { pass: true, passing_findings: 1, failing_findings: 0, warnings: [], missing_evidence: [], alternatives_in_play: 0 },
  nist_controls: ['ia-2.1'],
};

describe('validateOscal', () => {
  it('validates a real emitted assessment-results document against the NIST schema', () => {
    writeFileSync(resolve(tmp, 'KSI-IAM-MFA.json'), JSON.stringify(minimalEvidence));
    const r = emitOscalAssessmentResults({ outDir: tmp, runId: 'run-1', frmrVersion: '2025-06.r1', organizationName: 'Acme' });
    const res = validateOscalFile(r.path, 'assessment-results');
    if (!res.valid) console.error('OSCAL validation errors:', res.errors);
    expect(res.schema_found).toBe(true);
    expect(res.valid).toBe(true);
    expect(res.errors).toEqual([]);
  });

  it('rejects a document missing the assessment-results wrapper', () => {
    const res = validateOscal({ uuid: 'x', results: [] }, 'assessment-results');
    expect(res.valid).toBe(false);
    expect(res.errors.length).toBeGreaterThan(0);
  });

  it('rejects a wrapped document missing required fields', () => {
    const res = validateOscal({ 'assessment-results': { uuid: 'not-a-uuid' } }, 'assessment-results');
    expect(res.valid).toBe(false);
    expect(res.errors.length).toBeGreaterThan(0);
  });

  it('reports the file-not-found case cleanly', () => {
    const res = validateOscalFile(resolve(tmp, 'nope.json'));
    expect(res.valid).toBe(false);
    expect(res.errors[0]).toMatch(/file not found/);
  });
});
