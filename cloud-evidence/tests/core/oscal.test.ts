/**
 * Tests for core/oscal.ts — OSCAL Assessment Results emitter.
 *
 * We verify:
 *   1. The emitted document has the expected top-level shape.
 *   2. Every EvidenceFile in outDir produces exactly one OSCAL result.
 *   3. Pass/fail mapping is correct (satisfied / not-satisfied).
 *   4. RawEvidence becomes observations; findings reference them.
 *   5. Affected resources become subject-bearing observations.
 *   6. UUIDs are deterministic across re-runs (same evidence → same UUIDs).
 *   7. Files that aren't KSI evidence (manifest.json, etc.) are excluded.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { emitOscalAssessmentResults } from '../../core/oscal.ts';
import type { EvidenceFile } from '../../core/envelope.ts';

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(resolve(tmpdir(), 'cev-oscal-'));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

function fakeEvidence(overrides: Partial<EvidenceFile> = {}): EvidenceFile {
  return {
    ksi_id: 'KSI-IAM-MFA',
    ksi_name: 'Multi-Factor Authentication',
    ksi_statement: 'Multi-factor authentication is enforced for every human user.',
    scope: 'CLOUD',
    frmr_version: '2025-06.r1',
    run_id: 'run-test-1',
    collected_at: '2026-05-27T12:00:00.000Z',
    providers: [
      {
        provider: 'aws',
        account_id: '111122223333',
        region_set: ['us-east-1'],
        evidence: [
          { source: 'iam.GetAccountSummary', captured_at: '2026-05-27T12:00:01.000Z', data: { AccountMFAEnabled: 1 } },
          { source: 'iam.ListUsers', captured_at: '2026-05-27T12:00:02.000Z', data: { count: 2 } },
        ],
        findings: [
          {
            rule: 'aws.iam.root_mfa_enabled',
            passed: true,
            severity: 'critical',
            current_state: { summary: 'Root MFA is on.', observations: { AccountMFAEnabled: 1 } },
            target_state: { summary: 'Root MFA enabled.', rationale: 'Root has unlimited blast radius.' },
          },
          {
            rule: 'aws.iam.console_users_have_mfa',
            passed: false,
            severity: 'high',
            current_state: { summary: '1 of 2 console users lacks MFA.', observations: { without_mfa: ['bob.contractor'] } },
            target_state: { summary: 'All console users have MFA.', rationale: 'Phishing resistance.' },
            gap: {
              description: 'bob.contractor has no MFA device registered.',
              affected_resources: [{
                type: 'aws_iam_user',
                identifier: 'arn:aws:iam::111122223333:user/bob.contractor',
                name: 'bob.contractor',
                tags: { team: 'contractors' },
              }],
            },
            remediation: {
              summary: 'Enable MFA for bob.contractor.',
              options: [{
                approach: 'Have user register a virtual MFA device in the console.',
                mechanism: 'console',
                steps: ['Sign in to IAM console', 'Choose user bob.contractor', 'Manage MFA device', 'Assign virtual MFA'],
              }],
            },
          },
        ],
      },
    ],
    rollup: { pass: false, passing_findings: 1, failing_findings: 1, warnings: [], missing_evidence: [], alternatives_in_play: 0 },
    nist_controls: ['IA-2(1)', 'IA-2(2)'],
    ...overrides,
  };
}

describe('emitOscalAssessmentResults', () => {
  it('produces a valid OSCAL Assessment Results structure', () => {
    writeFileSync(resolve(tmp, 'KSI-IAM-MFA.json'), JSON.stringify(fakeEvidence()));
    const r = emitOscalAssessmentResults({ outDir: tmp, runId: 'run-test-1', frmrVersion: '2025-06.r1', organizationName: 'Acme Corp' });
    expect(r.result_count).toBe(1);
    const raw = JSON.parse(readFileSync(r.path, 'utf8'));
    expect(raw['assessment-results']).toBeTruthy();  // OSCAL documents wrap the model in a top-level key
    const doc = raw['assessment-results'];
    expect(doc.uuid).toMatch(/^[a-f0-9-]{36}$/);
    expect(doc.metadata.title).toMatch(/run-test-1/);
    expect(doc.metadata['oscal-version']).toBe('1.1.2');
    expect(doc.metadata.parties[0].name).toBe('Acme Corp');
    expect(doc['import-ap'].href).toBeTruthy();
    expect(doc.results).toHaveLength(1);
  });

  it('maps passed → satisfied and !passed → not-satisfied', () => {
    writeFileSync(resolve(tmp, 'KSI-IAM-MFA.json'), JSON.stringify(fakeEvidence()));
    emitOscalAssessmentResults({ outDir: tmp, runId: 'run-1', frmrVersion: '2025-06.r1' });
    const doc = JSON.parse(readFileSync(resolve(tmp, 'assessment-results.json'), 'utf8'))['assessment-results'];
    const findings = doc.results[0].findings;
    const root = findings.find((f: any) => f.title.startsWith('aws.iam.root_mfa_enabled'));
    const console_users = findings.find((f: any) => f.title.startsWith('aws.iam.console_users_have_mfa'));
    expect(root.target.status.state).toBe('satisfied');
    expect(console_users.target.status.state).toBe('not-satisfied');
    expect(console_users.target.status.reason).toMatch(/bob.contractor/);
  });

  it('emits observations per RawEvidence and links them from findings', () => {
    writeFileSync(resolve(tmp, 'KSI-IAM-MFA.json'), JSON.stringify(fakeEvidence()));
    emitOscalAssessmentResults({ outDir: tmp, runId: 'run-1', frmrVersion: '2025-06.r1' });
    const doc = JSON.parse(readFileSync(resolve(tmp, 'assessment-results.json'), 'utf8'))['assessment-results'];
    const result = doc.results[0];
    // 2 RawEvidence + 1 synthesized affected-resources obs (only for the failing finding)
    expect(result.observations.length).toBeGreaterThanOrEqual(3);
    // Findings reference observation UUIDs
    for (const f of result.findings) {
      expect(f['related-observations'].length).toBeGreaterThan(0);
    }
  });

  it('creates inventory-item subjects from affected_resources on failing findings', () => {
    writeFileSync(resolve(tmp, 'KSI-IAM-MFA.json'), JSON.stringify(fakeEvidence()));
    emitOscalAssessmentResults({ outDir: tmp, runId: 'run-1', frmrVersion: '2025-06.r1' });
    const doc = JSON.parse(readFileSync(resolve(tmp, 'assessment-results.json'), 'utf8'))['assessment-results'];
    const result = doc.results[0];
    const resourceObs = result.observations.find((o: any) => o.subjects && o.subjects.length > 0);
    expect(resourceObs).toBeTruthy();
    expect(resourceObs.subjects[0].type).toBe('inventory-item');
    expect(resourceObs.subjects[0].title).toBe('bob.contractor');
    expect(resourceObs.subjects[0].props.find((p: any) => p.name === 'tag:team').value).toBe('contractors');
  });

  it('encodes remediation steps + alternative satisfiers into the finding remarks', () => {
    writeFileSync(resolve(tmp, 'KSI-IAM-MFA.json'), JSON.stringify(fakeEvidence()));
    emitOscalAssessmentResults({ outDir: tmp, runId: 'run-1', frmrVersion: '2025-06.r1' });
    const doc = JSON.parse(readFileSync(resolve(tmp, 'assessment-results.json'), 'utf8'))['assessment-results'];
    const failing = doc.results[0].findings.find((f: any) => f.target.status.state === 'not-satisfied');
    expect(failing.remarks).toMatch(/Remediation/);
    expect(failing.remarks).toMatch(/Sign in to IAM console/);
    expect(failing.remarks).toMatch(/Affected resources/);
  });

  it('produces deterministic UUIDs across re-runs for the same evidence', () => {
    writeFileSync(resolve(tmp, 'KSI-IAM-MFA.json'), JSON.stringify(fakeEvidence()));
    emitOscalAssessmentResults({ outDir: tmp, runId: 'run-test-1', frmrVersion: '2025-06.r1' });
    const doc1 = JSON.parse(readFileSync(resolve(tmp, 'assessment-results.json'), 'utf8'))['assessment-results'];

    emitOscalAssessmentResults({ outDir: tmp, runId: 'run-test-1', frmrVersion: '2025-06.r1' });
    const doc2 = JSON.parse(readFileSync(resolve(tmp, 'assessment-results.json'), 'utf8'))['assessment-results'];

    // The top-level UUID + all finding & observation UUIDs should be identical
    expect(doc1.uuid).toBe(doc2.uuid);
    expect(doc1.results[0].findings.map((f: any) => f.uuid).sort()).toEqual(doc2.results[0].findings.map((f: any) => f.uuid).sort());
  });

  it('ignores manifest.json and other non-KSI files', () => {
    writeFileSync(resolve(tmp, 'KSI-IAM-MFA.json'), JSON.stringify(fakeEvidence()));
    writeFileSync(resolve(tmp, 'manifest.json'), JSON.stringify({ files: [] }));
    writeFileSync(resolve(tmp, 'pva-run-summary.json'), JSON.stringify({ summary: 1 }));
    writeFileSync(resolve(tmp, 'previous-run-snapshot.json'), JSON.stringify({ snap: 1 }));
    const r = emitOscalAssessmentResults({ outDir: tmp, runId: 'run-1', frmrVersion: '2025-06.r1' });
    expect(r.result_count).toBe(1); // only KSI-IAM-MFA.json
  });

  it('aggregates multiple KSI evidence files into one OSCAL document', () => {
    writeFileSync(resolve(tmp, 'KSI-IAM-MFA.json'), JSON.stringify(fakeEvidence({ ksi_id: 'KSI-IAM-MFA' })));
    writeFileSync(resolve(tmp, 'KSI-IAM-AAM.json'), JSON.stringify(fakeEvidence({ ksi_id: 'KSI-IAM-AAM', ksi_name: 'Account Mgmt' })));
    const r = emitOscalAssessmentResults({ outDir: tmp, runId: 'run-1', frmrVersion: '2025-06.r1' });
    expect(r.result_count).toBe(2);
    const doc = JSON.parse(readFileSync(r.path, 'utf8'))['assessment-results'];
    const ksiIds = doc.results.map((res: any) => res.props.find((p: any) => p.name === 'ksi-id').value).sort();
    expect(ksiIds).toEqual(['KSI-IAM-AAM', 'KSI-IAM-MFA']);
  });
});
