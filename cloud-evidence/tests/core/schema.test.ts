/**
 * Tests for core/schema.ts — the EvidenceFile JSON Schema validator.
 *
 * We assert:
 *   1. A canonical "good" envelope validates.
 *   2. The conditional `passed=false ⇒ gap+remediation required` rule fires.
 *   3. Bad severities, bad mechanisms, and missing required fields are caught.
 */
import { describe, it, expect } from 'vitest';
import { validateEvidenceFile, formatErrors } from '../../core/schema.ts';
import type { EvidenceFile } from '../../core/envelope.ts';

function baseEnvelope(): EvidenceFile {
  return {
    ksi_id: 'KSI-IAM-MFA',
    ksi_name: 'Multi-Factor Authentication',
    ksi_statement: 'Multi-factor authentication is enforced for every human user.',
    scope: 'CLOUD',
    frmr_version: '2025-06.r1',
    run_id: '00000000-0000-0000-0000-000000000001',
    collected_at: '2026-05-27T12:00:00.000Z',
    providers: [
      {
        provider: 'aws',
        account_id: '111122223333',
        region_set: ['us-east-1'],
        evidence: [
          { source: 'iam.GetAccountSummary', captured_at: '2026-05-27T12:00:01.000Z', data: { AccountMFAEnabled: 1 } },
        ],
        findings: [
          {
            rule: 'aws.iam.root_mfa_enabled',
            passed: true,
            severity: 'critical',
            current_state: { summary: 'Root MFA is enabled.', observations: { AccountMFAEnabled: 1 } },
            target_state: { summary: 'Root MFA enabled.', rationale: 'Root has unlimited blast radius.' },
          },
        ],
      },
    ],
    rollup: { pass: true, passing_findings: 1, failing_findings: 0, warnings: [], missing_evidence: [], alternatives_in_play: 0 },
  };
}

describe('EvidenceFile schema validator', () => {
  it('accepts a minimal valid envelope', () => {
    const r = validateEvidenceFile(JSON.parse(JSON.stringify(baseEnvelope())));
    expect(r.valid, formatErrors(r.errors)).toBe(true);
  });

  it('rejects envelope missing required ksi_id', () => {
    const env: any = baseEnvelope();
    delete env.ksi_id;
    const r = validateEvidenceFile(env);
    expect(r.valid).toBe(false);
    expect(r.errors.some((e) => e.params?.missingProperty === 'ksi_id')).toBe(true);
  });

  it('rejects invalid severity', () => {
    const env: any = baseEnvelope();
    env.providers[0].findings[0].severity = 'urgent'; // not in enum
    const r = validateEvidenceFile(env);
    expect(r.valid).toBe(false);
    expect(r.errors.some((e) => e.instancePath.includes('severity'))).toBe(true);
  });

  it('rejects failing finding without gap + remediation', () => {
    const env: any = baseEnvelope();
    env.providers[0].findings[0].passed = false;
    // Note: no gap, no remediation
    const r = validateEvidenceFile(env);
    expect(r.valid).toBe(false);
    const missing = r.errors.flatMap((e) => (e.params?.missingProperty ? [e.params.missingProperty] : []));
    expect(missing).toContain('gap');
    expect(missing).toContain('remediation');
  });

  it('accepts a failing finding with gap + remediation', () => {
    const env: any = baseEnvelope();
    env.providers[0].findings[0].passed = false;
    env.providers[0].findings[0].gap = {
      description: 'Root MFA off.',
      affected_resources: [{ type: 'aws_account', identifier: '111122223333' }],
    };
    env.providers[0].findings[0].remediation = {
      summary: 'Enable root MFA.',
      options: [{
        approach: 'Console: enable virtual MFA on root',
        mechanism: 'console',
        steps: ['Sign in as root', 'Enable MFA'],
      }],
    };
    env.rollup = { pass: false, passing_findings: 0, failing_findings: 1, warnings: [], missing_evidence: [], alternatives_in_play: 0 };
    const r = validateEvidenceFile(env);
    expect(r.valid, formatErrors(r.errors)).toBe(true);
  });

  it('rejects bad remediation mechanism enum', () => {
    const env: any = baseEnvelope();
    env.providers[0].findings[0].passed = false;
    env.providers[0].findings[0].gap = { description: 'x', affected_resources: [] };
    env.providers[0].findings[0].remediation = {
      summary: 'x',
      options: [{ approach: 'x', mechanism: 'kubernetes-yaml', steps: ['y'] }],  // bad enum
    };
    const r = validateEvidenceFile(env);
    expect(r.valid).toBe(false);
    expect(r.errors.some((e) => e.instancePath.includes('mechanism'))).toBe(true);
  });

  it('rejects bad scope value', () => {
    const env: any = baseEnvelope();
    env.scope = 'OPTIONAL';
    const r = validateEvidenceFile(env);
    expect(r.valid).toBe(false);
  });

  it('rejects empty steps in a remediation option', () => {
    const env: any = baseEnvelope();
    env.providers[0].findings[0].passed = false;
    env.providers[0].findings[0].gap = { description: 'x', affected_resources: [] };
    env.providers[0].findings[0].remediation = {
      summary: 'x',
      options: [{ approach: 'x', mechanism: 'cli', steps: [] }],  // steps must have minItems: 1
    };
    const r = validateEvidenceFile(env);
    expect(r.valid).toBe(false);
  });

  it('rejects unknown top-level property (additionalProperties: false)', () => {
    const env: any = baseEnvelope();
    env.extra_field_that_does_not_belong = true;
    const r = validateEvidenceFile(env);
    expect(r.valid).toBe(false);
  });
});
