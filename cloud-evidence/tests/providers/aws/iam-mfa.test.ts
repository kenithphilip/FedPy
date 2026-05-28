/**
 * Reference test for KSI-IAM-MFA AWS collector.
 *
 * Verifies the high-level pass/fail behavior of the four findings:
 *   - aws.iam.root_mfa_enabled
 *   - aws.iam.console_users_have_mfa
 *   - aws.iam.no_virtual_mfa_for_console_users
 *   - aws.org.scp_denies_actions_without_mfa
 *
 * Mocks core/auth/aws.ts so no real SDK calls are made.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { setFakeResponses, fakeAwsContext } from '../../helpers/fake-aws-sdk.ts';
import { iamMfaPassing } from '../../fixtures/iam-mfa-passing.ts';
import { iamMfaFailing } from '../../fixtures/iam-mfa-failing.ts';

// Replace the real AWS auth module with our fake. The factory returns the
// fake helper module wholesale; per-test responses are swapped via
// setFakeResponses() in beforeEach below.
vi.mock('../../../core/auth/aws.ts', () => import('../../helpers/fake-aws-sdk.ts'));

import { collectIamMfa } from '../../../providers/aws/iam.ts';

describe('KSI-IAM-MFA — AWS collector', () => {
  beforeEach(() => {
    // Reset to a known baseline before each test sets its own responses.
    setFakeResponses({});
  });

  it('passes when root MFA on + no standalone IAM users + SCP enforces MFA', async () => {
    setFakeResponses(iamMfaPassing);
    const result = await collectIamMfa(fakeAwsContext());
    const rootFinding = result.findings.find((f) => f.rule === 'aws.iam.root_mfa_enabled');
    expect(rootFinding?.passed).toBe(true);
    const scpFinding = result.findings.find((f) => f.rule === 'aws.org.scp_denies_actions_without_mfa');
    expect(scpFinding?.passed).toBe(true);
  });

  it('fails root_mfa_enabled when AccountMFAEnabled = 0', async () => {
    setFakeResponses(iamMfaFailing);
    const result = await collectIamMfa(fakeAwsContext());
    const rootFinding = result.findings.find((f) => f.rule === 'aws.iam.root_mfa_enabled');
    expect(rootFinding?.passed).toBe(false);
    expect(rootFinding?.severity).toBe('critical');
    expect(rootFinding?.gap?.affected_resources.length ?? 0).toBeGreaterThanOrEqual(1);
  });

  it('fails console_users_have_mfa when a console user lacks MFA', async () => {
    setFakeResponses(iamMfaFailing);
    const result = await collectIamMfa(fakeAwsContext());
    const userMfa = result.findings.find((f) => f.rule === 'aws.iam.console_users_have_mfa');
    // bob.contractor has console login but no MFA in the fixture
    expect(userMfa?.passed).toBe(false);
    expect(userMfa?.severity).toBe('critical');
  });

  it('detects external IdP as an alternative satisfier when SAML/OIDC providers present', async () => {
    setFakeResponses(iamMfaPassing);
    const result = await collectIamMfa(fakeAwsContext());
    const ksiAlts = result.ksi_level_alternatives ?? [];
    const externalIdp = ksiAlts.find((a) => /External SAML\/OIDC/i.test(a.via));
    expect(externalIdp?.detected).toBe(true);
    expect(externalIdp?.detection_signals?.length ?? 0).toBeGreaterThan(0);
  });

  it('produces evidence in v3 schema shape', async () => {
    setFakeResponses(iamMfaFailing);
    const result = await collectIamMfa(fakeAwsContext());

    expect(result.provider).toBe('aws');
    expect(result.account_id).toBe('111122223333');
    expect(result.evidence.length).toBeGreaterThan(0);
    expect(result.findings.length).toBeGreaterThan(0);

    // Every finding must have v3 required fields
    for (const f of result.findings) {
      expect(f.rule).toBeTruthy();
      expect(typeof f.passed).toBe('boolean');
      expect(f.severity).toMatch(/^(critical|high|medium|low|info)$/);
      expect(f.current_state?.summary).toBeTruthy();
      expect(f.target_state?.summary).toBeTruthy();
      expect(f.target_state?.rationale).toBeTruthy();
      if (!f.passed) {
        expect(f.gap?.description).toBeTruthy();
        expect(Array.isArray(f.gap?.affected_resources)).toBe(true);
        expect(f.remediation?.summary).toBeTruthy();
        expect(f.remediation?.options.length ?? 0).toBeGreaterThan(0);
        // Every remediation option must have steps[]
        for (const opt of f.remediation!.options) {
          expect(opt.steps.length).toBeGreaterThan(0);
          expect(opt.mechanism).toBeTruthy();
        }
      }
    }
  });
});
