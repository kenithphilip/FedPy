/**
 * Tests for core/aws-org-fanout.ts.
 *
 * Uses the same fake-aws-sdk machinery as the IAM-MFA test: replace
 * core/auth/aws.ts with our fake, and inject canned responses for
 * DescribeOrganization + ListAccounts.
 *
 * For STS AssumeRole probing, the fake's send() returns {} which the
 * fanout code treats as "AssumeRole succeeded" — that's fine for our
 * filtering tests. We separately exercise the failure path by injecting
 * an error.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { setFakeResponses } from '../helpers/fake-aws-sdk.ts';

vi.mock('../../core/auth/aws.ts', () => import('../helpers/fake-aws-sdk.ts'));
// AssumeRole goes through @aws-sdk/client-sts directly, so we also need to
// mock the credentials provider so fromTemporaryCredentials doesn't try to
// reach real AWS.
vi.mock('@aws-sdk/credential-providers', () => ({
  fromTemporaryCredentials: () => () => ({ accessKeyId: 'AKIATEST', secretAccessKey: 'x', sessionToken: 'y' }),
  fromNodeProviderChain: () => () => ({ accessKeyId: 'AKIATEST', secretAccessKey: 'x' }),
}));
vi.mock('@aws-sdk/client-sts', () => {
  // Reuse the fake client so AssumeRole "succeeds" — returning {} is enough.
  class STSClient {
    async send() { return {}; }
  }
  class AssumeRoleCommand {
    input: any;
    constructor(input: any) { this.input = input; }
  }
  class GetCallerIdentityCommand {
    input: any;
    constructor(input: any) { this.input = input ?? {}; }
  }
  return { STSClient, AssumeRoleCommand, GetCallerIdentityCommand };
});

import { buildFanoutPlan } from '../../core/aws-org-fanout.ts';

beforeEach(() => {
  setFakeResponses({});
});

describe('buildFanoutPlan', () => {
  it('returns single self target when DescribeOrganization fails', async () => {
    // No DescribeOrganization in fixture → fake returns {} → no Organization field → graceful fallback
    setFakeResponses({
      DescribeOrganization: () => { throw Object.assign(new Error('not in org'), { name: 'AWSOrganizationsNotInUseException' }); },
    });
    const plan = await buildFanoutPlan({ region: 'us-east-1' });
    expect(plan.organization_id).toBeNull();
    expect(plan.targets).toHaveLength(1);
    expect(plan.targets[0].account_id).toBe('self');
  });

  it('enumerates accounts and excludes the management account from AssumeRole', async () => {
    setFakeResponses({
      DescribeOrganization: { Organization: { Id: 'o-test', MasterAccountId: '111111111111' } },
      ListAccounts: {
        Accounts: [
          { Id: '111111111111', Name: 'mgmt', Email: 'mgmt@example.com', Status: 'ACTIVE' },
          { Id: '222222222222', Name: 'workload-prod', Email: 'wp@example.com', Status: 'ACTIVE' },
          { Id: '333333333333', Name: 'workload-dev', Email: 'wd@example.com', Status: 'ACTIVE' },
        ],
        NextToken: undefined,
      },
    });
    const plan = await buildFanoutPlan({ region: 'us-east-1' });
    expect(plan.organization_id).toBe('o-test');
    expect(plan.master_account_id).toBe('111111111111');
    expect(plan.targets.map((t) => t.account_id).sort()).toEqual(['111111111111', '222222222222', '333333333333']);
    expect(plan.total_discovered).toBe(3);
  });

  it('honors the includeAccounts filter', async () => {
    setFakeResponses({
      DescribeOrganization: { Organization: { Id: 'o-test', MasterAccountId: '111111111111' } },
      ListAccounts: {
        Accounts: [
          { Id: '111111111111', Name: 'mgmt', Status: 'ACTIVE' },
          { Id: '222222222222', Name: 'workload-prod', Status: 'ACTIVE' },
          { Id: '333333333333', Name: 'workload-dev', Status: 'ACTIVE' },
        ],
      },
    });
    const plan = await buildFanoutPlan({ region: 'us-east-1', includeAccounts: ['222222222222'] });
    expect(plan.targets.map((t) => t.account_id)).toEqual(['222222222222']);
    expect(plan.skipped.some((s) => s.account_id === '111111111111' && /not in --include/.test(s.reason))).toBe(true);
  });

  it('honors the excludeAccounts filter', async () => {
    setFakeResponses({
      DescribeOrganization: { Organization: { Id: 'o-test', MasterAccountId: '111111111111' } },
      ListAccounts: {
        Accounts: [
          { Id: '111111111111', Name: 'mgmt', Status: 'ACTIVE' },
          { Id: '222222222222', Name: 'workload-prod', Status: 'ACTIVE' },
        ],
      },
    });
    const plan = await buildFanoutPlan({ region: 'us-east-1', excludeAccounts: ['222222222222'] });
    expect(plan.targets.map((t) => t.account_id)).toEqual(['111111111111']);
    expect(plan.skipped.some((s) => s.account_id === '222222222222' && /in --exclude/.test(s.reason))).toBe(true);
  });

  it('skips suspended accounts', async () => {
    setFakeResponses({
      DescribeOrganization: { Organization: { Id: 'o-test', MasterAccountId: '111111111111' } },
      ListAccounts: {
        Accounts: [
          { Id: '111111111111', Name: 'mgmt', Status: 'ACTIVE' },
          { Id: '999999999999', Name: 'closed', Status: 'SUSPENDED' },
        ],
      },
    });
    const plan = await buildFanoutPlan({ region: 'us-east-1' });
    expect(plan.targets.map((t) => t.account_id)).toEqual(['111111111111']);
    expect(plan.skipped.some((s) => s.account_id === '999999999999' && /SUSPENDED/.test(s.reason))).toBe(true);
  });
});
