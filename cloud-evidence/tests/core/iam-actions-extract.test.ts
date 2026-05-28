/**
 * Tests for scripts/extract-iam-actions.mjs — the IAM-permission auto-extractor.
 * Pure-string parsing, so no disk/network needed.
 */
import { describe, it, expect } from 'vitest';
// @ts-expect-error — plain .mjs with exported helpers, no type decls.
import { extractAwsActionsFromSource, extractGcpRolesFromSource, awsServiceToIamPrefix } from '../../scripts/extract-iam-actions.mjs';

describe('awsServiceToIamPrefix', () => {
  it('maps known slugs to their IAM prefix', () => {
    expect(awsServiceToIamPrefix('lambda')).toBe('lambda');
    expect(awsServiceToIamPrefix('cloudwatch-logs')).toBe('logs');
    expect(awsServiceToIamPrefix('elastic-load-balancing-v2')).toBe('elasticloadbalancing');
    expect(awsServiceToIamPrefix('cognito-identity-provider')).toBe('cognito-idp');
    expect(awsServiceToIamPrefix('app-mesh')).toBe('appmesh');
    expect(awsServiceToIamPrefix('securitylake')).toBe('securitylake');
  });

  it('flags unknown slugs as _unmapped with a best-effort prefix', () => {
    const r = awsServiceToIamPrefix('some-new-service') as { prefix: string; _unmapped: boolean };
    expect(r._unmapped).toBe(true);
    expect(r.prefix).toBe('somenewservice');
  });
});

describe('extractAwsActionsFromSource', () => {
  it('maps *Command imports to svc:Action', () => {
    const src = `import { ListFunctionsCommand, GetFunctionUrlConfigCommand } from '@aws-sdk/client-lambda';`;
    const { actions } = extractAwsActionsFromSource(src);
    expect(actions).toContain('lambda:ListFunctions');
    expect(actions).toContain('lambda:GetFunctionUrlConfig');
  });

  it('resolves "X as Y" aliases to the real command name', () => {
    const src = `import { GetFindingsCommand as ShGetFindingsCommand } from '@aws-sdk/client-securityhub';`;
    const { actions } = extractAwsActionsFromSource(src);
    expect(actions).toEqual(['securityhub:GetFindings']);
  });

  it('handles multi-line import blocks and the cloudwatch-logs → logs remap', () => {
    const src = `import {\n  DescribeLogGroupsCommand,\n  DescribeSubscriptionFiltersCommand,\n} from '@aws-sdk/client-cloudwatch-logs';`;
    const { actions } = extractAwsActionsFromSource(src);
    expect(actions).toContain('logs:DescribeLogGroups');
    expect(actions).toContain('logs:DescribeSubscriptionFilters');
  });

  it('ignores non-Command imports and non-aws-sdk imports', () => {
    const src = `import { finding } from '../../core/findings.ts';\nimport { z } from 'zod';`;
    const { actions } = extractAwsActionsFromSource(src);
    expect(actions).toEqual([]);
  });

  it('reports unmapped slugs', () => {
    const src = `import { ListThingsCommand } from '@aws-sdk/client-totally-new';`;
    const { actions, unmappedSlugs } = extractAwsActionsFromSource(src);
    expect(actions).toEqual(['totallynew:ListThings']);
    expect(unmappedSlugs).toEqual(['totally-new']);
  });
});

describe('extractGcpRolesFromSource', () => {
  it('collects roles/ references, deduped and sorted', () => {
    const src = `diagnoseGcpError(e, 'x', 'logging.entries.list (roles/logging.viewer)');\n// also roles/iam.securityReviewer and roles/logging.viewer again`;
    expect(extractGcpRolesFromSource(src)).toEqual(['roles/iam.securityReviewer', 'roles/logging.viewer']);
  });

  it('does not capture a trailing sentence period', () => {
    const src = `Needs roles/iam.workloadIdentityUser. See docs.`;
    expect(extractGcpRolesFromSource(src)).toEqual(['roles/iam.workloadIdentityUser']);
  });
});
