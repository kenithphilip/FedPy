/**
 * Tests for core/readonly-guardrail.ts (the AWS SDK v3 guardrail).
 *
 * Verifies the operation-name allowlist:
 *   1. Read verbs (Get/List/Describe/BatchGet/Search/Generate/Simulate/Lookup) pass.
 *   2. Mutating verbs (Put/Create/Delete/Set/…) are blocked.
 *   3. The exact-allow set (AssumeRole*, Select* read queries) passes even though
 *      its verbs are not in the read-only prefix list — regression guard for the
 *      Config-backbone `SelectResourceConfig` block (inventory breadth collapse).
 */
import { describe, it, expect } from 'vitest';
import { _internal } from '../../core/readonly-guardrail.ts';

const isRO = _internal.isReadOnlyOperationName;

describe('isReadOnlyOperationName', () => {
  it('permits read-verb operations', () => {
    for (const op of [
      'GetCallerIdentity', 'ListBuckets', 'DescribeInstances', 'BatchGetProjects',
      'SearchCommand', 'GenerateCredentialReport', 'SimulatePrincipalPolicy',
      'LookupEvents', 'DescribeSecurityGroups', 'GetInventory',
    ]) {
      expect(isRO(op), op).toBe(true);
    }
  });

  it('blocks mutating operations', () => {
    for (const op of [
      'PutObject', 'CreateBucket', 'DeleteUser', 'UpdateStack', 'ModifyInstanceAttribute',
      'SetRepositoryPolicy', 'TerminateInstances', 'AttachRolePolicy', 'RebootInstances',
    ]) {
      expect(isRO(op), op).toBe(false);
    }
  });

  it('permits the Select* read queries via exact-allow (regression: Config backbone)', () => {
    // "Select" is not a READ_ONLY_VERBS prefix, so without the exact-allow these
    // would fall through to blocked — which silently collapsed inventory breadth.
    for (const op of ['SelectResourceConfig', 'SelectAggregateResourceConfig', 'SelectObjectContent']) {
      expect(isRO(op), op).toBe(true);
    }
  });

  it('permits AssumeRole family (exact-allow)', () => {
    for (const op of ['AssumeRole', 'AssumeRoleWithSAML', 'AssumeRoleWithWebIdentity', 'DecodeAuthorizationMessage']) {
      expect(isRO(op), op).toBe(true);
    }
  });

  it('still blocks Set-prefixed mutations (Select is not Set)', () => {
    expect(isRO('SetBucketPolicy')).toBe(false);
    expect(isRO('SetIdentityPoolConfiguration')).toBe(false);
  });
});
