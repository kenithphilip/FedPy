/**
 * Regression test for awsPartition — synthesized ARNs must use the right
 * partition or they duplicate the account's real ARNs (GovCloud/China).
 */
import { describe, it, expect } from 'vitest';
import { awsPartition } from '../../core/auth/aws.ts';

describe('awsPartition', () => {
  it('maps GovCloud regions to aws-us-gov', () => {
    expect(awsPartition('us-gov-west-1')).toBe('aws-us-gov');
    expect(awsPartition('us-gov-east-1')).toBe('aws-us-gov');
  });
  it('maps China regions to aws-cn', () => {
    expect(awsPartition('cn-north-1')).toBe('aws-cn');
    expect(awsPartition('cn-northwest-1')).toBe('aws-cn');
  });
  it('maps commercial regions (and null/blank) to aws', () => {
    expect(awsPartition('us-east-1')).toBe('aws');
    expect(awsPartition('eu-west-2')).toBe('aws');
    expect(awsPartition(null)).toBe('aws');
    expect(awsPartition(undefined)).toBe('aws');
    expect(awsPartition('')).toBe('aws');
  });
});
