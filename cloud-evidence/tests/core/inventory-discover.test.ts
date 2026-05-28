/**
 * Tests for the inventory discovery-backbone pure mappers (INV-7/8).
 * No cloud/disk needed — only the row→asset transforms are exercised.
 */
import { describe, it, expect } from 'vitest';
import { friendlyAwsType, configRowToAsset, resourceExplorerToAsset } from '../../providers/aws/discover.ts';
import { searchResultToAsset } from '../../providers/gcp/discover.ts';

describe('friendlyAwsType', () => {
  it('turns an AWS::Service::Resource type into spaced words', () => {
    expect(friendlyAwsType('AWS::EC2::Instance')).toBe('Instance');
    expect(friendlyAwsType('AWS::ElasticLoadBalancingV2::LoadBalancer')).toBe('Load Balancer');
    expect(friendlyAwsType(undefined)).toBeNull();
  });
});

describe('configRowToAsset', () => {
  it('maps a Config advanced-query row to a CloudAsset with tags + provenance', () => {
    const a = configRowToAsset({
      resourceId: 'i-1', resourceName: 'web', resourceType: 'AWS::EC2::Instance',
      awsRegion: 'us-east-1', availabilityZone: 'us-east-1a', arn: 'arn:aws:ec2:us-east-1:111:instance/i-1',
      resourceCreationTime: '2026-01-01T00:00:00Z', tags: [{ key: 'Owner', value: 'alice' }],
    }, '111')!;
    expect(a.uniqueId).toBe('arn:aws:ec2:us-east-1:111:instance/i-1');
    expect(a.resourceType).toBe('AWS::EC2::Instance');
    expect(a.assetType).toBe('Instance');
    expect(a.location).toBe('us-east-1a');
    expect(a.tags).toEqual({ Owner: 'alice' });
    expect(a.accountId).toBe('111');
    expect(a.sourceApi).toBe('aws-config-advanced-query');
  });
  it('falls back to type/id when no ARN, and returns null for empty rows', () => {
    expect(configRowToAsset({ resourceId: 'x', resourceType: 'AWS::S3::Bucket' }, null)!.uniqueId).toBe('AWS::S3::Bucket/x');
    expect(configRowToAsset({}, null)).toBeNull();
  });
});

describe('resourceExplorerToAsset', () => {
  it('maps a Resource Explorer result', () => {
    const a = resourceExplorerToAsset({ Arn: 'arn:aws:rds:us-east-1:111:db:p', ResourceType: 'AWS::RDS::DBInstance', Region: 'us-east-1', OwningAccountId: '111' })!;
    expect(a.uniqueId).toBe('arn:aws:rds:us-east-1:111:db:p');
    expect(a.assetType).toBe('DBInstance');
    expect(a.accountId).toBe('111');
    expect(a.sourceApi).toBe('aws-resource-explorer');
  });
  it('returns null without an ARN', () => {
    expect(resourceExplorerToAsset({ ResourceType: 'x' })).toBeNull();
  });
});

describe('searchResultToAsset (GCP CAI)', () => {
  it('maps a searchAllResources result with labels + kms + timestamps', () => {
    const a = searchResultToAsset({
      name: '//compute.googleapis.com/projects/p/zones/z/instances/i',
      assetType: 'compute.googleapis.com/Instance', location: 'us-central1-a',
      createTime: '2026-01-01T00:00:00Z', updateTime: '2026-02-01T00:00:00Z', state: 'RUNNING',
      kmsKey: 'projects/p/locations/l/keyRings/r/cryptoKeys/k', displayName: 'i',
      labels: { env: 'prod' }, project: 'projects/p',
    }, 'p');
    expect(a.uniqueId).toContain('instances/i');
    expect(a.resourceType).toBe('compute.googleapis.com/Instance');
    expect(a.assetType).toBe('Instance');
    expect(a.location).toBe('us-central1-a');
    expect(a.state).toBe('RUNNING');
    expect(a.kmsKeyId).toContain('cryptoKeys/k');
    expect(a.tags).toEqual({ env: 'prod' });
    expect(a.accountId).toBe('p');
    expect(a.sourceApi).toBe('gcp-cai-search');
  });
});
