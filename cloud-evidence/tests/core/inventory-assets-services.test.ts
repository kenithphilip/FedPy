/**
 * Tests for the additional-services depth-enricher pure mappers + node-fact
 * derivation. No cloud calls.
 */
import { describe, it, expect } from 'vitest';
import {
  elastiCacheRgToAsset, redshiftToAsset, efsToAsset, snsTopicToAsset,
  sqsQueueToAsset, apiGatewayToAsset, route53ZoneToAsset,
} from '../../providers/aws/inventory-assets-services.ts';
import { deriveNodeFacts, nodeOsFamilyFromHint } from '../../providers/aws/inventory-assets.ts';

describe('service mappers surface encryption posture', () => {
  it('ElastiCache RG: at-rest + in-transit', () => {
    const a = elastiCacheRgToAsset({ ARN: 'arn:x', ReplicationGroupId: 'rg1', Status: 'available', AtRestEncryptionEnabled: true, TransitEncryptionEnabled: true, KmsKeyId: 'k' }, 'us-gov-west-1')!;
    expect(a.resourceType).toBe('AWS::ElastiCache::ReplicationGroup');
    expect(a.encryptionAtRest).toBe(true);
    expect(a.encryptionInTransit).toBe(true);
  });
  it('Redshift: encrypted + public flag', () => {
    const a = redshiftToAsset({ ClusterIdentifier: 'wh', Encrypted: true, KmsKeyId: 'k', PubliclyAccessible: false, ClusterStatus: 'available' }, 'us-gov-west-1')!;
    expect(a.encryptionAtRest).toBe(true);
    expect(a.publicFacing).toBe(false);
  });
  it('EFS: encrypted', () => {
    expect(efsToAsset({ FileSystemId: 'fs-1', Encrypted: true, KmsKeyId: 'k' }, 'us-gov-west-1')!.encryptionAtRest).toBe(true);
  });
  it('SNS: SSE present vs absent vs unknown', () => {
    expect(snsTopicToAsset('arn:t', { KmsMasterKeyId: 'k' }, 'r')!.encryptionAtRest).toBe(true);
    expect(snsTopicToAsset('arn:t', {}, 'r')!.encryptionAtRest).toBe(false);
    expect(snsTopicToAsset('arn:t', undefined, 'r')!.encryptionAtRest).toBeNull();
  });
  it('SQS: KMS or managed SSE', () => {
    expect(sqsQueueToAsset('https://q/x', { SqsManagedSseEnabled: 'true' }, 'r', '1')!.encryptionAtRest).toBe(true);
    expect(sqsQueueToAsset('https://q/x', {}, 'r', '1')!.encryptionAtRest).toBe(false);
  });
  it('API Gateway: private vs public', () => {
    expect(apiGatewayToAsset({ id: 'a', name: 'api', endpointConfiguration: { types: ['PRIVATE'] } }, 'r')!.publicFacing).toBe(false);
    expect(apiGatewayToAsset({ id: 'a', endpointConfiguration: { types: ['REGIONAL'] } }, 'r')!.publicFacing).toBe(true);
  });
  it('Route53: public vs private zone', () => {
    expect(route53ZoneToAsset({ Id: '/hostedzone/Z1', Name: 'ex.com.', Config: { PrivateZone: false } }, 'r')!.publicFacing).toBe(true);
    expect(route53ZoneToAsset({ Id: '/hostedzone/Z2', Name: 'int.', Config: { PrivateZone: true } }, 'r')!.publicFacing).toBe(false);
  });
});

describe('node-fact derivation (Prisma Defender planning)', () => {
  it('extracts EKS cluster + Karpenter nodepool + FIPS tag from real tags', () => {
    const f = deriveNodeFacts({
      'kubernetes.io/cluster/prod-k8s-eks-pri': 'owned',
      'karpenter.sh/nodepool': 'default',
      'eks:nodegroup-name': '',
      'FIPSCompliant': 'true',
    });
    expect(f.k8sCluster).toBe('prod-k8s-eks-pri');
    expect(f.karpenterNodePool).toBe('default');
    expect(f.nodeGroup).toBe('default'); // falls back to nodepool
    expect(f.fipsTagged).toBe(true);
  });
  it('handles non-node instances (no cluster tags)', () => {
    const f = deriveNodeFacts({ Name: 'bastion' });
    expect(f.k8sCluster).toBeNull();
    expect(f.fipsTagged).toBeNull();
  });
  it('infers OS family incl. Bottlerocket (Defender DaemonSet signal)', () => {
    expect(nodeOsFamilyFromHint('Bottlerocket 1.62.1')).toBe('Bottlerocket');
    expect(nodeOsFamilyFromHint('Linux/UNIX', 'amzn2-ami-...')).toBe('Amazon Linux 2');
    expect(nodeOsFamilyFromHint(null)).toBeNull();
  });
});
