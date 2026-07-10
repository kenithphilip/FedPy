import { describe, it, expect } from 'vitest';
import type { CloudAsset } from '../../cloud-evidence/core/inventory-workbook.ts';
import { serviceRollupTable, encryptionGapTable, kmsRegisterTable, cryptoControlTable } from '../src/fips.ts';

function asset(p: Partial<CloudAsset>): CloudAsset {
  return { provider: 'aws', uniqueId: p.uniqueId ?? 'arn:x', ...p } as CloudAsset;
}

const ASSETS: CloudAsset[] = [
  asset({ uniqueId: 'v1', resourceType: 'AWS::EC2::Volume', function: 'vol-1', encryptionAtRest: true, kmsKeyId: 'k1' }),
  asset({ uniqueId: 'v2', resourceType: 'AWS::EC2::Volume', function: 'vol-2', encryptionAtRest: false }),
  asset({ uniqueId: 'd1', resourceType: 'AWS::DynamoDB::Table', function: 'lock', encryptionAtRest: false }),
  asset({ uniqueId: 'b1', resourceType: 'AWS::S3::Bucket', function: 'bkt', encryptionAtRest: null }), // unknown → VERIFY
  asset({ uniqueId: 'k', resourceType: 'AWS::KMS::Key', function: 'mrk-abc', kmsMultiRegion: true, kmsRotationEnabled: true, cmvpValidation: 'AWS KMS HSM — FIPS 140-2/140-3 CMVP validated (Level 3)' }),
  asset({ uniqueId: 'lb', resourceType: 'AWS::ElasticLoadBalancingV2::LoadBalancer', function: 'alb', tlsPolicy: 'ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04', fipsTlsPolicy: true, encryptionInTransit: true }),
];

describe('FIPS service rollup', () => {
  it('marks a service with unencrypted assets FAIL and unknown VERIFY', () => {
    const t = serviceRollupTable(ASSETS);
    const ebs = t.rows.find((r) => r['Service'] === 'EBS Volumes')!;
    expect(ebs['Status']).toBe('FAIL');       // v2 unencrypted
    expect(ebs['Total']).toBe('2');
    const s3 = t.rows.find((r) => r['Service'] === 'S3 Buckets')!;
    expect(s3['Status']).toBe('VERIFY');       // unknown encryption
    const ddb = t.rows.find((r) => r['Service'] === 'DynamoDB Tables')!;
    expect(ddb['Status']).toBe('FAIL');
  });
});

describe('FIPS encryption-gap list', () => {
  it('lists every unencrypted/unknown data store with SC-28 + action', () => {
    const t = encryptionGapTable(ASSETS, () => 'account-wide');
    // v2 (FAIL), d1 (FAIL), b1 (VERIFY) → 3 rows
    expect(t.rows).toHaveLength(3);
    expect(t.rows.every((r) => r['Control'] === 'SC-28')).toBe(true);
    expect(t.rows.some((r) => r['Status'] === 'FAIL')).toBe(true);
    expect(t.rows.some((r) => r['Status'] === 'VERIFY')).toBe(true);
  });
});

describe('FIPS KMS register', () => {
  it('surfaces multi-region + rotation + CMVP', () => {
    const t = kmsRegisterTable(ASSETS);
    expect(t.rows).toHaveLength(1);
    expect(t.rows[0]!['Multi-Region']).toBe('Yes');
    expect(t.rows[0]!['Rotation Enabled']).toBe('Yes');
    expect(t.rows[0]!['FIPS / CMVP']).toContain('FIPS 140-2');
  });
});

describe('FIPS control rollup', () => {
  it('maps SC-13/8/12/28 with SC-28 FAIL when a data store is unencrypted', () => {
    const t = cryptoControlTable(ASSETS);
    const ids = t.rows.map((r) => r['Control']);
    expect(ids).toEqual(['SC-13', 'SC-8', 'SC-12', 'SC-28']);
    const sc28 = t.rows.find((r) => r['Control'] === 'SC-28')!;
    expect(sc28['Status']).toBe('FAIL');
    const sc8 = t.rows.find((r) => r['Control'] === 'SC-8')!;
    expect(sc8['Status']).toBe('PASS'); // the ALB has a FIPS TLS policy, none non-FIPS
  });
});
