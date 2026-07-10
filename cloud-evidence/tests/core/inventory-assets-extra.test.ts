/**
 * Tests for the identity + crypto inventory depth-enricher pure mappers (INV-7b).
 * No cloud/disk — only the credential-report parser and the row→asset transforms.
 */
import { describe, it, expect } from 'vitest';
import {
  parseCredentialReport,
  credentialRowToAsset,
  kmsKeyToAsset,
} from '../../providers/aws/inventory-assets-extra.ts';

const NOW = Date.parse('2026-07-07T00:00:00Z');

describe('parseCredentialReport', () => {
  it('parses the IAM credential-report CSV into keyed rows', () => {
    const csv =
      'user,arn,mfa_active,password_enabled,access_key_1_last_rotated\n' +
      'alice,arn:aws:iam::111:user/alice,true,true,2026-06-01T00:00:00Z\n' +
      'bob,arn:aws:iam::111:user/bob,false,false,N/A';
    const rows = parseCredentialReport(csv);
    expect(rows).toHaveLength(2);
    expect(rows[0]!.user).toBe('alice');
    expect(rows[0]!.mfa_active).toBe('true');
    expect(rows[1]!.access_key_1_last_rotated).toBe('N/A');
  });

  it('returns [] for an empty or header-only report', () => {
    expect(parseCredentialReport('')).toEqual([]);
    expect(parseCredentialReport('user,arn')).toEqual([]);
  });
});

describe('credentialRowToAsset', () => {
  it('maps a user with an old key + console-no-MFA into a flagged asset', () => {
    const row = {
      user: 'alice', arn: 'arn:aws:iam::111:user/alice',
      mfa_active: 'false', password_enabled: 'true',
      access_key_1_last_rotated: '2026-01-01T00:00:00Z', // ~187 days before NOW
      access_key_2_last_rotated: 'N/A',
      password_last_used: '2026-07-01T00:00:00Z',
    };
    const a = credentialRowToAsset(row, NOW)!;
    expect(a.resourceType).toBe('AWS::IAM::User');
    expect(a.assetType).toBe('IAM User');
    expect(a.mfaEnabled).toBe(false);
    expect(a.accessKeyAgeDays).toBeGreaterThan(90);
    expect(a.comments).toContain('console access WITHOUT MFA');
    expect(a.comments).toContain('>90d');
    expect(a.lastUsedAt).toBe('2026-07-01T00:00:00Z');
  });

  it('labels the root account distinctly and handles no keys', () => {
    const row = {
      user: '<root_account>', arn: 'arn:aws:iam::111:root',
      mfa_active: 'true', password_enabled: 'true',
      access_key_1_last_rotated: 'N/A', access_key_2_last_rotated: 'N/A',
    };
    const a = credentialRowToAsset(row, NOW)!;
    expect(a.assetType).toBe('IAM Root Account');
    expect(a.accessKeyAgeDays).toBeNull();
    expect(a.mfaEnabled).toBe(true);
    expect(a.comments).toBeUndefined(); // MFA on + no old key ⇒ no flags
  });

  it('returns null without arn/user', () => {
    expect(credentialRowToAsset({ user: 'x' }, NOW)).toBeNull();
    expect(credentialRowToAsset({ arn: 'y' }, NOW)).toBeNull();
  });
});

describe('kmsKeyToAsset', () => {
  it('maps a customer-managed key with rotation on', () => {
    const a = kmsKeyToAsset('arn:aws:kms:us-east-1:111:key/abc', 'abc', 'us-east-1', '111', {
      manager: 'CUSTOMER', state: 'Enabled', rotation: true, rotationDays: 365,
    })!;
    expect(a.resourceType).toBe('AWS::KMS::Key');
    expect(a.kmsRotationEnabled).toBe(true);
    expect(a.kmsRotationPeriodDays).toBe(365);
    expect(a.encryptionAtRest).toBe(true);
    expect(a.comments).toContain('CUSTOMER-managed');
    expect(a.cmvpValidation).toContain('FIPS 140-2');
    expect(a.kmsMultiRegion).toBe(false);
  });

  it('flags multi-region keys (mrk-) — DR relevant for FIPS', () => {
    const a = kmsKeyToAsset('arn:aws-us-gov:kms:us-gov-west-1:111:key/mrk-abc', 'mrk-abc', 'us-gov-west-1', '111', { manager: 'CUSTOMER', state: 'Enabled', rotation: true })!;
    expect(a.kmsMultiRegion).toBe(true);
    expect(a.comments).toContain('multi-region');
  });

  it('synthesizes an ARN when only the key id is known', () => {
    const a = kmsKeyToAsset(undefined, 'xyz', 'eu-west-1', '222', { manager: 'AWS' })!;
    expect(a.uniqueId).toBe('arn:aws:kms:eu-west-1:222:key/xyz');
    expect(a.comments).toContain('AWS-managed');
  });

  it('returns null with neither arn nor key id', () => {
    expect(kmsKeyToAsset(undefined, undefined, 'us-east-1', '1', {})).toBeNull();
  });
});
