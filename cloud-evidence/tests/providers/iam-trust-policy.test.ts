import { describe, it, expect } from 'vitest';
import { crossAccountTrustWithoutGuard } from '../../providers/aws/iam.ts';

const OWN = '111111111111';
const enc = (o: unknown) => encodeURIComponent(JSON.stringify(o));

describe('crossAccountTrustWithoutGuard', () => {
  it('flags a cross-account AWS principal with no ExternalId / Condition', () => {
    const doc = enc({
      Version: '2012-10-17',
      Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Principal: { AWS: 'arn:aws:iam::999999999999:root' } }],
    });
    expect(crossAccountTrustWithoutGuard(doc, OWN)).toEqual(['arn:aws:iam::999999999999:root']);
  });

  it('is clean when a Condition (ExternalId) guards the trust', () => {
    const doc = enc({
      Statement: [{
        Effect: 'Allow', Action: 'sts:AssumeRole',
        Principal: { AWS: 'arn:aws:iam::999999999999:root' },
        Condition: { StringEquals: { 'sts:ExternalId': 'shared-secret' } },
      }],
    });
    expect(crossAccountTrustWithoutGuard(doc, OWN)).toEqual([]);
  });

  it('ignores same-account principals', () => {
    const doc = enc({
      Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Principal: { AWS: `arn:aws:iam::${OWN}:root` } }],
    });
    expect(crossAccountTrustWithoutGuard(doc, OWN)).toEqual([]);
  });

  it('ignores AWS service principals (Service, not AWS)', () => {
    const doc = enc({
      Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Principal: { Service: 'lambda.amazonaws.com' } }],
    });
    expect(crossAccountTrustWithoutGuard(doc, OWN)).toEqual([]);
  });

  it('flags a wildcard AWS principal', () => {
    const doc = enc({
      Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Principal: { AWS: '*' } }],
    });
    expect(crossAccountTrustWithoutGuard(doc, OWN)).toEqual(['*']);
  });

  it('handles the aws-us-gov partition ARN form', () => {
    const doc = enc({
      Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Principal: { AWS: 'arn:aws-us-gov:iam::999999999999:role/partner' } }],
    });
    expect(crossAccountTrustWithoutGuard(doc, OWN)).toEqual(['arn:aws-us-gov:iam::999999999999:role/partner']);
  });

  it('returns [] on malformed / non-JSON documents', () => {
    expect(crossAccountTrustWithoutGuard('not-json', OWN)).toEqual([]);
    expect(crossAccountTrustWithoutGuard('', OWN)).toEqual([]);
  });
});
