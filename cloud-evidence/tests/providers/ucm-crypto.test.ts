/**
 * Offline unit tests for the UCM (Using Cryptographic Modules) collectors.
 *
 * No live cloud calls: we assert the module surface (exported collectUcm fns),
 * the presence + shape of the CMVP reference tables, and the per-level
 * severity/key-word mapping via the small exported helpers. Behavioral
 * pass/fail of the collectors against real SDK data is exercised by the
 * provider smoke test; here we keep it purely deterministic.
 */
import { describe, it, expect } from 'vitest';

import * as awsCrypto from '../../providers/aws/crypto.ts';
import * as gcpCrypto from '../../providers/gcp/crypto.ts';
import type { ImpactTier } from '../../core/envelope.ts';

describe('UCM collectors — module surface', () => {
  it('AWS crypto.ts exports collectUcm', () => {
    expect(typeof awsCrypto.collectUcm).toBe('function');
  });

  it('GCP crypto.ts exports collectUcm', () => {
    expect(typeof gcpCrypto.collectUcm).toBe('function');
  });
});

describe('UCM — CMVP reference tables', () => {
  it('AWS reference table cites KMS HSM cert #4884 (FIPS 140-3 L3, active)', () => {
    const t = awsCrypto.AWS_CMVP_REFERENCE;
    expect(t).toBeTruthy();
    expect(t.kms_hsm.cert).toBe('4884');
    expect(t.kms_hsm.standard).toBe('FIPS 140-3');
    expect(t.kms_hsm.level).toBe(3);
    expect(t.kms_hsm.active).toBe(true);
    // AWS-LC FIPS backs the *-FIPS-* TLS policies + CloudHSM is an alternative.
    expect(t.aws_lc_fips.module).toMatch(/AWS-LC/i);
    expect(t.cloudhsm.standard).toBe('FIPS 140-2');
  });

  it('GCP reference table cites BoringCrypto cert #5104 (FIPS 140-3 L1, active)', () => {
    const t = gcpCrypto.GCP_CMVP_REFERENCE;
    expect(t).toBeTruthy();
    expect(t.boringcrypto.cert).toBe('5104');
    expect(t.boringcrypto.standard).toBe('FIPS 140-3');
    expect(t.boringcrypto.level).toBe(1);
    expect(t.boringcrypto.active).toBe(true);
    expect(t.cloud_hsm.standard).toBe('FIPS 140-2');
    expect(t.cloud_hsm.level).toBe(3);
  });
});

describe('UCM — per-level severity / key-word mapping (UCM-CSX-UVM)', () => {
  const cases: Array<{ level: ImpactTier; keyWord: string; severity: string }> = [
    { level: 'low', keyWord: 'MAY', severity: 'info' },
    { level: 'moderate', keyWord: 'SHOULD', severity: 'medium' },
    { level: 'high', keyWord: 'MUST', severity: 'high' },
  ];

  for (const { level, keyWord, severity } of cases) {
    it(`${level} -> ${keyWord} / failing severity '${severity}'`, () => {
      expect(awsCrypto.keyWordForUcm(level)).toBe(keyWord);
      expect(awsCrypto.severityForUcm(level)).toBe(severity);
      // GCP re-exports the same helpers; they must agree.
      expect(gcpCrypto.keyWordForUcm(level)).toBe(keyWord);
      expect(gcpCrypto.severityForUcm(level)).toBe(severity);
    });
  }
});

describe('UCM — impact level from env', () => {
  const ORIGINAL = process.env.CLOUD_EVIDENCE_IMPACT_LEVEL;
  const restore = () => {
    if (ORIGINAL === undefined) delete process.env.CLOUD_EVIDENCE_IMPACT_LEVEL;
    else process.env.CLOUD_EVIDENCE_IMPACT_LEVEL = ORIGINAL;
  };

  it('defaults to moderate when unset', () => {
    delete process.env.CLOUD_EVIDENCE_IMPACT_LEVEL;
    expect(awsCrypto.impactLevelFromEnv()).toBe('moderate');
    restore();
  });

  it('reads low / high (case-insensitive) and falls back to moderate on garbage', () => {
    process.env.CLOUD_EVIDENCE_IMPACT_LEVEL = 'LOW';
    expect(awsCrypto.impactLevelFromEnv()).toBe('low');
    process.env.CLOUD_EVIDENCE_IMPACT_LEVEL = 'High';
    expect(awsCrypto.impactLevelFromEnv()).toBe('high');
    process.env.CLOUD_EVIDENCE_IMPACT_LEVEL = 'banana';
    expect(awsCrypto.impactLevelFromEnv()).toBe('moderate');
    restore();
  });
});
