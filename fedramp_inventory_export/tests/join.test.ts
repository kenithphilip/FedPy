import { describe, it, expect } from 'vitest';
import { loadRun } from '../src/load.ts';
import {
  flattenFindings,
  joinAssetsToFindings,
  buildAccountComplianceRows,
  rollupRequirements,
  buildBenchmarks,
  joinRun,
} from '../src/join.ts';
import {
  writeSampleRun,
  sampleAssets,
  sampleKsiEncryption,
  sampleAwarenessFrr,
  sampleKsiRootMfa,
} from './fixtures.ts';

describe('loader', () => {
  it('loads inventory + only real evidence envelopes (skips manifest.json)', () => {
    const dir = writeSampleRun();
    const run = loadRun(dir);
    expect(run.assets).toHaveLength(3);
    expect(run.evidence.map((e) => e.ksi_id).sort()).toEqual(['KSI-CNA-ENC', 'VDR-FRP-CAP']);
    expect(run.accountIds).toContain('111122223333');
  });

  it('throws an actionable error when inventory.json is absent', () => {
    expect(() => loadRun('/tmp/does-not-exist-fedpy-xyz')).toThrow(/inventory\.json/);
  });
});

describe('flattenFindings', () => {
  it('flattens findings with parent context + affected identifiers', () => {
    const flat = flattenFindings([sampleKsiEncryption()]);
    expect(flat).toHaveLength(2);
    const fail = flat.find((f) => !f.passed)!;
    expect(fail.requirementId).toBe('KSI-CNA-ENC');
    expect(fail.severity).toBe('high');
    expect(fail.affectedIdentifiers).toContain('arn:aws:s3:::my-sensitive-bucket');
    expect(fail.affectedDisplay).toContain('arn:aws:s3:::my-sensitive-bucket');
  });

  it('renders an account-scope ("none") failing finding as "account-wide", not blank', () => {
    // sampleKsiRootMfa has a gap whose affected id is the bare account id.
    const flat = flattenFindings([sampleKsiRootMfa()]);
    const fail = flat.find((f) => !f.passed)!;
    // account id is not a real ARN → not matchable, but display must not be blank.
    expect(fail.affectedDisplay).not.toBe('');
  });
});

describe('joinAssetsToFindings', () => {
  it('marks the S3 bucket non-compliant and unmatched assets not-assessed', () => {
    const findings = flattenFindings([sampleKsiEncryption()]);
    const ac = joinAssetsToFindings(sampleAssets(), findings);
    const bucket = ac.find((a) => a.asset.uniqueId.includes('my-sensitive-bucket'))!;
    expect(bucket.status).toBe('non-compliant');
    expect(bucket.worstSeverity).toBe('high');
    expect(bucket.failingRules).toContain('KSI-CNA-ENC/aws.s3.encryption_enabled');
    expect(bucket.failingControls).toContain('SC-28');

    const gcp = ac.find((a) => a.asset.provider === 'gcp')!;
    expect(gcp.status).toBe('not-assessed'); // no finding names it
  });

  it('marks an assessed-but-clean asset compliant (via assessed_resource_ids)', () => {
    const findings = flattenFindings([sampleKsiEncryption()]);
    const assessed = new Set(['//compute.googleapis.com/projects/p/zones/us-central1-a/instances/db-1']);
    const ac = joinAssetsToFindings(sampleAssets(), findings, assessed);
    const gcp = ac.find((a) => a.asset.provider === 'gcp')!;
    expect(gcp.status).toBe('compliant'); // assessed, no failing finding
    const bucket = ac.find((a) => a.asset.uniqueId.includes('my-sensitive-bucket'))!;
    expect(bucket.status).toBe('non-compliant'); // failing finding still wins
  });
});

describe('buildAccountComplianceRows', () => {
  it('surfaces an account-level finding as a synthetic account row', () => {
    const findings = flattenFindings([sampleKsiRootMfa()]);
    // No real asset matches the bare account id → account-scope.
    const rows = buildAccountComplianceRows(['111122223333'], findings, () => false);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.asset.uniqueId).toBe('account:111122223333');
    expect(rows[0]!.status).toBe('non-compliant');
    expect(rows[0]!.worstSeverity).toBe('critical');
    expect(rows[0]!.failingRules).toContain('KSI-IAM-MFA/aws.iam.root_mfa_enabled');
  });

  it('does not create account rows when findings match real assets', () => {
    const findings = flattenFindings([sampleKsiEncryption()]);
    // The bucket finding matches a real asset → not account-scope.
    const rows = buildAccountComplianceRows(['111122223333'], findings, () => true);
    expect(rows).toHaveLength(0);
  });
});

describe('rollupRequirements', () => {
  it('rolls KSI to partially-met and awareness FRR to awareness', () => {
    const rollups = rollupRequirements([sampleKsiEncryption(), sampleAwarenessFrr()]);
    const enc = rollups.find((r) => r.requirementId === 'KSI-CNA-ENC')!;
    expect(enc.status).toBe('partially-met');
    expect(enc.passingFindings).toBe(1);
    expect(enc.failingFindings).toBe(1);

    const frr = rollups.find((r) => r.requirementId === 'VDR-FRP-CAP')!;
    expect(frr.status).toBe('awareness');
  });
});

describe('buildBenchmarks', () => {
  it('produces both Rev5 (Moderate baseline) and 20x framings', () => {
    const b = buildBenchmarks([sampleKsiEncryption(), sampleAwarenessFrr()]);
    // Rev5 Moderate baseline is large (287 controls) and includes SC-28.
    expect(b.rev5.impact_level).toBe('moderate');
    expect(b.rev5.framework).toBe('rev5');
    expect(b.rev5.totals.in_scope).toBeGreaterThan(100);
    const sc28 = b.rev5.controls.find((c) => c.id === 'sc-28')!;
    expect(sc28).toBeDefined();
    // sc-28 has a mixed (pass+fail) finding set → partially-satisfied.
    expect(sc28.status).toBe('partially-satisfied');

    // 20x framing: in-scope set is the controls the evaluated requirements reference.
    expect(b.twentyX.framework).toBe('20x');
    expect(b.twentyX.controls.some((c) => c.id === 'sc-28')).toBe(true);
  });
});

describe('joinRun summary', () => {
  it('computes a coherent compliance summary', () => {
    const dir = writeSampleRun();
    const run = loadRun(dir);
    const result = joinRun(run);
    expect(result.summary.assetCount).toBe(3);
    expect(result.summary.assetsNonCompliant).toBe(1);
    expect(result.summary.assetsNotAssessed).toBeGreaterThanOrEqual(1);
    expect(result.summary.requirementsAwareness).toBe(1);
    expect(result.summary.findingsFailing).toBe(1);
    expect(result.summary.impactLevel).toBe('moderate');
  });
});
