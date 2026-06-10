/**
 * Integration tests for core/risk-score-emit.ts — LOOP-B.B1 disk emitter.
 *
 * Covers per-slice doc §8 T17-T19 plus REO checks:
 *   - rewrites every KSI-*.json envelope in place with finding.risk_score (T17)
 *   - emits risk-scores.json with a G3 provenance block (check:provenance) (T18)
 *   - the OSCAL POA&M findingProps surface composite-score + cvss-* + epss-* (T19)
 *   - the emitted envelope carries a verifiable detached Ed25519 signature
 *   - the EPSS cache lands provenance-stamped (G3-clean in out/)
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { EvidenceFile, Finding } from '../../core/envelope.ts';
import { verifyDetached } from '../../core/sign.ts';
import { emitRiskScores, serializeUnsignedCanonical, RISK_SCORES_FILENAME, EPSS_CACHE_FILENAME } from '../../core/risk-score-emit.ts';
import { emitOscalPoam } from '../../core/oscal-poam.ts';

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-rse-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

const FIXED = () => new Date('2026-06-09T12:00:00.000Z');
const CHECK_PROVENANCE = fileURLToPath(new URL('../../scripts/check-provenance.mjs', import.meta.url));

function mkFinding(over: Partial<Finding> = {}): Finding {
  return {
    rule: 'aws.vdr.cve',
    passed: false,
    severity: 'high',
    current_state: { summary: 's', observations: {} },
    target_state: { summary: 't', rationale: 'r' },
    gap: { description: 'g', affected_resources: [{ type: 'aws_instance', identifier: 'arn:x' }] },
    ...over,
  };
}

function writeEnvelope(outDir: string, ksiId: string, findings: Finding[]): void {
  const env: EvidenceFile = {
    ksi_id: ksiId,
    ksi_name: `${ksiId} name`,
    ksi_statement: 'verbatim FRMR statement',
    scope: 'CLOUD',
    frmr_version: '25.06A',
    run_id: 'run-test',
    collected_at: '2026-06-09T00:00:00.000Z',
    providers: [
      {
        provider: 'aws',
        evidence: [{ source: 'ec2.DescribeInstances', captured_at: '2026-06-09T00:00:00.000Z', data: {} }],
        findings,
      },
    ],
    rollup: {
      pass: findings.every((f) => f.passed),
      passing_findings: findings.filter((f) => f.passed).length,
      failing_findings: findings.filter((f) => !f.passed).length,
      warnings: [],
      missing_evidence: [],
      alternatives_in_play: 0,
    },
  };
  writeFileSync(resolve(outDir, `${ksiId}.json`), JSON.stringify(env, null, 2));
}

function writeInventory(outDir: string): void {
  writeFileSync(
    resolve(outDir, 'inventory.json'),
    JSON.stringify(
      {
        assets: [{ identifier: 'arn:x', data_classification: 'cui', public_facing: true }],
        provenance: { emitter: 'test', emittedAt: '2026-06-09T00:00:00.000Z', sourceCalls: ['fixture'], signingKeyId: 'fixture' },
      },
      null,
      2,
    ),
  );
}

describe('emitRiskScores', () => {
  it('T17: attaches finding.risk_score to every finding in every KSI envelope (rewritten in place)', async () => {
    const outDir = tmp();
    writeInventory(outDir);
    writeEnvelope(outDir, 'KSI-VDR-SCAN', [
      mkFinding({ references: [{ title: 'NVD', url: 'u', cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] }),
    ]);
    writeEnvelope(outDir, 'KSI-IAM-MFA', [mkFinding({ rule: 'aws.iam.mfa', severity: 'medium' })]);

    const r = await emitRiskScores({ outDir, runId: 'run-test', epssEnabled: false, now: FIXED });
    expect(r.scored_findings + r.unscored_findings).toBe(2);

    const vdr = JSON.parse(readFileSync(resolve(outDir, 'KSI-VDR-SCAN.json'), 'utf8')) as EvidenceFile;
    expect(vdr.providers[0]!.findings[0]!.risk_score).toBeTruthy();
    expect(vdr.providers[0]!.findings[0]!.risk_score!.cvss!.base_score).toBe(9.8);
    const iam = JSON.parse(readFileSync(resolve(outDir, 'KSI-IAM-MFA.json'), 'utf8')) as EvidenceFile;
    expect(iam.providers[0]!.findings[0]!.risk_score).toBeTruthy();
    expect(iam.providers[0]!.findings[0]!.risk_score!.formula_version).toBe('risk-score.v1');
  });

  it('T18: emits risk-scores.json that passes check:provenance (G3)', async () => {
    const outDir = tmp();
    writeInventory(outDir);
    writeEnvelope(outDir, 'KSI-VDR-SCAN', [mkFinding()]);
    await emitRiskScores({ outDir, runId: 'run-test', epssEnabled: false, now: FIXED });

    const doc = JSON.parse(readFileSync(resolve(outDir, RISK_SCORES_FILENAME), 'utf8'));
    expect(doc.provenance.emitter).toBe('core/risk-score-emit.ts');
    expect(Array.isArray(doc.provenance.sourceCalls)).toBe(true);
    expect(doc.provenance.sourceCalls.length).toBeGreaterThan(0);
    expect(doc.provenance.signingKeyId).toBeTruthy();

    // The G3 guardrail script must exit 0 over the output directory.
    expect(() => execFileSync('node', [CHECK_PROVENANCE, '--dir', outDir], { stdio: 'pipe' })).not.toThrow();
  });

  it('emits a verifiable detached Ed25519 signature over the blanked canonical bytes', async () => {
    const outDir = tmp();
    writeInventory(outDir);
    writeEnvelope(outDir, 'KSI-VDR-SCAN', [mkFinding()]);
    await emitRiskScores({ outDir, runId: 'run-test', epssEnabled: false, now: FIXED });

    const doc = JSON.parse(readFileSync(resolve(outDir, RISK_SCORES_FILENAME), 'utf8'));
    const bytes = Buffer.from(serializeUnsignedCanonical(doc), 'utf8');
    expect(verifyDetached(bytes, doc.signature)).toBe(true);
  });

  it('T19: the OSCAL POA&M emits composite-score + cvss-* + risk-score-source props', async () => {
    const outDir = tmp();
    writeInventory(outDir);
    writeEnvelope(outDir, 'KSI-VDR-SCAN', [
      mkFinding({ references: [{ title: 'NVD', url: 'u', cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] }),
    ]);
    await emitRiskScores({ outDir, runId: 'run-test', epssEnabled: false, now: FIXED });

    const r = emitOscalPoam({ outDir, runId: 'run-test', frmrVersion: '25.06A' });
    expect(r.path).not.toBeNull();
    const poam = readFileSync(r.path!, 'utf8');
    expect(poam).toContain('"composite-score"');
    expect(poam).toContain('"cvss-version"');
    expect(poam).toContain('"risk-score-source-cvss"');
    expect(poam).toContain('"risk-score-formula"');
  });

  it('stamps the EPSS cache with provenance + signature (G3-clean) on a live-EPSS run', async () => {
    const outDir = tmp();
    writeInventory(outDir);
    writeEnvelope(outDir, 'KSI-VDR-SCAN', [
      mkFinding({ references: [{ title: 'NVD', url: 'u', cve_id: 'CVE-2021-44228', cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] }),
    ]);
    const fetchImpl = (async () =>
      ({
        ok: true,
        status: 200,
        json: async () => ({ data: [{ cve: 'CVE-2021-44228', epss: '0.97214', percentile: '0.99876', date: '2026-06-09' }] }),
      }) as unknown as Response) as unknown as typeof fetch;

    const r = await emitRiskScores({ outDir, runId: 'run-test', epssEnabled: true, now: FIXED, fetchImpl });
    expect(r.epss_api_calls).toBe(1);
    expect(r.cve_lookups).toBe(1);

    const cachePath = resolve(outDir, EPSS_CACHE_FILENAME);
    expect(existsSync(cachePath)).toBe(true);
    const cache = JSON.parse(readFileSync(cachePath, 'utf8'));
    expect(cache.provenance.emitter).toBe('core/risk-score-emit.ts');
    expect(cache.provenance.signingKeyId).toBeTruthy();
    expect(cache.entries['CVE-2021-44228']).toBeTruthy();

    // The whole out/ dir (incl. the dotfile cache) must pass G3.
    expect(() => execFileSync('node', [CHECK_PROVENANCE, '--dir', outDir], { stdio: 'pipe' })).not.toThrow();
  });
});
