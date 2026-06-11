/**
 * Tests for core/conmon-report.ts — the Monthly ConMon Analysis Report (LOOP-E.E1).
 *
 * Covers per-slice doc §8 tests 1-13: posture from KSI envelopes, POA&M
 * activity from the run diff, scan coverage + internet-reachable compliance
 * from inventory, REQUIRES-OPERATOR-INPUT sentinels (incident_summary +
 * system.fedrampId), file emission (json/md/pdf), PDF byte markers + embedded
 * text, the provenance block, malformed-month rejection, the pinned playbook
 * version, and byte-identical determinism.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, existsSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inflateSync } from 'node:zlib';
import type { EvidenceFile, Finding, Severity } from '../../core/envelope.ts';
import {
  buildConmonMonthlyReport,
  emitConmonMonthlyReport,
  InvalidMonthFormatError,
  TBD,
  type ConmonReportBuildOpts,
  type ConmonPlaybookPin,
} from '../../core/conmon-report.ts';

const PLAYBOOK_PATH = fileURLToPath(new URL('../../docs/fedramp-conmon-playbook.generated.json', import.meta.url));

const PLAYBOOK: ConmonPlaybookPin = {
  remediation_table: { critical: 30, high: 30, moderate: 90, low: 180, accepted_threshold_days: 192 },
  scan_cadence: { monthly_inventory: 1, internet_reachable_days: 3, internal_days: 7 },
  monthly_deliverables: ['POA&M', 'inventory'],
  playbook_version: '1.0',
  playbook_published: '2025-11-17',
  sha256: 'd96379ecc63a8f3b31093ffedbbfba4cb8627f8d0d75b458ebd0504eb817e945',
};

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-conmon-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

function mkFinding(severity: Severity, passed: boolean, over: Partial<Finding> = {}): Finding {
  return {
    rule: `rule.${severity}.${passed}`,
    passed,
    severity,
    current_state: { summary: 's', observations: {} },
    target_state: { summary: 't', rationale: 'r' },
    ...over,
  };
}

function mkEnvelope(ksiId: string, pass: boolean, findings: Finding[]): EvidenceFile {
  return {
    ksi_id: ksiId,
    ksi_name: `${ksiId} name`,
    ksi_statement: 'verbatim FRMR statement',
    scope: 'CLOUD',
    frmr_version: '25.06A',
    run_id: 'run-test',
    collected_at: '2026-07-01T00:00:00.000Z',
    providers: [{ provider: 'aws', evidence: [{ source: 'sdk.call', captured_at: '2026-07-01T00:00:00.000Z', data: {} }], findings }],
    rollup: { pass, passing_findings: findings.filter((f) => f.passed).length, failing_findings: findings.filter((f) => !f.passed).length, warnings: [], missing_evidence: [], alternatives_in_play: 0 },
  };
}

function baseOpts(over: Partial<ConmonReportBuildOpts> = {}): ConmonReportBuildOpts {
  return {
    runId: 'run-test',
    reportMonth: '2026-07',
    generatedAt: '2026-07-15T00:00:00.000Z',
    now: new Date('2026-07-15T00:00:00.000Z'),
    system: { impactLevel: 'moderate' },
    samplingPct: 100,
    frmrVersion: '25.06A',
    playbook: PLAYBOOK,
    poam: null,
    envelopes: [],
    inventory: null,
    diffReport: null,
    scn: null,
    deviationLedger: null,
    kevCveSet: null,
    sourcePresence: {},
    ...over,
  };
}

describe('conmon-report builder', () => {
  it('builds a posture snapshot from KSI envelopes', () => {
    const envelopes = [
      mkEnvelope('KSI-A-1', true, [mkFinding('low', true)]),
      mkEnvelope('KSI-B-2', false, [mkFinding('high', false)]),
      mkEnvelope('KSI-C-3', false, [mkFinding('medium', false)]),
    ];
    const r = buildConmonMonthlyReport(baseOpts({ envelopes }));
    expect(r.posture.ksi_pass_rate).toBeCloseTo(1 / 3, 10);
    expect(r.posture.open_poam_count).toBe(2);
    expect(r.posture.open_by_severity.high).toBe(1);
    expect(r.posture.open_by_severity.medium).toBe(1);
  });

  it('aggregates POA&M activity month-over-month from diff-report', () => {
    const r = buildConmonMonthlyReport(baseOpts({ diffReport: { new_findings_count: 2, fixed_count: 1, regressed_count: 3 } }));
    expect(r.poam_activity.opened).toBe(2);
    expect(r.poam_activity.closed).toBe(1);
    expect(r.poam_activity.status_changes).toBe(3);
  });

  it('computes scan_coverage from inventory.json and ksi-map', () => {
    const assets = Array.from({ length: 20 }, (_, i) => ({ uniqueId: `a${i}`, assetType: i % 2 ? 'Web' : 'Database', inLatestScan: true, publicFacing: false }));
    const r = buildConmonMonthlyReport(baseOpts({ inventory: { asset_count: 20, assets } }));
    expect(r.scan_coverage.assets_total).toBe(20);
    expect(r.scan_coverage.assets_scanned).toBe(20);
    expect(r.scan_coverage.by_class.Web!.total).toBe(10);
  });

  it('flags internet_reachable_compliant=false when any internet-reachable asset is missing from scan list', () => {
    const assets = [
      { uniqueId: 'pub-scanned', assetType: 'Web', publicFacing: true, inLatestScan: true },
      { uniqueId: 'pub-unscanned', assetType: 'Web', publicFacing: true, inLatestScan: false },
    ];
    const r = buildConmonMonthlyReport(baseOpts({ inventory: { asset_count: 2, assets } }));
    expect(r.scan_coverage.internet_reachable_compliant).toBe(false);
  });

  it('emits REQUIRES-OPERATOR-INPUT for incident_summary when tracker integration absent', () => {
    const r = buildConmonMonthlyReport(baseOpts());
    expect(r.incident_summary).toBe(TBD);
  });

  it('emits REQUIRES-OPERATOR-INPUT for system.fedrampId when --fedramp-package-id missing', () => {
    const r = buildConmonMonthlyReport(baseOpts());
    expect(r.system.fedrampId).toBe(TBD);
    const withId = buildConmonMonthlyReport(baseOpts({ system: { impactLevel: 'moderate', fedrampId: 'F1809051234' } }));
    expect(withId.system.fedrampId).toBe('F1809051234');
  });

  it('JSON output carries a provenance block naming this emitter (core/conmon-report.ts)', () => {
    const r = buildConmonMonthlyReport(baseOpts());
    expect(r.provenance.emitter).toBe('core/conmon-report.ts');
    expect(r.provenance.sourceCalls.length).toBeGreaterThan(0);
    expect(r.provenance.emittedAt).toBe('2026-07-15T00:00:00.000Z');
  });

  it('throws when --month is malformed (not YYYY-MM)', () => {
    expect(() => buildConmonMonthlyReport(baseOpts({ reportMonth: '2026-7' }))).toThrow(InvalidMonthFormatError);
    expect(() => buildConmonMonthlyReport(baseOpts({ reportMonth: '2026/07' }))).toThrow(InvalidMonthFormatError);
  });

  it('uses pinned playbook version from docs/fedramp-conmon-playbook.generated.json', () => {
    const r = buildConmonMonthlyReport(baseOpts());
    expect(r.provenance.conmonPlaybookVersion).toBe('1.0');
  });

  it('is deterministic — same inputs produce byte-identical JSON', () => {
    const envelopes = [mkEnvelope('KSI-A-1', false, [mkFinding('high', false)])];
    const a = JSON.stringify(buildConmonMonthlyReport(baseOpts({ envelopes })), null, 2);
    const b = JSON.stringify(buildConmonMonthlyReport(baseOpts({ envelopes })), null, 2);
    expect(a).toBe(b);
  });

  it('counts KEV exposure deduped against the catalog', () => {
    const env = mkEnvelope('KSI-V-1', false, [
      mkFinding('high', false, { references: [{ title: 'a', url: 'u', cve_id: 'CVE-2021-44228' }, { title: 'b', url: 'u', cve_id: 'cve-2021-44228' }] }),
    ]);
    const r = buildConmonMonthlyReport(baseOpts({ envelopes: [env], kevCveSet: new Set(['CVE-2021-44228']) }));
    expect(r.posture.kev_exposure_count).toBe(1); // deduped, case-insensitive
  });
});

describe('conmon-report disk emitter', () => {
  it('writes JSON + MD + PDF files with the expected names conmon-monthly-2026-07.{json,md,pdf}', async () => {
    const outDir = tmp();
    const r = await emitConmonMonthlyReport({ outDir, runId: 'run-test', reportMonth: '2026-07', frmrVersion: '25.06A', system: {}, playbookPath: PLAYBOOK_PATH, generatedAt: '2026-07-15T00:00:00.000Z' });
    expect(existsSync(join(outDir, 'conmon-monthly-2026-07.json'))).toBe(true);
    expect(existsSync(join(outDir, 'conmon-monthly-2026-07.md'))).toBe(true);
    expect(existsSync(join(outDir, 'conmon-monthly-2026-07.pdf'))).toBe(true);
    expect(r.jsonPath).toBe(join(outDir, 'conmon-monthly-2026-07.json'));
    // The signed JSON carries a verifiable detached signature + filled signingKeyId.
    const doc = JSON.parse(readFileSync(r.jsonPath, 'utf8'));
    expect(doc.signature?.algorithm).toBe('ed25519');
    expect(doc.provenance.signingKeyId).toBe(doc.signature.keyId);
  });

  it('PDF starts with %PDF-1.4 magic bytes and ends with %%EOF', async () => {
    const outDir = tmp();
    const r = await emitConmonMonthlyReport({ outDir, runId: 'run-test', reportMonth: '2026-07', frmrVersion: '25.06A', system: { name: 'Acme Cloud Platform' }, playbookPath: PLAYBOOK_PATH });
    const pdf = readFileSync(r.pdfPath);
    expect(pdf.subarray(0, 8).toString('latin1')).toBe('%PDF-1.4');
    expect(pdf.toString('latin1').trimEnd().endsWith('%%EOF')).toBe(true);
  });

  it('PDF contains the system name + report month rendered as text in a content stream', async () => {
    const outDir = tmp();
    const r = await emitConmonMonthlyReport({ outDir, runId: 'run-test', reportMonth: '2026-07', frmrVersion: '25.06A', system: { name: 'Acme Cloud Platform' }, playbookPath: PLAYBOOK_PATH });
    const pdf = readFileSync(r.pdfPath);
    const s = pdf.toString('latin1');
    const re = /<< \/Length (\d+) \/Filter \/FlateDecode >>\nstream\n/g;
    let m: RegExpExecArray | null;
    let text = '';
    while ((m = re.exec(s))) {
      const len = Number(m[1]);
      const start = m.index + m[0].length;
      text += inflateSync(pdf.subarray(start, start + len)).toString('latin1');
    }
    expect(text).toContain('Acme Cloud Platform');
    expect(text).toContain('2026-07');
  });

  it('rejects a malformed --month at the emitter boundary', async () => {
    const outDir = tmp();
    await expect(
      emitConmonMonthlyReport({ outDir, runId: 'run-test', reportMonth: '2026-13', frmrVersion: '25.06A', system: {}, playbookPath: PLAYBOOK_PATH }),
    ).rejects.toThrow(InvalidMonthFormatError);
  });
});
