/**
 * Tests for core/conmon-strategy-emit.ts — LOOP-C.C6 Continuous Monitoring
 * Strategy + Plan (CA-7 / CA-7(1) / PM-31).
 *
 * The 13 numbered tests below are the per-slice §8 contract; five extra tests
 * exercise the reporting-endpoint override, the disabled-scanner row (Q4), the
 * .signed.json fallback dedupe, the config.sample.yaml fixture round-trip, and
 * the structured log event.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, copyFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import {
  emitConmonStrategyDocx, renderConmonStrategyDocx, buildConmonStrategyBodyXml,
  readKsiCatalog, readVdrScanners, ConmonKsiScopeError,
  type ConmonStrategyEmitOptions, type ConmonTeamMember, type EscalationThreshold,
} from '../../core/conmon-strategy-emit.ts';
import { log } from '../../core/log.ts';

const FIXTURE_DIR = resolve(import.meta.dirname ?? '', 'fixtures/conmon');

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-conmon-'));
  dirs.push(d);
  return d;
}
/** A tmp outDir seeded with both VDR fixture files. */
function tmpWithVdr(): string {
  const d = tmp();
  copyFileSync(join(FIXTURE_DIR, 'KSI-VDR-IL.signed.json'), join(d, 'KSI-VDR-IL.signed.json'));
  copyFileSync(join(FIXTURE_DIR, 'KSI-VDR-AUS.signed.json'), join(d, 'KSI-VDR-AUS.signed.json'));
  return d;
}
afterEach(() => {
  vi.restoreAllMocks();
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

const ROSTER: ConmonTeamMember[] = [
  { role: 'ConMon Lead', name: 'Dana Monitor', org: 'Acme Corp', email: 'dana@acme.example' },
  { role: 'POA&M Coordinator', name: 'Sam Poam', org: 'Acme Corp', email: 'sam@acme.example' },
  { role: 'Scan Operator', name: 'Riley Scan', org: 'Acme Corp', email: 'riley@acme.example' },
  { role: 'Risk Reviewer', name: 'Jordan Risk', org: 'Acme Corp', email: 'jordan@acme.example' },
];

const ESCALATION: EscalationThreshold[] = [
  { trigger: 'CISA KEV catalog entry', sla: '14 days', notify: ['ConMon Lead'] },
  { trigger: 'Critical vulnerability', sla: '30 days', notify: ['ConMon Lead'] },
  { trigger: 'Low vulnerability', sla: '180 days', notify: ['Scan Operator'] },
];

function baseOpts(over: Partial<ConmonStrategyEmitOptions> = {}): ConmonStrategyEmitOptions {
  return { outDir: '/nonexistent-conmon-dir', runId: 'r-conmon-test', frmrVersion: '0.9.43-beta', impactLevel: 'moderate', ...over };
}

/** Every required-for-signature operator field supplied. */
function fullOpts(dir: string, over: Partial<ConmonStrategyEmitOptions> = {}): ConmonStrategyEmitOptions {
  return baseOpts({
    outDir: dir,
    systemName: 'Acme Platform', systemId: 'acme-prod-1', cspOrganization: 'Acme Corp',
    conmonTeamRoster: ROSTER,
    escalationThresholds: ESCALATION,
    deviationRequestProcess: 'The ISSO prepares a DR; the AO approves before FedRAMP submission.',
    ...over,
  });
}

// ── Test 1 ──
it('emits 13 sections in order', () => {
  const { xml } = buildConmonStrategyBodyXml(fullOpts(tmpWithVdr()));
  const idx = (s: string) => xml.indexOf(s);
  const sections = [
    '1. Introduction',
    '2. Three-Tier Continuous Monitoring Strategy',
    '3. FedRAMP Continuous-Monitoring Cadence',
    '4. Controls Under Continuous Monitoring',
    '5. Vulnerability Scanning',
    '6. POA&amp;M Management', // XML-escaped ampersand in document.xml
    '7. Inventory Management',
    '8. Deviation Requests',
    '9. Reporting Endpoint',
    '10. Continuous Monitoring Team Roster',
    '11. Escalation Thresholds',
    '12. Collaborative Continuous Monitoring',
    '13. Plan Maintenance',
  ];
  for (let i = 0; i < sections.length; i++) {
    expect(idx(sections[i]!)).toBeGreaterThan(-1);
    if (i > 0) expect(idx(sections[i]!)).toBeGreaterThan(idx(sections[i - 1]!));
  }
});

// ── Test 2 ──
it('§4 KSI table has >= 20 rows from the real ksi-map.ts', () => {
  const catalog = readKsiCatalog();
  expect(catalog.length).toBeGreaterThanOrEqual(20);
  // Every row carries a real scope enum.
  for (const r of catalog) expect(['CLOUD', 'HYBRID', 'PROCESS', 'INHERITED']).toContain(r.scope);
  const { xml, stats } = buildConmonStrategyBodyXml(fullOpts(tmpWithVdr()));
  expect(stats.ksi_count).toBe(catalog.length);
  // Real KSI ids + the derived Automated column appear in §4.
  expect(xml).toContain('KSI-IAM-MFA');
  expect(xml).toContain('KSI-AFR-VDR');
});

// ── Test 3 ──
it('§5 emits one scanner row per VDR provider block found', () => {
  const dir = tmpWithVdr();
  const rows = readVdrScanners(dir);
  expect(rows.length).toBe(2); // one aws block + one gcp block
  const { xml, stats } = buildConmonStrategyBodyXml(fullOpts(dir));
  expect(stats.scanner_count).toBe(2);
  expect(xml).toContain('Amazon Inspector v2');
  expect(xml).toContain('GCP Container/Artifact Analysis');
});

// ── Test 4 ──
it('§5 emits a REQUIRES-OPERATOR-INPUT row when no VDR evidence is found', () => {
  const { xml, stats } = buildConmonStrategyBodyXml(fullOpts(tmp())); // empty outDir
  expect(stats.scanner_count).toBe(0);
  expect(xml).toContain('No KSI-*VDR* evidence found in this run');
  expect(xml).toContain('REQUIRES-OPERATOR-INPUT');
});

// ── Test 5 ──
it('§3 quotes the FedRAMP ConMon cadence source verbatim and cites the ConMon Playbook v1.0', () => {
  const { xml } = buildConmonStrategyBodyXml(fullOpts(tmpWithVdr()));
  // Verbatim FedRAMP ConMon Strategy Guide v3.2 §3.1 quote.
  expect(xml).toContain('The CSP is required to perform continuous monitoring of all security controls in the SSP at the frequency identified by the FedRAMP requirements');
  // Cadence source cited.
  expect(xml).toContain('Continuous Monitoring Playbook v1.0 (2025-11-17)');
  expect(xml).toContain('https://www.fedramp.gov/resources/documents/Continuous_Monitoring_Playbook.pdf');
});

// ── Test 6 ──
it('§9 endpoint = USDA Connect.gov for Low/Moderate', () => {
  const mod = buildConmonStrategyBodyXml(fullOpts(tmpWithVdr(), { impactLevel: 'moderate' }));
  expect(mod.stats.reporting_endpoint).toBe('usda-connect.gov');
  expect(mod.xml).toContain('USDA Connect.gov');
  const low = buildConmonStrategyBodyXml(fullOpts(tmpWithVdr(), { impactLevel: 'low' }));
  expect(low.stats.reporting_endpoint).toBe('usda-connect.gov');
});

// ── Test 7 ──
it('§9 endpoint = agency-direct for High', () => {
  const { xml, stats } = buildConmonStrategyBodyXml(fullOpts(tmpWithVdr(), { impactLevel: 'high' }));
  expect(stats.reporting_endpoint).toBe('agency-direct');
  expect(xml).toContain('Agency-direct');
});

// ── Test 8 ──
it('§12 enables collaborative ConMon when >1 agency customer + flag set', () => {
  const agencies = [
    { agency: 'Dept of Example', ato_letter_date: '2026-01-15' },
    { agency: 'Bureau of Samples', ato_letter_date: '2026-03-20' },
  ];
  const on = buildConmonStrategyBodyXml(fullOpts(tmpWithVdr(), { collaborativeConmon: true, agencyCustomers: agencies }));
  expect(on.stats.collaborative_conmon).toBe(true);
  expect(on.xml).toContain('Collaborative Continuous Monitoring is ENABLED');
  // Flag set but only one agency → not enabled.
  const oneAgency = buildConmonStrategyBodyXml(fullOpts(tmpWithVdr(), { collaborativeConmon: true, agencyCustomers: agencies.slice(0, 1) }));
  expect(oneAgency.stats.collaborative_conmon).toBe(false);
  // Multiple agencies but flag unset → not enabled.
  const flagOff = buildConmonStrategyBodyXml(fullOpts(tmpWithVdr(), { collaborativeConmon: false, agencyCustomers: agencies }));
  expect(flagOff.stats.collaborative_conmon).toBe(false);
});

// ── Test 9 ──
it('escalation defaults to FedRAMP-baseline values with a verify marker, sorted SLA ascending', () => {
  const { xml } = buildConmonStrategyBodyXml(fullOpts(tmpWithVdr(), { escalationThresholds: undefined }));
  expect(xml).toContain('CISA KEV catalog entry');
  expect(xml).toContain('180 days');
  expect(xml).toContain('REQUIRES-OPERATOR-INPUT-VERIFY');
  // KEV (21d) sorts before Low (180d).
  const s11 = xml.indexOf('11. Escalation Thresholds');
  const kev = xml.indexOf('CISA KEV catalog entry', s11);
  const low = xml.indexOf('Low vulnerability', s11);
  expect(kev).toBeGreaterThan(-1);
  expect(low).toBeGreaterThan(kev);
});

// ── Test 10 ──
it('writes to outPath when supplied', () => {
  const dir = tmpWithVdr();
  const outPath = join(dir, 'custom-conmon.docx');
  const r = emitConmonStrategyDocx(fullOpts(dir, { outPath }));
  expect(r.path).toBe(outPath);
  expect(existsSync(outPath)).toBe(true);
  expect(r.bytes).toBeGreaterThan(0);
});

// ── Test 11 ──
it('deterministic output (same inputs → byte-identical .docx)', () => {
  const dir = tmpWithVdr();
  const a = renderConmonStrategyDocx(fullOpts(dir));
  const b = renderConmonStrategyDocx(fullOpts(dir));
  expect(Buffer.compare(a.buffer, b.buffer)).toBe(0);
});

// ── Test 12 ──
it('ready_for_signature requires team + escalation + deviation process', () => {
  const dir = tmpWithVdr();
  expect(buildConmonStrategyBodyXml(fullOpts(dir)).stats.ready_for_signature).toBe(true);
  // Drop the roster → not ready.
  expect(buildConmonStrategyBodyXml(fullOpts(dir, { conmonTeamRoster: [] })).stats.ready_for_signature).toBe(false);
  // Drop operator escalation (falls back to baseline) → not ready.
  expect(buildConmonStrategyBodyXml(fullOpts(dir, { escalationThresholds: undefined })).stats.ready_for_signature).toBe(false);
  // Drop the deviation process → not ready.
  expect(buildConmonStrategyBodyXml(fullOpts(dir, { deviationRequestProcess: undefined })).stats.ready_for_signature).toBe(false);
});

// ── Test 13 ──
it('cites RFC-0026 in §8 and §12', () => {
  const { xml } = buildConmonStrategyBodyXml(fullOpts(tmpWithVdr(), {
    collaborativeConmon: true,
    agencyCustomers: [
      { agency: 'Dept of Example', ato_letter_date: '2026-01-15' },
      { agency: 'Bureau of Samples', ato_letter_date: '2026-03-20' },
    ],
  }));
  const s8 = xml.indexOf('8. Deviation Requests');
  const s9 = xml.indexOf('9. Reporting Endpoint');
  const s12 = xml.indexOf('12. Collaborative Continuous Monitoring');
  const s13 = xml.indexOf('13. Plan Maintenance');
  // RFC-0026 appears within §8 and within §12.
  expect(xml.indexOf('https://www.fedramp.gov/rfcs/0026/', s8)).toBeGreaterThan(s8);
  expect(xml.indexOf('https://www.fedramp.gov/rfcs/0026/', s8)).toBeLessThan(s9);
  expect(xml.indexOf('https://www.fedramp.gov/rfcs/0026/', s12)).toBeGreaterThan(s12);
  expect(xml.indexOf('https://www.fedramp.gov/rfcs/0026/', s12)).toBeLessThan(s13);
});

// ── Extra 14: reportingEndpoint override wins over the impact-derived default ──
it('reportingEndpoint override wins over the impact-level default', () => {
  const { stats } = buildConmonStrategyBodyXml(fullOpts(tmpWithVdr(), { impactLevel: 'high', reportingEndpoint: 'usda-connect.gov' }));
  expect(stats.reporting_endpoint).toBe('usda-connect.gov');
});

// ── Extra 15: a disabled scanner is listed (never omitted) — Q4 ──
it('§5 lists a scanner with detection disabled (never omits the gap)', () => {
  const dir = tmp();
  writeFileSync(join(dir, 'KSI-AFR-VDR.json'), JSON.stringify({
    ksi_id: 'KSI-AFR-VDR', collected_at: '2026-06-30T00:00:00.000Z',
    providers: [{
      provider: 'aws',
      evidence: [{ source: 'vdr.summary', captured_at: 'x', data: { total: 0, overdue: 0, kev_count: 0 } }],
      findings: [{ rule: 'aws.vdr.detection_capability_enabled', passed: false, severity: 'high', current_state: { summary: 'Amazon Inspector v2 is NOT enabled/reachable — no native continuous vulnerability detection.', observations: { detection_enabled: false } } }],
    }],
    rollup: { pass: false },
  }));
  const rows = readVdrScanners(dir);
  expect(rows.length).toBe(1);
  expect(rows[0]!.detection_enabled).toBe(false);
  const { xml, stats } = buildConmonStrategyBodyXml(fullOpts(dir));
  expect(stats.scanner_count).toBe(1);
  // The scanner appears with Detection Enabled = No.
  expect(xml).toContain('Amazon Inspector v2');
});

// ── Extra 16: reader dedupes .signed.json vs .json (prefers plain .json) ──
it('readVdrScanners prefers KSI-AFR-VDR.json over KSI-AFR-VDR.signed.json for the same base', () => {
  const dir = tmp();
  const plain = { ksi_id: 'KSI-AFR-VDR', collected_at: '2026-07-01T00:00:00.000Z', providers: [{ provider: 'aws', evidence: [], findings: [{ rule: 'aws.vdr.detection_capability_enabled', passed: true, severity: 'info', current_state: { summary: 'Amazon Inspector v2 is enabled.', observations: {} } }] }] };
  const signed = { ...plain, collected_at: '1999-01-01T00:00:00.000Z' };
  writeFileSync(join(dir, 'KSI-AFR-VDR.json'), JSON.stringify(plain));
  writeFileSync(join(dir, 'KSI-AFR-VDR.signed.json'), JSON.stringify(signed));
  const rows = readVdrScanners(dir);
  expect(rows.length).toBe(1); // deduped
  expect(rows[0]!.last_collected_at).toBe('2026-07-01T00:00:00.000Z'); // the plain .json won
});

// ── Extra 17: the config.sample.yaml fixture maps to a ready-for-signature doc ──
it('the config.sample.yaml fixture maps to a ready-for-signature Strategy + Plan', () => {
  const parsed: any = parseYaml(readFileSync(join(FIXTURE_DIR, 'config.sample.yaml'), 'utf8'));
  const c = parsed.conmon;
  const dir = tmpWithVdr();
  const { stats } = buildConmonStrategyBodyXml(fullOpts(dir, {
    conmonTeamRoster: c.team,
    escalationThresholds: c.escalation,
    deviationRequestProcess: c.deviation_request_process,
    reportingEndpoint: c.reporting_endpoint,
    collaborativeConmon: c.collaborative_conmon,
    agencyCustomers: c.agency_customers,
  }));
  expect(stats.ready_for_signature).toBe(true);
  expect(stats.reporting_endpoint).toBe('usda-connect.gov');
  expect(stats.collaborative_conmon).toBe(true);
  expect(stats.agency_customer_count).toBe(2);
});

// ── Extra 18: emits a structured log event with counts ──
it('emits a structured log event with ksi_count + scanner_count', () => {
  const dir = tmpWithVdr();
  const spy = vi.spyOn(log, 'info').mockImplementation(() => {});
  emitConmonStrategyDocx(fullOpts(dir));
  const evt = spy.mock.calls.map((c) => c[0]).find((a: any) => a?.event === 'conmon-strategy.emitted');
  expect(evt).toBeTruthy();
  expect((evt as any).ksi_count).toBeGreaterThanOrEqual(20);
  expect((evt as any).scanner_count).toBe(2);
  expect(typeof (evt as any).bytes).toBe('number');
});

describe('ConmonKsiScopeError', () => {
  it('is a typed error', () => {
    const e = new ConmonKsiScopeError(3);
    expect(e).toBeInstanceOf(ConmonKsiScopeError);
    expect(e.message).toContain('expected >= 20');
  });
});
