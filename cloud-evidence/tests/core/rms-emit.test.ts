/**
 * Tests for core/rms-emit.ts — LOOP-C.C7 Risk Management Strategy (PM-9).
 *
 * The 12 numbered tests below are the per-slice §8 contract; six extra tests
 * exercise the §10 overdue + oldest-open-age computation, the PoamSeverityError
 * guard (Risk 2), the §6 acceptance-policy summary, the §7 ConMon cross-link,
 * the config.sample.yaml fixture round-trip, and the structured log event.
 */
import { it, expect, describe, afterEach, vi } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, copyFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import {
  emitRmsDocx, renderRmsDocx, buildRmsBodyXml,
  readRiskRegister, readAcceptancePolicy, summarizePoam, PoamSeverityError,
  type RmsEmitOptions, type RiskTolerance, type ExecutiveOversight,
} from '../../core/rms-emit.ts';
import { log } from '../../core/log.ts';

const FIXTURE_DIR = resolve(import.meta.dirname ?? '', 'fixtures/rms');

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-rms-'));
  dirs.push(d);
  return d;
}
/** Seed a tmp outDir with the poam + risk-register + acceptance snapshots + a ConMon doc. */
function tmpFull(): string {
  const d = tmp();
  copyFileSync(join(FIXTURE_DIR, 'poam.sample.json'), join(d, 'poam.json'));
  copyFileSync(join(FIXTURE_DIR, 'risk-register.sample.json'), join(d, 'risk-register.json'));
  writeFileSync(join(d, '.risk-acceptances.json'), JSON.stringify({ items: [{ uuid: 'a1' }, { uuid: 'a2' }] }));
  writeFileSync(join(d, '.compensating-controls.json'), JSON.stringify({ items: [{ uuid: 'c1' }] }));
  writeFileSync(join(d, 'conmon-strategy.docx'), 'PK (fixture docx bytes)');
  return d;
}
afterEach(() => {
  vi.restoreAllMocks();
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

const TOLERANCE: RiskTolerance = { confidentiality: 'moderate', integrity: 'moderate', availability: 'low' };
const EXECUTIVE: ExecutiveOversight[] = [
  { role: 'Authorizing Official', name: 'Alex Authorizing', org: 'Sponsoring Agency' },
  { role: 'Chief Information Security Officer', name: 'Casey Security', org: 'Acme Corp' },
];

function baseOpts(over: Partial<RmsEmitOptions> = {}): RmsEmitOptions {
  return { outDir: '/nonexistent-rms-dir', runId: 'r-rms-test', frmrVersion: '0.9.43-beta', impactLevel: 'moderate', ...over };
}

/** Every required-for-signature operator field supplied (over a full outDir). */
function fullOpts(dir: string, over: Partial<RmsEmitOptions> = {}): RmsEmitOptions {
  return baseOpts({
    outDir: dir,
    systemName: 'Acme Platform', systemId: 'acme-prod-1', cspOrganization: 'Acme Corp',
    agencyCustomerCount: 2,
    riskTolerance: TOLERANCE,
    executiveOversight: EXECUTIVE,
    ...over,
  });
}

// ── Test 1 ──
it('emits 11 sections in order', () => {
  const { xml } = buildRmsBodyXml(fullOpts(tmpFull()));
  const idx = (s: string) => xml.indexOf(s);
  const sections = [
    '1. Introduction',
    '2. Risk Framing',
    '3. Risk Assessment Methodology',
    '4. Risk Response Strategy',
    '5. Risk Register Reference',
    '6. Risk Acceptance Policy',
    '7. Continuous Risk Monitoring',
    '8. Risk Tolerance',
    '9. Executive Oversight and Governance',
    '10. POA&amp;M Summary', // XML-escaped ampersand in document.xml
    '11. Plan Maintenance',
  ];
  for (let i = 0; i < sections.length; i++) {
    expect(idx(sections[i]!)).toBeGreaterThan(-1);
    if (i > 0) expect(idx(sections[i]!)).toBeGreaterThan(idx(sections[i - 1]!));
  }
});

// ── Test 2 ──
it('quotes SP 800-39 §2 four-component process verbatim', () => {
  const { xml } = buildRmsBodyXml(fullOpts(tmpFull()));
  expect(xml).toContain('The risk management process involves four components: (i) framing risk; (ii) assessing risk; (iii) responding to risk; (iv) monitoring risk.');
  // The authoritative URL is cited in the provenance footer.
  expect(xml).toContain('nistspecialpublication800-39.pdf');
});

// ── Test 3 ──
it('§5 risk register link present when risk-register.json exists', () => {
  const dir = tmpFull();
  const ref = readRiskRegister(dir);
  expect(ref).not.toBeNull();
  expect(ref!.entries_total).toBe(6);
  expect(ref!.open_count).toBe(4);
  expect(ref!.high_inherent_count).toBe(2);
  const { xml, stats } = buildRmsBodyXml(fullOpts(dir));
  expect(stats.risk_register_present).toBe(true);
  expect(xml).toContain('./risk-register.json');
  expect(xml).toContain(ref!.sha256);
});

// ── Test 4 ──
it('§5 REQUIRES-OPERATOR-INPUT when risk-register.json absent', () => {
  const dir = tmp(); // empty outDir
  const { xml, stats } = buildRmsBodyXml(fullOpts(dir));
  expect(stats.risk_register_present).toBe(false);
  const s5 = xml.indexOf('5. Risk Register Reference');
  const s6 = xml.indexOf('6. Risk Acceptance Policy');
  const marker = xml.indexOf('REQUIRES-OPERATOR-INPUT', s5);
  expect(marker).toBeGreaterThan(s5);
  expect(marker).toBeLessThan(s6);
  expect(xml).toContain('Generate it via LOOP-B');
});

// ── Test 5 ──
it('§10 POA&M summary counts by severity from poam.json', () => {
  const dir = tmpFull();
  const summary = summarizePoam(dir);
  expect(summary).not.toBeNull();
  expect(summary!.poam_item_count).toBe(5);
  expect(summary!.count_by_severity).toEqual({ critical: 1, high: 1, medium: 1, low: 1, info: 1 });
  const { xml, stats } = buildRmsBodyXml(fullOpts(dir));
  expect(stats.poam_present).toBe(true);
  expect(stats.poam_item_count).toBe(5);
  expect(xml).toContain(summary!.sha256);
});

// ── Test 6 ──
it('§10 REQUIRES-OPERATOR-INPUT when poam.json absent', () => {
  const dir = tmp(); // no poam.json
  expect(summarizePoam(dir)).toBeNull();
  const { xml, stats } = buildRmsBodyXml(fullOpts(dir));
  expect(stats.poam_present).toBe(false);
  const s10 = xml.indexOf('10. POA&amp;M Summary');
  const s11 = xml.indexOf('11. Plan Maintenance');
  const marker = xml.indexOf('REQUIRES-OPERATOR-INPUT', s10);
  expect(marker).toBeGreaterThan(s10);
  expect(marker).toBeLessThan(s11);
});

// ── Test 7 ──
it('§8 renders riskTolerance verbatim', () => {
  const { xml } = buildRmsBodyXml(fullOpts(tmpFull(), {
    riskTolerance: { confidentiality: 'high', integrity: 'moderate', availability: 'low' },
  }));
  const s8 = xml.indexOf('8. Risk Tolerance');
  const s9 = xml.indexOf('9. Executive Oversight');
  const slice = xml.slice(s8, s9);
  expect(slice).toContain('Confidentiality');
  expect(slice).toContain('HIGH');
  expect(slice).toContain('MODERATE');
  expect(slice).toContain('LOW');
});

// ── Test 8 ──
it('§9 renders executiveOversight roster', () => {
  const { xml, stats } = buildRmsBodyXml(fullOpts(tmpFull(), {
    executiveOversight: [
      { role: 'Authorizing Official', name: 'Dana Authorizer', org: 'Agency X' },
      { role: 'CISO', name: 'Sam Secure', org: 'Acme Corp' },
    ],
  }));
  expect(stats.executive_oversight_count).toBe(2);
  const s9 = xml.indexOf('9. Executive Oversight');
  const s10 = xml.indexOf('10. POA&amp;M Summary');
  const slice = xml.slice(s9, s10);
  expect(slice).toContain('Dana Authorizer');
  expect(slice).toContain('Sam Secure');
});

// ── Test 9 ──
it('§4 risk-response matrix is a 4-row hard-coded standard NIST SP 800-39 table', () => {
  const { xml } = buildRmsBodyXml(fullOpts(tmpFull()));
  const s4 = xml.indexOf('4. Risk Response Strategy');
  const s5 = xml.indexOf('5. Risk Register Reference');
  const slice = xml.slice(s4, s5);
  for (const response of ['Accept', 'Avoid', 'Mitigate', 'Transfer']) {
    expect(slice).toContain(response);
  }
  // Independent of any operator config — present even with a bare outDir.
  const bare = buildRmsBodyXml(baseOpts());
  const b4 = bare.xml.indexOf('4. Risk Response Strategy');
  const b5 = bare.xml.indexOf('5. Risk Register Reference');
  for (const response of ['Accept', 'Avoid', 'Mitigate', 'Transfer']) {
    expect(bare.xml.slice(b4, b5)).toContain(response);
  }
});

// ── Test 10 ──
it('writes to outPath when supplied', () => {
  const dir = tmpFull();
  const outPath = join(dir, 'custom-rms.docx');
  const r = emitRmsDocx(fullOpts(dir, { outPath }));
  expect(r.path).toBe(outPath);
  expect(existsSync(outPath)).toBe(true);
  expect(r.bytes).toBeGreaterThan(0);
});

// ── Test 11 ──
it('deterministic output (same inputs → byte-identical .docx)', () => {
  const dir = tmpFull();
  const a = renderRmsDocx(fullOpts(dir));
  const b = renderRmsDocx(fullOpts(dir));
  expect(Buffer.compare(a.buffer, b.buffer)).toBe(0);
});

// ── Test 12 ──
it('ready_for_signature requires tolerance + executive + register link + acceptance policy', () => {
  const dir = tmpFull();
  expect(buildRmsBodyXml(fullOpts(dir)).stats.ready_for_signature).toBe(true);
  // Drop the tolerance → not ready.
  expect(buildRmsBodyXml(fullOpts(dir, { riskTolerance: undefined })).stats.ready_for_signature).toBe(false);
  // Drop the executive roster → not ready.
  expect(buildRmsBodyXml(fullOpts(dir, { executiveOversight: [] })).stats.ready_for_signature).toBe(false);
  // Drop the register link (empty outDir, no override) → not ready.
  expect(buildRmsBodyXml(fullOpts(tmp())).stats.ready_for_signature).toBe(false);
  // Register present but no acceptance snapshot + no href → not ready.
  const regOnly = tmp();
  copyFileSync(join(FIXTURE_DIR, 'risk-register.sample.json'), join(regOnly, 'risk-register.json'));
  expect(buildRmsBodyXml(fullOpts(regOnly)).stats.ready_for_signature).toBe(false);
  // ...but supplying the acceptance href closes the last gap.
  expect(buildRmsBodyXml(fullOpts(regOnly, { riskAcceptancePolicyHref: './acceptances.json' })).stats.ready_for_signature).toBe(true);
});

// ── Extra 13: §10 overdue + oldest-open age from the real poam ──
it('§10 computes count_overdue + oldest_open_finding_age_days from poam.json', () => {
  const dir = tmpFull();
  // Default "now" derives from the poam metadata last-modified (2026-07-07).
  const summary = summarizePoam(dir)!;
  expect(summary.count_overdue).toBe(1); // risk-critical deadline 2026-06-01, still open
  expect(summary.oldest_open_finding_age_days).toBe(67); // obs-critical collected 2026-05-01
  // Injecting a later "now" makes the second risk overdue too and ages everything.
  const later = summarizePoam(dir, new Date('2026-10-01T00:00:00.000Z'))!;
  expect(later.count_overdue).toBe(2);
  expect(later.oldest_open_finding_age_days).toBe(153);
});

// ── Extra 14: unknown severity throws PoamSeverityError (Risk 2) ──
it('summarizePoam throws PoamSeverityError on an unknown severity', () => {
  const dir = tmp();
  writeFileSync(join(dir, 'poam.json'), JSON.stringify({
    'plan-of-action-and-milestones': {
      uuid: 'x', metadata: { 'last-modified': '2026-07-07T00:00:00.000Z' },
      'poam-items': [{ uuid: 'p', title: 't', description: 'd', props: [{ name: 'severity', value: 'catastrophic' }] }],
    },
  }));
  expect(() => summarizePoam(dir)).toThrow(PoamSeverityError);
});

// ── Extra 15: §6 acceptance policy summary from the B.B3/B.B4 snapshots ──
it('§6 summarizes the risk-acceptance + compensating-control snapshots', () => {
  const dir = tmpFull();
  const policy = readAcceptancePolicy(dir);
  expect(policy.present).toBe(true);
  expect(policy.acceptance_count).toBe(2);
  expect(policy.compensating_count).toBe(1);
  const { xml, stats } = buildRmsBodyXml(fullOpts(dir));
  expect(stats.risk_acceptance_policy_present).toBe(true);
  const s6 = xml.indexOf('6. Risk Acceptance Policy');
  const s7 = xml.indexOf('7. Continuous Risk Monitoring');
  const slice = xml.slice(s6, s7);
  expect(slice).toContain('./.risk-acceptances.json');
  expect(slice).toContain('./.compensating-controls.json');
});

// ── Extra 16: §7 ConMon cross-link resolves when conmon-strategy.docx present ──
it('§7 cross-links to the ConMon Strategy when present, else REQUIRES-OPERATOR-INPUT', () => {
  const withDoc = buildRmsBodyXml(fullOpts(tmpFull())).xml;
  const s7a = withDoc.indexOf('7. Continuous Risk Monitoring');
  const s8a = withDoc.indexOf('8. Risk Tolerance');
  expect(withDoc.slice(s7a, s8a)).toContain('out/conmon-strategy.docx');
  // Without the ConMon doc → the cross-link degrades.
  const noConmon = tmp();
  copyFileSync(join(FIXTURE_DIR, 'poam.sample.json'), join(noConmon, 'poam.json'));
  const without = buildRmsBodyXml(fullOpts(noConmon)).xml;
  const s7b = without.indexOf('7. Continuous Risk Monitoring');
  const s8b = without.indexOf('8. Risk Tolerance');
  expect(without.slice(s7b, s8b)).toContain('REQUIRES-OPERATOR-INPUT');
});

// ── Extra 17: the config.sample.yaml fixture maps to a ready-for-signature doc ──
it('the config.sample.yaml fixture maps to a ready-for-signature Strategy', () => {
  const parsed: any = parseYaml(readFileSync(join(FIXTURE_DIR, 'config.sample.yaml'), 'utf8'));
  const c = parsed.rms;
  const dir = tmpFull();
  const { stats } = buildRmsBodyXml(fullOpts(dir, {
    riskTolerance: c.tolerance,
    executiveOversight: c.executive_oversight,
    agencyCustomerCount: c.agency_customer_count,
  }));
  expect(stats.ready_for_signature).toBe(true);
  expect(stats.executive_oversight_count).toBe(3);
});

// ── Extra 18: emits a structured log event with counts ──
it('emits a structured log event with poam + register presence', () => {
  const dir = tmpFull();
  const spy = vi.spyOn(log, 'info').mockImplementation(() => {});
  emitRmsDocx(fullOpts(dir));
  const evt = spy.mock.calls.map((c) => c[0]).find((a: any) => a?.event === 'rms.emitted');
  expect(evt).toBeTruthy();
  expect((evt as any).risk_register_present).toBe(true);
  expect((evt as any).poam_present).toBe(true);
  expect((evt as any).poam_item_count).toBe(5);
  expect(typeof (evt as any).bytes).toBe('number');
});

describe('PoamSeverityError', () => {
  it('is a typed error', () => {
    const e = new PoamSeverityError('catastrophic');
    expect(e).toBeInstanceOf(PoamSeverityError);
    expect(e.message).toContain('unknown severity');
  });
});
