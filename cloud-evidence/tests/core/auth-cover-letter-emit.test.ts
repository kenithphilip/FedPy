/**
 * Tests for core/auth-cover-letter-emit.ts — LOOP-C.C8 Authorization request
 * cover letter / package transmittal (PM-10).
 *
 * The 11 numbered tests below are the per-slice §8 contract; seven extra tests
 * exercise the 3PAO resolution precedence, the deterministic date fallback, the
 * real sha256-short + alphabetical sort, the INDEX.json reader's tolerance of
 * extra fields, the §3 degrade path, the config.sample.yaml round-trip, and the
 * structured log event.
 */
import { it, expect, describe, afterEach, vi } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, copyFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import {
  emitAuthCoverLetterDocx, renderAuthCoverLetterDocx, buildCoverLetterBodyXml,
  readIndexJson, readApMetadata, resolveThirdParty, resolveSubmissionDate,
  type AuthCoverLetterOptions, type CspExecutiveSignatory, type AoAddressee, type ThirdPartyAssessorLead,
} from '../../core/auth-cover-letter-emit.ts';
import { log } from '../../core/log.ts';

const FIXTURE_DIR = resolve(import.meta.dirname ?? '', 'fixtures/cover-letter');

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-acl-'));
  dirs.push(d);
  return d;
}
/** Seed a tmp outDir with the sample INDEX.json + ap.json. */
function tmpFull(): string {
  const d = tmp();
  copyFileSync(join(FIXTURE_DIR, 'INDEX.sample.json'), join(d, 'INDEX.json'));
  copyFileSync(join(FIXTURE_DIR, 'ap.sample.json'), join(d, 'ap.json'));
  return d;
}
afterEach(() => {
  vi.restoreAllMocks();
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

const SIGNATORY: CspExecutiveSignatory = {
  name: 'Jordan Executive', title: 'Chief Information Security Officer',
  email: 'jordan.executive@example.com', phone: '+1-703-555-0100',
};
const ADDRESSEE: AoAddressee = {
  name: 'Pat Authorizer', title: 'Authorizing Official',
  agency: 'Department of Example', address: 'Department of Example, Washington, DC 20500',
};
const TPA_LEAD: ThirdPartyAssessorLead = { name: 'Morgan Assessor', title: 'Lead Assessor', email: 'morgan.assessor@example.com' };

function baseOpts(over: Partial<AuthCoverLetterOptions> = {}): AuthCoverLetterOptions {
  return { outDir: '/nonexistent-acl-dir', runId: 'r-acl-test', frmrVersion: '0.9.43-beta', impactLevel: 'moderate', ...over };
}

/** Every required-for-signature operator field supplied over a full outDir. */
function fullOpts(dir: string, over: Partial<AuthCoverLetterOptions> = {}): AuthCoverLetterOptions {
  return baseOpts({
    outDir: dir,
    systemName: 'Acme Platform', systemId: 'acme-prod-1', cspOrganization: 'Acme Corp',
    cspAddress: '100 Cloud Way, Reston, VA 20190',
    cspExecutiveSignatory: SIGNATORY,
    aoAddressee: ADDRESSEE,
    thirdPartyAssessor: 'Rigorous Assessments LLC',
    thirdPartyAssessorLead: TPA_LEAD,
    requestedAtoType: 'initial-ato',
    submissionDate: '2026-07-10',
    ...over,
  });
}

// ── Test 1 ──
it('emits 7 sections + letterhead + addressee', () => {
  const { xml } = buildCoverLetterBodyXml(fullOpts(tmpFull()));
  const idx = (s: string) => xml.indexOf(s);
  const sections = [
    'Letterhead',
    'Addressee',
    '1. Subject',
    '2. Request Summary',
    '3. Independent Assessment (3PAO) Statement',
    '4. Package Contents',
    '5. Requested Action',
    '6. Primary Contacts',
    '7. Closing and Signature',
  ];
  for (let i = 0; i < sections.length; i++) {
    expect(idx(sections[i]!)).toBeGreaterThan(-1);
    if (i > 0) expect(idx(sections[i]!)).toBeGreaterThan(idx(sections[i - 1]!));
  }
});

// ── Test 2 ──
it('§4 Package Contents reflects INDEX.json artifacts', () => {
  const dir = tmpFull();
  const ref = readIndexJson(dir);
  expect(ref).not.toBeNull();
  expect(ref!.artifacts.length).toBe(12);
  const { xml, stats } = buildCoverLetterBodyXml(fullOpts(dir));
  expect(stats.index_present).toBe(true);
  expect(stats.artifact_count).toBe(12);
  const s4 = xml.indexOf('4. Package Contents');
  const s5 = xml.indexOf('5. Requested Action');
  const slice = xml.slice(s4, s5);
  // Real artifact rows appear in §4.
  for (const fn of ['ssp.json', 'poam.json', 'inventory-workbook.xlsx', 'manifest.sig']) {
    expect(slice).toContain(fn);
  }
  // Real per-artifact sha256-short (first 12 hex chars of ssp.json's digest).
  expect(slice).toContain('aaaa1111bbbb');
  // Row count is real.
  expect(slice).toContain('Total artifacts enclosed: 12');
});

// ── Test 3 ──
it('§4 REQUIRES-OPERATOR-INPUT with note when INDEX.json absent', () => {
  const dir = tmp(); // empty outDir
  expect(readIndexJson(dir)).toBeNull();
  const { xml, stats } = buildCoverLetterBodyXml(fullOpts(dir));
  expect(stats.index_present).toBe(false);
  expect(stats.artifact_count).toBe(0);
  const s4 = xml.indexOf('4. Package Contents');
  const s5 = xml.indexOf('5. Requested Action');
  const marker = xml.indexOf('REQUIRES-OPERATOR-INPUT', s4);
  expect(marker).toBeGreaterThan(s4);
  expect(marker).toBeLessThan(s5);
  expect(xml).toContain('INDEX-build → cover-letter → bundle-pack');
});

// ── Test 4 ──
it('§3 3PAO statement reads from out/ap.json metadata when present', () => {
  const dir = tmpFull();
  const ap = readApMetadata(dir);
  expect(ap).not.toBeNull();
  expect(ap!.organizations).toContain('Rigorous Assessments LLC');
  expect(ap!.lastModified).toBe('2026-07-02T00:00:00.000Z');
  // No operator-supplied 3PAO → resolved purely from ap.json (the non-CSP org).
  const { xml, stats } = buildCoverLetterBodyXml(fullOpts(dir, { thirdPartyAssessor: undefined }));
  expect(stats.ap_present).toBe(true);
  expect(stats.third_party_assessor_present).toBe(true);
  const s3 = xml.indexOf('3. Independent Assessment');
  const s4 = xml.indexOf('4. Package Contents');
  const slice = xml.slice(s3, s4);
  expect(slice).toContain('Rigorous Assessments LLC');
  expect(slice).toContain('2026-07-02'); // AP finalization date
});

// ── Test 5 ──
it('§2 requestedAtoType reflects opts', () => {
  const dir = tmpFull();
  const s2Of = (o: AuthCoverLetterOptions) => {
    const { xml } = buildCoverLetterBodyXml(o);
    return xml.slice(xml.indexOf('2. Request Summary'), xml.indexOf('3. Independent Assessment'));
  };
  expect(s2Of(fullOpts(dir, { requestedAtoType: 'reauthorization' }))).toContain('Reauthorization');
  expect(s2Of(fullOpts(dir, { requestedAtoType: 'continued-ato' }))).toContain('Continued Authorization');
  // Default when omitted.
  const def = buildCoverLetterBodyXml(fullOpts(dir, { requestedAtoType: undefined }));
  expect(def.stats.requested_ato_type).toBe('initial-ato');
  expect(s2Of(fullOpts(dir, { requestedAtoType: undefined }))).toContain('Initial Authorization to Operate');
});

// ── Test 6 ──
it('addressee REQUIRES-OPERATOR-INPUT when aoAddressee omitted', () => {
  const dir = tmpFull();
  const { xml, stats } = buildCoverLetterBodyXml(fullOpts(dir, { aoAddressee: undefined }));
  expect(stats.ao_addressee_present).toBe(false);
  const sA = xml.indexOf('Addressee');
  const s1 = xml.indexOf('1. Subject');
  const marker = xml.indexOf('REQUIRES-OPERATOR-INPUT', sA);
  expect(marker).toBeGreaterThan(sA);
  expect(marker).toBeLessThan(s1);
  expect(xml).toContain('auth_request.ao_addressee');
});

// ── Test 7 ──
it('cspExecutiveSignatory REQUIRES-OPERATOR-INPUT when omitted', () => {
  const dir = tmpFull();
  const { xml, stats } = buildCoverLetterBodyXml(fullOpts(dir, { cspExecutiveSignatory: undefined }));
  expect(stats.executive_signatory_present).toBe(false);
  const s7 = xml.indexOf('7. Closing and Signature');
  const prov = xml.indexOf('Provenance', s7);
  const marker = xml.indexOf('REQUIRES-OPERATOR-INPUT', s7);
  expect(marker).toBeGreaterThan(s7);
  expect(marker).toBeLessThan(prov);
  // The exec signature is never auto-signed (Risk 6).
  expect(xml).toContain('never auto-signed by the toolkit');
});

// ── Test 8 ──
it('subject line includes systemName + impactLevel', () => {
  const { xml } = buildCoverLetterBodyXml(fullOpts(tmpFull(), { systemName: 'Acme Platform', impactLevel: 'high' }));
  const s1 = xml.indexOf('1. Subject');
  const s2 = xml.indexOf('2. Request Summary');
  const slice = xml.slice(s1, s2);
  expect(slice).toContain('Acme Platform');
  expect(slice).toContain('HIGH');
});

// ── Test 9 ──
it('writes to outPath when supplied', () => {
  const dir = tmpFull();
  const outPath = join(dir, 'custom-cover-letter.docx');
  const r = emitAuthCoverLetterDocx(fullOpts(dir, { outPath }));
  expect(r.path).toBe(outPath);
  expect(existsSync(outPath)).toBe(true);
  expect(r.bytes).toBeGreaterThan(0);
});

// ── Test 10 ──
it('deterministic output for same INDEX.json + opts', () => {
  const dir = tmpFull();
  const a = renderAuthCoverLetterDocx(fullOpts(dir));
  const b = renderAuthCoverLetterDocx(fullOpts(dir));
  expect(Buffer.compare(a.buffer, b.buffer)).toBe(0);
});

// ── Test 11 ──
it('ready_for_signature requires signatory + addressee + tpa + atoType', () => {
  const dir = tmpFull();
  expect(buildCoverLetterBodyXml(fullOpts(dir)).stats.ready_for_signature).toBe(true);
  // Drop the exec signatory → not ready.
  expect(buildCoverLetterBodyXml(fullOpts(dir, { cspExecutiveSignatory: undefined })).stats.ready_for_signature).toBe(false);
  // Drop the AO addressee → not ready.
  expect(buildCoverLetterBodyXml(fullOpts(dir, { aoAddressee: undefined })).stats.ready_for_signature).toBe(false);
  // Drop the 3PAO (operator + ap.json) → not ready.
  const noAp = tmp();
  copyFileSync(join(FIXTURE_DIR, 'INDEX.sample.json'), join(noAp, 'INDEX.json'));
  expect(buildCoverLetterBodyXml(fullOpts(noAp, { thirdPartyAssessor: undefined })).stats.ready_for_signature).toBe(false);
  // atoType always resolves (default initial-ato) — never a blocker.
  expect(buildCoverLetterBodyXml(fullOpts(dir, { requestedAtoType: undefined })).stats.ready_for_signature).toBe(true);
});

// ── Extra 12: 3PAO resolution precedence (opts → ap.json → null) ──
it('resolveThirdParty prefers operator config, then ap.json non-CSP org, else null', () => {
  const dir = tmpFull();
  const ap = readApMetadata(dir);
  // Operator override wins.
  expect(resolveThirdParty(fullOpts(dir, { thirdPartyAssessor: 'Explicit 3PAO Inc' }), ap)).toBe('Explicit 3PAO Inc');
  // No operator override → the ap.json org that is not the CSP.
  expect(resolveThirdParty(fullOpts(dir, { thirdPartyAssessor: undefined, cspOrganization: 'Acme Corp' }), ap)).toBe('Rigorous Assessments LLC');
  // No operator override + no ap.json → null.
  expect(resolveThirdParty(fullOpts(dir, { thirdPartyAssessor: undefined }), null)).toBeNull();
});

// ── Extra 13: deterministic date fallback (operator → runId → pending) ──
it('resolveSubmissionDate resolves operator date, else runId ISO date, else a pending marker', () => {
  expect(resolveSubmissionDate(baseOpts({ submissionDate: '2026-07-10' }))).toEqual({ text: '2026-07-10', source: 'operator' });
  expect(resolveSubmissionDate(baseOpts({ runId: '2026-05-04-acme-run-7' }))).toEqual({ text: '2026-05-04', source: 'runId' });
  const pending = resolveSubmissionDate(baseOpts({ runId: 'r-no-date' }));
  expect(pending.source).toBe('pending');
  expect(pending.text).toContain('REQUIRES-OPERATOR-INPUT');
});

// ── Extra 14: §4 sha256-short is real + rows are alphabetically sorted (Q2) ──
it('§4 renders real 12-char sha prefixes and sorts artifacts alphabetically', () => {
  const dir = tmpFull();
  const { xml } = buildCoverLetterBodyXml(fullOpts(dir));
  const s4 = xml.indexOf('4. Package Contents');
  const s5 = xml.indexOf('5. Requested Action');
  const slice = xml.slice(s4, s5);
  // Alphabetical: ap.json before ssp.json before assessment-results... check a few orderings.
  expect(slice.indexOf('ap.json')).toBeLessThan(slice.indexOf('cmp.docx'));
  expect(slice.indexOf('cmp.docx')).toBeLessThan(slice.indexOf('ssp.json'));
  // sha256-short is exactly the first 12 hex chars (poam.json digest starts eeee5555ffff).
  expect(slice).toContain('eeee5555ffff');
  // ...and NOT the full 64-char digest.
  expect(slice).not.toContain('eeee5555ffff6666aaaa7777bbbb8888cccc9999dddd0000eeee1111ffff2222');
});

// ── Extra 15: readIndexJson tolerates extra fields + missing file ──
it('readIndexJson consumes narrow fields, tolerates extras, returns null when absent', () => {
  const dir = tmp();
  // Extra top-level + per-row fields (in_manifest, required, future-field) are ignored.
  writeFileSync(join(dir, 'INDEX.json'), JSON.stringify({
    run_id: 'run-x', future_top_field: 123,
    artifacts: [{ filename: 'x.json', role: 'oscal-ssp', sha256: 'deadbeef'.repeat(8), bytes: 42, in_manifest: true, required: true, future_row_field: 'ignored' }],
  }));
  const ref = readIndexJson(dir)!;
  expect(ref.runId).toBe('run-x');
  expect(ref.artifacts).toHaveLength(1);
  expect(ref.artifacts[0]).toMatchObject({ filename: 'x.json', role: 'oscal-ssp', bytes: 42 });
  // Absent file → null.
  expect(readIndexJson(tmp())).toBeNull();
});

// ── Extra 16: §3 degrades when neither operator nor ap.json names a 3PAO ──
it('§3 REQUIRES-OPERATOR-INPUT when no 3PAO from operator or ap.json', () => {
  const dir = tmp();
  copyFileSync(join(FIXTURE_DIR, 'INDEX.sample.json'), join(dir, 'INDEX.json')); // INDEX but no ap.json
  const { xml, stats } = buildCoverLetterBodyXml(fullOpts(dir, { thirdPartyAssessor: undefined }));
  expect(stats.third_party_assessor_present).toBe(false);
  const s3 = xml.indexOf('3. Independent Assessment');
  const s4 = xml.indexOf('4. Package Contents');
  const marker = xml.indexOf('REQUIRES-OPERATOR-INPUT', s3);
  expect(marker).toBeGreaterThan(s3);
  expect(marker).toBeLessThan(s4);
  expect(xml.slice(s3, s4)).toContain('--oscal-ap');
});

// ── Extra 17: the config.sample.yaml fixture maps to a ready-for-signature letter ──
it('the config.sample.yaml fixture maps to a ready-for-signature cover letter', () => {
  const parsed: any = parseYaml(readFileSync(join(FIXTURE_DIR, 'config.sample.yaml'), 'utf8'));
  const ar = parsed.auth_request;
  const dir = tmpFull();
  const { stats } = buildCoverLetterBodyXml(fullOpts(dir, {
    cspAddress: parsed.org.address,
    cspExecutiveSignatory: ar.executive_signatory,
    technicalContact: ar.technical_contact,
    thirdPartyAssessor: ar.tpa.organization,
    thirdPartyAssessorLead: ar.tpa.lead,
    aoAddressee: ar.ao_addressee,
    requestedAtoType: ar.ato_type,
    submissionDate: ar.submission_date,
  }));
  expect(stats.ready_for_signature).toBe(true);
  expect(stats.requires_operator_input).toHaveLength(0);
  expect(stats.requested_ato_type).toBe('initial-ato');
});

// ── Extra 18: emits a structured log event with counts ──
it('emits a structured log event with index + ap presence', () => {
  const dir = tmpFull();
  const spy = vi.spyOn(log, 'info').mockImplementation(() => {});
  emitAuthCoverLetterDocx(fullOpts(dir));
  const evt = spy.mock.calls.map((c) => c[0]).find((a: any) => a?.event === 'auth_cover_letter.emitted');
  expect(evt).toBeTruthy();
  expect((evt as any).index_present).toBe(true);
  expect((evt as any).artifact_count).toBe(12);
  expect((evt as any).ap_present).toBe(true);
  expect((evt as any).ready_for_signature).toBe(true);
  expect(typeof (evt as any).bytes).toBe('number');
});
