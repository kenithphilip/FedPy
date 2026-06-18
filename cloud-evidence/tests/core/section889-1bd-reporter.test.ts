/**
 * Tests for the LOOP-W.W3 FAR 52.204-25(d) 1-business-day reporter
 * (core/section889-1bd-reporter.ts) + the report-json filter/routing
 * (core/section889-report-json.ts).
 *
 * The end-to-end tests build a REAL signed W.W2 screen envelope via
 * emitProhibitedVendorsScreen (the W.W2 emit path) and run the reporter against
 * it, so the W.W2-signature-verify path is exercised for real (never mocked).
 *
 * Covers W.W3 §8: T5 (ledger dedupe), T6/T7/T9 (statutory-basis routing),
 * T10 (multi-vendor × multi-contract expansion), T11 (envelope schema +
 * provenance), T13 (Ed25519 signature verifies), T16 (emit notification via the
 * injected seam), the signature-invalid guard (a tampered screen is refused),
 * coverage augmentation, the contracts-loader validation, the requires-operator-
 * input diagnostic, the submission-bundle role registration, and the
 * 10-business-day follow-up composition.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  emitSection8891bdReports, composeFollowUpReport, verifySection889Report,
  EnvelopeSignatureInvalidError, type Section889Notification,
} from '../../core/section889-1bd-reporter.ts';
import {
  isReportableMatch, statutoryBasisFor, composeReportEnvelope, canonicalReportBytes,
} from '../../core/section889-report-json.ts';
import {
  REQUIRES_OPERATOR_INPUT, SCREEN_RELATED_CONTROLS,
  type ProhibitedVendorMatch, type ScreenSource,
} from '../../core/prohibited-vendors-screen.ts';
import { emitProhibitedVendorsScreen } from '../../core/prohibited-vendors-screen-emit.ts';
import { writeSignedCatalog, namedEntities } from '../helpers/prohibited-vendors-screen.ts';
import { buildSubmissionIndex } from '../../core/submission-bundle.ts';

const NOW = '2026-06-10T14:00:00.000Z';        // Wed 10:00 EDT — a federal business hour
const CATALOG_GEN = '2026-06-10T08:00:00.000Z'; // fresh (age < 24h)

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-w3-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

const CONTACTS_YAML = `schema_version: '1.0.0'
contracts:
  - contract_number: 47QFCA22F0001
    agency: GSA
    contracting_officer_email: co1@gsa.gov
    cage_code: 1A2B3
  - contract_number: HQ0034-22-F-0005
    agency: DoD
    endpoint_type: dod-dibnet
    contracting_officer_email: co2@dla.mil
`;

/** Build a real signed W.W2 screen envelope from subprocessor rows. */
function setupScreen(outDir: string, names: string[], completedAt = NOW): string {
  writeSignedCatalog(outDir, namedEntities(), CATALOG_GEN);
  const screen = emitProhibitedVendorsScreen({
    outDir, runId: 'run-w3', cspName: 'Acme Cloud Inc',
    completedAt, startedAt: completedAt,
    subprocessorRows: names.map((name) => ({ name })),
    subprocessorSourcePath: resolve(outDir, 'subprocessor-inventory.json'),
    writeXlsx: false,
  });
  return screen.json_path;
}

function writeContacts(outDir: string): string {
  const p = resolve(outDir, 'section889-contacts.yaml');
  writeFileSync(p, CONTACTS_YAML);
  return p;
}

function run(outDir: string, extra: Partial<Parameters<typeof emitSection8891bdReports>[0]> = {}) {
  return emitSection8891bdReports({
    outDir, runId: 'run-w3', cspName: 'Acme Cloud Inc',
    cspUei: 'ABC123DEF456', cspCageCode: '1A2B3',
    contactsPath: writeContacts(outDir),
    signingOfficerName: 'Jane Officer', signingOfficerTitle: 'Chief Information Security Officer',
    emittedAt: NOW,
    ...extra,
  });
}

// ─── Pure filter + statutory routing ─────────────────────────────────────────

function mkMatch(o: { source: ScreenSource; name: string; band?: 'high' | 'medium' | 'low'; suppressed?: boolean; contracts?: string[] }): ProhibitedVendorMatch {
  return {
    match_id: `pvm-${o.name.toLowerCase().replace(/\W+/g, '')}-${o.source}`,
    catalog_uid: `${o.source}::${o.name.toLowerCase().replace(/\W+/g, '-')}`,
    catalog_provenance: { source: o.source, citation: 'cite', extracted_at: CATALOG_GEN },
    surface: 'subprocessor-sheet', matched_entity_name: o.name, match_path: [o.name],
    confidence: o.band === 'medium' ? 0.7 : o.band === 'low' ? 0.5 : 1.0,
    confidence_band: o.band ?? 'high', matched_by: 'normalized-name',
    far_52_204_25_d_data_elements: {
      contract_numbers: o.contracts ?? [], order_numbers: [], supplier_name: o.name,
      supplier_uei: REQUIRES_OPERATOR_INPUT, supplier_cage_code: REQUIRES_OPERATOR_INPUT,
      brand: REQUIRES_OPERATOR_INPUT, model_number: REQUIRES_OPERATOR_INPUT,
      item_description: REQUIRES_OPERATOR_INPUT, mitigation_actions: REQUIRES_OPERATOR_INPUT,
    },
    poam_item_uuid: '11111111-1111-5111-8111-111111111111',
    related_controls: [...SCREEN_RELATED_CONTROLS], suppressed: o.suppressed ?? false,
    discovered_at: NOW, sources: { surface_evidence: `subprocessor-row:${o.name}` },
  };
}

describe('section889-report-json — reportable filter', () => {
  it('high-confidence non-suppressed Section 889 hit is reportable', () => {
    expect(isReportableMatch(mkMatch({ source: 'far-52-204-25', name: 'Huawei Technologies Company' }))).toBe(true);
    expect(isReportableMatch(mkMatch({ source: 'ndaa-889', name: 'ZTE Corporation' }))).toBe(true);
    expect(isReportableMatch(mkMatch({ source: 'ndaa-1634', name: 'Kaspersky Lab' }))).toBe(true);
    expect(isReportableMatch(mkMatch({ source: 'operator-manual-addition', name: 'Foo Corp' }))).toBe(true);
  });
  it('suppressed / medium-band / non-889-source hits are NOT reportable', () => {
    expect(isReportableMatch(mkMatch({ source: 'far-52-204-25', name: 'Huawei', suppressed: true }))).toBe(false);
    expect(isReportableMatch(mkMatch({ source: 'far-52-204-25', name: 'Huawei', band: 'medium' }))).toBe(false);
    expect(isReportableMatch(mkMatch({ source: 'ofac-sdn', name: 'Some SDN Entity' }))).toBe(false);
    expect(isReportableMatch(mkMatch({ source: 'sam-exclusions', name: 'Excluded LLC' }))).toBe(false);
  });
});

describe('section889-report-json — statutory basis routing', () => {
  it('T6: Huawei/ZTE → FAR a-1 + NDAA §889(f)(2)(A)', () => {
    expect(statutoryBasisFor(mkMatch({ source: 'far-52-204-25', name: 'Huawei Technologies Company' }))).toEqual(['far-52.204-25-a-1', 'ndaa-2019-sec-889-f-2-A']);
  });
  it('T7: Hytera/Hikvision/Dahua → FAR a-2 + NDAA §889(f)(2)(B)', () => {
    expect(statutoryBasisFor(mkMatch({ source: 'far-52-204-25', name: 'Hangzhou Hikvision Digital Technology Company' }))).toEqual(['far-52.204-25-a-2', 'ndaa-2019-sec-889-f-2-B']);
  });
  it('T9: Kaspersky → NDAA §1634 + DHS BOD 17-01', () => {
    expect(statutoryBasisFor(mkMatch({ source: 'ndaa-1634', name: 'Kaspersky Lab' }))).toEqual(['ndaa-2018-sec-1634', 'dhs-bod-17-01']);
  });
  it('operator addition → operator-addition; unknown named 889 entity → general a-4/f-2-D', () => {
    expect(statutoryBasisFor(mkMatch({ source: 'operator-manual-addition', name: 'Foo Corp' }))).toEqual(['operator-addition']);
    expect(statutoryBasisFor(mkMatch({ source: 'far-52-204-25', name: 'Unknown Telecom Co' }))).toEqual(['far-52.204-25-a-4', 'ndaa-2019-sec-889-f-2-D']);
  });
});

// ─── End-to-end emit ──────────────────────────────────────────────────────────

describe('section889-1bd-reporter — end-to-end', () => {
  it('T6/T7/T9: emits one signed JSON+docx+sig per reportable vendor with the right statutory basis', () => {
    const outDir = tmp();
    setupScreen(outDir, ['Huawei Technologies Company']);
    const r = run(outDir);
    expect(r.reportable_matches).toBe(1);
    expect(r.reports_emitted).toBe(2); // 1 vendor × 2 contracts
    const env = JSON.parse(readFileSync(r.reports[0]!.json_path, 'utf8'));
    expect(env.statutory_basis).toEqual(['far-52.204-25-a-1', 'ndaa-2019-sec-889-f-2-A']);
    expect(existsSync(r.reports[0]!.docx_path)).toBe(true);
    expect(existsSync(r.reports[0]!.sig_path)).toBe(true);
  });

  it('T10: 3 vendors × 2 contracts = 6 reports + 6 docx + a 6-line ledger', () => {
    const outDir = tmp();
    setupScreen(outDir, ['Huawei Technologies Company', 'Hytera Communications Corporation', 'Kaspersky Lab']);
    const r = run(outDir);
    expect(r.reportable_matches).toBe(3);
    expect(r.reports_emitted).toBe(6);
    const files = readdirSync(resolve(outDir, 'section889-1bd-reports'));
    expect(files.filter((f) => f.endsWith('.json')).length).toBe(6);
    expect(files.filter((f) => f.endsWith('.docx')).length).toBe(6);
    const ledgerLines = readFileSync(r.ledger_path, 'utf8').trim().split('\n');
    expect(ledgerLines.length).toBe(6);
  });

  it('T11: emitted envelope carries the schema + a top-level camelCase provenance block (G3)', () => {
    const outDir = tmp();
    setupScreen(outDir, ['Huawei Technologies Company']);
    const env = JSON.parse(readFileSync(run(outDir).reports[0]!.json_path, 'utf8'));
    expect(env.schema_version).toBe('1.0.0');
    expect(env.report_kind).toBe('initial-1bd');
    expect(typeof env.provenance.emitter).toBe('string');
    expect(typeof env.provenance.emittedAt).toBe('string');
    expect(Array.isArray(env.provenance.sourceCalls)).toBe(true);
    // nine (d)(2)(i) elements present
    for (const k of ['contract_number', 'order_numbers', 'supplier_name', 'supplier_uei', 'supplier_cage_code', 'brand', 'model_number', 'item_description', 'mitigation_actions']) {
      expect(env.far_d_2_i).toHaveProperty(k);
    }
  });

  it('T13: the emitted report\'s Ed25519 signature verifies', () => {
    const outDir = tmp();
    setupScreen(outDir, ['Huawei Technologies Company']);
    const env = JSON.parse(readFileSync(run(outDir).reports[0]!.json_path, 'utf8'));
    expect(verifySection889Report(env)).toBe(true);
    // tampering breaks verification
    env.far_d_2_i.supplier_name = 'Tampered Co';
    expect(verifySection889Report(env)).toBe(false);
  });

  it('deadline_at is one federal business day after discovery (Wed 10:00 → Thu 10:00 ET)', () => {
    const outDir = tmp();
    setupScreen(outDir, ['Huawei Technologies Company']);
    const env = JSON.parse(readFileSync(run(outDir).reports[0]!.json_path, 'utf8'));
    expect(new Date(env.deadline_at).getTime()).toBe(new Date('2026-06-11T14:00:00.000Z').getTime());
    expect(env.business_hours_remaining_at_emit).toBeCloseTo(8, 1);
  });

  it('T5: re-running the same screen is idempotent — no duplicate reports', () => {
    const outDir = tmp();
    setupScreen(outDir, ['Huawei Technologies Company', 'Kaspersky Lab']);
    const first = run(outDir);
    expect(first.reports_emitted).toBe(4);
    const second = run(outDir);
    expect(second.reports_emitted).toBe(0);
    expect(second.reports_already_present).toBe(4);
    expect(readFileSync(first.ledger_path, 'utf8').trim().split('\n').length).toBe(4); // ledger unchanged
  });

  it('T16: an emit notification fires per report via the injected seam', () => {
    const outDir = tmp();
    setupScreen(outDir, ['Huawei Technologies Company']);
    const captured: Section889Notification[] = [];
    const r = run(outDir, { notify: (n) => captured.push(n) });
    expect(captured.length).toBe(r.reports_emitted);
    expect(captured[0]!.kind).toBe('emitted');
    expect(captured[0]!.deadline_at).toBeTruthy();
  });

  it('augments inventory-coverage.json with a section889_1bd_coverage block (sibling — no G2 regression)', () => {
    const outDir = tmp();
    setupScreen(outDir, ['Huawei Technologies Company']);
    const covPath = resolve(outDir, 'inventory-coverage.json');
    writeFileSync(covPath, JSON.stringify({ existing: { fill_rate: 1 } }, null, 2));
    run(outDir);
    const cov = JSON.parse(readFileSync(covPath, 'utf8'));
    expect(cov.existing.fill_rate).toBe(1); // untouched
    expect(cov.section889_1bd_coverage.reports_emitted_this_run).toBe(2);
    expect(cov.section889_1bd_coverage.reportable_matches).toBe(1);
  });

  it('refuses to report from a screen whose signature does not verify', () => {
    const outDir = tmp();
    const screenPath = setupScreen(outDir, ['Huawei Technologies Company']);
    // Tamper the signed envelope after the fact.
    const env = JSON.parse(readFileSync(screenPath, 'utf8'));
    env.csp_name = 'Forged Corp';
    writeFileSync(screenPath, JSON.stringify(env, null, 2));
    expect(() => run(outDir)).toThrow(EnvelopeSignatureInvalidError);
    expect(existsSync(resolve(outDir, 'section889-1bd-reports'))).toBe(false);
  });

  it('a clean screen (no reportable hits) emits nothing and does not error', () => {
    const outDir = tmp();
    setupScreen(outDir, ['Acme Friendly Subprocessor LLC']);
    const r = run(outDir);
    expect(r.reportable_matches).toBe(0);
    expect(r.reports_emitted).toBe(0);
  });

  it('surfaces a requires_operator_input diagnostic when the signing officer is unset', () => {
    const outDir = tmp();
    setupScreen(outDir, ['Huawei Technologies Company']);
    const r = run(outDir, { signingOfficerName: undefined, signingOfficerTitle: undefined });
    expect(r.reports_emitted).toBe(2); // still emits (operator completes before transmit)
    expect(r.requires_operator_input).toContain('section_889.signing.corporate_signing_officer_name');
  });

  it('registers the report artifacts in the submission-bundle catalogue', () => {
    const outDir = tmp();
    setupScreen(outDir, ['Huawei Technologies Company']);
    run(outDir);
    const { index } = buildSubmissionIndex(outDir, { outDir, runId: 'run-w3', frmrVersion: '25.05' });
    const roles = index.artifacts.map((a) => a.role);
    expect(roles).toContain('section889-1bd-report-json');
    expect(roles).toContain('section889-1bd-report-docx');
    expect(roles).toContain('section889-1bd-ledger');
  });
});

describe('section889-1bd-reporter — 10-business-day follow-up', () => {
  it('composes a signed follow-up envelope linked to the initial report', () => {
    const outDir = tmp();
    setupScreen(outDir, ['Huawei Technologies Company']);
    const initial = JSON.parse(readFileSync(run(outDir).reports[0]!.json_path, 'utf8'));
    const { envelope } = composeFollowUpReport({
      outDir, initialReport: initial,
      followUp: { additional_mitigation_actions: 'device removed', prevention_efforts_undertaken: 'SBOM audit', future_prevention_efforts: 'CI gate enforced' },
      emittedAt: '2026-06-12T14:00:00.000Z',
    });
    expect(envelope.report_kind).toBe('follow-up-10bd');
    expect(envelope.source_initial_report_id).toBe(initial.report_id);
    expect(envelope.far_d_2_ii?.additional_mitigation_actions).toBe('device removed');
    expect(verifySection889Report(envelope)).toBe(true);
    // follow-up deadline is later than the initial 1BD deadline
    expect(new Date(envelope.deadline_at).getTime()).toBeGreaterThan(new Date(initial.deadline_at).getTime());
  });
});

describe('section889-report-json — canonical bytes are signature-blanked', () => {
  it('canonicalReportBytes ignores the signature fields', () => {
    const m = mkMatch({ source: 'far-52-204-25', name: 'Huawei Technologies Company' });
    const env = composeReportEnvelope({
      reportKind: 'initial-1bd', match: m, contractNumber: '47QFCA22F0001',
      endpointType: 'civilian-co-email', contractingOfficerEmail: 'co@gsa.gov',
      isSubcontractReport: false, primeContractorUei: null,
      cspName: 'Acme', cspUei: 'U', cspCageCode: 'C', runId: 'r',
      screenEnvelopePath: 's.json', screenEnvelopeSha256: 'x',
      catalogSnapshotRef: { path: 'c.json', sha256: 'y', generated_at: CATALOG_GEN },
      discoveryKind: 'screen-run', federalBusinessHoursTz: 'America/New_York',
      deadlineAt: '2026-06-11T14:00:00.000Z', businessHoursRemainingAtEmit: 8,
      signingOfficer: { name: 'A', title: 'B', key_id: '', key_version: '' },
      generatedAt: NOW, emittedAt: NOW, sourceDigests: [],
    });
    const before = canonicalReportBytes(env);
    env.provenance.signatureEd25519 = 'changed';
    env.provenance.signingKeyId = 'changed';
    env.provenance.publicKeyPem = 'changed';
    expect(canonicalReportBytes(env)).toBe(before);
  });
});
