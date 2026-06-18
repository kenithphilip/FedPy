/**
 * Tests for the LOOP-W.W3 FAR 52.204-25(d) report `.docx` renderer
 * (core/section889-report-docx.ts). Covers W.W3 §8 T8 (per-finding section
 * carries the match/evidence path), T12 (store-only ZIP with the required OOXML
 * parts + the reserved signature region bookmark), and the verbatim statutory
 * quotation routing for Section 889 Part A-1/A-2 + Kaspersky.
 */
import { describe, it, expect } from 'vitest';
import { renderSection889ReportDocx } from '../../core/section889-report-docx.ts';
import { composeReportEnvelope, type Section889ReportKind } from '../../core/section889-report-json.ts';
import {
  REQUIRES_OPERATOR_INPUT, SCREEN_RELATED_CONTROLS,
  type ProhibitedVendorMatch, type ScreenSource,
} from '../../core/prohibited-vendors-screen.ts';

/** Minimal store-only (method 0) ZIP reader: name → Buffer, via local headers. */
function unzipStore(buf: Buffer): Record<string, Buffer> {
  const out: Record<string, Buffer> = {};
  let i = 0;
  while (i + 4 <= buf.length && buf.readUInt32LE(i) === 0x04034b50) {
    const method = buf.readUInt16LE(i + 8);
    const size = buf.readUInt32LE(i + 18);
    const nameLen = buf.readUInt16LE(i + 26);
    const extraLen = buf.readUInt16LE(i + 28);
    const name = buf.toString('utf8', i + 30, i + 30 + nameLen);
    const dataStart = i + 30 + nameLen + extraLen;
    if (method !== 0) throw new Error(`entry ${name} is not store-only (method ${method})`);
    out[name] = buf.subarray(dataStart, dataStart + size);
    i = dataStart + size;
  }
  return out;
}

function mkMatch(o: { source: ScreenSource; name: string; matchPath?: string[] }): ProhibitedVendorMatch {
  return {
    match_id: `pvm-${o.name.toLowerCase().replace(/\W+/g, '')}`,
    catalog_uid: `${o.source}::${o.name.toLowerCase().replace(/\W+/g, '-')}`,
    catalog_provenance: { source: o.source, citation: 'FAR 52.204-25(a); Pub. L. 115-232 §889', extracted_at: '2026-06-08T00:00:00.000Z' },
    surface: 'sbom',
    matched_entity_name: o.name,
    match_path: o.matchPath ?? ['pkg-a@1.0.0', 'pkg-b@2.0.0', o.name],
    confidence: 1.0,
    confidence_band: 'high',
    matched_by: 'normalized-name',
    far_52_204_25_d_data_elements: {
      contract_numbers: [], order_numbers: [], supplier_name: o.name,
      supplier_uei: REQUIRES_OPERATOR_INPUT, supplier_cage_code: REQUIRES_OPERATOR_INPUT,
      brand: 'Acme', model_number: 'X-100', item_description: 'network switch',
      mitigation_actions: REQUIRES_OPERATOR_INPUT,
    },
    poam_item_uuid: '11111111-1111-5111-8111-111111111111',
    related_controls: [...SCREEN_RELATED_CONTROLS],
    suppressed: false,
    discovered_at: '2026-06-10T14:00:00.000Z',
    sources: { surface_evidence: 'sbom-package:pkg-b@2.0.0', sbom_package_purl: 'pkg:npm/pkg-b@2.0.0' },
  };
}

function compose(match: ProhibitedVendorMatch, kind: Section889ReportKind = 'initial-1bd') {
  return composeReportEnvelope({
    reportKind: kind, match, contractNumber: '47QFCA22F0001',
    endpointType: 'civilian-co-email', contractingOfficerEmail: 'co@gsa.gov',
    isSubcontractReport: false, primeContractorUei: null,
    cspName: 'Acme Cloud Inc', cspUei: 'ABC123DEF456', cspCageCode: '1A2B3',
    runId: 'run-xyz', screenEnvelopePath: 'prohibited-vendors-screen-result.json',
    screenEnvelopeSha256: 'deadbeef', catalogSnapshotRef: { path: 'prohibited-vendors-catalog.json', sha256: 'cafef00d', generated_at: '2026-06-08T00:00:00.000Z' },
    discoveryKind: 'screen-run', federalBusinessHoursTz: 'America/New_York',
    deadlineAt: '2026-06-11T14:00:00.000Z', businessHoursRemainingAtEmit: 8,
    signingOfficer: { name: 'Jane Officer', title: 'CISO', key_id: 'abc', key_version: 'abc' },
    generatedAt: '2026-06-10T15:00:00.000Z', emittedAt: '2026-06-10T15:00:00.000Z',
    sourceDigests: [{ kind: 'w2-screen-envelope', path: 'prohibited-vendors-screen-result.json', sha256: 'deadbeef' }],
  });
}

describe('section889-report-docx', () => {
  it('T12: produces a store-only ZIP with the required OOXML parts', () => {
    const buf = renderSection889ReportDocx(compose(mkMatch({ source: 'far-52-204-25', name: 'Huawei Technologies Company' })));
    expect(buf.subarray(0, 4)).toEqual(Buffer.from([0x50, 0x4b, 0x03, 0x04])); // PK\x03\x04
    const parts = unzipStore(buf);
    for (const name of ['[Content_Types].xml', '_rels/.rels', 'word/document.xml', 'word/styles.xml', 'word/_rels/document.xml.rels']) {
      expect(parts[name], `missing OOXML part ${name}`).toBeDefined();
    }
  });

  it('T12: document.xml carries the reserved signature-block bookmark', () => {
    const xml = unzipStore(renderSection889ReportDocx(compose(mkMatch({ source: 'far-52-204-25', name: 'Huawei Technologies Company' }))))['word/document.xml']!.toString('utf8');
    expect(xml).toContain('w:name="signature-block"');
    expect(xml).toContain('18 U.S.C. §1001'); // attestation clause
  });

  it('T8: per-finding section includes the match id + SBOM evidence path', () => {
    const m = mkMatch({ source: 'far-52-204-25', name: 'Hangzhou Hikvision Digital Technology Company' });
    const xml = unzipStore(renderSection889ReportDocx(compose(m)))['word/document.xml']!.toString('utf8');
    expect(xml).toContain(m.match_id);
    expect(xml).toContain('Hangzhou Hikvision Digital Technology Company');
  });

  it('T6/T7: Part A-1 (Huawei) and Part A-2 (Hikvision) quote the correct FAR paragraph verbatim', () => {
    const a1 = unzipStore(renderSection889ReportDocx(compose(mkMatch({ source: 'far-52-204-25', name: 'Huawei Technologies Company' }))))['word/document.xml']!.toString('utf8');
    expect(a1).toContain('Huawei Technologies Company or ZTE Corporation');
    const a2 = unzipStore(renderSection889ReportDocx(compose(mkMatch({ source: 'far-52-204-25', name: 'Hangzhou Hikvision Digital Technology Company' }))))['word/document.xml']!.toString('utf8');
    expect(a2).toContain('Hytera Communications Corporation, Hangzhou Hikvision Digital Technology Company, or Dahua Technology Company');
  });

  it('T9: Kaspersky report quotes NDAA §1634 and DHS BOD 17-01 verbatim', () => {
    const xml = unzipStore(renderSection889ReportDocx(compose(mkMatch({ source: 'ndaa-1634', name: 'Kaspersky Lab' }))))['word/document.xml']!.toString('utf8');
    expect(xml).toContain('Kaspersky Lab (or any successor entity)');
    expect(xml).toContain('Binding Operational Directive 17-01');
  });

  it('follow-up report renders the (d)(2)(ii) clause + the follow-up cover label', () => {
    const env = compose(mkMatch({ source: 'far-52-204-25', name: 'ZTE Corporation' }), 'follow-up-10bd');
    env.far_d_2_ii = { additional_mitigation_actions: 'removed device', prevention_efforts_undertaken: 'audited SBOM', future_prevention_efforts: 'CI gate' };
    const xml = unzipStore(renderSection889ReportDocx(env))['word/document.xml']!.toString('utf8');
    expect(xml).toContain('10-Business-Day Follow-up Report');
    expect(xml).toContain('Within 10 business days of submitting');
    expect(xml).toContain('removed device');
  });
});
