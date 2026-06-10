/**
 * Tests for core/ssdf-practices-catalog.ts — LOOP-T.T1 SSDF practice catalog.
 *
 * Verifies the committed, signed catalog data/ssdf-800-218-v1.1.json (extracted
 * verbatim from docs/sources/NIST.SP.800-218.pdf) plus the typed loader /
 * validator / lookup surface that LOOP-T.T2/T3/T5 consume:
 *   - 19 practices, 42 active tasks, 4 groups, PW.3 + 5 tasks withdrawn
 *   - verbatim 800-53 Rev 5 control mapping (17 of 19 practices; PW.2/PW.5 have
 *     none, matching NIST SP 800-218 Table 1 which cites no SP 800-53 reference)
 *   - CISA Common Form Section IV task labelling
 *   - curated FedRAMP KSI forward map (every id real in core/ksi-map.ts)
 *   - source_pdf_sha256 provenance that re-traces to the committed PDF byte-for-byte
 *   - verifiable detached Ed25519 signature over canonical bytes
 *   - typed SsdfExtractError on every shape/fidelity failure (no silent fallback)
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  loadSsdfCatalog, validateCatalog, verifySsdfCatalogSignature, serializeUnsignedCanonical,
  getPractice, getTasksByPracticeGroup, tasksByCommonFormSection,
  SsdfExtractError, EXPECTED_PRACTICE_IDS, EXPECTED_PRACTICE_COUNT, EXPECTED_TASK_COUNT,
  type SsdfCatalog,
} from '../../core/ssdf-practices-catalog.ts';

const fx = (p: string) => fileURLToPath(new URL(`../fixtures/ssdf/${p}`, import.meta.url));
const PDF_PATH = fileURLToPath(new URL('../../docs/sources/NIST.SP.800-218.pdf', import.meta.url));

/** The real committed catalog — primary positive-test target. */
const catalog: SsdfCatalog = loadSsdfCatalog();
/** Known KSI id universe, derived from the catalog's own (real) forward maps. */
const knownKsiIds = new Set(catalog.practices.flatMap((p) => p.fedramp_ksi_forward_map.map((e) => e.ksi_id)));

describe('SSDF catalog — structure', () => {
  it('T1: loads from disk and parses to an SsdfCatalog with 19 practices', () => {
    expect(catalog.catalog_id).toBe('ssdf-800-218-v1.1');
    expect(catalog.practices).toHaveLength(EXPECTED_PRACTICE_COUNT);
  });

  it('T2: the four practice groups are present in canonical order', () => {
    expect(catalog.practice_groups.map((g) => g.id)).toEqual(['PO', 'PS', 'PW', 'RV']);
    for (const g of catalog.practice_groups) expect(g.definition.length).toBeGreaterThan(20);
  });

  it('T3: practice ids match the canonical 19', () => {
    expect([...catalog.practices.map((p) => p.id)].sort()).toEqual([...EXPECTED_PRACTICE_IDS].sort());
  });

  it('T4: PW.3 is withdrawn — getPractice("PW.3") throws ERR_SSDF_PRACTICE_NOT_FOUND', () => {
    expect(() => getPractice('PW.3', catalog)).toThrowError(SsdfExtractError);
    try { getPractice('PW.3', catalog); } catch (e) { expect((e as SsdfExtractError).code).toBe('ERR_SSDF_PRACTICE_NOT_FOUND'); }
    expect(catalog.withdrawn_practices.map((w) => w.id)).toContain('PW.3');
  });

  it('counts 42 active tasks total with the published per-group split (13/4/16/9)', () => {
    const total = catalog.practices.reduce((a, p) => a + p.tasks.length, 0);
    expect(total).toBe(EXPECTED_TASK_COUNT);
    const byGroup = (g: 'PO' | 'PS' | 'PW' | 'RV') => getTasksByPracticeGroup(g, catalog).length;
    expect([byGroup('PO'), byGroup('PS'), byGroup('PW'), byGroup('RV')]).toEqual([13, 4, 16, 9]);
  });

  it('records exactly 5 withdrawn ("Moved to") tasks', () => {
    expect(catalog.withdrawn_tasks.map((w) => w.id).sort()).toEqual(['PW.3.1', 'PW.3.2', 'PW.4.3', 'PW.4.5', 'PW.5.2']);
  });
});

describe('SSDF catalog — NIST 800-53 Rev 5 mapping (verbatim from PDF Table 1)', () => {
  it('T5: 17 of 19 practices carry a non-empty 800-53 mapping; only PW.2 and PW.5 have none', () => {
    const empty = catalog.practices.filter((p) => p.nist_800_53_r5_controls.length === 0).map((p) => p.id);
    expect(empty.sort()).toEqual(['PW.2', 'PW.5']);
    expect(catalog.statistics.practices_with_53_mapping).toBe(17);
  });

  it('T6: PO.1 maps to the SP 800-53 controls published in its References cell', () => {
    const po1 = getPractice('PO.1', catalog).nist_800_53_r5_controls;
    for (const c of ['sa-1', 'sa-8', 'sa-15', 'sr-3']) expect(po1).toContain(c);
  });

  it('T7: RV.1 maps to the SP 800-53 controls published in its References cell', () => {
    const rv1 = getPractice('RV.1', catalog).nist_800_53_r5_controls;
    for (const c of ['sa-10', 'sa-11', 'sr-3', 'sr-4']) expect(rv1).toContain(c);
  });

  it('every control id is a lower-cased NIST control identifier', () => {
    for (const p of catalog.practices) {
      for (const c of p.nist_800_53_r5_controls) expect(c).toMatch(/^[a-z]{2}-\d+(\(\d+\))?$/);
    }
  });
});

describe('SSDF catalog — task statements + Common Form mapping', () => {
  it('T8: every task statement is non-empty and ASCII-normalized', () => {
    for (const p of catalog.practices) {
      for (const t of p.tasks) {
        expect(t.statement.length).toBeGreaterThan(20);
        expect(t.statement).toMatch(/^[\x20-\x7e]+$/);
      }
    }
  });

  it('PO.1.1 carries the verbatim NIST statement', () => {
    const po1 = getPractice('PO.1', catalog);
    const t = po1.tasks.find((x) => x.id === 'PO.1.1')!;
    expect(t.statement).toBe(
      "Identify and document all security requirements for the organization's software development infrastructures and processes, and maintain the requirements over time.",
    );
  });

  it('T9: 11 practices carry >=1 Common Form Section IV ref; the field is present on all 19', () => {
    expect(catalog.statistics.practices_with_common_form_ref).toBe(11);
    for (const p of catalog.practices) expect(Array.isArray(p.common_form_section_ref)).toBe(true);
    expect(getPractice('PO.2', catalog).common_form_section_ref).toEqual([]);
  });

  it('T11: tasksByCommonFormSection("§IV(3)") resolves to PS.3.2 (Provenance Data)', () => {
    const ids = tasksByCommonFormSection('§IV(3)', catalog).map((t) => t.id);
    expect(ids).toContain('PS.3.2');
    expect(ids.every((id) => id.startsWith('PS.3'))).toBe(true);
  });

  it('T10: getTasksByPracticeGroup("RV") returns only RV.* tasks, in order', () => {
    const ids = getTasksByPracticeGroup('RV', catalog).map((t) => t.id);
    expect(ids.length).toBeGreaterThan(0);
    expect(ids.every((id) => id.startsWith('RV.'))).toBe(true);
    expect(ids).toEqual([...ids].sort());
  });
});

describe('SSDF catalog — FedRAMP KSI forward map (curated)', () => {
  it('maps 12 practices to KSIs, every id real in core/ksi-map.ts, every entry carrying confidence + rationale', () => {
    expect(catalog.statistics.practices_with_ksi_map).toBe(12);
    for (const p of catalog.practices) {
      for (const e of p.fedramp_ksi_forward_map) {
        expect(e.ksi_id).toMatch(/^KSI-[A-Z]+-[A-Z0-9]+$/);
        expect(['high', 'medium', 'low']).toContain(e.confidence);
        expect(e.rationale.length).toBeGreaterThan(20);
      }
    }
  });

  it('PO.5 forward-maps to KSI-IAM-MFA (Common Form §IV(1)(c) secure-environment MFA)', () => {
    const ids = getPractice('PO.5', catalog).fedramp_ksi_forward_map.map((e) => e.ksi_id);
    expect(ids).toContain('KSI-IAM-MFA');
  });
});

describe('SSDF catalog — provenance + signature (REO)', () => {
  it('T12: provenance carries the G3 keys + a 64-hex source_pdf_sha256', () => {
    const pv = catalog.provenance;
    expect(pv.emitter).toBe('scripts/extract-ssdf-practices.mjs');
    expect(pv.emittedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(pv.sourceCalls.length).toBeGreaterThan(0);
    expect(pv.signingKeyId.length).toBeGreaterThan(0);
    expect(catalog.source_pdf_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(pv.sourcePdfSha256).toBe(catalog.source_pdf_sha256);
  });

  it('the catalog source_pdf_sha256 re-traces to the committed NIST PDF byte-for-byte', () => {
    const actual = createHash('sha256').update(readFileSync(PDF_PATH)).digest('hex');
    expect(catalog.source_pdf_sha256).toBe(actual);
  });

  it('T13: the embedded detached Ed25519 signature verifies; tampering breaks it', () => {
    expect(verifySsdfCatalogSignature(catalog)).toBe(true);
    const tampered: SsdfCatalog = JSON.parse(JSON.stringify(catalog));
    tampered.practices[0]!.tasks[0]!.statement = 'TAMPERED';
    expect(verifySsdfCatalogSignature(tampered)).toBe(false);
  });

  it('T18: canonical (signature-blanked) serialization is deterministic + lexicographically keyed', () => {
    const c1 = serializeUnsignedCanonical(catalog);
    const reordered: SsdfCatalog = JSON.parse(JSON.stringify(catalog));
    reordered.provenance = { ...reordered.provenance, signatureEd25519: 'zzz', publicKeyPem: 'zzz', signingKeyId: 'zzz' };
    expect(serializeUnsignedCanonical(reordered)).toBe(c1);
    expect(c1.startsWith('{"catalog_id":')).toBe(true);
  });
});

describe('SSDF catalog — loader validation (negative paths)', () => {
  it('valid fixture loads + passes validation against the real KSI universe', () => {
    const c = loadSsdfCatalog(fx('ssdf-catalog.valid.json'), { knownKsiIds });
    expect(c.practices).toHaveLength(19);
    expect(verifySsdfCatalogSignature(c)).toBe(true);
  });

  it('T14: a catalog with a dropped practice is rejected (ERR_SSDF_PRACTICE_COUNT_MISMATCH)', () => {
    try {
      loadSsdfCatalog(fx('ssdf-catalog.missing-practice.json'));
      throw new Error('expected load to throw');
    } catch (e) {
      expect(e).toBeInstanceOf(SsdfExtractError);
      expect((e as SsdfExtractError).code).toBe('ERR_SSDF_PRACTICE_COUNT_MISMATCH');
    }
  });

  it('T15: a forward map referencing an unknown KSI is rejected (ERR_SSDF_KSI_UNKNOWN)', () => {
    try {
      loadSsdfCatalog(fx('ssdf-catalog.bad-mapping.json'), { knownKsiIds });
      throw new Error('expected load to throw');
    } catch (e) {
      expect(e).toBeInstanceOf(SsdfExtractError);
      expect((e as SsdfExtractError).code).toBe('ERR_SSDF_KSI_UNKNOWN');
    }
  });

  it('validateCatalog rejects a wrong catalog_id (ERR_SSDF_SCHEMA_VERSION)', () => {
    const bad = JSON.parse(JSON.stringify(catalog)) as SsdfCatalog;
    (bad as { catalog_id: string }).catalog_id = 'not-ssdf';
    expect(() => validateCatalog(bad)).toThrowError(/ERR_SSDF_SCHEMA_VERSION|Unexpected catalog_id/);
  });
});
