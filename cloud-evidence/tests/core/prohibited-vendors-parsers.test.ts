/**
 * Tests for core/prohibited-vendors-parsers.ts — LOOP-W.W1 per-source parsers.
 *
 * Verifies each federal source parses into normalized ProhibitedVendorEntity[]:
 *   - OFAC SDN CSV (with ADD/ALT joins on ent_num)
 *   - BIS Entity List filter over the consolidated screening list CSV
 *   - SAM.gov Exclusions pagination flatten
 *   - FAR 52.204-25 / NDAA §889 / NDAA §1634 statutory constants
 *   - FASCSA operator-maintained register
 *   - name normalization (NFKC + uppercase + collapse) + suffix stripping
 *   - RFC-4180 CSV quoting + schema-drift detection
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  parseOfacSdn, parseBisEntityList, parseSamExclusions,
  parseFar52204_25, parseNdaa889, parseNdaa1634, parseFascsaOrders,
  normalizeName, normalizeNameStripped, parseCsv, SourceSchemaDriftError,
} from '../../core/prohibited-vendors-parsers.ts';

const fx = (p: string) => fileURLToPath(new URL(`../fixtures/prohibited-vendors/${p}`, import.meta.url));
const dataFile = (p: string) => fileURLToPath(new URL(`../../data/${p}`, import.meta.url));
const read = (p: string) => readFileSync(p, 'utf8');
const readJson = (p: string) => JSON.parse(readFileSync(p, 'utf8'));

describe('parseOfacSdn', () => {
  it('T1: ingests SDN.CSV with 3 entities and joins 2 aliases onto the first', () => {
    const entities = parseOfacSdn(read(fx('sdn-small.csv')), read(fx('add-small.csv')), read(fx('alt-small.csv')));
    expect(entities).toHaveLength(3);
    expect(entities.every((e) => e.source_id === 'ofac-sdn')).toBe(true);
    expect(entities[0]!.source_record_id).toBe('1001');
    expect(entities[0]!.aliases).toEqual(['HUAWEI', 'HUAWEI TECH']); // sorted + deduped
    expect(entities[0]!.aliases).toHaveLength(2);
  });

  it('maps SDN_Type and joins addresses on ent_num', () => {
    const entities = parseOfacSdn(read(fx('sdn-small.csv')), read(fx('add-small.csv')), read(fx('alt-small.csv')));
    const ivan = entities.find((e) => e.source_record_id === '1002')!;
    expect(ivan.entity_type).toBe('individual');
    const huawei = entities.find((e) => e.source_record_id === '1001')!;
    expect(huawei.entity_type).toBe('organization');
    expect(huawei.addresses.length).toBe(1);
    expect(huawei.addresses[0]!.country).toBe('China');
  });

  it('T11: a row missing the name keeps the entity and flags requires_operator_input', () => {
    const csv = '3001,"-0-","-0-","ENTITY","-0-","-0-","-0-","-0-","-0-","-0-","-0-","-0-"\n';
    const entities = parseOfacSdn(csv);
    expect(entities).toHaveLength(1);
    expect(entities[0]!.requires_operator_input).toBe('missing-name-canonical');
  });

  it('throws SourceSchemaDriftError when the column count collapses', () => {
    const broken = 'a,b\nc,d\n';
    expect(() => parseOfacSdn(broken)).toThrow(SourceSchemaDriftError);
  });
});

describe('parseBisEntityList', () => {
  it('T2: filters the consolidated CSV to only Entity List (EL) rows', () => {
    const entities = parseBisEntityList(read(fx('consolidated-mixed.csv')));
    expect(entities).toHaveLength(5); // 5 EL rows among 10 in the fixture
    expect(entities.every((e) => e.source_id === 'bis-entity-list')).toBe(true);
    const names = entities.map((e) => e.name_canonical);
    expect(names).toContain('HUAWEI TECHNOLOGIES CO., LTD.');
    const huawei = entities.find((e) => e.source_record_id === 'EL-001')!;
    expect(huawei.aliases).toContain('HUAWEI');
  });

  it('throws SourceSchemaDriftError when the required name column is renamed', () => {
    const broken = 'source,entity_number,company\n"Entity List (EL) - Bureau of Industry and Security","EL-9","X"\n';
    expect(() => parseBisEntityList(broken)).toThrow(SourceSchemaDriftError);
  });
});

describe('parseSamExclusions', () => {
  it('T3: flattens paginated pages and round-trips ueiSAM on source_record_id', () => {
    const pages = [readJson(fx('sam-page-001.json')), readJson(fx('sam-page-002.json'))];
    const entities = parseSamExclusions(pages);
    expect(entities).toHaveLength(10);
    expect(entities.every((e) => e.source_id === 'sam-exclusions')).toBe(true);
    expect(entities[0]!.source_record_id).toBe('UEI0000000001');
    expect(entities[0]!.effective_date).toBe('2024-01-01');
    expect(entities.find((e) => e.source_record_id === 'UEI0000000010')).toBeTruthy();
  });
});

describe('statutory-constant parsers', () => {
  it('T4: parseFar52204_25 emits the 5 named entities + the §889(f)(3)(D) catch-all', () => {
    const entities = parseFar52204_25(readJson(dataFile('far-52-204-25-named-entities.json')));
    expect(entities).toHaveLength(6);
    const names = new Set(entities.map((e) => e.name_canonical));
    expect(names.has('HUAWEI TECHNOLOGIES COMPANY')).toBe(true);
    expect(names.has('ZTE CORPORATION')).toBe(true);
    expect(names.has('HYTERA COMMUNICATIONS CORPORATION')).toBe(true);
    expect(names.has('HANGZHOU HIKVISION DIGITAL TECHNOLOGY COMPANY')).toBe(true);
    expect(names.has('DAHUA TECHNOLOGY COMPANY')).toBe(true);
    expect(names.has("ENTITIES OWNED OR CONTROLLED BY THE GOVERNMENT OF THE PEOPLE'S REPUBLIC OF CHINA")).toBe(true);
    expect(entities.every((e) => e.source_id === 'far-52-204-25')).toBe(true);
  });

  it('parseNdaa889 emits the 5 named telecom entities under the §889 source id', () => {
    const entities = parseNdaa889(readJson(dataFile('far-52-204-25-named-entities.json')));
    expect(entities).toHaveLength(5); // no catch-all
    expect(entities.every((e) => e.source_id === 'ndaa-889')).toBe(true);
    expect(entities.every((e) => e.authority_citation.includes('Pub. L. 115-232 §889'))).toBe(true);
  });

  it('T5: parseNdaa1634 emits the 4 Kaspersky covered-entity classes', () => {
    const entities = parseNdaa1634(readJson(dataFile('ndaa-1634-named-entities.json')));
    expect(entities).toHaveLength(4);
    expect(entities.every((e) => e.source_id === 'ndaa-1634')).toBe(true);
    expect(entities.every((e) => e.authority_citation.includes('Pub. L. 115-91 §1634'))).toBe(true);
    expect(entities.find((e) => e.name_canonical === 'KASPERSKY LAB')).toBeTruthy();
  });

  it('parseFascsaOrders ingests the register and flags unconfirmed order ids', () => {
    const entities = parseFascsaOrders(readJson(dataFile('fascsa-orders.json')));
    expect(entities.length).toBeGreaterThanOrEqual(1);
    expect(entities.every((e) => e.source_id === 'fascsa')).toBe(true);
    expect(entities[0]!.authority_citation).toContain('41 U.S.C. §1323');
    // The seeded Kaspersky order is confirmed → no requires_operator_input.
    const unconfirmed = parseFascsaOrders({ orders: [{ order_id: 'x', entity_name_verbatim: 'Y', confirmed: false }] });
    expect(unconfirmed[0]!.requires_operator_input).toBe('fascsa-order-id-unconfirmed');
  });
});

describe('normalization', () => {
  it('T7: normalizeName applies NFKC + uppercase + whitespace collapse', () => {
    expect(normalizeName('Huawei Technologies Co.,  Ltd.')).toBe('HUAWEI TECHNOLOGIES CO., LTD.');
    expect(normalizeName('  trailing  ')).toBe('TRAILING');
    // NFKC folds a full-width digit; café stays accented (NFC-equivalent).
    expect(normalizeName('ＡＢＣ')).toBe('ABC');
    expect(normalizeName('Café')).toBe('CAFÉ');
  });

  it('normalizeNameStripped removes corporate-form suffix tokens', () => {
    expect(normalizeNameStripped('Huawei Technologies Co., Ltd.')).toBe('HUAWEI TECHNOLOGIES');
    expect(normalizeNameStripped('Excluded Vendor One LLC')).toBe('EXCLUDED VENDOR ONE');
    expect(normalizeNameStripped('Acme Incorporated')).toBe('ACME');
  });
});

describe('parseCsv', () => {
  it('handles quoted fields with embedded commas and doubled quotes', () => {
    const rows = parseCsv('a,"b,c","d""e"\n1,2,3\n');
    expect(rows[0]).toEqual(['a', 'b,c', 'd"e']);
    expect(rows[1]).toEqual(['1', '2', '3']);
  });
});
