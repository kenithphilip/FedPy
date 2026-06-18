/**
 * Test helpers for the LOOP-W.W2 prohibited-vendor screen tests: build a
 * minimal `ProhibitedVendorEntity`, assemble a real signed catalog on disk, and
 * a normalizer/index factory. Fixtures only; never imported by production code.
 */
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  buildCatalog, signCatalog, CATALOG_FILENAME,
  type ProhibitedVendorsCatalog, type SourceIngestResult,
} from '../../core/prohibited-vendors-catalog.ts';
import type {
  ProhibitedVendorEntity, ProhibitedVendorsSourceId,
} from '../../core/prohibited-vendors-parsers.ts';
import { normalizeName, normalizeNameStripped } from '../../core/prohibited-vendors-parsers.ts';

export interface MakeEntityOpts {
  source_id?: ProhibitedVendorsSourceId;
  rid: string;
  name: string;
  aliases?: string[];
  subsidiaries?: string[];
  programs?: string[];
  authority?: string;
}

/** Build one normalized catalog entity (with optional `subsidiaries` extension). */
export function makeEntity(o: MakeEntityOpts): ProhibitedVendorEntity {
  const e: ProhibitedVendorEntity & { subsidiaries?: string[] } = {
    source_id: o.source_id ?? 'far-52-204-25',
    source_record_id: o.rid,
    name_canonical: normalizeName(o.name),
    name_canonical_stripped: normalizeNameStripped(o.name),
    name_verbatim: o.name,
    aliases: (o.aliases ?? []).map((a) => normalizeName(a)),
    entity_type: 'organization',
    addresses: [],
    programs: o.programs ?? ['FAR 52.204-25(a)'],
    authority_citation: o.authority ?? 'FAR 52.204-25(a); Pub. L. 115-232 §889',
    raw_record_pointer: { snapshot_filename: 'test-fixture.json' },
  };
  if (o.subsidiaries) e.subsidiaries = o.subsidiaries;
  return e;
}

/** Build an unsigned catalog object from a flat list of entities. */
export function buildTestCatalog(
  entities: ProhibitedVendorEntity[],
  generatedAt: string,
): ProhibitedVendorsCatalog {
  const ingest: SourceIngestResult = {
    meta: {
      id: 'far-52-204-25',
      source_url: 'https://www.acquisition.gov/far/52.204-25',
      snapshot_filename: 'test-fixture.json',
      sha256: 'test',
      bytes: 0,
      fetched_at: generatedAt,
      authority_citation: 'FAR 52.204-25(a)',
      entity_count: entities.length,
    },
    entities,
  };
  return buildCatalog({ ingests: [ingest], snapshotDir: 'test', generatedAt, sourceCalls: ['file:test-fixture.json'] });
}

/** Write a real, Ed25519-signed catalog to `outDir/prohibited-vendors-catalog.json`. */
export function writeSignedCatalog(
  outDir: string,
  entities: ProhibitedVendorEntity[],
  generatedAt: string,
): string {
  const catalog = buildTestCatalog(entities, generatedAt);
  const { signed } = signCatalog(catalog, outDir);
  const path = resolve(outDir, CATALOG_FILENAME);
  writeFileSync(path, JSON.stringify(signed, null, 2));
  return path;
}

/** The five FAR 52.204-25 / NDAA §1634 named entities, as catalog rows. */
export function namedEntities(): ProhibitedVendorEntity[] {
  return [
    makeEntity({ rid: 'huawei-technologies-company', name: 'Huawei Technologies Company', aliases: ['Huawei', 'Хуавэй'], subsidiaries: ['HiSilicon'] }),
    makeEntity({ rid: 'zte-corporation', name: 'ZTE Corporation', aliases: ['ZTE'] }),
    makeEntity({ rid: 'hytera-communications-corporation', name: 'Hytera Communications Corporation', aliases: ['Hytera'] }),
    makeEntity({ rid: 'hangzhou-hikvision-digital-technology-company', name: 'Hangzhou Hikvision Digital Technology Company', aliases: ['Hikvision'] }),
    makeEntity({ rid: 'dahua-technology-company', name: 'Dahua Technology Company', aliases: ['Dahua'] }),
    makeEntity({ source_id: 'ndaa-1634', rid: 'kaspersky-lab', name: 'Kaspersky Lab', aliases: ['Kaspersky'], programs: ['named'], authority: 'Pub. L. 115-91 §1634' }),
  ];
}
