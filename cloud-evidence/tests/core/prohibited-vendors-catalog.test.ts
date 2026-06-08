/**
 * Tests for core/prohibited-vendors-catalog.ts — LOOP-W.W1 catalog emitter.
 *
 * Verifies the build → sign → emit → load pipeline:
 *   - deterministic sort + within-source dedupe + cross-source preservation
 *   - canonical-JSON determinism + lexicographic key sorting
 *   - G3-compliant provenance + verifiable detached Ed25519 signature
 *   - end-to-end emit: catalog + .sig + snapshot MANIFEST + coverage augment
 *   - typed errors on fetch failure / missing SAM key (no stale/partial catalog)
 *   - air-gapped offline operation makes no network calls
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, copyFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../../core/sign.ts';
import {
  emitProhibitedVendorsCatalog, buildCatalog, ingestAllSources,
  serializeUnsignedCanonical, verifyCatalogSignature, loadProhibitedVendorsCatalog,
  OfacFetchError, CATALOG_FILENAME,
  type SourceIngestResult,
} from '../../core/prohibited-vendors-catalog.ts';
import { normalizeName, type ProhibitedVendorEntity, type ProhibitedVendorsSourceId } from '../../core/prohibited-vendors-parsers.ts';
import { normalizeProhibitedVendorsConfig, ConfigError } from '../../core/prohibited-vendors-config.ts';
import { augmentCoverageWithProhibitedVendors } from '../../core/inventory-coverage.ts';

const DATA_DIR = fileURLToPath(new URL('../../data', import.meta.url));
const fx = (p: string) => fileURLToPath(new URL(`../fixtures/prohibited-vendors/${p}`, import.meta.url));
const FIXED_NOW = '2026-06-07T12:00:00.000Z';

const dirs: string[] = [];
function tmp(prefix = 'cev-pv-'): string {
  const d = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

/** Seed a snapshot directory with the network-source fixtures under their canonical names. */
function seedSnapshot(): string {
  const snap = tmp('cev-pv-snap-');
  copyFileSync(fx('sdn-small.csv'), join(snap, 'sdn.csv'));
  copyFileSync(fx('add-small.csv'), join(snap, 'add.csv'));
  copyFileSync(fx('alt-small.csv'), join(snap, 'alt.csv'));
  copyFileSync(fx('consolidated-mixed.csv'), join(snap, 'consolidated.csv'));
  copyFileSync(fx('sam-page-001.json'), join(snap, 'sam-exclusions-page-001.json'));
  copyFileSync(fx('sam-page-002.json'), join(snap, 'sam-exclusions-page-002.json'));
  return snap;
}

function mkEntity(source_id: ProhibitedVendorsSourceId, id: string, name: string): ProhibitedVendorEntity {
  return {
    source_id, source_record_id: id,
    name_canonical: normalizeName(name), name_canonical_stripped: normalizeName(name),
    name_verbatim: name, aliases: [], entity_type: 'organization', addresses: [],
    programs: [], authority_citation: 'test', raw_record_pointer: { snapshot_filename: 'x' },
  };
}
function mkIngest(id: ProhibitedVendorsSourceId, entities: ProhibitedVendorEntity[]): SourceIngestResult {
  return {
    meta: { id, source_url: 'u', snapshot_filename: 'f', sha256: 'x', bytes: 1, fetched_at: FIXED_NOW, authority_citation: 'a', entity_count: entities.length },
    entities,
  };
}
const build = (ingests: SourceIngestResult[]) =>
  buildCatalog({ ingests, snapshotDir: 'snap', generatedAt: FIXED_NOW, sourceCalls: ['file:x'] });

describe('buildCatalog', () => {
  it('T8: sorts entities by (source_id, name_canonical, source_record_id)', () => {
    const cat = build([
      mkIngest('ofac-sdn', [mkEntity('ofac-sdn', '2', 'Zeta'), mkEntity('ofac-sdn', '1', 'Alpha')]),
      mkIngest('bis-entity-list', [mkEntity('bis-entity-list', '9', 'Mid')]),
    ]);
    const keys = cat.entities.map((e) => `${e.source_id}|${e.name_canonical}|${e.source_record_id}`);
    const sorted = [...keys].sort();
    expect(keys).toEqual(sorted);
    expect(cat.entities[0]!.source_id).toBe('bis-entity-list'); // 'bis' < 'ofac'
  });

  it('T9: collapses duplicates within a single source', () => {
    const cat = build([
      mkIngest('ofac-sdn', [mkEntity('ofac-sdn', '1', 'Dup'), mkEntity('ofac-sdn', '1', 'Dup')]),
    ]);
    expect(cat.entities).toHaveLength(1);
    expect(cat.statistics.duplicates_collapsed).toBe(1);
  });

  it('T10: does NOT collapse cross-source duplicates (same name on OFAC + BIS)', () => {
    const cat = build([
      mkIngest('ofac-sdn', [mkEntity('ofac-sdn', '1', 'Huawei')]),
      mkIngest('bis-entity-list', [mkEntity('bis-entity-list', '1', 'Huawei')]),
    ]);
    expect(cat.entities).toHaveLength(2);
    const sources = new Set(cat.entities.map((e) => e.source_id));
    expect(sources).toEqual(new Set(['ofac-sdn', 'bis-entity-list']));
    expect(cat.statistics.duplicates_collapsed).toBe(0);
  });

  it('computes statistics by_source and requires_operator_input_count', () => {
    const flagged = mkEntity('fascsa', 'x', 'Y');
    flagged.requires_operator_input = 'missing-name-canonical';
    const cat = build([
      mkIngest('ofac-sdn', [mkEntity('ofac-sdn', '1', 'A'), mkEntity('ofac-sdn', '2', 'B')]),
      mkIngest('fascsa', [flagged]),
    ]);
    expect(cat.statistics.total_entities).toBe(3);
    expect(cat.statistics.by_source['ofac-sdn']).toBe(2);
    expect(cat.statistics.requires_operator_input_count).toBe(1);
  });
});

describe('canonical serialization', () => {
  it('T12: canonical (signature-blanked) form is deterministic across two builds', () => {
    const snap = seedSnapshot();
    const a = ingestAllSources({ dataDir: DATA_DIR, snapshotDir: snap, fetchedAt: FIXED_NOW });
    const b = ingestAllSources({ dataDir: DATA_DIR, snapshotDir: snap, fetchedAt: FIXED_NOW });
    const c1 = serializeUnsignedCanonical(buildCatalog({ ingests: a.ingests, snapshotDir: 'snap', generatedAt: FIXED_NOW, sourceCalls: a.sourceCalls }));
    const c2 = serializeUnsignedCanonical(buildCatalog({ ingests: b.ingests, snapshotDir: 'snap', generatedAt: FIXED_NOW, sourceCalls: b.sourceCalls }));
    expect(c1).toBe(c2);
  });

  it('T13: canonical JSON keys are lexicographically sorted at every depth', () => {
    const cat = build([mkIngest('ofac-sdn', [mkEntity('ofac-sdn', '1', 'A')])]);
    const canonical = serializeUnsignedCanonical(cat);
    // 'entities' is the lexicographically smallest top-level key.
    expect(canonical.startsWith('{"entities":')).toBe(true);
    // Key order in the input must not change the canonical output.
    const reverseKeys = (v: any): any => {
      if (Array.isArray(v)) return v.map(reverseKeys);
      if (v && typeof v === 'object') {
        const out: Record<string, any> = {};
        for (const k of Object.keys(v).reverse()) out[k] = reverseKeys(v[k]);
        return out;
      }
      return v;
    };
    expect(canonicalize(reverseKeys(cat))).toBe(canonicalize(cat));
  });
});

describe('emitProhibitedVendorsCatalog (end-to-end)', () => {
  it('T15/T14: writes catalog + .sig + MANIFEST with a verifiable signature and G3 provenance', async () => {
    const snap = seedSnapshot();
    const out = tmp();
    const res = await emitProhibitedVendorsCatalog({ outDir: out, dataDir: DATA_DIR, snapshotDir: snap, generatedAt: FIXED_NOW });

    // Catalog + sidecar signature written.
    expect(existsSync(res.catalog_path)).toBe(true);
    expect(existsSync(res.sig_path)).toBe(true);

    // 7 sources: ofac-sdn, bis-entity-list, sam-exclusions, far-52-204-25, ndaa-889, ndaa-1634, fascsa.
    expect(res.source_count).toBe(7);
    // 3 OFAC + 5 BIS + 10 SAM + 6 FAR + 5 §889 + 4 §1634 + 1 FASCSA = 34.
    expect(res.entity_count).toBe(34);

    // G3 provenance: camelCase emitter/emittedAt/sourceCalls(non-empty)/signingKeyId.
    const { catalog, signatureValid } = loadProhibitedVendorsCatalog(res.catalog_path);
    expect(catalog.provenance.emitter).toBeTruthy();
    expect(catalog.provenance.emittedAt).toBe(FIXED_NOW);
    expect(catalog.provenance.sourceCalls.length).toBeGreaterThan(0);
    expect(catalog.provenance.signingKeyId).toBeTruthy();
    expect(signatureValid).toBe(true);
    expect(verifyCatalogSignature(catalog)).toBe(true);

    // Snapshot MANIFEST: every entry has a 64-hex sha256, bytes > 0, and a url.
    expect(res.manifest_path).toBeTruthy();
    const manifest = JSON.parse(readFileSync(res.manifest_path!, 'utf8'));
    expect(manifest.files.length).toBe(7);
    for (const f of manifest.files) {
      expect(f.sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(f.bytes).toBeGreaterThan(0);
      expect(f.url).toBeTruthy();
    }
  });

  it('tampering with the catalog breaks signature verification', async () => {
    const snap = seedSnapshot();
    const out = tmp();
    const res = await emitProhibitedVendorsCatalog({ outDir: out, dataDir: DATA_DIR, snapshotDir: snap, generatedAt: FIXED_NOW });
    const { catalog } = loadProhibitedVendorsCatalog(res.catalog_path, { verify: false });
    catalog.entities[0]!.name_canonical = 'TAMPERED';
    expect(verifyCatalogSignature(catalog)).toBe(false);
  });

  it('T16: augments an existing out/inventory-coverage.json with entity + source counts', async () => {
    const snap = seedSnapshot();
    const out = tmp();
    writeFileSync(join(out, 'inventory-coverage.json'), JSON.stringify({ schema_version: 1, columns: [], totals: {} }));
    const res = await emitProhibitedVendorsCatalog({ outDir: out, dataDir: DATA_DIR, snapshotDir: snap, generatedAt: FIXED_NOW });
    const cov = JSON.parse(readFileSync(join(out, 'inventory-coverage.json'), 'utf8'));
    expect(cov.prohibited_vendors_catalog_entity_count).toBe(res.entity_count);
    expect(cov.prohibited_vendors_catalog_source_count).toBe(7);
  });

  it('emits the statutory constants even with no network snapshot staged', async () => {
    const out = tmp();
    const emptySnap = tmp('cev-pv-empty-');
    const res = await emitProhibitedVendorsCatalog({ outDir: out, dataDir: DATA_DIR, snapshotDir: emptySnap, generatedAt: FIXED_NOW });
    // far-52-204-25, ndaa-889, ndaa-1634, fascsa = 4 offline constant sources.
    expect(res.source_count).toBe(4);
    expect(res.entity_count).toBe(6 + 5 + 4 + 1);
  });

  it('T20: a re-run on the same snapshot leaves the raw source files unchanged', async () => {
    const snap = seedSnapshot();
    const out = tmp();
    const before = readFileSync(join(snap, 'sdn.csv'));
    await emitProhibitedVendorsCatalog({ outDir: out, dataDir: DATA_DIR, snapshotDir: snap, generatedAt: FIXED_NOW });
    await emitProhibitedVendorsCatalog({ outDir: out, dataDir: DATA_DIR, snapshotDir: snap, generatedAt: FIXED_NOW });
    const after = readFileSync(join(snap, 'sdn.csv'));
    expect(after.equals(before)).toBe(true);
  });
});

describe('fetch path (typed errors, no stale/partial catalog)', () => {
  it('T17: an OFAC HTTP failure throws OfacFetchError and writes no catalog', async () => {
    const out = tmp();
    const snap = tmp('cev-pv-snap-');
    const config = normalizeProhibitedVendorsConfig({ sam_gov: { api_key: 'A'.repeat(40) } });
    const fetcher = async () => ({ status: 503, body: Buffer.from('service unavailable') });
    await expect(
      emitProhibitedVendorsCatalog({ outDir: out, dataDir: DATA_DIR, snapshotDir: snap, generatedAt: FIXED_NOW, fetch: true, fetcher, config }),
    ).rejects.toBeInstanceOf(OfacFetchError);
    expect(existsSync(join(out, CATALOG_FILENAME))).toBe(false);
  });

  it('T19: a missing SAM API key throws ConfigError before any network call', async () => {
    const out = tmp();
    const snap = tmp('cev-pv-snap-');
    const config = normalizeProhibitedVendorsConfig({}); // no api_key
    let calls = 0;
    const fetcher = async () => { calls++; return { status: 200, body: Buffer.from('') }; };
    await expect(
      emitProhibitedVendorsCatalog({ outDir: out, dataDir: DATA_DIR, snapshotDir: snap, generatedAt: FIXED_NOW, fetch: true, fetcher, config }),
    ).rejects.toBeInstanceOf(ConfigError);
    expect(calls).toBe(0);
  });

  it('T18: air-gapped offline emit makes no network calls and still includes FASCSA', async () => {
    const snap = seedSnapshot();
    const out = tmp();
    let calls = 0;
    const fetcher = async () => { calls++; return { status: 200, body: Buffer.from('') }; };
    const config = normalizeProhibitedVendorsConfig({ fascsa: { manual_pdf_paths: ['data/sources/local.pdf'] } });
    const res = await emitProhibitedVendorsCatalog({ outDir: out, dataDir: DATA_DIR, snapshotDir: snap, generatedAt: FIXED_NOW, fetcher, config });
    expect(calls).toBe(0); // offline path never touches the fetcher
    const { catalog } = loadProhibitedVendorsCatalog(res.catalog_path);
    expect(catalog.sources.some((s) => s.id === 'fascsa')).toBe(true);
  });
});

describe('augmentCoverageWithProhibitedVendors', () => {
  it('adds the two sibling counts without mutating the input or touching fillRate', () => {
    const report = { schema_version: 1 as const, columns: [{ column: 'X', fillRate: { aws: 1 } }] };
    const out = augmentCoverageWithProhibitedVendors(report, { entityCount: 34, sourceCount: 7 });
    expect(out.prohibited_vendors_catalog_entity_count).toBe(34);
    expect(out.prohibited_vendors_catalog_source_count).toBe(7);
    expect((report as any).prohibited_vendors_catalog_entity_count).toBeUndefined(); // pure
    expect(out.columns).toBe(report.columns); // fillRate untouched
  });
});
