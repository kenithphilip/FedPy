/**
 * Tests for the LOOP-W.W2 prohibited-vendor screen: matcher + surface walkers
 * (core/prohibited-vendors-screen.ts), end-to-end emit + signing
 * (core/prohibited-vendors-screen-emit.ts), and the POA&M item builder
 * (core/oscal-poam.ts:buildVendorScreenPoamItems).
 *
 * Covers W.W2 §8: T1-T5 (subprocessor exact/normalized/transliteration/
 * subsidiary depth-1/2), T10/T11 (inventory tag/sku), T12 (false positive),
 * T13 (suppression + expiry), T14 (manual addition), T15 (stale catalog),
 * T16 (POA&M emission), T17 (provenance), T18 (xlsx), T19/T20 (emit gating),
 * T21 (catalog signature failure), T22 (NDAA 1634 reportable), T23/T24/T25
 * (OFAC/BIS/SAM provenance propagation), T29 (reasonable-inquiry attestation),
 * plus dedupe, FAR REQUIRES-OPERATOR-INPUT, and the durable screen ledger.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, rmSync, readFileSync, existsSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { VendorNameNormalizer } from '../../core/vendor-name-normalizer.ts';
import {
  buildScreenIndex, screenSubprocessorRows, screenInventoryAssets,
  assembleScreenResult, dedupeMatches, REQUIRES_OPERATOR_INPUT,
  type ProhibitedVendorMatch, type SurfaceScreened,
} from '../../core/prohibited-vendors-screen.ts';
import {
  emitProhibitedVendorsScreen, CatalogSignatureInvalidError,
} from '../../core/prohibited-vendors-screen-emit.ts';
import { buildVendorScreenPoamItems } from '../../core/oscal-poam.ts';
import {
  makeEntity, buildTestCatalog, writeSignedCatalog, namedEntities,
} from '../helpers/prohibited-vendors-screen.ts';
import type { ProhibitedVendorEntity } from '../../core/prohibited-vendors-parsers.ts';

const fx = (p: string) => fileURLToPath(new URL(`../fixtures/prohibited-vendors/${p}`, import.meta.url));
const FIX_DIR = fileURLToPath(new URL('../fixtures/prohibited-vendors', import.meta.url));
const NOW = '2026-06-16T12:00:00.000Z';

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-w2-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

const norm = () => new VendorNameNormalizer();
function indexOf(entities: ProhibitedVendorEntity[], extra?: Parameters<typeof buildScreenIndex>[0]) {
  const catalog = buildTestCatalog(entities, NOW);
  return buildScreenIndex({ catalog, normalizer: norm(), ...extra });
}
const rows = (...names: string[]) => names.map((name) => ({ name }));

// ─── Matcher + subprocessor walker (T1-T5, T12) ──────────────────────────────

describe('subprocessor surface matcher', () => {
  it('T1: exact-case-insensitive Huawei match (confidence 1.0, reportable)', () => {
    const m = screenSubprocessorRows({ rows: rows('Huawei Technologies Company'), index: indexOf(namedEntities()), normalizer: norm(), discoveredAt: NOW });
    expect(m).toHaveLength(1);
    expect(m[0]!.matched_by).toBe('exact-case-insensitive');
    expect(m[0]!.confidence).toBe(1.0);
    expect(m[0]!.confidence_band).toBe('high');
  });

  it('T2: normalized-name match after corporate-suffix strip ("ZTE Corporation Ltd")', () => {
    const m = screenSubprocessorRows({ rows: rows('ZTE Corporation Ltd'), index: indexOf(namedEntities()), normalizer: norm(), discoveredAt: NOW });
    expect(m[0]!.matched_by).toBe('normalized-name');
    expect(m[0]!.confidence).toBe(1.0);
  });

  it('T3: Cyrillic transliteration match ("Хуавэй" -> Huawei, 0.95)', () => {
    const m = screenSubprocessorRows({ rows: rows('Хуавэй'), index: indexOf(namedEntities()), normalizer: norm(), discoveredAt: NOW });
    expect(m[0]!.matched_by).toBe('transliteration');
    expect(m[0]!.confidence).toBeCloseTo(0.95, 5);
  });

  it('T4: subsidiary-walk depth-1 ("HiSilicon" -> Huawei, 0.85)', () => {
    const m = screenSubprocessorRows({ rows: rows('HiSilicon'), index: indexOf(namedEntities()), normalizer: norm(), discoveredAt: NOW });
    expect(m[0]!.matched_by).toBe('subsidiary-walk');
    expect(m[0]!.confidence).toBeCloseTo(0.85, 5);
    expect(m[0]!.confidence_band).toBe('high');
  });

  it('T5: subsidiary-walk depth-2 (operator chain) lands in the medium band (0.7)', () => {
    const idx = indexOf(namedEntities(), {
      catalog: buildTestCatalog(namedEntities(), NOW),
      normalizer: norm(),
      manualAdditions: [{ entity_name: 'Hikvision Holdings', subsidiaries: ['Hikvision Holdings>HikMid>HikGrandchild'], justification: 'operator chain' }],
    });
    const m = screenSubprocessorRows({ rows: rows('HikGrandchild'), index: idx, normalizer: norm(), discoveredAt: NOW });
    const hit = m.find((x) => x.matched_by === 'subsidiary-walk');
    expect(hit).toBeDefined();
    expect(hit!.confidence).toBeCloseTo(0.7, 5);
    expect(hit!.confidence_band).toBe('medium');
  });

  it('T12: a vendor with a covered name glued inside a token does NOT match', () => {
    const m = screenSubprocessorRows({ rows: rows('Acmehikvisioninspired Optics'), index: indexOf(namedEntities()), normalizer: norm(), discoveredAt: NOW });
    expect(m).toHaveLength(0);
  });

  it('sets FAR data elements to REQUIRES-OPERATOR-INPUT when not operator-supplied', () => {
    const m = screenSubprocessorRows({ rows: rows('Huawei Technologies Company'), index: indexOf(namedEntities()), normalizer: norm(), discoveredAt: NOW });
    const far = m[0]!.far_52_204_25_d_data_elements;
    expect(far.supplier_uei).toBe(REQUIRES_OPERATOR_INPUT);
    expect(far.supplier_cage_code).toBe(REQUIRES_OPERATOR_INPUT);
    expect(far.supplier_name).toBe('Huawei Technologies Company');
    expect(m[0]!.related_controls).toEqual(['sr-1', 'sr-3', 'sr-5', 'sr-6', 'sr-11']);
  });
});

// ─── Inventory walker (T10, T11) ─────────────────────────────────────────────

describe('inventory surface matcher', () => {
  const inv = JSON.parse(readFileSync(fx('w2-inventory.json'), 'utf8')).assets;

  it('T10: provider_tag match ("huawei-public-cloud", high band)', () => {
    const m = screenInventoryAssets({ assets: inv, index: indexOf(namedEntities()), normalizer: norm(), discoveredAt: NOW });
    const hit = m.find((x) => x.catalog_uid.includes('huawei'));
    expect(hit).toBeDefined();
    expect(hit!.surface).toBe('inventory-provider-tag');
    expect(hit!.confidence_band).toBe('high');
    expect(hit!.sources.inventory_asset_id).toBe('asset-1');
  });

  it('T11: SKU substring match capped at 0.85 ("hikvision-camera-...")', () => {
    const m = screenInventoryAssets({ assets: inv, index: indexOf(namedEntities()), normalizer: norm(), discoveredAt: NOW });
    const hit = m.find((x) => x.catalog_uid.includes('hikvision'));
    expect(hit).toBeDefined();
    expect(hit!.confidence).toBeLessThanOrEqual(0.85);
  });
});

// ─── Provenance propagation (T22, T23, T24, T25) ─────────────────────────────

describe('catalog provenance propagation', () => {
  const entities = [
    makeEntity({ source_id: 'ofac-sdn', rid: '12345', name: 'Evil OFAC Corp', programs: ['CYBER2'], authority: 'OFAC SDN (IEEPA)' }),
    makeEntity({ source_id: 'bis-entity-list', rid: 'bis-1', name: 'BIS Bad Co', programs: ['EL'], authority: '15 CFR 744 Supp. 4' }),
    makeEntity({ source_id: 'sam-exclusions', rid: 'sam-1', name: 'SAM Excluded Inc', programs: ['Prohibition/Restriction'], authority: 'FAR 9.404' }),
    makeEntity({ source_id: 'ndaa-1634', rid: 'kaspersky-lab', name: 'Kaspersky Lab', aliases: ['Kaspersky'], authority: 'Pub. L. 115-91 §1634' }),
  ];

  it('T23: OFAC SDN source + list_program propagate onto the match', () => {
    const m = screenSubprocessorRows({ rows: rows('Evil OFAC Corp'), index: indexOf(entities), normalizer: norm(), discoveredAt: NOW });
    expect(m[0]!.catalog_provenance.source).toBe('ofac-sdn');
    expect(m[0]!.catalog_provenance.list_program).toBe('CYBER2');
  });

  it('T24: BIS Entity List program code propagates', () => {
    const m = screenSubprocessorRows({ rows: rows('BIS Bad Co'), index: indexOf(entities), normalizer: norm(), discoveredAt: NOW });
    expect(m[0]!.catalog_provenance.source).toBe('bis-entity-list');
    expect(m[0]!.catalog_provenance.list_program).toBe('EL');
  });

  it('T25: SAM Exclusions exclusion_type propagates', () => {
    const m = screenSubprocessorRows({ rows: rows('SAM Excluded Inc'), index: indexOf(entities), normalizer: norm(), discoveredAt: NOW });
    expect(m[0]!.catalog_provenance.source).toBe('sam-exclusions');
    expect(m[0]!.catalog_provenance.exclusion_type).toBe('Prohibition/Restriction');
  });

  it('T22: a Kaspersky (NDAA 1634) match sets reportable_under_ndaa_1634', () => {
    const matches = screenSubprocessorRows({ rows: rows('Kaspersky Lab'), index: indexOf(entities), normalizer: norm(), discoveredAt: NOW });
    const result = assembleScreenResult({
      runId: 'r1', cspName: 'Test CSP', startedAt: NOW, completedAt: NOW,
      catalogRef: { path: 'c', sha256: 'x', generated_at: NOW, age_hours: 1, is_stale: false },
      surfaces: [], matches, suppressions: new Map(), surfacesWalkedCount: 1,
    });
    expect(result.reportable_under_ndaa_1634).toBe(true);
  });
});

// ─── Assembly: dedupe, reportable flags, reasonable inquiry (T29) ─────────────

describe('assembleScreenResult', () => {
  it('dedupes matches by (surface, catalog_uid, name, path) keeping highest confidence', () => {
    const m = screenSubprocessorRows({ rows: rows('Huawei Technologies Company', 'Huawei Technologies Company'), index: indexOf(namedEntities()), normalizer: norm(), discoveredAt: NOW });
    expect(m.length).toBe(2);
    expect(dedupeMatches(m).length).toBe(1);
  });

  it('T29: reasonable_inquiry_attested requires 4 surfaces + fresh catalog + low suppression', () => {
    const matches = screenSubprocessorRows({ rows: rows('Huawei Technologies Company'), index: indexOf(namedEntities()), normalizer: norm(), discoveredAt: NOW });
    const surfaces: SurfaceScreened[] = ['subprocessor-sheet', 'sbom', 'oci-publisher', 'inventory-provider-tag']
      .map((s) => ({ surface: s as any, entries_screened: 1, source_path: s, walked_at: NOW }));
    const result = assembleScreenResult({
      runId: 'r1', cspName: 'CSP', startedAt: NOW, completedAt: NOW,
      catalogRef: { path: 'c', sha256: 'x', generated_at: NOW, age_hours: 1, is_stale: false },
      surfaces, matches, suppressions: new Map(), surfacesWalkedCount: 4,
    });
    expect(result.reasonable_inquiry_attested).toBe(true);
    expect(result.reportable_under_far_52_204_25_d).toBe(true);
  });

  it('reasonable_inquiry_attested=false when the catalog is stale', () => {
    const result = assembleScreenResult({
      runId: 'r1', cspName: 'CSP', startedAt: NOW, completedAt: NOW,
      catalogRef: { path: 'c', sha256: 'x', generated_at: NOW, age_hours: 72, is_stale: true },
      surfaces: [], matches: [], suppressions: new Map(), surfacesWalkedCount: 4,
    });
    expect(result.reasonable_inquiry_attested).toBe(false);
  });
});

// ─── POA&M item builder (T16) ────────────────────────────────────────────────

describe('buildVendorScreenPoamItems (T16)', () => {
  it('emits one high-severity POA&M item per non-suppressed match with SR controls', () => {
    const matches = screenSubprocessorRows({ rows: rows('Huawei Technologies Company'), index: indexOf(namedEntities()), normalizer: norm(), discoveredAt: NOW });
    const items = buildVendorScreenPoamItems(matches);
    expect(items).toHaveLength(1);
    const controls = (items[0]!.props ?? []).filter((p) => p.name === 'nist-control').map((p) => p.value);
    expect(controls).toEqual(['sr-1', 'sr-3', 'sr-5', 'sr-6', 'sr-11']);
    expect((items[0]!.props ?? []).find((p) => p.name === 'severity')?.value).toBe('high');
    expect(items[0]!.title).toContain('Huawei');
  });

  it('omits suppressed matches from the POA&M', () => {
    const matches = screenSubprocessorRows({ rows: rows('Huawei Technologies Company'), index: indexOf(namedEntities()), normalizer: norm(), discoveredAt: NOW });
    matches[0]!.suppressed = true;
    expect(buildVendorScreenPoamItems(matches)).toHaveLength(0);
  });
});

// ─── End-to-end emit (T13, T14, T15, T17, T18, T19/T20, T21) ─────────────────

describe('emitProhibitedVendorsScreen', () => {
  function fullRun(outDir: string, extra: Partial<Parameters<typeof emitProhibitedVendorsScreen>[0]> = {}) {
    writeSignedCatalog(outDir, namedEntities(), NOW);
    return emitProhibitedVendorsScreen({
      outDir, runId: 'run-1', cspName: 'Test CSP', completedAt: NOW,
      subprocessorRows: rows('Huawei Technologies Company', 'Clean Vendor LLC'),
      subprocessorSourcePath: undefined,
      sbomPaths: [fx('w2-sbom-spdx-transitive.json')],
      ociAttestationDir: FIX_DIR,
      inventoryPath: fx('w2-inventory.json'),
      ...extra,
    });
  }

  it('T17/T18/T19: writes a signed envelope + .sig + .xlsx + ledger with all four surfaces walked', () => {
    const outDir = tmp();
    const r = fullRun(outDir);
    expect(existsSync(r.json_path)).toBe(true);
    expect(existsSync(r.sig_path)).toBe(true);
    expect(r.xlsx_path && existsSync(r.xlsx_path)).toBeTruthy();
    expect(existsSync(r.ledger_path)).toBe(true);
    expect(r.surfaces_walked).toBe(4);
    // xlsx is a real OOXML zip (PK magic).
    const xlsx = readFileSync(r.xlsx_path!);
    expect(xlsx.subarray(0, 2).toString('latin1')).toBe('PK');
    // T17: camelCase provenance block populated (the G3 contract).
    const env = JSON.parse(readFileSync(r.json_path, 'utf8'));
    expect(env.provenance.emitter).toBeTruthy();
    expect(env.provenance.emittedAt).toBeTruthy();
    expect(env.provenance.sourceCalls.length).toBeGreaterThan(0);
    expect(env.provenance.signingKeyId).toBeTruthy();
    expect(env.provenance.sourceDigests.some((d: any) => d.kind === 'catalog-snapshot')).toBe(true);
    // Found Huawei across subprocessor + sbom surfaces.
    expect(env.matches.some((m: any) => m.catalog_uid.includes('huawei'))).toBe(true);
    expect(env.reasonable_inquiry_attested).toBe(true);
    // Durable ledger gained a record.
    const ledger = readFileSync(r.ledger_path, 'utf8').trim().split('\n');
    expect(ledger.length).toBe(1);
    expect(JSON.parse(ledger[0]!).run_id).toBe('run-1');
  });

  it('T20: re-emitting appends a second ledger record (append-only)', () => {
    const outDir = tmp();
    fullRun(outDir);
    const r2 = fullRun(outDir, { runId: 'run-2' });
    const ledger = readFileSync(r2.ledger_path, 'utf8').trim().split('\n');
    expect(ledger.length).toBe(2);
  });

  it('emit with no surfaces provided still writes a valid empty envelope (gating)', () => {
    const outDir = tmp();
    writeSignedCatalog(outDir, namedEntities(), NOW);
    const r = emitProhibitedVendorsScreen({ outDir, runId: 'r', cspName: 'CSP', completedAt: NOW, ociAttestationDir: undefined });
    expect(r.total_matches).toBe(0);
    expect(existsSync(r.json_path)).toBe(true);
  });

  it('T13: an unexpired suppression flags the match; a lapsed one does not', () => {
    const outDir = tmp();
    const r = fullRun(outDir, {
      subprocessorRows: rows('ZTE Corporation', 'Dahua Technology Company'),
      overridesPath: fx('w2-overrides-suppression.yaml'),
    });
    const zte = r.result.matches.find((m) => m.catalog_uid.includes('zte'));
    const dahua = r.result.matches.find((m) => m.catalog_uid.includes('dahua'));
    expect(zte!.suppressed).toBe(true);
    expect(zte!.suppression_justification).toMatch(/CISO/);
    expect(dahua!.suppressed).toBe(false); // suppression expired 2024-06-01
  });

  it('T14: an operator manual addition is screened like a catalog row', () => {
    const outDir = tmp();
    const r = fullRun(outDir, {
      subprocessorRows: rows('Suspicious Holdings'),
      overridesPath: fx('w2-overrides-valid.yaml'),
    });
    const hit = r.result.matches.find((m) => m.catalog_provenance.source === 'operator-manual-addition');
    expect(hit).toBeDefined();
    expect(hit!.matched_entity_name).toBe('Suspicious Holdings');
  });

  it('T15: a stale (>24h) catalog sets is_stale and clears reasonable_inquiry', () => {
    const outDir = tmp();
    const staleGeneratedAt = '2026-06-10T12:00:00.000Z'; // 6 days before NOW
    writeSignedCatalog(outDir, namedEntities(), staleGeneratedAt);
    const r = emitProhibitedVendorsScreen({
      outDir, runId: 'r', cspName: 'CSP', completedAt: NOW,
      subprocessorRows: rows('Huawei Technologies Company'),
      sbomPaths: [fx('w2-sbom-spdx-transitive.json')],
      ociAttestationDir: FIX_DIR, inventoryPath: fx('w2-inventory.json'),
    });
    expect(r.result.catalog_snapshot_ref.is_stale).toBe(true);
    expect(r.result.catalog_snapshot_ref.age_hours).toBeGreaterThan(24);
    expect(r.result.reasonable_inquiry_attested).toBe(false);
  });

  it('T21: a tampered catalog signature throws CatalogSignatureInvalidError', () => {
    const outDir = tmp();
    const catalogPath = writeSignedCatalog(outDir, namedEntities(), NOW);
    const tampered = readFileSync(catalogPath, 'utf8').replace('Huawei Technologies Company', 'Tampered Vendor');
    writeFileSync(catalogPath, tampered);
    expect(() => emitProhibitedVendorsScreen({ outDir, runId: 'r', cspName: 'CSP', completedAt: NOW }))
      .toThrow(CatalogSignatureInvalidError);
  });
});
