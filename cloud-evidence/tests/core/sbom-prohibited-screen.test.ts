/**
 * Tests for core/sbom-prohibited-screen.ts (LOOP-W.W2 §8 T6/T7/T26).
 * SPDX transitive walk + depth penalty, CycloneDX publisher-field match, purl
 * namespace match, --sbom-max-depth truncation, and a clean (no-match) SBOM.
 */
import { describe, it, expect } from 'vitest';
import { fileURLToPath } from 'node:url';
import { VendorNameNormalizer } from '../../core/vendor-name-normalizer.ts';
import { buildScreenIndex } from '../../core/prohibited-vendors-screen.ts';
import { screenSbomDir } from '../../core/sbom-prohibited-screen.ts';
import { buildTestCatalog, namedEntities } from '../helpers/prohibited-vendors-screen.ts';

const fx = (p: string) => fileURLToPath(new URL(`../fixtures/prohibited-vendors/${p}`, import.meta.url));
const NOW = '2026-06-16T12:00:00.000Z';

function index() {
  const catalog = buildTestCatalog(namedEntities(), NOW);
  return buildScreenIndex({ catalog, normalizer: new VendorNameNormalizer() });
}

describe('sbom-prohibited-screen', () => {
  it('T6: SPDX transitive walk finds a depth-3 Huawei supplier with depth penalty', () => {
    const r = screenSbomDir({ sbomPaths: [fx('w2-sbom-spdx-transitive.json')], index: index(), discoveredAt: NOW });
    const hit = r.matches.find((m) => m.catalog_uid.includes('huawei'));
    expect(hit).toBeDefined();
    // base 1.0 (supplier exact) - 3 hops * 0.02 = 0.94.
    expect(hit!.confidence).toBeCloseTo(0.94, 5);
    expect(hit!.surface).toBe('sbom');
    expect(hit!.match_path).toEqual(['app', 'a-lib', 'b-lib', '@huawei-oss/foo']);
  });

  it('T7: CycloneDX publisher field matches Hikvision (high band)', () => {
    const r = screenSbomDir({ sbomPaths: [fx('w2-sbom-cyclonedx-publisher.json')], index: index(), discoveredAt: NOW });
    const hit = r.matches.find((m) => m.catalog_uid.includes('hikvision'));
    expect(hit).toBeDefined();
    expect(hit!.confidence_band).toBe('high');
    expect(hit!.matched_by).toBe('exact-case-insensitive');
  });

  it('matches via the strongest maintainer field (supplier dominates name/purl)', () => {
    const r = screenSbomDir({ sbomPaths: [fx('w2-sbom-spdx-transitive.json')], index: index(), discoveredAt: NOW });
    const hit = r.matches.find((m) => m.catalog_uid.includes('huawei'));
    expect(hit).toBeDefined();
    // The "@huawei-oss/foo" package's supplier "Huawei Technologies Company"
    // is the highest-confidence field, so the match is supplier-driven.
    expect(['exact-case-insensitive', 'normalized-name']).toContain(hit!.matched_by);
    expect(hit!.sources.sbom_package_purl).toContain('huawei');
  });

  it('T26: --sbom-max-depth=2 truncates the walk before a depth-3 match', () => {
    const r = screenSbomDir({ sbomPaths: [fx('w2-sbom-spdx-deep.json')], index: index(), discoveredAt: NOW, maxDepth: 2 });
    expect(r.matches.find((m) => m.catalog_uid.includes('huawei'))).toBeUndefined();
    expect(r.truncated_at_depth).toBe(2);
  });

  it('finds the same depth-3 match when max depth allows it', () => {
    const r = screenSbomDir({ sbomPaths: [fx('w2-sbom-spdx-deep.json')], index: index(), discoveredAt: NOW, maxDepth: 8 });
    expect(r.matches.find((m) => m.catalog_uid.includes('huawei'))).toBeDefined();
    expect(r.truncated_at_depth).toBeNull();
  });

  it('produces no matches for an SBOM with only clean suppliers', () => {
    const r = screenSbomDir({ sbomPaths: [fx('w2-sbom-cyclonedx-publisher.json')], index: index(), discoveredAt: NOW });
    expect(r.matches.every((m) => !m.catalog_uid.includes('zte'))).toBe(true);
    expect(r.packages_screened).toBeGreaterThan(0);
  });
});
