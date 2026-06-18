/**
 * Tests for core/prohibited-vendors-overrides.ts (LOOP-W.W2 §8 T13/T28).
 * Valid load, schema rejection (missing justification), bad date, bad YAML,
 * suppression-map construction, and manual-addition / fingerprint shapes.
 */
import { describe, it, expect } from 'vitest';
import { fileURLToPath } from 'node:url';
import {
  loadProhibitedVendorsOverrides,
  normalizeOverrides,
  suppressionsByCatalogUid,
  ProhibitedVendorOverridesSchemaError,
} from '../../core/prohibited-vendors-overrides.ts';

const fx = (p: string) => fileURLToPath(new URL(`../fixtures/prohibited-vendors/${p}`, import.meta.url));

describe('prohibited-vendors-overrides loader', () => {
  it('loads a valid overrides file', () => {
    const o = loadProhibitedVendorsOverrides(fx('w2-overrides-valid.yaml'));
    expect(o.suppressions).toHaveLength(1);
    expect(o.suppressions[0]!.catalog_uid).toBe('ofac-sdn::99999');
    expect(o.manual_additions).toHaveLength(1);
    expect(o.manual_additions[0]!.entity_name).toBe('Suspicious Holdings');
    expect(o.manual_additions[0]!.subsidiaries).toContain('Suspicious Subsidiary');
    expect(o.manual_additions[0]!.fingerprints?.[0]).toMatch(/^sha256:/);
    expect(o.transliteration_overrides['сасписиус']).toBe('suspicious');
    expect(o.fingerprint_overrides[0]!.catalog_uid).toBe('far-52-204-25::huawei-technologies-company');
  });

  it('returns empty overrides when the path is missing', () => {
    const o = loadProhibitedVendorsOverrides(undefined);
    expect(o.suppressions).toEqual([]);
    expect(o.manual_additions).toEqual([]);
  });

  it('rejects a suppression missing its justification (T28)', () => {
    expect(() => loadProhibitedVendorsOverrides(fx('w2-overrides-bad-schema.yaml')))
      .toThrow(ProhibitedVendorOverridesSchemaError);
  });

  it('rejects an unparseable expires_at date', () => {
    expect(() => normalizeOverrides({
      suppressions: [{ catalog_uid: 'x::y', justification: 'why', expires_at: 'not-a-date' }],
    })).toThrow(/expires_at/);
  });

  it('rejects a manual addition missing entity_name', () => {
    expect(() => normalizeOverrides({ manual_additions: [{ justification: 'why' }] }))
      .toThrow(/entity_name/);
  });

  it('rejects a non-mapping transliteration_overrides', () => {
    expect(() => normalizeOverrides({ transliteration_overrides: ['nope'] }))
      .toThrow(/transliteration_overrides/);
  });

  it('builds a catalog_uid -> suppression map', () => {
    const o = loadProhibitedVendorsOverrides(fx('w2-overrides-suppression.yaml'));
    const map = suppressionsByCatalogUid(o);
    expect(map.get('far-52-204-25::zte-corporation')?.justification).toMatch(/CISO/);
    expect(map.size).toBe(2);
  });
});
