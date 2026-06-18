/**
 * Tests for core/vendor-name-normalizer.ts (LOOP-W.W2). Covers the eight
 * normalization paths (W.W2 §8 T27): case, NFKC, transliteration, corporate
 * suffix strip, parentheticals, diacritics, whitespace collapse, plus the
 * operator transliteration override + hasNonAscii signal.
 */
import { describe, it, expect } from 'vitest';
import { VendorNameNormalizer, createVendorNameNormalizer } from '../../core/vendor-name-normalizer.ts';

describe('VendorNameNormalizer', () => {
  const n = new VendorNameNormalizer();

  it('lowercases (case-insensitive) — normalizeLight', () => {
    expect(n.normalizeLight('Huawei Technologies Company')).toBe('huawei technologies company');
  });

  it('NFKC-normalizes full-width / compatibility characters', () => {
    // Full-width "ＺＴＥ" (U+FF3A...) -> "zte" under NFKC + lowercase.
    expect(n.normalizeLight('ＺＴＥ')).toBe('zte');
  });

  it('transliterates Cyrillic to Latin (char table)', () => {
    expect(n.normalizeFull('Хуавэй')).toBe('khuavey');
    expect(VendorNameNormalizer.hasNonAscii('Хуавэй')).toBe(true);
  });

  it('strips corporate-form suffix tokens in normalizeFull', () => {
    expect(n.normalizeFull('ZTE Corporation Ltd')).toBe('zte');
    expect(n.normalizeFull('Acme GmbH')).toBe('acme');
    expect(n.normalizeFull('Foo OOO')).toBe('foo');
  });

  it('does NOT strip suffixes in normalizeLight', () => {
    expect(n.normalizeLight('ZTE Corporation Ltd')).toBe('zte corporation ltd');
  });

  it('strips parenthetical and bracketed content', () => {
    expect(n.normalizeFull('Acme (Hong Kong) [HK] Ltd')).toBe('acme');
  });

  it('strips diacritics', () => {
    expect(n.normalizeFull('Société Générale')).toBe('societe generale');
    expect(VendorNameNormalizer.hasNonAscii('Société')).toBe(true);
  });

  it('collapses whitespace and tokenizes punctuation', () => {
    expect(n.normalizeFull('Z.T.E.   corp')).toBe('z t e');
    expect(n.tokens('zte-corp ltd')).toEqual(['zte']);
  });

  it('applies operator transliteration overrides before the built-in table', () => {
    const o = createVendorNameNormalizer({ transliterationOverrides: { 'хуавэй': 'huawei' } });
    expect(o.normalizeFull('Хуавэй')).toBe('huawei');
  });

  it('reports hasNonAscii=false for pure ASCII', () => {
    expect(VendorNameNormalizer.hasNonAscii('Huawei Technologies')).toBe(false);
  });

  it('returns empty tokens for empty/whitespace input', () => {
    expect(n.tokens('   ')).toEqual([]);
    expect(n.normalizeFull('')).toBe('');
  });
});
