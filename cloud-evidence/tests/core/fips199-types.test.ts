/**
 * Sanity tests for core/fips199-types.ts — LOOP-C.C5 SP 800-60 V2 Rev. 1 catalogue.
 *
 * The catalogue carries NIST-published codes + names (REO Rule 3 allowed
 * exception). These tests assert the codes are well-formed + distinct, the
 * Information and Technology Management (C.3.5.x) family is present in full, and
 * the lookup + selection-guidance exports behave.
 */
import { describe, it, expect } from 'vitest';
import {
  INFORMATION_TYPE_CATALOG, findInformationType,
  SOURCE_VERSION, SOURCE_URL, SELECTION_GUIDANCE,
} from '../../core/fips199-types.ts';

describe('fips199-types catalogue', () => {
  it('codes are well-formed (dotted numeric under appendix C) and non-empty names', () => {
    for (const e of INFORMATION_TYPE_CATALOG) {
      expect(e.code).toMatch(/^C(\.\d+)+$/);
      expect(e.name.trim().length).toBeGreaterThan(0);
      expect(e.appendix).toBe('C');
    }
    expect(INFORMATION_TYPE_CATALOG.length).toBeGreaterThanOrEqual(15);
  });

  it('codes are distinct', () => {
    const codes = INFORMATION_TYPE_CATALOG.map((e) => e.code);
    expect(new Set(codes).size).toBe(codes.length);
  });

  it('includes the full Information and Technology Management (C.3.5.x) family', () => {
    for (let n = 1; n <= 9; n++) {
      const e = findInformationType(`C.3.5.${n}`);
      expect(e, `C.3.5.${n} present`).toBeTruthy();
      expect(e!.category).toBe('Information and Technology Management');
    }
  });

  it('findInformationType returns undefined for a code outside the subset, trims input', () => {
    expect(findInformationType('D.99.9')).toBeUndefined();
    expect(findInformationType('  C.3.5.1  ')?.name).toBe('System Development');
  });

  it('exports a pinned SOURCE_VERSION + URL + selection guidance', () => {
    expect(SOURCE_VERSION).toBe('SP 800-60 Vol. 2 Rev. 1');
    expect(SOURCE_URL).toContain('csrc.nist.gov');
    expect(SELECTION_GUIDANCE).toContain('SP 800-60 Vol. 2 Rev. 1');
  });
});
