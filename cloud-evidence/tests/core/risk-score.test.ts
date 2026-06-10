/**
 * Tests for core/risk-score.ts — LOOP-B.B1 pure composite scorer + EPSS lookup.
 *
 * Covers the per-slice doc §8 test specifications T1-T16:
 *   - CVSS 3.1 (scope unchanged + changed) + 4.0 vector parsing
 *   - FIRST Qualitative Severity Rating Scale (Table 14) boundaries
 *   - CVSS source priority (collector-cited / operator / severity fallback)
 *   - EPSS batch lookup + on-disk cache (24h TTL) + persistent-failure handling
 *   - inventory-derived criticality + exposure
 *   - composite formula + weight re-normalisation
 *
 * REO: computeRiskScore is pure; the EPSS HTTP fetcher is injected at the wire
 * layer (no NODE_ENV branch). On persistent EPSS failure the code never
 * fabricates a zero — the CVE is reported missing.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Finding } from '../../core/envelope.ts';
import {
  parseCvssVector,
  cvssSeverityLabel,
  computeRiskScore,
  lookupEpss,
  collectCveIds,
  DEFAULT_WEIGHTS,
  CvssParseError,
  type RiskContext,
  type EpssScore,
  type RiskScoringOpts,
} from '../../core/risk-score.ts';

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-rs-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

const FIXED = () => new Date('2026-06-09T12:00:00.000Z');

function mkFinding(over: Partial<Finding> = {}): Finding {
  return {
    rule: 'test.rule',
    passed: false,
    severity: 'high',
    current_state: { summary: 's', observations: {} },
    target_state: { summary: 't', rationale: 'r' },
    ...over,
  };
}

function mkCtx(over: Partial<RiskContext> = {}): RiskContext {
  return { inventory: { assets: [] }, epssByCve: new Map(), epssEnabled: false, ...over };
}

const baseOpts: RiskScoringOpts = { weights: { ...DEFAULT_WEIGHTS }, now: FIXED };

/** Build a Response-like object for the injected fetcher. */
function fakeResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as unknown as Response;
}

describe('parseCvssVector (CVSS 3.1)', () => {
  it('T1: parses the spec example CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical', () => {
    const v = parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(v.version).toBe('3.1');
    expect(v.base_score).toBe(9.8);
    expect(v.severity_label).toBe('Critical');
    expect(v.vector).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
  });

  it('T2: applies the Scope Changed 1.08 multiplier (PR:L=0.68) → 6.4', () => {
    const v = parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N');
    expect(v.base_score).toBe(6.4);
    expect(v.severity_label).toBe('Medium');
  });

  it('throws CvssParseError on an unrecognised prefix', () => {
    expect(() => parseCvssVector('FOO:1.0/AV:N')).toThrow(CvssParseError);
  });
});

describe('parseCvssVector (CVSS 4.0)', () => {
  it('T3: parses a 4.0 vector and reports version 4.0 (approximate)', () => {
    const v = parseCvssVector('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
    expect(v.version).toBe('4.0');
    expect(v.approximate).toBe(true);
    expect(v.base_score).toBeGreaterThan(0);
    expect(v.base_score).toBeLessThanOrEqual(10);
  });
});

describe('cvssSeverityLabel (FIRST Table 14)', () => {
  it('T4: classifies the band boundaries', () => {
    expect(cvssSeverityLabel(0.0)).toBe('None');
    expect(cvssSeverityLabel(0.1)).toBe('Low');
    expect(cvssSeverityLabel(3.9)).toBe('Low');
    expect(cvssSeverityLabel(4.0)).toBe('Medium');
    expect(cvssSeverityLabel(6.9)).toBe('Medium');
    expect(cvssSeverityLabel(7.0)).toBe('High');
    expect(cvssSeverityLabel(8.9)).toBe('High');
    expect(cvssSeverityLabel(9.0)).toBe('Critical');
    expect(cvssSeverityLabel(10.0)).toBe('Critical');
  });
});

describe('computeRiskScore — CVSS source priority', () => {
  it('T5: severity-fallback marks cvss_source REQUIRES-OPERATOR-INPUT and sets no real cvss', () => {
    const rs = computeRiskScore(mkFinding({ severity: 'high' }), mkCtx(), baseOpts);
    expect(rs.sources.cvss_source).toBe('REQUIRES-OPERATOR-INPUT');
    expect(rs.cvss).toBeUndefined();
    // No epss/criticality/exposure → only the cvss term, renormalised to 1.0.
    expect(rs.composite_score).toBe(7.5); // high fallback base
  });

  it('T6: honours a collector-cited cvss_vector over the severity fallback', () => {
    const f = mkFinding({
      severity: 'low',
      references: [{ title: 'NVD', url: 'https://x', cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
    });
    const rs = computeRiskScore(f, mkCtx(), baseOpts);
    expect(rs.sources.cvss_source).toBe('finding-cited');
    expect(rs.cvss?.base_score).toBe(9.8);
  });

  it('uses an operator-supplied CVSS vector when no collector vector is cited', () => {
    const f = mkFinding({ references: [{ title: 'ref', url: 'u', cve_id: 'CVE-2021-44228' }] });
    const opts: RiskScoringOpts = {
      ...baseOpts,
      operatorCvssVectors: { 'CVE-2021-44228': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    };
    const rs = computeRiskScore(f, mkCtx(), opts);
    expect(rs.sources.cvss_source).toBe('operator-supplied');
    expect(rs.cvss?.base_score).toBe(9.8);
  });
});

describe('computeRiskScore — criticality + exposure', () => {
  const cuiAsset = { identifier: 'arn:x', data_classification: 'cui', public_facing: true };
  const publicAsset = { identifier: 'arn:pub', data_classification: 'public', public_facing: false, internet_reachable: false };
  const tier0Asset = { identifier: 'arn:t0', asset_tier: 'tier-0' };

  it('T10: derives criticality from data_classification (cui → 1.0, public → 0.1)', () => {
    const fCui = mkFinding({ gap: { description: 'g', affected_resources: [{ type: 't', identifier: 'arn:x' }] } });
    const rsCui = computeRiskScore(fCui, mkCtx({ inventory: { assets: [cuiAsset] } }), baseOpts);
    expect(rsCui.criticality).toBe(1.0);
    expect(rsCui.sources.criticality_source).toBe('data-classification');

    const fPub = mkFinding({ gap: { description: 'g', affected_resources: [{ type: 't', identifier: 'arn:pub' }] } });
    const rsPub = computeRiskScore(fPub, mkCtx({ inventory: { assets: [publicAsset] } }), baseOpts);
    expect(rsPub.criticality).toBe(0.1);
  });

  it('T11: derives criticality from asset_tier when data_classification is absent', () => {
    const f = mkFinding({ gap: { description: 'g', affected_resources: [{ type: 't', identifier: 'arn:t0' }] } });
    const rs = computeRiskScore(f, mkCtx({ inventory: { assets: [tier0Asset] } }), baseOpts);
    expect(rs.criticality).toBe(1.0);
    expect(rs.sources.criticality_source).toBe('asset-tier');
  });

  it('T12: derives exposure from public_facing / internet_reachable', () => {
    const fExposed = mkFinding({ gap: { description: 'g', affected_resources: [{ type: 't', identifier: 'arn:x' }] } });
    expect(computeRiskScore(fExposed, mkCtx({ inventory: { assets: [cuiAsset] } }), baseOpts).exposure).toBe(1.0);

    const fInternal = mkFinding({ gap: { description: 'g', affected_resources: [{ type: 't', identifier: 'arn:pub' }] } });
    expect(computeRiskScore(fInternal, mkCtx({ inventory: { assets: [publicAsset] } }), baseOpts).exposure).toBe(0.2);
  });

  it('T13: marks exposure_source REQUIRES-OPERATOR-INPUT (placeholder 0.5) when no asset matches', () => {
    const f = mkFinding({ gap: { description: 'g', affected_resources: [{ type: 't', identifier: 'arn:nope' }] } });
    const rs = computeRiskScore(f, mkCtx({ inventory: { assets: [cuiAsset] } }), baseOpts);
    expect(rs.exposure).toBe(0.5);
    expect(rs.sources.exposure_source).toBe('REQUIRES-OPERATOR-INPUT');
    expect(rs.criticality).toBe(0.5);
    expect(rs.sources.criticality_source).toBe('REQUIRES-OPERATOR-INPUT');
  });
});

describe('computeRiskScore — composite formula', () => {
  it('T14: worked example (CVSS 9.8, EPSS 0.972, crit 1.0, exp 1.0, default weights) → 9.84', () => {
    const f = mkFinding({
      references: [{ title: 'NVD', url: 'u', cve_id: 'CVE-2099-0001', cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
      gap: { description: 'g', affected_resources: [{ type: 't', identifier: 'arn:x' }] },
    });
    const ctx = mkCtx({
      inventory: { assets: [{ identifier: 'arn:x', data_classification: 'cui', public_facing: true }] },
      epssEnabled: true,
      epssByCve: new Map<string, EpssScore>([
        ['CVE-2099-0001', { cve: 'CVE-2099-0001', score: 0.972, percentile: 0.99, date: '2026-06-09', source: 'api' }],
      ]),
    });
    const rs = computeRiskScore(f, ctx, baseOpts);
    expect(rs.composite_score).toBe(9.84);
    expect(rs.epss?.score).toBe(0.972);
  });

  it('T15: respects operator weights (w_cvss=1.0 → composite equals CVSS base)', () => {
    const f = mkFinding({
      references: [{ title: 'NVD', url: 'u', cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
    });
    const opts: RiskScoringOpts = { weights: { cvss: 1.0, epss: 0, criticality: 0, exposure: 0 }, now: FIXED };
    const rs = computeRiskScore(f, mkCtx(), opts);
    expect(rs.composite_score).toBe(9.8);
  });

  it('T16: re-normalises remaining weights when the EPSS term is missing', () => {
    const f = mkFinding({
      references: [{ title: 'NVD', url: 'u', cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
      gap: { description: 'g', affected_resources: [{ type: 't', identifier: 'arn:x' }] },
    });
    // No CVE / EPSS disabled → epss term dropped; crit + exp present.
    const ctx = mkCtx({ inventory: { assets: [{ identifier: 'arn:x', data_classification: 'cui', public_facing: true }] } });
    const rs = computeRiskScore(f, ctx, baseOpts);
    expect(rs.sources.epss_source).toBe('REQUIRES-OPERATOR-INPUT');
    expect(rs.epss).toBeUndefined();
    // (0.4·9.8 + 0.2·10 + 0.1·10) / 0.7 = 6.92 / 0.7 = 9.886 → 9.89
    expect(rs.composite_score).toBeCloseTo(9.89, 2);
  });
});

describe('collectCveIds', () => {
  it('gathers CVE ids from references + affected-resource attributes (array or csv)', () => {
    const f = mkFinding({
      references: [{ title: 'r', url: 'u', cve_id: 'cve-2020-0001' }],
      gap: {
        description: 'g',
        affected_resources: [
          { type: 't', identifier: 'a', attributes: { cve_ids: ['CVE-2020-0002', 'CVE-2020-0003'] } },
          { type: 't', identifier: 'b', attributes: { cve_ids: 'CVE-2020-0004, CVE-2020-0005' } },
        ],
      },
    });
    expect(collectCveIds(f).sort()).toEqual([
      'CVE-2020-0001', 'CVE-2020-0002', 'CVE-2020-0003', 'CVE-2020-0004', 'CVE-2020-0005',
    ]);
  });
});

describe('lookupEpss (FIRST EPSS API + cache)', () => {
  const payload = {
    status: 'OK',
    data: [{ cve: 'CVE-2021-44228', epss: '0.97214', percentile: '0.99876', date: '2026-06-09' }],
  };

  it('T7: looks up EPSS via the batch API and writes the on-disk cache', async () => {
    const cachePath = join(tmp(), '.epss-cache.json');
    let calls = 0;
    const fetchImpl = (async (_url: string) => { calls++; return fakeResponse(payload); }) as unknown as typeof fetch;
    const r = await lookupEpss(['CVE-2021-44228'], { enabled: true, cachePath }, { fetchImpl, now: FIXED });
    expect(calls).toBe(1);
    expect(r.apiCalls).toBe(1);
    expect(r.scores.get('CVE-2021-44228')?.source).toBe('api');
    expect(r.scores.get('CVE-2021-44228')?.score).toBeCloseTo(0.97214, 5);
    const cache = JSON.parse(readFileSync(cachePath, 'utf8'));
    expect(cache.entries['CVE-2021-44228']).toBeTruthy();
  });

  it('T8: serves from cache within the 24h TTL with zero API hits', async () => {
    const cachePath = join(tmp(), '.epss-cache.json');
    const fetchImpl = (async () => fakeResponse(payload)) as unknown as typeof fetch;
    await lookupEpss(['CVE-2021-44228'], { enabled: true, cachePath }, { fetchImpl, now: FIXED });
    // Second call: fetch throws if called, proving the cache hit.
    const throwingFetch = (async () => { throw new Error('should not fetch'); }) as unknown as typeof fetch;
    const r2 = await lookupEpss(['CVE-2021-44228'], { enabled: true, cachePath }, { fetchImpl: throwingFetch, now: FIXED });
    expect(r2.apiCalls).toBe(0);
    expect(r2.cacheHits).toBe(1);
    expect(r2.scores.get('CVE-2021-44228')?.source).toBe('cache');
  });

  it('T9: marks the CVE missing on persistent API failure — never fabricates epss=0', async () => {
    const cachePath = join(tmp(), '.epss-cache.json');
    const fetchImpl = (async () => fakeResponse({ error: 'boom' }, 503)) as unknown as typeof fetch;
    const r = await lookupEpss(['CVE-2021-44228'], { enabled: true, cachePath, retryAttempts: 1 }, { fetchImpl, now: FIXED });
    expect(r.scores.has('CVE-2021-44228')).toBe(false);
    expect(r.missing).toContain('CVE-2021-44228');
  });

  it('returns nothing (no fetch) when EPSS is disabled', async () => {
    let calls = 0;
    const fetchImpl = (async () => { calls++; return fakeResponse(payload); }) as unknown as typeof fetch;
    const r = await lookupEpss(['CVE-2021-44228'], { enabled: false }, { fetchImpl, now: FIXED });
    expect(calls).toBe(0);
    expect(r.scores.size).toBe(0);
  });
});
