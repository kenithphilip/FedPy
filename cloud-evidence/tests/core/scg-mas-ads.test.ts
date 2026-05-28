/**
 * Tests for the three automated-signal modules that complement the process
 * tracker:
 *   - core/mas-reconcile.ts  — documented-vs-discovered scope diff math.
 *   - core/scg-comparator.ts — declared-vs-observed config mismatch detection.
 *   - core/ads-probe.ts      — read-only endpoint probe (injected fake fetch;
 *                              reachable + unreachable; never hits the network).
 *
 * All three are exercised offline: the only I/O (the ADS probe's HTTP call) is
 * dependency-injected via opts.fetchImpl.
 */
import { describe, it, expect } from 'vitest';
import { reconcileMas, buildMasFindings } from '../../core/mas-reconcile.ts';
import {
  compareScg,
  parseScgBaseline,
  buildScgFindings,
  type ScgBaseline,
} from '../../core/scg-comparator.ts';
import {
  probeAdsEndpoints,
  buildAdsFindings,
  ADS_CSO_PUB_FIELDS,
  type ProbeFetch,
  type ProbeResponse,
} from '../../core/ads-probe.ts';

// ───────────────────────────── MAS reconcile ─────────────────────────────

describe('reconcileMas — diff math', () => {
  it('partitions into in_both / undocumented / missing and counts drift', () => {
    const r = reconcileMas({
      documented: ['a', 'b', 'c'],
      discovered: ['b', 'c', 'd', 'e'],
    });
    expect(r.in_both).toEqual(['b', 'c']);
    expect(r.undocumented).toEqual(['d', 'e']); // discovered ∉ documented
    expect(r.missing).toEqual(['a']); // documented ∉ discovered
    expect(r.drift_count).toBe(3); // 2 undocumented + 1 missing
    expect(r.counts).toEqual({ documented: 3, discovered: 4, in_both: 2, undocumented: 2, missing: 1 });
  });

  it('reports zero drift when the sets match exactly (order-independent, de-duplicated)', () => {
    const r = reconcileMas({ documented: ['x', 'y', 'y'], discovered: ['y', 'x'] });
    expect(r.drift_count).toBe(0);
    expect(r.undocumented).toEqual([]);
    expect(r.missing).toEqual([]);
    expect(r.in_both).toEqual(['x', 'y']);
  });

  it('drops blank/whitespace identifiers and applies the normalizer', () => {
    const r = reconcileMas({
      documented: ['  A ', '', '   '],
      discovered: ['a', 'B'],
      normalize: (s) => s.trim().toLowerCase(),
    });
    expect(r.in_both).toEqual(['a']);
    expect(r.undocumented).toEqual(['b']);
    expect(r.missing).toEqual([]);
  });

  it('all-discovered-undocumented when nothing is documented', () => {
    const r = reconcileMas({ documented: [], discovered: ['s3-bucket-1', 'rds-1'] });
    expect(r.undocumented).toEqual(['rds-1', 's3-bucket-1']);
    expect(r.missing).toEqual([]);
    expect(r.drift_count).toBe(2);
  });
});

describe('buildMasFindings', () => {
  it('passes both findings when reconciled, fails on drift, and notes the human judgment', () => {
    const clean = buildMasFindings(reconcileMas({ documented: ['a'], discovered: ['a'] }), 'moderate');
    expect(clean.every((f) => f.passed)).toBe(true);

    const drift = buildMasFindings(
      reconcileMas({ documented: ['a', 'b'], discovered: ['a', 'c'] }),
      'moderate',
    );
    const boundary = drift.find((f) => f.rule === 'mas.cso.iir.boundary_reconciled')!;
    expect(boundary.passed).toBe(false);
    expect(boundary.severity).toBe('high'); // MUST
    expect(boundary.gap?.affected_resources.map((a) => a.identifier).sort()).toEqual(['b', 'c']);
    // The human-owns-the-judgment caveat must be explicit.
    expect(boundary.note).toMatch(/likely to handle federal customer data/i);

    const undoc = drift.find((f) => f.rule === 'mas.cso.iir.no_undocumented_resources')!;
    expect(undoc.passed).toBe(false);
    expect(undoc.gap?.affected_resources.map((a) => a.identifier)).toEqual(['c']);
  });

  it('treats no-inputs as a failing (non-vacuous) finding rather than a false pass', () => {
    const none = buildMasFindings(reconcileMas({ documented: [], discovered: [] }), 'low');
    expect(none.every((f) => f.passed)).toBe(false);
  });
});

// ───────────────────────────── SCG comparator ────────────────────────────

describe('compareScg — mismatch detection', () => {
  const guide: ScgBaseline = {
    version: '1.0.0',
    settings: {
      'root.mfa_enabled': true,
      'root.access_keys': 0,
      'password.min_length': 14,
      'tls.policy': 'ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04',
    },
  };

  it('flags a deviating setting and reports per-setting matches', () => {
    const r = compareScg({
      guide,
      observed: {
        'root.mfa_enabled': true,
        'root.access_keys': 2, // mismatch
        'password.min_length': 14,
        'tls.policy': 'ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04',
      },
    });
    expect(r.version).toBe('1.0.0');
    expect(r.counts.mismatches).toBe(1);
    expect(r.counts.matches).toBe(3);
    expect(r.counts.not_observed).toBe(0);
    const bad = r.comparisons.find((c) => c.key === 'root.access_keys')!;
    expect(bad.matches).toBe(false);
    expect(bad.actual).toBe(2);
  });

  it('coerces boolean-strings and numeric-strings so "14" matches 14 and "true" matches true', () => {
    const r = compareScg({
      guide,
      observed: {
        'root.mfa_enabled': 'true',
        'root.access_keys': '0',
        'password.min_length': '14',
        'tls.policy': 'ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04',
      },
    });
    expect(r.counts.mismatches).toBe(0);
    expect(r.counts.matches).toBe(4);
  });

  it('marks an absent observed key as not_observed (distinct from a value mismatch)', () => {
    const r = compareScg({
      guide,
      observed: { 'root.mfa_enabled': true, 'root.access_keys': 0, 'password.min_length': 14 },
    });
    const tls = r.comparisons.find((c) => c.key === 'tls.policy')!;
    expect(tls.not_observed).toBe(true);
    expect(tls.matches).toBe(false);
    expect(r.counts.not_observed).toBe(1);
    expect(r.counts.mismatches).toBe(0);
  });

  it('parseScgBaseline accepts both the bare map and the { version, settings } wrapper', () => {
    const bare = parseScgBaseline({ 'a': 1, 'b': 2 });
    expect(bare.settings).toEqual({ a: 1, b: 2 });
    expect(bare.version).toBeUndefined();

    const wrapped = parseScgBaseline({ version: '2.1', settings: { a: 1 } });
    expect(wrapped.version).toBe('2.1');
    expect(wrapped.settings).toEqual({ a: 1 });
  });
});

describe('buildScgFindings', () => {
  it('passes when fully conformant; fails (medium, SHOULD) on a mismatch', () => {
    const conformant = buildScgFindings(
      compareScg({ guide: { settings: { x: 1 } }, observed: { x: 1 } }),
      'moderate',
    );
    expect(conformant[0]!.passed).toBe(true);
    expect(conformant[0]!.applicable_key_word).toBe('SHOULD');

    const mismatch = buildScgFindings(
      compareScg({ guide: { settings: { x: 1 } }, observed: { x: 2 } }),
      'moderate',
    );
    expect(mismatch[0]!.passed).toBe(false);
    expect(mismatch[0]!.severity).toBe('medium'); // SHOULD → medium
    expect(mismatch[0]!.gap?.affected_resources[0]!.identifier).toBe('x');
  });

  it('treats an empty guide as missing-evidence (failing), not a vacuous pass', () => {
    const empty = buildScgFindings(compareScg({ guide: { settings: {} }, observed: {} }), 'low');
    expect(empty[0]!.passed).toBe(false);
    expect(empty[0]!.current_state.summary).toMatch(/no machine-readable secure configuration guide/i);
  });
});

// ───────────────────────────── ADS probe ─────────────────────────────────

/** A header bag → ProbeResponse.headerGet adapter. */
function resp(status: number, headers: Record<string, string>, body: string): ProbeResponse {
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
  return {
    ok: status >= 200 && status < 300,
    status,
    headerGet: (n: string) => lower[n.toLowerCase()] ?? null,
    text: async () => body,
  };
}

/** A body that satisfies all 13 ADS-CSO-PUB checklist fields. */
const FULL_CSO_BODY = `
  <html><body>
  FedRAMP Marketplace: https://marketplace.fedramp.gov/cso/123
  Service Model: SaaS. Deployment Model: Government Cloud. Business Category: GRC.
  UEI: ABCDEF123456. Contact: compliance@example.com.
  Service description / overview of the offering.
  Detailed service list of services.
  Customer responsibility and secure configuration summary. Shared responsibility.
  Trust Center: request access here. Availability status and support.
  Next OAR (ongoing authorization) date: 2026-09-30.
  Machine-readable OSCAL variant: /cso.json (application/json).
  </body></html>`;

describe('probeAdsEndpoints — injected fake fetch (offline)', () => {
  it('marks a reachable CSO page and runs the full 13-field checklist', async () => {
    const fetchImpl: ProbeFetch = async () => resp(200, { 'content-type': 'text/html' }, FULL_CSO_BODY);
    const result = await probeAdsEndpoints({
      urls: [{ url: 'https://example.com/cso', kind: 'cso_page', label: 'Public CSO page' }],
      fetchImpl,
    });
    expect(result.had_urls).toBe(true);
    expect(result.counts.reachable).toBe(1);
    const ep = result.endpoints[0]!;
    expect(ep.reachable).toBe(true);
    expect(ep.status).toBe(200);
    expect(ep.content_type).toBe('text/html');
    expect(ep.field_checklist?.satisfied).toBe(true);
    expect(ep.field_checklist?.missing).toEqual([]);
    expect(ep.field_checklist?.total).toBe(ADS_CSO_PUB_FIELDS.length);
  });

  it('detects missing required fields on a sparse CSO page', async () => {
    const fetchImpl: ProbeFetch = async () => resp(200, { 'content-type': 'text/html' }, '<html>nothing useful here</html>');
    const result = await probeAdsEndpoints({
      urls: [{ url: 'https://example.com/cso', kind: 'cso_page' }],
      fetchImpl,
    });
    const ep = result.endpoints[0]!;
    expect(ep.reachable).toBe(true);
    expect(ep.field_checklist?.satisfied).toBe(false);
    expect(ep.field_checklist!.missing.length).toBeGreaterThan(0);
    expect(ep.field_checklist!.missing).toContain('marketplace_link');
  });

  it('NEVER throws on a network failure — returns reachable:false + a clear reason', async () => {
    const fetchImpl: ProbeFetch = async () => {
      throw Object.assign(new Error('getaddrinfo ENOTFOUND example.invalid'), { code: 'ENOTFOUND' });
    };
    const result = await probeAdsEndpoints({
      urls: ['https://example.invalid/cso'],
      fetchImpl,
      attempts: 1,
    });
    expect(result.had_urls).toBe(true);
    const ep = result.endpoints[0]!;
    expect(ep.reachable).toBe(false);
    expect(ep.status).toBe(0);
    expect(ep.reason).toMatch(/ENOTFOUND|probe failed/i);
  });

  it('treats a 401/403 on an API endpoint as "present but access-gated" (reachable)', async () => {
    const fetchImpl: ProbeFetch = async () => resp(403, { 'content-type': 'application/json' }, '');
    const result = await probeAdsEndpoints({
      urls: [{ url: 'https://example.com/api', kind: 'api' }],
      fetchImpl,
    });
    const ep = result.endpoints[0]!;
    expect(ep.reachable).toBe(true);
    expect(ep.auth_gated).toBe(true);
  });

  it('rejects non-HTTP(S) URLs with a clear reason and does not call fetch', async () => {
    let called = false;
    const fetchImpl: ProbeFetch = async () => {
      called = true;
      return resp(200, {}, '');
    };
    const result = await probeAdsEndpoints({ urls: ['ftp://example.com/x'], fetchImpl });
    expect(called).toBe(false);
    expect(result.endpoints[0]!.reachable).toBe(false);
    expect(result.endpoints[0]!.reason).toMatch(/HTTPS/i);
  });

  it('returns had_urls:false when no URLs are configured', async () => {
    const fetchImpl: ProbeFetch = async () => resp(200, {}, '');
    const result = await probeAdsEndpoints({ urls: [], fetchImpl });
    expect(result.had_urls).toBe(false);
    expect(result.endpoints).toEqual([]);
  });
});

describe('buildAdsFindings', () => {
  it('emits a reachability finding + a field-checklist finding for a passing CSO page', async () => {
    const fetchImpl: ProbeFetch = async () => resp(200, { 'content-type': 'text/html' }, FULL_CSO_BODY);
    const result = await probeAdsEndpoints({ urls: [{ url: 'https://example.com/cso', kind: 'cso_page' }], fetchImpl });
    const findings = buildAdsFindings(result, 'moderate');
    const reach = findings.find((f) => f.rule.startsWith('ads.endpoint.reachable'))!;
    expect(reach.passed).toBe(true);
    const checklist = findings.find((f) => f.rule === 'ads.cso.pub.required_fields_present')!;
    expect(checklist.passed).toBe(true);
    expect(checklist.applicable_key_word).toBe('MUST');
  });

  it('reports unreachable as a reduced-severity advisory (medium), not a hard MUST fail', async () => {
    const fetchImpl: ProbeFetch = async () => {
      throw Object.assign(new Error('timeout'), { name: 'TimeoutError' });
    };
    const result = await probeAdsEndpoints({ urls: ['https://example.com/cso'], fetchImpl, attempts: 1 });
    const findings = buildAdsFindings(result, 'moderate');
    const reach = findings.find((f) => f.rule.startsWith('ads.endpoint.reachable'))!;
    expect(reach.passed).toBe(false);
    expect(reach.severity).toBe('medium');
  });

  it('emits a missing-evidence finding when no URLs were configured', () => {
    const findings = buildAdsFindings({ endpoints: [], had_urls: false, counts: { total: 0, reachable: 0, unreachable: 0 } }, 'moderate');
    expect(findings).toHaveLength(1);
    expect(findings[0]!.rule).toBe('ads.cso.pub.endpoints_configured');
    expect(findings[0]!.passed).toBe(false);
  });
});
