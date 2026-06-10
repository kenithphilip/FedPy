/**
 * Per-finding composite risk scoring (LOOP-B.B1).
 *
 * Replaces the LOOP-A.A1 severity-only POA&M sort with a defensible numeric
 * risk score that combines four real signals:
 *
 *   1. FIRST CVSS (3.1 + 4.0) base score — parsed from a collector- or
 *      operator-supplied vector string per the FIRST specifications.
 *   2. FIRST EPSS exploitation-probability — looked up live from the FIRST
 *      EPSS API (https://api.first.org/data/v1/epss) with an on-disk cache.
 *   3. Inventory-derived organisational criticality — from the affected
 *      asset's data_classification + asset_tier.
 *   4. Inventory-derived exposure — from the affected asset's public_facing +
 *      internet_reachable flags.
 *
 * REO standard (cloud-evidence/CLAUDE.md):
 *   - This module is PURE: computeRiskScore() does no IO and never reaches the
 *     network. The async EPSS lookup (lookupEpss) takes an injectable fetcher
 *     so tests mock at the wire layer; production code never branches on
 *     NODE_ENV.
 *   - No signal is ever silently faked. When CVSS / EPSS / criticality /
 *     exposure cannot be derived from real evidence, the corresponding
 *     `sources.*` field carries the literal string 'REQUIRES-OPERATOR-INPUT'
 *     and (except for CVSS, which always anchors the score via a clearly-
 *     flagged severity fallback) the term is dropped from the composite and
 *     the remaining weights are re-normalised to sum to 1.0.
 *
 * Authoritative sources (verbatim quotes in docs/slices/B/B.B1.md §
 * "Authoritative sources"):
 *   - FIRST CVSS v3.1 Specification Document (June 2019) — Equations 1-7 +
 *     metric constants (§7.4) + Qualitative Severity Rating Scale (Table 14).
 *   - FIRST CVSS v4.0 Specification Document (Nov 2023).
 *   - FIRST EPSS API (https://api.first.org/data/v1/epss).
 *   - NIST SP 800-30 Rev 1 §3.2 (Risk = f(likelihood, impact)).
 *   - NIST SP 800-53 Rev 5 RA-3 / RA-5.
 */
import type { Finding, Severity } from './envelope.ts';
import { withRetry } from './retry.ts';

// ─── Public types ────────────────────────────────────────────────────────────

export type CvssVersion = '3.1' | '4.0';
export type CvssSeverityLabel = 'None' | 'Low' | 'Medium' | 'High' | 'Critical';

export interface CvssVector {
  version: CvssVersion;
  /** The verbatim vector string, e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H". */
  vector: string;
  /** Base score on the 0.0-10.0 scale. */
  base_score: number;
  severity_label: CvssSeverityLabel;
  /** The parsed metric key/value pairs (AV:N → { AV: 'N' }). */
  parsed_metrics: Record<string, string>;
  /**
   * True when the score is the CVSS 4.0 first-cut qualitative approximation
   * (the full MacroVector equivalence-class table is a future enhancement).
   * The `version` string stays an honest '4.0'.
   */
  approximate?: boolean;
}

export type EpssSource = 'api' | 'cache' | 'config' | 'operator-supplied';

export interface EpssScore {
  cve: string;
  /** Probability in [0, 1] that the vulnerability is exploited in the wild. */
  score: number;
  /** Percentile in [0, 1] relative to all scored CVEs. */
  percentile: number;
  /** ISO date (YYYY-MM-DD) the EPSS model produced the score. */
  date: string;
  source: EpssSource;
}

export type CvssSourceKind =
  | 'finding-cited'
  | 'inventory-derived'
  | 'operator-supplied'
  | 'REQUIRES-OPERATOR-INPUT';
export type EpssSourceKind = 'api' | 'cache' | 'operator-supplied' | 'REQUIRES-OPERATOR-INPUT';
export type CriticalitySourceKind =
  | 'inventory-tag'
  | 'data-classification'
  | 'asset-tier'
  | 'REQUIRES-OPERATOR-INPUT';
export type ExposureSourceKind =
  | 'inventory-public-facing'
  | 'inventory-internet-reachable'
  | 'REQUIRES-OPERATOR-INPUT';

export interface RiskScoreSources {
  cvss_source: CvssSourceKind;
  epss_source: EpssSourceKind;
  criticality_source: CriticalitySourceKind;
  exposure_source: ExposureSourceKind;
}

export interface RiskScore {
  /** Composite 0.00-10.00 score, rounded to 2 decimals. */
  composite_score: number;
  cvss?: CvssVector;
  epss?: EpssScore;
  /** Organisational criticality in [0, 1]. */
  criticality: number;
  /** Exposure in [0, 1]. */
  exposure: number;
  sources: RiskScoreSources;
  /** ISO timestamp the score was computed. */
  computed_at: string;
  formula_version: 'risk-score.v1';
}

/** Inventory asset shape this module reads (all fields optional; read defensively). */
export interface InventoryAsset {
  identifier?: string;
  id?: string;
  arn?: string;
  name?: string;
  data_classification?: string;
  asset_tier?: string;
  public_facing?: boolean;
  internet_reachable?: boolean;
  [k: string]: unknown;
}

/** Per-run context the pure scorer reads (already-resolved EPSS + inventory). */
export interface RiskContext {
  inventory: { assets: InventoryAsset[] };
  /** CVE → resolved EPSS score (populated by the emitter via lookupEpss). */
  epssByCve: Map<string, EpssScore>;
  /** When true, the operator disabled the EPSS feed; the term is dropped. */
  epssEnabled: boolean;
}

export interface RiskWeights {
  cvss: number;
  epss: number;
  criticality: number;
  exposure: number;
}

export interface RiskScoringOpts {
  weights: RiskWeights;
  /** Operator-supplied CVE → CVSS vector map (lowest CVSS source priority). */
  operatorCvssVectors?: Record<string, string>;
  /** Injectable clock for deterministic tests; defaults to new Date(). */
  now?: () => Date;
}

export const DEFAULT_WEIGHTS: RiskWeights = { cvss: 0.4, epss: 0.3, criticality: 0.2, exposure: 0.1 };
export const FORMULA_VERSION = 'risk-score.v1' as const;
export const EPSS_ENDPOINT = 'https://api.first.org/data/v1/epss';

// ─── CVSS 3.1 (FIRST CVSS v3.1 Specification Document) ───────────────────────

const AV_3: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC_3: Record<string, number> = { L: 0.77, H: 0.44 };
const UI_3: Record<string, number> = { N: 0.85, R: 0.62 };
const PR_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };
const CIA_3: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };

/**
 * CVSS Roundup (FIRST CVSS v3.1 spec, Appendix A) — round UP to the nearest
 * 0.1 using the integer-safe definition so floating-point drift never moves a
 * score across a band boundary.
 */
export function cvssRoundup(input: number): number {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

/** Map a 0.0-10.0 base score to the FIRST Qualitative Severity Rating Scale (Table 14). */
export function cvssSeverityLabel(score: number): CvssSeverityLabel {
  if (score <= 0) return 'None';
  if (score < 4.0) return 'Low';
  if (score < 7.0) return 'Medium';
  if (score < 9.0) return 'High';
  return 'Critical';
}

function parseVectorMetrics(vector: string): Record<string, string> {
  const metrics: Record<string, string> = {};
  // Drop the leading "CVSS:3.1" / "CVSS:4.0" token; keep AV:N style pairs.
  for (const part of vector.split('/')) {
    const idx = part.indexOf(':');
    if (idx <= 0) continue;
    const key = part.slice(0, idx);
    const val = part.slice(idx + 1);
    if (key === 'CVSS') continue;
    metrics[key] = val;
  }
  return metrics;
}

function computeCvss31Base(m: Record<string, string>): number {
  const g = (k: string): string => m[k] ?? '';
  const scopeChanged = g('S') === 'C';
  const c = CIA_3[g('C')] ?? 0;
  const i = CIA_3[g('I')] ?? 0;
  const a = CIA_3[g('A')] ?? 0;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  const av = AV_3[g('AV')] ?? 0;
  const ac = AC_3[g('AC')] ?? 0;
  const pr = (scopeChanged ? PR_CHANGED : PR_UNCHANGED)[g('PR')] ?? 0;
  const ui = UI_3[g('UI')] ?? 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  if (impact <= 0) return 0;
  const raw = scopeChanged
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10);
  return cvssRoundup(raw);
}

// ─── CVSS 4.0 (FIRST CVSS v4.0 Specification Document) ───────────────────────
//
// First-cut qualitative approximation. The full CVSS 4.0 MacroVector
// equivalence-class table (270+ entries) is a documented future enhancement
// (docs/slices/B/B.B1.md Risk 1). We derive a base score from the parsed Base
// metrics using a transparent weighted blend of an exploitability factor and
// an impact factor (vulnerable + subsequent system). The `version` stays an
// honest '4.0' and `approximate: true` flags the method.

const AV_4: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC_4: Record<string, number> = { L: 0.77, H: 0.44 };
const AT_4: Record<string, number> = { N: 0.85, P: 0.55 };
const PR_4: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const UI_4: Record<string, number> = { N: 0.85, P: 0.62, A: 0.5 };
const IMPACT_4: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };

function computeCvss40Base(m: Record<string, string>): number {
  const g = (k: string): string => m[k] ?? '';
  const av = AV_4[g('AV')] ?? 0;
  const ac = AC_4[g('AC')] ?? 0;
  const at = AT_4[g('AT')] ?? 0.85;
  const pr = PR_4[g('PR')] ?? 0;
  const ui = UI_4[g('UI')] ?? 0;
  // Normalise exploitability against the maximum product (all best-case).
  const explMax = 0.85 * 0.77 * 0.85 * 0.85 * 0.85;
  const exploitability = (av * ac * at * pr * ui) / explMax; // 0..1

  const vc = IMPACT_4[g('VC')] ?? 0;
  const vi = IMPACT_4[g('VI')] ?? 0;
  const va = IMPACT_4[g('VA')] ?? 0;
  const sc = IMPACT_4[g('SC')] ?? 0;
  const si = IMPACT_4[g('SI')] ?? 0;
  const sa = IMPACT_4[g('SA')] ?? 0;
  const vulnImpact = 1 - (1 - vc) * (1 - vi) * (1 - va); // 0..1
  const subImpact = 1 - (1 - sc) * (1 - si) * (1 - sa); // 0..1
  const impact = Math.min(1, vulnImpact + 0.5 * subImpact * (1 - vulnImpact)); // 0..1

  if (impact <= 0) return 0;
  const raw = Math.min(10, 10 * (0.6 * impact + 0.4 * exploitability));
  return cvssRoundup(raw);
}

/**
 * Parse a CVSS vector string (3.1 or 4.0) and compute its base score.
 * Throws a typed error on an unrecognised version prefix or malformed vector.
 */
export class CvssParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CvssParseError';
  }
}

export function parseCvssVector(vector: string): CvssVector {
  const trimmed = vector.trim();
  const metrics = parseVectorMetrics(trimmed);
  if (trimmed.startsWith('CVSS:3.1') || trimmed.startsWith('CVSS:3.0')) {
    const base = computeCvss31Base(metrics);
    return {
      version: '3.1',
      vector: trimmed,
      base_score: base,
      severity_label: cvssSeverityLabel(base),
      parsed_metrics: metrics,
    };
  }
  if (trimmed.startsWith('CVSS:4.0')) {
    const base = computeCvss40Base(metrics);
    return {
      version: '4.0',
      vector: trimmed,
      base_score: base,
      severity_label: cvssSeverityLabel(base),
      parsed_metrics: metrics,
      approximate: true,
    };
  }
  throw new CvssParseError(`Unrecognised CVSS vector prefix (expected CVSS:3.1 or CVSS:4.0): ${trimmed.slice(0, 16)}`);
}

/** Severity → fallback base score when no real CVSS vector is available. */
const SEVERITY_FALLBACK_BASE: Record<Severity, number> = {
  critical: 9.5,
  high: 7.5,
  medium: 5.5,
  low: 2.5,
  info: 0.5,
};

// ─── Criticality + exposure (inventory-derived) ──────────────────────────────

const DATA_CLASS_SCORE: Record<string, number> = {
  cui: 1.0,
  pii: 0.9,
  confidential: 0.7,
  internal: 0.4,
  public: 0.1,
};
const ASSET_TIER_SCORE: Record<string, number> = {
  'tier-0': 1.0,
  'tier-1': 0.75,
  'tier-2': 0.5,
  'tier-3': 0.25,
};

function assetIdentifiers(a: InventoryAsset): string[] {
  return [a.identifier, a.id, a.arn, a.name].filter((x): x is string => typeof x === 'string' && x.length > 0);
}

/** Collect the CVE ids cited by a finding (references + affected-resource attributes). */
export function collectCveIds(finding: Finding): string[] {
  const out = new Set<string>();
  for (const ref of finding.references ?? []) {
    const cve = (ref as { cve_id?: string }).cve_id;
    if (typeof cve === 'string' && cve) out.add(cve.toUpperCase());
  }
  for (const r of finding.gap?.affected_resources ?? []) {
    const raw = r.attributes?.['cve_ids'];
    if (Array.isArray(raw)) {
      for (const c of raw) if (typeof c === 'string' && c) out.add(c.toUpperCase());
    } else if (typeof raw === 'string' && raw) {
      for (const c of raw.split(/[,\s]+/)) if (c) out.add(c.toUpperCase());
    }
  }
  return [...out];
}

function resolveCvss(
  finding: Finding,
  opts: RiskScoringOpts,
  cveIds: string[],
): { cvss?: CvssVector; base: number; source: CvssSourceKind } {
  // (a) collector-cited vector wins.
  for (const ref of finding.references ?? []) {
    const v = (ref as { cvss_vector?: string }).cvss_vector;
    if (typeof v === 'string' && v.trim()) {
      const cvss = parseCvssVector(v);
      return { cvss, base: cvss.base_score, source: 'finding-cited' };
    }
  }
  // (b) operator-supplied vector for any of the finding's CVEs.
  const map = opts.operatorCvssVectors ?? {};
  for (const cve of cveIds) {
    const v = map[cve] ?? map[cve.toLowerCase()];
    if (typeof v === 'string' && v.trim()) {
      const cvss = parseCvssVector(v);
      return { cvss, base: cvss.base_score, source: 'operator-supplied' };
    }
  }
  // (c) severity fallback — flagged REQUIRES-OPERATOR-INPUT, never a real cvss object.
  return { base: SEVERITY_FALLBACK_BASE[finding.severity] ?? 0.5, source: 'REQUIRES-OPERATOR-INPUT' };
}

function resolveEpss(
  ctx: RiskContext,
  cveIds: string[],
): { epss?: EpssScore; value: number; source: EpssSourceKind } {
  if (!ctx.epssEnabled || cveIds.length === 0) {
    return { value: 0, source: 'REQUIRES-OPERATOR-INPUT' };
  }
  let best: EpssScore | undefined;
  for (const cve of cveIds) {
    const s = ctx.epssByCve.get(cve) ?? ctx.epssByCve.get(cve.toUpperCase());
    if (s && (!best || s.score > best.score)) best = s;
  }
  if (!best) return { value: 0, source: 'REQUIRES-OPERATOR-INPUT' };
  const src: EpssSourceKind = best.source === 'config' ? 'operator-supplied' : best.source;
  return { epss: best, value: best.score, source: src };
}

function resolveCriticality(
  finding: Finding,
  ctx: RiskContext,
): { value: number; source: CriticalitySourceKind } {
  const resources = finding.gap?.affected_resources ?? [];
  let best = -1;
  let source: CriticalitySourceKind = 'REQUIRES-OPERATOR-INPUT';
  for (const r of resources) {
    const asset = ctx.inventory.assets.find((a) => assetIdentifiers(a).includes(r.identifier));
    if (!asset) continue;
    const dc = asset.data_classification ? DATA_CLASS_SCORE[String(asset.data_classification).toLowerCase()] : undefined;
    const tier = asset.asset_tier ? ASSET_TIER_SCORE[String(asset.asset_tier).toLowerCase()] : undefined;
    if (dc === undefined && tier === undefined) continue;
    const score = Math.max(dc ?? 0, tier ?? 0);
    if (score > best) {
      best = score;
      // data_classification is the stronger signal; fall back to tier label.
      source = dc !== undefined ? 'data-classification' : 'asset-tier';
    }
  }
  if (best < 0) return { value: 0.5, source: 'REQUIRES-OPERATOR-INPUT' };
  return { value: best, source };
}

function resolveExposure(
  finding: Finding,
  ctx: RiskContext,
): { value: number; source: ExposureSourceKind } {
  const resources = finding.gap?.affected_resources ?? [];
  let best = -1;
  let source: ExposureSourceKind = 'REQUIRES-OPERATOR-INPUT';
  for (const r of resources) {
    const asset = ctx.inventory.assets.find((a) => assetIdentifiers(a).includes(r.identifier));
    if (!asset) continue;
    if (asset.public_facing === undefined && asset.internet_reachable === undefined) continue;
    const exposed = asset.public_facing === true || asset.internet_reachable === true;
    const score = exposed ? 1.0 : 0.2;
    if (score > best) {
      best = score;
      source = asset.public_facing === true ? 'inventory-public-facing' : 'inventory-internet-reachable';
    }
  }
  if (best < 0) return { value: 0.5, source: 'REQUIRES-OPERATOR-INPUT' };
  return { value: best, source };
}

/** Round a number to 2 decimal places (banker-free, deterministic). */
function round2(n: number): number {
  return Math.round((n + Number.EPSILON) * 100) / 100;
}

/**
 * Compute the composite risk score for a single finding. PURE — no IO, no
 * network. The EPSS scores must already be resolved into ctx.epssByCve.
 *
 * Composite (docs/slices/B/B.B1.md §6.3):
 *   composite = w_cvss·cvss_base + w_epss·(epss·10)
 *             + w_criticality·(criticality·10) + w_exposure·(exposure·10)
 *
 * Re-normalisation: the EPSS / criticality / exposure terms are DROPPED (and
 * the remaining weights scaled to sum to 1.0) when their source is
 * REQUIRES-OPERATOR-INPUT. The CVSS term always anchors the score (real vector
 * or clearly-flagged severity fallback), so it is never dropped.
 */
export function computeRiskScore(finding: Finding, ctx: RiskContext, opts: RiskScoringOpts): RiskScore {
  const now = opts.now ?? (() => new Date());
  const cveIds = collectCveIds(finding);

  const cvss = resolveCvss(finding, opts, cveIds);
  const epss = resolveEpss(ctx, cveIds);
  const criticality = resolveCriticality(finding, ctx);
  const exposure = resolveExposure(finding, ctx);

  // Assemble weighted terms; drop REQUIRES-OPERATOR-INPUT signal terms.
  const terms: Array<{ weight: number; value: number }> = [
    { weight: opts.weights.cvss, value: cvss.base }, // always present
  ];
  if (epss.source !== 'REQUIRES-OPERATOR-INPUT') {
    terms.push({ weight: opts.weights.epss, value: epss.value * 10 });
  }
  if (criticality.source !== 'REQUIRES-OPERATOR-INPUT') {
    terms.push({ weight: opts.weights.criticality, value: criticality.value * 10 });
  }
  if (exposure.source !== 'REQUIRES-OPERATOR-INPUT') {
    terms.push({ weight: opts.weights.exposure, value: exposure.value * 10 });
  }
  const totalWeight = terms.reduce((s, t) => s + t.weight, 0);
  const composite =
    totalWeight > 0 ? terms.reduce((s, t) => s + (t.weight / totalWeight) * t.value, 0) : 0;

  return {
    composite_score: round2(composite),
    cvss: cvss.cvss,
    epss: epss.epss,
    criticality: round2(criticality.value),
    exposure: round2(exposure.value),
    sources: {
      cvss_source: cvss.source,
      epss_source: epss.source,
      criticality_source: criticality.source,
      exposure_source: exposure.source,
    },
    computed_at: now().toISOString(),
    formula_version: FORMULA_VERSION,
  };
}

// ─── EPSS lookup (FIRST EPSS API) with on-disk cache ─────────────────────────

import { readFileSync, writeFileSync, existsSync } from 'node:fs';

const EPSS_BATCH_SIZE = 100;
const EPSS_TTL_HOURS = 24;

interface EpssCacheEntry extends EpssScore {
  cached_at: string; // ISO timestamp the entry was written
}

interface EpssCacheFile {
  provenance?: unknown;
  entries: Record<string, EpssCacheEntry>;
  fetched_at: string;
}

export interface EpssLookupOptions {
  enabled: boolean;
  cachePath?: string;
  ttlHours?: number;
  endpoint?: string;
  /** Total HTTP attempts per batch (incl. the first). Default 5. */
  retryAttempts?: number;
}

export interface EpssLookupDeps {
  /** Injectable fetch (wire-layer seam for tests). Defaults to global fetch. */
  fetchImpl?: typeof fetch;
  now?: () => Date;
}

export interface EpssLookupResult {
  scores: Map<string, EpssScore>;
  apiCalls: number;
  cacheHits: number;
  /** CVEs requested but absent from both cache and the API response. */
  missing: string[];
}

export class EpssApiError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EpssApiError';
  }
}

function readEpssCache(path: string): EpssCacheFile {
  try {
    if (!existsSync(path)) return { entries: {}, fetched_at: '' };
    const doc = JSON.parse(readFileSync(path, 'utf8')) as EpssCacheFile;
    if (!doc || typeof doc !== 'object' || typeof doc.entries !== 'object') {
      return { entries: {}, fetched_at: '' };
    }
    return { entries: doc.entries ?? {}, fetched_at: doc.fetched_at ?? '' };
  } catch {
    return { entries: {}, fetched_at: '' };
  }
}

function isFresh(entry: EpssCacheEntry, nowMs: number, ttlHours: number): boolean {
  const t = Date.parse(entry.cached_at);
  if (Number.isNaN(t)) return false;
  return nowMs - t < ttlHours * 3600 * 1000;
}

/**
 * Look up EPSS scores for a list of CVEs. Honors an on-disk cache (24h TTL by
 * default), batches up to 100 CVEs per FIRST API request, and retries
 * transient HTTP failures via core/retry.ts withRetry().
 *
 * On persistent API failure the function does NOT throw and does NOT fabricate
 * a zero — it returns whatever cache hits it has, and reports the rest in
 * `missing` so callers mark epss_source = 'REQUIRES-OPERATOR-INPUT'.
 */
export async function lookupEpss(
  cveIds: string[],
  opts: EpssLookupOptions,
  deps: EpssLookupDeps = {},
): Promise<EpssLookupResult> {
  const scores = new Map<string, EpssScore>();
  if (!opts.enabled || cveIds.length === 0) {
    return { scores, apiCalls: 0, cacheHits: 0, missing: opts.enabled ? [...cveIds] : [] };
  }
  const fetchImpl = deps.fetchImpl ?? (globalThis.fetch as typeof fetch);
  const now = deps.now ?? (() => new Date());
  const nowMs = now().getTime();
  const ttlHours = opts.ttlHours ?? EPSS_TTL_HOURS;
  const endpoint = opts.endpoint ?? EPSS_ENDPOINT;

  const wanted = [...new Set(cveIds.map((c) => c.toUpperCase()))];

  // Cache pass.
  const cache = opts.cachePath ? readEpssCache(opts.cachePath) : { entries: {}, fetched_at: '' };
  let cacheHits = 0;
  const toFetch: string[] = [];
  for (const cve of wanted) {
    const hit = cache.entries[cve];
    if (hit && isFresh(hit, nowMs, ttlHours)) {
      scores.set(cve, { cve, score: hit.score, percentile: hit.percentile, date: hit.date, source: 'cache' });
      cacheHits++;
    } else {
      toFetch.push(cve);
    }
  }

  // API pass (batched).
  let apiCalls = 0;
  const missing: string[] = [];
  for (let i = 0; i < toFetch.length; i += EPSS_BATCH_SIZE) {
    const batch = toFetch.slice(i, i + EPSS_BATCH_SIZE);
    const url = `${endpoint}?cve=${encodeURIComponent(batch.join(','))}`;
    let returned: Set<string>;
    try {
      const data = await withRetry(
        async () => {
          const res = await fetchImpl(url);
          if (!res.ok) {
            const err: any = new Error(`EPSS API HTTP ${res.status}`);
            err.code = res.status;
            throw err;
          }
          return (await res.json()) as { data?: Array<{ cve: string; epss: string; percentile: string; date: string }> };
        },
        { attempts: opts.retryAttempts ?? 5 },
      );
      apiCalls++;
      returned = new Set<string>();
      for (const row of data.data ?? []) {
        if (!row || typeof row.cve !== 'string') continue;
        const score = Number(row.epss);
        const percentile = Number(row.percentile);
        if (Number.isNaN(score) || Number.isNaN(percentile) || !row.date) continue; // missing required field → not scored
        const cve = row.cve.toUpperCase();
        const entry: EpssScore = { cve, score, percentile, date: row.date, source: 'api' };
        scores.set(cve, entry);
        cache.entries[cve] = { ...entry, cached_at: now().toISOString() };
        returned.add(cve);
      }
    } catch {
      // Persistent failure for this batch: leave the batch unscored (no zero).
      returned = new Set<string>();
    }
    for (const cve of batch) if (!returned.has(cve)) missing.push(cve);
  }

  // Persist the (possibly grown) cache.
  if (opts.cachePath && apiCalls > 0) {
    const file: EpssCacheFile = { entries: cache.entries, fetched_at: now().toISOString() };
    try {
      writeFileSync(opts.cachePath, JSON.stringify(file, null, 2));
    } catch {
      /* cache write is best-effort */
    }
  }

  return { scores, apiCalls, cacheHits, missing };
}
