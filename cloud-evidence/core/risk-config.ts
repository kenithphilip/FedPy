/**
 * Typed loader + validator for risk-config.yaml (LOOP-B.B1).
 *
 * The composite risk score (core/risk-score.ts) is operator-tunable. This
 * module loads the operator's weights + EPSS settings + optional CVE→CVSS
 * vector overrides + optional composite band thresholds, validates them, and
 * returns a typed RiskConfig. Invalid config throws a typed RiskConfigError
 * naming the offending field — never a silent default that masks a typo.
 *
 * Defaults (docs/slices/B/B.B1.md §6.3): w_cvss=0.4, w_epss=0.3,
 * w_criticality=0.2, w_exposure=0.1 (sum = 1.0); EPSS enabled, 24h cache TTL.
 */
import { existsSync, readFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';
import { DEFAULT_WEIGHTS, type RiskWeights } from './risk-score.ts';

export class RiskConfigError extends Error {
  /** Dotted path of the offending field, e.g. "weights.cvss". */
  readonly field: string;
  constructor(field: string, message: string) {
    super(`risk-config: ${field}: ${message}`);
    this.name = 'RiskConfigError';
    this.field = field;
  }
}

export interface RiskBands {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface RiskConfig {
  weights: RiskWeights;
  epssEnabled: boolean;
  epssTtlHours: number;
  /** CVE (upper-cased) → CVSS vector string, operator-supplied. */
  operatorCvssVectors: Record<string, string>;
  /** Composite-score → qualitative band thresholds (descending). */
  bands: RiskBands;
}

export const DEFAULT_BANDS: RiskBands = { critical: 9.0, high: 7.0, medium: 4.0, low: 0.1 };

const WEIGHT_KEYS: Array<keyof RiskWeights> = ['cvss', 'epss', 'criticality', 'exposure'];
const WEIGHT_SUM_TOLERANCE = 0.01;

export function defaultRiskConfig(): RiskConfig {
  return {
    weights: { ...DEFAULT_WEIGHTS },
    epssEnabled: true,
    epssTtlHours: 24,
    operatorCvssVectors: {},
    bands: { ...DEFAULT_BANDS },
  };
}

function asNumber(v: unknown, field: string): number {
  const n = typeof v === 'string' ? Number(v) : v;
  if (typeof n !== 'number' || Number.isNaN(n)) throw new RiskConfigError(field, `expected a number, got ${JSON.stringify(v)}`);
  return n;
}

/**
 * Validate + normalise a parsed config object into a RiskConfig. Pure (no IO)
 * so it is directly unit-testable. Missing top-level sections fall back to
 * documented defaults; present-but-invalid values throw.
 */
export function normalizeRiskConfig(raw: unknown): RiskConfig {
  const cfg = defaultRiskConfig();
  if (raw === undefined || raw === null) return cfg;
  if (typeof raw !== 'object') throw new RiskConfigError('(root)', 'expected a YAML mapping');
  const o = raw as Record<string, unknown>;

  // Weights.
  if (o.weights !== undefined) {
    if (typeof o.weights !== 'object' || o.weights === null) throw new RiskConfigError('weights', 'expected a mapping');
    const w = o.weights as Record<string, unknown>;
    for (const k of WEIGHT_KEYS) {
      if (w[k] === undefined) throw new RiskConfigError(`weights.${k}`, 'missing (all four weights are required when `weights` is present)');
      const n = asNumber(w[k], `weights.${k}`);
      if (n < 0) throw new RiskConfigError(`weights.${k}`, 'must be >= 0');
      cfg.weights[k] = n;
    }
    const sum = WEIGHT_KEYS.reduce((s, k) => s + cfg.weights[k], 0);
    if (Math.abs(sum - 1.0) > WEIGHT_SUM_TOLERANCE) {
      throw new RiskConfigError('weights', `must sum to 1.0 (±${WEIGHT_SUM_TOLERANCE}); got ${sum.toFixed(4)}`);
    }
  }

  // EPSS.
  if (o.epss !== undefined) {
    if (typeof o.epss !== 'object' || o.epss === null) throw new RiskConfigError('epss', 'expected a mapping');
    const e = o.epss as Record<string, unknown>;
    if (e.enabled !== undefined) {
      if (typeof e.enabled !== 'boolean') throw new RiskConfigError('epss.enabled', 'expected a boolean');
      cfg.epssEnabled = e.enabled;
    }
    if (e.ttl_hours !== undefined) {
      const t = asNumber(e.ttl_hours, 'epss.ttl_hours');
      if (t <= 0) throw new RiskConfigError('epss.ttl_hours', 'must be > 0');
      cfg.epssTtlHours = t;
    }
  }

  // Operator CVSS vector overrides.
  if (o.cvss_vectors !== undefined) {
    if (typeof o.cvss_vectors !== 'object' || o.cvss_vectors === null) throw new RiskConfigError('cvss_vectors', 'expected a mapping of CVE → vector');
    for (const [cve, vec] of Object.entries(o.cvss_vectors as Record<string, unknown>)) {
      if (typeof vec !== 'string' || !vec.trim()) throw new RiskConfigError(`cvss_vectors.${cve}`, 'expected a non-empty vector string');
      cfg.operatorCvssVectors[cve.toUpperCase()] = vec.trim();
    }
  }

  // Bands (monotonic descending).
  if (o.bands !== undefined) {
    if (typeof o.bands !== 'object' || o.bands === null) throw new RiskConfigError('bands', 'expected a mapping');
    const b = o.bands as Record<string, unknown>;
    for (const k of ['critical', 'high', 'medium', 'low'] as const) {
      if (b[k] !== undefined) cfg.bands[k] = asNumber(b[k], `bands.${k}`);
    }
    if (!(cfg.bands.critical > cfg.bands.high && cfg.bands.high > cfg.bands.medium && cfg.bands.medium > cfg.bands.low)) {
      throw new RiskConfigError(
        'bands',
        `thresholds must be strictly descending (critical > high > medium > low); got ${cfg.bands.critical}/${cfg.bands.high}/${cfg.bands.medium}/${cfg.bands.low}`,
      );
    }
  }

  return cfg;
}

/**
 * Load risk-config.yaml from disk. When `path` is undefined or the file does
 * not exist, returns the documented defaults (operator opted out of tuning).
 */
export function loadRiskConfig(path?: string): RiskConfig {
  if (!path || !existsSync(path)) return defaultRiskConfig();
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (e: any) {
    throw new RiskConfigError('(file)', `cannot read ${path}: ${e?.message ?? String(e)}`);
  }
  let parsed: unknown;
  try {
    parsed = parseYaml(text);
  } catch (e: any) {
    throw new RiskConfigError('(yaml)', `parse error in ${path}: ${e?.message ?? String(e)}`);
  }
  return normalizeRiskConfig(parsed);
}

/** Map a composite score to its qualitative band label using the config thresholds. */
export function bandForScore(score: number, bands: RiskBands = DEFAULT_BANDS): 'critical' | 'high' | 'medium' | 'low' | 'none' {
  if (score >= bands.critical) return 'critical';
  if (score >= bands.high) return 'high';
  if (score >= bands.medium) return 'medium';
  if (score >= bands.low) return 'low';
  return 'none';
}
