/**
 * Typed loader + validator for `prohibited-vendors-config.yaml` (LOOP-W.W1).
 *
 * The operator commits this file (or relies on env-var defaults) to drive the
 * prohibited-vendor catalog ingester. Per cloud-evidence/CLAUDE.md REO Rule 4,
 * operator-supplied configuration is real data: when a required value is
 * missing we throw a typed `ConfigError` naming the field and where the
 * operator supplies it — never substitute a default that masquerades as real
 * input.
 *
 * `${ENV_VAR}` and `${ENV_VAR:-fallback}` references in string values are
 * resolved against `process.env` at load time, matching the repo's other
 * YAML configs.
 */
import { readFileSync, existsSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';

/** Thrown when a required config value is missing or malformed. */
export class ConfigError extends Error {
  readonly field: string;
  constructor(field: string, message: string) {
    super(message);
    this.name = 'ConfigError';
    this.field = field;
  }
}

export type OfacFeedChoice = 'csv' | 'xml' | 'xml_advanced';
export type BisSourceChoice = 'consolidated_csv' | 'ecfr_html';

export interface ProhibitedVendorsConfig {
  samGov: {
    apiKey: string | null;     // resolved; null when absent (only required for the SAM fetch path)
    rateLimitQps: number;
  };
  ofac: {
    feedChoice: OfacFeedChoice;
    fetchTimeoutSeconds: number;
  };
  bis: {
    source: BisSourceChoice;
  };
  fascsa: {
    ordersIndexUrl: string;
    manualPdfPaths: string[];
  };
  snapshotDir: string;
  proxy: {
    httpsProxy: string | null;
  };
  signing: {
    keyId: string | null;      // operator's expected Ed25519 key id; validated against the actual key at emit time
  };
}

/** Resolve `${VAR}` / `${VAR:-fallback}` references against process.env. */
function resolveEnv(value: string): string {
  return value.replace(/\$\{([A-Z0-9_]+)(?::-([^}]*))?\}/gi, (_m, name: string, fallback?: string) => {
    const v = process.env[name];
    if (v !== undefined && v !== '') return v;
    return fallback ?? '';
  });
}

function asString(v: unknown): string | null {
  if (typeof v !== 'string') return null;
  const resolved = resolveEnv(v).trim();
  return resolved === '' ? null : resolved;
}

function asNumber(v: unknown, fallback: number): number {
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  if (typeof v === 'string') {
    const n = Number(resolveEnv(v).trim());
    if (Number.isFinite(n)) return n;
  }
  return fallback;
}

const DEFAULTS = {
  rateLimitQps: 5,
  ofacFeedChoice: 'csv' as OfacFeedChoice,
  fetchTimeoutSeconds: 60,
  bisSource: 'consolidated_csv' as BisSourceChoice,
  fascsaOrdersIndexUrl: 'https://www.cisa.gov/fascsa',
  snapshotDir: 'data',
};

/**
 * Build a typed config from a parsed YAML object, applying env resolution and
 * defaults. Throws ConfigError on enum violations. Does NOT require the SAM API
 * key here (it is only required on the SAM fetch path — see requireSamApiKey).
 */
export function normalizeProhibitedVendorsConfig(raw: unknown): ProhibitedVendorsConfig {
  const obj = (raw && typeof raw === 'object' ? raw : {}) as Record<string, any>;
  const samGov = (obj.sam_gov ?? {}) as Record<string, any>;
  const ofac = (obj.ofac ?? {}) as Record<string, any>;
  const bis = (obj.bis ?? {}) as Record<string, any>;
  const fascsa = (obj.fascsa ?? {}) as Record<string, any>;
  const proxy = (obj.proxy ?? {}) as Record<string, any>;
  const signing = (obj.signing ?? {}) as Record<string, any>;

  const feedChoice = (asString(ofac.feed_choice) ?? DEFAULTS.ofacFeedChoice) as OfacFeedChoice;
  if (!['csv', 'xml', 'xml_advanced'].includes(feedChoice)) {
    throw new ConfigError('ofac.feed_choice', `ofac.feed_choice must be one of csv|xml|xml_advanced, got "${feedChoice}"`);
  }
  const bisSource = (asString(bis.source) ?? DEFAULTS.bisSource) as BisSourceChoice;
  if (!['consolidated_csv', 'ecfr_html'].includes(bisSource)) {
    throw new ConfigError('bis.source', `bis.source must be one of consolidated_csv|ecfr_html, got "${bisSource}"`);
  }

  const manualPdfPaths = Array.isArray(fascsa.manual_pdf_paths)
    ? fascsa.manual_pdf_paths.map((p: unknown) => asString(p)).filter((p): p is string => p !== null)
    : [];

  return {
    samGov: {
      apiKey: asString(samGov.api_key),
      rateLimitQps: asNumber(samGov.rate_limit_qps, DEFAULTS.rateLimitQps),
    },
    ofac: {
      feedChoice,
      fetchTimeoutSeconds: asNumber(ofac.fetch_timeout_seconds, DEFAULTS.fetchTimeoutSeconds),
    },
    bis: { source: bisSource },
    fascsa: {
      ordersIndexUrl: asString(fascsa.orders_index_url) ?? DEFAULTS.fascsaOrdersIndexUrl,
      manualPdfPaths,
    },
    snapshotDir: asString(obj.snapshot_dir) ?? DEFAULTS.snapshotDir,
    proxy: { httpsProxy: asString(proxy.https_proxy) },
    signing: { keyId: asString(signing.key_id) },
  };
}

/** Load + normalize the config from a YAML path. A missing file yields defaults. */
export function loadProhibitedVendorsConfig(path?: string): ProhibitedVendorsConfig {
  if (!path || !existsSync(path)) {
    return normalizeProhibitedVendorsConfig({});
  }
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (e) {
    throw new ConfigError('(file)', `Cannot read prohibited-vendors config at ${path}: ${(e as Error)?.message ?? String(e)}`);
  }
  let parsed: unknown;
  try {
    parsed = parseYaml(text);
  } catch (e) {
    throw new ConfigError('(yaml)', `prohibited-vendors config at ${path} is not valid YAML: ${(e as Error)?.message ?? String(e)}`);
  }
  return normalizeProhibitedVendorsConfig(parsed);
}

/**
 * Assert the SAM API key is present and well-formed before the SAM fetch path
 * runs. Called ONLY when the SAM exclusions source is actually being fetched —
 * the offline/snapshot path does not need it (test T19).
 */
export function requireSamApiKey(config: ProhibitedVendorsConfig): string {
  const key = config.samGov.apiKey;
  if (!key) {
    throw new ConfigError(
      'sam_gov.api_key',
      'SAM_GOV_API_KEY required to fetch SAM Exclusions; obtain at https://sam.gov/data-services and set it in prohibited-vendors-config.yaml (sam_gov.api_key) or the SAM_GOV_API_KEY env var.',
    );
  }
  if (!/^[A-Za-z0-9]{20,80}$/.test(key)) {
    throw new ConfigError(
      'sam_gov.api_key',
      `SAM_GOV_API_KEY is malformed (expected 20-80 alphanumeric chars); got ${key.length} char(s).`,
    );
  }
  return key;
}
