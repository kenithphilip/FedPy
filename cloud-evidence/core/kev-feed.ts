/**
 * CISA Known Exploited Vulnerabilities (KEV) catalog loader.
 *
 * Supports VDR-TFR-KEV ("Remediate KEVs by the CISA due date"), VDR-BST-AKE
 * ("Avoid deploying new resources carrying a KEV"), and the LEV-seeding arm of
 * VDR-EVA-ELX ("KEV membership = strong likely-exploitable signal"). See
 * docs/analysis/vdr.md (VDR-TFR-KEV / VDR-BST-AKE / VDR-EVA-ELX).
 *
 * Two sources, in priority order:
 *   1. A local cached JSON file (env CLOUD_EVIDENCE_KEV_PATH or `opts.path`).
 *      This is the path for offline / air-gapped runs and the deterministic
 *      path for tests — the read-only collector never *needs* the network.
 *   2. An optional unauthenticated HTTPS GET of the CISA feed, wrapped in
 *      withRetry, used only when `opts.fetch === true` and no usable local
 *      file was provided.
 *
 * This module is READ-ONLY and performs no cloud-SDK calls. The single network
 * call it can make is a GET of CISA's public feed; per vdr.md, a fetch failure
 * is recorded as a warning and yields an EMPTY catalog — it never throws on a
 * missing network and never silently "passes" a KEV check by default.
 *
 * The catalog shape mirrors the published feed
 * (https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json):
 *   { title, catalogVersion, dateReleased, count, vulnerabilities: [ { cveID,
 *     vendorProject, product, vulnerabilityName, dateAdded, shortDescription,
 *     requiredAction, dueDate, knownRansomwareCampaignUse, notes } ] }
 */
import { readFileSync } from 'node:fs';
import { withRetry } from './retry.ts';
import { log } from './log.ts';

/** Canonical CISA KEV feed URL (unauthenticated public HTTPS GET). */
export const CISA_KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

/** A single KEV catalog entry (subset of the published feed fields we use). */
export interface KevEntry {
  /** CVE identifier, e.g. "CVE-2021-44228". Normalized to upper-case. */
  cveID: string;
  /** ISO date (YYYY-MM-DD) the CVE was added to the KEV catalog. */
  dateAdded: string;
  /** ISO date (YYYY-MM-DD) by which CISA requires remediation (BOD 22-01). */
  dueDate: string;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  shortDescription?: string;
  requiredAction?: string;
  knownRansomwareCampaignUse?: string;
  notes?: string;
}

/** Where the catalog data came from, for provenance in evidence. */
export type KevSource = 'file' | 'network' | 'none';

export interface KevCatalog {
  /** CVE-ID (upper-case) → entry. */
  byCve: Map<string, KevEntry>;
  /** Number of entries loaded. */
  count: number;
  /** Provenance of the loaded data. */
  source: KevSource;
  /** Catalog version string from the feed, when available. */
  catalogVersion?: string;
  /** Catalog release date from the feed, when available. */
  dateReleased?: string;
  /** Human-readable, actionable warnings (e.g. fetch failed, file missing). */
  warnings: string[];
}

export interface LoadKevOptions {
  /**
   * Local cached JSON file path. Falls back to env CLOUD_EVIDENCE_KEV_PATH.
   * Preferred for offline / air-gapped / deterministic-test runs.
   */
  path?: string;
  /**
   * Allow a network fetch of the CISA feed when no usable local file exists.
   * Default false — the collector is offline-first; opt in explicitly.
   */
  fetch?: boolean;
  /** Override the feed URL (mainly for tests / mirrors). */
  url?: string;
  /** AbortSignal so a long fetch can be cancelled (e.g. on Ctrl-C). */
  signal?: AbortSignal;
}

/** Validate + normalize a raw entry; returns null if it lacks the key fields. */
function normalizeEntry(raw: unknown): KevEntry | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;
  const cveID = typeof r.cveID === 'string' ? r.cveID.trim().toUpperCase() : '';
  if (!cveID) return null;
  const dateAdded = typeof r.dateAdded === 'string' ? r.dateAdded : '';
  const dueDate = typeof r.dueDate === 'string' ? r.dueDate : '';
  return {
    cveID,
    dateAdded,
    dueDate,
    vendorProject: typeof r.vendorProject === 'string' ? r.vendorProject : undefined,
    product: typeof r.product === 'string' ? r.product : undefined,
    vulnerabilityName: typeof r.vulnerabilityName === 'string' ? r.vulnerabilityName : undefined,
    shortDescription: typeof r.shortDescription === 'string' ? r.shortDescription : undefined,
    requiredAction: typeof r.requiredAction === 'string' ? r.requiredAction : undefined,
    knownRansomwareCampaignUse:
      typeof r.knownRansomwareCampaignUse === 'string' ? r.knownRansomwareCampaignUse : undefined,
    notes: typeof r.notes === 'string' ? r.notes : undefined,
  };
}

/** Build a byCve map + count from a parsed feed object. */
function indexFeed(parsed: unknown): {
  byCve: Map<string, KevEntry>;
  catalogVersion?: string;
  dateReleased?: string;
  warnings: string[];
} {
  const byCve = new Map<string, KevEntry>();
  const warnings: string[] = [];
  if (!parsed || typeof parsed !== 'object') {
    warnings.push('KEV feed payload was not a JSON object; treating as empty.');
    return { byCve, warnings };
  }
  const obj = parsed as Record<string, unknown>;
  const vulns = obj.vulnerabilities;
  if (!Array.isArray(vulns)) {
    warnings.push('KEV feed has no "vulnerabilities" array; treating as empty.');
    return { byCve, warnings };
  }
  let skipped = 0;
  for (const v of vulns) {
    const entry = normalizeEntry(v);
    if (!entry) {
      skipped++;
      continue;
    }
    byCve.set(entry.cveID, entry);
  }
  if (skipped > 0) {
    warnings.push(`KEV feed: skipped ${skipped} entr${skipped === 1 ? 'y' : 'ies'} missing a usable cveID.`);
  }
  return {
    byCve,
    catalogVersion: typeof obj.catalogVersion === 'string' ? obj.catalogVersion : undefined,
    dateReleased: typeof obj.dateReleased === 'string' ? obj.dateReleased : undefined,
    warnings,
  };
}

/** Load the KEV catalog from a local cached JSON file path. */
function loadFromFile(path: string): KevCatalog {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (e) {
    return {
      byCve: new Map(),
      count: 0,
      source: 'none',
      warnings: [
        `Could not read KEV cache file "${path}": ${(e as Error)?.message ?? String(e)}. ` +
          `Provide a valid cached catalog via CLOUD_EVIDENCE_KEV_PATH, or enable fetch.`,
      ],
    };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    return {
      byCve: new Map(),
      count: 0,
      source: 'none',
      warnings: [`KEV cache file "${path}" is not valid JSON: ${(e as Error)?.message ?? String(e)}.`],
    };
  }
  const idx = indexFeed(parsed);
  return {
    byCve: idx.byCve,
    count: idx.byCve.size,
    source: 'file',
    catalogVersion: idx.catalogVersion,
    dateReleased: idx.dateReleased,
    warnings: idx.warnings,
  };
}

/** Fetch + index the CISA KEV feed over HTTPS, wrapped in withRetry. */
async function loadFromNetwork(url: string, signal?: AbortSignal): Promise<KevCatalog> {
  try {
    const parsed = await withRetry(
      async () => {
        const resp = await fetch(url, {
          method: 'GET',
          headers: { accept: 'application/json' },
          signal,
        });
        if (!resp.ok) {
          // Surface HTTP status in the AWS-SDK shape so isTransientError can
          // classify 5xx/429 as retryable.
          throw Object.assign(new Error(`KEV feed HTTP ${resp.status}`), {
            $metadata: { httpStatusCode: resp.status },
          });
        }
        return (await resp.json()) as unknown;
      },
      { attempts: 3, baseDelayMs: 500, maxDelayMs: 4000, signal },
    );
    const idx = indexFeed(parsed);
    return {
      byCve: idx.byCve,
      count: idx.byCve.size,
      source: 'network',
      catalogVersion: idx.catalogVersion,
      dateReleased: idx.dateReleased,
      warnings: idx.warnings,
    };
  } catch (e) {
    // Per vdr.md: do NOT throw on missing network. Return empty + a warning so
    // the KEV checks degrade to "missing_evidence", never a silent pass.
    const msg = (e as Error)?.message ?? String(e);
    log.warn({ event: 'kev.fetch.fail', url, err: msg });
    return {
      byCve: new Map(),
      count: 0,
      source: 'none',
      warnings: [
        `KEV feed fetch from ${url} failed: ${msg}. ` +
          `KEV-based checks cannot be evaluated; supply a cached catalog via ` +
          `CLOUD_EVIDENCE_KEV_PATH for offline runs.`,
      ],
    };
  }
}

/**
 * Load the CISA KEV catalog.
 *
 * Resolution order:
 *   1. `opts.path` or env CLOUD_EVIDENCE_KEV_PATH — local cached JSON.
 *   2. If no usable file AND `opts.fetch === true` — HTTPS GET of the feed.
 *   3. Otherwise — empty catalog + an actionable warning.
 *
 * Never throws for a missing file or missing network: callers get an empty
 * catalog and a warning so KEV checks become "missing_evidence", never a
 * default pass.
 */
export async function loadKevCatalog(opts: LoadKevOptions = {}): Promise<KevCatalog> {
  const path = opts.path ?? process.env.CLOUD_EVIDENCE_KEV_PATH;
  const url = opts.url ?? CISA_KEV_URL;

  if (path) {
    const fromFile = loadFromFile(path);
    if (fromFile.source === 'file') {
      return fromFile;
    }
    // File path was given but unusable. Fall through to network if allowed,
    // carrying the file warning forward.
    if (opts.fetch) {
      const fromNet = await loadFromNetwork(url, opts.signal);
      return { ...fromNet, warnings: [...fromFile.warnings, ...fromNet.warnings] };
    }
    return fromFile;
  }

  if (opts.fetch) {
    return loadFromNetwork(url, opts.signal);
  }

  return {
    byCve: new Map(),
    count: 0,
    source: 'none',
    warnings: [
      'No KEV catalog source available: set CLOUD_EVIDENCE_KEV_PATH (or pass ' +
        'opts.path) to a cached CISA KEV JSON file, or pass { fetch: true } to ' +
        'fetch the public feed. KEV-based checks will be reported as missing evidence.',
    ],
  };
}
