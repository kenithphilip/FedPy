/**
 * Prohibited-vendor catalog ingester + canonical-JSON emitter (LOOP-W.W1).
 *
 * Builds the single, canonical, Ed25519-signed prohibited-vendor catalog that
 * every downstream W slice (subprocessor screen W.W2, asset-tag screen W.W3,
 * FAR 52.204-26 representation W.W4) reads. It merges seven authoritative
 * federal sources into one deterministic, deduplicated, normalized JSON file
 * with a provenance block citing source URLs, snapshot SHA-256 digests, and a
 * detached Ed25519 signature. No interpretation, no inference — the catalog is
 * the raw substrate; downstream slices perform the matching logic.
 *
 * Architecture (matches the repo's offline-first convention — cf. core/kev-feed.ts
 * + scripts/extract-*.mjs): the CORE ingester reads source files from a snapshot
 * directory plus the committed statutory-constant files under `data/`. The
 * network arm lives in `scripts/extract-prohibited-vendors.mjs`, which fetches
 * the live OFAC/BIS/SAM feeds one-shot into the snapshot directory. This keeps
 * the core fully deterministic and testable with fixtures (no network in the
 * unit path). A thin, injectable fetch seam (`fetch: true` + `fetcher`) is
 * provided so the fetch-error and config-validation paths are exercised.
 *
 * Sources:
 *   - OFAC SDN (Treasury)              source_id ofac-sdn        — snapshot CSVs
 *   - BIS Entity List (Commerce)       source_id bis-entity-list — snapshot CSV
 *   - SAM.gov Exclusions (GSA)         source_id sam-exclusions  — snapshot JSON
 *   - FAR 52.204-25 named entities     source_id far-52-204-25   — committed const
 *   - NDAA FY2019 §889 named entities  source_id ndaa-889        — committed const
 *   - NDAA FY2018 §1634 Kaspersky      source_id ndaa-1634       — committed const
 *   - FASCSA covered-article orders    source_id fascsa          — operator register
 *
 * REO compliance: every emitted field traces to a real source byte or a statute
 * citation. The catalog file carries a top-level `provenance` block (emitter,
 * emittedAt, sourceCalls, signingKeyId) satisfying the G3 provenance guardrail,
 * plus a detached Ed25519 signature over the canonical (signature-blanked) bytes.
 */
import { readFileSync, writeFileSync, readdirSync, existsSync, mkdirSync } from 'node:fs';
import { resolve, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { canonicalize, signDetached, verifyDetached } from './sign.ts';
import { withRetry } from './retry.ts';
import { log } from './log.ts';
import {
  parseOfacSdn, parseBisEntityList, parseSamExclusions,
  parseFar52204_25, parseNdaa889, parseNdaa1634, parseFascsaOrders,
  type ProhibitedVendorEntity, type ProhibitedVendorsSourceId,
} from './prohibited-vendors-parsers.ts';
import {
  loadProhibitedVendorsConfig, requireSamApiKey,
  type ProhibitedVendorsConfig,
} from './prohibited-vendors-config.ts';

export type {
  ProhibitedVendorEntity, ProhibitedVendorsSourceId,
} from './prohibited-vendors-parsers.ts';

const __dirname = dirname(fileURLToPath(import.meta.url));
/** cloud-evidence/ root (core/ is one level down). */
const PROJECT_ROOT = resolve(__dirname, '..');
const EMITTER = 'core/prohibited-vendors-catalog.ts';
export const CATALOG_SCHEMA_VERSION = 'prohibited-vendors-catalog/v1';
export const CATALOG_FILENAME = 'prohibited-vendors-catalog.json';

// ─── Catalog shapes ──────────────────────────────────────────────────────────

export interface ProhibitedVendorsSourceMeta {
  id: ProhibitedVendorsSourceId;
  source_url: string;
  snapshot_filename: string;
  /** SHA-256 of the raw snapshot/constant file the entities were parsed from. */
  sha256: string;
  /** Byte length of the raw source file. */
  bytes: number;
  fetched_at: string;
  authority_citation: string;
  entity_count: number;
}

export interface CatalogStatistics {
  total_entities: number;
  by_source: Partial<Record<ProhibitedVendorsSourceId, number>>;
  duplicates_collapsed: number;
  requires_operator_input_count: number;
}

/** Top-level provenance — camelCase keys satisfy the G3 provenance guardrail. */
export interface ProhibitedVendorsProvenance {
  emitter: string;
  emittedAt: string;
  sourceCalls: string[];
  signingKeyId: string;
  algorithm: 'ed25519';
  signatureEd25519: string;
  publicKeyPem: string;
  rfc3161TimestampPath: string | null;
}

export interface ProhibitedVendorsCatalog {
  schema_version: typeof CATALOG_SCHEMA_VERSION;
  generated_at: string;
  snapshot_dir: string;
  sources: ProhibitedVendorsSourceMeta[];
  entities: ProhibitedVendorEntity[];
  statistics: CatalogStatistics;
  provenance: ProhibitedVendorsProvenance;
}

// ─── Typed fetch errors (no silent fallback to a stale catalog — REO 1.5) ────

export class OfacFetchError extends Error {
  constructor(message: string) { super(message); this.name = 'OfacFetchError'; }
}
export class BisFetchError extends Error {
  constructor(message: string) { super(message); this.name = 'BisFetchError'; }
}
export class SamFetchError extends Error {
  constructor(message: string) { super(message); this.name = 'SamFetchError'; }
}
export class FascsaFetchError extends Error {
  constructor(message: string) { super(message); this.name = 'FascsaFetchError'; }
}

// ─── Static source descriptors ───────────────────────────────────────────────

const SOURCE_URL: Record<ProhibitedVendorsSourceId, string> = {
  'ofac-sdn': 'https://www.treasury.gov/ofac/downloads/sdn.csv',
  'bis-entity-list': 'https://api.trade.gov/static/consolidated_screening_list/consolidated.csv',
  'sam-exclusions': 'https://api.sam.gov/entity-information/v3/entities?includeSections=exclusions',
  'far-52-204-25': 'https://www.acquisition.gov/far/52.204-25',
  'ndaa-889': 'https://www.govinfo.gov/app/details/PLAW-115publ232',
  'ndaa-1634': 'https://www.govinfo.gov/content/pkg/PLAW-115publ91/html/PLAW-115publ91.htm',
  'fascsa': 'https://www.cisa.gov/fascsa',
};

const SOURCE_AUTHORITY: Record<ProhibitedVendorsSourceId, string> = {
  'ofac-sdn': 'IEEPA (50 U.S.C. §§1701-1707); OFAC SDN List',
  'bis-entity-list': '15 CFR Part 744, Supplement No. 4 (EAR Entity List)',
  'sam-exclusions': 'FAR Subpart 9.4 (Debarment, Suspension, and Ineligibility); 48 CFR §9.404',
  'far-52-204-25': 'FAR 52.204-25(a) (Pub. L. 115-232 §889)',
  'ndaa-889': 'Pub. L. 115-232 §889',
  'ndaa-1634': 'Pub. L. 115-91 §1634 (FAR 52.204-23)',
  'fascsa': '41 U.S.C. §1323 (FASCSA of 2018); FAR Subpart 4.23',
};

function sha256Hex(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

function yyyymmdd(iso: string): string {
  return iso.slice(0, 10).replace(/-/g, '');
}

// ─── Pure builder ────────────────────────────────────────────────────────────

export interface SourceIngestResult {
  meta: ProhibitedVendorsSourceMeta;
  entities: ProhibitedVendorEntity[];
}

/** Sort comparator: (source_id asc, name_canonical asc, source_record_id asc). */
function compareEntities(a: ProhibitedVendorEntity, b: ProhibitedVendorEntity): number {
  return (
    a.source_id.localeCompare(b.source_id) ||
    a.name_canonical.localeCompare(b.name_canonical) ||
    a.source_record_id.localeCompare(b.source_record_id)
  );
}

/**
 * Build the (unsigned) catalog from a set of per-source ingest results. Dedupes
 * within each source by (source_id, source_record_id) — cross-source duplicates
 * are NOT merged (W.W1 §6 step 10) — sorts deterministically, and computes the
 * statistics + provenance scaffold. The provenance signature fields are left
 * blank here; signCatalog() fills them.
 */
export function buildCatalog(opts: {
  ingests: SourceIngestResult[];
  snapshotDir: string;
  generatedAt: string;
  sourceCalls: string[];
}): ProhibitedVendorsCatalog {
  const seen = new Set<string>();
  const entities: ProhibitedVendorEntity[] = [];
  let duplicatesCollapsed = 0;
  for (const ing of opts.ingests) {
    for (const e of ing.entities) {
      const key = `${e.source_id}::${e.source_record_id}`;
      if (seen.has(key)) { duplicatesCollapsed++; continue; }
      seen.add(key);
      entities.push(e);
    }
  }
  entities.sort(compareEntities);

  const bySource: Partial<Record<ProhibitedVendorsSourceId, number>> = {};
  for (const e of entities) bySource[e.source_id] = (bySource[e.source_id] ?? 0) + 1;
  const requiresOperatorInputCount = entities.filter((e) => e.requires_operator_input).length;

  const statistics: CatalogStatistics = {
    total_entities: entities.length,
    by_source: bySource,
    duplicates_collapsed: duplicatesCollapsed,
    requires_operator_input_count: requiresOperatorInputCount,
  };

  const sources = opts.ingests
    .map((i) => i.meta)
    .sort((a, b) => a.id.localeCompare(b.id));

  const provenance: ProhibitedVendorsProvenance = {
    emitter: EMITTER,
    emittedAt: opts.generatedAt,
    sourceCalls: opts.sourceCalls,
    signingKeyId: '',
    algorithm: 'ed25519',
    signatureEd25519: '',
    publicKeyPem: '',
    rfc3161TimestampPath: null,
  };

  return {
    schema_version: CATALOG_SCHEMA_VERSION,
    generated_at: opts.generatedAt,
    snapshot_dir: opts.snapshotDir,
    sources,
    entities,
    statistics,
    provenance,
  };
}

// ─── Signing ─────────────────────────────────────────────────────────────────

/** The catalog form that gets signed: provenance signature fields blanked. */
function toUnsignedForm(catalog: ProhibitedVendorsCatalog): ProhibitedVendorsCatalog {
  return {
    ...catalog,
    provenance: { ...catalog.provenance, signingKeyId: '', publicKeyPem: '', signatureEd25519: '' },
  };
}

/**
 * Canonical-JSON (RFC 8785-style) of the signature-blanked catalog — deterministic.
 * The JSON round-trip strips `undefined` optional fields so the bytes signed here
 * are byte-identical to those derived after the catalog is persisted + re-read
 * (JSON.stringify omits undefined; canonicalize would otherwise emit them).
 */
export function serializeUnsignedCanonical(catalog: ProhibitedVendorsCatalog): string {
  return canonicalize(JSON.parse(JSON.stringify(toUnsignedForm(catalog))));
}

/**
 * Sign the catalog: compute a detached Ed25519 signature over the canonical
 * (signature-blanked) bytes and return a copy with the provenance signature
 * fields populated. `outDir` is where an ephemeral key is persisted when
 * EVIDENCE_SIGNING_KEY_PATH is unset (identical to signRun()).
 */
export function signCatalog(catalog: ProhibitedVendorsCatalog, outDir: string): {
  signed: ProhibitedVendorsCatalog;
  ephemeralKey: boolean;
} {
  const canonical = serializeUnsignedCanonical(catalog);
  const sig = signDetached(Buffer.from(canonical, 'utf8'), outDir);
  return {
    signed: {
      ...catalog,
      provenance: {
        ...catalog.provenance,
        signingKeyId: sig.keyId,
        publicKeyPem: sig.publicKeyPem,
        signatureEd25519: sig.signatureBase64,
      },
    },
    ephemeralKey: sig.ephemeralKey,
  };
}

/** Verify a catalog's embedded detached signature against its canonical bytes. */
export function verifyCatalogSignature(catalog: ProhibitedVendorsCatalog): boolean {
  const canonical = serializeUnsignedCanonical(catalog);
  return verifyDetached(Buffer.from(canonical, 'utf8'), {
    publicKeyPem: catalog.provenance.publicKeyPem,
    signatureBase64: catalog.provenance.signatureEd25519,
  });
}

// ─── Snapshot ingestion (offline) ────────────────────────────────────────────

function readFileBuf(path: string): Buffer { return readFileSync(path); }

function ingestConstant(
  source: ProhibitedVendorsSourceId,
  filePath: string,
  fetchedAt: string,
  parse: (json: any, snapshotFilename: string) => ProhibitedVendorEntity[],
): SourceIngestResult | null {
  if (!existsSync(filePath)) return null;
  const buf = readFileBuf(filePath);
  const json = JSON.parse(buf.toString('utf8'));
  const snapshotFilename = basename(filePath);
  const entities = parse(json, snapshotFilename);
  return {
    meta: {
      id: source,
      source_url: SOURCE_URL[source],
      snapshot_filename: snapshotFilename,
      sha256: sha256Hex(buf),
      bytes: buf.length,
      fetched_at: fetchedAt,
      authority_citation: SOURCE_AUTHORITY[source],
      entity_count: entities.length,
    },
    entities,
  };
}

/**
 * Ingest every source available in `dataDir` (committed statutory constants)
 * and `snapshotDir` (staged network-source snapshots). Returns one ingest
 * result per source actually found, plus the sourceCalls audit list.
 */
export function ingestAllSources(opts: {
  dataDir: string;
  snapshotDir: string;
  fetchedAt: string;
}): { ingests: SourceIngestResult[]; sourceCalls: string[] } {
  const { dataDir, snapshotDir, fetchedAt } = opts;
  const ingests: SourceIngestResult[] = [];
  const sourceCalls: string[] = [];

  const pushFile = (path: string) => sourceCalls.push(`file:${basename(path)}`);

  // ── Committed statutory constants (always present in a checkout) ──
  const farPath = resolve(dataDir, 'far-52-204-25-named-entities.json');
  if (existsSync(farPath)) {
    const buf = readFileBuf(farPath);
    const json = JSON.parse(buf.toString('utf8'));
    const farEntities = parseFar52204_25(json, basename(farPath));
    const ndaa889Entities = parseNdaa889(json, basename(farPath));
    const sha = sha256Hex(buf);
    ingests.push({
      meta: { id: 'far-52-204-25', source_url: SOURCE_URL['far-52-204-25'], snapshot_filename: basename(farPath), sha256: sha, bytes: buf.length, fetched_at: fetchedAt, authority_citation: SOURCE_AUTHORITY['far-52-204-25'], entity_count: farEntities.length },
      entities: farEntities,
    });
    ingests.push({
      meta: { id: 'ndaa-889', source_url: SOURCE_URL['ndaa-889'], snapshot_filename: basename(farPath), sha256: sha, bytes: buf.length, fetched_at: fetchedAt, authority_citation: SOURCE_AUTHORITY['ndaa-889'], entity_count: ndaa889Entities.length },
      entities: ndaa889Entities,
    });
    pushFile(farPath);
  }

  const ndaa1634 = ingestConstant('ndaa-1634', resolve(dataDir, 'ndaa-1634-named-entities.json'), fetchedAt, parseNdaa1634);
  if (ndaa1634) { ingests.push(ndaa1634); pushFile(resolve(dataDir, 'ndaa-1634-named-entities.json')); }

  const fascsa = ingestConstant('fascsa', resolve(dataDir, 'fascsa-orders.json'), fetchedAt, parseFascsaOrders);
  if (fascsa) { ingests.push(fascsa); pushFile(resolve(dataDir, 'fascsa-orders.json')); }

  // ── Staged network-source snapshots (present only after extract/fetch) ──
  if (existsSync(snapshotDir)) {
    const sdnPath = resolve(snapshotDir, 'sdn.csv');
    if (existsSync(sdnPath)) {
      const buf = readFileBuf(sdnPath);
      const addPath = resolve(snapshotDir, 'add.csv');
      const altPath = resolve(snapshotDir, 'alt.csv');
      const addCsv = existsSync(addPath) ? readFileBuf(addPath).toString('utf8') : undefined;
      const altCsv = existsSync(altPath) ? readFileBuf(altPath).toString('utf8') : undefined;
      const entities = parseOfacSdn(buf.toString('utf8'), addCsv, altCsv, 'sdn.csv');
      ingests.push({
        meta: { id: 'ofac-sdn', source_url: SOURCE_URL['ofac-sdn'], snapshot_filename: 'sdn.csv', sha256: sha256Hex(buf), bytes: buf.length, fetched_at: fetchedAt, authority_citation: SOURCE_AUTHORITY['ofac-sdn'], entity_count: entities.length },
        entities,
      });
      pushFile(sdnPath);
    }

    const consPath = resolve(snapshotDir, 'consolidated.csv');
    if (existsSync(consPath)) {
      const buf = readFileBuf(consPath);
      const entities = parseBisEntityList(buf.toString('utf8'), 'consolidated.csv');
      ingests.push({
        meta: { id: 'bis-entity-list', source_url: SOURCE_URL['bis-entity-list'], snapshot_filename: 'consolidated.csv', sha256: sha256Hex(buf), bytes: buf.length, fetched_at: fetchedAt, authority_citation: SOURCE_AUTHORITY['bis-entity-list'], entity_count: entities.length },
        entities,
      });
      pushFile(consPath);
    }

    const samPages = readdirSync(snapshotDir)
      .filter((f) => /^sam-exclusions-page-\d+\.json$/.test(f))
      .sort();
    if (samPages.length > 0) {
      const pageObjs: unknown[] = [];
      let combined = Buffer.alloc(0);
      for (const f of samPages) {
        const buf = readFileBuf(resolve(snapshotDir, f));
        combined = Buffer.concat([combined, buf]);
        pageObjs.push(JSON.parse(buf.toString('utf8')));
        sourceCalls.push(`file:${f}`);
      }
      const entities = parseSamExclusions(pageObjs);
      ingests.push({
        meta: { id: 'sam-exclusions', source_url: SOURCE_URL['sam-exclusions'], snapshot_filename: samPages[0]!, sha256: sha256Hex(combined), bytes: combined.length, fetched_at: fetchedAt, authority_citation: SOURCE_AUTHORITY['sam-exclusions'], entity_count: entities.length },
        entities,
      });
    }
  }

  return { ingests, sourceCalls };
}

// ─── Network fetch seam (thin; the real bulk fetch lives in the extract script) ──

export type SourceFetcher = (url: string) => Promise<{ status: number; body: Buffer; contentType?: string }>;

/** Default fetcher: HTTPS GET via global fetch, wrapped in withRetry for transient errors. */
export const defaultSourceFetcher: SourceFetcher = async (url: string) => {
  return withRetry(
    async () => {
      const resp = await fetch(url, { method: 'GET', headers: { accept: '*/*' } });
      const ab = await resp.arrayBuffer();
      const out = { status: resp.status, body: Buffer.from(ab), contentType: resp.headers.get('content-type') ?? undefined };
      if (resp.status >= 500 || resp.status === 429) {
        throw Object.assign(new Error(`HTTP ${resp.status} for ${url}`), { $metadata: { httpStatusCode: resp.status } });
      }
      return out;
    },
    { attempts: 3, baseDelayMs: 500, maxDelayMs: 4000 },
  );
};

/**
 * Fetch the live network sources (OFAC, BIS, SAM) into `snapshotDir`. Throws a
 * typed `<Source>FetchError` on terminal failure rather than emitting a partial
 * or stale catalog (REO Rule 1.5). The SAM API key is validated FIRST, before
 * any network call (test T19). FASCSA + the statutory constants are not fetched
 * here — they come from the committed register/constants in `dataDir`.
 */
export async function fetchNetworkSources(opts: {
  snapshotDir: string;
  config: ProhibitedVendorsConfig;
  fetcher: SourceFetcher;
}): Promise<void> {
  const { snapshotDir, config, fetcher } = opts;
  // Validate the SAM key up front so a misconfiguration fails before any I/O.
  requireSamApiKey(config);
  mkdirSync(snapshotDir, { recursive: true });

  const get = async (url: string): Promise<{ status: number; body: Buffer }> => {
    try {
      return await fetcher(url);
    } catch (e) {
      return { status: 0, body: Buffer.from(String((e as Error)?.message ?? e)) };
    }
  };

  // OFAC SDN (+ ADD + ALT)
  for (const name of ['sdn.csv', 'add.csv', 'alt.csv']) {
    const url = `https://www.treasury.gov/ofac/downloads/${name}`;
    const res = await get(url);
    if (res.status !== 200) {
      throw new OfacFetchError(`OFAC fetch failed for ${url} (status ${res.status}); refusing to emit a stale/partial catalog.`);
    }
    writeFileSync(resolve(snapshotDir, name), res.body);
  }

  // BIS Entity List (consolidated screening list CSV)
  {
    const url = SOURCE_URL['bis-entity-list'];
    const res = await get(url);
    if (res.status !== 200) {
      throw new BisFetchError(`BIS consolidated screening list fetch failed for ${url} (status ${res.status}).`);
    }
    writeFileSync(resolve(snapshotDir, 'consolidated.csv'), res.body);
  }

  // SAM.gov Exclusions (first page; full pagination is in the extract script)
  {
    const key = config.samGov.apiKey ?? '';
    const url = `${SOURCE_URL['sam-exclusions']}&samRegistered=Yes&pageSize=1000&pageNumber=0&api_key=${encodeURIComponent(key)}`;
    const res = await get(url);
    if (res.status !== 200) {
      throw new SamFetchError(`SAM Exclusions fetch failed (status ${res.status}).`);
    }
    writeFileSync(resolve(snapshotDir, 'sam-exclusions-page-001.json'), res.body);
  }
}

// ─── Snapshot MANIFEST ───────────────────────────────────────────────────────

export interface SnapshotManifest {
  generated_at: string;
  files: Array<{ filename: string; sha256: string; bytes: number; url: string; fetched_at: string }>;
}

/**
 * Write `MANIFEST.json` into the snapshot directory: per-file sha256 + bytes +
 * url + fetched_at, sourced from the ingest results. This forensic-preservation
 * manifest survives independent of out/prohibited-vendors-catalog.json.
 */
export function writeSnapshotManifest(snapshotDir: string, ingests: SourceIngestResult[], generatedAt: string): string {
  const manifest: SnapshotManifest = {
    generated_at: generatedAt,
    files: ingests.map((i) => ({
      filename: i.meta.snapshot_filename,
      sha256: i.meta.sha256,
      bytes: i.meta.bytes,
      url: i.meta.source_url,
      fetched_at: i.meta.fetched_at,
    })),
  };
  const path = resolve(snapshotDir, 'MANIFEST.json');
  if (!existsSync(snapshotDir)) mkdirSync(snapshotDir, { recursive: true });
  writeFileSync(path, JSON.stringify(manifest, null, 2));
  return path;
}

// ─── Disk emitter ────────────────────────────────────────────────────────────

export interface CatalogEmitOptions {
  /** Where to write out/prohibited-vendors-catalog.json + its .sig. */
  outDir: string;
  /** Directory of committed statutory constants. Default <cloud-evidence>/data. */
  dataDir?: string;
  /** Directory of staged network-source snapshots. Default <snapshot_dir>/prohibited-vendors-snapshot-YYYYMMDD. */
  snapshotDir?: string;
  config?: ProhibitedVendorsConfig;
  configPath?: string;
  /** ISO timestamp for deterministic output. Default new Date().toISOString(). */
  generatedAt?: string;
  /** When true, fetch network sources into snapshotDir before ingesting. Default false (offline-first). */
  fetch?: boolean;
  /** Injectable fetcher seam (tests). Default defaultSourceFetcher. */
  fetcher?: SourceFetcher;
  /** Write the snapshot MANIFEST.json. Default true. */
  writeManifest?: boolean;
}

export interface CatalogEmitResult {
  catalog_path: string;
  sig_path: string;
  manifest_path: string | null;
  /** SHA-256 of the written catalog file bytes. */
  sha256: string;
  statistics: CatalogStatistics;
  source_count: number;
  entity_count: number;
  signing_key_id: string;
  ephemeral_key: boolean;
}

/**
 * End-to-end: (optionally fetch →) ingest snapshot + constants → build → sign →
 * write catalog + .sig + snapshot MANIFEST → augment inventory-coverage.json.
 */
export async function emitProhibitedVendorsCatalog(opts: CatalogEmitOptions): Promise<CatalogEmitResult> {
  const config = opts.config ?? loadProhibitedVendorsConfig(opts.configPath);
  const generatedAt = opts.generatedAt ?? new Date().toISOString();
  const dataDir = opts.dataDir ?? resolve(PROJECT_ROOT, 'data');
  const snapshotDir = opts.snapshotDir
    ?? resolve(config.snapshotDir, `prohibited-vendors-snapshot-${yyyymmdd(generatedAt)}`);

  if (opts.fetch) {
    await fetchNetworkSources({ snapshotDir, config, fetcher: opts.fetcher ?? defaultSourceFetcher });
  }

  const { ingests, sourceCalls } = ingestAllSources({ dataDir, snapshotDir, fetchedAt: generatedAt });
  if (ingests.length === 0) {
    throw new Error(
      `prohibited-vendors-catalog: no sources ingested. Expected committed constants under ${dataDir} ` +
      `(far-52-204-25-named-entities.json, ndaa-1634-named-entities.json, fascsa-orders.json) ` +
      `and/or a staged snapshot under ${snapshotDir}.`,
    );
  }

  const catalog = buildCatalog({ ingests, snapshotDir, generatedAt, sourceCalls });
  const { signed, ephemeralKey } = signCatalog(catalog, opts.outDir);

  if (!existsSync(opts.outDir)) mkdirSync(opts.outDir, { recursive: true });
  const catalogPath = resolve(opts.outDir, CATALOG_FILENAME);
  const catalogBytes = Buffer.from(JSON.stringify(signed, null, 2), 'utf8');
  writeFileSync(catalogPath, catalogBytes);

  const sigPath = resolve(opts.outDir, `${CATALOG_FILENAME}.sig`);
  writeFileSync(sigPath, JSON.stringify({
    algorithm: 'ed25519',
    keyId: signed.provenance.signingKeyId,
    publicKeyPem: signed.provenance.publicKeyPem,
    sigBase64: signed.provenance.signatureEd25519,
  }, null, 2));

  let manifestPath: string | null = null;
  if (opts.writeManifest !== false) {
    manifestPath = writeSnapshotManifest(snapshotDir, ingests, generatedAt);
  }

  // Augment inventory-coverage.json in-place if a prior collector wrote one.
  try {
    const covPath = resolve(opts.outDir, 'inventory-coverage.json');
    if (existsSync(covPath)) {
      const cov = JSON.parse(readFileSync(covPath, 'utf8'));
      cov.prohibited_vendors_catalog_entity_count = signed.entities.length;
      cov.prohibited_vendors_catalog_source_count = signed.sources.length;
      writeFileSync(covPath, JSON.stringify(cov, null, 2));
    }
  } catch (e) {
    log.warn({ event: 'prohibited_vendors.coverage_augment_failed', err: String((e as Error)?.message ?? e) });
  }

  log.info({
    event: 'prohibited_vendors.catalog_emitted',
    path: catalogPath,
    entity_count: signed.entities.length,
    source_count: signed.sources.length,
    duplicates_collapsed: signed.statistics.duplicates_collapsed,
    requires_operator_input: signed.statistics.requires_operator_input_count,
    ephemeral_key: ephemeralKey,
  });

  return {
    catalog_path: catalogPath,
    sig_path: sigPath,
    manifest_path: manifestPath,
    sha256: sha256Hex(catalogBytes),
    statistics: signed.statistics,
    source_count: signed.sources.length,
    entity_count: signed.entities.length,
    signing_key_id: signed.provenance.signingKeyId,
    ephemeral_key: ephemeralKey,
  };
}

// ─── Typed loader (for downstream W slices) ──────────────────────────────────

export interface LoadCatalogResult {
  catalog: ProhibitedVendorsCatalog;
  signatureValid: boolean;
}

/**
 * Load + (by default) verify the prohibited-vendor catalog. Downstream W slices
 * (W.W2/W.W3/W.W4) call this and MUST check `signatureValid` before trusting the
 * catalog — a forged catalog could mask a true prohibited vendor (W.W1 §9 R8).
 */
export function loadProhibitedVendorsCatalog(path: string, opts: { verify?: boolean } = {}): LoadCatalogResult {
  const raw = readFileSync(path, 'utf8');
  const catalog = JSON.parse(raw) as ProhibitedVendorsCatalog;
  if (catalog.schema_version !== CATALOG_SCHEMA_VERSION) {
    throw new Error(`prohibited-vendors-catalog: unexpected schema_version "${catalog.schema_version}" (expected "${CATALOG_SCHEMA_VERSION}") at ${path}`);
  }
  const signatureValid = opts.verify === false ? false : verifyCatalogSignature(catalog);
  return { catalog, signatureValid };
}
