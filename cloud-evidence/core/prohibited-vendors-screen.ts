/**
 * Prohibited-vendor screen — matcher engine + surface walkers + result
 * assembly (LOOP-W.W2).
 *
 * Screens four surfaces — the operator's subprocessor sheet, every package in
 * the SBOM (transitively), every OCI image publisher attested by cosign/Rekor,
 * and every inventory asset carrying a vendor tag/SKU — against the W.W1
 * prohibited-vendor catalog (FAR 52.204-25 named entities + NDAA §1634
 * Kaspersky + OFAC SDN + BIS Entity List + SAM Exclusions + FASCSA). It emits
 * a `ProhibitedVendorScreenResult` envelope; the disk/sign/xlsx wiring lives in
 * `core/prohibited-vendors-screen-emit.ts`. This file is pure (no disk I/O for
 * the matcher), so the matching logic is exercised directly with fixtures.
 *
 * Walking the catalog: the W.W1 catalog (`core/prohibited-vendors-catalog.ts`)
 * emits `ProhibitedVendorEntity[]` keyed by (source_id, source_record_id) with
 * `name_canonical`, `name_canonical_stripped`, and `aliases[]`. The published
 * federal lists do NOT enumerate corporate subsidiary edges, so the matcher
 * walks `subsidiaries[]` ONLY when an operator supplies them via
 * prohibited-vendors-overrides.yaml `manual_additions[].subsidiaries` (REO
 * Rule 4: operator-supplied data is real data) — for a pure federal-sourced
 * catalog, the subsidiary walk simply finds nothing, which is honest.
 *
 * REO compliance: every match traces to a real catalog row × a real surface
 * entry. Match records carry the catalog provenance, the surface evidence
 * pointer, a confidence band, and the FAR 52.204-25(d) data elements (with
 * `REQUIRES-OPERATOR-INPUT` markers where the operator must supply UEI / CAGE /
 * brand / model). The system NEVER auto-submits anything to a federal endpoint.
 */
import { createHash } from 'node:crypto';
import type {
  ProhibitedVendorsCatalog,
  ProhibitedVendorEntity,
  ProhibitedVendorsSourceId,
} from './prohibited-vendors-catalog.ts';
import { VendorNameNormalizer } from './vendor-name-normalizer.ts';
import type { ManualAddition, Suppression } from './prohibited-vendors-overrides.ts';
import type { SubprocessorRow } from './subprocessors-sheet.ts';

export const SCREEN_SCHEMA_VERSION = '1.0.0';
export const SCREEN_RESULT_FILENAME = 'prohibited-vendors-screen-result.json';
export const SCREEN_RESULT_XLSX_FILENAME = 'prohibited-vendors-screen-result.xlsx';
export const SCREEN_LEDGER_FILENAME = 'prohibited-vendor-screens.jsonl';
const EMITTER = 'core/prohibited-vendors-screen.ts';

/** The SR controls every prohibited-vendor finding cites (NIST SP 800-161r1). */
export const SCREEN_RELATED_CONTROLS = ['sr-1', 'sr-3', 'sr-5', 'sr-6', 'sr-11'] as const;

export type ScreenSource = ProhibitedVendorsSourceId | 'operator-manual-addition';
export type ScreenSurface = 'subprocessor-sheet' | 'sbom' | 'oci-publisher' | 'inventory-provider-tag';
export type ConfidenceBand = 'high' | 'medium' | 'low';
export type MatchedBy =
  | 'exact-case-insensitive'
  | 'normalized-name'
  | 'alias-table'
  | 'subsidiary-walk'
  | 'transliteration'
  | 'fingerprint'
  | 'domain-registrable';

/** Mapped catalog provenance carried onto every match (subset of the W.W1 entity). */
export interface MatchCatalogProvenance {
  source: ScreenSource;
  list_program?: string;
  exclusion_type?: string;
  citation: string;
  extracted_at: string;
}

/** FAR 52.204-25(d)(1) report data elements, pre-filled for W.W3 reuse. */
export interface FarDataElements {
  contract_numbers: string[];
  order_numbers: string[];
  supplier_name: string;
  supplier_uei: string;
  supplier_cage_code: string;
  brand: string;
  model_number: string;
  item_description: string;
  mitigation_actions: string;
}

export const REQUIRES_OPERATOR_INPUT = 'REQUIRES-OPERATOR-INPUT';

export interface ProhibitedVendorMatch {
  match_id: string;
  catalog_uid: string;
  catalog_provenance: MatchCatalogProvenance;
  surface: ScreenSurface;
  matched_entity_name: string;
  match_path: string[];
  confidence: number;
  confidence_band: ConfidenceBand;
  matched_by: MatchedBy;
  far_52_204_25_d_data_elements: FarDataElements;
  poam_item_uuid: string;
  related_controls: string[];
  suppressed: boolean;
  suppression_justification?: string;
  discovered_at: string;
  sources: {
    surface_evidence: string;
    sbom_package_purl?: string;
    oci_image_digest?: string;
    inventory_asset_id?: string;
  };
}

export interface SurfaceScreened {
  surface: ScreenSurface;
  entries_screened: number;
  source_path: string;
  walked_at: string;
}

export interface ProhibitedVendorScreenResult {
  schema_version: typeof SCREEN_SCHEMA_VERSION;
  run_id: string;
  csp_name: string;
  started_at: string;
  completed_at: string;
  catalog_snapshot_ref: {
    path: string;
    sha256: string;
    generated_at: string;
    age_hours: number;
    is_stale: boolean;
  };
  surfaces_screened: SurfaceScreened[];
  matches: ProhibitedVendorMatch[];
  summary: {
    total_matches: number;
    matches_by_source: Record<string, number>;
    matches_by_surface: Record<string, number>;
    matches_by_confidence_band: Record<ConfidenceBand, number>;
    suppressed_matches: number;
  };
  reportable_under_far_52_204_25_d: boolean;
  reportable_under_ndaa_1634: boolean;
  reasonable_inquiry_attested: boolean;
  provenance: {
    emitter: string;
    emittedAt: string;
    sourceCalls: string[];
    signingKeyId: string;
    algorithm: 'ed25519';
    signatureEd25519: string;
    publicKeyPem: string;
    rfc3161TimestampPath: string | null;
    sourceDigests: Array<{ kind: string; path: string; sha256: string }>;
  };
}

// ─── Catalog → screening index ───────────────────────────────────────────────

interface SubsidiaryCandidate {
  tokens: string[];
  depth: number;
}

interface IndexEntry {
  catalog_uid: string;
  entity_name: string;
  provenance: MatchCatalogProvenance;
  primaryLight: string;
  primaryTokens: string[];
  aliasTokens: string[][];
  subsidiaries: SubsidiaryCandidate[];
  fingerprints: string[];
  /** All first-tokens of every candidate, for the prefilter. */
  firstTokens: Set<string>;
}

export interface EntryMatch {
  entry: IndexEntry;
  matched_by: MatchedBy;
  confidence: number;
  matched_candidate: string;
}

function depthConfidence(depth: number): number {
  if (depth <= 1) return 0.85;
  if (depth === 2) return 0.7;
  return 0.5;
}

function bandFor(confidence: number): ConfidenceBand {
  if (confidence >= 0.85) return 'high';
  if (confidence >= 0.7) return 'medium';
  return 'low';
}

/** True when `needle` appears as a contiguous run of whole tokens in `hay`. */
function isContiguousTokenSubsequence(hay: string[], needle: string[]): boolean {
  if (needle.length === 0 || needle.length > hay.length) return false;
  for (let i = 0; i + needle.length <= hay.length; i++) {
    let ok = true;
    for (let j = 0; j < needle.length; j++) {
      if (hay[i + j] !== needle[j]) { ok = false; break; }
    }
    if (ok) return true;
  }
  return false;
}

/** Map a W.W1 source_id to the screen source + reportability buckets. */
function provenanceForEntity(
  e: ProhibitedVendorEntity,
  extractedAt: string,
): MatchCatalogProvenance {
  const prov: MatchCatalogProvenance = {
    source: e.source_id,
    citation: e.authority_citation,
    extracted_at: extractedAt,
  };
  if (e.programs && e.programs.length > 0) prov.list_program = e.programs[0];
  if (e.source_id === 'sam-exclusions' && e.programs && e.programs.length > 0) {
    prov.exclusion_type = e.programs[0];
  }
  return prov;
}

/**
 * The boundary-respecting matcher index. Built once per run from the catalog +
 * operator manual additions; every surface walker queries it via match().
 */
export class ProhibitedVendorIndex {
  private readonly entries: IndexEntry[] = [];
  /** firstToken -> entry indices that have a candidate starting with it. */
  private readonly byFirstToken = new Map<string, Set<number>>();
  private readonly norm: VendorNameNormalizer;

  constructor(norm: VendorNameNormalizer) {
    this.norm = norm;
  }

  private register(entry: IndexEntry): void {
    const idx = this.entries.length;
    this.entries.push(entry);
    for (const t of entry.firstTokens) {
      let set = this.byFirstToken.get(t);
      if (!set) { set = new Set<number>(); this.byFirstToken.set(t, set); }
      set.add(idx);
    }
  }

  /** Add one catalog entity (or a fixture entity carrying `subsidiaries`). */
  addEntity(e: ProhibitedVendorEntity, extractedAt: string): void {
    const provenance = provenanceForEntity(e, extractedAt);
    const primaryTokens = this.norm.tokens(e.name_verbatim || e.name_canonical);
    const aliasTokens = (e.aliases ?? [])
      .map((a) => this.norm.tokens(a))
      .filter((t) => t.length > 0);
    // The published catalog has no subsidiary edges; a fixture/extension entity
    // may carry a `subsidiaries: string[]` field, which we read when present.
    const subs = ((e as unknown as { subsidiaries?: string[] }).subsidiaries ?? [])
      .map((s) => ({ tokens: this.norm.tokens(s), depth: 1 }))
      .filter((s) => s.tokens.length > 0);
    this.registerEntry({
      catalog_uid: `${e.source_id}::${e.source_record_id}`,
      entity_name: e.name_verbatim || e.name_canonical,
      provenance,
      primaryLight: this.norm.normalizeLight(e.name_verbatim || e.name_canonical),
      primaryTokens,
      aliasTokens,
      subsidiaries: subs,
      fingerprints: [],
    });
  }

  /** Add an operator manual addition as a screening row (source=operator-manual-addition). */
  addManualAddition(m: ManualAddition, extractedAt: string): void {
    const primaryTokens = this.norm.tokens(m.entity_name);
    const aliasTokens = (m.aliases ?? [])
      .map((a) => this.norm.tokens(a))
      .filter((t) => t.length > 0);
    const subsidiaries: SubsidiaryCandidate[] = [];
    (m.subsidiaries ?? []).forEach((chain) => {
      // A subsidiary may be a single name (depth 1) or a "Parent>Child" chain.
      const parts = chain.split('>').map((p) => p.trim()).filter(Boolean);
      const leaf = parts[parts.length - 1] ?? chain;
      const tokens = this.norm.tokens(leaf);
      if (tokens.length > 0) subsidiaries.push({ tokens, depth: Math.max(1, parts.length - 1) || 1 });
    });
    this.registerEntry({
      catalog_uid: `operator-manual-addition::${slug(m.entity_name)}`,
      entity_name: m.entity_name,
      provenance: {
        source: 'operator-manual-addition',
        citation: m.justification,
        extracted_at: extractedAt,
      },
      primaryLight: this.norm.normalizeLight(m.entity_name),
      primaryTokens,
      aliasTokens,
      subsidiaries,
      fingerprints: (m.fingerprints ?? []).map((f) => f.toLowerCase()),
    });
  }

  /** Register cosign key fingerprints against a catalog entry (operator override). */
  addFingerprints(catalogUid: string, fingerprints: string[]): void {
    const entry = this.entries.find((e) => e.catalog_uid === catalogUid);
    if (!entry) return;
    for (const f of fingerprints) entry.fingerprints.push(f.toLowerCase());
  }

  private registerEntry(partial: Omit<IndexEntry, 'firstTokens'>): void {
    const firstTokens = new Set<string>();
    if (partial.primaryTokens[0]) firstTokens.add(partial.primaryTokens[0]);
    for (const a of partial.aliasTokens) if (a[0]) firstTokens.add(a[0]);
    for (const s of partial.subsidiaries) if (s.tokens[0]) firstTokens.add(s.tokens[0]);
    this.register({ ...partial, firstTokens });
  }

  /** Every catalog/manual fingerprint, for the OCI walker's fingerprint index. */
  fingerprintIndex(): Map<string, IndexEntry> {
    const out = new Map<string, IndexEntry>();
    for (const e of this.entries) for (const f of e.fingerprints) out.set(f, e);
    return out;
  }

  size(): number {
    return this.entries.length;
  }

  /**
   * Match a single surface string against every catalog candidate. Returns one
   * EntryMatch per catalog entry that fired (best candidate per entry). The
   * caller (a surface walker) wraps these into ProhibitedVendorMatch records.
   */
  match(surfaceRaw: string): EntryMatch[] {
    const sLight = this.norm.normalizeLight(surfaceRaw);
    const sTokens = this.norm.tokens(surfaceRaw);
    if (sTokens.length === 0) return [];
    const sTokenSet = new Set(sTokens);
    const nonAscii = VendorNameNormalizer.hasNonAscii(surfaceRaw);

    // Prefilter: only entries whose candidate first-token appears in the surface.
    const candidateIdx = new Set<number>();
    for (const t of sTokenSet) {
      const set = this.byFirstToken.get(t);
      if (set) for (const i of set) candidateIdx.add(i);
    }

    const out: EntryMatch[] = [];
    for (const i of candidateIdx) {
      const entry = this.entries[i]!;
      let best: { matched_by: MatchedBy; confidence: number; candidate: string } | null = null;
      const consider = (matched_by: MatchedBy, confidence: number, candidate: string): void => {
        if (!best || confidence > best.confidence) best = { matched_by, confidence, candidate };
      };

      if (isContiguousTokenSubsequence(sTokens, entry.primaryTokens)) {
        if (sLight === entry.primaryLight) consider('exact-case-insensitive', 1.0, entry.entity_name);
        else consider('normalized-name', 1.0, entry.entity_name);
      }
      for (const a of entry.aliasTokens) {
        if (isContiguousTokenSubsequence(sTokens, a)) consider('alias-table', 0.95, a.join(' '));
      }
      for (const s of entry.subsidiaries) {
        if (isContiguousTokenSubsequence(sTokens, s.tokens)) {
          consider('subsidiary-walk', depthConfidence(s.depth), s.tokens.join(' '));
        }
      }

      if (best) {
        const chosen = best as { matched_by: MatchedBy; confidence: number; candidate: string };
        let matched_by = chosen.matched_by;
        let confidence = chosen.confidence;
        // Transliteration overlay: a non-ASCII surface that matched only did so
        // because the normalizer romanized it — record that path, capped at 0.95.
        if (nonAscii) {
          matched_by = 'transliteration';
          confidence = Math.min(confidence, 0.95);
        }
        out.push({ entry, matched_by, confidence, matched_candidate: chosen.candidate });
      }
    }
    return out;
  }
}

// ─── Match construction ──────────────────────────────────────────────────────

function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'entity';
}

function deterministicId(prefix: string, parts: string[]): string {
  const h = createHash('sha256').update(parts.join('|')).digest('hex');
  return `${prefix}-${h.slice(0, 26)}`;
}

/** A stable, deterministic UUID (v4-shaped) derived from `parts`. */
export function deterministicUuidFrom(parts: string[]): string {
  const h = createHash('sha256').update(parts.join('|')).digest('hex');
  return [
    h.slice(0, 8),
    h.slice(8, 12),
    '5' + h.slice(13, 16),
    ((parseInt(h.slice(16, 18), 16) & 0x3f) | 0x80).toString(16).padStart(2, '0') + h.slice(18, 20),
    h.slice(20, 32),
  ].join('-');
}

export interface BuildMatchInput {
  entryMatch: EntryMatch;
  surface: ScreenSurface;
  matchedName: string;
  matchPath: string[];
  discoveredAt: string;
  sources: ProhibitedVendorMatch['sources'];
  /** Operator-supplied FAR data elements keyed for this vendor (UEI/CAGE/etc.). */
  farOverride?: Partial<FarDataElements>;
  /** Optional confidence override (OCI fingerprint=1.0, domain=0.85). */
  confidence?: number;
  matchedBy?: MatchedBy;
}

export function buildMatch(input: BuildMatchInput): ProhibitedVendorMatch {
  const { entry, confidence: emConf, matched_by: emBy } = input.entryMatch;
  const confidence = input.confidence ?? emConf;
  const matched_by = input.matchedBy ?? emBy;
  const far: FarDataElements = {
    contract_numbers: input.farOverride?.contract_numbers ?? [],
    order_numbers: input.farOverride?.order_numbers ?? [],
    supplier_name: input.farOverride?.supplier_name ?? input.matchedName,
    supplier_uei: input.farOverride?.supplier_uei ?? REQUIRES_OPERATOR_INPUT,
    supplier_cage_code: input.farOverride?.supplier_cage_code ?? REQUIRES_OPERATOR_INPUT,
    brand: input.farOverride?.brand ?? REQUIRES_OPERATOR_INPUT,
    model_number: input.farOverride?.model_number ?? REQUIRES_OPERATOR_INPUT,
    item_description: input.farOverride?.item_description ?? REQUIRES_OPERATOR_INPUT,
    mitigation_actions: input.farOverride?.mitigation_actions ?? REQUIRES_OPERATOR_INPUT,
  };
  const match_id = deterministicId('pvm', [
    input.surface, entry.catalog_uid, input.matchedName, input.matchPath.join('>'),
  ]);
  return {
    match_id,
    catalog_uid: entry.catalog_uid,
    catalog_provenance: entry.provenance,
    surface: input.surface,
    matched_entity_name: input.matchedName,
    match_path: input.matchPath,
    confidence: +confidence.toFixed(4),
    confidence_band: bandFor(confidence),
    matched_by,
    far_52_204_25_d_data_elements: far,
    poam_item_uuid: deterministicUuidFrom(['w.w2:poam', entry.catalog_uid, input.surface, input.matchedName]),
    related_controls: [...SCREEN_RELATED_CONTROLS],
    suppressed: false,
    discovered_at: input.discoveredAt,
    sources: input.sources,
  };
}

// ─── Surface walkers (subprocessor + inventory; SBOM/OCI in sibling modules) ──

export interface SubprocessorWalkOptions {
  rows: SubprocessorRow[];
  index: ProhibitedVendorIndex;
  discoveredAt: string;
  /** Operator FAR overrides keyed by normalized full vendor name. */
  farByVendor?: Map<string, Partial<FarDataElements>>;
  normalizer: VendorNameNormalizer;
}

/** Surface 1: screen each subprocessor row's `name` against the catalog. */
export function screenSubprocessorRows(opts: SubprocessorWalkOptions): ProhibitedVendorMatch[] {
  const out: ProhibitedVendorMatch[] = [];
  for (const row of opts.rows) {
    const name = (row.name ?? '').trim();
    if (!name) continue;
    const farOverride = opts.farByVendor?.get(opts.normalizer.normalizeFull(name));
    for (const em of opts.index.match(name)) {
      out.push(buildMatch({
        entryMatch: em,
        surface: 'subprocessor-sheet',
        matchedName: name,
        matchPath: [name],
        discoveredAt: opts.discoveredAt,
        farOverride,
        sources: { surface_evidence: `subprocessor-row:${name}` },
      }));
    }
  }
  return out;
}

export interface InventoryAsset {
  id?: string;
  unique_id?: string;
  provider_tag?: string;
  sku?: string;
  vendor?: string;
}

export interface InventoryWalkOptions {
  assets: InventoryAsset[];
  index: ProhibitedVendorIndex;
  discoveredAt: string;
  normalizer: VendorNameNormalizer;
}

/** Surface 4: screen each asset's provider_tag / sku / vendor against the catalog. */
export function screenInventoryAssets(opts: InventoryWalkOptions): ProhibitedVendorMatch[] {
  const out: ProhibitedVendorMatch[] = [];
  for (const asset of opts.assets) {
    const assetId = asset.id ?? asset.unique_id ?? '(unknown-asset)';
    const fields: Array<{ value: string; substring: boolean }> = [];
    if (asset.provider_tag) fields.push({ value: asset.provider_tag, substring: false });
    if (asset.vendor) fields.push({ value: asset.vendor, substring: false });
    if (asset.sku) fields.push({ value: asset.sku, substring: true });
    const seen = new Set<string>();
    for (const f of fields) {
      for (const em of opts.index.match(f.value)) {
        // SKU substring matches are capped at 0.85 (medium/high boundary).
        const confidence = f.substring ? Math.min(em.confidence, 0.85) : em.confidence;
        const key = `${em.entry.catalog_uid}|${f.value}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(buildMatch({
          entryMatch: em,
          surface: 'inventory-provider-tag',
          matchedName: f.value,
          matchPath: [assetId, f.value],
          discoveredAt: opts.discoveredAt,
          confidence,
          sources: { surface_evidence: `inventory-asset:${assetId}`, inventory_asset_id: assetId },
        }));
      }
    }
  }
  return out;
}

// ─── Post-processing: dedupe, suppress, summarize, reportable flags ───────────

/** De-duplicate by (surface, catalog_uid, matched_entity_name, normalized path); keep highest confidence. */
export function dedupeMatches(matches: ProhibitedVendorMatch[]): ProhibitedVendorMatch[] {
  const best = new Map<string, ProhibitedVendorMatch>();
  for (const m of matches) {
    const key = `${m.surface}|${m.catalog_uid}|${m.matched_entity_name.toLowerCase()}|${m.match_path.join('>').toLowerCase()}`;
    const prev = best.get(key);
    if (!prev || m.confidence > prev.confidence) best.set(key, m);
  }
  return [...best.values()].sort((a, b) =>
    a.surface.localeCompare(b.surface) ||
    a.catalog_uid.localeCompare(b.catalog_uid) ||
    a.match_id.localeCompare(b.match_id));
}

/** Apply unexpired suppressions (keyed by catalog_uid) to the match set in place. */
export function applySuppressions(
  matches: ProhibitedVendorMatch[],
  suppressions: Map<string, Suppression>,
  nowIso: string,
): ProhibitedVendorMatch[] {
  const now = Date.parse(nowIso);
  for (const m of matches) {
    const s = suppressions.get(m.catalog_uid);
    if (!s) continue;
    const expired = s.expires_at ? Date.parse(s.expires_at) <= now : false;
    if (!expired) {
      m.suppressed = true;
      m.suppression_justification = s.justification;
    }
  }
  return matches;
}

function isFarReportableSource(source: ScreenSource): boolean {
  return source === 'far-52-204-25' || source === 'ndaa-889' || source === 'operator-manual-addition';
}

export interface AssembleOptions {
  runId: string;
  cspName: string;
  startedAt: string;
  completedAt: string;
  catalogRef: ProhibitedVendorScreenResult['catalog_snapshot_ref'];
  surfaces: SurfaceScreened[];
  matches: ProhibitedVendorMatch[];
  suppressions: Map<string, Suppression>;
  /** The four screen surfaces that were actually walked, for reasonable-inquiry. */
  surfacesWalkedCount: number;
}

/**
 * Dedupe + suppress + summarize the matches and compute the FAR/NDAA reportable
 * flags + the FAR 4.2101 reasonable-inquiry attestation. The result's
 * provenance block is left blank here; the emit module fills + signs it.
 */
export function assembleScreenResult(opts: AssembleOptions): ProhibitedVendorScreenResult {
  const deduped = dedupeMatches(opts.matches);
  applySuppressions(deduped, opts.suppressions, opts.completedAt);

  const matchesBySource: Record<string, number> = {};
  const matchesBySurface: Record<string, number> = {};
  const matchesByBand: Record<ConfidenceBand, number> = { high: 0, medium: 0, low: 0 };
  let suppressed = 0;
  for (const m of deduped) {
    matchesBySource[m.catalog_provenance.source] = (matchesBySource[m.catalog_provenance.source] ?? 0) + 1;
    matchesBySurface[m.surface] = (matchesBySurface[m.surface] ?? 0) + 1;
    matchesByBand[m.confidence_band] += 1;
    if (m.suppressed) suppressed += 1;
  }

  const reportableFar = deduped.some((m) =>
    !m.suppressed && m.confidence_band === 'high' && isFarReportableSource(m.catalog_provenance.source));
  const reportableNdaa = deduped.some((m) =>
    !m.suppressed && m.catalog_provenance.source === 'ndaa-1634');

  // Reasonable inquiry per FAR 4.2101: all four surfaces walked, catalog fresh,
  // and the operator-bypass (suppression) rate under 5% of total matches.
  const total = deduped.length;
  const bypassUnderCeiling = total === 0 ? true : suppressed < 0.05 * total;
  const reasonableInquiry =
    opts.surfacesWalkedCount === 4 && !opts.catalogRef.is_stale && bypassUnderCeiling;

  return {
    schema_version: SCREEN_SCHEMA_VERSION,
    run_id: opts.runId,
    csp_name: opts.cspName,
    started_at: opts.startedAt,
    completed_at: opts.completedAt,
    catalog_snapshot_ref: opts.catalogRef,
    surfaces_screened: opts.surfaces,
    matches: deduped,
    summary: {
      total_matches: total,
      matches_by_source: matchesBySource,
      matches_by_surface: matchesBySurface,
      matches_by_confidence_band: matchesByBand,
      suppressed_matches: suppressed,
    },
    reportable_under_far_52_204_25_d: reportableFar,
    reportable_under_ndaa_1634: reportableNdaa,
    reasonable_inquiry_attested: reasonableInquiry,
    provenance: {
      emitter: EMITTER,
      emittedAt: opts.completedAt,
      sourceCalls: [],
      signingKeyId: '',
      algorithm: 'ed25519',
      signatureEd25519: '',
      publicKeyPem: '',
      rfc3161TimestampPath: null,
      sourceDigests: [],
    },
  };
}

/** Build the matcher index from a verified catalog + operator manual additions. */
export function buildScreenIndex(opts: {
  catalog: ProhibitedVendorsCatalog;
  normalizer: VendorNameNormalizer;
  manualAdditions?: ManualAddition[];
  fingerprintOverrides?: Array<{ catalog_uid: string; fingerprints: string[] }>;
}): ProhibitedVendorIndex {
  const index = new ProhibitedVendorIndex(opts.normalizer);
  const extractedAt = opts.catalog.generated_at;
  for (const e of opts.catalog.entities) index.addEntity(e, extractedAt);
  for (const m of opts.manualAdditions ?? []) index.addManualAddition(m, extractedAt);
  for (const f of opts.fingerprintOverrides ?? []) index.addFingerprints(f.catalog_uid, f.fingerprints);
  return index;
}
