/**
 * Prohibited-vendor screen emitter (LOOP-W.W2) — disk + provenance + signing.
 *
 * Integrates the surface walkers (`core/prohibited-vendors-screen.ts`,
 * `core/sbom-prohibited-screen.ts`, `core/oci-publisher-screen.ts`) into the
 * end-to-end pass: load + verify the W.W1 catalog, load operator overrides,
 * build the matcher index, walk the four surfaces, assemble the result, fill
 * the camelCase provenance block (G3), sign it with a detached Ed25519
 * signature over the canonical signature-blanked bytes (the W.W1 catalog
 * pattern), write the JSON envelope + `.sig` sidecar + `.xlsx` workbook, append
 * the append-only screen ledger, and augment inventory-coverage.json.
 *
 * REO compliance: a catalog whose embedded signature does not verify throws
 * `CatalogSignatureInvalidError` and the pass exits non-zero (a forged catalog
 * could mask a true prohibited vendor). Every provenance source_call cites a
 * real on-disk file with its SHA-256 digest.
 */
import { readFileSync, writeFileSync, appendFileSync, existsSync, mkdirSync } from 'node:fs';
import { resolve, basename } from 'node:path';
import { createHash } from 'node:crypto';
import { canonicalize, signDetached } from './sign.ts';
import { log } from './log.ts';
import {
  loadProhibitedVendorsCatalog,
  type ProhibitedVendorsCatalog,
} from './prohibited-vendors-catalog.ts';
import {
  loadProhibitedVendorsOverrides,
  suppressionsByCatalogUid,
  type ProhibitedVendorOverrides,
} from './prohibited-vendors-overrides.ts';
import { VendorNameNormalizer } from './vendor-name-normalizer.ts';
import {
  buildScreenIndex,
  screenSubprocessorRows,
  screenInventoryAssets,
  assembleScreenResult,
  SCREEN_RESULT_FILENAME,
  SCREEN_RESULT_XLSX_FILENAME,
  SCREEN_LEDGER_FILENAME,
  type ProhibitedVendorScreenResult,
  type ProhibitedVendorMatch,
  type SurfaceScreened,
  type FarDataElements,
  type InventoryAsset,
} from './prohibited-vendors-screen.ts';
import { screenSbomDir } from './sbom-prohibited-screen.ts';
import { screenOciPublishers } from './oci-publisher-screen.ts';
import { screenResultToXlsx } from './prohibited-vendors-screen-xlsx.ts';
import type { SubprocessorRow } from './subprocessors-sheet.ts';

const DEFAULT_CATALOG_FILENAME = 'prohibited-vendors-catalog.json';
const DEFAULT_INVENTORY_FILENAME = 'inventory.json';
const DEFAULT_OCI_ATTEST_DIR = 'oci-attestations';

/** Thrown when the W.W1 catalog's embedded Ed25519 signature does not verify. */
export class CatalogSignatureInvalidError extends Error {
  readonly path: string;
  constructor(path: string) {
    super(`prohibited-vendors-screen: catalog signature did not verify at ${path}; refusing to screen against an unverifiable catalog (a forged catalog could mask a true prohibited vendor).`);
    this.name = 'CatalogSignatureInvalidError';
    this.path = path;
  }
}

function sha256File(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function hoursBetween(laterIso: string, earlierIso: string): number {
  const ms = Date.parse(laterIso) - Date.parse(earlierIso);
  return +(ms / 3_600_000).toFixed(4);
}

export interface ScreenEmitOptions {
  outDir: string;
  runId: string;
  cspName: string;
  /** Deterministic clock (tests). Defaults to now. */
  completedAt?: string;
  startedAt?: string;
  /** Catalog path. Defaults to <outDir>/prohibited-vendors-catalog.json. */
  catalogPath?: string;
  /** Skip catalog signature verification (only for fixtures that are intentionally unsigned). */
  verifyCatalog?: boolean;
  overridesPath?: string;
  /** Subprocessor rows (from the J.J2 inventory / Google Sheet). */
  subprocessorRows?: SubprocessorRow[];
  subprocessorSourcePath?: string;
  /** SBOM inputs. */
  sbomDir?: string;
  sbomPaths?: string[];
  sbomMaxDepth?: number;
  /** OCI cosign/Rekor attestation directory. Defaults to <outDir>/oci-attestations. */
  ociAttestationDir?: string;
  /** Inventory inputs. */
  inventoryPath?: string;
  inventoryAssets?: InventoryAsset[];
  /** Operator FAR data overrides keyed by normalized full vendor name. */
  farByVendor?: Map<string, Partial<FarDataElements>>;
  writeXlsx?: boolean;
}

export interface ScreenEmitResult {
  result: ProhibitedVendorScreenResult;
  json_path: string;
  sig_path: string;
  xlsx_path: string | null;
  ledger_path: string;
  json_sha256: string;
  total_matches: number;
  surfaces_walked: number;
}

interface SurfaceInput {
  walked: boolean;
  surface: SurfaceScreened;
  matches: ProhibitedVendorMatch[];
}

/** End-to-end W.W2 screen pass. */
export function emitProhibitedVendorsScreen(opts: ScreenEmitOptions): ScreenEmitResult {
  const completedAt = opts.completedAt ?? new Date().toISOString();
  const startedAt = opts.startedAt ?? completedAt;
  const catalogPath = opts.catalogPath ?? resolve(opts.outDir, DEFAULT_CATALOG_FILENAME);

  // ── Load + verify catalog ──
  if (!existsSync(catalogPath)) {
    throw new Error(`prohibited-vendors-screen: catalog not found at ${catalogPath}. Run --prohibited-vendors-catalog (W.W1) first.`);
  }
  const verify = opts.verifyCatalog !== false;
  const { catalog, signatureValid } = loadProhibitedVendorsCatalog(catalogPath, { verify });
  if (verify && !signatureValid) {
    throw new CatalogSignatureInvalidError(catalogPath);
  }
  const catalogSha = sha256File(catalogPath);
  const ageHours = hoursBetween(completedAt, catalog.generated_at);
  const isStale = ageHours > 24;
  if (isStale) {
    log.warn({ event: 'w.w2.coverage_stale', catalog_age_hours: ageHours, note: 'prohibited-vendor catalog snapshot is older than 24h (coverage:stale).' });
  }

  // ── Load overrides + build normalizer + index ──
  const overrides: ProhibitedVendorOverrides = loadProhibitedVendorsOverrides(opts.overridesPath);
  const normalizer = new VendorNameNormalizer({
    transliterationOverrides: overrides.transliteration_overrides,
  });
  const index = buildScreenIndex({
    catalog,
    normalizer,
    manualAdditions: overrides.manual_additions,
    fingerprintOverrides: overrides.fingerprint_overrides,
  });
  const suppressions = suppressionsByCatalogUid(overrides);

  // ── Walk the four surfaces ──
  const surfaceInputs: SurfaceInput[] = [];

  // Surface 1: subprocessor sheet.
  if (opts.subprocessorRows) {
    const rows = opts.subprocessorRows;
    const m = screenSubprocessorRows({ rows, index, discoveredAt: completedAt, normalizer, farByVendor: opts.farByVendor });
    surfaceInputs.push({
      walked: true,
      surface: { surface: 'subprocessor-sheet', entries_screened: rows.length, source_path: opts.subprocessorSourcePath ?? 'subprocessor-sheet', walked_at: completedAt },
      matches: m,
    });
  }

  // Surface 2: SBOM (transitive).
  if (opts.sbomDir || opts.sbomPaths) {
    const r = screenSbomDir({ sbomDir: opts.sbomDir, sbomPaths: opts.sbomPaths, index, discoveredAt: completedAt, maxDepth: opts.sbomMaxDepth });
    surfaceInputs.push({
      walked: true,
      surface: { surface: 'sbom', entries_screened: r.packages_screened, source_path: opts.sbomDir ?? `${r.files_screened} file(s)`, walked_at: completedAt },
      matches: r.matches,
    });
    if (r.truncated_at_depth !== null) {
      log.info({ event: 'w.w2.sbom_walk_truncated', sbom_walks_truncated_at_depth: r.truncated_at_depth });
    }
  }

  // Surface 3: OCI publishers.
  const ociDir = opts.ociAttestationDir ?? resolve(opts.outDir, DEFAULT_OCI_ATTEST_DIR);
  if (opts.ociAttestationDir || existsSync(ociDir)) {
    const r = screenOciPublishers({ attestationDir: ociDir, index, discoveredAt: completedAt });
    surfaceInputs.push({
      walked: true,
      surface: { surface: 'oci-publisher', entries_screened: r.images_screened, source_path: ociDir, walked_at: completedAt },
      matches: r.matches,
    });
  }

  // Surface 4: inventory provider tags.
  const inventoryAssets = opts.inventoryAssets ?? loadInventoryAssets(opts.inventoryPath ?? resolve(opts.outDir, DEFAULT_INVENTORY_FILENAME));
  if (inventoryAssets) {
    const m = screenInventoryAssets({ assets: inventoryAssets, index, discoveredAt: completedAt, normalizer });
    surfaceInputs.push({
      walked: true,
      surface: { surface: 'inventory-provider-tag', entries_screened: inventoryAssets.length, source_path: opts.inventoryPath ?? DEFAULT_INVENTORY_FILENAME, walked_at: completedAt },
      matches: m,
    });
  }

  const allMatches = surfaceInputs.flatMap((s) => s.matches);
  const surfacesWalkedCount = surfaceInputs.filter((s) => s.walked).length;

  const result = assembleScreenResult({
    runId: opts.runId,
    cspName: opts.cspName,
    startedAt,
    completedAt,
    catalogRef: { path: catalogPath, sha256: catalogSha, generated_at: catalog.generated_at, age_hours: ageHours, is_stale: isStale },
    surfaces: surfaceInputs.map((s) => s.surface),
    matches: allMatches,
    suppressions,
    surfacesWalkedCount,
  });

  // ── Provenance block (camelCase for G3) ──
  const sourceDigests: Array<{ kind: string; path: string; sha256: string }> = [
    { kind: 'catalog-snapshot', path: relForProvenance(opts.outDir, catalogPath), sha256: catalogSha },
  ];
  if (opts.subprocessorSourcePath && existsSync(opts.subprocessorSourcePath)) {
    sourceDigests.push({ kind: 'subprocessor-sheet', path: relForProvenance(opts.outDir, opts.subprocessorSourcePath), sha256: sha256File(opts.subprocessorSourcePath) });
  }
  for (const p of opts.sbomPaths ?? []) {
    if (existsSync(p)) sourceDigests.push({ kind: 'sbom', path: relForProvenance(opts.outDir, p), sha256: sha256File(p) });
  }
  if (opts.overridesPath && existsSync(opts.overridesPath)) {
    sourceDigests.push({ kind: 'overrides', path: relForProvenance(opts.outDir, opts.overridesPath), sha256: sha256File(opts.overridesPath) });
  }
  const invPath = opts.inventoryPath ?? resolve(opts.outDir, DEFAULT_INVENTORY_FILENAME);
  if (existsSync(invPath)) {
    sourceDigests.push({ kind: 'inventory', path: relForProvenance(opts.outDir, invPath), sha256: sha256File(invPath) });
  }
  result.provenance.sourceDigests = sourceDigests;
  result.provenance.sourceCalls = sourceDigests.map((d) => `${d.kind}:${d.path}`);

  // ── Sign (detached Ed25519 over canonical signature-blanked bytes) ──
  if (!existsSync(opts.outDir)) mkdirSync(opts.outDir, { recursive: true });
  const canonical = canonicalize(JSON.parse(JSON.stringify(blankSignature(result))));
  const sig = signDetached(Buffer.from(canonical, 'utf8'), opts.outDir);
  result.provenance.signingKeyId = sig.keyId;
  result.provenance.publicKeyPem = sig.publicKeyPem;
  result.provenance.signatureEd25519 = sig.signatureBase64;

  const jsonPath = resolve(opts.outDir, SCREEN_RESULT_FILENAME);
  const jsonBytes = Buffer.from(JSON.stringify(result, null, 2), 'utf8');
  writeFileSync(jsonPath, jsonBytes);

  const sigPath = resolve(opts.outDir, `${SCREEN_RESULT_FILENAME}.sig`);
  writeFileSync(sigPath, JSON.stringify({
    algorithm: 'ed25519', keyId: sig.keyId, publicKeyPem: sig.publicKeyPem, sigBase64: sig.signatureBase64,
  }, null, 2));

  // ── XLSX ──
  let xlsxPath: string | null = null;
  if (opts.writeXlsx !== false) {
    xlsxPath = resolve(opts.outDir, SCREEN_RESULT_XLSX_FILENAME);
    writeFileSync(xlsxPath, screenResultToXlsx(result));
  }

  // ── Append-only screen ledger (durable record; the repo's ledger pattern) ──
  const ledgerPath = resolve(opts.outDir, SCREEN_LEDGER_FILENAME);
  appendFileSync(ledgerPath, JSON.stringify(ledgerRecord(result, sha256(jsonBytes))) + '\n');

  // ── Augment inventory-coverage.json (sibling fields; never a G2 regression) ──
  augmentCoverage(opts.outDir, result, surfaceInputs);

  log.info({
    event: 'w.w2.screen_emitted',
    path: jsonPath,
    total_matches: result.summary.total_matches,
    surfaces_walked: surfacesWalkedCount,
    reportable_far: result.reportable_under_far_52_204_25_d,
    reportable_ndaa: result.reportable_under_ndaa_1634,
    reasonable_inquiry: result.reasonable_inquiry_attested,
    ephemeral_key: sig.ephemeralKey,
  });

  return {
    result,
    json_path: jsonPath,
    sig_path: sigPath,
    xlsx_path: xlsxPath,
    ledger_path: ledgerPath,
    json_sha256: sha256(jsonBytes),
    total_matches: result.summary.total_matches,
    surfaces_walked: surfacesWalkedCount,
  };
}

function sha256(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

function blankSignature(result: ProhibitedVendorScreenResult): ProhibitedVendorScreenResult {
  return {
    ...result,
    provenance: { ...result.provenance, signingKeyId: '', publicKeyPem: '', signatureEd25519: '' },
  };
}

function relForProvenance(outDir: string, path: string): string {
  // Keep provenance paths stable + portable: basename for files under outDir,
  // otherwise the path as given.
  try {
    if (resolve(path).startsWith(resolve(outDir))) return basename(path);
  } catch { /* fall through */ }
  return path;
}

function ledgerRecord(result: ProhibitedVendorScreenResult, sha: string): Record<string, unknown> {
  return {
    run_id: result.run_id,
    completed_at: result.completed_at,
    csp_name: result.csp_name,
    total_matches: result.summary.total_matches,
    suppressed_matches: result.summary.suppressed_matches,
    reportable_under_far_52_204_25_d: result.reportable_under_far_52_204_25_d,
    reportable_under_ndaa_1634: result.reportable_under_ndaa_1634,
    reasonable_inquiry_attested: result.reasonable_inquiry_attested,
    json_sha256: sha,
    matches: result.matches.map((m) => ({
      match_id: m.match_id,
      catalog_uid: m.catalog_uid,
      surface: m.surface,
      matched_entity_name: m.matched_entity_name,
      confidence: m.confidence,
      confidence_band: m.confidence_band,
      suppressed: m.suppressed,
    })),
  };
}

function loadInventoryAssets(path: string): InventoryAsset[] | null {
  if (!existsSync(path)) return null;
  try {
    const doc = JSON.parse(readFileSync(path, 'utf8'));
    const assets = Array.isArray(doc?.assets) ? doc.assets : Array.isArray(doc) ? doc : [];
    return assets.map((a: any) => ({
      id: a.id ?? a.unique_id ?? a.uniqueId,
      unique_id: a.unique_id ?? a.uniqueId,
      provider_tag: a.provider_tag ?? a.providerTag,
      sku: a.sku,
      vendor: a.vendor,
    }));
  } catch (e) {
    log.warn({ event: 'w.w2.inventory_load_failed', err: String((e as Error)?.message ?? e) });
    return null;
  }
}

function augmentCoverage(outDir: string, result: ProhibitedVendorScreenResult, surfaces: SurfaceInput[]): void {
  const covPath = resolve(outDir, 'inventory-coverage.json');
  if (!existsSync(covPath)) return;
  try {
    const cov = JSON.parse(readFileSync(covPath, 'utf8'));
    const counts = (s: ProhibitedVendorScreenResult['surfaces_screened'][number]['surface']) =>
      surfaces.find((x) => x.surface.surface === s)?.surface.entries_screened ?? 0;
    cov.prohibited_vendor_screen_coverage = {
      surfaces_walked: result.surfaces_screened.length,
      subprocessor_rows_screened: counts('subprocessor-sheet'),
      sbom_packages_screened: counts('sbom'),
      oci_images_screened: counts('oci-publisher'),
      inventory_assets_screened: counts('inventory-provider-tag'),
      total_matches: result.summary.total_matches,
      catalog_age_hours: result.catalog_snapshot_ref.age_hours,
    };
    writeFileSync(covPath, JSON.stringify(cov, null, 2));
  } catch (e) {
    log.warn({ event: 'w.w2.coverage_augment_failed', err: String((e as Error)?.message ?? e) });
  }
}
