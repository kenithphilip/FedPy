/**
 * SSDF material-change detector + annual re-attestation ledger (LOOP-T.T4).
 *
 * Why this exists:
 *   OMB M-23-16 §III makes a CISA Common Form attestation self-perpetuating —
 *   "binding for future versions ... unless and until the software producer
 *   notifies the agencies ... that its development practices no longer conform".
 *   The producer-side instrument that fires that notification obligation is a
 *   MATERIAL CHANGE in the SSDF satisfaction posture. This module diffs
 *   successive snapshots of the T.T2 satisfaction matrix
 *   (out/ssdf-satisfaction-matrix*.json) and emits a typed `MaterialChangeEvent`
 *   whenever a practice regresses, a new un-attestable practice appears, a major
 *   version ships, the regime changes, or a new agency is added — the events that
 *   force interim re-attestation. It pairs that with the regime-aware cadence
 *   engine (core/ssdf-annual-attestation.ts) to render, per (product × agency),
 *   the last-submitted / next-due / due-state cadence view.
 *
 * Realizable-core posture (no tracker subsystem in this repo — no pg/express/
 * react/better-sqlite3; same posture as T.T2/T.T3/W.W3/W.W4):
 *   The per-slice doc §5.1 models four SQLite tables + REST routes + a React
 *   status pane. Those are DEFERRED (tracked LOOP-T-RISKS T.T4-21..24). This
 *   module ships the two spec'd PURE engines (§6 Step 1 cadence + §6 Step 2
 *   detector) plus a signed, content-addressed ON-DISK ledger that stands in for
 *   the tracker storage: prior matrix snapshots live at
 *   out/ssdf-attestation-snapshots/<product>/<sha256>.json (the §5.2 storage root
 *   relocated from tracker/storage), the append-only run index lives at
 *   out/ssdf-attestation-ledger.jsonl, and the detector emit is the signed
 *   out/ssdf-material-change-events.json (covered by the run manifest + RFC 3161
 *   TSR via core/sign.ts). The operator-supplied signed-PDF SHA-256 / RSAA
 *   submission id capture, the force-reattestation / withdrawal / legal-review
 *   actions, and the per-agency addenda are the deferred tracker layer.
 *
 * REO posture:
 *   - Pure detector + cadence: no clock, no I/O; `detected_at` is injected.
 *   - The emit records provenance (Rule 2.6) + a detached Ed25519 signature.
 *   - Never auto-signs a producer attestation and never files with an agency /
 *     CISA RSAA (Rule 4) — those are human actions captured out of band (T.T4
 *     tracker layer, deferred).
 */
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync, appendFileSync, existsSync, mkdirSync, statSync } from 'node:fs';
import { resolve, relative } from 'node:path';
import { canonicalize, signDetached } from './sign.ts';
import {
  ALL_REGIMES,
  isRegime,
  resolveCadence,
  addDaysUtc,
  computeDueState,
  type ResolvedCadence,
  type DueState,
} from './ssdf-annual-attestation.ts';
import { uuidV5 } from './ssdf-satisfaction-matrix.ts';
import type { SsdfSatisfactionMatrix, PracticeStatus } from './ssdf-satisfaction-matrix.ts';
import { augmentCoverageWithSsdfMaterialChange } from './inventory-coverage.ts';

// ─── Constants ────────────────────────────────────────────────────────────────

export const MATERIAL_CHANGE_SCHEMA_VERSION = '1.0' as const;
export const DETECTOR_EMITTER = 'core/ssdf-material-change-detector.ts';
export const DETECTOR_EMITTER_VERSION = '1.0.0';
export const MATERIAL_CHANGE_EVENTS_FILENAME = 'ssdf-material-change-events.json';
export const MATERIAL_CHANGE_EVENTS_SIG_FILENAME = `${MATERIAL_CHANGE_EVENTS_FILENAME}.sig`;
export const ATTESTATION_LEDGER_FILENAME = 'ssdf-attestation-ledger.jsonl';
export const ATTESTATION_SNAPSHOT_DIR = 'ssdf-attestation-snapshots';

/** Fixed namespace UUID for material-change event ids (constant; not secret). */
export const SSDF_EVENT_NAMESPACE = '2b1f8c7d-4e3a-5c9b-a6d0-8f2e1a4c7b30';

const MATRIX_FILE_RE = /^ssdf-satisfaction-matrix(\.[a-z0-9-]+)?\.json$/;

// ─── Product model (realizable subset of per-slice doc §4 config) ─────────────

export interface SsdfFederalAgency {
  id: string;
  name: string;
}

export interface SsdfProduct {
  id: string;
  legal_name: string;
  /** Operator-supplied regime; validated by the cadence engine (isRegime). */
  regime: string;
  critical_software: boolean;
  continuous_delivery: boolean;
  /** Regex (string) matched against the SBOM version to detect a major-version bump. */
  major_version_pattern: string;
  cadence_override_days: number | null;
  poam_extension_allowed: boolean;
  federal_agencies: SsdfFederalAgency[];
}

// ─── Event model (per-slice doc §5.3; per-event provenance collapsed to the ──
// file-level provenance block, consistent with the T.T2/T.T3 emit pattern) ────

export type MaterialChangeKind =
  | 'practice_regression'
  | 'new_untestable_practice'
  | 'major_version_bump'
  | 'ai_augmentation_gap'
  | 'operator_forced'
  | 'regime_change'
  | 'agency_added';

export interface MaterialChangeEvent {
  id: string;
  product_id: string;
  detected_at: string;
  prior_matrix_sha256: string | null;
  current_matrix_sha256: string;
  change_kind: MaterialChangeKind;
  /** Affected SSDF practice ids (e.g. ["PO.1", "PW.7"]); empty for non-practice events. */
  practice_ids: string[];
  triggers_reattestation: boolean;
  notification_due_at: string | null;
  notified_agency_ids: string[];
  notes: string | null;
}

/** Days after `detected_at` the producer should notify the agency, per change kind (§6 Step 7). */
export const NOTIFICATION_DAYS: Record<MaterialChangeKind, number | null> = {
  practice_regression: 14,
  new_untestable_practice: 14,
  ai_augmentation_gap: 14,
  major_version_bump: 30,
  regime_change: 30,
  agency_added: null,
  operator_forced: null,
};

/** Whether a change kind forces interim re-attestation (§6 Step 8). */
export const TRIGGERS_REATTESTATION: Record<MaterialChangeKind, boolean> = {
  practice_regression: true,
  new_untestable_practice: true,
  major_version_bump: true,
  regime_change: true,
  ai_augmentation_gap: false,
  operator_forced: false,
  agency_added: false,
};

// ─── Status-pane DTO (per-slice doc §5.4) ─────────────────────────────────────

export interface AttestationStatusRow {
  product_id: string;
  product_legal_name: string;
  agency_id: string;
  agency_name: string;
  regime: string;
  last_submission_id: string | null;
  last_submitted_at: string | null;
  next_due_at: string | null;
  due_state: DueState;
  open_material_change_event_ids: string[];
  poam_extension_active: boolean;
}

// ─── Deterministic event id (idempotent inserts; §6 Step 9) ───────────────────

/**
 * uuid v5 over `(product_id || prior_matrix_sha256 || current_matrix_sha256 ||
 * change_kind)` so re-runs on identical inputs produce the same id (idempotent).
 */
export function deriveEventId(
  productId: string,
  priorSha: string | null,
  currentSha: string,
  kind: MaterialChangeKind,
): string {
  return uuidV5([productId, priorSha ?? '', currentSha, kind].join('||'), SSDF_EVENT_NAMESPACE);
}

function makeEvent(
  productId: string,
  priorSha: string | null,
  currentSha: string,
  kind: MaterialChangeKind,
  practiceIds: string[],
  detectedAt: string,
  notes: string | null,
): MaterialChangeEvent {
  const notifDays = NOTIFICATION_DAYS[kind];
  return {
    id: deriveEventId(productId, priorSha, currentSha, kind),
    product_id: productId,
    detected_at: detectedAt,
    prior_matrix_sha256: priorSha,
    current_matrix_sha256: currentSha,
    change_kind: kind,
    practice_ids: practiceIds,
    triggers_reattestation: TRIGGERS_REATTESTATION[kind],
    notification_due_at: notifDays === null ? null : addDaysUtc(detectedAt, notifDays),
    notified_agency_ids: [],
    notes,
  };
}

function safeRegExp(pattern: string): RegExp | null {
  if (!pattern) return null;
  try {
    return new RegExp(pattern);
  } catch {
    return null;
  }
}

// ─── Detector (pure; per-slice doc §6 Step 2) ─────────────────────────────────

export interface DetectOptions {
  /** ISO-8601 UTC — `detected_at` for every event this run. */
  currentDate: string;
  /** SHA-256 of the current matrix file bytes. */
  currentMatrixSha256: string;
  /** SHA-256 of the prior matrix snapshot; null on the baseline run. */
  priorMatrixSha256?: string | null;
  /** Practices with an active POA&M-extension override — a regression is suppressed (T.T4-R2). */
  activeOverridePracticeIds?: ReadonlySet<string>;
  /** Regime recorded on the prior submission — a change fires `regime_change`. */
  priorRegime?: string;
  /** Agency ids on prior submissions (undefined = no baseline; suppresses `agency_added`). */
  priorAgencyIds?: readonly string[];
  /** Version recorded on the prior submission (undefined suppresses `major_version_bump`). */
  priorSbomVersion?: string;
  /** Current SBOM version (LOOP-J.J3.b). */
  currentSbomVersion?: string;
  /** Practice ids gapped only in the AI-augmented view (T.T5) — fires `ai_augmentation_gap`. */
  aiAugmentationGapPracticeIds?: readonly string[];
}

/**
 * Diff the prior + current satisfaction matrices for one product and emit the
 * material-change events. Deterministic pure function: identical inputs produce a
 * byte-identical event array (event ids are content-derived — §6 Step 9). At most
 * one event per change kind; each carries the aggregated affected practice ids.
 */
export function detectMaterialChange(
  prior: SsdfSatisfactionMatrix | null,
  current: SsdfSatisfactionMatrix,
  product: SsdfProduct,
  opts: DetectOptions,
): MaterialChangeEvent[] {
  const events: MaterialChangeEvent[] = [];
  const overrides = opts.activeOverridePracticeIds ?? new Set<string>();
  const priorSha = opts.priorMatrixSha256 ?? null;
  const detectedAt = opts.currentDate;
  const currentSha = opts.currentMatrixSha256;
  const emit = (kind: MaterialChangeKind, practiceIds: string[], notes: string | null): void => {
    events.push(makeEvent(product.id, priorSha, currentSha, kind, practiceIds, detectedAt, notes));
  };

  const priorStatus = new Map<string, PracticeStatus>();
  if (prior) for (const p of prior.practices) priorStatus.set(p.id, p.status);
  const currentPractices = current.practices.map((p) => ({ id: p.id, status: p.status }));

  // 1. practice_regression — satisfied → not-satisfied, no active override
  //    (T.T4-R2: `requires-operator-input` is a coverage gap, NOT a regression).
  if (prior) {
    const regressed = currentPractices
      .filter((p) => priorStatus.get(p.id) === 'satisfied' && p.status === 'not-satisfied' && !overrides.has(p.id))
      .map((p) => p.id)
      .sort();
    if (regressed.length) emit('practice_regression', regressed, `practices regressed satisfied→not-satisfied: ${regressed.join(', ')}`);
  }

  // 2. new_untestable_practice — a practice not in prior appears as not-satisfied
  if (prior) {
    const fresh = currentPractices
      .filter((p) => !priorStatus.has(p.id) && p.status === 'not-satisfied')
      .map((p) => p.id)
      .sort();
    if (fresh.length) emit('new_untestable_practice', fresh, `new not-satisfied practices: ${fresh.join(', ')}`);
  }

  // 3. major_version_bump — current SBOM version matches the pattern, prior didn't
  if (opts.currentSbomVersion !== undefined && opts.priorSbomVersion !== undefined) {
    const re = safeRegExp(product.major_version_pattern);
    if (re && re.test(opts.currentSbomVersion) && !re.test(opts.priorSbomVersion)) {
      emit('major_version_bump', [], `SBOM version ${opts.priorSbomVersion} → ${opts.currentSbomVersion} matched ${product.major_version_pattern}`);
    }
  }

  // 4. ai_augmentation_gap — a gap present only in the AI-augmented view (T.T5)
  if (opts.aiAugmentationGapPracticeIds && opts.aiAugmentationGapPracticeIds.length) {
    const ids = [...opts.aiAugmentationGapPracticeIds].sort();
    emit('ai_augmentation_gap', ids, `AI-augmentation gaps (SP 800-218A): ${ids.join(', ')}`);
  }

  // 5. regime_change — product regime differs from the prior submission's regime
  if (opts.priorRegime !== undefined && opts.priorRegime !== product.regime) {
    emit('regime_change', [], `regime ${opts.priorRegime} → ${product.regime}`);
  }

  // 6. agency_added — a federal agency not present on any prior submission
  if (opts.priorAgencyIds !== undefined) {
    const priorSet = new Set(opts.priorAgencyIds);
    const added = product.federal_agencies.map((a) => a.id).filter((id) => !priorSet.has(id)).sort();
    if (added.length) emit('agency_added', [], `agencies added: ${added.join(', ')}`);
  }

  return events;
}

// ─── Status rows (pure; per-slice doc §5.4) ───────────────────────────────────

export interface StatusSubmissionRef {
  last_submission_id: string | null;
  /** ISO-8601 UTC; null means never submitted. */
  last_submitted_at: string | null;
  poam_extension_active?: boolean;
}

/**
 * Render one `AttestationStatusRow` per federal agency for a product. `next_due_at`
 * is the internal review date (submitted_at + cadence); an invalid/absent regime
 * or no submission yields a null `next_due_at` (→ `never_submitted`). Returns an
 * empty array when the product declares no agencies (the caller records the gap).
 */
export function computeStatusRows(
  product: SsdfProduct,
  submission: StatusSubmissionRef,
  openEventIds: readonly string[],
  asOf: string,
): AttestationStatusRow[] {
  let nextDueAt: string | null = null;
  if (submission.last_submitted_at && isRegime(product.regime)) {
    nextDueAt = addDaysUtc(submission.last_submitted_at, resolveCadence(product).days);
  }
  const dueState = computeDueState(nextDueAt, asOf);
  const openIds = [...openEventIds].sort();
  return product.federal_agencies.map((a) => ({
    product_id: product.id,
    product_legal_name: product.legal_name,
    agency_id: a.id,
    agency_name: a.name,
    regime: product.regime,
    last_submission_id: submission.last_submission_id,
    last_submitted_at: submission.last_submitted_at,
    next_due_at: nextDueAt,
    due_state: dueState,
    open_material_change_event_ids: openIds,
    poam_extension_active: submission.poam_extension_active ?? false,
  }));
}

// ─── Emit report shapes ───────────────────────────────────────────────────────

export interface SsdfMaterialChangeProvenance {
  emitter: string;
  emitterVersion: string;
  emittedAt: string;
  sourceCalls: string[];
  sourceDigests: Array<{ kind: string; path: string; sha256: string }>;
  signingKeyId: string;
  algorithm: 'ed25519';
  signatureEd25519: string;
  publicKeyPem: string;
  /** RFC 3161 coverage comes from the run-level manifest TSR; null here. */
  timestampAuthority: string | null;
  coverageDiagnostics: string[];
}

export interface SsdfProductCadenceSummary {
  product_id: string;
  legal_name: string;
  regime: string;
  cadence_days: number | null;
  cadence_basis: string | null;
  last_submitted_at: string | null;
  next_due_at: string | null;
  due_state: DueState;
  /** True when this run is the first snapshot for the product (no prior to diff). */
  baseline: boolean;
  matrix_sha256: string;
  prior_matrix_sha256: string | null;
  events: number;
  diagnostics: string[];
}

export interface SsdfMaterialChangeReport {
  schema_version: typeof MATERIAL_CHANGE_SCHEMA_VERSION;
  generated_at: string;
  csp_name: string;
  products: SsdfProductCadenceSummary[];
  events: MaterialChangeEvent[];
  status_rows: AttestationStatusRow[];
  totals: {
    products: number;
    agencies: number;
    events: number;
    events_triggering_reattestation: number;
    products_never_submitted: number;
  };
  provenance: SsdfMaterialChangeProvenance;
}

/** Thrown when no T.T2 satisfaction matrix is present (T.T2 must run first). */
export class MissingMatrixError extends Error {
  constructor(dir: string) {
    super(`No SSDF satisfaction matrix (ssdf-satisfaction-matrix*.json) found in ${dir}; run T.T2 (--ssdf-attestation) first.`);
    this.name = 'MissingMatrixError';
  }
}

// ─── Matrix + snapshot + ledger I/O ───────────────────────────────────────────

interface LoadedMatrix {
  product_id: string;
  matrix: SsdfSatisfactionMatrix;
  path: string;
  bytes: Buffer;
  sha256: string;
}

function sha256Hex(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

/** Discover + parse every `ssdf-satisfaction-matrix*.json` in a directory (sorted). */
function loadMatrices(dir: string): LoadedMatrix[] {
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return [];
  }
  const out: LoadedMatrix[] = [];
  for (const name of names.sort()) {
    if (!MATRIX_FILE_RE.test(name)) continue;
    const path = resolve(dir, name);
    let bytes: Buffer;
    try {
      if (!statSync(path).isFile()) continue;
      bytes = readFileSync(path);
    } catch {
      continue;
    }
    let matrix: SsdfSatisfactionMatrix;
    try {
      matrix = JSON.parse(bytes.toString('utf8')) as SsdfSatisfactionMatrix;
    } catch {
      continue;
    }
    if (!matrix || !Array.isArray(matrix.practices) || !matrix.product) continue;
    out.push({ product_id: matrix.product.id, matrix, path, bytes, sha256: sha256Hex(bytes) });
  }
  return out;
}

function productSlug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '') || 'product';
}

export interface AttestationLedgerEntry {
  run_id: string;
  product_id: string;
  detected_at: string;
  matrix_sha256: string;
  /** Snapshot path relative to outDir. */
  matrix_snapshot_path: string;
  regime: string;
  agency_ids: string[];
  events: number;
  triggers_reattestation: number;
  next_due_at: string | null;
}

/** Read the append-only ledger grouped by product_id (chronological within a product). */
function readLedger(outDir: string): Map<string, AttestationLedgerEntry[]> {
  const byProduct = new Map<string, AttestationLedgerEntry[]>();
  const path = resolve(outDir, ATTESTATION_LEDGER_FILENAME);
  if (!existsSync(path)) return byProduct;
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    return byProduct;
  }
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let entry: AttestationLedgerEntry;
    try {
      entry = JSON.parse(trimmed) as AttestationLedgerEntry;
    } catch {
      continue;
    }
    if (!entry || typeof entry.product_id !== 'string') continue;
    const list = byProduct.get(entry.product_id) ?? [];
    list.push(entry);
    byProduct.set(entry.product_id, list);
  }
  return byProduct;
}

/** Content-addressed matrix snapshot; idempotent (same bytes → same path, written once). */
function archiveSnapshot(outDir: string, productId: string, sha256: string, bytes: Buffer): string {
  const dir = resolve(outDir, ATTESTATION_SNAPSHOT_DIR, productSlug(productId));
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  const path = resolve(dir, `${sha256}.json`);
  if (!existsSync(path)) writeFileSync(path, bytes);
  return path;
}

function loadSnapshot(outDir: string, relPath: string): SsdfSatisfactionMatrix | null {
  const path = resolve(outDir, relPath);
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as SsdfSatisfactionMatrix;
  } catch {
    return null;
  }
}

function anyNotSatisfied(matrix: SsdfSatisfactionMatrix): boolean {
  for (const p of matrix.practices) {
    if (p.status === 'not-satisfied' || p.status === 'partially-satisfied') return true;
    for (const t of p.tasks) if (t.status === 'not-satisfied' || t.status === 'partially-satisfied') return true;
  }
  return false;
}

function normalizeId(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '');
}

/** Build a minimal product from a matrix when no operator config product matches. */
function synthesizeProduct(matrix: SsdfSatisfactionMatrix): SsdfProduct {
  return {
    id: matrix.product.id,
    legal_name: matrix.product.name,
    regime: matrix.regime,
    critical_software: matrix.product.critical_software === true,
    continuous_delivery: false,
    major_version_pattern: '',
    cadence_override_days: null,
    poam_extension_allowed: true,
    federal_agencies: [],
  };
}

// ─── End-to-end emit (orchestrator entrypoint) ────────────────────────────────

export interface EmitMaterialChangesOptions {
  outDir: string;
  runId: string;
  cspName: string;
  /** Operator config products carrying the extended T.T4 cadence fields. */
  products: SsdfProduct[];
  /** Frozen clock (tests). Defaults to now. */
  generatedAt?: string;
  /** Matrix directory. Defaults to outDir. */
  evidenceDir?: string;
  /** Optional config.yaml path hashed into provenance.sourceDigests. */
  configPath?: string;
}

export interface EmitMaterialChangesResult {
  json_path: string;
  sig_path: string;
  json_sha256: string;
  events: number;
  events_triggering_reattestation: number;
  products_tracked: number;
  status_rows: number;
  baseline_products: number;
}

function toUnsignedReport(report: SsdfMaterialChangeReport): SsdfMaterialChangeReport {
  return {
    ...report,
    provenance: { ...report.provenance, signingKeyId: '', signatureEd25519: '', publicKeyPem: '' },
  };
}

/** Canonical (RFC 8785-style sorted-key) bytes of the signature-blanked report. */
export function serializeUnsignedCanonical(report: SsdfMaterialChangeReport): string {
  return canonicalize(JSON.parse(JSON.stringify(toUnsignedReport(report))));
}

/**
 * Full T.T4 detector pass: load every in-scope T.T2 matrix, diff each against its
 * most recent prior snapshot, compute the material-change events + per-agency
 * cadence rows, sign the report (detached Ed25519 over the canonical
 * signature-blanked bytes), write out/ssdf-material-change-events.json (+ .sig),
 * augment inventory-coverage, archive the current matrices as content-addressed
 * snapshots, and append the run to the ledger. Runs AFTER the T.T2 matrix emit +
 * BEFORE signing so the report is covered by the run manifest + RFC 3161 TSR.
 */
export function emitSsdfMaterialChanges(opts: EmitMaterialChangesOptions): EmitMaterialChangesResult {
  const emittedAt = opts.generatedAt ?? new Date().toISOString();
  const evidenceDir = opts.evidenceDir ?? opts.outDir;

  const matrices = loadMatrices(evidenceDir);
  if (matrices.length === 0) throw new MissingMatrixError(evidenceDir);

  const ledger = readLedger(opts.outDir);
  const productByKey = new Map<string, SsdfProduct>();
  for (const p of opts.products) productByKey.set(normalizeId(p.id), p);

  const coverageDiagnostics: string[] = [];
  const sourceDigests: Array<{ kind: string; path: string; sha256: string }> = [];
  if (opts.configPath && existsSync(opts.configPath)) {
    sourceDigests.push({ kind: 'operator-config', path: opts.configPath, sha256: sha256Hex(readFileSync(opts.configPath)) });
  } else {
    coverageDiagnostics.push('coverage:partial — config.yaml path not provided (product cadence fields hashed in-line only)');
  }

  const allEvents: MaterialChangeEvent[] = [];
  const allRows: AttestationStatusRow[] = [];
  const summaries: SsdfProductCadenceSummary[] = [];
  const newLedgerEntries: AttestationLedgerEntry[] = [];
  let baselineCount = 0;
  let neverSubmitted = 0;

  for (const lm of matrices) {
    sourceDigests.push({ kind: 'ssdf-satisfaction-matrix', path: lm.path, sha256: lm.sha256 });
    const product = productByKey.get(normalizeId(lm.product_id)) ?? synthesizeProduct(lm.matrix);
    const priorEntries = ledger.get(lm.product_id) ?? [];
    const priorEntry = priorEntries.length ? priorEntries[priorEntries.length - 1]! : null;
    const prior = priorEntry ? loadSnapshot(opts.outDir, priorEntry.matrix_snapshot_path) : null;
    const baseline = prior === null;
    if (baseline) baselineCount += 1;

    const diagnostics: string[] = [];

    // Cadence — submitted_at is the matrix generated_at (evidence-as-of; the
    // Common Form the officer signs + submits is built from this snapshot).
    const submittedAt = lm.matrix.generated_at;
    let cadence: ResolvedCadence | null = null;
    let nextDueAt: string | null = null;
    if (isRegime(product.regime)) {
      cadence = resolveCadence(product);
      nextDueAt = addDaysUtc(submittedAt, cadence.days);
    } else {
      const diag = `requires-operator-input: config.yaml ssdf.products[${product.id}].regime (one of ${ALL_REGIMES.join('|')}) — internal review cadence not computed`;
      diagnostics.push(diag);
      coverageDiagnostics.push(diag);
    }
    const dueState = computeDueState(nextDueAt, emittedAt);

    // Detect material changes vs the prior snapshot.
    const events = detectMaterialChange(prior, lm.matrix, product, {
      currentDate: emittedAt,
      currentMatrixSha256: lm.sha256,
      priorMatrixSha256: priorEntry?.matrix_sha256 ?? null,
      priorRegime: priorEntry?.regime,
      priorAgencyIds: priorEntry?.agency_ids,
    });
    allEvents.push(...events);

    // Cadence rows — this run's matrix is the current attestation baseline.
    const submissionId = `${lm.product_id}:${lm.sha256.slice(0, 12)}`;
    const openEventIds = events.filter((e) => e.triggers_reattestation).map((e) => e.id);
    const rows = computeStatusRows(
      product,
      { last_submission_id: submissionId, last_submitted_at: submittedAt, poam_extension_active: product.poam_extension_allowed && anyNotSatisfied(lm.matrix) },
      openEventIds,
      emittedAt,
    );
    if (rows.length === 0) {
      const diag = `requires-operator-input: config.yaml ssdf.products[${product.id}].federal_agencies (>=1 agency) — no per-agency cadence rows emitted`;
      diagnostics.push(diag);
      coverageDiagnostics.push(diag);
    }
    for (const r of rows) if (r.due_state === 'never_submitted') neverSubmitted += 1;
    allRows.push(...rows);

    // Archive the current matrix as a content-addressed snapshot + ledger entry.
    const snapshotPath = archiveSnapshot(opts.outDir, lm.product_id, lm.sha256, lm.bytes);
    newLedgerEntries.push({
      run_id: opts.runId,
      product_id: lm.product_id,
      detected_at: emittedAt,
      matrix_sha256: lm.sha256,
      matrix_snapshot_path: relative(opts.outDir, snapshotPath),
      regime: product.regime,
      agency_ids: product.federal_agencies.map((a) => a.id),
      events: events.length,
      triggers_reattestation: events.filter((e) => e.triggers_reattestation).length,
      next_due_at: nextDueAt,
    });

    summaries.push({
      product_id: product.id,
      legal_name: product.legal_name,
      regime: product.regime,
      cadence_days: cadence ? cadence.days : null,
      cadence_basis: cadence ? cadence.basis : null,
      last_submitted_at: submittedAt,
      next_due_at: nextDueAt,
      due_state: dueState,
      baseline,
      matrix_sha256: lm.sha256,
      prior_matrix_sha256: priorEntry?.matrix_sha256 ?? null,
      events: events.length,
      diagnostics,
    });
  }

  // Deterministic ordering across products.
  allEvents.sort((a, b) => (a.product_id + a.change_kind).localeCompare(b.product_id + b.change_kind, 'en'));
  allRows.sort((a, b) => (a.product_id + a.agency_id).localeCompare(b.product_id + b.agency_id, 'en'));
  summaries.sort((a, b) => a.product_id.localeCompare(b.product_id, 'en'));

  const agencyCount = new Set(allRows.map((r) => `${r.product_id}::${r.agency_id}`)).size;
  const report: SsdfMaterialChangeReport = {
    schema_version: MATERIAL_CHANGE_SCHEMA_VERSION,
    generated_at: emittedAt,
    csp_name: opts.cspName,
    products: summaries,
    events: allEvents,
    status_rows: allRows,
    totals: {
      products: summaries.length,
      agencies: agencyCount,
      events: allEvents.length,
      events_triggering_reattestation: allEvents.filter((e) => e.triggers_reattestation).length,
      products_never_submitted: neverSubmitted,
    },
    provenance: {
      emitter: DETECTOR_EMITTER,
      emitterVersion: DETECTOR_EMITTER_VERSION,
      emittedAt,
      sourceCalls: sourceDigests.map((d) => `${d.kind}:${d.path}`),
      sourceDigests,
      signingKeyId: '',
      algorithm: 'ed25519',
      signatureEd25519: '',
      publicKeyPem: '',
      timestampAuthority: null,
      coverageDiagnostics,
    },
  };

  // Detached signature over the canonical signature-blanked bytes.
  const canonical = serializeUnsignedCanonical(report);
  const sig = signDetached(Buffer.from(canonical, 'utf8'), opts.outDir);
  report.provenance.signingKeyId = sig.keyId;
  report.provenance.publicKeyPem = sig.publicKeyPem;
  report.provenance.signatureEd25519 = sig.signatureBase64;

  if (!existsSync(opts.outDir)) mkdirSync(opts.outDir, { recursive: true });
  const jsonPath = resolve(opts.outDir, MATERIAL_CHANGE_EVENTS_FILENAME);
  const jsonBytes = Buffer.from(JSON.stringify(report, null, 2), 'utf8');
  writeFileSync(jsonPath, jsonBytes);

  const sigPath = resolve(opts.outDir, MATERIAL_CHANGE_EVENTS_SIG_FILENAME);
  writeFileSync(
    sigPath,
    JSON.stringify({ algorithm: 'ed25519', keyId: sig.keyId, publicKeyPem: sig.publicKeyPem, sigBase64: sig.signatureBase64 }, null, 2),
  );

  // Sibling coverage (never a fill-rate cell — G2-safe).
  writeMaterialChangeCoverage(opts.outDir, {
    products_tracked: summaries.length,
    agencies_tracked: agencyCount,
    events_detected: allEvents.length,
    events_triggering_reattestation: allEvents.filter((e) => e.triggers_reattestation).length,
    products_never_submitted: neverSubmitted,
    baseline_products: baselineCount,
  });

  // Append the run to the ledger AFTER the report is written (chronological).
  if (newLedgerEntries.length) {
    appendFileSync(resolve(opts.outDir, ATTESTATION_LEDGER_FILENAME), newLedgerEntries.map((e) => JSON.stringify(e)).join('\n') + '\n');
  }

  return {
    json_path: jsonPath,
    sig_path: sigPath,
    json_sha256: sha256Hex(jsonBytes),
    events: allEvents.length,
    events_triggering_reattestation: allEvents.filter((e) => e.triggers_reattestation).length,
    products_tracked: summaries.length,
    status_rows: allRows.length,
    baseline_products: baselineCount,
  };
}

/** Merge the material-change coverage sibling into out/inventory-coverage.json. */
function writeMaterialChangeCoverage(
  outDir: string,
  counts: {
    products_tracked: number;
    agencies_tracked: number;
    events_detected: number;
    events_triggering_reattestation: number;
    products_never_submitted: number;
    baseline_products: number;
  },
): void {
  const path = resolve(outDir, 'inventory-coverage.json');
  let report: Record<string, unknown> = {};
  if (existsSync(path)) {
    try {
      report = JSON.parse(readFileSync(path, 'utf8'));
    } catch {
      report = {};
    }
  }
  writeFileSync(path, JSON.stringify(augmentCoverageWithSsdfMaterialChange(report, counts), null, 2));
}
