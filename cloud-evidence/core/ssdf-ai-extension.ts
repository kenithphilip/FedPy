/**
 * NIST SP 800-218A SSDF-AI extension — augments the T.T2 satisfaction matrix
 * with the AI-model-specific Recommendations / Considerations / Notes defined in
 * NIST SP 800-218A ("Secure Software Development Practices for Generative AI and
 * Dual-Use Foundation Models: An SSDF Community Profile") for any in-scope
 * product whose LOOP-O.O5 model card declares an AI use case or dual-use
 * foundation-model status (LOOP-T.T5).
 *
 * This is a PURE AUGMENTER: it loads the committed 800-218A catalogue
 * (data/ssdf-800-218A-{ipd,final}.json, produced by scripts/extract-800-218A.mjs
 * VERBATIM from the published NIST PDFs), joins it to the T.T2 matrix
 * (out/ssdf-satisfaction-matrix.json) and the model-card registry
 * (out/model-cards/*.json, LOOP-O.O5), computes per-augmentation status with the
 * same roll-up vocabulary as T.T2, and emits:
 *   - out/ssdf-ai-augmentation.json                    (signed; per-product matrix)
 *   - out/ssdf-satisfaction-matrix.augmented.json      (signed; T.T2 matrix with
 *                                                        augmentations interleaved)
 *   - out/ssdf-ai-augmentation.xlsx                    (operator workbook — T.T5-xlsx)
 *
 * REO compliance:
 *   - Every catalogue field traces to the pinned NIST PDF (its SHA-256 is in the
 *     catalogue provenance + copied into this module's provenance block).
 *   - New evidence collection on AI models is OUT of scope — that is LOOP-O.
 *     T.T5 never fabricates AI evidence; an augmentation with no AI-specific
 *     evidence inherits the parent task status (parent-satisfied ⇒
 *     partially-satisfied) or, for a NEW 800-218A AI task with no base SSDF
 *     parent, is requires-operator-input (REO Rule 4 — never a silent pass).
 *   - Conditional gate: T.T5 runs only when --ssdf-attestation is set AND
 *     config.ssdf.ai_augmentation_enabled === true AND at least one model card
 *     is in AI scope. With LOOP-O.O5 unshipped there are no model cards, so the
 *     orchestrator step no-ops with a coverage:skipped log line — the same
 *     realizable-core / graceful-degradation posture as T.T2/T.T3/T.T4.
 *   - The provenance block cites every input file read with its SHA-256.
 *
 * Spec reconciliation (T.T5.md §2.6/§4.1): the spec assumed an augmentation id
 * pattern `<task>.A<n>`; the published 800-218A uses `<task>.R<n>` /`.C<n>`/`.N<n>`
 * per its §3 legend. The catalogue + this module use the real scheme. 800-218A
 * also re-introduces PW.3.* + PS.1.2/1.3 + PO.5.3 (absent from base SSDF v1.1);
 * those carry `base_task_present:false` and have no T.T2 parent row to inherit.
 * RFC 3161 coverage is provided by the run-level manifest TSR (as with T.T2), not
 * a per-file .tsr.
 */
import { readFileSync, readdirSync, writeFileSync, appendFileSync, existsSync, mkdirSync } from 'node:fs';
import { resolve, basename, join } from 'node:path';
import { createHash } from 'node:crypto';
import { canonicalize, signDetached } from './sign.ts';
import { log } from './log.ts';
import { loadSsdfCatalog } from './ssdf-practices-catalog.ts';
import { uuidV5, type SsdfSatisfactionMatrix, type TaskStatus, type SsdfEvidencePointer } from './ssdf-satisfaction-matrix.ts';

// ─── Filenames + constants ──────────────────────────────────────────────────

export const AI_AUGMENTATION_FILENAME = 'ssdf-ai-augmentation.json';
export const AI_AUGMENTATION_XLSX_FILENAME = 'ssdf-ai-augmentation.xlsx';
export const AUGMENTED_MATRIX_FILENAME = 'ssdf-satisfaction-matrix.augmented.json';
export const AI_AUGMENTATION_LEDGER_FILENAME = 'ssdf-ai-augmentation.jsonl';
export const AI_EXTENSION_EMITTER = 'ssdf-ai-extension';
export const AI_EXTENSION_SCHEMA_VERSION = '1.0' as const;
export const SATISFACTION_MATRIX_FILENAME = 'ssdf-satisfaction-matrix.json';

/** Default committed catalogue paths (relative to repo root at runtime). */
export const IPD_CATALOGUE_PATH = 'data/ssdf-800-218A-ipd.json';
export const FINAL_CATALOGUE_PATH = 'data/ssdf-800-218A-final.json';

const MODEL_CARDS_DIR = 'model-cards';
const AI_KSI_ENVELOPE_RE = /^ksi-.*-AI-.*\.json$/i;

/** The EO lineage every augmented artefact carries so a contracting officer can
 * trace 800-218A's statutory authority after EO 14110's rescission (spec R4). */
export const EO_LINEAGE: string[] = [
  'EO 14028 §4(e)',
  'EO 14110 §4.2(a)(i) (rescinded by EO 14148, 2025-01-20)',
  'NIST SP 800-218A (not withdrawn)',
  'OMB M-26-05 (risk-based tailored regime)',
];

// ─── Status vocabulary ──────────────────────────────────────────────────────

export type AugmentationStatus = TaskStatus | 'not-applicable';
export type AiModelMode = 'generative-ai' | 'dual-use-foundation-model';
export type AugmentationDerivation = 'inherits-parent' | 'ai-specific-evidence' | 'requires-operator-input';

// ─── Catalogue shapes (produced by scripts/extract-800-218A.mjs) ────────────

export interface SsdfAiAugmentation {
  augmentation_id: string; // e.g. 'PO.1.2.R1'
  parent_task_id: string; // e.g. 'PO.1.2'
  item_type: 'R' | 'C' | 'N';
  statement: string;
  notes: string;
  informative_references: string[];
  applies_to: Array<'generative-ai' | 'dual-use-foundation-model' | 'both'>;
}
export interface SsdfAiCatalogueTask {
  task_id: string;
  task_statement: string;
  ssdf_1_1_tag: 'unchanged' | 'modified' | 'not-part-of-ssdf-1.1';
  base_task_present: boolean;
  priority: 'High' | 'Medium' | 'Low' | null;
  no_additions: boolean;
  informative_references: string[];
  augmentations: SsdfAiAugmentation[];
}
export interface SsdfAiCataloguePractice {
  practice_id: string;
  practice_group: 'PO' | 'PS' | 'PW' | 'RV';
  practice_group_name: string;
  practice_name: string;
  tasks: SsdfAiCatalogueTask[];
}
export interface SsdfAiAugmentationCatalogue {
  schema_version: string;
  version: 'IPD' | 'final';
  publication: { sp: string; title: string; publication_date: string };
  sha256_source_pdf: string;
  statistics: { practice_count: number; task_count: number; augmentation_count: number; new_ai_task_count: number };
  practices: SsdfAiCataloguePractice[];
}

// ─── Model card shape (LOOP-O.O5 output; T.T5 reads a projection) ───────────

export interface ModelCard {
  product_id: string;
  model_id: string;
  ai_use_case: string;
  is_dual_use_foundation_model: boolean;
  model_family?: { name?: string; version?: string; upstream_provider?: string | null; parameter_count_estimate?: number | null };
  training_data_provenance?: { datasets?: Array<{ id: string; source_path: string; license: string }>; attestation_pointer?: string | null };
  pre_deployment_evaluations?: Array<{ id: string; report_path: string }>;
  post_deployment_evaluations?: Array<{ id: string; report_path: string }>;
  red_team_engagements?: Array<{ id: string; engagement_path: string }>;
}

// ─── Result shapes ──────────────────────────────────────────────────────────

export interface EvidencePointers {
  ksi_envelope_hashes: string[];
  oscal_observation_uuids: string[];
  poam_item_uuids: string[];
  model_card_pointer: string | null;
  ai_evaluation_report_pointers: string[];
  red_team_engagement_pointers: string[];
  training_data_provenance_pointer: string | null;
}
export interface AugmentationEntry {
  augmentation_id: string;
  item_type: 'R' | 'C' | 'N';
  statement: string;
  notes: string;
  informative_references: string[];
  applies_to: Array<'generative-ai' | 'dual-use-foundation-model' | 'both'>;
  status: AugmentationStatus;
  evidence_pointers: EvidencePointers;
  derivation: AugmentationDerivation;
  derivation_explanation: string;
}
export interface AugmentedTask {
  parent_task_id: string;
  parent_task_status: TaskStatus | null; // null ⇒ new 800-218A AI task (no base parent)
  base_task_present: boolean;
  priority: 'High' | 'Medium' | 'Low' | null;
  parent_task_evidence_pointers: EvidencePointers;
  augmentations: AugmentationEntry[];
}
export interface AugmentedPractice {
  practice_id: string;
  practice_group: 'PO' | 'PS' | 'PW' | 'RV';
  practice_group_name: string;
  practice_name: string;
  tasks: AugmentedTask[];
}
export interface AugmentedProductMatrix {
  product_id: string;
  model_card_path: string;
  model_card_sha256: string;
  ai_use_case: string;
  is_dual_use_foundation_model: boolean;
  ai_specific_evidence_count: number;
  practices: AugmentedPractice[];
}
export interface AiAugmentationRollup {
  total_in_scope: number;
  total_augmentations_evaluated: number;
  satisfied: number;
  partially_satisfied: number;
  not_satisfied: number;
  not_assessed: number;
  requires_operator_input: number;
  not_applicable: number;
}
export interface SsdfAiAugmentationProvenance {
  emitter: string;
  emittedAt: string;
  sourceCalls: string[];
  sourceDigests: Array<{ kind: string; path: string; sha256: string }>;
  signingKeyId: string;
  publicKeyPem: string;
  signatureEd25519: string;
  timestampAuthority: string | null;
  coverageDiagnostics: string[];
}
export interface SsdfAiAugmentationResult {
  schema_version: typeof AI_EXTENSION_SCHEMA_VERSION;
  augmentation_id: string; // deterministic content id
  generated_at: string;
  catalogue_version: 'IPD' | 'final';
  catalogue_secondary_version: 'IPD' | 'final';
  catalogue_sha256: string;
  eo_lineage: string[];
  csp_name: string;
  products_in_scope: AugmentedProductMatrix[];
  products_out_of_scope: Array<{ product_id: string; reason: 'no-model-card' | 'empty-ai-use-case' | 'operator-excluded' }>;
  rollup: AiAugmentationRollup;
  provenance: SsdfAiAugmentationProvenance;
}

// ─── Typed errors ───────────────────────────────────────────────────────────

export class SsdfAiCatalogueIntegrityError extends Error {
  constructor(message: string) {
    super(`ssdf-ai-extension: ${message}`);
    this.name = 'SsdfAiCatalogueIntegrityError';
  }
}
export class MissingSatisfactionMatrixError extends Error {
  constructor(dir: string) {
    super(`ssdf-ai-extension: no T.T2 satisfaction matrix (${SATISFACTION_MATRIX_FILENAME}) found in ${dir}; run T.T2 (--ssdf-attestation) first.`);
    this.name = 'MissingSatisfactionMatrixError';
  }
}

// ─── Loaders ────────────────────────────────────────────────────────────────

function sha256File(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}
function sha256Buf(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

/** Load + shape-validate an 800-218A augmentation catalogue. */
export function loadAugmentationCatalogue(path: string, baseTaskIds?: Set<string>): SsdfAiAugmentationCatalogue {
  if (!existsSync(path)) throw new SsdfAiCatalogueIntegrityError(`catalogue not found at ${path}; run npm run build:ssdf-ai-catalog`);
  let cat: SsdfAiAugmentationCatalogue;
  try {
    cat = JSON.parse(readFileSync(path, 'utf8')) as SsdfAiAugmentationCatalogue;
  } catch (e) {
    throw new SsdfAiCatalogueIntegrityError(`catalogue at ${path} is not valid JSON: ${(e as Error)?.message ?? e}`);
  }
  // Shape check only — catalogue richness (all 4 SSDF groups, 48 tasks) is
  // enforced by the extractor at build time; the loader validates non-emptiness
  // + per-task/parent-join integrity so small test catalogues remain loadable.
  if (!cat || !Array.isArray(cat.practices) || cat.practices.length < 1) {
    throw new SsdfAiCatalogueIntegrityError(`catalogue at ${path} has no practices`);
  }
  const base = baseTaskIds ?? loadBaseTaskIds();
  for (const p of cat.practices) {
    for (const t of p.tasks) {
      if (!t.task_id || !t.task_statement) throw new SsdfAiCatalogueIntegrityError(`catalogue task ${t.task_id ?? '<unknown>'} has an empty statement`);
      // Integrity: a base-present task must actually exist in the base catalogue.
      if (t.base_task_present && !base.has(t.task_id)) {
        throw new SsdfAiCatalogueIntegrityError(`task ${t.task_id} is flagged base_task_present but does not exist in the base SSDF v1.1 catalogue`);
      }
      for (const a of t.augmentations) {
        if (a.parent_task_id !== t.task_id) {
          throw new SsdfAiCatalogueIntegrityError(`augmentation ${a.augmentation_id} parent ${a.parent_task_id} does not match its task ${t.task_id}`);
        }
        if (!a.statement) throw new SsdfAiCatalogueIntegrityError(`augmentation ${a.augmentation_id} has an empty statement`);
      }
    }
  }
  return cat;
}

function loadBaseTaskIds(): Set<string> {
  const cat = loadSsdfCatalog();
  const ids = new Set<string>();
  for (const p of cat.practices) for (const t of p.tasks) ids.add(t.id);
  return ids;
}

/** Walk out/model-cards/*.json (LOOP-O.O5). Absent dir ⇒ []. */
export function loadModelCards(outDir: string): Array<{ card: ModelCard; path: string; sha256: string }> {
  const dir = resolve(outDir, MODEL_CARDS_DIR);
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return [];
  }
  const out: Array<{ card: ModelCard; path: string; sha256: string }> = [];
  for (const name of names.sort()) {
    if (!name.endsWith('.json')) continue;
    const path = join(dir, name);
    let bytes: Buffer;
    let card: ModelCard;
    try {
      bytes = readFileSync(path);
      card = JSON.parse(bytes.toString('utf8')) as ModelCard;
    } catch {
      continue;
    }
    if (!card || typeof card.product_id !== 'string') continue;
    out.push({ card, path, sha256: sha256Buf(bytes) });
  }
  return out;
}

/** True when a model card puts its product in 800-218A scope. */
export function isModelCardInScope(card: ModelCard): boolean {
  return (typeof card.ai_use_case === 'string' && card.ai_use_case.trim() !== '') || card.is_dual_use_foundation_model === true;
}

/** AI-specific KSI envelopes (out/ksi-evidence/ksi-*-AI-*.json). Absent ⇒ Map(). */
function loadAiKsiEnvelopes(outDir: string): Map<string, string[]> {
  // augmentation_id -> [envelope sha256, ...] for envelopes whose findings
  // reference that augmentation id.
  const byAug = new Map<string, string[]>();
  const dir = resolve(outDir, 'ksi-evidence');
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return byAug;
  }
  for (const name of names.sort()) {
    if (!AI_KSI_ENVELOPE_RE.test(name)) continue;
    const path = join(dir, name);
    let doc: any;
    let sha: string;
    try {
      const bytes = readFileSync(path);
      sha = sha256Buf(bytes);
      doc = JSON.parse(bytes.toString('utf8'));
    } catch {
      continue;
    }
    const refs = collectAugmentationRefs(doc);
    for (const augId of refs) {
      if (!byAug.has(augId)) byAug.set(augId, []);
      byAug.get(augId)!.push(sha);
    }
  }
  return byAug;
}

/** Pull any `augmentation_id` / `ssdf_ai_augmentation` references out of an envelope's findings. */
function collectAugmentationRefs(doc: any): Set<string> {
  const refs = new Set<string>();
  const scan = (finding: any) => {
    for (const key of ['augmentation_id', 'ssdf_ai_augmentation', 'ssdf_augmentation_id']) {
      const v = finding?.[key];
      if (typeof v === 'string' && v) refs.add(v);
      if (Array.isArray(v)) for (const x of v) if (typeof x === 'string' && x) refs.add(x);
    }
  };
  for (const p of doc?.providers ?? []) for (const f of p?.findings ?? []) scan(f);
  for (const f of doc?.findings ?? []) scan(f);
  return refs;
}

// ─── Derivation (pure; per T.T5.md §6 step 6, adapted for new AI tasks) ──────

export interface DeriveInput {
  augmentation: SsdfAiAugmentation;
  parentStatus: TaskStatus | null; // null ⇒ no base parent
  mode: AiModelMode;
  aiEvidencePresent: boolean;
}
export interface DeriveOutput {
  status: AugmentationStatus;
  derivation: AugmentationDerivation;
  explanation: string;
}

export function deriveAugmentationStatus(inp: DeriveInput): DeriveOutput {
  const { augmentation, parentStatus, mode, aiEvidencePresent } = inp;
  // applies_to filter: 'both' always applies; otherwise the model mode must match.
  if (!augmentation.applies_to.includes('both') && !augmentation.applies_to.includes(mode)) {
    return { status: 'not-applicable', derivation: 'inherits-parent', explanation: `model mode "${mode}" is not in the augmentation's applies_to set` };
  }
  // NEW 800-218A AI task with no base SSDF parent: nothing to inherit.
  if (parentStatus === null) {
    if (aiEvidencePresent) return { status: 'satisfied', derivation: 'ai-specific-evidence', explanation: 'new 800-218A AI task; AI-specific evidence present' };
    return { status: 'requires-operator-input', derivation: 'requires-operator-input', explanation: 'new 800-218A AI task with no base SSDF parent and no AI-specific evidence; operator must classify' };
  }
  if (parentStatus === 'not-assessed') {
    return { status: 'not-assessed', derivation: 'inherits-parent', explanation: 'parent task not assessed' };
  }
  if (aiEvidencePresent) {
    if (parentStatus === 'satisfied') return { status: 'satisfied', derivation: 'ai-specific-evidence', explanation: 'parent satisfied + AI-specific evidence present' };
    if (parentStatus === 'partially-satisfied') return { status: 'partially-satisfied', derivation: 'ai-specific-evidence', explanation: 'parent partial; AI-specific evidence present' };
    // parent not-satisfied / requires-operator-input but AI evidence exists.
    return { status: 'partially-satisfied', derivation: 'ai-specific-evidence', explanation: `parent ${parentStatus}; AI-specific evidence present` };
  }
  // No AI-specific evidence yet.
  if (parentStatus === 'satisfied') return { status: 'partially-satisfied', derivation: 'inherits-parent', explanation: 'parent satisfied but no AI-specific evidence yet' };
  if (parentStatus === 'not-satisfied') return { status: 'not-satisfied', derivation: 'inherits-parent', explanation: 'parent not satisfied + no AI evidence' };
  return { status: 'requires-operator-input', derivation: 'requires-operator-input', explanation: 'operator must classify (no AI-specific evidence; parent requires operator input)' };
}

// ─── Evidence-pointer merge ─────────────────────────────────────────────────

function emptyPointers(): EvidencePointers {
  return {
    ksi_envelope_hashes: [],
    oscal_observation_uuids: [],
    poam_item_uuids: [],
    model_card_pointer: null,
    ai_evaluation_report_pointers: [],
    red_team_engagement_pointers: [],
    training_data_provenance_pointer: null,
  };
}

/** Project a T.T2 task's typed evidence pointers into the flat T.T5 shape. */
function parentPointers(pointers: SsdfEvidencePointer[]): EvidencePointers {
  const ep = emptyPointers();
  for (const p of pointers) {
    if (p.kind === 'ksi-envelope') ep.ksi_envelope_hashes.push(p.envelope_sha256);
    else if (p.kind === 'oscal-observation') ep.oscal_observation_uuids.push(p.observation_uuid);
    else if (p.kind === 'oscal-poam-item') ep.poam_item_uuids.push(p.poam_item_uuid);
  }
  return ep;
}

/** AI-specific evidence pointers from the model card + AI KSI envelopes. */
function aiPointers(
  modelCardPath: string,
  card: ModelCard,
  aiKsiHashes: string[],
): EvidencePointers {
  const ep = emptyPointers();
  ep.model_card_pointer = basename(modelCardPath);
  for (const e of card.pre_deployment_evaluations ?? []) if (e?.report_path) ep.ai_evaluation_report_pointers.push(e.report_path);
  for (const e of card.post_deployment_evaluations ?? []) if (e?.report_path) ep.ai_evaluation_report_pointers.push(e.report_path);
  for (const e of card.red_team_engagements ?? []) if (e?.engagement_path) ep.red_team_engagement_pointers.push(e.engagement_path);
  ep.training_data_provenance_pointer = card.training_data_provenance?.attestation_pointer ?? null;
  ep.ksi_envelope_hashes.push(...aiKsiHashes);
  return ep;
}

function mergePointers(parent: EvidencePointers, ai: EvidencePointers): EvidencePointers {
  return {
    ksi_envelope_hashes: dedupe([...parent.ksi_envelope_hashes, ...ai.ksi_envelope_hashes]),
    oscal_observation_uuids: dedupe([...parent.oscal_observation_uuids, ...ai.oscal_observation_uuids]),
    poam_item_uuids: dedupe([...parent.poam_item_uuids, ...ai.poam_item_uuids]),
    model_card_pointer: ai.model_card_pointer ?? parent.model_card_pointer,
    ai_evaluation_report_pointers: dedupe([...parent.ai_evaluation_report_pointers, ...ai.ai_evaluation_report_pointers]),
    red_team_engagement_pointers: dedupe([...parent.red_team_engagement_pointers, ...ai.red_team_engagement_pointers]),
    training_data_provenance_pointer: ai.training_data_provenance_pointer ?? parent.training_data_provenance_pointer,
  };
}

function dedupe(xs: string[]): string[] {
  return [...new Set(xs)];
}

function hasAiEvidence(card: ModelCard, aiKsiHashes: string[]): boolean {
  return (
    (card.pre_deployment_evaluations?.length ?? 0) > 0 ||
    (card.post_deployment_evaluations?.length ?? 0) > 0 ||
    (card.red_team_engagements?.length ?? 0) > 0 ||
    (card.training_data_provenance?.attestation_pointer != null && card.training_data_provenance.attestation_pointer !== '') ||
    aiKsiHashes.length > 0
  );
}

// ─── Matrix index (parent task lookup) ──────────────────────────────────────

interface MatrixTaskIndex {
  statusByTask: Map<string, TaskStatus>;
  pointersByTask: Map<string, SsdfEvidencePointer[]>;
}
function indexMatrix(matrix: SsdfSatisfactionMatrix): MatrixTaskIndex {
  const statusByTask = new Map<string, TaskStatus>();
  const pointersByTask = new Map<string, SsdfEvidencePointer[]>();
  for (const p of matrix.practices ?? []) {
    for (const t of p.tasks ?? []) {
      statusByTask.set(t.id, t.status);
      pointersByTask.set(t.id, t.evidence_pointers ?? []);
    }
  }
  return { statusByTask, pointersByTask };
}

// ─── Build (pure) ───────────────────────────────────────────────────────────

export interface BuildAiAugmentationOptions {
  outDir: string;
  cspName: string;
  catalogue: SsdfAiAugmentationCatalogue;
  secondaryCatalogueVersion: 'IPD' | 'final';
  matrix: SsdfSatisfactionMatrix;
  matrixSha256: string;
  modelCards: Array<{ card: ModelCard; path: string; sha256: string }>;
  aiKsiByAugmentation: Map<string, string[]>;
  productsInScopeOverride?: string[];
  generatedAt?: string;
  coverageDiagnostics?: string[];
  sourceDigests?: Array<{ kind: string; path: string; sha256: string }>;
}

export function buildAiAugmentation(opts: BuildAiAugmentationOptions): SsdfAiAugmentationResult {
  const generatedAt = opts.generatedAt ?? new Date().toISOString();
  const matrixIndex = indexMatrix(opts.matrix);
  const override = opts.productsInScopeOverride && opts.productsInScopeOverride.length > 0 ? new Set(opts.productsInScopeOverride) : null;

  const productsInScope: AugmentedProductMatrix[] = [];
  const productsOutOfScope: SsdfAiAugmentationResult['products_out_of_scope'] = [];

  const rollup: AiAugmentationRollup = {
    total_in_scope: 0,
    total_augmentations_evaluated: 0,
    satisfied: 0,
    partially_satisfied: 0,
    not_satisfied: 0,
    not_assessed: 0,
    requires_operator_input: 0,
    not_applicable: 0,
  };

  for (const entry of opts.modelCards) {
    const card = entry.card;
    if (!isModelCardInScope(card)) {
      productsOutOfScope.push({ product_id: card.product_id, reason: 'empty-ai-use-case' });
      continue;
    }
    if (override && !override.has(card.product_id)) {
      productsOutOfScope.push({ product_id: card.product_id, reason: 'operator-excluded' });
      continue;
    }

    const mode: AiModelMode = card.is_dual_use_foundation_model === true ? 'dual-use-foundation-model' : 'generative-ai';
    let aiEvidenceCount = 0;
    const practices: AugmentedPractice[] = [];

    for (const cp of opts.catalogue.practices) {
      const outTasks: AugmentedTask[] = [];
      for (const ct of cp.tasks) {
        if (ct.augmentations.length === 0) continue; // "No additions to SSDF 1.1" — nothing to augment
        const parentStatus = matrixIndex.statusByTask.get(ct.task_id) ?? null;
        const parentPtrs = parentPointers(matrixIndex.pointersByTask.get(ct.task_id) ?? []);

        const augEntries: AugmentationEntry[] = ct.augmentations.map((a) => {
          const aiKsiHashes = opts.aiKsiByAugmentation.get(a.augmentation_id) ?? [];
          const aiPresent = hasAiEvidence(card, aiKsiHashes);
          if (aiPresent) aiEvidenceCount++;
          const d = deriveAugmentationStatus({ augmentation: a, parentStatus, mode, aiEvidencePresent: aiPresent });
          const ai = aiPointers(entry.path, card, aiKsiHashes);
          const pointers = mergePointers(parentPtrs, ai);
          rollup.total_augmentations_evaluated++;
          tallyStatus(rollup, d.status);
          return {
            augmentation_id: a.augmentation_id,
            item_type: a.item_type,
            statement: a.statement,
            notes: a.notes,
            informative_references: a.informative_references,
            applies_to: a.applies_to,
            status: d.status,
            evidence_pointers: pointers,
            derivation: d.derivation,
            derivation_explanation: d.explanation,
          };
        });

        outTasks.push({
          parent_task_id: ct.task_id,
          parent_task_status: parentStatus,
          base_task_present: ct.base_task_present,
          priority: ct.priority,
          parent_task_evidence_pointers: parentPtrs,
          augmentations: augEntries,
        });
      }
      if (outTasks.length > 0) {
        practices.push({
          practice_id: cp.practice_id,
          practice_group: cp.practice_group,
          practice_group_name: cp.practice_group_name,
          practice_name: cp.practice_name,
          tasks: outTasks,
        });
      }
    }

    productsInScope.push({
      product_id: card.product_id,
      model_card_path: basename(entry.path),
      model_card_sha256: entry.sha256,
      ai_use_case: card.ai_use_case,
      is_dual_use_foundation_model: card.is_dual_use_foundation_model === true,
      ai_specific_evidence_count: aiEvidenceCount,
      practices,
    });
    rollup.total_in_scope++;
  }

  const augmentationId = uuidV5(
    canonicalize({
      catalogue_sha256: opts.catalogue.sha256_source_pdf,
      products: productsInScope.map((p) => ({ id: p.product_id, card: p.model_card_sha256 })).sort((a, b) => a.id.localeCompare(b.id, 'en')),
      matrix: opts.matrixSha256,
    }),
  );

  return {
    schema_version: AI_EXTENSION_SCHEMA_VERSION,
    augmentation_id: augmentationId,
    generated_at: generatedAt,
    catalogue_version: opts.catalogue.version,
    catalogue_secondary_version: opts.secondaryCatalogueVersion,
    catalogue_sha256: opts.catalogue.sha256_source_pdf,
    eo_lineage: EO_LINEAGE,
    csp_name: opts.cspName,
    products_in_scope: productsInScope,
    products_out_of_scope: productsOutOfScope,
    rollup,
    provenance: {
      emitter: AI_EXTENSION_EMITTER,
      emittedAt: generatedAt,
      sourceCalls: (opts.sourceDigests ?? []).map((d) => `${d.kind}:${d.path}`),
      sourceDigests: opts.sourceDigests ?? [],
      signingKeyId: '',
      publicKeyPem: '',
      signatureEd25519: '',
      timestampAuthority: null,
      coverageDiagnostics: opts.coverageDiagnostics ?? [],
    },
  };
}

function tallyStatus(rollup: AiAugmentationRollup, status: AugmentationStatus): void {
  switch (status) {
    case 'satisfied': rollup.satisfied++; break;
    case 'partially-satisfied': rollup.partially_satisfied++; break;
    case 'not-satisfied': rollup.not_satisfied++; break;
    case 'not-assessed': rollup.not_assessed++; break;
    case 'requires-operator-input': rollup.requires_operator_input++; break;
    case 'not-applicable': rollup.not_applicable++; break;
  }
}

// ─── Augmented satisfaction matrix (guardrail-safe re-emit) ──────────────────

/**
 * Re-emit the canonical T.T2 matrix with 800-218A augmentations interleaved
 * under each parent task (as `ai_augmentations[]`, NOT as sibling task rows — so
 * scripts/check-ssdf-no-silent-pass.mjs still sees only the base tasks). New
 * 800-218A AI tasks (no base parent) are appended as task rows carrying their
 * real evidence pointers; an evidence-less new task is `requires-operator-input`
 * so it never trips the no-silent-pass guardrail.
 */
export function buildAugmentedMatrix(
  matrix: SsdfSatisfactionMatrix,
  productMatrix: AugmentedProductMatrix | null,
  catalogue: SsdfAiAugmentationCatalogue,
): SsdfSatisfactionMatrix {
  const clone: SsdfSatisfactionMatrix = JSON.parse(JSON.stringify(matrix));
  const augByTask = new Map<string, AugmentationEntry[]>();
  const newTaskRows = new Map<string, AugmentedTask>();
  if (productMatrix) {
    for (const p of productMatrix.practices) {
      for (const t of p.tasks) {
        augByTask.set(t.parent_task_id, t.augmentations);
        if (!t.base_task_present) newTaskRows.set(t.parent_task_id, t);
      }
    }
  }

  // Attach ai_augmentations to existing base tasks.
  for (const p of clone.practices) {
    for (const t of p.tasks as any[]) {
      t.ai_augmentations = augByTask.get(t.id) ?? [];
    }
  }

  // Append the new 800-218A AI tasks (no base parent) as guardrail-safe rows.
  for (const cp of catalogue.practices) {
    let target = clone.practices.find((p) => p.id === cp.practice_id);
    if (!target) {
      target = {
        id: cp.practice_id,
        group: cp.practice_group,
        name: cp.practice_name,
        outcome: '',
        status: 'requires-operator-input',
        open_risk_score: null,
        tasks_by_status: { 'satisfied': 0, 'partially-satisfied': 0, 'not-satisfied': 0, 'not-assessed': 0, 'requires-operator-input': 0 },
        tasks: [],
      };
      clone.practices.push(target);
    }
    for (const ct of cp.tasks) {
      if (ct.base_task_present) continue;
      if (target.tasks.some((t) => t.id === ct.task_id)) continue;
      const row = newTaskRows.get(ct.task_id);
      const pointers: SsdfEvidencePointer[] = [];
      let status: TaskStatus = 'requires-operator-input';
      if (row) {
        // Surface AI evidence as ksi-envelope pointers so a satisfied new task
        // carries defensible pointers (no-silent-pass safe).
        for (const a of row.augmentations) {
          for (const h of a.evidence_pointers.ksi_envelope_hashes) {
            pointers.push({ kind: 'ksi-envelope', ksi_id: a.augmentation_id, envelope_sha256: h, signing_key_id: 'ai-ksi', signature_verified: false, source_path: a.evidence_pointers.model_card_pointer ?? 'model-card' });
          }
        }
        status = pointers.length > 0 ? 'partially-satisfied' : 'requires-operator-input';
      }
      (target.tasks as any[]).push({
        id: ct.task_id,
        statement: ct.task_statement,
        status,
        nist_800_53_r5_controls: [],
        crosswalk_ksi: [],
        common_form_section_ref: [],
        evidence_pointers: pointers,
        open_risk_score: null,
        diagnostics: status === 'requires-operator-input'
          ? [`requires-operator-input: ${ct.task_id} — new NIST SP 800-218A AI task (not part of base SSDF v1.1); no AI-specific evidence joined`]
          : [],
        ai_augmentations: augByTask.get(ct.task_id) ?? [],
      });
    }
  }

  (clone as any).ssdf_ai_extension = {
    catalogue_version: catalogue.version,
    catalogue_sha256: catalogue.sha256_source_pdf,
    eo_lineage: EO_LINEAGE,
    augmented: productMatrix !== null,
  };
  return clone;
}

// ─── Emit (gate + build + sign + write) ─────────────────────────────────────

export interface EmitAiAugmentationOptions {
  outDir: string;
  runId: string;
  cspName: string;
  /** config.ssdf.ai_augmentation_enabled — explicit opt-in (default false). */
  aiAugmentationEnabled: boolean;
  /** 'IPD' (spec default) | 'final'. */
  primaryCatalogue?: 'IPD' | 'final';
  productsInScope?: string[];
  ipdCataloguePath?: string;
  finalCataloguePath?: string;
  generatedAt?: string;
  writeXlsx?: boolean;
  /** Render function injected to avoid a hard dependency cycle with the xlsx module. */
  renderXlsx?: (result: SsdfAiAugmentationResult, catalogue: SsdfAiAugmentationCatalogue, delta: unknown) => Buffer;
  deltaPath?: string;
}

export type EmitAiAugmentationResult =
  | { skipped: true; reason: string }
  | {
      skipped: false;
      json_path: string;
      augmented_matrix_path: string;
      xlsx_path: string | null;
      augmentation_id: string;
      json_sha256: string;
      rollup: AiAugmentationRollup;
      products_in_scope: number;
      products_out_of_scope: number;
    };

export function emitSsdfAiAugmentation(opts: EmitAiAugmentationOptions): EmitAiAugmentationResult {
  // ── Conditional gate ──
  if (!opts.aiAugmentationEnabled) {
    log.info({ event: 't.t5.skipped', reason: 'ai-augmentation-disabled' });
    return { skipped: true, reason: 'ai-augmentation-disabled' };
  }
  const modelCards = loadModelCards(opts.outDir);
  if (modelCards.length === 0) {
    log.info({ event: 't.t5.skipped', reason: 'no-model-cards' });
    return { skipped: true, reason: 'no-model-cards' };
  }
  const inScopeCards = modelCards.filter((m) => isModelCardInScope(m.card));
  if (inScopeCards.length === 0) {
    log.info({ event: 't.t5.skipped', reason: 'no-ai-products-in-scope' });
    return { skipped: true, reason: 'no-ai-products-in-scope' };
  }

  // ── Matrix (required) ──
  const matrixPath = resolve(opts.outDir, SATISFACTION_MATRIX_FILENAME);
  if (!existsSync(matrixPath)) throw new MissingSatisfactionMatrixError(opts.outDir);
  const matrixBytes = readFileSync(matrixPath);
  const matrix = JSON.parse(matrixBytes.toString('utf8')) as SsdfSatisfactionMatrix;
  const matrixSha = sha256Buf(matrixBytes);

  // ── Catalogues ──
  const primary = opts.primaryCatalogue ?? 'IPD';
  const ipdPath = resolve(opts.outDir, '..', opts.ipdCataloguePath ?? IPD_CATALOGUE_PATH);
  const finalPath = resolve(opts.outDir, '..', opts.finalCataloguePath ?? FINAL_CATALOGUE_PATH);
  const baseIds = loadBaseTaskIds();
  const ipdCat = existsSync(ipdPath) ? loadAugmentationCatalogue(ipdPath, baseIds) : null;
  const finalCat = existsSync(finalPath) ? loadAugmentationCatalogue(finalPath, baseIds) : null;
  const catalogue = primary === 'final' ? (finalCat ?? ipdCat) : (ipdCat ?? finalCat);
  if (!catalogue) throw new SsdfAiCatalogueIntegrityError(`no 800-218A catalogue found (looked for ${ipdPath} and ${finalPath}); run npm run build:ssdf-ai-catalog`);
  const secondary: 'IPD' | 'final' = catalogue.version === 'IPD' ? 'final' : 'IPD';

  // ── Optional inputs / provenance sources ──
  const aiKsiByAug = loadAiKsiEnvelopes(opts.outDir);
  const coverageDiagnostics: string[] = [];
  if (aiKsiByAug.size === 0) coverageDiagnostics.push('coverage:partial — no AI-specific KSI envelopes (out/ksi-evidence/ksi-*-AI-*.json) present; augmentation status inherits parent tasks (LOOP-O collectors not yet run)');
  for (const p of inScopeCards) {
    if (!hasAiEvidence(p.card, [])) coverageDiagnostics.push(`coverage:partial — product ${p.card.product_id} declares an AI use case but carries no AI-specific evidence (no evaluations / red-team / training-provenance); augmentations inherit parent tasks`);
  }
  const sourceDigests: Array<{ kind: string; path: string; sha256: string }> = [
    { kind: 'augmentation-catalogue', path: primary === 'final' ? FINAL_CATALOGUE_PATH : IPD_CATALOGUE_PATH, sha256: catalogue.sha256_source_pdf },
    { kind: 'satisfaction-matrix', path: SATISFACTION_MATRIX_FILENAME, sha256: matrixSha },
  ];
  for (const m of inScopeCards) sourceDigests.push({ kind: 'model-card', path: basename(m.path), sha256: m.sha256 });

  const generatedAt = opts.generatedAt ?? new Date().toISOString();

  // ── Build ──
  const result = buildAiAugmentation({
    outDir: opts.outDir,
    cspName: opts.cspName,
    catalogue,
    secondaryCatalogueVersion: secondary,
    matrix,
    matrixSha256: matrixSha,
    modelCards,
    aiKsiByAugmentation: aiKsiByAug,
    productsInScopeOverride: opts.productsInScope,
    generatedAt,
    coverageDiagnostics,
    sourceDigests,
  });

  if (!existsSync(opts.outDir)) mkdirSync(opts.outDir, { recursive: true });

  // ── Sign the primary JSON (detached Ed25519 over canonical blanked bytes) ──
  const unsigned = { ...result, provenance: { ...result.provenance, signingKeyId: '', publicKeyPem: '', signatureEd25519: '' } };
  const canonical = canonicalize(JSON.parse(JSON.stringify(unsigned)));
  const sig = signDetached(Buffer.from(canonical, 'utf8'), opts.outDir);
  result.provenance.signingKeyId = sig.keyId;
  result.provenance.publicKeyPem = sig.publicKeyPem;
  result.provenance.signatureEd25519 = sig.signatureBase64;

  const jsonPath = resolve(opts.outDir, AI_AUGMENTATION_FILENAME);
  const jsonBytes = Buffer.from(JSON.stringify(result, null, 2), 'utf8');
  writeFileSync(jsonPath, jsonBytes);
  writeFileSync(resolve(opts.outDir, `${AI_AUGMENTATION_FILENAME}.sig`), JSON.stringify({ algorithm: 'ed25519', keyId: sig.keyId, publicKeyPem: sig.publicKeyPem, sigBase64: sig.signatureBase64 }, null, 2));

  // ── Augmented matrix (canonical product = matrix.product if in scope, else first) ──
  const canonicalProduct =
    result.products_in_scope.find((p) => p.product_id === matrix.product?.id) ?? result.products_in_scope[0] ?? null;
  const augmentedMatrix = buildAugmentedMatrix(matrix, canonicalProduct, catalogue);
  const augUnsigned = { ...augmentedMatrix, provenance: { ...augmentedMatrix.provenance, signingKeyId: '', publicKeyPem: '', signatureEd25519: '' } };
  const augCanonical = canonicalize(JSON.parse(JSON.stringify(augUnsigned)));
  const augSig = signDetached(Buffer.from(augCanonical, 'utf8'), opts.outDir);
  augmentedMatrix.provenance.emitter = AI_EXTENSION_EMITTER;
  augmentedMatrix.provenance.signingKeyId = augSig.keyId;
  augmentedMatrix.provenance.publicKeyPem = augSig.publicKeyPem;
  augmentedMatrix.provenance.signatureEd25519 = augSig.signatureBase64;
  const augPath = resolve(opts.outDir, AUGMENTED_MATRIX_FILENAME);
  writeFileSync(augPath, Buffer.from(JSON.stringify(augmentedMatrix, null, 2), 'utf8'));
  writeFileSync(resolve(opts.outDir, `${AUGMENTED_MATRIX_FILENAME}.sig`), JSON.stringify({ algorithm: 'ed25519', keyId: augSig.keyId, publicKeyPem: augSig.publicKeyPem, sigBase64: augSig.signatureBase64 }, null, 2));

  // ── XLSX (optional; injected renderer) ──
  let xlsxPath: string | null = null;
  if (opts.writeXlsx !== false && opts.renderXlsx) {
    let delta: unknown = null;
    const dp = opts.deltaPath ? resolve(opts.outDir, '..', opts.deltaPath) : null;
    if (dp && existsSync(dp)) {
      try { delta = JSON.parse(readFileSync(dp, 'utf8')); } catch { delta = null; }
    }
    xlsxPath = resolve(opts.outDir, AI_AUGMENTATION_XLSX_FILENAME);
    writeFileSync(xlsxPath, opts.renderXlsx(result, catalogue, delta));
  }

  // ── Ledger + coverage ──
  appendFileSync(
    resolve(opts.outDir, AI_AUGMENTATION_LEDGER_FILENAME),
    JSON.stringify({ run_id: opts.runId, augmentation_id: result.augmentation_id, generated_at: result.generated_at, catalogue_version: result.catalogue_version, products_in_scope: result.products_in_scope.length, rollup: result.rollup, json_sha256: sha256Buf(jsonBytes) }) + '\n',
  );
  augmentCoverage(opts.outDir, result);

  log.info({ event: 't.t5.emitted', path: jsonPath, products_in_scope: result.products_in_scope.length, augmentations: result.rollup.total_augmentations_evaluated, requires_operator_input: result.rollup.requires_operator_input, ephemeral_key: sig.ephemeralKey });

  return {
    skipped: false,
    json_path: jsonPath,
    augmented_matrix_path: augPath,
    xlsx_path: xlsxPath,
    augmentation_id: result.augmentation_id,
    json_sha256: sha256Buf(jsonBytes),
    rollup: result.rollup,
    products_in_scope: result.products_in_scope.length,
    products_out_of_scope: result.products_out_of_scope.length,
  };
}

/** Additive-only augmentation of inventory-coverage.json (never a G2 regression). */
function augmentCoverage(outDir: string, result: SsdfAiAugmentationResult): void {
  const covPath = resolve(outDir, 'inventory-coverage.json');
  if (!existsSync(covPath)) return;
  try {
    const cov = JSON.parse(readFileSync(covPath, 'utf8'));
    const ext = (cov.ssdf_ai_augmentation_coverage ??= {});
    for (const p of result.products_in_scope) {
      let evaluated = 0;
      let satisfied = 0;
      for (const pr of p.practices) for (const t of pr.tasks) for (const a of t.augmentations) { evaluated++; if (a.status === 'satisfied') satisfied++; }
      ext[p.product_id] = {
        augmentations_evaluated: evaluated,
        augmentations_satisfied: satisfied,
        ai_specific_evidence_count: p.ai_specific_evidence_count,
        catalogue_version: result.catalogue_version,
      };
    }
    writeFileSync(covPath, JSON.stringify(cov, null, 2));
  } catch (e) {
    log.warn({ event: 't.t5.coverage_augment_failed', err: String((e as Error)?.message ?? e) });
  }
}
