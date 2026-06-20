/**
 * SSDF satisfaction-matrix typedefs + canonical serialization + `.xlsx` render
 * (LOOP-T.T2).
 *
 * This module is the on-disk contract for `out/ssdf-satisfaction-matrix.json`
 * and its operator-readable `.xlsx` companion. The pure compute (joining the
 * T.T1 SSDF catalogue to the real KSI evidence + risk + supply-chain corpus)
 * lives in `core/ssdf-evidence-aggregator.ts`; this file holds only the shapes,
 * the deterministic `matrix_id` derivation (RFC 4122 v5), the canonical-JSON
 * serializer used for signing, and the two-sheet workbook renderer (composing
 * the OOXML writer from `core/supply-chain-risk.ts` — REO: compose, never
 * re-implement the zip/OOXML plumbing).
 *
 * Reconciliation note (vs the T.T2 spec §4/§5 idealised schema): the committed
 * T.T1 catalogue (`core/ssdf-practices-catalog.ts`) carries the FedRAMP-KSI and
 * 800-53 Rev 5 crosswalks at the PRACTICE level (`fedramp_ksi_forward_map`,
 * `nist_800_53_r5_controls`) and the CISA Common Form refs at the TASK level
 * (`common_form_section_ref`, values like "§IV(1)"). There is no per-task
 * `crosswalk_ksi[]`/`crosswalk_800_53_r5[]`. The matrix therefore joins evidence
 * at the practice level and attributes the resulting pointer set to each of the
 * practice's tasks; per-task rows preserve the task statement + Common Form ref.
 * The catalogue is 19 practices / 42 active tasks (PW.3 withdrawn in v1.1).
 */
import { createHash } from 'node:crypto';
import { canonicalize } from './sign.ts';
import { multiSheetXlsx } from './supply-chain-risk.ts';

export const SATISFACTION_MATRIX_FILENAME = 'ssdf-satisfaction-matrix.json';
export const SATISFACTION_MATRIX_XLSX_FILENAME = 'ssdf-satisfaction-matrix.xlsx';
export const SATISFACTION_MATRIX_LEDGER_FILENAME = 'ssdf-satisfaction-matrix.jsonl';
export const MATRIX_SCHEMA_VERSION = '1.0' as const;
export const MATRIX_EMITTER = 'core/ssdf-evidence-aggregator.ts';
export const MATRIX_EMITTER_VERSION = '1.0.0';

/** Filename for a product-scoped matrix. The first/default product owns the
 * canonical `ssdf-satisfaction-matrix.json`; additional products are suffixed. */
export function matrixJsonFilename(productId: string, isDefault: boolean): string {
  return isDefault ? SATISFACTION_MATRIX_FILENAME : `ssdf-satisfaction-matrix.${slug(productId)}.json`;
}
export function matrixXlsxFilename(productId: string, isDefault: boolean): string {
  return isDefault ? SATISFACTION_MATRIX_XLSX_FILENAME : `ssdf-satisfaction-matrix.${slug(productId)}.xlsx`;
}
function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '') || 'product';
}

// ─── Status enums ─────────────────────────────────────────────────────────────

export type TaskStatus =
  | 'satisfied'
  | 'partially-satisfied'
  | 'not-satisfied'
  | 'not-assessed'
  | 'requires-operator-input';

/** Identical enum to TaskStatus (per spec §5.1). */
export type PracticeStatus = TaskStatus;

export const ALL_STATUSES: TaskStatus[] = [
  'satisfied',
  'partially-satisfied',
  'not-satisfied',
  'not-assessed',
  'requires-operator-input',
];

// ─── Evidence pointers ────────────────────────────────────────────────────────

export type SsdfEvidencePointer =
  | { kind: 'ksi-envelope'; ksi_id: string; envelope_sha256: string; signing_key_id: string; signature_verified: boolean; source_path: string }
  | { kind: 'oscal-observation'; observation_uuid: string; control_id: string; source_path: string }
  | { kind: 'oscal-poam-item'; poam_item_uuid: string; control_id: string; source_path: string }
  | { kind: 'sbom'; sbom_format: 'cyclonedx' | 'spdx' | 'unknown'; sbom_sha256: string; source_path: string }
  | { kind: 'subprocessor-inventory'; subprocessor_id: string; source_path: string }
  | { kind: 'supply-chain-risk-register-row'; row_id: string; source_path: string };

export type EvidencePointerKind = SsdfEvidencePointer['kind'];

// ─── Matrix shapes ────────────────────────────────────────────────────────────

export interface SsdfTaskRow {
  id: string;
  statement: string;
  status: TaskStatus;
  /** Practice-level 800-53 Rev 5 controls (inherited; the catalogue maps controls per-practice). */
  nist_800_53_r5_controls: string[];
  /** Practice-level FedRAMP KSI ids (inherited from `fedramp_ksi_forward_map`). */
  crosswalk_ksi: string[];
  /** Task-level CISA Common Form Section IV refs (e.g. "§IV(1)"). */
  common_form_section_ref: string[];
  evidence_pointers: SsdfEvidencePointer[];
  open_risk_score: number | null;
  diagnostics: string[];
}

export interface SsdfPracticeRow {
  id: string;
  group: 'PO' | 'PS' | 'PW' | 'RV';
  name: string;
  outcome: string;
  status: PracticeStatus;
  open_risk_score: number | null;
  tasks_by_status: Record<TaskStatus, number>;
  tasks: SsdfTaskRow[];
}

export interface SsdfMatrixProvenance {
  emitter: string;
  emitterVersion: string;
  emittedAt: string;
  sourceCalls: string[];
  sourceDigests: Array<{ kind: string; path: string; sha256: string; signatureVerified: boolean }>;
  signingKeyId: string;
  publicKeyPem: string;
  signatureEd25519: string;
  /** RFC 3161 coverage is provided by the run-level manifest TSR; null here. */
  timestampAuthority: string | null;
  /** `coverage:partial — <input>` markers for optional inputs that were absent. */
  coverageDiagnostics: string[];
}

export interface SsdfSatisfactionMatrix {
  schema_version: typeof MATRIX_SCHEMA_VERSION;
  matrix_id: string;
  generated_at: string;
  csp_name: string;
  product: {
    id: string;
    name: string;
    ai_enabled: boolean;
    critical_software: boolean;
  };
  regime: string;
  catalogue_source: {
    sp: '800-218';
    version: string;
    publication_date: string;
    source_pdf_sha256: string;
  };
  totals: {
    practices: number;
    tasks: number;
    practices_by_status: Record<PracticeStatus, number>;
    tasks_by_status: Record<TaskStatus, number>;
  };
  practices: SsdfPracticeRow[];
  provenance: SsdfMatrixProvenance;
}

// ─── Deterministic matrix id (RFC 4122 v5, SHA-1 over namespace + name) ───────

/** Fixed namespace UUID for SSDF satisfaction matrices (constant; not secret). */
export const SSDF_MATRIX_NAMESPACE = '6f9c0e4a-9a8b-5d2e-bf3a-1c7e2d4b8a90';

function uuidParseToBytes(uuid: string): Buffer {
  const hex = uuid.replace(/-/g, '');
  if (hex.length !== 32) throw new Error(`invalid namespace uuid: ${uuid}`);
  return Buffer.from(hex, 'hex');
}

/** RFC 4122 §4.3 name-based UUID (version 5, SHA-1). Deterministic. */
export function uuidV5(name: string, namespace: string = SSDF_MATRIX_NAMESPACE): string {
  const ns = uuidParseToBytes(namespace);
  const hash = createHash('sha1').update(ns).update(Buffer.from(name, 'utf8')).digest();
  const b = Buffer.from(hash.subarray(0, 16));
  b[6] = ((b[6] ?? 0) & 0x0f) | 0x50; // version 5
  b[8] = ((b[8] ?? 0) & 0x3f) | 0x80; // RFC 4122 variant
  const h = b.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

/**
 * The deterministic matrix_id derives ONLY from the inputs (catalogue digest,
 * product identity, and the sorted set of source-file digests) — never from the
 * wall-clock `generated_at`/`emittedAt` — so identical inputs yield an identical
 * id across runs (test T2-14).
 */
export function deriveMatrixId(input: {
  productId: string;
  cataloguePdfSha256: string;
  sourceDigests: Array<{ kind: string; path: string; sha256: string }>;
}): string {
  const descriptor = {
    product: input.productId,
    catalogue_pdf_sha256: input.cataloguePdfSha256,
    sources: [...input.sourceDigests]
      .map((d) => ({ kind: d.kind, path: d.path, sha256: d.sha256 }))
      .sort((a, b) => (a.path + a.kind).localeCompare(b.path + b.kind, 'en')),
  };
  return uuidV5(canonicalize(descriptor));
}

// ─── Canonical serialization (signing) ───────────────────────────────────────

/** The signature-blanked form whose canonical bytes get the detached signature. */
export function toUnsignedForm(matrix: SsdfSatisfactionMatrix): SsdfSatisfactionMatrix {
  return {
    ...matrix,
    provenance: { ...matrix.provenance, signingKeyId: '', publicKeyPem: '', signatureEd25519: '' },
  };
}

/** Canonical-JSON (RFC 8785-style sorted keys) of the signature-blanked matrix. */
export function serializeUnsignedCanonical(matrix: SsdfSatisfactionMatrix): string {
  return canonicalize(JSON.parse(JSON.stringify(toUnsignedForm(matrix))));
}

// ─── Empty status tally helper ────────────────────────────────────────────────

export function emptyStatusTally(): Record<TaskStatus, number> {
  return {
    'satisfied': 0,
    'partially-satisfied': 0,
    'not-satisfied': 0,
    'not-assessed': 0,
    'requires-operator-input': 0,
  };
}

// ─── XLSX render (two sheets) ─────────────────────────────────────────────────

function pointerSummary(p: SsdfEvidencePointer): string {
  switch (p.kind) {
    case 'ksi-envelope': return `ksi-envelope:${p.source_path}`;
    case 'oscal-observation': return `oscal-observation:${p.source_path}`;
    case 'oscal-poam-item': return `oscal-poam-item:${p.source_path}`;
    case 'sbom': return `sbom:${p.source_path}`;
    case 'subprocessor-inventory': return `subprocessor-inventory:${p.source_path}`;
    case 'supply-chain-risk-register-row': return `supply-chain-risk-register-row:${p.source_path}`;
  }
}

/** Render the matrix to a 2-sheet `.xlsx` Buffer (Per-Task Matrix + Per-Practice Summary). */
export function satisfactionMatrixToXlsx(matrix: SsdfSatisfactionMatrix): Buffer {
  const taskHeaders = [
    'Group', 'Practice ID', 'Practice Name', 'Task ID', 'Task Statement', 'Status',
    '800-53 r5 Controls', 'KSI IDs', 'Common Form Clause(s)', 'Evidence Pointer Count',
    'Evidence Pointer Summary', 'Diagnostics', 'Open Risk (B.1 composite)',
  ];
  const taskRows: string[][] = [];
  for (const p of matrix.practices) {
    for (const t of p.tasks) {
      taskRows.push([
        p.group,
        p.id,
        p.name,
        t.id,
        t.statement,
        t.status,
        t.nist_800_53_r5_controls.join(', '),
        t.crosswalk_ksi.join(', '),
        t.common_form_section_ref.join(', '),
        String(t.evidence_pointers.length),
        t.evidence_pointers.map(pointerSummary).join('; '),
        t.diagnostics.join('; '),
        t.open_risk_score === null ? 'n/a' : t.open_risk_score.toFixed(2),
      ]);
    }
  }

  const summaryHeaders = [
    'Group', 'Practice ID', 'Practice Name', 'Outcome', 'Practice Status', 'Task Count',
    'Tasks Satisfied', 'Tasks Partially Satisfied', 'Tasks Not Satisfied', 'Tasks Not Assessed',
    'Tasks Requires Operator Input', 'Practice Open Risk Score',
  ];
  const summaryRows: string[][] = matrix.practices.map((p) => [
    p.group,
    p.id,
    p.name,
    p.outcome,
    p.status,
    String(p.tasks.length),
    String(p.tasks_by_status['satisfied']),
    String(p.tasks_by_status['partially-satisfied']),
    String(p.tasks_by_status['not-satisfied']),
    String(p.tasks_by_status['not-assessed']),
    String(p.tasks_by_status['requires-operator-input']),
    p.open_risk_score === null ? 'n/a' : p.open_risk_score.toFixed(2),
  ]);

  return multiSheetXlsx([
    { name: 'Per-Task Matrix', headers: taskHeaders, rows: taskRows },
    { name: 'Per-Practice Summary', headers: summaryHeaders, rows: summaryRows },
  ]);
}
