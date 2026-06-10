/**
 * NIST SP 800-218 v1.1 (SSDF) practice catalog — typed loader/validator/lookup
 * + shared builder for the offline extractor (LOOP-T.T1).
 *
 * This module is the in-memory contract for the signed catalog
 * `data/ssdf-800-218-v1.1.json` that downstream LOOP-T slices consume:
 *   - T.T2 (CISA Common Form generator) labels each Section IV attestation with
 *     the underlying SSDF practice/task ids via tasksByCommonFormSection().
 *   - T.T3 (evidence aggregator) computes per-practice satisfaction status.
 *   - T.T5 (KSI <-> SSDF gap matrix) renders the fedramp_ksi_forward_map.
 *
 * The catalog content is extracted VERBATIM from the committed NIST PDF
 * (docs/sources/NIST.SP.800-218.pdf) by scripts/extract-ssdf-practices.mjs.
 * The 19 practice names + 4 practice-group definitions are NIST published-
 * constant identifiers (allowed-list constants per cloud-evidence/CLAUDE.md REO
 * Rule 3) declared here and re-verified to appear verbatim in the PDF at build
 * time. The 800-53 Rev 5 control mappings are taken verbatim from the PDF's
 * Table 1 References column. The SSDF -> FedRAMP KSI forward map is the
 * operator's curated semantic mapping (scripts/data/ssdf-ksi-mapping.json).
 *
 * REO: the loader never substitutes defaults for missing data — it throws a
 * typed SsdfExtractError so a consumer (or 3PAO) sees the exact shape problem.
 */
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize, verifyDetached } from './sign.ts';

const __dirname = dirname(fileURLToPath(import.meta.url));
/** cloud-evidence/ root (core/ is one level down). */
const PROJECT_ROOT = resolve(__dirname, '..');

export const CATALOG_ID = 'ssdf-800-218-v1.1' as const;
export const CATALOG_FILENAME = 'ssdf-800-218-v1.1.json';
export const FRAMEWORK_VERSION = 'SSDF v1.1 (NIST SP 800-218, Feb 2022)';
export const EMITTER = 'scripts/extract-ssdf-practices.mjs';
export const EMITTER_VERSION = '1.0.0';
/**
 * As-of policy regime recorded on the catalog (risk T.T1-R4 / T-X19): the SSDF
 * catalog itself is framework-agnostic, but the provenance records which
 * procurement regime was in force at extraction time.
 */
export const POLICY_BASIS =
  'NIST SP 800-218 v1.1 (Feb 2022); procurement regime as of 2026-06-07: OMB M-22-18 + M-23-16 + CISA Common Form OMB 1670-0052, as modified by M-26-05 (risk-based / voluntary continuation).';

// ─── Practice group definitions (verbatim NIST SP 800-218 v1.1 §2 summaries) ──
export const PRACTICE_GROUPS: SsdfPracticeGroup[] = [
  { id: 'PO', name: 'Prepare the Organization', definition: "Ensure that the organization's people, processes, and technology are prepared to perform secure software development at the organization level. Many organizations will find some PO practices applicable to subsets of their software development, like individual development groups or projects." },
  { id: 'PS', name: 'Protect the Software', definition: 'Protect all components of the software from tampering and unauthorized access.' },
  { id: 'PW', name: 'Produce Well-Secured Software', definition: 'Produce well-secured software with minimal security vulnerabilities in its releases.' },
  { id: 'RV', name: 'Respond to Vulnerabilities', definition: 'Identify residual vulnerabilities in software releases and respond appropriately to address those vulnerabilities and prevent similar vulnerabilities from occurring in the future.' },
];

/** The 19 SSDF v1.1 practice names (NIST published-constant identifiers). */
export const PRACTICE_NAMES: Record<string, string> = {
  'PO.1': 'Define Security Requirements for Software Development',
  'PO.2': 'Implement Roles and Responsibilities',
  'PO.3': 'Implement Supporting Toolchains',
  'PO.4': 'Define and Use Criteria for Software Security Checks',
  'PO.5': 'Implement and Maintain Secure Environments for Software Development',
  'PS.1': 'Protect All Forms of Code from Unauthorized Access and Tampering',
  'PS.2': 'Provide a Mechanism for Verifying Software Release Integrity',
  'PS.3': 'Archive and Protect Each Software Release',
  'PW.1': 'Design Software to Meet Security Requirements and Mitigate Security Risks',
  'PW.2': 'Review the Software Design to Verify Compliance with Security Requirements and Risk Information',
  'PW.4': 'Reuse Existing, Well-Secured Software When Feasible Instead of Duplicating Functionality',
  'PW.5': 'Create Source Code by Adhering to Secure Coding Practices',
  'PW.6': 'Configure the Compilation, Interpreter, and Build Processes to Improve Executable Security',
  'PW.7': 'Review and/or Analyze Human-Readable Code to Identify Vulnerabilities and Verify Compliance with Security Requirements',
  'PW.8': 'Test Executable Code to Identify Vulnerabilities and Verify Compliance with Security Requirements',
  'PW.9': 'Configure Software to Have Secure Settings by Default',
  'RV.1': 'Identify and Confirm Vulnerabilities on an Ongoing Basis',
  'RV.2': 'Assess, Prioritize, and Remediate Vulnerabilities',
  'RV.3': 'Analyze Vulnerabilities to Identify Their Root Causes',
};

/** Canonical practice id order: PO before PS before PW before RV; ascending within group. */
export const EXPECTED_PRACTICE_IDS: string[] = Object.keys(PRACTICE_NAMES);
export const EXPECTED_PRACTICE_COUNT = 19;
export const EXPECTED_TASK_COUNT = 42;
export const EXPECTED_GROUP_COUNT = 4;
export const EXPECTED_WITHDRAWN_TASK_COUNT = 5;

/** PW.3 was withdrawn between SSDF v1.0 and v1.1 (its tasks moved to PO.1.3 + PW.4.4). */
export const WITHDRAWN_PRACTICES: SsdfWithdrawnPractice[] = [
  { id: 'PW.3', note: 'Verify Third-Party Software Complies with Security Requirements — withdrawn in v1.1; tasks moved to PO.1.3 and PW.4.4.' },
];

export type CommonFormSection = '§IV(1)' | '§IV(2)' | '§IV(3)' | '§IV(4)';

/**
 * CISA Self-Attestation Common Form (OMB 1670-0052) Section IV -> SSDF task
 * mapping, per the published CISA mapping (T.T1 §2.6 / LOOP-T-SPEC §2.6). Used
 * to label each task with the attestation paragraph(s) it backstops. Practices
 * with no entry are not directly referenced by the four Section IV attestations
 * (the Common Form covers a subset of the 19 practices).
 */
const COMMON_FORM_SECTION_TASKS: Record<CommonFormSection, string[]> = {
  '§IV(1)': ['PO.5.1', 'PO.5.2', 'PS.1.1'],
  '§IV(2)': ['PO.1.3', 'PO.3.2', 'PO.5.1', 'PS.3.1', 'PW.4.1', 'PW.4.4', 'RV.1.1', 'RV.1.2', 'RV.1.3'],
  '§IV(3)': ['PS.3.2'],
  '§IV(4)': ['PW.7.1', 'PW.7.2', 'PW.8.1', 'PW.8.2', 'RV.1.1', 'RV.1.2', 'RV.1.3', 'RV.2.1', 'RV.2.2', 'RV.3.1', 'RV.3.2', 'RV.3.3', 'RV.3.4'],
};

/** Inverted: task id -> sorted Common Form section refs. */
export const COMMON_FORM_TASK_MAP: Record<string, CommonFormSection[]> = (() => {
  const out: Record<string, CommonFormSection[]> = {};
  for (const section of Object.keys(COMMON_FORM_SECTION_TASKS) as CommonFormSection[]) {
    for (const taskId of COMMON_FORM_SECTION_TASKS[section]) {
      (out[taskId] ??= []).push(section);
    }
  }
  for (const taskId of Object.keys(out)) out[taskId]!.sort();
  return out;
})();

// ─── Catalog shapes ──────────────────────────────────────────────────────────

export interface SsdfPracticeGroup {
  id: 'PO' | 'PS' | 'PW' | 'RV';
  name: string;
  definition: string;
}

export interface SsdfTask {
  /** e.g. "PO.1.1". */
  id: string;
  /** Verbatim task statement from the NIST PDF. */
  statement: string;
  /** CISA Common Form Section IV paragraphs this task backstops (possibly empty). */
  common_form_section_ref: CommonFormSection[];
}

/** One curated SSDF practice -> FedRAMP KSI forward-map entry. */
export interface SsdfKsiForwardEntry {
  ksi_id: string;
  confidence: 'high' | 'medium' | 'low';
  rationale: string;
}

export interface SsdfPractice {
  /** e.g. "PO.1". */
  id: string;
  group: 'PO' | 'PS' | 'PW' | 'RV';
  name: string;
  intent: string;
  tasks: SsdfTask[];
  /** Verbatim SP 800-53 Rev 5 control ids (lower-cased) from the PDF References column. May be empty. */
  nist_800_53_r5_controls: string[];
  /** Union of the practice's tasks' Common Form Section IV refs. */
  common_form_section_ref: CommonFormSection[];
  /** Curated SSDF -> FedRAMP KSI forward map (operator-defined; may be empty). */
  fedramp_ksi_forward_map: SsdfKsiForwardEntry[];
}

export interface SsdfWithdrawnPractice {
  id: string;
  note: string;
}

export interface SsdfWithdrawnTask {
  id: string;
  moved_to: string;
}

export interface SsdfCatalogStatistics {
  practice_count: number;
  task_count: number;
  withdrawn_practice_count: number;
  withdrawn_task_count: number;
  practices_with_53_mapping: number;
  practices_with_ksi_map: number;
  practices_with_common_form_ref: number;
}

/** Top-level provenance — camelCase keys satisfy the G3 provenance guardrail. */
export interface SsdfCatalogProvenance {
  emitter: string;
  emitterVersion: string;
  emittedAt: string;
  sourceCalls: string[];
  signingKeyId: string;
  algorithm: 'ed25519';
  signatureEd25519: string;
  publicKeyPem: string;
  rfc3161TimestampPath: string | null;
  sourcePdfSha256: string;
  ksiMapSha256: string;
  mappingSource: string;
  nist53Revision: string;
  policyBasis: string;
  extractedByRunId: string;
}

export interface SsdfCatalog {
  catalog_id: typeof CATALOG_ID;
  framework_version: string;
  extracted_at: string;
  source_pdf_path: string;
  source_pdf_sha256: string;
  publication: { title: string; publisher: string; publication_date: string; doi: string };
  practice_groups: SsdfPracticeGroup[];
  practices: SsdfPractice[];
  withdrawn_practices: SsdfWithdrawnPractice[];
  withdrawn_tasks: SsdfWithdrawnTask[];
  statistics: SsdfCatalogStatistics;
  provenance: SsdfCatalogProvenance;
}

// ─── Typed errors ────────────────────────────────────────────────────────────

export type SsdfErrorCode =
  | 'ERR_SSDF_SOURCE_MISSING'
  | 'ERR_SSDF_SOURCE_SHA256_DRIFT'
  | 'ERR_SSDF_KSI_MAPPING_MISSING'
  | 'ERR_SSDF_KSI_MAPPING_UNREVIEWED'
  | 'ERR_SSDF_KSI_UNKNOWN'
  | 'ERR_SSDF_SHAPE_MISMATCH'
  | 'ERR_SSDF_PRACTICE_COUNT_MISMATCH'
  | 'ERR_SSDF_TASK_COUNT_MISMATCH'
  | 'ERR_SSDF_PRACTICE_NOT_FOUND'
  | 'ERR_SSDF_NAME_MISMATCH'
  | 'ERR_SSDF_STATEMENT_MISSING'
  | 'ERR_SSDF_SCHEMA_VERSION';

export class SsdfExtractError extends Error {
  code: SsdfErrorCode;
  constructor(code: SsdfErrorCode, message: string) {
    super(message);
    this.name = 'SsdfExtractError';
    this.code = code;
  }
}

// ─── Pure builder (shared with the extractor) ────────────────────────────────

const PUBLICATION = {
  title: 'Secure Software Development Framework (SSDF) Version 1.1: Recommendations for Mitigating the Risk of Software Vulnerabilities',
  publisher: 'NIST',
  publication_date: '2022-02',
  doi: '10.6028/NIST.SP.800-218',
};

const ASCII_RE = /^[\x20-\x7e]+$/;

export interface BuildSsdfCatalogOptions {
  /** practiceId -> verbatim intent string. */
  practiceIntents: Record<string, string>;
  /** Active tasks parsed from the PDF, in document order. */
  activeTasks: Array<{ id: string; statement: string; controls: string[] }>;
  /** Withdrawn ("Moved to") tasks parsed from the PDF. */
  withdrawnTasks: SsdfWithdrawnTask[];
  /** Normalized PDF text — used to re-verify practice names appear verbatim. */
  pdfText: string;
  sourcePdfSha256: string;
  /** Curated practiceId -> KSI forward-map entries. */
  ksiForwardMap: Record<string, SsdfKsiForwardEntry[]>;
  mappingSource: string;
  nist53Revision: string;
  ksiMapSha256: string;
  runId: string;
  extractedAt: string;
}

/**
 * Assemble + validate the (unsigned) SSDF catalog from parsed PDF inputs. The
 * provenance signature fields are left blank; the extractor fills them after
 * computing the detached Ed25519 signature. Throws SsdfExtractError on any
 * shape/fidelity problem (REO: no silent fallback).
 */
export function buildSsdfCatalog(opts: BuildSsdfCatalogOptions): SsdfCatalog {
  const tasksByPractice = new Map<string, SsdfTask[]>();
  for (const t of opts.activeTasks) {
    const practiceId = t.id.slice(0, t.id.lastIndexOf('.'));
    if (!t.statement || !ASCII_RE.test(t.statement)) {
      throw new SsdfExtractError('ERR_SSDF_STATEMENT_MISSING', `Task ${t.id} has an empty or non-ASCII statement after normalization.`);
    }
    const task: SsdfTask = {
      id: t.id,
      statement: t.statement,
      common_form_section_ref: COMMON_FORM_TASK_MAP[t.id] ?? [],
    };
    if (!tasksByPractice.has(practiceId)) tasksByPractice.set(practiceId, []);
    tasksByPractice.get(practiceId)!.push(task);
  }

  const practices: SsdfPractice[] = [];
  for (const id of EXPECTED_PRACTICE_IDS) {
    const name = PRACTICE_NAMES[id]!;
    if (!opts.pdfText.includes(name)) {
      throw new SsdfExtractError('ERR_SSDF_NAME_MISMATCH', `Practice ${id} name "${name}" does not appear verbatim in the source PDF text.`);
    }
    const intent = (opts.practiceIntents[id] ?? '').trim();
    if (!intent) {
      throw new SsdfExtractError('ERR_SSDF_STATEMENT_MISSING', `Practice ${id} has an empty intent.`);
    }
    const tasks = (tasksByPractice.get(id) ?? []).slice().sort((a, b) => a.id.localeCompare(b.id, 'en'));
    const controls = [...new Set(tasks.flatMap((t) => opts.activeTasks.find((x) => x.id === t.id)!.controls))].sort();
    const cfRefs = [...new Set(tasks.flatMap((t) => t.common_form_section_ref))].sort() as CommonFormSection[];
    practices.push({
      id,
      group: id.slice(0, 2) as SsdfPractice['group'],
      name,
      intent,
      tasks,
      nist_800_53_r5_controls: controls,
      common_form_section_ref: cfRefs,
      fedramp_ksi_forward_map: opts.ksiForwardMap[id] ?? [],
    });
  }

  const taskTotal = practices.reduce((a, p) => a + p.tasks.length, 0);
  if (practices.length !== EXPECTED_PRACTICE_COUNT) {
    throw new SsdfExtractError('ERR_SSDF_PRACTICE_COUNT_MISMATCH', `Expected ${EXPECTED_PRACTICE_COUNT} practices, parsed ${practices.length}.`);
  }
  if (taskTotal !== EXPECTED_TASK_COUNT) {
    throw new SsdfExtractError('ERR_SSDF_TASK_COUNT_MISMATCH', `Expected ${EXPECTED_TASK_COUNT} active tasks, parsed ${taskTotal}.`);
  }
  if (opts.withdrawnTasks.length !== EXPECTED_WITHDRAWN_TASK_COUNT) {
    throw new SsdfExtractError('ERR_SSDF_SHAPE_MISMATCH', `Expected ${EXPECTED_WITHDRAWN_TASK_COUNT} withdrawn tasks, parsed ${opts.withdrawnTasks.length}.`);
  }

  const statistics: SsdfCatalogStatistics = {
    practice_count: practices.length,
    task_count: taskTotal,
    withdrawn_practice_count: WITHDRAWN_PRACTICES.length,
    withdrawn_task_count: opts.withdrawnTasks.length,
    practices_with_53_mapping: practices.filter((p) => p.nist_800_53_r5_controls.length > 0).length,
    practices_with_ksi_map: practices.filter((p) => p.fedramp_ksi_forward_map.length > 0).length,
    practices_with_common_form_ref: practices.filter((p) => p.common_form_section_ref.length > 0).length,
  };

  const provenance: SsdfCatalogProvenance = {
    emitter: EMITTER,
    emitterVersion: EMITTER_VERSION,
    emittedAt: opts.extractedAt,
    sourceCalls: [`file:${opts.sourcePdfSha256.slice(0, 12)}:NIST.SP.800-218.pdf`, 'file:ssdf-ksi-mapping.json', 'module:core/ksi-map.ts'],
    signingKeyId: '',
    algorithm: 'ed25519',
    signatureEd25519: '',
    publicKeyPem: '',
    rfc3161TimestampPath: null,
    sourcePdfSha256: opts.sourcePdfSha256,
    ksiMapSha256: opts.ksiMapSha256,
    mappingSource: opts.mappingSource,
    nist53Revision: opts.nist53Revision,
    policyBasis: POLICY_BASIS,
    extractedByRunId: opts.runId,
  };

  const catalog: SsdfCatalog = {
    catalog_id: CATALOG_ID,
    framework_version: FRAMEWORK_VERSION,
    extracted_at: opts.extractedAt,
    source_pdf_path: 'docs/sources/NIST.SP.800-218.pdf',
    source_pdf_sha256: opts.sourcePdfSha256,
    publication: PUBLICATION,
    practice_groups: PRACTICE_GROUPS,
    practices,
    withdrawn_practices: WITHDRAWN_PRACTICES,
    withdrawn_tasks: opts.withdrawnTasks.slice().sort((a, b) => a.id.localeCompare(b.id, 'en')),
    statistics,
    provenance,
  };
  return catalog;
}

// ─── Signing helpers (mirror core/prohibited-vendors-catalog.ts) ─────────────

/** The catalog form that gets signed: provenance signature fields blanked. */
function toUnsignedForm(catalog: SsdfCatalog): SsdfCatalog {
  return {
    ...catalog,
    provenance: { ...catalog.provenance, signingKeyId: '', publicKeyPem: '', signatureEd25519: '' },
  };
}

/** Canonical-JSON (RFC 8785-style) of the signature-blanked catalog — deterministic. */
export function serializeUnsignedCanonical(catalog: SsdfCatalog): string {
  return canonicalize(JSON.parse(JSON.stringify(toUnsignedForm(catalog))));
}

/** Verify the catalog's embedded detached Ed25519 signature against its canonical bytes. */
export function verifySsdfCatalogSignature(catalog: SsdfCatalog): boolean {
  if (!catalog.provenance?.publicKeyPem || !catalog.provenance?.signatureEd25519) return false;
  return verifyDetached(Buffer.from(serializeUnsignedCanonical(catalog), 'utf8'), {
    publicKeyPem: catalog.provenance.publicKeyPem,
    signatureBase64: catalog.provenance.signatureEd25519,
  });
}

// ─── Validation (shared by the loader) ───────────────────────────────────────

export interface ValidateCatalogOptions {
  /** When provided, every fedramp_ksi_forward_map entry must reference an id in this set. */
  knownKsiIds?: Set<string>;
}

/**
 * Structurally validate a catalog object (counts, ids, non-empty statements,
 * and — when knownKsiIds is supplied — that every forward-mapped KSI exists).
 * Throws SsdfExtractError on the first problem.
 */
export function validateCatalog(catalog: SsdfCatalog, opts: ValidateCatalogOptions = {}): void {
  if (catalog.catalog_id !== CATALOG_ID) {
    throw new SsdfExtractError('ERR_SSDF_SCHEMA_VERSION', `Unexpected catalog_id "${catalog.catalog_id}" (expected "${CATALOG_ID}").`);
  }
  if (!Array.isArray(catalog.practice_groups) || catalog.practice_groups.length !== EXPECTED_GROUP_COUNT) {
    throw new SsdfExtractError('ERR_SSDF_SHAPE_MISMATCH', `Expected ${EXPECTED_GROUP_COUNT} practice groups.`);
  }
  if (!Array.isArray(catalog.practices) || catalog.practices.length !== EXPECTED_PRACTICE_COUNT) {
    throw new SsdfExtractError('ERR_SSDF_PRACTICE_COUNT_MISMATCH', `Expected ${EXPECTED_PRACTICE_COUNT} practices, found ${catalog.practices?.length ?? 0}.`);
  }
  const ids = catalog.practices.map((p) => p.id).sort();
  const expected = [...EXPECTED_PRACTICE_IDS].sort();
  if (ids.join(',') !== expected.join(',')) {
    throw new SsdfExtractError('ERR_SSDF_SHAPE_MISMATCH', `Practice id set does not match the canonical 19.`);
  }
  let taskTotal = 0;
  for (const p of catalog.practices) {
    for (const t of p.tasks) {
      taskTotal++;
      if (!t.statement || !ASCII_RE.test(t.statement)) {
        throw new SsdfExtractError('ERR_SSDF_STATEMENT_MISSING', `Task ${t.id} has an empty or non-ASCII statement.`);
      }
    }
    if (opts.knownKsiIds) {
      for (const entry of p.fedramp_ksi_forward_map) {
        if (!opts.knownKsiIds.has(entry.ksi_id)) {
          throw new SsdfExtractError('ERR_SSDF_KSI_UNKNOWN', `Practice ${p.id} forward-maps to unknown KSI "${entry.ksi_id}".`);
        }
      }
    }
  }
  if (taskTotal !== EXPECTED_TASK_COUNT) {
    throw new SsdfExtractError('ERR_SSDF_TASK_COUNT_MISMATCH', `Expected ${EXPECTED_TASK_COUNT} active tasks, found ${taskTotal}.`);
  }
}

// ─── Loader + lookups ────────────────────────────────────────────────────────

export function defaultCatalogPath(): string {
  return resolve(PROJECT_ROOT, 'data', CATALOG_FILENAME);
}

/**
 * Load + validate the SSDF catalog from disk. Defaults to the committed
 * data/ssdf-800-218-v1.1.json. Throws SsdfExtractError if the file is malformed
 * or fails structural validation.
 */
export function loadSsdfCatalog(path?: string, opts: ValidateCatalogOptions = {}): SsdfCatalog {
  const p = path ?? defaultCatalogPath();
  let raw: string;
  try {
    raw = readFileSync(p, 'utf8');
  } catch (e) {
    throw new SsdfExtractError('ERR_SSDF_SOURCE_MISSING', `Cannot read SSDF catalog at ${p}: ${(e as Error)?.message ?? String(e)}`);
  }
  const catalog = JSON.parse(raw) as SsdfCatalog;
  validateCatalog(catalog, opts);
  return catalog;
}

let DEFAULT_CATALOG: SsdfCatalog | null = null;
function defaultCatalog(): SsdfCatalog {
  if (!DEFAULT_CATALOG) DEFAULT_CATALOG = loadSsdfCatalog();
  return DEFAULT_CATALOG;
}

/** Look up a practice by id; throws ERR_SSDF_PRACTICE_NOT_FOUND if absent (e.g. PW.3). */
export function getPractice(id: string, catalog?: SsdfCatalog): SsdfPractice {
  const cat = catalog ?? defaultCatalog();
  const p = cat.practices.find((x) => x.id === id);
  if (!p) throw new SsdfExtractError('ERR_SSDF_PRACTICE_NOT_FOUND', `SSDF practice "${id}" not found in catalog ${cat.catalog_id}.`);
  return p;
}

/** All tasks belonging to a practice group, in practice/task order. */
export function getTasksByPracticeGroup(group: 'PO' | 'PS' | 'PW' | 'RV', catalog?: SsdfCatalog): SsdfTask[] {
  const cat = catalog ?? defaultCatalog();
  return cat.practices.filter((p) => p.group === group).flatMap((p) => p.tasks);
}

/** All tasks that backstop a given CISA Common Form Section IV paragraph. */
export function tasksByCommonFormSection(section: CommonFormSection, catalog?: SsdfCatalog): SsdfTask[] {
  const cat = catalog ?? defaultCatalog();
  return cat.practices.flatMap((p) => p.tasks).filter((t) => t.common_form_section_ref.includes(section));
}
