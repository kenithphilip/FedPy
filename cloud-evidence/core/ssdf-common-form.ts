/**
 * CISA Secure Software Development Attestation Common Form (OMB 1670-0052)
 * canonical aggregator + JSON builder (LOOP-T.T3).
 *
 * Why this exists:
 *   OMB M-22-18 (as amended by M-23-16) requires a software producer to attest
 *   to the Government-specified secure software development practices before its
 *   software may be used by a federal agency. CISA publishes the attestation as
 *   the "Secure Software Development Attestation Common Form" (OMB Control Number
 *   1670-0052, expiration 03/31/2027). This module projects the run's REAL
 *   evidence — the T.T2 per-practice satisfaction matrix — into the four
 *   Section IV attestation answers and emits a canonical-JSON shadow that the
 *   PDF renderer (core/ssdf-common-form-pdf.ts) and the bundle/sign pipeline
 *   consume. T.T3 emits the UNSIGNED form (the corporate officer signs out of
 *   band, captured by T.T4); the system never auto-signs the human attestation
 *   (REO Rule 1.10).
 *
 * Evidence flow (REO):
 *   producer config (config.yaml `ssdf.producer.*`)  ─┐
 *   out/ssdf-satisfaction-matrix*.json (T.T2)         ├─► CisaCommonFormCanonical
 *   out/poam.json (LOOP-A.A1, for cannot-comply refs) ─┘     (signed sidecar JSON)
 *
 * Spec reconciliation (vs the T.T3 per-slice doc §4/§5 idealised schema):
 *   1. The doc reads `out/ssdf-practice-map.json` (T.T1) + `out/ssdf-evidence-
 *      binding.json` (T.T2). Those filenames are stale: T.T1 ships the committed
 *      catalogue `data/ssdf-800-218-v1.1.json` and T.T2 ships the satisfaction
 *      matrix `out/ssdf-satisfaction-matrix.json` (see core/ssdf-satisfaction-
 *      matrix.ts). T.T3 reads the satisfaction matrix — the single artifact that
 *      already joins every SSDF task to its status + evidence pointers + its
 *      CISA Common Form Section IV ref (`common_form_section_ref`).
 *   2. The doc's status enum (implemented / partially-implemented / not-
 *      implemented / not-applicable) does not exist; the real matrix enum is
 *      satisfied / partially-satisfied / not-satisfied / not-assessed /
 *      requires-operator-input (core/ssdf-satisfaction-matrix.ts). The four
 *      Section IV selections derive from that real enum.
 *   3. The doc's illustrative `CISA_PRACTICE_TO_SSDF` table (1.a..4.c → guessed
 *      task ids) is superseded by the authoritative §IV(1..4) → task mapping the
 *      T.T1 catalogue already carries (core/ssdf-practices-catalog.ts
 *      `COMMON_FORM_TASK_MAP`), surfaced per-task on the matrix as
 *      `common_form_section_ref`. The Common Form's four attestations map 1:1 to
 *      §IV(1) (Practice 1, secure environments), §IV(2) (Practice 2, trusted
 *      supply chains), §IV(3) (Practice 3, provenance), §IV(4) (Practice 4,
 *      automated vulnerability tooling). Selection is computed per §IV section
 *      from the union of its tasks' statuses across every in-scope product.
 *   4. The binary CISA template PDF + CISA/OMB logo assets the doc §7 lists for
 *      verbatim-text fidelity + page imagery are not fetched in this clean-room
 *      tree; the verbatim Section IV text is reproduced from the public record
 *      cited in the per-slice doc §2.4, and the PDF renders a text-only header.
 *      See LOOP-T-RISKS T.T3-1 / T.T3-2.
 */
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync, existsSync, mkdirSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { canonicalize, signDetached } from './sign.ts';
import type {
  SsdfSatisfactionMatrix,
  SsdfTaskRow,
  TaskStatus,
} from './ssdf-satisfaction-matrix.ts';
import type { CommonFormSection } from './ssdf-practices-catalog.ts';

// ─── Constants (REO Rule 3 — published OMB / CISA / NIST identifiers) ──────────

export const OMB_CONTROL_NUMBER = '1670-0052' as const;
export const FORM_EXPIRATION_DATE = '03/31/2027' as const;
export const FORM_TITLE = 'Secure Software Development Attestation Common Form' as const;
export const FORM_SCHEMA = 'https://cisa.gov/forms/1670-0052#v2024-03' as const;
export const COMMON_FORM_EMITTER = 'core/ssdf-common-form.ts';
export const COMMON_FORM_EMITTER_VERSION = '1.0.0';
export const COMMON_FORM_JSON_FILENAME = 'cisa-common-form-1670-0052.json';
export const COMMON_FORM_PDF_FILENAME = 'cisa-common-form-1670-0052.pdf';

/** The four Section IV attestations, in form order, with their §IV section ref. */
export const CISA_PRACTICES: Array<{
  cisa_practice: '1' | '2' | '3' | '4';
  section: CommonFormSection;
  heading: string;
  /** Verbatim attestation text (CISA OMB 1670-0052 Section IV; per-slice doc §2.4). */
  statement: string;
  /** Verbatim sub-action text, where the form enumerates them. */
  sub_actions: Array<{ id: string; text: string }>;
}> = [
  {
    cisa_practice: '1',
    section: '§IV(1)',
    heading: 'Secure development environments',
    statement: 'The software was developed and built in secure environments.',
    sub_actions: [
      { id: '1.a', text: 'separating and protecting each environment involved in developing and building software;' },
      { id: '1.b', text: 'regularly logging, monitoring, and auditing trust relationships used for authorization and access (i) to any software development and build environments, and (ii) among components within each environment;' },
      { id: '1.c', text: 'enforcing multi-factor authentication and conditional access across the environments relevant to developing and building software in a manner that minimizes security risk;' },
      { id: '1.d', text: 'taking consistent and reasonable steps to document as well as minimize use or inclusion of software products that create undue risk within the environments used to develop and build software;' },
      { id: '1.e', text: 'encrypting sensitive data, such as credentials, to the extent practicable and based on risk;' },
      { id: '1.f', text: 'implementing defensive cybersecurity practices, including continuous monitoring of operations and alerts and, as necessary, responding to suspected and confirmed cyber incidents.' },
    ],
  },
  {
    cisa_practice: '2',
    section: '§IV(2)',
    heading: 'Trusted source code supply chains',
    statement:
      'The software producer has made a good-faith effort to maintain trusted source code supply chains by employing automated tools or comparable processes to address the security of internal code and third-party components and manage related vulnerabilities.',
    sub_actions: [],
  },
  {
    cisa_practice: '3',
    section: '§IV(3)',
    heading: 'Data provenance',
    statement:
      'The software producer maintains provenance for internal code and third-party components incorporated into the software to the greatest extent feasible.',
    sub_actions: [],
  },
  {
    cisa_practice: '4',
    section: '§IV(4)',
    heading: 'Automated vulnerability detection',
    statement:
      'The software producer employed automated tools or comparable processes that check for security vulnerabilities.',
    sub_actions: [
      { id: '4.a', text: 'the producer operated these processes on an ongoing basis and, at a minimum, prior to product, version, or update releases;' },
      { id: '4.b', text: 'the producer has a policy or process to address discovered security vulnerabilities prior to product release;' },
      { id: '4.c', text: 'the producer operates a vulnerability disclosure program and accepts, reviews, and addresses disclosed software vulnerabilities in a timely fashion.' },
    ],
  },
];

/** Verbatim signatory attestation language (CISA OMB 1670-0052; per-slice doc §2.4). */
export const SIGNATORY_ATTESTATION_TEXT =
  'I, the undersigned, hereby attest under penalty of perjury, by signing this form on behalf of the company, that the company satisfies the requirements identified in Section II of this form for all software covered by the scope of this attestation.';

// ─── Matrix file discovery ─────────────────────────────────────────────────────

const MATRIX_FILE_RE = /^ssdf-satisfaction-matrix(\.[a-z0-9-]+)?\.json$/;

// ─── Selection model ──────────────────────────────────────────────────────────

export type CommonFormSelection =
  | 'comply'
  | 'comply-with-conditions'
  | 'cannot-comply'
  | 'not-yet-determined';

/**
 * Reduce the union of a Section IV section's SSDF task statuses to a single
 * attestation selection. REO Rule 1.5 — a section that contains any task the
 * run could not assess (requires-operator-input / not-assessed) is reported as
 * `not-yet-determined`; it is NEVER silently promoted to `comply`.
 */
export function computeSelection(statuses: TaskStatus[]): CommonFormSelection {
  if (statuses.length === 0) return 'not-yet-determined';
  if (statuses.some((s) => s === 'requires-operator-input' || s === 'not-assessed')) {
    return 'not-yet-determined';
  }
  if (statuses.every((s) => s === 'satisfied')) return 'comply';
  if (statuses.every((s) => s === 'not-satisfied')) return 'cannot-comply';
  return 'comply-with-conditions';
}

// ─── Producer config (operator-supplied; REO Rule 4) ──────────────────────────

export interface CommonFormAddress {
  street: string;
  city: string;
  state: string;
  postal_code: string;
  country: string;
}

export interface CommonFormPointOfContact {
  name: string;
  title: string;
  email: string;
  phone: string;
}

export interface CommonFormProduct {
  name: string;
  version: string;
  cpe?: string;
}

export interface ValidatedProducer {
  legal_name: string;
  dba_name: string | null;
  address: CommonFormAddress;
  point_of_contact: CommonFormPointOfContact;
  signatory: { name: string; title: string };
  scope_of_attestation: { products: CommonFormProduct[] };
  ai_profile: boolean;
  poam_reference_overrides: Record<string, string[]>;
}

// ─── Typed errors ─────────────────────────────────────────────────────────────

/** Thrown when one or more required `ssdf.producer.*` fields are absent/invalid. */
export class MissingOperatorInputError extends Error {
  readonly fields: string[];
  constructor(fields: string[]) {
    super(`CISA Common Form is missing required operator input: ${fields.join(', ')}`);
    this.name = 'MissingOperatorInputError';
    this.fields = fields;
  }
}

/** Thrown when a Section IV attestation resolves to cannot-comply with no POA&M item to cite. */
export class MissingPoamReferenceError extends Error {
  constructor(cisaPractice: string) {
    super(
      `CISA Common Form Practice ${cisaPractice} resolved to "cannot-comply" but no POA&M item ` +
        `references its evidence; supply a POA&M (out/poam.json) or an ssdf.producer.poam_reference_overrides["${cisaPractice}"] entry.`,
    );
    this.name = 'MissingPoamReferenceError';
  }
}

/** Thrown when no T.T2 satisfaction matrix is present (T.T1/T.T2 must run first). */
export class MissingMatrixError extends Error {
  constructor(dir: string) {
    super(`No SSDF satisfaction matrix (ssdf-satisfaction-matrix*.json) found in ${dir}; run T.T2 (--ssdf-attestation) first.`);
    this.name = 'MissingMatrixError';
  }
}

/** Thrown when a scope-of-attestation product has no matching emitted matrix. */
export class ScopeMismatchError extends Error {
  constructor(product: string) {
    super(`scope_of_attestation product "${product}" has no matching SSDF satisfaction matrix; the attested product was not assessed by T.T2.`);
    this.name = 'ScopeMismatchError';
  }
}

// ─── Validation ───────────────────────────────────────────────────────────────

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE_RE = /^\+?[0-9().\-\s]{7,}$/;

function asString(v: unknown): string {
  return typeof v === 'string' ? v.trim() : '';
}

/**
 * Validate the operator's `ssdf.producer` block, collecting EVERY absent or
 * malformed required field before throwing (no silent defaulting; REO Rule 4).
 * Optional fields (dba_name, country, cpe, ai_profile, overrides) default
 * deterministically.
 */
export function validateProducer(raw: unknown): ValidatedProducer {
  const p = (raw ?? {}) as Record<string, any>;
  const missing: string[] = [];

  const legal_name = asString(p.legal_name);
  if (!legal_name) missing.push('ssdf.producer.legal_name');

  const addr = (p.address ?? {}) as Record<string, any>;
  const address: CommonFormAddress = {
    street: asString(addr.street),
    city: asString(addr.city),
    state: asString(addr.state),
    postal_code: asString(addr.postal_code),
    country: asString(addr.country) || 'US',
  };
  for (const k of ['street', 'city', 'state', 'postal_code'] as const) {
    if (!address[k]) missing.push(`ssdf.producer.address.${k}`);
  }

  const pocRaw = (p.point_of_contact ?? {}) as Record<string, any>;
  const point_of_contact: CommonFormPointOfContact = {
    name: asString(pocRaw.name),
    title: asString(pocRaw.title),
    email: asString(pocRaw.email),
    phone: asString(pocRaw.phone),
  };
  for (const k of ['name', 'title'] as const) {
    if (!point_of_contact[k]) missing.push(`ssdf.producer.point_of_contact.${k}`);
  }
  if (!point_of_contact.email) missing.push('ssdf.producer.point_of_contact.email');
  else if (!EMAIL_RE.test(point_of_contact.email)) missing.push('ssdf.producer.point_of_contact.email (invalid-format)');
  if (!point_of_contact.phone) missing.push('ssdf.producer.point_of_contact.phone');
  else if (!PHONE_RE.test(point_of_contact.phone)) missing.push('ssdf.producer.point_of_contact.phone (invalid-format)');

  const sigRaw = (p.signatory ?? {}) as Record<string, any>;
  const signatory = { name: asString(sigRaw.name), title: asString(sigRaw.title) };
  if (!signatory.name) missing.push('ssdf.producer.signatory.name');
  if (!signatory.title) missing.push('ssdf.producer.signatory.title');

  const scopeRaw = (p.scope_of_attestation ?? {}) as Record<string, any>;
  const productsRaw = Array.isArray(scopeRaw.products) ? scopeRaw.products : [];
  const products: CommonFormProduct[] = [];
  if (productsRaw.length === 0) {
    missing.push('ssdf.producer.scope_of_attestation.products[] (>=1 required)');
  } else {
    productsRaw.forEach((pr: any, i: number) => {
      const name = asString(pr?.name);
      const version = asString(pr?.version);
      if (!name) missing.push(`ssdf.producer.scope_of_attestation.products[${i}].name`);
      if (!version) missing.push(`ssdf.producer.scope_of_attestation.products[${i}].version`);
      const cpe = asString(pr?.cpe);
      products.push(cpe ? { name, version, cpe } : { name, version });
    });
  }

  if (missing.length > 0) throw new MissingOperatorInputError(missing);

  const overridesRaw = (p.poam_reference_overrides ?? {}) as Record<string, any>;
  const poam_reference_overrides: Record<string, string[]> = {};
  for (const [k, v] of Object.entries(overridesRaw)) {
    if (Array.isArray(v)) poam_reference_overrides[k] = v.map((x) => String(x)).filter(Boolean);
  }

  return {
    legal_name,
    dba_name: asString(p.dba_name) || null,
    address,
    point_of_contact,
    signatory,
    scope_of_attestation: { products },
    ai_profile: p.ai_profile === true,
    poam_reference_overrides,
  };
}

// ─── Canonical JSON shapes ────────────────────────────────────────────────────

export interface PracticeBox {
  cisa_practice: '1' | '2' | '3' | '4';
  common_form_section: CommonFormSection;
  heading: string;
  statement: string;
  sub_actions: Array<{ id: string; text: string }>;
  selection: CommonFormSelection;
  ssdf_v1_1_ids: string[];
  evidence_observation_uuids: string[];
  poam_item_uuids: string[];
  source: 'ssdf-satisfaction-matrix' | 'operator-config' | 'REQUIRES-OPERATOR-INPUT';
}

export interface CoverageRollupRow {
  cisa_practice: string;
  common_form_section: CommonFormSection;
  ssdf_v1_1_ids: string[];
  satisfied: number;
  partially_satisfied: number;
  not_satisfied: number;
  not_assessed: number;
  requires_operator_input: number;
}

export interface ProductFillRate {
  id: string;
  name: string;
  required_fields: number;
  populated_fields: number;
  fill_rate: number;
}

export interface CommonFormProvenance {
  emitter: string;
  emitterVersion: string;
  emittedAt: string;
  sourceCalls: string[];
  sourceDigests: Array<{ kind: string; path: string; sha256: string }>;
  signingKeyId: string;
  algorithm: 'ed25519';
  signatureEd25519: string;
  publicKeyPem: string;
  timestampAuthority: string | null;
  /** Provenance of the verbatim Section IV text (the binary template is not embedded; see T.T3-1). */
  formTextSource: { authority: string; omb_control_number: string; accessed: string; note: string };
  /** `coverage:partial — <input>` markers for optional inputs that were absent. */
  coverageDiagnostics: string[];
}

export interface CisaCommonFormCanonical {
  schema: typeof FORM_SCHEMA;
  omb_control_number: typeof OMB_CONTROL_NUMBER;
  expiration_date: typeof FORM_EXPIRATION_DATE;
  form_title: typeof FORM_TITLE;
  emittedAt: string;
  regime_note: string;
  producer: {
    legal_name: string;
    dba_name: string | null;
    address: CommonFormAddress;
    point_of_contact: CommonFormPointOfContact;
    signatory: { name: string; title: string };
    scope_of_attestation: { products: CommonFormProduct[] };
  };
  attestations: {
    practice_1_secure_environments: PracticeBox;
    practice_2_trusted_supply_chains: PracticeBox;
    practice_3_data_provenance: PracticeBox;
    practice_4_automated_vulnerability_tools: PracticeBox;
  };
  ssdf_coverage_rollup: CoverageRollupRow[];
  poam_references: Array<{ cisa_practice: string; poam_item_uuids: string[] }>;
  signatory_attestation_text: string;
  ai_profile_appendix?: {
    enabled: boolean;
    note: string;
    sp_800_218a_practices: Array<{ id: string; status: string }>;
  };
  coverage: { products: ProductFillRate[] };
  provenance: CommonFormProvenance;
}

// ─── Aggregation ──────────────────────────────────────────────────────────────

interface LoadedMatrix {
  product_id: string;
  product_name: string;
  ai_enabled: boolean;
  matrix: SsdfSatisfactionMatrix;
  path: string;
  sha256: string;
}

function normalizeName(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '');
}

/** Discover + parse every `ssdf-satisfaction-matrix*.json` in a directory. */
export function loadMatrices(dir: string): LoadedMatrix[] {
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
    out.push({
      product_id: matrix.product.id,
      product_name: matrix.product.name,
      ai_enabled: matrix.product.ai_enabled === true,
      matrix,
      path,
      sha256: createHash('sha256').update(bytes).digest('hex'),
    });
  }
  return out;
}

/** Resolve each scope product to a loaded matrix (by id or normalized name). */
function resolveScopeMatrices(scope: CommonFormProduct[], matrices: LoadedMatrix[]): LoadedMatrix[] {
  // Single-matrix + single-product is the common case — the lone matrix
  // represents the lone attested product even when names differ in casing.
  if (matrices.length === 1 && scope.length === 1) return matrices;
  const chosen: LoadedMatrix[] = [];
  for (const prod of scope) {
    const wantId = normalizeName(prod.name);
    const m = matrices.find(
      (x) => normalizeName(x.product_id) === wantId || normalizeName(x.product_name) === wantId,
    );
    if (!m) throw new ScopeMismatchError(prod.name);
    if (!chosen.includes(m)) chosen.push(m);
  }
  return chosen;
}

interface SectionAggregate {
  taskIds: Set<string>;
  statuses: TaskStatus[];
  observationUuids: Set<string>;
  poamUuids: Set<string>;
  tally: CoverageRollupRow;
}

function emptyTally(section: CommonFormSection, cisa: string): CoverageRollupRow {
  return {
    cisa_practice: cisa,
    common_form_section: section,
    ssdf_v1_1_ids: [],
    satisfied: 0,
    partially_satisfied: 0,
    not_satisfied: 0,
    not_assessed: 0,
    requires_operator_input: 0,
  };
}

function bumpTally(t: CoverageRollupRow, status: TaskStatus): void {
  switch (status) {
    case 'satisfied': t.satisfied += 1; break;
    case 'partially-satisfied': t.partially_satisfied += 1; break;
    case 'not-satisfied': t.not_satisfied += 1; break;
    case 'not-assessed': t.not_assessed += 1; break;
    case 'requires-operator-input': t.requires_operator_input += 1; break;
  }
}

/** Aggregate, per §IV section, every in-scope task's status + evidence pointers. */
function aggregateSections(scopeMatrices: LoadedMatrix[]): Record<CommonFormSection, SectionAggregate> {
  const agg = {} as Record<CommonFormSection, SectionAggregate>;
  for (const { section, cisa_practice } of CISA_PRACTICES) {
    agg[section] = {
      taskIds: new Set(),
      statuses: [],
      observationUuids: new Set(),
      poamUuids: new Set(),
      tally: emptyTally(section, cisa_practice),
    };
  }
  for (const lm of scopeMatrices) {
    for (const practice of lm.matrix.practices) {
      for (const task of practice.tasks) {
        for (const section of task.common_form_section_ref ?? []) {
          const a = agg[section as CommonFormSection];
          if (!a) continue;
          a.taskIds.add(task.id);
          a.statuses.push(task.status);
          bumpTally(a.tally, task.status);
          for (const ptr of task.evidence_pointers ?? []) {
            if (ptr.kind === 'oscal-observation') a.observationUuids.add(ptr.observation_uuid);
            else if (ptr.kind === 'oscal-poam-item') a.poamUuids.add(ptr.poam_item_uuid);
          }
        }
      }
    }
  }
  return agg;
}

// ─── Fill-rate coverage (per product) ─────────────────────────────────────────

/**
 * Per-product fill rate = populated required fields / total required fields. The
 * producer-level Section I/III fields + the four Section II selections are shared
 * across all attested products; each product additionally contributes its own
 * scope row (name + version). Returned per product so a multi-product attestation
 * surfaces one coverage figure each (per-slice doc §5.4).
 */
function computeFillRates(
  producer: ValidatedProducer,
  boxes: PracticeBox[],
): ProductFillRate[] {
  // Producer-level required fields (Section I + Section III signatory).
  const producerFields: Array<string> = [
    producer.legal_name,
    producer.address.street,
    producer.address.city,
    producer.address.state,
    producer.address.postal_code,
    producer.address.country,
    producer.point_of_contact.name,
    producer.point_of_contact.title,
    producer.point_of_contact.email,
    producer.point_of_contact.phone,
    producer.signatory.name,
    producer.signatory.title,
  ];
  const producerTotal = producerFields.length;
  const producerPopulated = producerFields.filter((v) => v && v.length > 0).length;
  // Section II — a determined selection counts as populated.
  const attestationTotal = boxes.length;
  const attestationPopulated = boxes.filter((b) => b.selection !== 'not-yet-determined').length;

  return producer.scope_of_attestation.products.map((prod) => {
    const productFields = [prod.name, prod.version];
    const productTotal = productFields.length;
    const productPopulated = productFields.filter((v) => v && v.length > 0).length;
    const required = producerTotal + attestationTotal + productTotal;
    const populated = producerPopulated + attestationPopulated + productPopulated;
    return {
      id: normalizeName(prod.name) || 'product',
      name: prod.name,
      required_fields: required,
      populated_fields: populated,
      fill_rate: required === 0 ? 0 : Math.round((populated / required) * 1e6) / 1e6,
    };
  });
}

// ─── Build (pure) ─────────────────────────────────────────────────────────────

export interface BuildCommonFormInput {
  producer: ValidatedProducer;
  scopeMatrices: LoadedMatrix[];
  /** POA&M item uuids known to exist (from out/poam.json); cannot-comply must cite >=1. */
  knownPoamItemUuids: Set<string>;
  emittedAt: string;
  regimeNote?: string;
  sourceDigests: Array<{ kind: string; path: string; sha256: string }>;
  coverageDiagnostics: string[];
  aiProfilePractices?: Array<{ id: string; status: string }>;
}

const DEFAULT_REGIME_NOTE =
  'OMB M-22-18 (Sep 14, 2022) as amended by M-23-16 (Jun 9, 2023). Under OMB M-26-05 ' +
  '(Jan 23, 2026) the Common Form is no longer a universal mandatory collection; it remains ' +
  'a valid attestation an agency may request under the risk-based regime.';

/**
 * Project the validated producer config + in-scope satisfaction matrices into the
 * canonical Common Form. Pure: no clock, no I/O, no signing (signature fields are
 * left blank for the caller to fill from the detached signature).
 */
export function buildCommonForm(input: BuildCommonFormInput): CisaCommonFormCanonical {
  const agg = aggregateSections(input.scopeMatrices);
  const boxes: PracticeBox[] = CISA_PRACTICES.map((p) => {
    const a = agg[p.section];
    const selection = computeSelection(a.statuses);
    const overrideUuids = input.producer.poam_reference_overrides[p.cisa_practice] ?? [];
    const poamUuids = [...new Set([...a.poamUuids, ...overrideUuids])].sort();
    if (selection === 'cannot-comply' && poamUuids.length === 0) {
      throw new MissingPoamReferenceError(p.cisa_practice);
    }
    const box: PracticeBox = {
      cisa_practice: p.cisa_practice,
      common_form_section: p.section,
      heading: p.heading,
      statement: p.statement,
      sub_actions: p.sub_actions,
      selection,
      ssdf_v1_1_ids: [...a.taskIds].sort(),
      evidence_observation_uuids: [...a.observationUuids].sort(),
      poam_item_uuids: poamUuids,
      source: selection === 'not-yet-determined' ? 'REQUIRES-OPERATOR-INPUT' : 'ssdf-satisfaction-matrix',
    };
    return box;
  });

  const rollup: CoverageRollupRow[] = CISA_PRACTICES.map((p) => {
    const t = agg[p.section].tally;
    return { ...t, ssdf_v1_1_ids: [...agg[p.section].taskIds].sort() };
  });

  const poam_references = boxes
    .filter((b) => b.poam_item_uuids.length > 0)
    .map((b) => ({ cisa_practice: b.cisa_practice, poam_item_uuids: b.poam_item_uuids }));

  const form: CisaCommonFormCanonical = {
    schema: FORM_SCHEMA,
    omb_control_number: OMB_CONTROL_NUMBER,
    expiration_date: FORM_EXPIRATION_DATE,
    form_title: FORM_TITLE,
    emittedAt: input.emittedAt,
    regime_note: input.regimeNote ?? DEFAULT_REGIME_NOTE,
    producer: {
      legal_name: input.producer.legal_name,
      dba_name: input.producer.dba_name,
      address: input.producer.address,
      point_of_contact: input.producer.point_of_contact,
      signatory: input.producer.signatory,
      scope_of_attestation: input.producer.scope_of_attestation,
    },
    attestations: {
      practice_1_secure_environments: boxes[0]!,
      practice_2_trusted_supply_chains: boxes[1]!,
      practice_3_data_provenance: boxes[2]!,
      practice_4_automated_vulnerability_tools: boxes[3]!,
    },
    ssdf_coverage_rollup: rollup,
    poam_references,
    signatory_attestation_text: SIGNATORY_ATTESTATION_TEXT,
    coverage: { products: computeFillRates(input.producer, boxes) },
    provenance: {
      emitter: COMMON_FORM_EMITTER,
      emitterVersion: COMMON_FORM_EMITTER_VERSION,
      emittedAt: input.emittedAt,
      sourceCalls: input.sourceDigests.map((d) => `${d.kind}:${d.path}`),
      sourceDigests: input.sourceDigests,
      signingKeyId: '',
      algorithm: 'ed25519',
      signatureEd25519: '',
      publicKeyPem: '',
      timestampAuthority: null,
      formTextSource: {
        authority: 'CISA Secure Software Development Attestation Common Form',
        omb_control_number: OMB_CONTROL_NUMBER,
        accessed: '2026-06-07',
        note: 'Section IV attestation text reproduced verbatim from the public record (per-slice doc §2.4); the binary CISA template PDF is not embedded in this tree (LOOP-T-RISKS T.T3-1).',
      },
      coverageDiagnostics: input.coverageDiagnostics,
    },
  };

  if (input.producer.ai_profile) {
    form.ai_profile_appendix = {
      enabled: true,
      note: 'Informational only — not a requirement of OMB 1670-0052 (NIST SP 800-218A Community Profile).',
      sp_800_218a_practices: input.aiProfilePractices ?? [],
    };
  }

  return form;
}

/** Canonical (RFC 8785-style sorted-key) bytes of the signature-blanked form. */
export function serializeUnsignedCanonical(form: CisaCommonFormCanonical): string {
  const blanked: CisaCommonFormCanonical = {
    ...form,
    provenance: { ...form.provenance, signingKeyId: '', signatureEd25519: '', publicKeyPem: '' },
  };
  return canonicalize(JSON.parse(JSON.stringify(blanked)));
}

// ─── POA&M reader ─────────────────────────────────────────────────────────────

/** Collect every poam-item uuid from an OSCAL POA&M document (for cannot-comply checks). */
export function readPoamItemUuids(poamPath: string): Set<string> {
  const uuids = new Set<string>();
  if (!existsSync(poamPath)) return uuids;
  let doc: any;
  try {
    doc = JSON.parse(readFileSync(poamPath, 'utf8'));
  } catch {
    return uuids;
  }
  const root = doc?.['plan-of-action-and-milestones'] ?? doc;
  const items = Array.isArray(root?.['poam-items']) ? root['poam-items'] : [];
  for (const it of items) {
    if (it && typeof it.uuid === 'string') uuids.add(it.uuid);
  }
  return uuids;
}

// ─── End-to-end emit (read matrices → build → sign → write JSON + PDF) ─────────

import { renderCommonFormPdf } from './ssdf-common-form-pdf.ts';
import { augmentCoverageWithSsdfCommonForm } from './inventory-coverage.ts';

export const POAM_FILENAME = 'poam.json';
export const COMMON_FORM_SIG_FILENAME = `${COMMON_FORM_JSON_FILENAME}.sig`;

export interface EmitCommonFormOptions {
  outDir: string;
  runId: string;
  /** Raw operator producer block (config.yaml `ssdf.producer`). */
  producer: unknown;
  regimeNote?: string;
  /** Frozen clock (tests). Defaults to now. */
  generatedAt?: string;
  /** Matrix + poam directory. Defaults to outDir. */
  evidenceDir?: string;
  /** Optional config.yaml path to hash into provenance.sourceDigests. */
  configPath?: string;
  /** Optional pre-loaded SP 800-218A practice statuses for Appendix B. */
  aiProfilePractices?: Array<{ id: string; status: string }>;
}

export interface EmitCommonFormResult {
  json_path: string;
  pdf_path: string;
  sig_path: string;
  json_sha256: string;
  pdf_sha256: string;
  selections: Record<string, CommonFormSelection>;
  fill_rates: ProductFillRate[];
  ai_profile: boolean;
}

function sha256Hex(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

/**
 * Full T.T3 pass: validate operator config, read the in-scope T.T2 matrices +
 * the POA&M, build the canonical Common Form, detached-Ed25519-sign it, and write
 * the canonical JSON + `.sig` + the deterministic unsigned PDF. The PDF + JSON are
 * additionally covered by the run manifest (core/sign.ts signs every `.json`/`.pdf`
 * by extension) and the RFC 3161 TSR; this never auto-signs the human attestation
 * (the signature/date lines are blank — REO Rule 1.10; the officer signs via T.T4).
 */
export function emitSsdfCommonForm(opts: EmitCommonFormOptions): EmitCommonFormResult {
  const emittedAt = opts.generatedAt ?? new Date().toISOString();
  const evidenceDir = opts.evidenceDir ?? opts.outDir;

  const producer = validateProducer(opts.producer);

  const matrices = loadMatrices(evidenceDir);
  if (matrices.length === 0) throw new MissingMatrixError(evidenceDir);
  const scopeMatrices = resolveScopeMatrices(producer.scope_of_attestation.products, matrices);

  const coverageDiagnostics: string[] = [];
  const sourceDigests: Array<{ kind: string; path: string; sha256: string }> = [];
  if (opts.configPath && existsSync(opts.configPath)) {
    sourceDigests.push({
      kind: 'operator-config',
      path: opts.configPath,
      sha256: sha256Hex(readFileSync(opts.configPath)),
    });
  } else {
    coverageDiagnostics.push('coverage:partial — config.yaml path not provided (producer block hashed in-line only)');
  }
  for (const m of scopeMatrices) {
    sourceDigests.push({ kind: 'ssdf-satisfaction-matrix', path: m.path, sha256: m.sha256 });
  }

  const poamPath = resolve(evidenceDir, POAM_FILENAME);
  let knownPoamItemUuids = new Set<string>();
  if (existsSync(poamPath)) {
    knownPoamItemUuids = readPoamItemUuids(poamPath);
    sourceDigests.push({ kind: 'oscal-poam', path: poamPath, sha256: sha256Hex(readFileSync(poamPath)) });
  } else {
    coverageDiagnostics.push('coverage:partial — out/poam.json absent (cannot-comply selections rely on operator overrides)');
  }

  const form = buildCommonForm({
    producer,
    scopeMatrices,
    knownPoamItemUuids,
    emittedAt,
    regimeNote: opts.regimeNote,
    sourceDigests,
    coverageDiagnostics,
    aiProfilePractices: opts.aiProfilePractices,
  });

  // Detached signature over the canonical signature-blanked bytes.
  const canonical = serializeUnsignedCanonical(form);
  const canonicalSha = sha256Hex(Buffer.from(canonical, 'utf8'));
  const sig = signDetached(Buffer.from(canonical, 'utf8'), opts.outDir);
  form.provenance.signingKeyId = sig.keyId;
  form.provenance.publicKeyPem = sig.publicKeyPem;
  form.provenance.signatureEd25519 = sig.signatureBase64;

  if (!existsSync(opts.outDir)) mkdirSync(opts.outDir, { recursive: true });

  const jsonPath = resolve(opts.outDir, COMMON_FORM_JSON_FILENAME);
  const jsonBytes = Buffer.from(JSON.stringify(form, null, 2), 'utf8');
  writeFileSync(jsonPath, jsonBytes);

  const sigPath = resolve(opts.outDir, COMMON_FORM_SIG_FILENAME);
  writeFileSync(
    sigPath,
    JSON.stringify(
      { algorithm: 'ed25519', keyId: sig.keyId, publicKeyPem: sig.publicKeyPem, sigBase64: sig.signatureBase64 },
      null,
      2,
    ),
  );

  // Deterministic PDF (docId seeded by the canonical digest, not the signature).
  const pdfBytes = renderCommonFormPdf(form, { docId: canonicalSha });
  const pdfPath = resolve(opts.outDir, COMMON_FORM_PDF_FILENAME);
  writeFileSync(pdfPath, pdfBytes);

  // Sibling coverage (never a fill-rate cell — G2-safe).
  writeCommonFormCoverage(opts.outDir, form.coverage.products);

  const selections: Record<string, CommonFormSelection> = {};
  for (const box of [
    form.attestations.practice_1_secure_environments,
    form.attestations.practice_2_trusted_supply_chains,
    form.attestations.practice_3_data_provenance,
    form.attestations.practice_4_automated_vulnerability_tools,
  ]) {
    selections[box.cisa_practice] = box.selection;
  }

  return {
    json_path: jsonPath,
    pdf_path: pdfPath,
    sig_path: sigPath,
    json_sha256: sha256Hex(jsonBytes),
    pdf_sha256: sha256Hex(pdfBytes),
    selections,
    fill_rates: form.coverage.products,
    ai_profile: producer.ai_profile,
  };
}

/** Merge the per-product fill-rate sibling into out/inventory-coverage.json (creating it if absent). */
function writeCommonFormCoverage(outDir: string, products: ProductFillRate[]): void {
  const path = resolve(outDir, 'inventory-coverage.json');
  let report: Record<string, unknown> = {};
  if (existsSync(path)) {
    try {
      report = JSON.parse(readFileSync(path, 'utf8'));
    } catch {
      report = {};
    }
  }
  const augmented = augmentCoverageWithSsdfCommonForm(report, products);
  writeFileSync(path, JSON.stringify(augmented, null, 2));
}
