/**
 * FAR 52.204-26 Section 889 Part B annual representation emitter (LOOP-W.W4) —
 * the SAM.gov "Covered Telecommunications Equipment or Services — Representation"
 * artifact pair (signed canonical-JSON envelope + printable `.docx`).
 *
 * W.W4 is the ANNUAL counterpart to W.W3's incident-driven 1-business-day
 * reporter. It ingests the W.W2 screen-result envelope
 * (out/prohibited-vendors-screen-result.json), verifies its detached Ed25519
 * signature (a forged screen could fabricate or mask a covered-vendor match and
 * thereby corrupt a legal representation made to the Government), computes the
 * two FAR 52.204-26(c) representation answers deterministically from the
 * non-suppressed matches, links any W.W3 1-business-day incidents that reference
 * the same matches, signs the envelope (detached Ed25519 + `.sig` sidecar),
 * renders the printable `.docx`, records the emission in an append-only ledger
 * (the delta / continuity substrate), and writes the LOOP-Q.Q1 Marketplace
 * "Section 889 Compliant" badge feed.
 *
 * The two representation answers map to FAR 52.204-26(c):
 *   (c)(1) provides_covered_equipment_or_services — driven by matches the
 *          offeror provides to the Government / surfaces in offered products
 *          (subprocessor sheet + inventory provider-tag / SKU surfaces).
 *   (c)(2) uses_covered_equipment_or_services — broader; driven by EVERY
 *          non-suppressed match (the offeror's own SBOM + OCI dependencies
 *          count as "use" even when not delivered to the Government).
 *
 * REO compliance: every emitted value derives from (a) the verified W.W2 screen
 * result, (b) operator config, or (c) the operator-supplied signing material;
 * nothing is invented, sampled, or fabricated. Mandatory operator fields are
 * validated BEFORE any artifact is written — a representation with a missing UEI
 * or unsigned officer block is legally void, so the emitter throws a typed
 * `requires_operator_input` diagnostic rather than emitting a partial artifact.
 * The system NEVER files the representation in SAM.gov on the operator's behalf
 * (REO Rule 4) — it produces the artifact pair; the operator submits.
 */
import {
  readFileSync, writeFileSync, appendFileSync, existsSync, mkdirSync,
} from 'node:fs';
import { resolve, basename } from 'node:path';
import { createHash } from 'node:crypto';
import { canonicalize, signDetached, verifyDetached } from './sign.ts';
import { log } from './log.ts';
import {
  SCREEN_RESULT_FILENAME, SCREEN_RELATED_CONTROLS,
  deterministicUuidFrom,
  type ProhibitedVendorScreenResult,
  type ProhibitedVendorMatch,
  type ScreenSurface,
} from './prohibited-vendors-screen.ts';
import { renderSection889AnnualRepDocx } from './section889-rep-docx.ts';

export const ANNUAL_REP_SCHEMA_VERSION = '1.0.0';
export const ANNUAL_REP_EMITTER = 'core/section889-annual-rep.ts';
export const ANNUAL_REP_EMITTER_VERSION = '1.0.0';
export const ANNUAL_REP_JSON_FILENAME = 'section889-annual-rep.json';
export const ANNUAL_REP_SIG_FILENAME = 'section889-annual-rep.json.sig';
export const ANNUAL_REP_DOCX_FILENAME = 'section889-annual-rep.docx';
export const ANNUAL_REP_LEDGER_FILENAME = 'section889-annual-reps.jsonl';
export const MARKETPLACE_BADGE_FILENAME = 'marketplace-section889-badge.json';

/** The W.W3 1-business-day report ledger W.W4 reads for linked incidents. */
const SECTION889_1BD_LEDGER = 'section889-1bd-reports.jsonl';

/** NIST SP 800-53 Rev 5 SR-family controls this representation evidences. */
export const CONTROLS_EVIDENCED = ['SR-1', 'SR-3', 'SR-5', 'SR-6', 'SR-11'] as const;

/** Default 365-day validity per FAR 52.204-8(d) (the SAM annual cycle). */
export const DEFAULT_VALID_UNTIL_DAYS = 365;

/** Surfaces whose hits count toward FAR 52.204-26(c)(1) "provides to the Government". */
const PROVIDES_SURFACES: ReadonlySet<ScreenSurface> = new Set<ScreenSurface>([
  'subprocessor-sheet',
  'inventory-provider-tag',
]);

const UEI_REGEX = /^[A-Z0-9]{12}$/;
const CAGE_REGEX = /^[A-Z0-9]{5}$/;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export type RepresentationAnswer = 'does' | 'does not';

export interface Address {
  street1: string;
  street2: string;
  city: string;
  state: string;
  zip: string;
  country: string;
}

export interface AnnualRepOfferorConfig {
  legal_name?: string;
  unique_entity_id?: string;
  cage_code?: string;
  duns?: string;
  physical_address?: Partial<Address>;
}

export interface AnnualRepOfficerConfig {
  full_name?: string;
  title?: string;
  email?: string;
  signing_key_id?: string;
}

export interface LinkedIncident {
  incident_id: string;
  reported_at: string;
  contract_number: string;
  status: 'reported' | 'mitigated' | 'open';
}

export interface Section889AnnualRepEnvelope {
  schema_version: typeof ANNUAL_REP_SCHEMA_VERSION;
  envelope_uuid: string;
  emitter: typeof ANNUAL_REP_EMITTER;
  csp_name: string;
  offeror: {
    legal_name: string;
    unique_entity_id: string;
    cage_code: string | null;
    duns: string | null;
    physical_address: Address;
  };
  representation: {
    provides_covered_equipment_or_services: RepresentationAnswer;
    uses_covered_equipment_or_services: RepresentationAnswer;
    rationale: {
      screen_run_id: string;
      catalog_snapshot_id: string;
      catalog_snapshot_sha256: string;
      total_matches: number;
      unsuppressed_matches: number;
      suppressed_matches: number;
      provides_basis: string;
      uses_basis: string;
    };
    linked_incidents: LinkedIncident[];
  };
  reasonable_inquiry: {
    methodology_path: string;
    methodology_sha256: string;
    inquiry_completed_at: string;
    inquiry_scope: {
      subprocessor_count: number;
      sbom_package_count: number;
      oci_image_count: number;
      inventory_asset_count: number;
    };
  };
  sam_review: {
    excluded_parties_review_date: string;
    excluded_parties_snapshot_id: string;
    excluded_parties_snapshot_sha256: string;
  };
  kaspersky_supplement?: {
    statute: 'NDAA-FY2018-§1634';
    bod_reference: 'DHS-BOD-17-01';
    representation_text: string;
  };
  authorized_officer: {
    full_name: string;
    title: string;
    email: string;
    signing_key_id: string;
  };
  signed_at: string;
  valid_until: string;
  previous_envelope_id: string | null;
  controls_evidenced: string[];
  rfc3161_timestamp: {
    status: 'attached' | 'pending';
    tsa_url: string | null;
    token: string | null;
    received_at: string | null;
  };
  provenance: {
    emitter: typeof ANNUAL_REP_EMITTER;
    emitterVersion: string;
    emittedAt: string;
    sourceCalls: string[];
    sourceDigests: Array<{ kind: string; path: string; sha256: string }>;
    signingKeyId: string;
    algorithm: 'ed25519';
    signatureEd25519: string;
    publicKeyPem: string;
  };
}

/** Thrown when the W.W2 screen envelope's detached signature does not verify. */
export class ScreenSignatureInvalidError extends Error {
  readonly path: string;
  constructor(path: string) {
    super(`section889-annual-rep: W.W2 screen-result signature did not verify at ${path}; refusing to compose a FAR 52.204-26 representation from an unverifiable screen (a forged screen could fabricate or mask a covered-vendor match in a legal representation made to the Government).`);
    this.name = 'ScreenSignatureInvalidError';
    this.path = path;
  }
}

/** Thrown when the W.W2 screen result is absent (the representation has no evidentiary basis). */
export class ScreenResultMissingError extends Error {
  constructor(path: string) {
    super(`section889-annual-rep: W.W2 screen result not found at ${path}. Run --prohibited-vendor-screen (W.W2) before --section889-annual-rep so the representation answers derive from a real reasonable-inquiry screen.`);
    this.name = 'ScreenResultMissingError';
  }
}

/** Thrown (strict catalog mode) when the screen's catalog snapshot is stale. */
export class StaleCatalogError extends Error {
  readonly ageHours: number;
  constructor(ageHours: number) {
    super(`section889-annual-rep: the W.W2 screen used a catalog snapshot ${ageHours.toFixed(1)}h old (>24h). A stale snapshot may miss a newly-covered entity and drive a materially-incorrect "does not" representation. Re-run W.W1 + W.W2 against a fresh catalog, or pass lenient mode to proceed with a coverage:stale-catalog warning.`);
    this.name = 'StaleCatalogError';
    this.ageHours = ageHours;
  }
}

/** Thrown when a mandatory operator-supplied field is missing or malformed. */
export class Section889AnnualRepInputError extends Error {
  readonly field: string;
  constructor(field: string, detail?: string) {
    super(`requires_operator_input: ${field}${detail ? ` (${detail})` : ''}`);
    this.name = 'Section889AnnualRepInputError';
    this.field = field;
  }
}

// ─── Operator-input validation ────────────────────────────────────────────────

export interface ValidatedOperatorInputs {
  offeror: Section889AnnualRepEnvelope['offeror'];
  authorizedOfficer: Section889AnnualRepEnvelope['authorized_officer'];
  methodologyPath: string;
  validUntilDays: number;
  warnings: string[];
}

/**
 * Validate every mandatory operator-supplied field per W.W4.md §11. Throws a
 * typed `requires_operator_input` diagnostic on the FIRST missing/invalid
 * mandatory field so the orchestrator never writes a half-filled, legally-void
 * representation. CAGE code is optional (a warning, not a throw).
 */
export function validateOperatorInputs(opts: {
  offeror: AnnualRepOfferorConfig;
  authorizedOfficer: AnnualRepOfficerConfig;
  methodologyPath?: string;
  validUntilDays?: number;
  fileExists?: (p: string) => boolean;
}): ValidatedOperatorInputs {
  const exists = opts.fileExists ?? existsSync;
  const warnings: string[] = [];
  const o = opts.offeror ?? {};
  const officer = opts.authorizedOfficer ?? {};

  const legalName = (o.legal_name ?? '').trim();
  if (!legalName) throw new Section889AnnualRepInputError('offeror.legal_name');

  const uei = (o.unique_entity_id ?? '').trim();
  if (!uei) throw new Section889AnnualRepInputError('offeror.unique_entity_id');
  if (!UEI_REGEX.test(uei)) {
    throw new Section889AnnualRepInputError('offeror.unique_entity_id', 'invalid-format: expected 12 chars [A-Z0-9] per UEI_REGEX');
  }

  const cage = (o.cage_code ?? '').trim();
  if (cage && !CAGE_REGEX.test(cage)) {
    throw new Section889AnnualRepInputError('offeror.cage_code', 'invalid-format: expected 5 chars [A-Z0-9] per CAGE_REGEX');
  }
  if (!cage) warnings.push('offeror.cage_code absent (optional for some entities); proceeding without a CAGE code');

  const addr = o.physical_address ?? {};
  for (const field of ['street1', 'city', 'state', 'zip', 'country'] as const) {
    if (!((addr[field] ?? '').trim())) {
      throw new Section889AnnualRepInputError(`offeror.physical_address.${field}`);
    }
  }

  const officerName = (officer.full_name ?? '').trim();
  if (!officerName) throw new Section889AnnualRepInputError('authorized_officer.full_name');
  const officerTitle = (officer.title ?? '').trim();
  if (!officerTitle) throw new Section889AnnualRepInputError('authorized_officer.title');
  const officerEmail = (officer.email ?? '').trim();
  if (!officerEmail) throw new Section889AnnualRepInputError('authorized_officer.email');
  if (!EMAIL_REGEX.test(officerEmail)) {
    throw new Section889AnnualRepInputError('authorized_officer.email', 'invalid-format');
  }
  const signingKeyId = (officer.signing_key_id ?? '').trim();
  if (!signingKeyId) throw new Section889AnnualRepInputError('authorized_officer.signing_key_id');

  const methodologyPath = (opts.methodologyPath ?? '').trim();
  if (!methodologyPath) throw new Section889AnnualRepInputError('reasonable_inquiry.methodology_path');
  if (!exists(methodologyPath)) {
    throw new Section889AnnualRepInputError('reasonable_inquiry.methodology_path', `file not found: ${methodologyPath}`);
  }

  const validUntilDays = opts.validUntilDays ?? DEFAULT_VALID_UNTIL_DAYS;
  if (!Number.isInteger(validUntilDays) || validUntilDays < 1 || validUntilDays > 730) {
    throw new Section889AnnualRepInputError('valid_until_days', 'out-of-range: expected integer 1..730');
  }

  return {
    offeror: {
      legal_name: legalName,
      unique_entity_id: uei,
      cage_code: cage || null,
      duns: (o.duns ?? '').trim() || null,
      physical_address: {
        street1: (addr.street1 ?? '').trim(),
        street2: (addr.street2 ?? '').trim(),
        city: (addr.city ?? '').trim(),
        state: (addr.state ?? '').trim(),
        zip: (addr.zip ?? '').trim(),
        country: (addr.country ?? '').trim(),
      },
    },
    authorizedOfficer: {
      full_name: officerName,
      title: officerTitle,
      email: officerEmail,
      signing_key_id: signingKeyId,
    },
    methodologyPath,
    validUntilDays,
    warnings,
  };
}

// ─── Representation computation ───────────────────────────────────────────────

export interface RepresentationVerdict {
  provides_status: RepresentationAnswer;
  uses_status: RepresentationAnswer;
  total_matches: number;
  unsuppressed_matches: number;
  suppressed_matches: number;
  provides_basis: string;
  uses_basis: string;
}

function countBySurface(matches: ProhibitedVendorMatch[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const m of matches) out[m.surface] = (out[m.surface] ?? 0) + 1;
  return out;
}

/**
 * Compute the two FAR 52.204-26(c) answers from the screen matches. A match
 * counts only when it is NOT operator-suppressed (a confirmed false positive).
 * (c)(1) "provides" is the narrower set — matches on the subprocessor sheet or an
 * inventory provider-tag/SKU (equipment/services the offeror provides to the
 * Government or surfaces in its offered products). (c)(2) "uses" is broader —
 * EVERY non-suppressed match, because FAR 4.2102 prohibits "use" regardless of
 * whether the item is delivered to the Government. The narratives cite each
 * driving match's surface so a 3PAO can verify the does/does-not split.
 */
export function computeRepresentation(
  matches: ProhibitedVendorMatch[],
  ctx: { screen_run_id: string; catalog_snapshot_id: string; catalog_snapshot_sha256: string;
         subprocessor_count: number; inventory_asset_count: number },
): RepresentationVerdict {
  const total = matches.length;
  const unsuppressed = matches.filter((m) => !m.suppressed);
  const suppressed = total - unsuppressed.length;
  const provides = unsuppressed.filter((m) => PROVIDES_SURFACES.has(m.surface));
  const uses = unsuppressed;

  const providesStatus: RepresentationAnswer = provides.length === 0 ? 'does not' : 'does';
  const usesStatus: RepresentationAnswer = uses.length === 0 ? 'does not' : 'does';

  const snapRef = `screen run ${ctx.screen_run_id} against catalog snapshot ${ctx.catalog_snapshot_id} (SHA-256 ${ctx.catalog_snapshot_sha256.slice(0, 16)}…)`;

  const describe = (ms: ProhibitedVendorMatch[]): string =>
    ms.map((m) => `${m.matched_entity_name} (surface=${m.surface}, confidence=${m.confidence.toFixed(2)} ${m.confidence_band}, source=${m.catalog_provenance.source}, match_id=${m.match_id})`).join('; ');

  let providesBasis: string;
  if (providesStatus === 'does not') {
    providesBasis = `Based on a W.W2 reasonable-inquiry ${snapRef}, no covered telecommunications equipment or services from any catalogued covered entity were found among products or services the offeror provides to the Government. The screen reviewed the subprocessor sheet (${ctx.subprocessor_count} entr${ctx.subprocessor_count === 1 ? 'y' : 'ies'}) and the inventory provider-tag / SKU surfaces (${ctx.inventory_asset_count} asset${ctx.inventory_asset_count === 1 ? '' : 's'}).`;
  } else {
    providesBasis = `Based on a W.W2 reasonable-inquiry ${snapRef}, ${provides.length} non-suppressed covered-entity match${provides.length === 1 ? '' : 'es'} were found among products or services the offeror provides to the Government, on surfaces governed by FAR 4.2102: ${describe(provides)}.`;
  }

  let usesBasis: string;
  if (usesStatus === 'does not') {
    usesBasis = `Based on a W.W2 reasonable-inquiry ${snapRef}, no covered telecommunications equipment or services were found in use by the offeror across the subprocessor sheet, the SBOM (transitive), OCI image publishers, and inventory provider-tag / SKU surfaces.`;
  } else {
    const bySurface = countBySurface(uses);
    const surfaceSummary = Object.entries(bySurface).map(([s, n]) => `${s}=${n}`).join(', ');
    usesBasis = `Based on a W.W2 reasonable-inquiry ${snapRef}, ${uses.length} non-suppressed covered-entity match${uses.length === 1 ? '' : 'es'} were found in use by the offeror (FAR 4.2102 prohibits use regardless of contract performance), across surfaces [${surfaceSummary}]: ${describe(uses)}.`;
  }

  return {
    provides_status: providesStatus,
    uses_status: usesStatus,
    total_matches: total,
    unsuppressed_matches: unsuppressed.length,
    suppressed_matches: suppressed,
    provides_basis: providesBasis,
    uses_basis: usesBasis,
  };
}

// ─── Linked W.W3 incidents (from the 1BD report ledger) ───────────────────────

/**
 * Read the W.W3 1-business-day report ledger and link every incident whose
 * `match_id` is among the unsuppressed matches that drive this representation.
 * Without a tracker DB (none exists in this repo), the append-only ledger
 * `section889-1bd-reports.jsonl` is the durable index of filed incidents.
 */
export function collectLinkedIncidents(ledgerPath: string, matchIds: Set<string>): LinkedIncident[] {
  if (!existsSync(ledgerPath)) return [];
  const out: LinkedIncident[] = [];
  const seen = new Set<string>();
  try {
    for (const line of readFileSync(ledgerPath, 'utf8').split('\n')) {
      const t = line.trim();
      if (!t) continue;
      let rec: Record<string, unknown>;
      try { rec = JSON.parse(t); } catch { continue; }
      const matchId = String(rec.match_id ?? '');
      const reportId = String(rec.report_id ?? '');
      if (!matchId || !matchIds.has(matchId) || seen.has(reportId)) continue;
      seen.add(reportId);
      out.push({
        incident_id: reportId,
        reported_at: String(rec.emitted_at ?? ''),
        contract_number: String(rec.contract_number ?? ''),
        status: 'reported',
      });
    }
  } catch (e) {
    log.warn({ event: 'w.w4.linked_incidents_read_failed', err: String((e as Error)?.message ?? e) });
  }
  return out.sort((a, b) => a.incident_id.localeCompare(b.incident_id));
}

// ─── NDAA §1634 Kaspersky supplement (verbatim published-law text) ────────────

const KASPERSKY_REPRESENTATION_TEXT =
  'Pursuant to NDAA FY2018 §1634 (Pub. L. 115-91) and DHS Binding Operational Directive 17-01, the offeror represents, after a reasonable inquiry, that it does not use any hardware, software, or services developed or provided, in whole or in part, by Kaspersky Lab (or any successor entity), any entity that controls, is controlled by, or is under common control with Kaspersky Lab, or any entity of which Kaspersky Lab has a majority ownership, except as disclosed in the linked-incident annex of this representation. NDAA FY2018 §1634(a): "No department, agency, organization, or other element of the Federal Government shall use, whether directly or through work with or on behalf of another department, agency, organization, or element of the Federal Government, any hardware, software, or services developed or provided, in whole or in part, by— (1) Kaspersky Lab (or any successor entity); (2) any entity that controls, is controlled by, or is under common control with Kaspersky Lab; or (3) any entity of which Kaspersky Lab has a majority ownership."';

// ─── Envelope composition (pure) ──────────────────────────────────────────────

export interface ComposeAnnualRepInput {
  cspName: string;
  offeror: Section889AnnualRepEnvelope['offeror'];
  authorizedOfficer: Section889AnnualRepEnvelope['authorized_officer'];
  verdict: RepresentationVerdict;
  linkedIncidents: LinkedIncident[];
  screen: ProhibitedVendorScreenResult;
  methodologyPath: string;
  methodologySha256: string;
  includeKaspersky: boolean;
  signedAt: string;
  validUntilDays: number;
  previousEnvelopeId: string | null;
  sourceDigests: Array<{ kind: string; path: string; sha256: string }>;
}

/** Compose the representation envelope. Signature fields are left blank for the emitter to fill. */
export function composeAnnualRepEnvelope(input: ComposeAnnualRepInput): Section889AnnualRepEnvelope {
  const screen = input.screen;
  const validUntil = new Date(Date.parse(input.signedAt) + input.validUntilDays * 86400000).toISOString();
  const envelopeUuid = deterministicUuidFrom(['w.w4', screen.run_id, input.offeror.unique_entity_id, input.signedAt]);
  const surfaceCount = (s: ScreenSurface): number =>
    screen.surfaces_screened.find((x) => x.surface === s)?.entries_screened ?? 0;

  const env: Section889AnnualRepEnvelope = {
    schema_version: ANNUAL_REP_SCHEMA_VERSION,
    envelope_uuid: envelopeUuid,
    emitter: ANNUAL_REP_EMITTER,
    csp_name: input.cspName,
    offeror: input.offeror,
    representation: {
      provides_covered_equipment_or_services: input.verdict.provides_status,
      uses_covered_equipment_or_services: input.verdict.uses_status,
      rationale: {
        screen_run_id: screen.run_id,
        catalog_snapshot_id: screen.catalog_snapshot_ref.path,
        catalog_snapshot_sha256: screen.catalog_snapshot_ref.sha256,
        total_matches: input.verdict.total_matches,
        unsuppressed_matches: input.verdict.unsuppressed_matches,
        suppressed_matches: input.verdict.suppressed_matches,
        provides_basis: input.verdict.provides_basis,
        uses_basis: input.verdict.uses_basis,
      },
      linked_incidents: input.linkedIncidents,
    },
    reasonable_inquiry: {
      methodology_path: input.methodologyPath,
      methodology_sha256: input.methodologySha256,
      inquiry_completed_at: screen.completed_at,
      inquiry_scope: {
        subprocessor_count: surfaceCount('subprocessor-sheet'),
        sbom_package_count: surfaceCount('sbom'),
        oci_image_count: surfaceCount('oci-publisher'),
        inventory_asset_count: surfaceCount('inventory-provider-tag'),
      },
    },
    sam_review: {
      excluded_parties_review_date: screen.catalog_snapshot_ref.generated_at,
      excluded_parties_snapshot_id: screen.catalog_snapshot_ref.path,
      excluded_parties_snapshot_sha256: screen.catalog_snapshot_ref.sha256,
    },
    authorized_officer: input.authorizedOfficer,
    signed_at: input.signedAt,
    valid_until: validUntil,
    previous_envelope_id: input.previousEnvelopeId,
    controls_evidenced: [...CONTROLS_EVIDENCED],
    rfc3161_timestamp: { status: 'pending', tsa_url: null, token: null, received_at: null },
    provenance: {
      emitter: ANNUAL_REP_EMITTER,
      emitterVersion: ANNUAL_REP_EMITTER_VERSION,
      emittedAt: input.signedAt,
      sourceCalls: input.sourceDigests.map((d) => `${d.kind}:${d.path}`),
      sourceDigests: input.sourceDigests,
      signingKeyId: '',
      algorithm: 'ed25519',
      signatureEd25519: '',
      publicKeyPem: '',
    },
  };

  if (input.includeKaspersky) {
    env.kaspersky_supplement = {
      statute: 'NDAA-FY2018-§1634',
      bod_reference: 'DHS-BOD-17-01',
      representation_text: KASPERSKY_REPRESENTATION_TEXT,
    };
  }
  return env;
}

/**
 * The canonical signature-blanked bytes the detached Ed25519 signature covers.
 * The three provenance signature fields are blanked because they are filled
 * FROM the signature; everything else (including signed_at / valid_until /
 * envelope_uuid / the representation answers) is part of the signed payload.
 */
export function canonicalAnnualRepBytes(env: Section889AnnualRepEnvelope): string {
  const blanked: Section889AnnualRepEnvelope = {
    ...env,
    provenance: { ...env.provenance, signingKeyId: '', publicKeyPem: '', signatureEd25519: '' },
  };
  return canonicalize(JSON.parse(JSON.stringify(blanked)));
}

/** Verify a representation envelope's detached signature (tests + 3PAO tooling). */
export function verifySection889AnnualRep(env: Section889AnnualRepEnvelope): boolean {
  if (!env.provenance?.signatureEd25519 || !env.provenance?.publicKeyPem) return false;
  return verifyDetached(Buffer.from(canonicalAnnualRepBytes(env), 'utf8'), {
    publicKeyPem: env.provenance.publicKeyPem,
    signatureBase64: env.provenance.signatureEd25519,
  });
}

// ─── LOOP-Q.Q1 Marketplace badge feed ─────────────────────────────────────────

export interface MarketplaceBadge {
  schema_version: '1.0.0';
  emitter: 'section889-marketplace-badge';
  badge: {
    enabled: boolean;
    label: string;
    envelope_uuid: string;
    valid_until: string;
    provides_status: RepresentationAnswer;
    uses_status: RepresentationAnswer;
    verification_url_pattern: string;
  };
  provenance: {
    emitter: string;
    emitterVersion: string;
    emittedAt: string;
    sourceCalls: string[];
    signingKeyId: string;
  };
}

/**
 * Build the LOOP-Q.Q1 "Section 889 Compliant" badge feed. The badge is enabled
 * iff BOTH representation answers are "does not" AND the representation is still
 * within its validity window (Q.Q1 grey-lists an expired or affirmative rep).
 */
export function buildMarketplaceBadge(
  env: Section889AnnualRepEnvelope,
  now: string,
): MarketplaceBadge {
  const both = env.representation.provides_covered_equipment_or_services === 'does not'
    && env.representation.uses_covered_equipment_or_services === 'does not';
  const current = Date.parse(env.valid_until) > Date.parse(now);
  const enabled = both && current;
  return {
    schema_version: '1.0.0',
    emitter: 'section889-marketplace-badge',
    badge: {
      enabled,
      label: enabled ? 'Section 889 Compliant' : 'Section 889 representation not current',
      envelope_uuid: env.envelope_uuid,
      valid_until: env.valid_until,
      provides_status: env.representation.provides_covered_equipment_or_services,
      uses_status: env.representation.uses_covered_equipment_or_services,
      verification_url_pattern: `sha256:${env.provenance.signingKeyId}`,
    },
    provenance: {
      emitter: ANNUAL_REP_EMITTER,
      emitterVersion: ANNUAL_REP_EMITTER_VERSION,
      emittedAt: env.signed_at,
      sourceCalls: [`section889-annual-rep:${ANNUAL_REP_JSON_FILENAME}`],
      signingKeyId: env.provenance.signingKeyId,
    },
  };
}

// ─── Ledger (delta / continuity substrate) ────────────────────────────────────

export interface AnnualRepLedgerRow {
  envelope_uuid: string;
  signed_at: string;
  valid_until: string;
  provides_status: RepresentationAnswer;
  uses_status: RepresentationAnswer;
  screen_run_id: string;
  catalog_snapshot_id: string;
  unsuppressed_match_count: number;
  json_sha256: string;
  json_path: string;
  docx_path: string;
}

/** Read the most-recent prior representation row from the ledger (for delta + flip detection). */
export function readPriorRep(ledgerPath: string): AnnualRepLedgerRow | null {
  if (!existsSync(ledgerPath)) return null;
  let last: AnnualRepLedgerRow | null = null;
  try {
    for (const line of readFileSync(ledgerPath, 'utf8').split('\n')) {
      const t = line.trim();
      if (!t) continue;
      try {
        const rec = JSON.parse(t) as AnnualRepLedgerRow;
        if (rec?.envelope_uuid && rec?.signed_at) last = rec;
      } catch { /* skip malformed line */ }
    }
  } catch (e) {
    log.warn({ event: 'w.w4.ledger_read_failed', err: String((e as Error)?.message ?? e) });
  }
  return last;
}

export interface RepresentationFlip {
  dimension: 'provides' | 'uses';
  from: RepresentationAnswer;
  to: RepresentationAnswer;
}

/** Detect a representation flip (e.g. "does not" → "does") vs the prior rep. */
export function detectFlips(prior: AnnualRepLedgerRow | null, env: Section889AnnualRepEnvelope): RepresentationFlip[] {
  if (!prior) return [];
  const flips: RepresentationFlip[] = [];
  if (prior.provides_status !== env.representation.provides_covered_equipment_or_services) {
    flips.push({ dimension: 'provides', from: prior.provides_status, to: env.representation.provides_covered_equipment_or_services });
  }
  if (prior.uses_status !== env.representation.uses_covered_equipment_or_services) {
    flips.push({ dimension: 'uses', from: prior.uses_status, to: env.representation.uses_covered_equipment_or_services });
  }
  return flips;
}

// ─── End-to-end emit (I/O) ─────────────────────────────────────────────────────

export interface Section889AnnualRepOptions {
  outDir: string;
  runId: string;
  cspName: string;
  offeror: AnnualRepOfferorConfig;
  authorizedOfficer: AnnualRepOfficerConfig;
  reasonableInquiryMethodologyPath?: string;
  includeKasperskyAttachment?: boolean;
  validUntilDays?: number;
  /** W.W2 envelope path. Defaults to <outDir>/prohibited-vendors-screen-result.json. */
  screenEnvelopePath?: string;
  /** Verify the W.W2 envelope signature before consuming it. Default true. */
  verifyScreenSignature?: boolean;
  /** W.W3 1BD report ledger path (linked incidents). Defaults to <outDir>/section889-1bd-reports.jsonl. */
  oneBdLedgerPath?: string;
  /** Annual-rep ledger path. Defaults to <outDir>/section889-annual-reps.jsonl. */
  ledgerPath?: string;
  /** Deterministic clock (tests). Defaults to now. */
  signedAt?: string;
  /** Strict catalog freshness: throw StaleCatalogError when the screen's snapshot is >24h old. */
  strictCatalogFreshness?: boolean;
}

export interface Section889AnnualRepResult {
  envelope: Section889AnnualRepEnvelope;
  json_path: string;
  sig_path: string;
  docx_path: string;
  marketplace_feed_path: string;
  ledger_path: string;
  provides_status: RepresentationAnswer;
  uses_status: RepresentationAnswer;
  previous_envelope_id: string | null;
  flips: RepresentationFlip[];
  linked_incidents_count: number;
  badge_enabled: boolean;
  warnings: string[];
}

function sha256Hex(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

function relForProvenance(outDir: string, path: string): string {
  try { if (resolve(path).startsWith(resolve(outDir))) return basename(path); } catch { /* fall through */ }
  return path;
}

/** Re-derive the W.W2 envelope's canonical signature-blanked bytes for verification. */
function w2CanonicalBlanked(env: ProhibitedVendorScreenResult): string {
  const blanked = {
    ...env,
    provenance: { ...env.provenance, signingKeyId: '', publicKeyPem: '', signatureEd25519: '' },
  };
  return canonicalize(JSON.parse(JSON.stringify(blanked)));
}

/**
 * End-to-end W.W4 pass: verify + ingest the W.W2 screen, validate operator
 * inputs, compute the FAR 52.204-26(c) answers, link W.W3 incidents, sign the
 * envelope, render the `.docx`, append the ledger row, write the Marketplace
 * badge feed, and augment coverage. Throws on a screen-signature failure, a
 * stale catalog (strict mode), or a missing mandatory operator input — in every
 * throwing case NO artifact is written (a representation is all-or-nothing).
 */
export function emitSection889AnnualRep(opts: Section889AnnualRepOptions): Section889AnnualRepResult {
  const signedAt = opts.signedAt ?? new Date().toISOString();
  const screenPath = opts.screenEnvelopePath ?? resolve(opts.outDir, SCREEN_RESULT_FILENAME);

  if (!existsSync(screenPath)) throw new ScreenResultMissingError(screenPath);
  const screen = JSON.parse(readFileSync(screenPath, 'utf8')) as ProhibitedVendorScreenResult;

  // ── Verify the W.W2 envelope signature (REO: never represent from a forged screen) ──
  if (opts.verifyScreenSignature !== false) {
    const canonical = w2CanonicalBlanked(screen);
    const ok = !!screen.provenance?.signatureEd25519 && !!screen.provenance?.publicKeyPem
      && verifyDetached(Buffer.from(canonical, 'utf8'), {
        publicKeyPem: screen.provenance.publicKeyPem,
        signatureBase64: screen.provenance.signatureEd25519,
      });
    if (!ok) throw new ScreenSignatureInvalidError(screenPath);
  }

  // ── Catalog freshness gate ──
  const warnings: string[] = [];
  if (screen.catalog_snapshot_ref.is_stale) {
    if (opts.strictCatalogFreshness) throw new StaleCatalogError(screen.catalog_snapshot_ref.age_hours);
    warnings.push(`coverage:stale-catalog the W.W2 screen used a catalog snapshot ${screen.catalog_snapshot_ref.age_hours.toFixed(1)}h old (>24h); the representation may miss a newly-covered entity`);
    log.warn({ event: 'w.w4.stale_catalog', age_hours: screen.catalog_snapshot_ref.age_hours });
  }

  // ── Validate operator inputs (throws before any write) ──
  const validated = validateOperatorInputs({
    offeror: opts.offeror,
    authorizedOfficer: opts.authorizedOfficer,
    methodologyPath: opts.reasonableInquiryMethodologyPath,
    validUntilDays: opts.validUntilDays,
  });
  warnings.push(...validated.warnings);

  // ── Compute the representation answers ──
  const subprocessorCount = screen.surfaces_screened.find((s) => s.surface === 'subprocessor-sheet')?.entries_screened ?? 0;
  const inventoryAssetCount = screen.surfaces_screened.find((s) => s.surface === 'inventory-provider-tag')?.entries_screened ?? 0;
  const verdict = computeRepresentation(screen.matches ?? [], {
    screen_run_id: screen.run_id,
    catalog_snapshot_id: screen.catalog_snapshot_ref.path,
    catalog_snapshot_sha256: screen.catalog_snapshot_ref.sha256,
    subprocessor_count: subprocessorCount,
    inventory_asset_count: inventoryAssetCount,
  });

  // ── Link W.W3 1-business-day incidents that reference the driving matches ──
  const oneBdLedgerPath = opts.oneBdLedgerPath ?? resolve(opts.outDir, SECTION889_1BD_LEDGER);
  const drivingMatchIds = new Set((screen.matches ?? []).filter((m) => !m.suppressed).map((m) => m.match_id));
  const linkedIncidents = collectLinkedIncidents(oneBdLedgerPath, drivingMatchIds);

  // ── Prior representation (delta + flip detection) ──
  const ledgerPath = opts.ledgerPath ?? resolve(opts.outDir, ANNUAL_REP_LEDGER_FILENAME);
  const prior = readPriorRep(ledgerPath);

  // ── Provenance source digests ──
  const screenSha = sha256Hex(readFileSync(screenPath));
  const methodologySha = sha256Hex(readFileSync(validated.methodologyPath));
  const sourceDigests = [
    { kind: 'prohibited-vendors-screen-envelope', path: relForProvenance(opts.outDir, screenPath), sha256: screenSha },
    { kind: 'reasonable-inquiry-methodology', path: relForProvenance(opts.outDir, validated.methodologyPath), sha256: methodologySha },
    { kind: 'prohibited-vendors-catalog-snapshot', path: screen.catalog_snapshot_ref.path, sha256: screen.catalog_snapshot_ref.sha256 },
  ];

  // ── Compose + sign ──
  const env = composeAnnualRepEnvelope({
    cspName: opts.cspName,
    offeror: validated.offeror,
    authorizedOfficer: validated.authorizedOfficer,
    verdict,
    linkedIncidents,
    screen,
    methodologyPath: relForProvenance(opts.outDir, validated.methodologyPath),
    methodologySha256: methodologySha,
    includeKaspersky: opts.includeKasperskyAttachment !== false,
    signedAt,
    validUntilDays: validated.validUntilDays,
    previousEnvelopeId: prior?.envelope_uuid ?? null,
    sourceDigests,
  });

  const canonical = canonicalAnnualRepBytes(env);
  const sig = signDetached(Buffer.from(canonical, 'utf8'), opts.outDir);
  env.provenance.signingKeyId = sig.keyId;
  env.provenance.publicKeyPem = sig.publicKeyPem;
  env.provenance.signatureEd25519 = sig.signatureBase64;

  const flips = detectFlips(prior, env);
  for (const f of flips) {
    log.warn({ event: 'w.w4.representation_flip', dimension: f.dimension, from: f.from, to: f.to, envelope_uuid: env.envelope_uuid });
  }

  // ── Write artifacts (only after every gate has passed) ──
  const jsonPath = resolve(opts.outDir, ANNUAL_REP_JSON_FILENAME);
  const jsonBytes = Buffer.from(JSON.stringify(env, null, 2), 'utf8');
  writeFileSync(jsonPath, jsonBytes);
  const sigPath = resolve(opts.outDir, ANNUAL_REP_SIG_FILENAME);
  writeFileSync(sigPath, JSON.stringify({ algorithm: 'ed25519', keyId: sig.keyId, publicKeyPem: sig.publicKeyPem, sigBase64: sig.signatureBase64 }, null, 2));
  const docxPath = resolve(opts.outDir, ANNUAL_REP_DOCX_FILENAME);
  writeFileSync(docxPath, renderSection889AnnualRepDocx(env));

  const badge = buildMarketplaceBadge(env, signedAt);
  const marketplacePath = resolve(opts.outDir, MARKETPLACE_BADGE_FILENAME);
  writeFileSync(marketplacePath, JSON.stringify(badge, null, 2));

  // ── Ledger row (delta / continuity substrate) ──
  appendFileSync(ledgerPath, JSON.stringify({
    envelope_uuid: env.envelope_uuid,
    signed_at: env.signed_at,
    valid_until: env.valid_until,
    provides_status: env.representation.provides_covered_equipment_or_services,
    uses_status: env.representation.uses_covered_equipment_or_services,
    screen_run_id: env.representation.rationale.screen_run_id,
    catalog_snapshot_id: env.representation.rationale.catalog_snapshot_id,
    unsuppressed_match_count: env.representation.rationale.unsuppressed_matches,
    json_sha256: sha256Hex(jsonBytes),
    json_path: ANNUAL_REP_JSON_FILENAME,
    docx_path: ANNUAL_REP_DOCX_FILENAME,
  } satisfies AnnualRepLedgerRow) + '\n');

  augmentCoverage(opts.outDir, env, linkedIncidents.length);

  log.info({
    event: 'w.w4.annual_rep_emitted',
    run_id: opts.runId,
    envelope_uuid: env.envelope_uuid,
    provides_status: env.representation.provides_covered_equipment_or_services,
    uses_status: env.representation.uses_covered_equipment_or_services,
    unsuppressed_matches: env.representation.rationale.unsuppressed_matches,
    linked_incidents: linkedIncidents.length,
    valid_until: env.valid_until,
    badge_enabled: badge.badge.enabled,
    flips: flips.length,
  });

  return {
    envelope: env,
    json_path: jsonPath,
    sig_path: sigPath,
    docx_path: docxPath,
    marketplace_feed_path: marketplacePath,
    ledger_path: ledgerPath,
    provides_status: env.representation.provides_covered_equipment_or_services,
    uses_status: env.representation.uses_covered_equipment_or_services,
    previous_envelope_id: env.previous_envelope_id,
    flips,
    linked_incidents_count: linkedIncidents.length,
    badge_enabled: badge.badge.enabled,
    warnings,
  };
}

function augmentCoverage(outDir: string, env: Section889AnnualRepEnvelope, linkedIncidents: number): void {
  const covPath = resolve(outDir, 'inventory-coverage.json');
  if (!existsSync(covPath)) return;
  try {
    const cov = JSON.parse(readFileSync(covPath, 'utf8'));
    cov.section889_annual_rep_coverage = {
      envelope_uuid: env.envelope_uuid,
      provides_status: env.representation.provides_covered_equipment_or_services,
      uses_status: env.representation.uses_covered_equipment_or_services,
      total_matches: env.representation.rationale.total_matches,
      unsuppressed_matches: env.representation.rationale.unsuppressed_matches,
      linked_incidents: linkedIncidents,
      valid_until: env.valid_until,
      controls_evidenced: env.controls_evidenced,
    };
    writeFileSync(covPath, JSON.stringify(cov, null, 2));
  } catch (e) {
    log.warn({ event: 'w.w4.coverage_augment_failed', err: String((e as Error)?.message ?? e) });
  }
}

/** Re-export the related controls for callers that cross-reference the SR family. */
export { SCREEN_RELATED_CONTROLS };
