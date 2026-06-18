/**
 * FAR 52.204-25(d) report envelope — types, reportable-match filter, statutory-
 * basis routing, and the canonical-JSON composer (LOOP-W.W3).
 *
 * Consumes the `ProhibitedVendorMatch` records emitted by the W.W2 screen
 * (core/prohibited-vendors-screen.ts) and composes one signed report envelope
 * per (reportable match × affected contract). The nine FAR 52.204-25(d)(2)(i)
 * data elements are read from the match's `far_52_204_25_d_data_elements` block
 * (pre-filled by W.W2, with `REQUIRES-OPERATOR-INPUT` markers where the operator
 * must supply UEI / CAGE / brand / model); W.W3 never invents them.
 *
 * The envelope carries a top-level camelCase `provenance` block (emitter,
 * emittedAt, sourceCalls) so the REO G3 provenance check passes, and the
 * detached Ed25519 signature is recorded in that block + a `.sig` sidecar — the
 * exact signing idiom of the W.W1 catalog and W.W2 screen result. The disk /
 * signing / docx wiring lives in `core/section889-1bd-reporter.ts`; this module
 * is pure (no I/O) so the composition + routing logic is fixture-testable.
 */
import { createHash } from 'node:crypto';
import { canonicalize } from './sign.ts';
import {
  REQUIRES_OPERATOR_INPUT,
  type ProhibitedVendorMatch,
  type ScreenSource,
} from './prohibited-vendors-screen.ts';

export const SECTION889_REPORT_SCHEMA_VERSION = '1.0.0';
export const SECTION889_REPORTS_DIRNAME = 'section889-1bd-reports';
export const SECTION889_REPORTS_LEDGER = 'section889-1bd-reports.jsonl';
export const SECTION889_REPORTER_EMITTER = 'core/section889-1bd-reporter.ts';
export const SECTION889_REPORTER_VERSION = '1.0.0';

export type Section889ReportKind = 'initial-1bd' | 'follow-up-10bd';
export type Section889DiscoveryKind = 'screen-run' | 'subcontractor-notification' | 'other-source';
export type Section889EndpointType = 'civilian-co-email' | 'dod-dibnet';

export type StatutoryBasis =
  | 'far-52.204-25-a-1'         // Huawei / ZTE
  | 'far-52.204-25-a-2'         // Hytera / Hikvision / Dahua
  | 'far-52.204-25-a-3'         // services provided by / using such equipment
  | 'far-52.204-25-a-4'         // SecDef-designated covered foreign country entity
  | 'ndaa-2019-sec-889-f-2-A'
  | 'ndaa-2019-sec-889-f-2-B'
  | 'ndaa-2019-sec-889-f-2-C'
  | 'ndaa-2019-sec-889-f-2-D'
  | 'ndaa-2018-sec-1634'        // Kaspersky (statutory)
  | 'dhs-bod-17-01'             // Kaspersky (operational directive)
  | 'operator-addition';

/** The nine FAR 52.204-25(d)(2)(i) data elements due within one business day. */
export interface FarD2iElements {
  contract_number: string;
  order_numbers: string[];
  supplier_name: string;
  supplier_uei: string;
  supplier_cage_code: string;
  brand: string;
  model_number: string;
  item_description: string;
  mitigation_actions: string;
}

/** The FAR 52.204-25(d)(2)(ii) follow-up content (10-business-day report). */
export interface FarD2iiContent {
  additional_mitigation_actions: string;
  prevention_efforts_undertaken: string;
  future_prevention_efforts: string;
}

export interface Section889SigningOfficer {
  name: string;
  title: string;
  key_id: string;
  key_version: string;
}

export interface Section8891bdReport {
  schema_version: typeof SECTION889_REPORT_SCHEMA_VERSION;
  report_id: string;
  report_kind: Section889ReportKind;
  generated_at: string;
  emitted_at: string;
  csp_name: string;
  csp_uei: string;
  csp_cage_code: string;

  source_screen_envelope_ref: { path: string; sha256: string; run_id: string };
  source_match_id: string;
  catalog_snapshot_ref: { path: string; sha256: string; generated_at: string };
  poam_item_uuid: string;
  source_initial_report_id?: string;   // set on follow-up-10bd reports

  far_d_2_i: FarD2iElements;
  far_d_2_ii?: FarD2iiContent;

  discovered_at: string;
  discovery_kind: Section889DiscoveryKind;
  federal_business_hours_tz: string;
  deadline_at: string;
  business_hours_remaining_at_emit: number;

  endpoint_type: Section889EndpointType;
  contracting_officer_email: string | null;
  dibnet_url: string | null;
  is_subcontract_report: boolean;
  prime_contractor_uei: string | null;

  statutory_basis: StatutoryBasis[];
  waiver_id: string | null;

  signing_officer: Section889SigningOfficer;

  rfc3161_timestamp: {
    status: 'attached' | 'pending';
    tsa_url: string | null;
    token: string | null;
    received_at: string | null;
  };

  provenance: {
    emitter: string;
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

// ─── Reportable-match filter ──────────────────────────────────────────────────

/** Catalog sources whose hits trigger a FAR 52.204-25(d) / NDAA §1634 report. */
const REPORTABLE_SOURCES: ReadonlySet<ScreenSource> = new Set<ScreenSource>([
  'far-52-204-25',
  'ndaa-889',
  'ndaa-1634',
  'operator-manual-addition',
]);

/**
 * A match is reportable under FAR 52.204-25(d) when it is a non-suppressed,
 * high-confidence positive identification against a Section 889 / Kaspersky /
 * operator-addition catalog source. This mirrors the W.W2 `reportable_*`
 * predicate so the reporter never re-litigates the upstream "is this covered"
 * verdict.
 */
export function isReportableMatch(m: ProhibitedVendorMatch): boolean {
  return !m.suppressed
    && m.confidence_band === 'high'
    && REPORTABLE_SOURCES.has(m.catalog_provenance.source);
}

const PART_A2_NAMES = ['hytera', 'hikvision', 'dahua'];
const PART_A1_NAMES = ['huawei', 'zte'];
const KASPERSKY_NAMES = ['kaspersky'];

/**
 * Map a reportable match to its statutory citation array. Section 889 hits cite
 * the FAR paragraph + the parallel NDAA §889(f)(2) subparagraph, refined to the
 * specific Part A-1 (Huawei/ZTE) vs Part A-2 (Hytera/Hikvision/Dahua) entity
 * when the matched name is one of the named entities; otherwise the general
 * citation is used (honest — the reporter does not guess a more specific
 * paragraph than the evidence supports). Kaspersky (NDAA §1634) hits are
 * reported under the FAR 52.204-25(d) framework with both authorities cited.
 */
export function statutoryBasisFor(m: ProhibitedVendorMatch): StatutoryBasis[] {
  const source = m.catalog_provenance.source;
  const name = `${m.matched_entity_name} ${m.far_52_204_25_d_data_elements.supplier_name}`.toLowerCase();

  if (source === 'ndaa-1634' || KASPERSKY_NAMES.some((n) => name.includes(n))) {
    return ['ndaa-2018-sec-1634', 'dhs-bod-17-01'];
  }
  if (source === 'operator-manual-addition') {
    return ['operator-addition'];
  }
  // Section 889 sources: far-52-204-25 / ndaa-889
  if (PART_A1_NAMES.some((n) => name.includes(n))) {
    return ['far-52.204-25-a-1', 'ndaa-2019-sec-889-f-2-A'];
  }
  if (PART_A2_NAMES.some((n) => name.includes(n))) {
    return ['far-52.204-25-a-2', 'ndaa-2019-sec-889-f-2-B'];
  }
  // Named-entity unknown but source is a Section 889 list → general citation.
  return ['far-52.204-25-a-4', 'ndaa-2019-sec-889-f-2-D'];
}

// ─── Composition ──────────────────────────────────────────────────────────────

/** Deterministic, idempotency-aligned report id derived from the dedupe key. */
export function reportIdFor(runId: string, matchId: string, contractNumber: string, kind: Section889ReportKind): string {
  const h = createHash('sha256').update([runId, matchId, contractNumber, kind].join('|')).digest('hex');
  return `s889-${h.slice(0, 26)}`;
}

export interface ComposeReportInput {
  reportKind: Section889ReportKind;
  match: ProhibitedVendorMatch;
  contractNumber: string;
  orderNumbers?: string[];
  endpointType: Section889EndpointType;
  contractingOfficerEmail: string | null;
  isSubcontractReport: boolean;
  primeContractorUei: string | null;

  cspName: string;
  cspUei: string;
  cspCageCode: string;

  runId: string;
  screenEnvelopePath: string;
  screenEnvelopeSha256: string;
  catalogSnapshotRef: { path: string; sha256: string; generated_at: string };

  discoveryKind: Section889DiscoveryKind;
  federalBusinessHoursTz: string;
  deadlineAt: string;
  businessHoursRemainingAtEmit: number;

  signingOfficer: Section889SigningOfficer;
  waiverId?: string | null;
  generatedAt: string;
  emittedAt: string;

  sourceDigests: Array<{ kind: string; path: string; sha256: string }>;
  followUp?: FarD2iiContent;
  sourceInitialReportId?: string;
}

/**
 * Compose one report envelope for a (reportable match × affected contract).
 * The provenance signature fields are left blank; the reporter module fills +
 * signs them via `core/sign.ts` (matching the W.W1/W.W2 detached-signature
 * idiom).
 */
export function composeReportEnvelope(input: ComposeReportInput): Section8891bdReport {
  const far = input.match.far_52_204_25_d_data_elements;
  const report_id = reportIdFor(input.runId, input.match.match_id, input.contractNumber, input.reportKind);

  const env: Section8891bdReport = {
    schema_version: SECTION889_REPORT_SCHEMA_VERSION,
    report_id,
    report_kind: input.reportKind,
    generated_at: input.generatedAt,
    emitted_at: input.emittedAt,
    csp_name: input.cspName,
    csp_uei: input.cspUei,
    csp_cage_code: input.cspCageCode,

    source_screen_envelope_ref: {
      path: input.screenEnvelopePath,
      sha256: input.screenEnvelopeSha256,
      run_id: input.runId,
    },
    source_match_id: input.match.match_id,
    catalog_snapshot_ref: input.catalogSnapshotRef,
    poam_item_uuid: input.match.poam_item_uuid,

    far_d_2_i: {
      contract_number: input.contractNumber,
      order_numbers: input.orderNumbers ?? far.order_numbers ?? [],
      supplier_name: far.supplier_name,
      supplier_uei: far.supplier_uei,
      supplier_cage_code: far.supplier_cage_code,
      brand: far.brand,
      model_number: far.model_number,
      item_description: far.item_description,
      mitigation_actions: far.mitigation_actions,
    },

    discovered_at: input.match.discovered_at,
    discovery_kind: input.discoveryKind,
    federal_business_hours_tz: input.federalBusinessHoursTz,
    deadline_at: input.deadlineAt,
    business_hours_remaining_at_emit: input.businessHoursRemainingAtEmit,

    endpoint_type: input.endpointType,
    contracting_officer_email: input.contractingOfficerEmail,
    dibnet_url: input.endpointType === 'dod-dibnet' ? 'https://dibnet.dod.mil/' : null,
    is_subcontract_report: input.isSubcontractReport,
    prime_contractor_uei: input.primeContractorUei,

    statutory_basis: statutoryBasisFor(input.match),
    waiver_id: input.waiverId ?? null,

    signing_officer: input.signingOfficer,

    rfc3161_timestamp: { status: 'pending', tsa_url: null, token: null, received_at: null },

    provenance: {
      emitter: SECTION889_REPORTER_EMITTER,
      emitterVersion: SECTION889_REPORTER_VERSION,
      emittedAt: input.emittedAt,
      sourceCalls: input.sourceDigests.map((d) => `${d.kind}:${d.path}`),
      sourceDigests: input.sourceDigests,
      signingKeyId: '',
      algorithm: 'ed25519',
      signatureEd25519: '',
      publicKeyPem: '',
    },
  };

  if (input.reportKind === 'follow-up-10bd' && input.followUp) {
    env.far_d_2_ii = input.followUp;
  }
  if (input.sourceInitialReportId) {
    env.source_initial_report_id = input.sourceInitialReportId;
  }
  return env;
}

/**
 * The canonical signature-blanked bytes a detached Ed25519 signature covers.
 * Both the provenance signature fields AND the signature-derived
 * `signing_officer.key_id` / `key_version` are blanked: the latter are
 * convenience copies of the signing key's fingerprint (recomputable from
 * `provenance.publicKeyPem`), so they are filled from the signature and
 * therefore must not be part of the signed payload.
 */
export function canonicalReportBytes(env: Section8891bdReport): string {
  const blanked: Section8891bdReport = {
    ...env,
    signing_officer: { ...env.signing_officer, key_id: '', key_version: '' },
    provenance: { ...env.provenance, signingKeyId: '', publicKeyPem: '', signatureEd25519: '' },
  };
  return canonicalize(JSON.parse(JSON.stringify(blanked)));
}

/** Has the operator supplied every (d)(2)(i) element, or are completions pending? */
export function pendingOperatorFields(env: Section8891bdReport): string[] {
  const far = env.far_d_2_i;
  const out: string[] = [];
  for (const [k, v] of Object.entries(far)) {
    if (v === REQUIRES_OPERATOR_INPUT) out.push(k);
  }
  return out;
}
