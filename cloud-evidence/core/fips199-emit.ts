/**
 * FIPS 199 security-categorization worksheet emitter — LOOP-C.C5.
 *
 * Renders `fips199.docx` — the CIA-impact-level categorization worksheet that
 * satisfies NIST SP 800-53 Rev. 5 control RA-2 (Security Categorization). The
 * system-level Security Category (SC) is computed as the high-water-mark across
 * the operator-supplied information types (drawn from the NIST SP 800-60 Vol. 2
 * Rev. 1 catalogue in core/fips199-types.ts). The worksheet cross-checks its
 * computed SC against the emitted OSCAL SSP's
 * `system-characteristics.security-impact-level` and reports CONSISTENT or
 * MISMATCH — the check a 3PAO performs during the RA-2 assessment.
 *
 * Authoritative sources (verbatim, cited in §1.2 + the provenance footer):
 *   - FIPS PUB 199 (2004-02), "Standards for Security Categorization of Federal
 *     Information and Information Systems" —
 *     https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.199.pdf
 *     §3 (p. 2) loss definitions; LOW / MODERATE / HIGH potential-impact
 *     definitions; the SC formula; and the high-water-mark practice — all quoted
 *     verbatim below.
 *   - FIPS PUB 200 (2006-03), "Minimum Security Requirements for Federal
 *     Information and Information Systems" —
 *     https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.200.pdf — the bridge from
 *     FIPS 199 categorization to the SP 800-53 baseline (cited in §4).
 *   - NIST SP 800-60 Vol. 1 Rev. 1 (2008-08) §3.1 — the information-type
 *     identification process (cited in §2 Methodology).
 *   - NIST SP 800-60 Vol. 2 Rev. 1 (2008-08) Appendix C/D — the information-type
 *     catalogue (core/fips199-types.ts).
 *   - NIST SP 800-53 Rev. 5 RA-2 —
 *     https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final.
 *   - FedRAMP SSP Attachment 10 — FIPS 199 Categorization Template (Rev4) —
 *     section ordering: Title → Information Types → Overall SC → Rationale →
 *     Signature.
 *
 * Approach (dependency-free .docx): a `.docx` is a ZIP of WordprocessingML XML
 * parts. We build the parts as strings and pack them with the store-only ZIP
 * writer the SSP-2 + RoE + CMP renderers use (core/zip.ts) — no external Word
 * library, no runtime network. The OOXML building blocks mirror cmp-emit.ts;
 * the shared docx-primitives module proposed in LOOP-C-SPEC §4 was never
 * extracted (LOOP-C-RISKS C-X-1 / C-C1-6..C-C4-8), so this emitter keeps its
 * OOXML constants local like the ten shipped docx emitters.
 *
 * REO compliance:
 *   - The overall SC is computed by `computeOverallSC()` over the operator's
 *     real information types — there is NO hardcoded "moderate/moderate/moderate"
 *     default. Zero information types → a single REQUIRES-OPERATOR-INPUT §3 row
 *     with the SP 800-60 V2 selection guidance quoted verbatim (never a
 *     fabricated info type).
 *   - The SSP cross-reference cites the real out/ssp.json path + SHA-256 in the
 *     provenance footer and compares the worksheet SC against the SSP value.
 *   - Impact-level definitions in §1.2 are verbatim FIPS 199 §3 quotes.
 *   - SP 800-60 V2 codes are NIST-published constants (REO Rule 3 allowed
 *     exception); the module header of core/fips199-types.ts declares
 *     SOURCE_VERSION for later-bump traceability.
 *   - The document is fully deterministic (no wall-clock time): the metadata
 *     UUID is `deterministicUuid('fips199:' + systemId + ':' + runId)` and the
 *     SSP provenance is a content SHA-256, so identical inputs produce a
 *     byte-identical .docx. Integrity is anchored by the signed submission-
 *     bundle INDEX.json (SHA-256 + Ed25519), the same coverage cmp.docx receives.
 *   - The §6 approval signature cells stay REQUIRES-OPERATOR-INPUT — the system
 *     never auto-signs a human attestation (REO Rule 1.10); RA-2.c requires the
 *     AO (or designee) to review and approve the categorization.
 *
 * Pure renderer (`renderFips199Docx` / `buildFips199BodyXml`) + disk emitter
 * (`emitFips199Docx`). `computeOverallSC` is exported for unit testing.
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { xmlEscape, zipStore } from './zip.ts';
import { deterministicUuid } from './oscal.ts';
import { log } from './log.ts';
import { findInformationType, SELECTION_GUIDANCE, SOURCE_URL, SOURCE_VERSION } from './fips199-types.ts';

const W_NS = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main';
/** Verbatim marker for missing operator input (REO Rule 4). */
const TBD = 'REQUIRES-OPERATOR-INPUT';
/** Verbatim marker for a code outside the SP 800-60 V2 SaaS-relevant subset. */
const UNKNOWN_CODE = 'UNKNOWN-TYPE-CODE';

// ─── Impact model ────────────────────────────────────────────────────────────

/** A confidentiality impact level. NOT APPLICABLE is permitted only for C. */
export type ConfidentialityImpact = 'low' | 'moderate' | 'high' | 'n/a';
/** An integrity / availability impact level. NOT APPLICABLE is NOT permitted. */
export type IaImpact = 'low' | 'moderate' | 'high';
/** An overall per-objective SC value. */
export type Impact = 'low' | 'moderate' | 'high' | 'n/a';

/** High-water-mark ordering. `n/a` contributes nothing to the mark. */
const RANK: Record<Impact, number> = { 'n/a': -1, low: 0, moderate: 1, high: 2 };
const BY_RANK: Impact[] = ['low', 'moderate', 'high'];

/** FIPS 199 §3 display token for an impact level. */
export function impactToken(v: Impact): string {
  return v === 'n/a' ? 'NOT APPLICABLE' : v.toUpperCase();
}

/** Thrown when an information type carries an invalid impact level. */
export class Fips199ImpactError extends Error {
  constructor(message: string) {
    super(`fips199-emit: ${message}`);
    this.name = 'Fips199ImpactError';
  }
}

/** One operator-supplied information type row (the RA-2 categorization input). */
export interface InformationType {
  /** SP 800-60 V2 R1 code — e.g. "C.3.5.1". */
  code: string;
  /** Information-type name (from the catalogue, or operator-supplied). */
  name: string;
  confidentiality: ConfidentialityImpact;
  integrity: IaImpact;
  availability: IaImpact;
  /** Operator rationale for the assigned levels. */
  rationale: string;
}

/**
 * Validate + normalize a single operator-supplied information type. Throws
 * Fips199ImpactError on an invalid impact value: integrity + availability MUST
 * be low/moderate/high (FIPS 199 §3 — NOT APPLICABLE is permitted only for
 * confidentiality); confidentiality MUST be low/moderate/high/n/a.
 */
export function validateInformationType(t: InformationType): InformationType {
  const c = String(t.confidentiality).toLowerCase().trim();
  const i = String(t.integrity).toLowerCase().trim();
  const a = String(t.availability).toLowerCase().trim();
  if (!['low', 'moderate', 'high', 'n/a'].includes(c)) {
    throw new Fips199ImpactError(`information type "${t.code}" has invalid confidentiality "${t.confidentiality}" (expected low/moderate/high/n/a)`);
  }
  if (!['low', 'moderate', 'high'].includes(i)) {
    throw new Fips199ImpactError(`information type "${t.code}" has invalid integrity "${t.integrity}" — FIPS 199 §3 requires low/moderate/high for integrity (NOT APPLICABLE is permitted only for confidentiality)`);
  }
  if (!['low', 'moderate', 'high'].includes(a)) {
    throw new Fips199ImpactError(`information type "${t.code}" has invalid availability "${t.availability}" — FIPS 199 §3 requires low/moderate/high for availability (NOT APPLICABLE is permitted only for confidentiality)`);
  }
  return {
    code: String(t.code).trim(),
    name: String(t.name).trim(),
    confidentiality: c as ConfidentialityImpact,
    integrity: i as IaImpact,
    availability: a as IaImpact,
    rationale: String(t.rationale ?? '').trim(),
  };
}

/**
 * Compute the system-level Security Category as the high-water-mark of the
 * per-objective impact levels across all information types.
 *
 * FIPS 199 §3 (p. 3): "The generally accepted practice is to use the 'high
 * water mark' over the security impact levels for confidentiality, integrity,
 * and availability assigned to the information types." NOT APPLICABLE (permitted
 * only for confidentiality) contributes nothing to the mark; if every type's
 * confidentiality is NOT APPLICABLE, the system confidentiality is NOT
 * APPLICABLE. An empty type set yields NOT APPLICABLE for all three (no
 * categorization has been performed yet).
 *
 * Exported for unit testing. Validates each type first (throws on an invalid
 * impact value).
 */
export function computeOverallSC(types: InformationType[]): { c: Impact; i: Impact; a: Impact } {
  let c: Impact = 'n/a';
  let i: Impact = 'n/a';
  let a: Impact = 'n/a';
  for (const raw of types) {
    const t = validateInformationType(raw);
    if (RANK[t.confidentiality] > RANK[c]) c = t.confidentiality;
    if (RANK[t.integrity] > RANK[i]) i = t.integrity;
    if (RANK[t.availability] > RANK[a]) a = t.availability;
  }
  return { c, i, a };
}

/** The single scalar system categorization = max of the three objectives. */
export function overallSystemLevel(sc: { c: Impact; i: Impact; a: Impact }): Impact {
  const marks = [sc.c, sc.i, sc.a].filter((v) => v !== 'n/a') as Impact[];
  if (marks.length === 0) return 'n/a';
  return BY_RANK[Math.max(...marks.map((m) => RANK[m]))]!;
}

// ─── OOXML building blocks (same pattern as cmp-emit.ts) ─────────────────────

function para(text: string, style?: string): string {
  const pPr = style ? `<w:pPr><w:pStyle w:val="${style}"/></w:pPr>` : '';
  if (text === '') return `<w:p>${pPr}</w:p>`;
  const runs = text.split('\n').map((line, idx) =>
    `${idx > 0 ? '<w:br/>' : ''}<w:t xml:space="preserve">${xmlEscape(line)}</w:t>`,
  ).join('');
  return `<w:p>${pPr}<w:r>${runs}</w:r></w:p>`;
}

function heading(text: string, level: 1 | 2 | 3): string {
  return para(text, `Heading${level}`);
}

interface TableOpts { headerRow?: boolean }

function table(headers: string[], rows: string[][], widths: number[], opts: TableOpts = {}): string {
  const headerRow = opts.headerRow ?? true;
  const grid = `<w:tblGrid>${widths.map((w) => `<w:gridCol w:w="${w}"/>`).join('')}</w:tblGrid>`;
  const border = '<w:top w:val="single" w:sz="4" w:space="0" w:color="999999"/>' +
    '<w:left w:val="single" w:sz="4" w:space="0" w:color="999999"/>' +
    '<w:bottom w:val="single" w:sz="4" w:space="0" w:color="999999"/>' +
    '<w:right w:val="single" w:sz="4" w:space="0" w:color="999999"/>' +
    '<w:insideH w:val="single" w:sz="4" w:space="0" w:color="999999"/>' +
    '<w:insideV w:val="single" w:sz="4" w:space="0" w:color="999999"/>';
  const tblPr = `<w:tblPr><w:tblW w:w="0" w:type="auto"/><w:tblBorders>${border}</w:tblBorders></w:tblPr>`;

  const cell = (text: string, w: number, bold: boolean, shade: boolean): string => {
    const shadeXml = shade ? '<w:shd w:val="clear" w:color="auto" w:fill="E7E6E6"/>' : '';
    const runPr = bold ? '<w:rPr><w:b/></w:rPr>' : '';
    const runs = text.split('\n').map((line, idx) =>
      `${idx > 0 ? '<w:br/>' : ''}<w:t xml:space="preserve">${xmlEscape(line)}</w:t>`,
    ).join('');
    return `<w:tc><w:tcPr><w:tcW w:w="${w}" w:type="dxa"/>${shadeXml}</w:tcPr>` +
      `<w:p><w:r>${runPr}${runs}</w:r></w:p></w:tc>`;
  };

  const tr = (cells: string[], bold: boolean, shade: boolean): string =>
    `<w:tr>${cells.map((cV, idx) => cell(cV, widths[idx] ?? 2000, bold, shade)).join('')}</w:tr>`;

  const body: string[] = [];
  if (headerRow) body.push(tr(headers, true, true));
  for (const r of rows) body.push(tr(r, false, false));
  return `<w:tbl>${tblPr}${grid}${body.join('')}</w:tbl>`;
}

function fieldTable(rows: Array<[string, string]>): string {
  return table(['Field', 'Value'], rows, [3000, 6000], { headerRow: false });
}

// ─── SSP cross-reference reader ──────────────────────────────────────────────

/** Result of the §4.1 SSP cross-reference. */
export interface SspCrossReference {
  /** 'consistent' | 'mismatch' | 'unavailable'. */
  status: 'consistent' | 'mismatch' | 'unavailable';
  /** Overall SSP level parsed from the SSP (or null if unavailable). */
  sspOverall: Impact | null;
  /** Per-objective SSP levels when the SSP carries the object shape. */
  sspObjectives: { c: Impact; i: Impact; a: Impact } | null;
  /** SHA-256 of out/ssp.json (provenance) or null when absent. */
  sspSha256: string | null;
  /** Human-readable note for §4.1. */
  note: string;
}

/** Parse an OSCAL `fips-199-<level>` enum (or bare "low"/"moderate"/"high"). */
function parseOscalLevel(raw: unknown): Impact | null {
  if (typeof raw !== 'string') return null;
  const s = raw.trim().toLowerCase().replace(/^fips-199-/, '');
  if (s === 'low' || s === 'moderate' || s === 'high') return s;
  return null;
}

/**
 * Read out/ssp.json (when present) and cross-check its security categorization
 * against the worksheet's computed overall SC. Handles BOTH the real emitted
 * shape — `security-impact-level` is an object with per-objective
 * `security-objective-{confidentiality,integrity,availability}` values, plus an
 * overall `security-sensitivity-level` string (core/oscal-ssp.ts) — AND the
 * per-slice-§schemas assumption that `security-impact-level` is a bare string.
 * Never throws (a malformed SSP yields status 'unavailable').
 */
export function crossReferenceSsp(
  outDir: string,
  workComputed: { c: Impact; i: Impact; a: Impact },
): SspCrossReference {
  const p = resolve(outDir, 'ssp.json');
  if (!existsSync(p)) {
    return {
      status: 'unavailable', sspOverall: null, sspObjectives: null, sspSha256: null,
      note: 'SSP unavailable for cross-reference (out/ssp.json not found) — the operator must verify the worksheet categorization against the SSP manually. Run with --oscal-ssp to emit ssp.json in the same run.',
    };
  }
  let sha256: string | null = null;
  let doc: any;
  try {
    const bytes = readFileSync(p);
    sha256 = createHash('sha256').update(bytes).digest('hex');
    doc = JSON.parse(bytes.toString('utf8'));
  } catch {
    return {
      status: 'unavailable', sspOverall: null, sspObjectives: null, sspSha256: sha256,
      note: 'SSP present but could not be parsed (out/ssp.json malformed) — verify manually.',
    };
  }
  const sc = doc?.['system-security-plan']?.['system-characteristics']
    ?? doc?.['system-characteristics'];
  const sil = sc?.['security-impact-level'];
  let sspObjectives: { c: Impact; i: Impact; a: Impact } | null = null;
  if (sil && typeof sil === 'object') {
    const c = parseOscalLevel(sil['security-objective-confidentiality']);
    const i = parseOscalLevel(sil['security-objective-integrity']);
    const a = parseOscalLevel(sil['security-objective-availability']);
    if (c && i && a) sspObjectives = { c, i, a };
  }
  // Overall: prefer the explicit sensitivity level; else derive from objectives;
  // else accept a bare-string security-impact-level (spec-assumed shape).
  const sspOverall: Impact | null =
    parseOscalLevel(sc?.['security-sensitivity-level'])
    ?? (sspObjectives ? overallSystemLevel(sspObjectives) : null)
    ?? (typeof sil === 'string' ? parseOscalLevel(sil) : null);

  if (!sspOverall) {
    return {
      status: 'unavailable', sspOverall: null, sspObjectives, sspSha256: sha256,
      note: 'SSP present but carries no recognizable security-impact-level / security-sensitivity-level — verify manually.',
    };
  }

  const workOverall = overallSystemLevel(workComputed);
  // The worksheet must produce a categorization to compare (≥1 info type).
  if (workOverall === 'n/a') {
    return {
      status: 'unavailable', sspOverall, sspObjectives, sspSha256: sha256,
      note: `SSP claims ${impactToken(sspOverall)} but the worksheet has no information types to categorize — supply information types, then re-emit to cross-check.`,
    };
  }

  // Per-objective comparison when the SSP carries the object shape (richer than
  // the spec's overall-only check). NOT APPLICABLE worksheet confidentiality is
  // treated as consistent with any SSP confidentiality (the OSCAL enum has no
  // NOT APPLICABLE — a public-data system that computes c=n/a satisfies any SSP
  // confidentiality value; noted rather than flagged).
  const diffs: string[] = [];
  if (sspObjectives) {
    if (workComputed.c !== 'n/a' && sspObjectives.c !== workComputed.c) {
      diffs.push(`confidentiality (SSP ${impactToken(sspObjectives.c)} vs worksheet ${impactToken(workComputed.c)})`);
    }
    if (sspObjectives.i !== workComputed.i) {
      diffs.push(`integrity (SSP ${impactToken(sspObjectives.i)} vs worksheet ${impactToken(workComputed.i)})`);
    }
    if (sspObjectives.a !== workComputed.a) {
      diffs.push(`availability (SSP ${impactToken(sspObjectives.a)} vs worksheet ${impactToken(workComputed.a)})`);
    }
  } else if (sspOverall !== workOverall) {
    diffs.push(`overall (SSP ${impactToken(sspOverall)} vs worksheet ${impactToken(workOverall)})`);
  }

  if (diffs.length === 0) {
    return {
      status: 'consistent', sspOverall, sspObjectives, sspSha256: sha256,
      note: `CONSISTENT: the SSP security categorization (${impactToken(sspOverall)}) agrees with this worksheet's computed overall SC (${impactToken(workOverall)}).`,
    };
  }
  return {
    status: 'mismatch', sspOverall, sspObjectives, sspSha256: sha256,
    note: `MISMATCH: the SSP and this worksheet disagree on ${diffs.join('; ')}. The high-water-mark practice (FIPS 199 §3) means the worksheet value is authoritative when the operator has categorized every information type; reconcile the SSP security-impact-level (or the information types in §3) before submission. A common cause is operator under-categorization of the information types in §3 (see §2 Methodology).`,
  };
}

// ─── Public options + result ─────────────────────────────────────────────────

/** The RA-2.c categorization approver (AO or designated representative). */
export interface Fips199Approver {
  name: string;
  role: string;
  org: string;
  date: string;
}

export interface Fips199EmitOptions {
  /** Where the orchestrator writes. The emitter reads ssp.json from here. */
  outDir: string;
  /** Output path (defaults to <outDir>/fips199.docx). */
  outPath?: string;
  /** Run id — captured in the provenance (§1) + deterministic UUID seed. */
  runId: string;
  /** FRMR catalog version — captured in the provenance (§1). */
  frmrVersion: string;
  /** System identity (reuses --system-name / --system-id / --csp-name). */
  systemName?: string;
  systemId?: string;
  cspOrganization?: string;
  /** Operator-supplied information types (config.yaml: fips199.information_types[]). */
  informationTypes?: InformationType[];
  /** §5 per-objective rationale (config.yaml: fips199.{c,i,a}_rationale). */
  overallConfidentialityRationale?: string;
  overallIntegrityRationale?: string;
  overallAvailabilityRationale?: string;
  /** §6 categorization approver (config.yaml: fips199.approver). */
  categorizationApprover?: Fips199Approver;
}

export interface Fips199EmitResult {
  path: string;
  bytes: number;
  /** Count of operator-supplied information types feeding §3 + the SC. */
  information_type_count: number;
  /** The computed overall system level (low/moderate/high/n/a). */
  overall_level: Impact;
  /** The SSP cross-reference status. */
  ssp_crossref: 'consistent' | 'mismatch' | 'unavailable';
  /** Codes supplied that are not in the SP 800-60 V2 subset (warnings). */
  unknown_type_codes: string[];
  /** True when every required-for-signature operator field was supplied. */
  ready_for_signature: boolean;
  /** Missing-input list for operator action. */
  requires_operator_input: string[];
}

// ─── Provenance digest ───────────────────────────────────────────────────────

function sspDigest(outDir: string): string | null {
  const p = resolve(outDir, 'ssp.json');
  if (!existsSync(p)) return null;
  try { return createHash('sha256').update(readFileSync(p)).digest('hex'); }
  catch { return null; }
}

// ─── Builder (pure) ──────────────────────────────────────────────────────────

export function buildFips199BodyXml(opts: Fips199EmitOptions): {
  xml: string;
  stats: Omit<Fips199EmitResult, 'path' | 'bytes'>;
} {
  const systemName = opts.systemName || TBD;
  const systemId = opts.systemId || TBD;
  const csp = opts.cspOrganization || TBD;

  // Validate every supplied information type up front (throws on bad impacts).
  const rawTypes = opts.informationTypes ?? [];
  const types = rawTypes.map(validateInformationType);

  // Codes outside the SP 800-60 V2 SaaS-relevant subset → warn + accept (Q3).
  const unknownCodes: string[] = [];
  for (const t of types) {
    if (!findInformationType(t.code)) unknownCodes.push(t.code);
  }

  // Required-for-signature input tracker (Q1 / test #12: ≥1 info type + 3
  // rationales + approver).
  const missing: string[] = [];
  const track = (label: string, val: string | undefined) => {
    if (!val || val.trim() === '') missing.push(label);
  };
  track('systemName', opts.systemName);
  track('systemId', opts.systemId);
  track('cspOrganization', opts.cspOrganization);
  if (types.length === 0) missing.push('informationTypes (config.yaml: fips199.information_types[] or --fips199-info-type)');
  track('overallConfidentialityRationale', opts.overallConfidentialityRationale);
  track('overallIntegrityRationale', opts.overallIntegrityRationale);
  track('overallAvailabilityRationale', opts.overallAvailabilityRationale);
  if (!opts.categorizationApprover || !opts.categorizationApprover.name?.trim()) {
    missing.push('categorizationApprover (config.yaml: fips199.approver)');
  }

  const sc = computeOverallSC(types);
  const overall = overallSystemLevel(sc);
  const crossref = crossReferenceSsp(opts.outDir, sc);
  const sspSha = sspDigest(opts.outDir);
  const docUuid = deterministicUuid(`fips199:${systemId}:${opts.runId}`);

  const parts: string[] = [];

  // ── Title block ──
  parts.push(para('FIPS 199 Security Categorization', 'Title'));
  parts.push(para(`${systemName} — Security Categorization Worksheet (RA-2)`, 'Subtitle'));
  parts.push(para(
    'DRAFT — auto-generated by fedramp-20x-cloud-evidence. The system-level Security ' +
    'Category is computed from the operator-supplied information types below via the FIPS 199 ' +
    `high-water-mark practice; the operator must complete every ${TBD} marker and the RA-2.c ` +
    'approval (§6) before the worksheet is final. The CSP / AO is the author-of-record.',
    'Disclaimer',
  ));

  // ── §1 Introduction ──
  parts.push(heading('1. Introduction', 1));
  parts.push(heading('1.1 Purpose', 2));
  parts.push(para(
    'This worksheet documents the FIPS 199 security categorization of the information system, ' +
    'satisfying NIST SP 800-53 Rev. 5 control RA-2 (Security Categorization): "a. Categorize the ' +
    'system and information it processes, stores, and transmits; b. Document the security ' +
    'categorization results, including supporting rationale, in the security plan for the system; ' +
    'c. Verify that the authorizing official or authorizing official designated representative ' +
    'reviews and approves the security categorization decision." (NIST SP 800-53 Rev. 5, RA-2) ' +
    'The System Security Plan carries the categorization result in ' +
    'system-characteristics.security-impact-level; this worksheet shows the work behind it.',
  ));
  parts.push(fieldTable([
    ['Document Title', `FIPS 199 Security Categorization — ${systemName}`],
    ['Document UUID', docUuid],
    ['Version', '1.0'],
    ['System Name', systemName],
    ['System ID', systemId],
    ['CSP Organization', csp],
    ['Satisfies Control', 'NIST SP 800-53 Rev. 5 RA-2 (Security Categorization); FIPS 199; FIPS 200; NIST SP 800-60'],
    ['Categorization Method', "High-water-mark of information-type security categories (FIPS 199 §3)"],
    ['Information Type Catalogue', `NIST ${SOURCE_VERSION} (core/fips199-types.ts)`],
    ['SSP Cross-Reference', sspSha ? `out/ssp.json (sha256 ${sspSha})` : '(SSP not present this run — see §4.1)'],
    ['Generated By', 'fedramp-20x-cloud-evidence (core/fips199-emit.ts)'],
    ['Run ID', opts.runId],
    ['FRMR Catalog Version', opts.frmrVersion],
  ]));

  parts.push(heading('1.2 FIPS 199 Impact-Level Definitions', 2));
  parts.push(para(
    'Loss definitions (FIPS 199 §3): "A loss of confidentiality is the unauthorized disclosure ' +
    'of information. A loss of integrity is the unauthorized modification or destruction of ' +
    'information. A loss of availability is the disruption of access to or use of information or ' +
    'an information system."',
  ));
  parts.push(table(
    ['Potential Impact', 'Definition (FIPS 199 §3, verbatim)'],
    [
      ['LOW', 'The loss of confidentiality, integrity, or availability could be expected to have a limited adverse effect on organizational operations, organizational assets, or individuals.'],
      ['MODERATE', 'The loss of confidentiality, integrity, or availability could be expected to have a serious adverse effect on organizational operations, organizational assets, or individuals.'],
      ['HIGH', 'The loss of confidentiality, integrity, or availability could be expected to have a severe or catastrophic adverse effect on organizational operations, organizational assets, or individuals.'],
    ],
    [1600, 7400],
  ));
  parts.push(para(
    'Security Category formula (FIPS 199 §3): SC information_type = {(confidentiality, impact), ' +
    '(integrity, impact), (availability, impact)}, where the acceptable values for potential ' +
    'impact are LOW, MODERATE, HIGH, or NOT APPLICABLE. NOT APPLICABLE is permitted only for the ' +
    'confidentiality objective (FIPS 199 §3).',
  ));

  // ── §2 Methodology ──
  parts.push(heading('2. Methodology', 1));
  parts.push(para(
    'Information types are identified following NIST SP 800-60 Vol. 1 Rev. 1 §3.1 and mapped to ' +
    `provisional impact levels using the NIST ${SOURCE_VERSION} catalogue (Appendix C — ` +
    'Management and Support Information; Appendix D — Mission-Based Information). For each ' +
    'information type the system owner assigns a confidentiality, integrity, and availability ' +
    'impact level with supporting rationale (§3). The system-level Security Category is then the ' +
    'high-water-mark across all information types (FIPS 199 §3): "The generally accepted practice ' +
    "is to use the 'high water mark' over the security impact levels for confidentiality, " +
    'integrity, and availability assigned to the information types."',
  ));
  parts.push(para(
    'Completeness is the system owner\'s responsibility: the worksheet computes the high-water-mark ' +
    'over the information types supplied in §3, but it cannot detect an information type the ' +
    'operator omitted or under-categorized. The categorization drives baseline selection per ' +
    'FIPS 200; the applied SP 800-53 Rev. 5 baseline is recorded in the SSP (§4 does not restate ' +
    'it). FedRAMP 20x Phase Two introduces no categorization steps beyond FIPS 199 as of the ' +
    'pinned catalogue (RFC-0026 and related are silent on RA-2).',
  ));

  // ── §3 Information Types Identified ──
  parts.push(heading('3. Information Types Identified', 1));
  if (types.length > 0) {
    parts.push(para(
      `The ${types.length} information type(s) below are the operator's RA-2 categorization input. ` +
      'A code not in the NIST SP 800-60 V2 SaaS-relevant subset (core/fips199-types.ts) is ' +
      `annotated ${UNKNOWN_CODE} in the Code column (accepted, but confirm it against the full ` +
      'SP 800-60 Vol. 2 catalogue).',
    ));
    parts.push(table(
      ['Code', 'Information Type', 'C', 'I', 'A', 'Rationale'],
      types.map((t) => [
        findInformationType(t.code) ? t.code : `${t.code} (${UNKNOWN_CODE})`,
        t.name || (findInformationType(t.code)?.name ?? TBD),
        impactToken(t.confidentiality),
        impactToken(t.integrity),
        impactToken(t.availability),
        t.rationale || TBD,
      ]),
      [1400, 2600, 900, 900, 900, 2300],
    ));
  } else {
    parts.push(para(
      `${TBD}: no information types were supplied. FIPS 199 categorization requires at least one ` +
      'information type.',
    ));
    parts.push(table(
      ['Code', 'Information Type', 'C', 'I', 'A', 'Rationale'],
      [[TBD, SELECTION_GUIDANCE, TBD, TBD, TBD, `Supply via config.yaml: fips199.information_types[] or --fips199-info-type. Catalogue: NIST ${SOURCE_VERSION}.`]],
      [1400, 2600, 900, 900, 900, 2300],
    ));
  }

  // ── §4 System Security Categorization ──
  parts.push(heading('4. System Security Categorization', 1));
  const scFormula =
    `SC ${systemName} = {(confidentiality, ${impactToken(sc.c)}), ` +
    `(integrity, ${impactToken(sc.i)}), (availability, ${impactToken(sc.a)})}`;
  parts.push(para(
    'Applying the FIPS 199 §3 high-water-mark across the information types in §3 yields the ' +
    'system-level Security Category:',
  ));
  parts.push(para(scFormula, 'Formula'));
  parts.push(fieldTable([
    ['Overall System Categorization', overall === 'n/a' ? `${TBD} (no information types categorized)` : impactToken(overall)],
    ['Confidentiality', impactToken(sc.c)],
    ['Integrity', impactToken(sc.i)],
    ['Availability', impactToken(sc.a)],
    ['Baseline Selection (FIPS 200)', 'The overall categorization selects the SP 800-53 Rev. 5 baseline per FIPS 200; the applied baseline is recorded in the SSP control-implementation, not restated here.'],
  ]));

  // ── §4.1 SSP Cross-Reference ──
  parts.push(heading('4.1 SSP Cross-Reference', 2));
  parts.push(para(crossref.note));
  if (crossref.sspObjectives && overall !== 'n/a') {
    parts.push(table(
      ['Objective', 'SSP (ssp.json)', 'Worksheet (§4)', 'Agreement'],
      [
        ['Confidentiality', impactToken(crossref.sspObjectives.c), impactToken(sc.c), (sc.c === 'n/a' || crossref.sspObjectives.c === sc.c) ? '✓' : '✗'],
        ['Integrity', impactToken(crossref.sspObjectives.i), impactToken(sc.i), crossref.sspObjectives.i === sc.i ? '✓' : '✗'],
        ['Availability', impactToken(crossref.sspObjectives.a), impactToken(sc.a), crossref.sspObjectives.a === sc.a ? '✓' : '✗'],
      ],
      [2600, 2400, 2400, 1600],
    ));
  }

  // ── §5 Categorization Rationale ──
  parts.push(heading('5. Categorization Rationale', 1));
  parts.push(para(
    'The system owner\'s rationale for each objective\'s system-level impact level:',
  ));
  parts.push(table(
    ['Objective', 'Level', 'Rationale'],
    [
      ['Confidentiality', impactToken(sc.c), opts.overallConfidentialityRationale?.trim() || TBD],
      ['Integrity', impactToken(sc.i), opts.overallIntegrityRationale?.trim() || TBD],
      ['Availability', impactToken(sc.a), opts.overallAvailabilityRationale?.trim() || TBD],
    ],
    [2600, 1600, 4800],
  ));

  // ── §6 Approval Signatures ──
  parts.push(heading('6. Approval Signatures', 1));
  parts.push(para(
    'RA-2.c requires the authorizing official (or designated representative) to review and ' +
    'approve the security categorization decision. Signatures are captured out-of-band; this ' +
    'toolkit never auto-signs a human attestation (REO Rule 1.10). The date is displayed ' +
    'verbatim and must be refreshed on each re-emission.',
  ));
  const approver = opts.categorizationApprover;
  parts.push(table(
    ['Role', 'Name', 'Organization', 'Date', 'Signature'],
    [
      [
        approver?.role?.trim() || 'Categorization Approver (AO or designee)',
        approver?.name?.trim() || TBD,
        approver?.org?.trim() || csp,
        approver?.date?.trim() || TBD,
        TBD,
      ],
      ['System Owner', TBD, csp, TBD, TBD],
    ],
    [2400, 2000, 2200, 1400, 1000],
  ));

  // ── Provenance footer ──
  parts.push(heading('Provenance', 2));
  parts.push(para(
    `Generated by core/fips199-emit.ts (run ${opts.runId}, FRMR ${opts.frmrVersion}). ` +
    `Information-type catalogue: NIST ${SOURCE_VERSION} — ${SOURCE_URL}. ` +
    `Impact-level definitions: FIPS PUB 199 §3 (verbatim). ` +
    (sspSha ? `SSP cross-reference source: out/ssp.json (sha256 ${sspSha}). ` : 'SSP not present this run. ') +
    'This document is deterministic (no wall-clock time); its integrity is anchored by the ' +
    'signed submission-bundle INDEX.json (SHA-256 + Ed25519).',
  ));

  // ── Page geometry (US Letter) ──
  const sectPr = '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/>' +
    '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr>';

  const xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<w:document xmlns:w="${W_NS}"><w:body>${parts.join('')}${sectPr}</w:body></w:document>`;

  return {
    xml,
    stats: {
      information_type_count: types.length,
      overall_level: overall,
      ssp_crossref: crossref.status,
      unknown_type_codes: unknownCodes,
      ready_for_signature: missing.length === 0,
      requires_operator_input: missing,
    },
  };
}

// ─── OOXML package parts ─────────────────────────────────────────────────────

function stylesXml(): string {
  const style = (id: string, name: string, o: { size?: number; bold?: boolean; color?: string; italic?: boolean; spacingBefore?: number; basedOn?: string }) => {
    const rPr = `<w:rPr>${o.bold ? '<w:b/>' : ''}${o.italic ? '<w:i/>' : ''}` +
      `${o.color ? `<w:color w:val="${o.color}"/>` : ''}` +
      `${o.size ? `<w:sz w:val="${o.size}"/>` : ''}</w:rPr>`;
    const pPr = o.spacingBefore ? `<w:pPr><w:spacing w:before="${o.spacingBefore}" w:after="120"/></w:pPr>` : '<w:pPr><w:spacing w:after="120"/></w:pPr>';
    return `<w:style w:type="paragraph" w:styleId="${id}"><w:name w:val="${name}"/>` +
      `${o.basedOn ? `<w:basedOn w:val="${o.basedOn}"/>` : ''}${pPr}${rPr}</w:style>`;
  };
  const docDefaults = '<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="22"/></w:rPr></w:rPrDefault></w:docDefaults>';
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<w:styles xmlns:w="${W_NS}">${docDefaults}` +
    `<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>` +
    style('Title', 'Title', { size: 56, bold: true, color: '1F3864' }) +
    style('Subtitle', 'Subtitle', { size: 30, color: '2E74B5' }) +
    style('Disclaimer', 'Disclaimer', { size: 18, italic: true, color: 'C00000' }) +
    style('Formula', 'Formula', { size: 26, bold: true, color: '1F4E79', spacingBefore: 120 }) +
    style('Heading1', 'heading 1', { size: 32, bold: true, color: '1F3864', spacingBefore: 360 }) +
    style('Heading2', 'heading 2', { size: 26, bold: true, color: '2E74B5', spacingBefore: 240 }) +
    style('Heading3', 'heading 3', { size: 24, bold: true, color: '1F4E79', spacingBefore: 160 }) +
    `</w:styles>`;
}

function coreXml(systemName: string, docUuid: string): string {
  const title = `FIPS 199 Security Categorization — ${systemName} [${docUuid}]`;
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" ` +
    `xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" ` +
    `xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">` +
    `<dc:title>${xmlEscape(title)}</dc:title>` +
    `<dc:creator>fedramp-20x-cloud-evidence</dc:creator>` +
    `<cp:contentStatus>DRAFT</cp:contentStatus>` +
    `</cp:coreProperties>`;
}

const CONTENT_TYPES = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
  `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
  `<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
  `<Default Extension="xml" ContentType="application/xml"/>` +
  `<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
  `<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>` +
  `<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>` +
  `</Types>`;

const ROOT_RELS = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
  `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
  `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
  `<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>` +
  `</Relationships>`;

const DOC_RELS = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
  `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
  `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>` +
  `</Relationships>`;

/** Pure: render the FIPS 199 worksheet Word document to a Buffer. */
export function renderFips199Docx(opts: Fips199EmitOptions): {
  buffer: Buffer;
  stats: Omit<Fips199EmitResult, 'path' | 'bytes'>;
} {
  const { xml, stats } = buildFips199BodyXml(opts);
  const systemName = opts.systemName || TBD;
  const systemId = opts.systemId || TBD;
  const docUuid = deterministicUuid(`fips199:${systemId}:${opts.runId}`);
  const b = (s: string) => Buffer.from(s, 'utf8');
  const buffer = zipStore([
    { name: '[Content_Types].xml', data: b(CONTENT_TYPES) },
    { name: '_rels/.rels', data: b(ROOT_RELS) },
    { name: 'docProps/core.xml', data: b(coreXml(systemName, docUuid)) },
    { name: 'word/document.xml', data: b(xml) },
    { name: 'word/styles.xml', data: b(stylesXml()) },
    { name: 'word/_rels/document.xml.rels', data: b(DOC_RELS) },
  ]);
  return { buffer, stats };
}

/** Read the SSP, render, and write fips199.docx. */
export function emitFips199Docx(opts: Fips199EmitOptions): Fips199EmitResult {
  const { buffer, stats } = renderFips199Docx(opts);
  const outPath = opts.outPath ?? resolve(opts.outDir, 'fips199.docx');
  writeFileSync(outPath, buffer);
  log.info({
    event: 'fips199.emitted',
    path: outPath,
    bytes: buffer.length,
    information_type_count: stats.information_type_count,
    overall_level: stats.overall_level,
    ssp_crossref: stats.ssp_crossref,
    unknown_type_code_count: stats.unknown_type_codes.length,
    ready_for_signature: stats.ready_for_signature,
    requires_operator_input_count: stats.requires_operator_input.length,
  });
  return { path: outPath, bytes: buffer.length, ...stats };
}
