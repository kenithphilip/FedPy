/**
 * Privacy Threshold Analysis (PTA) + Privacy Impact Assessment (PIA) emitter —
 * LOOP-C.C4.
 *
 * Renders `pta.docx` (ALWAYS emitted) and `pia.docx` (CONDITIONALLY emitted —
 * only when the PTA determination is positive, or the operator forces it with
 * `piaForceMode='always-emit'`). Both documents satisfy the NIST SP 800-53
 * Rev. 5 PT (PII Processing and Transparency) control family — PT-2 (Authority
 * to Process PII), PT-3 (PII Processing Purposes), PT-6 (System of Records
 * Notice and Privacy Act Statements) — plus AR-2 (Privacy Impact and Risk
 * Assessment) for the PIA. FedRAMP has not published a Rev. 5 PTA/PIA template
 * (help-desk article 28907995813275: "There are no current plans to provide a
 * Rev. 5 PTA/PIA template for CSPs to complete."), so the emitter ships the
 * published Rev4 SSP Attachment A04 PIA structure wrapped over Rev5 PT-family
 * control identifiers.
 *
 * The PTA §3 PII-inventory-evidence table is auto-derived from the REAL
 * `out/inventory.json`: every asset tagged `data_classification ∈ {pii, phi}`
 * becomes one evidence row. The system never invents PII categories (§2 of the
 * PIA) or fabricates a PII determination — every operator narrative slot
 * defaults to a verbatim REQUIRES-OPERATOR-INPUT marker (REO Rule 4).
 *
 * Authoritative sources (verbatim):
 *   - FedRAMP SSP Attachment A04 — Privacy Impact Assessment (PIA) Template
 *     (Rev4) —
 *     https://www.fedramp.gov/assets/resources/templates/SSP-A04-FedRAMP-PIA-Template.docx
 *     (retrieved 2026-06-07). Section ordering mirrored: PTA determination form
 *     (Q1-Q5) → PIA per-question expansion (Authority, Purpose, Categories,
 *     Sources, Sharing, Notice & Consent, Access & Correction, Retention,
 *     Disposal, Safeguards). Rev4 template because FedRAMP help-desk article
 *     28907995813275 confirms no Rev5 equivalent has been published.
 *   - NIST SP 800-53 Rev. 5 PT-2 (Authority to Process Personally Identifiable
 *     Information) — https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final :
 *     "a. Determine and document the [Assignment: organization-defined
 *      authority] that permits the [Assignment: organization-defined
 *      processing] of personally identifiable information; and b. Restrict the
 *      [Assignment: organization-defined processing] of personally identifiable
 *      information to only that which is authorized."
 *   - NIST SP 800-53 Rev. 5 PT-3 (Personally Identifiable Information Processing
 *     Purposes) — same catalog URL :
 *     "a. Identify and document the [Assignment: organization-defined
 *      purpose(s)] for processing personally identifiable information;
 *      b. Describe the purpose(s) in the public privacy notices and policies of
 *      the organization; c. Restrict the [Assignment: organization-defined
 *      processing] of personally identifiable information to only that which is
 *      compatible with the identified purpose(s); d. Monitor changes in
 *      processing personally identifiable information ..."
 *   - NIST SP 800-53 Rev. 5 PT-6 (System of Records Notice and Privacy Act
 *     Statements) — same catalog URL :
 *     "For systems that process information that will be maintained in a Privacy
 *      Act system of records: a. Draft and publish System of Records Notices in
 *      the Federal Register ...; b. Keep System of Records Notices accurate,
 *      up-to-date, and scoped ...; c. Review System of Records Notices
 *      [Assignment: organization-defined frequency]."
 *   - NIST SP 800-53 Rev. 5 AR-2 (Privacy Impact and Risk Assessment) — same
 *     catalog URL — mandates a PIA when PII is processed.
 *   - OMB Memorandum M-03-22 (E-Government Act §208) —
 *     https://www.whitehouse.gov/wp-content/uploads/legacy_drupal_files/omb/memoranda/2003/m03_22.pdf
 *     — the originating policy the FedRAMP A04 template cites.
 *   - NIST Privacy Framework v1.0 (2020-01-16) —
 *     https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.01162020.pdf — the
 *     Govern / Identify / Protect / Communicate / Respond crosswalk used in the
 *     PIA §8 Privacy Risk Assessment.
 *
 * Approach (dependency-free .docx): a `.docx` is a ZIP of WordprocessingML XML
 * parts packed with the store-only ZIP writer the CMP / ISCP / IRP / SSP-2 / RoE
 * renderers use (core/zip.ts) — no external Word library, no runtime network.
 * The OOXML building blocks mirror core/irp-emit.ts (a shared docx-primitives
 * module was proposed in LOOP-C-SPEC §4 but never extracted; see LOOP-C-RISKS
 * C-C4-8 / C-X-1 — this emitter follows the eight shipped docx emitters and
 * keeps its OOXML constants local).
 *
 * REO compliance:
 *   - §3 PII-evidence rows trace ONLY to real `inventory.json` data_classification
 *     tags; resource names are redacted (per-slice Risk 3) so the document never
 *     leaks PII. Absent inventory → a single REQUIRES-OPERATOR-INPUT row.
 *   - PIA §2 categories are empty (REQUIRES-OPERATOR-INPUT) when not
 *     operator-supplied — the emitter never invents "name, email, SSN".
 *   - Signature cells stay REQUIRES-OPERATOR-INPUT — the toolkit never
 *     auto-signs a human privacy attestation (REO Rule 1.10).
 *   - Fully deterministic (no wall-clock time): the metadata UUIDs are
 *     `deterministicUuid('pta:'+systemId+':'+runId)` / `'pia:'+systemId+':'+runId`
 *     and the inventory provenance is the content SHA-256, so identical inputs
 *     produce byte-identical .docx files. Integrity is anchored by the signed
 *     submission-bundle INDEX.json (SHA-256 + Ed25519), the same coverage
 *     irp.docx / iscp.docx / cmp.docx / roe.docx / ssp.docx receive.
 *
 * Pure builders (`buildPtaBodyXml` / `buildPiaBodyXml`) + disk emitter
 * (`emitPtaPiaDocx`).
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { xmlEscape, zipStore } from './zip.ts';
import { deterministicUuid } from './oscal.ts';
import { log } from './log.ts';

const W_NS = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main';
/** Verbatim marker for missing operator input (REO Rule 4). */
const TBD = 'REQUIRES-OPERATOR-INPUT';
/** Verbatim marker for inferred-not-confirmed input (operator confirms/overrides). */
const TBD_VERIFY = 'REQUIRES-OPERATOR-INPUT-VERIFY';
/** Accepted impact tiers. */
const IMPACT_LEVELS = ['low', 'moderate', 'high'] as const;
type ImpactLevel = (typeof IMPACT_LEVELS)[number];
/** PIA emission policy. */
const PIA_FORCE_MODES = ['auto', 'always-emit', 'never-emit'] as const;
export type PiaForceMode = (typeof PIA_FORCE_MODES)[number];
/** data_classification tag values that trigger a positive PII determination. */
const PII_CLASSIFICATIONS = new Set(['pii', 'phi']);
/** FedRAMP A04 PIA template URL (Rev4 — no Rev5 equivalent published). */
const A04_TEMPLATE_URL =
  'https://www.fedramp.gov/assets/resources/templates/SSP-A04-FedRAMP-PIA-Template.docx';
/** Access date for the A04 template + NIST catalog citations (deterministic). */
const SOURCE_RETRIEVED = '2026-06-07';

/** Thrown when an unknown impact level is supplied (must be low|moderate|high). */
export class PtaPiaImpactLevelError extends Error {
  constructor(value: string) {
    super(
      `pta-pia-emit: unknown impactLevel "${value}"; must be one of ${IMPACT_LEVELS.join(' | ')}.`,
    );
    this.name = 'PtaPiaImpactLevelError';
  }
}

/** Thrown when an unknown piaForceMode is supplied. */
export class PtaPiaForceModeError extends Error {
  constructor(value: string) {
    super(
      `pta-pia-emit: unknown piaForceMode "${value}"; must be one of ${PIA_FORCE_MODES.join(' | ')}.`,
    );
    this.name = 'PtaPiaForceModeError';
  }
}

// ─── OOXML building blocks (same pattern as irp-emit.ts / cmp-emit.ts) ─────────

/** A paragraph in the given style (Normal when omitted). Empty text → spacer. */
function para(text: string, style?: string): string {
  const pPr = style ? `<w:pPr><w:pStyle w:val="${style}"/></w:pPr>` : '';
  if (text === '') return `<w:p>${pPr}</w:p>`;
  const runs = text.split('\n').map((line, i) =>
    `${i > 0 ? '<w:br/>' : ''}<w:t xml:space="preserve">${xmlEscape(line)}</w:t>`,
  ).join('');
  return `<w:p>${pPr}<w:r>${runs}</w:r></w:p>`;
}

function heading(text: string, level: 1 | 2 | 3): string {
  return para(text, `Heading${level}`);
}

interface TableOpts { headerRow?: boolean }

/** A bordered table. `widths` are column widths in twips (dxa); 1 inch = 1440. */
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
    const runs = text.split('\n').map((line, i) =>
      `${i > 0 ? '<w:br/>' : ''}<w:t xml:space="preserve">${xmlEscape(line)}</w:t>`,
    ).join('');
    return `<w:tc><w:tcPr><w:tcW w:w="${w}" w:type="dxa"/>${shadeXml}</w:tcPr>` +
      `<w:p><w:r>${runPr}${runs}</w:r></w:p></w:tc>`;
  };

  const tr = (cells: string[], bold: boolean, shade: boolean): string =>
    `<w:tr>${cells.map((c, i) => cell(c, widths[i] ?? 2000, bold, shade)).join('')}</w:tr>`;

  const body: string[] = [];
  if (headerRow) body.push(tr(headers, true, true));
  for (const r of rows) body.push(tr(r, false, false));
  return `<w:tbl>${tblPr}${grid}${body.join('')}</w:tbl>`;
}

/** A 2-column field/value table (no header row). */
function fieldTable(rows: Array<[string, string]>): string {
  return table(['Field', 'Value'], rows, [3000, 6000], { headerRow: false });
}

/** Render a string[] as one paragraph per item, or a single TBD line when empty. */
function bulletsOrTbd(items: string[] | undefined, tbdPrompt: string): string {
  if (items && items.length > 0) {
    return items.map((s) => para(`• ${s}`)).join('');
  }
  return para(`${TBD}: ${tbdPrompt}`);
}

// ─── Public options + result ─────────────────────────────────────────────────

/** The five PTA determination questions (FedRAMP A04 + NIST SP 800-53 R5 PT-1). */
export interface PtaResponses {
  /** Q1 — Does the system collect PII? (auto-derived from inventory when absent) */
  collectsPII: boolean;
  /** Q2 — Is the PII identifiable to specific individuals? */
  identifiableData: boolean;
  /** Q3 — Will PII be shared with external entities? */
  sharingWithExternalEntities: boolean;
  /** Q4 — Are persistent user identifiers used? */
  persistentUserIdentifiers: boolean;
  /** Q5 — Is PII reused for secondary purposes? */
  reusedForSecondaryPurposes: boolean;
}

/** A single PIA data-sharing arrangement (§3). */
export interface PiaSharingEntry {
  recipient: string;
  purpose: string;
  mechanism: string;
}

/** Operator-supplied PIA responses (FedRAMP A04 per-question expansion). */
export interface PiaResponses {
  /** §1 — statutory / regulatory authority to collect (PT-2). */
  authorityToCollect: string;
  /** §1 — purpose(s) for processing (PT-3.a). */
  purposesOfCollection: string[];
  /** §2 — categories of PII collected (PT-3). NEVER defaulted to real values. */
  categoriesOfPII: string[];
  /** §2 — sources of the PII. */
  sourcesOfPII: string[];
  /** §3 — sharing arrangements (PT-3.c compatible-use). */
  sharing: PiaSharingEntry[];
  /** §4 — consent mechanism (PT-6 notice). */
  consentMechanism: string;
  /** §4 — SORN Federal Register reference/URL (PT-6). TBD when the system is
   * not a Privacy Act system of records or no citation is supplied (Risk 6). */
  sornReference?: string;
  /** §5 — access & correction process. */
  accessAndCorrection: string;
  /** §6 — retention period. */
  retentionPeriod: string;
  /** §6 — disposal method. */
  disposalMethod: string;
  /** §7 — technical & administrative safeguards. */
  safeguards: string[];
}

export interface PtaPiaEmitOptions {
  /** Where the orchestrator writes. The emitter reads inventory.json from here. */
  outDir: string;
  /** PTA output path (defaults to <outDir>/pta.docx). */
  outPath?: string;
  /** PIA output path (defaults to <outDir>/pia.docx). */
  piaOutPath?: string;
  /** Run id — captured in the provenance (§footer) + deterministic UUID seed. */
  runId: string;
  /** FRMR catalog version — captured in the provenance footer. */
  frmrVersion: string;
  /** Impact level (low/moderate/high). */
  impactLevel: ImpactLevel;
  /** System identity (reuses --system-name / --system-id / --csp-name). */
  systemName?: string;
  systemId?: string;
  cspOrganization?: string;
  /** PIA emission policy. Default 'auto' (emit iff PTA determination positive). */
  piaForceMode?: PiaForceMode;
  /** The five PTA booleans. When omitted, Q1 auto-derives from inventory and
   * Q2-Q5 render as REQUIRES-OPERATOR-INPUT. */
  ptaResponses?: PtaResponses;
  /** Operator-supplied PIA responses. Every field REQUIRES-OPERATOR-INPUT when
   * absent + the PIA is required. */
  piaResponses?: PiaResponses;
}

export interface PtaPiaEmitResult {
  /** Path of the always-emitted PTA. */
  ptaPath: string;
  ptaBytes: number;
  /** Path of the conditionally-emitted PIA (null when not required). */
  piaPath: string | null;
  piaBytes: number | null;
  /** Whether a PIA was required (and therefore emitted). */
  requiresPIA: boolean;
  /** The PTA-Q1 determination actually rendered (operator-set or auto-derived). */
  collectsPII: boolean;
  /** Count of §3 PII-tagged inventory assets that triggered the determination. */
  pii_asset_count: number;
  /** True when a positive PTA had its PIA suppressed by piaForceMode='never-emit'. */
  pia_suppressed: boolean;
  /** True when every required-for-signature operator field was supplied. */
  ready_for_signature: boolean;
  /** Missing-input list for operator action. */
  requires_operator_input: string[];
}

// ─── Inventory reader (§3 PII evidence) ──────────────────────────────────────

/** A PII-tagged inventory asset, name-redacted per Risk 3. */
export interface PiiInventoryAsset {
  /** Normalized asset type (e.g. s3-bucket, rds-instance). */
  assetType: string;
  /** The raw data_classification tag (pii | phi). */
  classification: string;
  /** Redacted identifier — resource name masked; short hash appended for
   * correlation without leaking the name (Risk 3). */
  redactedRef: string;
}

/** The narrow slice of out/inventory.json the PTA §3 consumes. */
export interface PiiInventoryEvidence {
  /** Whether inventory.json existed + parsed. */
  present: boolean;
  /** SHA-256 of the raw inventory bytes (chain-of-custody provenance). */
  sha256: string | null;
  /** PII/PHI-tagged assets (name-redacted). */
  piiAssets: PiiInventoryAsset[];
  /** Total assets walked. */
  totalAssets: number;
  /** Whether ANY asset carried a data_classification tag at all (Risk 2). */
  anyClassified: boolean;
}

/**
 * Redact the resource-name portion of an identifier so no PII leaks into the
 * document (per-slice Risk 3), while keeping a stable short hash for 3PAO
 * correlation. The last path/segment token (after the final `/` or `:`) is
 * replaced with `***`; a `ref:` hash of the full identifier is appended.
 */
function redactIdentifier(identifier: string): string {
  const ref = createHash('sha256').update(identifier).digest('hex').slice(0, 8);
  let masked = identifier;
  const slash = identifier.lastIndexOf('/');
  const colon = identifier.lastIndexOf(':');
  const cut = Math.max(slash, colon);
  if (cut > 0 && cut < identifier.length - 1) {
    masked = `${identifier.slice(0, cut + 1)}***`;
  } else if (identifier.length > 0) {
    masked = '***';
  }
  return `${masked} (ref:${ref})`;
}

/** First data_classification value found on an asset (snake_case + camelCase +
 * common tag keys), lowercased; undefined when none present. */
function assetClassification(a: any): string | undefined {
  const direct = a?.data_classification ?? a?.dataClassification ?? a?.classification;
  if (typeof direct === 'string' && direct) return direct.toLowerCase();
  const tags = a?.tags;
  if (tags && typeof tags === 'object') {
    for (const k of ['DataClassification', 'data_classification', 'classification', 'sensitivity']) {
      const v = (tags as any)[k];
      if (typeof v === 'string' && v) return v.toLowerCase();
    }
  }
  return undefined;
}

/**
 * JSON-parse-safe read of out/inventory.json, extracting PII/PHI-tagged assets
 * for the PTA §3 evidence table. Same defensive pattern as
 * cmp-emit.ts:readInventoryComponents — never throws on a missing or malformed
 * inventory (returns present=false). The `data_classification` field is a
 * free-form asset tag (applied by the inventory enrichers / operator tags), NOT
 * a hard enum — read defensively (LOOP-C-RISKS C-C4-7).
 */
export function readPiiInventory(outDir: string): PiiInventoryEvidence {
  const p = resolve(outDir, 'inventory.json');
  if (!existsSync(p)) return { present: false, sha256: null, piiAssets: [], totalAssets: 0, anyClassified: false };
  let bytes: Buffer;
  try { bytes = readFileSync(p); } catch { return { present: false, sha256: null, piiAssets: [], totalAssets: 0, anyClassified: false }; }
  let doc: any;
  try { doc = JSON.parse(bytes.toString('utf8')); }
  catch { return { present: false, sha256: null, piiAssets: [], totalAssets: 0, anyClassified: false }; }
  const assets: any[] = Array.isArray(doc?.assets) ? doc.assets : (Array.isArray(doc) ? doc : []);
  const piiAssets: PiiInventoryAsset[] = [];
  let anyClassified = false;
  for (const a of assets) {
    if (!a || typeof a !== 'object') continue;
    const cls = assetClassification(a);
    if (cls) anyClassified = true;
    if (cls && PII_CLASSIFICATIONS.has(cls)) {
      const assetType = String(a.assetType ?? a.type ?? a.resourceType ?? 'unknown');
      const identifier = String(a.identifier ?? a.id ?? a.arn ?? a.uniqueId ?? a.name ?? '(asset)');
      piiAssets.push({ assetType, classification: cls, redactedRef: redactIdentifier(identifier) });
    }
  }
  // Deterministic ordering: by classification then assetType then ref.
  piiAssets.sort((x, y) =>
    x.classification === y.classification
      ? (x.assetType === y.assetType ? x.redactedRef.localeCompare(y.redactedRef) : x.assetType.localeCompare(y.assetType))
      : x.classification.localeCompare(y.classification),
  );
  return {
    present: true,
    sha256: createHash('sha256').update(bytes).digest('hex'),
    piiAssets,
    totalAssets: assets.length,
    anyClassified,
  };
}

// ─── Determination logic ─────────────────────────────────────────────────────

interface Determination {
  /** Q1 rendered (operator-set collectsPII OR auto-derived from inventory). */
  collectsPII: boolean;
  /** True when any PTA question is affirmative (drives PIA requirement). */
  anyAffirmative: boolean;
  /** Final PIA requirement after applying piaForceMode. */
  requiresPIA: boolean;
  /** True when a positive determination had its PIA suppressed (never-emit). */
  suppressed: boolean;
}

function determine(opts: PtaPiaEmitOptions, inv: PiiInventoryEvidence): Determination {
  const mode: PiaForceMode = opts.piaForceMode ?? 'auto';
  const autoPii = inv.piiAssets.length > 0;
  const collectsPII = opts.ptaResponses ? opts.ptaResponses.collectsPII : autoPii;
  const anyAffirmative = opts.ptaResponses
    ? (opts.ptaResponses.collectsPII || opts.ptaResponses.identifiableData ||
       opts.ptaResponses.sharingWithExternalEntities || opts.ptaResponses.persistentUserIdentifiers ||
       opts.ptaResponses.reusedForSecondaryPurposes)
    : collectsPII; // only Q1 is known when the operator supplied nothing
  let requiresPIA: boolean;
  if (mode === 'never-emit') requiresPIA = false;
  else if (mode === 'always-emit') requiresPIA = true;
  else requiresPIA = anyAffirmative;
  return { collectsPII, anyAffirmative, requiresPIA, suppressed: mode === 'never-emit' && anyAffirmative };
}

// ─── PTA builder (pure) ──────────────────────────────────────────────────────

const PTA_QUESTIONS: Array<{ n: number; text: string; key: keyof PtaResponses }> = [
  { n: 1, text: 'Does the system collect, maintain, or disseminate personally identifiable information (PII)?', key: 'collectsPII' },
  { n: 2, text: 'Is the PII identifiable to specific individuals (as opposed to aggregated / de-identified data)?', key: 'identifiableData' },
  { n: 3, text: 'Will PII be shared with, or disclosed to, external entities (other agencies, contractors, or third parties)?', key: 'sharingWithExternalEntities' },
  { n: 4, text: 'Does the system use persistent user identifiers (e.g. persistent cookies, device IDs, tracking technologies)?', key: 'persistentUserIdentifiers' },
  { n: 5, text: 'Is PII reused for a secondary purpose incompatible with the purpose for which it was originally collected?', key: 'reusedForSecondaryPurposes' },
];

export function buildPtaBodyXml(opts: PtaPiaEmitOptions): {
  xml: string;
  stats: { requiresPIA: boolean; collectsPII: boolean; pii_asset_count: number; pia_suppressed: boolean };
} {
  if (!IMPACT_LEVELS.includes(opts.impactLevel)) throw new PtaPiaImpactLevelError(String(opts.impactLevel));
  const mode: PiaForceMode = opts.piaForceMode ?? 'auto';
  if (!PIA_FORCE_MODES.includes(mode)) throw new PtaPiaForceModeError(String(opts.piaForceMode));

  const systemName = opts.systemName || TBD;
  const systemId = opts.systemId || TBD;
  const csp = opts.cspOrganization || TBD;
  const inv = readPiiInventory(opts.outDir);
  const det = determine(opts, inv);
  const docUuid = deterministicUuid(`pta:${systemId}:${opts.runId}`);

  const parts: string[] = [];

  // ── Title block ──
  parts.push(para('Privacy Threshold Analysis', 'Title'));
  parts.push(para(`${systemName} — FedRAMP ${opts.impactLevel} (PT-2 / PT-3 / PT-6)`, 'Subtitle'));
  parts.push(para(
    'DRAFT — auto-filled by fedramp-20x-cloud-evidence. §3 (PII Inventory Evidence) derives from the ' +
    `real out/inventory.json data_classification tags. Every ${TBD} marker must be completed and the ` +
    'determination confirmed by the CSP privacy officer before the PTA is signed. The CSP is the ' +
    'author-of-record.',
    'Disclaimer',
  ));

  // ── §1 System Overview ──
  parts.push(heading('1. System Overview', 1));
  parts.push(para(
    `This Privacy Threshold Analysis (PTA) determines whether ${systemName} (System ID: ${systemId}), ` +
    `operated by ${csp} and categorized at the FedRAMP ${opts.impactLevel.toUpperCase()} impact level, ` +
    'processes personally identifiable information (PII) and therefore requires a Privacy Impact ' +
    'Assessment (PIA). The PTA satisfies the documentation obligations of NIST SP 800-53 Rev. 5 ' +
    'controls PT-2 (Authority to Process PII), PT-3 (PII Processing Purposes), and PT-6 (System of ' +
    'Records Notice and Privacy Act Statements), and screens for the AR-2 (Privacy Impact and Risk ' +
    'Assessment) PIA trigger.',
  ));
  parts.push(para(
    'CONTROL-ID NOTE (per-slice Risk 5): the Rev5 PT-2 / PT-3 / PT-6 controls are satisfied using the ' +
    'published Rev4 FedRAMP SSP Attachment A04 PTA/PIA template structure, because FedRAMP has not ' +
    'published a Rev5 PTA/PIA template (help-desk article 28907995813275: "There are no current plans ' +
    'to provide a Rev. 5 PTA/PIA template for CSPs to complete."). The control identifiers below are ' +
    'Rev5; the document outline is Rev4.',
  ));

  // ── §2 PTA Determination ──
  parts.push(heading('2. PTA Determination', 1));
  parts.push(para(
    'The five threshold questions below (FedRAMP A04 + NIST SP 800-53 Rev. 5 PT-1) determine whether a ' +
    'PIA is required. Q1 is auto-derived from the inventory data_classification tags (see §3); the ' +
    `remaining answers are ${(opts.ptaResponses ? 'operator-supplied' : `${TBD} for the operator to complete via config.yaml: privacy.pta`)}.`,
  ));
  const q1Auto = !opts.ptaResponses;
  parts.push(table(
    ['#', 'Threshold Question', 'Response'],
    PTA_QUESTIONS.map((q) => {
      let response: string;
      if (opts.ptaResponses) {
        response = opts.ptaResponses[q.key] ? 'Yes' : 'No';
      } else if (q.n === 1) {
        response = `${det.collectsPII ? 'Yes' : 'No'} (auto-derived from inventory)`;
      } else {
        response = TBD;
      }
      return [String(q.n), q.text, response];
    }),
    [600, 6800, 2000],
  ));
  void q1Auto;

  // ── §3 PII Inventory Evidence ──
  parts.push(heading('3. PII Inventory Evidence', 1));
  parts.push(para(
    'Assets tagged with a PII / PHI data_classification in the real out/inventory.json. Resource names ' +
    'are REDACTED (per-slice Risk 3) so this document never leaks PII; a short ref-hash is retained for ' +
    '3PAO correlation. This table counts assets, not records — the system does not enumerate individual ' +
    'PII records (per-slice Open Q1).',
  ));
  if (!inv.present) {
    parts.push(para(
      `${TBD}: no out/inventory.json was found at run time. Run inventory collection so §3 auto-fills ` +
      'from the real data_classification tags, then re-emit the PTA. The Q1 determination above defaulted ' +
      'to "No" (no evidence of PII).',
    ));
  } else if (inv.piiAssets.length > 0) {
    parts.push(table(
      ['Asset Type', 'Data Classification', 'Redacted Asset Reference'],
      inv.piiAssets.map((a) => [a.assetType, a.classification.toUpperCase(), a.redactedRef]),
      [2600, 2400, 4400],
    ));
    parts.push(para(
      `${inv.piiAssets.length} of ${inv.totalAssets} inventoried asset(s) carry a PII/PHI ` +
      'classification tag; their presence sets the Q1 determination to "Yes".',
    ));
  } else {
    parts.push(para(
      `No inventoried asset carries a PII or PHI data_classification tag (${inv.totalAssets} asset(s) ` +
      'walked). The Q1 determination defaults to "No".',
    ));
    if (!inv.anyClassified) {
      parts.push(para(
        `${TBD_VERIFY}: NO asset in the inventory carries ANY data_classification tag. A PTA-negative ` +
        'determination cannot be trusted until assets are classified (per-slice Risk 2). The privacy ' +
        'officer MUST confirm that no PII-bearing asset was left untagged before signing this PTA.',
      ));
    }
  }

  // ── §4 Determination + Signature ──
  parts.push(heading('4. Determination & Signature', 1));
  if (det.requiresPIA) {
    parts.push(para(
      'DETERMINATION: This system processes PII (or the operator forced a PIA). A Privacy Impact ' +
      'Assessment (PIA) IS REQUIRED and is emitted as the companion pia.docx (NIST SP 800-53 Rev. 5 ' +
      'AR-2). Complete every section of the PIA before signing.',
    ));
  } else if (det.suppressed) {
    parts.push(para(
      'DETERMINATION: This system shows an affirmative PII threshold answer, but PIA emission was ' +
      `SUPPRESSED by the operator (piaForceMode='never-emit'). ${TBD_VERIFY}: verify this suppression ` +
      'with the privacy officer — a positive PTA normally REQUIRES a PIA (per-slice Risk 4). If the ' +
      'suppression is incorrect, re-emit without the never-emit override.',
    ));
  } else {
    parts.push(para(
      'DETERMINATION: This system does not process PII in a form that triggers a Privacy Impact ' +
      'Assessment. NO PIA IS REQUIRED at this time. Re-run this PTA whenever the system changes such ' +
      'that it begins collecting, maintaining, or disseminating PII.',
    ));
  }
  parts.push(para(
    'The privacy officer / system owner signs below to record the determination. The toolkit never ' +
    'auto-signs a human privacy attestation (REO Rule 1.10); signatures are captured out-of-band.',
  ));
  parts.push(table(
    ['Role', 'Name', 'Signature', 'Date'],
    [
      ['CSP Privacy Officer', TBD, TBD, TBD],
      ['System Owner', TBD, TBD, TBD],
    ],
    [2600, 3000, 2400, 1400],
  ));

  parts.push(ptaProvenance(opts, docUuid, inv));

  const sectPr = '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/>' +
    '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr>';
  const xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<w:document xmlns:w="${W_NS}"><w:body>${parts.join('')}${sectPr}</w:body></w:document>`;

  return {
    xml,
    stats: {
      requiresPIA: det.requiresPIA,
      collectsPII: det.collectsPII,
      pii_asset_count: inv.piiAssets.length,
      pia_suppressed: det.suppressed,
    },
  };
}

/** Shared provenance footer for the PTA. */
function ptaProvenance(opts: PtaPiaEmitOptions, docUuid: string, inv: PiiInventoryEvidence): string {
  return heading('Provenance', 1) + fieldTable([
    ['Generated By', 'fedramp-20x-cloud-evidence (core/pta-pia-emit.ts)'],
    ['Document UUID', docUuid],
    ['Run ID', opts.runId],
    ['FRMR Catalog Version', opts.frmrVersion],
    ['Satisfies Controls', 'NIST SP 800-53 Rev. 5 PT-2, PT-3, PT-6 (AR-2 screening)'],
    ['Inventory Evidence Source', inv.present ? `inventory.json (sha256 ${inv.sha256})` : '(none — see §3)'],
    ['Template Source', `FedRAMP SSP Attachment A04 PIA Template (Rev4) — ${A04_TEMPLATE_URL} (retrieved ${SOURCE_RETRIEVED})`],
    ['Rev5 Note', 'FedRAMP help-desk article 28907995813275: no Rev5 PTA/PIA template published; Rev4 structure used with Rev5 PT-family control IDs.'],
  ]);
}

// ─── PIA builder (pure) ──────────────────────────────────────────────────────

export function buildPiaBodyXml(opts: PtaPiaEmitOptions): {
  xml: string;
  stats: { ready_pia: boolean; missing_pia: string[] };
} {
  if (!IMPACT_LEVELS.includes(opts.impactLevel)) throw new PtaPiaImpactLevelError(String(opts.impactLevel));
  const systemName = opts.systemName || TBD;
  const systemId = opts.systemId || TBD;
  const csp = opts.cspOrganization || TBD;
  const inv = readPiiInventory(opts.outDir);
  const pr = opts.piaResponses;
  const docUuid = deterministicUuid(`pia:${systemId}:${opts.runId}`);
  const hasPhi = inv.piiAssets.some((a) => a.classification === 'phi');

  const missing_pia: string[] = [];
  const trackStr = (label: string, v: string | undefined) => { if (!v) missing_pia.push(label); };
  const trackArr = (label: string, v: unknown[] | undefined) => { if (!v || v.length === 0) missing_pia.push(label); };
  trackStr('authorityToCollect', pr?.authorityToCollect);
  trackArr('purposesOfCollection', pr?.purposesOfCollection);
  trackArr('categoriesOfPII', pr?.categoriesOfPII);
  trackArr('sourcesOfPII', pr?.sourcesOfPII);
  trackStr('consentMechanism', pr?.consentMechanism);
  trackStr('accessAndCorrection', pr?.accessAndCorrection);
  trackStr('retentionPeriod', pr?.retentionPeriod);
  trackStr('disposalMethod', pr?.disposalMethod);
  trackArr('safeguards', pr?.safeguards);

  const parts: string[] = [];

  // ── Title block ──
  parts.push(para('Privacy Impact Assessment', 'Title'));
  parts.push(para(`${systemName} — FedRAMP ${opts.impactLevel} (PT-2 / PT-3 / PT-6 / AR-2)`, 'Subtitle'));
  parts.push(para(
    'DRAFT — auto-filled by fedramp-20x-cloud-evidence. This PIA follows the published FedRAMP SSP A04 ' +
    `(Rev4) structure with Rev5 PT-family control identifiers. Every ${TBD} marker is an operator ` +
    'narrative the CSP privacy officer must complete; the toolkit never invents PII categories or ' +
    'sources. The CSP is the author-of-record.',
    'Disclaimer',
  ));

  // ── §1 Authority + Purpose (PT-2) ──
  parts.push(heading('1. Authority & Purpose', 1));
  parts.push(para(
    `This Privacy Impact Assessment covers ${systemName} (System ID: ${systemId}) operated by ${csp}. ` +
    'It satisfies NIST SP 800-53 Rev. 5 AR-2 (Privacy Impact and Risk Assessment), required when a ' +
    'system processes PII.',
  ));
  parts.push(heading('1.1 Authority to Process (PT-2)', 2));
  parts.push(para(
    'NIST SP 800-53 Rev. 5 PT-2: "a. Determine and document the [Assignment: organization-defined ' +
    'authority] that permits the [Assignment: organization-defined processing] of personally ' +
    'identifiable information; and b. Restrict the [Assignment: organization-defined processing] of ' +
    'personally identifiable information to only that which is authorized." The originating policy is ' +
    'OMB Memorandum M-03-22 (E-Government Act §208).',
  ));
  parts.push(fieldTable([['Authority to Collect / Process PII', pr?.authorityToCollect || TBD]]));
  parts.push(heading('1.2 Purpose of Processing (PT-3.a)', 2));
  parts.push(bulletsOrTbd(pr?.purposesOfCollection,
    'identify and document each purpose for processing PII. Supply via config.yaml: privacy.pia.purposesOfCollection.'));

  // ── §2 PII Categories + Sources (PT-3) ──
  parts.push(heading('2. Categories & Sources of PII (PT-3)', 1));
  parts.push(heading('2.1 Categories of PII', 2));
  parts.push(bulletsOrTbd(pr?.categoriesOfPII,
    'list every category of PII the system processes (the toolkit never defaults these — invented ' +
    'categories would misrepresent the system). Supply via config.yaml: privacy.pia.categoriesOfPII.'));
  parts.push(heading('2.2 Sources of PII', 2));
  parts.push(bulletsOrTbd(pr?.sourcesOfPII,
    'list where the PII originates (data subject, third party, another system). Supply via ' +
    'config.yaml: privacy.pia.sourcesOfPII.'));

  // ── §3 Sharing + Use (PT-3) ──
  parts.push(heading('3. Sharing & Use (PT-3)', 1));
  parts.push(para(
    'NIST SP 800-53 Rev. 5 PT-3.c: "Restrict the [Assignment: organization-defined processing] of ' +
    'personally identifiable information to only that which is compatible with the identified ' +
    'purpose(s)." External sharing arrangements:',
  ));
  if (pr?.sharing && pr.sharing.length > 0) {
    parts.push(table(
      ['Recipient', 'Purpose', 'Mechanism'],
      pr.sharing.map((s) => [s.recipient || TBD, s.purpose || TBD, s.mechanism || TBD]),
      [3000, 3600, 2800],
    ));
  } else {
    parts.push(para(
      `${TBD}: document each external sharing arrangement (recipient, purpose, mechanism) or state that ` +
      'no PII is shared externally. Supply via config.yaml: privacy.pia.sharing.',
    ));
  }

  // ── §4 Notice & Consent (PT-6 SORN) ──
  parts.push(heading('4. Notice & Consent (PT-6)', 1));
  parts.push(para(
    'NIST SP 800-53 Rev. 5 PT-6: "For systems that process information that will be maintained in a ' +
    'Privacy Act system of records: a. Draft and publish System of Records Notices in the Federal ' +
    'Register ...; b. Keep System of Records Notices accurate, up-to-date, and scoped ...; c. Review ' +
    'System of Records Notices [Assignment: organization-defined frequency]."',
  ));
  parts.push(fieldTable([
    ['Consent / Notice Mechanism', pr?.consentMechanism || TBD],
    ['SORN Federal Register Reference', pr?.sornReference || `${TBD} (only if this is a Privacy Act system of records)`],
  ]));
  parts.push(para(
    'NOTE (per-slice Risk 6): a PIA cannot by itself satisfy PT-6 — publishing a System of Records ' +
    'Notice is a Federal Register process the agency customer initiates. This PIA records the SORN ' +
    'reference; it does not create the SORN.',
  ));

  // ── §5 Access & Correction ──
  parts.push(heading('5. Access & Correction', 1));
  parts.push(fieldTable([['Access & Correction Process', pr?.accessAndCorrection || TBD]]));

  // ── §6 Retention & Disposal ──
  parts.push(heading('6. Retention & Disposal', 1));
  parts.push(fieldTable([
    ['Retention Period', pr?.retentionPeriod || TBD],
    ['Disposal Method', pr?.disposalMethod || TBD],
  ]));

  // ── §7 Safeguards & Compensating Controls ──
  parts.push(heading('7. Safeguards & Compensating Controls', 1));
  parts.push(bulletsOrTbd(pr?.safeguards,
    'list the technical + administrative safeguards protecting the PII (encryption, access control, ' +
    'audit logging, minimization). Supply via config.yaml: privacy.pia.safeguards.'));

  // ── §8 Privacy Risk Assessment ──
  parts.push(heading('8. Privacy Risk Assessment', 1));
  parts.push(para(
    'The privacy risk to individuals is assessed against the NIST Privacy Framework v1.0 (2020-01-16) ' +
    'Functions — Govern, Identify, Protect, Communicate, Respond — and recorded per AR-2. The CSP ' +
    'privacy officer completes the assessment; unmitigated privacy risks are tracked as POA&M items ' +
    '(LOOP-A.A1).',
  ));
  parts.push(table(
    ['Privacy Framework Function', 'Assessment'],
    [
      ['Govern-P', TBD],
      ['Identify-P', TBD],
      ['Protect-P', TBD],
      ['Communicate-P', TBD],
      ['Respond-P', TBD],
    ],
    [3400, 6000],
  ));
  if (hasPhi) {
    parts.push(para(
      `${TBD_VERIFY} (per-slice Open Q3): one or more inventoried assets carry a PHI (protected health ` +
      'information) classification. If this system serves an HHS agency customer, HIPAA Security Rule / ' +
      'Breach Notification obligations may apply IN ADDITION to the FedRAMP privacy controls. HIPAA is ' +
      'outside FedRAMP authorization scope — this is an advisory flag only; confirm applicability with ' +
      'the privacy officer.',
    ));
  }

  // ── §9 Signature ──
  parts.push(heading('9. Signature', 1));
  parts.push(para(
    'The privacy officer / system owner signs below to attest the PIA is accurate and complete. The ' +
    'toolkit never auto-signs a human privacy attestation (REO Rule 1.10).',
  ));
  parts.push(table(
    ['Role', 'Name', 'Signature', 'Date'],
    [
      ['CSP Privacy Officer', TBD, TBD, TBD],
      ['System Owner', TBD, TBD, TBD],
    ],
    [2600, 3000, 2400, 1400],
  ));

  // ── Provenance footer ──
  parts.push(heading('Provenance', 1));
  parts.push(fieldTable([
    ['Generated By', 'fedramp-20x-cloud-evidence (core/pta-pia-emit.ts)'],
    ['Document UUID', docUuid],
    ['Run ID', opts.runId],
    ['FRMR Catalog Version', opts.frmrVersion],
    ['Satisfies Controls', 'NIST SP 800-53 Rev. 5 PT-2, PT-3, PT-6, AR-2'],
    ['Inventory Evidence Source', inv.present ? `inventory.json (sha256 ${inv.sha256})` : '(none)'],
    ['Template Source', `FedRAMP SSP Attachment A04 PIA Template (Rev4) — ${A04_TEMPLATE_URL} (retrieved ${SOURCE_RETRIEVED})`],
    ['Privacy Framework', `NIST Privacy Framework v1.0 (2020-01-16, retrieved ${SOURCE_RETRIEVED})`],
    ['Rev5 Note', 'FedRAMP help-desk article 28907995813275: no Rev5 PTA/PIA template published; Rev4 structure used with Rev5 PT-family control IDs.'],
  ]));

  const sectPr = '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/>' +
    '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr>';
  const xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<w:document xmlns:w="${W_NS}"><w:body>${parts.join('')}${sectPr}</w:body></w:document>`;

  return { xml, stats: { ready_pia: missing_pia.length === 0, missing_pia } };
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
    style('Heading1', 'heading 1', { size: 32, bold: true, color: '1F3864', spacingBefore: 360 }) +
    style('Heading2', 'heading 2', { size: 26, bold: true, color: '2E74B5', spacingBefore: 240 }) +
    style('Heading3', 'heading 3', { size: 24, bold: true, color: '1F4E79', spacingBefore: 160 }) +
    `</w:styles>`;
}

/** docProps/core.xml — deterministic title metadata (no wall-clock time). */
function coreXml(title: string): string {
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

/** Pack a WordprocessingML body XML into a .docx Buffer (store-only ZIP). */
function packDocx(bodyXml: string, title: string): Buffer {
  const b = (s: string) => Buffer.from(s, 'utf8');
  return zipStore([
    { name: '[Content_Types].xml', data: b(CONTENT_TYPES) },
    { name: '_rels/.rels', data: b(ROOT_RELS) },
    { name: 'docProps/core.xml', data: b(coreXml(title)) },
    { name: 'word/document.xml', data: b(bodyXml) },
    { name: 'word/styles.xml', data: b(stylesXml()) },
    { name: 'word/_rels/document.xml.rels', data: b(DOC_RELS) },
  ]);
}

/** Pure: render the PTA (and, when required, PIA) to Buffers + stats. */
export function renderPtaPiaDocx(opts: PtaPiaEmitOptions): {
  ptaBuffer: Buffer;
  piaBuffer: Buffer | null;
  stats: Omit<PtaPiaEmitResult, 'ptaPath' | 'ptaBytes' | 'piaPath' | 'piaBytes'>;
} {
  const systemName = opts.systemName || TBD;
  const systemId = opts.systemId || TBD;
  const ptaUuid = deterministicUuid(`pta:${systemId}:${opts.runId}`);
  const { xml: ptaXml, stats: ptaStats } = buildPtaBodyXml(opts);
  const ptaBuffer = packDocx(ptaXml, `Privacy Threshold Analysis — ${systemName} [${ptaUuid}]`);

  // Required-for-signature tracking: system identity always required; PTA
  // responses required for a complete determination; PIA fields required only
  // when the PIA is emitted.
  const missing: string[] = [];
  if (!opts.systemName) missing.push('systemName');
  if (!opts.systemId) missing.push('systemId');
  if (!opts.cspOrganization) missing.push('cspOrganization');
  if (!opts.ptaResponses) missing.push('ptaResponses');

  let piaBuffer: Buffer | null = null;
  if (ptaStats.requiresPIA) {
    const piaUuid = deterministicUuid(`pia:${systemId}:${opts.runId}`);
    const { xml: piaXml, stats: piaStats } = buildPiaBodyXml(opts);
    piaBuffer = packDocx(piaXml, `Privacy Impact Assessment — ${systemName} [${piaUuid}]`);
    for (const f of piaStats.missing_pia) missing.push(`piaResponses.${f}`);
  }

  return {
    ptaBuffer,
    piaBuffer,
    stats: {
      requiresPIA: ptaStats.requiresPIA,
      collectsPII: ptaStats.collectsPII,
      pii_asset_count: ptaStats.pii_asset_count,
      pia_suppressed: ptaStats.pia_suppressed,
      ready_for_signature: missing.length === 0,
      requires_operator_input: missing,
    },
  };
}

/** Read inventory, render, and write pta.docx (always) + pia.docx (conditional). */
export function emitPtaPiaDocx(opts: PtaPiaEmitOptions): PtaPiaEmitResult {
  const { ptaBuffer, piaBuffer, stats } = renderPtaPiaDocx(opts);
  const ptaPath = opts.outPath ?? resolve(opts.outDir, 'pta.docx');
  writeFileSync(ptaPath, ptaBuffer);
  let piaPath: string | null = null;
  let piaBytes: number | null = null;
  if (piaBuffer) {
    piaPath = opts.piaOutPath ?? resolve(opts.outDir, 'pia.docx');
    writeFileSync(piaPath, piaBuffer);
    piaBytes = piaBuffer.length;
  }
  log.info({
    event: 'pta-pia.emitted',
    pta_path: ptaPath,
    pta_bytes: ptaBuffer.length,
    pia_path: piaPath,
    pia_bytes: piaBytes,
    requires_pia: stats.requiresPIA,
    collects_pii: stats.collectsPII,
    pii_asset_count: stats.pii_asset_count,
    pia_suppressed: stats.pia_suppressed,
    ready_for_signature: stats.ready_for_signature,
    requires_operator_input_count: stats.requires_operator_input.length,
  });
  return { ptaPath, ptaBytes: ptaBuffer.length, piaPath, piaBytes, ...stats };
}
