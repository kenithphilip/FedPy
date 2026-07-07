/**
 * Information System Contingency Plan (ISCP) emitter — LOOP-C.C2.
 *
 * Renders `iscp.docx` — a Contingency Plan structured section-for-section per
 * the FedRAMP SSP Appendix G ISCP Template and NIST SP 800-34 Rev. 1, that
 * satisfies NIST SP 800-53 Rev. 5 controls CP-2 (Contingency Plan), CP-9
 * (System Backup), and CP-10 (System Recovery and Reconstitution). The §4.2
 * Recovery-evidence table is auto-filled from the real signed RPL-family KSI
 * evidence files (KSI-RPL-ABO/TRC/RRO/ARP) when the collector has run; the
 * Appendix B vendor-contact table is auto-pulled from the real J.J2
 * subprocessor inventory; every operator narrative slot (RTO/RPO, alternate
 * site, activation authority, rosters) defaults to a verbatim
 * `REQUIRES-OPERATOR-INPUT` marker rather than fabricating recovery language.
 * Closes a real FedRAMP 20x gap: CSPs currently hand-transcribe the Appendix G
 * template from a blank page every assessment cycle.
 *
 * Authoritative sources (verbatim):
 *   - FedRAMP SSP Appendix G — Information System Contingency Plan (ISCP)
 *     Template —
 *     https://www.fedramp.gov/assets/resources/templates/SSP-Appendix-G-Information-System-Contingency-Plan-(ISCP)-Template.docx
 *     (FedRAMP Rev5). Section order mirrored exactly: §1 Introduction & Scope;
 *     §2 Concept of Operations; §3 Activation & Notification; §4 Recovery;
 *     §5 Reconstitution; §6 Plan Maintenance; Appendix A Personnel Contact
 *     List; Appendix B Vendor Contacts; Appendix C Detailed Recovery
 *     Procedures; Appendix D Alternate Site Procedures; Appendix E System
 *     Validation Test Plan; Appendix F Contingency Plan Test Report.
 *   - NIST SP 800-34 Rev. 1 (Updated 2010-11-11), Contingency Planning Guide
 *     for Federal Information Systems —
 *     https://csrc.nist.gov/pubs/sp/800/34/r1/upd1/final :
 *     "The information system contingency planning process includes the
 *      following seven steps: 1) Develop the contingency planning policy;
 *      2) Conduct the business impact analysis (BIA); 3) Identify preventive
 *      controls; 4) Create contingency strategies; 5) Develop an information
 *      system contingency plan; 6) Ensure plan testing, training, and
 *      exercises; 7) Ensure plan maintenance." (§3.1, p. 17)
 *   - NIST SP 800-53 Rev. 5 CP-2 (Contingency Plan) —
 *     https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final :
 *     "Develop a contingency plan for the system that: a. Identifies essential
 *      mission and business functions and associated contingency requirements;
 *      b. Provides recovery objectives, restoration priorities, and metrics;
 *      c. Addresses contingency roles, responsibilities, assigned individuals
 *      with contact information; d. Addresses maintaining essential mission and
 *      business functions despite a system disruption, compromise, or failure;
 *      e. Addresses eventual, full system restoration without deterioration of
 *      the controls originally planned and implemented; f. Addresses the
 *      sharing of contingency information; g. Is reviewed and approved by
 *      [Assignment: organization-defined personnel or roles]."
 *   - NIST SP 800-53 Rev. 5 CP-9 (System Backup) + CP-10 (System Recovery and
 *     Reconstitution) — same catalog URL — anchor the §4.2 RPL-evidence rows.
 *
 * Approach (dependency-free .docx): a `.docx` is a ZIP of WordprocessingML XML
 * parts. We build the parts as strings and pack them with the store-only ZIP
 * writer the SSP-2 / RoE / CMP renderers use (core/zip.ts) — no external Word
 * library, no runtime network. The OOXML building blocks mirror the pattern
 * established by core/cmp-emit.ts (a shared docx-primitives module was proposed
 * in LOOP-C-SPEC §4 but never extracted; see LOOP-C-RISKS C-C2-10 / C-X-1 for
 * the reconciliation — this emitter follows the five shipped docx emitters and
 * keeps its OOXML constants local). The inventory reader (§2 component table)
 * is COMPOSED from core/cmp-emit.ts rather than re-implemented.
 *
 * REO compliance:
 *   - §4.2 Recovery-evidence rows trace ONLY to real signed KSI-RPL-*.json
 *     evidence files on disk; the emitter never invents a "backup is
 *     configured" row. Absent evidence → a single REQUIRES-OPERATOR-INPUT row
 *     explaining the fix.
 *   - Appendix B vendor contacts trace to the real subprocessor-inventory.json
 *     rows (J.J2); absent → a REQUIRES-OPERATOR-INPUT row. Contact/phone are
 *     not carried by the SA-9 inventory, so those cells stay
 *     REQUIRES-OPERATOR-INPUT (never fabricated).
 *   - Every recovery narrative (RTO/RPO, alternate site, activation, rosters)
 *     defaults to a verbatim REQUIRES-OPERATOR-INPUT marker (REO Rule 4).
 *   - The document is fully deterministic (no wall-clock time): the metadata
 *     UUID is `deterministicUuid('iscp:' + systemId + ':' + runId)` and the
 *     evidence provenance is content SHA-256, so identical inputs produce a
 *     byte-identical .docx. Integrity is anchored by the signed submission-
 *     bundle INDEX.json (which SHA-256s + Ed25519-signs every included file),
 *     the same coverage cmp.docx / roe.docx / ssp.docx receive.
 *
 * Pure renderer (`renderIscpDocx` / `buildIscpBodyXml`) + disk emitter
 * (`emitIscpDocx`).
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { xmlEscape, zipStore } from './zip.ts';
import { deterministicUuid } from './oscal.ts';
import { log } from './log.ts';
import { readInventoryComponents, groupComponents } from './cmp-emit.ts';

const W_NS = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main';
/** Verbatim marker for missing operator input (REO Rule 4). */
const TBD = 'REQUIRES-OPERATOR-INPUT';
/** Accepted impact tiers. */
const IMPACT_LEVELS = ['low', 'moderate', 'high'] as const;
type ImpactLevel = (typeof IMPACT_LEVELS)[number];

/** Thrown when an unknown impact level is supplied (must be low|moderate|high). */
export class IscpImpactLevelError extends Error {
  constructor(value: string) {
    super(
      `iscp-emit: unknown impactLevel "${value}"; must be one of ` +
      `${IMPACT_LEVELS.join(' | ')}.`,
    );
    this.name = 'IscpImpactLevelError';
  }
}

// ─── OOXML building blocks (same pattern as cmp-emit.ts / ssp-docx.ts) ────────

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

// ─── Public options + result ─────────────────────────────────────────────────

/** A contingency-team roster entry (Appendix A / §3). */
export interface IscpTeamMember {
  role: string;
  name: string;
  org: string;
  email: string;
  phone: string;
  /** Optional named alternate for the role. */
  alternate?: string;
}

/** A vendor / subprocessor contact entry (Appendix B). */
export interface IscpVendorContact {
  vendor: string;
  contact: string;
  role: string;
  phone: string;
  sla: string;
}

export interface IscpEmitOptions {
  /** Where the orchestrator writes. The emitter reads RPL/inventory/ssp from here. */
  outDir: string;
  /** Output path (defaults to <outDir>/iscp.docx). */
  outPath?: string;
  /** Run id — captured in the ISCP provenance (§1) + deterministic UUID seed. */
  runId: string;
  /** FRMR catalog version — captured in the ISCP provenance (§1). */
  frmrVersion: string;
  /** Impact level (low/moderate/high). */
  impactLevel: ImpactLevel;
  /** System identity (reuses --system-name / --system-id / --csp-name). */
  systemName?: string;
  systemId?: string;
  cspOrganization?: string;
  /** §4.1 Recovery Time Objective commitment. */
  rto?: { hours: number; rationale: string };
  /** §4.1 Recovery Point Objective commitment. */
  rpo?: { hours: number; rationale: string };
  /** §4 recovery-priority tier. */
  recoveryPriority?: 'mission-critical' | 'mission-essential' | 'standard';
  /** Appendix D alternate-site profile. */
  alternateSite?: { type: 'hot' | 'warm' | 'cold' | 'cloud'; location: string; activationProcedure: string };
  /** §3 activation authority (role authorized to declare a contingency). */
  activationAuthority?: string;
  /** §3 activation criteria (conditions that trigger the plan). */
  activationCriteria?: string[];
  /** §3 Contingency Plan Coordinator. */
  cpCoordinator?: { name: string; org: string; email: string; phone: string };
  /** Appendix A / §3 contingency-team roster. */
  teamRoster?: IscpTeamMember[];
  /** Appendix B vendor contacts (overrides the auto-pulled subprocessor rows). */
  vendorContacts?: IscpVendorContact[];
  /** §4.2 backup-strategy summary (auto-summarized from RPL evidence when absent). */
  backupStrategySummary?: string;
}

export interface IscpEmitResult {
  path: string;
  bytes: number;
  /** Count of RPL-family KSI evidence files found + cited in §4.2. */
  rpl_evidence_count: number;
  /** Count of real inventory assets feeding the §2 component table. */
  component_count: number;
  /** Count of vendor contacts in Appendix B (operator-supplied OR auto-pulled). */
  vendor_contact_count: number;
  /** True when every required-for-signature operator field was supplied. */
  ready_for_signature: boolean;
  /** Missing-input list for operator action. */
  requires_operator_input: string[];
}

// ─── RPL-family KSI evidence reader ──────────────────────────────────────────

/**
 * The narrow slice of a signed KSI evidence envelope the ISCP consumes. Defined
 * narrowly (only the fields the emitter reads) so RPL-collector schema drift —
 * new cloud backup features add fields — never breaks the emitter (LOOP-C-RISKS
 * C-C2-1). The full envelope shape is core/envelope.ts:EvidenceFile.
 */
export interface KsiEvidence {
  ksi_id: string;
  ksi_name?: string;
  /** Top-level aggregate outcome (envelope.rollup.pass). */
  passed: boolean;
  /** Top-level ISO timestamp the evidence was collected (envelope.collected_at). */
  last_collected_at: string;
  /** SHA-256 of the raw evidence-file bytes (chain-of-custody provenance). */
  sha256: string;
}

/** The four RPL-family KSIs, in ISCP §4.2 table order. Published FedRAMP KSI
 * constants (core/ksi-map.ts) — allowed fixed data per REO Rule 3. */
const RPL_KSIS = [
  { key: 'abo', id: 'KSI-RPL-ABO', name: 'Aligning Backups with Objectives', purpose: 'Automated Backups Configured', controls: 'CP-9' },
  { key: 'trc', id: 'KSI-RPL-TRC', name: 'Testing Recovery Capabilities', purpose: 'Tested Recovery Capability', controls: 'CP-4, CP-10' },
  { key: 'rro', id: 'KSI-RPL-RRO', name: 'Reviewing Recovery Objectives', purpose: 'Recovery RPO/RTO Objectives', controls: 'CP-2(3), CP-9' },
  { key: 'arp', id: 'KSI-RPL-ARP', name: 'Aligning Recovery Plan', purpose: 'Alternate Recovery Processing', controls: 'CP-2, CP-7, CP-10' },
] as const;

type RplKey = (typeof RPL_KSIS)[number]['key'];

/**
 * JSON-parse-safe read of a single signed KSI evidence file. Prefers the real
 * collector output name `KSI-<id>.json`; falls back to the `.signed.json`
 * variant the C.C2 spec §5 named (the collector filters `.signed.json` out as a
 * duplicate, so `.json` is authoritative — LOOP-C-RISKS C-C2-7). Never throws.
 */
function readKsiEvidence(outDir: string, ksiId: string): KsiEvidence | undefined {
  for (const name of [`${ksiId}.json`, `${ksiId}.signed.json`]) {
    const p = resolve(outDir, name);
    if (!existsSync(p)) continue;
    let bytes: Buffer;
    try { bytes = readFileSync(p); } catch { continue; }
    let doc: any;
    try { doc = JSON.parse(bytes.toString('utf8')); } catch { continue; }
    if (!doc || typeof doc !== 'object') continue;
    const rollup = doc.rollup ?? {};
    return {
      ksi_id: String(doc.ksi_id ?? ksiId),
      ksi_name: doc.ksi_name ? String(doc.ksi_name) : undefined,
      passed: rollup.pass === true,
      last_collected_at: String(doc.collected_at ?? doc.collectedAt ?? ''),
      sha256: createHash('sha256').update(bytes).digest('hex'),
    };
  }
  return undefined;
}

/** Read all four RPL-family evidence files from outDir (JSON-parse-safe). */
export function readRplEvidence(outDir: string): Partial<Record<RplKey, KsiEvidence>> {
  const out: Partial<Record<RplKey, KsiEvidence>> = {};
  for (const k of RPL_KSIS) {
    const ev = readKsiEvidence(outDir, k.id);
    if (ev) out[k.key] = ev;
  }
  return out;
}

// ─── Subprocessor (Appendix B) reader ────────────────────────────────────────

/**
 * Read the J.J2 subprocessor inventory for Appendix B vendor contacts. Prefers
 * the real collector output `subprocessor-inventory.json` (a `{ rows: [...] }`
 * envelope); falls back to the C.C2 spec-named `subprocessors.json` and
 * tolerates a bare top-level array (LOOP-C-RISKS C-C2-8). The SA-9 inventory
 * carries name/role/SLA but NOT a contact person or phone, so those cells stay
 * REQUIRES-OPERATOR-INPUT rather than being fabricated. Never throws.
 */
export function readSubprocessorContacts(outDir: string): IscpVendorContact[] {
  for (const name of ['subprocessor-inventory.json', 'subprocessors.json']) {
    const p = resolve(outDir, name);
    if (!existsSync(p)) continue;
    let doc: any;
    try { doc = JSON.parse(readFileSync(p, 'utf8')); }
    catch { continue; }
    const rows: any[] = Array.isArray(doc?.rows) ? doc.rows : (Array.isArray(doc) ? doc : []);
    const contacts: IscpVendorContact[] = [];
    for (const r of rows) {
      if (!r || typeof r !== 'object' || !r.name) continue;
      const sla = (r.incident_notification_sla_hours ?? r.sla);
      contacts.push({
        vendor: String(r.name),
        contact: TBD,
        role: String(r.role ?? TBD),
        phone: TBD,
        sla: (sla === undefined || sla === null || sla === '') ? TBD : `${sla} hours`,
      });
    }
    if (contacts.length > 0) return contacts;
  }
  return [];
}

// ─── Concept-of-Operations (§2) system-description reader ─────────────────────

/**
 * Read the system description from out/ssp.json when present. Per the C.C2 §10
 * Q2 resolution, the ISCP §2 is the CANONICAL contingency narrative (FedRAMP
 * Appendix G implies this); the SSP description, when available, seeds §2 as a
 * starting reference the operator refines. Never throws.
 */
export function readSspDescription(outDir: string): string | undefined {
  const p = resolve(outDir, 'ssp.json');
  if (!existsSync(p)) return undefined;
  try {
    const doc: any = JSON.parse(readFileSync(p, 'utf8'));
    const sc = doc?.['system-security-plan']?.['system-characteristics'] ?? doc?.['system-characteristics'];
    const desc = sc?.description;
    return (typeof desc === 'string' && desc.trim() !== '') ? desc : undefined;
  } catch {
    return undefined;
  }
}

// ─── Default team roster (all cells REQUIRES-OPERATOR-INPUT) ──────────────────

function defaultRoster(): IscpTeamMember[] {
  // Per REO Rule 4: emit a structurally-complete Appendix A so the operator
  // sees exactly which contingency roles to fill. Roles from NIST SP 800-34
  // Rev. 1 §4 (Contingency Plan roles).
  return [
    { role: 'Contingency Plan Coordinator', name: TBD, org: TBD, email: TBD, phone: TBD },
    { role: 'System Owner', name: TBD, org: TBD, email: TBD, phone: TBD },
    { role: 'Recovery Team Lead', name: TBD, org: TBD, email: TBD, phone: TBD },
    { role: 'Communications Lead', name: TBD, org: TBD, email: TBD, phone: TBD },
  ];
}

// ─── Backup-strategy summary (auto-derived from RPL evidence) ─────────────────

/**
 * Summarize the §4.2 backup strategy from the RPL evidence found on disk. Pure
 * — every phrase traces to a real evidence file's pass/fail. When no evidence
 * is present, returns a REQUIRES-OPERATOR-INPUT prompt.
 */
function deriveBackupStrategySummary(rpl: Partial<Record<RplKey, KsiEvidence>>): string {
  const found = RPL_KSIS.filter((k) => rpl[k.key]);
  if (found.length === 0) {
    return `${TBD}: no RPL-family evidence (KSI-RPL-ABO/TRC/RRO/ARP) found in the run ` +
      'output. Run the collector so the backup strategy is auto-summarized from real ' +
      'signed evidence, or supply --iscp (config.yaml: iscp.backup_strategy_summary).';
  }
  const passing = found.filter((k) => rpl[k.key]!.passed).map((k) => k.purpose);
  const failing = found.filter((k) => !rpl[k.key]!.passed).map((k) => k.purpose);
  const parts: string[] = [];
  if (passing.length > 0) {
    parts.push(`Recovery capabilities evidenced as satisfied this cycle: ${passing.join('; ')}.`);
  }
  if (failing.length > 0) {
    parts.push(`Recovery capabilities with open gaps (see §4.2 + the POA&M): ${failing.join('; ')}.`);
  }
  parts.push('Each row below cites the signed KSI evidence file it derives from (SHA-256 in the provenance footer).');
  return parts.join(' ');
}

// ─── Builder (pure) ──────────────────────────────────────────────────────────

export function buildIscpBodyXml(opts: IscpEmitOptions): {
  xml: string;
  stats: Omit<IscpEmitResult, 'path' | 'bytes'>;
} {
  if (!IMPACT_LEVELS.includes(opts.impactLevel)) {
    throw new IscpImpactLevelError(String(opts.impactLevel));
  }

  const systemName = opts.systemName || TBD;
  const systemId = opts.systemId || TBD;
  const csp = opts.cspOrganization || TBD;

  // Required-for-signature input tracker (CP-2 mandates these narratives).
  const missing: string[] = [];
  const track = (label: string, present: boolean) => { if (!present) missing.push(label); };
  track('systemName', !!opts.systemName);
  track('systemId', !!opts.systemId);
  track('cspOrganization', !!opts.cspOrganization);
  track('rto', !!opts.rto);
  track('rpo', !!opts.rpo);
  track('recoveryPriority', !!opts.recoveryPriority);
  track('alternateSite', !!opts.alternateSite);
  track('activationAuthority', !!(opts.activationAuthority && opts.activationAuthority.trim()));
  track('activationCriteria', !!(opts.activationCriteria && opts.activationCriteria.length > 0));
  track('cpCoordinator', !!opts.cpCoordinator);
  track('teamRoster', !!(opts.teamRoster && opts.teamRoster.length > 0));

  const rpl = readRplEvidence(opts.outDir);
  const rplEvidenceCount = RPL_KSIS.filter((k) => rpl[k.key]).length;
  const components = readInventoryComponents(opts.outDir);
  const groups = groupComponents(components);
  const sspDesc = readSspDescription(opts.outDir);
  const vendorContacts = (opts.vendorContacts && opts.vendorContacts.length > 0)
    ? opts.vendorContacts
    : readSubprocessorContacts(opts.outDir);

  const docUuid = deterministicUuid(`iscp:${systemId}:${opts.runId}`);

  const parts: string[] = [];

  // ── Title block ──
  parts.push(para('Information System Contingency Plan', 'Title'));
  parts.push(para(`${systemName} — FedRAMP ${opts.impactLevel} (CP-2 / CP-9 / CP-10)`, 'Subtitle'));
  parts.push(para(
    'DRAFT — auto-filled by fedramp-20x-cloud-evidence. The §4.2 Recovery-evidence ' +
    'table derives from the real signed RPL-family KSI evidence; Appendix B derives from ' +
    `the real subprocessor inventory. The operator must complete every ${TBD} marker ` +
    'before the plan is reviewed and approved (CP-2.g). The CSP is the author-of-record.',
    'Disclaimer',
  ));

  // ── §1 Introduction & Scope ──
  parts.push(heading('1. Introduction & Scope', 1));

  parts.push(heading('1.1 Background', 2));
  parts.push(para(
    `This Information System Contingency Plan (ISCP) documents the strategies and procedures ` +
    `to recover ${systemName} following a disruption, in satisfaction of NIST SP 800-53 Rev. 5 ` +
    'control CP-2 (Contingency Plan): "Develop a contingency plan for the system that: ' +
    'a. Identifies essential mission and business functions and associated contingency ' +
    'requirements; b. Provides recovery objectives, restoration priorities, and metrics; ' +
    'c. Addresses contingency roles, responsibilities, assigned individuals with contact ' +
    'information; d. Addresses maintaining essential mission and business functions despite a ' +
    'system disruption, compromise, or failure; e. Addresses eventual, full system restoration ' +
    'without deterioration of the controls originally planned and implemented; f. Addresses the ' +
    'sharing of contingency information; g. Is reviewed and approved by [Assignment: ' +
    'organization-defined personnel or roles]." (NIST SP 800-53 Rev. 5, CP-2)',
  ));

  parts.push(heading('1.2 Scope', 2));
  parts.push(para(
    `This plan applies to ${systemName} (System ID: ${systemId}) operated by ${csp}, ` +
    `categorized at the FedRAMP ${opts.impactLevel.toUpperCase()} impact level. The recovery ` +
    'objectives, roles, and procedures herein cover the information resources enumerated in ' +
    'the system inventory (see §2) and the recovery evidence collected under the RPL family ' +
    '(see §4.2).',
  ));

  parts.push(heading('1.3 Methodology', 2));
  parts.push(para(
    'This plan follows the NIST SP 800-34 Rev. 1 contingency planning process: ' +
    '"The information system contingency planning process includes the following seven steps: ' +
    '1) Develop the contingency planning policy; 2) Conduct the business impact analysis (BIA); ' +
    '3) Identify preventive controls; 4) Create contingency strategies; 5) Develop an ' +
    'information system contingency plan; 6) Ensure plan testing, training, and exercises; ' +
    '7) Ensure plan maintenance." (NIST SP 800-34 Rev. 1, §3.1)',
  ));

  parts.push(heading('1.4 Assumptions', 2));
  parts.push(para(
    'This plan assumes: (a) the recovery objectives and personnel rosters below are maintained ' +
    'by the CSP and reviewed at least annually (see §6); (b) the RPL-family evidence in §4.2 ' +
    'reflects the current backup + recovery posture at the time of the referenced collection; ' +
    '(c) the alternate processing capability in Appendix D is provisioned and reachable. ' +
    `Assumptions not yet confirmed by the operator are marked ${TBD}.`,
  ));

  // ── §2 Concept of Operations ──
  parts.push(heading('2. Concept of Operations', 1));
  parts.push(para(
    sspDesc
      ? `System description (seeded from out/ssp.json; the operator refines this as the ` +
        `canonical contingency narrative): ${sspDesc}`
      : `${TBD}: describe the system's normal concept of operations (architecture, essential ` +
        'functions, dependencies). When out/ssp.json is present its system description seeds ' +
        'this section; otherwise supply the narrative. Per FedRAMP Appendix G the ISCP is the ' +
        'canonical contingency narrative.',
  ));
  parts.push(heading('2.1 System Components', 2));
  parts.push(para(
    'The recoverable information resources below are auto-derived from out/inventory.json ' +
    '(CM-8 System Component Inventory), grouped by (provider, asset type). Each row represents ' +
    'real cloud resources discovered by the collector; no synthetic components appear.',
  ));
  if (groups.length > 0) {
    parts.push(table(
      ['Provider', 'Asset Type', 'Count', 'Location(s)'],
      groups.map((g) => [g.provider, g.assetType, String(g.count), g.locations.join(', ') || '—']),
      [2200, 2600, 1200, 3000],
    ));
  } else {
    parts.push(table(
      ['Provider', 'Asset Type', 'Count', 'Location(s)'],
      [[TBD, 'out/inventory.json missing or empty. Run the collector to populate the inventory, then re-emit the ISCP.', '0', '—']],
      [2200, 2600, 1200, 3000],
    ));
  }

  // ── §3 Activation & Notification Phase ──
  parts.push(heading('3. Activation & Notification Phase', 1));
  parts.push(heading('3.1 Activation Authority', 2));
  parts.push(para(
    opts.activationAuthority && opts.activationAuthority.trim()
      ? `The following role is authorized to declare a contingency and activate this plan: ${opts.activationAuthority}.`
      : `${TBD}: name the role authorized to declare a contingency and activate this plan ` +
        '(e.g., "the Contingency Plan Coordinator, or the System Owner in their absence").',
  ));
  parts.push(heading('3.2 Activation Criteria', 2));
  if (opts.activationCriteria && opts.activationCriteria.length > 0) {
    parts.push(table(
      ['#', 'Activation Criterion'],
      opts.activationCriteria.map((c, i) => [String(i + 1), c]),
      [800, 8200],
    ));
  } else {
    parts.push(para(
      `${TBD}: enumerate the conditions that trigger plan activation (e.g., primary region ` +
      'outage exceeding the RTO, confirmed data-integrity loss, declared disaster).',
    ));
  }
  parts.push(heading('3.3 Notification Sequence (Contingency Team)', 2));
  const roster = (opts.teamRoster && opts.teamRoster.length > 0) ? opts.teamRoster : defaultRoster();
  parts.push(table(
    ['Order', 'Role', 'Name', 'Alternate'],
    roster.map((m, i) => [String(i + 1), m.role, m.name || TBD, m.alternate || '—']),
    [1000, 3000, 3000, 2000],
  ));
  if (opts.cpCoordinator) {
    parts.push(para(
      `Contingency Plan Coordinator: ${opts.cpCoordinator.name} (${opts.cpCoordinator.org}) — ` +
      `${opts.cpCoordinator.email}, ${opts.cpCoordinator.phone}.`,
    ));
  } else {
    parts.push(para(`${TBD}: name the Contingency Plan Coordinator (primary point of contact for activation).`));
  }

  // ── §4 Recovery Phase ──
  parts.push(heading('4. Recovery Phase', 1));

  parts.push(heading('4.1 Recovery Objectives (RTO / RPO)', 2));
  parts.push(fieldTable([
    ['Recovery Time Objective (RTO)',
      opts.rto ? `${opts.rto.hours} hours — ${opts.rto.rationale}` : TBD],
    ['Recovery Point Objective (RPO)',
      opts.rpo ? `${opts.rpo.hours} hours — ${opts.rpo.rationale}` : TBD],
    ['Recovery Priority',
      opts.recoveryPriority ? opts.recoveryPriority : TBD],
  ]));

  parts.push(heading('4.2 Recovery Evidence (RPL family — CP-9 / CP-10)', 2));
  parts.push(para(
    opts.backupStrategySummary || deriveBackupStrategySummary(rpl),
  ));
  if (rplEvidenceCount > 0) {
    parts.push(table(
      ['KSI ID', 'Capability', 'Controls', 'Passed', 'Last Collected', 'Evidence Citation'],
      RPL_KSIS.map((k) => {
        const ev = rpl[k.key];
        if (!ev) {
          return [k.id, k.purpose, k.controls, TBD, TBD, `${TBD} (KSI-RPL evidence not collected this run)`];
        }
        return [
          k.id,
          ev.ksi_name || k.name,
          k.controls,
          ev.passed ? 'PASS' : 'FAIL',
          ev.last_collected_at || TBD,
          `${k.id}.json (sha256 ${ev.sha256})`,
        ];
      }),
      [1800, 2000, 1400, 900, 2000, 3200],
    ));
    parts.push(para(
      'The operator must confirm the most-recent Testing Recovery Capabilities (KSI-RPL-TRC) ' +
      'evidence falls within the annual CP-4 testing window; the After-Action Report ' +
      '(iscp-test-aar.docx, Appendix F) records that test.',
    ));
  } else {
    parts.push(table(
      ['KSI ID', 'Capability', 'Controls', 'Passed', 'Last Collected', 'Evidence Citation'],
      [[TBD, 'No RPL-family evidence found. Run the collector, then re-emit the ISCP.', 'CP-9 / CP-10', TBD, TBD, '—']],
      [1800, 2000, 1400, 900, 2000, 3200],
    ));
  }

  parts.push(heading('4.3 Recovery Sequence', 2));
  parts.push(para(
    'Recovery proceeds: (1) assess damage + confirm activation criteria (§3.2); (2) notify the ' +
    'contingency team (§3.3); (3) restore from the most-recent validated backup (CP-9); ' +
    '(4) bring recovery-priority resources online first per §4.1; (5) validate restored ' +
    'services against the checks in §5 before returning to production. Detailed, resource-level ' +
    'recovery steps are maintained in Appendix C.',
  ));

  // ── §5 Reconstitution Phase ──
  parts.push(heading('5. Reconstitution Phase', 1));
  parts.push(para(
    'Reconstitution returns the system to normal operations without deterioration of the ' +
    'security controls originally implemented (CP-2.e). Validation steps: (a) confirm data ' +
    'integrity against the RPO; (b) confirm the security controls (KSI coverage) are intact ' +
    'post-recovery; (c) confirm monitoring + logging resumed; (d) obtain System Owner sign-off ' +
    'to return to production; (e) conduct a post-incident review and file any lessons learned ' +
    'as POA&M items. The System Validation Test Plan (Appendix E) enumerates the specific ' +
    'checks; the most-recent test result is recorded in the After-Action Report (Appendix F).',
  ));

  // ── §6 Plan Maintenance ──
  parts.push(heading('6. Plan Maintenance', 1));
  parts.push(para(
    'This plan is reviewed and updated at least annually and whenever a significant change to ' +
    'the system, its recovery objectives, or its environment occurs (NIST SP 800-34 Rev. 1 ' +
    '§3.7 "Ensure plan maintenance"). The contingency plan is tested at least annually per ' +
    'CP-4; the test result is captured in the After-Action Report (Appendix F / iscp-test-aar.docx). ' +
    'The RPL-family evidence in §4.2 is re-collected each run, so re-emitting this plan after a ' +
    'collection refreshes the recovery-evidence snapshot.',
  ));

  // ── Appendix A — Personnel Contact List ──
  parts.push(heading('Appendix A — Personnel Contact List', 1));
  parts.push(para(
    'Contingency-team personnel and their contact information (CP-2.c). Blank cells are ' +
    `marked ${TBD} for the operator to complete; personnel contact details are handled per ` +
    'the CSP data-handling policy and are not logged by the toolkit.',
  ));
  parts.push(table(
    ['Role', 'Name', 'Organization', 'Email', 'Phone'],
    roster.map((m) => [m.role, m.name || TBD, m.org || TBD, m.email || TBD, m.phone || TBD]),
    [2400, 2000, 1800, 2000, 1600],
  ));

  // ── Appendix B — Vendor / Subprocessor Contacts ──
  parts.push(heading('Appendix B — Vendor / Subprocessor Contacts', 1));
  parts.push(para(
    'Vendor and subprocessor contacts relevant to recovery (SA-9). Rows are auto-pulled from ' +
    'the real subprocessor inventory (subprocessor-inventory.json, LOOP-J.J2) when present. ' +
    `The SA-9 inventory carries vendor + role + SLA but not a named contact or phone, so those ` +
    `cells are ${TBD} for the operator to complete.`,
  ));
  if (vendorContacts.length > 0) {
    parts.push(table(
      ['Vendor', 'Contact', 'Role', 'Phone', 'Notification SLA'],
      vendorContacts.map((v) => [v.vendor, v.contact || TBD, v.role || TBD, v.phone || TBD, v.sla || TBD]),
      [2400, 2000, 1800, 1600, 2000],
    ));
  } else {
    parts.push(table(
      ['Vendor', 'Contact', 'Role', 'Phone', 'Notification SLA'],
      [[TBD, TBD, TBD, TBD, 'No subprocessor-inventory.json found (run LOOP-J.J2), or supply vendorContacts.']],
      [2400, 2000, 1800, 1600, 2000],
    ));
  }

  // ── Appendix C — Detailed Recovery Procedures ──
  parts.push(heading('Appendix C — Detailed Recovery Procedures', 1));
  parts.push(para(
    `${TBD}: document the resource-level recovery runbooks (per component group in §2.1). ` +
    'This appendix is the framework; the CSP maintains the executable, step-by-step recovery ' +
    'procedures — often per-cloud runbooks — and references them here.',
  ));

  // ── Appendix D — Alternate Site Procedures ──
  parts.push(heading('Appendix D — Alternate Site Procedures', 1));
  if (opts.alternateSite) {
    const site = opts.alternateSite;
    parts.push(fieldTable([
      ['Alternate Site Type', site.type],
      ['Location', site.location],
      ['Activation Procedure', site.activationProcedure],
    ]));
    if (site.type === 'cloud') {
      parts.push(para(
        'Cloud alternate processing: recovery uses a cross-region (or cross-provider) ' +
        `deployment at ${site.location}. Confirm the alternate region holds current backups ` +
        '(CP-9) and that failover meets the RTO in §4.1 (CP-7 Alternate Processing Site).',
      ));
    }
  } else {
    parts.push(para(
      `${TBD}: describe the alternate processing capability (CP-7). Supply the site type ` +
      '(hot / warm / cold / cloud), its location, and the activation procedure.',
    ));
  }

  // ── Appendix E — System Validation Test Plan ──
  parts.push(heading('Appendix E — System Validation Test Plan', 1));
  parts.push(para(
    'The validation tests run during reconstitution (§5) to confirm the recovered system is ' +
    'fully functional and its security controls intact. The executed results of the annual ' +
    'CP-4 test are recorded in the Contingency Plan Test Report (Appendix F).',
  ));

  // ── Appendix F — Contingency Plan Test Report ──
  parts.push(heading('Appendix F — Contingency Plan Test Report', 1));
  parts.push(para(
    'The most-recent annual contingency-plan test (CP-4) and its After-Action Report are ' +
    'produced as a companion document: iscp-test-aar.docx (emit with --iscp-test-aar). That ' +
    'report records the test date, type (tabletop / functional / full-interruption), scenarios ' +
    'executed with RTO/RPO target-vs-actual, lessons learned, and sign-off.',
  ));

  // ── Provenance footer ──
  const evidenceLines = RPL_KSIS
    .filter((k) => rpl[k.key])
    .map((k) => `${k.id}.json sha256=${rpl[k.key]!.sha256}`);
  const invDigest = (() => {
    const p = resolve(opts.outDir, 'inventory.json');
    if (!existsSync(p)) return null;
    try { return createHash('sha256').update(readFileSync(p)).digest('hex'); }
    catch { return null; }
  })();
  parts.push(heading('Provenance', 1));
  parts.push(fieldTable([
    ['Generated By', 'fedramp-20x-cloud-evidence (core/iscp-emit.ts)'],
    ['Document UUID', docUuid],
    ['Run ID', opts.runId],
    ['FRMR Catalog Version', opts.frmrVersion],
    ['Inventory Source', invDigest ? `out/inventory.json (sha256 ${invDigest})` : '(none — see §2.1)'],
    ['RPL Evidence Sources', evidenceLines.length > 0 ? evidenceLines.join('\n') : '(none — see §4.2)'],
    ['Satisfies Controls', 'NIST SP 800-53 Rev. 5 CP-2, CP-9, CP-10 (CP-4 via the companion After-Action Report)'],
    ['Template Source', 'FedRAMP SSP Appendix G ISCP Template + NIST SP 800-34 Rev. 1'],
  ]));

  // ── Page geometry (US Letter) ──
  const sectPr = '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/>' +
    '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr>';

  const xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<w:document xmlns:w="${W_NS}"><w:body>${parts.join('')}${sectPr}</w:body></w:document>`;

  return {
    xml,
    stats: {
      rpl_evidence_count: rplEvidenceCount,
      component_count: components.length,
      vendor_contact_count: vendorContacts.length,
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
    style('Heading1', 'heading 1', { size: 32, bold: true, color: '1F3864', spacingBefore: 360 }) +
    style('Heading2', 'heading 2', { size: 26, bold: true, color: '2E74B5', spacingBefore: 240 }) +
    style('Heading3', 'heading 3', { size: 24, bold: true, color: '1F4E79', spacingBefore: 160 }) +
    `</w:styles>`;
}

/** docProps/core.xml — deterministic title metadata (no wall-clock time). */
function coreXml(systemName: string, docUuid: string): string {
  const title = `Information System Contingency Plan — ${systemName} [${docUuid}]`;
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

/** Pure: render an Information System Contingency Plan Word document to a Buffer. */
export function renderIscpDocx(opts: IscpEmitOptions): {
  buffer: Buffer;
  stats: Omit<IscpEmitResult, 'path' | 'bytes'>;
} {
  const { xml, stats } = buildIscpBodyXml(opts);
  const systemName = opts.systemName || TBD;
  const systemId = opts.systemId || TBD;
  const docUuid = deterministicUuid(`iscp:${systemId}:${opts.runId}`);
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

/** Read RPL/inventory/ssp/subprocessor evidence, render, and write iscp.docx. */
export function emitIscpDocx(opts: IscpEmitOptions): IscpEmitResult {
  const { buffer, stats } = renderIscpDocx(opts);
  const outPath = opts.outPath ?? resolve(opts.outDir, 'iscp.docx');
  writeFileSync(outPath, buffer);
  log.info({
    event: 'iscp.emitted',
    path: outPath,
    bytes: buffer.length,
    rpl_evidence_count: stats.rpl_evidence_count,
    component_count: stats.component_count,
    vendor_contact_count: stats.vendor_contact_count,
    ready_for_signature: stats.ready_for_signature,
    requires_operator_input_count: stats.requires_operator_input.length,
  });
  return { path: outPath, bytes: buffer.length, ...stats };
}
