/**
 * Incident Response Plan (IRP) emitter — LOOP-C.C3.
 *
 * Renders `irp.docx` — an Incident Response Plan structured per NIST SP 800-61
 * Rev. 3 (April 2025), whose incident life-cycle is organised around the NIST
 * Cybersecurity Framework (CSF) 2.0 Functions (Govern / Identify / Protect /
 * Detect / Respond / Recover). The document satisfies NIST SP 800-53 Rev. 5
 * controls IR-8 (Incident Response Plan), IR-3 (Incident Response Testing —
 * cross-linked to the companion irp-test-aar.docx), IR-4 (Incident Handling),
 * and IR-6 (Incident Reporting). The §4 Detect table is auto-filled from the
 * real signed KSI-INR-RIR evidence (Reviewing Incident Response Procedures,
 * IR-4/IR-4.1) when the collector has run; §9 Reporting Requirements bakes in
 * the FedRAMP Incident Communications Procedures notification SLAs; every
 * operator narrative slot (team roster, communications plan) defaults to a
 * verbatim REQUIRES-OPERATOR-INPUT marker rather than fabricating IR language.
 * Closes a real FedRAMP 20x gap: CSPs currently hand-transcribe the IR-8 plan
 * from a blank page every assessment cycle.
 *
 * Authoritative sources (verbatim):
 *   - NIST SP 800-61 Rev. 3 (April 2025), Incident Response Recommendations and
 *     Considerations for Cybersecurity Risk Management: A CSF 2.0 Community
 *     Profile —
 *     https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf
 *     §2.1 (p. 5): "This publication provides recommendations for managing
 *     incident response throughout the incident lifecycle, structured around
 *     the NIST Cybersecurity Framework (CSF) 2.0 Functions: Govern, Identify,
 *     Protect, Detect, Respond, and Recover." (Rev. 2 was officially withdrawn
 *     April 2025; the optional --irp-spec-version=800-61r2 flag renders the
 *     legacy four-phase model for 3PAOs still on that mental model.)
 *   - NIST SP 800-53 Rev. 5 IR-8 (Incident Response Plan) —
 *     https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final :
 *     "Develop an incident response plan that: 1. Provides the organization with
 *      a roadmap for implementing its incident response capability; ...
 *      5. Defines reportable incidents; 6. Provides metrics for measuring the
 *      incident response capability within the organization; ... 9. Is reviewed
 *      and approved by [Assignment: organization-defined personnel or roles];
 *      10. Explicitly designates responsibility for incident response to
 *      [Assignment: organization-defined entities, personnel, or roles]."
 *   - NIST SP 800-53 Rev. 5 IR-3 (Incident Response Testing), IR-4 (Incident
 *     Handling), IR-6 (Incident Reporting) — same catalog URL — anchor §5
 *     (Respond), §9 (Reporting), and §11 (Testing).
 *   - FedRAMP Incident Communications Procedures (CSP_Incident_Communications_
 *     Procedures.pdf) —
 *     https://www.fedramp.gov/assets/resources/documents/CSP_Incident_Communications_Procedures.pdf
 *     — CSP-side notification SLAs (1 hour to the FedRAMP PMO + 1 hour to each
 *     impacted customer agency + 4 hours to CISA US-CERT for incidents involving
 *     federal data), rendered as the §9 Reporting-Requirements baseline with a
 *     REQUIRES-OPERATOR-INPUT-VERIFY marker (the operator confirms the current
 *     SLAs against the live doc + any agency-specific ISA/MOU).
 *
 * Approach (dependency-free .docx): a `.docx` is a ZIP of WordprocessingML XML
 * parts packed with the store-only ZIP writer the CMP / ISCP / SSP-2 / RoE
 * renderers use (core/zip.ts) — no external Word library, no runtime network.
 * The OOXML building blocks mirror core/iscp-emit.ts (a shared docx-primitives
 * module was proposed in LOOP-C-SPEC §4 but never extracted; see LOOP-C-RISKS
 * C-C3-8 / C-X-1 for the reconciliation — this emitter follows the six shipped
 * docx emitters and keeps its OOXML constants local).
 *
 * REO compliance:
 *   - §4 Detect rows trace ONLY to the real signed KSI-INR-RIR evidence file's
 *     findings; the emitter never invents a detection source. Absent evidence →
 *     a single REQUIRES-OPERATOR-INPUT row explaining the fix.
 *   - §9 SLA rows quote the FedRAMP ICP doc values with the URL cited in this
 *     module header + the document provenance footer; the whole table carries a
 *     REQUIRES-OPERATOR-INPUT-VERIFY marker until the operator supplies an
 *     escalation matrix.
 *   - Every team-roster / communications narrative defaults to a verbatim
 *     REQUIRES-OPERATOR-INPUT marker (REO Rule 4).
 *   - The document is fully deterministic (no wall-clock time): the metadata
 *     UUID is `deterministicUuid('irp:' + systemId + ':' + runId)` and the
 *     INR-RIR provenance is content SHA-256, so identical inputs produce a
 *     byte-identical .docx. Integrity is anchored by the signed submission-
 *     bundle INDEX.json (SHA-256 + Ed25519), the same coverage
 *     iscp.docx / cmp.docx / roe.docx / ssp.docx receive.
 *
 * Pure renderer (`renderIrpDocx` / `buildIrpBodyXml`) + disk emitter
 * (`emitIrpDocx`).
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
/** Accepted IR spec versions (default r3 — current NIST standard). */
const SPEC_VERSIONS = ['800-61r2', '800-61r3'] as const;
export type IrpSpecVersion = (typeof SPEC_VERSIONS)[number];
/**
 * The NIST CSF 2.0 Functions, in life-cycle order (NIST SP 800-61 Rev. 3 §2.1).
 * Published NIST constant — allowed fixed data per REO Rule 3. If NIST renames a
 * CSF Function this single array is the only place to update (LOOP-C-RISKS
 * C-C3-5 mitigation).
 */
export const CSF_2_0_PHASES = ['Govern', 'Identify', 'Protect', 'Detect', 'Respond', 'Recover'] as const;
/** The legacy NIST SP 800-61 Rev. 2 four-phase IR life-cycle (withdrawn 2025). */
const R2_PHASES = ['Preparation', 'Detection & Analysis', 'Containment, Eradication & Recovery', 'Post-Incident Activity'] as const;
/** Coverage below this fill-rate surfaces a §4 warning row (per-slice Risk 4). */
const DETECTION_COVERAGE_WARN_THRESHOLD = 95;

/** Incident severity tiers, high→low. */
const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
type IncidentSeverity = (typeof SEVERITIES)[number];
const SEVERITY_RANK: Record<IncidentSeverity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

/** Thrown when an unknown impact level is supplied (must be low|moderate|high). */
export class IrpImpactLevelError extends Error {
  constructor(value: string) {
    super(
      `irp-emit: unknown impactLevel "${value}"; must be one of ${IMPACT_LEVELS.join(' | ')}.`,
    );
    this.name = 'IrpImpactLevelError';
  }
}

/** Thrown when an unknown spec version is supplied (must be 800-61r2|800-61r3). */
export class IrpSpecVersionError extends Error {
  constructor(value: string) {
    super(
      `irp-emit: unknown specVersion "${value}"; must be one of ${SPEC_VERSIONS.join(' | ')}.`,
    );
    this.name = 'IrpSpecVersionError';
  }
}

// ─── OOXML building blocks (same pattern as iscp-emit.ts / cmp-emit.ts) ────────

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

/** An incident-response-team roster entry (§2). */
export interface IrpTeamMember {
  role: 'IR Lead' | 'IR Analyst' | 'Forensics' | 'Communications' | 'Legal' | 'Executive Liaison';
  name: string;
  org: string;
  email: string;
  phone: string;
  /** Whether the member is on the on-call rotation. */
  on_call: boolean;
}

/** An escalation rule (§8): severity → SLA-minutes → notify list. */
export interface IrpEscalationRule {
  severity: IncidentSeverity;
  sla_minutes: number;
  notify: string[];
}

/** An external-contact entry (§7). */
export interface IrpExternalContact {
  entity: 'FedRAMP PMO' | 'CISA' | 'US-CERT' | 'Agency POC' | 'Law Enforcement';
  contact: string;
  channel: 'email' | 'phone' | 'web-form';
  sla_hours: number;
}

/** The §6 communications plan. */
export interface IrpCommunicationsPlan {
  internal: string;
  external: string;
  media: string;
}

/** A §3 incident-classification level. */
export interface IrpClassificationLevel {
  severity: string;
  definition: string;
  examples: string[];
}

export interface IrpEmitOptions {
  /** Where the orchestrator writes. The emitter reads KSI-INR-RIR from here. */
  outDir: string;
  /** Output path (defaults to <outDir>/irp.docx). */
  outPath?: string;
  /** Run id — captured in the IRP provenance (§1) + deterministic UUID seed. */
  runId: string;
  /** FRMR catalog version — captured in the IRP provenance (§1). */
  frmrVersion: string;
  /** Impact level (low/moderate/high). */
  impactLevel: ImpactLevel;
  /** System identity (reuses --system-name / --system-id / --csp-name). */
  systemName?: string;
  systemId?: string;
  cspOrganization?: string;
  /** IR life-cycle structure. Defaults to 800-61r3 (current NIST standard). */
  specVersion?: IrpSpecVersion;
  /** §2 IR-team roster. */
  irTeamRoster?: IrpTeamMember[];
  /** §8 escalation matrix (defaults to the FedRAMP ICP baseline, verify-marked). */
  escalationMatrix?: IrpEscalationRule[];
  /** §7 external contacts (defaults to the published role-based addresses). */
  externalContacts?: IrpExternalContact[];
  /** §6 communications plan (internal + external + media). */
  communicationsPlan?: IrpCommunicationsPlan;
  /** §3 incident-classification levels (defaults to the FedRAMP-baseline rows). */
  classificationLevels?: IrpClassificationLevel[];
}

export interface IrpEmitResult {
  path: string;
  bytes: number;
  /** Count of §4 detection-source rows traced to real INR-RIR evidence. */
  detection_source_count: number;
  /** §4 detection coverage percent (null when no INR-RIR evidence was found). */
  detection_coverage_percent: number | null;
  /** Count of IR-team-roster members rendered in §2 (operator-supplied). */
  team_member_count: number;
  /** True when every required-for-signature operator field was supplied. */
  ready_for_signature: boolean;
  /** Missing-input list for operator action. */
  requires_operator_input: string[];
}

// ─── INR-RIR evidence reader (§4 Detect) ─────────────────────────────────────

/** A single detection source derived from an INR-RIR collector finding. */
export interface InrRirDetectionSource {
  /** The collector's stable rule name (e.g. `aws.cloudtrail.org_trail_active`). */
  source: string;
  /** Whether the detection capability is evidenced as active (finding.passed). */
  active: boolean;
  /** Severity tag from the finding (informational). */
  severity?: string;
  /** One-line human summary from the finding's current_state. */
  summary: string;
}

/**
 * The narrow slice of a signed KSI-INR-RIR evidence envelope the IRP consumes.
 * Defined narrowly (only the fields the emitter reads) so INR-collector schema
 * drift never breaks the emitter (LOOP-C-RISKS C-C3-6). The full envelope shape
 * is core/envelope.ts:EvidenceFile. The per-slice §5 assumed a flat
 * `evidence[].detection_source` / `coverage_percent`; the real collector output
 * carries detection capabilities as `providers[].findings[]` (rule + passed +
 * current_state.summary) with the timestamp at the top level (`collected_at`),
 * so this reader flattens the findings into detection-source rows and derives
 * the coverage percent from the pass ratio (LOOP-C-RISKS C-C3-7).
 */
export interface InrRirEvidence {
  ksi_id: string;
  ksi_name?: string;
  /** Top-level ISO timestamp the evidence was collected (envelope.collected_at). */
  collected_at: string;
  /** SHA-256 of the raw evidence-file bytes (chain-of-custody provenance). */
  sha256: string;
  /** One row per collector finding across every provider block. */
  detection_sources: InrRirDetectionSource[];
  /** Round(active / total × 100). 0 when there are no findings. */
  coverage_percent: number;
}

/**
 * JSON-parse-safe read of the signed KSI-INR-RIR evidence file. Prefers the real
 * collector output name `KSI-INR-RIR.json`; falls back to the `.signed.json`
 * variant the C.C3 spec §7 named (the collector filters `.signed.json` out as a
 * duplicate, so `.json` is authoritative — LOOP-C-RISKS C-C3-7). Never throws.
 */
export function readInrRirEvidence(outDir: string): InrRirEvidence | undefined {
  for (const name of ['KSI-INR-RIR.json', 'KSI-INR-RIR.signed.json']) {
    const p = resolve(outDir, name);
    if (!existsSync(p)) continue;
    let bytes: Buffer;
    try { bytes = readFileSync(p); } catch { continue; }
    let doc: any;
    try { doc = JSON.parse(bytes.toString('utf8')); } catch { continue; }
    if (!doc || typeof doc !== 'object') continue;
    const sources: InrRirDetectionSource[] = [];
    const providers = Array.isArray(doc.providers) ? doc.providers : [];
    for (const pr of providers) {
      const findings = Array.isArray(pr?.findings) ? pr.findings : [];
      for (const f of findings) {
        if (!f || typeof f !== 'object' || !f.rule) continue;
        sources.push({
          source: String(f.rule),
          active: f.passed === true,
          severity: f.severity ? String(f.severity) : undefined,
          summary: String(f.current_state?.summary ?? ''),
        });
      }
    }
    const total = sources.length;
    const active = sources.filter((s) => s.active).length;
    return {
      ksi_id: String(doc.ksi_id ?? 'KSI-INR-RIR'),
      ksi_name: doc.ksi_name ? String(doc.ksi_name) : undefined,
      collected_at: String(doc.collected_at ?? doc.collectedAt ?? ''),
      sha256: createHash('sha256').update(bytes).digest('hex'),
      detection_sources: sources,
      coverage_percent: total > 0 ? Math.round((active / total) * 100) : 0,
    };
  }
  return undefined;
}

// ─── Defaults (all operator-completable / verify-marked) ─────────────────────

/** Structurally-complete §2 roster (all cells REQUIRES-OPERATOR-INPUT). Roles
 * are the six IR-team roles the per-slice §6 enumerates. */
function defaultRoster(): IrpTeamMember[] {
  return (['IR Lead', 'IR Analyst', 'Forensics', 'Communications', 'Legal', 'Executive Liaison'] as const).map(
    (role) => ({ role, name: TBD, org: TBD, email: TBD, phone: TBD, on_call: false }),
  );
}

/** FedRAMP-ICP-baseline escalation matrix (verify-marked — operator confirms). */
function defaultEscalationMatrix(): IrpEscalationRule[] {
  return [
    { severity: 'critical', sla_minutes: 60, notify: ['IR Lead', 'Executive Liaison', 'FedRAMP PMO', 'CISA US-CERT', 'Impacted Agency POC'] },
    { severity: 'high', sla_minutes: 60, notify: ['IR Lead', 'Communications', 'FedRAMP PMO'] },
    { severity: 'medium', sla_minutes: 240, notify: ['IR Lead'] },
    { severity: 'low', sla_minutes: 1440, notify: ['IR Analyst'] },
  ];
}

/** Published role-based external contacts (per-slice Risk 3 — no personal PII). */
function defaultExternalContacts(): IrpExternalContact[] {
  return [
    { entity: 'FedRAMP PMO', contact: 'info@fedramp.gov', channel: 'email', sla_hours: 1 },
    { entity: 'CISA', contact: 'report@cisa.gov (https://www.cisa.gov/report)', channel: 'web-form', sla_hours: 4 },
    { entity: 'Agency POC', contact: TBD, channel: 'email', sla_hours: 1 },
  ];
}

/** FedRAMP-baseline incident classification levels (§3). */
function defaultClassificationLevels(): IrpClassificationLevel[] {
  return [
    { severity: 'Critical', definition: 'Confirmed compromise of federal-data confidentiality, integrity, or availability, or a system-wide outage of the authorized service.', examples: ['Confirmed exfiltration of federal customer data', 'Ransomware encrypting production systems'] },
    { severity: 'High', definition: 'Significant impact to the authorized service or a credible threat to federal data.', examples: ['Privilege escalation to administrator on a production host', 'Credential-stuffing spike against the authenticated surface'] },
    { severity: 'Medium', definition: 'Limited or contained impact with no confirmed federal-data exposure.', examples: ['Single compromised non-privileged account', 'Malware detected and quarantined on one endpoint'] },
    { severity: 'Low', definition: 'Minimal impact; a policy violation or anomaly warranting review.', examples: ['Isolated external port scan', 'Non-sensitive misconfiguration detected and remediated'] },
  ];
}

// ─── Builder (pure) ──────────────────────────────────────────────────────────

export function buildIrpBodyXml(opts: IrpEmitOptions): {
  xml: string;
  stats: Omit<IrpEmitResult, 'path' | 'bytes'>;
} {
  if (!IMPACT_LEVELS.includes(opts.impactLevel)) {
    throw new IrpImpactLevelError(String(opts.impactLevel));
  }
  const specVersion: IrpSpecVersion = opts.specVersion ?? '800-61r3';
  if (!SPEC_VERSIONS.includes(specVersion)) {
    throw new IrpSpecVersionError(String(opts.specVersion));
  }

  const systemName = opts.systemName || TBD;
  const systemId = opts.systemId || TBD;
  const csp = opts.cspOrganization || TBD;

  // Required-for-signature input tracker (IR-8 mandates these narratives). The
  // escalation matrix + external contacts have safe FedRAMP defaults (verify-
  // marked) so they are NOT gating; the operator narratives with no safe default
  // are.
  const missing: string[] = [];
  const track = (label: string, present: boolean) => { if (!present) missing.push(label); };
  track('systemName', !!opts.systemName);
  track('systemId', !!opts.systemId);
  track('cspOrganization', !!opts.cspOrganization);
  track('irTeamRoster', !!(opts.irTeamRoster && opts.irTeamRoster.length > 0));
  track('communicationsPlan', !!opts.communicationsPlan);

  const roster = (opts.irTeamRoster && opts.irTeamRoster.length > 0) ? opts.irTeamRoster : defaultRoster();
  const escalationSupplied = !!(opts.escalationMatrix && opts.escalationMatrix.length > 0);
  const escalation = (escalationSupplied ? opts.escalationMatrix! : defaultEscalationMatrix())
    .slice()
    .sort((a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0));
  const externalContacts = (opts.externalContacts && opts.externalContacts.length > 0)
    ? opts.externalContacts : defaultExternalContacts();
  const classifications = (opts.classificationLevels && opts.classificationLevels.length > 0)
    ? opts.classificationLevels : defaultClassificationLevels();

  const inr = readInrRirEvidence(opts.outDir);
  const docUuid = deterministicUuid(`irp:${systemId}:${opts.runId}`);

  const parts: string[] = [];

  // ── Title block ──
  parts.push(para('Incident Response Plan', 'Title'));
  parts.push(para(`${systemName} — FedRAMP ${opts.impactLevel} (IR-8 / IR-3 / IR-4 / IR-6)`, 'Subtitle'));
  parts.push(para(
    'DRAFT — auto-filled by fedramp-20x-cloud-evidence. The §4 Detect table derives from ' +
    'the real signed KSI-INR-RIR evidence; the §9 Reporting-Requirements SLAs are the FedRAMP ' +
    `Incident Communications Procedures baseline. The operator must complete every ${TBD} marker ` +
    `and confirm every ${TBD_VERIFY} value before the plan is reviewed and approved (IR-8.9). ` +
    'The CSP is the author-of-record.',
    'Disclaimer',
  ));

  // ── §1 Introduction & Scope ──
  parts.push(heading('1. Introduction & Scope', 1));
  parts.push(heading('1.1 Purpose', 2));
  parts.push(para(
    `This Incident Response Plan (IRP) documents the incident-response capability for ${systemName}, ` +
    'in satisfaction of NIST SP 800-53 Rev. 5 control IR-8 (Incident Response Plan): "Develop an ' +
    'incident response plan that: 1. Provides the organization with a roadmap for implementing its ' +
    'incident response capability; 2. Describes the structure and organization of the incident ' +
    'response capability; ... 5. Defines reportable incidents; 6. Provides metrics for measuring ' +
    'the incident response capability within the organization; ... 9. Is reviewed and approved by ' +
    '[Assignment: organization-defined personnel or roles]; 10. Explicitly designates responsibility ' +
    'for incident response to [Assignment: organization-defined entities, personnel, or roles]." ' +
    '(NIST SP 800-53 Rev. 5, IR-8)',
  ));
  parts.push(heading('1.2 Scope', 2));
  parts.push(para(
    `This plan applies to ${systemName} (System ID: ${systemId}) operated by ${csp}, categorized at ` +
    `the FedRAMP ${opts.impactLevel.toUpperCase()} impact level. It covers the full incident ` +
    'life-cycle — detection through post-incident review — for the authorized service and the ' +
    'federal data it processes.',
  ));
  parts.push(heading('1.3 Methodology', 2));
  if (specVersion === '800-61r3') {
    parts.push(para(
      'This plan follows NIST SP 800-61 Rev. 3 (April 2025), which structures the incident life-cycle ' +
      'around the NIST Cybersecurity Framework (CSF) 2.0 Functions: "This publication provides ' +
      'recommendations for managing incident response throughout the incident lifecycle, structured ' +
      'around the NIST Cybersecurity Framework (CSF) 2.0 Functions: Govern, Identify, Protect, Detect, ' +
      'Respond, and Recover." (NIST SP 800-61 Rev. 3, §2.1) NIST officially withdrew SP 800-61 Rev. 2 ' +
      'in April 2025; this plan uses the current Rev. 3 structure.',
    ));
  } else {
    parts.push(para(
      'This plan is rendered against the legacy NIST SP 800-61 Rev. 2 four-phase incident-handling ' +
      'model (Preparation; Detection & Analysis; Containment, Eradication & Recovery; Post-Incident ' +
      'Activity) for reviewers still on that mental model. NOTE: NIST officially withdrew Rev. 2 in ' +
      'April 2025; the current standard is Rev. 3 (CSF 2.0 phases) — re-emit with the default ' +
      'specVersion to adopt it.',
    ));
  }

  // ── §2 Roles & Responsibilities ──
  parts.push(heading('2. Roles & Responsibilities', 1));
  parts.push(para(
    'The incident-response team and its responsibilities (IR-8.10 designates responsibility for ' +
    `incident response). Blank cells are marked ${TBD} for the operator to complete; personnel ` +
    'contact details are handled per the CSP data-handling policy and are not logged by the toolkit.',
  ));
  parts.push(table(
    ['Role', 'Name', 'Organization', 'Email', 'Phone', 'On-Call'],
    roster.map((m) => [m.role, m.name || TBD, m.org || TBD, m.email || TBD, m.phone || TBD, m.on_call ? 'Yes' : 'No']),
    [2000, 1800, 1800, 1900, 1400, 900],
  ));

  // ── §3 Incident Classification ──
  parts.push(heading('3. Incident Classification', 1));
  parts.push(para(
    'Severity definitions used to triage and prioritize incidents. These rows are the FedRAMP ' +
    `baseline${(opts.classificationLevels && opts.classificationLevels.length > 0) ? ' (operator-supplied)' : ` (${TBD_VERIFY} — confirm or override via config.yaml: irp.classification_levels)`}.`,
  ));
  parts.push(table(
    ['Severity', 'Definition', 'Examples'],
    classifications.map((c) => [c.severity, c.definition, c.examples.join('; ')]),
    [1400, 4200, 3400],
  ));

  // ── §4 Detect ──
  parts.push(heading('4. Detect', 1));
  parts.push(para(
    'Detection sources monitored for the authorized service. Rows are auto-derived from the real ' +
    'signed KSI-INR-RIR evidence (Reviewing Incident Response Procedures, IR-4/IR-4.1) — each ' +
    'collector finding is one detection capability. No synthetic detection sources appear.',
  ));
  if (inr && inr.detection_sources.length > 0) {
    parts.push(table(
      ['Detection Source', 'Status', 'Severity', 'Observed State'],
      inr.detection_sources.map((s) => [
        s.source,
        s.active ? 'ACTIVE' : 'GAP',
        s.severity || '—',
        s.summary || '—',
      ]),
      [3000, 1200, 1400, 3400],
    ));
    parts.push(para(
      `Logging / detection coverage this collection: ${inr.coverage_percent}% ` +
      `(${inr.detection_sources.filter((s) => s.active).length} of ${inr.detection_sources.length} ` +
      `capabilities active; KSI-INR-RIR collected ${inr.collected_at || TBD}).`,
    ));
    if (inr.coverage_percent < DETECTION_COVERAGE_WARN_THRESHOLD) {
      parts.push(para(
        `WARNING: detection coverage (${inr.coverage_percent}%) is below the ${DETECTION_COVERAGE_WARN_THRESHOLD}% ` +
        'target. The GAP rows above are open detection gaps — track each to closure via a POA&M item ' +
        '(LOOP-A.A1). The IRP must not paper over the gap (per-slice Risk 4).',
      ));
    }
  } else {
    parts.push(table(
      ['Detection Source', 'Status', 'Severity', 'Observed State'],
      [[TBD, TBD, '—', 'No KSI-INR-RIR evidence found. Run the collector so §4 auto-fills from real detection evidence, then re-emit the IRP.']],
      [3000, 1200, 1400, 3400],
    ));
  }

  // ── §5 Respond ──
  parts.push(heading('5. Respond', 1));
  if (specVersion === '800-61r3') {
    parts.push(para(
      'Incident response proceeds through the NIST CSF 2.0 Functions (NIST SP 800-61 Rev. 3). Each ' +
      'sub-section below maps a CSF Function to the concrete response actions for this system.',
    ));
    const csfProcedures: Record<(typeof CSF_2_0_PHASES)[number], string> = {
      Govern: 'Maintain the IR risk-management strategy, roles, and policy; ensure management support and the metrics in §10 are reviewed (CSF GV).',
      Identify: 'Determine the scope of the incident — the affected assets (system inventory), federal data, users, and subprocessors involved (CSF ID).',
      Protect: 'Apply safeguards to limit spread — isolate affected hosts, revoke or rotate credentials, block malicious indicators, and preserve forensic evidence (CSF PR).',
      Detect: 'Correlate the detection sources in §4 to confirm, characterize, and classify the incident against §3 (CSF DE).',
      Respond: 'Contain and eradicate the threat and execute the communications plan (§6) and escalation matrix (§8); notify external parties per §7 / §9 (CSF RS).',
      Recover: 'Restore affected services from validated backups and confirm data integrity + control coverage before returning to production; recovery procedures are maintained in the Information System Contingency Plan (iscp.docx, CP-2/CP-9/CP-10) (CSF RC).',
    };
    for (const phase of CSF_2_0_PHASES) {
      parts.push(heading(`5.${CSF_2_0_PHASES.indexOf(phase) + 1} ${phase}`, 2));
      parts.push(para(csfProcedures[phase]));
    }
  } else {
    parts.push(para(
      'Incident handling proceeds through the NIST SP 800-61 Rev. 2 four-phase model. Each ' +
      'sub-section below describes the concrete actions for this system.',
    ));
    const r2Procedures: Record<(typeof R2_PHASES)[number], string> = {
      'Preparation': 'Maintain the IR capability: rosters (§2), tooling, detection sources (§4), and training + testing (§11).',
      'Detection & Analysis': 'Correlate the detection sources in §4 to confirm, characterize, and classify the incident against §3.',
      'Containment, Eradication & Recovery': 'Contain the threat, eradicate its cause, and recover affected services from validated backups (cross-linked to the ISCP); execute the communications plan (§6) + escalation matrix (§8).',
      'Post-Incident Activity': 'Conduct the post-incident review (§10) and generate an After-Action Report (irp-test-aar.docx / real-incident AAR); file lessons learned as POA&M items.',
    };
    for (const phase of R2_PHASES) {
      parts.push(heading(`5.${R2_PHASES.indexOf(phase) + 1} ${phase}`, 2));
      parts.push(para(r2Procedures[phase]));
    }
  }

  // ── §6 Communications Plan ──
  parts.push(heading('6. Communications Plan', 1));
  if (opts.communicationsPlan) {
    parts.push(fieldTable([
      ['Internal Communications', opts.communicationsPlan.internal || TBD],
      ['External Communications', opts.communicationsPlan.external || TBD],
      ['Media / Public', opts.communicationsPlan.media || TBD],
    ]));
  } else {
    parts.push(para(
      `${TBD}: document the communications plan — internal notification (who tells whom, via what ` +
      'channel), external notification (customers, FedRAMP PMO, CISA — see §7/§9), and media/public ' +
      'statements. Supply via config.yaml: irp.communications.',
    ));
  }

  // ── §7 External Contacts ──
  parts.push(heading('7. External Contacts', 1));
  parts.push(para(
    'External parties contacted during an incident (IR-6 Incident Reporting). Default rows use ' +
    'FedRAMP + CISA published role-based addresses; agency-specific points of contact are ' +
    `${TBD} for the operator to complete (each agency customer has its own POC per the ISA/MOU).`,
  ));
  parts.push(table(
    ['Entity', 'Contact', 'Channel', 'Notification SLA'],
    externalContacts.map((c) => [c.entity, c.contact || TBD, c.channel, `${c.sla_hours} hour(s)`]),
    [2200, 3600, 1600, 1600],
  ));

  // ── §8 Escalation Matrix ──
  parts.push(heading('8. Escalation Matrix', 1));
  parts.push(para(
    'Severity-driven escalation, sorted highest-severity first. ' +
    (escalationSupplied
      ? 'These rows are operator-supplied.'
      : `These rows are the FedRAMP-ICP baseline (${TBD_VERIFY} — confirm or override via config.yaml: irp.escalation).`),
  ));
  parts.push(table(
    ['Severity', 'SLA (minutes)', 'Notify'],
    escalation.map((r) => [r.severity.toUpperCase(), String(r.sla_minutes), r.notify.join(', ')]),
    [1600, 1800, 5600],
  ));

  // ── §9 Reporting Requirements ──
  parts.push(heading('9. Reporting Requirements', 1));
  parts.push(para(
    'The FedRAMP Incident Communications Procedures mandate the CSP-side notification timelines ' +
    `below for incidents involving federal information (IR-6). These are the FedRAMP baseline ` +
    `(${TBD_VERIFY} — confirm against the current CSP_Incident_Communications_Procedures.pdf and ` +
    'any agency-specific ISA/MOU; the 4-hour CISA US-CERT SLA applies to incidents involving ' +
    'federal data).',
  ));
  parts.push(table(
    ['Recipient', 'Timeline', 'Trigger'],
    [
      ['FedRAMP PMO', '1 hour', 'Any incident affecting the confidentiality, integrity, or availability of the authorized service.'],
      ['Impacted customer agency', '1 hour', 'Any incident affecting that agency\'s data or use of the service.'],
      ['CISA US-CERT', '4 hours', 'Any incident involving federal data (per the FedRAMP Incident Communications Procedures + US-CERT federal reporting).'],
    ],
    [2600, 1600, 4800],
  ));

  // ── §10 Lessons Learned ──
  parts.push(heading('10. Lessons Learned', 1));
  parts.push(para(
    'After every incident the IR Lead conducts a post-incident review to capture what worked, what ' +
    'did not, and the corrective actions required. High/critical findings are filed as POA&M items ' +
    '(LOOP-A.A1) and tracked to closure with a remediation deadline (LOOP-B). The review output is ' +
    'recorded in an After-Action Report using the same structure as the annual test report ' +
    '(irp-test-aar.docx). This satisfies IR-4.1 (automated incident-handling support) + the IR-8 ' +
    'metrics obligation.',
  ));

  // ── §11 Plan Maintenance + Testing ──
  parts.push(heading('11. Plan Maintenance & Testing', 1));
  parts.push(para(
    'This plan is reviewed and updated at least annually and whenever a significant change to the ' +
    'system or its environment occurs. The incident-response capability is tested at least annually ' +
    '(NIST SP 800-53 Rev. 5 IR-3): the test result is captured in the Incident Response Test ' +
    'After-Action Report (irp-test-aar.docx, emit with --irp-test-aar), which records the test date, ' +
    'type (tabletop / functional / red-team), the 5-phase timing metrics (detection → recovery), ' +
    'lessons learned, and sign-off. The §4 detection evidence is re-collected each run, so ' +
    're-emitting this plan after a collection refreshes the detection snapshot.',
  ));

  // ── Provenance footer ──
  parts.push(heading('Provenance', 1));
  parts.push(fieldTable([
    ['Generated By', 'fedramp-20x-cloud-evidence (core/irp-emit.ts)'],
    ['Document UUID', docUuid],
    ['Run ID', opts.runId],
    ['FRMR Catalog Version', opts.frmrVersion],
    ['IR Spec Version', specVersion === '800-61r3' ? 'NIST SP 800-61 Rev. 3 (CSF 2.0 phases)' : 'NIST SP 800-61 Rev. 2 (four-phase, withdrawn April 2025)'],
    ['Detection Evidence Source', inr ? `KSI-INR-RIR.json (sha256 ${inr.sha256})` : '(none — see §4)'],
    ['Satisfies Controls', 'NIST SP 800-53 Rev. 5 IR-8, IR-3, IR-4, IR-6'],
    ['Reporting SLA Source', 'FedRAMP Incident Communications Procedures — https://www.fedramp.gov/assets/resources/documents/CSP_Incident_Communications_Procedures.pdf'],
    ['Template Source', 'NIST SP 800-61 Rev. 3 (CSF 2.0) + NIST SP 800-53 Rev. 5 IR family'],
  ]));

  // ── Page geometry (US Letter) ──
  const sectPr = '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/>' +
    '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr>';

  const xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<w:document xmlns:w="${W_NS}"><w:body>${parts.join('')}${sectPr}</w:body></w:document>`;

  return {
    xml,
    stats: {
      detection_source_count: inr ? inr.detection_sources.length : 0,
      detection_coverage_percent: inr ? inr.coverage_percent : null,
      team_member_count: (opts.irTeamRoster && opts.irTeamRoster.length > 0) ? opts.irTeamRoster.length : 0,
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
  const title = `Incident Response Plan — ${systemName} [${docUuid}]`;
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

/** Pure: render an Incident Response Plan Word document to a Buffer. */
export function renderIrpDocx(opts: IrpEmitOptions): {
  buffer: Buffer;
  stats: Omit<IrpEmitResult, 'path' | 'bytes'>;
} {
  const { xml, stats } = buildIrpBodyXml(opts);
  const systemName = opts.systemName || TBD;
  const systemId = opts.systemId || TBD;
  const docUuid = deterministicUuid(`irp:${systemId}:${opts.runId}`);
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

/** Read INR-RIR evidence, render, and write irp.docx. */
export function emitIrpDocx(opts: IrpEmitOptions): IrpEmitResult {
  const { buffer, stats } = renderIrpDocx(opts);
  const outPath = opts.outPath ?? resolve(opts.outDir, 'irp.docx');
  writeFileSync(outPath, buffer);
  log.info({
    event: 'irp.emitted',
    path: outPath,
    bytes: buffer.length,
    detection_source_count: stats.detection_source_count,
    detection_coverage_percent: stats.detection_coverage_percent,
    team_member_count: stats.team_member_count,
    ready_for_signature: stats.ready_for_signature,
    requires_operator_input_count: stats.requires_operator_input.length,
  });
  return { path: outPath, bytes: buffer.length, ...stats };
}
