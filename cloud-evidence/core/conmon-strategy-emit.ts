/**
 * Continuous Monitoring Strategy + Plan emitter — LOOP-C.C6.
 *
 * Renders `conmon-strategy.docx` — the FedRAMP-required continuous-monitoring
 * Strategy + Plan that satisfies NIST SP 800-53 Rev. 5 controls CA-7 (Continuous
 * Monitoring), CA-7(1) (Independent Assessment), and PM-31 (Continuous Monitoring
 * Strategy). The document names WHICH controls are under continuous monitoring
 * (§4, auto-derived from the live core/ksi-map.ts), at WHAT frequency, backed by
 * WHAT vulnerability-scanning evidence (§5, auto-derived from the run's real
 * KSI-*VDR* evidence files), with WHAT escalation SLAs (§11), reported to WHICH
 * FedRAMP endpoint (§9). LOOP-E (the ConMon agent) reads this document as its
 * configuration for the monthly ConMon runs.
 *
 * Authoritative sources (verbatim, cited in the body + the provenance footer):
 *   - NIST SP 800-53 Rev. 5 CA-7 / CA-7(1) / PM-31 —
 *     https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final — control text (§1 / §4).
 *   - FedRAMP Continuous Monitoring Strategy Guide v3.2 (2018-04-04) —
 *     https://www.fedramp.gov/assets/resources/documents/CSP_Continuous_Monitoring_Strategy_Guide.pdf
 *     §3.1 (p. 11) quoted VERBATIM in §3.
 *   - FedRAMP Continuous Monitoring Playbook v1.0 (2025-11-17) —
 *     https://www.fedramp.gov/resources/documents/Continuous_Monitoring_Playbook.pdf
 *     — the current-cadence source cited in §3 (monthly scan / POA&M / inventory
 *     + annual assessment). The Playbook's exact prose is not reproduced here
 *     (clean-room); the monthly cadence stated in §3 is the long-standing
 *     published FedRAMP baseline and carries a REQUIRES-OPERATOR-INPUT-VERIFY
 *     marker directing the operator to confirm it against the live Playbook.
 *   - RFC-0026 (Clarifying CA-7 Continuous Monitoring Expectations for Rev5
 *     Providers) — https://www.fedramp.gov/rfcs/0026/ — §8 Deviation Requests +
 *     §12 Collaborative ConMon.
 *   - NIST SP 800-137 (2011-09) — ISCM — https://csrc.nist.gov/pubs/sp/800/137/final
 *     §2.1 definition (§1) + §3 three-tier hierarchy (§2).
 *   - NIST SP 800-137A (2020-05) — Assessing ISCM Programs —
 *     https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-137A.pdf
 *     — assessment-method classifications (§6 basis).
 *   - CISA BOD 22-01 (KEV catalog) —
 *     https://www.cisa.gov/news-events/directives/binding-operational-directive-22-01
 *     — the §11 KEV escalation baseline.
 *   - R2 finding (docs/PRE-LOOP-A-RESEARCH-FINDINGS.md) — monthly full-document
 *     POA&M re-upload to USDA Connect.gov for Low/Moderate — drives §9.
 *
 * Approach (dependency-free .docx): a `.docx` is a ZIP of WordprocessingML XML
 * parts. We build the parts as strings and pack them with the store-only ZIP
 * writer the SSP-2 + RoE + CMP + FIPS 199 renderers use (core/zip.ts) — no
 * external Word library, no runtime network. The OOXML building blocks mirror
 * cmp-emit.ts / fips199-emit.ts; the shared docx-primitives module proposed in
 * LOOP-C-SPEC §4 was never extracted (LOOP-C-RISKS C-X-1 / C-C1-6..C-C6-8), so
 * this emitter keeps its OOXML constants local like the eleven shipped docx
 * emitters.
 *
 * REO compliance:
 *   - §4 Controls Under Continuous Monitoring traces to the LIVE core/ksi-map.ts
 *     source (grep, same pattern as roe-emit.ts:readKsiScope). The Automated
 *     column is derived from each KSI's real `scope` (CLOUD → automated cloud
 *     evidence; HYBRID → automated signal + process artifact; PROCESS → process
 *     artifact). `buildConmonStrategyBodyXml` throws ConmonKsiScopeError if fewer
 *     than 20 KSIs resolve (the live map carries ~44) — no silent under-report.
 *   - §5 Vulnerability Scanning traces to the run's REAL KSI-*VDR* evidence
 *     files on disk — one row per provider block (= one scanner). Scanner names
 *     are read from the collector's own detection finding; no synthetic scanner
 *     names. A scanner with detection disabled is emitted (never omitted) so the
 *     gap is visible. When no VDR evidence exists, §5 renders a single
 *     REQUIRES-OPERATOR-INPUT row (never a fabricated scanner).
 *   - §3 quotes the FedRAMP ConMon Strategy Guide v3.2 §3.1 VERBATIM and cites
 *     the ConMon Playbook v1.0 URL + retrieval date; the monthly cadence carries
 *     a REQUIRES-OPERATOR-INPUT-VERIFY marker.
 *   - §8 deviation-request process defaults to an RFC-0026-citation-only
 *     REQUIRES-OPERATOR-INPUT-VERIFY marker; no invented workflow.
 *   - §10 team roster + §11 escalation SLAs are operator-supplied; the escalation
 *     defaults are the published FedRAMP Rev5 / CISA BOD 22-01 baselines with a
 *     REQUIRES-OPERATOR-INPUT-VERIFY marker.
 *   - The document is fully deterministic (no wall-clock time): the metadata UUID
 *     is `deterministicUuid('conmon-strategy:' + systemId + ':' + runId)` and the
 *     provenance cites the VDR-evidence + SSP content SHA-256s, so identical
 *     inputs produce a byte-identical .docx. Integrity is anchored by the signed
 *     submission-bundle INDEX.json (SHA-256 + Ed25519), the same coverage
 *     cmp.docx / fips199.docx receive.
 *
 * Pure renderer (`renderConmonStrategyDocx` / `buildConmonStrategyBodyXml`) +
 * disk emitter (`emitConmonStrategyDocx`). The readers (`readKsiCatalog`,
 * `readVdrScanners`) are exported for unit testing.
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { xmlEscape, zipStore } from './zip.ts';
import { deterministicUuid } from './oscal.ts';
import { log } from './log.ts';

const W_NS = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main';
/** Verbatim marker for missing operator input (REO Rule 4). */
const TBD = 'REQUIRES-OPERATOR-INPUT';
/** Verbatim marker for an inferred-not-confirmed baseline (REO Rule 4). */
const TBD_VERIFY = 'REQUIRES-OPERATOR-INPUT-VERIFY';

// ─── Pinned authoritative-source constants (published — REO Rule 3) ──────────

const CONMON_PLAYBOOK_VERSION = 'v1.0 (2025-11-17)';
const CONMON_PLAYBOOK_URL = 'https://www.fedramp.gov/resources/documents/Continuous_Monitoring_Playbook.pdf';
const CONMON_STRATEGY_GUIDE_VERSION = 'v3.2 (2018-04-04)';
const CONMON_STRATEGY_GUIDE_URL = 'https://www.fedramp.gov/assets/resources/documents/CSP_Continuous_Monitoring_Strategy_Guide.pdf';
const RFC_0026_URL = 'https://www.fedramp.gov/rfcs/0026/';
const SP_800_137_URL = 'https://csrc.nist.gov/pubs/sp/800/137/final';
const BOD_22_01_URL = 'https://www.cisa.gov/news-events/directives/binding-operational-directive-22-01';

/** FedRAMP ConMon Strategy Guide v3.2 §3.1 (p. 11) — verbatim. */
const STRATEGY_GUIDE_QUOTE =
  'The CSP is required to perform continuous monitoring of all security controls in the ' +
  'SSP at the frequency identified by the FedRAMP requirements and as stated in the [CSP] ' +
  'System Security Plan.';

/** NIST SP 800-137 §2.1 — verbatim. */
const SP_800_137_DEFINITION =
  'Information security continuous monitoring (ISCM) is defined as maintaining ongoing ' +
  'awareness of information security, vulnerabilities, and threats to support ' +
  'organizational risk management decisions.';

// ─── Types ───────────────────────────────────────────────────────────────────

/** A ConMon program role captured in §10. */
export interface ConmonTeamMember {
  role: 'ConMon Lead' | 'POA&M Coordinator' | 'Scan Operator' | 'Risk Reviewer';
  name: string;
  org: string;
  email: string;
}

/** One escalation-threshold row (§11). `sla` starts with a day count for sorting. */
export interface EscalationThreshold {
  /** Trigger label, e.g. "CISA KEV entry", "Critical vulnerability". */
  trigger: string;
  /** SLA text; the leading integer is the remediation-day count, e.g. "30 days". */
  sla: string;
  /** Who is notified on trigger. */
  notify: string[];
}

/** An agency customer with an ATO (§12 collaborative-ConMon input). */
export interface AgencyCustomer {
  agency: string;
  ato_letter_date: string;
}

/** The FedRAMP reporting endpoint (§9). */
export type ReportingEndpoint = 'usda-connect.gov' | 'agency-direct' | 'other';

export interface ConmonStrategyEmitOptions {
  /** Where the orchestrator writes. The emitter reads KSI-*VDR* + ssp.json from here. */
  outDir: string;
  /** Output path (defaults to <outDir>/conmon-strategy.docx). */
  outPath?: string;
  /** Run id — captured in the provenance (§1) + deterministic UUID seed. */
  runId: string;
  /** FRMR catalog version — captured in the provenance (§1). */
  frmrVersion: string;
  /** System identity (reuses --system-name / --system-id / --csp-name). */
  systemName?: string;
  systemId?: string;
  cspOrganization?: string;
  /** Impact tier — drives the §9 reporting-endpoint default (low/mod → connect.gov; high → agency-direct). */
  impactLevel: 'low' | 'moderate' | 'high';
  /** §10 ConMon team roster (config.yaml: conmon.team[]). */
  conmonTeamRoster?: ConmonTeamMember[];
  /** §11 escalation thresholds (config.yaml: conmon.escalation[]); defaults to the FedRAMP baseline. */
  escalationThresholds?: EscalationThreshold[];
  /** §8 deviation-request process narrative (config.yaml: conmon.deviation_request_process). */
  deviationRequestProcess?: string;
  /** §9 reporting endpoint override (config.yaml: conmon.reporting_endpoint). */
  reportingEndpoint?: ReportingEndpoint;
  /** §12 agency customers (config.yaml: conmon.agency_customers[]). */
  agencyCustomers?: AgencyCustomer[];
  /** §12 collaborative-ConMon flag (config.yaml: conmon.collaborative_conmon). */
  collaborativeConmon?: boolean;
}

export interface ConmonStrategyEmitResult {
  path: string;
  bytes: number;
  /** Count of KSI rows in §4 (from the live ksi-map). */
  ksi_count: number;
  /** Count of scanner rows in §5 (one per VDR provider block found). */
  scanner_count: number;
  /** Count of agency customers feeding §12. */
  agency_customer_count: number;
  /** True when §12 collaborative ConMon is enabled (>1 agency customer + flag). */
  collaborative_conmon: boolean;
  /** The resolved §9 reporting endpoint. */
  reporting_endpoint: ReportingEndpoint;
  /** True when every required-for-signature operator field was supplied. */
  ready_for_signature: boolean;
  /** Missing-input list for operator action. */
  requires_operator_input: string[];
}

/** Thrown when fewer than 20 KSIs resolve from the ksi-map grep (map is broken). */
export class ConmonKsiScopeError extends Error {
  constructor(count: number) {
    super(`conmon-strategy-emit: only ${count} KSI(s) resolved from core/ksi-map.ts (expected >= 20) — the map grep is broken or the map is truncated.`);
    this.name = 'ConmonKsiScopeError';
  }
}

// ─── KSI catalogue reader (grep, same pattern as roe-emit.ts:readKsiScope) ───

/** One §4 KSI row derived from the live ksi-map source. */
export interface KsiCatalogRow {
  ksi: string;
  family: string;
  /** Real scope from the map: CLOUD | HYBRID | PROCESS | INHERITED. */
  scope: string;
}

/**
 * Grep core/ksi-map.ts for every registered KSI + its `scope`. We grep the
 * source (rather than importing KSI_MAP) so the emitter does not pull every
 * provider collector module into the bundle at emit time — the same trick
 * roe-emit.ts + cmp-emit.ts use. Each map key is at the start of a line
 * (`  'KSI-<FAM>-<IND>': {`) followed within the entry by `scope: '<SCOPE>'`.
 */
export function readKsiCatalog(): KsiCatalogRow[] {
  const p = resolve(import.meta.dirname ?? '', 'ksi-map.ts');
  let src: string;
  try { src = readFileSync(p, 'utf8'); }
  catch { return []; }
  const rows = new Map<string, KsiCatalogRow>();
  const re = /^\s*'(KSI-[A-Z]+-[A-Z0-9]+)'\s*:\s*\{[\s\S]*?scope:\s*'([A-Z]+)'/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src)) !== null) {
    const ksi = m[1]!;
    const scope = m[2]!;
    if (!rows.has(ksi)) {
      rows.set(ksi, { ksi, family: ksi.split('-')[1] ?? '', scope });
    }
  }
  return [...rows.values()].sort((a, b) => a.ksi.localeCompare(b.ksi));
}

/** Derived Automated label from a KSI scope. */
function automatedForScope(scope: string): string {
  switch (scope) {
    case 'CLOUD': return 'Yes';
    case 'HYBRID': return 'Partial';
    case 'PROCESS': return 'No';
    case 'INHERITED': return 'Inherited';
    default: return TBD_VERIFY;
  }
}

/** Derived assessment frequency from a KSI scope (FedRAMP CA-7 baseline). */
function frequencyForScope(scope: string): string {
  switch (scope) {
    case 'CLOUD': return 'Continuous (automated collector)';
    case 'HYBRID': return 'Continuous signal + monthly review';
    case 'PROCESS': return 'Per FedRAMP cadence (monthly/annual)';
    case 'INHERITED': return 'Inherited (leveraged authorization)';
    default: return TBD_VERIFY;
  }
}

/** Derived evidence type from a KSI scope. */
function evidenceTypeForScope(scope: string): string {
  switch (scope) {
    case 'CLOUD': return 'Automated cloud SDK evidence';
    case 'HYBRID': return 'Automated signal + process artifact';
    case 'PROCESS': return 'Process artifact (tracker)';
    case 'INHERITED': return 'Leveraged-authorization evidence';
    default: return TBD_VERIFY;
  }
}

// ─── VDR scanner reader (real KSI-*VDR* evidence files) ──────────────────────

/** One §5 scanner row derived from a VDR evidence provider block. */
export interface VdrScannerRow {
  /** Scanner display name read from the collector's detection finding. */
  scanner: string;
  /** Provider (aws/gcp/azure/k8s). */
  provider: string;
  /** True when the detection-capability finding passed. */
  detection_enabled: boolean;
  /** Total findings the VDR summary reported (0 when unavailable). */
  total_findings: number;
  /** KEV entries in scope the VDR summary reported (0 when unavailable). */
  kev_count: number;
  /** Envelope collected_at (ISO) — the last-scan timestamp. */
  last_collected_at: string;
  /** The evidence file the row was read from. */
  source_file: string;
  /** SHA-256 of the evidence file bytes (chain-of-custody provenance). */
  sha256: string;
}

/** Default scanner name for a provider when the finding summary is unreadable. */
function defaultScannerName(provider: string): string {
  switch (provider) {
    case 'aws': return 'Amazon Inspector v2';
    case 'gcp': return 'GCP Container/Artifact Analysis';
    case 'azure': return 'Microsoft Defender for Cloud';
    case 'k8s': return 'Kubernetes vulnerability scanner';
    default: return `${provider} scanner`;
  }
}

/** Extract the scanner name from a detection-capability finding summary. */
function scannerNameFromFinding(provider: string, finding: any): string {
  const summary = String(finding?.current_state?.summary ?? '');
  // The collector writes "<Scanner> is enabled — ..." / "<Scanner> is NOT enabled...".
  const m = summary.match(/^(.*?)\s+is (?:enabled|NOT enabled)/i);
  if (m && m[1] && m[1].trim()) return m[1].trim();
  return defaultScannerName(provider);
}

/**
 * Discover the run's VDR evidence files and return one scanner row per provider
 * block. The VDR collector registers as KSI-AFR-VDR (emitting KSI-AFR-VDR.json;
 * the `.signed.json` variant is filtered as a duplicate — LOOP-C-RISKS C-C6-7),
 * so the reader prefers the plain `.json` over `.signed.json` for the same base.
 * It also matches the per-slice §7 fixture naming (KSI-VDR-*.json) for
 * forward-compatibility. Never throws.
 */
export function readVdrScanners(outDir: string): VdrScannerRow[] {
  let names: string[];
  try { names = readdirSync(outDir); }
  catch { return []; }
  const vdrFiles = names.filter((n) => /^KSI-.*VDR.*\.json$/.test(n));
  // Dedupe: prefer `<base>.json` over `<base>.signed.json`.
  const plain = new Set(vdrFiles.filter((n) => !/\.signed\.json$/.test(n)));
  const selected = vdrFiles.filter((n) => {
    if (!/\.signed\.json$/.test(n)) return true;
    return !plain.has(n.replace(/\.signed\.json$/, '.json'));
  }).sort();

  const rows: VdrScannerRow[] = [];
  for (const f of selected) {
    const p = resolve(outDir, f);
    let bytes: Buffer;
    try { bytes = readFileSync(p); } catch { continue; }
    let doc: any;
    try { doc = JSON.parse(bytes.toString('utf8')); } catch { continue; }
    if (!doc || typeof doc !== 'object') continue;
    const sha256 = createHash('sha256').update(bytes).digest('hex');
    const collectedAt = String(doc.collected_at ?? doc.collectedAt ?? '');
    const providers = Array.isArray(doc.providers) ? doc.providers : [];
    for (const pr of providers) {
      if (!pr || typeof pr !== 'object') continue;
      const provider = String(pr.provider ?? 'unknown');
      const findings = Array.isArray(pr.findings) ? pr.findings : [];
      const detFinding = findings.find((fn: any) => typeof fn?.rule === 'string' && /vdr\.detection_capability_enabled/.test(fn.rule));
      const evidence = Array.isArray(pr.evidence) ? pr.evidence : [];
      const summaryEv = evidence.find((e: any) => e?.source === 'vdr.summary');
      const sd = summaryEv?.data ?? {};
      const obs = detFinding?.current_state?.observations ?? {};
      rows.push({
        scanner: scannerNameFromFinding(provider, detFinding),
        provider,
        detection_enabled: detFinding ? detFinding.passed === true : false,
        total_findings: Number(sd.total ?? obs.total_findings ?? 0) || 0,
        kev_count: Number(sd.kev_count ?? 0) || 0,
        last_collected_at: collectedAt,
        source_file: f,
        sha256,
      });
    }
  }
  return rows;
}

// ─── SSP provenance digest (§13 + footer, Q5) ────────────────────────────────

function sspDigest(outDir: string): string | null {
  const p = resolve(outDir, 'ssp.json');
  if (!existsSync(p)) return null;
  try { return createHash('sha256').update(readFileSync(p)).digest('hex'); }
  catch { return null; }
}

// ─── FedRAMP baseline escalation table (published — REO Rule 3) ──────────────

/**
 * The FedRAMP Rev5 remediation SLAs (High 30d / Moderate 90d / Low 180d) joined
 * with the CISA BOD 22-01 KEV baseline (21d — CISA may set a shorter per-CVE due
 * date, which wins). Rendered as a REQUIRES-OPERATOR-INPUT-VERIFY baseline; the
 * operator overrides via config.yaml: conmon.escalation[].
 */
function baselineEscalation(): EscalationThreshold[] {
  return [
    { trigger: 'CISA KEV catalog entry', sla: '21 days', notify: [TBD_VERIFY] },
    { trigger: 'Critical vulnerability', sla: '30 days', notify: [TBD_VERIFY] },
    { trigger: 'High vulnerability', sla: '30 days', notify: [TBD_VERIFY] },
    { trigger: 'Moderate vulnerability', sla: '90 days', notify: [TBD_VERIFY] },
    { trigger: 'Low vulnerability', sla: '180 days', notify: [TBD_VERIFY] },
  ];
}

/** Parse the leading integer day-count from an SLA string (for ascending sort). */
function slaDays(sla: string): number {
  const m = String(sla).match(/\d+/);
  return m ? Number(m[0]) : Number.MAX_SAFE_INTEGER;
}

// ─── OOXML building blocks (same pattern as cmp-emit.ts / fips199-emit.ts) ────

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

// ─── Builder (pure) ──────────────────────────────────────────────────────────

export function buildConmonStrategyBodyXml(opts: ConmonStrategyEmitOptions): {
  xml: string;
  stats: Omit<ConmonStrategyEmitResult, 'path' | 'bytes'>;
} {
  const systemName = opts.systemName || TBD;
  const systemId = opts.systemId || TBD;
  const csp = opts.cspOrganization || TBD;

  // §4 KSI catalogue — throws if the map grep is broken (Risk 2, C-C1-3 parity).
  const ksis = readKsiCatalog();
  if (ksis.length < 20) throw new ConmonKsiScopeError(ksis.length);

  // §5 scanners.
  const scanners = readVdrScanners(opts.outDir);

  // §9 reporting endpoint: low/mod → USDA Connect.gov (R2); high → agency-direct.
  const endpoint: ReportingEndpoint = opts.reportingEndpoint
    ?? (opts.impactLevel === 'high' ? 'agency-direct' : 'usda-connect.gov');

  // §11 escalation (sorted SLA-days ascending — KEV first; Q2/Q3).
  const escalationSupplied = (opts.escalationThresholds?.length ?? 0) > 0;
  const escalation = (escalationSupplied ? opts.escalationThresholds! : baselineEscalation())
    .slice()
    .sort((a, b) => slaDays(a.sla) - slaDays(b.sla));

  // §12 collaborative ConMon: enabled iff the flag is set AND >1 agency customer.
  const agencyCustomers = opts.agencyCustomers ?? [];
  const collaborative = opts.collaborativeConmon === true && agencyCustomers.length > 1;

  const sspSha = sspDigest(opts.outDir);
  const docUuid = deterministicUuid(`conmon-strategy:${systemId}:${opts.runId}`);

  // Required-for-signature tracker (test #12: team + escalation + deviation).
  const missing: string[] = [];
  const track = (label: string, val: string | undefined) => {
    if (!val || val.trim() === '') missing.push(label);
  };
  track('systemName', opts.systemName);
  track('systemId', opts.systemId);
  track('cspOrganization', opts.cspOrganization);
  if ((opts.conmonTeamRoster?.length ?? 0) === 0) missing.push('conmonTeamRoster (config.yaml: conmon.team[])');
  if (!escalationSupplied) missing.push('escalationThresholds (config.yaml: conmon.escalation[])');
  track('deviationRequestProcess', opts.deviationRequestProcess);

  const parts: string[] = [];

  // ── Title block ──
  parts.push(para('Continuous Monitoring Strategy and Plan', 'Title'));
  parts.push(para(`${systemName} — FedRAMP ${opts.impactLevel.toUpperCase()} Continuous Monitoring (CA-7)`, 'Subtitle'));
  parts.push(para(
    'DRAFT — auto-generated by fedramp-20x-cloud-evidence. §4 Controls Under Continuous ' +
    'Monitoring is derived from the live core/ksi-map.ts; §5 Vulnerability Scanning is derived ' +
    `from the run's real VDR evidence. The operator must complete every ${TBD} marker and ` +
    `confirm every ${TBD_VERIFY} baseline before this Strategy + Plan is final. The CSP is the ` +
    'author-of-record.',
    'Disclaimer',
  ));

  // ── §1 Introduction ──
  parts.push(heading('1. Introduction', 1));
  parts.push(para(
    'This Continuous Monitoring (ConMon) Strategy and Plan satisfies NIST SP 800-53 Rev. 5 ' +
    'control CA-7 (Continuous Monitoring), CA-7(1) (Independent Assessment), and PM-31 ' +
    '(Continuous Monitoring Strategy). CA-7 requires the organization to "Develop a system-level ' +
    'continuous monitoring strategy and implement continuous monitoring in accordance with the ' +
    'organization-level continuous monitoring strategy" — establishing system-level metrics, ' +
    'monitoring and assessment frequencies, ongoing control assessments, analysis, response ' +
    'actions, and reporting (NIST SP 800-53 Rev. 5, CA-7 a–g). The Strategy is the umbrella; the ' +
    'Plan is the executable cadence.',
  ));
  parts.push(para(
    `Per NIST SP 800-137 §2.1: "${SP_800_137_DEFINITION}"`,
  ));
  parts.push(fieldTable([
    ['Document Title', `Continuous Monitoring Strategy and Plan — ${systemName}`],
    ['Document UUID', docUuid],
    ['Version', '1.0'],
    ['System Name', systemName],
    ['System ID', systemId],
    ['CSP Organization', csp],
    ['Impact Level', opts.impactLevel.toUpperCase()],
    ['Satisfies Controls', 'NIST SP 800-53 Rev. 5 CA-7, CA-7(1), PM-31'],
    ['Primary Structure Source', `FedRAMP Continuous Monitoring Strategy Guide ${CONMON_STRATEGY_GUIDE_VERSION}`],
    ['Cadence Source', `FedRAMP Continuous Monitoring Playbook ${CONMON_PLAYBOOK_VERSION}`],
    ['Generated By', 'fedramp-20x-cloud-evidence (core/conmon-strategy-emit.ts)'],
    ['Run ID', opts.runId],
    ['FRMR Catalog Version', opts.frmrVersion],
  ]));

  // ── §2 Three-Tier Continuous Monitoring Strategy ──
  parts.push(heading('2. Three-Tier Continuous Monitoring Strategy', 1));
  parts.push(para(
    'Per NIST SP 800-137 §3, the ISCM program operates across three tiers. This Strategy addresses ' +
    'the Information System tier (Tier 3) as the executable Plan, within the Organization + ' +
    'Mission/Business-Process tiers the CSP maintains.',
  ));
  parts.push(table(
    ['Tier', 'Scope', 'This Program'],
    [
      ['Tier 1 — Organization', 'Enterprise risk tolerance, ISCM policy, common controls.', `${TBD}: reference the CSP organizational ISCM policy.`],
      ['Tier 2 — Mission / Business Process', 'ISCM strategy per mission/business line; control-frequency assignment.', `${TBD}: reference the mission-level ISCM strategy.`],
      ['Tier 3 — Information System', 'This system: continuous control monitoring, scanning, POA&M, reporting.', 'This document (§4–§13).'],
    ],
    [2600, 3800, 2600],
  ));

  // ── §3 FedRAMP Continuous-Monitoring Cadence ──
  parts.push(heading('3. FedRAMP Continuous-Monitoring Cadence', 1));
  parts.push(para(
    `Per the FedRAMP Continuous Monitoring Strategy Guide ${CONMON_STRATEGY_GUIDE_VERSION} §3.1 ` +
    `(p. 11): "${STRATEGY_GUIDE_QUOTE}"`,
  ));
  parts.push(para(
    `The cadence below is the published FedRAMP continuous-monitoring baseline; the current-state ` +
    `source is the FedRAMP Continuous Monitoring Playbook ${CONMON_PLAYBOOK_VERSION} ` +
    `(${CONMON_PLAYBOOK_URL}). ${TBD_VERIFY}: confirm each frequency against the live Playbook — ` +
    'FedRAMP may revise specific cadences.',
  ));
  parts.push(table(
    ['Activity', 'Frequency', 'Reference'],
    [
      ['Vulnerability scanning (OS / web / database, authenticated)', 'Monthly', `Playbook ${CONMON_PLAYBOOK_VERSION}; §5`],
      ['POA&M update + full-document re-submission', 'Monthly', 'LOOP-A.A1 monthly re-emission; §6'],
      ['Integrated Inventory Workbook refresh', 'Monthly', 'INV-S1 coverage; §7'],
      ['Significant Change Notification (as needed)', 'Event-driven', 'FedRAMP SCN process'],
      ['Annual security assessment (3PAO)', 'Annually', 'CA-7(1); §so far as the SAP/SAR cycle'],
      ['Authorization maintenance / reauthorization', 'Per FedRAMP policy', `${TBD_VERIFY}: confirm reauth cadence`],
    ],
    [3900, 2200, 2900],
  ));

  // ── §4 Controls Under Continuous Monitoring ──
  parts.push(heading('4. Controls Under Continuous Monitoring', 1));
  parts.push(para(
    `The ${ksis.length} Key Security Indicators (KSIs) below are auto-derived from the live ` +
    'cloud-evidence/core/ksi-map.ts and reflect exactly the controls the collector monitors each ' +
    'ConMon cycle. The Automated column is derived from each KSI\'s registered scope: CLOUD = ' +
    'automated cloud-SDK evidence; HYBRID = automated signal plus a periodic process-artifact ' +
    'review; PROCESS = process artifact captured in the tracker; INHERITED = leveraged ' +
    'authorization. Each KSI maps to the NIST SP 800-53 controls recorded in its evidence file.',
  ));
  parts.push(table(
    ['KSI ID', 'Family', 'Scope', 'Automated', 'Assessment Frequency', 'Evidence Type'],
    ksis.map((k) => [
      k.ksi,
      k.family,
      k.scope,
      automatedForScope(k.scope),
      frequencyForScope(k.scope),
      evidenceTypeForScope(k.scope),
    ]),
    [1900, 900, 1200, 1200, 2100, 1900],
  ));

  // ── §5 Vulnerability Scanning ──
  parts.push(heading('5. Vulnerability Scanning', 1));
  parts.push(para(
    'The scanner(s) below are auto-derived from the run\'s real VDR evidence files (KSI-*VDR*.json). ' +
    'Each row is one provider-scoped detection capability the collector observed; the Detection ' +
    'Enabled column reflects the collector\'s own finding. A disabled scanner is listed (never ' +
    'omitted) so the coverage gap is visible.',
  ));
  if (scanners.length > 0) {
    parts.push(table(
      ['Scanner', 'Provider', 'Detection Enabled', 'Findings', 'KEV', 'Last Collected', 'Evidence SHA-256'],
      scanners.map((s) => [
        s.scanner,
        s.provider,
        s.detection_enabled ? 'Yes' : 'No',
        String(s.total_findings),
        String(s.kev_count),
        s.last_collected_at || TBD,
        s.sha256.slice(0, 16) + '…',
      ]),
      [2100, 900, 1400, 1000, 700, 1800, 1200],
    ));
    parts.push(para(
      `${TBD_VERIFY}: the scanner version + per-asset coverage percent are not carried in the VDR ` +
      'evidence envelope; confirm scanner versions and coverage against the scanner console. If the ' +
      'CSP runs additional scanners (e.g. Snyk, GHAS, Wiz, Tenable) not auto-discovered above, add ' +
      'them here (Risk 5).',
    ));
  } else {
    parts.push(table(
      ['Scanner', 'Provider', 'Detection Enabled', 'Findings', 'KEV', 'Last Collected', 'Evidence SHA-256'],
      [[TBD, TBD, TBD, TBD, TBD, TBD, 'No KSI-*VDR* evidence found in this run. Enable a VDR collector (KSI-AFR-VDR) or add scanners here.']],
      [2100, 900, 1400, 1000, 700, 1800, 1200],
    ));
    // Note: the absence of a VDR collector this run is a coverage gap surfaced by
    // the §5 REQUIRES-OPERATOR-INPUT row + the scanner_count=0 stat, NOT an
    // operator-config gap — ready_for_signature stays driven by the §10/§11/§8
    // operator inputs (test #12), consistent with the fips199/cmp precedent.
  }

  // ── §6 POA&M Management ──
  parts.push(heading('6. POA&M Management', 1));
  parts.push(para(
    'Plan of Action and Milestones (POA&M) items are generated by LOOP-A.A1 (core/oscal-poam.ts) ' +
    'from the run\'s failing findings and re-emitted monthly as a full OSCAL document. Per the R2 ' +
    'research finding, Low/Moderate systems perform a monthly full-document POA&M re-upload to the ' +
    'FedRAMP secure repository (USDA Connect.gov); High systems report agency-direct (§9). Each ' +
    'POA&M item carries the finding\'s remediation deadline derived per the §11 escalation SLAs.',
  ));

  // ── §7 Inventory Management ──
  parts.push(heading('7. Inventory Management', 1));
  parts.push(para(
    'The Integrated Inventory Workbook (FedRAMP Appendix M) is regenerated each ConMon cycle from ' +
    'real cloud inventory (INV-S1), and out/inventory-coverage.json records per-cell fill rates so ' +
    'inventory completeness is monitored month-over-month (CM-8). New, changed, and removed assets ' +
    'flow into the monthly submission.',
  ));

  // ── §8 Deviation Requests ──
  parts.push(heading('8. Deviation Requests', 1));
  parts.push(para(
    `Deviation Requests (risk-adjustment, operational-requirement, and false-positive) follow the ` +
    `FedRAMP process clarified in RFC-0026 (${RFC_0026_URL}). ` +
    (opts.deviationRequestProcess?.trim()
      ? opts.deviationRequestProcess.trim()
      : `${TBD_VERIFY}: document the CSP's deviation-request submission + approval workflow ` +
        '(who prepares, who reviews, the FedRAMP submission path, and the tracker record). The ' +
        'default here cites RFC-0026 only; no workflow is invented.'),
  ));

  // ── §9 Reporting Endpoint ──
  parts.push(heading('9. Reporting Endpoint', 1));
  const endpointLabel = endpoint === 'usda-connect.gov'
    ? 'USDA Connect.gov (FedRAMP secure repository for Low/Moderate)'
    : endpoint === 'agency-direct'
      ? 'Agency-direct (the sponsoring agency\'s secure channel)'
      : 'Other (operator-specified)';
  parts.push(para(
    `This ${opts.impactLevel.toUpperCase()} system reports its monthly ConMon deliverables to: ` +
    `${endpointLabel}. Per the R2 research finding, Low/Moderate systems submit a monthly ` +
    'full-document POA&M re-upload to USDA Connect.gov; High systems report agency-direct.',
  ));
  parts.push(fieldTable([
    ['Reporting Endpoint', endpointLabel],
    ['Cadence', 'Monthly (POA&M + scan summary + inventory) per §3'],
    ['Endpoint Policy Note', `${TBD_VERIFY}: the USDA Connect.gov mandate may shift back to per-agency endpoints; confirm the current FedRAMP secure-repository policy (Risk 3).`],
  ]));

  // ── §10 ConMon Team Roster ──
  parts.push(heading('10. Continuous Monitoring Team Roster', 1));
  const roster: ConmonTeamMember[] = (opts.conmonTeamRoster && opts.conmonTeamRoster.length > 0)
    ? opts.conmonTeamRoster
    : (['ConMon Lead', 'POA&M Coordinator', 'Scan Operator', 'Risk Reviewer'] as const).map(
        (role) => ({ role, name: TBD, org: csp, email: TBD }),
      );
  parts.push(table(
    ['Role', 'Name', 'Organization', 'Email'],
    roster.map((m) => [m.role, m.name || TBD, m.org || csp, m.email || TBD]),
    [2400, 2400, 2400, 2400],
  ));

  // ── §11 Escalation Thresholds ──
  parts.push(heading('11. Escalation Thresholds', 1));
  parts.push(para(
    'Remediation SLAs escalate by trigger, sorted shortest-deadline first. The values below are the ' +
    'FedRAMP Rev5 remediation SLAs joined with the CISA BOD 22-01 KEV baseline ' +
    `(${BOD_22_01_URL}). Both apply: where CISA sets a shorter per-CVE KEV due date, the stricter ` +
    '(shorter) deadline wins (Q3). ' +
    (escalationSupplied ? '' : `${TBD_VERIFY}: these are FedRAMP baselines — confirm or tighten per the CSP's internal SLA (Risk 6).`),
  ));
  parts.push(table(
    ['Trigger', 'Remediation SLA', 'Notify'],
    escalation.map((e) => [e.trigger, e.sla, e.notify.join(', ')]),
    [3400, 2200, 3400],
  ));

  // ── §12 Collaborative Continuous Monitoring ──
  parts.push(heading('12. Collaborative Continuous Monitoring', 1));
  if (collaborative) {
    parts.push(para(
      `Collaborative Continuous Monitoring is ENABLED: ${agencyCustomers.length} agency customers ` +
      'leverage this authorization, so ConMon deliverables are shared across the leveraging agencies ' +
      `per RFC-0026 (${RFC_0026_URL}). ${TBD_VERIFY}: RFC-0026's collaborative-ConMon scope is ` +
      'evolving; confirm the shared-deliverable set with each agency (Risk 4).',
    ));
    parts.push(table(
      ['Agency Customer', 'ATO Letter Date'],
      agencyCustomers.map((a) => [a.agency || TBD, a.ato_letter_date || TBD]),
      [5000, 4000],
    ));
  } else {
    parts.push(para(
      'Collaborative Continuous Monitoring is not enabled for this system ' +
      `(${agencyCustomers.length} agency customer(s) recorded; the collaborative flag is ` +
      `${opts.collaborativeConmon === true ? 'set but requires >1 agency customer' : 'not set'}). ` +
      `When multiple agencies leverage this authorization, ConMon deliverables are shared per ` +
      `RFC-0026 (${RFC_0026_URL}). Configure via config.yaml: conmon.agency_customers[] + ` +
      'conmon.collaborative_conmon.',
    ));
  }

  // ── §13 Plan Maintenance ──
  parts.push(heading('13. Plan Maintenance', 1));
  parts.push(para(
    'This Strategy + Plan is reviewed at least annually and whenever a significant change, a new ' +
    'agency customer, or a FedRAMP ConMon policy update occurs. It is re-emitted each run so §4 ' +
    '(controls) and §5 (scanners) stay current with the live ksi-map + VDR evidence.',
  ));
  parts.push(fieldTable([
    ['Review Cadence', 'Annually + on significant change'],
    ['SSP Cross-Reference', sspSha ? `out/ssp.json (sha256 ${sspSha})` : '(SSP not present this run — emit with --oscal-ssp to anchor the chain of custody)'],
    ['Regenerated From', 'core/ksi-map.ts (§4) + KSI-*VDR* evidence (§5) each run'],
  ]));

  // ── Provenance footer ──
  parts.push(heading('Provenance', 2));
  parts.push(para(
    `Generated by core/conmon-strategy-emit.ts (run ${opts.runId}, FRMR ${opts.frmrVersion}). ` +
    `§4 controls: core/ksi-map.ts grep (${ksis.length} KSIs). ` +
    `§5 scanners: ${scanners.length} provider block(s) from ${new Set(scanners.map((s) => s.source_file)).size} VDR evidence file(s)` +
    (scanners.length > 0 ? ` (${scanners.map((s) => `${s.source_file}:${s.sha256.slice(0, 12)}`).join(', ')}). ` : '. ') +
    `Cadence source: FedRAMP ConMon Playbook ${CONMON_PLAYBOOK_VERSION} — ${CONMON_PLAYBOOK_URL}. ` +
    `Structure source: FedRAMP ConMon Strategy Guide ${CONMON_STRATEGY_GUIDE_VERSION} — ${CONMON_STRATEGY_GUIDE_URL}. ` +
    `Three-tier model: NIST SP 800-137 — ${SP_800_137_URL}. Deviation process: RFC-0026 — ${RFC_0026_URL}. ` +
    (sspSha ? `SSP cross-reference: out/ssp.json (sha256 ${sspSha}). ` : 'SSP not present this run. ') +
    'This document is deterministic (no wall-clock time); its integrity is anchored by the signed ' +
    'submission-bundle INDEX.json (SHA-256 + Ed25519).',
  ));

  // ── Page geometry (US Letter) ──
  const sectPr = '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/>' +
    '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr>';

  const xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<w:document xmlns:w="${W_NS}"><w:body>${parts.join('')}${sectPr}</w:body></w:document>`;

  return {
    xml,
    stats: {
      ksi_count: ksis.length,
      scanner_count: scanners.length,
      agency_customer_count: agencyCustomers.length,
      collaborative_conmon: collaborative,
      reporting_endpoint: endpoint,
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

function coreXml(systemName: string, docUuid: string): string {
  const title = `Continuous Monitoring Strategy and Plan — ${systemName} [${docUuid}]`;
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

/** Pure: render the ConMon Strategy + Plan Word document to a Buffer. */
export function renderConmonStrategyDocx(opts: ConmonStrategyEmitOptions): {
  buffer: Buffer;
  stats: Omit<ConmonStrategyEmitResult, 'path' | 'bytes'>;
} {
  const { xml, stats } = buildConmonStrategyBodyXml(opts);
  const systemName = opts.systemName || TBD;
  const systemId = opts.systemId || TBD;
  const docUuid = deterministicUuid(`conmon-strategy:${systemId}:${opts.runId}`);
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

/** Read the ksi-map + VDR evidence, render, and write conmon-strategy.docx. */
export function emitConmonStrategyDocx(opts: ConmonStrategyEmitOptions): ConmonStrategyEmitResult {
  const { buffer, stats } = renderConmonStrategyDocx(opts);
  const outPath = opts.outPath ?? resolve(opts.outDir, 'conmon-strategy.docx');
  writeFileSync(outPath, buffer);
  log.info({
    event: 'conmon-strategy.emitted',
    path: outPath,
    bytes: buffer.length,
    ksi_count: stats.ksi_count,
    scanner_count: stats.scanner_count,
    agency_customer_count: stats.agency_customer_count,
    collaborative_conmon: stats.collaborative_conmon,
    reporting_endpoint: stats.reporting_endpoint,
    ready_for_signature: stats.ready_for_signature,
    requires_operator_input_count: stats.requires_operator_input.length,
  });
  return { path: outPath, bytes: buffer.length, ...stats };
}
