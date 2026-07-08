/**
 * Risk Management Strategy (RMS) emitter — LOOP-C.C7.
 *
 * Renders `rms.docx` — the organization-level Risk Management Strategy that
 * satisfies NIST SP 800-53 Rev. 5 control PM-9 (Risk Management Strategy). The
 * RMS sits ABOVE the per-finding POA&M (LOOP-A.A1) and the per-system SSP in the
 * three-tier risk hierarchy NIST SP 800-39 defines (Organization → Mission /
 * Business Process → Information System). It frames how the CSP manages risk end
 * to end: framing, assessing, responding, and monitoring (SP 800-39 §2).
 *
 * The document auto-links to the real risk corpus the rest of the pipeline emits:
 *   - §5 Risk Register Reference   ← out/risk-register.json (LOOP-B.B5, RA-3).
 *   - §6 Risk Acceptance Policy    ← out/.risk-acceptances.json (LOOP-B.B3) +
 *                                     out/.compensating-controls.json (LOOP-B.B4).
 *   - §7 Continuous Risk Monitoring← out/conmon-strategy.docx (LOOP-C.C6, CA-7).
 *   - §10 POA&M Summary            ← out/poam.json (LOOP-A.A1) — severity
 *                                     histogram + overdue + oldest-open age.
 * When a LOOP-B input is absent the section degrades to a REQUIRES-OPERATOR-INPUT
 * marker with a "Generate via LOOP-B before finalizing" cross-link (Open Q2:
 * degrade, never block — REO Rule 4). The risk register + acceptance corpus are
 * never fabricated.
 *
 * Authoritative sources (verbatim, cited in the body + the provenance footer):
 *   - NIST SP 800-39 (2011-03) — Managing Information Security Risk —
 *     https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-39.pdf
 *     §2 four-component process quoted VERBATIM in §1; §2.1 three-tier hierarchy
 *     drives §2; the §4 Accept / Avoid / Mitigate / Transfer response set is the
 *     SP 800-39 risk-response terminology (REO Rule 3 allowed exception).
 *   - NIST SP 800-37 Rev. 2 (2018-12) — RMF —
 *     https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-37r2.pdf
 *     §3 RMF steps cited in §1.
 *   - NIST SP 800-30 Rev. 1 (2012-09) — Guide for Conducting Risk Assessments —
 *     https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf
 *     §3.2 methodology cited in §3.
 *   - NIST SP 800-53 Rev. 5 — PM-9 / PM-8 / RA-1 / RA-3 —
 *     https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final — control text (§1 / §3).
 *
 * Approach (dependency-free .docx): a `.docx` is a ZIP of WordprocessingML XML
 * parts. We build the parts as strings and pack them with the store-only ZIP
 * writer the twelve shipped docx emitters use (core/zip.ts) — no external Word
 * library, no runtime network. The OOXML building blocks mirror
 * conmon-strategy-emit.ts / fips199-emit.ts; the shared docx-primitives module
 * proposed in LOOP-C-SPEC §4 was never extracted (LOOP-C-RISKS C-X-1 /
 * C-C1-6..C-C6-8), so this emitter keeps its OOXML constants local like its
 * siblings — now the thirteenth emitter to migrate when C-X-1 lands.
 *
 * REO compliance:
 *   - §5 / §6 links + counts trace to the run's REAL LOOP-B output files on disk;
 *     a section degrades to REQUIRES-OPERATOR-INPUT when its input is absent —
 *     never a fabricated register or acceptance count.
 *   - §10 POA&M counts trace to the run's real out/poam.json. Severities are
 *     coerced through the honest envelope enum {critical, high, medium, low,
 *     info}; an unknown value throws PoamSeverityError (Risk 2 — no silent
 *     mis-bucket). count_overdue + oldest_open_finding_age_days are computed
 *     against a deterministic "now" (the POA&M metadata last-modified, an input
 *     datum — never a wall-clock Date.now(); injectable via opts.now for tests,
 *     Risk 3).
 *   - §8 Risk Tolerance + §9 Executive Oversight are operator-supplied
 *     (config.yaml: rms.tolerance / rms.executive_oversight[]); absent → a
 *     REQUIRES-OPERATOR-INPUT row. Executive names are never logged (only counts,
 *     Risk 6 / C-X-15).
 *   - The document is fully deterministic (no wall-clock time): the metadata UUID
 *     is `deterministicUuid('rms:' + systemId + ':' + runId)` and the provenance
 *     cites the poam / risk-register / acceptance / SSP content SHA-256s, so
 *     identical inputs produce a byte-identical .docx. Integrity is anchored by
 *     the signed submission-bundle INDEX.json (SHA-256 + Ed25519), the same
 *     coverage conmon-strategy.docx / fips199.docx receive.
 *
 * Pure renderer (`renderRmsDocx` / `buildRmsBodyXml`) + disk emitter
 * (`emitRmsDocx`). The readers (`readRiskRegister`, `readAcceptancePolicy`,
 * `summarizePoam`) are exported for unit testing.
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

// ─── Pinned authoritative-source constants (published — REO Rule 3) ──────────

const SP_800_39_URL = 'https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-39.pdf';
const SP_800_37_URL = 'https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-37r2.pdf';
const SP_800_30_URL = 'https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf';
const SP_800_53_URL = 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final';

/** NIST SP 800-39 §2 (p. 6) — verbatim (the four-component risk-management process). */
const SP_800_39_PROCESS =
  'The risk management process involves four components: (i) framing risk; ' +
  '(ii) assessing risk; (iii) responding to risk; (iv) monitoring risk.';

/** NIST SP 800-53 Rev. 5 PM-9(a) — verbatim (the strategy the RMS documents). */
const PM_9_QUOTE =
  'Develops a comprehensive strategy to manage: 1. Security risk to organizational ' +
  'operations and assets, individuals, other organizations, and the Nation associated ' +
  'with the operation and use of organizational systems; and 2. Privacy risk to ' +
  'individuals resulting from the authorized processing of personally identifiable ' +
  'information.';

// ─── Types ───────────────────────────────────────────────────────────────────

/** CIA risk-tolerance level (§8). */
export type ToleranceLevel = 'low' | 'moderate' | 'high';

/** The system-wide risk tolerance per CIA objective (§8, operator-supplied). */
export interface RiskTolerance {
  confidentiality: ToleranceLevel;
  integrity: ToleranceLevel;
  availability: ToleranceLevel;
}

/** One executive-oversight roster row (§9, operator-supplied). */
export interface ExecutiveOversight {
  role: string;
  name: string;
  org: string;
}

export interface RmsEmitOptions {
  /** Where the orchestrator writes. The emitter reads poam.json + risk-register.json + acceptance snapshots from here. */
  outDir: string;
  /** Output path (defaults to <outDir>/rms.docx). */
  outPath?: string;
  /** Run id — captured in the provenance (§1) + deterministic UUID seed. */
  runId: string;
  /** FRMR catalog version — captured in the provenance (§1). */
  frmrVersion: string;
  /** System identity (reuses --system-name / --system-id / --csp-name). */
  systemName?: string;
  systemId?: string;
  cspOrganization?: string;
  /** Impact tier — drives the §2 organizational-context framing. */
  impactLevel: 'low' | 'moderate' | 'high';
  /** §2 agency-customer count (organizational context). */
  agencyCustomerCount?: number;
  /** §8 risk tolerance per CIA objective (config.yaml: rms.tolerance). */
  riskTolerance?: RiskTolerance;
  /** §9 executive-oversight roster (config.yaml: rms.executive_oversight[]). */
  executiveOversight?: ExecutiveOversight[];
  /** §5 explicit risk-register href override; defaults to ./risk-register.json IFF present. */
  riskRegisterHref?: string;
  /** §6 explicit risk-acceptance-policy href override; defaults to ./ .risk-acceptances.json IFF present. */
  riskAcceptancePolicyHref?: string;
  /**
   * Deterministic "now" for the §10 overdue + oldest-open-age computation. Tests
   * inject this (Risk 3). In production it defaults to the POA&M metadata
   * last-modified (an input datum) — never a wall-clock read.
   */
  now?: Date;
}

/** §10 POA&M summary derived from a real out/poam.json (null when absent). */
export interface PoamSummary {
  /** Total poam-items in the document. */
  poam_item_count: number;
  /** Severity histogram keyed by the honest envelope enum. */
  count_by_severity: Record<'critical' | 'high' | 'medium' | 'low' | 'info', number>;
  /** Open (status != closed) risks whose remediation deadline is in the past. */
  count_overdue: number;
  /** Days since the oldest open finding was first observed (null when unresolvable). */
  oldest_open_finding_age_days: number | null;
  /** SHA-256 of the poam.json bytes (chain-of-custody). */
  sha256: string;
}

/** §5 risk-register reference derived from a real out/risk-register.json (null when absent). */
export interface RiskRegisterRef {
  href: string;
  entries_total: number;
  open_count: number;
  high_inherent_count: number;
  by_source: Record<string, number>;
  sha256: string;
}

/** §6 risk-acceptance policy corpus derived from the real LOOP-B snapshots. */
export interface AcceptancePolicyRef {
  /** Present when either snapshot resolved. */
  present: boolean;
  acceptances_href: string | null;
  acceptance_count: number;
  acceptance_sha256: string | null;
  compensating_href: string | null;
  compensating_count: number;
  compensating_sha256: string | null;
}

export interface RmsEmitResult {
  path: string;
  bytes: number;
  /** True when out/risk-register.json (B.B5) was found + linked in §5. */
  risk_register_present: boolean;
  /** True when either LOOP-B.B3/B.B4 acceptance snapshot fed §6. */
  risk_acceptance_policy_present: boolean;
  /** True when out/poam.json (A.A1) fed §10. */
  poam_present: boolean;
  /** poam-item count feeding §10 (0 when no POA&M). */
  poam_item_count: number;
  /** Executive-oversight roster size feeding §9 (count only — never the names). */
  executive_oversight_count: number;
  /** True when every required-for-signature operator field was supplied. */
  ready_for_signature: boolean;
  /** Missing-input list for operator action. */
  requires_operator_input: string[];
}

/** Thrown when a poam-item / risk carries a severity outside the envelope enum (Risk 2). */
export class PoamSeverityError extends Error {
  constructor(value: string) {
    super(`rms-emit: poam.json carries an unknown severity "${value}" — expected one of critical|high|medium|low|info. The LOOP-A.A1 severity enum changed; update summarizePoam's coercion.`);
    this.name = 'PoamSeverityError';
  }
}

// ─── SHA-256 helper ──────────────────────────────────────────────────────────

function fileSha(path: string): string | null {
  if (!existsSync(path)) return null;
  try { return createHash('sha256').update(readFileSync(path)).digest('hex'); }
  catch { return null; }
}

function readJson(path: string): any | null {
  if (!existsSync(path)) return null;
  try { return JSON.parse(readFileSync(path, 'utf8')); }
  catch { return null; }
}

// ─── §5 Risk Register reader (out/risk-register.json — LOOP-B.B5) ─────────────

/**
 * Read the aggregated Central Risk Register (LOOP-B.B5) and return its top-line
 * summary for §5. Answers Open Q1 by embedding the register SUMMARY (totals, not
 * every row) so a 3PAO sees the risk posture without a bloated doc. Returns null
 * when the file is absent (§5 degrades to REQUIRES-OPERATOR-INPUT, Q2).
 */
export function readRiskRegister(outDir: string, hrefOverride?: string): RiskRegisterRef | null {
  const p = resolve(outDir, 'risk-register.json');
  const doc = readJson(p);
  if (!doc || typeof doc !== 'object') return null;
  const sha = fileSha(p);
  if (!sha) return null;
  // Prefer the emitter's own summary; fall back to counting entries defensively.
  const entries = Array.isArray(doc.entries) ? doc.entries : [];
  const summary = doc.summary && typeof doc.summary === 'object' ? doc.summary : null;
  const by_source: Record<string, number> = {};
  if (summary?.by_source && typeof summary.by_source === 'object') {
    for (const [k, v] of Object.entries(summary.by_source)) by_source[k] = Number(v) || 0;
  } else {
    for (const e of entries) {
      const s = String(e?.source ?? 'unknown');
      by_source[s] = (by_source[s] ?? 0) + 1;
    }
  }
  const entries_total = Number(summary?.entries_total ?? entries.length) || 0;
  const open_count = Number(
    summary?.open_count ?? entries.filter((e: any) => e?.status === 'open').length,
  ) || 0;
  const high_inherent_count = Number(
    summary?.high_inherent_count
      ?? entries.filter((e: any) => e?.inherent_risk === 'high' || e?.inherent_risk === 'very-high').length,
  ) || 0;
  return {
    href: hrefOverride ?? './risk-register.json',
    entries_total,
    open_count,
    high_inherent_count,
    by_source,
    sha256: sha,
  };
}

// ─── §6 Risk Acceptance Policy reader (LOOP-B.B3 + B.B4 snapshots) ────────────

/** Count the item array in an acceptance/compensating snapshot (defensive shapes). */
function snapshotCount(doc: any): number {
  if (!doc) return 0;
  if (Array.isArray(doc)) return doc.length;
  if (Array.isArray(doc.items)) return doc.items.length;
  if (Array.isArray(doc.entries)) return doc.entries.length;
  return 0;
}

/**
 * Resolve the first existing filename from a candidate list (prefers the real
 * dotfile snapshot name, falls back to the per-slice-§7 non-dotted name).
 */
function firstExisting(outDir: string, names: string[]): string | null {
  for (const n of names) {
    if (existsSync(resolve(outDir, n))) return n;
  }
  return null;
}

/**
 * Read the LOOP-B.B3 signed risk-acceptance snapshot + the LOOP-B.B4 signed
 * compensating-control snapshot for §6. The real emitters write the dotfile
 * names `.risk-acceptances.json` / `.compensating-controls.json` (LOOP-B.B3 /
 * B.B4); the per-slice §7 named the non-dotted forms, so both are accepted
 * (C-C7-8 reconciliation). Never throws.
 */
export function readAcceptancePolicy(
  outDir: string,
  acceptancesHrefOverride?: string,
  compensatingHrefOverride?: string,
): AcceptancePolicyRef {
  const accName = firstExisting(outDir, ['.risk-acceptances.json', 'risk-acceptances.json']);
  const compName = firstExisting(outDir, ['.compensating-controls.json', 'compensating-controls.json']);

  const accDoc = accName ? readJson(resolve(outDir, accName)) : null;
  const compDoc = compName ? readJson(resolve(outDir, compName)) : null;

  const acceptance_count = snapshotCount(accDoc);
  const compensating_count = snapshotCount(compDoc);

  return {
    present: accName !== null || compName !== null,
    acceptances_href: acceptancesHrefOverride ?? (accName ? `./${accName}` : null),
    acceptance_count,
    acceptance_sha256: accName ? fileSha(resolve(outDir, accName)) : null,
    compensating_href: compensatingHrefOverride ?? (compName ? `./${compName}` : null),
    compensating_count,
    compensating_sha256: compName ? fileSha(resolve(outDir, compName)) : null,
  };
}

// ─── §10 POA&M summary reader (out/poam.json — LOOP-A.A1) ─────────────────────

const KNOWN_SEVERITIES: ReadonlyArray<'critical' | 'high' | 'medium' | 'low' | 'info'> =
  ['critical', 'high', 'medium', 'low', 'info'];

/** Read a `severity` prop value from an OSCAL props[] array (ns-agnostic). */
function severityProp(props: any): string | null {
  if (!Array.isArray(props)) return null;
  const p = props.find((x: any) => x && x.name === 'severity');
  return p ? String(p.value ?? '') : null;
}

/** Parse an ISO/date-only string to a Date; null when unparseable. */
function parseDate(s: any): Date | null {
  if (typeof s !== 'string' || s.trim() === '') return null;
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : new Date(t);
}

/** Whole days between two dates (a - b), floored; negative allowed. */
function daysBetween(a: Date, b: Date): number {
  return Math.floor((a.getTime() - b.getTime()) / 86_400_000);
}

/**
 * Summarize the run's real OSCAL POA&M for §10. Returns null when poam.json is
 * absent (§10 degrades to REQUIRES-OPERATOR-INPUT). The severity histogram is
 * counted over poam-items (one per failing finding); count_overdue + the
 * oldest-open age are computed over risks (which carry status + deadline +
 * related-observations). `now` defaults to the POA&M metadata last-modified so
 * the result is deterministic given the input file (Risk 3); opts inject it.
 */
export function summarizePoam(outDir: string, nowOverride?: Date): PoamSummary | null {
  const p = resolve(outDir, 'poam.json');
  const doc = readJson(p);
  if (!doc || typeof doc !== 'object') return null;
  const sha = fileSha(p);
  if (!sha) return null;
  const poam = doc['plan-of-action-and-milestones'];
  if (!poam || typeof poam !== 'object') return null;

  const items = Array.isArray(poam['poam-items']) ? poam['poam-items'] : [];
  const risks = Array.isArray(poam.risks) ? poam.risks : [];
  const observations = Array.isArray(poam.observations) ? poam.observations : [];

  // Deterministic "now": opts override → POA&M metadata last-modified → null.
  const now = nowOverride ?? parseDate(poam?.metadata?.['last-modified']);

  // §10 severity histogram over poam-items.
  const count_by_severity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const it of items) {
    const sev = severityProp(it?.props);
    if (sev === null) continue; // an item without a severity prop is not bucketed
    const norm = sev.toLowerCase();
    if (!(KNOWN_SEVERITIES as ReadonlyArray<string>).includes(norm)) {
      throw new PoamSeverityError(sev);
    }
    count_by_severity[norm as keyof typeof count_by_severity]++;
  }

  // Observation uuid → collected date map (for the oldest-open-age computation).
  const collectedByObs = new Map<string, Date>();
  for (const o of observations) {
    const d = parseDate(o?.collected);
    if (o?.uuid && d) collectedByObs.set(String(o.uuid), d);
  }

  // count_overdue + oldest_open_finding_age_days over open (status != closed) risks.
  let count_overdue = 0;
  let oldest_open_finding_age_days: number | null = null;
  for (const r of risks) {
    const open = String(r?.status ?? 'open') !== 'closed';
    if (!open) continue; // Q4: only currently-open risks count
    if (now) {
      const dl = parseDate(r?.deadline);
      if (dl && dl.getTime() < now.getTime()) count_overdue++;
      // Age from the earliest related observation's collected date.
      const rel = Array.isArray(r?.['related-observations']) ? r['related-observations'] : [];
      let earliest: Date | null = null;
      for (const ro of rel) {
        const d = collectedByObs.get(String(ro?.['observation-uuid']));
        if (d && (!earliest || d.getTime() < earliest.getTime())) earliest = d;
      }
      if (earliest) {
        const age = daysBetween(now, earliest);
        if (oldest_open_finding_age_days === null || age > oldest_open_finding_age_days) {
          oldest_open_finding_age_days = age;
        }
      }
    }
  }

  return {
    poam_item_count: items.length,
    count_by_severity,
    count_overdue,
    oldest_open_finding_age_days,
    sha256: sha,
  };
}

// ─── SSP provenance digest (footer, Q5) ──────────────────────────────────────

function sspDigest(outDir: string): string | null {
  return fileSha(resolve(outDir, 'ssp.json'));
}

/** True when the run emitted the C.C6 ConMon Strategy the §7 cross-link points at. */
function conmonStrategyPresent(outDir: string): boolean {
  return existsSync(resolve(outDir, 'conmon-strategy.docx'));
}

// ─── OOXML building blocks (same pattern as conmon-strategy-emit.ts) ──────────

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

export function buildRmsBodyXml(opts: RmsEmitOptions): {
  xml: string;
  stats: Omit<RmsEmitResult, 'path' | 'bytes'>;
} {
  const systemName = opts.systemName || TBD;
  const systemId = opts.systemId || TBD;
  const csp = opts.cspOrganization || TBD;
  const docUuid = deterministicUuid(`rms:${systemId}:${opts.runId}`);

  // Real LOOP-A / LOOP-B corpus.
  const register = readRiskRegister(opts.outDir, opts.riskRegisterHref);
  const acceptance = readAcceptancePolicy(opts.outDir, opts.riskAcceptancePolicyHref);
  const poam = summarizePoam(opts.outDir, opts.now);
  const sspSha = sspDigest(opts.outDir);
  const conmonPresent = conmonStrategyPresent(opts.outDir);

  // A resolvable §5 register link: an explicit override or a present risk-register.json.
  const registerHref = opts.riskRegisterHref ?? register?.href ?? null;
  // A resolvable §6 acceptance-policy link: an explicit override or a present snapshot.
  const acceptanceHref = opts.riskAcceptancePolicyHref
    ?? acceptance.acceptances_href
    ?? acceptance.compensating_href
    ?? null;

  // Required-for-signature tracking (test #12: tolerance + executive + register
  // link + acceptance policy; plus the system identity, like the sibling emitters).
  const missing: string[] = [];
  const track = (label: string, val: string | undefined) => {
    if (!val || val.trim() === '') missing.push(label);
  };
  track('systemName', opts.systemName);
  track('systemId', opts.systemId);
  track('cspOrganization', opts.cspOrganization);
  if (!opts.riskTolerance) missing.push('riskTolerance (config.yaml: rms.tolerance)');
  if ((opts.executiveOversight?.length ?? 0) === 0) missing.push('executiveOversight (config.yaml: rms.executive_oversight[])');
  if (!registerHref) missing.push('riskRegisterHref (out/risk-register.json — generate via LOOP-B.B5)');
  if (!acceptanceHref) missing.push('riskAcceptancePolicyHref (out/.risk-acceptances.json — generate via LOOP-B.B3/B.B4)');

  const parts: string[] = [];

  // ── Title block ──
  parts.push(para('Risk Management Strategy', 'Title'));
  parts.push(para(`${systemName} — FedRAMP ${opts.impactLevel.toUpperCase()} Organizational Risk Management (PM-9)`, 'Subtitle'));
  parts.push(para(
    'DRAFT — auto-generated by fedramp-20x-cloud-evidence. §5 Risk Register, §6 Risk ' +
    'Acceptance Policy, and §10 POA&M Summary are derived from the run\'s real risk corpus ' +
    `(risk-register.json, the risk-acceptance snapshots, and poam.json). The operator must ` +
    `complete every ${TBD} marker before this Strategy is final. The CSP is the ` +
    'author-of-record; the AO reviews and approves per PM-9(b)/(c).',
    'Disclaimer',
  ));

  // ── §1 Introduction ──
  parts.push(heading('1. Introduction', 1));
  parts.push(para(
    'This Risk Management Strategy (RMS) satisfies NIST SP 800-53 Rev. 5 control PM-9 ' +
    `(Risk Management Strategy). PM-9 requires the organization to: "${PM_9_QUOTE}" The ` +
    'strategy is implemented consistently across the organization (PM-9 b) and reviewed and ' +
    'updated at an organization-defined frequency (PM-9 c).',
  ));
  parts.push(para(
    `Per NIST SP 800-39 §2: "${SP_800_39_PROCESS}" Each component is addressed below: framing ` +
    '(§2), assessing (§3), responding (§4), and monitoring (§7). NIST SP 800-39 §2.1 defines the ' +
    'three-tier risk hierarchy — Tier 1 Organization, Tier 2 Mission / Business Process, Tier 3 ' +
    'Information System — and this RMS is the Tier 1 / Tier 2 umbrella above the per-system SSP ' +
    'and the per-finding POA&M (Tier 3). The RMS supervises the NIST SP 800-37 Rev. 2 Risk ' +
    'Management Framework steps (Prepare, Categorize, Select, Implement, Assess, Authorize, ' +
    'Monitor).',
  ));
  parts.push(fieldTable([
    ['Document Title', `Risk Management Strategy — ${systemName}`],
    ['Document UUID', docUuid],
    ['Version', '1.0'],
    ['System Name', systemName],
    ['System ID', systemId],
    ['CSP Organization', csp],
    ['Impact Level', opts.impactLevel.toUpperCase()],
    ['Satisfies Controls', 'NIST SP 800-53 Rev. 5 PM-9 (supporting: PM-8, RA-1, RA-3)'],
    ['Risk Hierarchy Source', 'NIST SP 800-39 §2.1 (Organization / Mission / Information System)'],
    ['RMF Reference', 'NIST SP 800-37 Rev. 2 §3'],
    ['Generated By', 'fedramp-20x-cloud-evidence (core/rms-emit.ts)'],
    ['Run ID', opts.runId],
    ['FRMR Catalog Version', opts.frmrVersion],
  ]));

  // ── §2 Risk Framing ──
  parts.push(heading('2. Risk Framing', 1));
  const agencyCount = opts.agencyCustomerCount;
  parts.push(para(
    'Risk framing (NIST SP 800-39 §2, component i) establishes the organizational context, ' +
    'risk assumptions, constraints, and priorities within which risk is assessed, responded to, ' +
    'and monitored. This organization operates a multi-tenant Software-as-a-Service (SaaS) cloud ' +
    `service authorized at FedRAMP ${opts.impactLevel.toUpperCase()}. The information system ` +
    'processes federal information on behalf of its agency customers, so the risk frame is bounded ' +
    'by the FedRAMP 20x / Rev5 requirements, the sponsoring agency\'s risk tolerance, and the ' +
    'NIST SP 800-53 baseline commensurate with the impact level.',
  ));
  parts.push(fieldTable([
    ['Deployment Model', 'Multi-tenant SaaS (cloud service provider)'],
    ['FedRAMP Impact Level', opts.impactLevel.toUpperCase()],
    ['Agency Customers', typeof agencyCount === 'number' ? String(agencyCount) : `${TBD} (config.yaml: rms — agency customer count)`],
    ['Risk Frame Boundary', 'FedRAMP 20x + Rev5; NIST SP 800-53 baseline for the impact level'],
    ['Governing Authority', 'PM-9(b) — the strategy is implemented consistently across the organization'],
  ]));

  // ── §3 Risk Assessment Methodology ──
  parts.push(heading('3. Risk Assessment Methodology', 1));
  parts.push(para(
    'Risk assessment (NIST SP 800-39 §2, component ii) follows NIST SP 800-30 Rev. 1 §3.2: threats ' +
    'and vulnerabilities are identified, the likelihood of exploitation and the magnitude of impact ' +
    'are determined, and risk is computed as a function of likelihood and impact. This is ' +
    'operationalized by the toolkit: control findings are collected as signed evidence, each failing ' +
    'finding is scored (CVSS + EPSS + inventory-derived criticality + exposure, LOOP-B.B1), and the ' +
    'aggregated results are recorded in the Central Risk Register (NIST SP 800-53 Rev. 5 RA-3, §5) ' +
    'with NIST SP 800-30 likelihood / impact / inherent / residual bands. RA-1 governs the ' +
    'risk-assessment policy and procedures that authorize this methodology.',
  ));

  // ── §4 Risk Response Strategy ──
  parts.push(heading('4. Risk Response Strategy', 1));
  parts.push(para(
    'Risk response (NIST SP 800-39 §2, component iii) selects one of the four standard NIST SP ' +
    '800-39 course-of-action alternatives for each assessed risk. FedRAMP does not prescribe a ' +
    'preferred response at Moderate versus High (Open Q3), so the generic NIST SP 800-39 matrix ' +
    'below applies; the selected response for each risk is recorded in the Central Risk Register ' +
    '(§5) and, for mitigated risks, tracked to closure in the POA&M (§10).',
  ));
  parts.push(table(
    ['Response', 'Definition (NIST SP 800-39)', 'When Applied'],
    [
      ['Accept', 'Acknowledge the risk and take no further action, accepting the potential for harm.', 'Residual risk is within the organization\'s risk tolerance (§8); recorded as a risk acceptance (§6).'],
      ['Avoid', 'Eliminate the risk source — e.g., decommission or decline to deploy the affected capability.', 'The risk exceeds tolerance and no cost-effective mitigation exists.'],
      ['Mitigate', 'Reduce likelihood and/or impact by implementing or strengthening security controls.', 'The default response for a failing control finding; tracked in the POA&M (§10).'],
      ['Transfer', 'Shift the risk to a third party (e.g., insurance, or a shared-responsibility inheritance).', 'The risk is better borne by a leveraged authorization or contractual party.'],
    ],
    [1600, 4400, 3000],
  ));

  // ── §5 Risk Register Reference ──
  parts.push(heading('5. Risk Register Reference', 1));
  if (register) {
    parts.push(para(
      `The Central Risk Register (NIST SP 800-53 Rev. 5 RA-3) is maintained at ${register.href} ` +
      '(LOOP-B.B5, signed). It aggregates finding-derived, acceptance-derived, and organizational ' +
      'risk entries with NIST SP 800-30 likelihood / impact / inherent / residual bands. The ' +
      'current posture (embedded here per Open Q1 as a summary, not a full row dump):',
    ));
    parts.push(fieldTable([
      ['Register Location', register.href],
      ['Total Risk Entries', String(register.entries_total)],
      ['Open Entries', String(register.open_count)],
      ['High / Very-High Inherent Risk', String(register.high_inherent_count)],
      ['Entries by Source', Object.keys(register.by_source).length > 0
        ? Object.entries(register.by_source).map(([k, v]) => `${k}: ${v}`).join('; ')
        : TBD],
      ['Register Evidence SHA-256', register.sha256],
    ]));
  } else {
    parts.push(para(
      `${TBD}: the Central Risk Register (out/risk-register.json) was not present in this run. ` +
      'Generate it via LOOP-B (run with --risk-register, which aggregates the finding-derived ' +
      'risks, the risk acceptances, and the organizational risks into the signed RA-3 register) ' +
      'before finalizing this Strategy. Until then, the CSP maintains the risk register out-of-band ' +
      'and the AO must confirm its RA-3 coverage.',
    ));
  }

  // ── §6 Risk Acceptance Policy ──
  parts.push(heading('6. Risk Acceptance Policy', 1));
  parts.push(para(
    'A risk is accepted only when its residual risk is within the organization\'s risk tolerance ' +
    '(§8) and the acceptance is approved by the authorizing official (or designee) with a documented ' +
    'justification and an expiration date. Accepted risks are recorded as FedRAMP Deviation Requests ' +
    'and surfaced in the POA&M with risk.status = deviation-approved (LOOP-B.B3); a compensating ' +
    'control (LOOP-B.B4) may be recorded against an accepted risk to reduce its residual exposure.',
  ));
  if (acceptance.present) {
    parts.push(fieldTable([
      ['Active Risk Acceptances', acceptance.acceptances_href
        ? `${acceptance.acceptance_count} (${acceptance.acceptances_href})`
        : `${TBD} — no acceptance snapshot this run`],
      ['Acceptance Snapshot SHA-256', acceptance.acceptance_sha256 ?? TBD],
      ['Active Compensating Controls', acceptance.compensating_href
        ? `${acceptance.compensating_count} (${acceptance.compensating_href})`
        : `${TBD} — no compensating-control snapshot this run`],
      ['Compensating Snapshot SHA-256', acceptance.compensating_sha256 ?? TBD],
    ]));
  } else {
    parts.push(para(
      `${TBD}: no risk-acceptance snapshot (out/.risk-acceptances.json, LOOP-B.B3) or ` +
      'compensating-control snapshot (out/.compensating-controls.json, LOOP-B.B4) was present in ' +
      'this run. Pull them from the tracker (run with --risk-acceptances / --compensating-controls) ' +
      'before finalizing. The acceptance policy above still governs; only the current-state counts ' +
      'are pending.',
    ));
  }

  // ── §7 Continuous Risk Monitoring ──
  parts.push(heading('7. Continuous Risk Monitoring', 1));
  parts.push(para(
    'Risk monitoring (NIST SP 800-39 §2, component iv) verifies that planned risk responses are ' +
    'implemented, that controls remain effective, and that changes in the system or its environment ' +
    'are reflected in the risk posture. The executable monitoring cadence is defined in the ' +
    'Continuous Monitoring Strategy and Plan (LOOP-C.C6, CA-7 / CA-7(1) / PM-31), which names which ' +
    'controls are monitored, at what frequency, and how findings escalate. ' +
    (conmonPresent
      ? 'That document (out/conmon-strategy.docx) is part of this submission and is the authoritative ConMon reference.'
      : `${TBD}: the Continuous Monitoring Strategy (out/conmon-strategy.docx) was not emitted in this run — generate it with --conmon-strategy so this cross-reference resolves (Risk 5).`),
  ));

  // ── §8 Risk Tolerance ──
  parts.push(heading('8. Risk Tolerance', 1));
  parts.push(para(
    'Risk tolerance is the level of risk the organization is willing to accept per security ' +
    'objective. It bounds the §6 acceptance policy: a residual risk above tolerance may not be ' +
    'accepted without an explicit, time-bounded AO deviation.',
  ));
  if (opts.riskTolerance) {
    parts.push(table(
      ['Security Objective', 'Risk Tolerance'],
      [
        ['Confidentiality', opts.riskTolerance.confidentiality.toUpperCase()],
        ['Integrity', opts.riskTolerance.integrity.toUpperCase()],
        ['Availability', opts.riskTolerance.availability.toUpperCase()],
      ],
      [4500, 4500],
    ));
    parts.push(para(
      'The per-objective tolerance above is the operator\'s single-level statement. A CSP with ' +
      'multi-tier nuance (e.g., different tolerances per data category) may append a free-text ' +
      'tolerance narrative via config.yaml: rms.tolerance_narrative (Risk 4).',
    ));
  } else {
    parts.push(para(
      `${TBD}: the per-objective risk tolerance was not supplied. Set config.yaml: rms.tolerance ` +
      '(confidentiality / integrity / availability, each low / moderate / high). Without it the ' +
      '§6 acceptance policy has no quantified ceiling.',
    ));
  }

  // ── §9 Executive Oversight + Governance ──
  parts.push(heading('9. Executive Oversight and Governance', 1));
  parts.push(para(
    'Executive oversight assigns organizational accountability for the risk-management strategy. ' +
    'The roles below own risk framing, acceptance authority, and the PM-9(c) periodic review of ' +
    'this strategy.',
  ));
  if (opts.executiveOversight && opts.executiveOversight.length > 0) {
    parts.push(table(
      ['Role', 'Name', 'Organization'],
      opts.executiveOversight.map((e) => [e.role || TBD, e.name || TBD, e.org || csp]),
      [3400, 3100, 2500],
    ));
  } else {
    parts.push(para(
      `${TBD}: the executive-oversight roster was not supplied. Set config.yaml: ` +
      'rms.executive_oversight[] (role / name / org) — typically the Authorizing Official, the ' +
      'Chief Information Security Officer, and the Risk Executive (function). Contacts are supplied ' +
      'via config (never logged by the toolkit).',
    ));
  }

  // ── §10 POA&M Summary ──
  parts.push(heading('10. POA&M Summary', 1));
  parts.push(para(
    'The counts below are auto-derived from the run\'s real Plan of Action and Milestones ' +
    '(out/poam.json, LOOP-A.A1) — the Tier 3 record of open corrective actions the RMS supervises. ' +
    'Severities use the toolkit\'s evidence enum (critical / high / medium / low / info); overdue ' +
    'counts open items whose remediation deadline has passed; the oldest-open age is measured from ' +
    'the earliest observation of the oldest still-open finding (Q4: only currently-open items).',
  ));
  if (poam) {
    const s = poam.count_by_severity;
    parts.push(fieldTable([
      ['Total POA&M Items', String(poam.poam_item_count)],
      ['Critical', String(s.critical)],
      ['High', String(s.high)],
      ['Medium', String(s.medium)],
      ['Low', String(s.low)],
      ['Informational', String(s.info)],
      ['Overdue (deadline passed, still open)', String(poam.count_overdue)],
      ['Oldest Open Finding Age (days)', poam.oldest_open_finding_age_days === null ? TBD : String(poam.oldest_open_finding_age_days)],
      ['POA&M Evidence SHA-256', poam.sha256],
    ]));
  } else {
    parts.push(para(
      `${TBD}: no POA&M (out/poam.json) was present in this run — either no failing findings exist ` +
      'or the OSCAL POA&M was not emitted. Run with --oscal-poam to generate it (LOOP-A.A1); the ' +
      'severity histogram, overdue count, and oldest-open age will then populate automatically.',
    ));
  }

  // ── §11 Plan Maintenance ──
  parts.push(heading('11. Plan Maintenance', 1));
  parts.push(para(
    'Per PM-9(c), this Risk Management Strategy is reviewed and updated at an organization-defined ' +
    'frequency (at least annually) and whenever a significant change, a new agency customer, or a ' +
    'material shift in the threat environment or risk tolerance occurs. It is re-emitted each run so ' +
    '§5 (register), §6 (acceptances), and §10 (POA&M) stay current with the live risk corpus.',
  ));
  parts.push(fieldTable([
    ['Review Cadence', 'Annually + on significant change (PM-9 c)'],
    ['SSP Cross-Reference', sspSha ? `out/ssp.json (sha256 ${sspSha})` : '(SSP not present this run — emit with --oscal-ssp to anchor the chain of custody)'],
    ['ConMon Cross-Reference', conmonPresent ? 'out/conmon-strategy.docx (LOOP-C.C6)' : `${TBD} — emit with --conmon-strategy`],
    ['Regenerated From', 'risk-register.json (§5) + acceptance snapshots (§6) + poam.json (§10) each run'],
  ]));

  // ── Provenance footer ──
  parts.push(heading('Provenance', 2));
  parts.push(para(
    `Generated by core/rms-emit.ts (run ${opts.runId}, FRMR ${opts.frmrVersion}). ` +
    `§5 risk register: ${register ? `risk-register.json (sha256 ${register.sha256})` : 'not present this run'}. ` +
    `§6 acceptances: ${acceptance.acceptance_sha256 ? `${acceptance.acceptances_href} (sha256 ${acceptance.acceptance_sha256})` : 'not present this run'}; ` +
    `compensating controls: ${acceptance.compensating_sha256 ? `${acceptance.compensating_href} (sha256 ${acceptance.compensating_sha256})` : 'not present this run'}. ` +
    `§10 POA&M: ${poam ? `poam.json (sha256 ${poam.sha256})` : 'not present this run'}. ` +
    (sspSha ? `SSP cross-reference: out/ssp.json (sha256 ${sspSha}). ` : 'SSP not present this run. ') +
    `Control basis: NIST SP 800-53 Rev. 5 PM-9 — ${SP_800_53_URL}. ` +
    `Risk process: NIST SP 800-39 — ${SP_800_39_URL}. RMF: NIST SP 800-37 Rev. 2 — ${SP_800_37_URL}. ` +
    `Assessment method: NIST SP 800-30 Rev. 1 — ${SP_800_30_URL}. ` +
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
      risk_register_present: register !== null,
      risk_acceptance_policy_present: acceptance.present,
      poam_present: poam !== null,
      poam_item_count: poam?.poam_item_count ?? 0,
      executive_oversight_count: opts.executiveOversight?.length ?? 0,
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
  const title = `Risk Management Strategy — ${systemName} [${docUuid}]`;
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

/** Pure: render the Risk Management Strategy Word document to a Buffer. */
export function renderRmsDocx(opts: RmsEmitOptions): {
  buffer: Buffer;
  stats: Omit<RmsEmitResult, 'path' | 'bytes'>;
} {
  const { xml, stats } = buildRmsBodyXml(opts);
  const systemName = opts.systemName || TBD;
  const systemId = opts.systemId || TBD;
  const docUuid = deterministicUuid(`rms:${systemId}:${opts.runId}`);
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

/** Read the risk corpus, render, and write rms.docx. */
export function emitRmsDocx(opts: RmsEmitOptions): RmsEmitResult {
  const { buffer, stats } = renderRmsDocx(opts);
  const outPath = opts.outPath ?? resolve(opts.outDir, 'rms.docx');
  writeFileSync(outPath, buffer);
  log.info({
    event: 'rms.emitted',
    path: outPath,
    bytes: buffer.length,
    risk_register_present: stats.risk_register_present,
    risk_acceptance_policy_present: stats.risk_acceptance_policy_present,
    poam_present: stats.poam_present,
    poam_item_count: stats.poam_item_count,
    executive_oversight_count: stats.executive_oversight_count,
    ready_for_signature: stats.ready_for_signature,
    requires_operator_input_count: stats.requires_operator_input.length,
  });
  return { path: outPath, bytes: buffer.length, ...stats };
}
