/**
 * LOOP-B.B5 — Central Risk Register aggregator (RA-3 deliverable).
 *
 * Aggregates four real evidence streams into a single, exec-readable
 * `out/risk-register.json` (+ `out/risk-register.xlsx` via risk-register-xlsx.ts):
 *
 *   1. Per-finding risks (B.B1+B.B2) — read from the OSCAL POA&M (`out/poam.json`)
 *      `risks[]`; each open risk becomes a `source='finding'` entry. Likelihood +
 *      impact bands are derived from the risk's own composite-score props
 *      (`epss-percentile` → likelihood, `criticality` → impact) so the register
 *      never re-scores; it JOINS.
 *   2. Signed risk acceptances (B.B3) — read from `out/.risk-acceptances.json`;
 *      each active acceptance becomes a `source='acceptance'` entry (treatment=accept),
 *      joined to its matching POA&M risk for bands.
 *   3. Compensating controls (B.B4) — read from `out/.compensating-controls.json`;
 *      an active, unexpired control linked to an acceptance drops the residual band.
 *   4. Operator-entered organisational risks — read from
 *      `out/.organisational-risks.json` (the tracker snapshot); copied verbatim.
 *
 * Likelihood/impact use the NIST SP 800-30 Rev 1 qualitative scale VERBATIM
 * (Very Low … Very High). Inherent risk = combine(likelihood, impact) via the
 * published Table I-2 5×5 matrix (INHERENT_RISK_MATRIX below). Residual risk is
 * inherent reduced by treatment + active compensating controls.
 *
 * REO compliance (cloud-evidence/CLAUDE.md):
 *   - Every finding entry traces to a real OSCAL `risk` in poam.json — no
 *     synthesised entries. The aggregator is a JOIN, not a generator.
 *   - When B.B1 recorded a `REQUIRES-OPERATOR-INPUT` source marker, the derived
 *     band carries that literal token through to JSON + XLSX (visible, never a
 *     silent zero).
 *   - The emitted `risk-register.json` carries a provenance block (emitter,
 *     emittedAt, sourceCalls, signingKeyId) and is signed by core/sign.ts.
 *
 * Pure builder (`buildRiskRegister`) + disk emitter (`emitRiskRegister`).
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { canonicalize, signDetached, type DetachedSignature } from './sign.ts';
import { renderRiskRegisterXlsx } from './risk-register-xlsx.ts';
import { loadCachedAcceptances, type PulledAcceptance } from './risk-acceptance-reader.ts';
import { loadCachedCompensatingControls, getCompensatingControl, type PulledCompensatingControl } from './compensating-control-reader.ts';
import { loadCachedOrganisationalRisks, type PulledOrganisationalRisk } from './organisational-risk-reader.ts';
import { log } from './log.ts';

// ─── Public types ────────────────────────────────────────────────────────────

/** NIST SP 800-30 Rev 1 qualitative band (Appendix G/H/I). Verbatim tokens. */
export type RiskBand = 'very-low' | 'low' | 'moderate' | 'high' | 'very-high';
/** The literal marker propagated when B.B1 could not derive a real score. */
export const REQUIRES_OPERATOR_INPUT = 'REQUIRES-OPERATOR-INPUT' as const;
/** A band that may honestly be un-derivable (finding entries only). */
export type RiskBandOrMarker = RiskBand | typeof REQUIRES_OPERATOR_INPUT;
export type RiskSource = 'finding' | 'acceptance' | 'organisational';
/** ISO 31000:2018 §6.5.3 risk-treatment options. */
export type RiskTreatment = 'accept' | 'mitigate' | 'transfer' | 'avoid';

export interface RiskRegisterReferences {
  finding_uuid?: string;
  poam_item_uuid?: string;
  risk_uuid?: string;
  acceptance_uuid?: string;
  organisational_risk_uuid?: string;
  compensating_control_uuids?: string[];
  nist_control_ids?: string[];
  cvss_base?: number;
  epss_score?: number;
  epss_percentile?: number;
}

export interface RiskRegisterEntry {
  uuid: string;
  source: RiskSource;
  title: string;
  description: string;
  category: string;
  likelihood: RiskBandOrMarker;
  impact: RiskBandOrMarker;
  inherent_risk: RiskBandOrMarker;
  residual_risk: RiskBandOrMarker;
  treatment: RiskTreatment;
  owner: string;
  review_date: string;
  status: 'open' | 'closed';
  /** NIST SP 800-30 revision the bands are derived from (Risk 8 mitigation). */
  nist_800_30_version: 'Rev 1';
  references: RiskRegisterReferences;
}

export interface RiskRegisterInputs {
  /** out/poam.json — the OSCAL POA&M the finding entries are joined from. */
  poamJsonPath: string;
  /** out/.risk-acceptances.json — signed B.B3 snapshot (optional). */
  acceptancesPath?: string;
  /** out/.compensating-controls.json — signed B.B4 snapshot (optional). */
  compensatingControlsPath?: string;
  /** out/.organisational-risks.json — tracker snapshot (optional). */
  organisationalRisksPath?: string;
  /** Injectable clock for expiry checks (deterministic tests). */
  now?: () => Date;
  /** Operator band-derivation thresholds (defaults documented below). */
  bands?: BandThresholds;
}

export interface RiskRegisterEmitOptions {
  outDir: string;
  runId: string;
  inputs?: Partial<RiskRegisterInputs>;
  now?: () => Date;
}

export interface RiskRegisterEmitResult {
  jsonPath: string;
  xlsxPath: string;
  entries_total: number;
  entries_by_source: Record<RiskSource, number>;
  open_count: number;
  high_inherent_count: number;
}

export const RISK_REGISTER_JSON = 'risk-register.json';
export const RISK_REGISTER_XLSX = 'risk-register.xlsx';

// ─── NIST SP 800-30 Rev 1 band derivation ────────────────────────────────────

const BAND_ORDER: RiskBand[] = ['very-low', 'low', 'moderate', 'high', 'very-high'];

/**
 * Operator-tunable EPSS-percentile → likelihood and criticality → impact
 * thresholds (per-slice doc §"Band derivation"). Defaults documented in
 * risk-config.example.yaml; the emitter uses these unless overridden (B.B5-1).
 */
export interface BandThresholds {
  /** EPSS percentile lower-bounds, descending (very-high first). */
  likelihood: { veryHigh: number; high: number; moderate: number; low: number };
  /** Criticality lower-bounds, descending. */
  impact: { veryHigh: number; high: number; moderate: number; low: number };
}

export const DEFAULT_BAND_THRESHOLDS: BandThresholds = {
  likelihood: { veryHigh: 0.95, high: 0.5, moderate: 0.05, low: 0.005 },
  impact: { veryHigh: 0.9, high: 0.7, moderate: 0.4, low: 0.2 },
};

/** EPSS percentile → NIST 800-30 likelihood band. */
export function likelihoodFromEpssPercentile(pct: number, t: BandThresholds = DEFAULT_BAND_THRESHOLDS): RiskBand {
  const b = t.likelihood;
  if (pct >= b.veryHigh) return 'very-high';
  if (pct >= b.high) return 'high';
  if (pct >= b.moderate) return 'moderate';
  if (pct >= b.low) return 'low';
  return 'very-low';
}

/** Organisational criticality [0,1] → NIST 800-30 impact band. */
export function impactFromCriticality(crit: number, t: BandThresholds = DEFAULT_BAND_THRESHOLDS): RiskBand {
  const b = t.impact;
  if (crit >= b.veryHigh) return 'very-high';
  if (crit >= b.high) return 'high';
  if (crit >= b.moderate) return 'moderate';
  if (crit >= b.low) return 'low';
  return 'very-low';
}

/**
 * NIST SP 800-30 Rev 1 Appendix I, Table I-2 — Level of Risk as the combination
 * of Likelihood (row) and Impact (column). Values pinned VERBATIM from the
 * published table (Risk 2 mitigation: the constant is the single source of truth,
 * overridable via config in a future slice). Indexed [likelihood][impact].
 */
export const INHERENT_RISK_MATRIX: Record<RiskBand, Record<RiskBand, RiskBand>> = {
  'very-high': { 'very-low': 'very-low', 'low': 'low', 'moderate': 'moderate', 'high': 'high', 'very-high': 'very-high' },
  'high':      { 'very-low': 'very-low', 'low': 'low', 'moderate': 'moderate', 'high': 'high', 'very-high': 'very-high' },
  'moderate':  { 'very-low': 'very-low', 'low': 'low', 'moderate': 'moderate', 'high': 'moderate', 'very-high': 'high' },
  'low':       { 'very-low': 'very-low', 'low': 'low', 'moderate': 'low', 'high': 'low', 'very-high': 'moderate' },
  'very-low':  { 'very-low': 'very-low', 'low': 'very-low', 'moderate': 'very-low', 'high': 'low', 'very-high': 'low' },
};

/** Combine likelihood × impact into the inherent risk band (NIST Table I-2). */
export function combineInherent(likelihood: RiskBand, impact: RiskBand): RiskBand {
  return INHERENT_RISK_MATRIX[likelihood][impact];
}

/** Drop `n` bands (clamped at very-low). */
export function dropBands(band: RiskBand, n: number): RiskBand {
  const i = BAND_ORDER.indexOf(band);
  return BAND_ORDER[Math.max(0, i - n)]!;
}

/**
 * Residual = inherent reduced by treatment + active compensating controls.
 * - transfer / avoid → drop two bands (operator-tunable).
 * - ≥1 active compensating control linked → drop one band.
 * - accept / mitigate with no CC → no reduction (residual = inherent).
 */
export function deriveResidual(inherent: RiskBand, treatment: RiskTreatment, activeCcCount: number): RiskBand {
  if (treatment === 'transfer' || treatment === 'avoid') return dropBands(inherent, 2);
  if (activeCcCount > 0) return dropBands(inherent, 1);
  return inherent;
}

// ─── OSCAL POA&M reading ──────────────────────────────────────────────────────

interface OscalPropLike { name: string; value: string }
interface OscalRiskLike {
  uuid: string;
  title: string;
  description?: string;
  status: string;
  deadline?: string;
  props?: OscalPropLike[];
}
interface OscalPoamItemLike {
  uuid: string;
  'related-risks'?: Array<{ 'risk-uuid': string }>;
}

function propValue(props: OscalPropLike[] | undefined, name: string): string | undefined {
  return props?.find((p) => p.name === name)?.value;
}
function propValues(props: OscalPropLike[] | undefined, name: string): string[] {
  return (props ?? []).filter((p) => p.name === name).map((p) => p.value);
}
function numProp(props: OscalPropLike[] | undefined, name: string): number | undefined {
  const v = propValue(props, name);
  if (v === undefined) return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}

/** Read + parse the OSCAL POA&M; returns risks + a risk-uuid → poam-item-uuid map. */
function readPoam(path: string): { risks: OscalRiskLike[]; poamItemByRisk: Map<string, string> } {
  if (!existsSync(path)) return { risks: [], poamItemByRisk: new Map() };
  let doc: any;
  try { doc = JSON.parse(readFileSync(path, 'utf8')); }
  catch (e) { log.warn({ event: 'risk-register:unreadable-poam', err: String(e) }, 'risk-register: poam.json unreadable; finding entries omitted'); return { risks: [], poamItemByRisk: new Map() }; }
  const poam = doc?.['plan-of-action-and-milestones'];
  const risks: OscalRiskLike[] = Array.isArray(poam?.risks) ? poam.risks : [];
  const items: OscalPoamItemLike[] = Array.isArray(poam?.['poam-items']) ? poam['poam-items'] : [];
  const poamItemByRisk = new Map<string, string>();
  for (const it of items) {
    for (const rr of it['related-risks'] ?? []) {
      if (rr['risk-uuid'] && !poamItemByRisk.has(rr['risk-uuid'])) poamItemByRisk.set(rr['risk-uuid'], it.uuid);
    }
  }
  return { risks, poamItemByRisk };
}

/** Bands + references derived from a single OSCAL POA&M risk. */
interface FindingBands {
  likelihood: RiskBandOrMarker;
  impact: RiskBandOrMarker;
  inherent: RiskBandOrMarker;
  references: RiskRegisterReferences;
}

function bandsFromRisk(risk: OscalRiskLike, poamItemUuid: string | undefined, bands: BandThresholds): FindingBands {
  const props = risk.props;
  const epssSource = propValue(props, 'risk-score-source-epss');
  const critSource = propValue(props, 'risk-score-source-criticality');
  const epssPct = numProp(props, 'epss-percentile');
  const criticality = numProp(props, 'criticality');

  const likelihood: RiskBandOrMarker =
    epssSource === REQUIRES_OPERATOR_INPUT || epssPct === undefined
      ? REQUIRES_OPERATOR_INPUT
      : likelihoodFromEpssPercentile(epssPct, bands);
  const impact: RiskBandOrMarker =
    critSource === REQUIRES_OPERATOR_INPUT || criticality === undefined
      ? REQUIRES_OPERATOR_INPUT
      : impactFromCriticality(criticality, bands);
  const inherent: RiskBandOrMarker =
    likelihood === REQUIRES_OPERATOR_INPUT || impact === REQUIRES_OPERATOR_INPUT
      ? REQUIRES_OPERATOR_INPUT
      : combineInherent(likelihood, impact);

  const references: RiskRegisterReferences = {
    risk_uuid: risk.uuid,
    poam_item_uuid: poamItemUuid,
    nist_control_ids: propValues(props, 'nist-control'),
    cvss_base: numProp(props, 'cvss-base'),
    epss_score: numProp(props, 'epss-score'),
    epss_percentile: epssPct,
  };
  const ccUuids = propValues(props, 'compensating-control-uuid');
  if (ccUuids.length) references.compensating_control_uuids = ccUuids;
  const accUuid = propValue(props, 'acceptance-uuid');
  if (accUuid) references.acceptance_uuid = accUuid;
  return { likelihood, impact, inherent, references };
}

// ─── Builder (pure) ────────────────────────────────────────────────────────────

export interface BuildInputs {
  risks: OscalRiskLike[];
  poamItemByRisk: Map<string, string>;
  acceptances: PulledAcceptance[];
  compensatingControls: PulledCompensatingControl[];
  organisationalRisks: PulledOrganisationalRisk[];
  bands?: BandThresholds;
  now?: Date;
}

/**
 * Count how many of an acceptance's cited compensating controls resolve to an
 * active, unexpired registry record (defence-in-depth via getCompensatingControl).
 */
function activeCcCount(ccUuids: string[], ccList: PulledCompensatingControl[], now: Date): number {
  let n = 0;
  for (const u of ccUuids) if (getCompensatingControl(u, ccList, now)) n++;
  return n;
}

export function buildRiskRegister(inp: BuildInputs): RiskRegisterEntry[] {
  const bands = inp.bands ?? DEFAULT_BAND_THRESHOLDS;
  const now = inp.now ?? new Date();
  const entries: RiskRegisterEntry[] = [];

  // Index poam risks by poam_item_uuid so acceptances can join to their finding.
  const bandsByPoamItem = new Map<string, FindingBands>();

  // 1. Finding-sourced entries — one per open OSCAL risk (Q3: skip closed).
  const findingEntries: RiskRegisterEntry[] = [];
  for (const risk of inp.risks) {
    if (risk.status === 'closed') continue;
    const poamItemUuid = inp.poamItemByRisk.get(risk.uuid);
    const fb = bandsFromRisk(risk, poamItemUuid, bands);
    if (poamItemUuid) bandsByPoamItem.set(poamItemUuid, fb);
    const treatment: RiskTreatment = 'mitigate';
    const ccCount = fb.references.compensating_control_uuids
      ? activeCcCount(fb.references.compensating_control_uuids, inp.compensatingControls, now)
      : 0;
    const residual: RiskBandOrMarker = fb.inherent === REQUIRES_OPERATOR_INPUT
      ? REQUIRES_OPERATOR_INPUT
      : deriveResidual(fb.inherent, treatment, ccCount);
    findingEntries.push({
      uuid: risk.uuid,
      source: 'finding',
      title: risk.title,
      description: risk.description ?? risk.title,
      category: 'ksi-finding',
      likelihood: fb.likelihood,
      impact: fb.impact,
      inherent_risk: fb.inherent,
      residual_risk: residual,
      treatment,
      owner: 'ISO',
      review_date: risk.deadline ?? '',
      status: 'open',
      nist_800_30_version: 'Rev 1',
      references: fb.references,
    });
  }

  // 2. Acceptance-sourced entries — one per active acceptance (treatment=accept).
  const acceptedPoamItems = new Set<string>();
  const acceptanceEntries: RiskRegisterEntry[] = [];
  for (const acc of inp.acceptances) {
    if (acc.status !== 'approved') continue;
    const expMs = Date.parse(acc.expiration_date);
    if (!Number.isFinite(expMs) || expMs <= now.getTime()) continue;
    acceptedPoamItems.add(acc.poam_item_uuid);
    const fb = bandsByPoamItem.get(acc.poam_item_uuid);
    const likelihood = fb?.likelihood ?? REQUIRES_OPERATOR_INPUT;
    const impact = fb?.impact ?? REQUIRES_OPERATOR_INPUT;
    const inherent = fb?.inherent ?? REQUIRES_OPERATOR_INPUT;
    const ccCount = activeCcCount(acc.compensating_control_uuids, inp.compensatingControls, now);
    const residual: RiskBandOrMarker = inherent === REQUIRES_OPERATOR_INPUT
      ? REQUIRES_OPERATOR_INPUT
      : deriveResidual(inherent, 'accept', ccCount);
    acceptanceEntries.push({
      uuid: acc.uuid,
      source: 'acceptance',
      title: `Accepted risk: ${acc.ksi_id} / ${acc.rule}`,
      description: acc.business_justification,
      category: acc.acceptance_type,
      likelihood,
      impact,
      inherent_risk: inherent,
      residual_risk: residual,
      treatment: 'accept',
      owner: 'AO',
      review_date: acc.expiration_date,
      status: 'open',
      nist_800_30_version: 'Rev 1',
      references: {
        acceptance_uuid: acc.uuid,
        finding_uuid: acc.finding_uuid || undefined,
        poam_item_uuid: acc.poam_item_uuid,
        compensating_control_uuids: acc.compensating_control_uuids.length ? [...acc.compensating_control_uuids] : undefined,
      },
    });
  }

  // De-dup: prefer the acceptance entry over a finding entry for the same
  // poam_item (Risk 4 / test 9).
  for (const fe of findingEntries) {
    const pi = fe.references.poam_item_uuid;
    if (pi && acceptedPoamItems.has(pi)) continue;
    entries.push(fe);
  }
  entries.push(...acceptanceEntries);

  // 3. Organisational entries — copied verbatim from the tracker snapshot.
  for (const o of inp.organisationalRisks) {
    entries.push({
      uuid: o.uuid,
      source: 'organisational',
      title: o.title,
      description: o.description,
      category: o.category,
      likelihood: o.likelihood,
      impact: o.impact,
      inherent_risk: o.inherent_risk,
      residual_risk: o.residual_risk,
      treatment: o.treatment,
      owner: o.owner ?? 'ISO',
      review_date: o.review_date,
      status: o.status,
      nist_800_30_version: 'Rev 1',
      references: {
        organisational_risk_uuid: o.uuid,
        compensating_control_uuids: o.compensating_control_uuids?.length ? [...o.compensating_control_uuids] : undefined,
        nist_control_ids: o.nist_control_ids?.length ? [...o.nist_control_ids] : undefined,
      },
    });
  }

  return entries;
}

// ─── Summary + emit ────────────────────────────────────────────────────────────

export interface RiskRegisterSummary {
  entries_total: number;
  by_source: Record<RiskSource, number>;
  open_count: number;
  high_inherent_count: number;
}

export function summarise(entries: RiskRegisterEntry[]): RiskRegisterSummary {
  const by_source: Record<RiskSource, number> = { finding: 0, acceptance: 0, organisational: 0 };
  let open_count = 0;
  let high_inherent_count = 0;
  for (const e of entries) {
    by_source[e.source]++;
    if (e.status === 'open') open_count++;
    if (e.inherent_risk === 'high' || e.inherent_risk === 'very-high') high_inherent_count++;
  }
  return { entries_total: entries.length, by_source, open_count, high_inherent_count };
}

export interface RiskRegisterDocument {
  schema_version: '1.0.0';
  run_id: string;
  provenance: { emitter: string; emittedAt: string; sourceCalls: string[]; signingKeyId: string };
  summary: RiskRegisterSummary;
  entries: RiskRegisterEntry[];
  signature?: DetachedSignature;
}

/**
 * Read the four inputs from `outDir`, aggregate, and write signed
 * risk-register.json + risk-register.xlsx. Returns the emit result.
 */
export function emitRiskRegister(opts: RiskRegisterEmitOptions): RiskRegisterEmitResult {
  const outDir = opts.outDir;
  const now = opts.now ? opts.now() : new Date();
  const poamPath = opts.inputs?.poamJsonPath ?? resolve(outDir, 'poam.json');

  const { risks, poamItemByRisk } = readPoam(poamPath);
  const acceptances = loadCachedAcceptances(outDir);
  const compensatingControls = loadCachedCompensatingControls(outDir);
  const organisationalRisks = loadCachedOrganisationalRisks(outDir);

  const entries = buildRiskRegister({
    risks, poamItemByRisk, acceptances, compensatingControls, organisationalRisks,
    bands: opts.inputs?.bands, now,
  });
  const summary = summarise(entries);

  const emittedAt = now.toISOString();
  const doc: RiskRegisterDocument = {
    schema_version: '1.0.0',
    run_id: opts.runId,
    provenance: {
      emitter: 'core/risk-register.ts',
      emittedAt,
      sourceCalls: [
        `fs.readFileSync(${poamPath})`,
        'loadCachedAcceptances(.risk-acceptances.json)',
        'loadCachedCompensatingControls(.compensating-controls.json)',
        'loadCachedOrganisationalRisks(.organisational-risks.json)',
      ],
      signingKeyId: '',
    },
    summary,
    entries,
  };

  const canonical = canonicalize({ ...doc, signature: undefined });
  const sig = signDetached(Buffer.from(canonical, 'utf8'), outDir);
  doc.provenance.signingKeyId = sig.keyId;
  doc.signature = sig;

  const jsonPath = resolve(outDir, RISK_REGISTER_JSON);
  writeFileSync(jsonPath, JSON.stringify(doc, null, 2));

  const xlsxPath = resolve(outDir, RISK_REGISTER_XLSX);
  writeFileSync(xlsxPath, renderRiskRegisterXlsx(entries));

  log.info(
    { event: 'risk-register.emitted', path: jsonPath, entries: summary.entries_total, open: summary.open_count, high_inherent: summary.high_inherent_count },
    'risk register emitted',
  );

  return {
    jsonPath,
    xlsxPath,
    entries_total: summary.entries_total,
    entries_by_source: summary.by_source,
    open_count: summary.open_count,
    high_inherent_count: summary.high_inherent_count,
  };
}
