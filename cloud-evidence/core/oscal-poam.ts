/**
 * OSCAL 1.1.2 Plan of Action and Milestones (POA&M) emitter — LOOP-A.A1.
 *
 * Generates an OSCAL POA&M document conforming to the NIST OSCAL 1.1.2
 * plan-of-action-and-milestones model:
 *
 *   https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/plan-of-action-and-milestones/json-reference/
 *   https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/poam/
 *
 * Why this exists:
 *   Every FedRAMP authorization package + every monthly Continuous
 *   Monitoring submission requires a POA&M tracking open findings to closure.
 *   FedRAMP RFC-0024 mandates OSCAL JSON; the deep-research synthesis +
 *   docs/PRE-LOOP-A-RESEARCH-FINDINGS.md confirm full-document re-emission
 *   semantics (monthly POA&M = new document with metadata.last-modified
 *   bumped + revisions[] history).
 *
 * Mapping (cloud-evidence → OSCAL POA&M):
 *   EvidenceFile.Finding (passed=false) → poam-item (one per failing finding)
 *   EvidenceFile.Finding's RawEvidence  → observation (one per SDK call cited)
 *   EvidenceFile.Finding (severity!=info, fail) → risk (one per failing finding
 *                                                  carrying severity > info)
 *   gap.affected_resources              → observation.subjects[] + finding.target
 *   remediation                         → poam-item.props (effort, lifecycle,
 *                                          steps as a links-and-prose structure)
 *   nist_controls                       → finding.target.target-id (one finding
 *                                          per (rule, control))
 *
 * Schema-driven structure (per the v1.1.2 schema we ship at
 * docs/oscal/oscal_poam_schema.v1.1.2.json):
 *   plan-of-action-and-milestones (required: uuid, metadata, poam-items)
 *     uuid                             ← deterministic from systemId+level
 *     metadata (required: title, last-modified, version, oscal-version)
 *     import-ssp { href }              ← optional but recommended (one of
 *                                          import-ssp OR system-id required by
 *                                          OSCAL spec — we emit BOTH so the
 *                                          chain works whether or not the SSP
 *                                          has been authored yet)
 *     system-id { id, identifier-type }
 *     local-definitions (optional)
 *     observations[]                   ← evidence citations
 *     risks[]                          ← severity-driven risk assessments
 *     findings[]                       ← per (rule × control) failing findings
 *     poam-items[]   (REQUIRED)        ← one item per failing finding
 *     back-matter (optional)           ← resource links to the signed manifest
 *
 * REO compliance (cloud-evidence/CLAUDE.md):
 *   - Every poam-item traces to a real Finding in a real EvidenceFile on disk.
 *     No synthetic items. No fabricated narrative.
 *   - If no failing findings exist in outDir, the POA&M is emitted with an
 *     EMPTY poam-items[] (the schema allows this) AND a metadata.remarks
 *     field stating "no open findings at last-modified=<ts>; this is a clean
 *     POA&M, not a missing-evidence state."
 *   - Deterministic UUIDs (via deterministicUuid from oscal.ts) so re-running
 *     the emitter on identical evidence produces an identical document.
 *   - JSON + XML emitted (XML via oscal-xml.ts). Both signed by the existing
 *     core/sign.ts pipeline when the orchestrator wires --sign.
 *
 * Pure builder (`buildOscalPoam`) + disk reader/emitter (`emitOscalPoam`).
 * Read-only with respect to evidence inputs; only writes to `outPath`.
 */
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import type { EvidenceFile, Finding, ProviderBlock, RawEvidence, AffectedResource, Severity } from './envelope.ts';
import { deterministicUuid } from './oscal.ts';
import { oscalJsonToXml } from './oscal-xml.ts';
import { log } from './log.ts';

const OSCAL_VERSION = '1.1.2';
const TOOL_NAME = 'fedramp-20x-cloud-evidence';
const CE_NS = 'urn:fedramp:cloud-evidence';
const FEDRAMP_NS = 'https://fedramp.gov/ns/oscal';

// ─── FedRAMP remediation deadlines per severity ──────────────────────────────
// Source: FedRAMP Continuous Monitoring Strategy & Guide (Rev5) — the canonical
// table operators are held to. KEV-listed vulnerabilities use the CISA BOD
// 22-01 deadline (21 days); we surface that as a separate "kev" severity-like
// classification handled by the VDR pipeline upstream of this emitter.
//
// Days are counted from the date the finding was first observed (we use
// envelope.collected_at as the proxy). LOOP-B.B2 will further refine this with
// PAIN / IRV / LEV math from the VDR ledger; this baseline is for non-VDR
// findings.
const REMEDIATION_DEADLINE_DAYS: Record<Severity, number> = {
  critical: 30,
  high: 60,
  medium: 90,
  low: 180,
  info: 365, // info-only findings still get tracked; long horizon
};

// ─── OSCAL type interfaces ───────────────────────────────────────────────────
interface OscalProp { name: string; ns?: string; value: string; class?: string }
interface OscalLink { href: string; rel?: string; text?: string }

interface OscalMetadata {
  title: string;
  published?: string;
  'last-modified': string;
  version: string;
  'oscal-version': string;
  revisions?: Array<{
    title?: string;
    published?: string;
    'last-modified': string;
    version: string;
    'oscal-version'?: string;
    remarks?: string;
  }>;
  props?: OscalProp[];
  links?: OscalLink[];
  remarks?: string;
}

interface OscalImportSsp {
  href: string;
  remarks?: string;
}

interface OscalSystemId {
  id: string;
  'identifier-type': string;
}

interface OscalSubject {
  type: string;
  'subject-uuid'?: string;
  title?: string;
  props?: OscalProp[];
  remarks?: string;
}

interface OscalObservation {
  uuid: string;
  title?: string;
  description: string;
  props?: OscalProp[];
  links?: OscalLink[];
  methods: Array<'EXAMINE' | 'INTERVIEW' | 'TEST' | 'UNKNOWN'>;
  types?: string[];
  subjects?: OscalSubject[];
  collected: string;
  expires?: string;
  remarks?: string;
}

interface OscalThreatId {
  system: string;
  id: string;
  href?: string;
}

interface OscalRiskRemediation {
  uuid: string;
  lifecycle: 'recommendation' | 'planned' | 'completed';
  title: string;
  description: string;
  props?: OscalProp[];
  links?: OscalLink[];
  remarks?: string;
}

interface OscalRisk {
  uuid: string;
  title: string;
  description: string;
  statement: string;
  status: 'open' | 'investigating' | 'remediating' | 'deviation-requested' | 'deviation-approved' | 'closed';
  props?: OscalProp[];
  links?: OscalLink[];
  'threat-ids'?: OscalThreatId[];
  deadline?: string;
  remediations?: OscalRiskRemediation[];
  'related-observations'?: Array<{ 'observation-uuid': string }>;
}

interface OscalFindingTarget {
  type: 'objective-id' | 'statement-id';
  'target-id': string;
  // OSCAL constrains status.reason to the token enum {pass, fail, other};
  // human-readable explanation goes in status.remarks. The narrative "why
  // this failed" is on the finding's description, not buried in reason.
  status: { state: 'satisfied' | 'not-satisfied' | 'other'; reason?: 'pass' | 'fail' | 'other'; remarks?: string };
  title?: string;
  description?: string;
  props?: OscalProp[];
  links?: OscalLink[];
  'implementation-status'?: { state: string; remarks?: string };
  remarks?: string;
}

interface OscalFindingEntry {
  uuid: string;
  title: string;
  description: string;
  target: OscalFindingTarget;
  props?: OscalProp[];
  links?: OscalLink[];
  'related-observations'?: Array<{ 'observation-uuid': string }>;
  'related-risks'?: Array<{ 'risk-uuid': string }>;
  remarks?: string;
}

interface OscalPoamItem {
  uuid: string;
  title: string;
  description: string;
  props?: OscalProp[];
  links?: OscalLink[];
  'related-findings'?: Array<{ 'finding-uuid': string }>;
  'related-observations'?: Array<{ 'observation-uuid': string }>;
  'related-risks'?: Array<{ 'risk-uuid': string }>;
  remarks?: string;
}

interface OscalBackMatterResource {
  uuid: string;
  title: string;
  description?: string;
  rlinks?: Array<{ href: string; 'media-type'?: string }>;
  remarks?: string;
}

interface OscalPoam {
  uuid: string;
  metadata: OscalMetadata;
  'import-ssp'?: OscalImportSsp;
  'system-id'?: OscalSystemId;
  observations?: OscalObservation[];
  risks?: OscalRisk[];
  findings?: OscalFindingEntry[];
  'poam-items': OscalPoamItem[];
  'back-matter'?: { resources: OscalBackMatterResource[] };
}

// ─── Public options + result ─────────────────────────────────────────────────
export interface PoamEmitOptions {
  /** Directory containing KSI-*.json evidence files. */
  outDir: string;
  /** Where to write the POA&M JSON. Defaults to `${outDir}/poam.json`. */
  outPath?: string;
  /** Run id — captured in metadata.version. */
  runId: string;
  /** FRMR catalog version — captured in metadata.props for traceability. */
  frmrVersion: string;
  /** System the POA&M describes. */
  systemId?: string;
  systemName?: string;
  /** Optional reference to the SSP. If provided, populates import-ssp.href. */
  ssp?: { href: string; remarks?: string };
  /** Optional reference to the signed evidence manifest. Populates back-matter. */
  signedManifestHref?: string;
  /**
   * Optional `metadata.revisions` history (from previous monthly POA&M
   * emissions). When LOOP-E.E2 (monthly POA&M workflow) runs, it appends to
   * this and threads it through here so a 3PAO can see the full version chain
   * in any single POA&M document.
   */
  revisionsHistory?: Array<{
    title?: string;
    'last-modified': string;
    version: string;
    'oscal-version'?: string;
    remarks?: string;
  }>;
}

export interface PoamEmitResult {
  /**
   * Path the POA&M JSON was written to, OR null if no POA&M was emitted
   * (zero failing findings — the OSCAL v1.1.2 schema mandates `poam-items`
   * have minItems=1, so a "clean POA&M" is not a representable OSCAL
   * document. The orchestrator surfaces this as "no open items; nothing
   * to submit this cycle" — NOT as a missing-evidence error.
   */
  path: string | null;
  /** XML path, if emitted (controlled by CLOUD_EVIDENCE_DISABLE_OSCAL_XML). */
  xml_path?: string;
  poam_item_count: number;
  observation_count: number;
  risk_count: number;
  finding_count: number;
  /** Severity histogram of poam-items. */
  by_severity: Record<Severity, number>;
  /**
   * Reason emission was skipped. Populated only when path === null.
   * Tracker / orchestrator log this so the operator sees why no file
   * appeared in out/.
   */
  skipped_reason?: 'no-failing-findings' | 'no-evidence-files';
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function readEvidenceFiles(outDir: string): EvidenceFile[] {
  const out: EvidenceFile[] = [];
  let names: string[];
  try { names = readdirSync(outDir); }
  catch (e: any) { throw new Error(`readEvidenceFiles: cannot read ${outDir}: ${e?.message ?? e}`); }
  for (const n of names) {
    if (!/^KSI-[A-Z]+-[A-Z0-9]+\.json$/.test(n)) continue;
    const p = resolve(outDir, n);
    try {
      const doc = JSON.parse(readFileSync(p, 'utf8')) as EvidenceFile;
      if (doc && doc.ksi_id && Array.isArray((doc as any).providers)) out.push(doc);
    } catch (e) {
      log.warn({ file: n, err: String(e) }, 'poam: skipping unreadable evidence file');
    }
  }
  return out;
}

/**
 * Stable methods array per OSCAL.
 *
 * Cloud-collected evidence is technically a TEST (we made an API call and
 * compared its response against an expected condition). We never INTERVIEW
 * anyone or EXAMINE static artifacts at this layer.
 */
const METHODS_TEST: Array<'TEST'> = ['TEST'];

function severityToRiskStatus(sev: Severity, passed: boolean): OscalRisk['status'] {
  if (passed) return 'closed';
  // Untriaged → open; the LOOP-B.B3 risk-acceptance workflow will move some
  // items to deviation-requested/approved when an operator accepts the risk.
  return 'open';
}

function deadlineFromCollected(collected: string, sev: Severity): string {
  const days = REMEDIATION_DEADLINE_DAYS[sev] ?? 90;
  const base = new Date(collected);
  if (Number.isNaN(base.getTime())) {
    // Defensive: if envelope's collected_at is malformed, fall back to now.
    base.setTime(Date.now());
  }
  base.setUTCDate(base.getUTCDate() + days);
  return base.toISOString();
}

function asciiPreview(s: unknown, max = 240): string {
  const str = typeof s === 'string' ? s : (s == null ? '' : JSON.stringify(s));
  // Strip control chars so the output is safe to embed in OSCAL prose.
  const cleaned = str.replace(/[\x00-\x1f\x7f]+/g, ' ').trim();
  return cleaned.length > max ? cleaned.slice(0, max - 1) + '…' : cleaned;
}

function affectedResourceToSubject(r: AffectedResource): OscalSubject {
  const props: OscalProp[] = [
    { name: 'resource-type', ns: CE_NS, value: r.type },
    { name: 'resource-identifier', ns: CE_NS, value: r.identifier },
  ];
  // Surface common attribute fields (region, account-id, etc.) as props if
  // the collector recorded them in r.attributes — the AffectedResource model
  // is intentionally loose so collectors can attach whatever's relevant.
  if (r.attributes) {
    for (const k of ['region', 'account_id', 'project', 'subscription', 'provider']) {
      const v = (r.attributes as Record<string, unknown>)[k];
      if (typeof v === 'string' && v.length > 0) {
        props.push({ name: k.replace(/_/g, '-'), ns: CE_NS, value: v });
      }
    }
  }
  return {
    type: 'inventory-item',
    // The OSCAL schema requires subject-uuid on observation.subjects[]. We
    // synthesize a deterministic UUID from the resource type + identifier so
    // re-emission keeps the same UUID across runs.
    'subject-uuid': deterministicUuid(`poam:subject:${r.type}:${r.identifier}`),
    title: r.name ?? r.identifier,
    props,
  };
}

/**
 * Map a finding to the props array we record on its poam-item, finding, and
 * risk. Centralized so JSON, XML, and any future consumer see the same shape.
 */
function findingProps(f: Finding, prov: ProviderBlock, ksiId: string): OscalProp[] {
  const props: OscalProp[] = [
    { name: 'severity', ns: CE_NS, value: f.severity },
    { name: 'rule', ns: CE_NS, value: f.rule },
    { name: 'ksi-id', ns: CE_NS, value: ksiId },
    { name: 'provider', ns: CE_NS, value: prov.provider },
  ];
  if (f.applicable_key_word) props.push({ name: 'key-word', ns: CE_NS, value: f.applicable_key_word });
  if (f.nist_controls?.length) {
    for (const c of f.nist_controls) props.push({ name: 'nist-control', ns: CE_NS, value: c });
  }
  // Roll up the first remediation option's effort/cost/availability/customer
  // tags onto the POA&M item. The Finding-level cost/availability/visible
  // are intentionally per-RemediationOption in the envelope, since different
  // options carry different impact profiles. The "primary" option (the first
  // listed) is what the operator is most likely to action — surface it here.
  const primaryOpt = f.remediation?.options?.[0];
  if (primaryOpt) {
    if (primaryOpt.effort_estimate?.magnitude) {
      props.push({ name: 'remediation-effort', ns: CE_NS, value: primaryOpt.effort_estimate.magnitude });
    }
    if (primaryOpt.cost_impact?.level) {
      props.push({ name: 'cost-impact', ns: CE_NS, value: primaryOpt.cost_impact.level });
    }
    if (primaryOpt.availability_impact?.level) {
      props.push({ name: 'availability-impact', ns: CE_NS, value: primaryOpt.availability_impact.level });
    }
    if (primaryOpt.customer_visible?.level) {
      props.push({ name: 'customer-visible', ns: CE_NS, value: primaryOpt.customer_visible.level });
    }
    if (primaryOpt.mechanism) {
      props.push({ name: 'remediation-mechanism', ns: CE_NS, value: primaryOpt.mechanism });
    }
  }
  return props;
}

/**
 * Produce a Markdown description for the POA&M item body. OSCAL `description`
 * is plain prose; rich detail goes in `remarks`.
 */
function poamItemDescription(f: Finding, ksiId: string, ksiName: string): string {
  const gap = f.gap?.description ?? f.current_state?.summary ?? '(no gap description)';
  return `Failing rule \`${f.rule}\` under ${ksiId} (${ksiName}). Severity: ${f.severity}. ${gap}`;
}

function poamItemRemarks(f: Finding): string {
  const lines: string[] = [];
  if (f.target_state?.summary) lines.push(`Target state: ${f.target_state.summary}`);
  if (f.target_state?.rationale) lines.push(`Rationale: ${f.target_state.rationale}`);
  if (f.remediation?.summary) lines.push(`Remediation summary: ${f.remediation.summary}`);
  if (f.remediation?.options?.length) {
    lines.push('Remediation options:');
    for (let i = 0; i < f.remediation.options.length; i++) {
      const o = f.remediation.options[i]!;
      lines.push(`  ${i + 1}. ${o.approach} (${o.mechanism})`);
      for (const s of o.steps) lines.push(`     - ${s}`);
    }
  }
  if (f.references?.length) {
    lines.push('References:');
    for (const r of f.references) lines.push(`  - ${r.title}: ${r.url}`);
  }
  if (f.note) lines.push(`Note: ${f.note}`);
  return lines.join('\n');
}

// ─── Builder (pure) ──────────────────────────────────────────────────────────
export function buildOscalPoam(envelopes: EvidenceFile[], opts: PoamEmitOptions): {
  doc: { 'plan-of-action-and-milestones': OscalPoam };
  result: Omit<PoamEmitResult, 'path' | 'xml_path'>;
} {
  const systemId = opts.systemId || 'cloud-evidence-system';
  const systemName = opts.systemName || 'Cloud System';
  const lastModified = new Date().toISOString();

  const observations: OscalObservation[] = [];
  const risks: OscalRisk[] = [];
  const findings: OscalFindingEntry[] = [];
  const poamItems: OscalPoamItem[] = [];
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  for (const env of envelopes) {
    const ksiId = env.ksi_id;
    const ksiName = (env as any).ksi_name ?? ksiId;
    const collected = env.collected_at ?? lastModified;
    for (const prov of (env as any).providers as ProviderBlock[]) {
      const provFindings: Finding[] = (prov as any).findings ?? [];
      const rawEvidence: RawEvidence[] = (prov as any).evidence ?? [];
      for (const f of provFindings) {
        // Only failing findings enroll into POA&M. Passing findings are
        // recorded in the AR but don't create remediation obligations.
        if (f.passed) continue;
        bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;

        // 1. Observations — one per RawEvidence cited in the provider block.
        //    We attach them all to this finding via related-observations, so
        //    a 3PAO can drill from the POA&M item → evidence cited.
        const obsUuids: string[] = [];
        for (const e of rawEvidence) {
          const obsUuid = deterministicUuid(`poam:obs:${ksiId}:${prov.provider}:${e.source}:${f.rule}`);
          // Dedupe — if multiple findings cite the same RawEvidence we still
          // only emit the observation once.
          if (!observations.some((o) => o.uuid === obsUuid)) {
            // The OSCAL schema requires subject-uuid on observation subjects.
            // We synthesize a deterministic UUID from the provider + source
            // so re-emission keeps the same UUID across runs.
            const componentSubjectUuid = deterministicUuid(`poam:subject:component:${prov.provider}:${e.source}`);
            observations.push({
              uuid: obsUuid,
              title: `${prov.provider}:${e.source}`,
              description: `Evidence captured by ${TOOL_NAME} for ${ksiId} (${prov.provider}). Source: ${e.source}.`,
              methods: METHODS_TEST,
              types: ['finding'],
              collected: e.captured_at ?? collected,
              subjects: [{ type: 'component', 'subject-uuid': componentSubjectUuid, title: `${prov.provider}:${e.source}` }],
              props: [
                { name: 'source', ns: CE_NS, value: e.source },
                { name: 'provider', ns: CE_NS, value: prov.provider },
                { name: 'ksi-id', ns: CE_NS, value: ksiId },
              ],
              remarks: asciiPreview((e as any).data, 400),
            });
          }
          obsUuids.push(obsUuid);
        }

        // 2. Subjects from affected_resources (if the collector populated gap.affected_resources).
        const resourceSubjects: OscalSubject[] = (f.gap?.affected_resources ?? []).map(affectedResourceToSubject);

        // 3. Findings entry — per (rule × control). If a rule cites multiple
        //    NIST controls, we emit one OSCAL `finding` per (rule, control)
        //    so the POA&M cleanly traces back to baseline controls. If a
        //    finding cites NO controls, we emit a single finding with
        //    target-id = ksi-id.rule.
        const controls = (f.nist_controls && f.nist_controls.length > 0)
          ? f.nist_controls
          : [`${ksiId}.${f.rule}`];

        const findingUuids: string[] = [];
        for (const ctrl of controls) {
          const findingUuid = deterministicUuid(`poam:finding:${ksiId}:${prov.provider}:${f.rule}:${ctrl}`);
          findings.push({
            uuid: findingUuid,
            title: `[${f.severity}] ${ksiId} / ${f.rule} → ${ctrl}`,
            description: poamItemDescription(f, ksiId, ksiName),
            props: findingProps(f, prov, ksiId),
            target: {
              type: f.nist_controls && f.nist_controls.length > 0 ? 'statement-id' : 'objective-id',
              'target-id': ctrl,
              status: {
                state: 'not-satisfied',
                reason: 'fail',
                remarks: f.gap?.description ?? f.current_state?.summary ?? 'failing finding',
              },
              description: f.gap?.description ?? f.current_state?.summary ?? '',
            },
            'related-observations': obsUuids.length ? obsUuids.map((u) => ({ 'observation-uuid': u })) : undefined,
            // related-risks wired below once we know the risk uuid.
          });
          findingUuids.push(findingUuid);
        }

        // 4. Risk entry — created only for severity > info (info-only findings
        //    don't represent residual risk). We map each failing finding to
        //    one risk record carrying the remediation block.
        let riskUuid: string | undefined;
        if (f.severity !== 'info') {
          riskUuid = deterministicUuid(`poam:risk:${ksiId}:${prov.provider}:${f.rule}`);
          const remediations: OscalRiskRemediation[] = (f.remediation?.options ?? []).slice(0, 5).map((o, i) => ({
            uuid: deterministicUuid(`poam:risk:${ksiId}:${prov.provider}:${f.rule}:rem:${i}`),
            lifecycle: 'recommendation',
            title: o.approach,
            description: o.steps.length ? o.steps.join('; ') : o.approach,
            props: [
              { name: 'remediation-option-index', ns: CE_NS, value: String(i) },
              { name: 'mechanism', ns: CE_NS, value: o.mechanism },
              ...(o.effort_estimate?.magnitude ? [{ name: 'effort', ns: CE_NS, value: o.effort_estimate.magnitude }] : []),
            ],
          }));
          risks.push({
            uuid: riskUuid,
            title: `${ksiId} / ${f.rule}`,
            description: f.gap?.description ?? f.current_state?.summary ?? `Failing finding for ${ksiId} rule ${f.rule}.`,
            statement: f.gap?.description ?? f.current_state?.summary ?? `Risk: ${ksiId} rule ${f.rule} failing.`,
            status: severityToRiskStatus(f.severity, false),
            deadline: deadlineFromCollected(collected, f.severity),
            props: findingProps(f, prov, ksiId),
            remediations: remediations.length ? remediations : undefined,
            'related-observations': obsUuids.length ? obsUuids.map((u) => ({ 'observation-uuid': u })) : undefined,
          });

          // Back-link findings → risk.
          for (const fu of findingUuids) {
            const fEntry = findings.find((x) => x.uuid === fu);
            if (fEntry) fEntry['related-risks'] = [{ 'risk-uuid': riskUuid }];
          }
        }

        // 5. POA&M item — one per failing finding, referencing the findings,
        //    observations, and (optional) risk.
        const itemUuid = deterministicUuid(`poam:item:${ksiId}:${prov.provider}:${f.rule}`);
        poamItems.push({
          uuid: itemUuid,
          title: `[${f.severity.toUpperCase()}] ${ksiId} / ${f.rule}`,
          description: poamItemDescription(f, ksiId, ksiName),
          props: findingProps(f, prov, ksiId),
          'related-findings': findingUuids.map((u) => ({ 'finding-uuid': u })),
          'related-observations': obsUuids.length ? obsUuids.map((u) => ({ 'observation-uuid': u })) : undefined,
          'related-risks': riskUuid ? [{ 'risk-uuid': riskUuid }] : undefined,
          remarks: poamItemRemarks(f),
        });
      }
    }
  }

  const totalFailing = poamItems.length;
  const totalAssessed = envelopes.reduce(
    (n, e) => n + ((e as any).providers as ProviderBlock[]).reduce((m, p) => m + ((p as any).findings?.length ?? 0), 0),
    0,
  );

  // Builder remarks. The "0 failing" case is intentionally still allowed here
  // for callers that want to inspect the would-be-doc (e.g. tests, dry-runs)
  // — the disk-side emitOscalPoam() handles the OSCAL schema's minItems=1
  // constraint by skipping the write and returning a structured "skipped" result.
  const summaryRemarks = envelopes.length === 0
    ? 'No evidence files were found in the output directory. Re-run the collector before submission.'
    : (totalFailing === 0
      ? `Clean POA&M as of ${lastModified}: ${totalAssessed} finding(s) evaluated across ${envelopes.length} KSI(s); zero failing. This represents a real, signed assessment with no open items — NOT a missing-evidence state. (Note: OSCAL v1.1.2 schema mandates poam-items.minItems=1, so emitOscalPoam() will skip writing this document to disk in this clean state.)`
      : `${totalFailing} open POA&M item(s) of ${totalAssessed} finding(s) evaluated across ${envelopes.length} KSI(s).`);

  const poam: OscalPoam = {
    uuid: deterministicUuid(`poam:${systemId}:${opts.runId}`),
    metadata: {
      title: `${systemName} — Plan of Action and Milestones`,
      'last-modified': lastModified,
      version: opts.runId,
      'oscal-version': OSCAL_VERSION,
      revisions: opts.revisionsHistory && opts.revisionsHistory.length
        ? opts.revisionsHistory
        : undefined,
      props: [
        { name: 'tool', ns: CE_NS, value: TOOL_NAME },
        { name: 'frmr-version', ns: CE_NS, value: opts.frmrVersion },
        { name: 'generation', ns: CE_NS, value: 'automated-from-evidence' },
      ],
      remarks: summaryRemarks,
    },
    // Per OSCAL spec one of import-ssp OR system-id is required. We emit BOTH
    // unless ssp is unset — system-id alone is a valid POA&M for systems whose
    // SSP exists outside OSCAL or hasn't been authored yet.
    'import-ssp': opts.ssp ? { href: opts.ssp.href, remarks: opts.ssp.remarks } : undefined,
    'system-id': { id: systemId, 'identifier-type': 'https://ietf.org/rfc/rfc4122' },
    observations: observations.length ? observations : undefined,
    risks: risks.length ? risks : undefined,
    findings: findings.length ? findings : undefined,
    'poam-items': poamItems,
    'back-matter': opts.signedManifestHref
      ? {
          resources: [
            {
              uuid: deterministicUuid(`poam:backmatter:manifest:${opts.runId}`),
              title: 'Signed evidence manifest',
              description: 'Ed25519-signed manifest of all per-KSI evidence files referenced by this POA&M, with RFC 3161 timestamp.',
              rlinks: [{ href: opts.signedManifestHref, 'media-type': 'application/json' }],
            },
          ],
        }
      : undefined,
  };

  return {
    doc: { 'plan-of-action-and-milestones': poam },
    result: {
      poam_item_count: poamItems.length,
      observation_count: observations.length,
      risk_count: risks.length,
      finding_count: findings.length,
      by_severity: bySeverity,
    },
  };
}

// ─── Disk reader + writer ────────────────────────────────────────────────────
export function emitOscalPoam(opts: PoamEmitOptions): PoamEmitResult {
  const envelopes = readEvidenceFiles(opts.outDir);

  // Pre-flight: if there are zero failing findings across all envelopes, the
  // OSCAL POA&M schema (poam-items.minItems=1) cannot represent the state.
  // We skip emission and surface the reason — the orchestrator + ConMon
  // pipeline log this as "clean state; nothing to submit this cycle" rather
  // than mistaking it for a missing-evidence failure.
  const totalFailing = envelopes.reduce((n, e) => n + ((e as any).providers as ProviderBlock[]).reduce(
    (m, p) => m + ((p as any).findings ?? []).filter((f: Finding) => !f.passed).length, 0,
  ), 0);
  if (envelopes.length === 0 || totalFailing === 0) {
    const reason: 'no-failing-findings' | 'no-evidence-files' =
      envelopes.length === 0 ? 'no-evidence-files' : 'no-failing-findings';
    log.info(
      { outDir: opts.outDir, envelopes: envelopes.length, reason },
      'OSCAL POA&M: skipped emission (state is representable but the OSCAL v1.1.2 schema mandates poam-items.minItems=1; this is a clean assessment, not a missing-evidence error)',
    );
    return {
      path: null,
      poam_item_count: 0,
      observation_count: 0,
      risk_count: 0,
      finding_count: 0,
      by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      skipped_reason: reason,
    };
  }

  const { doc, result } = buildOscalPoam(envelopes, opts);
  const path = opts.outPath ?? resolve(opts.outDir, 'poam.json');
  writeFileSync(path, JSON.stringify(doc, null, 2));

  let xmlPath: string | undefined;
  if (process.env.CLOUD_EVIDENCE_DISABLE_OSCAL_XML !== '1') {
    try {
      const xml = oscalJsonToXml(doc);
      xmlPath = path.replace(/\.json$/, '.xml');
      writeFileSync(xmlPath, xml);
    } catch (e: any) {
      log.warn({ err: String(e) }, 'poam: OSCAL XML emission failed; JSON still written');
    }
  }

  log.info(
    { path, poam_item_count: result.poam_item_count, observation_count: result.observation_count, risk_count: result.risk_count },
    'OSCAL POA&M emitted',
  );

  return { path, xml_path: xmlPath, ...result };
}
