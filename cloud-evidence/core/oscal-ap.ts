/**
 * OSCAL 1.1.2 Assessment Plan (SAP) emitter — LOOP-A.A2.
 *
 * Generates an OSCAL Assessment Plan conforming to the NIST OSCAL 1.1.2
 * assessment-plan model:
 *
 *   https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-plan/json-reference/
 *   https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/assessment-plan/
 *
 * Why this exists:
 *   The OSCAL chain SSP → AP → AR is mandatory: the AR must Import-AP, and
 *   the AP must Import-SSP (min/max=1). Without an AP, our AR and POA&M are
 *   floating without a documented assessment scope. The Assessment Plan is
 *   what the 3PAO authors to describe WHAT they will assess, by WHAT
 *   methods, against WHICH controls — typically delivered as a Word .docx
 *   today, but RFC-0024 mandates OSCAL JSON for 20x submissions.
 *
 *   This emitter bootstraps a draft AP from the same evidence the SSP and
 *   AR use, so the 3PAO has a populated starting point that they can refine
 *   and sign rather than authoring from scratch. The 3PAO remains the
 *   author-of-record; this is a draft, not a sign-off.
 *
 * Schema-required structure (per the committed v1.1.2 schema):
 *   assessment-plan (required: uuid, metadata, import-ssp, reviewed-controls)
 *     uuid                            ← deterministic from systemId+runId
 *     metadata (required: title, last-modified, version, oscal-version)
 *     import-ssp { href }   REQUIRED  ← min/max=1, ties AP to its SSP
 *     local-definitions               ← assessment-method definitions
 *     terms-and-conditions            ← reference to the RoE
 *     reviewed-controls (REQUIRED)    ← control-selections from the baseline
 *     assessment-subjects[]           ← from real inventory.json
 *     assessment-assets               ← cloud-evidence collector + tracker +
 *                                       3PAO tools as components/platforms
 *     tasks[]                         ← scoping/discovery/testing/reporting
 *     back-matter                     ← signed manifest + RoE + sampling
 *                                       methodology + SSP cross-references
 *
 * Mapping (cloud-evidence → OSCAL AP):
 *   FedRAMP baseline (level)       → reviewed-controls.control-selections[]
 *                                     (one select-control-by-id per baseline
 *                                      control)
 *   ksi-map                        → local-definitions.assessment-methods[]
 *                                     (one assessment-method per registered
 *                                      KSI, naming the rule set the method
 *                                      will execute against)
 *   inventory.json components      → assessment-subjects.include-subjects[]
 *                                     (one subject-reference per component)
 *   providers + tracker            → assessment-assets.components[] +
 *                                     assessment-platforms[]
 *   sampling methodology           → back-matter.resources (links to the
 *                                     sampling plan JSON LOOP-F.F3 emits)
 *
 * REO compliance (cloud-evidence/CLAUDE.md):
 *   - No fabricated narrative. When an opts field is missing (no operator-
 *     provided ROE href, no sampling methodology supplied yet), the emitter
 *     produces a `REQUIRES-OPERATOR-INPUT:` marker (consistent with the
 *     SSP-1 pattern) rather than substituting a default that looks like
 *     real content.
 *   - Every reviewed-control comes from the real NIST baseline
 *     (`buildControlBenchmark`) at the impact tier — no synthetic control
 *     IDs.
 *   - Every assessment-subject component is derived from the real
 *     inventory.json the orchestrator already emits (LOOP-A.A2 doesn't
 *     synthesize subjects).
 *   - Deterministic UUIDs via oscal.ts so re-emission is byte-stable on
 *     identical inputs.
 *
 * Pure builder (`buildOscalAp`) + disk reader/emitter (`emitOscalAp`).
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import type { ImpactTier } from './envelope.ts';
import { buildControlBenchmark, type ControlBenchmark } from './control-benchmark.ts';
import { deterministicUuid } from './oscal.ts';
import { oscalJsonToXml } from './oscal-xml.ts';
import { log } from './log.ts';

const OSCAL_VERSION = '1.1.2';
const TOOL_NAME = 'fedramp-20x-cloud-evidence';
const CE_NS = 'urn:fedramp:cloud-evidence';

// ─── OSCAL type interfaces ───────────────────────────────────────────────────
interface OscalProp { name: string; ns?: string; value: string; class?: string }
interface OscalLink { href: string; rel?: string; text?: string }

interface OscalRole { id: string; title: string }
interface OscalParty { uuid: string; type: 'organization' | 'person'; name: string }

interface OscalMetadata {
  title: string;
  published?: string;
  'last-modified': string;
  version: string;
  'oscal-version': string;
  roles?: OscalRole[];
  parties?: OscalParty[];
  props?: OscalProp[];
  links?: OscalLink[];
  remarks?: string;
}

interface OscalImportSsp { href: string; remarks?: string }

interface OscalSelectControl { 'control-id': string; 'statement-ids'?: string[] }
interface OscalControlSelection {
  description?: string;
  'include-controls'?: OscalSelectControl[];
  'include-all'?: Record<string, never>;
  'exclude-controls'?: OscalSelectControl[];
  remarks?: string;
}
interface OscalReviewedControls {
  description?: string;
  'control-selections': OscalControlSelection[];
  remarks?: string;
}

interface OscalActivity {
  // OSCAL v1.1.2 schema: `activity` is the canonical place to describe
  // assessment actions in AP local-definitions. Required: uuid, description.
  uuid: string;
  title?: string;
  description: string;
  props?: OscalProp[];
  links?: OscalLink[];
  steps?: Array<{
    uuid: string;
    title?: string;
    description: string;
    props?: OscalProp[];
    'reviewed-controls'?: OscalReviewedControls;
    remarks?: string;
  }>;
  'related-controls'?: { 'control-selections': OscalControlSelection[] };
  remarks?: string;
}

interface OscalLocalObjective {
  'control-id': string;
  description?: string;
  parts: Array<{
    uuid?: string;
    name: string;
    title?: string;
    prose?: string;
    props?: OscalProp[];
  }>;
  remarks?: string;
}

interface OscalLocalDefinitions {
  components?: Array<{
    uuid: string;
    type: string;
    title: string;
    description: string;
    status: { state: 'operational' | 'under-development' | 'disposition' | 'other' };
    props?: OscalProp[];
  }>;
  'inventory-items'?: Array<{
    uuid: string;
    description: string;
    props?: OscalProp[];
  }>;
  'objectives-and-methods'?: OscalLocalObjective[];
  activities?: OscalActivity[];
  remarks?: string;
}

interface OscalSubjectReference {
  'subject-uuid': string;
  type: 'component' | 'inventory-item' | 'location' | 'party' | 'user';
  title?: string;
  props?: OscalProp[];
}

interface OscalAssessmentSubject {
  type: 'component' | 'inventory-item' | 'location' | 'party' | 'user';
  description?: string;
  'include-all'?: Record<string, never>;
  'include-subjects'?: OscalSubjectReference[];
  'exclude-subjects'?: OscalSubjectReference[];
  remarks?: string;
}

interface OscalAssessmentPlatform {
  uuid: string;
  title?: string;
  props?: OscalProp[];
  links?: OscalLink[];
  'uses-components'?: Array<{ 'component-uuid': string; props?: OscalProp[] }>;
  remarks?: string;
}

interface OscalAssessmentAssets {
  components?: Array<{
    uuid: string;
    type: string;
    title: string;
    description: string;
    status: { state: 'operational' | 'under-development' | 'disposition' | 'other' };
    props?: OscalProp[];
  }>;
  'assessment-platforms': OscalAssessmentPlatform[];
}

interface OscalTask {
  uuid: string;
  type: 'milestone' | 'action';
  title: string;
  description?: string;
  props?: OscalProp[];
  links?: OscalLink[];
  timing?: { 'on-date'?: { date: string }; 'within-date-range'?: { start: string; end: string } };
  'associated-activities'?: Array<{ 'activity-uuid': string; subjects?: OscalAssessmentSubject[] }>;
  remarks?: string;
}

interface OscalBackMatterResource {
  uuid: string;
  title: string;
  description?: string;
  rlinks?: Array<{ href: string; 'media-type'?: string }>;
  remarks?: string;
}

interface OscalTermsAndConditions {
  parts?: Array<{ name: string; title?: string; prose?: string }>;
}

interface OscalAssessmentPlan {
  uuid: string;
  metadata: OscalMetadata;
  'import-ssp': OscalImportSsp;
  'local-definitions'?: OscalLocalDefinitions;
  'terms-and-conditions'?: OscalTermsAndConditions;
  'reviewed-controls': OscalReviewedControls;
  'assessment-subjects'?: OscalAssessmentSubject[];
  'assessment-assets'?: OscalAssessmentAssets;
  tasks?: OscalTask[];
  'back-matter'?: { resources: OscalBackMatterResource[] };
}

// ─── Public options + result ─────────────────────────────────────────────────
export interface ApEmitOptions {
  /** Directory containing KSI-*.json evidence + inventory.json. */
  outDir: string;
  /** Where to write the AP JSON. Defaults to `${outDir}/ap.json`. */
  outPath?: string;
  /** Run id — captured in metadata.version. */
  runId: string;
  /** FRMR catalog version — captured in metadata.props. */
  frmrVersion: string;
  /** Impact tier — drives the FedRAMP baseline scope. */
  impactLevel: ImpactTier;
  /** System the AP describes. */
  systemId?: string;
  systemName?: string;
  /**
   * REQUIRED by OSCAL spec — Import-SSP (min/max=1). The href references
   * the SSP this AP assesses. Defaults to "ssp.json" (local) when the SSP
   * is co-emitted in the same orchestrator run. Operator-supplied via
   * --ap-ssp-href.
   */
  sspHref?: string;
  /** Optional ROE reference (link in back-matter). */
  roeHref?: string;
  /** Optional sampling methodology reference (link in back-matter). */
  samplingMethodologyHref?: string;
  /** Optional 3PAO organization name (recorded as a metadata party). */
  thirdPartyAssessorName?: string;
  /** Optional CSP organization name. */
  organizationName?: string;
  /** Providers the AP scopes (drives the leveraged-component subjects). */
  providers?: Array<'aws' | 'gcp' | 'azure'>;
  /**
   * Optional task plan. When omitted, the emitter generates a
   * standard 4-task FedRAMP assessment plan (scoping → discovery →
   * testing → reporting) with `REQUIRES-OPERATOR-INPUT:` markers in
   * the timing fields (the 3PAO must commit to dates).
   */
  tasks?: Array<{
    title: string;
    description: string;
    type?: 'milestone' | 'action';
    startDate?: string;
    endDate?: string;
  }>;
}

export interface ApEmitResult {
  path: string;
  /** XML path, if emitted. */
  xml_path?: string;
  /** Count of controls reviewed (=baseline size). */
  reviewed_control_count: number;
  /** Count of activities registered (one per KSI in the ksi-map). */
  activity_count: number;
  /** Count of assessment-subjects (inventory-derived). */
  assessment_subject_count: number;
  /** Count of tasks in the plan. */
  task_count: number;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function readInventory(outDir: string): {
  components: Array<{ uuid: string; type: string; title: string; description: string }>;
  inventoryItems: Array<{ uuid: string; type: string; identifier: string; title: string }>;
} {
  const p = resolve(outDir, 'inventory.json');
  if (!existsSync(p)) return { components: [], inventoryItems: [] };
  let doc: any;
  try { doc = JSON.parse(readFileSync(p, 'utf8')); }
  catch { return { components: [], inventoryItems: [] }; }
  const assets: any[] = Array.isArray(doc?.assets) ? doc.assets : (Array.isArray(doc) ? doc : []);
  // Group by (provider, assetType) → one component per group.
  const componentMap = new Map<string, { provider: string; type: string; count: number }>();
  const items: ReturnType<typeof readInventory>['inventoryItems'] = [];
  for (const a of assets) {
    const provider = a?.provider ?? 'unknown';
    const type = a?.assetType ?? a?.resource_type ?? 'unknown';
    const key = `${provider}:${type}`;
    const e = componentMap.get(key) ?? { provider, type, count: 0 };
    e.count++;
    componentMap.set(key, e);
    if (a?.uniqueId) {
      items.push({
        uuid: deterministicUuid(`ap:item:${a.uniqueId}`),
        type: 'inventory-item',
        identifier: a.uniqueId,
        title: a?.name ?? a?.uniqueId,
      });
    }
  }
  const components = [...componentMap.values()].map((c) => ({
    uuid: deterministicUuid(`ap:component:${c.provider}:${c.type}`),
    type: 'service',
    title: `${c.provider}:${c.type}`,
    description: `${c.count} ${c.type} resource(s) in ${c.provider}.`,
  }));
  return { components, inventoryItems: items };
}

function loadKsiMap(): string[] {
  // Re-read the registered KSI ids from ksi-map.ts. This mirrors the trick
  // the extract-frmr-requirements.mjs script uses (grep the source) so we
  // don't depend on importing the actual map (which would pull in every
  // provider module).
  const p = resolve(import.meta.dirname ?? '', 'ksi-map.ts');
  try {
    const src = readFileSync(p, 'utf8');
    const ids = new Set<string>();
    for (const m of src.matchAll(/^\s*'(KSI-[A-Z]+-[A-Z]+)'\s*:/gm)) ids.add(m[1]!);
    return [...ids].sort();
  } catch {
    return [];
  }
}

function makeKsiActivities(ksiIds: string[]): OscalActivity[] {
  // AP local-definitions.activities[] is the canonical OSCAL v1.1.2 place to
  // describe assessment actions tied to controls. One activity per registered
  // KSI. Each activity carries method=TEST (the cloud-evidence collector is a
  // TEST-method action per NIST 800-53A Rev 5).
  return ksiIds.map((ksiId) => ({
    uuid: deterministicUuid(`ap:activity:${ksiId}`),
    title: `Run ${ksiId} collector`,
    description: `Automated cloud-evidence collection for ${ksiId}. The collector invokes the cloud SDK calls cited in the per-KSI evidence file's providers[].evidence[].source entries, evaluates each rule, and records pass/fail findings in a signed envelope. Method type: TEST per NIST SP 800-53A Rev 5.`,
    props: [
      { name: 'method', ns: CE_NS, value: 'TEST' },
      { name: 'ksi-id', ns: CE_NS, value: ksiId },
      { name: 'automated', ns: CE_NS, value: 'true' },
    ],
  }));
}

const PROVIDER_LABEL: Record<'aws' | 'gcp' | 'azure', { full: string; short: string }> = {
  aws: { full: 'Amazon Web Services (leveraged authorization)', short: 'AWS' },
  gcp: { full: 'Google Cloud Platform (leveraged authorization)', short: 'GCP' },
  azure: { full: 'Microsoft Azure (leveraged authorization)', short: 'Azure' },
};

function makeAssessmentAssets(providers: Array<'aws' | 'gcp' | 'azure'>, systemId: string): OscalAssessmentAssets {
  // The cloud-evidence collector itself is the primary assessment tool.
  // 3PAO's external tools (Tenable, Wiz, etc.) are NOT modeled here — the
  // 3PAO adds them when they refine the draft.
  const collectorUuid = deterministicUuid(`ap:asset:collector:${systemId}`);
  const trackerUuid = deterministicUuid(`ap:asset:tracker:${systemId}`);
  const components: NonNullable<OscalAssessmentAssets['components']> = [
    {
      uuid: collectorUuid,
      type: 'software',
      title: 'cloud-evidence collector',
      description: 'Read-only collector that invokes AWS / GCP / Azure SDK APIs to capture FedRAMP 20x KSI evidence. Emits per-KSI signed JSON envelopes + OSCAL Assessment Results + this Assessment Plan.',
      status: { state: 'operational' },
      props: [
        { name: 'tool', ns: CE_NS, value: TOOL_NAME },
        { name: 'method', ns: CE_NS, value: 'TEST' },
      ],
    },
    {
      uuid: trackerUuid,
      type: 'software',
      title: 'cloud-evidence tracker',
      description: 'Local-first web tracker that captures process-artifact KSIs (CMP, IRP, ISCP, etc.) and supports operator + 3PAO sign-off workflows. Provides EXAMINE-method evidence for KSIs that cannot be machine-validated.',
      status: { state: 'operational' },
      props: [
        { name: 'tool', ns: CE_NS, value: 'fedramp-20x-tracker' },
        { name: 'method', ns: CE_NS, value: 'EXAMINE' },
      ],
    },
  ];
  // Per-provider leveraged components.
  for (const p of providers) {
    const lbl = PROVIDER_LABEL[p];
    components.push({
      uuid: deterministicUuid(`ap:asset:leveraged:${p}:${systemId}`),
      type: 'service',
      title: lbl.full,
      description: `Underlying ${lbl.short} cloud infrastructure. Inheritance: many control requirements are inherited from this provider's existing FedRAMP authorization (verify customer-responsibility split in the CRM).`,
      status: { state: 'operational' },
      props: [
        { name: 'leveraged-authorization', ns: CE_NS, value: p },
      ],
    });
  }
  return {
    components,
    'assessment-platforms': [
      {
        uuid: deterministicUuid(`ap:platform:cloud-evidence:${systemId}`),
        title: 'cloud-evidence assessment platform',
        'uses-components': [
          { 'component-uuid': collectorUuid },
          { 'component-uuid': trackerUuid },
        ],
        props: [
          { name: 'fedramp-20x-aligned', ns: CE_NS, value: 'true' },
        ],
      },
    ],
  };
}

function makeDefaultTasks(): NonNullable<ApEmitOptions['tasks']> {
  // Standard 4-phase FedRAMP assessment. Dates are intentionally omitted —
  // they're 3PAO-supplied. The emitted task carries a REQUIRES-OPERATOR-INPUT
  // marker in remarks per the REO rule.
  return [
    { title: 'Phase 1 — Scoping', description: 'Confirm authorization boundary, system categorization (FIPS 199), and the assessment subject list with the CSP. Review the SSP for completeness.', type: 'milestone' },
    { title: 'Phase 2 — Discovery', description: 'Run cloud-evidence collectors across all in-scope providers. Capture inventory + per-KSI evidence + Appendix M workbook. Verify the signed manifest.', type: 'action' },
    { title: 'Phase 3 — Testing', description: 'Execute hybrid and process-artifact controls via the tracker (EXAMINE + INTERVIEW methods). Sample-test resources per the approved sampling methodology (Appendix B). Validate the OSCAL AR.', type: 'action' },
    { title: 'Phase 4 — Reporting', description: 'Compile the SAR (OSCAL AR), POA&M, and 3PAO recommendation letter. Submit the signed package to the FedRAMP secure repository.', type: 'milestone' },
  ];
}

// ─── Builder (pure) ──────────────────────────────────────────────────────────
export function buildOscalAp(benchmark: ControlBenchmark, opts: ApEmitOptions): {
  doc: { 'assessment-plan': OscalAssessmentPlan };
  result: Omit<ApEmitResult, 'path' | 'xml_path'>;
} {
  const systemId = opts.systemId || 'cloud-evidence-system';
  const systemName = opts.systemName || 'Cloud System';
  const lastModified = new Date().toISOString();
  const providers: Array<'aws' | 'gcp' | 'azure'> = opts.providers && opts.providers.length ? opts.providers : ['aws', 'gcp'];

  // ── Reviewed controls ─────────────────────────────────────────────────
  // One select-control-by-id per baseline control. (We do NOT use
  // include-all because the FedRAMP profile already tailors the baseline.)
  const reviewedControls: OscalReviewedControls = {
    description: `Controls reviewed during this assessment: the FedRAMP ${opts.impactLevel} baseline (${benchmark.controls.length} controls) as tailored by the FedRAMP profile. Per 800-53A Rev 5, all controls are subject to assessment via the methods enumerated in local-definitions.assessment-methods.`,
    'control-selections': [
      {
        description: `FedRAMP Rev5 ${opts.impactLevel} baseline (${benchmark.controls.length} controls).`,
        'include-controls': benchmark.controls.map((c) => ({ 'control-id': c.id })),
      },
    ],
  };

  // ── Local definitions ─────────────────────────────────────────────────
  // Per the OSCAL v1.1.2 AP schema, local-definitions accepts: components,
  // inventory-items, users, objectives-and-methods, activities, remarks.
  // We use `activities[]` to register one assessment activity per KSI
  // (the canonical home for assessment actions in the AP model).
  const ksiIds = loadKsiMap();
  const localDefinitions: OscalLocalDefinitions = {
    activities: makeKsiActivities(ksiIds),
  };

  // ── Assessment subjects ──────────────────────────────────────────────
  // The subject list is derived from real inventory (inventory.json).
  // If inventory hasn't been emitted yet, the emitter falls back to an
  // include-all subject group with a REQUIRES-OPERATOR-INPUT note.
  const inventory = readInventory(opts.outDir);
  const subjects: OscalAssessmentSubject[] = [];
  if (inventory.components.length > 0) {
    subjects.push({
      type: 'component',
      description: `${inventory.components.length} unique (provider × asset-type) component group(s) derived from out/inventory.json (run id: ${opts.runId}).`,
      'include-subjects': inventory.components.map((c) => ({
        'subject-uuid': c.uuid,
        type: 'component',
        title: c.title,
      })),
    });
  }
  if (inventory.inventoryItems.length > 0) {
    subjects.push({
      type: 'inventory-item',
      description: `${inventory.inventoryItems.length} discrete inventory item(s) from out/inventory.json. Sampling per Appendix B may reduce the testing population — full inventory is in scope for review.`,
      'include-subjects': inventory.inventoryItems.slice(0, 1000).map((i) => ({
        'subject-uuid': i.uuid,
        type: 'inventory-item',
        title: i.title,
        props: [{ name: 'identifier', ns: CE_NS, value: i.identifier }],
      })),
    });
  }
  if (subjects.length === 0) {
    subjects.push({
      type: 'component',
      description: 'REQUIRES-OPERATOR-INPUT: no inventory.json was found at emit-time. Run the orchestrator with --inventory-workbook first OR supply ApEmitOptions.providers so the AP can scope leveraged-authorization components. Until inventory is available, include-all is used as a broad fallback subject — the 3PAO will narrow this before testing begins.',
      'include-all': {},
    });
  }

  // ── Assessment assets ────────────────────────────────────────────────
  const assets = makeAssessmentAssets(providers, systemId);

  // ── Tasks ────────────────────────────────────────────────────────────
  const taskTemplates = opts.tasks && opts.tasks.length > 0 ? opts.tasks : makeDefaultTasks();
  const tasks: OscalTask[] = taskTemplates.map((t, i) => ({
    uuid: deterministicUuid(`ap:task:${systemId}:${i}:${t.title}`),
    type: t.type ?? 'action',
    title: t.title,
    description: t.description,
    timing: (t.startDate && t.endDate)
      ? { 'within-date-range': { start: t.startDate, end: t.endDate } }
      : undefined,
    remarks: (t.startDate && t.endDate)
      ? undefined
      : 'REQUIRES-OPERATOR-INPUT: timing.within-date-range not supplied. The 3PAO must commit to start + end dates before the AP is finalized. Pass dates via ApEmitOptions.tasks[].{startDate,endDate} or the --ap-task-dates flag.',
  }));

  // ── Terms and conditions ─────────────────────────────────────────────
  const tc: OscalTermsAndConditions = {
    parts: [
      {
        name: 'rules-of-engagement',
        title: 'Rules of Engagement',
        prose: opts.roeHref
          ? `Rules of Engagement: see back-matter resource referenced by this AP (href: ${opts.roeHref}).`
          : 'REQUIRES-OPERATOR-INPUT: Rules of Engagement document href not supplied. The 3PAO and CSP must sign a RoE before testing begins. Pass --ap-roe-href to populate this reference.',
      },
      {
        name: 'sampling-methodology',
        title: 'Sampling Methodology (Appendix B)',
        prose: opts.samplingMethodologyHref
          ? `Sampling methodology: see back-matter resource referenced by this AP (href: ${opts.samplingMethodologyHref}). Per FedRAMP Rev5 ConMon Vulnerability Scanning guidance, externally-accessible system components are scanned at 100%; internal-only components may be sampled with AO approval.`
          : 'REQUIRES-OPERATOR-INPUT: sampling methodology not supplied. Per FedRAMP Rev5, externally-accessible components MUST be 100% scanned; sampling is permitted for internal-only assets with AO approval. LOOP-F.F3 will emit a draft sampling plan; until then, pass --ap-sampling-href to reference the operator-supplied appendix.',
      },
    ],
  };

  // ── Back-matter resources ────────────────────────────────────────────
  const backMatterResources: OscalBackMatterResource[] = [];
  if (opts.roeHref) {
    backMatterResources.push({
      uuid: deterministicUuid(`ap:bm:roe:${systemId}`),
      title: 'Rules of Engagement',
      description: '3PAO/CSP-signed Rules of Engagement covering the assessment scope, scan windows, and escalation contacts.',
      rlinks: [{ href: opts.roeHref }],
    });
  }
  if (opts.samplingMethodologyHref) {
    backMatterResources.push({
      uuid: deterministicUuid(`ap:bm:sampling:${systemId}`),
      title: 'Sampling Methodology (Appendix B)',
      description: '3PAO sampling plan: which asset classes are sampled, stratification basis, percentage per class, AO approval timestamp.',
      rlinks: [{ href: opts.samplingMethodologyHref }],
    });
  }
  // Always reference the signed evidence manifest in the back-matter when
  // a run id is known — it's the audit-trail anchor.
  backMatterResources.push({
    uuid: deterministicUuid(`ap:bm:manifest:${opts.runId}`),
    title: 'Signed evidence manifest',
    description: 'Ed25519-signed manifest enumerating every per-KSI evidence file the AP authorizes review of, with RFC 3161 timestamp.',
    rlinks: [{ href: 'manifest.json', 'media-type': 'application/json' }],
  });

  // ── Metadata ─────────────────────────────────────────────────────────
  const parties: OscalParty[] = [];
  if (opts.organizationName) {
    parties.push({ uuid: deterministicUuid(`org:csp:${opts.organizationName}`), type: 'organization', name: opts.organizationName });
  }
  if (opts.thirdPartyAssessorName) {
    parties.push({ uuid: deterministicUuid(`org:3pao:${opts.thirdPartyAssessorName}`), type: 'organization', name: opts.thirdPartyAssessorName });
  }

  const ap: OscalAssessmentPlan = {
    uuid: deterministicUuid(`ap:${systemId}:${opts.runId}:${opts.impactLevel}`),
    metadata: {
      title: `${systemName} — Assessment Plan (FedRAMP ${opts.impactLevel})`,
      'last-modified': lastModified,
      version: opts.runId,
      'oscal-version': OSCAL_VERSION,
      roles: [
        { id: 'system-owner', title: 'System Owner' },
        { id: 'assessor', title: 'Assessor (3PAO)' },
        { id: 'authorizing-official', title: 'Authorizing Official' },
      ],
      parties: parties.length ? parties : undefined,
      props: [
        { name: 'tool', ns: CE_NS, value: TOOL_NAME },
        { name: 'frmr-version', ns: CE_NS, value: opts.frmrVersion },
        { name: 'generation', ns: CE_NS, value: 'draft-bootstrap-from-automated-evidence' },
        { name: 'impact-level', ns: CE_NS, value: opts.impactLevel },
      ],
      remarks:
        'DRAFT — bootstrapped by fedramp-20x-cloud-evidence from automated cloud-evidence inventory + ' +
        'ksi-map + NIST 800-53 Rev5 baseline. The 3PAO refines this draft (assessment-method tailoring, ' +
        'task dates, sampling-methodology details) and signs the finalized AP before testing begins.',
    },
    'import-ssp': {
      href: opts.sspHref ?? 'ssp.json',
      remarks: opts.sspHref ? undefined : 'Default local SSP reference. Override with --ap-ssp-href if the SSP lives elsewhere (e.g., a previously-emitted submission package or a remote OSCAL endpoint).',
    },
    'local-definitions': localDefinitions,
    'terms-and-conditions': tc,
    'reviewed-controls': reviewedControls,
    'assessment-subjects': subjects,
    'assessment-assets': assets,
    tasks,
    'back-matter': { resources: backMatterResources },
  };

  return {
    doc: { 'assessment-plan': ap },
    result: {
      reviewed_control_count: benchmark.controls.length,
      activity_count: localDefinitions.activities?.length ?? 0,
      assessment_subject_count: subjects.reduce((n, s) => n + (s['include-subjects']?.length ?? (s['include-all'] ? -1 : 0)), 0),
      task_count: tasks.length,
    },
  };
}

// ─── Disk reader + writer ────────────────────────────────────────────────────
export function emitOscalAp(opts: ApEmitOptions): ApEmitResult {
  // Build the FedRAMP baseline benchmark for the impact level. The benchmark
  // function takes outDir + opts; when no evidence files are present, it
  // returns a benchmark with all baseline controls in 'not-assessed' state —
  // the controls list is still complete, which is all the AP needs.
  const benchmark = buildControlBenchmark(opts.outDir, { framework: 'rev5', level: opts.impactLevel });

  const { doc, result } = buildOscalAp(benchmark, opts);

  const path = opts.outPath ?? resolve(opts.outDir, 'ap.json');
  writeFileSync(path, JSON.stringify(doc, null, 2));

  let xmlPath: string | undefined;
  if (process.env.CLOUD_EVIDENCE_DISABLE_OSCAL_XML !== '1') {
    try {
      const xml = oscalJsonToXml(doc);
      xmlPath = path.replace(/\.json$/, '.xml');
      writeFileSync(xmlPath, xml);
    } catch (e: any) {
      log.warn({ err: String(e) }, 'ap: OSCAL XML emission failed; JSON still written');
    }
  }

  log.info(
    { path, reviewed_control_count: result.reviewed_control_count, activity_count: result.activity_count, task_count: result.task_count },
    'OSCAL Assessment Plan emitted',
  );

  return { path, xml_path: xmlPath, ...result };
}
