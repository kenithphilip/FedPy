/**
 * OSCAL 1.1 Assessment Results emitter.
 *
 * Reads every EvidenceFile in `outDir` and emits a single
 * `assessment-results.json` document conforming to the NIST OSCAL 1.1
 * Assessment Results model:
 *
 *   https://pages.nist.gov/OSCAL/concepts/layer/assessment/assessment-results/
 *
 * Why this exists:
 *   FedRAMP 20x explicitly endorses OSCAL as the machine-readable interchange
 *   format. Paramify, eMASS, the FedRAMP Marketplace, and most modern GRC
 *   tooling can ingest OSCAL Assessment Results directly. By emitting OSCAL
 *   alongside our richer custom format we get:
 *     - Direct upload paths into existing FedRAMP tooling (no custom adapter).
 *     - Interoperability with auditor tooling (FedRAMP-IES, OpenControl, etc.).
 *     - A vendor-neutral artifact your 3PAO can validate against the public
 *       NIST schema.
 *
 * Mapping (cloud-evidence → OSCAL):
 *   EvidenceFile          → assessment-results.results[]
 *   Finding               → finding (with target.objective-id = ksi-id.rule)
 *   RawEvidence           → observation (one per raw SDK call)
 *   pass/fail             → target.status.state in {satisfied, not-satisfied}
 *   severity              → finding.props (custom property "severity")
 *   gap.affected_resources → finding.related-observations[].subjects[] (resource subjects)
 *   remediation.options[] → finding.props (links + steps as separate props for compactness)
 *
 * Limitations / pragmatic choices:
 *   - We synthesize a minimal `import-ap` reference because we don't actually
 *     consume an OSCAL Assessment Plan (FRMR is our source of truth). A real
 *     FedRAMP submission would need to either reference an existing AP UUID
 *     or generate one separately.
 *   - We embed remediation details in `finding.remarks` (Markdown) rather
 *     than via separate `risks[]` + `risk-response[]` entries — the latter
 *     is more semantically rich but bloats the output 3x. Configurable
 *     via `EVIDENCE_OSCAL_FULL_RISK=1` if a consumer wants the full risk
 *     model.
 */
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import type { EvidenceFile, Finding, ProviderBlock, RawEvidence, AffectedResource } from './envelope.ts';
import { log } from './log.ts';

const OSCAL_VERSION = '1.1.2';
const TOOL_NAME = 'fedramp-20x-cloud-evidence';
const TOOL_VERSION = '0.1.0';

/**
 * Generate a deterministic UUID v5-like identifier from a string.
 * OSCAL requires UUIDs everywhere; using deterministic IDs means re-running
 * the emitter on the same evidence produces a stable diff.
 */
export function deterministicUuid(seed: string): string {
  const h = createHash('sha256').update(seed).digest();
  // Format as a v4-shaped UUID; not technically v5 (would need namespace) but
  // structurally valid and stable.
  const bytes = h.subarray(0, 16);
  // RFC 4122 v4 markers (index access is safe: SHA-256 always produces 32 bytes)
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

interface OscalProp {
  name: string;
  ns?: string;
  value: string;
  class?: string;
}

interface OscalLink {
  href: string;
  rel?: string;
  text?: string;
}

interface OscalSubject {
  'subject-uuid'?: string;
  type: string;
  title?: string;
  remarks?: string;
  props?: OscalProp[];
}

interface OscalObservation {
  uuid: string;
  title?: string;
  description: string;
  props?: OscalProp[];
  methods: Array<'EXAMINE' | 'INTERVIEW' | 'TEST' | 'UNKNOWN'>;
  types?: string[];
  subjects?: OscalSubject[];
  'collected': string;
  remarks?: string;
}

interface OscalFinding {
  uuid: string;
  title: string;
  description: string;
  props?: OscalProp[];
  target: {
    type: 'objective-id' | 'statement-id';
    'target-id': string;
    status: { state: 'satisfied' | 'not-satisfied' | 'other'; reason?: string; remarks?: string };
    description?: string;
  };
  'related-observations'?: Array<{ 'observation-uuid': string }>;
  'related-risks'?: Array<{ 'risk-uuid': string }>;
  remarks?: string;
  links?: OscalLink[];
}

interface OscalResult {
  uuid: string;
  title: string;
  description: string;
  start: string;
  end?: string;
  props?: OscalProp[];
  'reviewed-controls': {
    'control-selections': Array<{
      description?: string;
      'include-controls'?: Array<{ 'control-id': string }>;
    }>;
  };
  observations?: OscalObservation[];
  findings?: OscalFinding[];
  'local-definitions'?: { remarks?: string };
}

interface OscalAssessmentResults {
  uuid: string;
  metadata: {
    title: string;
    'last-modified': string;
    version: string;
    'oscal-version': string;
    parties?: Array<{ uuid: string; type: 'organization' | 'person'; name: string }>;
    'responsible-parties'?: Array<{ 'role-id': string; 'party-uuids': string[] }>;
    props?: OscalProp[];
  };
  'import-ap': { href: string; remarks?: string };
  results: OscalResult[];
  'back-matter'?: { resources: Array<{ uuid: string; title: string; description?: string; rlinks?: OscalLink[] }> };
}

export interface OscalEmitOptions {
  outDir: string;
  outPath?: string;
  runId: string;
  frmrVersion: string;
  organizationName?: string;
  assessmentPlanHref?: string;
}

export interface OscalEmitResult {
  path: string;
  result_count: number;
  finding_count: number;
  observation_count: number;
}

function evidenceFiles(dir: string): string[] {
  return readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .filter((f) => !['manifest.json', 'manifest.tst.json', 'pva-run-summary.json', 'previous-run-snapshot.json',
                     'findings.csv', 'report.html', 'diff-report.json', 'diff-report.html',
                     'assessment-results.json'].includes(f))
    .filter((f) => f.startsWith('KSI-'))
    .sort();
}

function rawToObservation(ksiId: string, providerBlock: ProviderBlock, evidence: RawEvidence): OscalObservation {
  const seed = `${ksiId}:${providerBlock.provider}:${providerBlock.account_id ?? providerBlock.project_id ?? '-'}:${evidence.source}:${evidence.captured_at}`;
  return {
    uuid: deterministicUuid(seed),
    title: evidence.source,
    description: `Evidence collected from ${providerBlock.provider} via SDK call "${evidence.source}".`,
    methods: ['EXAMINE'],
    types: ['evidence'],
    collected: evidence.captured_at,
    props: [
      { name: 'cloud-provider', value: providerBlock.provider, ns: 'urn:fedramp:cloud-evidence' },
      ...(providerBlock.account_id ? [{ name: 'aws-account-id', value: providerBlock.account_id, ns: 'urn:fedramp:cloud-evidence' as const }] : []),
      ...(providerBlock.project_id ? [{ name: 'gcp-project-id', value: providerBlock.project_id, ns: 'urn:fedramp:cloud-evidence' as const }] : []),
      { name: 'evidence-source', value: evidence.source, ns: 'urn:fedramp:cloud-evidence' },
    ],
  };
}

function affectedToSubject(ar: AffectedResource): OscalSubject {
  return {
    type: 'inventory-item',
    title: ar.name ?? ar.identifier,
    remarks: `${ar.type}: ${ar.identifier}`,
    props: [
      { name: 'asset-type', value: ar.type, ns: 'urn:fedramp:cloud-evidence' },
      { name: 'asset-id', value: ar.identifier, ns: 'urn:fedramp:cloud-evidence' },
      ...Object.entries(ar.tags ?? {}).map(([k, v]) => ({ name: `tag:${k}`, value: v, ns: 'urn:fedramp:cloud-evidence' as const })),
    ],
  };
}

function findingToOscal(
  ksiId: string,
  providerBlock: ProviderBlock,
  f: Finding,
  observationUuids: string[],
): OscalFinding {
  const seed = `${ksiId}:${providerBlock.provider}:${providerBlock.account_id ?? providerBlock.project_id ?? '-'}:${f.rule}`;
  const findingUuid = deterministicUuid(seed);

  const remarksParts: string[] = [
    `**Current state:** ${f.current_state.summary}`,
    `**Target state:** ${f.target_state.summary}`,
    `**Rationale:** ${f.target_state.rationale}`,
  ];

  if (!f.passed && f.gap) {
    remarksParts.push(`**Gap:** ${f.gap.description}`);
    if (f.gap.affected_resources.length > 0) {
      const resList = f.gap.affected_resources.slice(0, 10).map((r) => `- ${r.type}/${r.identifier}`).join('\n');
      remarksParts.push(`**Affected resources (${f.gap.affected_resources.length}):**\n${resList}${f.gap.affected_resources.length > 10 ? `\n…and ${f.gap.affected_resources.length - 10} more` : ''}`);
    }
  }
  if (f.remediation) {
    remarksParts.push(`**Remediation:** ${f.remediation.summary}`);
    for (const opt of f.remediation.options.slice(0, 5)) {
      const steps = opt.steps.map((s) => `  1. ${s}`).join('\n');
      remarksParts.push(`*Option (${opt.mechanism}):* ${opt.approach}\n${steps}`);
    }
  }
  if ((f.alternative_satisfiers ?? []).some((a) => a.detected)) {
    const detected = f.alternative_satisfiers!.filter((a) => a.detected).map((a) => a.via).join(', ');
    remarksParts.push(`**Alternative satisfier(s) detected:** ${detected}`);
  }

  const subjects = f.gap?.affected_resources?.map(affectedToSubject) ?? [];
  const subjectObservation: OscalObservation | null = subjects.length > 0
    ? {
        uuid: deterministicUuid(seed + ':resources'),
        title: `Affected resources for ${f.rule}`,
        description: `${subjects.length} resource(s) affected by ${f.rule}.`,
        methods: ['EXAMINE'],
        types: ['finding-evidence'],
        collected: new Date().toISOString(),
        subjects,
      }
    : null;
  const allObsUuids = [...observationUuids, ...(subjectObservation ? [subjectObservation.uuid] : [])];

  const links: OscalLink[] = (f.references ?? []).map((r) => ({ href: r.url, rel: 'reference', text: r.title }));

  return {
    uuid: findingUuid,
    title: `${f.rule} (${providerBlock.provider})`,
    description: f.current_state.summary,
    props: [
      { name: 'severity', value: f.severity, ns: 'urn:fedramp:cloud-evidence' },
      { name: 'rule-id', value: f.rule, ns: 'urn:fedramp:cloud-evidence' },
      ...(f.nist_controls ?? []).map((c) => ({ name: 'nist-control', value: c, ns: 'urn:fedramp:cloud-evidence' as const })),
    ],
    target: {
      type: 'objective-id',
      'target-id': ksiId,
      status: {
        state: f.passed ? 'satisfied' : 'not-satisfied',
        reason: f.passed ? undefined : f.gap?.description?.slice(0, 200),
      },
    },
    'related-observations': allObsUuids.map((u) => ({ 'observation-uuid': u })),
    remarks: remarksParts.join('\n\n'),
    links: links.length > 0 ? links : undefined,
  };
}

function evidenceToResult(ef: EvidenceFile): {
  result: OscalResult;
  extraObservations: OscalObservation[]; // observations attached to findings (resources) live here for top-level emission
} {
  const observations: OscalObservation[] = [];
  const findings: OscalFinding[] = [];
  const extraObservations: OscalObservation[] = [];

  for (const pb of ef.providers) {
    const obsUuidsByProvider: string[] = [];
    for (const ev of pb.evidence) {
      const obs = rawToObservation(ef.ksi_id, pb, ev);
      observations.push(obs);
      obsUuidsByProvider.push(obs.uuid);
    }
    for (const f of pb.findings) {
      const findingOscal = findingToOscal(ef.ksi_id, pb, f, obsUuidsByProvider);
      findings.push(findingOscal);
      // Also emit the synthesized subject observation if any related-observation
      // points to one we haven't added.
      const hasResourceObs = f.gap && f.gap.affected_resources && f.gap.affected_resources.length > 0;
      if (hasResourceObs) {
        const seed = `${ef.ksi_id}:${pb.provider}:${pb.account_id ?? pb.project_id ?? '-'}:${f.rule}:resources`;
        const uuid = deterministicUuid(seed);
        extraObservations.push({
          uuid,
          title: `Affected resources for ${f.rule}`,
          description: `${f.gap!.affected_resources.length} resource(s) affected by ${f.rule}.`,
          methods: ['EXAMINE'],
          types: ['finding-evidence'],
          collected: ef.collected_at,
          subjects: f.gap!.affected_resources.map(affectedToSubject),
        });
      }
    }
  }

  return {
    result: {
      uuid: deterministicUuid(`result:${ef.ksi_id}:${ef.run_id}`),
      title: `${ef.ksi_id} — ${ef.ksi_name}`,
      description: ef.ksi_statement,
      start: ef.collected_at,
      end: ef.collected_at,
      props: [
        { name: 'ksi-id', value: ef.ksi_id, ns: 'urn:fedramp:cloud-evidence' },
        { name: 'ksi-scope', value: ef.scope, ns: 'urn:fedramp:cloud-evidence' },
        { name: 'frmr-version', value: ef.frmr_version, ns: 'urn:fedramp:cloud-evidence' },
        { name: 'rollup-pass', value: String(ef.rollup.pass), ns: 'urn:fedramp:cloud-evidence' },
      ],
      'reviewed-controls': {
        'control-selections': [
          {
            description: `NIST 800-53 controls mapped to ${ef.ksi_id}`,
            'include-controls': (ef.nist_controls ?? []).map((c) => ({ 'control-id': c.toLowerCase().replace(/[^a-z0-9-]/g, '-') })),
          },
        ],
      },
      observations: [...observations, ...extraObservations],
      findings,
    },
    extraObservations,
  };
}

/**
 * Build & write OSCAL Assessment Results from every EvidenceFile in `outDir`.
 */
export function emitOscalAssessmentResults(opts: OscalEmitOptions): OscalEmitResult {
  const files = evidenceFiles(opts.outDir);
  const results: OscalResult[] = [];
  let totalFindings = 0;
  let totalObservations = 0;

  for (const f of files) {
    let ef: EvidenceFile;
    try {
      ef = JSON.parse(readFileSync(resolve(opts.outDir, f), 'utf8'));
    } catch (e: any) {
      log.warn({ event: 'oscal.skip_unparseable', file: f, err: e?.message });
      continue;
    }
    const { result } = evidenceToResult(ef);
    results.push(result);
    totalFindings += result.findings?.length ?? 0;
    totalObservations += result.observations?.length ?? 0;
  }

  const orgUuid = deterministicUuid(`org:${opts.organizationName ?? 'CSP'}`);
  const ar: OscalAssessmentResults = {
    uuid: deterministicUuid(`assessment-results:${opts.runId}`),
    metadata: {
      title: `cloud-evidence Assessment Results — run ${opts.runId}`,
      'last-modified': new Date().toISOString(),
      version: opts.runId,
      'oscal-version': OSCAL_VERSION,
      parties: opts.organizationName ? [{ uuid: orgUuid, type: 'organization', name: opts.organizationName }] : undefined,
      props: [
        { name: 'tool', value: TOOL_NAME, ns: 'urn:fedramp:cloud-evidence' },
        { name: 'tool-version', value: TOOL_VERSION, ns: 'urn:fedramp:cloud-evidence' },
        { name: 'frmr-version', value: opts.frmrVersion, ns: 'urn:fedramp:cloud-evidence' },
      ],
    },
    'import-ap': {
      href: opts.assessmentPlanHref ?? '#cloud-evidence-synthetic-ap',
      remarks: 'cloud-evidence does not consume an external OSCAL Assessment Plan; results are derived directly from FRMR KSI definitions.',
    },
    results,
  };

  // NIST OSCAL documents wrap the model in a top-level key — the schema's root
  // requires `assessment-results`. (Previously we wrote the inner object directly,
  // which isn't a schema-valid OSCAL document; OSC-1 validation surfaced this.)
  const outPath = opts.outPath ?? resolve(opts.outDir, 'assessment-results.json');
  writeFileSync(outPath, JSON.stringify({ 'assessment-results': ar }, null, 2));

  log.info({
    event: 'oscal.emitted',
    path: outPath,
    result_count: results.length,
    finding_count: totalFindings,
    observation_count: totalObservations,
  });

  return {
    path: outPath,
    result_count: results.length,
    finding_count: totalFindings,
    observation_count: totalObservations,
  };
}
