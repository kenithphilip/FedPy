/**
 * OSCAL 1.1 System Security Plan (SSP) emitter — SSP-1.
 *
 * Generates a **draft** OSCAL System Security Plan that conforms to the NIST
 * OSCAL 1.1.2 `system-security-plan` model:
 *
 *   https://pages.nist.gov/OSCAL/concepts/layer/implementation/ssp/
 *
 * Why this exists:
 *   A FedRAMP authorization package is anchored by the SSP. Authoring one by hand
 *   means filling in an `implemented-requirement` for every control in the
 *   baseline. This emitter bootstraps that document from the evidence we already
 *   collect: it rolls our KSI/FRR findings up to NIST 800-53 controls (via
 *   `buildControlBenchmark`) and pre-populates each control's implementation
 *   status + narrative, citing the KSIs and rules that produced the evidence.
 *
 *   The output is a *starting point* for a human SSP author, NOT a final SSP.
 *   Controls with no automated cloud evidence are emitted as `planned` with a
 *   remark to assess manually or document as inherited from the underlying CSP.
 *
 * Mapping (cloud-evidence → OSCAL SSP):
 *   FedRAMP baseline (level)        → import-profile.href + implemented-requirements set
 *   ControlBenchmark control        → implemented-requirement (one per baseline control)
 *   ControlStatus                   → implementation-status state
 *     satisfied            → implemented
 *     partially-satisfied  → partial
 *     not-satisfied        → planned
 *     not-assessed         → planned (+ remark: assess manually / inherited)
 *   addressed_by (KSIs/rules)       → by-component.description narrative
 *
 * Pure builder (`buildOscalSsp`) + a disk reader/emitter (`emitOscalSsp`).
 * Read-only; reuses the committed NIST baseline membership and control names.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import type { ImpactTier } from './envelope.ts';
import {
  buildControlBenchmark,
  type ControlBenchmark,
  type ControlResult,
  type ControlStatus,
} from './control-benchmark.ts';
import { deterministicUuid } from './oscal.ts';
import { oscalJsonToXml } from './oscal-xml.ts';
import { log } from './log.ts';

const OSCAL_VERSION = '1.1.2';
const TOOL_NAME = 'fedramp-20x-cloud-evidence';
const FEDRAMP_NS = 'https://fedramp.gov/ns/oscal';
const CE_NS = 'urn:fedramp:cloud-evidence';

/** Published FedRAMP Rev5 baseline OSCAL profiles (referenced by href; not fetched). */
const FEDRAMP_BASELINE_PROFILE: Record<ImpactTier, string> = {
  low: 'https://raw.githubusercontent.com/GSA/fedramp-automation/master/dist/content/rev5/baselines/json/FedRAMP_rev5_LOW-baseline_profile.json',
  moderate: 'https://raw.githubusercontent.com/GSA/fedramp-automation/master/dist/content/rev5/baselines/json/FedRAMP_rev5_MODERATE-baseline_profile.json',
  high: 'https://raw.githubusercontent.com/GSA/fedramp-automation/master/dist/content/rev5/baselines/json/FedRAMP_rev5_HIGH-baseline_profile.json',
};

type ImplState = 'implemented' | 'partial' | 'planned' | 'alternative' | 'not-applicable';

function statusToImplState(s: ControlStatus): ImplState {
  switch (s) {
    case 'satisfied': return 'implemented';
    case 'partially-satisfied': return 'partial';
    case 'not-satisfied': return 'planned';
    case 'not-assessed': return 'planned';
  }
}

interface OscalProp { name: string; ns?: string; value: string; class?: string }
interface OscalRole { id: string; title: string }
interface OscalImplStatus { state: ImplState; remarks?: string }

interface OscalByComponent {
  'component-uuid': string;
  uuid: string;
  description: string;
  props?: OscalProp[];
  'implementation-status'?: OscalImplStatus;
  remarks?: string;
}

interface OscalImplementedRequirement {
  uuid: string;
  'control-id': string;
  props?: OscalProp[];
  'by-components'?: OscalByComponent[];
  remarks?: string;
}

interface OscalComponent {
  uuid: string;
  type: string;
  title: string;
  description: string;
  purpose?: string;
  props?: OscalProp[];
  status: { state: 'under-development' | 'operational' | 'disposition' | 'other'; remarks?: string };
}

interface OscalSystemUser {
  uuid: string;
  title?: string;
  'role-ids'?: string[];
  description?: string;
}

/**
 * OSCAL `leveraged-authorization` — another authorized system from which this
 * system inherits capabilities (a common-control provider). Required fields per
 * the NIST OSCAL 1.1.2 SSP schema: uuid, title, party-uuid, date-authorized.
 */
interface OscalLeveragedAuthorization {
  uuid: string;
  title: string;
  'party-uuid': string;
  'date-authorized': string;
  props?: OscalProp[];
  links?: Array<{ href: string; rel?: string; text?: string }>;
  remarks?: string;
}

/**
 * Minimal subprocessor row the SSP needs to derive leveraged-authorizations
 * (from subprocessor-inventory.json, LOOP-J.J2). Only FedRAMP-authorized rows
 * with a real ISO date become leveraged-authorizations — a date is never
 * fabricated (REO).
 */
export interface LeveragedSubprocessorRow {
  name: string;
  fedramp_authorized?: 'yes' | 'no' | 'equivalency-attest';
  last_audit_date?: string;
  risk_tier?: string;
}

interface OscalInformationType {
  uuid: string;
  title: string;
  description: string;
  'confidentiality-impact'?: { base: string };
  'integrity-impact'?: { base: string };
  'availability-impact'?: { base: string };
}

interface OscalSsp {
  uuid: string;
  metadata: {
    title: string;
    'last-modified': string;
    version: string;
    'oscal-version': string;
    roles?: OscalRole[];
    parties?: Array<{ uuid: string; type: 'organization' | 'person'; name: string }>;
    'responsible-parties'?: Array<{ 'role-id': string; 'party-uuids': string[] }>;
    props?: OscalProp[];
    remarks?: string;
  };
  'import-profile': { href: string; remarks?: string };
  'system-characteristics': {
    'system-ids': Array<{ id: string; 'identifier-type'?: string }>;
    'system-name': string;
    description: string;
    'security-sensitivity-level'?: string;
    'system-information': { 'information-types': OscalInformationType[] };
    'security-impact-level'?: {
      'security-objective-confidentiality': string;
      'security-objective-integrity': string;
      'security-objective-availability': string;
    };
    status: { state: 'operational' | 'under-development' | 'under-major-modification' | 'disposition' | 'other'; remarks?: string };
    'authorization-boundary': { description: string };
    props?: OscalProp[];
  };
  'system-implementation': {
    'leveraged-authorizations'?: OscalLeveragedAuthorization[];
    users: OscalSystemUser[];
    components: OscalComponent[];
    remarks?: string;
  };
  'control-implementation': {
    description: string;
    'implemented-requirements': OscalImplementedRequirement[];
  };
  'back-matter'?: {
    resources: Array<{
      uuid: string;
      title?: string;
      description?: string;
      rlinks?: Array<{ href: string; 'media-type'?: string }>;
    }>;
  };
}

export interface SspSystemOptions {
  systemName?: string;
  systemId?: string;
  systemShortName?: string;
  systemDescription?: string;
  organizationName?: string;
  importProfileHref?: string;
  systemStatus?: OscalSsp['system-characteristics']['status']['state'];
  /** Providers in play — drive the leveraged infrastructure components. */
  providers?: Array<'aws' | 'gcp' | 'azure'>;
  /**
   * Operator-supplied authorization-boundary description. Per the REO standard
   * (cloud-evidence/CLAUDE.md), the system never substitutes a default that
   * looks like real data. If omitted, the SSP emits an explicit
   * REQUIRES-OPERATOR-INPUT marker naming the field, the consumer, and where
   * the operator provides it — so a 3PAO/PMO can see at-a-glance that the
   * boundary narrative needs to come from the system owner.
   */
  authorizationBoundaryDescription?: string;
  /**
   * Operator-supplied user role/responsibility entries for the SSP's
   * system-implementation.users[]. If omitted, the SSP emits an explicit
   * REQUIRES-OPERATOR-INPUT user entry under the assumed `admin` role,
   * making the gap visible rather than substituting fake user data.
   */
  userRoles?: Array<{ uuid?: string; title: string; roleIds: string[]; description: string }>;
  /**
   * Subprocessor rows (from subprocessor-inventory.json, LOOP-J.J2). Rows with
   * `fedramp_authorized === 'yes'` AND a real `last_audit_date` (YYYY-MM-DD)
   * become OSCAL `system-implementation.leveraged-authorizations[]` entries,
   * each with a backing organization party. Rows without a real date are
   * omitted rather than emitted with a fabricated date-authorized.
   */
  leveragedSubprocessors?: LeveragedSubprocessorRow[];
  /**
   * When set (LOOP-J.J3), add a `back-matter.resources[]` entry pointing at the
   * supply-chain risk register artifacts. emitOscalSsp() sets this when
   * out/supply-chain-risk-register.json is present.
   */
  supplyChainRegister?: { jsonHref: string; xlsxHref: string };
}

export interface SspBuildContext {
  runId: string;
  frmrVersion: string;
  impactLevel: ImpactTier;
}

export interface SspEmitOptions extends SspSystemOptions, SspBuildContext {
  outDir: string;
  outPath?: string;
}

export interface SspEmitResult {
  path: string;
  /**
   * Path to the XML representation, if emitted (OSC-3). Always emitted
   * alongside the JSON unless `CLOUD_EVIDENCE_DISABLE_OSCAL_XML=1` is set.
   */
  xml_path?: string;
  control_count: number;
  implemented: number;
  partial: number;
  planned: number;
}

function narrative(c: ControlResult): { description: string; remark?: string } {
  const scoring = c.addressed_by.filter((a) => !a.awareness_only);
  if (scoring.length === 0) {
    return {
      description:
        `No automated cloud-API evidence maps to ${c.id.toUpperCase()} in this run. ` +
        `Assess this control manually, or document it as inherited from the underlying ` +
        `cloud service provider's FedRAMP authorization.`,
      remark: 'Generated as planned: requires manual assessment or inheritance documentation.',
    };
  }
  const byKsi = new Map<string, { pass: number; fail: number }>();
  for (const a of scoring) {
    const e = byKsi.get(a.requirement_id) ?? { pass: 0, fail: 0 };
    if (a.passed) e.pass++; else e.fail++;
    byKsi.set(a.requirement_id, e);
  }
  const passCount = scoring.filter((a) => a.passed).length;
  const parts = [...byKsi.entries()]
    .map(([k, v]) => `${k} (${v.pass} pass${v.fail ? `, ${v.fail} fail` : ''})`)
    .sort();
  return {
    description:
      `Implemented and continuously verified by automated cloud evidence: ` +
      `${passCount}/${scoring.length} check(s) passing across ${byKsi.size} FedRAMP 20x ` +
      `Key Security Indicator(s) — ${parts.join('; ')}. ` +
      `See the signed evidence package (per-KSI JSON + manifest) for the underlying findings.`,
  };
}

/** Pure: build the OSCAL SSP document object from a control benchmark. */
export function buildOscalSsp(benchmark: ControlBenchmark, opts: SspEmitOptions): {
  doc: { 'system-security-plan': OscalSsp };
  result: Omit<SspEmitResult, 'path'>;
} {
  const level = opts.impactLevel;
  const systemName = opts.systemName || 'Cloud System';
  const systemId = opts.systemId || 'cloud-evidence-system';
  const sysDesc =
    opts.systemDescription ||
    `${systemName} — FedRAMP ${level} system. This System Security Plan was bootstrapped ` +
      `from automated cloud evidence (FedRAMP 20x KSIs rolled up to NIST SP 800-53 Rev5 ` +
      `controls) and must be reviewed and completed by the system owner.`;

  const thisSystemUuid = deterministicUuid(`ssp:component:this-system:${systemId}`);
  const providers: Array<'aws' | 'gcp' | 'azure'> = opts.providers && opts.providers.length ? opts.providers : ['aws', 'gcp'];

  const components: OscalComponent[] = [
    {
      uuid: thisSystemUuid,
      type: 'this-system',
      title: systemName,
      description: sysDesc,
      status: { state: 'operational' },
    },
  ];
  const providerLabel: Record<'aws' | 'gcp' | 'azure', { full: string; short: string }> = {
    aws: { full: 'Amazon Web Services (leveraged cloud infrastructure)', short: 'AWS' },
    gcp: { full: 'Google Cloud Platform (leveraged cloud infrastructure)', short: 'GCP' },
    azure: { full: 'Microsoft Azure (leveraged cloud infrastructure)', short: 'Azure' },
  };
  for (const p of providers) {
    const lbl = providerLabel[p];
    components.push({
      uuid: deterministicUuid(`ssp:component:leveraged:${p}`),
      type: 'service',
      title: lbl.full,
      description:
        `Underlying ${lbl.short} cloud infrastructure. Many infrastructure ` +
        `controls are inherited from this provider's FedRAMP authorization; confirm and ` +
        `document the customer-responsibility split (CRM) for each.`,
      props: [{ name: 'leveraged-authorization', ns: FEDRAMP_NS, value: p }],
      status: { state: 'operational' },
    });
  }

  // One implemented-requirement per baseline control.
  let implemented = 0, partial = 0, planned = 0;
  const irs: OscalImplementedRequirement[] = benchmark.controls.map((c) => {
    const state = statusToImplState(c.status);
    if (state === 'implemented') implemented++;
    else if (state === 'partial') partial++;
    else planned++;
    const n = narrative(c);
    return {
      uuid: deterministicUuid(`ssp:ir:${systemId}:${c.id}`),
      'control-id': c.id,
      props: [
        { name: 'implementation-status', ns: FEDRAMP_NS, value: state },
        { name: 'control-name', ns: CE_NS, value: c.name ?? c.id.toUpperCase() },
      ],
      'by-components': [
        {
          'component-uuid': thisSystemUuid,
          uuid: deterministicUuid(`ssp:bc:${systemId}:${c.id}`),
          description: n.description,
          'implementation-status': { state, remarks: n.remark },
        },
      ],
    };
  });

  // ── LOOP-J.J2: subprocessor-derived leveraged authorizations ──
  // Only FedRAMP-authorized subprocessors with a REAL authorization date become
  // OSCAL leveraged-authorizations; we never fabricate a date-authorized. Each
  // gets a backing organization party so the OSCAL party-uuid reference resolves.
  const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
  const subprocessorParties: Array<{ uuid: string; type: 'organization'; name: string }> = [];
  const leveragedAuths: OscalLeveragedAuthorization[] = [];
  for (const s of opts.leveragedSubprocessors ?? []) {
    if (s.fedramp_authorized !== 'yes') continue;
    const dateAuthorized = (s.last_audit_date ?? '').trim();
    if (!ISO_DATE_RE.test(dateAuthorized)) continue;
    const partyUuid = deterministicUuid(`ssp:party:subprocessor:${systemId}:${s.name}`);
    subprocessorParties.push({ uuid: partyUuid, type: 'organization', name: s.name });
    const props: OscalProp[] = [];
    if (s.risk_tier) props.push({ name: 'risk-tier', ns: FEDRAMP_NS, value: s.risk_tier });
    props.push({ name: 'fedramp-authorization-status', ns: FEDRAMP_NS, value: s.fedramp_authorized });
    leveragedAuths.push({
      uuid: deterministicUuid(`ssp:leveraged-auth:${systemId}:${s.name}`),
      title: s.name,
      'party-uuid': partyUuid,
      'date-authorized': dateAuthorized,
      props,
    });
  }
  const parties = [
    ...(opts.organizationName
      ? [{ uuid: deterministicUuid(`org:${opts.organizationName}`), type: 'organization' as const, name: opts.organizationName }]
      : []),
    ...subprocessorParties,
  ];

  // LOOP-J.J3: SSP back-matter reference to the supply-chain risk register.
  const backMatter = opts.supplyChainRegister
    ? {
        resources: [
          {
            uuid: deterministicUuid(`ssp:back-matter:supply-chain-risk-register:${systemId}`),
            title: 'Supply Chain Risk Register (SR-3, NIST SP 800-161r1)',
            description:
              'Per-system C-SCRM Plan / supplier-risk register joining SBOM-derived CVEs, CISA KEV exposure, subprocessor risk tiers, and operator-asserted advisories. Signed (Ed25519).',
            rlinks: [
              { href: opts.supplyChainRegister.jsonHref, 'media-type': 'application/json' },
              {
                href: opts.supplyChainRegister.xlsxHref,
                'media-type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
              },
            ],
          },
        ],
      }
    : undefined;

  const ssp: OscalSsp = {
    uuid: deterministicUuid(`ssp:${systemId}:${level}`),
    metadata: {
      title: `${systemName} — System Security Plan (FedRAMP ${level}, draft)`,
      'last-modified': new Date().toISOString(),
      version: opts.runId,
      'oscal-version': OSCAL_VERSION,
      roles: [
        { id: 'system-owner', title: 'System Owner' },
        { id: 'admin', title: 'System Administrator' },
        { id: 'assessor', title: 'Assessor' },
      ],
      parties: parties.length > 0 ? parties : undefined,
      props: [
        { name: 'tool', ns: CE_NS, value: TOOL_NAME },
        { name: 'frmr-version', ns: CE_NS, value: opts.frmrVersion },
        { name: 'generation', ns: CE_NS, value: 'draft-bootstrap-from-automated-evidence' },
      ],
      remarks:
        'DRAFT — bootstrapped by fedramp-20x-cloud-evidence from automated cloud evidence. ' +
        'Control narratives, parameters, responsible roles, the authorization boundary, and ' +
        'inheritance (CRM) details must be reviewed and completed by the system owner before submission.',
    },
    'import-profile': {
      href: opts.importProfileHref || FEDRAMP_BASELINE_PROFILE[level],
      remarks: `FedRAMP Rev5 ${level} baseline.`,
    },
    'system-characteristics': {
      'system-ids': [{ id: systemId, 'identifier-type': 'https://ietf.org/rfc/rfc4122' }],
      'system-name': systemName,
      description: sysDesc,
      'security-sensitivity-level': level,
      'system-information': {
        'information-types': [
          {
            uuid: deterministicUuid(`ssp:info-type:${systemId}`),
            title: 'System information',
            description:
              'Information stored, processed, or transmitted by the system. Replace with the ' +
              'NIST SP 800-60 information types applicable to this system.',
            'confidentiality-impact': { base: `fips-199-${level}` },
            'integrity-impact': { base: `fips-199-${level}` },
            'availability-impact': { base: `fips-199-${level}` },
          },
        ],
      },
      'security-impact-level': {
        'security-objective-confidentiality': `fips-199-${level}`,
        'security-objective-integrity': `fips-199-${level}`,
        'security-objective-availability': `fips-199-${level}`,
      },
      status: { state: opts.systemStatus || 'operational' },
      'authorization-boundary': {
        description:
          opts.authorizationBoundaryDescription
          ?? (
            'REQUIRES-OPERATOR-INPUT: authorization-boundary narrative not supplied. ' +
            'Provide a description of the components, services, data flows, and trust ' +
            'boundaries within the authorization boundary, with a companion diagram, via ' +
            "SspEmitOptions.authorizationBoundaryDescription or the orchestrator's --ssp-boundary flag. " +
            'A 3PAO will reject the SSP if this field remains as the REQUIRES-OPERATOR-INPUT marker.'
          ),
      },
    },
    'system-implementation': {
      // Only present when ≥1 qualifying subprocessor exists (OSCAL minItems: 1).
      ...(leveragedAuths.length > 0 ? { 'leveraged-authorizations': leveragedAuths } : {}),
      users: (opts.userRoles && opts.userRoles.length > 0)
        ? opts.userRoles.map((u) => ({
            uuid: u.uuid ?? deterministicUuid(`ssp:user:${systemId}:${u.title}`),
            title: u.title,
            'role-ids': u.roleIds,
            description: u.description,
          }))
        : [
            {
              uuid: deterministicUuid(`ssp:user:admin:${systemId}`),
              title: 'System Administrator',
              'role-ids': ['admin'],
              description:
                'REQUIRES-OPERATOR-INPUT: system-implementation.users[] not supplied. ' +
                "Provide the system's real user roles + responsibilities via " +
                "SspEmitOptions.userRoles or the orchestrator's --ssp-user-roles flag. " +
                'A 3PAO will reject the SSP if this field remains as the REQUIRES-OPERATOR-INPUT marker.',
            },
          ],
      components,
      remarks: 'Components and inventory are a starting point; complete from the inventory workbook.',
    },
    'control-implementation': {
      description:
        `Control implementation for the FedRAMP ${level} baseline, pre-populated from automated ` +
        `cloud evidence. Each implemented-requirement carries an implementation-status derived ` +
        `from the NIST 800-53 control benchmark; "planned" controls have no automated cloud ` +
        `evidence yet and need manual assessment or inheritance documentation.`,
      'implemented-requirements': irs,
    },
    'back-matter': backMatter,
  };

  return {
    doc: { 'system-security-plan': ssp },
    result: { control_count: benchmark.controls.length, implemented, partial, planned },
  };
}

/**
 * Read the LOOP-J.J2 subprocessor inventory from `outDir`, returning the rows
 * the SSP needs to build leveraged-authorizations. Returns [] when the file is
 * absent or unreadable — the SSP simply omits leveraged-authorizations then.
 */
function readLeveragedSubprocessors(outDir: string): LeveragedSubprocessorRow[] {
  try {
    const doc = JSON.parse(readFileSync(resolve(outDir, 'subprocessor-inventory.json'), 'utf8'));
    if (!doc || !Array.isArray(doc.rows)) return [];
    return doc.rows.map((r: any) => ({
      name: String(r.name),
      fedramp_authorized: r.fedramp_authorized,
      last_audit_date: r.last_audit_date,
      risk_tier: r.risk_tier,
    }));
  } catch {
    return [];
  }
}

/** Read evidence from `outDir`, build the SSP, and write it to disk. */
export function emitOscalSsp(opts: SspEmitOptions): SspEmitResult {
  // An SSP documents the WHOLE baseline, so we always benchmark against the full
  // FedRAMP Rev5 baseline for the level (independent of the run's --framework).
  const benchmark = buildControlBenchmark(opts.outDir, { framework: 'rev5', level: opts.impactLevel });
  // LOOP-J.J2: fold subprocessor-inventory.json (if present) into the SSP's
  // leveraged-authorizations. Explicit opts.leveragedSubprocessors win.
  const leveragedSubprocessors = opts.leveragedSubprocessors ?? readLeveragedSubprocessors(opts.outDir);
  // LOOP-J.J3: add a back-matter reference to the supply-chain risk register
  // when it is present in outDir.
  const supplyChainRegister =
    opts.supplyChainRegister ??
    (existsSync(resolve(opts.outDir, 'supply-chain-risk-register.json'))
      ? { jsonHref: 'supply-chain-risk-register.json', xlsxHref: 'supply-chain-risk-register.xlsx' }
      : undefined);
  const { doc, result } = buildOscalSsp(benchmark, { ...opts, leveragedSubprocessors, supplyChainRegister });
  const outPath = opts.outPath ?? resolve(opts.outDir, 'ssp.json');
  writeFileSync(outPath, JSON.stringify(doc, null, 2));

  // OSC-3: XML representation alongside the JSON (downstream FedRAMP tooling).
  let xmlPath: string | undefined;
  if (process.env.CLOUD_EVIDENCE_DISABLE_OSCAL_XML !== '1') {
    xmlPath = outPath.replace(/\.json$/, '') + '.xml';
    if (xmlPath === outPath) xmlPath = `${outPath}.xml`;
    writeFileSync(xmlPath, oscalJsonToXml(doc));
  }

  log.info({
    event: 'oscal_ssp.emitted',
    path: outPath,
    xml_path: xmlPath,
    control_count: result.control_count,
    implemented: result.implemented,
    partial: result.partial,
    planned: result.planned,
  });
  return { path: outPath, xml_path: xmlPath, ...result };
}
