/**
 * Configuration Management Plan (CMP) emitter — LOOP-C.C1.
 *
 * Renders `cmp.docx` — an 11-section, auto-filled Configuration Management
 * Plan that satisfies NIST SP 800-53 Rev. 5 control CM-9. The Configuration
 * Items table (§4) is derived from the real `out/inventory.json` (CM-8); the
 * Configuration Monitoring list (§7) is derived from the real registered
 * KSI map (`core/ksi-map.ts`); every process-narrative section (§3 roles,
 * §6 change control, §8 change windows, §9 rollback, §10 tooling) falls back
 * to a verbatim `REQUIRES-OPERATOR-INPUT` marker rather than fabricating
 * workflow language. Closes a real FedRAMP 20x gap: FedRAMP does not publish
 * a CMP template, so CSPs re-author from blank pages every cycle.
 *
 * Authoritative sources (verbatim):
 *   - NIST SP 800-53 Rev. 5 CM-9 (Configuration Management Plan) —
 *     https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final :
 *     "Develop, document, and implement a configuration management plan for
 *      the system that: a. Addresses roles, responsibilities, and
 *      configuration management processes and procedures; b. Establishes a
 *      process for identifying configuration items throughout the system
 *      development life cycle and for managing the configuration of the
 *      configuration items; c. Defines the configuration items for the
 *      system and places the configuration items under configuration
 *      management; d. Is reviewed and approved by [Assignment: organization-
 *      defined personnel or roles]; e. Protects the configuration management
 *      plan from unauthorized disclosure and modification."
 *   - NIST SP 800-128 §2.1 (Guide for Security-Focused Configuration
 *     Management) — https://csrc.nist.gov/pubs/sp/800/128/upd1/final :
 *     "The roles and responsibilities for SecCM should be clearly identified
 *      within the organization. These roles often include configuration
 *      control board, change initiator, change implementer, and change
 *      approver." Appendix D drives the §1–§11 section structure.
 *   - NIST SP 800-53 Rev. 5 CM-3 (Configuration Change Control) + CM-4
 *     (Security Impact Analyses) + CM-8 (System Component Inventory) —
 *     same catalog URL.
 *
 * Approach (dependency-free .docx): a `.docx` is a ZIP of WordprocessingML
 * XML parts. We build the parts as strings and pack them with the store-only
 * ZIP writer the SSP-2 + RoE renderers use (core/zip.ts) — no external Word
 * library, no runtime network. The OOXML building blocks mirror the pattern
 * established by core/ssp-docx.ts + core/roe-emit.ts (a shared docx-primitives
 * module was proposed in LOOP-C-SPEC §4 but never extracted; see LOOP-C-RISKS
 * C-C1-6 for the reconciliation — this emitter follows the four shipped docx
 * emitters and keeps its OOXML constants local).
 *
 * REO compliance:
 *   - §4 Configuration Items are derived ONLY from real assets in
 *     inventory.json; the emitter never invents component types. Empty/absent
 *     inventory → a single REQUIRES-OPERATOR-INPUT row explaining the fix.
 *   - §7 Configuration Monitoring lists the real KSI domains grepped from
 *     core/ksi-map.ts (the same trick the RoE + AP emitters use); the emitter
 *     throws if fewer than 20 domains resolve (a broken map must fail loud).
 *   - §3/§6/§8/§9/§10 default to verbatim REQUIRES-OPERATOR-INPUT markers.
 *     Inferred (not confirmed) CM tooling is marked REQUIRES-OPERATOR-INPUT-
 *     VERIFY, distinct from the plain marker, so the operator confirms use.
 *   - The document is fully deterministic (no wall-clock time): the metadata
 *     UUID is `deterministicUuid('cmp:' + systemId + ':' + runId)` and the
 *     inventory provenance is a content SHA-256, so identical inputs produce
 *     a byte-identical .docx. Integrity is anchored by the signed submission-
 *     bundle INDEX.json (which SHA-256s + Ed25519-signs every included file),
 *     the same coverage roe.docx + ssp.docx receive.
 *
 * Pure renderer (`renderCmpDocx` / `buildCmpBodyXml`) + disk emitter
 * (`emitCmpDocx`).
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
/** Verbatim marker for inferred-but-unconfirmed input (distinct from TBD). */
const TBD_VERIFY = 'REQUIRES-OPERATOR-INPUT-VERIFY';
/** The §7 monitoring list must resolve at least this many KSI domains. */
const KSI_MIN = 20;

/** Thrown when core/ksi-map.ts cannot be read or yields too few KSI domains. */
export class CmpKsiScopeError extends Error {
  constructor(count: number) {
    super(
      `cmp-emit: KSI scope read from core/ksi-map.ts returned ${count} domain(s) ` +
      `(< ${KSI_MIN}); refusing to emit a CMP with an incomplete Configuration ` +
      `Monitoring scope (§7). Verify core/ksi-map.ts export shape.`,
    );
    this.name = 'CmpKsiScopeError';
  }
}

// ─── OOXML building blocks (same pattern as ssp-docx.ts / roe-emit.ts) ───────

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

/** A Configuration Control Board roster entry (NIST SP 800-128 §2.1). */
export interface CmpCcbRosterEntry {
  /** CCB role — commonly CCB Chair / Change Initiator / Implementer / Approver. */
  role: string;
  name: string;
  organization: string;
  email?: string;
}

/** A configuration-management tooling entry (§10). */
export interface CmpTooling {
  name: string;
  purpose: string;
}

export interface CmpEmitOptions {
  /** Where the orchestrator writes. The emitter reads inventory.json from here. */
  outDir: string;
  /** Output path (defaults to <outDir>/cmp.docx). */
  outPath?: string;
  /** Run id — captured in the CMP provenance (§1) + deterministic UUID seed. */
  runId: string;
  /** FRMR catalog version — captured in the CMP provenance (§1). */
  frmrVersion: string;
  /** Impact level (low/moderate/high). */
  impactLevel: 'low' | 'moderate' | 'high';
  /** System identity (reuses --system-name / --system-id / --csp-name). */
  systemName?: string;
  systemId?: string;
  cspOrganization?: string;
  /** §6 operator-supplied change-control workflow narrative. */
  approvalWorkflowNarrative?: string;
  /** §9 operator-supplied rollback authority + criteria. */
  rollbackAuthority?: string;
  /** §8 operator-supplied change/maintenance windows. */
  changeWindowsDescription?: string;
  /** §5 link to the CM-2 Baseline Configuration document (C.C9). */
  baselineConfigHref?: string;
  /** §10 operator-supplied CM tooling (config.yaml: cmp.tooling[]). */
  cmTooling?: CmpTooling[];
  /** §3 operator-supplied CCB roster (config.yaml: cmp.ccb_roster[]). */
  ccbRoster?: CmpCcbRosterEntry[];
}

export interface CmpEmitResult {
  path: string;
  bytes: number;
  /** Count of real inventory assets feeding the §4 Configuration Items table. */
  component_count: number;
  /** Count of KSI domains listed in the §7 Configuration Monitoring table. */
  ksi_count: number;
  /** True when every required-for-signature operator field was supplied. */
  ready_for_signature: boolean;
  /** Missing-input list for operator action. */
  requires_operator_input: string[];
}

// ─── Inventory reader ────────────────────────────────────────────────────────

/** A single normalized inventory component (one per real asset). */
export interface CmpComponent {
  uniqueId: string;
  type: string;
  provider: string;
  location: string;
  assetType: string;
}

/**
 * Read out/inventory.json and normalize to components. Same JSON-parse-safe
 * pattern as roe-emit.ts:readInventoryIps — never throws on a missing or
 * malformed inventory (returns []).
 */
export function readInventoryComponents(outDir: string): CmpComponent[] {
  const p = resolve(outDir, 'inventory.json');
  if (!existsSync(p)) return [];
  let doc: any;
  try { doc = JSON.parse(readFileSync(p, 'utf8')); }
  catch { return []; }
  const assets: any[] = Array.isArray(doc?.assets) ? doc.assets : (Array.isArray(doc) ? doc : []);
  const out: CmpComponent[] = [];
  for (const a of assets) {
    if (!a || typeof a !== 'object') continue;
    const assetType = String(a.assetType ?? a.type ?? 'unknown');
    out.push({
      uniqueId: String(a.uniqueId ?? a.name ?? '(asset)'),
      type: assetType,
      provider: String(a.provider ?? 'unknown'),
      location: String(a.location ?? ''),
      assetType,
    });
  }
  return out;
}

/** A (provider, assetType) group for the §4 Configuration Items table. */
export interface CmpComponentGroup {
  provider: string;
  assetType: string;
  count: number;
  locations: string[];
}

/** Group components by (provider, assetType); rows sorted for determinism. */
export function groupComponents(components: CmpComponent[]): CmpComponentGroup[] {
  const map = new Map<string, CmpComponentGroup>();
  for (const c of components) {
    const key = `${c.provider} ${c.assetType}`;
    let g = map.get(key);
    if (!g) { g = { provider: c.provider, assetType: c.assetType, count: 0, locations: [] }; map.set(key, g); }
    g.count += 1;
    if (c.location && !g.locations.includes(c.location)) g.locations.push(c.location);
  }
  const groups = [...map.values()];
  for (const g of groups) g.locations.sort();
  groups.sort((a, b) => (a.provider === b.provider
    ? a.assetType.localeCompare(b.assetType)
    : a.provider.localeCompare(b.provider)));
  return groups;
}

// ─── KSI scope reader ────────────────────────────────────────────────────────

/**
 * Grep core/ksi-map.ts for the registered KSI domains — the same trick the
 * RoE + AP emitters use so we don't import the map (which would pull every
 * provider module into the bundle at emit time).
 */
export function readKsiScope(): Array<{ ksi: string }> {
  const p = resolve(import.meta.dirname ?? '', 'ksi-map.ts');
  try {
    const src = readFileSync(p, 'utf8');
    const ids = new Set<string>();
    for (const m of src.matchAll(/^\s*'(KSI-[A-Z]+-[A-Z]+)'\s*:/gm)) ids.add(m[1]!);
    return [...ids].sort().map((ksi) => ({ ksi }));
  } catch {
    return [];
  }
}

// ─── Inventory provenance digest ─────────────────────────────────────────────

function inventoryDigest(outDir: string): string | null {
  const p = resolve(outDir, 'inventory.json');
  if (!existsSync(p)) return null;
  try { return createHash('sha256').update(readFileSync(p)).digest('hex'); }
  catch { return null; }
}

// ─── Default CCB roster (all cells REQUIRES-OPERATOR-INPUT) ───────────────────

function defaultRoster(): CmpCcbRosterEntry[] {
  // Per REO Rule 4: emit a structurally-complete table with the four
  // NIST SP 800-128 §2.1 roles so the operator sees exactly what to fill.
  return [
    { role: 'CCB Chair', name: TBD, organization: TBD, email: TBD },
    { role: 'Change Initiator', name: TBD, organization: TBD, email: TBD },
    { role: 'Change Implementer', name: TBD, organization: TBD, email: TBD },
    { role: 'Change Approver', name: TBD, organization: TBD, email: TBD },
  ];
}

// ─── §10 tooling rows (operator-confirmed OR inferred-VERIFY) ─────────────────

/** Cloud-native CM tooling inferred from an inventory provider (unconfirmed). */
const PROVIDER_TOOLING: Record<string, { name: string; purpose: string }> = {
  aws: { name: 'AWS Systems Manager', purpose: 'Automated configuration management + patch/state compliance for AWS resources' },
  gcp: { name: 'GCP Config Connector', purpose: 'Declarative configuration management for GCP resources' },
  azure: { name: 'Azure Arc / Automanage', purpose: 'Configuration management + drift remediation for Azure + hybrid resources' },
};

interface ToolingRow { tool: string; purpose: string; confirmation: string }

function buildToolingRows(opts: CmpEmitOptions, components: CmpComponent[]): ToolingRow[] {
  if (opts.cmTooling && opts.cmTooling.length > 0) {
    return opts.cmTooling.map((t) => ({
      tool: t.name,
      purpose: t.purpose,
      confirmation: 'operator-confirmed',
    }));
  }
  // Infer from the distinct inventory providers — but mark each row VERIFY
  // (the system cannot confirm the operator actually uses the tool).
  const providers = [...new Set(components.map((c) => c.provider))]
    .filter((p) => PROVIDER_TOOLING[p]).sort();
  if (providers.length === 0) {
    return [{
      tool: TBD,
      purpose: 'No CM tooling supplied (config.yaml: cmp.tooling[]) and no cloud provider inferred from inventory.',
      confirmation: TBD,
    }];
  }
  return providers.map((p) => ({
    tool: PROVIDER_TOOLING[p]!.name,
    purpose: PROVIDER_TOOLING[p]!.purpose,
    confirmation: TBD_VERIFY,
  }));
}

// ─── Builder (pure) ──────────────────────────────────────────────────────────

export function buildCmpBodyXml(opts: CmpEmitOptions): {
  xml: string;
  stats: Omit<CmpEmitResult, 'path' | 'bytes'>;
} {
  const systemName = opts.systemName || TBD;
  const systemId = opts.systemId || TBD;
  const csp = opts.cspOrganization || TBD;

  // Required-for-signature input tracker.
  const missing: string[] = [];
  const track = (label: string, val: string | undefined) => {
    if (!val || val.trim() === '') missing.push(label);
  };
  track('systemName', opts.systemName);
  track('systemId', opts.systemId);
  track('cspOrganization', opts.cspOrganization);
  track('approvalWorkflowNarrative', opts.approvalWorkflowNarrative);
  track('rollbackAuthority', opts.rollbackAuthority);
  track('changeWindowsDescription', opts.changeWindowsDescription);
  track('baselineConfigHref', opts.baselineConfigHref);
  if (!opts.ccbRoster || opts.ccbRoster.length === 0) missing.push('ccbRoster');
  if (!opts.cmTooling || opts.cmTooling.length === 0) missing.push('cmTooling');

  const components = readInventoryComponents(opts.outDir);
  if (components.length === 0) missing.push('inventory (out/inventory.json missing or empty)');

  const ksis = readKsiScope();
  if (ksis.length < KSI_MIN) throw new CmpKsiScopeError(ksis.length);

  const invDigest = inventoryDigest(opts.outDir);
  const docUuid = deterministicUuid(`cmp:${systemId}:${opts.runId}`);
  const groups = groupComponents(components);

  const parts: string[] = [];

  // ── Title block ──
  parts.push(para('Configuration Management Plan', 'Title'));
  parts.push(para(`${systemName} — FedRAMP ${opts.impactLevel} (CM-9)`, 'Subtitle'));
  parts.push(para(
    'DRAFT — auto-filled by fedramp-20x-cloud-evidence from real inventory + ksi-map. ' +
    `The operator must complete every ${TBD} marker before the plan is reviewed and ` +
    'approved (CM-9.d). The CSP is the author-of-record for the finalized plan.',
    'Disclaimer',
  ));

  // ── §1 Document Information ──
  parts.push(heading('1. Document Information', 1));
  parts.push(fieldTable([
    ['Document Title', `Configuration Management Plan — ${systemName}`],
    ['Document UUID', docUuid],
    ['Version', '1.0'],
    ['System Name', systemName],
    ['System ID', systemId],
    ['Impact Level', opts.impactLevel.toUpperCase()],
    ['CSP Organization', csp],
    ['Satisfies Control', 'NIST SP 800-53 Rev. 5 CM-9 (Configuration Management Plan)'],
    ['Reviewed & Approved By (CM-9.d)', opts.ccbRoster?.find((r) => r.role === 'CCB Chair')?.name || TBD],
    ['Plan Protection (CM-9.e)',
      'Protected from unauthorized disclosure and modification: stored in the CSP evidence ' +
      'repository with access restricted to authorized configuration-management personnel; ' +
      'integrity is anchored by the signed submission-bundle INDEX.json (SHA-256 + Ed25519).'],
    ['Generated By', 'fedramp-20x-cloud-evidence (core/cmp-emit.ts)'],
    ['Inventory Source', invDigest ? `out/inventory.json (sha256 ${invDigest})` : '(none — see §4)'],
    ['KSI Map Source', 'core/ksi-map.ts'],
    ['Run ID', opts.runId],
    ['FRMR Catalog Version', opts.frmrVersion],
  ]));

  // ── §2 Purpose & Scope ──
  parts.push(heading('2. Purpose & Scope', 1));
  parts.push(para(
    'This Configuration Management Plan (CMP) satisfies NIST SP 800-53 Rev. 5 control ' +
    'CM-9, which requires the organization to:',
  ));
  parts.push(para(
    '"Develop, document, and implement a configuration management plan for the system that: ' +
    'a. Addresses roles, responsibilities, and configuration management processes and procedures; ' +
    'b. Establishes a process for identifying configuration items throughout the system development ' +
    'life cycle and for managing the configuration of the configuration items; c. Defines the ' +
    'configuration items for the system and places the configuration items under configuration ' +
    'management; d. Is reviewed and approved by [Assignment: organization-defined personnel or ' +
    'roles]; e. Protects the configuration management plan from unauthorized disclosure and ' +
    'modification." (NIST SP 800-53 Rev. 5, CM-9)',
  ));
  parts.push(para(
    'The roles addressed in §3 follow NIST SP 800-128 §2.1: "The roles and responsibilities for ' +
    'SecCM should be clearly identified within the organization. These roles often include ' +
    'configuration control board, change initiator, change implementer, and change approver." ' +
    'The document structure follows the NIST SP 800-128 Appendix D SecCM Plan outline.',
  ));

  // ── §3 Roles & Responsibilities ──
  parts.push(heading('3. Roles & Responsibilities', 1));
  parts.push(para(
    'The Configuration Control Board (CCB) roles below are drawn from NIST SP 800-128 §2.1. ' +
    'The operator supplies each name + organization (config.yaml: cmp.ccb_roster[]).',
  ));
  const roster = (opts.ccbRoster && opts.ccbRoster.length > 0) ? opts.ccbRoster : defaultRoster();
  parts.push(table(
    ['Role', 'Name', 'Organization', 'Email'],
    roster.map((r) => [r.role, r.name || TBD, r.organization || TBD, r.email || TBD]),
    [2400, 2200, 2400, 2000],
  ));

  // ── §4 Configuration Items (auto-derived) ──
  parts.push(heading('4. Configuration Items', 1));
  parts.push(para(
    'The configuration items below are auto-derived from out/inventory.json (CM-8 System ' +
    'Component Inventory), grouped by (provider, asset type). Each row represents real cloud ' +
    'resources discovered by the collector; no synthetic component types appear. Placing these ' +
    'items under configuration management satisfies CM-9.b and CM-9.c.',
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
      [[TBD, 'out/inventory.json missing or empty. Run the collector to populate the inventory, then re-emit the CMP.', '0', '—']],
      [2200, 2600, 1200, 3000],
    ));
  }

  // ── §5 Baseline Configuration Reference ──
  parts.push(heading('5. Baseline Configuration Reference', 1));
  if (opts.baselineConfigHref) {
    parts.push(para(`The current baseline configuration (CM-2) is documented in: ${opts.baselineConfigHref}`));
    parts.push(para(
      'The baseline is maintained under configuration control and updated through the ' +
      'change-control process defined in §6.',
    ));
  } else {
    parts.push(para(
      `${TBD}: reference the Baseline Configuration document (CM-2). When the collector emits ` +
      'baseline-config.docx (LOOP-C.C9) in the same run this link auto-resolves to ' +
      './baseline-config.docx; otherwise supply --cmp-baseline-config-href.',
    ));
  }

  // ── §6 Configuration Change Control Process ──
  parts.push(heading('6. Configuration Change Control Process', 1));
  parts.push(para(
    'This section documents the CSP configuration change-control workflow satisfying CM-3 ' +
    '(Configuration Change Control) and CM-4 (Security Impact Analyses).',
  ));
  if (opts.approvalWorkflowNarrative) {
    parts.push(para(opts.approvalWorkflowNarrative));
  } else {
    parts.push(para(
      `${TBD}: document the configuration change-control workflow (proposal → review → ` +
      'security-impact analysis → test → approval → implementation). Model language ' +
      '(NIST SP 800-128 §3.2): "All configuration changes need to be formally identified, ' +
      'proposed, reviewed, analyzed for security impact, tested, and approved prior to ' +
      'implementation."',
    ));
  }
  parts.push(para(
    'Security impact analysis (CM-4) is performed prior to change implementation: "Analyze ' +
    'changes to the system to determine potential security and privacy impacts prior to change ' +
    'implementation." (NIST SP 800-53 Rev. 5, CM-4)',
  ));

  // ── §7 Configuration Monitoring (auto-derived from ksi-map) ──
  parts.push(heading('7. Configuration Monitoring', 1));
  parts.push(para(
    'Configuration changes are continuously monitored through the automated Key Security ' +
    'Indicator (KSI) evidence collection this toolkit performs. The KSI domains below are ' +
    'auto-derived from core/ksi-map.ts and reflect the actual rules the collector runs each ' +
    'cycle. Per-run coverage is reported in out/inventory-coverage.json.',
  ));
  parts.push(table(
    ['KSI ID', 'Family'],
    ksis.map((k) => [k.ksi, k.ksi.split('-')[1] ?? '']),
    [4500, 4500],
  ));

  // ── §8 Change Windows ──
  parts.push(heading('8. Change Windows', 1));
  parts.push(para(
    opts.changeWindowsDescription ||
    `${TBD}: document the approved maintenance / change windows (e.g., "Standard changes ` +
    'deploy continuously via CI/CD; scheduled maintenance windows are Sundays 02:00–06:00 UTC; ' +
    'emergency changes follow the expedited CCB path").',
  ));

  // ── §9 Rollback Authority ──
  parts.push(heading('9. Rollback Authority', 1));
  parts.push(para(
    opts.rollbackAuthority ||
    `${TBD}: name the role authorized to order a rollback of a configuration change, and the ` +
    'criteria that trigger a rollback.',
  ));

  // ── §10 Configuration Management Tooling ──
  parts.push(heading('10. Configuration Management Tooling', 1));
  parts.push(para(
    'The tooling below supports automated configuration management (CM-9.a processes and ' +
    'procedures). Operator-supplied entries are confirmed; entries inferred from the inventory ' +
    'provider set are flagged for operator verification (in the Confirmation column) until the ' +
    'operator confirms they are actually in use.',
  ));
  const toolingRows = buildToolingRows(opts, components);
  parts.push(table(
    ['Tool', 'Purpose', 'Confirmation'],
    toolingRows.map((t) => [t.tool, t.purpose, t.confirmation]),
    [2600, 4400, 2000],
  ));

  // ── §11 Plan Maintenance ──
  parts.push(heading('11. Plan Maintenance', 1));
  parts.push(para(
    'This plan is reviewed and updated at least annually and whenever a significant change to the ' +
    'system or its environment occurs, per NIST SP 800-128 §3.5: "Configuration management plans ' +
    'should be reviewed and updated on an organization-defined frequency and as needed to reflect ' +
    'changes to the system or its environment." The inventory snapshot in §4 is anchored to the ' +
    'SHA-256 recorded in §1; when the inventory is rebuilt, re-emit this plan so the ' +
    'configuration-item table stays current (mitigates inventory drift between emit-time and ' +
    '3PAO sample-time).',
  ));

  // ── Page geometry (US Letter) ──
  const sectPr = '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/>' +
    '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr>';

  const xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<w:document xmlns:w="${W_NS}"><w:body>${parts.join('')}${sectPr}</w:body></w:document>`;

  return {
    xml,
    stats: {
      component_count: components.length,
      ksi_count: ksis.length,
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
  const title = `Configuration Management Plan — ${systemName} [${docUuid}]`;
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

/** Pure: render a Configuration Management Plan Word document to a Buffer. */
export function renderCmpDocx(opts: CmpEmitOptions): {
  buffer: Buffer;
  stats: Omit<CmpEmitResult, 'path' | 'bytes'>;
} {
  const { xml, stats } = buildCmpBodyXml(opts);
  const systemName = opts.systemName || TBD;
  const systemId = opts.systemId || TBD;
  const docUuid = deterministicUuid(`cmp:${systemId}:${opts.runId}`);
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

/** Read inventory + ksi-map, render, and write cmp.docx. */
export function emitCmpDocx(opts: CmpEmitOptions): CmpEmitResult {
  const { buffer, stats } = renderCmpDocx(opts);
  const outPath = opts.outPath ?? resolve(opts.outDir, 'cmp.docx');
  writeFileSync(outPath, buffer);
  log.info({
    event: 'cmp.emitted',
    path: outPath,
    bytes: buffer.length,
    component_count: stats.component_count,
    ksi_count: stats.ksi_count,
    ready_for_signature: stats.ready_for_signature,
    requires_operator_input_count: stats.requires_operator_input.length,
  });
  return { path: outPath, bytes: buffer.length, ...stats };
}
