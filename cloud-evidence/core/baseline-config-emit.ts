/**
 * Baseline Configuration document emitter — LOOP-C.C9.
 *
 * Renders `baseline-config.docx` — the NIST SP 800-53 Rev. 5 control CM-2
 * (Baseline Configuration) document: the documented, approved baseline the
 * Configuration Management Plan (LOOP-C.C1, CMP §5) cross-links to. Rev. 5 split
 * CM-2 (the approved configuration each component is authorized to run) from CM-8
 * (the inventory of what components exist); this document is the CM-2 half and is
 * DISTINCT from the CM-8 inventory workbook and from the AFR Secure Configuration
 * Guide (LOOP-G.G5 AFR-SCG) — the SCG is the RECOMMENDED secure configuration,
 * this is the CSP's baseline-of-record. CM-2(2) (Automation Support for Accuracy
 * and Currency) is satisfied by auto-deriving the baseline from the run's real
 * inventory + the provider reference-architecture source files rather than by hand.
 *
 * The document auto-derives from three real sources:
 *   - §3 Baseline Configuration Items ← out/inventory.json (LOOP-A inventory
 *     chain / CM-8): every asset's current image + hardening baseline, grouped by
 *     (provider, component class) so ephemeral / auto-scaling assets collapse into
 *     their class baseline instead of fabricating a per-instance baseline.
 *   - §4 Reference Architecture ← providers/{aws,gcp,azure}/reference-arch.ts:
 *     the documented hardening expectations (each `finding({ rule, target, ...,
 *     nist_controls })` block) are grep-read from source, the same trick the RoE
 *     emitter uses on ksi-map.ts so no provider SDK module is pulled in at emit
 *     time.
 *   - §5 Deviations from Baseline ← a pure diff of the real inventory rows against
 *     the reference-architecture hardening anchors; each deviation's severity is
 *     taken from the anchoring reference finding's declared severity (never
 *     defaulted — Risk 4).
 *
 * Authoritative sources (cited in the body + the provenance footer):
 *   - NIST SP 800-53 Rev. 5 — CM-2 Baseline Configuration (+ CM-2(2) Automation
 *     Support, CM-2(7) High-Risk Areas) —
 *     https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final — control text (§1).
 *   - NIST SP 800-128 (with Update 1, 2019-10) — Guide for Security-Focused
 *     Configuration Management of Information Systems —
 *     https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-128.pdf —
 *     §3.2 baseline-configuration definition (quoted verbatim in §1).
 *   - CIS Benchmarks — https://www.cisecurity.org/cis-benchmarks — the upstream
 *     standard the provider reference-arch.ts files draw from (cited, not copied —
 *     CIS content is licensed; Risk 7).
 *
 * Approach (dependency-free .docx): a `.docx` is a ZIP of WordprocessingML XML
 * parts built as strings and packed with the store-only ZIP writer the shipped
 * docx emitters use (core/zip.ts) — no external Word library, no runtime network.
 * The OOXML building blocks mirror auth-cover-letter-emit.ts / rms-emit.ts; the
 * shared docx-primitives module proposed in LOOP-C-SPEC §4 was never extracted
 * (LOOP-C-RISKS C-X-1), so this emitter keeps its OOXML constants local like its
 * siblings — now the fifteenth emitter to migrate when C-X-1 lands.
 *
 * REO compliance:
 *   - §3 / §4 / §5 trace to the real inventory.json + reference-arch.ts source +
 *     the pure diff of the two. No fabricated baseline values; when a component
 *     class has no documented reference expectation, or a provider file yields no
 *     entries, the document says so explicitly (coverage gap) rather than inventing
 *     a baseline.
 *   - Deviation severity is the anchoring reference finding's real declared
 *     severity — never a default (Risk 4).
 *   - Operator identity fields (baseline approver, deviation-log location, review
 *     cadence) are operator-supplied; absent → a REQUIRES-OPERATOR-INPUT marker
 *     (REO Rule 4). The approval signature block is never auto-signed.
 *   - Deterministic (no wall-clock time): the metadata UUID is
 *     `deterministicUuid('baseline-config:' + systemId + ':' + runId)` and the
 *     provenance footer cites the content SHA-256 of every source read
 *     (inventory.json + each reference-arch.ts), so identical inputs produce a
 *     byte-identical .docx. Integrity is anchored by the signed submission-bundle
 *     INDEX.json (SHA-256 + Ed25519), the same coverage the sibling docx receive.
 *
 * Pure renderer (`renderBaselineConfigDocx` / `buildBaselineConfigBodyXml`) + disk
 * emitter (`emitBaselineConfigDocx`). The readers
 * (`readInventoryBaselineRows`, `readReferenceArchitecturesAllProviders`,
 * `diffInventoryVsReference`) are exported for unit testing.
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

const SP_800_53_URL = 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final';
const SP_800_128_URL = 'https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-128.pdf';
const CIS_BENCHMARKS_URL = 'https://www.cisecurity.org/cis-benchmarks';

/** NIST SP 800-53 Rev. 5 CM-2(a) — verbatim (the baseline-configuration mandate). */
const CM_2_QUOTE =
  'Develop, document, and maintain under configuration control, a current baseline configuration of the system.';

/** NIST SP 800-128 §3.2 — verbatim (what a baseline configuration IS; quoted in §1). */
const SP_800_128_QUOTE =
  'A baseline configuration is a documented, formally reviewed and agreed-upon specification for a system or ' +
  'configuration item within a system. A baseline configuration provides the basis for future builds, releases, ' +
  'and changes to systems.';

/** Providers whose reference-arch.ts source files carry the documented hardening baseline. */
const PROVIDERS = ['aws', 'gcp', 'azure'] as const;
type Provider = (typeof PROVIDERS)[number];

// ─── Types ───────────────────────────────────────────────────────────────────

/** §8 baseline approver (operator-supplied; never auto-signed). */
export interface BaselineConfigApprover {
  name: string;
  role: string;
  org: string;
  /** Approval date (ISO); optional — signed at approval time when absent. */
  date?: string;
}

/** Operator override for a component whose reference-arch coverage is incomplete (§3/§5, rarely used). */
export interface BaselineConfigItemOverride {
  component: string;
  baseline: string;
  deviations: string[];
}

export interface BaselineConfigOptions {
  /** Where the orchestrator writes. The emitter reads inventory.json from here. */
  outDir: string;
  /** Output path (defaults to <outDir>/baseline-config.docx). */
  outPath?: string;
  /** Run id — captured in the provenance (§1) + the deterministic UUID seed. */
  runId: string;
  /** FRMR catalog version — captured in the provenance (§1). */
  frmrVersion: string;
  /** System identity (reuses --system-name / --system-id / --oscal-org). */
  systemName?: string;
  systemId?: string;
  cspOrganization?: string;
  /** Impact tier — drives the §1 subject line. */
  impactLevel: 'low' | 'moderate' | 'high';
  /** §8 baseline approver (config.yaml: baseline_config.approver). */
  baselineApprover?: BaselineConfigApprover;
  /** §7 deviation-log location — URL or path (config.yaml: baseline_config.deviation_log). */
  deviationLogLocation?: string;
  /** §6 review cadence; defaults to 'annually' per CM-2 (config.yaml: baseline_config.review_cadence). */
  baselineReviewCadence?: 'monthly' | 'quarterly' | 'annually';
  /** §3/§5 operator override when the reference architecture is incomplete (rarely used). */
  configurationItemsOverride?: BaselineConfigItemOverride[];
  /**
   * Base directory holding the provider reference-arch.ts source read for §4.
   * Defaults to the shipped `providers/` directory; overridable so the source
   * location can be relocated without editing the emitter. Production leaves this
   * unset (the default resolves to the real providers/ tree).
   */
  providersRoot?: string;
}

/** One inventory row projected for baseline analysis (from a real CloudAsset). */
export interface InventoryBaselineRow {
  uniqueId: string;
  provider: string;
  /** Normalized class (compute / database / storage / network / identity / container / serverless / other). */
  componentClass: string;
  /** Provider-native type string (assetType || resourceType). */
  componentType: string;
  /** Current image (imageId || hardwareMakeModel) or null when unknown. */
  currentImage: string | null;
  /** Current hardening baseline (baselineConfig || osNameVersion) or null when undocumented. */
  currentConfig: string | null;
  /** Encryption-at-rest posture (null = unknown). */
  encryptionAtRest: boolean | null;
  /** Lifecycle state (running / stopped / …) or null. */
  state: string | null;
}

/** One §3 baseline-configuration-item group (per provider + component class). */
export interface BaselineItemRow {
  component: string;
  baselineImage: string;
  baselineConfig: string;
  currentCount: number;
  controls: string[];
}

/** One documented reference-architecture hardening expectation grep-read from source. */
export interface RefArchEntry {
  provider: string;
  /** The check rule name (e.g. aws.ec2.approved_ami_provenance). */
  rule: string;
  /** The documented baseline expectation (the finding target summary). */
  baseline: string;
  /** NIST controls the expectation anchors to. */
  controls: string[];
  /** Declared severity of the anchoring finding (drives deviation severity — Risk 4). */
  severity: string;
}

/** Reference-architecture read result across all providers (with per-provider coverage). */
export interface RefArchReadResult {
  entries: RefArchEntry[];
  /** entry count per provider (§4 coverage-delta footer — Risk 5). */
  perProvider: Record<string, number>;
  /** true when the provider source file was readable (distinct from 0 entries). */
  readable: Record<string, boolean>;
  /** SHA-256 of each reference-arch.ts read (chain-of-custody). */
  sha256: Record<string, string | null>;
}

/** One §5 deviation-from-baseline row. */
export interface DeviationRow {
  component: string;
  baseline: string;
  current: string;
  deviation: string;
  severity: string;
}

export interface BaselineConfigResult {
  path: string;
  bytes: number;
  /** True when out/inventory.json fed §3. */
  inventory_present: boolean;
  /** §3 baseline-item group count (0 when inventory absent). */
  baseline_item_count: number;
  /** Total assets covered by §3. */
  asset_count: number;
  /** §4 reference-architecture entry count across all providers. */
  reference_entry_count: number;
  /** Providers whose reference-arch.ts yielded ≥1 entry. */
  providers_covered: string[];
  /** §5 computed deviation count. */
  deviation_count: number;
  /** True when a review cadence was resolved (operator or the CM-2 default). */
  review_cadence: 'monthly' | 'quarterly' | 'annually';
  /** True when every required-for-signature operator field was supplied. */
  ready_for_signature: boolean;
  /** Missing signature-blocker list for operator action. */
  requires_operator_input: string[];
}

// ─── Readers ─────────────────────────────────────────────────────────────────

function fileSha(path: string): string | null {
  if (!existsSync(path)) return null;
  try { return createHash('sha256').update(readFileSync(path)).digest('hex'); }
  catch { return null; }
}

/**
 * Normalize a provider-native asset type into a stable component class so §3
 * groups compute / db / storage / network / identity / container / serverless
 * regardless of the per-cloud type strings (Risk 3). Mirrors the CMDB-class
 * heuristic in inventory-emit.ts.
 */
export function componentClassFor(assetType: string | null | undefined, resourceType: string | null | undefined): string {
  const t = `${assetType ?? ''} ${resourceType ?? ''}`.toLowerCase();
  if (/function|lambda|serverless|cloud run|cloud function/.test(t)) return 'serverless';
  if (/cluster|kubernetes|\beks\b|\bgke\b|\baks\b|container|node group|nodepool/.test(t)) return 'container';
  if (/database|\bsql\b|dynamodb|\brds\b|\btable\b|cosmos|bigtable|spanner|firestore|redis|memorystore/.test(t)) return 'database';
  if (/bucket|storage|volume|disk|\bblob\b|\bs3\b|\bebs\b|\befs\b|filestore|file share/.test(t)) return 'storage';
  if (/load ?balancer|\blb\b|\bcdn\b|distribution|\bvpc\b|subnet|network|firewall|gateway|\bdns\b|route|nat/.test(t)) return 'network';
  if (/\biam\b|role|\buser\b|service ?account|principal|key ?vault|\bkms\b|secret|identity/.test(t)) return 'identity';
  if (/instance|compute|\bvm\b|\bec2\b|virtual machine|server/.test(t)) return 'compute';
  return 'other';
}

/**
 * Read the LOOP-A inventory.json and project each asset into a baseline row.
 * Returns null when the file is absent or unparseable (§3 degrades to
 * REQUIRES-OPERATOR-INPUT — test #5). Consumes only the fields §3/§5 need and
 * tolerates the rich superset of CloudAsset fields.
 */
export function readInventoryBaselineRows(outDir: string): { rows: InventoryBaselineRow[]; sha256: string } | null {
  const p = resolve(outDir, 'inventory.json');
  if (!existsSync(p)) return null;
  let doc: any;
  try { doc = JSON.parse(readFileSync(p, 'utf8')); }
  catch { return null; }
  if (!doc || typeof doc !== 'object' || !Array.isArray(doc.assets)) return null;
  const sha = fileSha(p);
  if (!sha) return null;
  const rows: InventoryBaselineRow[] = [];
  for (const a of doc.assets) {
    if (!a || typeof a !== 'object') continue;
    const uniqueId = typeof a.uniqueId === 'string' ? a.uniqueId : null;
    if (!uniqueId) continue;
    const provider = typeof a.provider === 'string' ? a.provider : 'unknown';
    const assetType = typeof a.assetType === 'string' ? a.assetType : null;
    const resourceType = typeof a.resourceType === 'string' ? a.resourceType : null;
    const currentImage =
      typeof a.imageId === 'string' && a.imageId.trim() !== '' ? a.imageId
      : typeof a.hardwareMakeModel === 'string' && a.hardwareMakeModel.trim() !== '' ? a.hardwareMakeModel
      : null;
    const currentConfig =
      typeof a.baselineConfig === 'string' && a.baselineConfig.trim() !== '' ? a.baselineConfig
      : typeof a.osNameVersion === 'string' && a.osNameVersion.trim() !== '' ? a.osNameVersion
      : null;
    rows.push({
      uniqueId,
      provider,
      componentClass: componentClassFor(assetType, resourceType),
      componentType: assetType ?? resourceType ?? 'unknown',
      currentImage,
      currentConfig,
      encryptionAtRest: typeof a.encryptionAtRest === 'boolean' ? a.encryptionAtRest : null,
      state: typeof a.state === 'string' ? a.state : null,
    });
  }
  return { rows, sha256: sha };
}

/**
 * Parse a comma-separated single-quoted control list — e.g. `'sc-12', 'sc-13'` —
 * from a `nist_controls: [ … ]` capture into a clean array.
 */
function parseControlsCapture(capture: string): string[] {
  const out: string[] = [];
  for (const m of capture.matchAll(/'([^']+)'/g)) {
    const c = m[1]!.trim();
    if (c) out.push(c);
  }
  return out;
}

/**
 * Grep one provider's reference-arch.ts SOURCE for its documented hardening
 * expectations. Each expectation is a `finding({ rule: '…', … target: { summary:
 * '…', … }, … nist_controls: ['…', …] })` block; we pair each `rule` with the
 * FOLLOWING target summary + nist_controls (self-contained, in-order blocks).
 * The grep-against-source technique (same as roe-emit.ts:readKsiScope) avoids
 * importing the provider module — which would pull cloud SDK clients into the
 * emit path. Returns [] when the file is unreadable (caller records the gap).
 */
export function readReferenceArchitecture(provider: Provider, providersRoot?: string): { entries: RefArchEntry[]; readable: boolean; sha256: string | null } {
  const root = providersRoot ?? resolve(import.meta.dirname ?? '', '..', 'providers');
  const p = resolve(root, provider, 'reference-arch.ts');
  let src: string;
  try { src = readFileSync(p, 'utf8'); }
  catch { return { entries: [], readable: false, sha256: null }; }
  const sha = createHash('sha256').update(src).digest('hex');
  const entries: RefArchEntry[] = [];
  const re =
    /rule:\s*'([^']+)'[\s\S]*?severity:\s*'([^']+)'[\s\S]*?target:\s*\{\s*summary:\s*'((?:\\.|[^'\\])*)'[\s\S]*?nist_controls:\s*\[([^\]]*)\]/g;
  for (const m of src.matchAll(re)) {
    const rule = m[1]!.trim();
    const severity = m[2]!.trim();
    const baseline = m[3]!.replace(/\\'/g, "'").trim();
    const controls = parseControlsCapture(m[4]!);
    if (rule && baseline) entries.push({ provider, rule, baseline, controls, severity });
  }
  return { entries, readable: true, sha256: sha };
}

/** Read the documented reference architecture across all three providers. */
export function readReferenceArchitecturesAllProviders(providersRoot?: string): RefArchReadResult {
  const entries: RefArchEntry[] = [];
  const perProvider: Record<string, number> = {};
  const readable: Record<string, boolean> = {};
  const sha256: Record<string, string | null> = {};
  for (const provider of PROVIDERS) {
    const r = readReferenceArchitecture(provider, providersRoot);
    entries.push(...r.entries);
    perProvider[provider] = r.entries.length;
    readable[provider] = r.readable;
    sha256[provider] = r.sha256;
  }
  return { entries, perProvider, readable, sha256 };
}

// ─── Deviation diff (pure) ────────────────────────────────────────────────────

/** true when a reference entry is the image/AMI hardening-baseline anchor (CM-2/CM-6/CM-8 image provenance). */
function isHardeningImageAnchor(e: RefArchEntry): boolean {
  const controlHit = e.controls.some((c) => c === 'cm-2' || c === 'cm-6' || c === 'cm-8');
  const ruleHit = /\bami\b|image|approved|hardened|baseline|provenance/i.test(e.rule);
  return controlHit && ruleHit;
}

/** true when a reference entry anchors encryption-at-rest (SC-28 / KMS). */
function isEncryptionAnchor(e: RefArchEntry): boolean {
  return e.controls.some((c) => c.startsWith('sc-28') || c === 'sc-12' || c === 'sc-13') ||
    /kms|encrypt|customer_managed/i.test(e.rule);
}

/** Pick the first anchor matching a predicate for a provider (deterministic — entries are in source order). */
function anchorFor(entries: RefArchEntry[], provider: string, pred: (e: RefArchEntry) => boolean): RefArchEntry | null {
  return entries.find((e) => e.provider === provider && pred(e)) ?? null;
}

/**
 * Diff the real inventory rows against the reference-architecture hardening
 * anchors. Pure + deterministic. Deviations are grouped by (provider, component
 * class) so ephemeral / auto-scaling assets collapse into their class (Q4) rather
 * than fabricating a per-instance baseline. Two honest, source-grounded deviation
 * kinds are computed:
 *   1. Undocumented hardening baseline — an image-bearing class (compute /
 *      container) has ≥1 asset whose currentConfig is empty, while the provider
 *      reference architecture documents an approved-image/hardening expectation.
 *   2. Encryption-at-rest disabled — ≥1 asset reports encryptionAtRest === false
 *      while the provider reference architecture documents an encryption anchor.
 * Each deviation's severity is the anchoring reference finding's DECLARED severity
 * (never defaulted — Risk 4). When a provider documents no matching anchor, no
 * deviation is invented for that dimension.
 */
export function diffInventoryVsReference(inv: InventoryBaselineRow[], ref: RefArchEntry[]): DeviationRow[] {
  const out: DeviationRow[] = [];
  // Group inventory by provider + class (sorted for determinism).
  const groups = new Map<string, InventoryBaselineRow[]>();
  for (const r of inv) {
    const key = `${r.provider} ${r.componentClass}`;
    (groups.get(key) ?? groups.set(key, []).get(key)!).push(r);
  }
  const keys = [...groups.keys()].sort();
  for (const key of keys) {
    const rows = groups.get(key)!;
    const [provider, componentClass] = key.split(' ') as [string, string];

    // Deviation 1 — undocumented hardening baseline on image-bearing classes.
    if (componentClass === 'compute' || componentClass === 'container') {
      const undocumented = rows.filter((r) => r.currentConfig === null);
      const anchor = anchorFor(ref, provider, isHardeningImageAnchor);
      if (undocumented.length > 0 && anchor) {
        out.push({
          component: `${provider}/${componentClass}`,
          baseline: anchor.baseline,
          current: `${undocumented.length} of ${rows.length} ${componentClass} asset(s) run without a documented hardening baseline (baselineConfig empty)`,
          deviation: `Component class has no documented hardening baseline; the reference architecture expects an approved / STIG- or CIS-hardened image (${anchor.rule}, ${anchor.controls.join(', ')})`,
          severity: anchor.severity,
        });
      }
    }

    // Deviation 2 — encryption-at-rest disabled where the reference expects it.
    const unencrypted = rows.filter((r) => r.encryptionAtRest === false);
    if (unencrypted.length > 0) {
      const anchor = anchorFor(ref, provider, isEncryptionAnchor);
      if (anchor) {
        out.push({
          component: `${provider}/${componentClass}`,
          baseline: anchor.baseline,
          current: `${unencrypted.length} of ${rows.length} ${componentClass} asset(s) report encryption-at-rest disabled`,
          deviation: `Encryption at rest is disabled; the reference architecture expects encryption under customer-managed keys (${anchor.rule}, ${anchor.controls.join(', ')})`,
          severity: anchor.severity,
        });
      }
    }
  }
  return out;
}

// ─── §3 baseline-item projection (pure) ──────────────────────────────────────

/** Distinct, sorted, non-null values (capped) joined for a table cell. */
function distinctJoin(values: Array<string | null>, cap = 3): string {
  const set = [...new Set(values.filter((v): v is string => v !== null))].sort();
  if (set.length === 0) return TBD;
  const shown = set.slice(0, cap);
  return shown.join('; ') + (set.length > cap ? `; … (+${set.length - cap} more)` : '');
}

/** Project inventory rows into §3 baseline-item groups (per provider + class). */
export function buildBaselineItemRows(inv: InventoryBaselineRow[]): BaselineItemRow[] {
  const groups = new Map<string, InventoryBaselineRow[]>();
  for (const r of inv) {
    const key = `${r.provider} ${r.componentClass}`;
    (groups.get(key) ?? groups.set(key, []).get(key)!).push(r);
  }
  const rows: BaselineItemRow[] = [];
  for (const key of [...groups.keys()].sort()) {
    const g = groups.get(key)!;
    const [provider, componentClass] = key.split(' ') as [string, string];
    rows.push({
      component: `${provider}/${componentClass}`,
      baselineImage: distinctJoin(g.map((r) => r.currentImage)),
      baselineConfig: distinctJoin(g.map((r) => r.currentConfig)),
      currentCount: g.length,
      // CM-2 (baseline) + CM-8 (inventory) always; CM-6 (settings) for the baseline record.
      controls: ['CM-2', 'CM-6', 'CM-8'],
    });
  }
  return rows;
}

// ─── OOXML building blocks (same pattern as auth-cover-letter-emit.ts) ────────

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

export function buildBaselineConfigBodyXml(opts: BaselineConfigOptions): {
  xml: string;
  stats: Omit<BaselineConfigResult, 'path' | 'bytes'>;
} {
  const systemName = opts.systemName || TBD;
  const systemId = opts.systemId || TBD;
  const csp = opts.cspOrganization || TBD;
  const cadence: 'monthly' | 'quarterly' | 'annually' = opts.baselineReviewCadence ?? 'annually';
  const docUuid = deterministicUuid(`baseline-config:${systemId}:${opts.runId}`);

  // Real corpus.
  const inventory = readInventoryBaselineRows(opts.outDir);
  const refArch = readReferenceArchitecturesAllProviders(opts.providersRoot);
  const itemRows = inventory ? buildBaselineItemRows(inventory.rows) : [];
  const deviations = inventory ? diffInventoryVsReference(inventory.rows, refArch.entries) : [];
  const providersCovered = PROVIDERS.filter((p) => refArch.perProvider[p]! > 0);
  const anyRefReadable = PROVIDERS.some((p) => refArch.readable[p]);

  // Required-for-signature tracking (test #13: approver + deviation-log + cadence).
  const missing: string[] = [];
  if (!opts.baselineApprover) missing.push('baselineApprover (config.yaml: baseline_config.approver)');
  if (!opts.deviationLogLocation || opts.deviationLogLocation.trim() === '') missing.push('deviationLogLocation (config.yaml: baseline_config.deviation_log)');
  if (!opts.baselineReviewCadence) missing.push('baselineReviewCadence (config.yaml: baseline_config.review_cadence — defaulted to annually per CM-2 until set)');

  const parts: string[] = [];

  // ── Title block ──
  parts.push(para('Baseline Configuration Document', 'Title'));
  parts.push(para(`${systemName} — FedRAMP ${opts.impactLevel.toUpperCase()} — NIST SP 800-53 Rev. 5 CM-2`, 'Subtitle'));
  parts.push(para(
    'DRAFT — auto-generated by fedramp-20x-cloud-evidence. §3 Baseline Configuration Items is derived from the ' +
    'run\'s real inventory.json (CM-8); §4 Reference Architecture is grep-read from the ' +
    'providers/{aws,gcp,azure}/reference-arch.ts source; §5 Deviations from Baseline is a pure diff of the two. ' +
    `The operator must complete every ${TBD} marker and the baseline approver must sign §8 before this document ` +
    'is treated as the approved baseline of record. This is the CM-2 baseline (what each component is approved to ' +
    'run) — distinct from the CM-8 inventory (what components exist) and from the AFR Secure Configuration Guide ' +
    '(the recommended secure configuration).',
    'Disclaimer',
  ));

  // ── §1 Introduction ──
  parts.push(heading('1. Introduction and Purpose', 1));
  parts.push(para(
    'This document is the baseline configuration for the system identified below, satisfying NIST SP 800-53 ' +
    `Rev. 5 control CM-2 (Baseline Configuration): "${CM_2_QUOTE}" NIST SP 800-128 §3.2 (Guide for ` +
    `Security-Focused Configuration Management of Information Systems) defines the artifact: "${SP_800_128_QUOTE}"`,
  ));
  parts.push(para(
    'Rev. 5 separates CM-2 (the approved configuration of record) from CM-8 (the inventory of components). This ' +
    'document is the CM-2 half; the CM-8 inventory is maintained in the Integrated Inventory Workbook. CM-2(2) ' +
    '(Automation Support for Accuracy and Currency) is satisfied by auto-deriving the baseline from the real ' +
    'inventory and the provider reference-architecture source rather than by hand, and CM-2(7) (Configure Systems ' +
    'and Components for High-Risk Areas) is addressed through the hardening expectations in §4. This baseline is ' +
    'the specification the Configuration Management Plan (CMP §5, LOOP-C.C1) cross-links to and the basis the ' +
    'continuous-monitoring pipeline uses to detect drift.',
  ));
  parts.push(fieldTable([
    ['System Name', systemName],
    ['System ID', systemId],
    ['CSP Organization', csp],
    ['FedRAMP Impact Level', opts.impactLevel.toUpperCase()],
    ['Run ID', opts.runId],
    ['FRMR Catalog Version', opts.frmrVersion],
    ['Document UUID', docUuid],
  ]));

  // ── §2 Methodology ──
  parts.push(heading('2. Methodology and Provenance', 1));
  parts.push(para(
    'The baseline is assembled from three real sources, each cited by content SHA-256 in the Provenance footer:',
  ));
  parts.push(para(
    '• §3 Baseline Configuration Items — grouped from the run\'s real out/inventory.json. Assets are grouped by ' +
    '(cloud provider, component class), where component class is a normalized mapping (compute, container, ' +
    'database, storage, network, identity, serverless) over the provider-native asset types, so ephemeral and ' +
    'auto-scaling assets collapse into their class baseline instead of producing an unstable per-instance ' +
    'baseline.\n' +
    '• §4 Reference Architecture — grep-read from the providers/{aws,gcp,azure}/reference-arch.ts source files. ' +
    'Each documented hardening expectation (rule, target, NIST controls) is extracted directly from source, the ' +
    'same technique the Rules of Engagement emitter uses on ksi-map.ts, so no provider cloud SDK client is loaded ' +
    'at emit time.\n' +
    '• §5 Deviations from Baseline — a pure diff of the real inventory rows against the §4 hardening anchors. Each ' +
    'deviation\'s severity is the declared severity of the anchoring reference finding (never defaulted). The ' +
    'related AFR Secure Configuration Guide comparator (core/scg-comparator.ts, LOOP-G.G5) performs the ' +
    'complementary setting-level compare of observed settings against the recommended secure defaults; it is the ' +
    'RECOMMENDED-configuration counterpart to this baseline-of-record.',
  ));

  // ── §3 Baseline Configuration Items ──
  parts.push(heading('3. Baseline Configuration Items', 1));
  if (inventory && itemRows.length > 0) {
    parts.push(para(
      `The following configuration-item groups are derived from the ${inventory.rows.length} asset(s) in the ` +
      'run\'s inventory.json (CM-8). Each row is the approved baseline for a (provider, component class) group: ' +
      'the current image(s) in use and the documented hardening baseline. Per-asset detail lives in the ' +
      'Integrated Inventory Workbook, which this baseline cross-references (CM-2 ↔ CM-8).',
    ));
    parts.push(table(
      ['Configuration Item (provider / class)', 'Baseline Image(s)', 'Baseline Config / Hardening', 'Count', 'Controls'],
      itemRows.map((r) => [r.component, r.baselineImage, r.baselineConfig, String(r.currentCount), r.controls.join(', ')]),
      [3000, 2600, 2600, 800, 1200],
    ));
    parts.push(para(
      `Total configuration-item groups: ${itemRows.length} across ${inventory.rows.length} asset(s). Where the ` +
      `Baseline Config / Hardening cell reads ${TBD}, the asset group has no documented hardening baseline recorded ` +
      'in inventory (no baselineConfig / osNameVersion) — those groups are surfaced as deviations in §5.',
    ));
  } else {
    parts.push(para(
      `${TBD}: the inventory (out/inventory.json) was not present or carried no assets when this document was ` +
      'generated, so the baseline configuration items could not be auto-derived. Run the collector so inventory.json ' +
      'is written before the baseline-config document is emitted (the orchestrator sequences inventory → ' +
      'baseline-config → CMP). Until then, enumerate the baseline configuration items manually.',
    ));
  }
  if (opts.configurationItemsOverride && opts.configurationItemsOverride.length > 0) {
    parts.push(heading('3.1 Operator Configuration-Item Overrides', 2));
    parts.push(para(
      'The operator supplied the following configuration-item baselines where the reference architecture is ' +
      'incomplete. These are operator-declared baselines (config.yaml: baseline_config.configuration_items_override).',
    ));
    parts.push(table(
      ['Component', 'Operator-Declared Baseline', 'Declared Deviations'],
      opts.configurationItemsOverride.map((o) => [o.component, o.baseline, o.deviations.length > 0 ? o.deviations.join('; ') : 'none declared']),
      [3000, 3500, 2900],
    ));
  }

  // ── §4 Reference Architecture ──
  parts.push(heading('4. Reference Architecture', 1));
  if (anyRefReadable && refArch.entries.length > 0) {
    parts.push(para(
      'The documented hardening expectations below are grep-read from the ' +
      'providers/{aws,gcp,azure}/reference-arch.ts source. Each expectation states the approved secure baseline ' +
      'the running environment is measured against and the NIST controls it anchors. These expectations derive ' +
      'from published CIS Benchmarks and cloud-vendor reference architectures (cited, not copied — CIS content is ' +
      'licensed).',
    ));
    parts.push(table(
      ['Provider', 'Baseline Expectation (rule)', 'Reference Baseline', 'Controls'],
      refArch.entries.map((e) => [e.provider.toUpperCase(), e.rule, e.baseline, e.controls.join(', ')]),
      [1100, 2600, 3900, 1400],
    ));
    parts.push(para(
      'Per-provider reference-architecture coverage: ' +
      PROVIDERS.map((p) => `${p.toUpperCase()} ${refArch.perProvider[p]} expectation(s)${refArch.readable[p] ? '' : ' (source not readable)'}`).join('; ') +
      '. A provider with fewer documented expectations carries a smaller reference baseline — surfaced here so the ' +
      '3PAO can weigh coverage per cloud (Risk 5).',
    ));
  } else {
    parts.push(para(
      `${TBD}: no provider reference-architecture source (providers/{aws,gcp,azure}/reference-arch.ts) was ` +
      'readable when this document was generated, so §4 could not be auto-derived and §5 has no hardening anchors ' +
      'to diff against. Confirm the reference-arch.ts source files are present in the checkout; until then, ' +
      'document the reference architecture manually against the applicable CIS Benchmarks.',
    ));
  }

  // ── §5 Deviations from Baseline ──
  parts.push(heading('5. Deviations from Baseline', 1));
  if (!inventory || !anyRefReadable) {
    parts.push(para(
      'Deviation analysis requires both the inventory and the reference architecture. One or both were absent this ' +
      `run (see §3 / §4), so no automated deviation diff was computed. Resolve the ${TBD} markers above and re-run ` +
      'to populate this section.',
    ));
  } else if (deviations.length > 0) {
    parts.push(para(
      `The pure diff of the real inventory against the §4 reference-architecture hardening anchors found the ` +
      `following ${deviations.length} deviation(s). Each severity is the declared severity of the anchoring ` +
      'reference finding — not a default. Each deviation is tracked to closure through the §7 deviation-approval ' +
      'process (CMP §6 Change Control).',
    ));
    parts.push(table(
      ['Component', 'Baseline (reference)', 'Current (observed)', 'Deviation', 'Severity'],
      deviations.map((d) => [d.component, d.baseline, d.current, d.deviation, d.severity]),
      [1800, 2600, 2400, 2800, 1000],
    ));
  } else {
    parts.push(para(
      'The pure diff of the real inventory against the §4 reference-architecture hardening anchors found no ' +
      'deviations: every image-bearing component group has a documented hardening baseline and no asset reports ' +
      'encryption-at-rest disabled where the reference architecture expects it. New deviations are detected on each ' +
      'run and by the continuous-monitoring pipeline.',
    ));
  }

  // ── §6 Baseline Maintenance ──
  parts.push(heading('6. Baseline Maintenance', 1));
  parts.push(para(
    `This baseline is reviewed and updated on a ${cadence} cadence and additionally whenever system components are ` +
    'installed or upgraded, or when a significant change is proposed — per CM-2(b). The automated derivation ' +
    '(CM-2(2)) means each collector run re-computes §3–§5 from the then-current inventory and reference ' +
    'architecture, so the baseline stays current between formal reviews.',
  ));
  parts.push(fieldTable([
    ['Review Cadence', cadence + (opts.baselineReviewCadence ? '' : ` (${TBD} — defaulted to annually per CM-2; set config.yaml: baseline_config.review_cadence)`)],
    ['On-Change Triggers', 'Component install / upgrade; significant change; a §5 deviation reaching the approval threshold'],
    ['Automation (CM-2(2))', 'Re-derived from inventory.json + reference-arch.ts on every collector run'],
  ]));

  // ── §7 Deviation Approval Process ──
  parts.push(heading('7. Deviation Approval Process', 1));
  parts.push(para(
    'Each §5 deviation is reviewed for security impact, tested, and either remediated to the baseline or formally ' +
    'accepted with a documented risk decision, through the change-control workflow defined in the Configuration ' +
    'Management Plan (cmp.docx §6, LOOP-C.C1) and NIST SP 800-128 §3.2. Accepted deviations are recorded in the ' +
    'deviation log below and reflected in the POA&M when they carry residual risk.',
  ));
  parts.push(fieldTable([
    ['Change-Control Reference', 'cmp.docx §6 (Configuration Management Plan, CM-3 / CM-4)'],
    ['Deviation Log Location', opts.deviationLogLocation && opts.deviationLogLocation.trim() !== '' ? opts.deviationLogLocation : `${TBD} (config.yaml: baseline_config.deviation_log)`],
    ['Security-Impact Analysis', 'Per CM-4; required before a deviation is approved'],
  ]));

  // ── §8 Approval Signatures ──
  parts.push(heading('8. Approval Signatures', 1));
  parts.push(para(
    'The baseline configuration is formally reviewed and approved below (NIST SP 800-128 §3.2 — "formally reviewed ' +
    'and agreed-upon"). This signature block is the human baseline approval and is never auto-signed by the ' +
    'toolkit; the document\'s integrity is separately anchored by the pipeline (SHA-256 + Ed25519 over the signed ' +
    'submission-bundle INDEX.json).',
  ));
  const approver = opts.baselineApprover;
  if (approver) {
    parts.push(para(''));
    parts.push(para('_______________________________________'));
    parts.push(para(`${approver.name}`));
    parts.push(para(`${approver.role}, ${approver.org}`));
    parts.push(para(`Date: ${approver.date && approver.date.trim() !== '' ? approver.date : '____________________'}`));
  } else {
    parts.push(para(
      `${TBD}: the baseline approver was not supplied, so the approval signature block is left unfilled. Set ` +
      'config.yaml: baseline_config.approver (name / role / org / optional date). A CM-2 baseline is not the ' +
      'approved baseline of record until it is formally reviewed and signed.',
    ));
  }

  // ── Provenance footer ──
  parts.push(heading('Provenance', 2));
  parts.push(para(
    `Generated by core/baseline-config-emit.ts (run ${opts.runId}, FRMR ${opts.frmrVersion}). ` +
    `§3 baseline items: ${inventory ? `inventory.json (sha256 ${inventory.sha256}, ${inventory.rows.length} asset(s), ${itemRows.length} group(s))` : 'inventory.json not present this run'}. ` +
    `§4 reference architecture: ${PROVIDERS.map((p) => `${p} reference-arch.ts (${refArch.readable[p] ? `sha256 ${refArch.sha256[p]}, ${refArch.perProvider[p]} expectation(s)` : 'not readable'})`).join('; ')}. ` +
    `§5 deviations: ${deviations.length} computed. ` +
    `Control basis: NIST SP 800-53 Rev. 5 CM-2 — ${SP_800_53_URL}. Configuration-management guide: NIST SP 800-128 §3.2 — ${SP_800_128_URL}. Hardening standard: CIS Benchmarks — ${CIS_BENCHMARKS_URL}. ` +
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
      inventory_present: inventory !== null,
      baseline_item_count: itemRows.length,
      asset_count: inventory?.rows.length ?? 0,
      reference_entry_count: refArch.entries.length,
      providers_covered: providersCovered,
      deviation_count: deviations.length,
      review_cadence: cadence,
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
  const title = `Baseline Configuration Document (CM-2) — ${systemName} [${docUuid}]`;
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

/** Pure: render the baseline configuration Word document to a Buffer. */
export function renderBaselineConfigDocx(opts: BaselineConfigOptions): {
  buffer: Buffer;
  stats: Omit<BaselineConfigResult, 'path' | 'bytes'>;
} {
  const { xml, stats } = buildBaselineConfigBodyXml(opts);
  const systemName = opts.systemName || TBD;
  const systemId = opts.systemId || TBD;
  const docUuid = deterministicUuid(`baseline-config:${systemId}:${opts.runId}`);
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

/** Read inventory.json + reference-arch.ts, render, and write baseline-config.docx. */
export function emitBaselineConfigDocx(opts: BaselineConfigOptions): BaselineConfigResult {
  const { buffer, stats } = renderBaselineConfigDocx(opts);
  const outPath = opts.outPath ?? resolve(opts.outDir, 'baseline-config.docx');
  writeFileSync(outPath, buffer);
  log.info({
    event: 'baseline_config.emitted',
    path: outPath,
    bytes: buffer.length,
    inventory_present: stats.inventory_present,
    baseline_item_count: stats.baseline_item_count,
    asset_count: stats.asset_count,
    reference_entry_count: stats.reference_entry_count,
    providers_covered: stats.providers_covered,
    deviation_count: stats.deviation_count,
    review_cadence: stats.review_cadence,
    ready_for_signature: stats.ready_for_signature,
    requires_operator_input_count: stats.requires_operator_input.length,
  });
  return { path: outPath, bytes: buffer.length, ...stats };
}
