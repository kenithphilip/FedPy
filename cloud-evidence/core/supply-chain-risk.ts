/**
 * Supply Chain Risk Register (SR-3) + SBOM integration — LOOP-J.J3.
 *
 * Joins SBOM-derived CVEs (core/sbom.ts), CISA KEV exposure (core/kev-feed.ts),
 * subprocessor risk-tier data (core/subprocessor-inventory.ts, J.J2), and
 * operator-asserted advisory events into a single per-system C-SCRM Plan
 * artifact — the NIST SP 800-53 Rev 5 SR-3 "supply chain processes and
 * controls" document and the NIST SP 800-161r1 Tier-3 supplier-risk register.
 *
 * Emits a signed, canonical `supply-chain-risk-register.json` + a multi-sheet
 * `supply-chain-risk-register.xlsx` (one sheet per RiskCategory + Summary +
 * SBOM-Provenance). The register's open critical/high entries also flow back as
 * POA&M `risk-source = supply-chain` items (wired in core/oscal-poam.ts) and an
 * SSP back-matter resource (core/oscal-ssp.ts).
 *
 * REO compliance:
 *   - Every entry traces to a real source: parsed SBOM (Syft/Trivy/Grype output
 *     via core/sbom.ts), committed CISA KEV catalog (core/kev-feed.ts), the J.J2
 *     subprocessor inventory, or an operator --risks-config (REO Rule 4 input).
 *   - No invented CVE ids / severities — SBOM CVEs flow through core/sbom.ts NVD
 *     correlation; `UNKNOWN` maps to `medium` and is FLAGGED, never silently
 *     downgraded. KEV elevation (→ critical) is CISA-published guidance.
 *   - Mitigation language is operator-input only; the REQUIRES-OPERATOR-INPUT
 *     literal is emitted when a non-open entry lacks one.
 *   - NTIA SBOM minimum-element flags are computed from the real parse, never
 *     assumed true.
 *   - The output carries a G3 provenance block (emitter/emittedAt/sourceCalls/
 *     signingKeyId) + a self-contained detached Ed25519 signature.
 *
 * Pure builder (`buildSupplyChainRiskRegister`) + disk emitter
 * (`emitSupplyChainRiskRegister`) + operator-config reader (`readRisksConfig`).
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, isAbsolute, basename } from 'node:path';
import YAML from 'yaml';
import { canonicalize, signDetached, type DetachedSignature } from './sign.ts';
import { xmlEscape, zipStore } from './zip.ts';
import { deterministicUuid } from './oscal.ts';
import type { SbomReport } from './sbom.ts';
import { loadKevCatalog, type KevEntry } from './kev-feed.ts';
import type { SubprocessorInventory } from './subprocessor-inventory.ts';
import type { SubprocessorRow } from './subprocessors-sheet.ts';

export const SUPPLY_CHAIN_RISK_JSON = 'supply-chain-risk-register.json';
export const SUPPLY_CHAIN_RISK_XLSX = 'supply-chain-risk-register.xlsx';

/** Operator-input marker (mirrors core/roe-emit.ts precedent). */
const TBD = 'REQUIRES-OPERATOR-INPUT';

export type RiskCategory =
  | 'sbom-cve'
  | 'sbom-cve-kev'
  | 'subprocessor-risk-tier'
  | 'subprocessor-soc2-expired'
  | 'unsigned-sbom'
  | 'vendor-advisory'
  | 'operator-asserted-risk';

export type RiskSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type RiskStatus = 'open' | 'monitoring' | 'mitigated' | 'accepted';

export interface RiskEntry {
  id: string;
  category: RiskCategory;
  title: string;
  description: string;
  severity: RiskSeverity;
  status: RiskStatus;
  affected_components?: string[];
  affected_subprocessors?: string[];
  cve_ids?: string[];
  kev_due_date?: string;
  mitigation_summary?: string;
  evidence_source: { module: string; record_id?: string };
  first_seen: string;
  last_seen: string;
  related_nist_controls: string[];
}

export interface SbomProvenance {
  sbom_file: string;
  format: 'cyclonedx' | 'spdx' | 'unknown';
  supplier_name_field_present: boolean;
  component_name_field_present: boolean;
  version_field_present: boolean;
  unique_identifier_field_present: boolean;
  dependency_field_present: boolean;
  author_field_present: boolean;
  timestamp_field_present: boolean;
  signature_status: 'verified' | 'unverified' | 'absent';
}

export interface RegisterCoverage {
  total_entries: number;
  open_critical: number;
  open_high: number;
  open_medium: number;
  open_low: number;
  kev_exposed: number;
  unsigned_sboms: number;
  tier_1_critical_subprocessors: number;
  entries_missing_mitigation: string[];
}

export interface SubprocessorSummary {
  total: number;
  tier_1_critical: number;
  tier_2_significant: number;
  tier_3_routine: number;
  missing_risk_tier: number;
}

interface RegisterProvenance {
  emitter: 'core/supply-chain-risk.ts';
  emittedAt: string;
  sourceCalls: string[];
  /** Modules actually consulted to build this register. */
  sourceModules: string[];
  /** Real files on disk that were read. */
  sourceFiles: string[];
  signingKeyId: string;
}

export interface SupplyChainRiskRegister {
  schema_version: '1.0.0';
  generated_at: string;
  system_id?: string;
  run_id: string;
  entries: RiskEntry[];
  coverage: RegisterCoverage;
  sbom_provenance: SbomProvenance[];
  subprocessor_summary: SubprocessorSummary;
  warnings: string[];
  /** `${entry.id}:${field}` markers where an operator input is required. */
  requires_operator_input: string[];
  provenance: RegisterProvenance;
  signature?: DetachedSignature;
}

export interface OperatorRiskEntry {
  id?: string;
  category?: RiskCategory;
  title: string;
  description?: string;
  severity?: RiskSeverity;
  status?: RiskStatus;
  affected_components?: string[];
  affected_subprocessors?: string[];
  mitigation_summary?: string;
  first_seen?: string;
  related_nist_controls?: string[];
}

export interface MitigationOverride {
  entry_id_match: string;
  mitigation_summary?: string;
  status?: RiskStatus;
}

const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}/;
const SEVERITY_ENUM: RiskSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];
const STATUS_ENUM: RiskStatus[] = ['open', 'monitoring', 'mitigated', 'accepted'];

/** Map core/sbom.ts UPPERCASE NVD severity → register lower-case severity. */
function mapSbomSeverity(s: string | undefined): { severity: RiskSeverity; unknown: boolean } {
  switch (s) {
    case 'CRITICAL':
      return { severity: 'critical', unknown: false };
    case 'HIGH':
      return { severity: 'high', unknown: false };
    case 'MEDIUM':
      return { severity: 'medium', unknown: false };
    case 'LOW':
      return { severity: 'low', unknown: false };
    default:
      // UNKNOWN / undefined → medium, FLAGGED (never silently 'low').
      return { severity: 'medium', unknown: true };
  }
}

/** Date-only string (YYYY-MM-DD) from an ISO date/datetime; '' if unparseable. */
function dateOnly(s: string | undefined): string {
  if (!s) return '';
  const m = ISO_DATE_RE.exec(s);
  return m ? s.slice(0, 10) : '';
}

/** Add `days` to a YYYY-MM-DD date, returning YYYY-MM-DD (UTC). */
export function addDaysIso(dateStr: string, days: number): string {
  const base = new Date(`${dateStr.slice(0, 10)}T00:00:00Z`);
  if (Number.isNaN(base.getTime())) return dateStr;
  base.setUTCDate(base.getUTCDate() + days);
  return base.toISOString().slice(0, 10);
}

// ─── NTIA SBOM minimum-element flag computation (per-format, from real parse) ──

function ntiaFlags(format: 'cyclonedx' | 'spdx' | 'unknown', raw: any): Omit<
  SbomProvenance,
  'sbom_file' | 'format' | 'signature_status'
> {
  const F = (b: unknown) => Boolean(b);
  if (format === 'cyclonedx' && raw) {
    const comps: any[] = Array.isArray(raw.components) ? raw.components : [];
    const md = raw.metadata ?? {};
    return {
      supplier_name_field_present: F(comps.some((c) => c?.supplier?.name)),
      component_name_field_present: F(comps.some((c) => c?.name)),
      version_field_present: F(comps.some((c) => c?.version)),
      unique_identifier_field_present: F(comps.some((c) => c?.purl || c?.cpe || c?.swid)),
      dependency_field_present: F(Array.isArray(raw.dependencies) && raw.dependencies.length > 0),
      author_field_present: F(
        (Array.isArray(md.authors) && md.authors.length > 0) || md.manufacture || md.tools,
      ),
      timestamp_field_present: F(md.timestamp),
    };
  }
  if (format === 'spdx' && raw) {
    const pkgs: any[] = Array.isArray(raw.packages) ? raw.packages : [];
    const rels: any[] = Array.isArray(raw.relationships) ? raw.relationships : [];
    const ci = raw.creationInfo ?? {};
    return {
      supplier_name_field_present: F(pkgs.some((p) => p?.supplier && p.supplier !== 'NOASSERTION')),
      component_name_field_present: F(pkgs.some((p) => p?.name)),
      version_field_present: F(pkgs.some((p) => p?.versionInfo)),
      unique_identifier_field_present: F(
        pkgs.some((p) => (p?.externalRefs ?? []).some((r: any) => r?.referenceCategory === 'PACKAGE-MANAGER')),
      ),
      dependency_field_present: F(rels.some((r) => r?.relationshipType === 'DEPENDS_ON')),
      author_field_present: F(Array.isArray(ci.creators) && ci.creators.length > 0),
      timestamp_field_present: F(ci.created),
    };
  }
  // Unknown format or no raw payload — cannot verify; all false (never assumed).
  return {
    supplier_name_field_present: false,
    component_name_field_present: false,
    version_field_present: false,
    unique_identifier_field_present: false,
    dependency_field_present: false,
    author_field_present: false,
    timestamp_field_present: false,
  };
}

// ─── Builder input ────────────────────────────────────────────────────────────

export interface BuildRegisterInput {
  sbomReport: SbomReport | null;
  /** Parsed raw SBOM payloads keyed by SbomFile.path (for NTIA-flag computation). */
  sbomRaw?: Record<string, unknown>;
  subprocessorInventory: SubprocessorInventory | null;
  /** CISA KEV catalog, CVE-ID (upper-case) → entry. */
  kev: Map<string, KevEntry>;
  operatorRisks?: OperatorRiskEntry[];
  mitigations?: MitigationOverride[];
  warnings?: string[];
  sourceModules: string[];
  sourceFiles: string[];
}

export interface BuildRegisterOptions {
  runId: string;
  systemId?: string;
  now?: () => Date;
}

/**
 * Pure builder. Joins SBOM CVEs (+ KEV elevation), unsigned SBOMs, subprocessor
 * risk tiers / expired SOC2, and operator-asserted risks into a single sorted,
 * deterministic register with coverage + NTIA SBOM provenance.
 */
export function buildSupplyChainRiskRegister(
  input: BuildRegisterInput,
  opts: BuildRegisterOptions,
): SupplyChainRiskRegister {
  const now = opts.now ?? (() => new Date());
  const nowDate = now();
  const nowIso = nowDate.toISOString();
  const nowDateOnly = nowIso.slice(0, 10);
  const warnings = [...(input.warnings ?? [])];
  const requires = new Set<string>();
  const byId = new Map<string, RiskEntry>();
  const add = (e: RiskEntry) => byId.set(e.id, e);

  // Best-effort run-level first_seen anchor from the first SBOM's metadata.
  const sbomTimestamp = (() => {
    for (const s of input.sbomReport?.sboms ?? []) {
      const raw: any = input.sbomRaw?.[s.path];
      const t = s.format === 'spdx' ? raw?.creationInfo?.created : raw?.metadata?.timestamp;
      const d = dateOnly(t);
      if (d) return d;
    }
    return '';
  })();

  // 1. SBOM CVEs (deduped by CVE id; KEV elevation removes the plain entry).
  for (const v of input.sbomReport?.vulnerabilities ?? []) {
    const cve = (v.cve_id ?? '').toUpperCase();
    if (!cve) continue;
    const mapped = mapSbomSeverity(v.severity);
    const kevEntry = input.kev.get(cve);
    const category: RiskCategory = kevEntry ? 'sbom-cve-kev' : 'sbom-cve';
    const id = deterministicUuid(`scrr:${category}:${cve}`);
    const firstSeen = kevEntry?.dateAdded
      ? dateOnly(kevEntry.dateAdded) || sbomTimestamp || nowDateOnly
      : sbomTimestamp || nowDateOnly;
    const severity: RiskSeverity = kevEntry ? 'critical' : mapped.severity;
    const title = kevEntry
      ? `[KEV] ${kevEntry.vulnerabilityName ?? cve}`
      : `${cve} in ${v.affected_components.length} component(s)`;
    const description = kevEntry
      ? `CISA KEV-listed: ${kevEntry.shortDescription ?? kevEntry.vulnerabilityName ?? cve}. ` +
        `Required action by CISA due date ${kevEntry.dueDate}. Affects: ${v.affected_components.join(', ')}.`
      : `SBOM-derived CVE ${cve}${mapped.unknown ? ' (NVD severity UNKNOWN → mapped to medium, REQUIRES-OPERATOR-INPUT)' : ''}. ` +
        `Affects: ${v.affected_components.join(', ')}.`;
    if (mapped.unknown && !kevEntry) requires.add(`${id}:severity`);
    add({
      id,
      category,
      title,
      description,
      severity,
      status: 'open',
      affected_components: [...v.affected_components],
      cve_ids: [cve],
      kev_due_date: kevEntry?.dueDate,
      evidence_source: { module: 'core/sbom.ts', record_id: cve },
      first_seen: firstSeen,
      last_seen: nowDateOnly,
      related_nist_controls: kevEntry ? ['sr-3', 'sr-4', 'si-2', 'ra-5'] : ['sr-3', 'sr-4', 'ra-5'],
    });
  }

  // 2. Unsigned SBOMs.
  for (const s of input.sbomReport?.sboms ?? []) {
    if (s.signature_status === 'verified') continue;
    const id = deterministicUuid(`scrr:unsigned-sbom:${s.path}`);
    const distinction =
      s.signature_status === 'unverified'
        ? 'cosign verification ran but did NOT succeed (no key, missing binary, or signature mismatch)'
        : 'no signature sidecar was present (verification was not attempted)';
    add({
      id,
      category: 'unsigned-sbom',
      title: `Unsigned SBOM: ${basename(s.path)}`,
      description: `SBOM ${s.image} (${s.format}) is not verifiably signed — ${distinction}. Per FedRAMP SR-4 provenance expectations, sign SBOMs with cosign and publish the public key.`,
      severity: 'medium',
      status: 'open',
      affected_components: [s.image],
      evidence_source: { module: 'core/sbom.ts', record_id: s.path },
      first_seen: sbomTimestamp || nowDateOnly,
      last_seen: nowDateOnly,
      related_nist_controls: ['sr-3', 'sr-4'],
    });
  }

  // 3. Subprocessor risk (tier-1-critical + expired SOC2).
  const rows: SubprocessorRow[] = input.subprocessorInventory?.rows ?? [];
  for (const r of rows) {
    if (r.name === TBD) continue; // skip the J.J2 no-source sentinel row
    if (r.risk_tier === 'tier-1-critical') {
      const id = deterministicUuid(`scrr:subprocessor-risk-tier:${r.name}`);
      add({
        id,
        category: 'subprocessor-risk-tier',
        title: `Tier-1-critical subprocessor: ${r.name}`,
        description: `${r.name}${r.role ? ` (${r.role})` : ''} is a tier-1-critical subprocessor (SA-9 / 800-161r1 supplier-risk). Maintain continuous oversight + monitoring.`,
        severity: 'high',
        status: 'open',
        affected_subprocessors: [r.name],
        evidence_source: { module: 'core/subprocessor-inventory.ts', record_id: r.name },
        first_seen: r.last_audit_date && dateOnly(r.last_audit_date) ? dateOnly(r.last_audit_date) : nowDateOnly,
        last_seen: nowDateOnly,
        related_nist_controls: ['sr-3', 'sr-6', 'sa-9'],
      });
    }
    if (r.soc2_expiry) {
      const expiryMs = Date.parse(r.soc2_expiry);
      if (!Number.isNaN(expiryMs) && expiryMs < nowDate.getTime()) {
        const id = deterministicUuid(`scrr:subprocessor-soc2-expired:${r.name}`);
        add({
          id,
          category: 'subprocessor-soc2-expired',
          title: `Expired SOC2 attestation: ${r.name}`,
          description: `${r.name}'s SOC2 attestation expired on ${r.soc2_expiry}. Obtain a current attestation or re-assess the supplier (SR-6).`,
          severity: 'medium',
          status: 'open',
          affected_subprocessors: [r.name],
          evidence_source: { module: 'core/subprocessor-inventory.ts', record_id: r.name },
          first_seen: dateOnly(r.soc2_expiry) || nowDateOnly,
          last_seen: nowDateOnly,
          related_nist_controls: ['sr-3', 'sr-6'],
        });
      }
    }
  }

  // 4. Operator-asserted risks.
  for (const o of input.operatorRisks ?? []) {
    const category: RiskCategory = o.category ?? 'operator-asserted-risk';
    const id = o.id ? o.id : deterministicUuid(`scrr:${category}:${o.title}`);
    add({
      id,
      category,
      title: o.title,
      description: o.description ?? o.title,
      severity: o.severity ?? 'medium',
      status: o.status ?? 'open',
      affected_components: o.affected_components,
      affected_subprocessors: o.affected_subprocessors,
      mitigation_summary: o.mitigation_summary,
      evidence_source: { module: 'operator:--risks-config', record_id: o.id },
      first_seen: (o.first_seen && dateOnly(o.first_seen)) || nowDateOnly,
      last_seen: nowDateOnly,
      related_nist_controls: o.related_nist_controls ?? ['sr-3'],
    });
  }

  // 5. Mitigation overrides (status + mitigation_summary only).
  for (const m of input.mitigations ?? []) {
    const entry = byId.get(m.entry_id_match);
    if (!entry) continue;
    if (m.status) entry.status = m.status;
    if (m.mitigation_summary) entry.mitigation_summary = m.mitigation_summary;
    if (
      entry.category === 'sbom-cve-kev' &&
      m.status === 'accepted' &&
      (!m.mitigation_summary || m.mitigation_summary.length < 50)
    ) {
      warnings.push(
        `Operator override accepted KEV entry ${entry.id} without a substantive (≥50 char) mitigation_summary — surfaced for 3PAO review.`,
      );
    }
  }

  // Mitigation-required marker: non-open entry without a mitigation_summary.
  for (const e of byId.values()) {
    if (e.status !== 'open' && !e.mitigation_summary) {
      e.mitigation_summary = TBD;
      requires.add(`${e.id}:mitigation_summary`);
    }
  }

  const entries = [...byId.values()].sort(
    (a, b) =>
      a.category.localeCompare(b.category) ||
      SEVERITY_ENUM.indexOf(a.severity) - SEVERITY_ENUM.indexOf(b.severity) ||
      a.id.localeCompare(b.id),
  );

  // Coverage.
  const openOf = (sev: RiskSeverity) => entries.filter((e) => e.status === 'open' && e.severity === sev).length;
  const coverage: RegisterCoverage = {
    total_entries: entries.length,
    open_critical: openOf('critical'),
    open_high: openOf('high'),
    open_medium: openOf('medium'),
    open_low: openOf('low'),
    kev_exposed: entries.filter((e) => e.category === 'sbom-cve-kev').length,
    unsigned_sboms: entries.filter((e) => e.category === 'unsigned-sbom').length,
    tier_1_critical_subprocessors: entries.filter((e) => e.category === 'subprocessor-risk-tier').length,
    entries_missing_mitigation: entries
      .filter((e) => e.status !== 'open' && (!e.mitigation_summary || e.mitigation_summary === TBD))
      .map((e) => e.id),
  };

  // SBOM provenance (NTIA flags per ingested SBOM, from real parse).
  const sbomProvenance: SbomProvenance[] = (input.sbomReport?.sboms ?? []).map((s) => ({
    sbom_file: basename(s.path),
    format: s.format,
    ...ntiaFlags(s.format, input.sbomRaw?.[s.path]),
    signature_status: s.signature_status,
  }));

  // Subprocessor summary.
  const realRows = rows.filter((r) => r.name !== TBD);
  const subprocessorSummary: SubprocessorSummary = {
    total: realRows.length,
    tier_1_critical: realRows.filter((r) => r.risk_tier === 'tier-1-critical').length,
    tier_2_significant: realRows.filter((r) => r.risk_tier === 'tier-2-significant').length,
    tier_3_routine: realRows.filter((r) => r.risk_tier === 'tier-3-routine').length,
    missing_risk_tier: realRows.filter((r) => !r.risk_tier).length,
  };

  return {
    schema_version: '1.0.0',
    generated_at: nowIso,
    system_id: opts.systemId,
    run_id: opts.runId,
    entries,
    coverage,
    sbom_provenance: sbomProvenance,
    subprocessor_summary: subprocessorSummary,
    warnings,
    requires_operator_input: [...requires].sort(),
    provenance: {
      emitter: 'core/supply-chain-risk.ts',
      emittedAt: nowIso,
      sourceCalls: input.sourceModules.map((m) => `module:${m}`),
      sourceModules: input.sourceModules,
      sourceFiles: input.sourceFiles,
      signingKeyId: '',
    },
  };
}

// ─── Operator risks-config reader ─────────────────────────────────────────────

export interface RisksConfig {
  risks: OperatorRiskEntry[];
  mitigations: MitigationOverride[];
}

const ALLOWED_RISKS_KEYS = new Set(['risks', 'mitigations']);

/** Read + validate an operator --risks-config (YAML/JSON). Rejects unknown top-level keys. */
export function readRisksConfig(path: string): RisksConfig {
  const lower = path.toLowerCase();
  const raw = readFileSync(path, 'utf8');
  let parsed: any;
  if (lower.endsWith('.yaml') || lower.endsWith('.yml')) parsed = YAML.parse(raw);
  else if (lower.endsWith('.json')) parsed = JSON.parse(raw);
  else throw new Error(`risks config: unsupported extension for ${path} (expected .yaml, .yml, or .json)`);
  if (!parsed || typeof parsed !== 'object') {
    throw new Error(`risks config ${path}: did not parse to an object`);
  }
  for (const k of Object.keys(parsed)) {
    if (!ALLOWED_RISKS_KEYS.has(k)) throw new Error(`risks config ${path}: unknown top-level key "${k}"`);
  }
  const risks: OperatorRiskEntry[] = Array.isArray(parsed.risks) ? parsed.risks : [];
  for (const r of risks) {
    if (!r || typeof r.title !== 'string' || !r.title) {
      throw new Error(`risks config ${path}: every risks[] entry requires a non-empty "title"`);
    }
    if (r.severity && !SEVERITY_ENUM.includes(r.severity)) {
      throw new Error(`risks config ${path}: invalid severity "${r.severity}" for "${r.title}"`);
    }
    if (r.status && !STATUS_ENUM.includes(r.status)) {
      throw new Error(`risks config ${path}: invalid status "${r.status}" for "${r.title}"`);
    }
    if (r.first_seen && !ISO_DATE_RE.test(r.first_seen)) {
      throw new Error(`risks config ${path}: first_seen "${r.first_seen}" is not an ISO date (YYYY-MM-DD)`);
    }
  }
  const mitigations: MitigationOverride[] = Array.isArray(parsed.mitigations) ? parsed.mitigations : [];
  for (const m of mitigations) {
    if (!m || typeof m.entry_id_match !== 'string' || !m.entry_id_match) {
      throw new Error(`risks config ${path}: every mitigations[] entry requires "entry_id_match"`);
    }
    if (m.status && !STATUS_ENUM.includes(m.status)) {
      throw new Error(`risks config ${path}: invalid mitigation status "${m.status}"`);
    }
  }
  return { risks, mitigations };
}

// ─── Multi-sheet XLSX writer (composed from core/zip.ts) ──────────────────────

interface Sheet {
  name: string;
  headers: string[];
  rows: string[][];
}

function colLetter(n: number): string {
  let s = '';
  while (n > 0) {
    const m = (n - 1) % 26;
    s = String.fromCharCode(65 + m) + s;
    n = Math.floor((n - 1) / 26);
  }
  return s;
}

function sheetXml(sheet: Sheet): string {
  const allRows: string[][] = [sheet.headers, ...sheet.rows];
  const xmlRows = allRows
    .map((cells, ri) => {
      const r = ri + 1;
      const xmlCells = cells
        .map((val, ci) => {
          if (val === '') return '';
          return `<c r="${colLetter(ci + 1)}${r}" t="inlineStr"><is><t xml:space="preserve">${xmlEscape(val)}</t></is></c>`;
        })
        .join('');
      return `<row r="${r}">${xmlCells}</row>`;
    })
    .join('');
  return (
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>${xmlRows}</sheetData></worksheet>`
  );
}

/** Produce a multi-sheet `.xlsx` (one worksheet per Sheet). */
export function multiSheetXlsx(sheets: Sheet[]): Buffer {
  const sheetParts = sheets.map((s, i) => ({
    name: `xl/worksheets/sheet${i + 1}.xml`,
    data: Buffer.from(sheetXml(s), 'utf8'),
  }));
  const contentTypes =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
    `<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
    `<Default Extension="xml" ContentType="application/xml"/>` +
    `<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
    sheets
      .map(
        (_s, i) =>
          `<Override PartName="/xl/worksheets/sheet${i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`,
      )
      .join('') +
    `</Types>`;
  const workbook =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">` +
    `<sheets>` +
    sheets.map((s, i) => `<sheet name="${xmlEscape(s.name)}" sheetId="${i + 1}" r:id="rId${i + 1}"/>`).join('') +
    `</sheets></workbook>`;
  const workbookRels =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
    sheets
      .map(
        (_s, i) =>
          `<Relationship Id="rId${i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${i + 1}.xml"/>`,
      )
      .join('') +
    `</Relationships>`;
  const rootRels =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
    `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>` +
    `</Relationships>`;
  return zipStore([
    { name: '[Content_Types].xml', data: Buffer.from(contentTypes, 'utf8') },
    { name: '_rels/.rels', data: Buffer.from(rootRels, 'utf8') },
    { name: 'xl/workbook.xml', data: Buffer.from(workbook, 'utf8') },
    { name: 'xl/_rels/workbook.xml.rels', data: Buffer.from(workbookRels, 'utf8') },
    ...sheetParts,
  ]);
}

/** Build the 8-sheet workbook from a register. */
export function registerToXlsx(reg: SupplyChainRiskRegister): Buffer {
  const cov = reg.coverage;
  const entryRow = (e: RiskEntry): string[] => [
    e.id,
    e.severity,
    e.status,
    e.title,
    (e.cve_ids ?? []).join('; '),
    e.kev_due_date ?? '',
    (e.affected_components ?? e.affected_subprocessors ?? []).join('; '),
    e.mitigation_summary ?? '',
    e.first_seen,
    e.related_nist_controls.join('; '),
  ];
  const entryHeaders = [
    'ID', 'Severity', 'Status', 'Title', 'CVE IDs', 'KEV Due Date',
    'Affected', 'Mitigation', 'First Seen', 'NIST Controls',
  ];
  const cat = (c: RiskCategory) => reg.entries.filter((e) => e.category === c).map(entryRow);
  const sheets: Sheet[] = [
    {
      name: 'Summary',
      headers: ['Metric', 'Value'],
      rows: [
        ['total_entries', String(cov.total_entries)],
        ['open_critical', String(cov.open_critical)],
        ['open_high', String(cov.open_high)],
        ['open_medium', String(cov.open_medium)],
        ['open_low', String(cov.open_low)],
        ['kev_exposed', String(cov.kev_exposed)],
        ['unsigned_sboms', String(cov.unsigned_sboms)],
        ['tier_1_critical_subprocessors', String(cov.tier_1_critical_subprocessors)],
        ['entries_missing_mitigation', cov.entries_missing_mitigation.join('; ')],
      ],
    },
    { name: 'SBOM-CVE', headers: entryHeaders, rows: cat('sbom-cve') },
    { name: 'SBOM-CVE-KEV', headers: entryHeaders, rows: cat('sbom-cve-kev') },
    {
      name: 'Subprocessor-Risk',
      headers: entryHeaders,
      rows: reg.entries
        .filter((e) => e.category === 'subprocessor-risk-tier' || e.category === 'subprocessor-soc2-expired')
        .map(entryRow),
    },
    { name: 'Unsigned-SBOM', headers: entryHeaders, rows: cat('unsigned-sbom') },
    { name: 'Vendor-Advisory', headers: entryHeaders, rows: cat('vendor-advisory') },
    { name: 'Operator-Asserted', headers: entryHeaders, rows: cat('operator-asserted-risk') },
    {
      name: 'SBOM-Provenance',
      headers: [
        'SBOM File', 'Format', 'Supplier Name', 'Component Name', 'Version',
        'Unique ID', 'Dependency', 'Author', 'Timestamp', 'Signature Status',
      ],
      rows: reg.sbom_provenance.map((p) => [
        p.sbom_file,
        p.format,
        p.supplier_name_field_present ? 'Yes' : 'No',
        p.component_name_field_present ? 'Yes' : 'No',
        p.version_field_present ? 'Yes' : 'No',
        p.unique_identifier_field_present ? 'Yes' : 'No',
        p.dependency_field_present ? 'Yes' : 'No',
        p.author_field_present ? 'Yes' : 'No',
        p.timestamp_field_present ? 'Yes' : 'No',
        p.signature_status,
      ]),
    },
  ];
  return multiSheetXlsx(sheets);
}

// ─── Signing ──────────────────────────────────────────────────────────────────

export function serializeUnsignedCanonical(doc: SupplyChainRiskRegister): string {
  const blanked = JSON.parse(
    JSON.stringify({
      ...doc,
      provenance: { ...doc.provenance, signingKeyId: '' },
      signature: undefined,
    }),
  );
  return canonicalize(blanked);
}

function signRegister(doc: SupplyChainRiskRegister, outDir: string): DetachedSignature {
  const sig = signDetached(Buffer.from(serializeUnsignedCanonical(doc), 'utf8'), outDir);
  doc.provenance.signingKeyId = sig.keyId;
  doc.signature = sig;
  return sig;
}

// ─── Disk emitter ─────────────────────────────────────────────────────────────

export interface SupplyChainRiskEmitOptions {
  outDir: string;
  runId: string;
  systemId?: string;
  /** SBOM report path; defaults to <outDir>/sbom-report.json. */
  sbomReportPath?: string;
  /** Subprocessor inventory path; defaults to <outDir>/subprocessor-inventory.json. */
  subprocessorInventoryPath?: string;
  /** KEV catalog path (CLOUD_EVIDENCE_KEV_PATH-style). */
  kevCatalogPath?: string;
  /** Operator --risks-config path. */
  risksConfigPath?: string;
  now?: () => Date;
}

export interface SupplyChainRiskEmitResult {
  json_path: string;
  xlsx_path: string;
  register: SupplyChainRiskRegister;
  bytes_json: number;
  bytes_xlsx: number;
  warnings: string[];
  requires_operator_input: string[];
}

function readJsonSafe<T>(path: string): T | null {
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as T;
  } catch {
    return null;
  }
}

/**
 * Read SBOM report + subprocessor inventory + KEV catalog + operator config from
 * disk, build the register, sign it, and write the JSON + multi-sheet XLSX.
 * Throws a typed error when NO source data is available (never emits a bare
 * register).
 */
export async function emitSupplyChainRiskRegister(
  opts: SupplyChainRiskEmitOptions,
): Promise<SupplyChainRiskEmitResult> {
  const warnings: string[] = [];
  const sourceModules: string[] = [];
  const sourceFiles: string[] = [];

  // SBOM report.
  const sbomReportPath = opts.sbomReportPath ?? resolve(opts.outDir, 'sbom-report.json');
  const sbomReport = readJsonSafe<SbomReport>(sbomReportPath);
  const sbomRaw: Record<string, unknown> = {};
  if (sbomReport) {
    sourceModules.push('core/sbom.ts');
    sourceFiles.push(sbomReportPath);
    for (const s of sbomReport.sboms) {
      const raw = readJsonSafe<unknown>(s.path);
      if (raw) sbomRaw[s.path] = raw;
    }
  }

  // Subprocessor inventory (J.J2 output).
  const subInvPath = opts.subprocessorInventoryPath ?? resolve(opts.outDir, 'subprocessor-inventory.json');
  const subprocessorInventory = readJsonSafe<SubprocessorInventory>(subInvPath);
  if (subprocessorInventory) {
    sourceModules.push('core/subprocessor-inventory.ts');
    sourceFiles.push(subInvPath);
  }

  // CISA KEV catalog.
  const kevCat = await loadKevCatalog({ path: opts.kevCatalogPath });
  if (kevCat.count > 0) {
    sourceModules.push('core/kev-feed.ts');
    if (opts.kevCatalogPath) sourceFiles.push(opts.kevCatalogPath);
  } else if (kevCat.source === 'file') {
    warnings.push('KEV catalog loaded but empty — verify the catalog file freshness.');
  }
  warnings.push(...kevCat.warnings.filter((w) => !/No KEV catalog source available/.test(w)));

  // Operator risks config.
  let operatorRisks: OperatorRiskEntry[] = [];
  let mitigations: MitigationOverride[] = [];
  if (opts.risksConfigPath) {
    const cfg = readRisksConfig(opts.risksConfigPath);
    operatorRisks = cfg.risks;
    mitigations = cfg.mitigations;
    sourceModules.push('operator:--risks-config');
    sourceFiles.push(isAbsolute(opts.risksConfigPath) ? opts.risksConfigPath : resolve(process.cwd(), opts.risksConfigPath));
  }

  const hasAnySource =
    (sbomReport && (sbomReport.sboms.length > 0 || sbomReport.vulnerabilities.length > 0)) ||
    (subprocessorInventory && subprocessorInventory.rows.some((r) => r.name !== TBD)) ||
    operatorRisks.length > 0;
  if (!hasAnySource) {
    throw new Error(
      'supply-chain-risk: no source data available; rerun with at least one of ' +
        '--sbom-dir / --subprocessors-config / --risks-config / a KEV catalog present',
    );
  }

  sourceModules.push('core/supply-chain-risk.ts');

  const register = buildSupplyChainRiskRegister(
    {
      sbomReport,
      sbomRaw,
      subprocessorInventory,
      kev: kevCat.byCve,
      operatorRisks,
      mitigations,
      warnings,
      sourceModules: [...new Set(sourceModules)],
      sourceFiles: [...new Set(sourceFiles)],
    },
    { runId: opts.runId, systemId: opts.systemId ?? subprocessorInventory?.system_id, now: opts.now },
  );

  signRegister(register, opts.outDir);

  const jsonPath = resolve(opts.outDir, SUPPLY_CHAIN_RISK_JSON);
  const xlsxPath = resolve(opts.outDir, SUPPLY_CHAIN_RISK_XLSX);
  const jsonBuf = Buffer.from(JSON.stringify(register, null, 2), 'utf8');
  const xlsxBuf = registerToXlsx(register);
  writeFileSync(jsonPath, jsonBuf);
  writeFileSync(xlsxPath, xlsxBuf);

  return {
    json_path: jsonPath,
    xlsx_path: xlsxPath,
    register,
    bytes_json: jsonBuf.length,
    bytes_xlsx: xlsxBuf.length,
    warnings: register.warnings,
    requires_operator_input: register.requires_operator_input,
  };
}
