/**
 * SA-9 Subprocessor Inventory builder + emitter (LOOP-J.J2).
 *
 * NIST SP 800-53 Rev 5 SA-9 ("External System Services") requires the CSP to
 * identify each external service provider, capture the contractual controls
 * each has agreed to implement, define organizational oversight, and monitor
 * compliance on an ongoing basis. FedRAMP implements SA-9 via the SaaS
 * Subprocessor Inventory, the Customer Responsibility Matrix, and the
 * Significant Change Notification process.
 *
 * This module extends the existing Google-Sheets-only reader
 * (core/subprocessors-sheet.ts) with first-class YAML/JSON operator config and
 * the SA-9 fields (risk_tier, monitoring_methods, contracted_controls,
 * incident_notification_sla_hours, data_residency, subprocessor_subprocessors,
 * oversight_party_uuid). It emits a signed, canonical `subprocessor-inventory.json`
 * + a FedRAMP-style `subprocessor-inventory.xlsx`, both covered by the run
 * manifest and registered in the submission-bundle catalogue. The SSP emitter
 * reads the JSON to populate `system-implementation.leveraged-authorizations[]`.
 *
 * REO compliance:
 *   - Inputs are real: operator YAML/JSON (fs.readFileSync) and/or the live
 *     Google Sheets reader (sheets.spreadsheets.values.get). No fake rows.
 *   - When NEITHER source yields rows, a single, explicit REQUIRES-OPERATOR-INPUT
 *     row names both surfaces — the inventory is structurally valid but the gap
 *     is visible rather than masked.
 *   - Missing SA-9 fields are surfaced (coverage counters + the XLSX shows the
 *     REQUIRES-OPERATOR-INPUT literal) rather than silently defaulted.
 *   - The output carries a G3 provenance block (emitter / emittedAt / sourceCalls
 *     / signingKeyId) and a self-contained detached Ed25519 signature, composed
 *     from the run's signing key (core/sign.ts) — never a separate identity.
 *
 * Pure builder (`buildSubprocessorInventory`) + disk reader/emitter
 * (`readSubprocessorConfig`, `emitSubprocessorInventory`).
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, isAbsolute } from 'node:path';
import YAML from 'yaml';
import { canonicalize, signDetached, type DetachedSignature } from './sign.ts';
import { xmlEscape, zipStore } from './zip.ts';
import { readSubprocessors, type SubprocessorRow, type SheetConfig } from './subprocessors-sheet.ts';

export const SUBPROCESSOR_INVENTORY_JSON = 'subprocessor-inventory.json';
export const SUBPROCESSOR_INVENTORY_XLSX = 'subprocessor-inventory.xlsx';

/** Literal used when an operator-supplied SA-9 field is absent (visible gap, REO). */
const REQUIRES_OPERATOR_INPUT = 'REQUIRES-OPERATOR-INPUT';

/**
 * Single-sheet column contract, matching the FedRAMP SaaS Subprocessor Inventory
 * template column order. Parameterized so a future template revision is a
 * one-line patch (+ a fixture update) rather than a rewrite.
 */
export const COLUMN_ORDER: ReadonlyArray<{ key: keyof SubprocessorRow; header: string }> = [
  { key: 'name', header: 'Name' },
  { key: 'role', header: 'Role' },
  { key: 'data_categories', header: 'Data Categories' },
  { key: 'fedramp_authorized', header: 'FedRAMP Authorized' },
  { key: 'attestation_doc_url', header: 'Attestation Doc URL' },
  { key: 'soc2_expiry', header: 'SOC2 Expiry' },
  { key: 'contract_review_date', header: 'Contract Review Date' },
  { key: 'in_scope_for_csi', header: 'In Scope for CSI' },
  { key: 'risk_tier', header: 'Risk Tier' },
  { key: 'data_residency', header: 'Data Residency' },
  { key: 'last_audit_date', header: 'Last Audit Date' },
  { key: 'monitoring_methods', header: 'Monitoring Methods' },
  { key: 'incident_notification_sla_hours', header: 'Incident Notification SLA (hours)' },
  { key: 'subprocessor_subprocessors', header: 'Subprocessor Subprocessors' },
  { key: 'contracted_controls', header: 'Contracted Controls' },
  { key: 'oversight_party_uuid', header: 'Oversight Party UUID' },
  { key: 'source', header: 'Source' },
  { key: 'source_ref', header: 'Source Ref' },
] as const;

/**
 * SA-9 fields the operator supplies. When absent on a row, the XLSX cell renders
 * the REQUIRES-OPERATOR-INPUT literal and the field is recorded in
 * `requires_operator_input` so the gap is auditable rather than blank.
 */
const REQUIRED_OPERATOR_FIELDS: ReadonlyArray<keyof SubprocessorRow> = [
  'risk_tier',
  'monitoring_methods',
  'contracted_controls',
  'oversight_party_uuid',
  'incident_notification_sla_hours',
  'data_residency',
];

export interface InventoryCoverage {
  total_rows: number;
  rows_with_risk_tier: number;
  rows_missing_risk_tier: string[];
  rows_with_expired_soc2: string[];
  rows_with_fedramp_authorization: number;
  tier_1_critical_count: number;
  tier_2_significant_count: number;
  tier_3_routine_count: number;
}

interface InventoryProvenance {
  emitter: 'core/subprocessor-inventory.ts';
  emittedAt: string;
  /** SDK calls / catalog reads (e.g. 'sheets.spreadsheets.values.get', 'fs.readFileSync(<path>)'). */
  sourceCalls: string[];
  /** Absolute config-file paths read, if any. */
  sourceFiles: string[];
  signingKeyId: string;
}

export interface SubprocessorInventory {
  schema_version: '1.0.0';
  generated_at: string;
  system_id?: string;
  cso_id?: string;
  run_id: string;
  rows: SubprocessorRow[];
  coverage: InventoryCoverage;
  warnings: string[];
  /** Distinct SA-9 field names that are missing on ≥1 row (sorted). */
  requires_operator_input: string[];
  provenance: InventoryProvenance;
  signature?: DetachedSignature;
}

interface SubprocessorConfigFile {
  system_id?: string;
  cso_id?: string;
  subprocessors: Array<Partial<SubprocessorRow> & { name: string }>;
}

export interface ReadConfigResult {
  system_id?: string;
  cso_id?: string;
  rows: SubprocessorRow[];
}

/**
 * Read an operator subprocessor config file. Format is detected by extension:
 * `.yaml`/`.yml` → YAML, `.json` → JSON. Each parsed row is stamped with its
 * provenance (`source` + absolute `source_ref`). Throws a typed error on an
 * unsupported extension or a missing `subprocessors` array.
 */
export function readSubprocessorConfig(path: string): ReadConfigResult {
  const lower = path.toLowerCase();
  const raw = readFileSync(path, 'utf8');
  let parsed: SubprocessorConfigFile;
  let sourceKind: SubprocessorRow['source'];
  if (lower.endsWith('.yaml') || lower.endsWith('.yml')) {
    parsed = YAML.parse(raw) as SubprocessorConfigFile;
    sourceKind = 'yaml-config';
  } else if (lower.endsWith('.json')) {
    parsed = JSON.parse(raw) as SubprocessorConfigFile;
    sourceKind = 'json-config';
  } else {
    throw new Error(
      `subprocessor config: unsupported extension for ${path} (expected .yaml, .yml, or .json)`,
    );
  }
  if (!parsed || !Array.isArray(parsed.subprocessors)) {
    throw new Error(`subprocessor config ${path}: missing required "subprocessors" array`);
  }
  const absRef = isAbsolute(path) ? path : resolve(process.cwd(), path);
  const rows: SubprocessorRow[] = parsed.subprocessors.map((s) => ({
    ...s,
    name: String(s.name),
    source: sourceKind,
    source_ref: absRef,
  }));
  return { system_id: parsed.system_id, cso_id: parsed.cso_id, rows };
}

/** Canonical dedup key for a subprocessor name: lower-cased, whitespace-collapsed. */
function canonicalName(name: string): string {
  return name.toLowerCase().replace(/\s+/g, ' ').trim();
}

export interface BuildInventoryInput {
  /** Pre-aggregated rows. Caller orders sheet rows BEFORE config rows so that, on
   * a name conflict, the operator's local config (later) wins. */
  rows: SubprocessorRow[];
  system_id?: string;
  cso_id?: string;
  /** Warnings accumulated by the reader(s) (e.g. a Sheets failure). */
  warnings?: string[];
  sourceCalls: string[];
  sourceFiles: string[];
}

export interface BuildInventoryOptions {
  runId: string;
  /** Injectable clock for deterministic tests + SOC2-expiry evaluation. */
  now?: () => Date;
}

/**
 * Pure builder: dedup rows by canonical name (later row wins, conflict recorded
 * as a warning), compute SA-9 coverage deterministically, and assemble the
 * signed-ready inventory document. Rows are sorted by display name for stable,
 * byte-reproducible output.
 */
export function buildSubprocessorInventory(
  input: BuildInventoryInput,
  opts: BuildInventoryOptions,
): SubprocessorInventory {
  const now = opts.now ?? (() => new Date());
  const nowDate = now();
  const warnings = [...(input.warnings ?? [])];

  // Dedup by canonical name. Later rows (config, by caller ordering) win.
  const byKey = new Map<string, SubprocessorRow>();
  for (const row of input.rows) {
    const key = canonicalName(row.name);
    const existing = byKey.get(key);
    if (existing) {
      warnings.push(
        `Subprocessor "${row.name}" defined in both ${existing.source} (${existing.source_ref}) ` +
          `and ${row.source} (${row.source_ref}); using ${row.source} row`,
      );
    }
    byKey.set(key, row);
  }
  const rows = [...byKey.values()].sort((a, b) => a.name.localeCompare(b.name));

  // Coverage + REQUIRES-OPERATOR-INPUT accounting.
  const missingTier: string[] = [];
  const expiredSoc2: string[] = [];
  const requires = new Set<string>();
  let withTier = 0;
  let withFedramp = 0;
  let t1 = 0;
  let t2 = 0;
  let t3 = 0;
  for (const r of rows) {
    if (r.risk_tier) {
      withTier++;
      if (r.risk_tier === 'tier-1-critical') t1++;
      else if (r.risk_tier === 'tier-2-significant') t2++;
      else if (r.risk_tier === 'tier-3-routine') t3++;
    } else {
      missingTier.push(r.name);
    }
    if (r.fedramp_authorized === 'yes') withFedramp++;
    if (r.soc2_expiry) {
      const expiryMs = Date.parse(r.soc2_expiry);
      if (!Number.isNaN(expiryMs) && expiryMs < nowDate.getTime()) expiredSoc2.push(r.name);
    }
    for (const field of REQUIRED_OPERATOR_FIELDS) {
      const v = r[field];
      if (v == null || (Array.isArray(v) && v.length === 0)) requires.add(field);
    }
  }

  const coverage: InventoryCoverage = {
    total_rows: rows.length,
    rows_with_risk_tier: withTier,
    rows_missing_risk_tier: missingTier,
    rows_with_expired_soc2: expiredSoc2,
    rows_with_fedramp_authorization: withFedramp,
    tier_1_critical_count: t1,
    tier_2_significant_count: t2,
    tier_3_routine_count: t3,
  };

  return {
    schema_version: '1.0.0',
    generated_at: nowDate.toISOString(),
    system_id: input.system_id,
    cso_id: input.cso_id,
    run_id: opts.runId,
    rows,
    coverage,
    warnings,
    requires_operator_input: [...requires].sort(),
    provenance: {
      emitter: 'core/subprocessor-inventory.ts',
      emittedAt: nowDate.toISOString(),
      sourceCalls: input.sourceCalls,
      sourceFiles: input.sourceFiles,
      signingKeyId: '',
    },
  };
}

// ─── Signing (detached Ed25519 over the signature-blanked canonical bytes) ────

/**
 * Serialize the signature-blanked canonical form. The JSON round-trip strips
 * `undefined` (signature) so the signed bytes are byte-identical to a verifier
 * re-deriving them from the on-disk file. Mirrors the LOOP-B.B1 / LOOP-W.W1
 * signing convention.
 */
export function serializeUnsignedCanonical(doc: SubprocessorInventory): string {
  const blanked = JSON.parse(
    JSON.stringify({
      ...doc,
      provenance: { ...doc.provenance, signingKeyId: '' },
      signature: undefined,
    }),
  );
  return canonicalize(blanked);
}

function signInventory(doc: SubprocessorInventory, outDir: string): DetachedSignature {
  const canonical = serializeUnsignedCanonical(doc);
  const sig = signDetached(Buffer.from(canonical, 'utf8'), outDir);
  doc.provenance.signingKeyId = sig.keyId;
  doc.signature = sig;
  return sig;
}

// ─── Minimal store-only XLSX writer (parameterized by COLUMN_ORDER) ───────────

/** Column letter for a 1-based index (1→A, 26→Z, 27→AA). */
function colLetter(n: number): string {
  let s = '';
  while (n > 0) {
    const m = (n - 1) % 26;
    s = String.fromCharCode(65 + m) + s;
    n = Math.floor((n - 1) / 26);
  }
  return s;
}

/** Render one cell value; arrays join with "; ", booleans render Yes/No, and a
 * missing operator-supplied SA-9 field renders the REQUIRES-OPERATOR-INPUT
 * literal so the gap is visible in the spreadsheet. */
function cellValue(row: SubprocessorRow, key: keyof SubprocessorRow): string {
  const v = row[key];
  if (v == null || (Array.isArray(v) && v.length === 0)) {
    return REQUIRED_OPERATOR_FIELDS.includes(key) ? REQUIRES_OPERATOR_INPUT : '';
  }
  if (Array.isArray(v)) return v.join('; ');
  if (typeof v === 'boolean') return v ? 'Yes' : 'No';
  return String(v);
}

function sheetXml(rows: SubprocessorRow[]): string {
  const headers = COLUMN_ORDER.map((c) => c.header);
  const allRows: string[][] = [headers, ...rows.map((r) => COLUMN_ORDER.map((c) => cellValue(r, c.key)))];
  const xmlRows = allRows
    .map((cells, ri) => {
      const r = ri + 1;
      const xmlCells = cells
        .map((val, ci) => {
          if (val === '') return '';
          const ref = `${colLetter(ci + 1)}${r}`;
          return `<c r="${ref}" t="inlineStr"><is><t xml:space="preserve">${xmlEscape(val)}</t></is></c>`;
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

/** Produce a minimal valid `.xlsx` (single "Subprocessors" sheet, inline strings). */
export function inventoryToXlsx(rows: SubprocessorRow[]): Buffer {
  const files: Array<{ name: string; data: Buffer }> = [
    {
      name: '[Content_Types].xml',
      data: Buffer.from(
        `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
          `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
          `<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
          `<Default Extension="xml" ContentType="application/xml"/>` +
          `<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
          `<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>` +
          `</Types>`,
        'utf8',
      ),
    },
    {
      name: '_rels/.rels',
      data: Buffer.from(
        `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
          `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
          `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>` +
          `</Relationships>`,
        'utf8',
      ),
    },
    {
      name: 'xl/workbook.xml',
      data: Buffer.from(
        `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
          `<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">` +
          `<sheets><sheet name="Subprocessors" sheetId="1" r:id="rId1"/></sheets></workbook>`,
        'utf8',
      ),
    },
    {
      name: 'xl/_rels/workbook.xml.rels',
      data: Buffer.from(
        `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
          `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
          `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>` +
          `</Relationships>`,
        'utf8',
      ),
    },
    { name: 'xl/worksheets/sheet1.xml', data: Buffer.from(sheetXml(rows), 'utf8') },
  ];
  return zipStore(files);
}

// ─── Disk emitter ─────────────────────────────────────────────────────────────

export interface SubprocessorInventoryEmitOptions {
  outDir: string;
  runId: string;
  /** Operator YAML/JSON config path. */
  configPath?: string;
  /** Google-Sheets reader config (the existing single-sheet path). */
  sheetConfig?: SheetConfig;
  /** Optional system identity (CLI/orchestrator); config-file values fill in if absent. */
  systemId?: string;
  csoId?: string;
  now?: () => Date;
  /** Injectable Google-Sheets reader (wire-layer seam for tests); defaults to readSubprocessors. */
  readSheetImpl?: (cfg: SheetConfig) => Promise<{ rows: SubprocessorRow[]; warnings: string[] }>;
}

export interface SubprocessorInventoryEmitResult {
  json_path: string;
  xlsx_path: string;
  inventory: SubprocessorInventory;
  bytes_json: number;
  bytes_xlsx: number;
  warnings: string[];
  /** True when no real rows were available (synthetic no-source row) OR ≥1 SA-9 field is missing. */
  requires_operator_input: boolean;
}

/**
 * Read the configured source(s), merge + dedup, sign, and write
 * `subprocessor-inventory.json` + `.xlsx` to `outDir`. Sheet rows are read
 * BEFORE config rows so that, on a name conflict, the operator's local config
 * wins (build-step ordering). When neither source yields a row, a single
 * REQUIRES-OPERATOR-INPUT row is emitted naming both surfaces.
 */
export async function emitSubprocessorInventory(
  opts: SubprocessorInventoryEmitOptions,
): Promise<SubprocessorInventoryEmitResult> {
  const warnings: string[] = [];
  const sourceCalls: string[] = [];
  const sourceFiles: string[] = [];
  const rows: SubprocessorRow[] = [];
  let systemId = opts.systemId;
  let csoId = opts.csoId;

  // Sheet first (so config rows win on conflict). readSubprocessors() stamps
  // each row's source/source_ref itself.
  if (opts.sheetConfig) {
    const readSheet = opts.readSheetImpl ?? readSubprocessors;
    try {
      const res = await readSheet(opts.sheetConfig);
      rows.push(...res.rows);
      warnings.push(...res.warnings);
      sourceCalls.push('sheets.spreadsheets.values.get');
    } catch (e: any) {
      // A Sheets failure must NOT block the run — record + continue with config rows.
      warnings.push(`Subprocessor sheet read failed: ${e?.message ?? String(e)}`);
    }
  }

  if (opts.configPath) {
    const cfg = readSubprocessorConfig(opts.configPath);
    rows.push(...cfg.rows);
    systemId ??= cfg.system_id;
    csoId ??= cfg.cso_id;
    sourceCalls.push(`fs.readFileSync(${opts.configPath})`);
    sourceFiles.push(opts.configPath);
  }

  let noSourceRow = false;
  if (rows.length === 0) {
    noSourceRow = true;
    rows.push({
      name: REQUIRES_OPERATOR_INPUT,
      source: 'yaml-config',
      source_ref:
        '<configure --subprocessors-config <path.yaml> OR subprocessors.spreadsheet_id in config.yaml>',
    });
    warnings.push(
      'No subprocessor sheet and no config file provided — emitted a single ' +
        'REQUIRES-OPERATOR-INPUT row. Configure --subprocessors-config <path> or the ' +
        'subprocessors block (spreadsheet_id / config_path) in config.yaml.',
    );
  }
  if (sourceCalls.length === 0) sourceCalls.push('none (no subprocessor source configured)');

  const inventory = buildSubprocessorInventory(
    { rows, system_id: systemId, cso_id: csoId, warnings, sourceCalls, sourceFiles },
    { runId: opts.runId, now: opts.now },
  );

  signInventory(inventory, opts.outDir);

  const jsonPath = resolve(opts.outDir, SUBPROCESSOR_INVENTORY_JSON);
  const xlsxPath = resolve(opts.outDir, SUBPROCESSOR_INVENTORY_XLSX);
  const jsonBuf = Buffer.from(JSON.stringify(inventory, null, 2), 'utf8');
  const xlsxBuf = inventoryToXlsx(inventory.rows);
  writeFileSync(jsonPath, jsonBuf);
  writeFileSync(xlsxPath, xlsxBuf);

  return {
    json_path: jsonPath,
    xlsx_path: xlsxPath,
    inventory,
    bytes_json: jsonBuf.length,
    bytes_xlsx: xlsxBuf.length,
    warnings: inventory.warnings,
    requires_operator_input: noSourceRow || inventory.requires_operator_input.length > 0,
  };
}
