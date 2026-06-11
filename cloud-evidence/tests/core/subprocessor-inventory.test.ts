/**
 * Tests for core/subprocessor-inventory.ts — the SA-9 Subprocessor Inventory
 * builder + emitter (LOOP-J.J2).
 *
 * Covers: YAML + JSON config reading, sheet/config merge with config precedence,
 * SA-9 coverage accounting (risk_tier gaps, expired SOC2, tier counts), the
 * FedRAMP-style XLSX column contract, the REQUIRES-OPERATOR-INPUT no-source path,
 * Sheets-failure resilience, provenance + detached-signature integrity, ajv
 * schema validation of the operator config, and the SSP leveraged-authorizations
 * integration.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import YAML from 'yaml';
import {
  readSubprocessorConfig,
  buildSubprocessorInventory,
  emitSubprocessorInventory,
  inventoryToXlsx,
  serializeUnsignedCanonical,
  COLUMN_ORDER,
  SUBPROCESSOR_INVENTORY_JSON,
  SUBPROCESSOR_INVENTORY_XLSX,
  type SubprocessorInventory,
} from '../../core/subprocessor-inventory.ts';
import type { SubprocessorRow, SheetConfig } from '../../core/subprocessors-sheet.ts';
import { verifyDetached } from '../../core/sign.ts';
import { emitOscalSsp } from '../../core/oscal-ssp.ts';
import { validateOscalFile } from '../../core/oscal-validate.ts';

const FIXTURE_YAML = fileURLToPath(new URL('../fixtures/subprocessors/example.yaml', import.meta.url));
const FIXTURE_JSON = fileURLToPath(new URL('../fixtures/subprocessors/example.json', import.meta.url));
const FIXTURE_SCHEMA = fileURLToPath(new URL('../fixtures/subprocessor-config.schema.json', import.meta.url));

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-subproc-'));
  dirs.push(d);
  return d;
}
const at = (iso: string) => () => new Date(iso);

afterEach(() => {
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* */ }
  }
});

function row(partial: Partial<SubprocessorRow> & { name: string }): SubprocessorRow {
  return { source: 'yaml-config', source_ref: '/tmp/fixture.yaml', ...partial };
}

describe('readSubprocessorConfig', () => {
  it('reads subprocessors from a YAML file', () => {
    const r = readSubprocessorConfig(FIXTURE_YAML);
    expect(r.rows).toHaveLength(3);
    expect(r.system_id).toBe('sys-test-jj2');
    for (const row of r.rows) {
      expect(row.source).toBe('yaml-config');
      expect(row.source_ref.endsWith('example.yaml')).toBe(true);
    }
    const acme = r.rows.find((x) => x.name === 'AcmeCloud Infrastructure')!;
    expect(acme.fedramp_authorized).toBe('yes');
    expect(acme.contracted_controls).toEqual(['ac-2', 'au-6', 'sc-13', 'sc-28']);
  });

  it('reads subprocessors from a JSON file', () => {
    const r = readSubprocessorConfig(FIXTURE_JSON);
    expect(r.rows).toHaveLength(3);
    for (const row of r.rows) expect(row.source).toBe('json-config');
    expect(r.rows.find((x) => x.name === 'AcmeCloud Infrastructure')!.incident_notification_sla_hours).toBe(24);
  });

  it('records the source_ref for each row as an absolute path', () => {
    const r = readSubprocessorConfig(FIXTURE_YAML);
    for (const row of r.rows) expect(row.source_ref.startsWith('/')).toBe(true);
  });

  it('throws on an unsupported file extension', () => {
    const d = tmp();
    const p = join(d, 'subs.txt');
    writeFileSync(p, 'name: x');
    expect(() => readSubprocessorConfig(p)).toThrow(/unsupported extension/);
  });
});

describe('buildSubprocessorInventory (pure)', () => {
  it('merges sheet rows + config rows with config precedence on a name conflict', () => {
    const sheet = row({ name: 'AcmeCorp', risk_tier: 'tier-1-critical', source: 'google-sheet', source_ref: 'sid!Sheet1!A1:Z' });
    const cfg = row({ name: 'AcmeCorp', risk_tier: 'tier-2-significant', source: 'yaml-config', source_ref: '/abs/subs.yaml' });
    const inv = buildSubprocessorInventory(
      { rows: [sheet, cfg], sourceCalls: ['sheets.spreadsheets.values.get', 'fs.readFileSync(/abs/subs.yaml)'], sourceFiles: ['/abs/subs.yaml'] },
      { runId: 'r1', now: at('2026-06-06T00:00:00Z') },
    );
    expect(inv.rows).toHaveLength(1);
    expect(inv.rows[0]!.risk_tier).toBe('tier-2-significant');   // config wins
    expect(inv.warnings.some((w) => /defined in both/.test(w))).toBe(true);
  });

  it('canonicalizes names for dedup but preserves the displayed name casing', () => {
    const sheet = row({ name: 'Acme Corp', source: 'google-sheet', source_ref: 'sid!r' });
    const cfg = row({ name: 'acme corp', source: 'yaml-config', source_ref: '/abs' });
    const inv = buildSubprocessorInventory({ rows: [sheet, cfg], sourceCalls: ['x'], sourceFiles: [] }, { runId: 'r' });
    expect(inv.rows).toHaveLength(1);
    expect(inv.rows[0]!.name).toBe('acme corp');                 // config row's casing
  });

  it('flags rows missing risk_tier in coverage.rows_missing_risk_tier', () => {
    const inv = buildSubprocessorInventory(
      { rows: [row({ name: 'NoTier' }), row({ name: 'Tiered', risk_tier: 'tier-3-routine' })], sourceCalls: ['x'], sourceFiles: [] },
      { runId: 'r' },
    );
    expect(inv.coverage.rows_missing_risk_tier).toEqual(['NoTier']);
    expect(inv.requires_operator_input).toContain('risk_tier');
  });

  it('flags expired SOC2 attestations based on opts.now', () => {
    const inv = buildSubprocessorInventory(
      { rows: [row({ name: 'Old', soc2_expiry: '2024-01-01' }), row({ name: 'Fresh', soc2_expiry: '2027-03-15' })], sourceCalls: ['x'], sourceFiles: [] },
      { runId: 'r', now: at('2026-06-06T00:00:00Z') },
    );
    expect(inv.coverage.rows_with_expired_soc2).toEqual(['Old']);
  });

  it('computes tier_1/2/3 counts + fedramp-authorization count correctly', () => {
    const r = readSubprocessorConfig(FIXTURE_YAML);
    const inv = buildSubprocessorInventory({ rows: r.rows, sourceCalls: ['x'], sourceFiles: [] }, { runId: 'r', now: at('2026-06-06T00:00:00Z') });
    expect(inv.coverage.tier_1_critical_count).toBe(1);
    expect(inv.coverage.tier_2_significant_count).toBe(1);
    expect(inv.coverage.tier_3_routine_count).toBe(1);
    expect(inv.coverage.rows_with_fedramp_authorization).toBe(1);
  });

  it('preserves operator-supplied incident_notification_sla_hours verbatim', () => {
    const inv = buildSubprocessorInventory({ rows: [row({ name: 'X', incident_notification_sla_hours: 24 })], sourceCalls: ['x'], sourceFiles: [] }, { runId: 'r' });
    expect(inv.rows[0]!.incident_notification_sla_hours).toBe(24);
  });

  it('is deterministic: same inputs + clock → byte-identical canonical form', () => {
    const rows = readSubprocessorConfig(FIXTURE_YAML).rows;
    const a = buildSubprocessorInventory({ rows, sourceCalls: ['x'], sourceFiles: [] }, { runId: 'r', now: at('2026-06-06T00:00:00Z') });
    const b = buildSubprocessorInventory({ rows: [...rows].reverse(), sourceCalls: ['x'], sourceFiles: [] }, { runId: 'r', now: at('2026-06-06T00:00:00Z') });
    expect(serializeUnsignedCanonical(a)).toBe(serializeUnsignedCanonical(b));
  });
});

describe('inventoryToXlsx', () => {
  it('emits an XLSX whose header row matches COLUMN_ORDER verbatim', () => {
    const rows = readSubprocessorConfig(FIXTURE_YAML).rows;
    const buf = inventoryToXlsx(rows);
    // Store-only zip → the sheet XML lives uncompressed inside; assert headers.
    const text = buf.toString('latin1');
    for (const c of COLUMN_ORDER) {
      expect(text.includes(`<t xml:space="preserve">${c.header}</t>`)).toBe(true);
    }
    // PK zip magic.
    expect(buf.subarray(0, 2).toString('latin1')).toBe('PK');
  });

  it('renders REQUIRES-OPERATOR-INPUT in the XLSX for a missing SA-9 field', () => {
    const buf = inventoryToXlsx([row({ name: 'Gappy' })]);   // no risk_tier / monitoring_methods / etc.
    expect(buf.toString('latin1')).toContain('REQUIRES-OPERATOR-INPUT');
  });
});

describe('emitSubprocessorInventory (disk emitter)', () => {
  it('writes a signed JSON + XLSX with a G3 provenance block from a YAML config', async () => {
    const out = tmp();
    const r = await emitSubprocessorInventory({ outDir: out, runId: 'run-1', configPath: FIXTURE_YAML, now: at('2026-06-06T00:00:00Z') });
    expect(existsSync(join(out, SUBPROCESSOR_INVENTORY_JSON))).toBe(true);
    expect(existsSync(join(out, SUBPROCESSOR_INVENTORY_XLSX))).toBe(true);
    const doc = JSON.parse(readFileSync(r.json_path, 'utf8')) as SubprocessorInventory;
    // G3 provenance contract.
    expect(doc.provenance.emitter).toBe('core/subprocessor-inventory.ts');
    expect(doc.provenance.sourceCalls.some((s) => s.startsWith('fs.readFileSync('))).toBe(true);
    expect(doc.provenance.signingKeyId).toMatch(/^[0-9a-f]{16}$/);
    // Detached signature verifies against the signature-blanked canonical bytes.
    expect(doc.signature).toBeTruthy();
    const canonical = serializeUnsignedCanonical(doc);
    expect(verifyDetached(Buffer.from(canonical, 'utf8'), doc.signature!)).toBe(true);
  });

  it('writes a single REQUIRES-OPERATOR-INPUT row when no sheet + no config provided', async () => {
    const out = tmp();
    const r = await emitSubprocessorInventory({ outDir: out, runId: 'run-2' });
    expect(r.inventory.rows).toHaveLength(1);
    expect(r.inventory.rows[0]!.name).toBe('REQUIRES-OPERATOR-INPUT');
    expect(r.requires_operator_input).toBe(true);
  });

  it('returns warnings + keeps YAML rows when the Sheets reader throws', async () => {
    const out = tmp();
    const throwingSheet = async (_cfg: SheetConfig) => { throw new Error('ADC not configured'); };
    const r = await emitSubprocessorInventory({
      outDir: out, runId: 'run-3', configPath: FIXTURE_YAML,
      sheetConfig: { spreadsheet_id: 'sid', sheet_range: 'Sheet1!A1:Z', columns: { name: 0 } },
      readSheetImpl: throwingSheet,
      now: at('2026-06-06T00:00:00Z'),
    });
    expect(r.inventory.rows).toHaveLength(3);                          // YAML rows preserved
    expect(r.warnings.some((w) => /sheet read failed/i.test(w))).toBe(true);
  });

  it('records provenance.sourceCalls listing the sheet call AND the config read', async () => {
    const out = tmp();
    const fakeSheet = async (_cfg: SheetConfig) => ({ rows: [row({ name: 'SheetOnly', source: 'google-sheet', source_ref: 'sid!r' })], warnings: [] });
    const r = await emitSubprocessorInventory({
      outDir: out, runId: 'run-4', configPath: FIXTURE_JSON,
      sheetConfig: { spreadsheet_id: 'sid', sheet_range: 'Sheet1!A1:Z', columns: { name: 0 } },
      readSheetImpl: fakeSheet,
      now: at('2026-06-06T00:00:00Z'),
    });
    const calls = r.inventory.provenance.sourceCalls;
    expect(calls).toContain('sheets.spreadsheets.values.get');
    expect(calls.some((c) => c.startsWith('fs.readFileSync('))).toBe(true);
  });
});

describe('ajv schema validation of the operator config', () => {
  const ajv = addFormats(new Ajv({ allErrors: true }));
  const schema = JSON.parse(readFileSync(FIXTURE_SCHEMA, 'utf8'));

  it('accepts the committed example YAML config', () => {
    const validate = ajv.compile(schema);
    const data = YAML.parse(readFileSync(FIXTURE_YAML, 'utf8'));
    const ok = validate(data);
    if (!ok) throw new Error(JSON.stringify(validate.errors, null, 2));
    expect(ok).toBe(true);
  });

  it('rejects a config with an unknown top-level field (REO safety net)', () => {
    const validate = ajv.compile(schema);
    const ok = validate({ subprocessors: [{ name: 'X' }], bogus_field: true });
    expect(ok).toBe(false);
  });
});

describe('SSP leveraged-authorizations integration (LOOP-J.J2 → SSP)', () => {
  let prevBaselines: string | undefined;
  afterEach(() => {
    if (prevBaselines === undefined) delete process.env.NIST_BASELINES_PATH;
    else process.env.NIST_BASELINES_PATH = prevBaselines;
    prevBaselines = undefined;
  });

  it('emits leveraged-authorizations[] in the SSP for fedramp_authorized=yes rows', async () => {
    const out = tmp();
    // Inject a small NIST baseline fixture.
    const bdir = tmp();
    const bpath = join(bdir, 'baselines.json');
    writeFileSync(bpath, JSON.stringify({ low: ['ac-2'], moderate: ['ac-2'], high: ['ac-2'] }));
    prevBaselines = process.env.NIST_BASELINES_PATH;
    process.env.NIST_BASELINES_PATH = bpath;
    // A KSI evidence file so the benchmark has something to roll up.
    writeFileSync(join(out, 'KSI-IAM-MFA.json'), JSON.stringify({ ksi_id: 'KSI-IAM-MFA', providers: [{ provider: 'aws', findings: [{ rule: 'mfa', passed: true, nist_controls: ['ac-2'] }] }], rollup: { pass: true } }));
    // Emit the subprocessor inventory first (SSP reads it from outDir).
    await emitSubprocessorInventory({ outDir: out, runId: 'run-ssp', configPath: FIXTURE_YAML, now: at('2026-06-06T00:00:00Z') });

    const r = emitOscalSsp({ outDir: out, runId: 'run-ssp', frmrVersion: '25.05', impactLevel: 'moderate', systemId: 'sys-test', organizationName: 'Acme Corp' });
    const ssp = JSON.parse(readFileSync(r.path, 'utf8'))['system-security-plan'];
    const las = ssp['system-implementation']['leveraged-authorizations'];
    expect(Array.isArray(las)).toBe(true);
    expect(las).toHaveLength(1);                                 // only AcmeCloud (yes + last_audit_date)
    expect(las[0].title).toBe('AcmeCloud Infrastructure');
    expect(las[0]['date-authorized']).toBe('2025-09-01');
    // The referenced party exists in metadata.parties.
    const partyUuids = (ssp.metadata.parties ?? []).map((p: any) => p.uuid);
    expect(partyUuids).toContain(las[0]['party-uuid']);
    // The SSP still validates against the committed NIST OSCAL 1.1.2 schema.
    const v = validateOscalFile(r.path, 'ssp');
    if (!v.valid) throw new Error(`SSP schema invalid:\n${v.errors.slice(0, 8).join('\n')}`);
    expect(v.valid).toBe(true);
  });
});
