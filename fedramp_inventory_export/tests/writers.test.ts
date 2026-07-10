import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadRun } from '../src/load.ts';
import { joinRun } from '../src/join.ts';
import { buildTables } from '../src/tables.ts';
import { buildDashboard } from '../src/dashboard.ts';
import {
  tableToCsv,
  writeCsvs,
  buildWorkbook,
  writeWorkbook,
  summaryCoverFacts,
} from '../src/writers.ts';
import { writeSampleRun } from './fixtures.ts';

function tables() {
  return buildTables(joinRun(loadRun(writeSampleRun())));
}

function dashboard() {
  return buildDashboard(joinRun(loadRun(writeSampleRun())), { account: '111122223333', generatedAt: '2026-07-08T00:00:00Z' });
}
const META = (extra = {}) => ({ title: 'T', subtitle: 'S', coverFacts: [['k', 'v']] as Array<[string, string]>, ...extra });

describe('buildTables', () => {
  it('produces the core sheets + family segmentation', () => {
    const names = tables().map((t) => t.name);
    // Core tables always present.
    for (const core of [
      'service_availability', 'lever_summary', 'remediation_plan', 'family_summary', 'cluster_summary',
      'ksi_coverage_matrix', 'manual_obligations',
      'full_inventory', 'asset_compliance', 'requirement_status',
      'rev5_control_benchmark', 'twentyx_control_benchmark', 'findings', 'gaps',
    ]) {
      expect(names, core).toContain(core);
    }
    // Family sheets: the sample has an EC2 (Compute) + S3 (Storage) + GCP compute.
    expect(names).toContain('inv_compute');
    expect(names).toContain('inv_storage');
    // Flow-down order: coverage (service availability) first, then action (levers),
    // detail (inventory) later.
    expect(names[0]).toBe('service_availability');
    expect(names.indexOf('lever_summary')).toBeLessThan(names.indexOf('remediation_plan'));
    expect(names.indexOf('remediation_plan')).toBeLessThan(names.indexOf('full_inventory'));
  });

  it('prunes empty columns from per-family tabs but keeps the full master + flow-down keys', () => {
    const ts = tables();
    const full = ts.find((t) => t.name === 'full_inventory')!;
    const compute = ts.find((t) => t.name === 'inv_compute')!;
    // Master keeps the complete contract; a family tab has fewer columns.
    expect(compute.columns.length).toBeLessThan(full.columns.length);
    // No column on a family tab is empty for every row (unless a retained key).
    const KEEP = new Set(['Family', 'Cluster / Grouping', 'Account/Project/Subscription', 'Location', 'Resource Type', 'Function', 'Unique Asset Identifier']);
    for (const c of compute.columns) {
      if (KEEP.has(c)) continue;
      expect(compute.rows.some((r) => (r[c] ?? '').trim() !== ''), `column "${c}" should not be all-empty`).toBe(true);
    }
    // Flow-down keys are always present even if sparse.
    for (const k of ['Family', 'Cluster / Grouping', 'Resource Type']) {
      expect(compute.columns).toContain(k);
    }
  });

  it('builds a KSI Coverage Matrix classifying every KSI-indicator', () => {
    const m = tables().find((t) => t.name === 'ksi_coverage_matrix')!;
    expect(m.columns).toContain('Assessment Type');
    expect(m.columns).toContain('What Still Needs Manual Evidence');
    // Fixture KSIs: KSI-CNA-ENC (CLOUD → automated), KSI-IAM-MFA (CLOUD → automated).
    expect(m.rows.length).toBeGreaterThanOrEqual(1);
    const types = new Set(m.rows.map((r) => r['Assessment Type'] ?? ''));
    expect([...types].some((t) => /Automated/.test(t))).toBe(true);
    // Automated rows carry a live config coverage status, never a bare "not-met".
    for (const r of m.rows) {
      expect(r['Coverage Status']).not.toBe('not-met');
      expect(r['Coverage Status']).not.toBe('');
    }
  });

  it('lists manual/documentation/external obligations on their own sheet', () => {
    const o = tables().find((t) => t.name === 'manual_obligations')!;
    expect(o.columns).toContain('Artifact / Evidence Owed');
    // The awareness-only FRR (VDR-FRP-CAP) is external → appears here with an artifact.
    const ext = o.rows.find((r) => r['Requirement ID'] === 'VDR-FRP-CAP');
    expect(ext).toBeTruthy();
    expect(ext!['Artifact / Evidence Owed']).not.toBe('');
    // Every obligation row names an artifact + a reason.
    for (const r of o.rows) {
      expect((r['Artifact / Evidence Owed'] ?? '').length).toBeGreaterThan(0);
      expect((r['Why Not Automatable'] ?? '').length).toBeGreaterThan(0);
    }
  });

  it('surfaces service availability with non-ENABLED services ranked first', () => {
    const sa = tables().find((t) => t.name === 'service_availability')!;
    expect(sa.columns[0]).toBe('Status');
    const statuses = sa.rows.map((r) => r['Status']);
    // DISABLED / NOT_AVAILABLE (the actionable "why a lens is empty" rows) sort
    // above ENABLED.
    expect(statuses).toContain('DISABLED');
    expect(statuses).toContain('NOT_AVAILABLE');
    expect(statuses.indexOf('ENABLED')).toBe(statuses.length - 1);
    const inspector = sa.rows.find((r) => r['Service'] === 'Amazon Inspector v2')!;
    expect(inspector['Detail']).toMatch(/enable to populate/i);
  });

  it('includes the reference + coverage sheets', () => {
    const names = tables().map((t) => t.name);
    expect(names).toContain('data_dictionary');
    expect(names).toContain('requirement_coverage');
    const dd = tables().find((t) => t.name === 'data_dictionary')!;
    // Every dictionary row names a column + has a definition.
    expect(dd.rows.length).toBeGreaterThan(20);
    expect(dd.rows.every((r) => (r['Column'] ?? '') !== '' && (r['Definition'] ?? '') !== '')).toBe(true);
  });

  it('every asset appears in exactly one family sheet (sum = flat inventory)', () => {
    const ts = tables();
    const flat = ts.find((t) => t.name === 'full_inventory')!;
    const famSheets = ts.filter((t) => t.name.startsWith('inv_'));
    const famRowTotal = famSheets.reduce((n, t) => n + t.rows.length, 0);
    expect(famRowTotal).toBe(flat.rows.length);
  });

  it('full inventory row carries the rich asset fields', () => {
    const inv = tables().find((t) => t.name === 'full_inventory')!;
    const bucket = inv.rows.find((r) => (r['Unique Asset Identifier'] ?? '').includes('my-sensitive-bucket'))!;
    expect(bucket['Encryption At Rest']).toBe('No');
    expect(bucket['Data Classification']).toBe('Sensitive (Macie)');
    expect(bucket['Provider']).toBe('aws');
  });

  it('gaps table only contains failing findings', () => {
    const gaps = tables().find((t) => t.name === 'gaps')!;
    expect(gaps.rows.length).toBeGreaterThan(0);
    expect(gaps.rows.every((r) => r['Result'] === 'FAIL')).toBe(true);
  });
});

describe('CSV writer', () => {
  it('escapes commas/quotes and round-trips headers', () => {
    const t = tables()[0]!;
    const csv = tableToCsv(t);
    const firstLine = csv.split('\r\n')[0]!;
    expect(firstLine).toBe(t.columns.map((c) => (/[",\r\n]/.test(c) ? `"${c}"` : c)).join(','));
  });

  it('writes one CSV per table', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fedpy-csv-'));
    const ts = tables();
    const paths = writeCsvs(ts, dir);
    expect(paths).toHaveLength(ts.length);
    expect(paths.length).toBeGreaterThanOrEqual(8); // core + at least the family sheets
    for (const p of paths) expect(existsSync(p)).toBe(true);
  });
});

describe('XLSX writer', () => {
  it('produces a real ZIP with an Executive Summary + one sheet per table', () => {
    const ts = tables();
    const buf = buildWorkbook(ts, META({ dashboard: dashboard() }));
    // ZIP local-file-header magic.
    expect(buf.subarray(0, 4)).toEqual(Buffer.from([0x50, 0x4b, 0x03, 0x04]));
    const asText = buf.toString('latin1');
    expect(asText).toContain('xl/workbook.xml');
    expect(asText).toContain('xl/styles.xml');
    expect(asText).toContain('xl/sharedStrings.xml');
    // Executive Summary + N table sheets exist; one beyond the last must NOT.
    const total = ts.length + 1;
    expect(asText).toContain(`xl/worksheets/sheet${total}.xml`);
    expect(asText).not.toContain(`xl/worksheets/sheet${total + 1}.xml`);
  });

  it('is unzippable + workbook.xml well-formed + sheet names legal/unique', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fedpy-xlsx-'));
    const path = join(dir, 'wb.xlsx');
    const ts = tables();
    writeWorkbook(ts, META({ dashboard: dashboard() }), path);
    const listing = execFileSync('unzip', ['-l', path], { encoding: 'utf8' });
    expect(listing).toContain('xl/workbook.xml');
    const xml = execFileSync('unzip', ['-p', path, 'xl/workbook.xml'], { encoding: 'utf8' });
    // Executive Summary + one sheet per table.
    expect((xml.match(/<sheet /g) ?? []).length).toBe(ts.length + 1);
    const names = [...xml.matchAll(/name="([^"]+)"/g)].map((m) => m[1]!);
    expect(names[0]).toBe('Executive Summary');
    for (const n of names) expect(n, n).not.toMatch(/[:\\/?*\[\]]/);
    expect(new Set(names.map((n) => n.toLowerCase())).size).toBe(names.length);
  });

  it('workbook without a dashboard has exactly one sheet per table', () => {
    const ts = tables();
    const buf = buildWorkbook(ts, META()); // no dashboard
    const asText = buf.toString('latin1');
    expect(asText).toContain(`xl/worksheets/sheet${ts.length}.xml`);
    expect(asText).not.toContain(`xl/worksheets/sheet${ts.length + 1}.xml`);
  });
});

describe('summaryCoverFacts', () => {
  it('summarizes both framings', () => {
    const facts = summaryCoverFacts(joinRun(loadRun(writeSampleRun())).summary);
    const flat = facts.map(([k]) => k).join('|');
    expect(flat).toContain('Rev5 assessed pass rate');
    expect(flat).toContain('20x assessed pass rate');
  });
});

describe('dashboard model', () => {
  it('produces KPIs, posture, severity, top levers and family posture', () => {
    const d = dashboard();
    expect(d.kpis.length).toBeGreaterThanOrEqual(6);
    expect(d.kpis.some((k) => k.label === 'Assets Inventoried')).toBe(true);
    expect(d.controlPosture).toHaveLength(2);
    expect(d.severity).toHaveProperty('critical');
    // The sample has a failing encryption finding → at least one lever.
    expect(d.topLevers.length).toBeGreaterThan(0);
    expect(d.familyPosture.length).toBeGreaterThan(0);
    expect(d.notes.length).toBeGreaterThan(0);
  });
});
