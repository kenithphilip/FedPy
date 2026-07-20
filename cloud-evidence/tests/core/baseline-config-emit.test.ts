/**
 * LOOP-C.C9 — Baseline Configuration document (CM-2) emitter tests.
 *
 * 13 tests per docs/slices/C/C.C9.md §8. §3/§4/§5 trace to the real inventory.json
 * fixture + the real providers/{aws,gcp,azure}/reference-arch.ts source greps + a
 * pure diff of the two. No mocked emitter internals — the readers, the diff, and
 * the OOXML builder run for real; only the outDir (and, for the degraded §4 test,
 * the providersRoot) are pointed at test locations.
 */
import { it, expect, describe, afterEach } from 'vitest';
import { mkdtempSync, copyFileSync, existsSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  emitBaselineConfigDocx,
  renderBaselineConfigDocx,
  buildBaselineConfigBodyXml,
  buildBaselineItemRows,
  readInventoryBaselineRows,
  readReferenceArchitecturesAllProviders,
  diffInventoryVsReference,
  componentClassFor,
  type BaselineConfigOptions,
  type BaselineConfigApprover,
} from '../../core/baseline-config-emit.ts';

const FIXTURE_DIR = resolve(import.meta.dirname ?? '', 'fixtures/baseline');

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-bcfg-'));
  dirs.push(d);
  return d;
}
/** Seed a tmp outDir with the fixture inventory.json. */
function tmpFull(): string {
  const d = tmp();
  copyFileSync(join(FIXTURE_DIR, 'inventory.sample.json'), join(d, 'inventory.json'));
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

const APPROVER: BaselineConfigApprover = {
  name: 'Dana Baseline', role: 'Configuration Control Board Chair', org: 'Acme Corp', date: '2026-07-11',
};

function baseOpts(over: Partial<BaselineConfigOptions> = {}): BaselineConfigOptions {
  return { outDir: '/nonexistent-bcfg-dir', runId: 'r-bcfg-test', frmrVersion: '0.9.43-beta', impactLevel: 'moderate', ...over };
}
/** Every required-for-signature operator field supplied over a full outDir. */
function fullOpts(dir: string, over: Partial<BaselineConfigOptions> = {}): BaselineConfigOptions {
  return baseOpts({
    outDir: dir,
    systemName: 'Acme Platform', systemId: 'acme-prod-1', cspOrganization: 'Acme Corp',
    baselineApprover: APPROVER,
    deviationLogLocation: 'https://cmdb.acme.example/baseline/deviations',
    baselineReviewCadence: 'quarterly',
    ...over,
  });
}

// ── Test 1 ──
it('emits 8 sections', () => {
  const { xml } = buildBaselineConfigBodyXml(fullOpts(tmpFull()));
  const idx = (s: string) => xml.indexOf(s);
  const sections = [
    '1. Introduction and Purpose',
    '2. Methodology and Provenance',
    '3. Baseline Configuration Items',
    '4. Reference Architecture',
    '5. Deviations from Baseline',
    '6. Baseline Maintenance',
    '7. Deviation Approval Process',
    '8. Approval Signatures',
  ];
  for (let i = 0; i < sections.length; i++) {
    expect(idx(sections[i]!)).toBeGreaterThan(-1);
    if (i > 0) expect(idx(sections[i]!)).toBeGreaterThan(idx(sections[i - 1]!));
  }
});

// ── Test 2 ──
it('§3 component-group rows derived from inventory.json', () => {
  const dir = tmpFull();
  const inv = readInventoryBaselineRows(dir);
  expect(inv).not.toBeNull();
  expect(inv!.rows.length).toBe(6);
  const rows = buildBaselineItemRows(inv!.rows);
  // 6 assets collapse into 6 (provider, class) groups.
  const components = rows.map((r) => r.component).sort();
  expect(components).toEqual([
    'aws/compute', 'aws/database', 'aws/storage', 'azure/compute', 'azure/storage', 'gcp/compute',
  ]);
  const { xml, stats } = buildBaselineConfigBodyXml(fullOpts(dir));
  expect(stats.inventory_present).toBe(true);
  expect(stats.baseline_item_count).toBe(6);
  expect(stats.asset_count).toBe(6);
  const s3 = xml.indexOf('3. Baseline Configuration Items');
  const s4 = xml.indexOf('4. Reference Architecture');
  const slice = xml.slice(s3, s4);
  // Real baseline images from the inventory appear in §3.
  expect(slice).toContain('ami-0c55b159cbfafe1f0');
  expect(slice).toContain('CIS GCP Foundation Benchmark 1.3.0');
  expect(slice).toContain('aws/compute');
});

// ── Test 3 ──
it('§4 reference architecture rows derived from providers/*/reference-arch.ts source greps', () => {
  const dir = tmpFull();
  const ref = readReferenceArchitecturesAllProviders();
  // Real rule names grep-read from the reference-arch.ts source.
  const rules = ref.entries.map((e) => e.rule);
  expect(rules).toContain('aws.kms.customer_managed_keys_in_use');
  expect(rules).toContain('aws.ec2.approved_ami_provenance');
  // Controls extracted from the real nist_controls arrays.
  const kms = ref.entries.find((e) => e.rule === 'aws.kms.customer_managed_keys_in_use');
  expect(kms!.controls).toContain('sc-28');
  expect(kms!.severity).toBe('high');
  const { xml, stats } = buildBaselineConfigBodyXml(fullOpts(dir));
  expect(stats.reference_entry_count).toBe(ref.entries.length);
  expect(stats.reference_entry_count).toBeGreaterThanOrEqual(30);
  const s4 = xml.indexOf('4. Reference Architecture');
  const s5 = xml.indexOf('5. Deviations from Baseline');
  const slice = xml.slice(s4, s5);
  expect(slice).toContain('aws.ec2.approved_ami_provenance');
  // The documented baseline expectation text (real finding target summary) appears.
  expect(slice).toContain('customer-managed KMS keys');
});

// ── Test 4 ──
it('§5 deviation rows from diffInventoryVsReference', () => {
  const dir = tmpFull();
  const inv = readInventoryBaselineRows(dir)!;
  const ref = readReferenceArchitecturesAllProviders();
  const devs = diffInventoryVsReference(inv.rows, ref.entries);
  // EC2 (compute) with empty baselineConfig → undocumented-hardening deviation
  // (severity from aws.ec2.approved_ami_provenance = medium). RDS (database) with
  // encryptionAtRest=false → encryption deviation (severity from the AWS KMS
  // anchor = high). Exactly two deviations, both on AWS.
  expect(devs.length).toBe(2);
  const compute = devs.find((d) => d.component === 'aws/compute');
  const database = devs.find((d) => d.component === 'aws/database');
  expect(compute).toBeDefined();
  expect(compute!.severity).toBe('medium');
  expect(compute!.current).toContain('without a documented hardening baseline');
  expect(database).toBeDefined();
  expect(database!.severity).toBe('high');
  expect(database!.current).toContain('encryption-at-rest disabled');
  // The severities appear in the rendered §5 table.
  const { xml, stats } = buildBaselineConfigBodyXml(fullOpts(dir));
  expect(stats.deviation_count).toBe(2);
  const s5 = xml.indexOf('5. Deviations from Baseline');
  const s6 = xml.indexOf('6. Baseline Maintenance');
  const slice = xml.slice(s5, s6);
  expect(slice).toContain('aws/database');
});

// ── Test 5 ──
it('REQUIRES-OPERATOR-INPUT when inventory.json absent', () => {
  const dir = tmp(); // empty outDir
  expect(readInventoryBaselineRows(dir)).toBeNull();
  const { xml, stats } = buildBaselineConfigBodyXml(fullOpts(dir));
  expect(stats.inventory_present).toBe(false);
  expect(stats.baseline_item_count).toBe(0);
  expect(stats.asset_count).toBe(0);
  const s3 = xml.indexOf('3. Baseline Configuration Items');
  const s4 = xml.indexOf('4. Reference Architecture');
  const marker = xml.indexOf('REQUIRES-OPERATOR-INPUT', s3);
  expect(marker).toBeGreaterThan(s3);
  expect(marker).toBeLessThan(s4);
  expect(xml).toContain('inventory → baseline-config → CMP');
});

// ── Test 6 ──
it('REQUIRES-OPERATOR-INPUT when no reference-arch.ts files readable', () => {
  const dir = tmpFull();
  const emptyProviders = tmp(); // a dir with no aws|gcp|azure/reference-arch.ts
  const ref = readReferenceArchitecturesAllProviders(emptyProviders);
  expect(ref.entries.length).toBe(0);
  expect(ref.readable.aws).toBe(false);
  expect(ref.readable.gcp).toBe(false);
  expect(ref.readable.azure).toBe(false);
  const { xml, stats } = buildBaselineConfigBodyXml(fullOpts(dir, { providersRoot: emptyProviders }));
  expect(stats.reference_entry_count).toBe(0);
  expect(stats.providers_covered).toEqual([]);
  // §4 degrades to a REQUIRES-OPERATOR-INPUT marker and §5 has nothing to diff.
  const s4 = xml.indexOf('4. Reference Architecture');
  const s5 = xml.indexOf('5. Deviations from Baseline');
  const s6 = xml.indexOf('6. Baseline Maintenance');
  expect(xml.indexOf('REQUIRES-OPERATOR-INPUT', s4)).toBeGreaterThan(s4);
  expect(xml.slice(s5, s6)).toContain('no automated deviation diff was computed');
  expect(stats.deviation_count).toBe(0);
});

// ── Test 7 ──
it('§7 cross-links to cmp.docx when present', () => {
  const { xml } = buildBaselineConfigBodyXml(fullOpts(tmpFull()));
  const s7 = xml.indexOf('7. Deviation Approval Process');
  const s8 = xml.indexOf('8. Approval Signatures');
  const slice = xml.slice(s7, s8);
  // Cross-links to the CMP (C.C1) by relative filename (Q5 — anchor links are
  // not well-supported in .docx).
  expect(slice).toContain('cmp.docx §6');
});

// ── Test 8 ──
it('renders baselineApprover signature block', () => {
  const { xml } = buildBaselineConfigBodyXml(fullOpts(tmpFull()));
  const s8 = xml.indexOf('8. Approval Signatures');
  const prov = xml.indexOf('Provenance', s8);
  const slice = xml.slice(s8, prov);
  expect(slice).toContain('Dana Baseline');
  expect(slice).toContain('Configuration Control Board Chair, Acme Corp');
  expect(slice).toContain('Date: 2026-07-11');
  // The signature block is fully supplied — no operator-input marker in §8.
  expect(slice).not.toContain('REQUIRES-OPERATOR-INPUT');
});

// ── Test 9 ──
it('quotes SP 800-128 §3.2 verbatim in §1', () => {
  const { xml } = buildBaselineConfigBodyXml(fullOpts(tmpFull()));
  const s1 = xml.indexOf('1. Introduction and Purpose');
  const s2 = xml.indexOf('2. Methodology and Provenance');
  const slice = xml.slice(s1, s2);
  expect(slice).toContain('A baseline configuration is a documented, formally reviewed and agreed-upon specification');
  expect(slice).toContain('provides the basis for future builds, releases, and changes to systems');
  // CM-2 control text is also quoted.
  expect(slice).toContain('a current baseline configuration of the system');
});

// ── Test 10 ──
it('handles multi-cloud (AWS+GCP+Azure) reference-arch parsing', () => {
  const ref = readReferenceArchitecturesAllProviders();
  expect(ref.readable.aws).toBe(true);
  expect(ref.readable.gcp).toBe(true);
  expect(ref.readable.azure).toBe(true);
  expect(ref.perProvider.aws).toBeGreaterThan(0);
  expect(ref.perProvider.gcp).toBeGreaterThan(0);
  expect(ref.perProvider.azure).toBeGreaterThan(0);
  // Rules from every cloud are present.
  const providers = new Set(ref.entries.map((e) => e.provider));
  expect(providers).toEqual(new Set(['aws', 'gcp', 'azure']));
  expect(ref.entries.some((e) => e.rule.startsWith('gcp.'))).toBe(true);
  expect(ref.entries.some((e) => e.rule.startsWith('azure.'))).toBe(true);
  const { stats } = buildBaselineConfigBodyXml(fullOpts(tmpFull()));
  expect(stats.providers_covered).toEqual(['aws', 'gcp', 'azure']);
});

// ── Test 11 ──
it('writes to outPath when supplied', () => {
  const dir = tmpFull();
  const outPath = join(dir, 'custom-baseline.docx');
  const r = emitBaselineConfigDocx(fullOpts(dir, { outPath }));
  expect(r.path).toBe(outPath);
  expect(existsSync(outPath)).toBe(true);
  expect(r.bytes).toBeGreaterThan(0);
  // A .docx is a ZIP — first bytes are the local-file-header signature 'PK\x03\x04'.
  const head = readFileSync(outPath);
  expect(head[0]).toBe(0x50);
  expect(head[1]).toBe(0x4b);
  expect(r.inventory_present).toBe(true);
  expect(r.deviation_count).toBe(2);
});

// ── Test 12 ──
it('deterministic output', () => {
  const dir = tmpFull();
  const a = renderBaselineConfigDocx(fullOpts(dir));
  const b = renderBaselineConfigDocx(fullOpts(dir));
  expect(a.buffer.equals(b.buffer)).toBe(true);
  // Same body XML too (no wall-clock time anywhere).
  const xa = buildBaselineConfigBodyXml(fullOpts(dir)).xml;
  const xb = buildBaselineConfigBodyXml(fullOpts(dir)).xml;
  expect(xa).toBe(xb);
});

// ── Test 13 ──
it('ready_for_signature requires approver + deviation-log + cadence', () => {
  const dir = tmpFull();
  // All three supplied → ready.
  expect(buildBaselineConfigBodyXml(fullOpts(dir)).stats.ready_for_signature).toBe(true);
  // Missing approver.
  const noApprover = buildBaselineConfigBodyXml(fullOpts(dir, { baselineApprover: undefined })).stats;
  expect(noApprover.ready_for_signature).toBe(false);
  expect(noApprover.requires_operator_input.some((m) => m.includes('baselineApprover'))).toBe(true);
  // Missing deviation-log.
  const noLog = buildBaselineConfigBodyXml(fullOpts(dir, { deviationLogLocation: undefined })).stats;
  expect(noLog.ready_for_signature).toBe(false);
  expect(noLog.requires_operator_input.some((m) => m.includes('deviationLogLocation'))).toBe(true);
  // Missing cadence (defaults to annually but flags for operator confirmation).
  const noCadence = buildBaselineConfigBodyXml(fullOpts(dir, { baselineReviewCadence: undefined })).stats;
  expect(noCadence.ready_for_signature).toBe(false);
  expect(noCadence.review_cadence).toBe('annually');
  expect(noCadence.requires_operator_input.some((m) => m.includes('baselineReviewCadence'))).toBe(true);
});

// ── Extra REO coverage: the provenance footer cites the SHA-256 of every source
//    read (inventory.json + each reference-arch.ts), so the artifact is
//    reconstructable and byte-verifiable (C.C9 REO note). ──
it('provenance footer cites sha256 of inventory + reference-arch sources', () => {
  const dir = tmpFull();
  const inv = readInventoryBaselineRows(dir)!;
  const ref = readReferenceArchitecturesAllProviders();
  const { xml } = buildBaselineConfigBodyXml(fullOpts(dir));
  const prov = xml.indexOf('Provenance');
  const slice = xml.slice(prov);
  expect(slice).toContain(inv.sha256);
  expect(slice).toContain(ref.sha256.aws!);
  expect(slice).toContain(ref.sha256.gcp!);
  expect(slice).toContain(ref.sha256.azure!);
  // Control basis + configuration-management guide URLs are cited verbatim.
  expect(slice).toContain('https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final');
  expect(slice).toContain('NIST.SP.800-128.pdf');
});

// ── Extra unit coverage for the normalization helper (not one of the 13; keeps
//    the componentClassFor mapping honest across clouds). ──
describe('componentClassFor normalization', () => {
  it('maps provider-native types to stable classes', () => {
    expect(componentClassFor('Compute Instance', 'AWS::EC2::Instance')).toBe('compute');
    expect(componentClassFor('Relational Database Instance', 'AWS::RDS::DBInstance')).toBe('database');
    expect(componentClassFor('Object Storage', 'AWS::S3::Bucket')).toBe('storage');
    expect(componentClassFor('Virtual Machine', 'Microsoft.Compute/virtualMachines')).toBe('compute');
    expect(componentClassFor('Kubernetes Cluster', 'AWS::EKS::Cluster')).toBe('container');
    expect(componentClassFor(null, null)).toBe('other');
  });
});
