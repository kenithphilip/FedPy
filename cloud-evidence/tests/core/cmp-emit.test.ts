/**
 * Tests for core/cmp-emit.ts — LOOP-C.C1 Configuration Management Plan (CM-9).
 *
 * Verifies:
 *   1. Emitted cmp.docx is a valid store-only ZIP with the expected OOXML parts.
 *   2. The 11 numbered sections appear in document.xml in order.
 *   3. §4 Configuration Items are auto-derived + grouped from a real inventory.
 *   4. Missing inventory → a REQUIRES-OPERATOR-INPUT row (not an empty table).
 *   5. Missing process narratives → REQUIRES-OPERATOR-INPUT markers.
 *   6. Operator-supplied narrative renders verbatim.
 *   7. §5 cross-links to the C.C9 baseline-config.docx when the href is supplied.
 *   8. §7 Configuration Monitoring lists ≥20 real KSI domains from ksi-map.ts.
 *   9. Inferred CM tooling is marked REQUIRES-OPERATOR-INPUT-VERIFY (distinct).
 *  10. Fully deterministic output (same inputs → byte-identical .docx + title).
 *  11. Writes to a custom outPath.
 *  12. Emits a structured log event with bytes + component_count + ksi_count.
 *  13. ready_for_signature is false when any operator field is omitted.
 *  14. ready_for_signature is true when every field is supplied + inventory ≥1.
 *  15. Operator-supplied tooling is confirmed (not VERIFY-marked).
 *  16. §1 provenance cites emitter path + inventory sha256 + runId + FRMR.
 *  17. The config.sample.yaml fixture maps to a ready-for-signature CMP.
 *  18. CM-9 + SP 800-128 §2.1 + CM-4 source text appears verbatim.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { parse as parseYaml } from 'yaml';
import {
  emitCmpDocx, renderCmpDocx, buildCmpBodyXml,
  readInventoryComponents, groupComponents,
  type CmpEmitOptions,
} from '../../core/cmp-emit.ts';
import { log } from '../../core/log.ts';

const FIXTURE_DIR = resolve(import.meta.dirname ?? '', 'fixtures/cmp');

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-cmp-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  vi.restoreAllMocks();
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

/** Copy the sample inventory fixture into <dir>/inventory.json. */
function loadSampleInventory(dir: string): void {
  writeFileSync(join(dir, 'inventory.json'), readFileSync(join(FIXTURE_DIR, 'inventory.sample.json')));
}

function baseOpts(over: Partial<CmpEmitOptions> = {}): CmpEmitOptions {
  return { outDir: '/nonexistent-cmp-dir', runId: 'r-cmp-test', frmrVersion: '0.9.43-beta', impactLevel: 'moderate', ...over };
}

/** Every required-for-signature operator field supplied. */
function fullOpts(dir: string, over: Partial<CmpEmitOptions> = {}): CmpEmitOptions {
  return baseOpts({
    outDir: dir,
    systemName: 'Acme Platform', systemId: 'acme-prod-1', cspOrganization: 'Acme Corp',
    approvalWorkflowNarrative: 'The CCB convenes weekly and reviews every change for security impact.',
    rollbackAuthority: 'The on-call Engineering Manager may order an immediate rollback.',
    changeWindowsDescription: 'Standard changes deploy continuously; maintenance is Sundays 02:00-06:00 UTC.',
    baselineConfigHref: './baseline-config.docx',
    ccbRoster: [{ role: 'CCB Chair', name: 'Jane Doe', organization: 'Acme', email: 'jane@acme.example' }],
    cmTooling: [{ name: 'AWS Systems Manager', purpose: 'Automated CM + patch compliance' }],
    ...over,
  });
}

/** List every entry name in a store-only ZIP. */
function listZipEntries(buf: Buffer): string[] {
  const names: string[] = [];
  let off = 0;
  while (off < buf.length - 22) {
    if (buf.readUInt32LE(off) !== 0x04034b50) break;
    const nameLen = buf.readUInt16LE(off + 26);
    const extraLen = buf.readUInt16LE(off + 28);
    const compSize = buf.readUInt32LE(off + 18);
    names.push(buf.subarray(off + 30, off + 30 + nameLen).toString('utf8'));
    off += 30 + nameLen + extraLen + compSize;
  }
  return names;
}

/** Read a named part from a store-only ZIP. */
function readPart(buf: Buffer, partName: string): string {
  let off = 0;
  while (off < buf.length - 22) {
    if (buf.readUInt32LE(off) !== 0x04034b50) break;
    const nameLen = buf.readUInt16LE(off + 26);
    const extraLen = buf.readUInt16LE(off + 28);
    const compSize = buf.readUInt32LE(off + 18);
    const name = buf.subarray(off + 30, off + 30 + nameLen).toString('utf8');
    const dataStart = off + 30 + nameLen + extraLen;
    if (name === partName) return buf.subarray(dataStart, dataStart + compSize).toString('utf8');
    off = dataStart + compSize;
  }
  throw new Error(`${partName} not found in zip`);
}

/** Extract ordered Heading1 titles from document.xml. */
function heading1Titles(xml: string): string[] {
  return [...xml.matchAll(/<w:pStyle w:val="Heading1"\/><\/w:pPr><w:r><w:t xml:space="preserve">([^<]*)<\/w:t>/g)].map((m) => m[1]!);
}

describe('CMP emitter — package structure', () => {
  it('produces a valid .docx with all 5 OOXML parts (+ docProps/core.xml)', () => {
    const { buffer } = renderCmpDocx(fullOpts(tmp()));
    const names = listZipEntries(buffer);
    expect(names).toContain('[Content_Types].xml');
    expect(names).toContain('_rels/.rels');
    expect(names).toContain('word/document.xml');
    expect(names).toContain('word/styles.xml');
    expect(names).toContain('word/_rels/document.xml.rels');
    expect(names).toContain('docProps/core.xml');
  });

  it('emits 11 numbered sections in document.xml in order', () => {
    const { xml } = buildCmpBodyXml(fullOpts(tmp()));
    const titles = heading1Titles(xml);
    expect(titles.length).toBe(11);
    titles.forEach((t, i) => expect(t.startsWith(`${i + 1}.`)).toBe(true));
    expect(titles[0]).toContain('Document Information');
    expect(titles[3]).toContain('Configuration Items');
    expect(titles[6]).toContain('Configuration Monitoring');
    expect(titles[10]).toContain('Plan Maintenance');
  });
});

describe('CMP emitter — §4 Configuration Items (auto-derived)', () => {
  it('auto-derives component groups from inventory.json (6 assets → 3 rows)', () => {
    const d = tmp();
    loadSampleInventory(d);
    const comps = readInventoryComponents(d);
    expect(comps.length).toBe(6);
    const groups = groupComponents(comps);
    expect(groups.length).toBe(3);
    for (const g of groups) expect(g.count).toBe(2);
    const { xml, stats } = buildCmpBodyXml(baseOpts({ outDir: d }));
    expect(stats.component_count).toBe(6);
    expect(xml).toContain('EC2 Instance');
    expect(xml).toContain('RDS Database');
    expect(xml).toContain('Cloud Storage Bucket');
  });

  it('falls back to REQUIRES-OPERATOR-INPUT when inventory.json is missing', () => {
    const d = tmp();
    const { xml, stats } = buildCmpBodyXml(baseOpts({ outDir: d }));
    expect(stats.component_count).toBe(0);
    expect(stats.requires_operator_input).toContain('inventory (out/inventory.json missing or empty)');
    expect(xml).toContain('REQUIRES-OPERATOR-INPUT');
    expect(xml).toContain('missing or empty');
  });
});

describe('CMP emitter — REQUIRES-OPERATOR-INPUT behaviour', () => {
  it('emits REQUIRES-OPERATOR-INPUT for approvalWorkflowNarrative when omitted', () => {
    const { xml, stats } = buildCmpBodyXml(baseOpts());
    expect(stats.requires_operator_input).toContain('approvalWorkflowNarrative');
    expect(xml).toContain('REQUIRES-OPERATOR-INPUT');
  });

  it('renders operator-supplied narrative verbatim', () => {
    const { xml } = buildCmpBodyXml(baseOpts({ approvalWorkflowNarrative: 'CCB convenes every Tuesday' }));
    expect(xml).toContain('CCB convenes every Tuesday');
  });

  it('cross-links to C.C9 baseline-config.docx when href supplied', () => {
    const { xml } = buildCmpBodyXml(baseOpts({ baselineConfigHref: './baseline-config.docx' }));
    expect(xml).toContain('./baseline-config.docx');
  });
});

describe('CMP emitter — §7 Configuration Monitoring (ksi-map)', () => {
  it('reads ksi-map.ts for the §7 monitored-controls list (≥20 domains)', () => {
    const { xml, stats } = buildCmpBodyXml(baseOpts());
    expect(stats.ksi_count).toBeGreaterThanOrEqual(20);
    expect(xml).toContain('Configuration Monitoring');
    const distinct = new Set((xml.match(/KSI-[A-Z]+-[A-Z]+/g) ?? []));
    expect(distinct.size).toBeGreaterThanOrEqual(20);
  });
});

describe('CMP emitter — §10 tooling', () => {
  it('marks inferred cmTooling as REQUIRES-OPERATOR-INPUT-VERIFY', () => {
    const d = tmp();
    loadSampleInventory(d); // aws + gcp providers → inferred tooling
    const { xml } = buildCmpBodyXml(baseOpts({ outDir: d }));
    expect(xml).toContain('REQUIRES-OPERATOR-INPUT-VERIFY');
    expect(xml).toContain('AWS Systems Manager');
    expect(xml).toContain('GCP Config Connector');
  });

  it('renders operator-supplied tooling as operator-confirmed (not VERIFY)', () => {
    const d = tmp();
    loadSampleInventory(d);
    const { xml } = buildCmpBodyXml(baseOpts({
      outDir: d,
      cmTooling: [{ name: 'Terraform Cloud', purpose: 'IaC with policy-as-code gating' }],
    }));
    expect(xml).toContain('Terraform Cloud');
    expect(xml).toContain('operator-confirmed');
    expect(xml).not.toContain('REQUIRES-OPERATOR-INPUT-VERIFY');
  });
});

describe('CMP emitter — determinism + metadata', () => {
  it('produces byte-identical output + title metadata for identical inputs', () => {
    const a = renderCmpDocx(baseOpts({ systemName: 'Sys', systemId: 'sys-1' }));
    const b = renderCmpDocx(baseOpts({ systemName: 'Sys', systemId: 'sys-1' }));
    expect(Buffer.compare(a.buffer, b.buffer)).toBe(0);
    const coreA = readPart(a.buffer, 'docProps/core.xml');
    const coreB = readPart(b.buffer, 'docProps/core.xml');
    expect(coreA).toBe(coreB);
    expect(coreA).toContain('<dc:title>');
    expect(coreA).toContain('Configuration Management Plan');
    // Deterministic UUID (v4-shaped) present in the title metadata.
    expect(coreA).toMatch(/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/);
  });
});

describe('CMP emitter — disk (emitCmpDocx)', () => {
  it('writes to outPath when supplied', () => {
    const d = tmp();
    const outPath = join(d, 'custom-cmp.docx');
    const r = emitCmpDocx(baseOpts({ outDir: d, outPath }));
    expect(r.path).toBe(outPath);
    expect(existsSync(outPath)).toBe(true);
    expect(r.bytes).toBeGreaterThan(10000);
  });

  it('logs a structured event with bytes + component_count + ksi_count', () => {
    const d = tmp();
    loadSampleInventory(d);
    const spy = vi.spyOn(log, 'info').mockImplementation(() => log as any);
    emitCmpDocx(baseOpts({ outDir: d }));
    expect(spy).toHaveBeenCalledWith(expect.objectContaining({
      event: 'cmp.emitted',
      bytes: expect.any(Number),
      component_count: 6,
      ksi_count: expect.any(Number),
    }));
  });
});

describe('CMP emitter — ready_for_signature', () => {
  it('is false when any operator field is omitted', () => {
    const d = tmp();
    loadSampleInventory(d);
    const opts = fullOpts(d);
    delete (opts as any).rollbackAuthority;
    const { stats } = buildCmpBodyXml(opts);
    expect(stats.ready_for_signature).toBe(false);
    expect(stats.requires_operator_input).toContain('rollbackAuthority');
  });

  it('is true when every operator field is supplied + inventory has ≥1 component', () => {
    const d = tmp();
    loadSampleInventory(d);
    const { stats } = buildCmpBodyXml(fullOpts(d));
    expect(stats.ready_for_signature).toBe(true);
    expect(stats.requires_operator_input).toEqual([]);
  });
});

describe('CMP emitter — provenance + sources', () => {
  it('§1 provenance cites emitter path + inventory sha256 + runId + FRMR version', () => {
    const d = tmp();
    loadSampleInventory(d);
    const digest = createHash('sha256').update(readFileSync(join(d, 'inventory.json'))).digest('hex');
    const { xml } = buildCmpBodyXml(baseOpts({ outDir: d, runId: 'run-xyz-42', frmrVersion: '0.9.43-beta' }));
    expect(xml).toContain('core/cmp-emit.ts');
    expect(xml).toContain(digest);
    expect(xml).toContain('run-xyz-42');
    expect(xml).toContain('0.9.43-beta');
    expect(xml).toContain('ksi-map.ts');
  });

  it('quotes CM-9 + SP 800-128 §2.1 + CM-4 source text verbatim', () => {
    const { xml } = buildCmpBodyXml(baseOpts());
    expect(xml).toContain('Develop, document, and implement a configuration management plan');
    expect(xml).toContain('These roles often include configuration control board');
    expect(xml).toContain('Analyze changes to the system to determine potential security');
  });

  it('maps the config.sample.yaml fixture to a ready-for-signature CMP', () => {
    const d = tmp();
    loadSampleInventory(d);
    const cfg: any = parseYaml(readFileSync(join(FIXTURE_DIR, 'config.sample.yaml'), 'utf8'));
    const c = cfg.cmp;
    const { xml, stats } = buildCmpBodyXml(baseOpts({
      outDir: d,
      systemName: 'Acme Platform', systemId: 'acme-prod-1', cspOrganization: 'Acme Corp',
      approvalWorkflowNarrative: c.approval_narrative,
      rollbackAuthority: c.rollback_authority,
      changeWindowsDescription: c.change_windows,
      baselineConfigHref: c.baseline_config_href,
      ccbRoster: c.ccb_roster,
      cmTooling: c.tooling,
    }));
    expect(stats.ready_for_signature).toBe(true);
    expect(stats.requires_operator_input).toEqual([]);
    expect(xml).toContain('Jordan Lee');
    expect(xml).toContain('AWS Systems Manager');
    expect(xml).toContain('operator-confirmed');
  });
});
