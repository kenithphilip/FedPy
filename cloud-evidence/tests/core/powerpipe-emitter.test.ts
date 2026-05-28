/**
 * Tests for core/powerpipe-emitter.ts.
 *
 * The generator reads from the KSI catalog (which is real, not mocked) and
 * emits real HCL files. We verify:
 *   1. The directory structure and key files are present.
 *   2. Every supported KSI produces a corresponding control HCL block.
 *   3. The mod.pp, benchmark and dashboard files are syntactically plausible
 *      (parse-light, not full HCL parser).
 *   4. README points at the right evidence dir.
 *   5. Control SQL references the correct file path.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, readFileSync, readdirSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { emitPowerpipeMod } from '../../core/powerpipe-emitter.ts';
import { SUPPORTED_KSIS } from '../../core/ksi-map.ts';

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(resolve(tmpdir(), 'cev-pp-'));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

describe('emitPowerpipeMod', () => {
  it('creates the expected directory structure', () => {
    emitPowerpipeMod({ outDir: tmp });
    const ppDir = resolve(tmp, 'powerpipe');
    expect(existsSync(resolve(ppDir, 'mod.pp'))).toBe(true);
    expect(existsSync(resolve(ppDir, 'benchmarks', 'fedramp_20x.pp'))).toBe(true);
    expect(existsSync(resolve(ppDir, 'controls'))).toBe(true);
    expect(existsSync(resolve(ppDir, 'dashboards', 'overview.pp'))).toBe(true);
    expect(existsSync(resolve(ppDir, 'docs', 'overview.md'))).toBe(true);
    expect(existsSync(resolve(ppDir, 'README.md'))).toBe(true);
  });

  it('emits one control HCL block per supported KSI', () => {
    const r = emitPowerpipeMod({ outDir: tmp });
    expect(r.control_count).toBe(SUPPORTED_KSIS.length);

    // Concatenate every controls/*.pp and count `control "..." {` declarations
    const ctlFiles = readdirSync(resolve(tmp, 'powerpipe', 'controls'));
    const combined = ctlFiles.map((f) => readFileSync(resolve(tmp, 'powerpipe', 'controls', f), 'utf8')).join('\n');
    const ctlMatches = combined.match(/control\s+"[a-z0-9_]+"/g) ?? [];
    expect(ctlMatches.length).toBe(SUPPORTED_KSIS.length);
  });

  it('embeds the KSI ID into each control SQL', () => {
    emitPowerpipeMod({ outDir: tmp });
    const combined = readdirSync(resolve(tmp, 'powerpipe', 'controls'))
      .map((f) => readFileSync(resolve(tmp, 'powerpipe', 'controls', f), 'utf8')).join('\n');
    for (const ksi of SUPPORTED_KSIS) {
      expect(combined, `Expected control SQL to reference ${ksi}.json`).toMatch(new RegExp(`${ksi}\\.json`));
    }
  });

  it('mod.pp contains the expected mod name and file plugin require', () => {
    emitPowerpipeMod({ outDir: tmp });
    const mod = readFileSync(resolve(tmp, 'powerpipe', 'mod.pp'), 'utf8');
    expect(mod).toMatch(/mod "cloud_evidence"/);
    expect(mod).toMatch(/plugin "file"/);
  });

  it('top-level benchmark groups every domain', () => {
    emitPowerpipeMod({ outDir: tmp });
    const bench = readFileSync(resolve(tmp, 'powerpipe', 'benchmarks', 'fedramp_20x.pp'), 'utf8');
    expect(bench).toMatch(/benchmark "fedramp_20x"/);
    // At minimum we should see IAM and CNA domains in our shipped KSI catalog
    expect(bench).toMatch(/benchmark.domain_iam/i);
    expect(bench).toMatch(/benchmark.domain_cna/i);
  });

  it('README points at the configured evidence directory', () => {
    const evidenceDir = '/tmp/my-evidence';
    emitPowerpipeMod({ outDir: tmp, evidenceDirAbsolute: evidenceDir });
    const readme = readFileSync(resolve(tmp, 'powerpipe', 'README.md'), 'utf8');
    expect(readme).toMatch(/\/tmp\/my-evidence/);
  });

  it('returned counts match emitted file contents', () => {
    const r = emitPowerpipeMod({ outDir: tmp });
    // domain_count = unique KSI domain prefixes; benchmark_count = domains + 1 top-level
    const ctlFiles = readdirSync(resolve(tmp, 'powerpipe', 'controls'));
    expect(ctlFiles.length).toBe(r.domain_count);
    expect(r.benchmark_count).toBe(r.domain_count + 1);
  });
});
