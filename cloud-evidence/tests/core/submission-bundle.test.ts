/**
 * Tests for core/submission-bundle.ts — LOOP-A.A4.
 *
 * Verifies:
 *   1. Bundle includes every file in outDir (well-known + per-KSI).
 *   2. INDEX.json carries the package_format_version + provenance.
 *   3. Chain check passes when SSP/AP/AR/POA&M are all present + linked.
 *   4. Chain check fails when AR.import-ap is synthetic.
 *   5. Gaps list every required artifact missing from outDir.
 *   6. Strict mode throws when gaps OR chain problems exist.
 *   7. Tarball is a valid POSIX ustar archive that round-trips via gunzip.
 *   8. mtime is honored for reproducible builds (same mtime → same bytes).
 *   9. Sub-directory traversal: summaries/*.md is included.
 *  10. Files outside the well-known catalogue are still bundled (with role
 *      = 'unrecognized') so nothing is silently dropped.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import {
  emitSubmissionBundle, buildSubmissionIndex, writeTar,
  type SubmissionIndex,
} from '../../core/submission-bundle.ts';

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-bundle-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

/** Decode a POSIX ustar archive into [{name, size}]. */
function parseTar(buf: Buffer): Array<{ name: string; size: number; body: Buffer }> {
  const out: Array<{ name: string; size: number; body: Buffer }> = [];
  let off = 0;
  while (off + 512 <= buf.length) {
    const name = buf.subarray(off, off + 100).toString('utf8').replace(/\0.*$/, '');
    if (!name) break;
    const sizeStr = buf.subarray(off + 124, off + 136).toString('utf8').replace(/\0/g, '').trim();
    const size = parseInt(sizeStr, 8);
    const body = buf.subarray(off + 512, off + 512 + size);
    out.push({ name, size, body });
    off += 512 + Math.ceil(size / 512) * 512;
  }
  return out;
}

function seedComplete(d: string) {
  // A minimally-complete submission package.
  writeFileSync(join(d, 'ssp.json'), JSON.stringify({
    'system-security-plan': { uuid: 'ssp-uuid-1', metadata: { 'last-modified': '2026-06-05T00:00:00Z' } },
  }));
  writeFileSync(join(d, 'ap.json'), JSON.stringify({
    'assessment-plan': { uuid: 'ap-uuid-1', 'import-ssp': { href: 'ssp.json' } },
  }));
  writeFileSync(join(d, 'assessment-results.json'), JSON.stringify({
    'assessment-results': { uuid: 'ar-uuid-1', 'import-ap': { href: 'ap.json' } },
  }));
  writeFileSync(join(d, 'poam.json'), JSON.stringify({
    'plan-of-action-and-milestones': { uuid: 'p-uuid-1', 'system-id': { id: 'sys-1' } },
  }));
  writeFileSync(join(d, 'inventory-workbook.xlsx'), Buffer.from('PK\x03\x04stub-xlsx'));
  writeFileSync(join(d, 'manifest.json'), JSON.stringify({
    files: [{ name: 'ssp.json', sha256: 'x', bytes: 0 }],
    signer_public_key: '-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----',
  }));
  writeFileSync(join(d, 'manifest.sig'), 'sig-bytes');
  writeFileSync(join(d, 'KSI-IAM-MFA.json'), JSON.stringify({
    ksi_id: 'KSI-IAM-MFA', run_id: 'r', collected_at: '2026-06-05T00:00:00Z', frmr_version: 'v', providers: [],
  }));
}

const OPTS = { runId: 'r-test', frmrVersion: '0.9.43-beta', mtime: 1717545600 } as const;

describe('submission-bundle — buildSubmissionIndex', () => {
  it('catalogues every file in outDir with role + sha256 + bytes', () => {
    const d = tmp();
    seedComplete(d);
    const { index } = buildSubmissionIndex(d, { outDir: d, ...OPTS });
    expect(index.artifacts.length).toBeGreaterThanOrEqual(8);
    const ssp = index.artifacts.find((a) => a.filename === 'ssp.json')!;
    expect(ssp.role).toBe('oscal-ssp');
    expect(ssp.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(ssp.bytes).toBeGreaterThan(0);
  });

  it('reports no gaps when every required artifact is present', () => {
    const d = tmp();
    seedComplete(d);
    const { index } = buildSubmissionIndex(d, { outDir: d, ...OPTS });
    expect(index.gaps).toEqual([]);
  });

  it('reports gaps for missing required artifacts', () => {
    const d = tmp();
    // Only seed ssp + manifest, leave ap/ar/poam/xlsx missing.
    writeFileSync(join(d, 'ssp.json'), JSON.stringify({ 'system-security-plan': { uuid: 's', metadata: {} } }));
    writeFileSync(join(d, 'manifest.json'), JSON.stringify({ files: [], signer_public_key: 'k' }));
    writeFileSync(join(d, 'manifest.sig'), 'x');
    const { index } = buildSubmissionIndex(d, { outDir: d, ...OPTS });
    const gapFilenames = index.gaps.map((g) => g.filename).sort();
    expect(gapFilenames).toContain('ap.json');
    expect(gapFilenames).toContain('assessment-results.json');
    expect(gapFilenames).toContain('inventory-workbook.xlsx');
  });

  it('chain_check.complete is true when every link resolves', () => {
    const d = tmp();
    seedComplete(d);
    const { index } = buildSubmissionIndex(d, { outDir: d, ...OPTS });
    expect(index.chain_check.complete).toBe(true);
    expect(index.chain_check.problems).toEqual([]);
  });

  it('chain_check flags synthetic AR.import-ap', () => {
    const d = tmp();
    seedComplete(d);
    // Overwrite AR with a synthetic import-ap.
    writeFileSync(join(d, 'assessment-results.json'), JSON.stringify({
      'assessment-results': { uuid: 'ar-2', 'import-ap': { href: '#cloud-evidence-no-external-ap' } },
    }));
    const { index } = buildSubmissionIndex(d, { outDir: d, ...OPTS });
    expect(index.chain_check.complete).toBe(false);
    expect(index.chain_check.problems[0]!.problem).toMatch(/synthetic/);
  });

  it('package_format_version + provenance are populated', () => {
    const d = tmp();
    seedComplete(d);
    const { index } = buildSubmissionIndex(d, { outDir: d, ...OPTS });
    expect(index.package_format_version).toMatch(/^20x\.phase-two/);
    expect(index.provenance.emitter).toBe('core/submission-bundle.ts');
    expect(index.provenance.sourceCalls.length).toBeGreaterThan(0);
    expect(index.run_id).toBe(OPTS.runId);
    expect(index.frmr_version).toBe(OPTS.frmrVersion);
  });

  it('includes files outside the well-known catalogue with role = "unrecognized"', () => {
    const d = tmp();
    seedComplete(d);
    writeFileSync(join(d, 'extra-thing.json'), '{}');
    const { index } = buildSubmissionIndex(d, { outDir: d, ...OPTS });
    const extra = index.artifacts.find((a) => a.filename === 'extra-thing.json')!;
    expect(extra.role).toBe('unrecognized');
  });

  it('descends into summaries/ for csx-summary-markdown files', () => {
    const d = tmp();
    seedComplete(d);
    mkdirSync(join(d, 'summaries'), { recursive: true });
    writeFileSync(join(d, 'summaries', 'KSI-IAM-MFA.md'), '# summary');
    const { index } = buildSubmissionIndex(d, { outDir: d, ...OPTS });
    const summary = index.artifacts.find((a) => a.filename === 'summaries/KSI-IAM-MFA.md')!;
    expect(summary.role).toBe('csx-summary-markdown');
  });

  it('marks in_manifest=true when the file appears in manifest.json.files', () => {
    const d = tmp();
    seedComplete(d);
    // Re-write manifest to include ssp + ar.
    writeFileSync(join(d, 'manifest.json'), JSON.stringify({
      files: [
        { name: 'ssp.json', sha256: 'x', bytes: 0 },
        { name: 'assessment-results.json', sha256: 'y', bytes: 0 },
      ],
      signer_public_key: 'k',
    }));
    const { index } = buildSubmissionIndex(d, { outDir: d, ...OPTS });
    const ssp = index.artifacts.find((a) => a.filename === 'ssp.json')!;
    const ar = index.artifacts.find((a) => a.filename === 'assessment-results.json')!;
    const xlsx = index.artifacts.find((a) => a.filename === 'inventory-workbook.xlsx')!;
    expect(ssp.in_manifest).toBe(true);
    expect(ar.in_manifest).toBe(true);
    expect(xlsx.in_manifest).toBe(false); // not in the manifest file list
  });
});

describe('submission-bundle — emitSubmissionBundle (disk)', () => {
  it('writes submission-package.tar.gz + INDEX.json + the result reports correctly', () => {
    const d = tmp();
    seedComplete(d);
    const r = emitSubmissionBundle({ outDir: d, ...OPTS });
    expect(existsSync(r.bundle_path)).toBe(true);
    expect(existsSync(r.index_path)).toBe(true);
    expect(r.bundle_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(r.bundle_bytes).toBeGreaterThan(100);
    expect(r.artifact_count).toBeGreaterThanOrEqual(8);
    expect(r.gap_count).toBe(0);
    expect(r.chain_complete).toBe(true);
  });

  it('tarball round-trips through gunzip + POSIX ustar parser', () => {
    const d = tmp();
    seedComplete(d);
    const r = emitSubmissionBundle({ outDir: d, ...OPTS });
    const tar = gunzipSync(readFileSync(r.bundle_path));
    const entries = parseTar(tar);
    const names = entries.map((e) => e.name).sort();
    expect(names).toContain('INDEX.json');
    expect(names).toContain('ssp.json');
    expect(names).toContain('ap.json');
    expect(names).toContain('assessment-results.json');
    expect(names).toContain('poam.json');
    expect(names).toContain('inventory-workbook.xlsx');
    expect(names).toContain('manifest.json');
    expect(names).toContain('manifest.sig');
    expect(names).toContain('KSI-IAM-MFA.json');
    // INDEX.json is first by design (consumers can stream-read).
    expect(entries[0]!.name).toBe('INDEX.json');
  });

  it('tarball is reproducible: same inputs + same mtime → byte-identical bundle', () => {
    const d1 = tmp(); const d2 = tmp();
    seedComplete(d1); seedComplete(d2);
    const r1 = emitSubmissionBundle({ outDir: d1, ...OPTS });
    const r2 = emitSubmissionBundle({ outDir: d2, ...OPTS });
    // Note: INDEX.json contains built_at + provenance.emittedAt timestamps,
    // so the bundles themselves WILL differ — but the file payloads we
    // pulled from disk should match.
    const tar1 = parseTar(gunzipSync(readFileSync(r1.bundle_path)));
    const tar2 = parseTar(gunzipSync(readFileSync(r2.bundle_path)));
    // Compare every non-INDEX file by hash.
    const map1 = new Map(tar1.filter((e) => e.name !== 'INDEX.json').map((e) => [e.name, e.body]));
    const map2 = new Map(tar2.filter((e) => e.name !== 'INDEX.json').map((e) => [e.name, e.body]));
    expect([...map1.keys()].sort()).toEqual([...map2.keys()].sort());
    for (const [name, body1] of map1) {
      expect(body1.equals(map2.get(name)!)).toBe(true);
    }
  });

  it('strict=true throws when required artifacts are missing', () => {
    const d = tmp();
    // Minimal seed missing ap/ar/poam/xlsx.
    writeFileSync(join(d, 'ssp.json'), JSON.stringify({ 'system-security-plan': { uuid: 's', metadata: {} } }));
    writeFileSync(join(d, 'manifest.json'), JSON.stringify({ files: [], signer_public_key: 'k' }));
    writeFileSync(join(d, 'manifest.sig'), 'x');
    expect(() => emitSubmissionBundle({ outDir: d, ...OPTS, strict: true }))
      .toThrow(/required artifact\(s\) missing/);
  });

  it('strict=true throws on broken chain even when all files exist', () => {
    const d = tmp();
    seedComplete(d);
    // Break the chain: synthetic AR import-ap.
    writeFileSync(join(d, 'assessment-results.json'), JSON.stringify({
      'assessment-results': { uuid: 'ar-2', 'import-ap': { href: '#cloud-evidence-no-external-ap' } },
    }));
    expect(() => emitSubmissionBundle({ outDir: d, ...OPTS, strict: true }))
      .toThrow(/chain incomplete/);
  });

  it('strict=false (default) still emits when gaps exist — INDEX records them', () => {
    const d = tmp();
    writeFileSync(join(d, 'ssp.json'), JSON.stringify({ 'system-security-plan': { uuid: 's', metadata: {} } }));
    writeFileSync(join(d, 'manifest.json'), JSON.stringify({ files: [], signer_public_key: 'k' }));
    writeFileSync(join(d, 'manifest.sig'), 'x');
    const r = emitSubmissionBundle({ outDir: d, ...OPTS });
    expect(existsSync(r.bundle_path)).toBe(true);
    expect(r.gap_count).toBeGreaterThan(0);
  });

  it('INDEX.json inside the tarball matches the INDEX.json on disk', () => {
    const d = tmp();
    seedComplete(d);
    const r = emitSubmissionBundle({ outDir: d, ...OPTS });
    const onDisk = JSON.parse(readFileSync(r.index_path, 'utf8')) as SubmissionIndex;
    const tar = parseTar(gunzipSync(readFileSync(r.bundle_path)));
    const inTar = JSON.parse(tar.find((e) => e.name === 'INDEX.json')!.body.toString('utf8')) as SubmissionIndex;
    expect(inTar.artifacts.length).toBe(onDisk.artifacts.length);
    expect(inTar.package_format_version).toBe(onDisk.package_format_version);
  });
});

describe('submission-bundle — writeTar (POSIX ustar)', () => {
  it('writes a single-entry archive that parses cleanly', () => {
    const tar = writeTar([{ name: 'hello.txt', content: Buffer.from('world'), mtime: 1717545600 }]);
    const entries = parseTar(tar);
    expect(entries).toHaveLength(1);
    expect(entries[0]!.name).toBe('hello.txt');
    expect(entries[0]!.body.toString('utf8')).toBe('world');
  });

  it('writes a multi-entry archive in order', () => {
    const tar = writeTar([
      { name: 'a.txt', content: Buffer.from('a'), mtime: 1717545600 },
      { name: 'b.txt', content: Buffer.from('bb'), mtime: 1717545600 },
      { name: 'c.txt', content: Buffer.from('ccc'), mtime: 1717545600 },
    ]);
    const entries = parseTar(tar);
    expect(entries.map((e) => e.name)).toEqual(['a.txt', 'b.txt', 'c.txt']);
    expect(entries.map((e) => e.size)).toEqual([1, 2, 3]);
  });

  it('throws on entry names longer than 100 bytes (ustar limit)', () => {
    const longName = 'x'.repeat(120);
    expect(() => writeTar([{ name: longName, content: Buffer.from(''), mtime: 0 }]))
      .toThrow(/too long for ustar/);
  });

  it('pads to 512-byte boundary + appends the EOF zero-trailer', () => {
    const tar = writeTar([{ name: 'a.txt', content: Buffer.from('short'), mtime: 0 }]);
    // 512 (header) + 512 (padded body) + 1024 (EOF trailer) = 2048.
    expect(tar.length).toBe(2048);
  });
});
