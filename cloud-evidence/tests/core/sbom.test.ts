/**
 * Tests for core/sbom.ts — parsing CycloneDX + SPDX, vuln correlation, signatures.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { buildSbomReport, listSbomFiles, sbomFingerprint } from '../../core/sbom.ts';

let tmp: string;
let sbomDir: string;

beforeEach(() => {
  tmp = mkdtempSync(resolve(tmpdir(), 'cev-sbom-'));
  sbomDir = resolve(tmp, 'sboms');
  // create the dir
  writeFileSync(resolve(tmp, '_init'), '');
  rmSync(resolve(tmp, '_init'));
  // mkdir
  require('node:fs').mkdirSync(sbomDir, { recursive: true });
  delete process.env.SBOM_NVD_INDEX_PATH;
  delete process.env.COSIGN_PUBLIC_KEY;
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

const cycloneDxSample = {
  bomFormat: 'CycloneDX',
  specVersion: '1.4',
  metadata: { component: { name: 'my-app:1.0.0', type: 'application' } },
  components: [
    { type: 'library', name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21',
      licenses: [{ license: { id: 'MIT' } }] },
    { type: 'library', name: 'express', version: '4.18.2', purl: 'pkg:npm/express@4.18.2' },
  ],
};

const spdxSample = {
  spdxVersion: 'SPDX-2.3',
  name: 'my-other-app:2.0.0',
  packages: [
    {
      name: 'requests',
      versionInfo: '2.31.0',
      primaryPackagePurpose: 'LIBRARY',
      externalRefs: [
        { referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: 'pkg:pypi/requests@2.31.0' },
      ],
      licenseConcluded: 'Apache-2.0',
    },
  ],
};

describe('buildSbomReport', () => {
  it('parses CycloneDX into the normalized component shape', () => {
    writeFileSync(resolve(sbomDir, 'my-app.cdx.json'), JSON.stringify(cycloneDxSample));
    const r = buildSbomReport({ sbomDir });
    expect(r.sboms).toHaveLength(1);
    expect(r.sboms[0].format).toBe('cyclonedx');
    expect(r.sboms[0].image).toBe('my-app:1.0.0');
    expect(r.sboms[0].components.length).toBe(2);
    const lodash = r.sboms[0].components.find((c) => c.name === 'lodash');
    expect(lodash?.version).toBe('4.17.21');
    expect(lodash?.licenses).toContain('MIT');
  });

  it('parses SPDX into the normalized component shape', () => {
    writeFileSync(resolve(sbomDir, 'my-app.spdx.json'), JSON.stringify(spdxSample));
    const r = buildSbomReport({ sbomDir });
    expect(r.sboms[0].format).toBe('spdx');
    expect(r.sboms[0].image).toBe('my-other-app:2.0.0');
    expect(r.sboms[0].components[0].purl).toBe('pkg:pypi/requests@2.31.0');
  });

  it('produces summary counts', () => {
    writeFileSync(resolve(sbomDir, 'a.cdx.json'), JSON.stringify(cycloneDxSample));
    writeFileSync(resolve(sbomDir, 'b.spdx.json'), JSON.stringify(spdxSample));
    const r = buildSbomReport({ sbomDir });
    expect(r.summary.sbom_count).toBe(2);
    expect(r.summary.total_components).toBe(3);
    expect(r.summary.unique_components).toBe(3);
    expect(r.summary.unsigned_sboms).toBe(2);
    expect(r.summary.signed_sboms).toBe(0);
  });

  it('correlates vulnerabilities when SBOM_NVD_INDEX_PATH is set', () => {
    const nvdPath = resolve(tmp, 'nvd-index.json');
    const nvdIndex = {
      'CVE-2023-12345': {
        severity: 'HIGH',
        affects: ['pkg:npm/lodash@'],
        fix_versions: { 'pkg:npm/lodash': '4.17.22' },
      },
      'CVE-2024-99999': {
        severity: 'CRITICAL',
        affects: ['pkg:pypi/notinstalled@'],
      },
    };
    writeFileSync(nvdPath, JSON.stringify(nvdIndex));
    process.env.SBOM_NVD_INDEX_PATH = nvdPath;

    writeFileSync(resolve(sbomDir, 'app.cdx.json'), JSON.stringify(cycloneDxSample));
    const r = buildSbomReport({ sbomDir });
    expect(r.vulnerabilities.length).toBe(1); // only the lodash CVE matches
    expect(r.vulnerabilities[0].cve_id).toBe('CVE-2023-12345');
    expect(r.vulnerabilities[0].severity).toBe('HIGH');
    expect(r.vulnerabilities[0].affected_components).toContain('lodash@4.17.21');
    expect(r.summary.high_vulns).toBe(1);
    expect(r.summary.critical_vulns).toBe(0);
  });

  it('skips unparseable JSON files with a warning, not a crash', () => {
    writeFileSync(resolve(sbomDir, 'bad.json'), '{not valid');
    writeFileSync(resolve(sbomDir, 'good.cdx.json'), JSON.stringify(cycloneDxSample));
    const r = buildSbomReport({ sbomDir });
    expect(r.summary.sbom_count).toBe(1);
  });

  it('skips files whose format is neither cyclonedx nor spdx', () => {
    writeFileSync(resolve(sbomDir, 'random.json'), JSON.stringify({ foo: 'bar' }));
    const r = buildSbomReport({ sbomDir });
    expect(r.summary.sbom_count).toBe(0);
  });

  it('writes sbom-report.json to disk', () => {
    writeFileSync(resolve(sbomDir, 'app.cdx.json'), JSON.stringify(cycloneDxSample));
    buildSbomReport({ sbomDir });
    const reportPath = resolve(sbomDir, '..', 'sbom-report.json');
    const r = JSON.parse(readFileSync(reportPath, 'utf8'));
    expect(r.sboms.length).toBe(1);
  });
});

describe('sbomFingerprint', () => {
  it('returns a stable hash for the same content', () => {
    const p = resolve(sbomDir, 'a.json');
    writeFileSync(p, JSON.stringify(cycloneDxSample));
    const h1 = sbomFingerprint(p);
    const h2 = sbomFingerprint(p);
    expect(h1).toBe(h2);
    expect(h1).toMatch(/^[a-f0-9]{64}$/);
  });
});

describe('listSbomFiles', () => {
  it('returns an empty array for missing directory', () => {
    expect(listSbomFiles('/nonexistent/path')).toEqual([]);
  });

  it('finds *.json, *.spdx.json, *.cdx.json files', () => {
    writeFileSync(resolve(sbomDir, 'a.json'), '{}');
    writeFileSync(resolve(sbomDir, 'b.cdx.json'), '{}');
    writeFileSync(resolve(sbomDir, 'c.spdx.json'), '{}');
    writeFileSync(resolve(sbomDir, 'd.txt'), 'no');
    const files = listSbomFiles(sbomDir);
    expect(files.length).toBe(3);
  });
});
