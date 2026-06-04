/**
 * Tests for `core/inventory-coverage.ts` + `core/inventory-coverage-report.ts`.
 *
 * The point of this test suite is to *make slice regressions visible*:
 *   - registry must stay aligned with APPENDIX_M_COLUMNS (order + length);
 *   - every entry must declare a source per cloud (no orphan blanks);
 *   - the per-run report computes fill rates honestly from the asset list;
 *   - the only `operator-only` cell is "Comments" (one row of T28).
 */
import { describe, it, expect } from 'vitest';
import { APPENDIX_M_COLUMNS } from '../../core/inventory-workbook.ts';
import type { CloudAsset } from '../../core/inventory-workbook.ts';
import {
  COVERAGE_REGISTRY,
  isCellFilled,
  type CoverageEntry,
} from '../../core/inventory-coverage.ts';
import {
  buildCoverageReport,
  coverageSummary,
} from '../../core/inventory-coverage-report.ts';

describe('coverage registry — invariants', () => {
  it('has exactly one entry per FedRAMP Appendix M column, in order', () => {
    expect(COVERAGE_REGISTRY.length).toBe(APPENDIX_M_COLUMNS.length);
    for (let i = 0; i < COVERAGE_REGISTRY.length; i++) {
      expect(COVERAGE_REGISTRY[i]!.column).toBe(APPENDIX_M_COLUMNS[i]!.header);
    }
  });

  it('every entry declares an explicit source + status for all three clouds', () => {
    for (const e of COVERAGE_REGISTRY) {
      for (const p of ['aws', 'gcp', 'azure'] as const) {
        const s = e.sources[p];
        expect(s, `${e.column}/${p}`).toBeDefined();
        expect(s.description.length, `${e.column}/${p} description`).toBeGreaterThan(0);
        expect(['filled','partial','tag-based','operator-only','not-yet']).toContain(s.status);
      }
    }
  });

  it('exactly one column is operator-only (Comments)', () => {
    const operatorOnly = COVERAGE_REGISTRY.filter((e) =>
      Object.values(e.sources).every((s) => s.status === 'operator-only'),
    );
    expect(operatorOnly.map((e) => e.column)).toEqual(['Comments']);
  });

  it('Comments is the only entry with a populated blankReason', () => {
    const withReason = COVERAGE_REGISTRY.filter((e) => e.blankReason !== null);
    expect(withReason.map((e) => e.column)).toEqual(['Comments']);
  });

  it('every "not-yet" source declares the slice that will ship it', () => {
    for (const e of COVERAGE_REGISTRY) {
      for (const p of ['aws','gcp','azure'] as const) {
        const s = e.sources[p];
        if (s.status === 'not-yet') {
          expect(s.shippedIn, `${e.column}/${p}`).toMatch(/^INV-S\d+/);
        }
      }
    }
  });
});

describe('isCellFilled', () => {
  function asset(over: Partial<CloudAsset> = {}): CloudAsset {
    return { provider: 'aws', uniqueId: 'arn:x', ...over } as CloudAsset;
  }
  const colByName = (name: string): CoverageEntry =>
    COVERAGE_REGISTRY.find((e) => e.column === name)!;

  it('treats undefined / null / "" / [] as blank', () => {
    expect(isCellFilled(asset({ dns: undefined }), colByName('DNS Name or URL'))).toBe(false);
    expect(isCellFilled(asset({ dns: null as unknown as undefined }), colByName('DNS Name or URL'))).toBe(false);
    expect(isCellFilled(asset({ dns: '' }), colByName('DNS Name or URL'))).toBe(false);
    expect(isCellFilled(asset({ ips: [] }), colByName('IPv4 or IPv6 Address'))).toBe(false);
  });

  it('treats non-empty strings / arrays as filled', () => {
    expect(isCellFilled(asset({ dns: 'example.com' }), colByName('DNS Name or URL'))).toBe(true);
    expect(isCellFilled(asset({ ips: ['10.0.0.1'] }), colByName('IPv4 or IPv6 Address'))).toBe(true);
    expect(isCellFilled(asset({ virtual: true }), colByName('Virtual'))).toBe(true);
  });

  it('NetBIOS Name + Diagram Label are real CloudAsset fields now (post INV-S3/S4/S6)', () => {
    // Both started as `(synthetic)` in the registry; the OS-level + workbook
    // slices materialized them as real CloudAsset fields. Blank asset → blank
    // cell, populated asset → filled cell.
    expect(isCellFilled(asset(), colByName('Diagram Label'))).toBe(false);
    expect(isCellFilled(asset(), colByName('NetBIOS Name'))).toBe(false);
    expect(isCellFilled(asset({ diagramLabel: 'web-1@us-east-1' }), colByName('Diagram Label'))).toBe(true);
    expect(isCellFilled(asset({ netbiosName: 'WIN-PROD-01' }), colByName('NetBIOS Name'))).toBe(true);
  });
});

describe('buildCoverageReport', () => {
  it('returns zero totals for an empty asset list', () => {
    const r = buildCoverageReport([]);
    expect(r.totals.aws.assets).toBe(0);
    expect(r.totals.gcp.assets).toBe(0);
    expect(r.totals.azure.assets).toBe(0);
    expect(r.columns).toHaveLength(COVERAGE_REGISTRY.length);
    for (const c of r.columns) {
      expect(c.fillRate.aws).toBe(0);
      expect(c.fillRate.gcp).toBe(0);
      expect(c.fillRate.azure).toBe(0);
    }
  });

  it('computes per-cloud fill rate per column from real assets', () => {
    const assets: CloudAsset[] = [
      // AWS: full row
      { provider: 'aws', uniqueId: 'arn:1', ips: ['10.0.0.1'], dns: 'host-1', virtual: true, location: 'us-east-1', assetType: 'Instance' },
      // AWS: missing DNS
      { provider: 'aws', uniqueId: 'arn:2', ips: ['10.0.0.2'], virtual: true, location: 'us-east-1', assetType: 'Instance' },
      // GCP: full row
      { provider: 'gcp', uniqueId: 'gcp-1', ips: ['10.0.1.1'], dns: 'srv-1', virtual: true, location: 'us-central1', assetType: 'Instance' },
      // Azure: NIC IPs missing (Azure depth gap pre-S2)
      { provider: 'azure', uniqueId: '/az/1', virtual: true, location: 'eastus', assetType: 'virtual-machine' },
    ];
    const r = buildCoverageReport(assets);
    const dns = r.columns.find((c) => c.column === 'DNS Name or URL')!;
    expect(dns.filled.aws).toBe(1);    // 1 of 2 AWS has dns
    expect(dns.fillRate.aws).toBeCloseTo(0.5, 5);
    expect(dns.filled.gcp).toBe(1);
    expect(dns.fillRate.gcp).toBeCloseTo(1.0, 5);
    expect(dns.filled.azure).toBe(0);
    expect(dns.fillRate.azure).toBeCloseTo(0.0, 5);

    const ips = r.columns.find((c) => c.column === 'IPv4 or IPv6 Address')!;
    expect(ips.filled.azure).toBe(0); // pre-S2
    expect(ips.filled.aws).toBe(2);

    expect(r.totals.aws.assets).toBe(2);
    expect(r.totals.gcp.assets).toBe(1);
    expect(r.totals.azure.assets).toBe(1);
  });

  it('total fill rate reflects the registry "operator-only" floor (Comments stays 0)', () => {
    const assets: CloudAsset[] = [
      { provider: 'aws', uniqueId: 'arn:full', ips: ['10.0.0.1'], virtual: true, location: 'us-east-1', assetType: 'Instance',
        dns: 'h', baselineConfig: 'stig', osNameVersion: 'al2023', hardwareMakeModel: 't3.large',
        softwareDatabaseVendor: 'PostgreSQL', softwareDatabaseNameVersion: 'PostgreSQL 16.1', patchLevel: '100%',
        vlanNetworkId: 'vpc-1/subnet-1', systemOwner: 'sre', applicationOwner: 'app', function: 'web',
        endOfLife: '2030-01-01', macs: ['00:11:22:33:44:55'], publicFacing: false, authenticatedScan: true, inLatestScan: true,
      },
    ];
    const r = buildCoverageReport(assets);
    const comments = r.columns.find((c) => c.column === 'Comments')!;
    expect(comments.filled.aws).toBe(0);
    expect(comments.blankReason).toMatch(/operator-supplied/);
  });
});

describe('coverageSummary', () => {
  it('returns a human-readable one-liner', () => {
    const assets: CloudAsset[] = [
      { provider: 'aws', uniqueId: 'arn:1', ips: ['1.2.3.4'], virtual: true, location: 'us', assetType: 'EC2' },
      { provider: 'gcp', uniqueId: 'gcp-1', virtual: true, location: 'us', assetType: 'GCE' },
    ];
    const r = buildCoverageReport(assets);
    const s = coverageSummary(r);
    expect(s).toContain('AWS');
    expect(s).toContain('GCP');
    expect(s).not.toContain('AZURE'); // no azure assets in this run
  });

  it('handles empty inventory', () => {
    const r = buildCoverageReport([]);
    expect(coverageSummary(r)).toBe('no assets');
  });
});
