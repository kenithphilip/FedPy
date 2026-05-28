/**
 * Tests for core/inventory-workbook.ts — the FedRAMP Appendix M inventory
 * workbook generator. Pure formatting + a self-contained xlsx writer, so no
 * disk/cloud needed (the writer functions are exercised in-memory).
 */
import { describe, it, expect } from 'vitest';
import {
  APPENDIX_M_COLUMNS,
  assetToRows,
  assetsToRows,
  rowsToCsv,
  rowsToXlsx,
  enrichFromTags,
  reconcileScans,
  annotateWithFindings,
  identifiersMatch,
  dedupeAssets,
  buildInventorySnapshot,
  type CloudAsset,
} from '../../core/inventory-workbook.ts';

const baseAsset: CloudAsset = {
  provider: 'aws',
  uniqueId: 'arn:aws:ec2:us-east-1:111122223333:instance/i-0abc',
  ips: ['10.0.1.5'],
  virtual: true,
  publicFacing: false,
  dns: 'host.internal',
  osNameVersion: 'Amazon Linux 2023',
  location: 'us-east-1a',
  assetType: 'Compute Instance',
  hardwareMakeModel: 'AWS EC2 t3.large',
  vlanNetworkId: 'vpc-0abc/subnet-0def',
  function: 'App server',
};

describe('APPENDIX_M_COLUMNS', () => {
  it('has exactly the 25 Appendix M data columns in order', () => {
    expect(APPENDIX_M_COLUMNS).toHaveLength(25);
    expect(APPENDIX_M_COLUMNS[0]!.header).toBe('Unique Asset Identifier');
    expect(APPENDIX_M_COLUMNS[24]!.header).toBe('End-of-Life');
    // Appendix M additions vs the old A-13
    const headers = APPENDIX_M_COLUMNS.map((c) => c.header);
    expect(headers).toContain('Diagram Label');
    expect(headers).toContain('End-of-Life');
  });
  it('has unique keys and headers', () => {
    expect(new Set(APPENDIX_M_COLUMNS.map((c) => c.key)).size).toBe(25);
    expect(new Set(APPENDIX_M_COLUMNS.map((c) => c.header)).size).toBe(25);
  });
});

describe('assetToRows', () => {
  it('maps a single-IP asset to one fully-formed row', () => {
    const [row] = assetToRows(baseAsset);
    expect(row!['Unique Asset Identifier']).toBe(baseAsset.uniqueId);
    expect(row!['Serial #/Asset Tag#']).toBe(baseAsset.uniqueId); // U mirrors B for cloud
    expect(row!['IPv4 or IPv6 Address']).toBe('10.0.1.5');
    expect(row!['Virtual']).toBe('Yes');
    expect(row!['Public']).toBe('No');
    expect(row!['OS Name and Version']).toBe('Amazon Linux 2023');
    expect(row!['Asset Type']).toBe('Compute Instance');
    // every column key is present (even if blank)
    for (const c of APPENDIX_M_COLUMNS) expect(row!).toHaveProperty(c.header);
  });

  it('defaults Virtual to Yes and leaves Public blank when unknown', () => {
    const [row] = assetToRows({ provider: 'gcp', uniqueId: 'x' });
    expect(row!['Virtual']).toBe('Yes');
    expect(row!['Public']).toBe('');
  });

  it('fans out one row per IP, aligning MAC by index', () => {
    const rows = assetToRows({ ...baseAsset, ips: ['10.0.1.5', '10.0.1.6'], macs: ['aa:bb', 'cc:dd'] });
    expect(rows).toHaveLength(2);
    expect(rows[0]!['IPv4 or IPv6 Address']).toBe('10.0.1.5');
    expect(rows[0]!['MAC Address']).toBe('aa:bb');
    expect(rows[1]!['IPv4 or IPv6 Address']).toBe('10.0.1.6');
    expect(rows[1]!['MAC Address']).toBe('cc:dd');
  });

  it('emits one row with a blank IP when no IPs are known', () => {
    const rows = assetToRows({ provider: 'aws', uniqueId: 'arn:bucket' });
    expect(rows).toHaveLength(1);
    expect(rows[0]!['IPv4 or IPv6 Address']).toBe('');
  });
});

describe('rowsToCsv', () => {
  it('starts with the exact 25-column header row', () => {
    const csv = rowsToCsv(assetsToRows([baseAsset]));
    const firstLine = csv.split('\r\n')[0]!;
    expect(firstLine).toBe(APPENDIX_M_COLUMNS.map((c) => c.header).join(','));
  });

  it('escapes commas, quotes, and newlines', () => {
    const csv = rowsToCsv(assetToRows({ provider: 'aws', uniqueId: 'a,b', comments: 'has "quote"\nand newline' }));
    expect(csv).toContain('"a,b"');
    expect(csv).toContain('"has ""quote""\nand newline"');
  });

  it('produces header + one data line per row', () => {
    const csv = rowsToCsv(assetsToRows([baseAsset, { provider: 'gcp', uniqueId: 'g' }]));
    const lines = csv.trimEnd().split('\r\n');
    expect(lines).toHaveLength(3); // header + 2
  });
});

describe('rowsToXlsx', () => {
  it('produces a structurally valid store-only zip (.xlsx)', () => {
    const buf = rowsToXlsx(assetsToRows([baseAsset]));
    // ZIP local-file-header magic "PK\x03\x04"
    expect(buf.subarray(0, 4)).toEqual(Buffer.from([0x50, 0x4b, 0x03, 0x04]));
    // End-of-central-directory signature present
    expect(buf.includes(Buffer.from([0x50, 0x4b, 0x05, 0x06]))).toBe(true);
    // required OOXML parts present (store method ⇒ names + content are verbatim)
    const s = buf.toString('latin1');
    expect(s).toContain('[Content_Types].xml');
    expect(s).toContain('xl/worksheets/sheet1.xml');
    expect(s).toContain('<sheet name="Inventory"');
    // header + data values land in the sheet as inline strings
    expect(s).toContain('Unique Asset Identifier');
    expect(s).toContain('Amazon Linux 2023');
    expect(s).toContain('t="inlineStr"');
  });

  it('xml-escapes special characters in cell values', () => {
    const buf = rowsToXlsx(assetToRows({ provider: 'aws', uniqueId: 'a&b<c>"d"' }));
    const s = buf.toString('latin1');
    expect(s).toContain('a&amp;b&lt;c&gt;&quot;d&quot;');
  });
});

describe('enrichFromTags', () => {
  it('fills owner / function / baseline from tags when unset', () => {
    const a: CloudAsset = { provider: 'aws', uniqueId: 'x', tags: { Owner: 'alice', Function: 'web', STIG: 'RHEL9 STIG', AppOwner: 'bob' } };
    enrichFromTags(a);
    expect(a.systemOwner).toBe('alice');
    expect(a.applicationOwner).toBe('bob');
    expect(a.function).toBe('web');
    expect(a.baselineConfig).toBe('RHEL9 STIG');
  });
  it('does not overwrite values the collector already set', () => {
    const a: CloudAsset = { provider: 'aws', uniqueId: 'x', function: 'set-by-collector', tags: { Function: 'tag-value' } };
    enrichFromTags(a);
    expect(a.function).toBe('set-by-collector');
  });
  it('is case-insensitive on tag keys', () => {
    const a: CloudAsset = { provider: 'gcp', uniqueId: 'x', tags: { owner: 'carol' } };
    enrichFromTags(a);
    expect(a.systemOwner).toBe('carol');
  });
});

describe('identifiersMatch', () => {
  it('matches identical ARNs and shared resource-id tokens', () => {
    expect(identifiersMatch('arn:aws:ec2:us-east-1:111:instance/i-0abcdef123', 'arn:aws:ec2:us-east-1:111:instance/i-0abcdef123')).toBe(true);
    expect(identifiersMatch('arn:aws:ec2:us-east-1:111:instance/i-0abcdef123', 'i-0abcdef123')).toBe(true);
  });
  it('does not match on trivial / short tokens', () => {
    expect(identifiersMatch('arn:aws:s3:::a', 'arn:aws:ec2:::b')).toBe(false);
  });
});

describe('reconcileScans', () => {
  it('marks assets in the scanned set as in-scan + authenticated', () => {
    const assets: CloudAsset[] = [
      { provider: 'aws', uniqueId: 'arn:aws:ec2:us-east-1:111:instance/i-0abcdef123' },
      { provider: 'aws', uniqueId: 'arn:aws:s3:::unscanned-bucket' },
    ];
    const matched = reconcileScans(assets, ['i-0abcdef123']);
    expect(matched).toBe(1);
    expect(assets[0]!.inLatestScan).toBe(true);
    expect(assets[0]!.authenticatedScan).toBe(true);
    expect(assets[1]!.inLatestScan).toBeUndefined();
  });
});

describe('annotateWithFindings', () => {
  it('appends failing + passing KSI findings to Comments for matching assets', () => {
    const assets: CloudAsset[] = [{ provider: 'aws', uniqueId: 'arn:aws:rds:us-east-1:111:db:prod-db-001' }];
    const n = annotateWithFindings(assets, [
      { identifier: 'arn:aws:rds:us-east-1:111:db:prod-db-001', ksiId: 'KSI-SVC-VRI', rule: 'scan_on', passed: false },
      { identifier: 'prod-db-001', ksiId: 'KSI-SVC-RUD', rule: 'retention', passed: true },
      { identifier: 'arn:aws:ec2:::other', ksiId: 'KSI-IAM-MFA', rule: 'mfa', passed: false },
    ]);
    expect(n).toBe(1);
    expect(assets[0]!.comments).toContain('failing KSI findings: KSI-SVC-VRI/scan_on');
    expect(assets[0]!.comments).toContain('passing: KSI-SVC-RUD');
    expect(assets[0]!.comments).not.toContain('KSI-IAM-MFA'); // different resource
  });
  it('leaves non-matching assets untouched', () => {
    const assets: CloudAsset[] = [{ provider: 'gcp', uniqueId: '//compute.googleapis.com/x', comments: 'orig' }];
    annotateWithFindings(assets, [{ identifier: 'unrelated-resource-id', ksiId: 'K', rule: 'r', passed: false }]);
    expect(assets[0]!.comments).toBe('orig');
  });
});

describe('dedupeAssets', () => {
  it('merges two records of the same resource, later non-null wins, arrays union', () => {
    const merged = dedupeAssets([
      { provider: 'aws', uniqueId: 'arn:x', resourceType: 'AWS::EC2::Instance', ips: ['10.0.0.1'], osNameVersion: null },
      { provider: 'aws', uniqueId: 'arn:x', ips: ['10.0.0.2'], osNameVersion: 'AL2023', kmsKeyId: 'key-1' },
    ]);
    expect(merged).toHaveLength(1);
    expect(merged[0]!.ips!.sort()).toEqual(['10.0.0.1', '10.0.0.2']);
    expect(merged[0]!.osNameVersion).toBe('AL2023');
    expect(merged[0]!.kmsKeyId).toBe('key-1');
    expect(merged[0]!.resourceType).toBe('AWS::EC2::Instance');
  });
  it('keeps distinct resources separate', () => {
    expect(dedupeAssets([{ provider: 'aws', uniqueId: 'a' }, { provider: 'gcp', uniqueId: 'b' }])).toHaveLength(2);
  });
  it('merges tag records', () => {
    const merged = dedupeAssets([
      { provider: 'aws', uniqueId: 'a', tags: { Owner: 'alice' } },
      { provider: 'aws', uniqueId: 'a', tags: { Env: 'prod' } },
    ]);
    expect(merged[0]!.tags).toEqual({ Owner: 'alice', Env: 'prod' });
  });
});

describe('buildInventorySnapshot', () => {
  it('summarizes counts by provider and type', () => {
    const snap = buildInventorySnapshot([
      { provider: 'aws', uniqueId: 'a', resourceType: 'AWS::EC2::Instance' },
      { provider: 'aws', uniqueId: 'b', resourceType: 'AWS::S3::Bucket' },
      { provider: 'gcp', uniqueId: 'c', resourceType: 'storage.googleapis.com/Bucket' },
    ], [{ from: 'a', to: 'b', type: 'x' }]);
    expect(snap.asset_count).toBe(3);
    expect(snap.edge_count).toBe(1);
    expect(snap.by_provider).toEqual({ aws: 2, gcp: 1 });
    expect(snap.by_type['AWS::EC2::Instance']).toBe(1);
    expect(typeof snap.generated_at).toBe('string');
  });
});
