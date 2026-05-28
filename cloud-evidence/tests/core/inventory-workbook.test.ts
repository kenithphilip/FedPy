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
