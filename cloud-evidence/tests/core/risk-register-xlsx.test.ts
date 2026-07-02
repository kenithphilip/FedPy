/**
 * LOOP-B.B5 — Risk Register XLSX renderer tests.
 *
 * The workbook is a dependency-free store-only OOXML zip; this package ships no
 * SheetJS, so the spec's "SheetJS round-trip" is realised as "valid-OOXML
 * round-trip via the repo's zip reader" (LOOP-B-RISKS B.B5-11). We parse the
 * store-only local-file headers directly (method 0 = store, same approach as
 * inventory-workbook.test.ts) and assert structure + conditional formatting.
 */
import { describe, it, expect } from 'vitest';
import { renderRiskRegisterXlsx, RISK_REGISTER_COLUMNS, entryToRow } from '../../core/risk-register-xlsx.ts';
import type { RiskRegisterEntry } from '../../core/risk-register.ts';

function entry(over: Partial<RiskRegisterEntry> = {}): RiskRegisterEntry {
  return {
    uuid: 'r-1', source: 'finding', title: 'MFA not enforced', description: 'x'.repeat(300),
    category: 'ksi-finding', likelihood: 'very-high', impact: 'very-high', inherent_risk: 'very-high',
    residual_risk: 'very-high', treatment: 'mitigate', owner: 'ISO', review_date: '2026-12-31T00:00:00.000Z',
    status: 'open', nist_800_30_version: 'Rev 1',
    references: { risk_uuid: 'r-1', poam_item_uuid: 'pi-1', nist_control_ids: ['ra-5', 'ac-2'], cvss_base: 9.8, epss_score: 0.8, epss_percentile: 0.96 },
    ...over,
  };
}

/** Extract every part (name → utf8 text) from a store-only zip buffer. */
function readZipParts(buf: Buffer): Record<string, string> {
  const parts: Record<string, string> = {};
  let i = 0;
  while (i + 4 <= buf.length) {
    const sig = buf.readUInt32LE(i);
    if (sig !== 0x04034b50) break;
    const compSize = buf.readUInt32LE(i + 18);
    const nameLen = buf.readUInt16LE(i + 26);
    const extraLen = buf.readUInt16LE(i + 28);
    const name = buf.toString('utf8', i + 30, i + 30 + nameLen);
    const dataStart = i + 30 + nameLen + extraLen;
    parts[name] = buf.toString('utf8', dataStart, dataStart + compSize);
    i = dataStart + compSize;
  }
  return parts;
}

describe('renderRiskRegisterXlsx', () => {
  it('emits risk-register.xlsx with 20 columns and one row per entry plus header', () => {
    expect(RISK_REGISTER_COLUMNS).toHaveLength(20);
    const buf = renderRiskRegisterXlsx([entry({ uuid: 'a' }), entry({ uuid: 'b' })]);
    const parts = readZipParts(buf);
    const sheet = parts['xl/worksheets/sheet1.xml'];
    expect(sheet).toBeTruthy();
    // Header row + 2 data rows = 3 <row> elements.
    expect((sheet.match(/<row /g) ?? [])).toHaveLength(3);
    // Header cell A1 carries the first column name.
    expect(sheet).toContain('<t xml:space="preserve">Risk ID</t>');
    // Row 2 col A is the first entry uuid.
    expect(sheet).toContain('<c r="A2" t="inlineStr"><is><t xml:space="preserve">a</t></is></c>');
  });

  it('round-trips through the repo zip reader (valid OOXML parts present)', () => {
    const parts = readZipParts(renderRiskRegisterXlsx([entry()]));
    expect(Object.keys(parts)).toEqual(expect.arrayContaining([
      '[Content_Types].xml', '_rels/.rels', 'xl/workbook.xml',
      'xl/_rels/workbook.xml.rels', 'xl/styles.xml', 'xl/worksheets/sheet1.xml',
    ]));
    // Frozen header pane present (Q7).
    expect(parts['xl/worksheets/sheet1.xml']).toContain('<pane ySplit="1" topLeftCell="A2"');
    // Sheet named "Risk Register".
    expect(parts['xl/workbook.xml']).toContain('name="Risk Register"');
  });

  it('conditional formatting flags high/very-high inherent rows', () => {
    const parts = readZipParts(renderRiskRegisterXlsx([
      entry({ uuid: 'hi', inherent_risk: 'very-high', residual_risk: 'very-high' }),
      entry({ uuid: 'lo', inherent_risk: 'low', residual_risk: 'low' }),
    ]));
    const sheet = parts['xl/worksheets/sheet1.xml'];
    // Row 2 (very-high inherent) → column G carries the red-fill style (s="1").
    expect(sheet).toMatch(/<c r="G2" s="1"/);
    // Row 2 residual very-high → column H carries the bold-red style (s="2").
    expect(sheet).toMatch(/<c r="H2" s="2"/);
    // Row 3 (low inherent) → column G has no conditional style.
    expect(sheet).not.toMatch(/<c r="G3" s="1"/);
    // styles.xml declares the red fill.
    expect(parts['xl/styles.xml']).toContain('FFFFC7CE');
  });

  it('Description column wraps long text (wrap style + full content preserved)', () => {
    const long = 'y'.repeat(500);
    const parts = readZipParts(renderRiskRegisterXlsx([entry({ description: long })]));
    const sheet = parts['xl/worksheets/sheet1.xml'];
    // Column T (20th) is the Description; carries the wrap style (s="3").
    expect(sheet).toMatch(/<c r="T2" s="3"/);
    expect(sheet).toContain(long);
    // styles.xml declares wrapText on the wrap cellXf.
    expect(parts['xl/styles.xml']).toContain('wrapText="1"');
    // entryToRow puts the description last (20 fields).
    expect(entryToRow(entry())).toHaveLength(20);
    expect(entryToRow(entry({ description: long }))[19]).toBe(long);
  });
});
