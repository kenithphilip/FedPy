/**
 * Tests for core/ssp-docx.ts — the OSCAL SSP → Word (.docx) renderer (SSP-2).
 *
 * The .docx is a store-only ZIP of OOXML parts. We render a small SSP (built by
 * buildOscalSsp) and assert:
 *   1. The output is a valid ZIP (PK magic, walkable local headers).
 *   2. It contains the required OOXML parts.
 *   3. word/document.xml is well-formed-ish and carries the system name, headings,
 *      and control rows from the SSP.
 */
import { describe, it, expect } from 'vitest';
import { renderSspDocx } from '../../core/ssp-docx.ts';
import { buildOscalSsp } from '../../core/oscal-ssp.ts';
import { benchmarkControls } from '../../core/control-benchmark.ts';

/** Minimal store-only (method 0) ZIP reader: name → Buffer, via local headers. */
function unzipStore(buf: Buffer): Record<string, Buffer> {
  const out: Record<string, Buffer> = {};
  let i = 0;
  while (i + 4 <= buf.length && buf.readUInt32LE(i) === 0x04034b50) {
    const method = buf.readUInt16LE(i + 8);
    const size = buf.readUInt32LE(i + 18);
    const nameLen = buf.readUInt16LE(i + 26);
    const extraLen = buf.readUInt16LE(i + 28);
    const name = buf.toString('utf8', i + 30, i + 30 + nameLen);
    const dataStart = i + 30 + nameLen + extraLen;
    if (method !== 0) throw new Error(`entry ${name} is not store-only (method ${method})`);
    out[name] = buf.subarray(dataStart, dataStart + size);
    i = dataStart + size;
  }
  return out;
}

function sampleSsp() {
  const benchmark = benchmarkControls(
    [
      { ksi_id: 'KSI-IAM-MFA', providers: [{ provider: 'aws', findings: [{ rule: 'mfa', passed: true, nist_controls: ['ac-2'] }] }] } as any,
      { ksi_id: 'KSI-SVC-VRI', providers: [{ provider: 'aws', findings: [{ rule: 'scan', passed: false, nist_controls: ['ra-5'] }] }] } as any,
    ],
    ['ac-2', 'ra-5', 'au-6'],
    'rev5',
    'moderate',
  );
  return buildOscalSsp(benchmark, {
    outDir: '/tmp', runId: 'run-x', frmrVersion: '25.05', impactLevel: 'moderate',
    systemName: 'Acme Cloud', systemId: 'acme-1', organizationName: 'Acme Corp', providers: ['aws', 'gcp'],
  }).doc;
}

describe('renderSspDocx', () => {
  it('produces a valid store-only ZIP with the required OOXML parts', () => {
    const { buffer, controlCount } = renderSspDocx(sampleSsp());
    expect(buffer.subarray(0, 4)).toEqual(Buffer.from([0x50, 0x4b, 0x03, 0x04])); // "PK\x03\x04"
    expect(controlCount).toBe(3);

    const parts = unzipStore(buffer);
    for (const name of ['[Content_Types].xml', '_rels/.rels', 'word/document.xml', 'word/styles.xml', 'word/_rels/document.xml.rels']) {
      expect(parts[name], `missing part ${name}`).toBeDefined();
    }
  });

  it('renders the system name, headings, and control rows into document.xml', () => {
    const { buffer } = renderSspDocx(sampleSsp());
    const doc = unzipStore(buffer)['word/document.xml']!.toString('utf8');
    expect(doc.startsWith('<?xml')).toBe(true);
    expect(doc).toContain('<w:document');
    expect(doc).toContain('Acme Cloud');
    expect(doc).toContain('System Security Plan');
    expect(doc).toContain('Control Implementation');
    expect(doc).toContain('System Characteristics');
    // Control ids are upper-cased in the controls table.
    expect(doc).toContain('AC-2');
    expect(doc).toContain('RA-5');
    // Tag balance: equal number of <w:p ...> open vs </w:p> close tags.
    const open = (doc.match(/<w:p[ >]/g) ?? []).length;
    const close = (doc.match(/<\/w:p>/g) ?? []).length;
    expect(open).toBe(close);
  });

  it('escapes XML metacharacters in user-supplied fields', () => {
    const benchmark = benchmarkControls([], ['ac-2'], 'rev5', 'low');
    const doc = buildOscalSsp(benchmark, {
      outDir: '/tmp', runId: 'r', frmrVersion: 'v', impactLevel: 'low',
      systemName: 'A & B <Cloud>', systemId: 'x',
    }).doc;
    const { buffer } = renderSspDocx(doc);
    const xml = unzipStore(buffer)['word/document.xml']!.toString('utf8');
    expect(xml).toContain('A &amp; B &lt;Cloud&gt;');
    expect(xml).not.toContain('A & B <Cloud>');
  });

  it('accepts both wrapped and unwrapped SSP input', () => {
    const wrapped = sampleSsp();
    const unwrapped = wrapped['system-security-plan'];
    const a = renderSspDocx(wrapped).buffer.toString('latin1');
    const b = renderSspDocx(unwrapped).buffer.toString('latin1');
    expect(a).toBe(b);
  });
});
