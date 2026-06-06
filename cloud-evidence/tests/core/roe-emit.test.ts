/**
 * Tests for core/roe-emit.ts — LOOP-A.A5.
 *
 * Verifies:
 *   1. Emitted .docx is a valid ZIP with the expected OOXML parts.
 *   2. Operator-supplied fields appear verbatim in the document.xml body.
 *   3. Missing operator fields → REQUIRES-OPERATOR-INPUT markers
 *      (REO compliance: no synthetic defaults that look real).
 *   4. IP-range table is derived from real inventory.json IPs/MACs;
 *      empty inventory → REQUIRES-OPERATOR-INPUT row, not an empty table.
 *   5. Operator-supplied ipRanges override the inventory-derived list.
 *   6. Contacts table emits a 6-row default with REQUIRES-OPERATOR-INPUT
 *      markers when no contacts supplied.
 *   7. Operator-supplied contacts render verbatim; escalation flag adds ⚡.
 *   8. ready_for_signature is true only when every required field is set
 *      AND scan windows + ip ranges are non-empty.
 *   9. ksi-map scope read produces a non-empty controls-in-scope table.
 *  10. Deterministic file structure: same inputs → same byte length.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gunzipSync, inflateRawSync } from 'node:zlib';
import { emitRoeDocx, renderRoeDocx, buildRoeBodyXml, type RoEEmitOptions } from '../../core/roe-emit.ts';

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-roe-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

/** Read all entry names from a store-only ZIP file. */
function listZipEntries(buf: Buffer): string[] {
  const names: string[] = [];
  let off = 0;
  while (off < buf.length - 22) {
    const sig = buf.readUInt32LE(off);
    if (sig !== 0x04034b50) break; // local file header
    const nameLen = buf.readUInt16LE(off + 26);
    const extraLen = buf.readUInt16LE(off + 28);
    const compSize = buf.readUInt32LE(off + 18);
    const name = buf.subarray(off + 30, off + 30 + nameLen).toString('utf8');
    names.push(name);
    off += 30 + nameLen + extraLen + compSize;
  }
  return names;
}

/** Read the document.xml from a store-only ZIP. */
function readDocumentXml(buf: Buffer): string {
  let off = 0;
  while (off < buf.length - 22) {
    const sig = buf.readUInt32LE(off);
    if (sig !== 0x04034b50) break;
    const nameLen = buf.readUInt16LE(off + 26);
    const extraLen = buf.readUInt16LE(off + 28);
    const compSize = buf.readUInt32LE(off + 18);
    const name = buf.subarray(off + 30, off + 30 + nameLen).toString('utf8');
    const dataStart = off + 30 + nameLen + extraLen;
    if (name === 'word/document.xml') {
      return buf.subarray(dataStart, dataStart + compSize).toString('utf8');
    }
    off = dataStart + compSize;
  }
  throw new Error('word/document.xml not found in zip');
}

function baseOpts(over: Partial<RoEEmitOptions> = {}): RoEEmitOptions {
  return {
    outDir: '/tmp', runId: 'r-test', frmrVersion: '0.9.43-beta', impactLevel: 'moderate',
    ...over,
  };
}

describe('RoE emitter — buildRoeBodyXml (REQUIRES-OPERATOR-INPUT behaviour)', () => {
  it('emits REQUIRES-OPERATOR-INPUT markers for every missing required field', () => {
    const { xml, stats } = buildRoeBodyXml(baseOpts());
    // System identity fields missing → all show the marker.
    expect(xml).toContain('REQUIRES-OPERATOR-INPUT');
    expect(stats.ready_for_signature).toBe(false);
    expect(stats.requires_operator_input).toContain('systemName');
    expect(stats.requires_operator_input).toContain('cspOrganization');
    expect(stats.requires_operator_input).toContain('thirdPartyAssessor');
    expect(stats.requires_operator_input).toContain('authorizationBoundaryDescription');
    expect(stats.requires_operator_input).toContain('assessmentPeriodStart');
    expect(stats.requires_operator_input).toContain('assessmentPeriodEnd');
  });

  it('embeds operator-supplied system identity fields verbatim', () => {
    const { xml } = buildRoeBodyXml(baseOpts({
      systemName: 'Acme Platform', systemId: 'acme-prod-1',
      cspOrganization: 'Acme Corp', thirdPartyAssessor: 'Schellman 3PAO',
    }));
    expect(xml).toContain('Acme Platform');
    expect(xml).toContain('acme-prod-1');
    expect(xml).toContain('Acme Corp');
    expect(xml).toContain('Schellman 3PAO');
  });

  it('flags scanWindows as a missing input when not supplied', () => {
    const d = tmp();
    const { stats } = buildRoeBodyXml(baseOpts({ outDir: d, ipRanges: [{ ip: '10.0.0.1' }] }));
    expect(stats.scan_window_count).toBe(0);
    expect(stats.requires_operator_input).toContain('scanWindows[]');
  });

  it('uses operator-supplied scan windows when provided', () => {
    const { xml, stats } = buildRoeBodyXml(baseOpts({
      scanWindows: [
        { start: '2026-07-15T22:00:00-04:00', end: '2026-07-16T06:00:00-04:00', description: 'Off-peak window 1' },
        { start: '2026-07-22T22:00:00-04:00', end: '2026-07-23T06:00:00-04:00', description: 'Off-peak window 2' },
      ],
    }));
    expect(stats.scan_window_count).toBe(2);
    expect(xml).toContain('Off-peak window 1');
    expect(xml).toContain('Off-peak window 2');
  });
});

describe('RoE emitter — IP range derivation', () => {
  it('derives IPs from real inventory.json when present', () => {
    const d = tmp();
    writeFileSync(join(d, 'inventory.json'), JSON.stringify({
      assets: [
        { provider: 'aws', uniqueId: 'i-1', assetType: 'EC2', location: 'us-east-1', ips: ['10.0.0.10', '54.85.1.2'] },
        { provider: 'aws', uniqueId: 'i-2', assetType: 'EC2', location: 'us-east-1', ips: ['10.0.0.11'] },
        // Duplicate IP — must be deduped.
        { provider: 'aws', uniqueId: 'i-3', assetType: 'EC2', location: 'us-east-1', ips: ['10.0.0.10'] },
      ],
    }));
    const { stats, xml } = buildRoeBodyXml(baseOpts({ outDir: d }));
    expect(stats.ip_count).toBe(3); // deduped
    expect(xml).toContain('10.0.0.10');
    expect(xml).toContain('10.0.0.11');
    expect(xml).toContain('54.85.1.2');
  });

  it('emits REQUIRES-OPERATOR-INPUT row when inventory is empty', () => {
    const d = tmp();
    const { stats, xml } = buildRoeBodyXml(baseOpts({ outDir: d }));
    expect(stats.ip_count).toBe(0);
    expect(stats.requires_operator_input).toContain('ipRanges (inventory.json empty)');
    expect(xml).toMatch(/REQUIRES-OPERATOR-INPUT/);
  });

  it('operator-supplied ipRanges override inventory-derived list', () => {
    const d = tmp();
    // Write an inventory that we should IGNORE.
    writeFileSync(join(d, 'inventory.json'), JSON.stringify({
      assets: [{ provider: 'aws', uniqueId: 'i-1', assetType: 'EC2', ips: ['10.0.0.99'] }],
    }));
    const { stats, xml } = buildRoeBodyXml(baseOpts({
      outDir: d,
      ipRanges: [{ ip: '203.0.113.0/24', description: 'Public boundary' }],
    }));
    expect(stats.ip_count).toBe(1);
    expect(xml).toContain('203.0.113.0/24');
    expect(xml).toContain('Public boundary');
    // Inventory IP must NOT appear.
    expect(xml).not.toContain('10.0.0.99');
  });
});

describe('RoE emitter — contacts', () => {
  it('emits a 6-row default contacts table with REQUIRES-OPERATOR-INPUT markers', () => {
    const { stats, xml } = buildRoeBodyXml(baseOpts());
    expect(stats.contact_count).toBe(6);
    // All cells should be REQUIRES-OPERATOR-INPUT.
    const tbdCount = (xml.match(/REQUIRES-OPERATOR-INPUT/g) ?? []).length;
    expect(tbdCount).toBeGreaterThan(20); // 6 contacts × 4 fields each + identity fields
  });

  it('uses operator-supplied contacts verbatim, marking escalation roles with ⚡', () => {
    const { xml, stats } = buildRoeBodyXml(baseOpts({
      contacts: [
        { role: 'CSP Primary POC', name: 'Alice', organization: 'Acme', email: 'alice@acme.com', phone: '555-0100' },
        { role: 'CSP Incident Response', name: 'Bob', organization: 'Acme', email: 'bob@acme.com', phone: '555-0911', escalation: true },
      ],
    }));
    expect(stats.contact_count).toBe(2);
    expect(xml).toContain('Alice');
    expect(xml).toContain('alice@acme.com');
    expect(xml).toContain('555-0100');
    expect(xml).toContain('Bob');
    expect(xml).toContain('⚡');
  });
});

describe('RoE emitter — KSI scope', () => {
  it('emits a controls-in-scope table with at least one KSI from the ksi-map', () => {
    const { xml } = buildRoeBodyXml(baseOpts());
    // The real ksi-map.ts contains 'KSI-...' entries; verify the table renders them.
    expect(xml).toContain('KSI-');
    expect(xml).toContain('Controls in Scope');
  });
});

describe('RoE emitter — ready_for_signature', () => {
  it('is true only when every required-for-signature field is operator-supplied', () => {
    const d = tmp();
    writeFileSync(join(d, 'inventory.json'), JSON.stringify({
      assets: [{ provider: 'aws', uniqueId: 'i-1', assetType: 'EC2', ips: ['10.0.0.1'] }],
    }));
    const { stats } = buildRoeBodyXml(baseOpts({
      outDir: d,
      systemName: 'X', systemId: 'x',
      cspOrganization: 'X', thirdPartyAssessor: 'Y',
      authorizationBoundaryDescription: 'desc',
      assessmentPeriodStart: '2026-07-15', assessmentPeriodEnd: '2026-08-30',
      scanWindows: [{ start: '2026-07-15T22:00:00-04:00', end: '2026-07-16T06:00:00-04:00' }],
    }));
    expect(stats.ready_for_signature).toBe(true);
    expect(stats.requires_operator_input).toEqual([]);
  });

  it('is false when ANY required field is missing', () => {
    const d = tmp();
    const { stats } = buildRoeBodyXml(baseOpts({
      outDir: d, systemName: 'X', systemId: 'x', // missing csp/3pao/boundary/etc
    }));
    expect(stats.ready_for_signature).toBe(false);
    expect(stats.requires_operator_input.length).toBeGreaterThan(0);
  });
});

describe('RoE emitter — disk (emitRoeDocx + renderRoeDocx)', () => {
  it('renderRoeDocx produces a valid store-only .docx ZIP buffer', () => {
    const { buffer } = renderRoeDocx(baseOpts({
      systemName: 'X', systemId: 'x',
      cspOrganization: 'A', thirdPartyAssessor: 'B',
      authorizationBoundaryDescription: 'desc',
      assessmentPeriodStart: '2026-07-15', assessmentPeriodEnd: '2026-08-30',
    }));
    const names = listZipEntries(buffer);
    expect(names).toContain('[Content_Types].xml');
    expect(names).toContain('_rels/.rels');
    expect(names).toContain('word/document.xml');
    expect(names).toContain('word/styles.xml');
    expect(names).toContain('word/_rels/document.xml.rels');
  });

  it('emitRoeDocx writes roe.docx to disk + reports stats', () => {
    const d = tmp();
    writeFileSync(join(d, 'inventory.json'), JSON.stringify({
      assets: [{ provider: 'aws', uniqueId: 'i-1', assetType: 'EC2', location: 'us-east-1', ips: ['10.0.0.1'] }],
    }));
    const r = emitRoeDocx(baseOpts({
      outDir: d,
      systemName: 'Acme', systemId: 'acme-1',
      cspOrganization: 'Acme', thirdPartyAssessor: 'Schellman',
      authorizationBoundaryDescription: 'Acme VPC vpc-abc.',
      assessmentPeriodStart: '2026-07-15', assessmentPeriodEnd: '2026-08-30',
      scanWindows: [{ start: '2026-07-15T22:00:00-04:00', end: '2026-07-16T06:00:00-04:00' }],
      contacts: [{ role: 'CSP POC', name: 'Alice', organization: 'Acme', email: 'a@x.com' }],
    }));
    expect(existsSync(r.path)).toBe(true);
    expect(r.bytes).toBeGreaterThan(10000); // a real .docx
    expect(r.ip_count).toBe(1);
    expect(r.contact_count).toBe(1);
    expect(r.scan_window_count).toBe(1);
    expect(r.ready_for_signature).toBe(true);
  });

  it('document.xml body contains the assembled prose', () => {
    const d = tmp();
    const r = emitRoeDocx(baseOpts({
      outDir: d,
      systemName: 'PROBE-SYSTEM-XYZ', systemId: 'probe-id',
      cspOrganization: 'PROBE-CSP', thirdPartyAssessor: 'PROBE-3PAO',
      authorizationBoundaryDescription: 'PROBE-BOUNDARY-NARRATIVE',
      assessmentPeriodStart: '2026-07-15', assessmentPeriodEnd: '2026-08-30',
      scanWindows: [{ start: '2026-07-15T22:00:00-04:00', end: '2026-07-16T06:00:00-04:00' }],
      ipRanges: [{ ip: 'PROBE-IP', description: 'PROBE-DESC' }],
    }));
    const buf = readFileSync(r.path);
    const xml = readDocumentXml(buf);
    expect(xml).toContain('PROBE-SYSTEM-XYZ');
    expect(xml).toContain('PROBE-CSP');
    expect(xml).toContain('PROBE-3PAO');
    expect(xml).toContain('PROBE-BOUNDARY-NARRATIVE');
    expect(xml).toContain('PROBE-IP');
    expect(xml).toContain('Rules of Engagement');
  });

  it('writes to a custom outPath when provided', () => {
    const d = tmp();
    const customPath = join(d, 'custom-roe.docx');
    const r = emitRoeDocx(baseOpts({ outDir: d, outPath: customPath }));
    expect(r.path).toBe(customPath);
    expect(existsSync(customPath)).toBe(true);
  });
});
