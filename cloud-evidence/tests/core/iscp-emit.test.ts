/**
 * Tests for core/iscp-emit.ts — LOOP-C.C2 Information System Contingency Plan
 * (CP-2 / CP-9 / CP-10).
 *
 * Verifies (13 tests per C.C2.md §8):
 *   1. Emits 6 numbered sections + 6 appendices in order.
 *   2. Auto-fills §4.2 Recovery-evidence table from real RPL-ABO/TRC/RRO/ARP files.
 *   3. Emits REQUIRES-OPERATOR-INPUT when no RPL evidence files exist.
 *   4. Renders RTO/RPO opts verbatim into §4.1.
 *   5. Renders teamRoster into Appendix A.
 *   6. Auto-pulls vendor contacts from the subprocessor inventory when present.
 *   7. Handles alternateSite.type="cloud" with cross-region detail.
 *   8. Cross-references iscp-test-aar.docx in Appendix F.
 *   9. Rejects an unknown impactLevel (must be low|moderate|high).
 *  10. ready_for_signature requires every required-for-signature field.
 *  11. Produces deterministic (byte-identical) output for identical inputs.
 *  12. Quotes NIST SP 800-34 §3.1 verbatim in §1.3.
 *  13. Logs a structured emission event.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, copyFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  emitIscpDocx, renderIscpDocx, buildIscpBodyXml, readRplEvidence,
  readSubprocessorContacts, IscpImpactLevelError,
  type IscpEmitOptions,
} from '../../core/iscp-emit.ts';
import { log } from '../../core/log.ts';

const FIXTURE_DIR = resolve(import.meta.dirname ?? '', 'fixtures/iscp');
const RPL_IDS = ['KSI-RPL-ABO', 'KSI-RPL-TRC', 'KSI-RPL-RRO', 'KSI-RPL-ARP'];

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-iscp-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  vi.restoreAllMocks();
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

/** Copy the 4 RPL evidence fixtures into <dir> as KSI-RPL-*.json. */
function loadRplEvidence(dir: string): void {
  for (const id of RPL_IDS) copyFileSync(join(FIXTURE_DIR, `${id}.json`), join(dir, `${id}.json`));
}
function loadSampleInventory(dir: string): void {
  copyFileSync(join(FIXTURE_DIR, 'inventory.sample.json'), join(dir, 'inventory.json'));
}
function loadSubprocessors(dir: string): void {
  copyFileSync(join(FIXTURE_DIR, 'subprocessors.sample.json'), join(dir, 'subprocessor-inventory.json'));
}

function baseOpts(over: Partial<IscpEmitOptions> = {}): IscpEmitOptions {
  return { outDir: '/nonexistent-iscp-dir', runId: 'r-iscp-test', frmrVersion: '0.9.43-beta', impactLevel: 'moderate', ...over };
}

/** Every required-for-signature operator field supplied. */
function fullOpts(dir: string, over: Partial<IscpEmitOptions> = {}): IscpEmitOptions {
  return baseOpts({
    outDir: dir,
    systemName: 'Acme Platform', systemId: 'acme-prod-1', cspOrganization: 'Acme Corp',
    rto: { hours: 4, rationale: 'Mission-critical SLA of 4h.' },
    rpo: { hours: 1, rationale: 'Hourly snapshot cadence.' },
    recoveryPriority: 'mission-critical',
    alternateSite: { type: 'cloud', location: 'us-west-2', activationProcedure: 'Promote the DR region via runbook DR-01.' },
    activationAuthority: 'The Contingency Plan Coordinator declares a contingency.',
    activationCriteria: ['Primary region outage exceeding RTO', 'Confirmed data-integrity loss'],
    cpCoordinator: { name: 'Jane Doe', org: 'Acme', email: 'jane@acme.example', phone: '+1-555-0100' },
    teamRoster: [{ role: 'Contingency Plan Coordinator', name: 'Jane Doe', org: 'Acme', email: 'jane@acme.example', phone: '+1-555-0100' }],
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

describe('ISCP emitter — package structure + section order', () => {
  it('produces a valid .docx with all 6 OOXML parts', () => {
    const { buffer } = renderIscpDocx(fullOpts(tmp()));
    const names = listZipEntries(buffer);
    for (const p of ['[Content_Types].xml', '_rels/.rels', 'word/document.xml', 'word/styles.xml', 'word/_rels/document.xml.rels', 'docProps/core.xml']) {
      expect(names).toContain(p);
    }
  });

  it('emits 6 numbered sections + 6 appendices (A–F) in order', () => {
    const { xml } = buildIscpBodyXml(fullOpts(tmp()));
    const titles = heading1Titles(xml);
    // 6 numbered sections come first, in 1..6 order.
    for (let i = 0; i < 6; i++) expect(titles[i]!.startsWith(`${i + 1}.`)).toBe(true);
    // then 6 appendices A..F.
    const appendices = titles.filter((t) => t.startsWith('Appendix'));
    expect(appendices.length).toBe(6);
    ['A', 'B', 'C', 'D', 'E', 'F'].forEach((letter, i) =>
      expect(appendices[i]!.startsWith(`Appendix ${letter}`)).toBe(true));
    expect(titles[0]).toContain('Introduction');
    expect(titles[3]).toContain('Recovery Phase');
  });
});

describe('ISCP emitter — §4.2 Recovery evidence (RPL family)', () => {
  it('auto-fills §4.2 from real KSI-RPL-ABO/TRC/RRO/ARP evidence files', () => {
    const d = tmp();
    loadRplEvidence(d);
    const rpl = readRplEvidence(d);
    expect(Object.keys(rpl).sort()).toEqual(['abo', 'arp', 'rro', 'trc']);
    const { xml, stats } = buildIscpBodyXml(baseOpts({ outDir: d }));
    expect(stats.rpl_evidence_count).toBe(4);
    for (const id of RPL_IDS) expect(xml).toContain(id);
    // Each row cites the evidence file with its sha256.
    expect(xml).toContain('KSI-RPL-ABO.json (sha256 ');
    // ARP fixture is a FAIL — the table renders both PASS and FAIL.
    expect(xml).toContain('PASS');
    expect(xml).toContain('FAIL');
  });

  it('emits REQUIRES-OPERATOR-INPUT when no RPL evidence files exist', () => {
    const d = tmp();
    const { xml, stats } = buildIscpBodyXml(baseOpts({ outDir: d }));
    expect(stats.rpl_evidence_count).toBe(0);
    expect(xml).toContain('No RPL-family evidence found');
    expect(xml).toContain('REQUIRES-OPERATOR-INPUT');
  });

  it('renders RTO/RPO opts verbatim into §4.1', () => {
    const { xml } = buildIscpBodyXml(baseOpts({
      rto: { hours: 4, rationale: 'Mission-critical SLA of 4h.' },
      rpo: { hours: 1, rationale: 'Hourly snapshot cadence.' },
    }));
    expect(xml).toContain('4 hours — Mission-critical SLA of 4h.');
    expect(xml).toContain('1 hours — Hourly snapshot cadence.');
  });
});

describe('ISCP emitter — rosters + vendor contacts', () => {
  it('renders teamRoster into Appendix A', () => {
    const { xml } = buildIscpBodyXml(baseOpts({
      teamRoster: [{ role: 'Recovery Lead', name: 'Alex Rivera', org: 'Acme', email: 'alex@acme.example', phone: '+1-555-0111' }],
    }));
    expect(xml).toContain('Appendix A');
    expect(xml).toContain('Alex Rivera');
    expect(xml).toContain('Recovery Lead');
  });

  it('auto-pulls vendor contacts from the subprocessor inventory when present', () => {
    const d = tmp();
    loadSubprocessors(d);
    const contacts = readSubprocessorContacts(d);
    expect(contacts.length).toBe(2);
    const { xml, stats } = buildIscpBodyXml(baseOpts({ outDir: d }));
    expect(stats.vendor_contact_count).toBe(2);
    expect(xml).toContain('Amazon Web Services');
    expect(xml).toContain('Datadog');
    expect(xml).toContain('24 hours');
  });
});

describe('ISCP emitter — alternate site + cross-references', () => {
  it('handles alternateSite.type="cloud" with cross-region detail', () => {
    const { xml } = buildIscpBodyXml(baseOpts({
      alternateSite: { type: 'cloud', location: 'us-west-2', activationProcedure: 'Promote DR region.' },
    }));
    expect(xml).toContain('Cloud alternate processing');
    expect(xml).toContain('us-west-2');
  });

  it('cross-references iscp-test-aar.docx in Appendix F', () => {
    const { xml } = buildIscpBodyXml(baseOpts());
    expect(xml).toContain('Appendix F');
    expect(xml).toContain('iscp-test-aar.docx');
  });
});

describe('ISCP emitter — validation + readiness', () => {
  it('rejects an unknown impactLevel (must be low|moderate|high)', () => {
    expect(() => buildIscpBodyXml(baseOpts({ impactLevel: 'extreme' as any }))).toThrow(IscpImpactLevelError);
  });

  it('ready_for_signature requires every required-for-signature field', () => {
    const d = tmp();
    const full = buildIscpBodyXml(fullOpts(d));
    expect(full.stats.ready_for_signature).toBe(true);
    expect(full.stats.requires_operator_input).toEqual([]);
    const partial = fullOpts(d);
    delete (partial as any).rto;
    const p = buildIscpBodyXml(partial);
    expect(p.stats.ready_for_signature).toBe(false);
    expect(p.stats.requires_operator_input).toContain('rto');
  });
});

describe('ISCP emitter — determinism + sources', () => {
  it('produces byte-identical output for identical inputs', () => {
    const d = tmp();
    loadRplEvidence(d);
    loadSampleInventory(d);
    const a = renderIscpDocx(fullOpts(d));
    const b = renderIscpDocx(fullOpts(d));
    expect(Buffer.compare(a.buffer, b.buffer)).toBe(0);
    const core = readPart(a.buffer, 'docProps/core.xml');
    expect(core).toContain('Information System Contingency Plan');
    expect(core).toMatch(/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/);
  });

  it('quotes NIST SP 800-34 §3.1 verbatim in §1.3', () => {
    const { xml } = buildIscpBodyXml(baseOpts());
    expect(xml).toContain('The information system contingency planning process includes the following seven steps');
    expect(xml).toContain('Conduct the business impact analysis (BIA)');
  });
});

describe('ISCP emitter — disk (emitIscpDocx)', () => {
  it('writes to outPath + logs a structured emission event', () => {
    const d = tmp();
    loadRplEvidence(d);
    const outPath = join(d, 'custom-iscp.docx');
    const spy = vi.spyOn(log, 'info').mockImplementation(() => log as any);
    const r = emitIscpDocx(baseOpts({ outDir: d, outPath }));
    expect(r.path).toBe(outPath);
    expect(existsSync(outPath)).toBe(true);
    expect(r.bytes).toBeGreaterThan(8000);
    expect(spy).toHaveBeenCalledWith(expect.objectContaining({
      event: 'iscp.emitted',
      bytes: expect.any(Number),
      rpl_evidence_count: 4,
    }));
  });
});
