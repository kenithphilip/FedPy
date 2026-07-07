/**
 * Tests for core/irp-emit.ts — LOOP-C.C3 Incident Response Plan
 * (IR-8 / IR-3 / IR-4 / IR-6).
 *
 * Verifies (13 tests per C.C3.md §8):
 *   1. Emits 11 sections in CSF 2.0 phase order for the r3 default.
 *   2. Auto-fills §4 detection-sources from the real KSI-INR-RIR evidence.
 *   3. Emits REQUIRES-OPERATOR-INPUT when no INR-RIR evidence exists.
 *   4. Renders irTeamRoster with the on_call flag visible.
 *   5. Emits FedRAMP ICP-mandated SLAs in §9 even without an escalationMatrix
 *      (with a verify marker).
 *   6. Quotes the NIST SP 800-61r3 CSF 2.0 phase definition verbatim.
 *   7. escalationMatrix sorts by severity descending.
 *   8. externalContacts groups CISA + FedRAMP PMO + Agency POC.
 *   9. specVersion=800-61r2 replaces §5 with the four-phase model.
 *  10. Writes to outPath when supplied.
 *  11. Produces deterministic (byte-identical) output.
 *  12. Logs a structured emission event.
 *  13. ready_for_signature = false when irTeamRoster is empty.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import { mkdtempSync, copyFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  emitIrpDocx, renderIrpDocx, buildIrpBodyXml, readInrRirEvidence,
  IrpImpactLevelError, IrpSpecVersionError,
  type IrpEmitOptions, type IrpTeamMember, type IrpEscalationRule,
} from '../../core/irp-emit.ts';
import { log } from '../../core/log.ts';

const FIXTURE_DIR = resolve(import.meta.dirname ?? '', 'fixtures/irp');

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-irp-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  vi.restoreAllMocks();
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

/** Copy the KSI-INR-RIR evidence fixture into <dir>. */
function loadInrRir(dir: string): void {
  copyFileSync(join(FIXTURE_DIR, 'KSI-INR-RIR.json'), join(dir, 'KSI-INR-RIR.json'));
}

function baseOpts(over: Partial<IrpEmitOptions> = {}): IrpEmitOptions {
  return { outDir: '/nonexistent-irp-dir', runId: 'r-irp-test', frmrVersion: '0.9.43-beta', impactLevel: 'moderate', ...over };
}

const sampleRoster: IrpTeamMember[] = [
  { role: 'IR Lead', name: 'Sam Okafor', org: 'Acme', email: 'ir-lead@acme.example', phone: '+1-555-0100', on_call: true },
];

/** Every required-for-signature operator field supplied. */
function fullOpts(dir: string, over: Partial<IrpEmitOptions> = {}): IrpEmitOptions {
  return baseOpts({
    outDir: dir,
    systemName: 'Acme Platform', systemId: 'acme-prod-1', cspOrganization: 'Acme Corp',
    irTeamRoster: sampleRoster,
    communicationsPlan: { internal: 'PagerDuty on-call.', external: 'Notify agency POCs.', media: 'Legal approval required.' },
    ...over,
  });
}

/** Extract ordered Heading1 titles from document.xml. */
function heading1Titles(xml: string): string[] {
  return [...xml.matchAll(/<w:pStyle w:val="Heading1"\/><\/w:pPr><w:r><w:t xml:space="preserve">([^<]*)<\/w:t>/g)].map((m) => m[1]!);
}
/** Extract ordered Heading2 titles from document.xml. */
function heading2Titles(xml: string): string[] {
  return [...xml.matchAll(/<w:pStyle w:val="Heading2"\/><\/w:pPr><w:r><w:t xml:space="preserve">([^<]*)<\/w:t>/g)].map((m) => m[1]!);
}

describe('IRP emitter — section structure', () => {
  it('emits 11 numbered sections in order + §5 in CSF 2.0 phase order for the r3 default', () => {
    const { xml } = buildIrpBodyXml(fullOpts(tmp()));
    const titles = heading1Titles(xml);
    // 11 numbered sections come first, in 1..11 order.
    for (let i = 0; i < 11; i++) expect(titles[i]!.startsWith(`${i + 1}.`)).toBe(true);
    expect(titles[0]).toContain('Introduction');
    expect(titles[3]).toContain('Detect');
    expect(titles[4]).toContain('Respond');
    expect(titles[10]).toContain('Plan Maintenance');
    // §5 Respond sub-sections follow the CSF 2.0 Function order.
    const csf = heading2Titles(xml).filter((t) => t.startsWith('5.'));
    expect(csf.map((t) => t.replace(/^5\.\d+ /, ''))).toEqual(['Govern', 'Identify', 'Protect', 'Detect', 'Respond', 'Recover']);
  });
});

describe('IRP emitter — §4 Detect (INR-RIR)', () => {
  it('auto-fills §4 detection-sources from the real KSI-INR-RIR evidence', () => {
    const d = tmp();
    loadInrRir(d);
    const inr = readInrRirEvidence(d);
    expect(inr?.detection_sources.length).toBe(4);
    expect(inr?.coverage_percent).toBe(75);
    const { xml, stats } = buildIrpBodyXml(baseOpts({ outDir: d }));
    expect(stats.detection_source_count).toBe(4);
    expect(stats.detection_coverage_percent).toBe(75);
    expect(xml).toContain('aws.cloudtrail.org_trail_active');
    expect(xml).toContain('ACTIVE');
    expect(xml).toContain('GAP');
    // Coverage < 95% surfaces the warning row (per-slice Risk 4).
    expect(xml).toContain('below the 95% target');
  });

  it('emits REQUIRES-OPERATOR-INPUT when no INR-RIR evidence exists', () => {
    const d = tmp();
    const { xml, stats } = buildIrpBodyXml(baseOpts({ outDir: d }));
    expect(stats.detection_source_count).toBe(0);
    expect(stats.detection_coverage_percent).toBeNull();
    expect(xml).toContain('No KSI-INR-RIR evidence found');
    expect(xml).toContain('REQUIRES-OPERATOR-INPUT');
  });
});

describe('IRP emitter — roster + SLAs + contacts', () => {
  it('renders irTeamRoster with the on_call flag visible', () => {
    const { xml, stats } = buildIrpBodyXml(baseOpts({
      irTeamRoster: [{ role: 'Forensics', name: 'Alex Rivera', org: 'Acme', email: 'f@acme.example', phone: '+1-555-0111', on_call: true }],
    }));
    expect(stats.team_member_count).toBe(1);
    expect(xml).toContain('Alex Rivera');
    expect(xml).toContain('Forensics');
    // on_call true → "Yes" cell.
    expect(xml).toContain('>Yes<');
  });

  it('emits FedRAMP ICP-mandated SLAs in §9 even when escalationMatrix is not supplied (with verify marker)', () => {
    const { xml } = buildIrpBodyXml(baseOpts());
    expect(xml).toContain('FedRAMP PMO');
    expect(xml).toContain('CISA US-CERT');
    expect(xml).toContain('1 hour');
    expect(xml).toContain('4 hours');
    expect(xml).toContain('REQUIRES-OPERATOR-INPUT-VERIFY');
  });

  it('groups CISA + FedRAMP PMO + Agency POC in §7 external contacts by default', () => {
    const { xml } = buildIrpBodyXml(baseOpts());
    for (const entity of ['FedRAMP PMO', 'CISA', 'Agency POC']) expect(xml).toContain(entity);
    expect(xml).toContain('info@fedramp.gov');
  });
});

describe('IRP emitter — verbatim source + escalation sort', () => {
  it('quotes the NIST SP 800-61r3 CSF 2.0 phase definition verbatim', () => {
    const { xml } = buildIrpBodyXml(baseOpts());
    expect(xml).toContain('structured around the NIST Cybersecurity Framework (CSF) 2.0 Functions: Govern, Identify, Protect, Detect, Respond, and Recover');
  });

  it('escalationMatrix sorts by severity descending', () => {
    const outOfOrder: IrpEscalationRule[] = [
      { severity: 'low', sla_minutes: 1440, notify: ['IR Analyst'] },
      { severity: 'critical', sla_minutes: 60, notify: ['IR Lead'] },
      { severity: 'medium', sla_minutes: 240, notify: ['IR Lead'] },
      { severity: 'high', sla_minutes: 120, notify: ['IR Lead'] },
    ];
    const { xml } = buildIrpBodyXml(baseOpts({ escalationMatrix: outOfOrder }));
    const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => xml.indexOf(`>${s}<`));
    expect(order).toEqual([...order].sort((a, b) => a - b));
    for (const idx of order) expect(idx).toBeGreaterThan(-1);
  });
});

describe('IRP emitter — spec version', () => {
  it('specVersion=800-61r2 replaces §5 with the four-phase model', () => {
    const { xml } = buildIrpBodyXml(baseOpts({ specVersion: '800-61r2' }));
    // Heading text is XML-escaped, so "&" renders as "&amp;".
    const r2 = heading2Titles(xml).filter((t) => t.startsWith('5.')).map((t) => t.replace(/^5\.\d+ /, ''));
    expect(r2).toEqual(['Preparation', 'Detection &amp; Analysis', 'Containment, Eradication &amp; Recovery', 'Post-Incident Activity']);
    // The r3 CSF sub-section heading "5.1 Govern" is absent.
    expect(xml).not.toContain('5.1 Govern');
  });

  it('rejects an unknown impactLevel and an unknown specVersion', () => {
    expect(() => buildIrpBodyXml(baseOpts({ impactLevel: 'extreme' as any }))).toThrow(IrpImpactLevelError);
    expect(() => buildIrpBodyXml(baseOpts({ specVersion: '800-61r9' as any }))).toThrow(IrpSpecVersionError);
  });
});

describe('IRP emitter — disk + determinism + readiness', () => {
  it('writes to outPath when supplied', () => {
    const d = tmp();
    const outPath = join(d, 'custom-irp.docx');
    const spy = vi.spyOn(log, 'info').mockImplementation(() => log as any);
    const r = emitIrpDocx(fullOpts(d, { outPath }));
    expect(r.path).toBe(outPath);
    expect(existsSync(outPath)).toBe(true);
    expect(r.bytes).toBeGreaterThan(8000);
    void spy;
  });

  it('produces byte-identical output for identical inputs', () => {
    const d = tmp();
    loadInrRir(d);
    const a = renderIrpDocx(fullOpts(d));
    const b = renderIrpDocx(fullOpts(d));
    expect(Buffer.compare(a.buffer, b.buffer)).toBe(0);
  });

  it('logs a structured emission event', () => {
    const d = tmp();
    loadInrRir(d);
    const spy = vi.spyOn(log, 'info').mockImplementation(() => log as any);
    emitIrpDocx(fullOpts(d));
    expect(spy).toHaveBeenCalledWith(expect.objectContaining({
      event: 'irp.emitted',
      detection_source_count: 4,
      ready_for_signature: true,
    }));
  });

  it('ready_for_signature = false when irTeamRoster is empty', () => {
    const d = tmp();
    const empty = buildIrpBodyXml(baseOpts({ outDir: d, systemName: 'Acme', systemId: 'a1', cspOrganization: 'Acme Corp', communicationsPlan: { internal: 'x', external: 'y', media: 'z' } }));
    expect(empty.stats.ready_for_signature).toBe(false);
    expect(empty.stats.requires_operator_input).toContain('irTeamRoster');
    // Full opts → ready.
    const full = buildIrpBodyXml(fullOpts(d));
    expect(full.stats.ready_for_signature).toBe(true);
    expect(full.stats.requires_operator_input).toEqual([]);
  });
});
