/**
 * Tests for core/pta-pia-emit.ts — LOOP-C.C4 Privacy Threshold Analysis (PTA)
 * + Privacy Impact Assessment (PIA) — PT-2 / PT-3 / PT-6 / AR-2.
 *
 * Verifies (14 tests per C.C4.md §8, plus 2 additional for error-guards +
 * PII-redaction so the slice also clears the universal ≥15-new-tests floor):
 *   1. Emits PTA only when no PII detected and the operator did not force PIA.
 *   2. Emits both PTA + PIA when inventory has PII-tagged assets.
 *   3. Emits both when piaForceMode = 'always-emit'.
 *   4. Emits PTA only when piaForceMode = 'never-emit' even if PII present.
 *   5. PTA §3 lists which assets triggered the PII determination.
 *   6. PIA §2 categories of PII default to REQUIRES-OPERATOR-INPUT.
 *   7. PIA §6 retention period verbatim from opts.
 *   8. Quotes Rev5 PT-2 + PT-3 + PT-6 control IDs in §1 header.
 *   9. Cross-references SSP system-name and system-id.
 *  10. Document footer cites the FedRAMP A04 template URL.
 *  11. Writes to outPath dir when supplied.
 *  12. Deterministic (byte-identical) output for same inputs.
 *  13. ready_for_signature requires every PTA + (if applicable) every PIA field.
 *  14. Handles inventory.json missing gracefully — emit PTA with TBD §3.
 *  15. Rejects an unknown impactLevel + an unknown piaForceMode.
 *  16. §3 redacts resource names (REO — no PII leaks into the document).
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import { mkdtempSync, copyFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  emitPtaPiaDocx, renderPtaPiaDocx, buildPtaBodyXml, buildPiaBodyXml, readPiiInventory,
  PtaPiaImpactLevelError, PtaPiaForceModeError,
  type PtaPiaEmitOptions, type PtaResponses, type PiaResponses,
} from '../../core/pta-pia-emit.ts';
import { log } from '../../core/log.ts';

const FIXTURE_DIR = resolve(import.meta.dirname ?? '', 'fixtures/pta-pia');

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-pta-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  vi.restoreAllMocks();
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

/** Copy an inventory fixture ('with-pii' | 'no-pii') into <dir>/inventory.json. */
function loadInventory(dir: string, which: 'with-pii' | 'no-pii'): void {
  copyFileSync(join(FIXTURE_DIR, `inventory.${which}.json`), join(dir, 'inventory.json'));
}

function baseOpts(over: Partial<PtaPiaEmitOptions> = {}): PtaPiaEmitOptions {
  return { outDir: '/nonexistent-pta-dir', runId: 'r-pta-test', frmrVersion: '0.9.43-beta', impactLevel: 'moderate', ...over };
}

const fullPta: PtaResponses = {
  collectsPII: true, identifiableData: true, sharingWithExternalEntities: true,
  persistentUserIdentifiers: false, reusedForSecondaryPurposes: false,
};

const fullPia: PiaResponses = {
  authorityToCollect: '44 U.S.C. §3554 (FISMA) as incorporated into the FedRAMP boundary.',
  purposesOfCollection: ['Authenticate federal end-users.', 'Deliver the contracted SaaS.'],
  categoriesOfPII: ['Full name', 'Government email address'],
  sourcesOfPII: ['Provided by the data subject.'],
  sharing: [{ recipient: 'Agency IdP', purpose: 'Federated auth', mechanism: 'SAML 2.0 over TLS' }],
  consentMechanism: 'Notice at account creation.',
  sornReference: 'Not a Privacy Act system of records.',
  accessAndCorrection: 'Via the agency privacy office.',
  retentionPeriod: 'Contract term plus 90 days, then purged.',
  disposalMethod: 'Cryptographic erasure + NIST SP 800-88 sanitization.',
  safeguards: ['AES-256-GCM at rest; TLS 1.3 in transit.'],
};

/** Every required-for-signature field supplied (system identity + PTA + PIA). */
function fullOpts(dir: string, over: Partial<PtaPiaEmitOptions> = {}): PtaPiaEmitOptions {
  return baseOpts({
    outDir: dir,
    systemName: 'Acme Platform', systemId: 'acme-prod-1', cspOrganization: 'Acme Corp',
    ptaResponses: fullPta, piaResponses: fullPia,
    ...over,
  });
}

/** Extract ordered Heading1 titles from document.xml. */
function heading1Titles(xml: string): string[] {
  return [...xml.matchAll(/<w:pStyle w:val="Heading1"\/><\/w:pPr><w:r><w:t xml:space="preserve">([^<]*)<\/w:t>/g)].map((m) => m[1]!);
}

describe('PTA/PIA emitter — determination + conditional PIA', () => {
  it('emits PTA only when no PII detected and operator did not force PIA', () => {
    const d = tmp();
    loadInventory(d, 'no-pii');
    const r = emitPtaPiaDocx(baseOpts({ outDir: d }));
    expect(existsSync(r.ptaPath)).toBe(true);
    expect(r.requiresPIA).toBe(false);
    expect(r.collectsPII).toBe(false);
    expect(r.piaPath).toBeNull();
    expect(existsSync(join(d, 'pia.docx'))).toBe(false);
  });

  it('emits both PTA + PIA when inventory has PII-tagged assets', () => {
    const d = tmp();
    loadInventory(d, 'with-pii');
    const r = emitPtaPiaDocx(baseOpts({ outDir: d }));
    expect(r.collectsPII).toBe(true);
    expect(r.requiresPIA).toBe(true);
    expect(r.pii_asset_count).toBe(2); // pii + phi (public excluded)
    expect(r.piaPath).not.toBeNull();
    expect(existsSync(r.piaPath!)).toBe(true);
  });

  it('emits both when piaForceMode = "always-emit" (even with no PII)', () => {
    const d = tmp();
    loadInventory(d, 'no-pii');
    const r = emitPtaPiaDocx(baseOpts({ outDir: d, piaForceMode: 'always-emit' }));
    expect(r.collectsPII).toBe(false);
    expect(r.requiresPIA).toBe(true);
    expect(existsSync(r.piaPath!)).toBe(true);
  });

  it('emits PTA only when piaForceMode = "never-emit" even if PII present (with warning note)', () => {
    const d = tmp();
    loadInventory(d, 'with-pii');
    const r = emitPtaPiaDocx(baseOpts({ outDir: d, piaForceMode: 'never-emit' }));
    expect(r.requiresPIA).toBe(false);
    expect(r.pia_suppressed).toBe(true);
    expect(r.piaPath).toBeNull();
    // §4 renders the suppression warning.
    const { xml } = buildPtaBodyXml(baseOpts({ outDir: d, piaForceMode: 'never-emit' }));
    expect(xml).toContain('SUPPRESSED by the operator');
    expect(xml).toContain('REQUIRES-OPERATOR-INPUT-VERIFY');
  });
});

describe('PTA/PIA emitter — §3 evidence + PII redaction', () => {
  it('PTA §3 lists which assets triggered the PII determination', () => {
    const d = tmp();
    loadInventory(d, 'with-pii');
    const inv = readPiiInventory(d);
    expect(inv.piiAssets.length).toBe(2);
    const { xml } = buildPtaBodyXml(baseOpts({ outDir: d }));
    expect(xml).toContain('s3-bucket');
    expect(xml).toContain('rds-instance');
    expect(xml).toContain('PII');
    expect(xml).toContain('PHI');
    expect(xml).toContain('2 of 3 inventoried asset(s)');
  });

  it('§3 redacts resource names — no PII leaks into the document (REO Risk 3)', () => {
    const d = tmp();
    loadInventory(d, 'with-pii');
    const { xml } = buildPtaBodyXml(baseOpts({ outDir: d }));
    // The raw resource names must NOT appear anywhere in the document.
    expect(xml).not.toContain('acme-prod-customer-pii-store');
    expect(xml).not.toContain('acme-patient-records');
    // A redacted reference + correlation hash is present instead.
    expect(xml).toContain('***');
    expect(xml).toContain('ref:');
  });
});

describe('PTA/PIA emitter — PIA sections', () => {
  it('PIA §2 categories of PII default to REQUIRES-OPERATOR-INPUT', () => {
    const d = tmp();
    // PIA required via always-emit, but no piaResponses supplied.
    const { xml } = buildPiaBodyXml(baseOpts({ outDir: d, piaForceMode: 'always-emit' }));
    expect(xml).toContain('Categories of PII');
    // The categories bullet is a TBD prompt, and the toolkit never invents categories.
    expect(xml).toContain('the toolkit never defaults these');
    expect(xml).not.toContain('name, email, SSN');
    expect(xml).toContain('REQUIRES-OPERATOR-INPUT');
  });

  it('PIA §6 retention period is rendered verbatim from opts', () => {
    const d = tmp();
    const { xml } = buildPiaBodyXml(fullOpts(d));
    expect(xml).toContain('Contract term plus 90 days, then purged.');
  });

  it('quotes Rev5 PT-2 + PT-3 + PT-6 control IDs in the §1 header', () => {
    const d = tmp();
    const { xml } = buildPtaBodyXml(baseOpts({ outDir: d, systemName: 'Acme', systemId: 'a1' }));
    for (const id of ['PT-2', 'PT-3', 'PT-6']) expect(xml).toContain(id);
    // §1 is present and names the controls.
    expect(heading1Titles(xml)[0]).toContain('System Overview');
  });

  it('cross-references the SSP system-name and system-id', () => {
    const d = tmp();
    const { xml } = buildPtaBodyXml(baseOpts({ outDir: d, systemName: 'Acme Platform', systemId: 'acme-prod-1' }));
    expect(xml).toContain('Acme Platform');
    expect(xml).toContain('acme-prod-1');
  });

  it('document footer cites the FedRAMP A04 template URL', () => {
    const d = tmp();
    const { xml } = buildPtaBodyXml(baseOpts({ outDir: d }));
    expect(xml).toContain('https://www.fedramp.gov/assets/resources/templates/SSP-A04-FedRAMP-PIA-Template.docx');
  });
});

describe('PTA/PIA emitter — disk + determinism + readiness', () => {
  it('writes to outPath + piaOutPath dirs when supplied', () => {
    const d = tmp();
    loadInventory(d, 'with-pii');
    const outPath = join(d, 'custom-pta.docx');
    const piaOutPath = join(d, 'custom-pia.docx');
    const spy = vi.spyOn(log, 'info').mockImplementation(() => log as any);
    const r = emitPtaPiaDocx(fullOpts(d, { outPath, piaOutPath }));
    expect(r.ptaPath).toBe(outPath);
    expect(r.piaPath).toBe(piaOutPath);
    expect(existsSync(outPath)).toBe(true);
    expect(existsSync(piaOutPath)).toBe(true);
    expect(r.ptaBytes).toBeGreaterThan(4000);
    void spy;
  });

  it('produces byte-identical output for identical inputs', () => {
    const d = tmp();
    loadInventory(d, 'with-pii');
    const a = renderPtaPiaDocx(fullOpts(d));
    const b = renderPtaPiaDocx(fullOpts(d));
    expect(Buffer.compare(a.ptaBuffer, b.ptaBuffer)).toBe(0);
    expect(a.piaBuffer).not.toBeNull();
    expect(Buffer.compare(a.piaBuffer!, b.piaBuffer!)).toBe(0);
  });

  it('ready_for_signature requires every PTA + (if applicable) every PIA field', () => {
    const d = tmp();
    loadInventory(d, 'with-pii');
    // Missing everything → not ready; PIA required (PII present) so PIA fields tracked too.
    const bare = renderPtaPiaDocx(baseOpts({ outDir: d }));
    expect(bare.stats.ready_for_signature).toBe(false);
    expect(bare.stats.requires_operator_input).toContain('systemName');
    expect(bare.stats.requires_operator_input).toContain('ptaResponses');
    expect(bare.stats.requires_operator_input).toContain('piaResponses.categoriesOfPII');
    // Everything supplied → ready.
    const full = renderPtaPiaDocx(fullOpts(d));
    expect(full.stats.ready_for_signature).toBe(true);
    expect(full.stats.requires_operator_input).toEqual([]);
  });

  it('handles inventory.json missing gracefully — emits PTA with a TBD §3', () => {
    const d = tmp(); // no inventory.json copied in
    const r = emitPtaPiaDocx(baseOpts({ outDir: d }));
    expect(existsSync(r.ptaPath)).toBe(true);
    expect(r.collectsPII).toBe(false);
    expect(r.pii_asset_count).toBe(0);
    const { xml } = buildPtaBodyXml(baseOpts({ outDir: d }));
    expect(xml).toContain('no out/inventory.json was found');
    expect(xml).toContain('REQUIRES-OPERATOR-INPUT');
  });

  it('logs a structured emission event', () => {
    const d = tmp();
    loadInventory(d, 'with-pii');
    const spy = vi.spyOn(log, 'info').mockImplementation(() => log as any);
    emitPtaPiaDocx(fullOpts(d));
    expect(spy).toHaveBeenCalledWith(expect.objectContaining({
      event: 'pta-pia.emitted',
      requires_pia: true,
      collects_pii: true,
    }));
  });

  it('rejects an unknown impactLevel and an unknown piaForceMode', () => {
    expect(() => buildPtaBodyXml(baseOpts({ impactLevel: 'extreme' as any }))).toThrow(PtaPiaImpactLevelError);
    expect(() => buildPtaBodyXml(baseOpts({ piaForceMode: 'sometimes' as any }))).toThrow(PtaPiaForceModeError);
  });
});
