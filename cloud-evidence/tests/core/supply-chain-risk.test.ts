/**
 * Tests for core/supply-chain-risk.ts — the SR-3 / NIST SP 800-161r1 supply
 * chain risk register (LOOP-J.J3) + its POA&M and SSP integrations.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, copyFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  buildSupplyChainRiskRegister,
  emitSupplyChainRiskRegister,
  readRisksConfig,
  registerToXlsx,
  serializeUnsignedCanonical,
  addDaysIso,
  type BuildRegisterInput,
  type OperatorRiskEntry,
  type SupplyChainRiskRegister,
} from '../../core/supply-chain-risk.ts';
import type { SbomReport } from '../../core/sbom.ts';
import type { KevEntry } from '../../core/kev-feed.ts';
import type { SubprocessorInventory } from '../../core/subprocessor-inventory.ts';
import { emitOscalPoam } from '../../core/oscal-poam.ts';
import { emitOscalSsp } from '../../core/oscal-ssp.ts';

const F = (n: string) => fileURLToPath(new URL(`../fixtures/supply-chain-risk/${n}`, import.meta.url));
const SBOM_FIXTURE = F('sbom-report.fixture.json');
const SUBINV_FIXTURE = F('subprocessor-inventory.fixture.json');
const KEV_FIXTURE = F('kev-catalog.fixture.json');
const RISKS_FIXTURE = F('risks-config.example.yaml');

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-scrr-'));
  dirs.push(d);
  return d;
}
const at = (iso: string) => () => new Date(iso);

afterEach(() => {
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* */ }
  }
});

function sbomReport(): SbomReport {
  return JSON.parse(readFileSync(SBOM_FIXTURE, 'utf8')) as SbomReport;
}
function subInv(): SubprocessorInventory {
  return JSON.parse(readFileSync(SUBINV_FIXTURE, 'utf8')) as SubprocessorInventory;
}
function kevMap(): Map<string, KevEntry> {
  const cat = JSON.parse(readFileSync(KEV_FIXTURE, 'utf8'));
  const m = new Map<string, KevEntry>();
  for (const v of cat.vulnerabilities) m.set(v.cveID, v as KevEntry);
  return m;
}
function input(overrides: Partial<BuildRegisterInput> = {}): BuildRegisterInput {
  return {
    sbomReport: sbomReport(),
    subprocessorInventory: subInv(),
    kev: kevMap(),
    operatorRisks: [],
    mitigations: [],
    sourceModules: ['core/sbom.ts', 'core/kev-feed.ts', 'core/subprocessor-inventory.ts'],
    sourceFiles: [],
    ...overrides,
  };
}
const opts = { runId: 'run-jj3', now: at('2026-06-06T00:00:00Z') };

describe('buildSupplyChainRiskRegister (pure)', () => {
  it('builds a register from a CycloneDX SBOM report + KEV catalog (KEV elevation)', () => {
    const reg = buildSupplyChainRiskRegister(input(), opts);
    const kevEntries = reg.entries.filter((e) => e.category === 'sbom-cve-kev');
    expect(kevEntries).toHaveLength(1);
    expect(kevEntries[0]!.severity).toBe('critical');
    expect(kevEntries[0]!.cve_ids).toEqual(['CVE-2021-44228']);
    // The plain sbom-cve entry for that CVE must NOT also exist (no double-emit).
    expect(reg.entries.some((e) => e.category === 'sbom-cve' && e.cve_ids?.includes('CVE-2021-44228'))).toBe(false);
  });

  it('uses the CISA KEV published due-date verbatim as kev_due_date', () => {
    const reg = buildSupplyChainRiskRegister(input(), opts);
    const kev = reg.entries.find((e) => e.category === 'sbom-cve-kev')!;
    expect(kev.kev_due_date).toBe('2021-12-24');
  });

  it('emits exactly one unsigned-sbom entry per unverified SBOM file', () => {
    const reg = buildSupplyChainRiskRegister(input(), opts);
    const unsigned = reg.entries.filter((e) => e.category === 'unsigned-sbom');
    expect(unsigned).toHaveLength(1);                 // image-a unverified; image-b verified
    expect(unsigned[0]!.severity).toBe('medium');
    expect(unsigned[0]!.status).toBe('open');
  });

  it('distinguishes unverified vs absent SBOM signature in the description', () => {
    const sb = sbomReport();
    sb.sboms[1]!.signature_status = 'absent';
    const reg = buildSupplyChainRiskRegister(input({ sbomReport: sb }), opts);
    const unsigned = reg.entries.filter((e) => e.category === 'unsigned-sbom');
    expect(unsigned).toHaveLength(2);
    expect(unsigned.some((e) => /verification ran but did NOT succeed/.test(e.description))).toBe(true);
    expect(unsigned.some((e) => /no signature sidecar was present/.test(e.description))).toBe(true);
  });

  it('emits a subprocessor-risk-tier entry for each tier-1-critical subprocessor', () => {
    const reg = buildSupplyChainRiskRegister(input(), opts);
    const tier1 = reg.entries.filter((e) => e.category === 'subprocessor-risk-tier');
    expect(tier1).toHaveLength(1);
    expect(tier1[0]!.affected_subprocessors).toEqual(['AcmeCloud Infrastructure']);
  });

  it('emits subprocessor-soc2-expired entries when soc2_expiry is past opts.now', () => {
    const reg = buildSupplyChainRiskRegister(input(), opts);
    const expired = reg.entries.filter((e) => e.category === 'subprocessor-soc2-expired');
    expect(expired).toHaveLength(1);
    expect(expired[0]!.affected_subprocessors).toEqual(['LegacyVault Backup']);
  });

  it('bumps UNKNOWN NVD severity to medium and records requires_operator_input', () => {
    const reg = buildSupplyChainRiskRegister(input(), opts);
    const unknown = reg.entries.find((e) => e.cve_ids?.includes('CVE-2026-22222'))!;
    expect(unknown.severity).toBe('medium');
    expect(reg.requires_operator_input).toContain(`${unknown.id}:severity`);
  });

  it('computes coverage.kev_exposed correctly', () => {
    const reg = buildSupplyChainRiskRegister(input(), opts);
    expect(reg.coverage.kev_exposed).toBe(1);
  });

  it('merges operator-asserted risks and applies mitigation overrides by id', () => {
    const cfg = readRisksConfig(RISKS_FIXTURE);
    const reg = buildSupplyChainRiskRegister(
      input({ operatorRisks: cfg.risks, mitigations: cfg.mitigations }),
      opts,
    );
    const adv = reg.entries.find((e) => e.id === 'vendor-advisory-2026-cve-12345')!;
    expect(adv.category).toBe('vendor-advisory');
    expect(adv.status).toBe('mitigated');             // mitigation override applied
    expect(adv.mitigation_summary).toMatch(/image rebuild 2026-05-15/);
  });

  it('emits REQUIRES-OPERATOR-INPUT for mitigation_summary when status != open and none supplied', () => {
    const risk: OperatorRiskEntry = { id: 'op-accepted-1', title: 'Accepted without justification', severity: 'high', status: 'accepted' };
    const reg = buildSupplyChainRiskRegister(input({ operatorRisks: [risk] }), opts);
    const e = reg.entries.find((x) => x.id === 'op-accepted-1')!;
    expect(e.mitigation_summary).toBe('REQUIRES-OPERATOR-INPUT');
    expect(reg.coverage.entries_missing_mitigation).toContain('op-accepted-1');
    expect(reg.requires_operator_input).toContain('op-accepted-1:mitigation_summary');
  });

  it('records sbom_provenance NTIA flags from the real parse (timestamp missing → false)', () => {
    const cdx = {
      bomFormat: 'CycloneDX',
      metadata: { authors: [{ name: 'syft' }] },   // no timestamp
      components: [{ name: 'lib', version: '1.0', purl: 'pkg:npm/lib@1.0', supplier: { name: 'Acme' } }],
      dependencies: [{ ref: 'lib' }],
    };
    const sb: SbomReport = {
      generated_at: '2026-06-01T00:00:00Z',
      sboms: [{ path: '/x/cdx.json', format: 'cyclonedx', image: 'img', bytes: 1, components: [], signature_status: 'verified' }],
      vulnerabilities: [],
      summary: { sbom_count: 1, total_components: 1, unique_components: 1, signed_sboms: 1, unsigned_sboms: 0, critical_vulns: 0, high_vulns: 0, medium_vulns: 0 },
    };
    const reg = buildSupplyChainRiskRegister(
      input({ sbomReport: sb, sbomRaw: { '/x/cdx.json': cdx }, subprocessorInventory: null, operatorRisks: [{ title: 'keep-source-nonempty' }] }),
      opts,
    );
    const p = reg.sbom_provenance[0]!;
    expect(p.timestamp_field_present).toBe(false);
    expect(p.supplier_name_field_present).toBe(true);
    expect(p.component_name_field_present).toBe(true);
    expect(p.version_field_present).toBe(true);
    expect(p.unique_identifier_field_present).toBe(true);
    expect(p.dependency_field_present).toBe(true);
    expect(p.author_field_present).toBe(true);
  });

  it('is deterministic: same inputs → identical unsigned canonical form regardless of order', () => {
    const a = buildSupplyChainRiskRegister(input(), opts);
    const sb = sbomReport();
    sb.vulnerabilities.reverse();
    const b = buildSupplyChainRiskRegister(input({ sbomReport: sb }), opts);
    expect(serializeUnsignedCanonical(a)).toBe(serializeUnsignedCanonical(b));
  });
});

describe('readRisksConfig', () => {
  it('reads risks + mitigations from a YAML config', () => {
    const cfg = readRisksConfig(RISKS_FIXTURE);
    expect(cfg.risks).toHaveLength(1);
    expect(cfg.mitigations).toHaveLength(1);
    expect(cfg.risks[0]!.title).toBe('Vendor X advisory CVE-2026-12345');
  });

  it('rejects a config with an unknown top-level key (REO safety net)', () => {
    const d = tmp();
    const p = join(d, 'bad.yaml');
    writeFileSync(p, 'risks: []\nbogus: true\n');
    expect(() => readRisksConfig(p)).toThrow(/unknown top-level key/);
  });
});

describe('registerToXlsx', () => {
  it('writes an XLSX with one sheet per category plus Summary + SBOM-Provenance', () => {
    const reg = buildSupplyChainRiskRegister(input(), opts);
    const buf = registerToXlsx(reg);
    expect(buf.subarray(0, 2).toString('latin1')).toBe('PK');
    const text = buf.toString('latin1');
    for (const name of ['Summary', 'SBOM-CVE', 'SBOM-CVE-KEV', 'Subprocessor-Risk', 'Unsigned-SBOM', 'Vendor-Advisory', 'Operator-Asserted', 'SBOM-Provenance']) {
      expect(text.includes(`name="${name}"`)).toBe(true);
    }
    // 8 worksheet parts.
    expect((text.match(/xl\/worksheets\/sheet\d+\.xml/g) ?? []).length).toBeGreaterThanOrEqual(8);
  });
});

describe('emitSupplyChainRiskRegister (disk emitter)', () => {
  it('throws a typed error when no source data is available', async () => {
    const out = tmp();
    await expect(emitSupplyChainRiskRegister({ outDir: out, runId: 'r' })).rejects.toThrow(
      /--sbom-dir.*--subprocessors-config.*--risks-config|no source data available/s,
    );
  });

  it('records provenance.sourceModules listing exactly the modules consulted', async () => {
    const out = tmp();
    copyFileSync(SBOM_FIXTURE, join(out, 'sbom-report.json'));
    copyFileSync(SUBINV_FIXTURE, join(out, 'subprocessor-inventory.json'));
    const r = await emitSupplyChainRiskRegister({ outDir: out, runId: 'r', kevCatalogPath: KEV_FIXTURE, now: at('2026-06-06T00:00:00Z') });
    const mods = r.register.provenance.sourceModules;
    expect(mods).toContain('core/sbom.ts');
    expect(mods).toContain('core/kev-feed.ts');
    expect(mods).toContain('core/subprocessor-inventory.ts');
    expect(mods).not.toContain('operator:--risks-config');     // no --risks-config passed
    // G3 provenance + detached signature.
    expect(r.register.provenance.signingKeyId).toMatch(/^[0-9a-f]{16}$/);
    expect(r.register.signature).toBeTruthy();
  });
});

describe('POA&M integration (LOOP-J.J3 → core/oscal-poam.ts)', () => {
  function writeRegister(outDir: string, ops: OperatorRiskEntry[]) {
    const reg = buildSupplyChainRiskRegister(input({ operatorRisks: ops }), opts);
    writeFileSync(join(outDir, 'supply-chain-risk-register.json'), JSON.stringify(reg, null, 2));
    return reg;
  }
  function writeFailingKsi(outDir: string) {
    writeFileSync(join(outDir, 'KSI-IAM-MFA.json'), JSON.stringify({
      ksi_id: 'KSI-IAM-MFA', collected_at: '2026-06-01T00:00:00Z',
      providers: [{ provider: 'aws', findings: [{ rule: 'mfa_on', passed: false, severity: 'high', nist_controls: ['ac-2'] }], evidence: [] }],
    }));
  }

  it('emits POA&M items for open critical/high register entries with risk-source=supply-chain', () => {
    const out = tmp();
    writeRegister(out, []);
    writeFailingKsi(out);
    const r = emitOscalPoam({ outDir: out, runId: 'run-poam', frmrVersion: '25.05' });
    const doc = JSON.parse(readFileSync(r.path!, 'utf8'))['plan-of-action-and-milestones'];
    const scItems = doc['poam-items'].filter((it: any) => it.props?.some((p: any) => p.name === 'risk-source' && p.value === 'supply-chain'));
    expect(scItems.length).toBeGreaterThan(0);
  });

  it('uses RiskEntry.first_seen as the POA&M deadline anchor, not the run timestamp', () => {
    const out = tmp();
    writeRegister(out, [{ id: 'crit-1', title: 'Critical supply-chain risk', severity: 'critical', status: 'open', first_seen: '2026-04-01' }]);
    writeFailingKsi(out);
    const r = emitOscalPoam({ outDir: out, runId: 'run-poam2', frmrVersion: '25.05' });
    const doc = JSON.parse(readFileSync(r.path!, 'utf8'))['plan-of-action-and-milestones'];
    const item = doc['poam-items'].find((it: any) => it.props?.some((p: any) => p.name === 'category' && p.value === 'operator-asserted-risk'));
    expect(item).toBeTruthy();
    const deadline = item.props.find((p: any) => p.name === 'remediation-deadline').value;
    expect(deadline).toBe('2026-05-01');           // 2026-04-01 + 30 days (critical)
    expect(addDaysIso('2026-04-01', 30)).toBe('2026-05-01');
  });
});

describe('SSP back-matter integration (LOOP-J.J3 → core/oscal-ssp.ts)', () => {
  let prevBaselines: string | undefined;
  afterEach(() => {
    if (prevBaselines === undefined) delete process.env.NIST_BASELINES_PATH;
    else process.env.NIST_BASELINES_PATH = prevBaselines;
    prevBaselines = undefined;
  });

  it('adds a back-matter resource pointing at the register when run alongside --oscal-ssp', () => {
    const out = tmp();
    const bdir = tmp();
    const bpath = join(bdir, 'baselines.json');
    writeFileSync(bpath, JSON.stringify({ low: ['ac-2'], moderate: ['ac-2'], high: ['ac-2'] }));
    prevBaselines = process.env.NIST_BASELINES_PATH;
    process.env.NIST_BASELINES_PATH = bpath;
    writeFileSync(join(out, 'KSI-IAM-MFA.json'), JSON.stringify({ ksi_id: 'KSI-IAM-MFA', providers: [{ provider: 'aws', findings: [{ rule: 'mfa', passed: true, nist_controls: ['ac-2'] }] }], rollup: { pass: true } }));
    const reg = buildSupplyChainRiskRegister(input(), opts);
    writeFileSync(join(out, 'supply-chain-risk-register.json'), JSON.stringify(reg, null, 2));

    const r = emitOscalSsp({ outDir: out, runId: 'run-ssp', frmrVersion: '25.05', impactLevel: 'moderate', systemId: 'sys-test' });
    const ssp = JSON.parse(readFileSync(r.path, 'utf8'))['system-security-plan'];
    const resources = ssp['back-matter']?.resources ?? [];
    expect(resources.some((res: any) => res.title === 'Supply Chain Risk Register (SR-3, NIST SP 800-161r1)')).toBe(true);
  });
});
