/**
 * Tests for the VDR automation modules:
 *   - core/kev-feed.ts    — CISA KEV catalog loader (file + graceful fallback)
 *   - core/vdr-ledger.ts  — normalized ledger + VDR-TFR-* SLA evaluation
 *   - core/vdr-report.ts  — ledger summary for the orchestrator
 *
 * All time-sensitive assertions use a fixed `now` for determinism.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';

import { loadKevCatalog } from '../../core/kev-feed.ts';
import {
  buildLedger,
  PVR_TABLE_LOW,
  EVU_EVALUATION_DAYS,
  MAV_ACCEPTANCE_DAYS,
  pvrWindowDays,
  type LedgerEntry,
} from '../../core/vdr-ledger.ts';
import { summarizeVdr } from '../../core/vdr-report.ts';
import type { KevCatalog } from '../../core/kev-feed.ts';

const NOW = '2026-05-28T00:00:00.000Z';

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(resolve(tmpdir(), 'cev-vdr-'));
  delete process.env.CLOUD_EVIDENCE_KEV_PATH;
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

function writeKevFile(name = 'kev.json'): string {
  const path = resolve(tmp, name);
  const feed = {
    title: 'CISA Catalog of Known Exploited Vulnerabilities',
    catalogVersion: '2026.05.01',
    dateReleased: '2026-05-01T00:00:00.000Z',
    count: 2,
    vulnerabilities: [
      {
        cveID: 'CVE-2021-44228', // Log4Shell — past due
        vendorProject: 'Apache',
        product: 'Log4j2',
        vulnerabilityName: 'Apache Log4j2 RCE',
        dateAdded: '2021-12-10',
        shortDescription: 'JNDI lookup RCE',
        requiredAction: 'Apply updates',
        dueDate: '2021-12-24',
        knownRansomwareCampaignUse: 'Known',
        notes: '',
      },
      {
        cveID: 'cve-2099-00001', // lower-case on purpose — far-future due
        vendorProject: 'Acme',
        product: 'Widget',
        vulnerabilityName: 'Future KEV',
        dateAdded: '2099-01-01',
        dueDate: '2099-12-31',
      },
    ],
  };
  writeFileSync(path, JSON.stringify(feed));
  return path;
}

/** Minimal KEV catalog from the file fixture for ledger tests. */
async function fixtureCatalog(): Promise<KevCatalog> {
  return loadKevCatalog({ path: writeKevFile() });
}

describe('kev-feed: loadKevCatalog from a local file', () => {
  it('loads + indexes entries from a temp JSON file (case-insensitive CVE keys)', async () => {
    const cat = await loadKevCatalog({ path: writeKevFile() });
    expect(cat.source).toBe('file');
    expect(cat.count).toBe(2);
    expect(cat.catalogVersion).toBe('2026.05.01');
    // Keys normalized to upper-case regardless of input casing.
    expect(cat.byCve.has('CVE-2021-44228')).toBe(true);
    expect(cat.byCve.has('CVE-2099-00001')).toBe(true);
    expect(cat.byCve.get('CVE-2021-44228')?.dueDate).toBe('2021-12-24');
    expect(cat.warnings).toEqual([]);
  });

  it('honors CLOUD_EVIDENCE_KEV_PATH env var', async () => {
    process.env.CLOUD_EVIDENCE_KEV_PATH = writeKevFile('env-kev.json');
    const cat = await loadKevCatalog();
    expect(cat.source).toBe('file');
    expect(cat.count).toBe(2);
  });

  it('returns empty + actionable warning when no source is available (no throw)', async () => {
    const cat = await loadKevCatalog(); // no path, no fetch
    expect(cat.source).toBe('none');
    expect(cat.count).toBe(0);
    expect(cat.byCve.size).toBe(0);
    expect(cat.warnings.length).toBeGreaterThan(0);
    expect(cat.warnings[0]).toMatch(/CLOUD_EVIDENCE_KEV_PATH|fetch/);
  });

  it('returns empty + warning for a missing file path (no throw)', async () => {
    const cat = await loadKevCatalog({ path: resolve(tmp, 'does-not-exist.json') });
    expect(cat.source).toBe('none');
    expect(cat.count).toBe(0);
    expect(cat.warnings[0]).toMatch(/Could not read KEV cache file/);
  });

  it('returns empty + warning for malformed JSON (no throw)', async () => {
    const bad = resolve(tmp, 'bad.json');
    writeFileSync(bad, '{ not valid json');
    const cat = await loadKevCatalog({ path: bad });
    expect(cat.source).toBe('none');
    expect(cat.warnings[0]).toMatch(/not valid JSON/);
  });
});

describe('vdr-ledger: SLA day-tables match vdr.md', () => {
  it('PVR Low table matches the published values (vdr.md line 462)', () => {
    expect(PVR_TABLE_LOW.N5).toEqual({ irv_lev: 4, nirv_lev: 8, non_lev: 32 });
    expect(PVR_TABLE_LOW.N4).toEqual({ irv_lev: 8, nirv_lev: 32, non_lev: 64 });
    expect(PVR_TABLE_LOW.N3).toEqual({ irv_lev: 32, nirv_lev: 64, non_lev: 192 });
    expect(PVR_TABLE_LOW.N2).toEqual({ irv_lev: 96, nirv_lev: 160, non_lev: 192 });
  });

  it('EVU latency + MAV acceptance windows match vdr.md', () => {
    expect(EVU_EVALUATION_DAYS).toEqual({ low: 7, moderate: 5, high: 2 });
    expect(MAV_ACCEPTANCE_DAYS).toBe(192);
  });

  it('pvrWindowDays keys correctly on (PAIN, IRV, LEV)', () => {
    expect(pvrWindowDays(PVR_TABLE_LOW, 'N5', true, true)).toBe(4); // IRV+LEV
    expect(pvrWindowDays(PVR_TABLE_LOW, 'N5', false, true)).toBe(8); // nIRV+LEV
    expect(pvrWindowDays(PVR_TABLE_LOW, 'N5', true, false)).toBe(32); // non-LEV
    expect(pvrWindowDays(PVR_TABLE_LOW, 'N1', true, true)).toBeUndefined(); // N1 = no SLA
  });
});

describe('vdr-ledger: buildLedger KEV enrichment + due dates', () => {
  it('flags a KEV CVE past its dueDate as overdue (VDR-TFR-KEV)', async () => {
    const kev = await fixtureCatalog();
    const findings: LedgerEntry[] = [
      { cve: 'CVE-2021-44228', severity: 'critical', first_seen: '2025-01-01T00:00:00Z', source: 'inspector2', kev: false },
    ];
    const ledger = buildLedger(findings, kev, { tier: 'moderate', now: NOW });
    const entry = ledger[0]!;
    expect(entry.kev).toBe(true);
    expect(entry.due).toBe('2021-12-24'); // inherited from CISA catalog
    expect(entry.sla?.basis).toBe('kev');
    expect(entry.sla?.overdue).toBe(true);
    expect(entry.sla?.days_remaining).toBeGreaterThan(0); // positive = days overdue
  });

  it('a KEV CVE with a far-future due date is NOT overdue', async () => {
    const kev = await fixtureCatalog();
    const findings: LedgerEntry[] = [
      // evaluated_at recent so EVU/MAV deadlines are also in the future — this
      // isolates the KEV-due-date rule (2099 → far in the future).
      {
        cve: 'CVE-2099-00001',
        severity: 'high',
        first_seen: '2026-05-25T00:00:00Z',
        evaluated_at: '2026-05-26T00:00:00Z',
        source: 'ecr',
        kev: false,
      },
    ];
    const ledger = buildLedger(findings, kev, { now: NOW });
    expect(ledger[0]!.kev).toBe(true);
    expect(ledger[0]!.sla?.overdue).toBe(false);
    expect(ledger[0]!.sla?.days_remaining).toBeLessThan(0); // negative = days remaining
  });

  it('a non-KEV CVE is not flagged and inherits no KEV due date', async () => {
    const kev = await fixtureCatalog();
    const findings: LedgerEntry[] = [
      { cve: 'CVE-2024-99999', severity: 'medium', first_seen: '2026-05-20T00:00:00Z', source: 'scc', kev: false },
    ];
    const ledger = buildLedger(findings, kev, { now: NOW });
    expect(ledger[0]!.kev).toBe(false);
    expect(ledger[0]!.due).toBeUndefined();
  });

  it('does not mutate the input findings (pure)', async () => {
    const kev = await fixtureCatalog();
    const findings: LedgerEntry[] = [
      { cve: 'CVE-2021-44228', severity: 'critical', first_seen: '2025-01-01T00:00:00Z', source: 'inspector2', kev: false },
    ];
    const snapshot = JSON.parse(JSON.stringify(findings));
    buildLedger(findings, kev, { now: NOW });
    expect(findings).toEqual(snapshot);
  });
});

describe('vdr-ledger: VDR-TFR-PVR remediation-SLA table application', () => {
  const emptyKev: KevCatalog = { byCve: new Map(), count: 0, source: 'none', warnings: [] };

  it('flags a critical N5 IRV+LEV finding older than its Low window (4d) as a breach', () => {
    // Evaluated 30 days before NOW; Low N5 IRV+LEV window = 4 days → overdue.
    const findings: LedgerEntry[] = [
      {
        cve: 'CVE-2026-00001',
        severity: 'critical',
        first_seen: '2026-04-01T00:00:00Z',
        evaluated_at: '2026-04-28T00:00:00Z', // 30 days before NOW
        pain: 'N5',
        irv: true,
        lev: true,
        source: 'inspector2',
        kev: false,
      },
    ];
    const ledger = buildLedger(findings, emptyKev, { tier: 'low', now: NOW });
    const sla = ledger[0]!.sla!;
    expect(sla.basis).toBe('pvr');
    expect(sla.window_days).toBe(4);
    expect(sla.overdue).toBe(true);
  });

  it('does NOT flag a finding still within its PVR window', () => {
    // N3 non-LEV at Low = 192d window; evaluated only 10 days ago → fine.
    const findings: LedgerEntry[] = [
      {
        cve: 'CVE-2026-00002',
        severity: 'medium',
        first_seen: '2026-05-10T00:00:00Z',
        evaluated_at: '2026-05-18T00:00:00Z', // 10 days before NOW
        pain: 'N3',
        irv: false,
        lev: false,
        source: 'inspector2',
        kev: false,
      },
    ];
    const ledger = buildLedger(findings, emptyKev, { tier: 'low', now: NOW });
    const sla = ledger[0]!.sla!;
    // PVR window (192d) is not the soonest deadline here; MAV (192d) ties.
    expect(sla.overdue).toBe(false);
  });

  it('Moderate tier tightens the window vs Low (N5 IRV+LEV: 4d Low → 2d Moderate)', () => {
    const base: LedgerEntry = {
      cve: 'CVE-2026-00003',
      severity: 'critical',
      first_seen: '2026-05-24T00:00:00Z',
      evaluated_at: '2026-05-25T00:00:00Z', // 3 days before NOW
      pain: 'N5',
      irv: true,
      lev: true,
      source: 'inspector2',
      kev: false,
    };
    // Low window 4d → not overdue at 3d.
    const low = buildLedger([base], emptyKev, { tier: 'low', now: NOW })[0]!;
    expect(low.sla?.window_days).toBe(4);
    expect(low.sla?.overdue).toBe(false);
    // Moderate window 2d → overdue at 3d.
    const mod = buildLedger([base], emptyKev, { tier: 'moderate', now: NOW })[0]!;
    expect(mod.sla?.window_days).toBe(2);
    expect(mod.sla?.overdue).toBe(true);
  });

  it('marks SLA indeterminate when PAIN/IRV/LEV + evaluation are absent', () => {
    const findings: LedgerEntry[] = [
      { cve: 'CVE-2026-00004', severity: 'low', first_seen: '2026-05-27T00:00:00Z', source: 'ecr', kev: false },
    ];
    // Within EVU window (5d Moderate) at 1 day, so EVU is the basis, not indeterminate.
    const ledger = buildLedger(findings, emptyKev, { tier: 'moderate', now: NOW });
    expect(ledger[0]!.sla?.basis).toBe('evu');
    expect(ledger[0]!.sla?.indeterminate).toBe(false);
    expect(ledger[0]!.sla?.overdue).toBe(false);
  });

  it('terminal states (remediated/accepted) are never overdue', () => {
    const findings: LedgerEntry[] = [
      {
        cve: 'CVE-2021-44228',
        severity: 'critical',
        first_seen: '2021-01-01T00:00:00Z',
        evaluated_at: '2021-06-01T00:00:00Z',
        due: '2021-12-24',
        pain: 'N5',
        irv: true,
        lev: true,
        state: 'remediated',
        source: 'inspector2',
        kev: true,
      },
    ];
    const ledger = buildLedger(findings, emptyKev, { tier: 'low', now: NOW });
    expect(ledger[0]!.sla?.overdue).toBe(false);
  });

  it('VDR-TFR-EVU: an unevaluated finding past its eval latency is overdue', () => {
    const findings: LedgerEntry[] = [
      // Detected 10 days ago, never evaluated; Moderate EVU window = 5d → overdue.
      { cve: 'CVE-2026-00005', severity: 'high', first_seen: '2026-05-18T00:00:00Z', source: 'inspector2', kev: false },
    ];
    const ledger = buildLedger(findings, emptyKev, { tier: 'moderate', now: NOW });
    expect(ledger[0]!.sla?.basis).toBe('evu');
    expect(ledger[0]!.sla?.overdue).toBe(true);
  });
});

describe('vdr-report: summarizeVdr', () => {
  it('counts totals, KEV, breaches, severity, and oldest-open age', async () => {
    const kev = await fixtureCatalog();
    const findings: LedgerEntry[] = [
      // 1: KEV past due → breach.
      { cve: 'CVE-2021-44228', severity: 'critical', first_seen: '2025-01-01T00:00:00Z', source: 'inspector2', kev: false },
      // 2: KEV far-future due, recently evaluated → not a breach but counts as KEV.
      { cve: 'CVE-2099-00001', severity: 'high', first_seen: '2026-05-25T00:00:00Z', evaluated_at: '2026-05-26T00:00:00Z', source: 'ecr', kev: false },
      // 3: PVR breach (N5 IRV+LEV evaluated 30d ago, Low window 4d).
      {
        cve: 'CVE-2026-00006',
        severity: 'critical',
        first_seen: '2026-04-01T00:00:00Z',
        evaluated_at: '2026-04-28T00:00:00Z',
        pain: 'N5',
        irv: true,
        lev: true,
        source: 'scc',
        kev: false,
      },
      // 4: recently detected, within EVU → not a breach.
      { cve: 'CVE-2026-00007', severity: 'medium', first_seen: '2026-05-27T00:00:00Z', source: 'inspector2', kev: false },
    ];
    const ledger = buildLedger(findings, kev, { tier: 'low', now: NOW });
    const summary = summarizeVdr(ledger, NOW);

    expect(summary.total).toBe(4);
    expect(summary.kev_count).toBe(2);
    expect(summary.overdue).toBe(2); // entries 1 and 3
    expect(summary.sla_breaches).toHaveLength(2);
    expect(summary.by_severity.critical).toBe(2);
    expect(summary.by_severity.high).toBe(1);
    expect(summary.by_severity.medium).toBe(1);
    // Oldest open = entry 1 (first_seen 2025-01-01) → ~512 days before NOW.
    expect(summary.oldest_open_days).toBeGreaterThan(500);
  });

  it('handles an empty ledger deterministically', () => {
    const summary = summarizeVdr([], NOW);
    expect(summary.total).toBe(0);
    expect(summary.kev_count).toBe(0);
    expect(summary.overdue).toBe(0);
    expect(summary.oldest_open_days).toBe(0);
    expect(summary.sla_breaches).toEqual([]);
    expect(summary.by_severity).toEqual({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  });

  it('excludes terminal-state findings from oldest-open age', async () => {
    const kev = await fixtureCatalog();
    const findings: LedgerEntry[] = [
      { cve: 'CVE-2020-0001', severity: 'high', first_seen: '2020-01-01T00:00:00Z', state: 'remediated', source: 'ecr', kev: false },
      { cve: 'CVE-2026-00008', severity: 'low', first_seen: '2026-05-25T00:00:00Z', state: 'detected', source: 'ecr', kev: false },
    ];
    const ledger = buildLedger(findings, kev, { now: NOW });
    const summary = summarizeVdr(ledger, NOW);
    // The 2020 finding is remediated → ignored; oldest open is the 2026 one (~3 days).
    expect(summary.oldest_open_days).toBeLessThan(10);
  });
});
