/**
 * Read a FedPy `cloud-evidence` run directory (read-only, offline).
 *
 * A run's `out/` holds:
 *   - `inventory.json`      — the rich InventorySnapshot (every asset the
 *                             collectors enumerated). Source of truth for inventory.
 *   - `KSI-*.json` / FRR    — one per-requirement evidence envelope (EvidenceFile),
 *     evidence files          each carrying providers[].findings[] with pass/fail
 *                             + affected_resources on failing findings.
 *
 * This module only reads those artifacts; it makes no cloud calls and imports no
 * cloud SDK. All FedPy types are imported so the join can never drift from the
 * shapes the collectors actually emit.
 */
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { InventorySnapshot, CloudAsset } from '../../cloud-evidence/core/inventory-workbook.ts';
import type { EvidenceFile } from '../../cloud-evidence/core/envelope.ts';

/**
 * Non-evidence JSON files that live in `out/` alongside the per-requirement
 * envelopes. Kept in sync with the skip sets in cloud-evidence's own
 * `control-benchmark.ts` / `inventory-workbook.ts` readers.
 */
const NON_EVIDENCE_FILES = new Set([
  'pva-run-summary.json', 'manifest.json', 'coverage-report.json', 'family-rollup.json',
  'vdr-report.json', 'crosswalk-report.json', 'diff-report.json', 'anomaly-report.json',
  'sbom-report.json', 'llm-prs.json', 'control-benchmark.json', 'assessment-results.json',
  'inventory.json', 'inventory-oscal.json', 'inventory-cmdb.json', 'inventory-diff.json',
  'inventory-cost.json', 'inventory-coverage.json',
  'nist-r5-controls.generated.json', 'nist-r5-baselines.generated.json',
  'frmr-requirements.generated.json',
]);

export class RunLoadError extends Error {}

/** Load the rich inventory snapshot. Throws an actionable error if absent/bad. */
export function loadInventory(outDir: string): InventorySnapshot {
  const path = join(outDir, 'inventory.json');
  if (!existsSync(path)) {
    throw new RunLoadError(
      `No inventory.json in ${outDir}. Run the collector with --inventory-workbook first ` +
        `(e.g. \`npm run collect -- --inventory-workbook\` in cloud-evidence), or pass ` +
        `--collect to have this tool run it for you.`,
    );
  }
  let snap: InventorySnapshot;
  try {
    snap = JSON.parse(readFileSync(path, 'utf8')) as InventorySnapshot;
  } catch (e: any) {
    throw new RunLoadError(`inventory.json is not valid JSON: ${e?.message ?? e}`);
  }
  if (!snap || !Array.isArray(snap.assets)) {
    throw new RunLoadError(`inventory.json has no "assets" array — is it a FedPy inventory snapshot?`);
  }
  return snap;
}

/**
 * Load every per-requirement evidence envelope from `outDir`. An envelope is any
 * `.json` (outside the non-evidence set) that has a `ksi_id` + `providers` array.
 * Returns [] when the directory has none (a pure inventory-only run).
 */
export function loadEvidenceFiles(outDir: string): EvidenceFile[] {
  const out: EvidenceFile[] = [];
  let names: string[] = [];
  try { names = readdirSync(outDir); } catch { return out; }
  for (const name of names.sort()) {
    if (!name.endsWith('.json') || NON_EVIDENCE_FILES.has(name)) continue;
    let data: any;
    try { data = JSON.parse(readFileSync(join(outDir, name), 'utf8')); } catch { continue; }
    if (data && typeof data === 'object' && data.ksi_id && Array.isArray(data.providers)) {
      out.push(data as EvidenceFile);
    }
  }
  return out;
}

export interface LoadedRun {
  outDir: string;
  snapshot: InventorySnapshot;
  assets: CloudAsset[];
  evidence: EvidenceFile[];
  /** Account/project/subscription ids observed across the inventory. */
  accountIds: string[];
  /** Locations (regions/zones) observed across the inventory. */
  locations: string[];
  /**
   * Resource identifiers that a scan/assessment KSI reported having ASSESSED
   * (from evidence `assessed_resource_ids`). An assessed asset with no failing
   * finding is genuinely "compliant" — this is what lets that status populate
   * (failing findings alone can't, since only failures carry affected_resources).
   */
  assessedIdentifiers: Set<string>;
  /** Detective/data service availability (from service-availability.json), if present. */
  serviceAvailability: ServiceAvailabilityRow[];
}

export interface ServiceAvailabilityRow {
  service: string;
  status: string;   // ENABLED / DISABLED / NOT_AVAILABLE / ACCESS_DENIED / UNKNOWN
  impact: string;
  detail: string;
}

/** Read service-availability.json (written by the collector). [] if absent. */
export function loadServiceAvailability(outDir: string): ServiceAvailabilityRow[] {
  const path = join(outDir, 'service-availability.json');
  if (!existsSync(path)) return [];
  try {
    const d = JSON.parse(readFileSync(path, 'utf8'));
    return Array.isArray(d?.services) ? d.services : [];
  } catch { return []; }
}

/** VDR / vulnerability-scan KSIs whose assessed resources count as "scanned". */
const SCAN_KSI = /VDR|SVC-VRI|SCR-MON|SCR-MIT|MLA/i;

/**
 * Collect the `assessed_resource_ids` published by scan/assessment evidence
 * entries (mirrors cloud-evidence's `readInventoryContext`). These are the assets
 * a collector actually looked at — the basis for a positive "compliant" verdict.
 */
export function collectAssessedIdentifiers(evidence: EvidenceFile[]): Set<string> {
  const ids = new Set<string>();
  for (const ef of evidence) {
    const isScan = SCAN_KSI.test(String(ef.ksi_id));
    for (const p of ef.providers ?? []) {
      // Passing findings that name resources count as assessed-and-clean.
      for (const f of p.findings ?? []) {
        if (!f.passed) continue;
        for (const r of f.gap?.affected_resources ?? []) {
          if (r?.identifier && r.identifier !== 'none') ids.add(r.identifier);
        }
      }
      if (!isScan) continue;
      for (const e of p.evidence ?? []) {
        const arr = (e?.data as { assessed_resource_ids?: unknown })?.assessed_resource_ids;
        if (!Array.isArray(arr)) continue;
        for (const id of arr) if (typeof id === 'string' && id.trim() && id !== 'none') ids.add(id);
      }
    }
  }
  return ids;
}

/** Load and lightly summarize a full run directory. */
export function loadRun(outDir: string): LoadedRun {
  const snapshot = loadInventory(outDir);
  const evidence = loadEvidenceFiles(outDir);
  const assets = snapshot.assets;
  const accountIds = [...new Set(assets.map((a) => a.accountId).filter((x): x is string => !!x))].sort();
  const locations = [...new Set(assets.map((a) => a.location).filter((x): x is string => !!x))].sort();
  const assessedIdentifiers = collectAssessedIdentifiers(evidence);
  const serviceAvailability = loadServiceAvailability(outDir);
  return { outDir, snapshot, assets, evidence, accountIds, locations, assessedIdentifiers, serviceAvailability };
}
