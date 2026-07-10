/**
 * Canonical lister for per-requirement evidence files in an `out/` run.
 *
 * A run emits one JSON per requirement — KSI indicators (`KSI-*.json`) AND the
 * 163 FRR requirements (`ADS-*`, `CCM-*`, `VDR-*`, `SCN-*`, `FSI-*`, `ICP-*`,
 * `MAS-*`, `PVA-*`, `SCG-*`, `UCM-*`, `KSI-CSX-*`, …). Human-facing aggregators
 * (HTML report, findings CSV, run diff, anomaly feed) historically filtered on
 * the `KSI-` filename prefix, which SILENTLY DROPPED every FRR/VDR/CCM
 * requirement failure from those views. This shared lister fixes that: it selects
 * a file as evidence by SHAPE (`ksi_id` + `providers` + `rollup`), not by name —
 * matching what `family-rollup.ts` / `control-benchmark.ts` already do — so every
 * requirement's findings reach every report.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { EvidenceFile } from './envelope.ts';

/**
 * Non-evidence JSON outputs that live in `out/` alongside the envelopes. Kept a
 * superset of the per-emitter skip lists so nothing spurious is treated as a
 * requirement. `*-input.json` (e.g. `KSI-CSX-SUM-input.json`) is a collector
 * scratch file, not a requirement envelope.
 */
const NON_EVIDENCE_FILES = new Set([
  'pva-run-summary.json', 'manifest.json', 'manifest.tst.json', 'coverage-report.json',
  'family-rollup.json', 'vdr-report.json', 'crosswalk-report.json', 'diff-report.json',
  'anomaly-report.json', 'sbom-report.json', 'llm-prs.json', 'control-benchmark.json',
  'assessment-results.json', 'previous-run-snapshot.json',
  'inventory.json', 'inventory-oscal.json', 'inventory-cmdb.json', 'inventory-diff.json',
  'inventory-cost.json', 'inventory-coverage.json', 'risk-scores.json',
  'nist-r5-controls.generated.json', 'nist-r5-baselines.generated.json',
  'frmr-requirements.generated.json',
]);

/** True when a file name is a per-requirement evidence envelope by name convention. */
function isCandidateName(name: string): boolean {
  if (!name.endsWith('.json')) return false;
  if (NON_EVIDENCE_FILES.has(name)) return false;
  if (name.endsWith('-input.json')) return false; // collector scratch (e.g. KSI-CSX-SUM-input.json)
  return true;
}

/**
 * Read every per-requirement evidence file (KSI + FRR) from `outDir`. Selection
 * is by shape (`ksi_id` + `providers` array), so FRR/VDR/CCM/etc. requirements
 * are included, not just `KSI-*`. Unparseable / non-evidence files are skipped.
 * Returned sorted by `ksi_id` for deterministic output.
 */
export function listEvidenceFiles(outDir: string): EvidenceFile[] {
  const out: EvidenceFile[] = [];
  let names: string[] = [];
  try { names = readdirSync(outDir); } catch { return out; }
  for (const name of names) {
    if (!isCandidateName(name)) continue;
    let data: any;
    try { data = JSON.parse(readFileSync(join(outDir, name), 'utf8')); } catch { continue; }
    if (data && typeof data === 'object' && data.ksi_id && Array.isArray(data.providers) && data.rollup) {
      out.push(data as EvidenceFile);
    }
  }
  return out.sort((a, b) => a.ksi_id.localeCompare(b.ksi_id));
}
