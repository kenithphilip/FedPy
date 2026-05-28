/**
 * Family roll-up: aggregate per-requirement evidence files into a per-family
 * compliance posture for the chosen impact tier. Answers "how is the IAM family
 * doing?" / "how much of VDR is attested vs gapped?" at a glance.
 *
 * A requirement's family is its `family` field (when present) or the second
 * segment of its id (KSI-IAM-MFA → IAM, VDR-CSO-DET → VDR). Awareness-only items
 * (obligating FedRAMP/agency/3PAO) are counted separately and excluded from the
 * provider's pass/fail.
 *
 * Pure core (`rollupFromEvidence`) + a thin disk reader (`buildFamilyRollup`).
 * Read-only.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { EvidenceFile, ImpactTier } from './envelope.ts';

export interface FamilyStat {
  family: string;
  total: number;
  passed: number;
  failed: number;
  awareness: number;
  /** Of the provider-scoped (non-awareness) requirements, how many passed. */
  pass_rate: number; // 0..1
  by_category: { 'ksi-indicator': number; 'frr-requirement': number; other: number };
}

export interface FamilyRollupResult {
  impact_level?: ImpactTier;
  families: FamilyStat[];
  totals: { total: number; passed: number; failed: number; awareness: number; pass_rate: number };
}

function familyOf(f: Pick<EvidenceFile, 'family' | 'ksi_id'>): string {
  if (f.family) return f.family;
  const parts = String(f.ksi_id ?? '').split('-');
  return parts.length >= 2 ? parts[1]! : (f.ksi_id ?? 'UNKNOWN');
}

/** Pure: roll up a set of (parsed) evidence files into per-family stats. */
export function rollupFromEvidence(files: Array<Partial<EvidenceFile>>): FamilyRollupResult {
  const byFamily = new Map<string, FamilyStat>();
  let impact: ImpactTier | undefined;

  for (const f of files) {
    if (!f || !f.ksi_id) continue;
    if (f.impact_level && !impact) impact = f.impact_level;
    const fam = familyOf(f as EvidenceFile);
    let stat = byFamily.get(fam);
    if (!stat) {
      stat = { family: fam, total: 0, passed: 0, failed: 0, awareness: 0, pass_rate: 0, by_category: { 'ksi-indicator': 0, 'frr-requirement': 0, other: 0 } };
      byFamily.set(fam, stat);
    }
    stat.total++;
    if (f.category === 'ksi-indicator') stat.by_category['ksi-indicator']++;
    else if (f.category === 'frr-requirement') stat.by_category['frr-requirement']++;
    else stat.by_category.other++;

    if (f.awareness_only) {
      stat.awareness++;
    } else if (f.rollup?.pass) {
      stat.passed++;
    } else {
      stat.failed++;
    }
  }

  const families = [...byFamily.values()].map((s) => {
    const providerScoped = s.passed + s.failed;
    s.pass_rate = providerScoped > 0 ? s.passed / providerScoped : 1;
    return s;
  }).sort((a, b) => a.family.localeCompare(b.family));

  const totals = families.reduce(
    (acc, s) => {
      acc.total += s.total; acc.passed += s.passed; acc.failed += s.failed; acc.awareness += s.awareness;
      return acc;
    },
    { total: 0, passed: 0, failed: 0, awareness: 0, pass_rate: 0 },
  );
  const ps = totals.passed + totals.failed;
  totals.pass_rate = ps > 0 ? totals.passed / ps : 1;

  return { impact_level: impact, families, totals };
}

/** Read every *.json evidence file in `outDir` and roll it up by family. */
export function buildFamilyRollup(outDir: string): FamilyRollupResult {
  const files: Array<Partial<EvidenceFile>> = [];
  let names: string[] = [];
  try { names = readdirSync(outDir); } catch { return rollupFromEvidence([]); }
  for (const name of names) {
    if (!name.endsWith('.json')) continue;
    // Skip non-evidence outputs.
    if (['pva-run-summary.json', 'manifest.json', 'coverage-report.json', 'family-rollup.json', 'vdr-report.json', 'crosswalk-report.json', 'diff-report.json', 'anomaly-report.json', 'sbom-report.json', 'llm-prs.json'].includes(name)) continue;
    try {
      const data = JSON.parse(readFileSync(join(outDir, name), 'utf8'));
      if (data && typeof data === 'object' && data.ksi_id && data.rollup) files.push(data);
    } catch { /* skip unparseable */ }
  }
  return rollupFromEvidence(files);
}
