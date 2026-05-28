/**
 * NIST SP 800-53 control benchmark.
 *
 * Rolls the collector's KSI/FRR findings UP to NIST 800-53 controls and scores
 * each control in the chosen baseline. Lets the end user benchmark their cloud
 * infrastructure against NIST 800-53 at Low / Moderate / High — for both
 * frameworks:
 *
 *   - framework="rev5": the in-scope control set is the full NIST SP 800-53B Rev5
 *     baseline for the level (149 / 287 / 370 controls). Honestly shows which
 *     baseline controls have automated cloud evidence vs which still need manual
 *     assessment (most of a baseline is not cloud-API-testable).
 *   - framework="20x": the in-scope control set is the controls referenced by the
 *     20x KSIs/FRRs evaluated in the run — "how covered are the controls 20x cares
 *     about" at this level.
 *
 * A control's status is derived from the findings that map to it (via each
 * finding's / file's nist_controls):
 *   satisfied            — has mapping findings, all passed
 *   partially-satisfied  — mapping findings are mixed
 *   not-satisfied        — has mapping findings, all failed
 *   not-assessed         — no finding maps to it (no automated evidence)
 *
 * Pure core (`benchmarkControls`) + a disk reader (`buildControlBenchmark`).
 * Read-only.
 */
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { EvidenceFile, ImpactTier } from './envelope.ts';
import { controlDetails } from './nist-r5.ts';

const __dirname = dirname(fileURLToPath(import.meta.url));
const BASELINES_PATH = resolve(__dirname, '..', 'docs', 'nist-r5-baselines.generated.json');

export type BenchmarkFramework = 'rev5' | '20x';
export type ControlStatus = 'satisfied' | 'partially-satisfied' | 'not-satisfied' | 'not-assessed';

export interface ControlContribution {
  requirement_id: string;
  rule: string;
  passed: boolean;
  awareness_only: boolean;
}

export interface ControlResult {
  id: string;
  name: string | null;
  family: string | null;
  status: ControlStatus;
  /** Findings/requirements that produced evidence mapping to this control. */
  addressed_by: ControlContribution[];
}

export interface ControlBenchmark {
  framework: BenchmarkFramework;
  impact_level: ImpactTier;
  control_source: string;
  generated_at: string;
  totals: {
    in_scope: number;
    satisfied: number;
    partially_satisfied: number;
    not_satisfied: number;
    not_assessed: number;
    /** satisfied / (in_scope − not_assessed), i.e. of the controls we have evidence for. */
    assessed_pass_rate: number;
    /** satisfied / in_scope, i.e. share of the whole baseline with passing automated evidence. */
    baseline_coverage_rate: number;
  };
  controls: ControlResult[];
}

interface Baselines { low: string[]; moderate: string[]; high: string[]; _source?: string }

export function loadBaselines(path = process.env.NIST_BASELINES_PATH ?? BASELINES_PATH): Baselines {
  if (!existsSync(path)) {
    throw new Error(
      `NIST baseline membership not found at ${path}. Regenerate with ` +
        `\`node scripts/extract-nist-baselines.mjs\` (needs network or a cached OSCAL catalog).`,
    );
  }
  return JSON.parse(readFileSync(path, 'utf8')) as Baselines;
}

/** All controls a finding addresses: its own nist_controls, else its file's. */
function controlsForFinding(file: Partial<EvidenceFile>, findingControls: string[] | undefined): string[] {
  const fc = (findingControls ?? []).map((c) => c.toLowerCase());
  if (fc.length > 0) return fc;
  return (file.nist_controls ?? []).map((c) => c.toLowerCase());
}

/**
 * Pure: benchmark a set of evidence files against an in-scope control id set.
 */
export function benchmarkControls(
  files: Array<Partial<EvidenceFile>>,
  inScope: string[],
  framework: BenchmarkFramework,
  level: ImpactTier,
): ControlBenchmark {
  // control id (lowercase) → contributions
  const map = new Map<string, ControlContribution[]>();
  for (const id of inScope) map.set(id.toLowerCase(), []);

  for (const file of files) {
    if (!file || !file.ksi_id || !Array.isArray(file.providers)) continue;
    const awareness = file.awareness_only === true;
    for (const p of file.providers) {
      for (const f of p.findings ?? []) {
        const controls = controlsForFinding(file, f.nist_controls);
        for (const c of controls) {
          const bucket = map.get(c);
          if (!bucket) continue; // control not in scope for this framework/level
          bucket.push({ requirement_id: file.ksi_id, rule: f.rule, passed: f.passed, awareness_only: awareness });
        }
      }
    }
  }

  const details = new Map(controlDetails(inScope).map((d, i) => [inScope[i]!.toLowerCase(), d]));
  const controls: ControlResult[] = [];
  let satisfied = 0, partial = 0, notSat = 0, notAssessed = 0;

  for (const id of inScope) {
    const key = id.toLowerCase();
    const contribs = map.get(key) ?? [];
    // Provider-relevant contributions for status (awareness items don't make a
    // control "satisfied" on their own, but if they're the only signal we treat
    // it as not-assessed for scoring while still listing them).
    const scoring = contribs.filter((c) => !c.awareness_only);
    let status: ControlStatus;
    if (scoring.length === 0) { status = 'not-assessed'; notAssessed++; }
    else if (scoring.every((c) => c.passed)) { status = 'satisfied'; satisfied++; }
    else if (scoring.every((c) => !c.passed)) { status = 'not-satisfied'; notSat++; }
    else { status = 'partially-satisfied'; partial++; }
    const d = details.get(key);
    controls.push({ id: key, name: d?.name ?? null, family: d?.family ?? null, status, addressed_by: contribs });
  }

  const inScopeN = inScope.length;
  const assessed = inScopeN - notAssessed;
  return {
    framework,
    impact_level: level,
    control_source: framework === 'rev5' ? 'NIST SP 800-53B Rev5 baseline' : '20x KSI-referenced NIST 800-53 controls',
    generated_at: new Date().toISOString(),
    totals: {
      in_scope: inScopeN,
      satisfied,
      partially_satisfied: partial,
      not_satisfied: notSat,
      not_assessed: notAssessed,
      assessed_pass_rate: assessed > 0 ? satisfied / assessed : 0,
      baseline_coverage_rate: inScopeN > 0 ? satisfied / inScopeN : 0,
    },
    controls: controls.sort((a, b) => a.id.localeCompare(b.id)),
  };
}

/** Resolve the in-scope control id set for a framework + level. */
export function inScopeControls(
  framework: BenchmarkFramework,
  level: ImpactTier,
  files: Array<Partial<EvidenceFile>>,
  baselines = loadBaselines(),
): string[] {
  if (framework === 'rev5') return baselines[level] ?? [];
  // 20x: the union of NIST controls the evaluated KSIs/FRRs reference.
  const set = new Set<string>();
  for (const f of files) {
    for (const c of f.nist_controls ?? []) set.add(c.toLowerCase());
    for (const p of f.providers ?? []) for (const fi of p.findings ?? []) for (const c of fi.nist_controls ?? []) set.add(c.toLowerCase());
  }
  return [...set].sort();
}

/** Read evidence files from `outDir` (skipping non-evidence outputs). */
function loadEvidenceFiles(outDir: string): Array<Partial<EvidenceFile>> {
  const skip = new Set(['pva-run-summary.json', 'manifest.json', 'coverage-report.json', 'family-rollup.json', 'vdr-report.json', 'crosswalk-report.json', 'diff-report.json', 'anomaly-report.json', 'sbom-report.json', 'llm-prs.json', 'control-benchmark.json', 'nist-r5-controls.generated.json', 'nist-r5-baselines.generated.json', 'frmr-requirements.generated.json']);
  const out: Array<Partial<EvidenceFile>> = [];
  let names: string[] = [];
  try { names = readdirSync(outDir); } catch { return out; }
  for (const name of names) {
    if (!name.endsWith('.json') || skip.has(name)) continue;
    try {
      const data = JSON.parse(readFileSync(join(outDir, name), 'utf8'));
      if (data && typeof data === 'object' && data.ksi_id && data.providers) out.push(data);
    } catch { /* skip */ }
  }
  return out;
}

/** Build the control benchmark for a run's output directory. */
export function buildControlBenchmark(
  outDir: string,
  opts: { framework: BenchmarkFramework; level: ImpactTier },
): ControlBenchmark {
  const files = loadEvidenceFiles(outDir);
  const inScope = inScopeControls(opts.framework, opts.level, files);
  return benchmarkControls(files, inScope, opts.framework, opts.level);
}
