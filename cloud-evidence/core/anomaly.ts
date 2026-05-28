/**
 * Anomaly detection over historical evidence runs.
 *
 * The diff-report.ts module compares one run to the previous run. That's
 * useful for "what changed today?" but misses gradual drift: e.g. a slow
 * uptick in failing findings across a domain, or a new rule appearing.
 *
 * This module compares the CURRENT run to a rolling window of N previous
 * runs (default 7) and flags:
 *   1. Findings whose pass/fail flipped to FAIL and stayed there for 2+ runs.
 *   2. KSI domains where failing-finding-count exceeded the window's max+1.
 *   3. Rules that appeared for the first time in this run (could be new
 *      coverage OR could be a bug — investigator decides).
 *   4. KSIs that completely regressed (passed = true → false).
 *
 * Storage:
 *   - On every run, we APPEND a slim snapshot to `out/anomaly-history.jsonl`
 *     (one JSON line per run: { run_id, finished_at, findings: [...] }).
 *   - The history file is owned by the orchestrator's working directory
 *     so re-running in a clean repo (CI ephemerally) requires the file to
 *     be checked-in or pulled from a stable location (e.g. S3 sync).
 *
 * Output:
 *   - `anomaly-report.json` summarizing detected anomalies.
 *   - Returns a count + the report so the orchestrator can notify on
 *     `--notify-on-anomaly` (separate from drift notifications).
 */
import { readFileSync, writeFileSync, existsSync, appendFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import type { EvidenceFile } from './envelope.ts';
import { log } from './log.ts';

const HISTORY_FILE = 'anomaly-history.jsonl';
const REPORT_FILE = 'anomaly-report.json';
const DEFAULT_WINDOW = 7;

interface FindingSnapshot {
  ksi_id: string;
  rule: string;
  passed: boolean;
  severity: string;
}

interface RunSnapshot {
  run_id: string;
  finished_at: string;
  findings: FindingSnapshot[];
}

export interface Anomaly {
  type: 'persistent_regression' | 'spike' | 'new_rule' | 'ksi_full_regression';
  ksi_id?: string;
  rule?: string;
  description: string;
  severity_hint?: string;
  /** Numeric context for spike-class anomalies. */
  current_value?: number;
  baseline_max?: number;
  baseline_mean?: number;
}

export interface AnomalyReport {
  generated_at: string;
  current_run_id: string;
  window_runs: number;
  anomalies: Anomaly[];
  summary: {
    total: number;
    by_type: Record<string, number>;
  };
}

function readKsiEvidence(outDir: string): EvidenceFile[] {
  const out: EvidenceFile[] = [];
  for (const f of readdirSync(outDir)) {
    if (!f.startsWith('KSI-') || !f.endsWith('.json')) continue;
    if (f.includes('CSX-SUM')) continue;
    try {
      out.push(JSON.parse(readFileSync(resolve(outDir, f), 'utf8')));
    } catch { /* ignore */ }
  }
  return out;
}

function flattenFindings(evidence: EvidenceFile[]): FindingSnapshot[] {
  const out: FindingSnapshot[] = [];
  for (const ef of evidence) {
    for (const p of ef.providers) {
      for (const f of p.findings) {
        out.push({ ksi_id: ef.ksi_id, rule: f.rule, passed: f.passed, severity: f.severity });
      }
    }
  }
  return out;
}

function loadHistory(historyPath: string): RunSnapshot[] {
  if (!existsSync(historyPath)) return [];
  const lines = readFileSync(historyPath, 'utf8').split('\n').filter(Boolean);
  const out: RunSnapshot[] = [];
  for (const line of lines) {
    try {
      out.push(JSON.parse(line));
    } catch { /* skip malformed */ }
  }
  return out;
}

/**
 * Append the current run's findings to the history file. Caps history to
 * the most-recent 500 runs to keep the file bounded.
 */
function appendHistory(historyPath: string, snap: RunSnapshot): void {
  appendFileSync(historyPath, JSON.stringify(snap) + '\n');
  // Trim if huge (cheap check)
  try {
    const all = loadHistory(historyPath);
    if (all.length > 500) {
      const trimmed = all.slice(-500);
      writeFileSync(historyPath, trimmed.map((s) => JSON.stringify(s)).join('\n') + '\n');
    }
  } catch { /* ignore */ }
}

export interface AnomalyOptions {
  outDir: string;
  runId: string;
  finishedAt: string;
  /** How many previous runs to use as baseline. Default 7. */
  windowSize?: number;
}

/**
 * Detect anomalies vs the rolling history, then append this run's snapshot
 * so the next invocation has context.
 */
export function detectAnomalies(opts: AnomalyOptions): AnomalyReport {
  const windowSize = opts.windowSize ?? DEFAULT_WINDOW;
  const historyPath = resolve(opts.outDir, HISTORY_FILE);
  const history = loadHistory(historyPath).slice(-windowSize); // last N runs

  const current = flattenFindings(readKsiEvidence(opts.outDir));
  const anomalies: Anomaly[] = [];

  // Build a lookup of (ksi_id, rule) → passed[] across history
  const ruleHistory = new Map<string, boolean[]>();
  for (const h of history) {
    for (const f of h.findings) {
      const key = `${f.ksi_id}|${f.rule}`;
      if (!ruleHistory.has(key)) ruleHistory.set(key, []);
      ruleHistory.get(key)!.push(f.passed);
    }
  }

  // 1. Persistent regression: failing now AND failed in previous 1+ runs
  // 3. New rule: appears in current but never in history
  const currentRuleSet = new Set<string>();
  for (const f of current) {
    const key = `${f.ksi_id}|${f.rule}`;
    currentRuleSet.add(key);
    const hist = ruleHistory.get(key) ?? [];

    if (hist.length === 0) {
      anomalies.push({
        type: 'new_rule',
        ksi_id: f.ksi_id,
        rule: f.rule,
        description: `Finding rule "${f.rule}" first observed in this run for ${f.ksi_id}.`,
        severity_hint: f.severity,
      });
    } else if (!f.passed) {
      const consecutiveFails = (() => {
        let n = 0;
        for (let i = hist.length - 1; i >= 0; i--) {
          if (!hist[i]) n++; else break;
        }
        return n;
      })();
      if (consecutiveFails >= 1) {
        anomalies.push({
          type: 'persistent_regression',
          ksi_id: f.ksi_id,
          rule: f.rule,
          description: `${f.ksi_id}.${f.rule} has been failing for ${consecutiveFails + 1} consecutive runs (including this one).`,
          severity_hint: f.severity,
        });
      }
    }
  }

  // 2. Spike: per-domain failing-finding count exceeded the window max by 2+
  const currentFailsByDomain: Record<string, number> = {};
  for (const f of current) {
    if (!f.passed) {
      const dom = f.ksi_id.split('-')[1] ?? 'OTHER';
      currentFailsByDomain[dom] = (currentFailsByDomain[dom] ?? 0) + 1;
    }
  }
  // Build per-domain baseline. Record 0 for runs that had no failures in
  // a domain — otherwise a domain that's been clean for the whole window
  // (baseline_max = 0) wouldn't generate a spike when it suddenly fails.
  const domainsSeen = new Set<string>();
  for (const h of history) for (const f of h.findings) domainsSeen.add(f.ksi_id.split('-')[1] ?? 'OTHER');
  for (const f of current) domainsSeen.add(f.ksi_id.split('-')[1] ?? 'OTHER');
  const histFailsByDomainPerRun: Record<string, number[]> = {};
  for (const h of history) {
    const byDom: Record<string, number> = {};
    for (const dom of domainsSeen) byDom[dom] = 0;
    for (const f of h.findings) {
      if (!f.passed) {
        const dom = f.ksi_id.split('-')[1] ?? 'OTHER';
        byDom[dom] = (byDom[dom] ?? 0) + 1;
      }
    }
    for (const [d, n] of Object.entries(byDom)) {
      if (!histFailsByDomainPerRun[d]) histFailsByDomainPerRun[d] = [];
      histFailsByDomainPerRun[d].push(n);
    }
  }
  for (const [dom, current] of Object.entries(currentFailsByDomain)) {
    const baseline = histFailsByDomainPerRun[dom] ?? [];
    if (baseline.length === 0) continue;
    const max = Math.max(...baseline);
    const mean = baseline.reduce((a, b) => a + b, 0) / baseline.length;
    if (current > max + 1) {
      anomalies.push({
        type: 'spike',
        ksi_id: `KSI-${dom}-*`,
        description: `${dom} domain has ${current} failing findings; previous max in window was ${max} (mean ${mean.toFixed(1)}).`,
        current_value: current,
        baseline_max: max,
        baseline_mean: Number(mean.toFixed(2)),
      });
    }
  }

  // 4. KSI full regression: any KSI that previously had pass=true for all findings,
  //    but now has at least one failing finding.
  const currentKsiPassMap = new Map<string, boolean>();
  for (const f of current) {
    const prev = currentKsiPassMap.get(f.ksi_id);
    currentKsiPassMap.set(f.ksi_id, (prev ?? true) && f.passed);
  }
  if (history.length > 0) {
    const lastRun = history[history.length - 1]!;  // length > 0 ensures defined
    const prevKsiPassMap = new Map<string, boolean>();
    for (const f of lastRun.findings) {
      const prev = prevKsiPassMap.get(f.ksi_id);
      prevKsiPassMap.set(f.ksi_id, (prev ?? true) && f.passed);
    }
    for (const [ksi, nowPass] of currentKsiPassMap) {
      if (!nowPass && prevKsiPassMap.get(ksi) === true) {
        anomalies.push({
          type: 'ksi_full_regression',
          ksi_id: ksi,
          description: `${ksi} regressed from all-passing in the previous run to at least one failing finding.`,
        });
      }
    }
  }

  const by_type: Record<string, number> = {};
  for (const a of anomalies) by_type[a.type] = (by_type[a.type] ?? 0) + 1;

  const report: AnomalyReport = {
    generated_at: new Date().toISOString(),
    current_run_id: opts.runId,
    window_runs: history.length,
    anomalies,
    summary: { total: anomalies.length, by_type },
  };

  writeFileSync(resolve(opts.outDir, REPORT_FILE), JSON.stringify(report, null, 2));

  // Append the current run's snapshot for future invocations.
  appendHistory(historyPath, {
    run_id: opts.runId,
    finished_at: opts.finishedAt,
    findings: current,
  });

  log.info({
    event: 'anomaly.report_emitted',
    total: anomalies.length,
    persistent_regressions: by_type.persistent_regression ?? 0,
    spikes: by_type.spike ?? 0,
    new_rules: by_type.new_rule ?? 0,
    ksi_regressions: by_type.ksi_full_regression ?? 0,
  });

  return report;
}
