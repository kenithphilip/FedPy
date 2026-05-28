/**
 * Run-over-run diff report.
 * Reads current evidence files + a previous-run snapshot (if provided) and emits:
 *   - out/diff-report.json — structured diff
 *   - out/diff-report.html — human-readable diff (auditor-friendly)
 *
 * "previous-run snapshot" is a single JSON file produced by snapshotRun() below;
 * each run produces one and the next run reads it. Stored as out/previous-run-snapshot.json.
 */
import { readdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { EvidenceFile } from './envelope.ts';

interface FindingState { rule: string; passed: boolean; severity: string; affected_count: number; }
interface KsiSnapshot { ksi_id: string; pass: boolean; findings: FindingState[]; }
interface RunSnapshot { run_id: string; collected_at: string; ksis: KsiSnapshot[]; }

export function snapshotRun(outDir: string, snapshotPath: string): RunSnapshot {
  const ksis: KsiSnapshot[] = [];
  for (const f of readdirSync(outDir)) {
    if (!f.startsWith('KSI-') || !f.endsWith('.json')) continue;
    if (f === 'KSI-CSX-SUM-input.json') continue;
    let data: EvidenceFile;
    try { data = JSON.parse(readFileSync(join(outDir, f), 'utf8')); } catch { continue; }
    const findings: FindingState[] = data.providers.flatMap((p) => p.findings.map((x) => ({
      rule: `${p.provider}:${x.rule}`,
      passed: x.passed,
      severity: x.severity,
      affected_count: x.gap?.affected_resources?.length ?? 0,
    })));
    ksis.push({ ksi_id: data.ksi_id, pass: data.rollup.pass, findings });
  }
  // Read the first KSI evidence file once to recover the run_id. Defensive
  // against a malformed/truncated file so the snapshot still gets written.
  let runId = '';
  if (ksis[0]) {
    try {
      const first = JSON.parse(readFileSync(join(outDir, `${ksis[0].ksi_id}.json`), 'utf8'));
      runId = first?.run_id ?? '';
    } catch { /* leave runId empty; snapshot is still useful for diffing */ }
  }
  const snap: RunSnapshot = {
    run_id: runId,
    collected_at: new Date().toISOString(),
    ksis,
  };
  writeFileSync(snapshotPath, JSON.stringify(snap, null, 2));
  return snap;
}

interface FindingChange { rule: string; previous: FindingState | null; current: FindingState | null; change: 'regressed' | 'fixed' | 'new' | 'removed' | 'affected_count_grew' | 'affected_count_shrank'; }
interface KsiDiff { ksi_id: string; previous_pass?: boolean; current_pass?: boolean; finding_changes: FindingChange[]; }

export interface DiffSummary {
  current_run: string;
  previous_run: string | null;
  total_changes: number;
  ksi_diffs: KsiDiff[];
  regressed_count: number;
  fixed_count: number;
  new_findings_count: number;
}

export function diffReport(currentOutDir: string, previousSnapshotPath: string, diffJsonPath: string, diffHtmlPath: string): DiffSummary {
  const current = snapshotRun(currentOutDir, '/tmp/cev-current-tmp.json'); // not persisted
  const ksiCurrent = new Map(current.ksis.map((k) => [k.ksi_id, k]));

  let previous: RunSnapshot | null = null;
  if (existsSync(previousSnapshotPath)) {
    try { previous = JSON.parse(readFileSync(previousSnapshotPath, 'utf8')); } catch { /* */ }
  }
  const ksiPrevious = new Map((previous?.ksis ?? []).map((k) => [k.ksi_id, k]));

  const ksiDiffs: KsiDiff[] = [];
  let regressed = 0, fixed = 0, newFindings = 0;
  const allKsis = new Set([...ksiCurrent.keys(), ...ksiPrevious.keys()]);

  for (const ksiId of allKsis) {
    const c = ksiCurrent.get(ksiId);
    const p = ksiPrevious.get(ksiId);
    const changes: FindingChange[] = [];
    const findingsCurrent = new Map((c?.findings ?? []).map((f) => [f.rule, f]));
    const findingsPrev = new Map((p?.findings ?? []).map((f) => [f.rule, f]));
    const allRules = new Set([...findingsCurrent.keys(), ...findingsPrev.keys()]);
    for (const rule of allRules) {
      const cf = findingsCurrent.get(rule) ?? null;
      const pf = findingsPrev.get(rule) ?? null;
      if (!pf && cf) {
        changes.push({ rule, previous: null, current: cf, change: 'new' });
        newFindings++;
      } else if (pf && !cf) {
        changes.push({ rule, previous: pf, current: null, change: 'removed' });
      } else if (pf && cf) {
        if (pf.passed && !cf.passed) { changes.push({ rule, previous: pf, current: cf, change: 'regressed' }); regressed++; }
        else if (!pf.passed && cf.passed) { changes.push({ rule, previous: pf, current: cf, change: 'fixed' }); fixed++; }
        else if (cf.affected_count > pf.affected_count) {
          changes.push({ rule, previous: pf, current: cf, change: 'affected_count_grew' });
        } else if (cf.affected_count < pf.affected_count) {
          changes.push({ rule, previous: pf, current: cf, change: 'affected_count_shrank' });
        }
      }
    }
    if (changes.length > 0 || (p && c && p.pass !== c.pass)) {
      ksiDiffs.push({
        ksi_id: ksiId,
        previous_pass: p?.pass,
        current_pass: c?.pass,
        finding_changes: changes,
      });
    }
  }

  const summary: DiffSummary = {
    current_run: current.run_id,
    previous_run: previous?.run_id ?? null,
    total_changes: ksiDiffs.reduce((s, k) => s + k.finding_changes.length, 0),
    ksi_diffs: ksiDiffs.sort((a, b) => {
      // Regressions first, then fixes, then everything else
      const sev = (k: KsiDiff) => k.finding_changes.some((c) => c.change === 'regressed') ? 0 :
                                  k.finding_changes.some((c) => c.change === 'new') ? 1 :
                                  k.finding_changes.some((c) => c.change === 'fixed') ? 2 : 3;
      return sev(a) - sev(b);
    }),
    regressed_count: regressed,
    fixed_count: fixed,
    new_findings_count: newFindings,
  };

  writeFileSync(diffJsonPath, JSON.stringify(summary, null, 2));
  writeFileSync(diffHtmlPath, renderDiffHtml(summary));
  return summary;
}

function esc(s: unknown): string {
  if (s == null) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function renderDiffHtml(s: DiffSummary): string {
  const changeIcon: Record<string, string> = {
    regressed: '🔴', fixed: '🟢', new: '🟡', removed: '⚪',
    affected_count_grew: '🟠', affected_count_shrank: '🔵',
  };
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>Diff Report</title>
<style>
  body{font:14px -apple-system,system-ui,sans-serif;background:#f6f8fa;color:#1f2328;max-width:1100px;margin:0 auto;padding:20px;}
  h1{font-size:20px;margin:0 0 6px;}
  h2{font-size:14px;margin:18px 0 4px;}
  table{width:100%;border-collapse:collapse;background:white;border:1px solid #d1d9e0;border-radius:8px;}
  th,td{padding:6px 10px;border-bottom:1px solid #d1d9e0;font-size:13px;text-align:left;}
  .mono{font-family:ui-monospace,Menlo,monospace;font-size:12px;}
  .pill{padding:1px 6px;border-radius:999px;font-size:11px;}
  .pill.regressed{background:#ffebe9;color:#cf222e;}
  .pill.fixed{background:#dafbe1;color:#1a7f37;}
  .pill.new{background:#fff8c5;color:#9a6700;}
  .scoreboard{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:12px 0;}
  .card{background:white;border:1px solid #d1d9e0;border-radius:8px;padding:10px;}
  .card .v{font-size:22px;font-weight:600;}
  .card .l{font-size:11px;text-transform:uppercase;color:#59636e;}
  .card.red .v{color:#cf222e;}
  .card.green .v{color:#1a7f37;}
</style></head><body>
<h1>Cloud Evidence — Run Diff</h1>
<p>Current: <span class="mono">${esc(s.current_run)}</span>${s.previous_run ? ` · vs previous: <span class="mono">${esc(s.previous_run)}</span>` : ' · <em>no previous run</em>'}</p>
<div class="scoreboard">
  <div class="card red"><div class="v">${s.regressed_count}</div><div class="l">Regressed (pass→fail)</div></div>
  <div class="card green"><div class="v">${s.fixed_count}</div><div class="l">Fixed (fail→pass)</div></div>
  <div class="card"><div class="v">${s.new_findings_count}</div><div class="l">New findings</div></div>
  <div class="card"><div class="v">${s.total_changes}</div><div class="l">Total changes</div></div>
</div>
${s.ksi_diffs.map((k) => `
  <h2 class="mono">${esc(k.ksi_id)} ${k.previous_pass !== k.current_pass ? `<span class="pill ${k.current_pass ? 'fixed' : 'regressed'}">${k.previous_pass ? 'PASS' : 'FAIL'} → ${k.current_pass ? 'PASS' : 'FAIL'}</span>` : ''}</h2>
  <table>
    <thead><tr><th>Change</th><th>Rule</th><th>Prev</th><th>Now</th><th>Affected (prev→now)</th></tr></thead>
    <tbody>
    ${k.finding_changes.map((c) => `<tr>
      <td>${changeIcon[c.change] ?? ''} <span class="pill ${c.change}">${esc(c.change)}</span></td>
      <td class="mono">${esc(c.rule)}</td>
      <td>${c.previous ? (c.previous.passed ? 'PASS' : 'FAIL') : '—'}</td>
      <td>${c.current ? (c.current.passed ? 'PASS' : 'FAIL') : '—'}</td>
      <td>${c.previous?.affected_count ?? '—'} → ${c.current?.affected_count ?? '—'}</td>
    </tr>`).join('')}
    </tbody>
  </table>
`).join('')}
</body></html>`;
}
