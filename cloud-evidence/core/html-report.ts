/**
 * Self-contained HTML report — single file, no external deps.
 * Suitable as an auditor-facing artifact at the end of every run.
 */
import { writeFileSync } from 'node:fs';
import type { EvidenceFile } from './envelope.ts';
import { listEvidenceFiles } from './evidence-files.ts';

function esc(s: unknown): string {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function generateHtmlReport(outDir: string, htmlPath: string): { path: string; ksis: number } {
  // Every requirement (KSI + FRR/VDR/CCM/…), selected by shape not name prefix,
  // so non-KSI requirement failures are not silently hidden from the report.
  const files: EvidenceFile[] = listEvidenceFiles(outDir);

  const totalKsis = files.length;
  const passedKsis = files.filter((f) => f.rollup.pass).length;
  const failedKsis = totalKsis - passedKsis;
  const totalFindings = files.flatMap((f) => f.providers.flatMap((p) => p.findings)).length;
  const failingFindings = files.flatMap((f) => f.providers.flatMap((p) => p.findings.filter((x) => !x.passed)));
  const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of failingFindings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;

  const generatedAt = new Date().toISOString();
  const frmrVersion = files[0]?.frmr_version ?? '?';
  const runId = files[0]?.run_id ?? '?';

  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>FedRAMP 20x Evidence Report — ${esc(runId)}</title>
<style>
  body { font: 14px -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; background: #f6f8fa; color: #1f2328; max-width: 1300px; margin: 0 auto; padding: 20px; }
  h1 { font-size: 22px; margin: 0 0 6px; }
  h2 { font-size: 16px; margin: 24px 0 8px; }
  .sub { color: #59636e; margin: 0 0 18px; }
  .scoreboard { display: grid; grid-template-columns: repeat(6, 1fr); gap: 10px; margin: 14px 0 22px; }
  .card { background: white; border: 1px solid #d1d9e0; border-radius: 8px; padding: 12px; }
  .card .v { font-size: 22px; font-weight: 600; }
  .card .l { font-size: 11px; text-transform: uppercase; color: #59636e; letter-spacing: 0.3px; }
  .card.crit .v { color: #cf222e; }
  .card.high .v { color: #d29922; }
  .card.ok .v { color: #1a7f37; }
  table { width: 100%; border-collapse: collapse; background: white; border: 1px solid #d1d9e0; border-radius: 8px; overflow: hidden; }
  th, td { padding: 8px 12px; border-bottom: 1px solid #d1d9e0; vertical-align: top; font-size: 13px; text-align: left; }
  th { background: #f6f8fa; font-weight: 600; cursor: pointer; user-select: none; }
  th:hover { background: #eaeef2; }
  tr:last-child td { border-bottom: none; }
  .pill { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; }
  .pill.pass { background: #dafbe1; color: #1a7f37; }
  .pill.fail { background: #ffebe9; color: #cf222e; }
  .pill.critical { background: #ffebe9; color: #cf222e; }
  .pill.high { background: #fff8c5; color: #9a6700; }
  .pill.medium { background: #ddf4ff; color: #0969da; }
  .pill.low { background: #f6f8fa; color: #59636e; }
  .pill.info { background: #f6f8fa; color: #59636e; }
  details { margin: 4px 0; }
  summary { cursor: pointer; padding: 4px 0; font-weight: 500; }
  .mono { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 12px; }
  .filter { margin: 8px 0 12px; display: flex; gap: 8px; }
  .filter input, .filter select { font: inherit; padding: 6px 10px; border: 1px solid #d1d9e0; border-radius: 6px; }
  .filter input { flex: 1; }
  .nist { font-family: ui-monospace, Menlo, monospace; font-size: 11px; color: #59636e; }
  .note { background: #fffae6; border-left: 3px solid #d29922; padding: 8px 12px; margin: 8px 0; font-size: 13px; }
</style>
</head>
<body>
<h1>FedRAMP 20x Evidence Report</h1>
<p class="sub">Run <span class="mono">${esc(runId)}</span> · generated ${esc(generatedAt)} · FRMR ${esc(frmrVersion)}</p>

<div class="scoreboard">
  <div class="card"><div class="v">${totalKsis}</div><div class="l">KSIs evaluated</div></div>
  <div class="card ok"><div class="v">${passedKsis}</div><div class="l">Passing</div></div>
  <div class="card crit"><div class="v">${failedKsis}</div><div class="l">Failing</div></div>
  <div class="card crit"><div class="v">${bySeverity.critical}</div><div class="l">Critical findings</div></div>
  <div class="card high"><div class="v">${bySeverity.high}</div><div class="l">High findings</div></div>
  <div class="card"><div class="v">${totalFindings}</div><div class="l">Total findings</div></div>
</div>

<h2>KSI summary</h2>
<div class="filter">
  <input id="ksi-filter" placeholder="Filter by KSI ID or name…">
  <select id="status-filter">
    <option value="">All status</option>
    <option value="pass">Passing</option>
    <option value="fail">Failing</option>
  </select>
  <select id="scope-filter">
    <option value="">All scope</option>
    <option value="CLOUD">CLOUD</option>
    <option value="HYBRID">HYBRID</option>
  </select>
</div>
<table id="ksi-table">
  <thead><tr><th data-sort="0">KSI</th><th data-sort="1">Name</th><th data-sort="2">Scope</th><th data-sort="3">Status</th><th data-sort="4">Findings (fail/total)</th><th data-sort="5">NIST</th></tr></thead>
  <tbody>
${files.map((f) => {
  const findings = f.providers.flatMap((p) => p.findings);
  const failing = findings.filter((x) => !x.passed).length;
  return `<tr data-status="${f.rollup.pass ? 'pass' : 'fail'}" data-scope="${esc(f.scope)}">
    <td class="mono"><a href="#${esc(f.ksi_id)}">${esc(f.ksi_id)}</a></td>
    <td>${esc(f.ksi_name)}</td>
    <td>${esc(f.scope)}</td>
    <td><span class="pill ${f.rollup.pass ? 'pass' : 'fail'}">${f.rollup.pass ? 'PASS' : 'FAIL'}</span></td>
    <td>${failing}/${findings.length}</td>
    <td class="nist">${esc((f.nist_controls ?? []).join(', '))}</td>
  </tr>`;
}).join('\n')}
  </tbody>
</table>

<h2>Per-KSI detail</h2>
${files.map((f) => `
<div id="${esc(f.ksi_id)}" style="background: white; border: 1px solid #d1d9e0; border-radius: 8px; padding: 14px 18px; margin: 12px 0;">
  <h3 style="margin: 0 0 8px;">${esc(f.ksi_id)} — ${esc(f.ksi_name)} <span class="pill ${f.rollup.pass ? 'pass' : 'fail'}" style="margin-left: 8px;">${f.rollup.pass ? 'PASS' : 'FAIL'}</span></h3>
  <p style="margin: 0 0 8px; color: #59636e; font-style: italic;">${esc(f.ksi_statement)}</p>
  ${f.summary_for_llm ? `<div class="note">${esc(f.summary_for_llm)}</div>` : ''}
  ${f.providers.map((p) => `
    <h4 style="margin: 12px 0 6px;">${esc(p.provider)}${p.account_id ? ` (acct ${esc(p.account_id)})` : ''}${p.project_id ? ` (project ${esc(p.project_id)})` : ''}</h4>
    ${p.findings.map((finding) => `
      <details ${finding.passed ? '' : 'open'}>
        <summary><span class="pill ${finding.severity}">${esc(finding.severity)}</span> <span class="pill ${finding.passed ? 'pass' : 'fail'}">${finding.passed ? 'PASS' : 'FAIL'}</span> <span class="mono">${esc(finding.rule)}</span></summary>
        <p><strong>Current:</strong> ${esc(finding.current_state.summary)}</p>
        <p><strong>Target:</strong> ${esc(finding.target_state.summary)}<br><em>${esc(finding.target_state.rationale)}</em></p>
        ${finding.gap ? `
          <p><strong>Gap:</strong> ${esc(finding.gap.description)}</p>
          ${finding.gap.affected_resources.length ? `
            <details><summary>Affected resources (${finding.gap.affected_resources.length})</summary>
              <ul>${finding.gap.affected_resources.slice(0, 50).map((r) => `<li class="mono">${esc(r.type)}: ${esc(r.identifier)}</li>`).join('')}</ul>
            </details>
          ` : ''}
        ` : ''}
        ${finding.remediation ? `
          <p><strong>Remediation:</strong> ${esc(finding.remediation.summary)}</p>
          ${finding.remediation.options.map((opt) => `
            <details>
              <summary>${esc(opt.approach)} (${esc(opt.mechanism)}${opt.owner_team ? ` · ${esc(opt.owner_team)}` : ''})</summary>
              ${opt.cost_impact ? `<p>💰 Cost: <strong>${esc(opt.cost_impact.level)}</strong> — ${esc(opt.cost_impact.notes)}</p>` : ''}
              ${opt.availability_impact ? `<p>⚠️ Availability: <strong>${esc(opt.availability_impact.level)}</strong> — ${esc(opt.availability_impact.notes)}</p>` : ''}
              ${opt.customer_visible ? `<p>👤 Customer visibility: <strong>${esc(opt.customer_visible.level)}</strong> — ${esc(opt.customer_visible.notes)}</p>` : ''}
              ${opt.effort_estimate ? `<p>⏱️ Effort: <strong>${esc(opt.effort_estimate.magnitude)}</strong> — ${esc(opt.effort_estimate.notes)}</p>` : ''}
              ${opt.steps.length ? `<ol>${opt.steps.map((s) => `<li>${esc(s)}</li>`).join('')}</ol>` : ''}
              ${opt.example_code ? `<pre class="mono" style="background: #f6f8fa; padding: 12px; border-radius: 6px; overflow: auto;">${esc(opt.example_code)}</pre>` : ''}
            </details>
          `).join('')}
        ` : ''}
        ${(finding.alternative_satisfiers ?? []).length ? `
          <p><strong>Alternative paths:</strong></p>
          <ul>${(finding.alternative_satisfiers ?? []).map((a) => `<li>${a.detected ? '✅' : '⚪'} ${esc(a.via)} — ${esc(a.description)}</li>`).join('')}</ul>
        ` : ''}
        ${finding.nist_controls?.length ? `<p class="nist">NIST: ${esc(finding.nist_controls.join(', '))}</p>` : ''}
      </details>
    `).join('')}
  `).join('')}
</div>
`).join('\n')}

<script>
// Filter
const ksiFilter = document.getElementById('ksi-filter');
const statusFilter = document.getElementById('status-filter');
const scopeFilter = document.getElementById('scope-filter');
function applyFilters() {
  const q = ksiFilter.value.toLowerCase();
  const status = statusFilter.value;
  const scope = scopeFilter.value;
  document.querySelectorAll('#ksi-table tbody tr').forEach((row) => {
    const text = row.textContent.toLowerCase();
    const rowStatus = row.dataset.status;
    const rowScope = row.dataset.scope;
    const match = (!q || text.includes(q)) && (!status || rowStatus === status) && (!scope || rowScope === scope);
    row.style.display = match ? '' : 'none';
  });
}
ksiFilter.addEventListener('input', applyFilters);
statusFilter.addEventListener('change', applyFilters);
scopeFilter.addEventListener('change', applyFilters);

// Sort
let sortAsc = true;
document.querySelectorAll('#ksi-table th').forEach((th, i) => {
  th.addEventListener('click', () => {
    const tbody = document.querySelector('#ksi-table tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    rows.sort((a, b) => {
      const av = a.children[i].textContent.trim();
      const bv = b.children[i].textContent.trim();
      const cmp = av.localeCompare(bv, undefined, { numeric: true });
      return sortAsc ? cmp : -cmp;
    });
    rows.forEach((r) => tbody.appendChild(r));
    sortAsc = !sortAsc;
  });
});
</script>
</body>
</html>`;

  writeFileSync(htmlPath, html);
  return { path: htmlPath, ksis: totalKsis };
}
