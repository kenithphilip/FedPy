/**
 * CSV export — one row per finding across all KSI evidence files.
 * Suitable for review committees who prefer spreadsheets.
 */
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { EvidenceFile } from './envelope.ts';

const COLUMNS = [
  'ksi_id', 'ksi_name', 'scope', 'provider', 'account_or_project',
  'finding_rule', 'severity', 'passed', 'current_summary', 'target_summary',
  'rationale', 'gap_description', 'affected_resource_count',
  'remediation_summary', 'remediation_option_count', 'primary_owner_team',
  'primary_cost_impact', 'primary_availability_impact', 'primary_customer_visible',
  'primary_effort', 'alternative_satisfier_detected', 'nist_controls',
  'cross_ksi_dependencies', 'collected_at',
];

function csvEscape(v: unknown): string {
  if (v == null) return '';
  const s = String(v);
  if (/[",\r\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

export function exportFindingsCsv(outDir: string, csvPath: string): { rows: number; path: string } {
  const rows: string[] = [];
  rows.push(COLUMNS.join(','));

  for (const f of readdirSync(outDir)) {
    if (!f.startsWith('KSI-') || !f.endsWith('.json')) continue;
    if (f === 'KSI-CSX-SUM-input.json') continue;
    let data: EvidenceFile;
    try { data = JSON.parse(readFileSync(join(outDir, f), 'utf8')); } catch { continue; }

    for (const p of data.providers) {
      const accountOrProject = p.provider === 'aws' ? (p.account_id ?? '') : (p.project_id ?? '');
      for (const finding of p.findings) {
        const opt0 = finding.remediation?.options?.[0];
        const altDetected = (finding.alternative_satisfiers ?? []).some((a) => a.detected);
        const affectedCount = finding.gap?.affected_resources?.length ?? 0;
        rows.push([
          finding.rule.startsWith('KSI') ? '' : data.ksi_id, // safety: keep KSI col stable
          data.ksi_id,
          data.ksi_name,
          data.scope,
          p.provider,
          accountOrProject,
          finding.rule,
          finding.severity,
          String(finding.passed),
          finding.current_state.summary,
          finding.target_state.summary,
          finding.target_state.rationale,
          finding.gap?.description ?? '',
          String(affectedCount),
          finding.remediation?.summary ?? '',
          String(finding.remediation?.options?.length ?? 0),
          opt0?.owner_team ?? '',
          opt0?.cost_impact?.level ?? '',
          opt0?.availability_impact?.level ?? '',
          opt0?.customer_visible?.level ?? '',
          opt0?.effort_estimate?.magnitude ?? '',
          String(altDetected),
          (finding.nist_controls ?? []).join('; '),
          (finding.cross_ksi_dependencies ?? []).map((d) => `${d.ksi_id}:${d.relationship}`).join('; '),
          data.collected_at,
        ].slice(1).map(csvEscape).join(',')); // .slice(1) drops the safety col
      }
    }
  }

  writeFileSync(csvPath, rows.join('\n') + '\n');
  return { rows: rows.length - 1, path: csvPath };
}
