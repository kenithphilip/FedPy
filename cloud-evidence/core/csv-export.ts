/**
 * CSV export — one row per finding across all KSI evidence files.
 * Suitable for review committees who prefer spreadsheets.
 */
import { writeFileSync } from 'node:fs';
import type { EvidenceFile } from './envelope.ts';
import { listEvidenceFiles } from './evidence-files.ts';

const COLUMNS = [
  'ksi_id', 'ksi_name', 'category', 'family', 'awareness_only', 'scope', 'provider', 'account_or_project',
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

  // Every requirement (KSI + FRR), selected by shape so non-KSI failures appear.
  for (const data of listEvidenceFiles(outDir)) {
    for (const p of data.providers) {
      const accountOrProject = p.provider === 'aws' ? (p.account_id ?? '') : (p.project_id ?? '');
      for (const finding of p.findings) {
        const opt0 = finding.remediation?.options?.[0];
        const altDetected = (finding.alternative_satisfiers ?? []).some((a) => a.detected);
        const affectedCount = finding.gap?.affected_resources?.length ?? 0;
        rows.push([
          data.ksi_id,
          data.ksi_name,
          data.category ?? (data.ksi_id.startsWith('KSI-') ? 'ksi-indicator' : 'frr-requirement'),
          data.family ?? '',
          String(data.awareness_only === true),
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
        ].map(csvEscape).join(','));
      }
    }
  }

  writeFileSync(csvPath, rows.join('\n') + '\n');
  return { rows: rows.length - 1, path: csvPath };
}
