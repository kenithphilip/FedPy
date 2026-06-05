/**
 * KSI-CSX-SUM — Implementation Summaries aggregator.
 *
 * Reads every KSI-*.json evidence file in outDir and emits:
 *   - summaries/KSI-<id>.md  — one current-state markdown per KSI (per decision: markdown-in-git, no per-run snapshots)
 *   - out/KSI-CSX-SUM-input.json — structured input for Paramify / static-site renderer
 */
import { readdirSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { EvidenceFile } from './envelope.ts';

export interface CsxSumInput {
  outDir: string;
  summariesDir: string;     // where to write per-KSI .md files
  frmrVersion: string;
}

interface KsiSummary {
  ksi_id: string;
  ksi_name: string;
  scope: string;
  ksi_statement: string;
  pass_fail_criteria: string[];      // finding rule names
  validation_module: string;
  validated_resources_summary: string;
  validation_cadence_days: number;   // default 1; can be tuned via thresholds.yaml later
  last_run_at: string;
  last_pass_status: boolean;
  failing_findings_summary: string[];
  process_artifacts_required: string[];
  nist_controls: string[];
  related_ksis: Array<{ ksi_id: string; relationship: string; note: string }>;
}

export function buildCsxSum(input: CsxSumInput): { summaries: KsiSummary[]; markdownFiles: number } {
  const summaries: KsiSummary[] = [];
  let markdownFiles = 0;

  mkdirSync(input.summariesDir, { recursive: true });

  for (const f of readdirSync(input.outDir)) {
    if (!f.startsWith('KSI-') || !f.endsWith('.json')) continue;
    if (f === 'KSI-CSX-SUM-input.json') continue;
    const path = join(input.outDir, f);
    let data: EvidenceFile;
    try { data = JSON.parse(readFileSync(path, 'utf8')); } catch { continue; }

    const allFindings = data.providers.flatMap((p) => p.findings);
    const failingFindings = allFindings.filter((f2) => !f2.passed);
    const totalResources = data.providers.flatMap((p) => p.findings.flatMap((f2) => f2.gap?.affected_resources ?? [])).length;

    const summary: KsiSummary = {
      ksi_id: data.ksi_id,
      ksi_name: data.ksi_name,
      scope: data.scope,
      ksi_statement: data.ksi_statement,
      pass_fail_criteria: allFindings.map((f2) => `${f2.rule} (${f2.severity})`),
      validation_module: `cloud-evidence collector for ${data.ksi_id}`,
      validated_resources_summary: data.scope === 'PROCESS'
        ? 'Process KSI — see process artifact tracker'
        : `${data.providers.length} provider block(s); ${allFindings.length} finding(s); ${totalResources} affected resource(s) identified.`,
      validation_cadence_days: 1,
      last_run_at: data.collected_at,
      last_pass_status: data.rollup.pass,
      failing_findings_summary: failingFindings.map((f2) =>
        `${f2.rule}: ${typeof f2.current_state.summary === 'string' ? f2.current_state.summary : ''}`,
      ),
      process_artifacts_required: data.process_artifacts_required ?? [],
      nist_controls: data.nist_controls ?? [],
      related_ksis: (data.related_ksis ?? []).map((r) => ({
        ksi_id: r.ksi_id,
        relationship: r.relationship,
        note: r.note,
      })),
    };
    summaries.push(summary);

    // Write per-KSI markdown file
    const md = renderMarkdown(summary, data);
    writeFileSync(join(input.summariesDir, `${data.ksi_id}.md`), md);
    markdownFiles++;
  }

  // Write the aggregated JSON
  writeFileSync(
    join(input.outDir, 'KSI-CSX-SUM-input.json'),
    JSON.stringify({
      frmr_version: input.frmrVersion,
      generated_at: new Date().toISOString(),
      summaries,
    }, null, 2),
  );

  return { summaries, markdownFiles };
}

function renderMarkdown(s: KsiSummary, data: EvidenceFile): string {
  const lines: string[] = [];
  lines.push(`# ${s.ksi_id} — ${s.ksi_name}`);
  lines.push('');
  lines.push(`**Scope:** ${s.scope}`);
  lines.push(`**Last evaluated:** ${s.last_run_at}`);
  lines.push(`**Status:** ${s.last_pass_status ? '✅ PASS' : '❌ FAIL'}`);
  if (s.nist_controls.length) {
    lines.push(`**NIST 800-53 controls:** ${s.nist_controls.join(', ')}`);
  }
  lines.push('');
  lines.push('## FRMR statement');
  lines.push('');
  lines.push('> ' + s.ksi_statement);
  lines.push('');

  lines.push('## Goals & pass/fail criteria');
  lines.push('');
  if (s.pass_fail_criteria.length) {
    for (const c of s.pass_fail_criteria) lines.push(`- ${c}`);
  } else {
    lines.push('_No automated criteria — see process artifacts._');
  }
  lines.push('');

  lines.push('## Validated resources');
  lines.push('');
  lines.push(s.validated_resources_summary);
  lines.push('');

  lines.push('## Validation cadence');
  lines.push('');
  lines.push(`Every ${s.validation_cadence_days} day(s) via \`${s.validation_module}\`.`);
  lines.push('');

  if (s.failing_findings_summary.length) {
    lines.push('## Current gaps');
    lines.push('');
    for (const f of s.failing_findings_summary) lines.push(`- ${f}`);
    lines.push('');
  }

  if (s.process_artifacts_required.length) {
    lines.push('## Required process artifacts (human-attached)');
    lines.push('');
    for (const a of s.process_artifacts_required) lines.push(`- ${a}`);
    lines.push('');
  }

  if (s.related_ksis.length) {
    lines.push('## Related KSIs');
    lines.push('');
    for (const r of s.related_ksis) lines.push(`- **${r.ksi_id}** (${r.relationship}): ${r.note}`);
    lines.push('');
  }

  if (data.summary_for_llm) {
    lines.push('## LLM consumption summary');
    lines.push('');
    lines.push('> ' + data.summary_for_llm);
    lines.push('');
  }

  lines.push('---');
  lines.push(`_Generated by cloud-evidence CSX-SUM aggregator from FRMR ${data.frmr_version}._`);
  return lines.join('\n');
}
