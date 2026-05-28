/**
 * csx-sum-aggregator — produces per-KSI markdown implementation summaries.
 *
 * Per the FRMR KSI-CSX-SUM requirement: providers MUST maintain a high-level
 * summary per KSI with goals, pass/fail criteria, in-scope resources,
 * validation processes + cadence.
 *
 * Reads every KSI-*.json from the evidence directory and emits one
 * summaries/KSI-XXX.md per KSI (overwritten each run). Git history of the
 * summaries/ directory becomes the persistent-validation drift archive.
 *
 * Usage:
 *   npx tsx tools/csx-sum-aggregator.ts --out ./out --summaries ./summaries
 */
import { readFileSync, readdirSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import type { EvidenceFile, Finding, ProviderBlock } from '../core/envelope.ts';

interface Args { outDir: string; summariesDir: string; }
function parseArgs(argv: string[]): Args {
  const args: Args = {
    outDir: resolve(process.cwd(), 'out'),
    summariesDir: resolve(process.cwd(), 'summaries'),
  };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--out') args.outDir = resolve(argv[++i] ?? './out');
    else if (argv[i] === '--summaries') args.summariesDir = resolve(argv[++i] ?? './summaries');
    else if (argv[i] === '-h' || argv[i] === '--help') {
      console.log('Usage: csx-sum-aggregator --out <dir> --summaries <dir>');
      process.exit(0);
    }
  }
  return args;
}

function statusBadge(file: EvidenceFile): string {
  if (file.rollup.pass) return '✅ MET';
  if (file.rollup.alternatives_in_play > 0) return '🟡 IN PROGRESS (alternatives detected)';
  return '❌ FAILING';
}

function fmtFinding(provider: string, f: Finding): string {
  const sev = `**${f.severity.toUpperCase()}**`;
  const verdict = f.passed ? '✅' : '❌';
  let s = `- ${verdict} ${sev} \`${provider}:${f.rule}\` — ${f.current_state.summary}\n`;
  s += `  - **Target:** ${f.target_state.summary}\n`;
  s += `  - **Rationale:** ${f.target_state.rationale}\n`;
  if (f.gap) {
    s += `  - **Gap:** ${f.gap.description}\n`;
    if (f.gap.affected_resources.length) {
      s += `  - **Affected resources:** ${f.gap.affected_resources.length} (${f.gap.affected_resources.slice(0, 5).map((r) => r.identifier).join(', ')}${f.gap.affected_resources.length > 5 ? '…' : ''})\n`;
    }
  }
  if (f.remediation?.options.length) {
    s += `  - **Remediation options:**\n`;
    for (const o of f.remediation.options.slice(0, 3)) {
      s += `    - ${o.approach} *(${o.mechanism}, owner: ${o.owner_team ?? 'tbd'}, effort: ${o.effort_estimate?.magnitude ?? 'tbd'}, cost: ${o.cost_impact?.level ?? 'tbd'})*\n`;
    }
  }
  if (f.alternative_satisfiers?.length) {
    for (const a of f.alternative_satisfiers.filter((x) => x.detected)) {
      s += `  - **Alternative satisfier detected:** ${a.via}\n`;
    }
  }
  if (f.note) s += `  - *${f.note}*\n`;
  return s;
}

function buildSummary(file: EvidenceFile): string {
  const lines: string[] = [];
  lines.push(`# ${file.ksi_id} — ${file.ksi_name}`);
  lines.push('');
  lines.push(`> **Status:** ${statusBadge(file)}  ·  **Scope:** ${file.scope}  ·  **Run:** \`${file.run_id}\`  ·  **Collected:** ${file.collected_at}`);
  lines.push('');
  lines.push('## FedRAMP statement');
  lines.push('');
  lines.push(`> ${file.ksi_statement}`);
  lines.push('');

  if (file.nist_controls?.length) {
    lines.push(`**NIST 800-53 controls:** ${file.nist_controls.map((c) => `\`${c}\``).join(', ')}`);
    lines.push('');
  }

  lines.push('## Implementation goal');
  lines.push('');
  const allFindings = file.providers.flatMap((p) => p.findings);
  const goals = [...new Set(allFindings.map((f) => f.target_state.summary))];
  for (const g of goals) lines.push(`- ${g}`);
  lines.push('');

  lines.push('## Pass / fail criteria');
  lines.push('');
  for (const p of file.providers) {
    for (const f of p.findings) {
      lines.push(`- \`${p.provider}:${f.rule}\` (severity: ${f.severity})`);
    }
  }
  lines.push('');

  lines.push('## In-scope resources observed');
  lines.push('');
  for (const p of file.providers) {
    const scope = p.provider === 'aws' ? `account ${p.account_id ?? 'unknown'} (${p.region_set?.join(',')})` : `project ${p.project_id ?? 'unknown'}`;
    lines.push(`### ${p.provider.toUpperCase()} — ${scope}`);
    lines.push('');
    for (const ev of p.evidence.slice(0, 8)) {
      // Surface a compact summary line per evidence source
      const data = ev.data as any;
      let count = '';
      if (Array.isArray(data)) count = ` (${data.length} items)`;
      else if (data && typeof data === 'object' && 'count' in data) count = ` (count: ${data.count})`;
      else if (data && typeof data === 'object' && 'total' in data) count = ` (total: ${data.total})`;
      lines.push(`- \`${ev.source}\`${count}`);
    }
    if (p.evidence.length > 8) lines.push(`- *…and ${p.evidence.length - 8} more sources*`);
    lines.push('');
  }

  lines.push('## Validation process + cadence');
  lines.push('');
  lines.push(`- Validation tool: \`cloud-evidence\` collector (this repo).`);
  lines.push(`- Cadence: scheduled run via GitHub Actions (daily by default).`);
  lines.push(`- Last run: ${file.collected_at}`);
  lines.push(`- Run ID: ${file.run_id}`);
  lines.push('');

  lines.push('## Current findings');
  lines.push('');
  for (const p of file.providers) {
    lines.push(`### ${p.provider.toUpperCase()}`);
    lines.push('');
    if (p.findings.length === 0) lines.push('*(no findings)*');
    for (const f of p.findings) lines.push(fmtFinding(p.provider, f));
    if (p.warnings?.length) {
      lines.push('');
      lines.push('**Warnings:**');
      for (const w of p.warnings) lines.push(`- ${w}`);
    }
    if (p.third_party_tools_detected?.length) {
      lines.push('');
      lines.push('**3rd-party tools detected:**');
      for (const t of p.third_party_tools_detected) {
        lines.push(`- ${t.name} (${t.category}, ${t.confidence}): ${t.detection_signals.join('; ')}`);
      }
    }
    lines.push('');
  }

  if (file.related_ksis?.length) {
    lines.push('## Related KSIs');
    lines.push('');
    for (const r of file.related_ksis) lines.push(`- [${r.ksi_id}](./${r.ksi_id}.md) — *${r.relationship}*: ${r.note}`);
    lines.push('');
  }

  if (file.process_artifacts_required?.length) {
    lines.push('## Process artifacts required (HYBRID)');
    lines.push('');
    for (const a of file.process_artifacts_required) lines.push(`- ${a}`);
    lines.push('');
  }

  lines.push('---');
  lines.push('');
  lines.push(`*Auto-generated from \`${file.ksi_id}.json\`. Do not edit — re-run \`tools/csx-sum-aggregator.ts\` to refresh.*`);
  lines.push('');
  return lines.join('\n');
}

function main(): void {
  const args = parseArgs(process.argv.slice(2));
  mkdirSync(args.summariesDir, { recursive: true });
  const files = readdirSync(args.outDir).filter((f) => f.startsWith('KSI-') && f.endsWith('.json') && !f.includes('.example.'));
  console.log(`CSX-SUM aggregator: ${files.length} KSI evidence file(s) → ${args.summariesDir}`);
  for (const f of files) {
    const file = JSON.parse(readFileSync(resolve(args.outDir, f), 'utf8')) as EvidenceFile;
    const md = buildSummary(file);
    const out = resolve(args.summariesDir, `${file.ksi_id}.md`);
    writeFileSync(out, md);
    console.log(`  → ${out}`);
  }
  console.log(`\nDone. Commit ${args.summariesDir} to git; git history is the drift archive.`);
}

main();
