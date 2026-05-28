/**
 * Powerpipe mod emitter.
 *
 * Powerpipe (https://powerpipe.io, Turbot) is the dominant OSS compliance-
 * dashboard tool. Most Powerpipe mods (CIS AWS, CIS GCP, FedRAMP Moderate
 * by Turbot, etc.) wrap a Steampipe table — but Powerpipe also supports
 * "static" data via JSON-backed dashboards.
 *
 * What this module emits:
 *   out/powerpipe/
 *     mod.pp                       — Mod manifest (name, title, requires steampipe)
 *     benchmarks/fedramp_20x.pp    — Top-level benchmark grouping every KSI by domain
 *     controls/<domain>.pp         — One file per KSI domain (IAM, MLA, …)
 *     dashboards/overview.pp       — Single-pane-of-glass dashboard
 *     README.md                    — Integration instructions
 *
 * Each generated control's SQL queries the Steampipe `file` plugin pointed at
 * our `out/` directory:
 *
 *   select
 *     'KSI-IAM-MFA' as resource,
 *     case when (content::jsonb -> 'rollup' ->> 'pass')::boolean then 'ok' else 'alarm' end as status,
 *     (content::jsonb ->> 'ksi_name') ||
 *       ': ' || (content::jsonb -> 'rollup' ->> 'failing_findings') ||
 *       ' failing findings' as reason
 *   from file_content
 *   where path = '${cloud_evidence_dir}/KSI-IAM-MFA.json'
 *
 * Why generate vs hand-write?
 *   - Mods need one control per KSI, which means dozens of files. Generating
 *     from the same KSI catalog the orchestrator uses means we can't drift.
 *   - When we add KSIs in future phases, the mod auto-updates on the next
 *     `--powerpipe` run.
 *
 * Limitations:
 *   - The generated mod assumes the user has Steampipe + the `file` plugin
 *     installed. We document this in the README.
 *   - We don't ship a custom Steampipe plugin (huge undertaking) — `file` is
 *     the universal-fit option that works for any JSON.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { KSI_MAP, SUPPORTED_KSIS, type KsiEntry } from './ksi-map.ts';
import { log } from './log.ts';

const MOD_NAME = 'cloud_evidence';
const MOD_TITLE = 'FedRAMP 20x Cloud Evidence';
const MOD_DESCRIPTION = 'Compliance benchmark generated from cloud-evidence collector output. Each control reads the corresponding KSI evidence file and reports pass/fail.';

export interface PowerpipeEmitOptions {
  /** Where to write the powerpipe/ subdirectory. */
  outDir: string;
  /**
   * Absolute path the generated controls should query (defaults to outDir
   * itself, but a CI/CD pipeline may want to publish evidence to a different
   * location and have the mod read from there).
   */
  evidenceDirAbsolute?: string;
}

export interface PowerpipeEmitResult {
  mod_dir: string;
  control_count: number;
  benchmark_count: number;
  domain_count: number;
}

function groupByDomain(ksis: KsiEntry[]): Map<string, KsiEntry[]> {
  // KSI ID looks like "KSI-IAM-MFA"; domain is the middle segment.
  const m = new Map<string, KsiEntry[]>();
  for (const k of ksis) {
    const dom = k.id.split('-')[1] ?? 'OTHER';
    if (!m.has(dom)) m.set(dom, []);
    m.get(dom)!.push(k);
  }
  // Sort by id within each domain for stable output
  for (const arr of m.values()) arr.sort((a, b) => a.id.localeCompare(b.id));
  return m;
}

function hclEscape(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

function controlBlock(ksi: KsiEntry, evidenceDir: string): string {
  const description = hclEscape(ksi.statement.slice(0, 240));
  // Each control becomes a SQL query against the `file_content` table from
  // the Steampipe file plugin. The query returns one row per evidence file
  // matched, with a status of ok/alarm.
  return `
control "${ksi.id.toLowerCase().replace(/-/g, '_')}" {
  title       = "${hclEscape(ksi.id + ': ' + ksi.name)}"
  description = "${description}"
  severity    = "high"
  sql         = <<-EOQ
    select
      '${ksi.id}' as resource,
      case when (content::jsonb -> 'rollup' ->> 'pass')::boolean
           then 'ok' else 'alarm' end as status,
      (content::jsonb ->> 'ksi_name') ||
        coalesce(': ' || (content::jsonb -> 'rollup' ->> 'failing_findings') || ' failing findings', '') as reason
    from
      file_content
    where
      path = '${evidenceDir}/${ksi.id}.json';
  EOQ

  tags = {
    ksi_id   = "${ksi.id}"
    domain   = "${ksi.id.split('-')[1] ?? 'OTHER'}"
    scope    = "${ksi.scope}"
    nist     = "${(ksi.nist_controls ?? []).join(' ')}"
  }
}
`.trim();
}

function benchmarkBlock(domain: string, controlNames: string[]): string {
  const child = controlNames.map((n) => `    control.${n},`).join('\n');
  return `
benchmark "domain_${domain.toLowerCase()}" {
  title       = "${domain} domain"
  description = "All KSIs in the ${domain} domain."
  children = [
${child}
  ]
}
`.trim();
}

function topBenchmark(domains: string[]): string {
  const child = domains.map((d) => `    benchmark.domain_${d.toLowerCase()},`).join('\n');
  return `
benchmark "fedramp_20x" {
  title         = "FedRAMP 20x — All KSIs"
  description   = "Top-level rollup grouping every KSI by domain (IAM, MLA, CNA, …)."
  documentation = file("./docs/overview.md")

  children = [
${child}
  ]
}
`.trim();
}

function modManifest(): string {
  return `
mod "${MOD_NAME}" {
  title       = "${MOD_TITLE}"
  description = "${MOD_DESCRIPTION}"

  require {
    plugin "file" {
      version = "*"
    }
  }
}
`.trim();
}

function dashboardOverview(domains: string[]): string {
  const cards = domains.map((d) => `
  card {
    width = 2
    query = query.${MOD_NAME}_count_${d.toLowerCase()}_failing
    type  = "alert"
  }
`).join('\n');
  const queries = domains.map((d) => `
query "${MOD_NAME}_count_${d.toLowerCase()}_failing" {
  title = "${d} failing"
  sql   = <<-EOQ
    select count(*) as "${d} Failing KSIs"
    from file_content
    where path like '%${d}-%.json'
      and (content::jsonb -> 'rollup' ->> 'pass')::boolean = false;
  EOQ
}
`).join('\n');

  return `
dashboard "fedramp_20x_overview" {
  title = "FedRAMP 20x Overview"

  container {
${cards}
  }

  table {
    title = "All KSI Status"
    query = query.${MOD_NAME}_all_status
  }
}

query "${MOD_NAME}_all_status" {
  sql = <<-EOQ
    select
      content::jsonb ->> 'ksi_id' as "KSI",
      content::jsonb ->> 'ksi_name' as "Name",
      case when (content::jsonb -> 'rollup' ->> 'pass')::boolean then '✓' else '✗' end as "Pass",
      content::jsonb -> 'rollup' ->> 'failing_findings' as "Failing"
    from file_content
    where path like '%KSI-%.json' and path not like '%manifest%'
    order by 1;
  EOQ
}

${queries}
`.trim();
}

function readme(evidenceDirAbsolute: string, controlCount: number): string {
  return `# Powerpipe mod: cloud_evidence

Auto-generated from \`cloud-evidence\` collector output. ${controlCount} controls covering every supported KSI.

## Prerequisites

1. **Steampipe** with the **file** plugin:
   \`\`\`bash
   brew install steampipe         # macOS
   steampipe plugin install file
   \`\`\`

2. **Powerpipe**:
   \`\`\`bash
   brew install powerpipe         # macOS
   \`\`\`

## Configure the file plugin

The generated controls read the evidence files at:

\`\`\`
${evidenceDirAbsolute}
\`\`\`

If you move the evidence elsewhere, regenerate this mod with:

\`\`\`bash
npm run collect -- --powerpipe --out /new/path
\`\`\`

Steampipe's \`file\` plugin needs to be configured to allow reading from that
path. Edit \`~/.steampipe/config/file.spc\`:

\`\`\`hcl
connection "file" {
  plugin = "file"
  paths  = ["${evidenceDirAbsolute}/*.json"]
}
\`\`\`

## Run the benchmark

\`\`\`bash
cd ${MOD_NAME}/
powerpipe benchmark run fedramp_20x
\`\`\`

## Open the dashboard

\`\`\`bash
powerpipe server
# browse to http://localhost:9033
\`\`\`

## Regenerating

Every \`--powerpipe\` run overwrites this directory. Hand-edits will be lost
on the next collector run — fork the directory if you want to customize.
`;
}

export function emitPowerpipeMod(opts: PowerpipeEmitOptions): PowerpipeEmitResult {
  const modDir = resolve(opts.outDir, 'powerpipe');
  const benchmarksDir = resolve(modDir, 'benchmarks');
  const controlsDir = resolve(modDir, 'controls');
  const dashboardsDir = resolve(modDir, 'dashboards');
  const docsDir = resolve(modDir, 'docs');
  mkdirSync(benchmarksDir, { recursive: true });
  mkdirSync(controlsDir, { recursive: true });
  mkdirSync(dashboardsDir, { recursive: true });
  mkdirSync(docsDir, { recursive: true });

  const ksis = SUPPORTED_KSIS.map((id) => KSI_MAP[id]).filter((k): k is KsiEntry => !!k);
  const byDomain = groupByDomain(ksis);
  const evidenceDir = opts.evidenceDirAbsolute ?? resolve(opts.outDir);

  // mod manifest
  writeFileSync(resolve(modDir, 'mod.pp'), modManifest() + '\n');

  // per-domain controls
  const controlNamesByDomain: Map<string, string[]> = new Map();
  for (const [domain, list] of byDomain) {
    const blocks = list.map((k) => controlBlock(k, evidenceDir));
    writeFileSync(
      resolve(controlsDir, `${domain.toLowerCase()}.pp`),
      `# Controls for the ${domain} domain. Auto-generated — do not edit.\n\n` + blocks.join('\n\n') + '\n',
    );
    controlNamesByDomain.set(domain, list.map((k) => k.id.toLowerCase().replace(/-/g, '_')));
  }

  // benchmarks
  const benchmarkBlocks: string[] = [];
  const domainList = Array.from(byDomain.keys()).sort();
  for (const dom of domainList) {
    benchmarkBlocks.push(benchmarkBlock(dom, controlNamesByDomain.get(dom) ?? []));
  }
  benchmarkBlocks.push(topBenchmark(domainList));
  writeFileSync(resolve(benchmarksDir, 'fedramp_20x.pp'), benchmarkBlocks.join('\n\n') + '\n');

  // dashboard
  writeFileSync(resolve(dashboardsDir, 'overview.pp'), dashboardOverview(domainList) + '\n');

  // docs
  writeFileSync(resolve(docsDir, 'overview.md'),
    `# FedRAMP 20x Benchmark\n\nAuto-generated cloud-evidence Powerpipe mod, covering ${ksis.length} KSIs across ${domainList.length} domains: ${domainList.join(', ')}.\n`);

  // README
  writeFileSync(resolve(modDir, 'README.md'), readme(evidenceDir, ksis.length));

  log.info({
    event: 'powerpipe.emitted',
    mod_dir: modDir,
    control_count: ksis.length,
    benchmark_count: domainList.length + 1,
    domain_count: domainList.length,
  });

  return {
    mod_dir: modDir,
    control_count: ksis.length,
    benchmark_count: domainList.length + 1,
    domain_count: domainList.length,
  };
}
