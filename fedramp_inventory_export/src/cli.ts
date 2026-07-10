/**
 * fedramp-inventory-export — CLI entry point.
 *
 * Produces a consolidated full-inventory + FedRAMP 20x/Rev5-Moderate compliance
 * export (XLSX + CSV) from a FedPy cloud-evidence run.
 *
 * Default mode is a READ-ONLY, OFFLINE transform of an existing `out/` directory
 * (inventory.json + per-requirement evidence envelopes). Pass `--collect` to run
 * FedPy's read-only collector first (one-command experience with a read-only AWS
 * role).
 *
 * Usage:
 *   tsx src/cli.ts                              # transform ../cloud-evidence/out
 *   tsx src/cli.ts --run-dir /path/to/out       # transform a specific run
 *   tsx src/cli.ts --out-dir ./out              # where to write the export
 *   tsx src/cli.ts --collect                    # collect (read-only) THEN transform
 *   tsx src/cli.ts --no-xlsx | --no-csv         # emit one format only
 */
import { resolve, dirname, join as pathJoin } from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeFileSync, mkdirSync } from 'node:fs';
import { loadRun, RunLoadError } from './load.ts';
import { joinRun } from './join.ts';
import { buildTables } from './tables.ts';
import { buildDashboard } from './dashboard.ts';
import { writeCsvs, writeWorkbook, summaryCoverFacts } from './writers.ts';
import { runCollector } from './collect.ts';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..', '..');
const DEFAULT_COLLECTOR_DIR = pathJoin(REPO_ROOT, 'cloud-evidence');
const DEFAULT_RUN_DIR = pathJoin(DEFAULT_COLLECTOR_DIR, 'out');
const DEFAULT_OUT_DIR = pathJoin(__dirname, '..', 'out');

interface Args {
  runDir: string;
  outDir: string;
  collectorDir: string;
  collect: boolean;
  xlsx: boolean;
  csv: boolean;
  providers?: string[];
  workbookName: string;
}

function parseArgs(argv: string[]): Args {
  const a: Args = {
    runDir: DEFAULT_RUN_DIR,
    outDir: DEFAULT_OUT_DIR,
    collectorDir: DEFAULT_COLLECTOR_DIR,
    collect: false,
    xlsx: true,
    csv: true,
    workbookName: 'fedramp-inventory-compliance.xlsx',
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    switch (arg) {
      case '--run-dir': a.runDir = resolve(argv[++i]!); break;
      case '--out-dir': a.outDir = resolve(argv[++i]!); break;
      case '--collector-dir': a.collectorDir = resolve(argv[++i]!); break;
      case '--collect': a.collect = true; break;
      case '--no-xlsx': a.xlsx = false; break;
      case '--no-csv': a.csv = false; break;
      case '--providers': a.providers = argv[++i]!.split(',').map((s) => s.trim()).filter(Boolean); break;
      case '--workbook-name': a.workbookName = argv[++i]!; break;
      case '-h': case '--help': printHelp(); process.exit(0);
      default:
        console.error(`Unknown argument: ${arg}\n`);
        printHelp();
        process.exit(2);
    }
  }
  // When collecting, the run we transform is the run we just wrote.
  if (a.collect) a.runDir = a.runDir === DEFAULT_RUN_DIR ? pathJoin(a.collectorDir, 'out') : a.runDir;
  return a;
}

function printHelp(): void {
  console.log(`fedramp-inventory-export — full inventory + FedRAMP 20x/Rev5-Moderate compliance export

Reads a FedPy cloud-evidence run (inventory.json + per-requirement evidence
envelopes) and emits a consolidated XLSX + CSV export: full inventory, per-asset
compliance standing, per-requirement status, and the NIST 800-53 control benchmark
in BOTH the Rev5 (Moderate baseline) and 20x-referenced framings.

Options:
  --run-dir <dir>        FedPy run directory to read (default: ../cloud-evidence/out)
  --out-dir <dir>        Where to write the export (default: ./out)
  --collect              Run FedPy's read-only collector first, then transform
  --collector-dir <dir>  cloud-evidence project dir (default: ../cloud-evidence)
  --providers a,b        With --collect: providers to sweep (e.g. aws,gcp)
  --workbook-name <f>    XLSX file name (default: fedramp-inventory-compliance.xlsx)
  --no-xlsx | --no-csv   Emit only one format
  -h, --help             Show this help

The transform is read-only and offline; --collect delegates all cloud access to
FedPy's collector (viewer-only IAM + runtime read-only guardrail).`);
}

async function main(argv: string[]): Promise<number> {
  const args = parseArgs(argv);

  if (args.collect) {
    console.log(`Collecting (read-only) via FedPy → ${args.runDir} ...`);
    try {
      await runCollector({
        collectorDir: args.collectorDir,
        outDir: args.runDir,
        providers: args.providers,
      });
    } catch (e: any) {
      console.error(`ERROR: collection failed: ${e?.message ?? e}`);
      return 1;
    }
  }

  let run;
  try {
    run = loadRun(args.runDir);
  } catch (e) {
    if (e instanceof RunLoadError) { console.error(`ERROR: ${e.message}`); return 2; }
    throw e;
  }

  console.log(`fedramp-inventory-export`);
  console.log(`  run dir    : ${args.runDir}`);
  console.log(`  inventory  : ${run.assets.length} asset(s) · ${run.snapshot.edge_count} edge(s)`);
  console.log(`  evidence   : ${run.evidence.length} requirement envelope(s)`);
  console.log(`  account(s) : ${run.accountIds.join(', ') || '(none tagged)'}`);
  console.log(`  location(s): ${run.locations.length}`);
  console.log(`  joining inventory ↔ compliance (Moderate; Rev5 + 20x) ...`);

  const joined = joinRun(run);
  const tables = buildTables(joined);
  const dashboard = buildDashboard(joined, {
    account: run.accountIds.join(', ') || '(untagged)',
    generatedAt: run.snapshot.generated_at ?? new Date().toISOString(),
  });

  mkdirSync(args.outDir, { recursive: true });
  const written: string[] = [];

  if (args.csv) written.push(...writeCsvs(tables, args.outDir));
  if (args.xlsx) {
    const xlsxPath = pathJoin(args.outDir, args.workbookName);
    writeWorkbook(tables, {
      title: 'FedRAMP 20x / Rev5 — Inventory & Compliance Export',
      subtitle: 'Full cloud inventory with per-asset compliance standing (Impact level: Moderate)',
      coverFacts: summaryCoverFacts(joined.summary),
      dashboard,
    }, xlsxPath);
    written.push(xlsxPath);
  }

  // A machine-readable summary alongside the human deliverables.
  const summaryPath = pathJoin(args.outDir, 'compliance-summary.json');
  writeFileSync(summaryPath, JSON.stringify(joined.summary, null, 2));
  written.push(summaryPath);

  const sm = joined.summary;
  console.log('');
  console.log('  Assets       : ' +
    `${sm.assetCount} total · ${sm.assetsNonCompliant} non-compliant · ` +
    `${sm.assetsCompliant} compliant · ${sm.assetsNotAssessed} not-assessed`);
  console.log('  Requirements : ' +
    `${sm.requirementsMet} met · ${sm.requirementsNotMet} not-met · ` +
    `${sm.requirementsPartial} partial · ${sm.requirementsNotAssessed} not-assessed · ` +
    `${sm.requirementsAwareness} awareness`);
  console.log('  Rev5 (Mod)   : ' +
    `${sm.rev5.satisfied}/${sm.rev5.inScope} satisfied · ` +
    `assessed pass ${(sm.rev5.assessedPassRate * 100).toFixed(1)}%`);
  console.log('  20x (Mod)    : ' +
    `${sm.twentyX.satisfied}/${sm.twentyX.inScope} satisfied · ` +
    `assessed pass ${(sm.twentyX.assessedPassRate * 100).toFixed(1)}%`);
  console.log('');
  console.log('  Written:');
  for (const p of written) console.log(`    ${p}`);
  return 0;
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err) => { console.error(err); process.exit(1); },
);
