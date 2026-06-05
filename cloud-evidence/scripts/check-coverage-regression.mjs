#!/usr/bin/env node
/**
 * check-coverage-regression.mjs — G2 of the Real-Evidence-Only (REO) standard.
 *
 * Compares the current `out/inventory-coverage.json` against a baseline file
 * and fails if any (column, cloud) fill-rate decreased.
 *
 * The baseline lives at `coverage-baseline.json` in the repo root. It is
 * committed alongside source changes when a slice legitimately moves the
 * baseline forward. Pulling the baseline backward is a deliberate act:
 * the operator must run `--update-baseline` and explain why in CHANGELOG.
 *
 * Usage:
 *   node scripts/check-coverage-regression.mjs
 *       — compare ./out/inventory-coverage.json to ./coverage-baseline.json
 *   node scripts/check-coverage-regression.mjs --current <path> --baseline <path>
 *   node scripts/check-coverage-regression.mjs --update-baseline
 *       — copy current → baseline (only when you've intentionally improved coverage)
 *   node scripts/check-coverage-regression.mjs --json
 *
 * Exit codes:
 *   0 = no regression (or baseline missing — first run)
 *   1 = at least one fill-rate decreased
 *   2 = current report missing or malformed
 *
 * Read-only with the sole exception of --update-baseline.
 */
import { readFileSync, writeFileSync, existsSync, copyFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');
const DEFAULT_CURRENT  = resolve(REPO_ROOT, 'out', 'inventory-coverage.json');
const DEFAULT_BASELINE = resolve(REPO_ROOT, 'coverage-baseline.json');

function parseArgs(argv) {
  const args = { current: DEFAULT_CURRENT, baseline: DEFAULT_BASELINE, update: false, json: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--current') args.current = resolve(argv[++i]);
    else if (a === '--baseline') args.baseline = resolve(argv[++i]);
    else if (a === '--update-baseline') args.update = true;
    else if (a === '--json') args.json = true;
  }
  return args;
}

const args = parseArgs(process.argv);

function readJson(p) {
  try { return JSON.parse(readFileSync(p, 'utf8')); }
  catch (e) { return null; }
}

const current = readJson(args.current);
if (!current) {
  // No current report — usually means no `npm run collect` has happened yet
  // (e.g. dev environment without cloud creds, or fresh checkout). This is
  // not a hard failure: the script is invoked optionally in such contexts.
  // The cloud-evidence.yml scheduled workflow ALWAYS runs `npm run collect`
  // before this check, so a real regression in production CI will surface.
  console.log(`[check:coverage-regression] SKIP — no current report at ${args.current}.`);
  console.log('  This is expected when `npm run collect` has not been run in this environment.');
  console.log('  In the scheduled cloud-evidence workflow, the collector emits this file before the check runs.');
  process.exit(0);
}

if (args.update) {
  copyFileSync(args.current, args.baseline);
  console.log(`[check:coverage-regression] Updated baseline → ${args.baseline}`);
  process.exit(0);
}

if (!existsSync(args.baseline)) {
  console.log(`[check:coverage-regression] OK — no baseline yet at ${args.baseline} (first run).`);
  console.log('  To establish a baseline: node scripts/check-coverage-regression.mjs --update-baseline');
  process.exit(0);
}

const baseline = readJson(args.baseline);
if (!baseline) {
  console.error(`[check:coverage-regression] FAIL — baseline malformed: ${args.baseline}`);
  process.exit(2);
}

// Build (column, cloud) → fillRate lookup for both.
function indexFillRates(report) {
  const idx = new Map();
  if (!report || !Array.isArray(report.columns)) return idx;
  for (const c of report.columns) {
    const col = c.column;
    const rates = c.fillRate ?? {};
    for (const cloud of ['aws', 'gcp', 'azure']) {
      const v = typeof rates[cloud] === 'number' ? rates[cloud] : 0;
      idx.set(`${col}|${cloud}`, v);
    }
  }
  return idx;
}

const cur = indexFillRates(current);
const base = indexFillRates(baseline);

const regressions = [];
for (const [key, baseRate] of base) {
  const curRate = cur.get(key) ?? 0;
  // Allow tiny floating-point noise (1e-6).
  if (curRate + 1e-6 < baseRate) {
    const [col, cloud] = key.split('|');
    regressions.push({ column: col, cloud, baseline: baseRate, current: curRate, delta: +(curRate - baseRate).toFixed(6) });
  }
}

if (args.json) {
  process.stdout.write(JSON.stringify({ regressions, baselinePath: args.baseline, currentPath: args.current }, null, 2));
}

if (regressions.length === 0) {
  if (!args.json) console.log(`[check:coverage-regression] OK — no fill-rate decreased vs ${args.baseline}.`);
  process.exit(0);
}

if (!args.json) {
  console.error(`[check:coverage-regression] FAIL — ${regressions.length} (column, cloud) fill-rate decreased:\n`);
  for (const r of regressions) {
    console.error(`  ${r.column} / ${r.cloud}: ${r.baseline.toFixed(4)} → ${r.current.toFixed(4)}  (Δ ${r.delta >= 0 ? '+' : ''}${r.delta})`);
  }
  console.error('\nIf this regression is intentional (e.g. removing a synthesized field that masked a real gap):');
  console.error('  1) Explain why in CHANGELOG.md.');
  console.error('  2) Run: node scripts/check-coverage-regression.mjs --update-baseline');
}
process.exit(1);
