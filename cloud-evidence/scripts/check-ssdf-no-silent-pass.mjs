#!/usr/bin/env node
/**
 * check-ssdf-no-silent-pass.mjs — LOOP-T.T2 REO guardrail.
 *
 * The SSDF satisfaction matrix (`out/ssdf-satisfaction-matrix*.json`) must never
 * mark a task or practice `satisfied` without at least one real evidence
 * pointer backing it. A `satisfied` cell with zero pointers is the canonical
 * Real-Evidence-Only violation: it asserts compliance the matrix cannot defend
 * at audit. This script fails the build when any such cell exists.
 *
 * It also asserts the inverse REO invariant: a task with zero evidence pointers
 * MUST carry status `requires-operator-input` (never a quiet pass-through).
 *
 * Usage:
 *   node scripts/check-ssdf-no-silent-pass.mjs                 # scan ./out/
 *   node scripts/check-ssdf-no-silent-pass.mjs --dir <path>    # scan a directory
 *   node scripts/check-ssdf-no-silent-pass.mjs --json
 *
 * Exit codes:
 *   0 = every `satisfied` cell has >=1 evidence pointer (or no matrices found)
 *   1 = one or more `satisfied` cells lack evidence (REO violation)
 *
 * Read-only: never modifies files.
 */
import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs';
import { join, resolve, relative, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');
const DEFAULT_DIR = resolve(REPO_ROOT, 'out');

const MATRIX_FILE_RE = /^ssdf-satisfaction-matrix(\.[a-z0-9-]+)?\.json$/;

function parseArgs(argv) {
  const args = { dir: DEFAULT_DIR, json: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--dir') args.dir = resolve(argv[++i]);
    else if (a === '--json') args.json = true;
  }
  return args;
}

function checkMatrix(doc, rel) {
  const issues = [];
  const practices = Array.isArray(doc?.practices) ? doc.practices : [];
  for (const p of practices) {
    for (const t of p?.tasks ?? []) {
      const ptrs = Array.isArray(t?.evidence_pointers) ? t.evidence_pointers.length : 0;
      if (t?.status === 'satisfied' && ptrs === 0) {
        issues.push({ file: rel, cell: `${t.id}`, issue: 'task marked satisfied with zero evidence pointers' });
      }
      if (ptrs === 0 && t?.status !== 'requires-operator-input') {
        issues.push({ file: rel, cell: `${t.id}`, issue: `task has zero evidence pointers but status is "${t?.status}" (expected requires-operator-input)` });
      }
    }
    // A practice rolled up to satisfied must have at least one satisfied task
    // (which itself was already pointer-checked above).
    if (p?.status === 'satisfied') {
      const anySatisfiedTask = (p?.tasks ?? []).some((t) => t?.status === 'satisfied' && (t?.evidence_pointers?.length ?? 0) > 0);
      if (!anySatisfiedTask) {
        issues.push({ file: rel, cell: `${p.id}`, issue: 'practice marked satisfied with no evidence-backed satisfied task' });
      }
    }
  }
  return issues;
}

const args = parseArgs(process.argv);

if (!existsSync(args.dir)) {
  console.log(`[check:ssdf-no-silent-pass] no scan directory at ${args.dir} — nothing to verify (clean run).`);
  process.exit(0);
}

let entries = [];
try {
  entries = readdirSync(args.dir).filter((n) => MATRIX_FILE_RE.test(n));
} catch {
  entries = [];
}

const issues = [];
let scanned = 0;
for (const name of entries) {
  const path = join(args.dir, name);
  try {
    if (!statSync(path).isFile()) continue;
  } catch {
    continue;
  }
  scanned += 1;
  let doc;
  try {
    doc = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    issues.push({ file: relative(REPO_ROOT, path), cell: '-', issue: 'JSON parse error' });
    continue;
  }
  issues.push(...checkMatrix(doc, relative(REPO_ROOT, path)));
}

if (args.json) {
  process.stdout.write(JSON.stringify({ scanned, issues }, null, 2));
} else if (issues.length === 0) {
  console.log(`[check:ssdf-no-silent-pass] OK — ${scanned} matrix file(s) scanned, every satisfied cell is evidence-backed.`);
} else {
  console.error(`[check:ssdf-no-silent-pass] FAIL — ${issues.length} REO violation(s):\n`);
  for (const i of issues) console.error(`  ${i.file}  [${i.cell}] ${i.issue}`);
  console.error('\nEvery "satisfied" cell must trace to >=1 real evidence pointer; a cell with no evidence must be "requires-operator-input". See cloud-evidence/CLAUDE.md (REO standard).');
}

process.exit(issues.length === 0 ? 0 : 1);
