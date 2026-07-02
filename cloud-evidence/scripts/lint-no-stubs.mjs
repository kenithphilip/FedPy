#!/usr/bin/env node
/**
 * lint-no-stubs.mjs — G1 of the Real-Evidence-Only (REO) standard.
 *
 * Fails the build if any forbidden token appears in production paths:
 *   - "TODO", "FIXME", "XXX"
 *   - "stub", "placeholder", "lorem"
 *   - "coming soon", "not yet implemented", "not_yet_implemented"
 *   - "sample data", "fake data", "dummy data"
 *
 * Production paths = cloud-evidence/{core,providers,tracker,scripts}/
 *   minus: tests/, **\/*.test.ts, **\/fixtures/**, docs/,
 *          scripts/extract-*.mjs (those legitimately consume external catalogs)
 *
 * Allowlist:
 *   A handful of files legitimately contain forbidden tokens in a comment
 *   describing the rule itself (this script, CLAUDE.md, etc.).
 *   Files in `ALLOWLIST` are skipped.
 *
 * Usage:
 *   node scripts/lint-no-stubs.mjs              # scan whole tree, exit 1 on miss
 *   node scripts/lint-no-stubs.mjs --paths file1.ts file2.ts   # scan subset
 *   node scripts/lint-no-stubs.mjs --json       # JSON output for CI
 *
 * Read-only: never modifies files.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');

// ─── Forbidden tokens ─────────────────────────────────────────────────────────
//
// Each pattern is a case-insensitive regex applied per line. We require word
// boundaries where appropriate so that e.g. "sample-emit.ts" filename doesn't
// trigger.
const FORBIDDEN = [
  { id: 'TODO',          re: /\bTODO\b/i,                desc: 'unfinished work marker' },
  { id: 'FIXME',         re: /\bFIXME\b/i,               desc: 'unfinished work marker' },
  { id: 'XXX',           re: /\bXXX\b/,                  desc: 'unfinished work marker (case-sensitive — "xxx" is OK as a value)' },
  { id: 'stub',          re: /\b(stubbed?|stub-?function|stub-?out|stub-?value)\b/i, desc: 'stub implementation' },
  // HTML/JSX `placeholder="..."` form-field attributes are legitimate UI hints,
  // not placeholder data — exclude them via negative lookahead.
  { id: 'placeholder',   re: /\bplaceholder\b(?!\s*[:=]\s*["'`])/i, desc: 'placeholder value (use real value or operator-input prompt)' },
  { id: 'lorem',         re: /\blorem\b/i,               desc: 'lorem-ipsum filler' },
  { id: 'coming-soon',   re: /coming\s+soon/i,           desc: 'deferred feature' },
  { id: 'not-impl',      re: /not\s*[-_]?\s*yet\s*[-_]?\s*implemented/i, desc: 'unimplemented feature' },
  { id: 'sample-data',   re: /\bsample\s+(data|value|response|output|finding|asset|evidence)\b/i, desc: 'sample/fake data' },
  { id: 'fake-data',     re: /\bfake\s+(data|value|response|output|finding|asset|evidence|signature|timestamp)\b/i, desc: 'fake/mock data in production' },
  { id: 'dummy-data',    re: /\bdummy\s+(data|value|response|output|finding|asset|evidence)\b/i, desc: 'dummy data' },
  { id: 'hardcoded',     re: /\bhard[-_]?coded?\s+(sample|fake|test|dummy)\b/i, desc: 'hardcoded test data in production' },
];

// ─── Production path scope ────────────────────────────────────────────────────
const PROD_DIRS = ['core', 'providers', 'tracker', 'scripts'];

// Skip patterns (anywhere in the path)
const SKIP_PATTERNS = [
  /\/node_modules\//,
  /\/dist\//,
  /\/build\//,
  /\/coverage\//,
  /\/out\//,
  /\/\.git\//,
  /\/tests?\//,
  /\.test\.ts$/,
  /\.spec\.ts$/,
  /\/fixtures?\//,
  /\/__snapshots__\//,
  /\/docs\//,
];

// Files that legitimately mention forbidden tokens in their explanatory prose
// or allowlist code. The lint rule itself, the CLAUDE.md standard, and the
// extract-* scripts that consume external catalogs all describe the rule
// without violating it.
const ALLOWLIST = new Set([
  'scripts/lint-no-stubs.mjs',
  'scripts/check-provenance.mjs',
  'scripts/check-coverage-regression.mjs',
  // extractors legitimately reference external KSI/FRR ids that may include
  // strings like "todo" inside their FRMR source text passthrough; the
  // extractors themselves never *introduce* stubs, only re-emit external data.
  'scripts/extract-frmr-requirements.mjs',
  'scripts/extract-iam-actions.mjs',
  'scripts/extract-nist-baselines.mjs',
  'scripts/extract-nist-r5.mjs',
  // extract-800-218A re-emits verbatim NIST SP 800-218A Table 1 text (which
  // includes phrases like "adversarial samples") into a vendored data/ catalogue;
  // it introduces no stubs of its own (LOOP-T.T5).
  'scripts/extract-800-218A.mjs',
  'scripts/extract-oscal-schemas.mjs',
]);

// ─── Walk + scan ──────────────────────────────────────────────────────────────
function walk(dir, out = []) {
  let entries;
  try { entries = readdirSync(dir); } catch { return out; }
  for (const name of entries) {
    const p = join(dir, name);
    const rel = relative(REPO_ROOT, p);
    if (SKIP_PATTERNS.some((re) => re.test('/' + rel))) continue;
    let st;
    try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) walk(p, out);
    else if (st.isFile() && /\.(ts|tsx|mjs|cjs|js|jsx)$/.test(name)) out.push(p);
  }
  return out;
}

function scanFile(path) {
  const rel = relative(REPO_ROOT, path);
  if (ALLOWLIST.has(rel)) return [];
  let src;
  try { src = readFileSync(path, 'utf8'); } catch { return []; }
  const lines = src.split(/\r?\n/);
  const hits = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const tok of FORBIDDEN) {
      if (tok.re.test(line)) {
        hits.push({
          file: rel,
          line: i + 1,
          token: tok.id,
          desc: tok.desc,
          excerpt: line.trim().slice(0, 160),
        });
      }
    }
  }
  return hits;
}

// ─── CLI ──────────────────────────────────────────────────────────────────────
function parseArgs(argv) {
  const args = { paths: null, json: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--paths') { args.paths = []; while (argv[i + 1] && !argv[i + 1].startsWith('--')) args.paths.push(argv[++i]); }
    else if (a === '--json') args.json = true;
  }
  return args;
}

const args = parseArgs(process.argv);

let files;
if (args.paths && args.paths.length) {
  files = args.paths.map((p) => resolve(p));
} else {
  files = [];
  for (const d of PROD_DIRS) files.push(...walk(join(REPO_ROOT, d)));
}

const allHits = [];
for (const f of files) allHits.push(...scanFile(f));

if (args.json) {
  process.stdout.write(JSON.stringify({ totalFilesScanned: files.length, hits: allHits }, null, 2));
} else {
  if (allHits.length === 0) {
    console.log(`[lint:no-stubs] OK — scanned ${files.length} files, 0 violations.`);
  } else {
    console.error(`[lint:no-stubs] FAIL — ${allHits.length} violation(s) in ${files.length} file(s):\n`);
    for (const h of allHits) {
      console.error(`  ${h.file}:${h.line}  [${h.token}] ${h.desc}`);
      console.error(`    ${h.excerpt}`);
    }
    console.error('\nFix by completing the implementation or removing the marker. See cloud-evidence/CLAUDE.md (REO standard).');
  }
}

process.exit(allHits.length === 0 ? 0 : 1);
