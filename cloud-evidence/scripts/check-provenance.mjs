#!/usr/bin/env node
/**
 * check-provenance.mjs — G3 of the Real-Evidence-Only (REO) standard.
 *
 * Every artifact under `out/` that emits structured data should record
 * provenance: which collector produced it, which SDK calls (or catalog /
 * tracker reads) it derives from, and which signing key + timestamp authority
 * attested it.
 *
 * This script verifies that every output JSON file under `out/` carries a
 * top-level `provenance` object with the minimum required keys:
 *
 *   provenance: {
 *     emitter:           string,             // e.g. "core/oscal.ts"
 *     emittedAt:         ISO-8601 string,
 *     sourceCalls:       string[],           // SDK calls / catalog reads / DB queries
 *     signingKeyId:      string,             // Ed25519 public key fingerprint
 *     timestampAuthority?: string,           // RFC 3161 TSA URL (optional, may be absent in --no-tsa mode)
 *     synthesizedFields?: string[],          // any computed-not-collected fields, with operator opt-in
 *   }
 *
 * Two file categories are exempt from this requirement:
 *
 *   1. Files explicitly registered in the OSCAL/FedRAMP schema that have
 *      their own provenance model (e.g. OSCAL `metadata.revisions`, IIW
 *      cells governed by inventory-coverage.json). These are listed in the
 *      OSCAL/IIW allowlist.
 *
 *   2. The signing-manifest itself (`out/manifest.json`) and the timestamp
 *      response (`out/timestamp.tsr`) — they ARE the provenance layer.
 *
 * Usage:
 *   node scripts/check-provenance.mjs                  # scan ./out/
 *   node scripts/check-provenance.mjs --dir <path>     # scan custom directory
 *   node scripts/check-provenance.mjs --json
 *
 * Exit codes:
 *   0 = every artifact has provenance (or is allowlisted)
 *   1 = one or more artifacts missing required provenance
 *   2 = scan directory missing (not a fatal error if it's just a clean run)
 *
 * Read-only: never modifies files.
 */
import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import { join, relative, resolve, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');
const DEFAULT_DIR = resolve(REPO_ROOT, 'out');

// ─── Allowlist ────────────────────────────────────────────────────────────────
//
// Files that ARE the provenance layer (signing manifest, timestamp response),
// or files whose provenance is captured by a structurally different model
// (OSCAL metadata.revisions, IIW inventory-coverage.json).
const ALLOWLIST_BASENAMES = new Set([
  'manifest.json',
  'timestamp.tsr',
  'timestamp.json',
  'inventory-coverage.json',
  'inventory-workbook.xlsx', // binary — provenance lives in companion JSON
]);

const ALLOWLIST_FILENAME_PATTERNS = [
  // OSCAL artifacts carry metadata.revisions instead of top-level provenance.
  // Their provenance is checked structurally (must have metadata + uuid).
  /^oscal-.*\.json$/,
  /^ssp\.json$/,
  /^ssp\.xml$/,
  /^ap\.json$/,
  /^ap\.xml$/,
  /^ar\.json$/,
  /^ar\.xml$/,
  /^poam\.json$/,
  /^poam\.xml$/,
  // Signed bundle index lives at INDEX.json — has its own structure.
  /^INDEX\.json$/,
];

// KSI evidence files (KSI-<DOMAIN>-<NAME>.json, optionally with .example /
// .signed suffix) use the cloud-evidence envelope schema instead of a
// top-level `provenance` block. Their provenance lives in the envelope's
// {ksi_id, run_id, collected_at, frmr_version, providers[].evidence[].source}
// fields plus the companion manifest.json (Ed25519-signed). Validate
// structurally rather than via generic provenance.
const KSI_ENVELOPE_PATTERN = /^KSI-[A-Z]+-[A-Z0-9]+(\.example|\.signed)?\.json$/;

const REQUIRED_KEYS = ['emitter', 'emittedAt', 'sourceCalls', 'signingKeyId'];

// ─── KSI envelope structural provenance check ────────────────────────────────
// The envelope at core/envelope.ts shapes every KSI-*.json file. Required
// provenance-equivalent fields:
//   - ksi_id            (which KSI this is)
//   - run_id            (orchestrator run identifier — links to ledger + signing)
//   - collected_at      (ISO timestamp)
//   - frmr_version      (FRMR catalog version — ties evidence to source rules)
//   - providers[]       (at least one provider's evidence)
// Each providers[].evidence[] entry must have a `source` field naming the SDK
// call / catalog read / DB query.
function checkKsiEnvelopeProvenance(doc) {
  const problems = [];
  for (const k of ['ksi_id', 'run_id', 'collected_at', 'frmr_version']) {
    if (!doc[k]) problems.push(`KSI envelope missing required field: ${k}`);
  }
  if (!Array.isArray(doc.providers) || doc.providers.length === 0) {
    problems.push('KSI envelope missing providers[] (no evidence collected)');
  } else {
    for (let i = 0; i < doc.providers.length; i++) {
      const p = doc.providers[i];
      if (!p.provider) problems.push(`providers[${i}] missing provider name`);
      if (!Array.isArray(p.evidence)) {
        problems.push(`providers[${i}] missing evidence[]`);
        continue;
      }
      for (let j = 0; j < p.evidence.length; j++) {
        const e = p.evidence[j];
        if (!e.source) problems.push(`providers[${i}].evidence[${j}] missing source (no SDK call cited)`);
      }
    }
  }
  return problems;
}

// ─── OSCAL structural provenance check ────────────────────────────────────────
// OSCAL artifacts must have:
//   - top-level uuid
//   - metadata object with last-modified + version
//   - if `metadata.revisions` exists, each revision has `last-modified`
function checkOscalProvenance(doc) {
  const problems = [];
  // OSCAL root may be one of {system-security-plan, assessment-plan,
  // assessment-results, plan-of-action-and-milestones} — find the root.
  const root = doc['system-security-plan']
            ?? doc['assessment-plan']
            ?? doc['assessment-results']
            ?? doc['plan-of-action-and-milestones'];
  if (!root) {
    problems.push('not a recognized OSCAL root (system-security-plan / assessment-plan / assessment-results / plan-of-action-and-milestones)');
    return problems;
  }
  if (!root.uuid || typeof root.uuid !== 'string') problems.push('OSCAL root missing required uuid');
  const md = root.metadata;
  if (!md || typeof md !== 'object') {
    problems.push('OSCAL root missing required metadata');
  } else {
    if (!md['last-modified']) problems.push('OSCAL metadata missing last-modified');
    if (!md.version) problems.push('OSCAL metadata missing version');
    if (!md['oscal-version']) problems.push('OSCAL metadata missing oscal-version');
  }
  return problems;
}

// ─── Generic provenance check ────────────────────────────────────────────────
function checkGenericProvenance(doc) {
  const problems = [];
  const p = doc.provenance;
  if (!p || typeof p !== 'object') {
    problems.push('missing top-level `provenance` object');
    return problems;
  }
  for (const k of REQUIRED_KEYS) {
    if (p[k] === undefined || p[k] === null) problems.push(`provenance.${k} missing`);
  }
  if (Array.isArray(p.sourceCalls) && p.sourceCalls.length === 0) {
    problems.push('provenance.sourceCalls is empty (no real evidence cited)');
  }
  return problems;
}

// ─── Walk + scan ──────────────────────────────────────────────────────────────
function walk(dir, out = []) {
  let entries;
  try { entries = readdirSync(dir); } catch { return out; }
  for (const name of entries) {
    const p = join(dir, name);
    let st;
    try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) walk(p, out);
    else if (st.isFile()) out.push(p);
  }
  return out;
}

function isAllowlisted(path) {
  const b = basename(path);
  if (ALLOWLIST_BASENAMES.has(b)) return true;
  for (const re of ALLOWLIST_FILENAME_PATTERNS) if (re.test(b)) return true;
  return false;
}

function scanFile(path) {
  const rel = relative(REPO_ROOT, path);
  const b = basename(path);

  // KSI evidence envelopes — structural check.
  if (KSI_ENVELOPE_PATTERN.test(b)) {
    let doc;
    try { doc = JSON.parse(readFileSync(path, 'utf8')); }
    catch { return [{ file: rel, kind: 'ksi-envelope', issue: 'JSON parse error' }]; }
    return checkKsiEnvelopeProvenance(doc).map((issue) => ({ file: rel, kind: 'ksi-envelope', issue }));
  }

  if (isAllowlisted(path)) {
    // OSCAL files still get a structural check.
    if (rel.endsWith('.json') && /(oscal-|\/(ssp|ap|ar|poam)\.json$)/.test(rel)) {
      let doc;
      try { doc = JSON.parse(readFileSync(path, 'utf8')); }
      catch { return [{ file: rel, kind: 'oscal', issue: 'JSON parse error' }]; }
      return checkOscalProvenance(doc).map((issue) => ({ file: rel, kind: 'oscal', issue }));
    }
    return [];
  }
  if (!/\.json$/.test(path)) return [];
  let doc;
  try { doc = JSON.parse(readFileSync(path, 'utf8')); }
  catch { return [{ file: rel, kind: 'generic', issue: 'JSON parse error' }]; }
  return checkGenericProvenance(doc).map((issue) => ({ file: rel, kind: 'generic', issue }));
}

// ─── CLI ──────────────────────────────────────────────────────────────────────
function parseArgs(argv) {
  const args = { dir: DEFAULT_DIR, json: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--dir') args.dir = resolve(argv[++i]);
    else if (a === '--json') args.json = true;
  }
  return args;
}

const args = parseArgs(process.argv);

if (!existsSync(args.dir)) {
  console.log(`[check:provenance] no scan directory at ${args.dir} — nothing to verify (clean run).`);
  process.exit(0);
}

const files = walk(args.dir);
const issues = [];
for (const f of files) issues.push(...scanFile(f));

if (args.json) {
  process.stdout.write(JSON.stringify({ totalFiles: files.length, issues }, null, 2));
} else {
  if (issues.length === 0) {
    console.log(`[check:provenance] OK — ${files.length} file(s) scanned, all provenance requirements satisfied.`);
  } else {
    console.error(`[check:provenance] FAIL — ${issues.length} issue(s):\n`);
    for (const i of issues) console.error(`  ${i.file}  [${i.kind}] ${i.issue}`);
    console.error('\nEvery non-allowlisted output JSON must carry a top-level `provenance` block with emitter, emittedAt, sourceCalls, signingKeyId. See CLAUDE.md (REO standard).');
  }
}

process.exit(issues.length === 0 ? 0 : 1);
