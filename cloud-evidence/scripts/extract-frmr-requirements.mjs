#!/usr/bin/env node
/**
 * extract-frmr-requirements.mjs
 *
 * Produce a canonical, flat, machine-readable inventory of EVERY FedRAMP 20x
 * requirement — both KSI indicators and FRR (FedRAMP Requirement) statements —
 * from the official FedRAMP machine-readable documentation (FRMR.documentation.json).
 *
 * Why this exists:
 *   The FRMR doc is deeply nested (FRR.<family>.data.<track>.<actor>.<id>, and
 *   KSI.<domain>.indicators.<id>) and some requirements carry per-impact-level
 *   variants under `varies_by_level`. To analyze and build coverage for the full
 *   set (Low / Moderate / High) we need ONE flat list with stable fields, the
 *   level applicability resolved, and a coverage flag against the collectors we
 *   already ship.
 *
 * Source of truth:
 *   The FedRAMP docs repo (https://github.com/FedRAMP/docs) — its aggregate
 *   `FRMR.documentation.json`. Point at it with --in <path> or FRMR_DOC_PATH;
 *   defaults to ../docs/FRMR.documentation.json relative to the repo root.
 *
 * Impact levels:
 *   - Low / Moderate come straight from the 20x machine-readable data:
 *       * a requirement on the "20x" or "both" track applies to 20x;
 *       * `varies_by_level.{low,moderate}` overrides the statement/keyword per level.
 *   - High is NOT published as 20x machine-readable. We mark High applicability as
 *     DERIVED from the NIST SP 800-53 Rev5 HIGH baseline via each requirement's
 *     `controls[]` (resolved later by the analyzer); this script flags it derived.
 *
 * Output:
 *   A JSON array written to --out (default cloud-evidence/docs/frmr-requirements.generated.json),
 *   plus a human summary to stderr.
 *
 * This script is READ-ONLY and has no side effects beyond writing the output file.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const inPath = resolve(
  arg('--in', process.env.FRMR_DOC_PATH ?? resolve(REPO_ROOT, '..', 'docs', 'FRMR.documentation.json')),
);
const outPath = resolve(arg('--out', resolve(REPO_ROOT, 'docs', 'frmr-requirements.generated.json')));
const ksiMapPath = resolve(REPO_ROOT, 'core', 'ksi-map.ts');

if (!existsSync(inPath)) {
  console.error(`[extract-frmr] FRMR documentation not found at: ${inPath}`);
  console.error('[extract-frmr] Clone https://github.com/FedRAMP/docs and pass --in <path/to/FRMR.documentation.json>');
  console.error('[extract-frmr]   or set FRMR_DOC_PATH. This repo expects it at ../docs/FRMR.documentation.json.');
  process.exit(1);
}

const doc = JSON.parse(readFileSync(inPath, 'utf8'));

// Which collectors are already registered (coverage flag). Read the ksi-map so
// this stays accurate as new collectors are added.
let registered = new Set();
try {
  const mapSrc = readFileSync(ksiMapPath, 'utf8');
  for (const m of mapSrc.matchAll(/^\s*'(KSI-[A-Z]+-[A-Z]+)'\s*:/gm)) registered.add(m[1]);
} catch {
  /* coverage flag will all be false; non-fatal */
}

const LEVELS = ['low', 'moderate', 'high'];

/** Normalize a `varies_by_level` block into {low,moderate,high}->{statement,key_word}. */
function resolveLevels(node) {
  const out = {};
  const vbl = node.varies_by_level;
  for (const lvl of LEVELS) {
    if (vbl && vbl[lvl] && typeof vbl[lvl].statement === 'string') {
      out[lvl] = {
        applies: true,
        statement: vbl[lvl].statement,
        key_word: vbl[lvl].primary_key_word ?? node.primary_key_word ?? null,
        source: '20x-machine-readable',
      };
    } else if (typeof node.statement === 'string') {
      // Uniform statement: applies to the levels the track covers (low+moderate for 20x).
      out[lvl] = {
        applies: lvl !== 'high' ? true : null, // high resolved later (Rev5-derived)
        statement: node.statement,
        key_word: node.primary_key_word ?? null,
        source: lvl !== 'high' ? '20x-machine-readable' : 'derived-rev5-pending',
      };
    } else {
      out[lvl] = { applies: false, statement: null, key_word: null, source: null };
    }
  }
  return out;
}

const requirements = [];

// ── 1. KSI indicators (the testable security indicators) ──────────────────
for (const domain of Object.keys(doc.KSI ?? {})) {
  const block = doc.KSI[domain];
  const indicators = block.indicators ?? {};
  for (const id of Object.keys(indicators)) {
    const ind = indicators[id];
    requirements.push({
      id,
      category: 'ksi-indicator',
      family: domain,
      family_name: block.name ?? domain,
      name: ind.name ?? id,
      statement: ind.statement ?? null,
      key_word: ind.primary_key_word ?? 'MUST',
      track: '20x',
      affects: ind.affects ?? ['Providers'],
      controls: ind.controls ?? [],
      terms: ind.terms ?? [],
      fka: ind.fka ?? ind.fkas ?? null,
      reference: ind.reference ?? null,
      reference_url: ind.reference_url ?? null,
      levels: resolveLevels(ind),
      covered: registered.has(id),
    });
  }
}

// ── 2. FRR requirements (the broader FedRAMP requirements / process rules) ──
function walkFrr(node, ctx) {
  if (!node || typeof node !== 'object') return;
  // A requirement leaf: has a statement or a varies_by_level block, plus an fka/name.
  const isLeaf =
    (typeof node.statement === 'string' || node.varies_by_level) &&
    (node.fka || node.fkas || node.name || node.primary_key_word);
  if (isLeaf) {
    // All leaves inside FRR.* are FRR requirements. Earlier versions of this
    // script reclassified KSI-prefixed leaves under FRR.KSI (KSI-CSX-MAS,
    // KSI-CSX-ORD, KSI-CSX-SUM) as `ksi-indicator` to inflate the "63 KSIs"
    // count, but inspection of the upstream FRMR.documentation.json
    // (v0.9.43-beta) confirms the authoritative KSI section has exactly 60
    // entries across 11 families — CSX is NOT a KSI domain. These three
    // entries are FRR-class meta-requirements about the KSI assessment
    // process (Minimum Assessment Scope, AFR Order, Implementation Summaries)
    // and stay classified as `frr-requirement` here. The orchestrator still
    // emits a synthetic `KSI-CSX-SUM.json` aggregator output because it's
    // a useful artifact in its own right; that's an orchestration choice,
    // not a catalog claim.
    requirements.push({
      id: ctx.id,
      category: 'frr-requirement',
      family: ctx.family,
      family_name: ctx.familyName,
      name: node.name ?? ctx.id,
      statement: node.statement ?? null,
      key_word: node.primary_key_word ?? null,
      track: ctx.track ?? 'unknown',
      actor: ctx.actor ?? null,
      affects: node.affects ?? [],
      controls: node.controls ?? [],
      terms: node.terms ?? [],
      fka: node.fka ?? node.fkas ?? null,
      reference: node.reference ?? null,
      reference_url: node.reference_url ?? null,
      levels: resolveLevels(node),
      covered: false, // FRR requirements are not yet covered by collectors
    });
    return;
  }
  for (const k of Object.keys(node)) {
    const child = node[k];
    if (!child || typeof child !== 'object') continue;
    // Track which structural level we're at to capture track/actor/id.
    const next = { ...ctx };
    if (['20x', 'rev5', 'both'].includes(k)) next.track = k;
    else if (/^[A-Z]{2,4}-[A-Z]{2,4}-[A-Z]{2,4}$/.test(k)) next.id = k;        // requirement id
    else if (/^[A-Z]{2,4}$/.test(k) && !next.actorSet) { next.actor = k; next.actorSet = true; } // actor group
    walkFrr(child, next);
  }
}
for (const family of Object.keys(doc.FRR ?? {})) {
  const block = doc.FRR[family];
  if (!block || !block.data) continue;
  walkFrr(block.data, { family, familyName: block.info?.name ?? family });
}

// De-dup by id (a requirement can appear under multiple tracks; keep first, merge tracks).
const byId = new Map();
for (const r of requirements) {
  if (!byId.has(r.id)) byId.set(r.id, r);
  else {
    const ex = byId.get(r.id);
    if (r.track && ex.track && !String(ex.track).includes(r.track)) ex.track = `${ex.track},${r.track}`;
  }
}
const finalList = [...byId.values()].sort((a, b) => a.id.localeCompare(b.id));

writeFileSync(outPath, JSON.stringify(finalList, null, 2));

// ── Summary to stderr ──────────────────────────────────────────────────────
const ksi = finalList.filter((r) => r.category === 'ksi-indicator');
const frr = finalList.filter((r) => r.category === 'frr-requirement');
const coveredKsi = ksi.filter((r) => r.covered).length;
const byFamily = {};
for (const r of finalList) {
  const f = (byFamily[r.family] ??= { total: 0, covered: 0, cat: r.category });
  f.total++; if (r.covered) f.covered++;
}
console.error('─'.repeat(64));
console.error(`FRMR source : ${inPath}`);
console.error(`Output      : ${outPath}`);
console.error(`Total requirements : ${finalList.length}  (KSI ${ksi.length}, FRR ${frr.length})`);
console.error(`KSI coverage       : ${coveredKsi}/${ksi.length} collectors registered`);
console.error('─'.repeat(64));
console.error('family    total  covered  category');
for (const f of Object.keys(byFamily).sort()) {
  const b = byFamily[f];
  console.error(`${f.padEnd(8)} ${String(b.total).padStart(5)}  ${String(b.covered).padStart(7)}  ${b.cat}`);
}
console.error('─'.repeat(64));
console.error('Uncovered (gap) requirement IDs:');
console.error(finalList.filter((r) => !r.covered).map((r) => r.id).join(' '));
