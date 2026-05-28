#!/usr/bin/env node
/**
 * extract-nist-r5.mjs
 *
 * Produce a committed control-id → {name, family} lookup for NIST SP 800-53 Rev5,
 * from the GovReady `nist-sp-800-53-r5-data` repo (control-metadata.yaml). This
 * lets the collector ENRICH High-derived findings with the official Rev5 control
 * names as grounding evidence, without the runtime depending on the (gitignored)
 * reference clone.
 *
 * Source: git@github.com:GovReady/nist-sp-800-53-r5-data.git → control-metadata.yaml
 *   Each entry: { control: "AC-2(1)", family: "AC", number: 2, enhancement: 1, name: ... }
 *
 * The FRMR data references controls in lowercase dotted form ("ac-2", "ac-2.2"),
 * so we key the lookup that way: AC-2 → ac-2 ; AC-2(2) → ac-2.2.
 *
 * Usage: node scripts/extract-nist-r5.mjs [--in <control-metadata.yaml>] [--out <json>]
 * Defaults: ../nist-r5-data/control-metadata.yaml → cloud-evidence/docs/nist-r5-controls.generated.json
 *
 * READ-ONLY apart from writing the output file.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const inPath = resolve(arg('--in', process.env.NIST_R5_METADATA ?? resolve(REPO_ROOT, '..', 'nist-r5-data', 'control-metadata.yaml')));
const outPath = resolve(arg('--out', resolve(REPO_ROOT, 'docs', 'nist-r5-controls.generated.json')));

if (!existsSync(inPath)) {
  console.error(`[extract-nist-r5] control-metadata.yaml not found at: ${inPath}`);
  console.error('[extract-nist-r5] Clone git@github.com:GovReady/nist-sp-800-53-r5-data.git and pass --in, or set NIST_R5_METADATA.');
  process.exit(1);
}

/** Normalize "AC-2", "AC-2(1)" → FRMR-style "ac-2", "ac-2.1". */
function frmrKey(control) {
  const m = String(control).match(/^([A-Za-z]{2})-(\d+)(?:\((\d+)\))?$/);
  if (!m) return String(control).toLowerCase();
  const [, fam, num, enh] = m;
  return enh ? `${fam.toLowerCase()}-${num}.${enh}` : `${fam.toLowerCase()}-${num}`;
}

const entries = parseYaml(readFileSync(inPath, 'utf8'));
if (!Array.isArray(entries)) {
  console.error('[extract-nist-r5] expected a YAML array of control metadata');
  process.exit(1);
}

const lookup = {};
for (const e of entries) {
  if (!e || !e.control) continue;
  lookup[frmrKey(e.control)] = { id: e.control, name: e.name ?? null, family: e.family ?? null };
}

writeFileSync(outPath, JSON.stringify(lookup, null, 2));
console.error(`[extract-nist-r5] wrote ${Object.keys(lookup).length} controls → ${outPath}`);
