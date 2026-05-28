#!/usr/bin/env node
/**
 * extract-oscal-schemas.mjs (OSC-2)
 *
 * Fetch NIST's official OSCAL JSON Schemas once and commit them under
 * docs/oscal/ so the collector can validate the OSCAL it emits OFFLINE (same
 * "commit generated data, no runtime network" pattern as the NIST 800-53 data).
 *
 * Source: usnistgov/OSCAL GitHub release assets for a pinned version.
 *
 * Usage:
 *   node scripts/extract-oscal-schemas.mjs            # fetch + write
 *   node scripts/extract-oscal-schemas.mjs --offline  # require local cache only
 */
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');
const OUT_DIR = resolve(REPO_ROOT, 'docs', 'oscal');
const OFFLINE = process.argv.includes('--offline');

export const OSCAL_VERSION = '1.1.2';
/** Models we emit (assessment-results) or will emit (ssp, poam for the SSP pipeline). */
const MODELS = ['assessment-results', 'ssp', 'poam'];

const assetUrl = (model) =>
  `https://github.com/usnistgov/OSCAL/releases/download/v${OSCAL_VERSION}/oscal_${model}_schema.json`;

async function main() {
  if (OFFLINE) { console.error('[extract-oscal-schemas] --offline: nothing to fetch'); return; }
  mkdirSync(OUT_DIR, { recursive: true });
  for (const model of MODELS) {
    const url = assetUrl(model);
    const res = await fetch(url);
    if (!res.ok) throw new Error(`fetch ${url} → HTTP ${res.status}`);
    const json = await res.json();
    const out = resolve(OUT_DIR, `oscal_${model}_schema.v${OSCAL_VERSION}.json`);
    writeFileSync(out, JSON.stringify(json));
    console.error(`[extract-oscal-schemas] ${model}: ${(JSON.stringify(json).length / 1024).toFixed(0)} KB → ${out}`);
  }
  console.error(`[extract-oscal-schemas] done (OSCAL v${OSCAL_VERSION}).`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch((e) => { console.error(`[extract-oscal-schemas] ${e.message}`); process.exit(1); });
}

/** Path to a committed schema for a model (used by the runtime validator). */
export function oscalSchemaPath(model) {
  return resolve(OUT_DIR, `oscal_${model}_schema.v${OSCAL_VERSION}.json`);
}
