#!/usr/bin/env node
/**
 * extract-nist-baselines.mjs
 *
 * Produce a committed NIST SP 800-53 Rev5 baseline-membership lookup:
 *   { low: [control-ids], moderate: [...], high: [...] }
 * from NIST's official OSCAL "resolved baseline catalog" content (SP 800-53B).
 *
 * Source: usnistgov/oscal-content (the authoritative machine-readable 800-53B
 * baselines). We fetch the three resolved-profile catalogs and flatten every
 * control id (incl. enhancements, e.g. "ac-2.1") per baseline.
 *
 * This answers "which controls are in Low / Moderate / High" — the baseline
 * MEMBERSHIP the control benchmark gates on. Committed so the runtime never
 * needs network. Re-run to refresh.
 *
 * Usage:
 *   node scripts/extract-nist-baselines.mjs            # fetch from NIST + write
 *   node scripts/extract-nist-baselines.mjs --offline  # require local cached catalogs
 * Caches downloaded catalogs under ../nist-r5-data/oscal-cache/ (gitignored).
 */
import { writeFileSync, readFileSync, existsSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');
const CACHE_DIR = resolve(REPO_ROOT, '..', 'nist-r5-data', 'oscal-cache');
const OUT = resolve(REPO_ROOT, 'docs', 'nist-r5-baselines.generated.json');
const OFFLINE = process.argv.includes('--offline');

const BASE = 'https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json';
const BASELINES = {
  low: `${BASE}/NIST_SP-800-53_rev5_LOW-baseline-resolved-profile_catalog.json`,
  moderate: `${BASE}/NIST_SP-800-53_rev5_MODERATE-baseline-resolved-profile_catalog.json`,
  high: `${BASE}/NIST_SP-800-53_rev5_HIGH-baseline-resolved-profile_catalog.json`,
};

async function loadCatalog(level, url) {
  const cachePath = resolve(CACHE_DIR, `${level}.json`);
  if (existsSync(cachePath)) {
    return JSON.parse(readFileSync(cachePath, 'utf8'));
  }
  if (OFFLINE) throw new Error(`--offline set but no cached catalog at ${cachePath}`);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`fetch ${url} → HTTP ${res.status}`);
  const json = await res.json();
  mkdirSync(CACHE_DIR, { recursive: true });
  writeFileSync(cachePath, JSON.stringify(json));
  return json;
}

/** Recursively collect every control id under a catalog/group. */
function collectControlIds(node, acc) {
  for (const c of node.controls ?? []) {
    if (c.id) acc.add(c.id);
    collectControlIds(c, acc); // enhancements live as nested controls
  }
  for (const g of node.groups ?? []) collectControlIds(g, acc);
}

const out = { _source: 'NIST SP 800-53B Rev5 (usnistgov/oscal-content)', _generated_at: new Date().toISOString(), low: [], moderate: [], high: [] };
for (const [level, url] of Object.entries(BASELINES)) {
  const doc = await loadCatalog(level, url);
  const cat = doc.catalog ?? doc;
  const ids = new Set();
  collectControlIds(cat, ids);
  out[level] = [...ids].sort();
  console.error(`[extract-nist-baselines] ${level}: ${out[level].length} controls`);
}
writeFileSync(OUT, JSON.stringify(out, null, 2));
console.error(`[extract-nist-baselines] wrote ${OUT}`);
