#!/usr/bin/env node
/**
 * extract-prohibited-vendors.mjs — offline one-shot snapshot fetcher for
 * LOOP-W.W1.
 *
 * Downloads the live federal prohibited-vendor feeds into a dated snapshot
 * directory and writes a MANIFEST.json (per-file SHA-256 + bytes + url +
 * fetched_at). The core ingester (core/prohibited-vendors-catalog.ts) then
 * reads this snapshot deterministically — the collector never needs the network
 * at catalog-emit time. This mirrors the repo's other extract-*.mjs scripts:
 * the network lives here; the core reads committed/snapshotted files.
 *
 * Network sources fetched:
 *   - OFAC SDN          : sdn.csv, add.csv, alt.csv (Treasury)
 *   - BIS Entity List   : consolidated.csv (trade.gov consolidated screening list)
 *   - SAM.gov Exclusions: sam-exclusions-page-NNN.json (paginated; needs SAM_GOV_API_KEY)
 *
 * Committed statutory constants (far-52-204-25-named-entities.json,
 * ndaa-1634-named-entities.json, fascsa-orders.json) are copied into the
 * snapshot for a complete forensic record.
 *
 * Usage:
 *   node scripts/extract-prohibited-vendors.mjs                 # today's snapshot
 *   node scripts/extract-prohibited-vendors.mjs --date 20260607 # explicit date
 *   node scripts/extract-prohibited-vendors.mjs --force         # re-download existing files
 *   node scripts/extract-prohibited-vendors.mjs --skip-sam      # omit the SAM fetch
 *
 * Idempotent: re-running on the same day reuses the directory and skips files
 * already present unless --force is passed. On a terminal fetch failure the
 * script exits non-zero and does NOT write a partial MANIFEST (no silent
 * fallback to stale data).
 */
import { mkdirSync, writeFileSync, readFileSync, existsSync, copyFileSync, statSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');
const DATA_DIR = resolve(REPO_ROOT, 'data');

const OFAC_FILES = ['sdn.csv', 'add.csv', 'alt.csv'];
const OFAC_BASE = 'https://www.treasury.gov/ofac/downloads';
const BIS_URL = 'https://api.trade.gov/static/consolidated_screening_list/consolidated.csv';
const SAM_BASE = 'https://api.sam.gov/entity-information/v3/entities';
const CONSTANT_FILES = [
  'far-52-204-25-named-entities.json',
  'ndaa-1634-named-entities.json',
  'fascsa-orders.json',
];

function parseArgs(argv) {
  const args = { date: null, force: false, skipSam: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--date') args.date = argv[++i] ?? null;
    else if (a === '--force') args.force = true;
    else if (a === '--skip-sam') args.skipSam = true;
  }
  return args;
}

function todayYyyymmdd() {
  // Date is intentionally read from the system clock; the snapshot directory is
  // named for the fetch date so re-runs on the same day are idempotent.
  return new Date().toISOString().slice(0, 10).replace(/-/g, '');
}

function sha256Hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

async function fetchBuffer(url) {
  const resp = await fetch(url, { method: 'GET', headers: { accept: '*/*' } });
  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status} ${resp.statusText} for ${url}`);
  }
  const ab = await resp.arrayBuffer();
  return Buffer.from(ab);
}

async function fetchWithRetry(url, attempts = 3) {
  let lastErr;
  for (let i = 1; i <= attempts; i++) {
    try {
      return await fetchBuffer(url);
    } catch (e) {
      lastErr = e;
      if (i < attempts) {
        const delay = 1000 * Math.pow(4, i - 1);
        await new Promise((r) => setTimeout(r, delay));
      }
    }
  }
  throw lastErr;
}

function writeAndRecord(records, snapshotDir, filename, buf, url) {
  const path = join(snapshotDir, filename);
  writeFileSync(path, buf);
  records.push({
    filename,
    sha256: sha256Hex(buf),
    bytes: buf.length,
    url,
    fetched_at: new Date().toISOString(),
  });
}

async function main() {
  const args = parseArgs(process.argv);
  const date = args.date ?? todayYyyymmdd();
  const snapshotDir = resolve(DATA_DIR, `prohibited-vendors-snapshot-${date}`);
  mkdirSync(snapshotDir, { recursive: true });
  console.log(`[extract-prohibited-vendors] snapshot dir: ${snapshotDir}`);

  const records = [];
  const existingFresh = (filename) => existsSync(join(snapshotDir, filename)) && !args.force;

  // OFAC SDN feeds.
  for (const f of OFAC_FILES) {
    if (existingFresh(f)) {
      const buf = readFileSync(join(snapshotDir, f));
      records.push({ filename: f, sha256: sha256Hex(buf), bytes: buf.length, url: `${OFAC_BASE}/${f}`, fetched_at: new Date(statSync(join(snapshotDir, f)).mtime).toISOString() });
      console.log(`[ofac] reuse ${f} (${buf.length} bytes)`);
      continue;
    }
    const url = `${OFAC_BASE}/${f}`;
    const buf = await fetchWithRetry(url);
    writeAndRecord(records, snapshotDir, f, buf, url);
    console.log(`[ofac] fetched ${f} (${buf.length} bytes)`);
  }

  // BIS Entity List via the trade.gov consolidated screening list.
  if (existingFresh('consolidated.csv')) {
    const buf = readFileSync(join(snapshotDir, 'consolidated.csv'));
    records.push({ filename: 'consolidated.csv', sha256: sha256Hex(buf), bytes: buf.length, url: BIS_URL, fetched_at: new Date(statSync(join(snapshotDir, 'consolidated.csv')).mtime).toISOString() });
    console.log(`[bis] reuse consolidated.csv (${buf.length} bytes)`);
  } else {
    const buf = await fetchWithRetry(BIS_URL);
    writeAndRecord(records, snapshotDir, 'consolidated.csv', buf, BIS_URL);
    console.log(`[bis] fetched consolidated.csv (${buf.length} bytes)`);
  }

  // SAM.gov Exclusions (paginated). Requires SAM_GOV_API_KEY.
  if (!args.skipSam) {
    const key = process.env.SAM_GOV_API_KEY;
    if (!key || !/^[A-Za-z0-9]{20,80}$/.test(key)) {
      throw new Error('SAM_GOV_API_KEY required (20-80 alphanumeric) to fetch SAM Exclusions; obtain at https://sam.gov/data-services, or pass --skip-sam.');
    }
    let pageNumber = 0;
    let totalRecords = Infinity;
    const pageSize = 1000;
    while (pageNumber * pageSize < totalRecords) {
      const url = `${SAM_BASE}?samRegistered=Yes&includeSections=exclusions&pageSize=${pageSize}&pageNumber=${pageNumber}&api_key=${encodeURIComponent(key)}`;
      const buf = await fetchWithRetry(url);
      const pageFile = `sam-exclusions-page-${String(pageNumber + 1).padStart(3, '0')}.json`;
      // Record the URL with the key redacted so MANIFEST.json carries no secret.
      writeAndRecord(records, snapshotDir, pageFile, buf, url.replace(/api_key=[^&]+/, 'api_key=[redacted]'));
      try {
        const parsed = JSON.parse(buf.toString('utf8'));
        if (typeof parsed.totalRecords === 'number') totalRecords = parsed.totalRecords;
        else totalRecords = (pageNumber + 1) * pageSize; // single page when the count is absent
      } catch {
        totalRecords = (pageNumber + 1) * pageSize;
      }
      console.log(`[sam] fetched ${pageFile} (page ${pageNumber + 1})`);
      pageNumber++;
      if (pageNumber > 1000) break; // hard ceiling against a runaway pager
    }
  } else {
    console.log('[sam] skipped (--skip-sam)');
  }

  // Copy committed statutory constants into the snapshot for a complete record.
  for (const f of CONSTANT_FILES) {
    const src = resolve(DATA_DIR, f);
    if (!existsSync(src)) {
      console.warn(`[constants] missing committed constant ${f} — skipping`);
      continue;
    }
    copyFileSync(src, join(snapshotDir, f));
    const buf = readFileSync(src);
    records.push({ filename: f, sha256: sha256Hex(buf), bytes: buf.length, url: `committed:data/${f}`, fetched_at: new Date().toISOString() });
    console.log(`[constants] copied ${f}`);
  }

  const manifest = { generated_at: new Date().toISOString(), files: records.sort((a, b) => a.filename.localeCompare(b.filename)) };
  writeFileSync(join(snapshotDir, 'MANIFEST.json'), JSON.stringify(manifest, null, 2));
  console.log(`[extract-prohibited-vendors] wrote MANIFEST.json with ${records.length} file(s).`);
  console.log(`[extract-prohibited-vendors] done. Run the orchestrator with --prohibited-vendors-catalog (snapshot: ${snapshotDir}).`);
}

main().catch((e) => {
  console.error(`[extract-prohibited-vendors] FAILED: ${e?.message ?? e}`);
  process.exit(1);
});
