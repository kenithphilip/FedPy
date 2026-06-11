#!/usr/bin/env node
/**
 * fetch-conmon-playbook.mjs — human-run pin of the FedRAMP Continuous
 * Monitoring Playbook (LOOP-E.E1).
 *
 * The FedRAMP ConMon Playbook v1.0 (2025-11-17) is an 888 KB PDF. We do NOT
 * parse the PDF at build time (no poppler / no PDF text-extract dependency in
 * production). Instead this script — run by a human on a network-connected
 * machine, the same pattern as scripts/extract-frmr-requirements.mjs — does
 * three things and writes the result to docs/fedramp-conmon-playbook.generated.json:
 *
 *   1. Downloads the canonical PDF from fedramp.gov.
 *   2. Computes the SHA-256 of the exact bytes downloaded (the drift anchor —
 *      a future re-run that produces a different hash means FedRAMP republished
 *      the playbook and the pinned constants below MUST be re-reviewed).
 *   3. Writes a JSON projection of the playbook's machine-relevant constants:
 *      the remediation-deadline table, the scan-cadence table, the monthly
 *      deliverables list, and the version / publication date.
 *
 * The remediation table + scan cadence + monthly-deliverables values are
 * FedRAMP-published constants (REO Rule 3 — "FedRAMP-published constants"),
 * quoted verbatim from the Rev5 ConMon Playbook and the Rev5 Playbook ConMon
 * Overview / Vulnerability Scanning pages. They are encoded here, not invented:
 *   - Remediation: Critical/High 30 days, Moderate 90 days, Low 180 days;
 *     accepted-vulnerability threshold 192 days.
 *   - Scan cadence: 100% monthly inventory; internet-reachable >= every 3 days;
 *     non-internet-reachable >= weekly (7 days).
 *
 * Re-run quarterly (RUNBOOK) to detect playbook drift.
 *
 * Usage:
 *   node scripts/fetch-conmon-playbook.mjs
 *   node scripts/fetch-conmon-playbook.mjs --offline   # re-pin constants without re-download (keeps prior sha256)
 */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');
const OUT_PATH = resolve(REPO_ROOT, 'docs/fedramp-conmon-playbook.generated.json');

const SOURCE_URL = 'https://www.fedramp.gov/resources/documents/Continuous_Monitoring_Playbook.pdf';

// FedRAMP-published constants (REO Rule 3). Verbatim from the Rev5 ConMon
// Playbook POA&M remediation table + the Rev5 Playbook ConMon Overview /
// Vulnerability Scanning pages.
const REMEDIATION_TABLE = { critical: 30, high: 30, moderate: 90, low: 180, accepted_threshold_days: 192 };
const SCAN_CADENCE = { monthly_inventory: 1.0, internet_reachable_days: 3, internal_days: 7 };
const MONTHLY_DELIVERABLES = [
  'Up-to-date Plan of Action and Milestones (POA&M)',
  'Up-to-date system inventory',
  'Raw vulnerability scan files (when required by agreements with agency customers)',
  'Monthly continuous-monitoring report(s) to the secure repository',
];
const PLAYBOOK_VERSION = '1.0';
const PLAYBOOK_PUBLISHED = '2025-11-17';

async function downloadSha256(url) {
  const res = await fetch(url, { redirect: 'follow' });
  if (!res.ok) throw new Error(`download failed: HTTP ${res.status} for ${url}`);
  const buf = Buffer.from(await res.arrayBuffer());
  return { sha256: createHash('sha256').update(buf).digest('hex'), bytes: buf.length };
}

async function main() {
  const offline = process.argv.includes('--offline');
  let sha256;
  let sourceBytes;

  if (offline) {
    if (!existsSync(OUT_PATH)) {
      throw new Error('--offline requires an existing docs/fedramp-conmon-playbook.generated.json to keep its sha256');
    }
    const prior = JSON.parse(readFileSync(OUT_PATH, 'utf8'));
    sha256 = prior.sha256;
    sourceBytes = prior.source_bytes ?? null;
    console.log(`[fetch-conmon-playbook] --offline: keeping prior sha256 ${sha256}`);
  } else {
    console.log(`[fetch-conmon-playbook] downloading ${SOURCE_URL} ...`);
    const dl = await downloadSha256(SOURCE_URL);
    sha256 = dl.sha256;
    sourceBytes = dl.bytes;
    console.log(`[fetch-conmon-playbook] ${sourceBytes} bytes, sha256=${sha256}`);
  }

  const projection = {
    remediation_table: REMEDIATION_TABLE,
    scan_cadence: SCAN_CADENCE,
    monthly_deliverables: MONTHLY_DELIVERABLES,
    playbook_version: PLAYBOOK_VERSION,
    playbook_published: PLAYBOOK_PUBLISHED,
    source_url: SOURCE_URL,
    source_bytes: sourceBytes,
    fetched_at: new Date().toISOString(),
    sha256,
  };

  writeFileSync(OUT_PATH, JSON.stringify(projection, null, 2) + '\n');
  console.log(`[fetch-conmon-playbook] wrote ${OUT_PATH}`);
}

main().catch((e) => {
  console.error(`[fetch-conmon-playbook] ${e?.message ?? e}`);
  process.exit(1);
});
