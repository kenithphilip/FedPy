#!/usr/bin/env node
/**
 * extract-ssdf-practices.mjs — offline one-shot extractor for LOOP-T.T1.
 *
 * Builds the canonical, Ed25519-signed NIST SP 800-218 v1.1 (SSDF) practice
 * catalog (`data/ssdf-800-218-v1.1.json`) that downstream LOOP-T slices (T.T2
 * Common Form generator, T.T3 evidence aggregator, T.T5 KSI <-> SSDF gap matrix)
 * read via core/ssdf-practices-catalog.ts.
 *
 * Architecture (matches the repo's offline-first convention — cf.
 * scripts/extract-prohibited-vendors.mjs + core/prohibited-vendors-catalog.ts):
 * the published NIST PDF lives under version control at
 * `docs/sources/NIST.SP.800-218.pdf`. This extractor reads that committed PDF,
 * parses Table 1 (Practices / Tasks / References) deterministically, and emits a
 * signed catalog. Every practice intent, task statement, and SP 800-53 Rev 5
 * control mapping is taken VERBATIM from the PDF text — none is invented. The
 * 19 practice names + 4 practice-group definitions are NIST published-constant
 * identifiers (allowed-list constants per cloud-evidence/CLAUDE.md REO Rule 3);
 * each is re-verified to appear verbatim in the PDF text before emit
 * (ERR_SSDF_NAME_MISMATCH otherwise). The SSDF -> FedRAMP KSI forward map is the
 * operator's curated semantic mapping (scripts/data/ssdf-ksi-mapping.json), with
 * every referenced KSI id cross-checked against core/ksi-map.ts.
 *
 * REO compliance: every field traces to the NIST PDF, the curated KSI mapping,
 * or the signing key — none is invented. The catalog carries a top-level
 * `provenance` block (emitter, emittedAt, sourceCalls, signingKeyId — G3 keys)
 * plus the source PDF SHA-256 and a detached Ed25519 signature over the
 * canonical (signature-blanked) bytes.
 *
 * Run via tsx (it composes core/sign.ts):
 *   npm run build:ssdf-catalog                       # rebuild data/ssdf-800-218-v1.1.json
 *   tsx scripts/extract-ssdf-practices.mjs --out data # explicit out dir
 *   tsx scripts/extract-ssdf-practices.mjs --run-id <uuid>
 *
 * Idempotent: re-running against the same committed PDF produces byte-identical
 * canonical content (the only run-varying fields are the envelope signature +
 * extractedAt, which the consumer strips when comparing). On a typed failure the
 * extractor exits non-zero and writes NO catalog (no silent fallback to stale).
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { PDFParse } from 'pdf-parse';
import { signDetached } from '../core/sign.ts';
import {
  buildSsdfCatalog, serializeUnsignedCanonical, CATALOG_ID, CATALOG_FILENAME,
  EXPECTED_PRACTICE_IDS, SsdfExtractError,
} from '../core/ssdf-practices-catalog.ts';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');
const PDF_REL = 'docs/sources/NIST.SP.800-218.pdf';
const KSI_MAP_PATH = resolve(REPO_ROOT, 'core/ksi-map.ts');
const KSI_MAPPING_PATH = resolve(REPO_ROOT, 'scripts/data/ssdf-ksi-mapping.json');

/** Error -> process exit code (T.T1 §8 test T17 expects 4 on SHA-256 drift). */
const EXIT_CODES = {
  ERR_SSDF_SOURCE_MISSING: 2,
  ERR_SSDF_KSI_MAPPING_MISSING: 2,
  ERR_SSDF_SHAPE_MISMATCH: 3,
  ERR_SSDF_NAME_MISMATCH: 3,
  ERR_SSDF_STATEMENT_MISSING: 3,
  ERR_SSDF_KSI_UNKNOWN: 3,
  ERR_SSDF_KSI_MAPPING_UNREVIEWED: 3,
  ERR_SSDF_SOURCE_SHA256_DRIFT: 4,
};

function sha256Hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

function parseArgs(argv) {
  const args = { out: 'data', runId: null };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--out') args.out = argv[++i] ?? 'data';
    else if (a === '--run-id') args.runId = argv[++i] ?? null;
  }
  return args;
}

/** Read core/ksi-map.ts and return the set of known KSI ids (no TS import needed). */
function loadKnownKsiIds() {
  const src = readFileSync(KSI_MAP_PATH, 'utf8');
  const ids = new Set();
  for (const m of src.matchAll(/id:\s*'(KSI-[A-Z0-9-]+)'/g)) ids.add(m[1]);
  if (ids.size === 0) {
    throw new SsdfExtractError('ERR_SSDF_KSI_MAPPING_MISSING', `No KSI ids found in ${KSI_MAP_PATH}`);
  }
  return ids;
}

/** Normalize PDF text: smart quotes/dashes -> ASCII, collapse nbsp. */
function normalize(s) {
  return s
    .replace(/’|‘/g, "'")
    .replace(/“|”/g, '"')
    .replace(/–|—/g, '-')
    .replace(/ /g, ' ');
}

/**
 * Parse Table 1 of NIST SP 800-218 v1.1 from the extracted PDF text.
 * Returns { practiceIntents, activeTasks, withdrawnTasks } where:
 *   - practiceIntents: { [practiceId]: intent string (verbatim) }
 *   - activeTasks:     [{ id, statement, controls: string[] }] in document order
 *   - withdrawnTasks:  [{ id, moved_to }]
 */
function parsePdfText(rawText) {
  const text = normalize(rawText);
  const squashed = text.replace(/\s+/g, ' ');

  // Region: from the first practice anchor "(PO.1): " to the first Appendix.
  const start = squashed.indexOf('(PO.1): ');
  if (start < 0) throw new SsdfExtractError('ERR_SSDF_SHAPE_MISMATCH', 'Could not locate Table 1 start "(PO.1): " in PDF text.');
  const apxIdx = squashed.search(/Appendix [A-F]/);
  const region = squashed.slice(start, apxIdx > start ? apxIdx : undefined);

  // Task headings, in document order.
  const taskRe = /\b((?:PO|PS|PW|RV)\.\d+\.\d+): /g;
  const marks = [];
  let m;
  while ((m = taskRe.exec(region))) marks.push({ id: m[1], at: m.index, after: m.index + m[0].length });

  const activeTasks = [];
  const withdrawnTasks = [];
  for (let i = 0; i < marks.length; i++) {
    const cur = marks[i];
    const next = marks[i + 1];
    const seg = region.slice(cur.after, next ? next.at : region.length);
    const trimmed = seg.trim();
    if (/^Moved to/.test(trimmed)) {
      // Destination id(s): take everything up to the first page-artifact / sentence end.
      const dest = trimmed.replace(/^Moved to\s+/, '').split(/\s+(?:--|NIST SP|$)/)[0].trim();
      withdrawnTasks.push({ id: cur.id, moved_to: dest });
      continue;
    }
    // Statement = text up to the first "Example N:".
    const exIdx = seg.search(/ Example \d+: /);
    const statement = (exIdx >= 0 ? seg.slice(0, exIdx) : seg).trim();
    // SP 800-53 controls from the per-task "SP80053:" reference line.
    const sp = seg.match(/SP80053: ([A-Z0-9()\-,. ]+?)(?: [A-Z][A-Za-z0-9]+:| Example | (?:PO|PS|PW|RV)\.|$)/);
    const controls = sp
      ? sp[1].split(',').map((s) => s.trim().toLowerCase()).filter((s) => /^[a-z]{2}-\d/.test(s))
      : [];
    activeTasks.push({ id: cur.id, statement, controls });
  }

  // Practice intents: text between "(ID): " and the practice's first task heading.
  const practiceIntents = {};
  for (const id of EXPECTED_PRACTICE_IDS) {
    const anchor = `(${id}): `;
    const ai = squashed.indexOf(anchor);
    if (ai < 0) throw new SsdfExtractError('ERR_SSDF_SHAPE_MISMATCH', `Practice anchor "${anchor}" not found in PDF text.`);
    const s = ai + anchor.length;
    const tr = /(?:PO|PS|PW|RV)\.\d+\.\d+: /g;
    tr.lastIndex = s;
    const tm = tr.exec(squashed);
    practiceIntents[id] = squashed.slice(s, tm ? tm.index : s).trim();
  }

  return { practiceIntents, activeTasks, withdrawnTasks, squashed };
}

async function main() {
  const args = parseArgs(process.argv);
  const outDir = resolve(REPO_ROOT, args.out);
  const pdfPath = resolve(REPO_ROOT, PDF_REL);

  if (!existsSync(pdfPath)) {
    throw new SsdfExtractError('ERR_SSDF_SOURCE_MISSING',
      `Source PDF missing at ${PDF_REL}. Download from https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf and commit it.`);
  }
  if (!existsSync(KSI_MAPPING_PATH)) {
    throw new SsdfExtractError('ERR_SSDF_KSI_MAPPING_MISSING', `Curated KSI mapping missing at ${KSI_MAPPING_PATH}.`);
  }

  // 1. Source PDF: read + SHA-256. Drift-check against any prior catalog.
  const pdfBuf = readFileSync(pdfPath);
  const sourcePdfSha256 = sha256Hex(pdfBuf);
  const catalogPath = resolve(outDir, CATALOG_FILENAME);
  if (existsSync(catalogPath)) {
    try {
      const prior = JSON.parse(readFileSync(catalogPath, 'utf8'));
      const priorSha = prior?.source_pdf_sha256;
      if (priorSha && priorSha !== sourcePdfSha256) {
        throw new SsdfExtractError('ERR_SSDF_SOURCE_SHA256_DRIFT',
          `Source PDF SHA-256 (${sourcePdfSha256.slice(0, 12)}…) differs from the committed catalog's pinned hash (${String(priorSha).slice(0, 12)}…). ` +
          `NIST may have republished 800-218; do NOT silently overwrite — review the change and bump the catalog version deliberately.`);
      }
    } catch (e) {
      if (e instanceof SsdfExtractError) throw e;
      /* malformed prior catalog: fall through and regenerate */
    }
  }

  // 2. Parse PDF text.
  const parser = new PDFParse({ data: new Uint8Array(pdfBuf) });
  const parsed = await parser.getText();
  const { practiceIntents, activeTasks, withdrawnTasks, squashed } = parsePdfText(parsed.text);

  // 3. Curated KSI forward map + cross-check against core/ksi-map.ts.
  const mapping = JSON.parse(readFileSync(KSI_MAPPING_PATH, 'utf8'));
  if (mapping.reviewed !== true) {
    throw new SsdfExtractError('ERR_SSDF_KSI_MAPPING_UNREVIEWED',
      `${KSI_MAPPING_PATH} must set "reviewed": true before the curated SSDF->KSI forward map can ship.`);
  }
  const knownKsi = loadKnownKsiIds();
  for (const [practiceId, pairs] of Object.entries(mapping.map ?? {})) {
    for (const pair of pairs) {
      if (!knownKsi.has(pair.ksi_id)) {
        throw new SsdfExtractError('ERR_SSDF_KSI_UNKNOWN',
          `KSI "${pair.ksi_id}" referenced for SSDF practice ${practiceId} does not exist in core/ksi-map.ts.`);
      }
    }
  }
  const ksiMapSha256 = sha256Hex(readFileSync(KSI_MAPPING_PATH));

  // 4. Build the (unsigned) catalog — shared builder validates shape + names.
  const catalog = buildSsdfCatalog({
    practiceIntents,
    activeTasks,
    withdrawnTasks,
    pdfText: squashed,
    sourcePdfSha256,
    ksiForwardMap: mapping.map ?? {},
    mappingSource: mapping.mapping_source,
    nist53Revision: mapping.nist_53_revision,
    ksiMapSha256,
    runId: args.runId ?? randomUUID(),
    extractedAt: new Date().toISOString(),
  });

  // 5. Sign (detached Ed25519 over the canonical signature-blanked bytes).
  //    When EVIDENCE_SIGNING_KEY_PATH is unset, signDetached persists an
  //    ephemeral keypair into the key dir — keep that OUT of the committed
  //    data/ dir by using a transient temp dir (the catalog self-verifies via
  //    its embedded public key, so the ephemeral private key is not retained).
  if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
  const keyDir = mkdtempSync(resolve(tmpdir(), 'ssdf-sign-'));
  const canonical = serializeUnsignedCanonical(catalog);
  const sig = signDetached(Buffer.from(canonical, 'utf8'), keyDir);
  if (!process.env.EVIDENCE_SIGNING_KEY_PATH) {
    try { rmSync(keyDir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
  catalog.provenance.signingKeyId = sig.keyId;
  catalog.provenance.publicKeyPem = sig.publicKeyPem;
  catalog.provenance.signatureEd25519 = sig.signatureBase64;

  // 6. Write catalog + detached .sig sidecar.
  const catalogBytes = Buffer.from(JSON.stringify(catalog, null, 2) + '\n', 'utf8');
  writeFileSync(catalogPath, catalogBytes);
  writeFileSync(resolve(outDir, `${CATALOG_FILENAME}.sig`), JSON.stringify({
    algorithm: 'ed25519',
    keyId: sig.keyId,
    publicKeyPem: sig.publicKeyPem,
    sigBase64: sig.signatureBase64,
  }, null, 2) + '\n');

  const taskTotal = catalog.practices.reduce((a, p) => a + p.tasks.length, 0);
  console.log(`[extract-ssdf-practices] ${CATALOG_ID}: ${catalog.practices.length} practices, ${taskTotal} tasks, ` +
    `${catalog.statistics.withdrawn_task_count} withdrawn tasks, ${catalog.statistics.practices_with_ksi_map} KSI-mapped practices.`);
  console.log(`[extract-ssdf-practices] source_pdf_sha256=${sourcePdfSha256}`);
  console.log(`[extract-ssdf-practices] wrote ${catalogPath} (${catalogBytes.length} bytes), ephemeral_key=${sig.ephemeralKey}.`);
}

main().catch((e) => {
  if (e instanceof SsdfExtractError) {
    console.error(`[extract-ssdf-practices] FAILED [${e.code}]: ${e.message}`);
    process.exit(EXIT_CODES[e.code] ?? 3);
  }
  console.error(`[extract-ssdf-practices] FAILED: ${e?.stack ?? e?.message ?? e}`);
  process.exit(1);
});
