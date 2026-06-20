/**
 * FedRAMP 20x submission package bundler — LOOP-A.A4.
 *
 * Produces a single, signed, timestamped tarball that contains EVERYTHING a
 * 3PAO / FedRAMP PMO / Authorizing Official needs to review a submission:
 *
 *   submission-package.tar.gz
 *     INDEX.json              ← top-level manifest of every artifact (this file)
 *     ssp.json + ssp.xml      ← OSCAL SSP (LOOP-A from SSP-1) — if present
 *     ssp.docx                ← FedRAMP Word render (SSP-2) — if present
 *     ap.json  + ap.xml       ← OSCAL Assessment Plan (LOOP-A.A2) — if present
 *     assessment-results.json + .xml  ← OSCAL AR (LOOP-A.A3 chain) — if present
 *     poam.json + poam.xml    ← OSCAL POA&M (LOOP-A.A1) — if present
 *     inventory-workbook.xlsx ← FedRAMP Appendix M IIW — if present
 *     manifest.json           ← existing Ed25519-signed file manifest
 *     manifest.sig            ← Ed25519 signature
 *     timestamp.tsr           ← RFC 3161 trusted timestamp — if present
 *     KSI-*.json              ← per-KSI evidence envelopes
 *     summaries/*.md          ← CSX-SUM per-KSI markdown — if present
 *
 * Why this exists:
 *   The FedRAMP secure repository (USDA Connect.gov for Low/Moderate per R2
 *   findings) expects a single uploadable artifact per submission, not a
 *   loose directory. The bundler also performs:
 *     1. Chain integrity check — SSP → AP → AR → POA&M references resolve.
 *     2. Manifest coverage check — every JSON/XML in the bundle is covered
 *        by manifest.json (or explicitly excluded with a documented reason).
 *     3. Package-format versioning — `INDEX.json.package_format_version`
 *        carries the operator's claim about which FedRAMP submission format
 *        the bundle targets. We default to "20x.phase-two.preview.2026" per
 *        R3 (no post-pilot guidance published yet); a future format shift
 *        produces a clean version bump.
 *
 * Tarball implementation:
 *   POSIX ustar (header + body) + gzip via node's built-in zlib. No external
 *   dependencies. Deterministic when mtime is fixed (we set every header's
 *   mtime to the run's wall-clock OR an operator-supplied --mtime for
 *   reproducible builds). All files emitted with mode 0644 / uid 0 / gid 0
 *   so the bundle hash is stable across machines.
 *
 * REO compliance:
 *   - Every byte in the bundle is sourced from a real on-disk file the
 *     orchestrator emitted earlier in the same run. The bundler never
 *     synthesizes content — it only packages.
 *   - The INDEX.json provenance entry names the bundler module + cites
 *     every file it included with sha256.
 *   - When a required artifact is missing (e.g. no SSP), the bundler
 *     records that gap in INDEX.json.gaps[] and (if --strict-bundle is
 *     set) refuses to write the tarball.
 *
 * Pure builder (`buildSubmissionIndex`, `writeTar`) + disk reader/emitter
 * (`emitSubmissionBundle`).
 */
import { readFileSync, writeFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { resolve, basename, relative } from 'node:path';
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { log } from './log.ts';

const PACKAGE_FORMAT_VERSION = '20x.phase-two.preview.2026';
const TOOL_NAME = 'fedramp-20x-cloud-evidence';
const BUNDLER_MODULE = 'core/submission-bundle.ts';

// ─── Artifact catalogue ──────────────────────────────────────────────────────
//
// The bundler knows about a fixed list of "well-known" artifacts each with a
// stable role + required/optional status. Any file outside this list that
// also lives in the manifest is included verbatim (e.g. KSI-*.json) so the
// per-KSI evidence ships alongside the OSCAL package.

type Role =
  | 'oscal-ssp'
  | 'oscal-ssp-xml'
  | 'oscal-ssp-docx'
  | 'oscal-ap'
  | 'oscal-ap-xml'
  | 'oscal-ar'
  | 'oscal-ar-xml'
  | 'oscal-poam'
  | 'oscal-poam-xml'
  | 'rules-of-engagement-docx'
  | 'inventory-workbook-xlsx'
  | 'inventory-workbook-csv'
  | 'inventory-coverage-report'
  | 'integrated-inventory-json'
  | 'signed-manifest'
  | 'signed-manifest-sig'
  | 'rfc3161-timestamp'
  | 'ksi-evidence'
  | 'csx-summary-markdown'
  | 'crosswalk-report'
  | 'diff-report'
  | 'scn-classification'
  | 'scn-notice-draft'
  | 'pva-summary'
  | 'oscal-validation-report'
  | 'prohibited-vendors-catalog'
  | 'prohibited-vendors-screen-json'
  | 'prohibited-vendors-screen-xlsx'
  | 'risk-scores-json'
  | 'epss-cache'
  | 'ssdf-practice-catalog-json'
  | 'subprocessor-inventory-json'
  | 'subprocessor-inventory-xlsx'
  | 'supply-chain-risk-register-json'
  | 'supply-chain-risk-register-xlsx'
  | 'deadline-audit-json'
  | 'conmon-monthly-report-json'
  | 'conmon-monthly-report-md'
  | 'conmon-monthly-report-pdf'
  | 'poam-delta-md'
  | 'poam-ledger'
  | 'poam-archive'
  | 'section889-1bd-report-json'
  | 'section889-1bd-report-docx'
  | 'section889-1bd-report-sig'
  | 'section889-1bd-ledger'
  | 'section889-annual-rep-json'
  | 'section889-annual-rep-docx'
  | 'section889-annual-rep-sig'
  | 'section889-annual-rep-ledger'
  | 'marketplace-section889-badge'
  | 'ssdf-satisfaction-matrix-json'
  | 'ssdf-satisfaction-matrix-xlsx';

interface WellKnownArtifact {
  role: Role;
  filename: string | RegExp;
  required?: boolean;
  description: string;
}

const WELL_KNOWN: WellKnownArtifact[] = [
  { role: 'oscal-ssp', filename: 'ssp.json', required: true, description: 'OSCAL System Security Plan (v1.1.2)' },
  { role: 'oscal-ssp-xml', filename: 'ssp.xml', description: 'OSCAL SSP — XML representation' },
  { role: 'oscal-ssp-docx', filename: 'ssp.docx', description: 'FedRAMP-style Word render of the SSP' },
  { role: 'oscal-ap', filename: 'ap.json', required: true, description: 'OSCAL Assessment Plan / SAP draft (v1.1.2)' },
  { role: 'oscal-ap-xml', filename: 'ap.xml', description: 'OSCAL AP — XML representation' },
  { role: 'oscal-ar', filename: 'assessment-results.json', required: true, description: 'OSCAL Assessment Results / SAR (v1.1.2)' },
  { role: 'oscal-ar-xml', filename: 'assessment-results.xml', description: 'OSCAL AR — XML representation' },
  { role: 'oscal-poam', filename: 'poam.json', description: 'OSCAL Plan of Action and Milestones (v1.1.2) — emitted only when failing findings exist' },
  { role: 'oscal-poam-xml', filename: 'poam.xml', description: 'OSCAL POA&M — XML representation' },
  { role: 'rules-of-engagement-docx', filename: 'roe.docx', description: 'Rules of Engagement Word template — 3PAO completes + signs' },
  { role: 'inventory-workbook-xlsx', filename: 'inventory-workbook.xlsx', required: true, description: 'FedRAMP Integrated Inventory Workbook (Appendix M)' },
  { role: 'inventory-workbook-csv', filename: 'inventory-workbook.csv', description: 'Inventory Workbook — CSV representation' },
  { role: 'inventory-coverage-report', filename: 'inventory-coverage.json', description: 'Per-run cell-level coverage report against the FedRAMP Appendix M contract' },
  { role: 'integrated-inventory-json', filename: 'inventory.json', description: 'Structured inventory (asset-level) used by SSP + AP + IIW' },
  { role: 'signed-manifest', filename: 'manifest.json', required: true, description: 'Ed25519-signed manifest of every JSON/XML/PEM file' },
  { role: 'signed-manifest-sig', filename: 'manifest.sig', required: true, description: 'Detached Ed25519 signature over the canonical manifest' },
  { role: 'rfc3161-timestamp', filename: 'timestamp.tsr', description: 'RFC 3161 trusted timestamp over the manifest' },
  { role: 'ksi-evidence', filename: /^KSI-[A-Z]+-[A-Z0-9]+(\.signed)?\.json$/, description: 'Per-KSI evidence envelope (one per registered KSI)' },
  { role: 'csx-summary-markdown', filename: /^summaries\/KSI-[A-Z]+-[A-Z0-9]+\.md$/, description: 'Per-KSI Implementation Summary (CSX-SUM)' },
  { role: 'crosswalk-report', filename: 'crosswalk-report.json', description: 'NIST → SOC2/ISO27001/HIPAA crosswalk' },
  { role: 'diff-report', filename: 'diff-report.json', description: 'Run-over-run drift analysis' },
  { role: 'scn-classification', filename: 'scn-classification.json', description: 'SCN classifier output for the run\'s diff' },
  { role: 'scn-notice-draft', filename: 'scn-notice-draft.md', description: 'Draft SCN notice Markdown (operator review)' },
  { role: 'pva-summary', filename: 'pva-run-summary.json', description: 'Persistent Validation & Assessment run summary' },
  { role: 'oscal-validation-report', filename: 'oscal-validation-report.json', description: 'ajv validation report for emitted OSCAL artifacts' },
  { role: 'prohibited-vendors-catalog', filename: 'prohibited-vendors-catalog.json', description: 'Prohibited-vendor catalog merged from OFAC SDN + BIS Entity List + SAM Exclusions + FAR 52.204-25 + NDAA §889 + NDAA §1634 + FASCSA (LOOP-W.W1)' },
  { role: 'prohibited-vendors-screen-json', filename: 'prohibited-vendors-screen-result.json', description: 'Prohibited-vendor screen result envelope per FAR 4.2101 reasonable inquiry — subprocessor + SBOM + OCI publisher + inventory surfaces screened against the W.W1 catalog (LOOP-W.W2)' },
  { role: 'prohibited-vendors-screen-xlsx', filename: 'prohibited-vendors-screen-result.xlsx', description: 'Operator-readable prohibited-vendor screen workbook — Matches / Surfaces Screened / Summary (LOOP-W.W2)' },
  { role: 'risk-scores-json', filename: 'risk-scores.json', description: 'Per-finding CVSS+EPSS+criticality+exposure composite scores (LOOP-B.B1)' },
  { role: 'epss-cache', filename: '.epss-cache.json', description: 'On-disk FIRST EPSS API response cache (24h TTL) — provenance-stamped (LOOP-B.B1)' },
  { role: 'ssdf-practice-catalog-json', filename: 'ssdf-800-218-v1.1.json', description: 'NIST SP 800-218 v1.1 (SSDF) practice catalog — 19 practices, 42 tasks, 800-53 Rev 5 + FedRAMP KSI crosswalk (LOOP-T.T1); included when --include-ssdf-catalog is set (T.T2)' },
  { role: 'subprocessor-inventory-json', filename: 'subprocessor-inventory.json', description: 'SA-9 Subprocessor Inventory — risk-tiered, signed; feeds SSP leveraged-authorizations (LOOP-J.J2)' },
  { role: 'subprocessor-inventory-xlsx', filename: 'subprocessor-inventory.xlsx', description: 'SA-9 Subprocessor Inventory — FedRAMP-style Excel format (LOOP-J.J2)' },
  { role: 'supply-chain-risk-register-json', filename: 'supply-chain-risk-register.json', description: 'SR-3 / NIST SP 800-161r1 supply chain risk register (per-system C-SCRM Plan) — signed (LOOP-J.J3)' },
  { role: 'supply-chain-risk-register-xlsx', filename: 'supply-chain-risk-register.xlsx', description: 'Supply chain risk register — FedRAMP-style Excel (one sheet per category) (LOOP-J.J3)' },
  { role: 'deadline-audit-json', filename: 'deadline-audit.json', description: 'Per-finding remediation-deadline-source audit log — KEV / FedRAMP CMP / PAIN-IRV-LEV / operator-override / severity-fallback (LOOP-B.B2)' },
  { role: 'conmon-monthly-report-json', filename: /^conmon-monthly-\d{4}-\d{2}\.json$/, description: 'Monthly ConMon analysis report — machine-readable JSON (signed; posture + scan coverage + POA&M activity + KEV exposure) (LOOP-E.E1)' },
  { role: 'conmon-monthly-report-md', filename: /^conmon-monthly-\d{4}-\d{2}\.md$/, description: 'Monthly ConMon analysis report — Markdown render for operator review (LOOP-E.E1)' },
  { role: 'conmon-monthly-report-pdf', filename: /^conmon-monthly-\d{4}-\d{2}\.pdf$/, description: 'Monthly ConMon analysis report — PDF for the FedRAMP secure-repository upload (LOOP-E.E1)' },
  { role: 'poam-delta-md', filename: /^poam-delta-\d{4}-\d{2}\.md$/, description: 'Month-over-month POA&M delta (items opened / closed / status + severity flips / past-deadline) for operator review before the monthly upload (LOOP-E.E2)' },
  { role: 'poam-ledger', filename: 'poam-ledger.jsonl', description: 'Append-only ledger of monthly POA&M emissions (run_id, report_month, version, last-modified, sha256, archive path) — the version-chain index (LOOP-E.E2)' },
  { role: 'poam-archive', filename: /^archive\/poam-\d{4}-\d{2}\.json$/, description: 'Immutable monthly snapshot of the OSCAL POA&M, hashed in the ledger so the version chain is reconstructable (LOOP-E.E2)' },
  { role: 'section889-1bd-report-json', filename: /^section889-1bd-reports\/s889-[0-9a-f]+\.json$/, description: 'FAR 52.204-25(d) 1-business-day prohibited-vendor discovery report — signed canonical-JSON, one per (match × affected contract) (LOOP-W.W3)' },
  { role: 'section889-1bd-report-docx', filename: /^section889-1bd-reports\/s889-[0-9a-f]+\.docx$/, description: 'OOXML rendering of the FAR 52.204-25(d) 1-business-day report for operator transmission to the Contracting Officer / DIBNet (LOOP-W.W3)' },
  { role: 'section889-1bd-report-sig', filename: /^section889-1bd-reports\/s889-[0-9a-f]+\.json\.sig$/, description: 'Detached Ed25519 signature sidecar over the FAR 52.204-25(d) report envelope (LOOP-W.W3)' },
  { role: 'section889-1bd-ledger', filename: 'section889-1bd-reports.jsonl', description: 'Append-only ledger of FAR 52.204-25(d) 1BD report emissions (run_id, match_id, contract, report_kind, deadline, sha256) — the idempotency + audit index (LOOP-W.W3)' },
  { role: 'section889-annual-rep-json', filename: 'section889-annual-rep.json', description: 'FAR 52.204-26 Section 889 Part B annual representation — signed canonical-JSON envelope (the SAM.gov "does / does not" representation, driven by the W.W2 screen) (LOOP-W.W4)' },
  { role: 'section889-annual-rep-docx', filename: 'section889-annual-rep.docx', description: 'FAR 52.204-26 annual representation — printable OOXML for officer signature + SAM.gov submission (LOOP-W.W4)' },
  { role: 'section889-annual-rep-sig', filename: 'section889-annual-rep.json.sig', description: 'Detached Ed25519 signature sidecar over the FAR 52.204-26 annual representation envelope (LOOP-W.W4)' },
  { role: 'section889-annual-rep-ledger', filename: 'section889-annual-reps.jsonl', description: 'Append-only ledger of FAR 52.204-26 annual-representation emissions (envelope_uuid, signed_at, valid_until, provides/uses status, sha256) — the delta + continuity index (LOOP-W.W4)' },
  { role: 'marketplace-section889-badge', filename: 'marketplace-section889-badge.json', description: 'LOOP-Q.Q1 "Section 889 Compliant" Marketplace badge feed — enabled iff both representation answers are "does not" AND the representation is within its validity window (LOOP-W.W4)' },
  { role: 'ssdf-satisfaction-matrix-json', filename: /^ssdf-satisfaction-matrix(\.[a-z0-9-]+)?\.json$/, description: 'NIST SSDF (SP 800-218 v1.1) per-practice x per-task satisfaction matrix with typed evidence pointers, joining the T.T1 catalogue to the signed KSI evidence + risk + supply-chain corpus; backs the CISA Common Form Section IV attestations (LOOP-T.T2)' },
  { role: 'ssdf-satisfaction-matrix-xlsx', filename: /^ssdf-satisfaction-matrix(\.[a-z0-9-]+)?\.xlsx$/, description: 'Operator-readable SSDF satisfaction workbook — Per-Task Matrix + Per-Practice Summary (LOOP-T.T2)' },
];

// ─── Tar (POSIX ustar) writer ────────────────────────────────────────────────

interface TarEntry {
  name: string;
  content: Buffer;
  mtime: number;   // seconds since epoch
  mode?: number;   // POSIX file mode (default 0644)
}

/**
 * Write a POSIX ustar header (512 bytes) for a single file entry.
 * Reference: https://www.gnu.org/software/tar/manual/html_node/Standard.html
 */
function writeUstarHeader(name: string, size: number, mtime: number, mode: number): Buffer {
  const header = Buffer.alloc(512);
  // Name must be <= 100 bytes for ustar; longer names need the prefix field
  // (155 bytes) which we don't use because all our files are short.
  const nameBytes = Buffer.from(name, 'utf8');
  if (nameBytes.length > 100) {
    throw new Error(`submission-bundle: entry name too long for ustar (${nameBytes.length} > 100): ${name}`);
  }
  nameBytes.copy(header, 0);
  // mode (8 bytes, octal ASCII, NUL-terminated)
  Buffer.from(mode.toString(8).padStart(7, '0') + '\0').copy(header, 100);
  // uid (8) — always 0
  Buffer.from('0000000\0').copy(header, 108);
  // gid (8) — always 0
  Buffer.from('0000000\0').copy(header, 116);
  // size (12, octal ASCII)
  Buffer.from(size.toString(8).padStart(11, '0') + '\0').copy(header, 124);
  // mtime (12, octal ASCII, seconds since epoch)
  Buffer.from(mtime.toString(8).padStart(11, '0') + '\0').copy(header, 136);
  // checksum (8) — populated below after spaces fill
  Buffer.from('        ').copy(header, 148);
  // typeflag (1) — '0' = regular file
  header[156] = 0x30; // '0'
  // linkname (100) — empty
  // magic (6) — "ustar\0"
  Buffer.from('ustar\0').copy(header, 257);
  // version (2) — "00"
  Buffer.from('00').copy(header, 263);
  // uname (32) — "root"
  Buffer.from('root\0').copy(header, 265);
  // gname (32) — "root"
  Buffer.from('root\0').copy(header, 297);
  // Compute checksum: sum of all bytes treating the checksum field as spaces.
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += header[i]!;
  Buffer.from(sum.toString(8).padStart(6, '0') + '\0 ').copy(header, 148);
  return header;
}

/** Serialize a list of TarEntry to a single Buffer in POSIX ustar format. */
export function writeTar(entries: TarEntry[]): Buffer {
  const chunks: Buffer[] = [];
  for (const e of entries) {
    chunks.push(writeUstarHeader(e.name, e.content.length, e.mtime, e.mode ?? 0o644));
    chunks.push(e.content);
    // Pad to 512-byte boundary.
    const pad = (512 - (e.content.length % 512)) % 512;
    if (pad > 0) chunks.push(Buffer.alloc(pad));
  }
  // End-of-archive: two consecutive 512-byte zero blocks.
  chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks);
}

// ─── Discovery + INDEX.json builder ──────────────────────────────────────────

function sha256Hex(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

/**
 * Walk outDir + the optional `summaries/` subdir, returning every file
 * relative to outDir along with its absolute path on disk.
 */
function listOutDir(outDir: string): string[] {
  const out: string[] = [];
  const top = readdirSync(outDir);
  for (const n of top) {
    const p = resolve(outDir, n);
    let st;
    try { st = statSync(p); } catch { continue; }
    if (st.isFile()) out.push(n);
    else if (st.isDirectory() && (n === 'summaries' || n === 'section889-1bd-reports')) {
      for (const m of readdirSync(p)) {
        const sub = resolve(p, m);
        try { if (statSync(sub).isFile()) out.push(`${n}/${m}`); } catch { /* ignore */ }
      }
    }
  }
  return out.sort();
}

function matchRole(filename: string): WellKnownArtifact | null {
  for (const a of WELL_KNOWN) {
    if (typeof a.filename === 'string') {
      if (a.filename === filename) return a;
    } else if (a.filename.test(filename)) {
      return a;
    }
  }
  return null;
}

// ─── INDEX entry + result types ──────────────────────────────────────────────

export interface IndexEntry {
  filename: string;
  role: Role | 'unrecognized';
  description: string;
  sha256: string;
  bytes: number;
  /** True when the file is also covered by manifest.json. */
  in_manifest: boolean;
  /** Required-status from WELL_KNOWN; null for ksi-evidence + summaries (presence-based). */
  required: boolean | null;
}

export interface IndexGap {
  role: Role;
  filename: string;
  reason: string;
}

export interface ChainCheckResult {
  /** True when every link in the SSP→AP→AR→POA&M chain resolves locally. */
  complete: boolean;
  /** Findings: each broken link is recorded with a description. */
  problems: Array<{ link: string; problem: string }>;
}

export interface SubmissionIndex {
  /**
   * Package-format version. Operators inspecting the bundle key off this
   * string to pick the right ingest path. Bumps cleanly when FedRAMP
   * publishes post-Phase-Two guidance (R3 caveat).
   */
  package_format_version: string;
  /** Wall-clock at bundle time. */
  built_at: string;
  /** Run id from the orchestrator. */
  run_id: string;
  /** FRMR catalog version embedded in evidence. */
  frmr_version: string;
  /** Tool that built the bundle (this module). */
  builder: { name: string; module: string; version?: string };
  /** Every artifact in the bundle, deterministically sorted by filename. */
  artifacts: IndexEntry[];
  /** Required artifacts that are MISSING from outDir. */
  gaps: IndexGap[];
  /** SSP → AP → AR → POA&M chain validation result. */
  chain_check: ChainCheckResult;
  /** Top-level provenance for the bundle itself. */
  provenance: {
    emitter: string;
    emittedAt: string;
    sourceCalls: string[];
    signingKeyId: string;
  };
}

export interface BundleEmitOptions {
  /** Source directory containing the orchestrator's output. */
  outDir: string;
  /** Where to write the bundle tarball. Defaults to `${outDir}/submission-package.tar.gz`. */
  outPath?: string;
  /** Run id (from orchestrator). */
  runId: string;
  /** FRMR catalog version. */
  frmrVersion: string;
  /**
   * Deterministic mtime for every entry in the tarball (seconds since epoch).
   * Defaults to `Math.floor(Date.now()/1000)` so the bundle is reproducible
   * within a run but bumps each new run. Pass a fixed value to get
   * byte-identical tarballs across machines.
   */
  mtime?: number;
  /**
   * When true, the bundler throws if any `required: true` well-known artifact
   * is missing from outDir, OR the SSP→AP→AR→POA&M chain is broken. The
   * orchestrator passes this when `--strict-bundle` is set so production
   * submissions never ship incomplete.
   */
  strict?: boolean;
}

export interface BundleEmitResult {
  /** Path to the tarball. */
  bundle_path: string;
  /** Path to the INDEX.json companion (written alongside the tarball + included inside it). */
  index_path: string;
  /** SHA-256 of the tarball itself (uncompressed-then-gzipped output). */
  bundle_sha256: string;
  /** Bytes of the gzipped tarball. */
  bundle_bytes: number;
  /** Count of artifacts in the bundle. */
  artifact_count: number;
  /** Count of required-artifact gaps (informational; throws under strict). */
  gap_count: number;
  /** Chain-validation summary. */
  chain_complete: boolean;
}

// ─── Chain check ─────────────────────────────────────────────────────────────

function readJsonSafe(path: string): any | null {
  if (!existsSync(path)) return null;
  try { return JSON.parse(readFileSync(path, 'utf8')); }
  catch { return null; }
}

function checkChain(outDir: string): ChainCheckResult {
  const problems: ChainCheckResult['problems'] = [];
  const ssp = readJsonSafe(resolve(outDir, 'ssp.json'));
  const ap = readJsonSafe(resolve(outDir, 'ap.json'));
  const ar = readJsonSafe(resolve(outDir, 'assessment-results.json'));
  const poam = readJsonSafe(resolve(outDir, 'poam.json'));

  if (!ssp) problems.push({ link: 'SSP→AP', problem: 'ssp.json missing — cannot verify chain root' });
  if (!ap) problems.push({ link: 'AP→AR', problem: 'ap.json missing — chain has no Assessment Plan' });
  else {
    const apImportSsp = ap['assessment-plan']?.['import-ssp']?.href;
    if (!apImportSsp) problems.push({ link: 'SSP→AP', problem: 'ap.json has no import-ssp.href' });
  }
  if (!ar) problems.push({ link: 'AR-exists', problem: 'assessment-results.json missing' });
  else {
    const arImportAp = ar['assessment-results']?.['import-ap']?.href;
    if (!arImportAp) problems.push({ link: 'AP→AR', problem: 'assessment-results.json has no import-ap.href' });
    else if (arImportAp.startsWith('#cloud-evidence')) {
      problems.push({ link: 'AP→AR', problem: `assessment-results.json import-ap is synthetic (href=${arImportAp}); a complete submission package should reference a real AP. Re-run with --oscal-ap or pass --ap-href.` });
    }
  }
  if (poam) {
    const poamSystemId = poam['plan-of-action-and-milestones']?.['system-id'];
    const poamImportSsp = poam['plan-of-action-and-milestones']?.['import-ssp'];
    if (!poamSystemId && !poamImportSsp) {
      problems.push({ link: 'POA&M→system', problem: 'poam.json has neither system-id nor import-ssp — OSCAL POA&M v1.1.2 requires at least one.' });
    }
  }
  return { complete: problems.length === 0, problems };
}

// ─── Builder (pure) ──────────────────────────────────────────────────────────

export function buildSubmissionIndex(outDir: string, opts: BundleEmitOptions): {
  index: SubmissionIndex;
  files: Array<{ filename: string; absolute: string }>;
} {
  const files = listOutDir(outDir);

  // Map manifest's covered files for the in_manifest flag.
  const manifestPath = resolve(outDir, 'manifest.json');
  const manifest = readJsonSafe(manifestPath);
  const manifestFiles = new Set<string>(
    Array.isArray(manifest?.files) ? manifest.files.map((f: any) => f.name) : [],
  );
  const signerPublicKey: string = manifest?.signer_public_key ?? '';

  const artifacts: IndexEntry[] = [];
  const sourceCalls: string[] = [];

  for (const f of files) {
    const abs = resolve(outDir, f);
    let content: Buffer;
    try { content = readFileSync(abs); }
    catch (e) { log.warn({ event: 'bundle.skip_unreadable', file: f, err: String(e) }); continue; }
    const role = matchRole(f);
    artifacts.push({
      filename: f,
      role: role?.role ?? 'unrecognized',
      description: role?.description ?? 'File present in outDir but not in the bundler\'s well-known catalogue. Included for completeness; review before submission.',
      sha256: sha256Hex(content),
      bytes: content.length,
      in_manifest: manifestFiles.has(f),
      required: role?.required ?? null,
    });
    sourceCalls.push(`fs.readFileSync(${f})`);
  }

  // Determine gaps: required artifacts that are NOT present in outDir.
  const gaps: IndexGap[] = [];
  for (const a of WELL_KNOWN) {
    if (!a.required) continue;
    if (typeof a.filename !== 'string') continue;
    if (!files.includes(a.filename)) {
      gaps.push({
        role: a.role,
        filename: a.filename,
        reason: `Required artifact missing from outDir. ${a.description}`,
      });
    }
  }

  const chainCheck = checkChain(outDir);

  const index: SubmissionIndex = {
    package_format_version: PACKAGE_FORMAT_VERSION,
    built_at: new Date().toISOString(),
    run_id: opts.runId,
    frmr_version: opts.frmrVersion,
    builder: { name: TOOL_NAME, module: BUNDLER_MODULE },
    artifacts: artifacts.sort((a, b) => a.filename.localeCompare(b.filename)),
    gaps,
    chain_check: chainCheck,
    provenance: {
      emitter: BUNDLER_MODULE,
      emittedAt: new Date().toISOString(),
      sourceCalls: ['fs.readdirSync(outDir)', 'fs.readFileSync(manifest.json)', ...sourceCalls.slice(0, 50)],
      signingKeyId: signerPublicKey ? sha256Hex(Buffer.from(signerPublicKey)).slice(0, 16) : 'unsigned',
    },
  };

  return {
    index,
    files: files.map((f) => ({ filename: f, absolute: resolve(outDir, f) })),
  };
}

// ─── Disk emitter ────────────────────────────────────────────────────────────

export function emitSubmissionBundle(opts: BundleEmitOptions): BundleEmitResult {
  const { index, files } = buildSubmissionIndex(opts.outDir, opts);

  // Strict-mode enforcement before we write anything.
  if (opts.strict) {
    if (index.gaps.length > 0) {
      throw new Error(
        `submission-bundle: STRICT mode — ${index.gaps.length} required artifact(s) missing:\n` +
        index.gaps.map((g) => `  - ${g.filename} (${g.role}): ${g.reason}`).join('\n'),
      );
    }
    if (!index.chain_check.complete) {
      throw new Error(
        `submission-bundle: STRICT mode — OSCAL chain incomplete:\n` +
        index.chain_check.problems.map((p) => `  - ${p.link}: ${p.problem}`).join('\n'),
      );
    }
  }

  const indexPath = resolve(opts.outDir, 'INDEX.json');
  const indexBuf = Buffer.from(JSON.stringify(index, null, 2), 'utf8');
  writeFileSync(indexPath, indexBuf);

  // Build the tar entries. INDEX.json goes first so a consumer reading the
  // tar stream sequentially sees the manifest before any payload.
  const mtime = opts.mtime ?? Math.floor(Date.now() / 1000);
  const entries: TarEntry[] = [
    { name: 'INDEX.json', content: indexBuf, mtime },
    ...files.map((f) => ({ name: f.filename, content: readFileSync(f.absolute), mtime })),
  ];
  const tarBuf = writeTar(entries);
  const gzipped = gzipSync(tarBuf, { level: 9 });
  const bundlePath = opts.outPath ?? resolve(opts.outDir, 'submission-package.tar.gz');
  writeFileSync(bundlePath, gzipped);

  log.info({
    event: 'submission_bundle.emitted',
    path: bundlePath,
    bundle_bytes: gzipped.length,
    artifact_count: index.artifacts.length,
    gap_count: index.gaps.length,
    chain_complete: index.chain_check.complete,
  });

  return {
    bundle_path: bundlePath,
    index_path: indexPath,
    bundle_sha256: sha256Hex(gzipped),
    bundle_bytes: gzipped.length,
    artifact_count: index.artifacts.length,
    gap_count: index.gaps.length,
    chain_complete: index.chain_check.complete,
  };
}
