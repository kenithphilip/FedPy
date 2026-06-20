/**
 * SSDF per-practice evidence aggregator + satisfaction matrix (LOOP-T.T2).
 *
 * Joins the T.T1 SSDF practices catalogue (`core/ssdf-practices-catalog.ts`)
 * with the REAL evidence already collected by prior loops — the signed per-KSI
 * evidence envelopes (`out/KSI-*.json`, LOOPs B-K via `core/envelope.ts`), the
 * LOOP-B.B1 composite risk register (`out/risk-scores.json`), the LOOP-J.J2
 * subprocessor inventory (`out/subprocessor-inventory.json`), the LOOP-J.J3
 * supply-chain risk register (`out/supply-chain-risk-register.json`), the SBOM
 * report (`out/sbom-report.json`), and the OSCAL POA&M (`out/poam.json`) — and
 * emits a per-practice x per-task satisfaction matrix with typed evidence
 * pointers. The matrix is the data backbone of the CISA Common Form (T.T3) and
 * the OMB M-22-18 paragraph III.E POA&M safety valve.
 *
 * REO compliance:
 *   - Every `satisfied` cell traces to at least one real signed KSI envelope
 *     (enforced by `scripts/check-ssdf-no-silent-pass.mjs`).
 *   - A task with no joined evidence is `requires-operator-input`, never a
 *     silent pass.
 *   - When a manifest.json is present, an evidence file whose on-disk SHA-256
 *     does not match its manifest entry throws `EnvelopeSignatureError` (FATAL):
 *     the matrix refuses to ship over tampered/unverifiable evidence.
 *   - The provenance block cites every input file read with its SHA-256.
 *
 * The matrix join is at the PRACTICE level because the committed catalogue maps
 * FedRAMP KSIs + 800-53 Rev 5 controls per practice (`fedramp_ksi_forward_map`,
 * `nist_800_53_r5_controls`), not per task; the practice's pointer set is
 * attributed to each of its tasks, whose rows preserve the per-task statement +
 * CISA Common Form Section IV reference.
 */
import { readFileSync, readdirSync, writeFileSync, appendFileSync, existsSync, mkdirSync } from 'node:fs';
import { resolve, basename } from 'node:path';
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { canonicalize, signDetached } from './sign.ts';
import { log } from './log.ts';
import {
  loadSsdfCatalog,
  type SsdfCatalog,
  type SsdfPractice,
} from './ssdf-practices-catalog.ts';
import {
  type SsdfSatisfactionMatrix,
  type SsdfPracticeRow,
  type SsdfTaskRow,
  type SsdfEvidencePointer,
  type TaskStatus,
  type PracticeStatus,
  MATRIX_SCHEMA_VERSION,
  MATRIX_EMITTER,
  MATRIX_EMITTER_VERSION,
  SATISFACTION_MATRIX_LEDGER_FILENAME,
  emptyStatusTally,
  deriveMatrixId,
  serializeUnsignedCanonical,
  satisfactionMatrixToXlsx,
  matrixJsonFilename,
  matrixXlsxFilename,
} from './ssdf-satisfaction-matrix.ts';

// ─── Per-practice ancillary-input attachment sets (NIST SSDF practice ids — ──
// published-constant identifiers, allowed fixed data per CLAUDE.md REO Rule 3) ─

/** Release-integrity / build / archive practices that SBOM + build provenance back. */
const SBOM_INTEGRITY_PRACTICES = new Set(['PS.2', 'PS.3', 'PW.6']);
/** Third-party-component practice that the supply-chain risk register backs. */
const SUPPLY_CHAIN_PRACTICES = new Set(['PW.4']);
/** Organisational toolchain / third-party-developer-tool practices the subprocessor inventory backs. */
const ORG_TOOLCHAIN_PRACTICES = new Set(['PO.1', 'PO.3', 'PW.4']);

const KSI_FILE_RE = /^KSI-[A-Z]+-[A-Z0-9]+\.json$/;

// ─── Typed errors ─────────────────────────────────────────────────────────────

export class SsdfCatalogTamperError extends Error {
  readonly expected: string;
  readonly actual: string;
  constructor(expected: string, actual: string) {
    super(`ssdf-evidence-aggregator: catalogue source_pdf_sha256 mismatch — pinned ${expected}, catalogue carries ${actual}. Refusing to build a matrix over an untrusted catalogue.`);
    this.name = 'SsdfCatalogTamperError';
    this.expected = expected;
    this.actual = actual;
  }
}

export class EnvelopeSignatureError extends Error {
  readonly path: string;
  constructor(path: string, detail: string) {
    super(`ssdf-evidence-aggregator: evidence integrity check failed for ${path}: ${detail}. Refusing to ship a matrix over unverifiable evidence (a tampered envelope could mask a true gap).`);
    this.name = 'EnvelopeSignatureError';
    this.path = path;
  }
}

// ─── Lightweight projections of the evidence corpus ───────────────────────────

interface EnvelopeRecord {
  ksi_id: string;
  source_path: string;
  sha256: string;
  signature_verified: boolean;
  /** True when any provider finding is a failing high/critical (the KSI is unmet). */
  failing_high_crit: boolean;
}

interface RiskIndex {
  present: boolean;
  /** ksi_id -> max composite score across that KSI's scored findings. */
  byKsi: Map<string, number>;
}

interface SubprocessorIndex {
  present: boolean;
  source_path: string;
  entries: Array<{ id: string }>;
}

interface SupplyChainIndex {
  present: boolean;
  source_path: string;
  /** rows with their related controls for the PW.4 join. */
  rows: Array<{ id: string; controls: string[] }>;
}

interface SbomIndex {
  present: boolean;
  source_path: string;
  sha256: string;
  format: 'cyclonedx' | 'spdx' | 'unknown';
}

interface PoamIndex {
  present: boolean;
  source_path: string;
  /** control id (lower-cased) -> matching {observation uuids, poam item uuids}. */
  observationsByControl: Map<string, Set<string>>;
  poamItemsByControl: Map<string, Set<string>>;
}

// ─── Build options ────────────────────────────────────────────────────────────

export interface SsdfProductConfig {
  id: string;
  name: string;
  ai_enabled?: boolean;
  critical_software?: boolean;
}

export interface BuildSsdfMatrixOptions {
  /** Directory holding the run's evidence envelopes + register artefacts. */
  outDir: string;
  cspName: string;
  product: SsdfProductConfig;
  regime?: string;
  /** Injected catalogue (tests). Defaults to the committed data/ssdf-800-218-v1.1.json. */
  catalog?: SsdfCatalog;
  catalogPath?: string;
  /** When set, assert the catalogue's source_pdf_sha256 equals this pinned hash. */
  pinnedPdfSha256?: string;
  /** Evidence-envelope dir. Defaults to outDir. */
  evidenceDir?: string;
  /** Optional per-product KSI scoping: ksi_id -> product ids it applies to. */
  ksiToProductMap?: Record<string, string[]>;
  /** Deterministic clock (tests). Defaults to now. */
  generatedAt?: string;
  /** When true (default) and a manifest.json exists, verify evidence-file digests. */
  verifyManifest?: boolean;
}

// ─── Input readers (defensive; absent optional inputs degrade to coverage:partial) ──

function sha256File(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function discoverEnvelopes(
  evidenceDir: string,
  manifest: Map<string, string> | null,
  manifestPath: string,
): EnvelopeRecord[] {
  const records: EnvelopeRecord[] = [];
  let names: string[];
  try {
    names = readdirSync(evidenceDir);
  } catch {
    return records;
  }
  for (const name of names.sort()) {
    if (!KSI_FILE_RE.test(name)) continue;
    const path = resolve(evidenceDir, name);
    let doc: any;
    let bytes: Buffer;
    try {
      bytes = readFileSync(path);
      doc = JSON.parse(bytes.toString('utf8'));
    } catch {
      continue;
    }
    if (!doc || typeof doc.ksi_id !== 'string' || !Array.isArray(doc.providers)) continue;
    const sha = createHash('sha256').update(bytes).digest('hex');
    let signatureVerified = false;
    if (manifest) {
      const recorded = manifest.get(name);
      if (recorded !== undefined) {
        if (recorded !== sha) {
          throw new EnvelopeSignatureError(
            path,
            `on-disk SHA-256 ${sha.slice(0, 12)}… does not match the manifest entry ${recorded.slice(0, 12)}… (manifest: ${basename(manifestPath)})`,
          );
        }
        signatureVerified = true;
      }
    }
    let failing = false;
    for (const p of doc.providers) {
      for (const f of p?.findings ?? []) {
        if (f && f.passed === false && (f.severity === 'high' || f.severity === 'critical')) {
          failing = true;
        }
      }
    }
    records.push({ ksi_id: doc.ksi_id, source_path: name, sha256: sha, signature_verified: signatureVerified, failing_high_crit: failing });
  }
  return records;
}

/** Read + verify the run manifest, returning a name->sha256 map (or null when absent). */
function readManifest(outDir: string, verify: boolean): { map: Map<string, string> | null; path: string } {
  const manifestPath = resolve(outDir, 'manifest.json');
  if (!verify || !existsSync(manifestPath)) return { map: null, path: manifestPath };
  let doc: any;
  try {
    doc = JSON.parse(readFileSync(manifestPath, 'utf8'));
  } catch {
    return { map: null, path: manifestPath };
  }
  if (!doc || !Array.isArray(doc.files)) return { map: null, path: manifestPath };
  // If a signature sidecar is present, verify it; an invalid signature is fatal.
  const sigPath = resolve(outDir, 'manifest.sig');
  if (existsSync(sigPath) && typeof doc.signer_public_key === 'string') {
    try {
      const ok = cryptoVerify(
        null,
        Buffer.from(canonicalize(doc), 'utf8'),
        createPublicKey(doc.signer_public_key),
        Buffer.from(readFileSync(sigPath, 'utf8'), 'base64'),
      );
      if (!ok) throw new EnvelopeSignatureError(manifestPath, 'run manifest signature did not verify');
    } catch (e) {
      if (e instanceof EnvelopeSignatureError) throw e;
      // A malformed key/sig is treated as unverifiable → fatal.
      throw new EnvelopeSignatureError(manifestPath, `run manifest signature could not be verified: ${(e as Error)?.message ?? String(e)}`);
    }
  }
  const map = new Map<string, string>();
  for (const f of doc.files) {
    if (f && typeof f.name === 'string' && typeof f.sha256 === 'string') map.set(f.name, f.sha256);
  }
  return { map, path: manifestPath };
}

function readRiskIndex(path: string): RiskIndex {
  if (!existsSync(path)) return { present: false, byKsi: new Map() };
  const byKsi = new Map<string, number>();
  try {
    const doc = JSON.parse(readFileSync(path, 'utf8'));
    for (const f of doc?.findings ?? []) {
      const id = String(f?.ksi_id ?? '');
      const score = Number(f?.composite_score);
      if (!id || !Number.isFinite(score)) continue;
      byKsi.set(id, Math.max(byKsi.get(id) ?? 0, score));
    }
  } catch {
    return { present: false, byKsi: new Map() };
  }
  return { present: true, byKsi };
}

function readSubprocessorIndex(path: string): SubprocessorIndex {
  if (!existsSync(path)) return { present: false, source_path: basename(path), entries: [] };
  try {
    const doc = JSON.parse(readFileSync(path, 'utf8'));
    const rows = (doc?.subprocessors ?? doc?.entries ?? doc?.rows ?? []) as any[];
    const entries = rows
      .map((r, i) => ({ id: String(r?.id ?? r?.name ?? r?.vendor ?? `subprocessor-${i}`).trim() }))
      .filter((r) => r.id);
    return { present: true, source_path: basename(path), entries };
  } catch {
    return { present: false, source_path: basename(path), entries: [] };
  }
}

function readSupplyChainIndex(path: string): SupplyChainIndex {
  if (!existsSync(path)) return { present: false, source_path: basename(path), rows: [] };
  try {
    const doc = JSON.parse(readFileSync(path, 'utf8'));
    const rows = (doc?.entries ?? []) as any[];
    return {
      present: true,
      source_path: basename(path),
      rows: rows
        .map((r) => ({ id: String(r?.id ?? ''), controls: (r?.related_nist_controls ?? []).map((c: any) => String(c).toLowerCase()) }))
        .filter((r) => r.id),
    };
  } catch {
    return { present: false, source_path: basename(path), rows: [] };
  }
}

function readSbomIndex(path: string): SbomIndex {
  if (!existsSync(path)) return { present: false, source_path: basename(path), sha256: '', format: 'unknown' };
  try {
    const sha = sha256File(path);
    const doc = JSON.parse(readFileSync(path, 'utf8'));
    const fmtRaw = String(doc?.format ?? doc?.files?.[0]?.format ?? 'unknown').toLowerCase();
    const format: SbomIndex['format'] = fmtRaw.includes('cyclonedx') ? 'cyclonedx' : fmtRaw.includes('spdx') ? 'spdx' : 'unknown';
    return { present: true, source_path: basename(path), sha256: sha, format };
  } catch {
    return { present: false, source_path: basename(path), sha256: '', format: 'unknown' };
  }
}

function addControlRef(map: Map<string, Set<string>>, control: string, uuid: string): void {
  const key = control.toLowerCase();
  if (!map.has(key)) map.set(key, new Set());
  map.get(key)!.add(uuid);
}

/** Scan an arbitrary OSCAL node's text surfaces for a control id reference. */
function nodeMentionsControl(node: any, controlLc: string): boolean {
  const hay: string[] = [];
  if (typeof node?.title === 'string') hay.push(node.title);
  if (typeof node?.description === 'string') hay.push(node.description);
  if (typeof node?.statement === 'string') hay.push(node.statement);
  for (const pr of node?.props ?? []) {
    if (typeof pr?.value === 'string') hay.push(pr.value);
    if (typeof pr?.name === 'string') hay.push(pr.name);
  }
  const tgt = node?.target?.['target-id'];
  if (typeof tgt === 'string') hay.push(tgt);
  const joined = hay.join('  ').toLowerCase();
  // Match the control id as a token (e.g. "ac-2" but not "ac-20" when looking for "ac-2").
  const re = new RegExp(`(^|[^a-z0-9-])${controlLc.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([^a-z0-9-]|$)`);
  return re.test(joined);
}

function readPoamIndex(path: string, allControls: Set<string>): PoamIndex {
  const empty: PoamIndex = { present: false, source_path: basename(path), observationsByControl: new Map(), poamItemsByControl: new Map() };
  if (!existsSync(path) || allControls.size === 0) return empty;
  let poam: any;
  try {
    const doc = JSON.parse(readFileSync(path, 'utf8'));
    poam = doc?.['plan-of-action-and-milestones'] ?? doc;
  } catch {
    return empty;
  }
  const observationsByControl = new Map<string, Set<string>>();
  const poamItemsByControl = new Map<string, Set<string>>();
  const controlsLc = [...allControls].map((c) => c.toLowerCase());
  for (const obs of poam?.observations ?? []) {
    for (const c of controlsLc) {
      if (obs?.uuid && nodeMentionsControl(obs, c)) addControlRef(observationsByControl, c, String(obs.uuid));
    }
  }
  for (const item of poam?.['poam-items'] ?? []) {
    for (const c of controlsLc) {
      if (item?.uuid && nodeMentionsControl(item, c)) addControlRef(poamItemsByControl, c, String(item.uuid));
    }
  }
  return { present: true, source_path: basename(path), observationsByControl, poamItemsByControl };
}

// ─── Status computation ───────────────────────────────────────────────────────

interface PracticeEvidence {
  pointers: SsdfEvidencePointer[];
  failingHighCrit: boolean;
  hasOpenPoam: boolean;
  hasKsiEnvelope: boolean;
  openRiskScore: number | null;
}

/** Per-task status (REO: a task with no pointers is requires-operator-input). */
export function computeTaskStatus(ev: PracticeEvidence): TaskStatus {
  if (ev.pointers.length === 0) return 'requires-operator-input';
  if (ev.failingHighCrit) return 'not-satisfied';
  if (ev.hasOpenPoam) return 'partially-satisfied';
  if (ev.hasKsiEnvelope) return 'satisfied';
  return 'not-assessed';
}

/** Per-practice roll-up (worst contributing task status; spec §6 step 8). */
export function rollUpPracticeStatus(tally: Record<TaskStatus, number>): PracticeStatus {
  if (tally['not-satisfied'] > 0) return 'not-satisfied';
  if (tally['requires-operator-input'] > 0) return 'requires-operator-input';
  if (tally['not-assessed'] > 0) return 'not-assessed';
  if (tally['partially-satisfied'] > 0) return 'partially-satisfied';
  return 'satisfied';
}

// ─── Build ────────────────────────────────────────────────────────────────────

export function buildSsdfSatisfactionMatrix(opts: BuildSsdfMatrixOptions): SsdfSatisfactionMatrix {
  const generatedAt = opts.generatedAt ?? new Date().toISOString();
  const evidenceDir = opts.evidenceDir ?? opts.outDir;
  const verifyManifest = opts.verifyManifest !== false;

  const catalog = opts.catalog ?? loadSsdfCatalog(opts.catalogPath);
  if (opts.pinnedPdfSha256 && catalog.source_pdf_sha256 !== opts.pinnedPdfSha256) {
    throw new SsdfCatalogTamperError(opts.pinnedPdfSha256, catalog.source_pdf_sha256);
  }

  // ── Evidence corpus ──
  const { map: manifestMap, path: manifestPath } = readManifest(opts.outDir, verifyManifest);
  const envelopes = discoverEnvelopes(evidenceDir, manifestMap, manifestPath);
  const envelopesByKsi = new Map<string, EnvelopeRecord[]>();
  for (const e of envelopes) {
    if (!envelopesByKsi.has(e.ksi_id)) envelopesByKsi.set(e.ksi_id, []);
    envelopesByKsi.get(e.ksi_id)!.push(e);
  }

  // ── Ancillary inputs ──
  const risk = readRiskIndex(resolve(opts.outDir, 'risk-scores.json'));
  const subproc = readSubprocessorIndex(resolve(opts.outDir, 'subprocessor-inventory.json'));
  const scrm = readSupplyChainIndex(resolve(opts.outDir, 'supply-chain-risk-register.json'));
  const sbom = readSbomIndex(resolve(opts.outDir, 'sbom-report.json'));
  const allControls = new Set<string>(catalog.practices.flatMap((p) => p.nist_800_53_r5_controls.map((c) => c.toLowerCase())));
  const poam = readPoamIndex(resolve(opts.outDir, 'poam.json'), allControls);

  // ── Per-product KSI scoping ──
  const ksiApplies = (ksiId: string): boolean => {
    const map = opts.ksiToProductMap;
    if (!map || !(ksiId in map)) return true;
    return (map[ksiId] ?? []).includes(opts.product.id);
  };

  // ── Coverage diagnostics for absent optional inputs ──
  const coverageDiagnostics: string[] = [];
  if (!risk.present) coverageDiagnostics.push('coverage:partial — risk-scores.json absent (open_risk_score unavailable)');
  if (!subproc.present) coverageDiagnostics.push('coverage:partial — subprocessor-inventory.json absent');
  if (!scrm.present) coverageDiagnostics.push('coverage:partial — supply-chain-risk-register.json absent');
  if (!sbom.present) coverageDiagnostics.push('coverage:partial — sbom-report.json absent');
  if (!poam.present) coverageDiagnostics.push('coverage:partial — poam.json absent (control-based evidence unavailable)');
  // cosign/build-attestation verification is not collected as a standalone
  // artefact in this repo; record the gap so a 3PAO sees the coverage boundary.
  coverageDiagnostics.push('coverage:partial — cosign build-attestation state not collected (tracked as T.T2 deferral)');

  const sourceDigests: SsdfMatrixSourceDigest[] = [];
  const sourceCalls: string[] = [];
  const recordSource = (kind: string, absPath: string, name: string, signatureVerified: boolean) => {
    if (!existsSync(absPath)) return;
    sourceDigests.push({ kind, path: name, sha256: sha256File(absPath), signatureVerified });
    sourceCalls.push(`${kind}:${name}`);
  };

  // catalogue source (always present)
  if (opts.catalogPath && existsSync(opts.catalogPath)) {
    recordSource('ssdf-catalog', opts.catalogPath, basename(opts.catalogPath), true);
  } else {
    sourceCalls.push('ssdf-catalog:data/ssdf-800-218-v1.1.json');
    sourceDigests.push({ kind: 'ssdf-catalog', path: 'data/ssdf-800-218-v1.1.json', sha256: catalog.source_pdf_sha256, signatureVerified: true });
  }
  for (const e of envelopes) {
    sourceDigests.push({ kind: 'ksi-envelope', path: e.source_path, sha256: e.sha256, signatureVerified: e.signature_verified });
    sourceCalls.push(`ksi-envelope:${e.source_path}`);
  }
  recordSource('risk-register', resolve(opts.outDir, 'risk-scores.json'), 'risk-scores.json', false);
  recordSource('subprocessor-inventory', resolve(opts.outDir, 'subprocessor-inventory.json'), 'subprocessor-inventory.json', false);
  recordSource('supply-chain-risk-register', resolve(opts.outDir, 'supply-chain-risk-register.json'), 'supply-chain-risk-register.json', false);
  recordSource('sbom', resolve(opts.outDir, 'sbom-report.json'), 'sbom-report.json', false);
  recordSource('oscal-poam', resolve(opts.outDir, 'poam.json'), 'poam.json', false);

  // ── Per-practice evidence build ──
  const practiceRows: SsdfPracticeRow[] = [];
  for (const practice of catalog.practices) {
    const ev = buildPracticeEvidence(practice, {
      envelopesByKsi, ksiApplies, risk, subproc, scrm, sbom, poam,
    });

    const tally = emptyStatusTally();
    const tasks: SsdfTaskRow[] = practice.tasks.map((t) => {
      const status = computeTaskStatus(ev);
      tally[status] += 1;
      const diagnostics: string[] = [];
      if (status === 'requires-operator-input') {
        diagnostics.push(`requires-operator-input: ${t.id} — no on-disk evidence joined; capture a KSI envelope, an OSCAL POA&M reference, or an operator-supplied process artefact for practice ${practice.id}`);
      }
      if (status === 'not-assessed') {
        diagnostics.push(`not-assessed: ${t.id} — only ancillary evidence present (no authoritative KSI envelope); operator confirmation required`);
      }
      return {
        id: t.id,
        statement: t.statement,
        status,
        nist_800_53_r5_controls: practice.nist_800_53_r5_controls,
        crosswalk_ksi: practice.fedramp_ksi_forward_map.map((m) => m.ksi_id),
        common_form_section_ref: t.common_form_section_ref,
        evidence_pointers: ev.pointers,
        open_risk_score: ev.openRiskScore,
        diagnostics,
      };
    });

    practiceRows.push({
      id: practice.id,
      group: practice.group,
      name: practice.name,
      outcome: practice.intent,
      status: rollUpPracticeStatus(tally),
      open_risk_score: ev.openRiskScore,
      tasks_by_status: tally,
      tasks,
    });
  }

  // ── Totals ──
  const practicesByStatus = emptyStatusTally();
  const tasksByStatus = emptyStatusTally();
  let taskCount = 0;
  for (const p of practiceRows) {
    practicesByStatus[p.status] += 1;
    for (const t of p.tasks) {
      tasksByStatus[t.status] += 1;
      taskCount += 1;
    }
  }

  const matrixId = deriveMatrixId({
    productId: opts.product.id,
    cataloguePdfSha256: catalog.source_pdf_sha256,
    sourceDigests,
  });

  const matrix: SsdfSatisfactionMatrix = {
    schema_version: MATRIX_SCHEMA_VERSION,
    matrix_id: matrixId,
    generated_at: generatedAt,
    csp_name: opts.cspName,
    product: {
      id: opts.product.id,
      name: opts.product.name,
      ai_enabled: opts.product.ai_enabled === true,
      critical_software: opts.product.critical_software === true,
    },
    regime: opts.regime ?? 'm-22-18-mandatory',
    catalogue_source: {
      sp: '800-218',
      version: '1.1',
      publication_date: catalog.publication.publication_date,
      source_pdf_sha256: catalog.source_pdf_sha256,
    },
    totals: {
      practices: practiceRows.length,
      tasks: taskCount,
      practices_by_status: practicesByStatus,
      tasks_by_status: tasksByStatus,
    },
    practices: practiceRows,
    provenance: {
      emitter: MATRIX_EMITTER,
      emitterVersion: MATRIX_EMITTER_VERSION,
      emittedAt: generatedAt,
      sourceCalls,
      sourceDigests,
      signingKeyId: '',
      publicKeyPem: '',
      signatureEd25519: '',
      timestampAuthority: null,
      coverageDiagnostics,
    },
  };
  return matrix;
}

interface SsdfMatrixSourceDigest { kind: string; path: string; sha256: string; signatureVerified: boolean }

function buildPracticeEvidence(
  practice: SsdfPractice,
  ctx: {
    envelopesByKsi: Map<string, EnvelopeRecord[]>;
    ksiApplies: (ksiId: string) => boolean;
    risk: RiskIndex;
    subproc: SubprocessorIndex;
    scrm: SupplyChainIndex;
    sbom: SbomIndex;
    poam: PoamIndex;
  },
): PracticeEvidence {
  const pointers: SsdfEvidencePointer[] = [];
  let failingHighCrit = false;
  let hasOpenPoam = false;
  let hasKsiEnvelope = false;
  let maxRisk: number | null = null;

  // 1. KSI evidence envelopes (primary join via fedramp_ksi_forward_map).
  for (const entry of practice.fedramp_ksi_forward_map) {
    if (!ctx.ksiApplies(entry.ksi_id)) continue;
    const envs = ctx.envelopesByKsi.get(entry.ksi_id) ?? [];
    for (const e of envs) {
      hasKsiEnvelope = true;
      if (e.failing_high_crit) failingHighCrit = true;
      pointers.push({
        kind: 'ksi-envelope',
        ksi_id: entry.ksi_id,
        envelope_sha256: e.sha256,
        signing_key_id: e.signature_verified ? 'run-manifest' : 'unverified',
        signature_verified: e.signature_verified,
        source_path: e.source_path,
      });
    }
    const score = ctx.risk.byKsi.get(entry.ksi_id);
    if (score !== undefined) maxRisk = maxRisk === null ? score : Math.max(maxRisk, score);
  }

  // 2. OSCAL POA&M (secondary control-based join).
  if (ctx.poam.present) {
    for (const control of practice.nist_800_53_r5_controls) {
      const key = control.toLowerCase();
      for (const uuid of ctx.poam.observationsByControl.get(key) ?? []) {
        pointers.push({ kind: 'oscal-observation', observation_uuid: uuid, control_id: control, source_path: ctx.poam.source_path });
      }
      for (const uuid of ctx.poam.poamItemsByControl.get(key) ?? []) {
        hasOpenPoam = true;
        pointers.push({ kind: 'oscal-poam-item', poam_item_uuid: uuid, control_id: control, source_path: ctx.poam.source_path });
      }
    }
  }

  // 3. SBOM (release-integrity / build / archive practices).
  if (ctx.sbom.present && SBOM_INTEGRITY_PRACTICES.has(practice.id)) {
    pointers.push({ kind: 'sbom', sbom_format: ctx.sbom.format, sbom_sha256: ctx.sbom.sha256, source_path: ctx.sbom.source_path });
  }

  // 4. Subprocessor inventory (organisational toolchain practices).
  if (ctx.subproc.present && ORG_TOOLCHAIN_PRACTICES.has(practice.id)) {
    for (const s of ctx.subproc.entries) {
      pointers.push({ kind: 'subprocessor-inventory', subprocessor_id: s.id, source_path: ctx.subproc.source_path });
    }
  }

  // 5. Supply-chain risk register (third-party component practice PW.4).
  if (ctx.scrm.present && SUPPLY_CHAIN_PRACTICES.has(practice.id)) {
    const controlsLc = new Set(practice.nist_800_53_r5_controls.map((c) => c.toLowerCase()));
    for (const row of ctx.scrm.rows) {
      const relevant = controlsLc.size === 0 || row.controls.length === 0 || row.controls.some((c) => controlsLc.has(c));
      if (relevant) pointers.push({ kind: 'supply-chain-risk-register-row', row_id: row.id, source_path: ctx.scrm.source_path });
    }
  }

  return { pointers, failingHighCrit, hasOpenPoam, hasKsiEnvelope, openRiskScore: maxRisk };
}

// ─── Emit (sign + write JSON + .sig + xlsx + ledger + coverage augment) ───────

export interface EmitSsdfMatrixOptions {
  outDir: string;
  runId: string;
  cspName: string;
  regime?: string;
  /** Products to emit one matrix each. Empty/undefined -> a single default product. */
  products?: SsdfProductConfig[];
  ksiToProductMap?: Record<string, string[]>;
  generatedAt?: string;
  catalog?: SsdfCatalog;
  catalogPath?: string;
  pinnedPdfSha256?: string;
  evidenceDir?: string;
  verifyManifest?: boolean;
  writeXlsx?: boolean;
}

export interface EmitSsdfMatrixResult {
  product_id: string;
  json_path: string;
  sig_path: string;
  xlsx_path: string | null;
  matrix_id: string;
  json_sha256: string;
  totals: SsdfSatisfactionMatrix['totals'];
}

function sha256(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

/** End-to-end T.T2 pass: build + sign + write one matrix per product. */
export function emitSsdfSatisfactionMatrix(opts: EmitSsdfMatrixOptions): EmitSsdfMatrixResult[] {
  const generatedAt = opts.generatedAt ?? new Date().toISOString();
  const products: SsdfProductConfig[] = (opts.products && opts.products.length > 0)
    ? opts.products
    : [{ id: defaultProductSlug(opts.cspName), name: opts.cspName, ai_enabled: false, critical_software: false }];

  if (!existsSync(opts.outDir)) mkdirSync(opts.outDir, { recursive: true });
  const results: EmitSsdfMatrixResult[] = [];

  products.forEach((product, idx) => {
    const isDefault = idx === 0;
    const matrix = buildSsdfSatisfactionMatrix({
      outDir: opts.outDir,
      cspName: opts.cspName,
      product,
      regime: opts.regime,
      catalog: opts.catalog,
      catalogPath: opts.catalogPath,
      pinnedPdfSha256: opts.pinnedPdfSha256,
      evidenceDir: opts.evidenceDir,
      ksiToProductMap: opts.ksiToProductMap,
      generatedAt,
      verifyManifest: opts.verifyManifest,
    });

    // Sign (detached Ed25519 over the canonical signature-blanked bytes).
    const canonical = serializeUnsignedCanonical(matrix);
    const sig = signDetached(Buffer.from(canonical, 'utf8'), opts.outDir);
    matrix.provenance.signingKeyId = sig.keyId;
    matrix.provenance.publicKeyPem = sig.publicKeyPem;
    matrix.provenance.signatureEd25519 = sig.signatureBase64;

    const jsonName = matrixJsonFilename(product.id, isDefault);
    const jsonPath = resolve(opts.outDir, jsonName);
    const jsonBytes = Buffer.from(JSON.stringify(matrix, null, 2), 'utf8');
    writeFileSync(jsonPath, jsonBytes);

    const sigPath = resolve(opts.outDir, `${jsonName}.sig`);
    writeFileSync(sigPath, JSON.stringify({ algorithm: 'ed25519', keyId: sig.keyId, publicKeyPem: sig.publicKeyPem, sigBase64: sig.signatureBase64 }, null, 2));

    let xlsxPath: string | null = null;
    if (opts.writeXlsx !== false) {
      xlsxPath = resolve(opts.outDir, matrixXlsxFilename(product.id, isDefault));
      writeFileSync(xlsxPath, satisfactionMatrixToXlsx(matrix));
    }

    appendFileSync(
      resolve(opts.outDir, SATISFACTION_MATRIX_LEDGER_FILENAME),
      JSON.stringify(ledgerRecord(matrix, opts.runId, sha256(jsonBytes))) + '\n',
    );

    augmentCoverage(opts.outDir, matrix);

    log.info({
      event: 't.t2.matrix_emitted',
      path: jsonPath,
      product: product.id,
      practices: matrix.totals.practices,
      tasks: matrix.totals.tasks,
      tasks_satisfied: matrix.totals.tasks_by_status['satisfied'],
      tasks_requires_operator_input: matrix.totals.tasks_by_status['requires-operator-input'],
      ephemeral_key: sig.ephemeralKey,
    });

    results.push({
      product_id: product.id,
      json_path: jsonPath,
      sig_path: sigPath,
      xlsx_path: xlsxPath,
      matrix_id: matrix.matrix_id,
      json_sha256: sha256(jsonBytes),
      totals: matrix.totals,
    });
  });

  return results;
}

function defaultProductSlug(cspName: string): string {
  return cspName.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '') || 'default-product';
}

function ledgerRecord(matrix: SsdfSatisfactionMatrix, runId: string, jsonSha: string): Record<string, unknown> {
  return {
    run_id: runId,
    matrix_id: matrix.matrix_id,
    generated_at: matrix.generated_at,
    product_id: matrix.product.id,
    practices: matrix.totals.practices,
    tasks: matrix.totals.tasks,
    tasks_by_status: matrix.totals.tasks_by_status,
    json_sha256: jsonSha,
  };
}

/** Additive-only augmentation of inventory-coverage.json (never a G2 regression). */
function augmentCoverage(outDir: string, matrix: SsdfSatisfactionMatrix): void {
  const covPath = resolve(outDir, 'inventory-coverage.json');
  if (!existsSync(covPath)) return;
  try {
    const cov = JSON.parse(readFileSync(covPath, 'utf8'));
    const ssdf = (cov.ssdf_satisfaction_matrix_coverage ??= {});
    ssdf[matrix.product.id] = {
      practices: matrix.totals.practices,
      tasks: matrix.totals.tasks,
      tasks_satisfied: matrix.totals.tasks_by_status['satisfied'],
      tasks_partially_satisfied: matrix.totals.tasks_by_status['partially-satisfied'],
      tasks_not_satisfied: matrix.totals.tasks_by_status['not-satisfied'],
      tasks_not_assessed: matrix.totals.tasks_by_status['not-assessed'],
      tasks_requires_operator_input: matrix.totals.tasks_by_status['requires-operator-input'],
    };
    writeFileSync(covPath, JSON.stringify(cov, null, 2));
  } catch (e) {
    log.warn({ event: 't.t2.coverage_augment_failed', err: String((e as Error)?.message ?? e) });
  }
}
