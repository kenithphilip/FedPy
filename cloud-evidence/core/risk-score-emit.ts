/**
 * Disk emitter for per-finding composite risk scores (LOOP-B.B1).
 *
 * Pipeline:
 *   1. Load risk-config.yaml (weights, EPSS settings, operator CVSS overrides).
 *   2. Read inventory.json (criticality + exposure signals).
 *   3. Walk every out/KSI-*.json evidence envelope; collect the CVE universe.
 *   4. Resolve EPSS once (batched, cached) via core/risk-score.ts lookupEpss().
 *   5. Compute a RiskScore per finding (pure) and rewrite each envelope IN
 *      PLACE so downstream consumers (POA&M, AR, dashboards) see finding.risk_score.
 *   6. Emit out/risk-scores.json with a G3 provenance block + a self-contained
 *      detached Ed25519 signature, and finalise the EPSS cache with provenance.
 *
 * Runs BEFORE the OSCAL POA&M emitter and BEFORE run signing, so the rewritten
 * envelopes + risk-scores.json + cache are all covered by the run manifest.
 *
 * REO: every signal traces to real evidence (collector-cited / operator-
 * supplied CVSS, live EPSS API, real inventory reads) or is marked
 * REQUIRES-OPERATOR-INPUT. No NODE_ENV branches; the EPSS fetcher + clock are
 * dependency-injected for tests.
 */
import { readdirSync, readFileSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { resolve, basename } from 'node:path';
import { canonicalize, signDetached, type DetachedSignature } from './sign.ts';
import type { EvidenceFile, Finding } from './envelope.ts';
import {
  computeRiskScore,
  collectCveIds,
  lookupEpss,
  EPSS_ENDPOINT,
  FORMULA_VERSION,
  type RiskContext,
  type RiskScore,
  type EpssScore,
  type InventoryAsset,
} from './risk-score.ts';
import { loadRiskConfig, type RiskConfig } from './risk-config.ts';

export const RISK_SCORES_FILENAME = 'risk-scores.json';
export const EPSS_CACHE_FILENAME = '.epss-cache.json';

const KSI_FILE_RE = /^KSI-[A-Za-z0-9-]+\.json$/;

export interface RiskScoreEmitOptions {
  outDir: string;
  runId: string;
  inventoryPath?: string;
  riskConfigPath?: string;
  /** CLI/env override of the EPSS feed enable flag (else the config value). */
  epssEnabled?: boolean;
  epssCachePath?: string;
  /** Injectable clock for deterministic tests; defaults to new Date(). */
  now?: () => Date;
  /** Injectable fetch (wire-layer seam for tests); defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

export interface RiskScoreEmitResult {
  path: string;
  scored_findings: number;
  unscored_findings: number;
  cve_lookups: number;
  epss_cache_hits: number;
  epss_api_calls: number;
}

interface ScoredFindingRow {
  ksi_id: string;
  provider: string;
  rule: string;
  severity: string;
  passed: boolean;
  composite_score: number;
  criticality: number;
  exposure: number;
  sources: RiskScore['sources'];
  cvss?: RiskScore['cvss'];
  epss?: RiskScore['epss'];
}

interface RiskScoresProvenance {
  emitter: string;
  emittedAt: string;
  sourceCalls: string[];
  signingKeyId: string;
}

interface RiskScoresDoc {
  schema_version: '1.0.0';
  run_id: string;
  computed_at: string;
  formula_version: typeof FORMULA_VERSION;
  weights: RiskConfig['weights'];
  epss_enabled: boolean;
  summary: {
    scored_findings: number;
    unscored_findings: number;
    cve_lookups: number;
    epss_cache_hits: number;
    epss_api_calls: number;
    requires_operator_input: {
      cvss: number;
      epss: number;
      criticality: number;
      exposure: number;
    };
  };
  findings: ScoredFindingRow[];
  provenance: RiskScoresProvenance;
  signature?: DetachedSignature;
}

function readInventoryAssets(path: string): InventoryAsset[] {
  try {
    if (!existsSync(path)) return [];
    const doc = JSON.parse(readFileSync(path, 'utf8'));
    if (doc && Array.isArray(doc.assets)) return doc.assets as InventoryAsset[];
    return [];
  } catch {
    return [];
  }
}

/** A finding is "scored" when at least one signal beyond the CVSS severity-fallback is real. */
function isReallyScored(rs: RiskScore): boolean {
  return (
    rs.sources.cvss_source !== 'REQUIRES-OPERATOR-INPUT' ||
    rs.sources.epss_source !== 'REQUIRES-OPERATOR-INPUT' ||
    rs.sources.criticality_source !== 'REQUIRES-OPERATOR-INPUT' ||
    rs.sources.exposure_source !== 'REQUIRES-OPERATOR-INPUT'
  );
}

/**
 * Serialize the signature-blanked canonical form of a doc. The JSON round-trip
 * strips `undefined` optional fields (signature, cvss, epss) so the bytes
 * signed here are byte-identical to a verifier re-deriving them from the
 * on-disk file (which JSON.stringify wrote without those keys). Mirrors the
 * LOOP-W.W1 catalog signing convention.
 */
export function serializeUnsignedCanonical(doc: unknown): string {
  const blanked = JSON.parse(
    JSON.stringify({
      ...(doc as Record<string, unknown>),
      provenance: { ...((doc as any).provenance ?? {}), signingKeyId: '' },
      signature: undefined,
    }),
  );
  return canonicalize(blanked);
}

/** Sign + embed a detached Ed25519 signature over the signature-blanked canonical bytes. */
function signDoc<T extends { provenance: { signingKeyId: string }; signature?: DetachedSignature }>(
  doc: T,
  outDir: string,
): DetachedSignature {
  const canonical = serializeUnsignedCanonical(doc);
  const sig = signDetached(Buffer.from(canonical, 'utf8'), outDir);
  doc.provenance.signingKeyId = sig.keyId;
  doc.signature = sig;
  return sig;
}

/** Give the EPSS cache file a G3 provenance block + detached signature. */
function finalizeEpssCacheProvenance(cachePath: string, outDir: string, emittedAt: string): void {
  if (!existsSync(cachePath)) return;
  let parsed: any;
  try {
    parsed = JSON.parse(readFileSync(cachePath, 'utf8'));
  } catch {
    return;
  }
  const doc = {
    provenance: { emitter: 'core/risk-score-emit.ts', emittedAt, sourceCalls: [EPSS_ENDPOINT], signingKeyId: '' },
    entries: parsed.entries ?? {},
    fetched_at: parsed.fetched_at ?? emittedAt,
    signature: undefined as DetachedSignature | undefined,
  };
  signDoc(doc, outDir);
  writeFileSync(cachePath, JSON.stringify(doc, null, 2));
}

/**
 * Compute + emit per-finding risk scores. Returns counts for the orchestrator
 * log line. The function is idempotent: re-running rewrites the same scores.
 */
export async function emitRiskScores(opts: RiskScoreEmitOptions): Promise<RiskScoreEmitResult> {
  const now = opts.now ?? (() => new Date());
  const config = loadRiskConfig(opts.riskConfigPath);
  const epssEnabled = opts.epssEnabled ?? config.epssEnabled;
  const inventoryPath = opts.inventoryPath ?? resolve(opts.outDir, 'inventory.json');
  const cachePath = opts.epssCachePath ?? resolve(opts.outDir, EPSS_CACHE_FILENAME);

  const inventory = { assets: readInventoryAssets(inventoryPath) };

  // Discover KSI envelopes (skip already-signed snapshots — we score pre-sign).
  const ksiFiles = readdirSync(opts.outDir)
    .filter((f) => KSI_FILE_RE.test(f) && !f.endsWith('.signed.json') && !f.endsWith('.example.json'))
    .filter((f) => {
      try {
        return statSync(resolve(opts.outDir, f)).isFile();
      } catch {
        return false;
      }
    })
    .sort();

  // Parse envelopes + collect the CVE universe.
  const envelopes: Array<{ file: string; doc: EvidenceFile }> = [];
  const cveUniverse = new Set<string>();
  for (const f of ksiFiles) {
    let doc: EvidenceFile;
    try {
      doc = JSON.parse(readFileSync(resolve(opts.outDir, f), 'utf8')) as EvidenceFile;
    } catch {
      continue; // unreadable/parse error → skip; do not fabricate
    }
    envelopes.push({ file: f, doc });
    for (const p of doc.providers ?? []) {
      for (const finding of p.findings ?? []) {
        for (const cve of collectCveIds(finding)) cveUniverse.add(cve);
      }
    }
  }

  // Resolve EPSS once for the whole run (batched + cached).
  const epss = await lookupEpss(
    [...cveUniverse],
    { enabled: epssEnabled, cachePath, ttlHours: config.epssTtlHours, endpoint: EPSS_ENDPOINT },
    { fetchImpl: opts.fetchImpl, now },
  );
  const epssByCve = epss.scores as Map<string, EpssScore>;

  const ctx: RiskContext = { inventory, epssByCve, epssEnabled };

  // Score + rewrite each envelope in place.
  const rows: ScoredFindingRow[] = [];
  const rfi = { cvss: 0, epss: 0, criticality: 0, exposure: 0 };
  let scored = 0;
  let unscored = 0;
  for (const { file, doc } of envelopes) {
    let mutated = false;
    for (const p of doc.providers ?? []) {
      for (const finding of p.findings ?? []) {
        const rs = computeRiskScore(finding, ctx, {
          weights: config.weights,
          operatorCvssVectors: config.operatorCvssVectors,
          now,
        });
        (finding as Finding).risk_score = rs;
        mutated = true;
        if (isReallyScored(rs)) scored++;
        else unscored++;
        if (rs.sources.cvss_source === 'REQUIRES-OPERATOR-INPUT') rfi.cvss++;
        if (rs.sources.epss_source === 'REQUIRES-OPERATOR-INPUT') rfi.epss++;
        if (rs.sources.criticality_source === 'REQUIRES-OPERATOR-INPUT') rfi.criticality++;
        if (rs.sources.exposure_source === 'REQUIRES-OPERATOR-INPUT') rfi.exposure++;
        rows.push({
          ksi_id: doc.ksi_id,
          provider: p.provider,
          rule: finding.rule,
          severity: finding.severity,
          passed: finding.passed,
          composite_score: rs.composite_score,
          criticality: rs.criticality,
          exposure: rs.exposure,
          sources: rs.sources,
          cvss: rs.cvss,
          epss: rs.epss,
        });
      }
    }
    if (mutated) {
      writeFileSync(resolve(opts.outDir, file), JSON.stringify(doc, null, 2));
    }
  }

  // Deterministic ordering for canonical stability.
  rows.sort(
    (a, b) =>
      a.ksi_id.localeCompare(b.ksi_id) ||
      a.provider.localeCompare(b.provider) ||
      a.rule.localeCompare(b.rule),
  );

  const emittedAt = now().toISOString();
  const sourceCalls = [
    ...ksiFiles.map((f) => `evidence:${f}`),
    `inventory:${basename(inventoryPath)}`,
    EPSS_ENDPOINT,
  ];

  const out: RiskScoresDoc = {
    schema_version: '1.0.0',
    run_id: opts.runId,
    computed_at: emittedAt,
    formula_version: FORMULA_VERSION,
    weights: config.weights,
    epss_enabled: epssEnabled,
    summary: {
      scored_findings: scored,
      unscored_findings: unscored,
      cve_lookups: cveUniverse.size,
      epss_cache_hits: epss.cacheHits,
      epss_api_calls: epss.apiCalls,
      requires_operator_input: rfi,
    },
    findings: rows,
    provenance: {
      emitter: 'core/risk-score-emit.ts',
      emittedAt,
      sourceCalls,
      signingKeyId: '',
    },
  };

  const outPath = resolve(opts.outDir, RISK_SCORES_FILENAME);
  signDoc(out, opts.outDir);
  writeFileSync(outPath, JSON.stringify(out, null, 2));

  // Give the EPSS cache its own provenance + signature (G3-clean in out/).
  finalizeEpssCacheProvenance(cachePath, opts.outDir, emittedAt);

  return {
    path: outPath,
    scored_findings: scored,
    unscored_findings: unscored,
    cve_lookups: cveUniverse.size,
    epss_cache_hits: epss.cacheHits,
    epss_api_calls: epss.apiCalls,
  };
}
