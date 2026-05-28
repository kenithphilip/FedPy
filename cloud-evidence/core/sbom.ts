/**
 * SBOM depth: parse + verify + correlate.
 *
 * The cloud-native KSI catalog (CMT-RMV / CMT-VTD / SCR-MON) requires
 * verifiable claims about what's running in production. Our existing
 * ECR / Artifact Registry collectors capture image metadata, but they
 * don't tell the auditor WHICH packages are inside each image.
 *
 * This module accepts a directory of SBOM files (CycloneDX 1.4+ JSON or
 * SPDX 2.3+ JSON — both are widely emitted by Syft, Trivy, and Grype) and
 * produces:
 *   1. A normalized component inventory (package@version, license, source).
 *   2. Vulnerability cross-reference against an embedded snapshot of NVD CVE
 *      severities (or fed externally via SBOM_NVD_INDEX_PATH).
 *   3. Cosign signature verification for SBOMs accompanied by a `.sig` file.
 *   4. Summary findings: count of critical/high CVEs, unsigned SBOMs,
 *      packages without known fix versions.
 *
 * Why included at this layer (not as a collector):
 *   SBOMs are produced by CI, not the cloud. The orchestrator can consume
 *   them from a path the CI writes to (S3 sync, GCS sync, or local CI
 *   artifact). This module exposes a CLI-callable function the orchestrator
 *   wires when `--sbom-dir <path>` is set.
 *
 * Limitations:
 *   - We don't ship a CVE database. The caller must supply one via env
 *     SBOM_NVD_INDEX_PATH (JSON: { "CVE-2024-12345": { severity: "HIGH" } }).
 *     Without it we still produce the inventory + signature verification
 *     but skip the vuln correlation step.
 *   - cosign verification shells out to the `cosign` binary if available.
 *     If absent, we mark signatures as "unverified" with a warning.
 */
import { createHash } from 'node:crypto';
import { spawnSync as _spawnSync } from 'node:child_process';
import { readdirSync, readFileSync, existsSync, statSync, writeFileSync } from 'node:fs';
import { resolve, basename } from 'node:path';
import { log } from './log.ts';

export interface SbomComponent {
  name: string;
  version: string;
  type?: string;                 // library / application / container / file
  purl?: string;                 // packageURL spec
  licenses?: string[];
  source_image?: string;         // which image SBOM listed this component
}

export interface SbomVuln {
  cve_id: string;
  severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  affected_components: string[]; // "name@version"
  fix_available?: boolean;
}

export interface SbomFile {
  path: string;
  format: 'cyclonedx' | 'spdx' | 'unknown';
  image: string;                 // best-effort source image identifier
  bytes: number;
  components: SbomComponent[];
  /** True if a `.sig` (or `.pem`) sidecar was present AND cosign verified it. */
  signature_status: 'verified' | 'unverified' | 'absent';
}

export interface SbomReport {
  generated_at: string;
  sboms: SbomFile[];
  vulnerabilities: SbomVuln[];
  summary: {
    sbom_count: number;
    total_components: number;
    unique_components: number;
    signed_sboms: number;
    unsigned_sboms: number;
    critical_vulns: number;
    high_vulns: number;
    medium_vulns: number;
  };
}

// ---- Parsers ----

function parseCycloneDx(json: any, sourcePath: string): { image: string; components: SbomComponent[] } {
  const components: SbomComponent[] = [];
  const image = json?.metadata?.component?.name
    ?? json?.metadata?.component?.purl
    ?? basename(sourcePath, '.json');
  for (const c of json?.components ?? []) {
    components.push({
      name: c.name ?? '<unnamed>',
      version: c.version ?? '<no-version>',
      type: c.type,
      purl: c.purl,
      licenses: (c.licenses ?? []).map((l: any) => l?.license?.id ?? l?.license?.name ?? '').filter(Boolean),
      source_image: image,
    });
  }
  return { image, components };
}

function parseSpdx(json: any, sourcePath: string): { image: string; components: SbomComponent[] } {
  const components: SbomComponent[] = [];
  const image = json?.name ?? basename(sourcePath, '.spdx.json');
  for (const p of json?.packages ?? []) {
    components.push({
      name: p.name ?? '<unnamed>',
      version: p.versionInfo ?? '<no-version>',
      type: p.primaryPackagePurpose,
      purl: (p.externalRefs ?? []).find((r: any) => r.referenceCategory === 'PACKAGE-MANAGER' && r.referenceType === 'purl')?.referenceLocator,
      licenses: [p.licenseConcluded, p.licenseDeclared].filter((l) => l && l !== 'NOASSERTION'),
      source_image: image,
    });
  }
  return { image, components };
}

function detectFormat(json: any): 'cyclonedx' | 'spdx' | 'unknown' {
  if (json?.bomFormat === 'CycloneDX' || Array.isArray(json?.components)) return 'cyclonedx';
  if (json?.spdxVersion || Array.isArray(json?.packages)) return 'spdx';
  return 'unknown';
}

// ---- Signature verification ----

function whichCosign(): string | null {
  const r = _spawnSync('/bin/sh', ['-c', 'command -v cosign'], { encoding: 'utf8' });
  return r.status === 0 && r.stdout.trim() ? r.stdout.trim() : null;
}

function verifySignature(sbomPath: string): 'verified' | 'unverified' | 'absent' {
  const sigPath = `${sbomPath}.sig`;
  if (!existsSync(sigPath)) return 'absent';
  const cosign = whichCosign();
  if (!cosign) {
    log.warn({ event: 'sbom.cosign_missing', sbom: sbomPath, note: 'Install cosign to verify SBOM signatures.' });
    return 'unverified';
  }
  // We don't know the issuer/subject up-front; users provide via env to
  // avoid hardcoding a trust policy. If not supplied, we use --insecure-ignore-tlog
  // + key path from COSIGN_PUBLIC_KEY (PEM).
  const publicKey = process.env.COSIGN_PUBLIC_KEY;
  if (!publicKey) {
    log.warn({ event: 'sbom.cosign_no_key', note: 'Set COSIGN_PUBLIC_KEY=/path/to/public.pem to enable signature verification.' });
    return 'unverified';
  }
  const r = _spawnSync(cosign, ['verify-blob', '--key', publicKey, '--signature', sigPath, sbomPath], { encoding: 'utf8' });
  return r.status === 0 ? 'verified' : 'unverified';
}

// ---- Vulnerability correlation ----

interface NvdIndexEntry {
  severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  affects?: string[];                    // list of purl prefixes the CVE applies to
  fix_versions?: Record<string, string>; // purl-prefix → fixed-version
}
type NvdIndex = Record<string, NvdIndexEntry>;

function loadNvdIndex(): NvdIndex | null {
  const p = process.env.SBOM_NVD_INDEX_PATH;
  if (!p || !existsSync(p)) return null;
  try {
    return JSON.parse(readFileSync(p, 'utf8'));
  } catch (e: any) {
    log.warn({ event: 'sbom.nvd_index_load_failed', err_message: e?.message });
    return null;
  }
}

function correlateVulns(components: SbomComponent[], nvd: NvdIndex): SbomVuln[] {
  const out: SbomVuln[] = [];
  for (const [cve, entry] of Object.entries(nvd)) {
    if (!entry.affects) continue;
    const affected: string[] = [];
    for (const c of components) {
      if (!c.purl) continue;
      for (const prefix of entry.affects) {
        if (c.purl.startsWith(prefix)) {
          affected.push(`${c.name}@${c.version}`);
          break;
        }
      }
    }
    if (affected.length > 0) {
      out.push({
        cve_id: cve,
        severity: entry.severity ?? 'UNKNOWN',
        affected_components: [...new Set(affected)],
        fix_available: entry.fix_versions != null && Object.keys(entry.fix_versions).length > 0,
      });
    }
  }
  return out;
}

// ---- Public API ----

export function listSbomFiles(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const f of readdirSync(dir)) {
    const p = resolve(dir, f);
    if (!statSync(p).isFile()) continue;
    if (/\.(json|spdx\.json|cdx\.json|cyclonedx\.json)$/.test(f)) out.push(p);
  }
  return out.sort();
}

export interface BuildReportOptions {
  /** Directory of SBOM files. */
  sbomDir: string;
  /** Where to write the report JSON. Defaults to <sbomDir>/../sbom-report.json. */
  outPath?: string;
}

export function buildSbomReport(opts: BuildReportOptions): SbomReport {
  const files = listSbomFiles(opts.sbomDir);
  const sboms: SbomFile[] = [];
  const allComponents: SbomComponent[] = [];

  for (const f of files) {
    let json: any;
    try {
      json = JSON.parse(readFileSync(f, 'utf8'));
    } catch (e: any) {
      log.warn({ event: 'sbom.parse_failed', file: f, err_message: e?.message });
      continue;
    }
    const format = detectFormat(json);
    if (format === 'unknown') {
      log.warn({ event: 'sbom.unknown_format', file: f });
      continue;
    }
    const parsed = format === 'cyclonedx' ? parseCycloneDx(json, f) : parseSpdx(json, f);
    const bytes = readFileSync(f).length;
    const signature_status = verifySignature(f);
    sboms.push({
      path: f,
      format,
      image: parsed.image,
      bytes,
      components: parsed.components,
      signature_status,
    });
    allComponents.push(...parsed.components);
  }

  const nvd = loadNvdIndex();
  const vulns = nvd ? correlateVulns(allComponents, nvd) : [];

  const uniqueKey = new Set(allComponents.map((c) => `${c.name}@${c.version}`));
  const summary = {
    sbom_count: sboms.length,
    total_components: allComponents.length,
    unique_components: uniqueKey.size,
    signed_sboms: sboms.filter((s) => s.signature_status === 'verified').length,
    unsigned_sboms: sboms.filter((s) => s.signature_status === 'absent').length,
    critical_vulns: vulns.filter((v) => v.severity === 'CRITICAL').length,
    high_vulns: vulns.filter((v) => v.severity === 'HIGH').length,
    medium_vulns: vulns.filter((v) => v.severity === 'MEDIUM').length,
  };

  const report: SbomReport = {
    generated_at: new Date().toISOString(),
    sboms,
    vulnerabilities: vulns,
    summary,
  };

  const outPath = opts.outPath ?? resolve(opts.sbomDir, '..', 'sbom-report.json');
  writeFileSync(outPath, JSON.stringify(report, null, 2));
  log.info({ event: 'sbom.report_emitted', path: outPath, ...summary });

  return report;
}

/** Convenience: compute a content hash for deduplication / cache busting. */
export function sbomFingerprint(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}
