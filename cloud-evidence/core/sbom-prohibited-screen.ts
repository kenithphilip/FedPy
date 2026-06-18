/**
 * SBOM prohibited-vendor screener (LOOP-W.W2, surface 2).
 *
 * Walks every package in the cosign-verified SBOMs produced upstream (LOOP-E.E2
 * / `core/sbom.ts`) and screens each package's maintainer signal — name,
 * supplier, originator, publisher, and purl namespace — against the W.W1
 * prohibited-vendor catalog. The walk is transitive: FAR 4.2102's "uses"
 * language reaches an indirect dependency at depth-N, so we follow the SPDX
 * `relationships[]` / CycloneDX `dependencies[]` graph up to `--sbom-max-depth`
 * (default 8) and record the full `match_path` of package names from the root.
 *
 * This module reads the raw SPDX/CycloneDX bytes itself (rather than the
 * flattened `core/sbom.ts` component list) because the dependency graph + the
 * supplier/publisher/originator fields are only present in the source document.
 * It composes `listSbomFiles()` from `core/sbom.ts` for file discovery.
 *
 * Confidence: the catalog matcher's base confidence is capped by which field
 * fired (supplier/name = exact, publisher/originator = 0.95, purl namespace =
 * 0.85) and then reduced by a per-hop transitive penalty (-0.02/hop, floor 0.5).
 */
import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import { log } from './log.ts';
import { listSbomFiles } from './sbom.ts';
import type {
  ProhibitedVendorIndex,
  ProhibitedVendorMatch,
  EntryMatch,
  MatchedBy,
} from './prohibited-vendors-screen.ts';
import { buildMatch } from './prohibited-vendors-screen.ts';

const PER_HOP_PENALTY = 0.02;
const CONFIDENCE_FLOOR = 0.5;
const DEFAULT_MAX_DEPTH = 8;

interface SbomPackage {
  key: string;
  name: string;
  supplier?: string;
  originator?: string;
  publisher?: string;
  homepage?: string;
  purl?: string;
}

interface ParsedSbom {
  format: 'spdx' | 'cyclonedx';
  packages: Map<string, SbomPackage>;
  /** key -> child keys (dependency edges). */
  edges: Map<string, string[]>;
  roots: string[];
}

/** Strip an SPDX "Organization: " / "Person: " annotation prefix. */
function stripSpdxActorPrefix(v: string | undefined): string | undefined {
  if (!v || v === 'NOASSERTION') return undefined;
  const m = /^(?:Organization|Person|Tool):\s*(.+)$/.exec(v);
  return ((m?.[1] ?? v).trim()) || undefined;
}

function purlNamespace(purl: string | undefined): string | undefined {
  if (!purl) return undefined;
  // pkg:npm/@huawei-oss/foo@1 -> "@huawei-oss"; pkg:golang/github.com/zte/x -> "github.com/zte".
  const m = /^pkg:[^/]+\/([^@]+)/.exec(purl);
  if (!m) return undefined;
  const path = m[1]!;
  const parts = path.split('/');
  return parts.length > 1 ? parts.slice(0, -1).join(' ') : path;
}

function parseSpdx(json: any): ParsedSbom {
  const packages = new Map<string, SbomPackage>();
  for (const p of json?.packages ?? []) {
    const key = p.SPDXID ?? p.name;
    if (!key) continue;
    packages.set(key, {
      key,
      name: p.name ?? key,
      supplier: stripSpdxActorPrefix(p.supplier),
      originator: stripSpdxActorPrefix(p.originator),
      homepage: p.packageHomePage && p.packageHomePage !== 'NOASSERTION' ? p.packageHomePage : undefined,
      purl: (p.externalRefs ?? []).find(
        (r: any) => r.referenceType === 'purl' || r.referenceCategory === 'PACKAGE-MANAGER',
      )?.referenceLocator,
    });
  }
  const edges = new Map<string, string[]>();
  const children = new Set<string>();
  const describes: string[] = [];
  for (const rel of json?.relationships ?? []) {
    const type = String(rel.relationshipType ?? '');
    const from = rel.spdxElementId;
    const to = rel.relatedSpdxElement;
    if (!from || !to) continue;
    if (type === 'DESCRIBES' && packages.has(to)) { describes.push(to); continue; }
    if (type === 'DEPENDS_ON' || type === 'CONTAINS') {
      if (!packages.has(from) || !packages.has(to)) continue;
      const list = edges.get(from) ?? [];
      list.push(to);
      edges.set(from, list);
      children.add(to);
    }
  }
  const roots = describes.length > 0
    ? describes
    : [...packages.keys()].filter((k) => !children.has(k));
  return { format: 'spdx', packages, edges, roots: roots.length ? roots : [...packages.keys()] };
}

function parseCycloneDx(json: any): ParsedSbom {
  const packages = new Map<string, SbomPackage>();
  const keyFor = (c: any): string => c['bom-ref'] ?? c.purl ?? c.name;
  const rootComp = json?.metadata?.component;
  if (rootComp) {
    const k = keyFor(rootComp);
    if (k) packages.set(k, {
      key: k, name: rootComp.name ?? k,
      publisher: rootComp.publisher, supplier: rootComp.supplier?.name, purl: rootComp.purl,
    });
  }
  for (const c of json?.components ?? []) {
    const k = keyFor(c);
    if (!k) continue;
    packages.set(k, {
      key: k,
      name: c.name ?? k,
      publisher: c.publisher,
      supplier: c.supplier?.name,
      purl: c.purl,
    });
  }
  const edges = new Map<string, string[]>();
  const children = new Set<string>();
  for (const d of json?.dependencies ?? []) {
    if (!d?.ref) continue;
    const deps = (d.dependsOn ?? []).filter((x: any) => typeof x === 'string');
    edges.set(d.ref, deps);
    for (const c of deps) children.add(c);
  }
  const rootKey = rootComp ? keyFor(rootComp) : undefined;
  const roots = rootKey && packages.has(rootKey)
    ? [rootKey]
    : [...packages.keys()].filter((k) => !children.has(k));
  return { format: 'cyclonedx', packages, edges, roots: roots.length ? roots : [...packages.keys()] };
}

function detectAndParse(json: any): ParsedSbom | null {
  if (json?.bomFormat === 'CycloneDX' || Array.isArray(json?.dependencies) && json?.components) {
    return parseCycloneDx(json);
  }
  if (json?.spdxVersion || Array.isArray(json?.packages)) return parseSpdx(json);
  if (Array.isArray(json?.components)) return parseCycloneDx(json);
  return null;
}

export interface SbomScreenResult {
  matches: ProhibitedVendorMatch[];
  packages_screened: number;
  files_screened: number;
  truncated_at_depth: number | null;
}

export interface SbomScreenOptions {
  sbomDir?: string;
  sbomPaths?: string[];
  index: ProhibitedVendorIndex;
  discoveredAt: string;
  maxDepth?: number;
}

/** Screen the maintainer fields of one package; returns the best EntryMatch+field per catalog entry. */
function screenPackageFields(
  pkg: SbomPackage,
  index: ProhibitedVendorIndex,
): Array<{ em: EntryMatch; field: string; cap: number; matchedName: string }> {
  const fields: Array<{ value: string | undefined; field: string; cap: number }> = [
    { value: pkg.supplier, field: 'supplier', cap: 1.0 },
    { value: pkg.name, field: 'name', cap: 1.0 },
    { value: pkg.originator, field: 'originator', cap: 0.95 },
    { value: pkg.publisher, field: 'publisher', cap: 0.95 },
    { value: purlNamespace(pkg.purl), field: 'purl', cap: 0.85 },
  ];
  const bestByEntry = new Map<string, { em: EntryMatch; field: string; cap: number; matchedName: string }>();
  for (const f of fields) {
    if (!f.value) continue;
    for (const em of index.match(f.value)) {
      const effective = Math.min(em.confidence, f.cap);
      const prev = bestByEntry.get(em.entry.catalog_uid);
      const prevEff = prev ? Math.min(prev.em.confidence, prev.cap) : -1;
      if (!prev || effective > prevEff) {
        bestByEntry.set(em.entry.catalog_uid, { em, field: f.field, cap: f.cap, matchedName: f.value });
      }
    }
  }
  return [...bestByEntry.values()];
}

/** Screen every SBOM under `sbomDir` (or `sbomPaths`) transitively. */
export function screenSbomDir(opts: SbomScreenOptions): SbomScreenResult {
  const files = opts.sbomPaths ?? (opts.sbomDir ? listSbomFiles(opts.sbomDir) : []);
  const maxDepth = opts.maxDepth ?? DEFAULT_MAX_DEPTH;
  const matches: ProhibitedVendorMatch[] = [];
  let packagesScreened = 0;
  let truncatedAtDepth: number | null = null;

  for (const file of files) {
    let json: any;
    try {
      json = JSON.parse(readFileSync(file, 'utf8'));
    } catch (e) {
      log.warn({ event: 'w.w2.sbom_parse_failed', file: basename(file), err: String((e as Error)?.message ?? e) });
      continue;
    }
    const parsed = detectAndParse(json);
    if (!parsed) {
      log.warn({ event: 'w.w2.sbom_unknown_format', file: basename(file) });
      continue;
    }

    const visited = new Set<string>();
    const walk = (key: string, path: string[], depth: number): void => {
      if (depth > maxDepth) { truncatedAtDepth = maxDepth; return; }
      if (visited.has(key)) return;
      visited.add(key);
      const pkg = parsed.packages.get(key);
      if (!pkg) return;
      packagesScreened += 1;
      const matchPath = [...path];
      for (const hit of screenPackageFields(pkg, opts.index)) {
        const penalty = PER_HOP_PENALTY * depth;
        const capped = Math.min(hit.em.confidence, hit.cap);
        const confidence = Math.max(CONFIDENCE_FLOOR, +(capped - penalty).toFixed(4));
        const matchedBy: MatchedBy = hit.field === 'purl' ? 'domain-registrable' : hit.em.matched_by;
        matches.push(buildMatch({
          entryMatch: hit.em,
          surface: 'sbom',
          matchedName: hit.matchedName,
          matchPath,
          discoveredAt: opts.discoveredAt,
          confidence,
          matchedBy,
          sources: {
            surface_evidence: `sbom:${parsed.format}:${pkg.purl ?? pkg.key}`,
            sbom_package_purl: pkg.purl,
          },
        }));
      }
      for (const child of parsed.edges.get(key) ?? []) {
        const childPkg = parsed.packages.get(child);
        walk(child, [...path, childPkg?.name ?? child], depth + 1);
      }
    };

    for (const root of parsed.roots) {
      const rootPkg = parsed.packages.get(root);
      walk(root, [rootPkg?.name ?? root], 0);
    }
  }

  return {
    matches,
    packages_screened: packagesScreened,
    files_screened: files.length,
    truncated_at_depth: truncatedAtDepth,
  };
}
