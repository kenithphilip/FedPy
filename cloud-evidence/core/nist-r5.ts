/**
 * NIST SP 800-53 Rev5 control enrichment.
 *
 * Loads the committed control-id → {name, family} lookup
 * (docs/nist-r5-controls.generated.json, produced by scripts/extract-nist-r5.mjs
 * from the GovReady nist-sp-800-53-r5-data repo) and resolves a requirement's
 * `controls[]` to official Rev5 control names. This grounds the DERIVED High
 * applicability with evidence: instead of a bare "ra-5", the evidence shows
 * "ra-5 — Vulnerability Monitoring and Scanning (RA)".
 *
 * Read-only; the lookup ships with the repo so no reference clone is needed at runtime.
 */
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEFAULT_PATH = resolve(__dirname, '..', 'docs', 'nist-r5-controls.generated.json');

export interface NistControl {
  /** Canonical Rev5 id, e.g. "RA-5(2)". */
  id: string;
  /** Official control title. */
  name: string | null;
  /** Control family code, e.g. "RA". */
  family: string | null;
}

let _cache: Record<string, NistControl> | null = null;

/** Load (and cache) the Rev5 control lookup. Returns {} if the file is absent. */
export function loadNistControls(path = process.env.NIST_R5_LOOKUP_PATH ?? DEFAULT_PATH): Record<string, NistControl> {
  if (_cache) return _cache;
  if (!existsSync(path)) { _cache = {}; return _cache; }
  try {
    _cache = JSON.parse(readFileSync(path, 'utf8')) as Record<string, NistControl>;
  } catch {
    _cache = {};
  }
  return _cache;
}

/** Reset cache (tests). */
export function _resetNistCache(): void { _cache = null; }

/**
 * Resolve FRMR-style control ids ("ra-5", "ra-5.2") to Rev5 details. Unknown ids
 * are returned with name=null so nothing is silently dropped.
 */
export function controlDetails(ids: string[] | undefined): NistControl[] {
  if (!ids || ids.length === 0) return [];
  const lookup = loadNistControls();
  return ids.map((raw) => {
    const key = String(raw).toLowerCase().trim();
    return lookup[key] ?? { id: raw, name: null, family: deriveFamily(key) };
  });
}

/** One-line "ra-5 — Vulnerability Monitoring and Scanning" string per control. */
export function describeControls(ids: string[] | undefined): string[] {
  return controlDetails(ids).map((c) => (c.name ? `${c.id.toLowerCase()} — ${c.name}` : c.id.toLowerCase()));
}

function deriveFamily(key: string): string | null {
  const m = key.match(/^([a-z]{2})-/);
  return m ? m[1]!.toUpperCase() : null;
}

/**
 * Normalise a control id to the catalog's key form: lowercase, and OSCAL /
 * human-style enhancement parentheses `AC-2(3)` collapsed to the FRMR-style dot
 * `ac-2.3`. Operators type either form; the catalog is keyed `ac-2.3`. Reused
 * server-side by the tracker (LOOP-B.B4) so both validate identically.
 */
export function normalizeControlId(id: string): string {
  return String(id).trim().toLowerCase().replace(/\((\d+)\)/g, '.$1');
}

/**
 * True when `id` resolves to a real NIST SP 800-53 Rev 5 control or control
 * enhancement in the committed catalog. Accepts base controls (`AC-2`) and
 * enhancements in either notation (`AC-2(3)` or `ac-2.3`). LOOP-B.B4 validates
 * every operator-supplied compensating-control NIST id through this gate.
 */
export function isValidControlId(id: string): boolean {
  const key = normalizeControlId(id);
  if (!key) return false;
  return key in loadNistControls();
}
