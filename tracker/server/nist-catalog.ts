/**
 * LOOP-B.B4 — NIST SP 800-53 Rev 5 control catalog (tracker side).
 *
 * The compensating-controls registry validates every operator-supplied
 * `nist_control_ids[]` entry against the real published catalog. The catalog is
 * a committed copy of cloud-evidence/docs/nist-r5-controls.generated.json (single
 * source of truth in the repo — per B.B4.md open-question Q1 we ship a copy under
 * tracker/server/data/ rather than fetching it from cloud-evidence at boot, so
 * the tracker has no runtime cross-system dependency).
 *
 * The lookup is loaded once into a Set keyed by the catalog's canonical key form
 * (lowercase, dot-notation enhancements) so validation is O(1) per id (B.B4-7).
 * The normaliser mirrors cloud-evidence/core/nist-r5.ts:normalizeControlId so a
 * control that validates here validates identically on the cloud-evidence side.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CATALOG_PATH = process.env.TRACKER_NIST_CATALOG_PATH ?? join(__dirname, 'data', 'nist-r5-controls.generated.json');

let _keys: Set<string> | null = null;
let _catalogVersion: string | null = null;

/**
 * Normalise a control id to the catalog key form: lowercase, `AC-2(3)` → `ac-2.3`.
 * Byte-identical to cloud-evidence/core/nist-r5.ts:normalizeControlId.
 */
export function normalizeControlId(id: string): string {
  return String(id).trim().toLowerCase().replace(/\((\d+)\)/g, '.$1');
}

function keys(): Set<string> {
  if (_keys) return _keys;
  try {
    const raw = JSON.parse(readFileSync(CATALOG_PATH, 'utf8')) as Record<string, unknown>;
    _keys = new Set(Object.keys(raw));
  } catch {
    // A missing/corrupt catalog is a fatal misconfiguration for validation — an
    // empty set makes every id invalid rather than silently accepting anything.
    _keys = new Set<string>();
  }
  return _keys;
}

/** Reset the in-process cache (tests that swap TRACKER_NIST_CATALOG_PATH). */
export function _resetNistCatalog(): void { _keys = null; _catalogVersion = null; }

/** True when `id` is a real Rev 5 control / enhancement (base `AC-2` or `AC-2(3)`/`ac-2.3`). */
export function isValidControlId(id: string): boolean {
  const key = normalizeControlId(id);
  if (!key) return false;
  return keys().has(key);
}

/**
 * Split a list of operator-supplied ids into { valid, invalid }. Preserves the
 * caller's original casing/notation in both buckets so a 400 response can name
 * the exact offending value the operator typed.
 */
export function partitionControlIds(ids: string[]): { valid: string[]; invalid: string[] } {
  const valid: string[] = [];
  const invalid: string[] = [];
  for (const id of ids) (isValidControlId(id) ? valid : invalid).push(id);
  return { valid, invalid };
}

/** Catalog version tag stamped on each record's OSCAL prop (B.B4-1 catalog drift). */
export function catalogVersion(): string {
  if (_catalogVersion) return _catalogVersion;
  _catalogVersion = `nist-800-53r5:${keys().size}`;
  return _catalogVersion;
}
