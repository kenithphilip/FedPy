/**
 * Typed loader + validator for `prohibited-vendors-overrides.yaml` (LOOP-W.W2).
 *
 * The operator optionally commits this file to (a) suppress verified false
 * positives, (b) add operator-discovered vendors that are not on any published
 * federal list (FAR 4.2101 "reasonable inquiry" of entities in the operator's
 * possession), (c) register cosign key fingerprints against catalog rows, and
 * (d) extend the transliteration table. Per CLAUDE.md REO Rule 4, every field
 * here is real operator-supplied data: a malformed file throws a typed error
 * and the screen exits non-zero rather than silently ignoring the override.
 *
 * Every suppression MUST carry a non-empty justification (no silent
 * suppression — a 3PAO can audit the trail) and an `expires_at` that, when
 * present, must be a valid date so the suppression cannot live forever
 * un-reviewed.
 */
import { readFileSync, existsSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';

export const OVERRIDES_SCHEMA_VERSION = '1.0.0';

/** Thrown when the overrides file is malformed or violates the schema. */
export class ProhibitedVendorOverridesSchemaError extends Error {
  readonly path: string;
  constructor(path: string, message: string) {
    super(`prohibited-vendors-overrides: ${message}`);
    this.name = 'ProhibitedVendorOverridesSchemaError';
    this.path = path;
  }
}

export interface Suppression {
  /** Optional human label for the suppressed vendor (audit readability). */
  vendor?: string;
  /** The catalog row this suppression applies to (`<source_id>::<record_id>`). */
  catalog_uid: string;
  /** REQUIRED — why the operator verified this is not a covered entity. */
  justification: string;
  /** Optional ISO date; after it the match re-surfaces (no permanent suppression). */
  expires_at?: string | null;
}

export interface ManualAddition {
  /** Canonical vendor name to screen for. */
  entity_name: string;
  aliases?: string[];
  /** Operator-asserted subsidiary names (or "Parent>Child" chains). */
  subsidiaries?: string[];
  /** cosign key fingerprints attributable to this entity (OCI surface). */
  fingerprints?: string[];
  /** REQUIRED — the operator's basis for adding this off-list entity. */
  justification: string;
}

export interface FingerprintOverride {
  catalog_uid: string;
  fingerprints: string[];
}

export interface ProhibitedVendorOverrides {
  schema_version: string;
  suppressions: Suppression[];
  manual_additions: ManualAddition[];
  transliteration_overrides: Record<string, string>;
  fingerprint_overrides: FingerprintOverride[];
}

function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

function reqString(path: string, v: unknown, field: string): string {
  if (typeof v !== 'string' || v.trim() === '') {
    throw new ProhibitedVendorOverridesSchemaError(path, `${field} is required and must be a non-empty string`);
  }
  return v.trim();
}

function optStringArray(path: string, v: unknown, field: string): string[] {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v)) {
    throw new ProhibitedVendorOverridesSchemaError(path, `${field} must be an array of strings`);
  }
  return v.map((x, i) => {
    if (typeof x !== 'string') {
      throw new ProhibitedVendorOverridesSchemaError(path, `${field}[${i}] must be a string`);
    }
    return x.trim();
  }).filter(Boolean);
}

/** Validate + normalize a parsed overrides object. `path` is for error messages only. */
export function normalizeOverrides(raw: unknown, path = '(inline)'): ProhibitedVendorOverrides {
  if (raw === null || raw === undefined) {
    return { schema_version: OVERRIDES_SCHEMA_VERSION, suppressions: [], manual_additions: [], transliteration_overrides: {}, fingerprint_overrides: [] };
  }
  if (typeof raw !== 'object') {
    throw new ProhibitedVendorOverridesSchemaError(path, 'top-level document must be a mapping');
  }
  const obj = raw as Record<string, unknown>;
  const schemaVersion = typeof obj.schema_version === 'string' ? obj.schema_version : OVERRIDES_SCHEMA_VERSION;

  const suppressions: Suppression[] = asArray(obj.suppressions).map((s, i) => {
    if (s === null || typeof s !== 'object') {
      throw new ProhibitedVendorOverridesSchemaError(path, `suppressions[${i}] must be a mapping`);
    }
    const o = s as Record<string, unknown>;
    const catalog_uid = reqString(path, o.catalog_uid, `suppressions[${i}].catalog_uid`);
    const justification = reqString(path, o.justification, `suppressions[${i}].justification`);
    let expires_at: string | null = null;
    if (o.expires_at !== undefined && o.expires_at !== null) {
      const raw_expires = String(o.expires_at);
      if (Number.isNaN(Date.parse(raw_expires))) {
        throw new ProhibitedVendorOverridesSchemaError(path, `suppressions[${i}].expires_at "${raw_expires}" is not a valid date`);
      }
      expires_at = raw_expires;
    }
    const out: Suppression = { catalog_uid, justification, expires_at };
    if (typeof o.vendor === 'string') out.vendor = o.vendor.trim();
    return out;
  });

  const manual_additions: ManualAddition[] = asArray(obj.manual_additions).map((m, i) => {
    if (m === null || typeof m !== 'object') {
      throw new ProhibitedVendorOverridesSchemaError(path, `manual_additions[${i}] must be a mapping`);
    }
    const o = m as Record<string, unknown>;
    return {
      entity_name: reqString(path, o.entity_name, `manual_additions[${i}].entity_name`),
      justification: reqString(path, o.justification, `manual_additions[${i}].justification`),
      aliases: optStringArray(path, o.aliases, `manual_additions[${i}].aliases`),
      subsidiaries: optStringArray(path, o.subsidiaries, `manual_additions[${i}].subsidiaries`),
      fingerprints: optStringArray(path, o.fingerprints, `manual_additions[${i}].fingerprints`),
    };
  });

  const transliteration_overrides: Record<string, string> = {};
  if (obj.transliteration_overrides !== undefined) {
    if (obj.transliteration_overrides === null || typeof obj.transliteration_overrides !== 'object' || Array.isArray(obj.transliteration_overrides)) {
      throw new ProhibitedVendorOverridesSchemaError(path, 'transliteration_overrides must be a mapping of source -> latin');
    }
    for (const [k, v] of Object.entries(obj.transliteration_overrides as Record<string, unknown>)) {
      if (typeof v !== 'string') {
        throw new ProhibitedVendorOverridesSchemaError(path, `transliteration_overrides["${k}"] must be a string`);
      }
      transliteration_overrides[k] = v;
    }
  }

  const fingerprint_overrides: FingerprintOverride[] = asArray(obj.fingerprint_overrides).map((f, i) => {
    if (f === null || typeof f !== 'object') {
      throw new ProhibitedVendorOverridesSchemaError(path, `fingerprint_overrides[${i}] must be a mapping`);
    }
    const o = f as Record<string, unknown>;
    return {
      catalog_uid: reqString(path, o.catalog_uid, `fingerprint_overrides[${i}].catalog_uid`),
      fingerprints: optStringArray(path, o.fingerprints, `fingerprint_overrides[${i}].fingerprints`),
    };
  });

  return { schema_version: schemaVersion, suppressions, manual_additions, transliteration_overrides, fingerprint_overrides };
}

/** Build a `Map<catalog_uid, Suppression>` for O(1) suppression lookup. */
export function suppressionsByCatalogUid(overrides: ProhibitedVendorOverrides): Map<string, Suppression> {
  const map = new Map<string, Suppression>();
  for (const s of overrides.suppressions) map.set(s.catalog_uid, s);
  return map;
}

/** Load + validate the overrides from a YAML path. A missing file yields empty overrides. */
export function loadProhibitedVendorsOverrides(path?: string): ProhibitedVendorOverrides {
  if (!path || !existsSync(path)) {
    return normalizeOverrides(null);
  }
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (e) {
    throw new ProhibitedVendorOverridesSchemaError(path, `cannot read file: ${(e as Error)?.message ?? String(e)}`);
  }
  let parsed: unknown;
  try {
    parsed = parseYaml(text);
  } catch (e) {
    throw new ProhibitedVendorOverridesSchemaError(path, `not valid YAML: ${(e as Error)?.message ?? String(e)}`);
  }
  return normalizeOverrides(parsed, path);
}
