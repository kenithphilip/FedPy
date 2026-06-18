/**
 * Typed loader for `section889-agency-closures.yaml` (LOOP-W.W3).
 *
 * One-off federal agency-closure days proclaimed by the President under
 * 5 U.S.C. §6103(c) that are NOT in OPM's standing 11-holiday list (e.g. an
 * Inauguration-Day closure, or a day-of-mourning proclamation). These extend
 * the federal-business-day clock's exclusion set beyond weekends + the
 * computed §6103 holidays. Per REO Rule 4 the operator supplies them; the
 * system invents none.
 *
 * Returns a `Set<string>` of `YYYY-MM-DD` closure dates ready to hand to
 * `core/section889-clock.ts` as `extraClosures`.
 */
import { readFileSync, existsSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';

export class Section889ClosuresError extends Error {
  readonly field: string;
  constructor(field: string, message: string) {
    super(message);
    this.name = 'Section889ClosuresError';
    this.field = field;
  }
}

export interface Section889Closure {
  date: string; // YYYY-MM-DD
  reason: string;
  appliesToFederalBusinessHours: boolean;
}

export interface Section889Closures {
  schemaVersion: string;
  closures: Section889Closure[];
}

const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

function asString(v: unknown): string | null {
  if (typeof v !== 'string') return null;
  const t = v.trim();
  return t === '' ? null : t;
}

/**
 * Build the typed closures from a parsed YAML object. Closure lists are
 * collected from every `closures_*` key (e.g. `closures_2026`, `closures_2027`)
 * as well as a flat `closures:` list, so a single file can carry several years.
 */
export function normalizeSection889Closures(raw: unknown): Section889Closures {
  const obj = (raw && typeof raw === 'object' ? raw : {}) as Record<string, any>;
  const out: Section889Closure[] = [];
  const lists: any[] = [];
  if (Array.isArray(obj.closures)) lists.push(obj.closures);
  for (const key of Object.keys(obj)) {
    if (/^closures_\d{4}$/.test(key) && Array.isArray(obj[key])) lists.push(obj[key]);
  }
  for (const list of lists) {
    for (const row of list) {
      const date = asString(row?.date);
      if (!date || !ISO_DATE_RE.test(date)) {
        throw new Section889ClosuresError('closures[].date', `Each agency closure needs a valid YYYY-MM-DD date; got "${row?.date}".`);
      }
      const reason = asString(row?.reason);
      if (!reason) {
        throw new Section889ClosuresError('closures[].reason', `Agency closure on ${date} is missing a reason (required for the audit trail).`);
      }
      out.push({
        date,
        reason,
        appliesToFederalBusinessHours: row?.applies_to_federal_business_hours !== false,
      });
    }
  }
  return { schemaVersion: asString(obj.schema_version) ?? '1.0.0', closures: out };
}

/** Load closures from a YAML path. A missing file yields an empty set (no closures). */
export function loadSection889Closures(path?: string): Section889Closures {
  if (!path || !existsSync(path)) return { schemaVersion: '1.0.0', closures: [] };
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (e) {
    throw new Section889ClosuresError('(file)', `Cannot read section889-agency-closures.yaml at ${path}: ${(e as Error)?.message ?? String(e)}`);
  }
  let parsed: unknown;
  try {
    parsed = parseYaml(text);
  } catch (e) {
    throw new Section889ClosuresError('(yaml)', `section889-agency-closures.yaml at ${path} is not valid YAML: ${(e as Error)?.message ?? String(e)}`);
  }
  return normalizeSection889Closures(parsed);
}

/** The set of `YYYY-MM-DD` dates that count as closures for the clock. */
export function closureDateSet(closures: Section889Closures): Set<string> {
  return new Set(closures.closures.filter((c) => c.appliesToFederalBusinessHours).map((c) => c.date));
}
