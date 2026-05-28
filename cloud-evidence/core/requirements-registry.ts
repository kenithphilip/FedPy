/**
 * Runtime registry of EVERY FedRAMP 20x requirement (KSI indicators + FRR
 * requirements), loaded from the committed `docs/frmr-requirements.generated.json`
 * (produced by `scripts/extract-frmr-requirements.mjs` against the FedRAMP docs repo).
 *
 * This is the single source of truth the orchestrator uses to decide, for a
 * chosen impact tier, WHICH requirements are in scope and at what obligation
 * strength (MUST/SHOULD/MAY) — and which are awareness-only (obligate FedRAMP /
 * an agency / a 3PAO rather than the provider).
 *
 * Level model:
 *   - low / moderate applicability + key word come straight from the 20x data.
 *   - high is DERIVED from the NIST SP 800-53 Rev5 High baseline via controls[];
 *     when a requirement has no controls[] to anchor, High is `derived-rev5-pending`
 *     and we DO NOT assert an obligation (it is reported as not-applicable-at-high).
 */
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ImpactTier, KeyWord, ActorScope, LevelSource } from './envelope.ts';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEFAULT_REGISTRY = resolve(__dirname, '..', 'docs', 'frmr-requirements.generated.json');

export interface LevelApplicability {
  applies: boolean | null;
  statement: string | null;
  key_word: KeyWord | string | null;
  source: string | null;
}

export interface RequirementEntry {
  id: string;
  category: 'ksi-indicator' | 'frr-requirement';
  family: string;
  family_name: string;
  name: string;
  statement: string | null;
  key_word: string | null;
  track: string;
  actor?: string | null;
  affects: string[];
  controls: string[];
  terms: string[];
  fka: string | string[] | null;
  reference?: string | null;
  reference_url?: string | null;
  levels: Record<ImpactTier, LevelApplicability>;
  covered?: boolean;
}

let _cache: RequirementEntry[] | null = null;

/** Load (and cache) the requirement registry. Throws an actionable error if absent. */
export function loadRequirements(path = process.env.FRMR_REGISTRY_PATH ?? DEFAULT_REGISTRY): RequirementEntry[] {
  if (_cache) return _cache;
  if (!existsSync(path)) {
    throw new Error(
      `Requirement registry not found at ${path}. Regenerate it with ` +
        `\`node scripts/extract-frmr-requirements.mjs\` (needs a clone of github.com/FedRAMP/docs), ` +
        `or set FRMR_REGISTRY_PATH.`,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'));
  } catch (e: any) {
    throw new Error(`Requirement registry ${path} is not valid JSON: ${e?.message ?? e}`);
  }
  if (!Array.isArray(parsed)) {
    throw new Error(`Requirement registry ${path} did not parse to an array.`);
  }
  _cache = parsed as RequirementEntry[];
  return _cache;
}

/** Reset the cache (tests). */
export function _resetRegistryCache(): void {
  _cache = null;
}

/**
 * Classify who a requirement obligates. The CSP (provider) can only *satisfy*
 * `provider` items; everything else is awareness-only.
 *
 * Primary signal is the FedRAMP `affects` array; the actor segment of the id
 * (e.g. ADS-CSO-PUB, VDR-AGM-MAP) is a fallback heuristic.
 */
export function actorScopeOf(req: RequirementEntry): ActorScope {
  const affects = (req.affects ?? []).map((a) => String(a).toLowerCase());
  if (affects.some((a) => a.includes('provider'))) return 'provider';
  if (affects.some((a) => a.includes('fedramp'))) return 'fedramp';
  if (affects.some((a) => a.includes('agenc'))) return 'agency';
  if (affects.some((a) => a.includes('assessor') || a.includes('3pao') || a.includes('third'))) return '3pao';
  // Fallback: actor code in the id.
  const actor = (req.actor ?? req.id.split('-')[1] ?? '').toUpperCase();
  if (actor === 'FRP') return 'fedramp';
  if (actor === 'AGM') return 'agency';
  if (actor === 'TPX' || actor === 'TRC') return '3pao';
  if (['CSO', 'CSX', 'CSL', 'OAR', 'QTR', 'RPT', 'TFR', 'BST', 'EVA', 'ENH', 'ADP', 'RTR', 'TRF', 'UTC', 'AUR', 'FIR', 'HRM', 'ICU', 'IRA', 'IRC', 'IRF', 'RPT', 'RSD'].includes(actor)) {
    return 'provider';
  }
  // KSI indicators always obligate the provider.
  if (req.category === 'ksi-indicator') return 'provider';
  return 'unknown';
}

export interface ResolvedApplicability {
  applies: boolean;
  key_word: KeyWord | null;
  statement: string;
  source: LevelSource;
}

/**
 * Resolve whether (and how) a requirement applies at a given impact tier.
 *
 * For low/moderate this is straight from the data. For high:
 *   - if the data publishes an explicit high statement → use it;
 *   - else if the requirement has controls[] → derived-rev5 (applies, derived);
 *   - else → derived-rev5-pending and NOT applied (no obligation to assert).
 */
export function appliesAtLevel(req: RequirementEntry, tier: ImpactTier): ResolvedApplicability {
  const lvl = req.levels?.[tier];
  const baseStatement = req.statement ?? lvl?.statement ?? '';
  const kw = normalizeKeyWord(lvl?.key_word ?? req.key_word);

  if (tier !== 'high') {
    return {
      applies: lvl?.applies === true,
      key_word: kw,
      statement: lvl?.statement ?? baseStatement,
      source: '20x-machine-readable',
    };
  }

  // High tier.
  if (lvl?.applies === true && lvl?.source === '20x-machine-readable') {
    // Explicitly published high statement (rare, e.g. UCM-CSX-UVM).
    return { applies: true, key_word: kw, statement: lvl.statement ?? baseStatement, source: '20x-machine-readable' };
  }
  if ((req.controls?.length ?? 0) > 0) {
    return { applies: true, key_word: kw, statement: baseStatement, source: 'derived-rev5' };
  }
  // No Rev5 anchor — do not fabricate an obligation.
  return { applies: false, key_word: null, statement: baseStatement, source: 'derived-rev5-pending' };
}

function normalizeKeyWord(v: unknown): KeyWord | null {
  const s = String(v ?? '').toUpperCase();
  return s === 'MUST' || s === 'SHOULD' || s === 'MAY' ? (s as KeyWord) : null;
}

export interface RequirementSelection {
  /** Requirements the provider must satisfy at this tier (in scope, provider-actor). */
  inScope: RequirementEntry[];
  /** In-scope-at-tier but obligating FedRAMP / agency / 3PAO — tracked for awareness only. */
  awareness: RequirementEntry[];
  /** Not applicable at this tier (e.g. high with no Rev5 anchor, or level says no). */
  notApplicable: RequirementEntry[];
}

/**
 * Partition the full requirement set for a chosen impact tier.
 */
export function selectForLevel(tier: ImpactTier, opts: { registryPath?: string } = {}): RequirementSelection {
  const all = loadRequirements(opts.registryPath);
  const inScope: RequirementEntry[] = [];
  const awareness: RequirementEntry[] = [];
  const notApplicable: RequirementEntry[] = [];
  for (const req of all) {
    const ap = appliesAtLevel(req, tier);
    if (!ap.applies) {
      notApplicable.push(req);
      continue;
    }
    if (actorScopeOf(req) === 'provider') inScope.push(req);
    else awareness.push(req);
  }
  return { inScope, awareness, notApplicable };
}

/** Convenience: look up one requirement by id. */
export function getRequirement(id: string, registryPath?: string): RequirementEntry | undefined {
  return loadRequirements(registryPath).find((r) => r.id === id);
}
