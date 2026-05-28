/**
 * SCG comparator — Secure Configuration Guide vs observed config.
 *
 * Per docs/analysis/pva-scg-ucm.md (SCG-CSO-SDF / SCG-ENH-CMP / SCG-ENH-MRG):
 * the keystone enhancement is a machine-readable Secure Configuration Guide
 * (the "RSC") that DECLARES the provider's recommended secure default settings.
 * Once that guide is machine-readable, a read-only collector can diff the
 * declared settings against the OBSERVED live config values and emit a
 * per-setting pass/fail — which simultaneously demonstrates the SCG-ENH-CMP
 * "compare current settings vs recommended defaults" capability.
 *
 * Guide format (kept deliberately simple + documented):
 *   A JSON map of setting-key → expected value, e.g.
 *     {
 *       "root.mfa_enabled": true,
 *       "root.access_keys": 0,
 *       "password.min_length": 14,
 *       "tls.policy": "ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04"
 *     }
 *   Optionally wrapped with metadata: { "version": "1.2.0", "settings": { ... } }
 *   loadScgBaseline() accepts either the bare map or the wrapped form, and can
 *   load it from a file path. Comparison is a value-equality check with light,
 *   documented coercion (numeric strings, boolean strings, deep-equal arrays).
 *
 * This module's only optional I/O is reading the guide file; the comparison
 * itself is pure. Missing guide / missing observed value degrade gracefully to
 * missing_evidence, never a crash.
 */
import { readFileSync } from 'node:fs';
import type { Finding, ImpactTier, KeyWord, AffectedResource } from './envelope.ts';
import { finding, severityForKeyWord } from './findings.ts';

/** A machine-readable Secure Configuration Guide: setting-key → expected value. */
export type ScgSettingMap = Record<string, unknown>;

/** The parsed guide baseline, with optional version metadata. */
export interface ScgBaseline {
  /** Optional semantic version of the guide (SCG-ENH-VRH). */
  version?: string;
  /** The declared setting → expected value map. */
  settings: ScgSettingMap;
  /** Where the baseline came from (for evidence). */
  source?: string;
}

export interface ScgCompareInput {
  guide: ScgBaseline;
  /** Observed live config values, keyed by the same setting keys as the guide. */
  observed: Record<string, unknown>;
}

export interface ScgSettingComparison {
  key: string;
  expected: unknown;
  /** undefined when the setting was not observed (couldn't be evaluated). */
  actual: unknown;
  /** true only when actual was observed AND equals expected (after coercion). */
  matches: boolean;
  /** true when the key had no observed value at all (distinct from a mismatch). */
  not_observed: boolean;
}

export interface ScgCompareResult {
  version?: string;
  comparisons: ScgSettingComparison[];
  counts: { total: number; matches: number; mismatches: number; not_observed: number };
}

/**
 * Load an SCG baseline from a parsed object (bare map or { version, settings }).
 * Never throws on shape; an empty/invalid object yields an empty settings map.
 */
export function parseScgBaseline(raw: unknown, source?: string): ScgBaseline {
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    const obj = raw as Record<string, unknown>;
    // Wrapped form: { settings: {...}, version?: "..." }
    if (obj.settings && typeof obj.settings === 'object' && !Array.isArray(obj.settings)) {
      return {
        version: typeof obj.version === 'string' ? obj.version : undefined,
        settings: { ...(obj.settings as ScgSettingMap) },
        source,
      };
    }
    // Bare map form.
    return { settings: { ...obj }, source };
  }
  return { settings: {}, source };
}

/**
 * Load an SCG baseline from a JSON file path. Returns a baseline with an empty
 * settings map plus a populated `source` describing the failure if the file is
 * missing/unreadable/unparseable — callers turn that into missing_evidence.
 */
export function loadScgBaseline(path: string): { baseline: ScgBaseline; error?: string } {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (e) {
    return {
      baseline: { settings: {}, source: `unreadable:${path}` },
      error: `Secure Configuration Guide not found / unreadable at "${path}": ${(e as Error)?.message ?? String(e)}`,
    };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    return {
      baseline: { settings: {}, source: `unparseable:${path}` },
      error: `Secure Configuration Guide at "${path}" is not valid JSON: ${(e as Error)?.message ?? String(e)}`,
    };
  }
  return { baseline: parseScgBaseline(parsed, path) };
}

/** Light, documented value coercion so "14" === 14 and "true" === true. */
function valuesEqual(expected: unknown, actual: unknown): boolean {
  if (expected === actual) return true;
  // Boolean / boolean-string equivalence.
  const asBool = (v: unknown): boolean | null =>
    typeof v === 'boolean' ? v : v === 'true' ? true : v === 'false' ? false : null;
  const eb = asBool(expected);
  const ab = asBool(actual);
  if (eb !== null && ab !== null) return eb === ab;
  // Numeric / numeric-string equivalence.
  const asNum = (v: unknown): number | null => {
    if (typeof v === 'number' && Number.isFinite(v)) return v;
    if (typeof v === 'string' && v.trim() !== '' && Number.isFinite(Number(v))) return Number(v);
    return null;
  };
  const en = asNum(expected);
  const an = asNum(actual);
  if (en !== null && an !== null) return en === an;
  // Deep equality for arrays/objects via stable JSON (order-sensitive for arrays).
  if (expected !== null && actual !== null && typeof expected === 'object' && typeof actual === 'object') {
    try {
      return JSON.stringify(expected) === JSON.stringify(actual);
    } catch {
      return false;
    }
  }
  return false;
}

/**
 * Diff the guide's declared settings against observed config values.
 * Pure + deterministic. A setting absent from `observed` is `not_observed`
 * (and counts as a non-match, but is reported distinctly from a value
 * mismatch so the operator can tell "missing reading" from "wrong value").
 */
export function compareScg(input: ScgCompareInput): ScgCompareResult {
  const settings = input.guide?.settings ?? {};
  const observed = input.observed ?? {};
  const comparisons: ScgSettingComparison[] = [];
  let matches = 0;
  let mismatches = 0;
  let notObserved = 0;

  for (const key of Object.keys(settings).sort()) {
    const expected = settings[key];
    const present = Object.prototype.hasOwnProperty.call(observed, key);
    const actual = present ? observed[key] : undefined;
    const not_observed = !present;
    const matched = present && valuesEqual(expected, actual);
    if (matched) matches++;
    else if (not_observed) notObserved++;
    else mismatches++;
    comparisons.push({ key, expected, actual, matches: matched, not_observed });
  }

  return {
    version: input.guide?.version,
    comparisons,
    counts: { total: comparisons.length, matches, mismatches, not_observed: notObserved },
  };
}

/** SCG-CSO-SDF is a SHOULD at all levels; High derived-pending. */
function scgKeyWord(_tier: ImpactTier): KeyWord {
  return 'SHOULD';
}

const SCG_NIST_CONTROLS = ['cm-2', 'cm-6', 'cm-6.1', 'sa-5'];

function mismatchAffected(cmps: ScgSettingComparison[]): AffectedResource[] {
  return cmps
    .filter((c) => !c.matches)
    .map((c) => ({
      type: 'fedramp_secure_config_setting',
      identifier: c.key,
      name: c.key,
      attributes: {
        expected: c.expected,
        actual: c.not_observed ? '<not observed>' : c.actual,
        status: c.not_observed ? 'not_observed' : 'mismatch',
      },
    }));
}

/**
 * Build SCG-CSO-SDF / SCG-ENH-CMP findings from a comparison result.
 *
 * Passes when every declared setting was observed AND matches. A non-empty
 * guide that produced zero observed values is treated as missing_evidence-style
 * (the comparator could not actually compare anything). An empty guide returns
 * a missing-evidence finding rather than a vacuous pass.
 */
export function buildScgFindings(result: ScgCompareResult, tier: ImpactTier): Finding[] {
  const kw = scgKeyWord(tier);
  const c = result.counts;
  const emptyGuide = c.total === 0;
  const nothingObserved = c.total > 0 && c.matches === 0 && c.mismatches === 0; // all not_observed
  const conformant = c.total > 0 && c.mismatches === 0 && c.not_observed === 0;

  const summary = emptyGuide
    ? 'No machine-readable Secure Configuration Guide supplied — nothing to compare against observed config.'
    : nothingObserved
      ? `Secure Configuration Guide declares ${c.total} setting(s) but none were observed in the live config — comparison could not be evaluated.`
      : conformant
        ? `All ${c.total} SCG-declared setting(s) match the observed live configuration${result.version ? ` (guide v${result.version})` : ''}.`
        : `${c.mismatches} setting(s) deviate from the Secure Configuration Guide and ${c.not_observed} could not be observed (of ${c.total} declared).`;

  return [
    finding({
      rule: 'scg.cso.sdf.observed_matches_guide',
      passed: conformant,
      severity: severityForKeyWord(kw, 'medium'),
      applicable_key_word: kw,
      current: {
        summary,
        observations: {
          guide_version: result.version ?? null,
          counts: c,
          comparisons: result.comparisons,
        },
      },
      target: {
        summary: 'Live configuration of top-level administrative and privileged accounts matches the provider\'s published recommended secure defaults.',
        rationale:
          'FedRAMP 20x SCG-CSO-SDF (secure defaults) + SCG-ENH-CMP (compare current vs recommended). ' +
          'A machine-readable Secure Configuration Guide (SCG-ENH-MRG) lets a read-only collector diff declared defaults against observed state. ' +
          'NIST CM-2 / CM-6 (configuration settings), SA-5. Caveat: a collector observes CURRENT state, not initial-provisioning state — IaC/landing-zone templates remain the true "at provisioning" evidence. ' +
          'High applicability is derived-rev5-pending (no controls[] to anchor).',
      },
      gap: conformant
        ? undefined
        : {
            description: emptyGuide
              ? 'No Secure Configuration Guide was loaded. Register a machine-readable SCG (JSON setting→expected map) so the collector can compare it to live config.'
              : nothingObserved
                ? 'The SCG declares settings but none were observed. Wire the observed-config source (e.g. IAM/org-policy readers) for the declared keys.'
                : `${c.mismatches} setting(s) deviate from the SCG and ${c.not_observed} were not observed.`,
            affected_resources: emptyGuide
              ? [{ type: 'fedramp_secure_config_guide', identifier: 'scg', name: 'Secure Configuration Guide', attributes: { loaded: false } }]
              : mismatchAffected(result.comparisons),
          },
      remediation: conformant
        ? undefined
        : {
            summary: emptyGuide
              ? 'Publish a machine-readable Secure Configuration Guide and register its path.'
              : 'Bring deviating settings into line with the SCG, or update the SCG if the live default is the intended one.',
            options: [
              {
                approach: emptyGuide
                  ? 'Author the SCG as a JSON setting→expected-value map (the SCG-ENH-MRG keystone) and point the collector at it.'
                  : 'Reconcile each deviating setting; treat the SCG as the source of truth for secure defaults.',
                mechanism: emptyGuide ? 'process' : 'terraform',
                owner_team: 'Security',
                steps: emptyGuide
                  ? [
                      'Enumerate the recommended secure defaults for top-level admin + privileged accounts (root MFA, no access keys, password policy, TLS policy, etc.).',
                      'Express them as a JSON map of setting-key → expected value (optionally wrapped { version, settings }).',
                      'Publish the guide (SCG-CSO-PUB) and register the file path for the comparator.',
                      'Re-run cloud-evidence to compare declared defaults against live config.',
                    ]
                  : [
                      'For each MISMATCH, change the live setting to the SCG-declared value (or amend the SCG if the live value is the correct secure default).',
                      'For each NOT-OBSERVED setting, wire the observed-config reader so the value can be evaluated.',
                      'Capture the change in IaC so the secure default is enforced at provisioning (the true SDF evidence).',
                      'Re-run cloud-evidence to confirm conformance.',
                    ],
                cost_impact: { level: 'none', notes: 'Configuration / documentation effort.' },
                availability_impact: { level: 'low', notes: 'Tightening defaults may affect existing privileged workflows — test first.' },
                customer_visible: { level: 'low', notes: 'A published SCG is customer-facing; default changes can affect tenant behavior.' },
                effort_estimate: { magnitude: 'hours', notes: 'Scales with the number of deviating settings.' },
                references: [
                  { title: 'NIST SP 800-53 CM-6', url: 'https://csf.tools/reference/nist-sp-800-53/r5/cm/cm-6/' },
                ],
              },
            ],
          },
      alternative_satisfiers: [
        {
          via: 'CSPM / posture tool (Prowler, Steampipe/Powerpipe, AWS Security Hub, GCP SCC)',
          description: 'A posture tool the customer runs can produce the same current-vs-recommended diff against a CIS/OSCAL benchmark.',
          evidence_required: ['Detected posture tool', 'Benchmark mapping the SCG defaults', 'Sample diff output'],
          detected: false,
          detection_signals: [],
        },
      ],
      nist_controls: SCG_NIST_CONTROLS,
      cross_ksi_dependencies: [
        { ksi_id: 'SCG-ENH-MRG', relationship: 'depends-on', note: 'The machine-readable SCG is what powers this comparator.' },
        { ksi_id: 'SCG-ENH-CMP', relationship: 'shares-remediation', note: 'Running this comparison demonstrates the SCG-ENH-CMP compare capability.' },
        { ksi_id: 'UCM-CSX-CAT', relationship: 'shares-remediation', note: 'Secure-default crypto settings overlap with validated-module tenant defaults.' },
      ],
      note:
        (nothingObserved
          ? 'No observed values matched any declared key — verify the observed-config keys use the same names as the guide. '
          : '') +
        'A read-only collector observes CURRENT state, not initial-provisioning state; the IaC/landing-zone template is the authoritative "secure-by-default at provisioning" evidence. ' +
        'High applicability is derived-rev5-pending.',
    }),
  ];
}
