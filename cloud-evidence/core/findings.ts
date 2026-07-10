/**
 * Helpers to construct rich Finding objects.
 *
 * Schema v2: each Finding carries current_state, target_state, gap,
 * remediation, alternative_satisfiers, nist_controls, references.
 *
 * These helpers exist to keep collector code legible — they don't hide any
 * required fields. A collector still has to spell out remediation options
 * and alternative satisfiers explicitly, because the script has the
 * authoritative knowledge of what it observed.
 */
import type { Finding, Severity, KeyWord } from './envelope.ts';

export interface FindingInput {
  rule: string;
  passed: boolean;
  severity: Severity;

  current: { summary: string; observations: unknown };
  target: { summary: string; rationale: string };

  gap?: NonNullable<Finding['gap']>;
  remediation?: NonNullable<Finding['remediation']>;
  alternative_satisfiers?: NonNullable<Finding['alternative_satisfiers']>;
  nist_controls?: string[];
  references?: NonNullable<Finding['references']>;
  cross_ksi_dependencies?: NonNullable<Finding['cross_ksi_dependencies']>;
  compliance_blockers?: string[];
  note?: string;
  /** Obligation strength at the run's impact tier (MUST/SHOULD/MAY). */
  applicable_key_word?: KeyWord;
  /**
   * Pre-computed composite risk score (LOOP-B.B1). Collectors that natively
   * know CVSS (e.g. vdr-scan.ts) may attach it at construction time; otherwise
   * the risk-score emitter attaches it post-collection.
   */
  risk_score?: NonNullable<Finding['risk_score']>;
}

export function finding(input: FindingInput): Finding {
  // Enforce the "remediation-grade failing finding" invariant AT CONSTRUCTION,
  // not just via the ajv if/then at emit time (which is warn-only by default).
  // A failing finding a 3PAO reads must always say WHAT is wrong (gap +
  // ≥1 affected resource) and HOW to fix it (≥1 remediation option). Throwing
  // here fails the collector fast rather than shipping a thin finding.
  if (input.passed === false) {
    const affectedCount = input.gap?.affected_resources?.length ?? 0;
    const optionCount = input.remediation?.options?.length ?? 0;
    if (!input.gap || affectedCount === 0 || !input.remediation || optionCount === 0) {
      throw new Error(
        `finding("${input.rule}"): a failing finding must carry gap.affected_resources (>=1) ` +
        `and remediation.options (>=1). Got affected_resources=${affectedCount}, ` +
        `remediation.options=${optionCount}. Populate the real resources/remediation, ` +
        `or if the check could not be evaluated, name the indeterminate subject explicitly.`,
      );
    }
  }
  return {
    rule: input.rule,
    passed: input.passed,
    severity: input.severity,
    current_state: input.current,
    target_state: input.target,
    gap: input.passed ? undefined : input.gap,
    remediation: input.passed ? undefined : input.remediation,
    alternative_satisfiers: input.alternative_satisfiers,
    nist_controls: input.nist_controls,
    references: input.references,
    cross_ksi_dependencies: input.cross_ksi_dependencies,
    compliance_blockers: input.compliance_blockers,
    note: input.note,
    applicable_key_word: input.applicable_key_word,
    risk_score: input.risk_score,
  };
}

/**
 * Map an obligation key word to the severity a FAILING finding should carry.
 * A missing MUST is high; a missing SHOULD is medium; a missing MAY is low/info.
 */
export function severityForKeyWord(kw: KeyWord | null | undefined, base: Severity = 'high'): Severity {
  if (kw === 'SHOULD') return 'medium';
  if (kw === 'MAY') return 'low';
  return base; // MUST or unknown
}

// Legacy helpers (pass/fail/check/maxCount/mustBeZero/emptySet/neutralizedByAlternative)
// were removed in 2026-05 — they produced v2 Findings with stub target/current text
// and were entirely superseded by `finding()` once every collector was rebuilt to
// the rich schema. Confirmed zero callers across providers/ before removal.
