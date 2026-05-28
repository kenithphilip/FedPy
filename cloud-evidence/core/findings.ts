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
import type { Finding, Severity } from './envelope.ts';

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
}

export function finding(input: FindingInput): Finding {
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
  };
}

// Legacy helpers (pass/fail/check/maxCount/mustBeZero/emptySet/neutralizedByAlternative)
// were removed in 2026-05 — they produced v2 Findings with stub target/current text
// and were entirely superseded by `finding()` once every collector was rebuilt to
// the rich schema. Confirmed zero callers across providers/ before removal.
