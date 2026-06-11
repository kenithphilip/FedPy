/**
 * Output JSON envelope shared by every per-KSI evidence file.
 *
 * Schema v2: rich evidence designed for two consumers —
 *   1. Security engineers / SRE remediating gaps.
 *   2. AI/LLM agents generating implementation plans and gap analyses.
 *
 * Each finding carries: full current-state observations, target-state +
 * rationale, gap details with IaC-friendly affected-resource records,
 * concrete remediation options (Terraform/CloudFormation/console/CLI),
 * and alternative-satisfaction detection (e.g. external IdP, 3rd-party
 * SOAR) so the consumer can recognize when the KSI is met outside the
 * cloud-native primitives.
 */
import type { RiskScore } from './risk-score.ts';

export type ProviderName = 'aws' | 'gcp' | 'azure' | 'k8s';
export type KsiScope = 'CLOUD' | 'HYBRID' | 'PROCESS' | 'INHERITED';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ImpactLevel = 'none' | 'low' | 'medium' | 'high';

/**
 * FedRAMP 20x impact tier selected at run time. Distinct from `ImpactLevel`
 * (which grades cost/availability/customer-visible impact of a remediation).
 *   - low / moderate come straight from the 20x machine-readable data.
 *   - high is DERIVED from the NIST SP 800-53 Rev5 High baseline (never published
 *     as 20x machine-readable) and is always labeled as such.
 */
export type ImpactTier = 'low' | 'moderate' | 'high';
/** FedRAMP requirement obligation strength (RFC 2119 style). */
export type KeyWord = 'MUST' | 'SHOULD' | 'MAY';
/** Who the requirement actually obligates. The CSP (provider) can only satisfy `provider` items. */
export type ActorScope = 'provider' | 'fedramp' | 'agency' | '3pao' | 'unknown';
/** Provenance of a level's applicability decision. */
export type LevelSource = '20x-machine-readable' | 'derived-rev5' | 'derived-rev5-pending' | 'not-applicable';
export type EffortMagnitude = 'minutes' | 'hours' | 'days' | 'weeks' | 'months';
export type OwnerTeam =
  | 'Security'
  | 'SRE'
  | 'Platform'
  | 'Identity / IT'
  | 'Compliance'
  | 'Engineering'
  | 'Product'
  | 'Legal';

export interface RawEvidence {
  /** Logical source identifier, e.g. "iam.GetAccountSummary". */
  source: string;
  /** ISO timestamp at the moment the SDK call returned. */
  captured_at: string;
  /** The raw (or lightly normalized) data returned by the SDK call. */
  data: unknown;
}

/** An affected resource expressed in IaC-friendly terms. */
export interface AffectedResource {
  /** IaC-style type, e.g. "aws_iam_user", "google_compute_firewall". */
  type: string;
  /** Stable identifier: ARN / GCP relative name / etc. */
  identifier: string;
  /** Friendly display name (may equal identifier). */
  name?: string;
  /** Current attribute values worth showing the consumer. */
  attributes?: Record<string, unknown>;
  /** Any tags / labels on the resource. */
  tags?: Record<string, string>;
}

export interface RemediationOption {
  /** Short headline of the approach, e.g. "Apply an SCP denying actions w/o recent MFA". */
  approach: string;
  /** How the change is delivered. */
  mechanism: 'terraform' | 'cloudformation' | 'console' | 'cli' | 'process' | 'external-tool';
  /** Ordered step list a human can follow. */
  steps: string[];
  /** Ready-to-paste code snippet (Terraform HCL, CFN YAML, gcloud / aws CLI). */
  example_code?: string;
  /** Things that may break or behave differently after this change. */
  side_effects?: string[];
  /** What must already be true before applying this change. */
  prerequisites?: string[];
  /** Doc / runbook URLs to consult. */
  references?: Array<{ title: string; url: string }>;

  /** Rough $ impact (license fees, increased usage, etc.). */
  cost_impact?: { level: ImpactLevel; notes: string };
  /** Risk this change introduces downtime, latency, or service disruption. */
  availability_impact?: { level: ImpactLevel; notes: string };
  /** Whether agency customers / Trust Center consumers will see / feel this change. */
  customer_visible?: { level: ImpactLevel; notes: string };
  /** Coarse estimate of how long the change will take to apply (incl. testing). */
  effort_estimate?: { magnitude: EffortMagnitude; notes: string };
  /** Which team typically owns this remediation. */
  owner_team?: OwnerTeam;
}

export interface AlternativeSatisfier {
  /** Short label, e.g. "Okta with WebAuthn enforcement". */
  via: string;
  /** Why this counts as satisfying the KSI. */
  description: string;
  /** What artifacts/exports the user would need to attach if this is their path. */
  evidence_required: string[];
  /** Did the script see signals this alternative is actually in use? */
  detected: boolean;
  /** What concrete signals informed `detected` (or its absence). */
  detection_signals?: string[];
}

export interface Finding {
  /** Stable rule name, e.g. "aws.iam.root_mfa_enabled". */
  rule: string;
  /** Boolean outcome. */
  passed: boolean;
  /** Severity tag — drives threshold rollup behaviour. */
  severity: Severity;

  current_state: {
    /** One-line human summary of what was observed. */
    summary: string;
    /** Full structured data. NOT just a count — include the records an LLM/engineer needs to act. */
    observations: unknown;
  };

  target_state: {
    /** One-line description of the desired state. */
    summary: string;
    /** Why this matters — tied to FedRAMP intent or NIST control. */
    rationale: string;
  };

  /** Populated only when passed=false. */
  gap?: {
    description: string;
    affected_resources: AffectedResource[];
  };

  /** Concrete options for closing the gap. */
  remediation?: {
    summary: string;
    options: RemediationOption[];
  };

  /** Alternative ways this KSI may be satisfied outside cloud-native primitives. */
  alternative_satisfiers?: AlternativeSatisfier[];

  /** NIST 800-53 control IDs this finding traces to. */
  nist_controls?: string[];

  /**
   * Relevant doc URLs. A reference may also carry a CVE id and/or a FIRST CVSS
   * vector string so the LOOP-B.B1 risk scorer can derive a real CVSS base
   * score + EPSS lookup from collector-cited evidence.
   */
  references?: Array<{ title: string; url: string; cve_id?: string; cvss_vector?: string }>;

  /** Other KSIs whose gaps overlap with this one (so an LLM won't propose duplicate or conflicting plans). */
  cross_ksi_dependencies?: Array<{
    ksi_id: string;
    relationship: 'shares-remediation' | 'precedes' | 'follows' | 'conflicts-with' | 'depends-on';
    note: string;
  }>;

  /** Prerequisites that may not exist in the environment and prevent remediation. */
  compliance_blockers?: string[];

  /** Free-form note from the collector (e.g. "skipped because PAM not enabled"). */
  note?: string;

  /**
   * The obligation strength that applies at the run's impact tier (MUST/SHOULD/MAY).
   * Set when a requirement's `varies_by_level` changes the key word per tier
   * (e.g. UCM-CSX-UVM: Low MAY / Moderate SHOULD / High MUST). A failing SHOULD/MAY
   * is reported at reduced severity vs a failing MUST.
   */
  applicable_key_word?: KeyWord;

  /**
   * Per-finding composite risk score (LOOP-B.B1). Attached by the risk-score
   * emitter (core/risk-score-emit.ts) after collection; combines CVSS + EPSS +
   * inventory-derived criticality + exposure. Backward compatible — absent on
   * envelopes produced before B.B1 or when --risk-score is not enabled.
   */
  risk_score?: RiskScore;
  /**
   * VDR-pipeline per-finding signals (LOOP-B.B2 deadline acceleration). Emitted
   * by the VDR collector when a finding carries a vulnerability the VDR ledger
   * evaluated. Backward compatible — absent on non-VDR findings.
   *   - irv: Internet-Reachable Verdict (security-group / NACL / route-table analysis).
   *   - lev: Likely-Exploitable Verdict (EPSS percentile ≥ 0.95 OR KEV membership).
   *   - pain: Possible Adverse Impact Number (operator-supplied, 1-5).
   */
  irv?: boolean;
  lev?: boolean;
  pain?: number;
}

/** A 3rd-party tool / vendor recognized by signatures in IAM, audit log, or org config. */
export interface ThirdPartyToolMatch {
  /** Canonical product name (e.g. "Okta", "Teleport", "Datadog"). */
  name: string;
  /** Category (IdP, JIT, SOAR, SIEM, observability, GRC, supply-chain, dev-platform, etc.). */
  category: string;
  /** Whether the script saw a direct signature, or inferred via heuristics. */
  confidence: 'direct' | 'inferred';
  /** What was matched. */
  detection_signals: string[];
  /** Which KSIs this tool may help satisfy (cross-cutting). */
  satisfies_ksis: string[];
}

export interface ProviderBlock {
  provider: ProviderName;
  account_id?: string | null;
  project_id?: string | null;
  region_set?: string[];
  evidence: RawEvidence[];
  findings: Finding[];
  warnings?: string[];
  /**
   * KSI-level alternative satisfiers (independent of any specific finding).
   * Useful when the entire KSI may be met externally (e.g. all of IAM-MFA
   * via Okta).
   */
  ksi_level_alternatives?: AlternativeSatisfier[];
  /** 3rd-party tools recognized in this provider's environment. */
  third_party_tools_detected?: ThirdPartyToolMatch[];
}

export interface Rollup {
  pass: boolean;
  passing_findings: number;
  failing_findings: number;
  warnings: string[];
  missing_evidence: string[];
  /** How many findings were neutralized by a detected alternative_satisfier. */
  alternatives_in_play: number;
}

export interface EvidenceFile {
  ksi_id: string;
  ksi_name: string;
  ksi_statement: string;       // verbatim FRMR statement, embedded for LLM consumption
  scope: KsiScope;
  frmr_version: string;
  run_id: string;
  collected_at: string;
  providers: ProviderBlock[];
  rollup: Rollup;
  /** Process artifacts the human reviewer must still attach (HYBRID only). */
  process_artifacts_required?: string[];
  /** NIST controls mapped to this KSI as a whole. */
  nist_controls?: string[];
  /** KSIs that share remediation effort or share dependencies with this one. */
  related_ksis?: Array<{
    ksi_id: string;
    relationship: 'shares-remediation' | 'precedes' | 'follows' | 'depends-on';
    note: string;
  }>;
  /** Natural-language one-paragraph summary for LLM consumption (built by orchestrator). */
  summary_for_llm?: string;

  // ── Impact-tier / requirement-taxonomy metadata (added for full-level coverage) ──
  /** Which FedRAMP requirement category this file represents. */
  category?: 'ksi-indicator' | 'frr-requirement';
  /** FRMR family (e.g. IAM, VDR, CCM). */
  family?: string;
  /** The impact tier this run was evaluated at. */
  impact_level?: ImpactTier;
  /** Obligation strength at this tier (from varies_by_level when present). */
  applicable_key_word?: KeyWord;
  /** How the requirement's applicability at this tier was decided. */
  level_source?: LevelSource;
  /**
   * Who the requirement obligates. Requirements that obligate FedRAMP / an agency /
   * a 3PAO (not the provider) are emitted as awareness items and excluded from the
   * provider's own pass/fail rollup.
   */
  actor_scope?: ActorScope;
  /** True when this requirement is tracked for awareness only (not the provider's to satisfy). */
  awareness_only?: boolean;
}

export function nowIso(): string {
  return new Date().toISOString();
}

export function makeRollup(providers: ProviderBlock[]): Rollup {
  let pass = 0;
  let fail = 0;
  let alts = 0;
  const warnings: string[] = [];
  for (const p of providers) {
    for (const f of p.findings) {
      if (f.passed) pass++;
      else fail++;
    }
    if (p.warnings) warnings.push(...p.warnings.map((w) => `${p.provider}: ${w}`));
    alts += (p.ksi_level_alternatives ?? []).filter((a) => a.detected).length;
    for (const f of p.findings) {
      alts += (f.alternative_satisfiers ?? []).filter((a) => a.detected).length;
    }
  }
  return {
    pass: fail === 0,
    passing_findings: pass,
    failing_findings: fail,
    warnings,
    missing_evidence: [],
    alternatives_in_play: alts,
  };
}
