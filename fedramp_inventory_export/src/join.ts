/**
 * Join the inventory to the compliance evidence (pure, deterministic, offline).
 *
 * Three products, all derived from a LoadedRun:
 *   1. Per-asset compliance — every asset annotated with the requirement findings
 *      whose affected-resource identifier matches it (pass/fail, worst severity,
 *      the failing requirement ids). Uses FedPy's own `identifiersMatch` so the
 *      match semantics are identical to the collector's inventory cross-linker.
 *   2. Per-requirement status at Moderate — each in-scope requirement rolled up to
 *      met / not-met / partial / not-assessed / awareness, with its finding tally.
 *   3. Control benchmarks — the NIST 800-53 posture for BOTH framings the user
 *      asked for (Rev5 Moderate baseline + 20x-referenced controls at Moderate),
 *      via FedPy's own `benchmarkControls`.
 *
 * Nothing here calls a cloud API or mutates the run.
 */
import type { CloudAsset } from '../../cloud-evidence/core/inventory-workbook.ts';
import { identifiersMatch } from '../../cloud-evidence/core/inventory-workbook.ts';
import type { EvidenceFile, Severity } from '../../cloud-evidence/core/envelope.ts';
import {
  benchmarkControls,
  inScopeControls,
  type ControlBenchmark,
} from '../../cloud-evidence/core/control-benchmark.ts';
import type { LoadedRun } from './load.ts';
import { classifyRequirement, type AssessmentType } from './classify.ts';

const IMPACT_LEVEL = 'moderate' as const;

// --------------------------------------------------------------------------- #
// Severity ordering (worst-first) — matches FedPy's Severity union.
// --------------------------------------------------------------------------- #

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

function worseSeverity(a: Severity | null, b: Severity): Severity {
  if (a === null) return b;
  return SEVERITY_RANK[b] < SEVERITY_RANK[a] ? b : a;
}

// --------------------------------------------------------------------------- #
// A single finding, flattened out of the envelope with its parent context.
// --------------------------------------------------------------------------- #

export interface FlatFinding {
  requirementId: string;       // envelope ksi_id (KSI indicator or FRR id)
  requirementName: string;
  family: string | null;
  category: EvidenceFile['category'];
  scope: EvidenceFile['scope'];
  awarenessOnly: boolean;
  provider: string;
  rule: string;
  passed: boolean;
  severity: Severity;
  keyWord: string | null;
  summary: string;
  gapDescription: string;
  nistControls: string[];
  /**
   * Matchable affected-resource identifiers — real resource ARNs/ids only
   * (account-scope sentinels like "none"/"aggregate" are excluded so they don't
   * false-match a real asset). Used for the per-asset join.
   */
  affectedIdentifiers: string[];
  /**
   * Human display of the affected scope for the Findings/Gaps cell:
   * real identifiers when present, else "account-wide" for a failing finding
   * whose gap named only an account-scope sentinel, else "" (passing / no gap).
   */
  affectedDisplay: string;
  /** One-line remediation summary (from the finding's remediation block). */
  remediationSummary: string;
  /** Suggested owning team from the primary remediation option (if any). */
  ownerTeam: string;
  /** How many distinct resources the gap names (0 for account-scope / passing). */
  affectedCount: number;
}

/** Identifiers that name no specific resource — account-scope / rollup sentinels. */
const ACCOUNT_SCOPE_SENTINELS = new Set(['none', 'aggregate', 'n/a', 'na', 'all', '*', 'account']);

/** Flatten every finding across every envelope into a single stream. */
export function flattenFindings(evidence: EvidenceFile[]): FlatFinding[] {
  const out: FlatFinding[] = [];
  for (const ef of evidence) {
    const awarenessOnly = ef.awareness_only === true;
    for (const p of ef.providers ?? []) {
      for (const f of p.findings ?? []) {
        const rawIdentifiers = (f.gap?.affected_resources ?? [])
          .map((r) => r.identifier)
          .filter((id): id is string => !!id && id.trim() !== '');
        // Matchable = real resource ids (drop account-scope sentinels entirely).
        const affected = rawIdentifiers.filter((id) => !ACCOUNT_SCOPE_SENTINELS.has(id.toLowerCase()));
        // Display: real ids, else "account-wide" when a FAILING finding named only
        // a sentinel (so the cell isn't misleadingly blank), else "".
        const affectedDisplay = affected.length
          ? affected.join('; ')
          : (!f.passed && rawIdentifiers.length > 0 ? 'account-wide' : '');
        out.push({
          requirementId: ef.ksi_id,
          requirementName: ef.ksi_name ?? ef.ksi_id,
          family: ef.family ?? null,
          category: ef.category,
          scope: ef.scope,
          awarenessOnly,
          provider: p.provider,
          rule: f.rule,
          passed: f.passed,
          severity: f.severity,
          keyWord: f.applicable_key_word ?? ef.applicable_key_word ?? null,
          summary: f.current_state?.summary ?? '',
          gapDescription: f.gap?.description ?? '',
          nistControls: (f.nist_controls ?? ef.nist_controls ?? []).map((c) => c),
          affectedIdentifiers: affected,
          affectedDisplay,
          remediationSummary: f.remediation?.summary ?? '',
          ownerTeam: f.remediation?.options?.[0]?.owner_team ?? '',
          affectedCount: affected.length,
        });
      }
    }
  }
  return out;
}

// --------------------------------------------------------------------------- #
// 1. Per-asset compliance
// --------------------------------------------------------------------------- #

export type AssetComplianceStatus =
  | 'non-compliant'   // >=1 failing finding touches this asset
  | 'compliant'       // >=1 finding touches it, all passed
  | 'not-assessed';   // no automated finding names this asset

export interface AssetCompliance {
  asset: CloudAsset;
  status: AssetComplianceStatus;
  worstSeverity: Severity | null;
  passingCount: number;
  failingCount: number;
  /** Failing "requirement/rule" pairs, deduped, worst-severity first. */
  failingRules: string[];
  /** Requirement ids with a passing finding on this asset. */
  passingRequirements: string[];
  /** NIST controls implicated by this asset's failing findings. */
  failingControls: string[];
}

/**
 * Annotate every asset with the findings whose affected-resource identifier
 * matches it, then classify:
 *   - non-compliant: >=1 failing finding names it.
 *   - compliant:     no failing finding, AND it was either named by a passing
 *                    finding or appears in a scan/assessment's assessed_resource_ids
 *                    (`assessed`) — i.e. a collector actually looked at it and found
 *                    nothing wrong. This is what makes "compliant" reachable; failing
 *                    findings alone can't populate it (only failures carry
 *                    affected_resources in the envelope schema).
 *   - not-assessed:  no automated evidence names or assessed it (never assumed clean).
 *
 * `assessed` is the set from LoadedRun.assessedIdentifiers.
 */
export function joinAssetsToFindings(
  assets: CloudAsset[],
  findings: FlatFinding[],
  assessed: Set<string> = new Set(),
): AssetCompliance[] {
  const withIds = findings.filter((f) => f.affectedIdentifiers.length > 0);
  const assessedList = [...assessed];

  return assets.map((asset) => {
    let worst: Severity | null = null;
    let passing = 0;
    let failing = 0;
    const failingRulesSev: Array<{ label: string; sev: Severity }> = [];
    const passingReqs = new Set<string>();
    const failingControls = new Set<string>();

    for (const f of withIds) {
      if (!f.affectedIdentifiers.some((id) => identifiersMatch(asset.uniqueId, id))) continue;
      if (f.passed) {
        passing++;
        passingReqs.add(f.requirementId);
      } else {
        failing++;
        worst = worseSeverity(worst, f.severity);
        failingRulesSev.push({ label: `${f.requirementId}/${f.rule}`, sev: f.severity });
        for (const c of f.nistControls) failingControls.add(c.toUpperCase());
      }
    }

    const wasAssessed = passing > 0 || assessedList.some((id) => identifiersMatch(asset.uniqueId, id));
    const status: AssetComplianceStatus =
      failing > 0 ? 'non-compliant' : wasAssessed ? 'compliant' : 'not-assessed';

    // Dedupe failing rules, worst-severity first, then alphabetic for determinism.
    const seen = new Set<string>();
    const failingRules = failingRulesSev
      .sort((a, b) => SEVERITY_RANK[a.sev] - SEVERITY_RANK[b.sev] || a.label.localeCompare(b.label))
      .filter((r) => (seen.has(r.label) ? false : (seen.add(r.label), true)))
      .map((r) => r.label);

    return {
      asset,
      status,
      worstSeverity: worst,
      passingCount: passing,
      failingCount: failing,
      failingRules,
      passingRequirements: [...passingReqs].sort(),
      failingControls: [...failingControls].sort(),
    };
  });
}

/**
 * Build synthetic "account" pseudo-assets so account-scope findings (root MFA,
 * CloudTrail/Config enablement, etc.) that name the bare account id, a sentinel
 * like "aggregate", or nothing matchable still surface on the Asset Compliance
 * sheet — instead of silently living only in the Findings/Gaps sheets.
 *
 * A finding is treated as account-scope when NONE of its affected identifiers
 * matches any real inventory asset (after the per-asset join has run).
 */
export function buildAccountComplianceRows(
  accountIds: string[],
  findings: FlatFinding[],
  matchedAnyAsset: (identifier: string) => boolean,
): AssetCompliance[] {
  // Findings whose identifiers name no real asset → attribute to the account.
  const accountFindings = findings.filter((f) => {
    if (f.passed) return false;
    if (f.affectedIdentifiers.length === 0) return true; // no target at all → account-wide
    // account-wide if every identifier is a sentinel or the bare account id or unmatched
    return f.affectedIdentifiers.every(
      (id) => ACCOUNT_SCOPE_SENTINELS.has(id.toLowerCase()) || accountIds.includes(id) || !matchedAnyAsset(id),
    );
  });
  if (accountFindings.length === 0) return [];

  // Attribute a finding to a specific account when its identifier is that id;
  // otherwise fan it out to every account in the run (single-account is the norm).
  const rows: AssetCompliance[] = [];
  const accounts = accountIds.length ? accountIds : ['(account)'];
  for (const acct of accounts) {
    const relevant = accountFindings.filter(
      (f) => f.affectedIdentifiers.length === 0 ||
        f.affectedIdentifiers.some((id) => ACCOUNT_SCOPE_SENTINELS.has(id.toLowerCase()) || id === acct || !matchedAnyAsset(id)),
    );
    if (relevant.length === 0) continue;
    let worst: Severity | null = null;
    const failingControls = new Set<string>();
    const seen = new Set<string>();
    const failingRulesSev: Array<{ label: string; sev: Severity }> = [];
    for (const f of relevant) {
      worst = worseSeverity(worst, f.severity);
      failingRulesSev.push({ label: `${f.requirementId}/${f.rule}`, sev: f.severity });
      for (const c of f.nistControls) failingControls.add(c.toUpperCase());
    }
    const failingRules = failingRulesSev
      .sort((a, b) => SEVERITY_RANK[a.sev] - SEVERITY_RANK[b.sev] || a.label.localeCompare(b.label))
      .filter((r) => (seen.has(r.label) ? false : (seen.add(r.label), true)))
      .map((r) => r.label);
    rows.push({
      asset: {
        provider: 'aws',
        uniqueId: `account:${acct}`,
        accountId: acct,
        resourceType: 'Account',
        assetType: 'AWS Account (account-level controls)',
        function: `Account ${acct}`,
      },
      status: 'non-compliant',
      worstSeverity: worst,
      passingCount: 0,
      failingCount: relevant.length,
      failingRules,
      passingRequirements: [],
      failingControls: [...failingControls].sort(),
    });
  }
  return rows;
}

// --------------------------------------------------------------------------- #
// 2. Per-requirement status (at Moderate)
// --------------------------------------------------------------------------- #

export type RequirementStatus =
  | 'met'            // has findings, all passed
  | 'not-met'        // has findings, all failed
  | 'partially-met'  // mixed
  | 'not-assessed'   // no findings emitted
  | 'awareness';     // obligates FedRAMP / agency / 3PAO, not the provider

export interface RequirementRollup {
  requirementId: string;
  requirementName: string;
  family: string | null;
  category: EvidenceFile['category'];
  scope: EvidenceFile['scope'];
  keyWord: string | null;
  status: RequirementStatus;
  passingFindings: number;
  failingFindings: number;
  nistControls: string[];
  /** One-line human summary drawn from the requirement's findings. */
  note: string;
  /** How this requirement is evidenced (automated / hybrid / documentation / external). */
  assessmentType: AssessmentType;
  /** Human label for the assessment type. */
  assessmentLabel: string;
  /** Explanation of how it is (or must be) evidenced. */
  assessmentBasis: string;
  /** Named artifact/action the provider owes for the manual portion ('' if none). */
  artifactOwed: string;
  /** Statement text of the requirement (from the envelope). */
  statement: string;
}

/** Roll every evidence envelope up to a single per-requirement status. */
export function rollupRequirements(evidence: EvidenceFile[]): RequirementRollup[] {
  const rollups: RequirementRollup[] = [];
  for (const ef of evidence) {
    const findings = (ef.providers ?? []).flatMap((p) => p.findings ?? []);
    const passing = findings.filter((f) => f.passed).length;
    const failing = findings.length - passing;
    const awareness = ef.awareness_only === true;

    let status: RequirementStatus;
    if (awareness) status = 'awareness';
    else if (findings.length === 0) status = 'not-assessed';
    else if (failing === 0) status = 'met';
    else if (passing === 0) status = 'not-met';
    else status = 'partially-met';

    const controls = new Set<string>();
    for (const c of ef.nist_controls ?? []) controls.add(c.toUpperCase());
    for (const f of findings) for (const c of f.nist_controls ?? []) controls.add(c.toUpperCase());

    const cls = classifyRequirement({
      ksi_id: ef.ksi_id,
      family: ef.family ?? null,
      scope: ef.scope,
      awareness_only: ef.awareness_only,
      actor_scope: ef.actor_scope ?? null,
    });

    rollups.push({
      requirementId: ef.ksi_id,
      requirementName: ef.ksi_name ?? ef.ksi_id,
      family: ef.family ?? null,
      category: ef.category,
      scope: ef.scope,
      keyWord: ef.applicable_key_word ?? null,
      status,
      passingFindings: passing,
      failingFindings: failing,
      nistControls: [...controls].sort(),
      note: ef.rollup?.pass
        ? `All ${passing} finding(s) passed`
        : failing > 0
          ? `${failing} failing / ${passing} passing finding(s)`
          : awareness
            ? 'Awareness-only (not the provider to satisfy)'
            : 'No automated evidence produced',
      assessmentType: cls.assessmentType,
      assessmentLabel: cls.label,
      assessmentBasis: cls.basis,
      artifactOwed: cls.artifactOwed,
      statement: ef.ksi_statement ?? '',
    });
  }
  return rollups.sort((a, b) => a.requirementId.localeCompare(b.requirementId));
}

// --------------------------------------------------------------------------- #
// 3. Control benchmarks (both framings, at Moderate)
// --------------------------------------------------------------------------- #

export interface Benchmarks {
  rev5: ControlBenchmark;
  twentyX: ControlBenchmark;
}

/**
 * Build the NIST 800-53 control benchmark for BOTH framings the user asked for,
 * at Moderate. Reuses FedPy's `inScopeControls` + `benchmarkControls` verbatim so
 * the scoring is identical to what the collector's own control-benchmark.json
 * would show.
 */
export function buildBenchmarks(evidence: EvidenceFile[]): Benchmarks {
  const rev5InScope = inScopeControls('rev5', IMPACT_LEVEL, evidence);
  const twentyXInScope = inScopeControls('20x', IMPACT_LEVEL, evidence);
  return {
    rev5: benchmarkControls(evidence, rev5InScope, 'rev5', IMPACT_LEVEL),
    twentyX: benchmarkControls(evidence, twentyXInScope, '20x', IMPACT_LEVEL),
  };
}

// --------------------------------------------------------------------------- #
// Top-level assembly
// --------------------------------------------------------------------------- #

export interface JoinResult {
  assetCompliance: AssetCompliance[];
  requirements: RequirementRollup[];
  findings: FlatFinding[];
  benchmarks: Benchmarks;
  summary: ComplianceSummary;
  serviceAvailability: LoadedRun['serviceAvailability'];
}

export interface ComplianceSummary {
  impactLevel: 'moderate';
  assetCount: number;
  assetsNonCompliant: number;
  assetsCompliant: number;
  assetsNotAssessed: number;
  requirementsTotal: number;
  requirementsMet: number;
  requirementsNotMet: number;
  requirementsPartial: number;
  requirementsNotAssessed: number;
  requirementsAwareness: number;
  findingsTotal: number;
  findingsFailing: number;
  rev5: BenchmarkHeadline;
  twentyX: BenchmarkHeadline;
}

export interface BenchmarkHeadline {
  inScope: number;
  satisfied: number;
  partiallySatisfied: number;
  notSatisfied: number;
  notAssessed: number;
  assessedPassRate: number;
  baselineCoverageRate: number;
}

function headline(b: ControlBenchmark): BenchmarkHeadline {
  return {
    inScope: b.totals.in_scope,
    satisfied: b.totals.satisfied,
    partiallySatisfied: b.totals.partially_satisfied,
    notSatisfied: b.totals.not_satisfied,
    notAssessed: b.totals.not_assessed,
    assessedPassRate: b.totals.assessed_pass_rate,
    baselineCoverageRate: b.totals.baseline_coverage_rate,
  };
}

/** Run the full join over a loaded run. */
export function joinRun(run: LoadedRun): JoinResult {
  const findings = flattenFindings(run.evidence);
  const realAssetCompliance = joinAssetsToFindings(run.assets, findings, run.assessedIdentifiers);

  // Account-level findings that matched no real asset → synthetic account rows,
  // so account-wide gaps (root MFA, Config, CloudTrail) appear on Asset Compliance.
  const matchedAnyAsset = (identifier: string): boolean =>
    run.assets.some((a) => identifiersMatch(a.uniqueId, identifier));
  const accountRows = buildAccountComplianceRows(run.accountIds, findings, matchedAnyAsset);
  const assetCompliance = [...accountRows, ...realAssetCompliance];

  const requirements = rollupRequirements(run.evidence);
  const benchmarks = buildBenchmarks(run.evidence);

  const summary: ComplianceSummary = {
    impactLevel: IMPACT_LEVEL,
    assetCount: assetCompliance.length,
    assetsNonCompliant: assetCompliance.filter((a) => a.status === 'non-compliant').length,
    assetsCompliant: assetCompliance.filter((a) => a.status === 'compliant').length,
    assetsNotAssessed: assetCompliance.filter((a) => a.status === 'not-assessed').length,
    requirementsTotal: requirements.length,
    requirementsMet: requirements.filter((r) => r.status === 'met').length,
    requirementsNotMet: requirements.filter((r) => r.status === 'not-met').length,
    requirementsPartial: requirements.filter((r) => r.status === 'partially-met').length,
    requirementsNotAssessed: requirements.filter((r) => r.status === 'not-assessed').length,
    requirementsAwareness: requirements.filter((r) => r.status === 'awareness').length,
    findingsTotal: findings.length,
    findingsFailing: findings.filter((f) => !f.passed).length,
    rev5: headline(benchmarks.rev5),
    twentyX: headline(benchmarks.twentyX),
  };

  return { assetCompliance, requirements, findings, benchmarks, summary, serviceAvailability: run.serviceAvailability };
}
