/**
 * Coverage check: verify a run produced the evidence we expected.
 *
 * The orchestrator can complete "successfully" while silently missing entire
 * accounts, regions, or KSIs — e.g. an expired AWS profile, a misconfigured
 * GCP impersonation, a collector returning zero findings because the wrong
 * region was queried. Coverage check exists to catch those failure modes
 * BEFORE the evidence reaches Paramify / the assessor.
 *
 * Checks performed (each emits a warning, never aborts):
 *   1. Expected AWS account is not present in any evidence file.
 *   2. Expected GCP project(s) are missing.
 *   3. KSIs in the supported set that produced no evidence file at all.
 *   4. KSIs that produced an evidence file with zero findings (collector ran
 *      but failed silently or every provider block was empty).
 *   5. Expected regions (from config.aws.regions) are absent from every
 *      evidence file's region_set.
 *   6. Collector-level warnings count exceeds a configurable threshold —
 *      lots of warnings hints at a permissions or quota issue.
 *
 * The returned `CoverageResult` is also persisted to disk as
 * `coverage-report.json` so it can be diffed run-over-run.
 */
import { writeFileSync, readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { EvidenceFile } from './envelope.ts';
import { listEvidenceFiles } from './evidence-files.ts';

/** Non-evidence JSON outputs — mirrors evidence-files.ts so we don't flag them as corrupt. */
const NON_EVIDENCE = new Set([
  'pva-run-summary.json', 'manifest.json', 'manifest.tst.json', 'coverage-report.json',
  'family-rollup.json', 'vdr-report.json', 'crosswalk-report.json', 'diff-report.json',
  'anomaly-report.json', 'sbom-report.json', 'llm-prs.json', 'control-benchmark.json',
  'assessment-results.json', 'previous-run-snapshot.json', 'inventory.json',
  'inventory-oscal.json', 'inventory-cmdb.json', 'inventory-diff.json', 'inventory-cost.json',
  'inventory-coverage.json', 'risk-scores.json',
]);

/**
 * Find `.json` files that look like requirement envelopes by name but fail to
 * parse — a corrupt/partial write is a coverage gap, not something to skip
 * silently. Returns the offending file names.
 */
function findCorruptEvidenceFiles(outDir: string): string[] {
  const corrupt: string[] = [];
  let names: string[] = [];
  try { names = readdirSync(outDir); } catch { return corrupt; }
  for (const name of names) {
    if (!name.endsWith('.json') || NON_EVIDENCE.has(name) || name.endsWith('-input.json')) continue;
    if (name.endsWith('.generated.json')) continue;
    try { JSON.parse(readFileSync(join(outDir, name), 'utf8')); } catch { corrupt.push(name); }
  }
  return corrupt;
}

export interface CoverageResult {
  expected_aws_account: string | null;
  expected_gcp_projects: string[];
  expected_regions: string[];
  expected_ksis: string[];
  actual_aws_accounts: string[];
  actual_gcp_projects: string[];
  actual_regions: string[];
  actual_ksis: string[];
  missing_aws: boolean;
  missing_gcp_projects: string[];
  missing_regions: string[];
  missing_ksis: string[];
  ksis_with_zero_findings: string[];
  ksis_with_no_evidence: string[];
  ksis_with_excess_warnings: Array<{ ksi: string; warnings: number }>;
  /**
   * Requirements that ROLLED UP TO PASS while a provider block also logged an
   * access-denied / permission / throttle warning — the "false-pass smell". A
   * pass built on top of a call we couldn't actually make is not trustworthy.
   */
  ksis_passing_despite_access_errors: Array<{ ksi: string; warnings: string[] }>;
  total_evidence_files: number;
  total_findings: number;
  total_collector_warnings: number;
  warnings: string[];
}

export interface CheckCoverageOptions {
  awsAccount: string | null;
  gcpProjects: string[];
  /** Configured regions; we'll warn if a region is in this list but absent from every evidence file's region_set. */
  regions?: string[];
  /** The full set of KSIs the orchestrator attempted to run (so we can detect missing files). */
  expectedKsis?: string[];
  /** Threshold for "this collector had too many warnings — investigate." Default 5. */
  warningThresholdPerKsi?: number;
  /** Where to persist coverage-report.json. Defaults to outDir/coverage-report.json. */
  reportPath?: string;
}

/** Warning text that signals we could NOT read something (not a real "clean"). */
const ACCESS_ERROR_RE = /access\s*denied|not\s*authorized|unauthorized|forbidden|throttl|rate\s*exceeded|could not|unable to|indeterminate|explicit deny|expired|credential/i;

export function checkCoverage(
  outDir: string,
  expected: CheckCoverageOptions,
): CoverageResult {
  const seenAwsAccounts = new Set<string>();
  const seenGcpProjects = new Set<string>();
  const seenRegions = new Set<string>();
  const seenKsis = new Set<string>();
  const ksisWithZeroFindings: string[] = [];
  const ksisWithExcessWarnings: Array<{ ksi: string; warnings: number }> = [];
  const ksisPassingDespiteAccessErrors: Array<{ ksi: string; warnings: string[] }> = [];
  let totalFiles = 0;
  let totalFindings = 0;
  let totalWarnings = 0;
  const warnings: string[] = [];
  const warningThreshold = expected.warningThresholdPerKsi ?? 5;

  // Corrupt/partial envelope files are a coverage gap — surface them explicitly
  // (the shape-based lister silently skips unparseable files).
  const corruptFiles = findCorruptEvidenceFiles(outDir);
  for (const f of corruptFiles) {
    warnings.push(`Could not parse evidence file ${f} (corrupt or partial write).`);
  }
  totalFiles += corruptFiles.length; // counted, though their content is unusable

  // Shape-based selection covers KSI *and* FRR requirement files (not just KSI-*).
  for (const data of listEvidenceFiles(outDir)) {
    totalFiles++;
    seenKsis.add(data.ksi_id);
    let ksiFindings = 0;
    let ksiWarnings = 0;
    const accessErrorWarnings: string[] = [];
    for (const p of data.providers) {
      if (p.provider === 'aws' && p.account_id) seenAwsAccounts.add(p.account_id);
      if (p.provider === 'gcp' && p.project_id) seenGcpProjects.add(p.project_id);
      for (const r of p.region_set ?? []) seenRegions.add(r);
      ksiFindings += p.findings.length;
      ksiWarnings += (p.warnings ?? []).length;
      for (const w of p.warnings ?? []) if (ACCESS_ERROR_RE.test(w)) accessErrorWarnings.push(w);
    }
    totalFindings += ksiFindings;
    totalWarnings += ksiWarnings;
    if (ksiFindings === 0) ksisWithZeroFindings.push(data.ksi_id);
    if (ksiWarnings >= warningThreshold) {
      ksisWithExcessWarnings.push({ ksi: data.ksi_id, warnings: ksiWarnings });
    }
    // False-pass smell: the requirement rolled up to PASS, but a provider logged
    // an access/throttle error — so the "pass" may rest on data we couldn't read.
    // (With the collector gating fix such a case now usually FAILs; this catches
    // any remaining or newly-introduced instance.)
    if (data.rollup?.pass === true && accessErrorWarnings.length > 0 && data.awareness_only !== true) {
      ksisPassingDespiteAccessErrors.push({ ksi: data.ksi_id, warnings: [...new Set(accessErrorWarnings)].slice(0, 5) });
    }
  }

  // 1 / 2: account / project missing
  const missingAws = !!expected.awsAccount && !seenAwsAccounts.has(expected.awsAccount);
  const missingGcpProjects = expected.gcpProjects.filter((p) => !seenGcpProjects.has(p));
  if (missingAws) {
    warnings.push(`Expected AWS account ${expected.awsAccount} but no evidence file references it. Possible silent auth failure.`);
  }
  for (const p of missingGcpProjects) {
    warnings.push(`Expected GCP project ${p} but no evidence file references it. Possible silent auth/impersonation failure.`);
  }

  // 3: KSIs we expected but never produced
  const expectedKsis = expected.expectedKsis ?? [];
  const missingKsis = expectedKsis.filter((k) => !seenKsis.has(k));
  for (const k of missingKsis) {
    warnings.push(`Expected KSI ${k} to be collected but no evidence file was emitted.`);
  }

  // 4: KSIs with zero findings (file exists, findings = 0)
  for (const k of ksisWithZeroFindings) {
    warnings.push(`${k}: collector produced 0 findings — possible empty provider block or silent SDK error.`);
  }

  // 5: regions
  const expectedRegions = expected.regions ?? [];
  const missingRegions = expectedRegions.filter((r) => !seenRegions.has(r));
  for (const r of missingRegions) {
    warnings.push(`Expected region ${r} but no evidence file recorded it in any provider's region_set.`);
  }

  // 6: excess warnings
  for (const { ksi, warnings: w } of ksisWithExcessWarnings) {
    warnings.push(`${ksi}: ${w} collector warnings (threshold ${warningThreshold}). Likely missing IAM permissions or service unavailable in this region.`);
  }

  // 7: passing-despite-access-errors (false-pass smell)
  for (const { ksi } of ksisPassingDespiteAccessErrors) {
    warnings.push(`${ksi}: rolled up to PASS but a collector logged an access/throttle error — the pass may rest on data that could not be read. Verify IAM permissions and re-run.`);
  }

  const result: CoverageResult = {
    expected_aws_account: expected.awsAccount,
    expected_gcp_projects: expected.gcpProjects,
    expected_regions: expectedRegions,
    expected_ksis: expectedKsis,
    actual_aws_accounts: Array.from(seenAwsAccounts).sort(),
    actual_gcp_projects: Array.from(seenGcpProjects).sort(),
    actual_regions: Array.from(seenRegions).sort(),
    actual_ksis: Array.from(seenKsis).sort(),
    missing_aws: missingAws,
    missing_gcp_projects: missingGcpProjects,
    missing_regions: missingRegions,
    missing_ksis: missingKsis,
    ksis_with_zero_findings: ksisWithZeroFindings,
    ksis_with_no_evidence: missingKsis, // alias for consumer clarity
    ksis_with_excess_warnings: ksisWithExcessWarnings,
    ksis_passing_despite_access_errors: ksisPassingDespiteAccessErrors,
    total_evidence_files: totalFiles,
    total_findings: totalFindings,
    total_collector_warnings: totalWarnings,
    warnings,
  };

  // Persist for run-over-run diff
  const reportPath = expected.reportPath ?? resolve(outDir, 'coverage-report.json');
  writeFileSync(reportPath, JSON.stringify(result, null, 2));

  return result;
}
