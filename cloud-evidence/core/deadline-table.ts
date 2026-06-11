/**
 * FedRAMP vulnerability-remediation deadline tables (LOOP-B.B2).
 *
 * `FEDRAMP_CMP_DEADLINES` is the FedRAMP Continuous Monitoring Strategy & Guide
 * (Rev 5) severity → calendar-days table. These are FedRAMP-published constants
 * (REO Rule 3 — FedRAMP-published constants are allowed fixed data), cited to:
 *
 *   - FedRAMP Continuous Monitoring Strategy & Guide, Rev 5, §3.3
 *     "Vulnerability Scanning":
 *     https://www.fedramp.gov/assets/resources/documents/CSP_Continuous_Monitoring_Strategy_Guide.pdf
 *   - FedRAMP Rev5 Playbook — ConMon Vulnerability Scanning:
 *     https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/vulnerability-scanning/
 *
 * Published cadence reproduced here:
 *     "High vulnerabilities — 30 days. Moderate vulnerabilities — 90 days.
 *      Low vulnerabilities — 180 days."
 * Critical vulnerabilities are handled per KEV / operational risk; the standard
 * cadence is 15 days.
 *
 * REQUIRES-OPERATOR-INPUT: the source PDF returns HTTP 403 to anonymous fetches.
 * The `critical: 15` value in particular MUST be confirmed against a manually
 * downloaded copy at docs/sources/fedramp-conmon-strategy-guide.pdf and this
 * table updated atomically with its pinning test (deadline-table.test.ts) if the
 * published cadence changes. The `--strict-risk` orchestrator mode fails the
 * build when a finding falls through to the severity-fallback table (a sign this
 * table was not loaded), so an unverified gap can never silently reach a
 * submission package.
 */
import type { Severity } from './envelope.ts';

/**
 * FedRAMP ConMon Strategy & Guide (Rev 5) severity → days. The single source of
 * truth for remediation deadlines; LOOP-A.A1's hardcoded table is retained only
 * as the observable severity-fallback below.
 */
export const FEDRAMP_CMP_DEADLINES: Record<Severity, number> = {
  critical: 15,
  high: 30,
  medium: 90,
  low: 180,
  info: 365,
};

/**
 * The original LOOP-A.A1 `REMEDIATION_DEADLINE_DAYS` values, kept ONLY as the
 * observable severity-fallback the deadline engine reports as
 * `source: 'severity-fallback'` (which `--strict-risk` rejects). Production
 * deadlines come from KEV / PAIN-IRV-LEV / FEDRAMP_CMP_DEADLINES.
 */
export const SEVERITY_FALLBACK_DEADLINES: Record<Severity, number> = {
  critical: 30,
  high: 60,
  medium: 90,
  low: 180,
  info: 365,
};
