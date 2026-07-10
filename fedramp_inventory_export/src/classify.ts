/**
 * KSI / requirement assessment-type classification (pure, offline).
 *
 * FedRAMP 20x KSIs are not uniform: some are fully provable from read-only cloud
 * config, some are part-config / part-process, and some are pure governance that
 * no cloud API can observe. Showing a documentation obligation as a plain
 * "not-met" misleads a reader into treating it as a misconfiguration. This module
 * classifies every requirement into one honest assessment type so the workbook can
 * say WHAT KIND of evidence closes it — and, for the manual ones, exactly which
 * artifact the provider owes.
 *
 * The classification is derived, not hardcoded per KSI: it keys off the evidence
 * envelope's `scope` (CLOUD / HYBRID / PROCESS — set by the collector from the FRMR
 * catalog) plus `awareness_only` and the `actor_scope`. The small `ARTIFACT_HINTS`
 * table is the one place we map a process/hybrid KSI family to the named FedRAMP
 * artifact that satisfies it — those names come straight from the FRMR KSI names
 * (e.g. "Secure Configuration Guide"), not invented here.
 */
import type { EvidenceFile } from '../../cloud-evidence/core/envelope.ts';

/**
 * How a requirement's compliance can be evidenced:
 *   - automated:     fully provable from read-only cloud configuration (CLOUD scope).
 *                    Status reflects live config exactly as collected.
 *   - hybrid:        config plumbing IS checked, but full satisfaction also needs a
 *                    documented / reviewed process (HYBRID scope). The cloud half is
 *                    real evidence; the review half is a manual obligation.
 *   - documentation: pure governance / process — not cloud-observable (PROCESS scope,
 *                    obligates the Provider). Closed by a document or tracker record.
 *   - external:      obligates FedRAMP, an Agency, or a 3PAO — not the provider
 *                    (awareness_only / actor_scope not the CSP). Informational.
 */
export type AssessmentType = 'automated' | 'hybrid' | 'documentation' | 'external';

export interface Classification {
  assessmentType: AssessmentType;
  /** Short human label for a status cell. */
  label: string;
  /** One-line explanation of how this requirement is (or must be) evidenced. */
  basis: string;
  /**
   * For hybrid/documentation/external: the specific artifact or action the provider
   * (or external party) owes to close the manual portion. '' for pure automated.
   */
  artifactOwed: string;
}

/**
 * Named FedRAMP artifacts / evidence that satisfy the manual portion of a KSI,
 * keyed by KSI id (exact) or family prefix (fallback). Values are the artifacts a
 * 3PAO expects to see; the names track the FRMR KSI names + FedRAMP process docs.
 */
const ARTIFACT_HINTS: Record<string, string> = {
  // AFR — Authorization by FedRAMP (process KSIs name their own artifact).
  'KSI-AFR-ADS': 'Authorization Data Sharing configuration (repository access granted to FedRAMP)',
  'KSI-AFR-CCM': 'Collaborative Continuous Monitoring participation record',
  'KSI-AFR-FSI': 'FedRAMP Security Inbox monitored + documented (staffed contact + response SLA)',
  'KSI-AFR-ICP': 'Incident Communications Procedures document',
  'KSI-AFR-MAS': 'Minimum Assessment Scope definition',
  'KSI-AFR-SCG': 'Secure Configuration Guide (customer-facing secure-by-default guidance)',
  'KSI-AFR-SCN': 'Significant Change Notification process + templates',
  'KSI-AFR-UCM': 'Cryptographic module selection record (CMVP certificate references)',
  'KSI-AFR-VDR': 'Vulnerability Detection & Response methodology document',
  // CED — Cybersecurity Education (training review records).
  'KSI-CED-DET': 'Development & engineering security-training review record',
  'KSI-CED-RGT': 'General security-awareness training review record',
  'KSI-CED-RRT': 'Response & recovery training review record',
  'KSI-CED-RST': 'Role-specific training review record',
  // CSX — Customer Systems / MAS applicability.
  'KSI-CSX-MAS': 'Statement of applicability within the Minimum Assessment Scope',
  'KSI-CSX-ORD': 'AFR order-of-criticality determination',
  // PIY — Policy & Inventory (leadership / SDLC governance reviews).
  'KSI-PIY-RES': 'Executive-support review record (leadership sign-off)',
  'KSI-PIY-RIS': 'Security-investment review record',
  'KSI-PIY-RSD': 'Secure-SDLC review record',
  'KSI-PIY-RVD': 'Vulnerability-disclosure program review record',
  // Hybrid KSIs — the review / operate portion that config cannot prove.
  'KSI-CMT-RVP': 'Change-management procedure review record',
  'KSI-CMT-VTD': 'Deployment validation procedure (test + scan gates documented)',
  'KSI-IAM-JIT': 'Just-in-time access model documentation',
  'KSI-IAM-SUS': 'Suspicious-activity auto-response runbook',
  'KSI-INR-AAR': 'Incident after-action report + lessons-learned log',
  'KSI-INR-RIR': 'Incident-response procedure review record',
  'KSI-INR-RPI': 'Past-incident pattern review record',
  'KSI-MLA-LET': 'Logged-event-types list (resources + event types to audit)',
  'KSI-MLA-OSM': 'SIEM operating procedure + coverage documentation',
  'KSI-RPL-ABO': 'Backup-to-recovery-objective alignment review record',
  'KSI-RPL-ARP': 'Recovery-plan alignment review record',
  'KSI-RPL-RRO': 'RTO / RPO definition + review record',
  'KSI-RPL-TRC': 'Recovery-capability test record (restore test evidence)',
  'KSI-SCR-MIT': 'Supply-chain risk mitigation review record',
  'KSI-SCR-MON': 'Third-party upstream-vulnerability monitoring record',
  'KSI-SVC-EIS': 'Security-improvement evaluation record',
  'KSI-SVC-PRR': 'Residual-risk review record',
  'KSI-SVC-VCM': 'Communications-validation documentation (service-to-service auth)',
};

/** Family-level fallback when a specific KSI has no explicit hint. */
const FAMILY_HINT: Record<string, string> = {
  AFR: 'FedRAMP authorization process artifact',
  CED: 'Training program review record',
  PIY: 'Governance review record',
  CSX: 'Applicability determination',
};

function artifactFor(id: string, family: string | null): string {
  if (ARTIFACT_HINTS[id]) return ARTIFACT_HINTS[id];
  const fam = (id.split('-')[1] ?? family ?? '').toUpperCase();
  return FAMILY_HINT[fam] ?? 'Documented procedure or review record';
}

/**
 * Classify one evidence envelope into its assessment type + the artifact owed.
 * `scope` and `awareness_only` come from the collector (FRMR-derived), so this
 * mirrors the authoritative catalog, not a guess.
 */
export function classifyRequirement(ef: {
  ksi_id: string;
  family?: string | null;
  scope?: EvidenceFile['scope'];
  awareness_only?: boolean;
  actor_scope?: string | null;
}): Classification {
  const id = ef.ksi_id;
  const family = ef.family ?? null;
  const scope = ef.scope;
  const awareness = ef.awareness_only === true;
  const actor = (ef.actor_scope ?? '').toLowerCase();

  // External: the obligation falls on FedRAMP / an agency / a 3PAO, not the CSP.
  if (awareness || (actor && actor !== 'provider' && actor !== 'csp')) {
    return {
      assessmentType: 'external',
      label: 'External / Awareness',
      basis: 'Obligates FedRAMP, an agency, or the assessor — not the provider to satisfy.',
      artifactOwed: artifactFor(id, family),
    };
  }

  // Pure automated: cloud config proves it end-to-end.
  if (scope === 'CLOUD') {
    return {
      assessmentType: 'automated',
      label: 'Automated (Cloud Config)',
      basis: 'Fully evidenced from read-only cloud configuration; status reflects live config.',
      artifactOwed: '',
    };
  }

  // Hybrid: config plumbing checked here, review/operate portion is manual.
  if (scope === 'HYBRID') {
    return {
      assessmentType: 'hybrid',
      label: 'Hybrid (Config + Process)',
      basis: 'Cloud plumbing is verified automatically; full satisfaction also needs a documented/reviewed process.',
      artifactOwed: artifactFor(id, family),
    };
  }

  // Everything else (PROCESS scope) is a documentation / governance obligation.
  return {
    assessmentType: 'documentation',
    label: 'Documentation Required',
    basis: 'Governance / process control — not observable from any cloud API. Closed by a documented artifact.',
    artifactOwed: artifactFor(id, family),
  };
}
