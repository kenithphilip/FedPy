/**
 * Static cross-KSI dependency map.
 *
 * For each KSI, lists which other KSIs share remediation effort, depend on it,
 * or are blocked by it. Collectors include the relevant subset on each finding
 * so an LLM can avoid proposing conflicting plans.
 */
import type { EvidenceFile } from './envelope.ts';

export interface KsiRelation {
  ksi_id: string;
  relationship: 'shares-remediation' | 'precedes' | 'follows' | 'depends-on';
  note: string;
}

export const CROSS_KSI_MAP: Record<string, KsiRelation[]> = {
  // IAM family — these all interact heavily.
  'KSI-IAM-MFA': [
    { ksi_id: 'KSI-IAM-AAM', relationship: 'shares-remediation', note: 'Migrating users to Identity Center addresses both MFA enforcement and account-lifecycle automation.' },
    { ksi_id: 'KSI-IAM-APM', relationship: 'shares-remediation', note: 'Phishing-resistant MFA and passwordless paths are typically configured in the same IdP policy.' },
    { ksi_id: 'KSI-IAM-SNU', relationship: 'precedes', note: 'Replacing IAM users with IAM roles / workload identity for non-human consumers is a prerequisite to declaring MFA-required org-wide.' },
    { ksi_id: 'KSI-AFR-UCM', relationship: 'depends-on', note: 'WebAuthn / FIDO2 modules used for MFA must be FIPS-validated; UCM rationale should reference these.' },
  ],
  'KSI-IAM-AAM': [
    { ksi_id: 'KSI-IAM-MFA', relationship: 'shares-remediation', note: 'Identity Center + IdP federation satisfies both AAM (lifecycle) and MFA enforcement.' },
    { ksi_id: 'KSI-IAM-ELP', relationship: 'shares-remediation', note: 'Federation via permission sets is the natural moment to redefine least-privilege role design.' },
    { ksi_id: 'KSI-IAM-SNU', relationship: 'shares-remediation', note: 'Migrating standalone IAM users to roles + Workload Identity / IRSA reduces both human-IAM-user count (AAM) and long-lived credentials (SNU).' },
    { ksi_id: 'KSI-CED-RST', relationship: 'follows', note: 'After AAM is automated, the role-specific training population (privileged users) can be derived programmatically.' },
  ],
  'KSI-IAM-APM': [
    { ksi_id: 'KSI-IAM-MFA', relationship: 'shares-remediation', note: 'Passwordless + MFA fallback are typically configured together in the IdP authentication policy.' },
  ],
  'KSI-IAM-ELP': [
    { ksi_id: 'KSI-IAM-AAM', relationship: 'shares-remediation', note: 'Account lifecycle decisions drive permission-set design; least-privilege is the design goal of the lifecycle.' },
    { ksi_id: 'KSI-IAM-JIT', relationship: 'precedes', note: 'Establishing least-privilege baseline lets JIT meaningfully scope time-bound escalations.' },
    { ksi_id: 'KSI-CNA-DFP', relationship: 'shares-remediation', note: 'IAM policy hygiene (no wildcards) is the same problem at IAM-policy and SCP level.' },
  ],
  'KSI-IAM-JIT': [
    { ksi_id: 'KSI-IAM-ELP', relationship: 'depends-on', note: 'JIT is only meaningful on top of a least-privilege baseline.' },
    { ksi_id: 'KSI-IAM-SUS', relationship: 'shares-remediation', note: 'Both pair with privileged-session monitoring + auto-disable workflows.' },
  ],
  'KSI-IAM-SNU': [
    { ksi_id: 'KSI-IAM-AAM', relationship: 'shares-remediation', note: 'Replacing service IAM users with roles improves both AAM and SNU posture.' },
    { ksi_id: 'KSI-SVC-ASM', relationship: 'shares-remediation', note: 'Secret rotation + Workload Identity together eliminate long-lived credentials.' },
    { ksi_id: 'KSI-CMT-VTD', relationship: 'follows', note: 'Once CI/CD principals use OIDC federation instead of access keys, downstream pipelines can also gate on attestations.' },
  ],
  'KSI-IAM-SUS': [
    { ksi_id: 'KSI-MLA-OSM', relationship: 'depends-on', note: 'SIEM is the source of suspicious-activity findings.' },
    { ksi_id: 'KSI-INR-RIR', relationship: 'shares-remediation', note: 'Response automation maps the same alert → runbook plumbing.' },
    { ksi_id: 'KSI-IAM-JIT', relationship: 'shares-remediation', note: 'Anomalous JIT grant requests are a primary suspicious-activity signal.' },
  ],
};

/** Attach relations to a single evidence file. */
export function relatedKsisFor(ksiId: string): EvidenceFile['related_ksis'] {
  return (CROSS_KSI_MAP[ksiId] ?? []).map((r) => ({
    ksi_id: r.ksi_id,
    relationship: r.relationship,
    note: r.note,
  }));
}
