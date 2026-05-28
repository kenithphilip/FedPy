/**
 * Per-requirement playbooks for the process-artifact tracker.
 *
 * ~99 of the FedRAMP 20x requirements (plus the hybrid/awareness governance
 * items) cannot be proven by a read-only cloud API call. For those, the
 * process-artifact tracker (`core/process-artifact-tracker.ts`) emits a signed,
 * schema-valid PROCESS-scope evidence file from a tracked ARTIFACT + ATTESTATION.
 *
 * This module supplies the SPECIFIC, FedRAMP-aligned guidance the tracker
 * attaches to each such requirement, in place of the generic fallback text:
 *
 *   - `artifacts_required`  — the concrete artifact a reviewer attaches.
 *   - `remediation_steps`   — practical, FedRAMP-satisfying steps.
 *   - `alternative_satisfiers` — the real vendor/process alternatives (Vanta,
 *     Drata, Paramify, KnowBe4, HackerOne/Bugcrowd, ServiceNow/Jira, PagerDuty/
 *     Opsgenie, Wiz, etc.). `detected: false` here — runtime detection
 *     (`core/detect/third-party-tools.ts`) flips it via `detection_signals`.
 *   - `sla`                 — businessDays / calendarDays / cadence for the
 *     deadline- or cadence-bearing requirements (SCN notification windows, VDR
 *     remediation timeframes, CCM/PVA cadences, ICP/FSI reaction times).
 *   - `nist_controls`       — the requirement's NIST 800-53 controls (or the
 *     conceptual family mapping when controls[] is empty in the registry).
 *   - `references`          — FedRAMP / CISA / statute doc URLs where known.
 *
 * Data-only module: no I/O, no cloud SDK calls, no network. Mined from
 * `docs/analysis/*.md`.
 */
import type { RequirementPlaybook } from './process-artifact-tracker.ts';
import type { AlternativeSatisfier } from './envelope.ts';

// ── Reference URLs ──────────────────────────────────────────────────────────
const REF = {
  ads: { title: 'FedRAMP 20x — Authorization Data Sharing (ADS)', url: 'https://www.fedramp.gov/20x/' },
  ccm: { title: 'FedRAMP 20x — Collaborative Continuous Monitoring (CCM)', url: 'https://www.fedramp.gov/20x/' },
  scn: { title: 'FedRAMP 20x — Significant Change Notifications (SCN)', url: 'https://www.fedramp.gov/20x/' },
  vdr: { title: 'FedRAMP 20x — Vulnerability Detection and Response (VDR)', url: 'https://www.fedramp.gov/20x/' },
  fsi: { title: 'FedRAMP — FedRAMP Security Inbox (FSI)', url: 'https://www.fedramp.gov/20x/' },
  icp: { title: 'FedRAMP — Incident Communications Procedures (ICP)', url: 'https://www.fedramp.gov/20x/' },
  pva: { title: 'FedRAMP 20x — Persistent Validation and Assessment (PVA)', url: 'https://www.fedramp.gov/20x/' },
  scg: { title: 'FedRAMP 20x — Secure Configuration Guide (SCG)', url: 'https://www.fedramp.gov/20x/' },
  ucm: { title: 'FedRAMP 20x — Using Cryptographic Modules (UCM)', url: 'https://www.fedramp.gov/20x/' },
  mas: { title: 'FedRAMP 20x — Minimum Assessment Scope (MAS)', url: 'https://www.fedramp.gov/20x/' },
  ced: { title: 'FedRAMP 20x — Key Security Indicators (KSI)', url: 'https://www.fedramp.gov/20x/' },
  afr: { title: 'FedRAMP 20x — Applicable FedRAMP Requirements (AFR)', url: 'https://www.fedramp.gov/20x/' },
  cmvp: { title: 'NIST CMVP — Validated Modules Search', url: 'https://csrc.nist.gov/projects/cryptographic-module-validation-program' },
  kev: { title: 'CISA Known Exploited Vulnerabilities Catalog', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' },
  bod2201: { title: 'CISA BOD 22-01', url: 'https://www.cisa.gov/news-events/directives/bod-22-01-reducing-significant-risk-known-exploited-vulnerabilities' },
  cisaIrf: { title: 'CISA Incident Reporting System', url: 'https://www.cisa.gov/report' },
  cisaGuidelines: { title: 'CISA Federal Incident Notification Guidelines', url: 'https://www.cisa.gov/federal-incident-notification-guidelines' },
} as const;

// ── Alternative-satisfier factories (vendor catalogs, detected:false) ───────
function grcAlt(extra?: string): AlternativeSatisfier {
  return {
    via: 'Continuous-compliance / GRC platform (Vanta, Drata, Secureframe, Paramify)',
    description: `A GRC platform can own this obligation and produce the artifact + attestation history on cadence.${extra ? ' ' + extra : ''}`,
    evidence_required: ['Platform tenant + the control/test mapped to this requirement', 'Export showing the obligation is met on the required cadence'],
    detected: false,
    detection_signals: ['vanta', 'drata', 'secureframe', 'paramify', 'grc'],
  };
}
function trustCenterAlt(): AlternativeSatisfier {
  return {
    via: 'FedRAMP-compatible Trust Center (Paramify, SafeBase, Vanta Trust Center)',
    description: 'A Trust Center serves as the definitive source for authorization data and can render/publish the required artifact to all necessary parties.',
    evidence_required: ['Configured Trust Center URL', 'Export/screenshot showing the published artifact + access controls'],
    detected: false,
    detection_signals: ['safebase', 'paramify', 'vanta trust center', 'trust.', 'trustcenter'],
  };
}
function ticketingAlt(extra?: string): AlternativeSatisfier {
  return {
    via: 'ITSM / change-management platform (ServiceNow, Jira)',
    description: `A ticketing/change-management system records the activity with timestamps, owners, and SLA timers as the audit ledger.${extra ? ' ' + extra : ''}`,
    evidence_required: ['Read-only export of the relevant project/table covering the period', 'Records showing the required field(s) / SLA outcome'],
    detected: false,
    detection_signals: ['servicenow', 'jira', 'atlassian'],
  };
}
function pagerDutyAlt(extra?: string): AlternativeSatisfier {
  return {
    via: 'Incident on-call / escalation platform (PagerDuty, Opsgenie)',
    description: `Escalation policies route urgent FedRAMP/security communications to the security on-call and produce timestamped notification records.${extra ? ' ' + extra : ''}`,
    evidence_required: ['Escalation policy export referencing the FedRAMP notification SLAs', 'Notification/timeline log for the relevant event'],
    detected: false,
    detection_signals: ['pagerduty', 'opsgenie'],
  };
}
function soarAlt(extra?: string): AlternativeSatisfier {
  return {
    via: 'SOAR / automation platform (Tines, Torq, Swimlane, ServiceNow Flow)',
    description: `A SOAR playbook can automate the notification/report and emit a confirmation record.${extra ? ' ' + extra : ''}`,
    evidence_required: ['Playbook export showing the automated action', 'Delivery/confirmation record for the relevant event'],
    detected: false,
    detection_signals: ['tines', 'torq', 'swimlane'],
  };
}
function scannerAlt(extra?: string): AlternativeSatisfier {
  return {
    via: 'CNAPP / vulnerability scanner (Wiz, Prisma Cloud, Orca, Lacework, Tenable, Qualys, Snyk)',
    description: `An enterprise scanner performs the detection/evaluation and exposes the required SLA dashboards and finding metadata.${extra ? ' ' + extra : ''}`,
    evidence_required: ['Scanner tenant + coverage/config export', 'Finding/SLA export covering this requirement'],
    detected: false,
    detection_signals: ['wiz', 'prisma', 'orca', 'lacework', 'tenable', 'qualys', 'snyk'],
  };
}
function bugBountyAlt(): AlternativeSatisfier {
  return {
    via: 'Vulnerability disclosure / bug-bounty program (HackerOne, Bugcrowd, security.txt)',
    description: 'A managed VDP/bug-bounty program is a recognized vulnerability-detection source; its dashboard documents inbound reports and resolution.',
    evidence_required: ['Program URL / security.txt', 'Program activity export (reports received, triaged, resolved) for the period'],
    detected: false,
    detection_signals: ['hackerone', 'bugcrowd', 'security.txt'],
  };
}
function knowBe4Alt(): AlternativeSatisfier {
  return {
    via: 'Security-awareness / training platform (KnowBe4, Proofpoint, Secure Code Warrior, internal LMS)',
    description: 'A training platform measures completion AND effectiveness (e.g. KnowBe4 phish-prone %), which is the literal effectiveness signal this KSI requires.',
    evidence_required: ['Platform completion + effectiveness report (e.g. phish-prone %) for the review period', 'Roster reconciliation against the IdP/HRIS to prove coverage'],
    detected: false,
    detection_signals: ['knowbe4', 'proofpoint', 'secure code warrior', 'pluralsight', 'hoxhunt'],
  };
}
function cmvpAlt(): AlternativeSatisfier {
  return {
    via: 'CMVP-validated module / HSM / subprocessor inheritance (CloudHSM, Thales, HashiCorp Vault FIPS, AWS-LC FIPS)',
    description: 'Cryptographic protection is provided by a module with an active CMVP validation, or inherited from a subprocessor whose modules are CMVP-validated.',
    evidence_required: ['CMVP certificate number(s) for the module(s) in use', 'Mapping of services to modules; subprocessor crypto attestation if inherited'],
    detected: false,
    detection_signals: ['cloudhsm', 'vault', 'fips', 'cmvp'],
  };
}
function mailGatewayAlt(): AlternativeSatisfier {
  return {
    via: 'Mail-security gateway (Proofpoint, Mimecast, Google Workspace, M365)',
    description: 'A mail gateway with @fedramp.gov / @gsa.gov explicitly allowlisted (safe-sender) ensures FedRAMP email is received without disruption or spam-filtering.',
    evidence_required: ['Exported safe-sender / allowlist policy covering the two FedRAMP domains', 'SPF/DKIM/DMARC posture for inbound from those domains'],
    detected: false,
    detection_signals: ['proofpoint', 'mimecast', 'google workspace', 'microsoft 365'],
  };
}
function none(): AlternativeSatisfier[] {
  return [];
}

// Common SLA cadence helpers.
const QUARTERLY = { calendarDays: 92, cadence: 'every 3 months (quarterly)' };
const MONTHLY = { calendarDays: 31, cadence: 'at least monthly' };

/**
 * The playbook catalog. Keyed by requirement id.
 */
export const REQUIREMENT_PLAYBOOKS: Record<string, RequirementPlaybook> = {
  // ════════════════════════════════════════════════════════════════════════
  // ADS — Authorization Data Sharing
  // ════════════════════════════════════════════════════════════════════════
  'ADS-CSL-LRE': {
    artifacts_required: ['Record asserting (or declining) the Rev5-High legacy-repository exception, with the CSO authorization basis'],
    remediation_steps: [
      'Confirm the CSO is Rev5-Authorized at FedRAMP High and still uses a legacy self-managed authorization-data repository.',
      'If electing the exception, document the election and its rationale in the authorization data.',
      'Otherwise, proceed with the full ADS process (Trust Center / USDA Connect).',
    ],
    alternative_satisfiers: none(),
    nist_controls: [],
    references: [REF.ads],
  },
  'ADS-CSL-TCM': {
    artifacts_required: ['Trust Center migration notice to all necessary parties (FedRAMP + agency customers)', 'USDA Connect secure-folder instructions explaining how to use the new Trust Center'],
    remediation_steps: [
      'Stand up the FedRAMP-compatible Trust Center as the definitive authorization-data source.',
      'Notify all necessary parties (always FedRAMP + every agency customer) of the migration.',
      'Place use-the-Trust-Center instructions in the existing USDA Connect Community Portal secure folders.',
      'Record the notification recipients + dates in the attestation register.',
    ],
    alternative_satisfiers: [trustCenterAlt()],
    nist_controls: [],
    references: [REF.ads],
  },
  'ADS-CSL-UCP': {
    artifacts_required: ['Evidence that authorization data is shared via USDA Connect Community Portal, OR a configured FedRAMP-compatible Trust Center URL'],
    remediation_steps: [
      'Choose the sharing surface: USDA Connect Community Portal, or a FedRAMP-compatible Trust Center.',
      'Publish current authorization data to the chosen surface.',
      'Record the surface URL and the date it went live.',
    ],
    alternative_satisfiers: [trustCenterAlt()],
    nist_controls: [],
    references: [REF.ads],
  },
  'ADS-CSL-UTC': {
    artifacts_required: ['Documented decision to use a FedRAMP-compatible Trust Center (or the USDA Connect fallback) to store/share authorization data'],
    remediation_steps: [
      'Select a FedRAMP-compatible Trust Center for authorization-data sharing.',
      'Publish the authorization package to it for all necessary parties.',
      'Record the choice; note this is the Rev5 SHOULD twin of the 20x MUST (ADS-CSX-UTC).',
    ],
    alternative_satisfiers: [trustCenterAlt()],
    nist_controls: [],
    references: [REF.ads],
  },
  'ADS-CSO-CBF': {
    artifacts_required: ['Description of the automation that keeps human-readable and machine-readable authorization data consistent (single-source generation pipeline)'],
    remediation_steps: [
      'Single-source the authorization data and generate both HR and MR formats from it via automation.',
      'Document the generation pipeline and how it prevents drift between formats.',
      'Attach a sample showing the two formats agree.',
    ],
    alternative_satisfiers: [grcAlt('Paramify/SafeBase single-source both formats from one model.')],
    nist_controls: [],
    references: [REF.ads],
  },
  'ADS-CSO-HAD': {
    artifacts_required: ['Historical authorization-data store covering 3 years, available to all necessary parties (quarterly delta consolidation allowed)'],
    remediation_steps: [
      'Retain historical versions of authorization data for three years (unless FedRAMP directs otherwise).',
      'Expose the history to all necessary parties via the Trust Center / sharing surface.',
      'Optionally consolidate deltas quarterly; record the retention policy.',
    ],
    alternative_satisfiers: [trustCenterAlt()],
    nist_controls: [],
    references: [REF.ads],
  },
  'ADS-CSO-PUB': {
    artifacts_required: ['Public CSO info page (HR + MR) with Marketplace link, service/deployment/business models, UEI, contacts, service description, service list, customer-responsibility summary, Trust Center access process + status, and next OAR date'],
    remediation_steps: [
      'Assemble the required public fields (Marketplace link, models, UEI, contacts, descriptions, service list, responsibility summary, Trust Center process/status, next OAR date).',
      'Publish in both human-readable and machine-readable formats.',
      'Record the public URL and verify all required fields are present.',
    ],
    alternative_satisfiers: [trustCenterAlt()],
    nist_controls: [],
    references: [REF.ads],
  },
  'ADS-CSO-RIS': {
    artifacts_required: ['Sensitivity-review sign-off confirming authorization data supports decisions without disclosing info that would likely aid an adversary'],
    remediation_steps: [
      'Define a pre-publication sensitivity/disclosure review checklist.',
      'Have an accountable reviewer sign off before each publication.',
      'Record the reviewer + date in the register.',
    ],
    alternative_satisfiers: [grcAlt('GRC tool with a redaction/review gate.')],
    nist_controls: [],
    references: [REF.ads],
  },
  'ADS-CSO-SVC': {
    artifacts_required: ['Public detailed service list with service/feature names matching public marketing and their security objectives, scoped to the Minimum Assessment Scope'],
    remediation_steps: [
      'Enumerate the specific services/features in the CSO with names matching public marketing.',
      'State each service\'s security objective and whether it is in the Minimum Assessment Scope.',
      'Publish the list and record the URL.',
    ],
    alternative_satisfiers: [trustCenterAlt()],
    nist_controls: [],
    references: [REF.ads],
  },
  'ADS-CSX-UTC': {
    artifacts_required: ['Configured FedRAMP-compatible Trust Center used to store and share authorization data with all necessary parties (20x MUST)'],
    remediation_steps: [
      'Adopt a FedRAMP-compatible Trust Center (the 20x MUST path; USDA Connect is the Rev5 path).',
      'Publish all authorization data to it for all necessary parties.',
      'Record the Trust Center URL and verify uninterrupted availability.',
    ],
    alternative_satisfiers: [trustCenterAlt()],
    nist_controls: [],
    references: [REF.ads],
  },
  'ADS-TRC-AAI': {
    artifacts_required: ['Trust Center agency-access inventory + history export, available to FedRAMP without interruption'],
    remediation_steps: [
      'Ensure the Trust Center maintains an inventory + history of agency users/systems with access to authorization data.',
      'Confirm FedRAMP can retrieve it without interruption.',
      'Attach the vendor access-inventory export (or vendor SOC2/FedRAMP letter covering the capability).',
    ],
    alternative_satisfiers: [trustCenterAlt()],
    nist_controls: [],
    references: [REF.ads],
  },
  'ADS-TRC-ACL': {
    artifacts_required: ['Trust Center access logs with ≥6-month retention; per-party summaries available on request'],
    remediation_steps: [
      'Confirm the Trust Center logs access to authorization data and retains summaries for at least 6 months.',
      'Verify per-party access info is available on that party\'s request.',
      'Attach the access-log export + retention policy.',
    ],
    alternative_satisfiers: [trustCenterAlt()],
    nist_controls: [],
    references: [REF.ads],
  },
  'ADS-TRC-HMR': {
    artifacts_required: ['Evidence the Trust Center offers authorization data in both human-readable and machine-readable view/download formats'],
    remediation_steps: [
      'Confirm the Trust Center renders authorization data in HR and MR formats.',
      'Attach a vendor capability attestation if downloads are auth-gated.',
    ],
    alternative_satisfiers: [trustCenterAlt()],
    nist_controls: [],
    references: [REF.ads],
  },
  'ADS-TRC-PAC': {
    artifacts_required: ['Documented programmatic (API) access to all authorization data, including HR materials (e.g. OpenAPI spec)'],
    remediation_steps: [
      'Confirm the Trust Center provides documented API access to all authorization data.',
      'Attach the published API docs / OpenAPI spec.',
    ],
    alternative_satisfiers: [trustCenterAlt()],
    nist_controls: [],
    references: [REF.ads],
  },
  'ADS-TRC-RSP': {
    artifacts_required: ['Trust Center status page / SLA / uptime report demonstrating responsive performance'],
    remediation_steps: [
      'Confirm the Trust Center delivers responsive performance under normal conditions.',
      'Attach the vendor status page / SLA / uptime report.',
    ],
    alternative_satisfiers: [trustCenterAlt()],
    nist_controls: [],
    references: [REF.ads],
  },
  'ADS-TRC-SSM': {
    artifacts_required: ['Documentation of Trust Center self-service access-provisioning/management features'],
    remediation_steps: [
      'Confirm the Trust Center includes self-service access provisioning/management for all necessary parties.',
      'Attach the vendor self-service feature docs.',
    ],
    alternative_satisfiers: [trustCenterAlt()],
    nist_controls: [],
    references: [REF.ads],
  },
  'ADS-TRC-USH': {
    artifacts_required: ['Trust Center SLA + status-page history demonstrating uninterrupted sharing of authorization data'],
    remediation_steps: [
      'Confirm the Trust Center shares authorization data without interruption.',
      'Attach the vendor SLA + status-page history.',
    ],
    alternative_satisfiers: [trustCenterAlt()],
    nist_controls: [],
    references: [REF.ads],
  },
  'ADS-UTC-AAD': {
    artifacts_required: ['Record of any agency access denial + the email to info@fedramp.gov notifying FedRAMP within 5 business days'],
    remediation_steps: [
      'On denying an agency access request for authorization data, email info@fedramp.gov.',
      'Send it within 5 business days of the denial.',
      'Record the denial, the notification, and dates in the register.',
    ],
    alternative_satisfiers: [ticketingAlt('Workflow that auto-records the denial event and the FedRAMP notification.')],
    nist_controls: [],
    sla: { businessDays: 5, cadence: 'notify FedRAMP within 5 business days of an agency access denial' },
    references: [REF.ads],
  },
  'ADS-UTC-AGA': {
    artifacts_required: ['Evidence the authorization package is shared with agencies upon request (e.g. Trust Center self-service grant)'],
    remediation_steps: [
      'Provide the authorization package to agencies on request.',
      'Prefer Trust Center self-service access so this is automatic.',
      'Record the request-fulfillment workflow.',
    ],
    alternative_satisfiers: [trustCenterAlt()],
    nist_controls: [],
    references: [REF.ads],
  },
  'ADS-UTC-PGD': {
    artifacts_required: ['Public plain-language guidance explaining how to obtain and manage access to authorization data in the Trust Center'],
    remediation_steps: [
      'Author plain-language access policies/guidance for all necessary parties.',
      'Publish it publicly (or use the Trust Center\'s built-in access-guidance page).',
      'Record the public URL.',
    ],
    alternative_satisfiers: [trustCenterAlt()],
    nist_controls: [],
    references: [REF.ads],
  },

  // ════════════════════════════════════════════════════════════════════════
  // CCM — Collaborative Continuous Monitoring (AGM awareness + OAR/QTR CSP)
  // ════════════════════════════════════════════════════════════════════════
  'CCM-AGM-CSC': {
    artifacts_required: ['Informational context row (agency-side staffing decision; no CSP finding)'],
    remediation_steps: ['Record for completeness — this obligates the agency, not the provider.'],
    alternative_satisfiers: none(),
    nist_controls: [],
    references: [REF.ccm],
  },
  'CCM-AGM-NAR': {
    artifacts_required: ['Inbound-demand log: any agency requirement levied beyond FedRAMP\'s baseline'],
    remediation_steps: ['If an agency levies extra requirements, log the inbound demand for the compliance team; this obligates the agency, not the provider.'],
    alternative_satisfiers: none(),
    nist_controls: [],
    references: [REF.ccm],
  },
  'CCM-AGM-NFA': {
    artifacts_required: ['Informational context row (agency emails FedRAMP after extra-info requests)'],
    remediation_steps: ['Record for awareness — agency obligation; no CSP-side signal.'],
    alternative_satisfiers: none(),
    nist_controls: [],
    references: [REF.ccm],
  },
  'CCM-AGM-NFR': {
    artifacts_required: ['Informational context row (agency emails FedRAMP of concerns)'],
    remediation_steps: ['Record for awareness; correlate to OAR/QTR quality, but agency-side.'],
    alternative_satisfiers: none(),
    nist_controls: [],
    references: [REF.ccm],
  },
  'CCM-AGM-NPC': {
    artifacts_required: ['Inbound-concern register keyed to the documented CSP security-contact mailbox, with response SLA'],
    remediation_steps: [
      'Document the CSP security-contact mailbox where agencies send concerns.',
      'Log received concerns + the response taken in an inbound-concern register.',
      'Track a response SLA for each.',
    ],
    alternative_satisfiers: [ticketingAlt('Shared mailbox / ticket queue capturing inbound concerns.')],
    nist_controls: [],
    references: [REF.ccm],
  },
  'CCM-AGM-ROR': {
    artifacts_required: ['Informational context row (agency reviews each OAR)'],
    remediation_steps: ['Record for awareness — agency-side review activity.'],
    alternative_satisfiers: none(),
    nist_controls: [],
    references: [REF.ccm],
  },
  'CCM-AGM-SSR': {
    artifacts_required: ['Informational context row (agency may/at-High should designate a senior security reviewer)'],
    remediation_steps: ['Record for awareness — agency staffing; obligation strengthens to SHOULD at High.'],
    alternative_satisfiers: none(),
    nist_controls: [],
    references: [REF.ccm],
  },
  'CCM-OAR-AVL': {
    artifacts_required: ['Published Ongoing Authorization Report (every 3 months) covering changes to authorization data, planned changes (≥3 mo), accepted vulnerabilities, transformative changes, and updated recommendations'],
    remediation_steps: [
      'Produce an OAR every 3 months covering the whole period since the last one, in a consistent human-readable format.',
      'Include the 5 required summaries: authorization-data changes, planned changes, accepted vulnerabilities, transformative changes, updated security/config/usage recommendations.',
      'Publish to all necessary parties (FedRAMP + agency customers) at the authorization-data surface.',
      'Record the publish date + next-due date in the OAR register; cross-feed accepted vulns (VDR) and transformative changes (SCN).',
    ],
    alternative_satisfiers: [grcAlt('Vanta/Drata/Paramify/SecureFrame generate ConMon deliverables; Paramify authors FedRAMP packages.')],
    nist_controls: ['ca-7', 'pm-31'],
    sla: QUARTERLY,
    references: [REF.ccm],
  },
  'CCM-OAR-AFS': {
    artifacts_required: ['Anonymized, desensitized feedback/Q&A summary attached as an addendum to each OAR'],
    remediation_steps: [
      'Collect feedback/Q&A about each OAR.',
      'Anonymize and desensitize it into an addendum to that OAR.',
      'Link OAR → addendum in the register and refresh per cycle.',
    ],
    alternative_satisfiers: [grcAlt('OAR feedback captured/anonymized in a GRC or support portal.')],
    nist_controls: [],
    sla: QUARTERLY,
    references: [REF.ccm],
  },
  'CCM-OAR-FBM': {
    artifacts_required: ['Documented asynchronous feedback channel (email or portal/form URL) for OAR questions, shared with all necessary parties'],
    remediation_steps: [
      'Establish an asynchronous feedback channel (email by default; an interactive channel is encouraged).',
      'Share it with all necessary parties alongside each OAR.',
      'Record the channel address/URL and verify it resolves.',
    ],
    alternative_satisfiers: [grcAlt('Support desk / community portal documented in the package.')],
    nist_controls: [],
    references: [REF.ccm],
  },
  'CCM-OAR-LSI': {
    artifacts_required: ['Per-OAR sensitivity/disclosure-review attestation (reviewer + date) confirming no irresponsible disclosure'],
    remediation_steps: [
      'Run a sensitivity/disclosure review of each OAR before publication.',
      'Record the reviewer + review date in the register.',
      'Optionally add a DLP/secret-scanning pre-publish gate (weak heuristic only).',
    ],
    alternative_satisfiers: [grcAlt('DLP / secret-scanning pre-publish gate (e.g. gitleaks on the OAR repo).')],
    nist_controls: [],
    references: [REF.ccm],
  },
  'CCM-OAR-NRD': {
    artifacts_required: ['Publicly stated target date for the next OAR (present, future, ≤ ~3 months out)'],
    remediation_steps: [
      'Publish the next-OAR target date with the public authorization data.',
      'Verify it is a future date within ~3 months.',
      'Record it in the OAR register.',
    ],
    alternative_satisfiers: [trustCenterAlt()],
    nist_controls: [],
    references: [REF.ccm],
  },
  'CCM-OAR-RPS': {
    artifacts_required: ['Optional decision record (what was shared publicly + the no-adverse-effect determination + approver)'],
    remediation_steps: ['If sharing an OAR publicly, record the no-adverse-effect determination and approver. Permissive — never fails.'],
    alternative_satisfiers: [trustCenterAlt()],
    nist_controls: [],
    references: [REF.ccm],
  },
  'CCM-OAR-SOR': {
    artifacts_required: ['OAR publish-date history showing a regular 3-month cadence anchored to the beginning/middle/end of each quarter'],
    remediation_steps: [
      'Set a regular 3-month OAR cycle anchored to the start, middle, or end of each quarter.',
      'Keep the offset consistent (~90-day spacing) so agencies aren\'t swamped.',
      'Record the schedule + history.',
    ],
    alternative_satisfiers: [grcAlt('GRC calendar enforcing scheduling discipline.')],
    nist_controls: [],
    sla: QUARTERLY,
    references: [REF.ccm],
  },
  'CCM-QTR-ACT': {
    artifacts_required: ['Quarterly Review agenda/deck artifacts per cycle'],
    remediation_steps: ['Include additional agency-relevant content in each Quarterly Review; attach the agenda/deck. Record-only (judgment).'],
    alternative_satisfiers: none(),
    nist_controls: [],
    sla: QUARTERLY,
    references: [REF.ccm],
  },
  'CCM-QTR-MTG': {
    artifacts_required: ['Quarterly Review meeting record (held date + next-scheduled date), open to all necessary parties, covering recent OARs'],
    remediation_steps: [
      'Host a synchronous Quarterly Review every 3 months, open to all necessary parties.',
      'Cover the most agency-relevant parts of recent OARs.',
      'Record held + next-scheduled dates; note obligation is SHOULD at Low, MUST at Moderate/High.',
    ],
    alternative_satisfiers: [grcAlt('Webinar platform (Zoom/Teams/On24) event history exported into the register.')],
    nist_controls: [],
    sla: QUARTERLY,
    references: [REF.ccm],
  },
  'CCM-QTR-NID': {
    artifacts_required: ['Per-QTR content-review attestation (reviewer + date) confirming no irresponsible disclosure'],
    remediation_steps: ['Run a content/disclosure review of each QTR deck before the meeting; record reviewer + date.'],
    alternative_satisfiers: [grcAlt('Pre-review of the QTR deck by security/legal.')],
    nist_controls: [],
    references: [REF.ccm],
  },
  'CCM-QTR-NRD': {
    artifacts_required: ['Publicly stated target date for the next Quarterly Review (present, future, ≤ ~3 months out)'],
    remediation_steps: [
      'Publish the next-QTR target date with public authorization data.',
      'Verify it is future and within ~3 months.',
      'Record it in the QTR register.',
    ],
    alternative_satisfiers: [trustCenterAlt()],
    nist_controls: [],
    references: [REF.ccm],
  },
  'CCM-QTR-REG': {
    artifacts_required: ['Registration link OR downloadable .ics calendar file for the Quarterly Review, included in authorization data'],
    remediation_steps: [
      'Include a registration URL or an .ics calendar file with QTR meeting info in the authorization data.',
      'Verify the URL resolves / the .ics parses.',
      'Cross-reference ADS-CSL-UCP / ADS-CSO-FCT consistency.',
    ],
    alternative_satisfiers: [trustCenterAlt()],
    nist_controls: [],
    references: [REF.ccm],
  },
  'CCM-QTR-RTP': {
    artifacts_required: ['QTR invite/attendee-list review attestation'],
    remediation_steps: ['Review the QTR invite list; do not invite irrelevant third parties (the CSP\'s own 3PAO is relevant by default). Record-only advisory.'],
    alternative_satisfiers: none(),
    nist_controls: [],
    references: [REF.ccm],
  },
  'CCM-QTR-RTR': {
    artifacts_required: ['Quarterly Review recording or transcript artifact linked per cycle, available to all necessary parties'],
    remediation_steps: [
      'Record or transcribe each Quarterly Review.',
      'Make it available to all necessary parties with other authorization data.',
      'Link the artifact in the QTR register and verify reachability.',
    ],
    alternative_satisfiers: [grcAlt('Auto-transcription (Zoom cloud recording, Otter, Fireflies) feeding the register.')],
    nist_controls: [],
    sla: QUARTERLY,
    references: [REF.ccm],
  },
  'CCM-QTR-SAR': {
    artifacts_required: ['OAR-release date and QTR-meeting date showing the QTR lands ≥3 and ≤10 business days after the OAR release'],
    remediation_steps: [
      'Schedule each Quarterly Review to occur at least 3 business days after releasing the OAR.',
      'Ensure it occurs within 10 business days of that release.',
      'Record both dates so the business-day window can be verified.',
    ],
    alternative_satisfiers: [grcAlt('Scheduling automation in a GRC calendar.')],
    nist_controls: [],
    sla: { businessDays: 10, cadence: 'Quarterly Review ≥3 and ≤10 business days after OAR release' },
    references: [REF.ccm],
  },
  'CCM-QTR-SCR': {
    artifacts_required: ['Optional share decision-record + no-adverse-effect determination'],
    remediation_steps: ['If sharing QTR content publicly, record the no-adverse-effect determination. Permissive — never fails.'],
    alternative_satisfiers: [trustCenterAlt()],
    nist_controls: [],
    references: [REF.ccm],
  },
  'CCM-QTR-SRR': {
    artifacts_required: ['Optional redaction attestation + no-adverse-effect determination before sharing recordings'],
    remediation_steps: ['If sharing QTR recordings, remove all agency info (comments, questions, names) and record the redaction attestation + no-adverse-effect determination. Permissive.'],
    alternative_satisfiers: none(),
    nist_controls: [],
    references: [REF.ccm],
  },

  // ════════════════════════════════════════════════════════════════════════
  // SCN — Significant Change Notifications
  // ════════════════════════════════════════════════════════════════════════
  'SCN-CSO-EVA': {
    artifacts_required: ['Change-management workflow with a mandatory SCN-categorization field on every change {impact-categorization, transformative, adaptive, routine-recurring, not-significant}'],
    remediation_steps: [
      'Add a required "SCN type" field/label to change tickets / PR-release templates.',
      'Evaluate every potential significant change and categorize it from the valid set.',
      'Apply the appropriate SCN process per categorization (impact-categorization → new assessment; TRF/ADP/RTR processes; or not-significant).',
      'Retain the categorization decision with each change.',
    ],
    alternative_satisfiers: [ticketingAlt('ServiceNow/Jira change-mgmt with a mandatory categorization field.'), grcAlt()],
    nist_controls: ['cm-3', 'cm-4', 'ra-3'],
    references: [REF.scn],
  },
  'SCN-CSO-MAR': {
    artifacts_required: ['Durable, queryable evaluation records (change tickets with categorization history, or a maintained evaluation log) carrying evaluator + timestamp, available to FedRAMP on request'],
    remediation_steps: [
      'Retain SCN-EVA evaluation records durably and queryably.',
      'Ensure each record carries the evaluator + timestamp.',
      'Confirm the store is reachable and non-empty for the period; make it available to FedRAMP on request.',
    ],
    alternative_satisfiers: [ticketingAlt('ServiceNow change audit history / Jira issue history as the durable record.')],
    nist_controls: ['cm-3', 'au-6'],
    references: [REF.scn],
  },
  'SCN-CSO-HIS': {
    artifacts_required: ['Published SCN archive/feed with a continuous trailing 12-month window of Significant Change Notifications'],
    remediation_steps: [
      'Maintain 12 months of historical SCNs with the authorization data.',
      'Ensure the archive has no large gaps (oldest entry ≤ now − 12 months).',
      'Record the archive/feed URL.',
    ],
    alternative_satisfiers: [trustCenterAlt()],
    nist_controls: [],
    sla: { calendarDays: 365, cadence: 'maintain a trailing 12-month SCN archive' },
    references: [REF.scn],
  },
  'SCN-CSO-HRM': {
    artifacts_required: ['Both a human-readable SCN doc (HTML/PDF/Markdown) and a machine-readable feed (CSV/JSON) conforming to the SCN schema'],
    remediation_steps: [
      'Publish all SCNs and related audit records in both human-readable and machine-readable formats.',
      'Validate the machine feed parses and conforms to the SCN-CSO-INF 10-field schema.',
      'Link the human-readable counterpart.',
    ],
    alternative_satisfiers: [trustCenterAlt()],
    nist_controls: [],
    references: [REF.scn],
  },
  'SCN-CSO-INF': {
    artifacts_required: ['Each SCN containing the 10 required fields (FedRAMP ID; assessor name if applicable; related POA&M if applicable; change type + categorization explanation; change description; reason; customer-impact summary; plan/timeline incl. KSI/control re-validation; business/security impact analysis; approver name + title)'],
    remediation_steps: [
      'Adopt an SCN template enforcing the 10 required fields (treating "if applicable" as conditionally required).',
      'Schema-validate each SCN record against the field list before publishing.',
      'Surface any record missing required fields for correction.',
    ],
    alternative_satisfiers: [grcAlt('GRC/ServiceNow SCN template enforcing required fields at entry; Paramify SCN authoring.')],
    nist_controls: [],
    references: [REF.scn],
  },
  'SCN-CSO-NOM': {
    artifacts_required: ['Documented, easily accessible notification mechanism in the authorization package'],
    remediation_steps: ['Document how parties are notified (email list, Trust Center subscription, webhook/RSS) and make it easily accessible. Permissive on the how.'],
    alternative_satisfiers: [trustCenterAlt()],
    nist_controls: [],
    references: [REF.scn],
  },
  'SCN-CSO-ARI': {
    artifacts_required: ['Optional additional relevant information attached to SCNs'],
    remediation_steps: ['Include additional relevant context in SCNs as useful. Permissive no-op — nothing to validate.'],
    alternative_satisfiers: none(),
    nist_controls: [],
    references: [REF.scn],
  },
  'SCN-CSO-EMG': {
    artifacts_required: ['Documented emergency-change procedure; for each emergency change, retroactive SCN materials + a post-incident assessment record linked'],
    remediation_steps: [
      'Document an emergency-change procedure in the package.',
      'For changes executed under emergency/incident, follow all relevant procedures and notify all necessary parties.',
      'Retroactively produce all SCN materials and complete the post-incident assessment, linking them to the change.',
    ],
    alternative_satisfiers: [pagerDutyAlt('Incident process with post-incident review tied to the change record.'), ticketingAlt()],
    nist_controls: ['cm-3', 'ir-4'],
    references: [REF.scn],
  },
  'SCN-ADP-NTF': {
    artifacts_required: ['For each adaptive change: notification within 10 business days after finishing, by updating authorization data, with a new-risk/POA&M summary if applicable'],
    remediation_steps: [
      'For adaptive changes, notify all necessary parties within 10 business days after finishing.',
      'Update authorization data as the notification mechanism.',
      'Include a summary of any new risks/POA&Ms resulting (if applicable).',
      'Record finish_date and notification_date to verify the window.',
    ],
    alternative_satisfiers: [ticketingAlt('Change-mgmt SLA automation that auto-notifies on close.')],
    nist_controls: ['cm-3', 'cm-4'],
    sla: { businessDays: 10, cadence: 'notify within 10 business days after finishing an adaptive change' },
    references: [REF.scn],
  },
  'SCN-RTR-NNR': {
    artifacts_required: ['Consistency record showing routine-recurring changes are excluded from the formal SCN feed (no over-notification)'],
    remediation_steps: [
      'Configure change-mgmt rules to auto-exempt routine-recurring changes from formal SCNs.',
      'Verify RTR-categorized items do not generate SCNs (and that they are not erroneously notified).',
    ],
    alternative_satisfiers: [ticketingAlt('Change-mgmt rules that auto-exempt RTR categories.')],
    nist_controls: [],
    references: [REF.scn],
  },
  'SCN-TRF-NIP': {
    artifacts_required: ['For each transformative change: initial-plan notification ≥30 business days before starting, with a likely-security-impact summary'],
    remediation_steps: [
      'For transformative changes, notify all necessary parties of initial plans at least 30 business days before starting.',
      'Include a summary of likely security impacts / risk changes.',
      'Record start_date and initial_plan_notification_date to verify the ≥30-business-day lead time.',
    ],
    alternative_satisfiers: [ticketingAlt('Release-planning workflow with a mandatory advance-notice gate.')],
    nist_controls: ['cm-3', 'cm-4'],
    sla: { businessDays: 30, cadence: 'notify ≥30 business days before starting a transformative change' },
    references: [REF.scn],
  },
  'SCN-TRF-NFP': {
    artifacts_required: ['For each transformative change: final-plan notification ≥10 business days before starting, updating all previously sent info'],
    remediation_steps: [
      'Notify all necessary parties of final plans at least 10 business days before starting the transformative change.',
      'Update all previously sent information.',
      'Record start_date and final_plan_notification_date; link to the initial-plan notice.',
    ],
    alternative_satisfiers: [ticketingAlt('Release-gate workflow.')],
    nist_controls: ['cm-3', 'cm-4'],
    sla: { businessDays: 10, cadence: 'notify ≥10 business days before starting a transformative change (final plans)' },
    references: [REF.scn],
  },
  'SCN-TRF-NAF': {
    artifacts_required: ['For each transformative change: notification within 5 business days after finishing, updating all previously sent info'],
    remediation_steps: [
      'Notify all necessary parties within 5 business days after finishing the transformative change.',
      'Update all previously sent information.',
      'Record finish_date and post_finish_notification_date to verify the window.',
    ],
    alternative_satisfiers: [ticketingAlt('Auto-notify-on-close automation.')],
    nist_controls: ['cm-3', 'cm-4'],
    sla: { businessDays: 5, cadence: 'notify within 5 business days after finishing a transformative change' },
    references: [REF.scn],
  },
  'SCN-TRF-NAV': {
    artifacts_required: ['For each transformative change: notification within 5 business days after completing verification/assessment/validation, with new-risk summary + SAR (if applicable)'],
    remediation_steps: [
      'Complete verification/assessment/validation (Persistent Validation) of impacted KSIs after the change.',
      'Notify all necessary parties within 5 business days of completing it.',
      'Attach updates to prior info, a new-risk/POA&M summary (if applicable), and the SAR (if applicable).',
      'Record verification_complete_date and post_verification_notification_date.',
    ],
    alternative_satisfiers: [grcAlt('3PAO/GRC assessment workflow producing the SAR.')],
    nist_controls: ['ca-2', 'ca-7'],
    sla: { businessDays: 5, cadence: 'notify within 5 business days after completing verification of a transformative change' },
    references: [REF.scn],
  },
  'SCN-TRF-UPD': {
    artifacts_required: ['Updated service documentation (user guides, marketplace listing) within 30 business days after finishing a transformative change'],
    remediation_steps: [
      'Update service documentation (not the SSP/authorization package) to reflect the transformative change.',
      'Publish within 30 business days of finishing.',
      'Record the doc-update artifact / repo commit / "last updated" timestamp.',
    ],
    alternative_satisfiers: [{
      via: 'Docs-as-code pipeline (GitBook, Docusaurus, readme.io)',
      description: 'A docs-as-code pipeline provides commit "last modified" timestamps that directly evidence the doc-update deadline.',
      evidence_required: ['Docs repo/site commit history', 'Commit timestamp within 30 business days of the change finish'],
      detected: false,
      detection_signals: ['gitbook', 'docusaurus', 'readme.io'],
    }],
    nist_controls: ['cm-3'],
    sla: { businessDays: 30, cadence: 'publish updated service docs within 30 business days after finishing a transformative change' },
    references: [REF.scn],
  },
  'SCN-TRF-TPR': {
    artifacts_required: ['For TRF changes needing human validation: a pre-start 3PAO-review artifact (engagement record / signed review)'],
    remediation_steps: [
      'For transformative changes where human validation is necessary, engage a third-party assessor before starting.',
      'Limit the review to security decisions requiring human validation.',
      'Attach the pre-start 3PAO engagement record / signed review.',
    ],
    alternative_satisfiers: [{
      via: 'Engaged 3PAO / FedRAMP package-authoring tool (Paramify)',
      description: 'A configured assessor relationship or Paramify package authoring provides the pre-start third-party review record.',
      evidence_required: ['3PAO engagement record / signed scope-and-impact review', 'Date showing it preceded the change start'],
      detected: false,
      detection_signals: ['paramify', '3pao', 'assessor'],
    }],
    nist_controls: ['ca-2'],
    references: [REF.scn],
  },
  'SCN-FRP-CAP': {
    artifacts_required: ['CAP-conditions register (any imposed delay period / advance-approval gate) feeding the SCN deadline logic'],
    remediation_steps: [
      'If subject to a Corrective Action Plan, record the imposed SCN conditions (delay period, advance-approval gate).',
      'Treat those conditions as overrides to the SCN-TRF/ADP deadline logic.',
      'This obligates FedRAMP; track its conditions, not a CSP finding.',
    ],
    alternative_satisfiers: none(),
    nist_controls: [],
    references: [REF.scn],
  },

  // ════════════════════════════════════════════════════════════════════════
  // FSI — FedRAMP Security Inbox
  // ════════════════════════════════════════════════════════════════════════
  'FSI-CSO-INB': {
    artifacts_required: ['Documented, monitored FedRAMP Security Inbox email address routed to a ticket queue / on-call'],
    remediation_steps: [
      'Establish a security inbox address meeting the FedRAMP Security Inbox requirements.',
      'Route it to a monitored ticket queue (Jira/ServiceNow) or on-call so urgent messages are handled.',
      'Record the address + routing in the register.',
    ],
    alternative_satisfiers: [ticketingAlt('Shared mailbox routed to a ticket queue with inbound-email integration.'), pagerDutyAlt()],
    nist_controls: ['ir-6', 'ir-7'],
    references: [REF.fsi],
  },
  'FSI-CSO-RCV': {
    artifacts_required: ['Mail-security config showing FedRAMP email is received without challenge-response, greylisting, or allowlist gating'],
    remediation_steps: [
      'Configure mail security so FedRAMP email is delivered without disruption (no challenge-response, no greylisting bounces, no per-message allowlist requests).',
      'Explicitly allowlist the two FedRAMP domains.',
      'Attach the exported gateway config.',
    ],
    alternative_satisfiers: [mailGatewayAlt()],
    nist_controls: ['ir-6', 'sc-7'],
    references: [REF.fsi],
  },
  'FSI-CSO-TFG': {
    artifacts_required: ['Mail-gateway safe-sender policy trusting @fedramp.gov and @gsa.gov by default'],
    remediation_steps: [
      'Configure the mail gateway to treat @fedramp.gov and @gsa.gov as genuine by default (not spam-filtered).',
      'Document the exception: if a message is confirmed spoofed, FSI requirements stop applying to it.',
      'Attach the safe-sender policy export.',
    ],
    alternative_satisfiers: [mailGatewayAlt()],
    nist_controls: ['si-3', 'sc-7'],
    references: [REF.fsi],
  },
  'FSI-CSO-NOC': {
    artifacts_required: ['Record of any FSI address change + the immediate email to info@fedramp.gov (CSO name, FedRAMP ID, new address)'],
    remediation_steps: [
      'On any FSI address change, immediately email info@fedramp.gov.',
      'Include the CSO name, FedRAMP ID, and the new address.',
      'Record the change + notification.',
    ],
    alternative_satisfiers: none(),
    nist_controls: ['ir-6'],
    references: [REF.fsi],
  },
  'FSI-CSO-ACK': {
    artifacts_required: ['Evidence of prompt, automatic acknowledgement of messages arriving in the FSI'],
    remediation_steps: [
      'Configure an automatic acknowledgement (ticketing inbound-email auto-response) for FSI messages.',
      'Ensure it fires promptly (without unnecessary delay).',
      'Attach a sample auto-acknowledgement.',
    ],
    alternative_satisfiers: [ticketingAlt('ServiceNow/Jira inbound-email auto-response.')],
    nist_controls: ['ir-6'],
    references: [REF.fsi],
  },
  'FSI-CSO-EMR': {
    artifacts_required: ['Escalation policy routing any Emergency-designated message to a senior security official for awareness'],
    remediation_steps: [
      'Define an escalation that routes Emergency-designated messages to the security on-call / senior security official.',
      'Attach the escalation policy export.',
      'Verify the routing on a test message.',
    ],
    alternative_satisfiers: [pagerDutyAlt('Escalation policy targeting the security on-call for Emergency messages.')],
    nist_controls: ['ir-4', 'ir-6'],
    references: [REF.fsi],
  },
  'FSI-CSO-CRA': {
    artifacts_required: ['SLA record showing required actions in Emergency / Emergency Test messages were completed within the stated timeframe (default: High ≤12h; Moderate by 3pm ET 2nd business day; Low by 3pm ET 3rd business day)'],
    remediation_steps: [
      'Log each Emergency / Emergency Test message as a ticket with an SLA timer.',
      'Complete the required actions within the message\'s stated timeframe (default per FSI-FRP-ERT).',
      'Attach the SLA record demonstrating on-time completion.',
    ],
    alternative_satisfiers: [ticketingAlt('ServiceNow SIR / Jira with the message logged and an SLA timer.')],
    nist_controls: ['ir-4'],
    sla: { businessDays: 2, cadence: 'complete Emergency actions per FSI-FRP-ERT (High ≤12h; Mod 2nd business day; Low 3rd business day)' },
    references: [REF.fsi],
  },
  'FSI-CSO-IMA': {
    artifacts_required: ['Record showing required actions in Important-designated messages were completed within the stated timeframe'],
    remediation_steps: [
      'Log Important-designated messages and complete the required actions within the stated reasonable timeframe.',
      'Attach the SLA-tracking record.',
    ],
    alternative_satisfiers: [ticketingAlt('Ticketing SLA tracking.')],
    nist_controls: ['ir-4'],
    references: [REF.fsi],
  },
  // FSI-FRP-* obligate FedRAMP (awareness items) — guidance documents the rule.
  'FSI-FRP-VRE': {
    artifacts_required: ['Awareness: FedRAMP sends from official @fedramp.gov/@gsa.gov with SPF/DKIM/DMARC configured'],
    remediation_steps: ['Awareness item — FedRAMP\'s obligation. Provider should support trusting verified FedRAMP senders (see FSI-CSO-TFG/RCV).'],
    alternative_satisfiers: none(),
    nist_controls: [],
    references: [REF.fsi],
  },
  'FSI-FRP-CDS': {
    artifacts_required: ['Awareness: FedRAMP signals criticality via subject-line designators (Emergency / Emergency Test / Important)'],
    remediation_steps: ['Awareness item — FedRAMP\'s obligation. Provider should recognize the designators when routing (FSI-CSO-EMR).'],
    alternative_satisfiers: none(),
    nist_controls: [],
    references: [REF.fsi],
  },
  'FSI-FRP-UFS': {
    artifacts_required: ['Awareness: FedRAMP sends Emergency/Emergency Test from fedramp_security@gsa.gov or fedramp_security@fedramp.gov'],
    remediation_steps: ['Awareness item — FedRAMP\'s obligation. Provider should trust these emergency sender addresses.'],
    alternative_satisfiers: none(),
    nist_controls: [],
    references: [REF.fsi],
  },
  'FSI-FRP-PNT': {
    artifacts_required: ['Awareness: FedRAMP posts public notice ≥10 business days before an Emergency Test'],
    remediation_steps: ['Awareness item — FedRAMP\'s obligation; the provider may use the notice to prepare.'],
    alternative_satisfiers: none(),
    nist_controls: [],
    sla: { businessDays: 10, cadence: 'FedRAMP posts public notice ≥10 business days before an Emergency Test' },
    references: [REF.fsi],
  },
  'FSI-FRP-RQA': {
    artifacts_required: ['Awareness: FedRAMP states required actions in the body of elevated-reaction messages'],
    remediation_steps: ['Awareness item — FedRAMP\'s obligation; the provider acts on the stated required actions (FSI-CSO-CRA).'],
    alternative_satisfiers: none(),
    nist_controls: [],
    references: [REF.fsi],
  },
  'FSI-FRP-ERT': {
    artifacts_required: ['Awareness: FedRAMP states expected completion timeframes (High ≤12h; Moderate by 3pm ET 2nd business day; Low by 3pm ET 3rd business day)'],
    remediation_steps: ['Awareness item — FedRAMP\'s obligation; these default timeframes drive the provider\'s FSI-CSO-CRA SLA.'],
    alternative_satisfiers: none(),
    nist_controls: [],
    sla: { businessDays: 2, cadence: 'default reaction timeframes: High ≤12h; Moderate 2nd business day; Low 3rd business day' },
    references: [REF.fsi],
  },
  'FSI-FRP-COR': {
    artifacts_required: ['Awareness: FedRAMP states the corrective actions that follow failure'],
    remediation_steps: ['Awareness item — FedRAMP\'s obligation.'],
    alternative_satisfiers: none(),
    nist_controls: [],
    references: [REF.fsi],
  },
  'FSI-FRP-RPM': {
    artifacts_required: ['Awareness: FedRAMP may track/publish reaction metrics'],
    remediation_steps: ['Awareness item — FedRAMP\'s permissive option.'],
    alternative_satisfiers: none(),
    nist_controls: [],
    references: [REF.fsi],
  },

  // ════════════════════════════════════════════════════════════════════════
  // ICP — Incident Communications Procedures
  // ════════════════════════════════════════════════════════════════════════
  'ICP-CSX-IRF': {
    artifacts_required: ['Record of reporting each incident to FedRAMP within 1 hour of identification (email fedramp_security@fedramp.gov or @gsa.gov)'],
    remediation_steps: [
      'On identifying an incident, email fedramp_security@fedramp.gov or @gsa.gov within 1 hour.',
      'Record the identification time and notification time to prove the 1-hour window.',
      'Automate with a SOAR playbook where possible.',
    ],
    alternative_satisfiers: [soarAlt('Auto-notify that emails fedramp_security@… on incident open.')],
    nist_controls: ['ir-6'],
    sla: { calendarDays: 1, cadence: 'report to FedRAMP within 1 hour of identification' },
    references: [REF.icp],
  },
  'ICP-CSX-IRA': {
    artifacts_required: ['Record of reporting each incident to all agency customers within 1 hour of identification, via each agency\'s incident-comms POC'],
    remediation_steps: [
      'On identifying an incident, notify all agency customers within 1 hour using each agency\'s incident-communications POC.',
      'Maintain the per-agency POC list.',
      'Record identification + notification times and send logs.',
    ],
    alternative_satisfiers: [{
      via: 'Status-page / customer-comms tool (Statuspage, ServiceNow Customer Service)',
      description: 'A customer-comms tool broadcasts to agency contacts and logs the send time, evidencing the 1-hour window.',
      evidence_required: ['Tool config with agency contacts', 'Send logs showing delivery within 1 hour of identification'],
      detected: false,
      detection_signals: ['statuspage', 'servicenow'],
    }],
    nist_controls: ['ir-6', 'ac-21'],
    sla: { calendarDays: 1, cadence: 'report to agency customers within 1 hour of identification' },
    references: [REF.icp],
  },
  'ICP-CSX-IRC': {
    artifacts_required: ['Record of reporting to CISA within 1 hour of identification (when a CISA-taxonomy attack vector is confirmed/suspected) via the CISA Incident Reporting System'],
    remediation_steps: [
      'Determine whether the incident is confirmed/suspected to involve a CISA-taxonomy attack vector.',
      'If so, report to CISA within 1 hour via the CISA Incident Reporting System (myservices.cisa.gov/irf), following the Federal Incident Notification Guidelines.',
      'Record the IRF submission confirmation.',
    ],
    alternative_satisfiers: [soarAlt('Playbook that files the CISA IRF and captures the confirmation.')],
    nist_controls: ['ir-6'],
    sla: { calendarDays: 1, cadence: 'report to CISA within 1 hour of identification (CISA-taxonomy vectors)' },
    references: [REF.icp, REF.cisaIrf, REF.cisaGuidelines],
  },
  'ICP-CSX-ICU': {
    artifacts_required: ['Daily incident updates to all necessary parties (FedRAMP, CISA if applicable, all agency customers) until resolved and recovery complete'],
    remediation_steps: [
      'Update all necessary parties at least once per calendar day until the incident is resolved and recovery is complete.',
      'Use a status-page incident or major-incident comms cadence.',
      'Record each daily update.',
    ],
    alternative_satisfiers: [{
      via: 'Status page / ServiceNow major-incident comms',
      description: 'A status-page incident with daily update posts (or ServiceNow major-incident comms cadence) provides the daily-update record.',
      evidence_required: ['Status-page / comms log', 'Posts showing at least one update per calendar day'],
      detected: false,
      detection_signals: ['statuspage', 'servicenow'],
    }],
    nist_controls: ['ir-6', 'ir-4'],
    sla: { calendarDays: 1, cadence: 'update all necessary parties at least once per calendar day during an incident' },
    references: [REF.icp],
  },
  'ICP-CSX-RPT': {
    artifacts_required: ['Incident-report information available in the secure FedRAMP repository (USDA Connect) or Trust Center'],
    remediation_steps: [
      'Publish incident-report information to the secure FedRAMP repository or Trust Center.',
      'Verify access controls for all necessary parties.',
      'Record the URL.',
    ],
    alternative_satisfiers: [trustCenterAlt()],
    nist_controls: ['ir-6', 'ac-21'],
    references: [REF.icp],
  },
  'ICP-CSX-RSD': {
    artifacts_required: ['Incident-comms review/approval record balancing responsible disclosure (no detail that would likely increase impact) with enough info for risk decisions'],
    remediation_steps: [
      'Add a legal/comms review-and-approval step on incident-communications.',
      'Withhold sensitive detail that would likely increase the incident\'s impact, while disclosing enough for informed risk decisions to all necessary parties.',
      'Record the approval.',
    ],
    alternative_satisfiers: [ticketingAlt('Approval step on incident-comms tickets.')],
    nist_controls: ['ac-21', 'ir-6'],
    references: [REF.icp],
  },
  'ICP-CSX-FIR': {
    artifacts_required: ['Final incident report covering: (1) what occurred, (2) root cause, (3) response, (4) lessons learned, (5) changes needed'],
    remediation_steps: [
      'After resolution + recovery, produce a final incident report with the 5 required sections.',
      'Distribute to all necessary parties and store with incident-report info (ICP-CSX-RPT).',
      'Attach the report / post-incident review export.',
    ],
    alternative_satisfiers: [{
      via: 'Post-incident review tooling (ServiceNow PIR, Jira PIR, Blameless, incident.io)',
      description: 'A PIR/retro tool produces the structured final report with the required sections.',
      evidence_required: ['PIR/retro export', 'Sections mapping to what/root-cause/response/lessons/changes'],
      detected: false,
      detection_signals: ['blameless', 'incident.io', 'servicenow', 'jira'],
    }],
    nist_controls: ['ir-6', 'ir-4'],
    references: [REF.icp],
  },
  'ICP-CSX-AUR': {
    artifacts_required: ['Automated incident-reporting mechanism (SOAR playbook / event orchestration) reporting and updating all necessary parties incl. CISA'],
    remediation_steps: [
      'Use automated mechanisms (SOAR / event orchestration) to report incidents and provide updates.',
      'Cover all necessary parties including CISA.',
      'Attach the playbook export.',
    ],
    alternative_satisfiers: [soarAlt('Tines/Torq/Swimlane, PagerDuty Event Orchestration, ServiceNow Flow.')],
    nist_controls: ['ir-6'],
    references: [REF.icp],
  },
  'ICP-CSX-HRM': {
    artifacts_required: ['Incident-report info in consistent human-readable AND machine-readable formats (e.g. PDF + JSON / OCSF)'],
    remediation_steps: [
      'Publish incident-report info in both human-readable and machine-readable formats.',
      'Consider OCSF incident objects to a SIEM for the machine feed.',
      'Attach a sample of both formats.',
    ],
    alternative_satisfiers: [{
      via: 'Incident tooling export + OCSF SIEM feed (incident.io, ServiceNow, OCSF)',
      description: 'Incident tooling exporting both PDF and JSON, plus OCSF incident objects to a SIEM, satisfies dual-format availability.',
      evidence_required: ['Sample HR + MR exports', 'OCSF feed config if used'],
      detected: false,
      detection_signals: ['incident.io', 'servicenow', 'ocsf'],
    }],
    nist_controls: ['ir-6', 'si-5'],
    references: [REF.icp],
  },

  // ════════════════════════════════════════════════════════════════════════
  // PVA — Persistent Validation and Assessment
  // ════════════════════════════════════════════════════════════════════════
  'PVA-CSX-VAL': {
    artifacts_required: ['Documented persistent-validation process for the KSIs, with a scan/validation history showing recurring execution'],
    remediation_steps: [
      'Define and run a persistent process that validates the KSIs over time, with status always known.',
      'Drive it from this collector or a continuous-compliance platform.',
      'Attach the scan-history export + coverage matrix.',
    ],
    alternative_satisfiers: [grcAlt('Vanta/Drata/Paramify/SecureFrame drive the validation cycle.')],
    nist_controls: ['ca-7', 'ca-7.6', 'ra-5'],
    references: [REF.pva],
  },
  'PVA-CSX-PMV': {
    artifacts_required: ['Machine-based KSI validation run on cadence (≥ every 7 days at Low, every 3 days at Moderate; more frequent at High)'],
    remediation_steps: [
      'Validate machine-based information-resource KSIs on the required cadence.',
      'Configure the scheduler accordingly (Low ≤7 days; Moderate ≤3 days; High more frequent).',
      'Record scan timestamps.',
    ],
    alternative_satisfiers: [grcAlt('GRC platform with documented machine-scan cadence.'), scannerAlt()],
    nist_controls: ['ca-7', 'ca-7.4', 'si-4'],
    sla: { calendarDays: 7, cadence: 'machine validation ≥ every 7 days (Low) / 3 days (Moderate); High more frequent' },
    references: [REF.pva],
  },
  'PVA-CSX-NMV': {
    artifacts_required: ['Non-machine KSI validation (policies, procedures, people) completed at least once every 3 months'],
    remediation_steps: [
      'Validate non-machine-based KSIs (policies, procedures, employees) at least every 3 months.',
      'Use a recurring review module / task cadence.',
      'Record the completion history.',
    ],
    alternative_satisfiers: [grcAlt('GRC recurring "controls review" cadence with completion history.')],
    nist_controls: ['ca-7', 'pl-2', 'pm-14'],
    sla: { calendarDays: 92, cadence: 'complete non-machine validation at least every 3 months' },
    references: [REF.pva],
  },
  'PVA-CSX-FAV': {
    artifacts_required: ['Process routing any validation issue (and any validation-process failure) into the VDR process as a vulnerability'],
    remediation_steps: [
      'Treat any issue found during persistent validation — and any failure of the validation process itself — as a vulnerability.',
      'Auto-route it through the VDR detection-and-response process.',
      'Attach the routing/automation config.',
    ],
    alternative_satisfiers: [soarAlt('Auto-ticketing on validation failure into the VDR workflow.')],
    nist_controls: ['ra-5', 'si-2', 'ca-7'],
    references: [REF.pva],
  },
  'PVA-CSX-RPV': {
    artifacts_required: ['Persistent-validation activity included in the VDR reports (not a separate report)'],
    remediation_steps: [
      'Fold persistent-validation output into the existing VDR detection-and-response reports.',
      'Confirm the report includes validation activity for the period.',
    ],
    alternative_satisfiers: [grcAlt('GRC platform rolls evidence into its continuous-monitoring report.')],
    nist_controls: ['ca-7', 'ra-5', 'pm-31'],
    references: [REF.pva],
  },
  'PVA-CSX-PTE': {
    artifacts_required: ['Technical explanations/demonstrations + supporting info provided to all necessary assessors (FedRAMP + 3PAO)'],
    remediation_steps: [
      'Provide assessors technical explanations, demos, and supporting info for the capabilities meeting KSIs.',
      'Prefer read access to the GRC/evidence tenant for self-service.',
      'Record the assessor access grant.',
    ],
    alternative_satisfiers: [grcAlt('Read access to a GRC tenant where the assessor self-serves.')],
    nist_controls: ['ca-2', 'ca-7', 'sa-4.7'],
    references: [REF.pva],
  },
  'PVA-CSX-RAD': {
    artifacts_required: ['Optional record of advice requested/accepted from the assessor (without compromising objectivity)'],
    remediation_steps: ['Optionally request/accept assessor advice on posture or validation-procedure clarity, unless it would compromise objectivity. Permissive.'],
    alternative_satisfiers: none(),
    nist_controls: ['ca-2', 'ca-7'],
    references: [REF.pva],
  },
  'PVA-CSX-IVV': {
    artifacts_required: ['Independent assessment results (from a FedRAMP-recognized 3PAO or FedRAMP directly), included unmodified in authorization data'],
    remediation_steps: [
      'Engage a FedRAMP-recognized independent assessor (or use FedRAMP-direct assessment) to assess goals and validation processes.',
      'Include the results unmodified in the authorization data.',
      'Attach the assessment artifact.',
    ],
    alternative_satisfiers: [{
      via: 'FedRAMP-direct assessment (in lieu of a 3PAO)',
      description: 'FedRAMP may assess the offering directly; the FedRAMP-issued assessment artifact satisfies independent verification.',
      evidence_required: ['FedRAMP-issued assessment artifact', 'Inclusion in the authorization data, unmodified'],
      detected: false,
      detection_signals: ['fedramp assessment', '3pao'],
    }],
    nist_controls: ['ca-2', 'ca-2.1', 'ca-7'],
    references: [REF.pva],
  },
  // PVA-TPX-* obligate the assessor (3PAO) — awareness items.
  'PVA-TPX-UNP': {
    artifacts_required: ['Awareness: assessor verifies/validates the underlying machine + non-machine validation processes'],
    remediation_steps: ['Awareness item — assessor (3PAO) obligation. Provider should support the assessor\'s process verification.'],
    alternative_satisfiers: none(),
    nist_controls: ['ca-2', 'ca-7'],
    references: [REF.pva],
  },
  'PVA-TPX-PDK': {
    artifacts_required: ['Awareness: assessor verifies implementation of KSI-derived processes against documented process/goals'],
    remediation_steps: ['Awareness item — assessor obligation.'],
    alternative_satisfiers: none(),
    nist_controls: ['ca-2', 'ca-7'],
    references: [REF.pva],
  },
  'PVA-TPX-OUC': {
    artifacts_required: ['Awareness: assessor validates the processes consistently produce the documented security outcome'],
    remediation_steps: ['Awareness item — assessor obligation; provider may supply historical pass-rate trend data.'],
    alternative_satisfiers: none(),
    nist_controls: ['ca-7', 'ca-7.4'],
    references: [REF.pva],
  },
  'PVA-TPX-MME': {
    artifacts_required: ['Awareness: assessor uses mixed quantitative + qualitative methods, documenting which applies where'],
    remediation_steps: ['Awareness item — assessor obligation.'],
    alternative_satisfiers: none(),
    nist_controls: ['ca-2'],
    references: [REF.pva],
  },
  'PVA-TPX-PEX': {
    artifacts_required: ['Awareness: assessor engages provider experts and does independent research'],
    remediation_steps: ['Awareness item — assessor obligation; provider should make experts available.'],
    alternative_satisfiers: none(),
    nist_controls: ['ca-2'],
    references: [REF.pva],
  },
  'PVA-TPX-STE': {
    artifacts_required: ['Awareness: assessor must not rely on static evidence (screenshots/config dumps) except to test the generating process'],
    remediation_steps: ['Awareness item — assessor obligation.'],
    alternative_satisfiers: none(),
    nist_controls: ['ca-2', 'ca-7'],
    references: [REF.pva],
  },
  'PVA-TPX-PAD': {
    artifacts_required: ['Awareness: assessor verifies procedures are consistently followed (not just documented)'],
    remediation_steps: ['Awareness item — assessor obligation.'],
    alternative_satisfiers: none(),
    nist_controls: ['ca-2', 'ca-7'],
    references: [REF.pva],
  },
  'PVA-TPX-SUM': {
    artifacts_required: ['Awareness: assessor delivers a per-KSI assessment summary, included in the authorization data'],
    remediation_steps: ['Awareness item — assessor obligation; the summary becomes part of the provider\'s authorization data.'],
    alternative_satisfiers: none(),
    nist_controls: ['ca-2', 'ca-7'],
    references: [REF.pva],
  },
  'PVA-TPX-NOR': {
    artifacts_required: ['Awareness: assessor must NOT deliver an overall authorization recommendation (FedRAMP decides)'],
    remediation_steps: ['Awareness item — assessor obligation.'],
    alternative_satisfiers: none(),
    nist_controls: ['ca-2'],
    references: [REF.pva],
  },
  'PVA-TPX-SHA': {
    artifacts_required: ['Awareness: assessor may share improvement advice unless it compromises objectivity'],
    remediation_steps: ['Awareness item — assessor permissive option.'],
    alternative_satisfiers: none(),
    nist_controls: ['ca-2'],
    references: [REF.pva],
  },

  // ════════════════════════════════════════════════════════════════════════
  // SCG — Secure Configuration Guide
  // ════════════════════════════════════════════════════════════════════════
  'SCG-CSO-RSC': {
    artifacts_required: ['Maintained Secure Configuration Guide covering secure access/config/operation/decommission of top-level admin accounts and security settings'],
    remediation_steps: [
      'Author and maintain a Secure Configuration Guide for the offering.',
      'Cover at least the required topics (admin-account lifecycle, security settings) per the FedRAMP RSC/SCG standard.',
      'Make it available (publicly preferred); record the URL.',
    ],
    alternative_satisfiers: [{
      via: 'Published CIS-benchmark-aligned hardening guide + machine-readable benchmark (OSCAL/SCAP)',
      description: 'A published hardening guide aligned to CIS benchmarks, with an OSCAL/SCAP machine-readable file, serves as the SCG.',
      evidence_required: ['Public guide URL', 'Machine-readable benchmark file (OSCAL/SCAP)'],
      detected: false,
      detection_signals: ['cis benchmark', 'oscal', 'scap'],
    }],
    nist_controls: ['cm-2', 'cm-6', 'cm-6.1', 'sa-5'],
    references: [REF.scg],
  },
  'SCG-CSO-AUP': {
    artifacts_required: ['Instructions in the authorization package explaining how to obtain and use the Secure Configuration Guide'],
    remediation_steps: [
      'Add instructions to the authorization package explaining how to obtain and use the SCG.',
      'Link the public SCG (overlaps SCG-CSO-PUB).',
      'Verify the link resolves.',
    ],
    alternative_satisfiers: [grcAlt()],
    nist_controls: ['sa-5', 'cm-6'],
    references: [REF.scg],
  },
  'SCG-CSO-PUB': {
    artifacts_required: ['Publicly available Secure Configuration Guide URL'],
    remediation_steps: [
      'Publish the SCG publicly (docs site / GitHub Pages / Trust Center).',
      'Record the public URL and verify reachability.',
    ],
    alternative_satisfiers: [trustCenterAlt()],
    nist_controls: ['sa-5', 'cm-6'],
    references: [REF.scg],
  },
  'SCG-CSO-SDF': {
    artifacts_required: ['Evidence that top-level admin/privileged accounts are provisioned with recommended secure defaults (IaC/landing-zone enforcement)'],
    remediation_steps: [
      'Set recommended secure defaults for top-level admin and privileged accounts at provisioning time.',
      'Enforce via a landing-zone/IaC module (Control Tower, Terraform Landing Zone, GCP org policies).',
      'Attach the IaC template / org-policy bundle.',
    ],
    alternative_satisfiers: [{
      via: 'Landing-zone / IaC baseline (AWS Control Tower, Terraform Landing Zone, GCP org policies)',
      description: 'A landing-zone module enforces secure defaults at provisioning, evidencing secure-by-default.',
      evidence_required: ['IaC template / org-policy bundle', 'Provisioned-account config showing the defaults applied'],
      detected: false,
      detection_signals: ['control tower', 'landing zone', 'org-policy'],
    }],
    nist_controls: ['cm-2', 'cm-6', 'cm-6.1', 'ac-6'],
    references: [REF.scg],
  },
  'SCG-ENH-API': {
    artifacts_required: ['Customer-facing capability (API or similar) to view and adjust the product\'s security settings'],
    remediation_steps: [
      'Offer customers an API (or config-as-code provider) to view and adjust security settings of the CSP product.',
      'Document the capability.',
      'Attach the API docs / registry entry.',
    ],
    alternative_satisfiers: [{
      via: 'Terraform/Pulumi provider for the CSP product',
      description: 'A published config-as-code provider is the "similar capability" letting customers manage security settings.',
      evidence_required: ['Published provider/registry entry', 'Docs covering the security settings'],
      detected: false,
      detection_signals: ['terraform provider', 'pulumi provider'],
    }],
    nist_controls: ['cm-6', 'ac-3', 'sa-5'],
    references: [REF.scg],
  },
  'SCG-ENH-EXP': {
    artifacts_required: ['Capability to export all security settings in a machine-readable format'],
    remediation_steps: [
      'Offer customers a machine-readable export of all security settings.',
      'Attach a sample export.',
    ],
    alternative_satisfiers: [{
      via: 'Config-as-code export (Terraform state/HCL)',
      description: 'Config-as-code export of security settings provides the machine-readable export.',
      evidence_required: ['Sample export file (HCL/JSON)'],
      detected: false,
      detection_signals: ['terraform', 'pulumi'],
    }],
    nist_controls: ['cm-6', 'au-7', 'sa-5'],
    references: [REF.scg],
  },
  'SCG-ENH-CMP': {
    artifacts_required: ['Capability to compare current settings for top-level admin/privileged accounts against recommended secure defaults (drift/diff)'],
    remediation_steps: [
      'Offer customers a drift/diff feature comparing current settings to recommended secure defaults.',
      'Attach a sample comparison output.',
    ],
    alternative_satisfiers: [{
      via: 'CSPM / posture tool (Prowler, Steampipe/Powerpipe, GCP SCC, AWS Security Hub)',
      description: 'A CSPM tool the customer runs produces the same settings-vs-defaults diff.',
      evidence_required: ['CSPM tool config', 'Sample comparison/diff report'],
      detected: false,
      detection_signals: ['prowler', 'steampipe', 'powerpipe', 'security hub', 'scc'],
    }],
    nist_controls: ['cm-6', 'cm-2.2', 'ca-7'],
    references: [REF.scg],
  },
  'SCG-ENH-MRG': {
    artifacts_required: ['Secure Configuration Guide also published in a machine-readable format (SCAP/OVAL/OSCAL) usable by customers/tools'],
    remediation_steps: [
      'Publish the SCG itself in a machine-readable format (SCAP/OVAL/OSCAL profile).',
      'Ensure it can be used to compare against current settings.',
      'Attach the machine-readable file.',
    ],
    alternative_satisfiers: [{
      via: 'Machine-readable benchmark (SCAP/OSCAL) + Config conformance pack / SCC posture',
      description: 'Publishing the guide as a SCAP/OSCAL profile (or an AWS Config conformance pack / GCP SCC posture analog) satisfies machine-readable guidance.',
      evidence_required: ['Valid SCAP/OSCAL file', 'Conformance pack / posture definition if used'],
      detected: false,
      detection_signals: ['scap', 'oscal', 'conformance pack'],
    }],
    nist_controls: ['cm-6', 'sa-5'],
    references: [REF.scg],
  },
  'SCG-ENH-VRH': {
    artifacts_required: ['Versioning + release history for the recommended secure defaults as they change over time'],
    remediation_steps: [
      'Maintain versioning and a release history for the recommended secure defaults.',
      'Use git tags / GitHub Releases / a CHANGELOG on the SCG repo.',
      'Attach the tag/release list.',
    ],
    alternative_satisfiers: [{
      via: 'Git tags / GitHub Releases + CHANGELOG on the SCG repo',
      description: 'Version-control tags/releases and a CHANGELOG provide the versioning + release history.',
      evidence_required: ['Tag/release list', 'CHANGELOG.md'],
      detected: false,
      detection_signals: ['github releases', 'git tag', 'changelog'],
    }],
    nist_controls: ['cm-2.3', 'cm-6', 'sa-5', 'sa-10'],
    references: [REF.scg],
  },

  // ════════════════════════════════════════════════════════════════════════
  // UCM — Using Cryptographic Modules
  // ════════════════════════════════════════════════════════════════════════
  'UCM-CSX-CMD': {
    artifacts_required: ['Cryptographic-module inventory: per service (or group sharing modules) protecting federal customer data, the module and whether it is CMVP-validated or an update stream thereof'],
    remediation_steps: [
      'Identify every service where cryptography protects federal customer data.',
      'Document the module used by each (or each group sharing modules) and its CMVP status (validated / update stream).',
      'For inherited crypto, capture the subprocessor\'s CMVP attestation.',
      'Maintain the inventory in the register.',
    ],
    alternative_satisfiers: [cmvpAlt()],
    nist_controls: ['sc-13', 'sc-12', 'sc-8.1', 'ia-7', 'sa-9'],
    references: [REF.ucm, REF.cmvp],
  },
  'UCM-CSX-CAT': {
    artifacts_required: ['Evidence agency tenants default to CMVP-validated crypto where available (FIPS-enabled node pools / AMIs / provisioning baseline)'],
    remediation_steps: [
      'Configure agency tenants by default to use CMVP-validated cryptographic services where available.',
      'Pin validated-crypto defaults in the provisioning/landing-zone module (FIPS GKE node pools, FIPS AMIs).',
      'Attach the IaC baseline / node-pool/AMI flags.',
    ],
    alternative_satisfiers: [cmvpAlt()],
    nist_controls: ['sc-13', 'cm-6', 'cm-6.1'],
    references: [REF.ucm, REF.cmvp],
  },
  'UCM-CSX-UVM': {
    artifacts_required: ['Evidence that cryptographic services protecting federal customer data use modules with active CMVP validations (or update streams), with CMVP cert numbers'],
    remediation_steps: [
      'Use cryptographic modules with active CMVP validations (or update streams) wherever crypto protects federal customer data.',
      'Capture the CMVP certificate numbers and map them to services.',
      'Note the level-scaled obligation: Low MAY, Moderate SHOULD, High MUST.',
      'For inherited crypto, attach the subprocessor\'s CMVP attestation.',
    ],
    alternative_satisfiers: [cmvpAlt()],
    nist_controls: ['sc-13', 'sc-12', 'sc-8.1', 'ia-7'],
    references: [REF.ucm, REF.cmvp],
  },

  // ════════════════════════════════════════════════════════════════════════
  // MAS — Minimum Assessment Scope
  // ════════════════════════════════════════════════════════════════════════
  'MAS-CSO-FLO': {
    artifacts_required: ['Documented information flows and security objectives for all information resources in the CSO'],
    remediation_steps: [
      'Identify, document, and explain information flows and security objectives for every information resource (or set) in the CSO.',
      'Include third-party information resources that handle data.',
      'Maintain as a data-flow/architecture diagram or architecture-as-code.',
    ],
    alternative_satisfiers: [{
      via: 'CSPM topology export / architecture-as-code (Wiz, Lacework, Terraform graph)',
      description: 'A CSPM topology export or maintained Terraform graph documents the information flows.',
      evidence_required: ['Topology/data-flow export', 'Security objectives annotated per resource'],
      detected: false,
      detection_signals: ['wiz', 'lacework', 'terraform graph'],
    }],
    nist_controls: ['ac-4', 'pl-2', 'ca-3'],
    references: [REF.mas],
  },
  'MAS-CSO-IIR': {
    artifacts_required: ['Identified set of information resources to assess — all IRs likely to handle federal customer data or impact its CIA (this set is the CSO)'],
    remediation_steps: [
      'Identify all information resources likely to handle federal customer data or impact its CIA.',
      'Treat that set as the cloud service offering / Minimum Assessment Scope.',
      'Maintain the authoritative inventory.',
    ],
    alternative_satisfiers: [{
      via: 'CNAPP / CMDB authoritative inventory (Wiz, Lacework, ServiceNow CMDB)',
      description: 'A CNAPP/CMDB asset inventory serves as the authoritative discovery source for the scope.',
      evidence_required: ['Asset inventory export', 'Mapping of which assets handle federal customer data'],
      detected: false,
      detection_signals: ['wiz', 'lacework', 'cmdb', 'servicenow'],
    }],
    nist_controls: ['cm-8', 'pm-5'],
    references: [REF.mas],
  },
  'MAS-CSO-MDI': {
    artifacts_required: ['Metadata (including metadata about federal customer data) included in the Minimum Assessment Scope (only if MAS-CSO-IIR applies)'],
    remediation_steps: [
      'If MAS-CSO-IIR applies, include relevant metadata (including metadata about federal customer data) in the assessment scope.',
      'Use the same inventory tooling as IIR.',
    ],
    alternative_satisfiers: [grcAlt()],
    nist_controls: ['cm-8'],
    references: [REF.mas],
  },
  'MAS-CSO-SUP': {
    artifacts_required: ['Optional package supplement of materials about non-CSO information resources, clearly marked and separated'],
    remediation_steps: ['If including supplemental materials about IRs not part of the CSO, clearly mark and separate them; note they are not FedRAMP-authorized. Permissive.'],
    alternative_satisfiers: none(),
    nist_controls: [],
    references: [REF.mas],
  },
  'MAS-CSO-TPR': {
    artifacts_required: ['For each third-party information resource (only if MAS-CSO-IIR applies): usage/config, justification, mitigations reducing impact to federal customer data, and compensating controls'],
    remediation_steps: [
      'For each third-party information resource used by the CSO, document: (1) general usage/configuration; (2) justification for use; (3) mitigation measures; (4) compensating controls.',
      'Maintain a subprocessor/vendor register.',
      'Address potential impact to federal customer data.',
    ],
    alternative_satisfiers: [{
      via: 'GRC subprocessor/vendor register (Vanta, Drata vendor module)',
      description: 'A GRC vendor-risk module maintains the third-party inventory with usage, justification, and mitigations.',
      evidence_required: ['Vendor/subprocessor register export', 'Per-vendor mitigation + compensating-control documentation'],
      detected: false,
      detection_signals: ['vanta', 'drata', 'vendor risk'],
    }],
    nist_controls: ['sa-9'],
    references: [REF.mas],
  },

  // ════════════════════════════════════════════════════════════════════════
  // CED — Cybersecurity Education (training KSIs)
  // ════════════════════════════════════════════════════════════════════════
  'KSI-CED-DET': {
    artifacts_required: ['Review of the effectiveness of role-specific secure-development training for dev/engineering staff (completion + effectiveness metrics)'],
    remediation_steps: [
      'Deliver role-specific secure-software training to dev/engineering staff.',
      'Persistently review its effectiveness (not just completion) — e.g. secure-code assessment results.',
      'Reconcile completion against the IdP/HRIS roster.',
      'Record the review + metrics.',
    ],
    alternative_satisfiers: [knowBe4Alt()],
    nist_controls: ['cp-3', 'ir-2', 'ps-6'],
    sla: QUARTERLY,
    references: [REF.ced],
  },
  'KSI-CED-RGT': {
    artifacts_required: ['Review of the effectiveness of general security training for all employees (e.g. phish-prone % + completion)'],
    remediation_steps: [
      'Deliver general security-awareness training to all employees.',
      'Persistently review its effectiveness (e.g. KnowBe4 phish-prone %).',
      'Prove coverage: 100% of active IdP users completed.',
      'Record the review + metrics.',
    ],
    alternative_satisfiers: [knowBe4Alt()],
    nist_controls: ['at-2', 'at-2.2', 'at-2.3', 'at-3.5', 'at-4', 'ir-2.3'],
    sla: QUARTERLY,
    references: [REF.ced],
  },
  'KSI-CED-RRT': {
    artifacts_required: ['Review of the effectiveness of response/recovery training for incident-response and disaster-recovery staff (e.g. tabletop/exercise records)'],
    remediation_steps: [
      'Deliver role-specific incident-response / disaster-recovery training.',
      'Persistently review its effectiveness via tabletop exercises / post-incident review participation.',
      'Record the exercise results + review.',
    ],
    alternative_satisfiers: [{
      via: 'Tabletop / cyber-range platform + PagerDuty PIR participation (AttackIQ, RangeForce)',
      description: 'Exercise-platform records and post-incident-review participation evidence the effectiveness of response/recovery training.',
      evidence_required: ['Exercise/tabletop records', 'PIR participation logs'],
      detected: false,
      detection_signals: ['attackiq', 'rangeforce', 'pagerduty'],
    }],
    nist_controls: ['ir-2', 'ir-2.3', 'cp-3'],
    sla: QUARTERLY,
    references: [REF.ced],
  },
  'KSI-CED-RST': {
    artifacts_required: ['Review of the effectiveness of role-specific training for high-risk roles (at minimum, privileged-access roles)'],
    remediation_steps: [
      'Deliver role-specific training for high-risk roles, at minimum those with privileged access.',
      'Persistently review its effectiveness.',
      'Reconcile against the privileged-role roster.',
      'Record the review + metrics.',
    ],
    alternative_satisfiers: [knowBe4Alt()],
    nist_controls: ['at-2', 'at-2.3', 'at-3', 'sr-11.1'],
    sla: QUARTERLY,
    references: [REF.ced],
  },

  // ════════════════════════════════════════════════════════════════════════
  // VDR — Vulnerability Detection and Response
  // ════════════════════════════════════════════════════════════════════════
  'VDR-AGM-DRE': {
    artifacts_required: ['Awareness: agency does not request vuln info beyond FedRAMP\'s baseline without a documented need'],
    remediation_steps: ['Awareness item — agency obligation. If an out-of-band request arrives, log it (e.g. tagged vdr-extra-info).'],
    alternative_satisfiers: none(),
    nist_controls: ['ca-7'],
    references: [REF.vdr],
  },
  'VDR-AGM-MAP': {
    artifacts_required: ['Awareness: agency folds provider-reported vuln info into its own POA&Ms'],
    remediation_steps: ['Awareness item — agency obligation (agency-side POA&M / eMASS).'],
    alternative_satisfiers: none(),
    nist_controls: ['ca-5'],
    references: [REF.vdr],
  },
  'VDR-AGM-NFR': {
    artifacts_required: ['Awareness: agency emails info@fedramp.gov after requesting extra vuln info'],
    remediation_steps: ['Awareness item — agency obligation; provider may retain a copy of the notification.'],
    alternative_satisfiers: none(),
    nist_controls: [],
    references: [REF.vdr],
  },
  'VDR-AGM-RVR': {
    artifacts_required: ['Awareness: agency reviews provider vuln reports at intervals matching its ATO risk posture'],
    remediation_steps: ['Awareness item — agency obligation; provider should supply a machine-readable feed (see VDR-TFR-MRH).'],
    alternative_satisfiers: none(),
    nist_controls: ['ca-7'],
    references: [REF.vdr],
  },
  'VDR-BST-ADT': {
    artifacts_required: ['Evidence automated detection services are enabled and running (scanner config + last-run logs)'],
    remediation_steps: [
      'Enable automated services to streamline vulnerability detection and response.',
      'Confirm scanners are enabled and running across the CSO.',
      'Attach the scanner SaaS config export + last-run logs.',
    ],
    alternative_satisfiers: [scannerAlt('Wiz/Prisma/Orca/Lacework (agentless), Tenable/Qualys (host), Snyk (SCA/container).')],
    nist_controls: ['ra-5', 'ra-5.2'],
    references: [REF.vdr],
  },
  'VDR-BST-AKE': {
    artifacts_required: ['Evidence newly deployed machine-based resources are gated against KEVs (admission control / scan-on-push)'],
    remediation_steps: [
      'Block deployment/activation of new machine-based resources carrying a Known Exploited Vulnerability.',
      'Enforce via admission control (Kyverno/Gatekeeper, GKE Binary Authorization, ECR scan-on-push gate) or scanner KEV-aware deploy policy.',
      'Attach the policy + a sample blocked-deploy record.',
    ],
    alternative_satisfiers: [scannerAlt('KEV-aware deploy policy; admission controllers blocking KEV images.')],
    nist_controls: ['si-2', 'ra-5'],
    references: [REF.vdr, REF.kev],
  },
  'VDR-BST-DAC': {
    artifacts_required: ['CI/CD scan stage running detection on representative samples of new/changed resources before deploy'],
    remediation_steps: [
      'Add a vulnerability-scan stage to the change/CI-CD pipeline (Trivy/Grype/Snyk or scanner change-triggered scan).',
      'Run detection on representative samples of new or significantly changed resources.',
      'Attach the pipeline YAML showing the scan gate.',
    ],
    alternative_satisfiers: [scannerAlt('CI/CD scan stage; change-triggered scan in Wiz/Prisma.')],
    nist_controls: ['ra-5', 'si-2', 'cm-3'],
    references: [REF.vdr],
  },
  'VDR-BST-DFR': {
    artifacts_required: ['Architecture decision records / well-architected review output showing resilience-by-default choices (immutable infra, minimal images, segmentation, managed services)'],
    remediation_steps: [
      'Make architecture/design choices that mitigate vulnerability risk by default.',
      'Document them (ADRs, well-architected review output).',
      'Attach the design records.',
    ],
    alternative_satisfiers: none(),
    nist_controls: ['sa-8', 'sc-7', 'cm-6'],
    references: [REF.vdr],
  },
  'VDR-BST-MSP': {
    artifacts_required: ['Scanner-access design doc showing detection does not weaken security (prefer agentless/side-scanning; no scanner-specific ingress holes)'],
    remediation_steps: [
      'Do not weaken information-resource security to enable scanning (no opened firewalls, no disabled auth for an agent).',
      'Prefer agentless/side-scanning (Wiz/Orca) that needs no inbound holes.',
      'Attach the scanner-access design doc evidencing the absence of security degradation.',
    ],
    alternative_satisfiers: [scannerAlt('Agentless side-scanning (Wiz/Orca) needs no inbound holes.')],
    nist_controls: ['cm-6', 'ra-5', 'sc-7'],
    references: [REF.vdr],
  },
  'VDR-BST-SIR': {
    artifacts_required: ['Sampling methodology document for effectively-identical resources (UNLESS sampling reduces detection efficiency)'],
    remediation_steps: ['Optionally sample effectively-identical machine-based resources during detection; document the methodology, and do not sample where it reduces effectiveness. Permissive.'],
    alternative_satisfiers: [scannerAlt('Scanner-native sampling config (e.g. Inspector coverage by tag).')],
    nist_controls: ['ra-5'],
    references: [REF.vdr],
  },
  'VDR-CSO-DET': {
    artifacts_required: ['Documented vulnerability-detection methodology covering the whole CSO (scanning, threat intel, VDP, bug bounty, supply-chain monitoring) running persistently and promptly'],
    remediation_steps: [
      'Persistently and promptly discover vulnerabilities across the whole CSO using appropriate techniques.',
      'Cover assessment, scanning, threat intel, VDP, bug bounty, and supply-chain monitoring.',
      'Attach scanner config + the VDP/bug-bounty program artifacts.',
    ],
    alternative_satisfiers: [scannerAlt('Full-stack coverage (Wiz/Prisma/Orca/Lacework, Tenable, Snyk).'), bugBountyAlt()],
    nist_controls: ['ra-5', 'ra-5.2', 'si-5', 'sr-6'],
    references: [REF.vdr],
  },
  'VDR-CSO-DOC': {
    artifacts_required: ['Deviation register: for each declined FedRAMP recommendation (SHOULD), the reason + customer implications, included in authorization data'],
    remediation_steps: [
      'When declining a FedRAMP recommendation (a SHOULD), document the reason and customer implications.',
      'Include that documentation in the CSO\'s authorization data.',
      'Maintain a deviation register.',
    ],
    alternative_satisfiers: [grcAlt('Paramify / OSCAL SSP narrative entries.')],
    nist_controls: ['pl-2', 'ca-1'],
    references: [REF.vdr],
  },
  'VDR-CSO-RES': {
    artifacts_required: ['Vulnerability-response ledger showing track→evaluate→monitor→mitigate→remediate→report state transitions for all detected vulnerabilities, run persistently and promptly'],
    remediation_steps: [
      'Persistently and promptly track, evaluate, monitor, mitigate, remediate, assess-exploitation-of, and report all detected vulnerabilities.',
      'Maintain a vulnerability ledger with state transitions.',
      'Attach the ledger export.',
    ],
    alternative_satisfiers: [scannerAlt('Wiz/Prisma issue lifecycle; DefectDojo vuln-mgmt.'), ticketingAlt()],
    nist_controls: ['si-2', 'ra-5', 'ca-7', 'ir-4'],
    references: [REF.vdr],
  },
  'VDR-EVA-EFA': {
    artifacts_required: ['Evaluation rubric documenting the ≥8 factors (Criticality, Reachability, Exploitability, Detectability, Prevalence, Privilege, Proximate Vulnerabilities, Known Threats)'],
    remediation_steps: [
      'Define an evaluation rubric covering the ≥8 named factors.',
      'Apply it when evaluating detected vulnerabilities in CSO context.',
      'Attach the rubric.',
    ],
    alternative_satisfiers: [scannerAlt('Contextual risk scoring (CVSS+EPSS+reachability).')],
    nist_controls: ['ra-3', 'ra-5'],
    references: [REF.vdr],
  },
  'VDR-EVA-EFP': {
    artifacts_required: ['False-positive disposition log distinguishing real vulnerabilities from spurious findings'],
    remediation_steps: [
      'Evaluate detected vulnerabilities in CSO context to identify false positives (present but not loaded/running).',
      'Record dispositions with an audit trail.',
      'Attach the FP-disposition log.',
    ],
    alternative_satisfiers: [scannerAlt('FP-disposition workflow with audit trail.')],
    nist_controls: ['ra-5'],
    references: [REF.vdr],
  },
  'VDR-EVA-EIR': {
    artifacts_required: ['Internet-reachability evaluation per vuln (IRV yes/no via attack-path/exposure analysis)'],
    remediation_steps: [
      'Evaluate each detected vulnerability for internet-reachability (IRV).',
      'Use attack-path/exposure (network reachability) analysis.',
      'Record the IRV determination feeding the VDR-TFR SLAs.',
    ],
    alternative_satisfiers: [scannerAlt('Wiz/Orca attack-path / exposure analysis.')],
    nist_controls: ['ra-5', 'sc-7', 'ca-3'],
    references: [REF.vdr],
  },
  'VDR-EVA-ELX': {
    artifacts_required: ['Exploitability evaluation per vuln (LEV yes/no: not fully mitigated AND reachable AND likely actor could gain access/cause harm)'],
    remediation_steps: [
      'Evaluate each detected vulnerability for likely-exploitability (LEV).',
      'Fuse EPSS + KEV + reachability + context.',
      'Record the LEV determination feeding the VDR-TFR SLAs and incident bridges.',
    ],
    alternative_satisfiers: [scannerAlt('Exploitability scoring (EPSS+KEV+reachability); Tenable VPR.')],
    nist_controls: ['ra-5', 'ra-3'],
    references: [REF.vdr],
  },
  'VDR-EVA-EPA': {
    artifacts_required: ['Potential Adverse Impact (PAIN) N1–N5 rating per vuln, estimating cumulative harm to agency customers'],
    remediation_steps: [
      'Assign a Potential Adverse Impact (PAIN) rating N1–N5 to each detected vulnerability.',
      'Use the FedRAMP scale (N1 negligible … N5 catastrophic to >1 agency).',
      'Maintain the per-finding N-rating ledger driving PVR remediation SLAs and incident bridges.',
    ],
    alternative_satisfiers: [scannerAlt('Business-impact scoring with crown-jewel tagging.')],
    nist_controls: ['ra-3', 'ra-2'],
    references: [REF.vdr],
  },
  'VDR-EVA-GRV': {
    artifacts_required: ['Grouping of vulnerabilities by logical clusters of affected resources, with grouping rationale'],
    remediation_steps: [
      'Group detected vulnerabilities by logical clusters of affected resources to make response efficient.',
      'Apply subsequent VDR requirements to the group.',
      'Document the grouping rationale.',
    ],
    alternative_satisfiers: [scannerAlt('Issue-grouping by image/package; DefectDojo finding-grouping.')],
    nist_controls: ['ra-5'],
    references: [REF.vdr],
  },
  'VDR-FRP-ADV': {
    artifacts_required: ['Awareness: FedRAMP may require sharing extra/sensitive vuln detail; record when shared on request'],
    remediation_steps: ['Awareness item — FedRAMP option. Comply if asked; record that sensitive detail was shared via a secure channel.'],
    alternative_satisfiers: none(),
    nist_controls: [],
    references: [REF.vdr],
  },
  'VDR-FRP-ARP': {
    artifacts_required: ['Awareness: FedRAMP may require extra vuln info / alternative reports / cadence as a CAP condition; record the adjusted cadence'],
    remediation_steps: ['Awareness item — FedRAMP option. If directed via a CAP, record the adjusted reporting cadence and comply.'],
    alternative_satisfiers: none(),
    nist_controls: [],
    references: [REF.vdr],
  },
  'VDR-RPT-AVI': {
    artifacts_required: ['Accepted-vulnerability report section with the 8 required fields (tracking ID; detection time+source; evaluation time; IRV?; LEV?; current PAIN; why accepted; supplementary risk info)'],
    remediation_steps: [
      'For each accepted vulnerability, include the 8 required fields in the report.',
      'Validate completeness before publishing.',
      'Attach the AVI report section.',
    ],
    alternative_satisfiers: [scannerAlt('"Risk accepted" records with required metadata (Wiz/DefectDojo).')],
    nist_controls: ['ca-5', 'pm-4', 'ra-5'],
    references: [REF.vdr],
  },
  'VDR-RPT-HLO': {
    artifacts_required: ['High-level overviews of all detection/response activity (VDP, bug bounty, pentests, assessments) in the period'],
    remediation_steps: [
      'Include high-level overviews of all detection/response activity in each report.',
      'Cover the non-cloud detection arms (VDP, bug bounty, pentests, assessments).',
      'Attach the report overview section.',
    ],
    alternative_satisfiers: [bugBountyAlt()],
    nist_controls: ['ca-7', 'ra-5'],
    references: [REF.vdr],
  },
  'VDR-RPT-NID': {
    artifacts_required: ['Disclosure policy + redaction profile balancing no-irresponsible-disclosure with enough info for necessary parties to make risk decisions'],
    remediation_steps: [
      'Do not irresponsibly disclose sensitive vuln detail that would likely lead to exploitation.',
      'Disclose enough for all necessary parties to make informed risk decisions.',
      'Attach the disclosure policy + redaction profile.',
    ],
    alternative_satisfiers: [grcAlt('Tiered-disclosure workflow in GRC.')],
    nist_controls: ['si-5', 'ra-5.5'],
    references: [REF.vdr],
  },
  'VDR-RPT-PER': {
    artifacts_required: ['Persistent vuln reports to all necessary parties, each summarizing all activity since the previous one, as authorization data (ADS process)'],
    remediation_steps: [
      'Persistently report detection/response activity to all necessary parties.',
      'Each report summarizes all activity since the previous one.',
      'Treat reports as authorization data subject to the ADS process; retain ADS submission receipts.',
    ],
    alternative_satisfiers: [grcAlt('Vanta/Drata continuous reporting; Trust Center.')],
    nist_controls: ['ca-7', 'pm-31'],
    references: [REF.vdr],
  },
  'VDR-RPT-RPD': {
    artifacts_required: ['Optional public-disclosure decision log + the no-likely-exploitation determination'],
    remediation_steps: ['If publicly disclosing a vulnerability (or sharing with other parties), record the determination that it will not likely lead to exploitation. Permissive — gated by provider judgment.'],
    alternative_satisfiers: [{
      via: 'CVE Numbering Authority workflow / public security advisory page',
      description: 'A CNA workflow or public advisory page documents the responsible public-disclosure decision.',
      evidence_required: ['Advisory / CVE record', 'Disclosure-decision log'],
      detected: false,
      detection_signals: ['cve', 'security advisory'],
    }],
    nist_controls: ['si-5'],
    references: [REF.vdr],
  },
  'VDR-RPT-VDT': {
    artifacts_required: ['Per-vuln report section with the 11 required fields (tracking ID; detection time+source; evaluation time; IRV?; LEV?; historical+current PAIN; each PAIN-reduction time+level; next reduction time+target; overdue?; supplementary risk info; final disposition)'],
    remediation_steps: [
      'For each non-accepted vulnerability, include the 11 required fields (if applicable) in the report.',
      'Validate completeness before publishing.',
      'Attach the VDT report section.',
    ],
    alternative_satisfiers: [scannerAlt('Finding export mapped to the 11 fields (Wiz/Prisma/DefectDojo).')],
    nist_controls: ['ca-7', 'ra-5', 'pm-4'],
    references: [REF.vdr],
  },
  'VDR-TFR-EVU': {
    artifacts_required: ['Evidence VDR evaluation of all vulns completes within the time limit (7 days Low / 5 days Moderate / 2 days High of detection)'],
    remediation_steps: [
      'Complete VDR-EVA evaluation of all vulnerabilities within the time limit (Low 7 / Moderate 5 / High 2 days of detection).',
      'Track detection→evaluation latency.',
      'Attach the SLA report.',
    ],
    alternative_satisfiers: [scannerAlt('SLA dashboards measuring triage time.')],
    nist_controls: ['ra-5', 'ra-3'],
    sla: { calendarDays: 5, cadence: 'evaluate all vulns within 7 days (Low) / 5 days (Moderate) / 2 days (High) of detection' },
    references: [REF.vdr],
  },
  'VDR-TFR-IRI': {
    artifacts_required: ['Incident records: IRV that is also LEV with PAIN N4/N5 treated as a security incident until partially mitigated to ≤N3'],
    remediation_steps: [
      'Treat an internet-reachable + likely-exploitable vuln with PAIN N4/N5 as a security incident.',
      'Maintain incident status until partially mitigated to N3 or below.',
      'Bridge into the incident-response process (INR / ICP).',
    ],
    alternative_satisfiers: [soarAlt('Auto-incident creation (Tines/Torq, PagerDuty).')],
    nist_controls: ['ir-4', 'ir-6', 'ra-5'],
    references: [REF.vdr],
  },
  'VDR-TFR-KEV': {
    artifacts_required: ['KEV remediation report showing Known Exploited Vulnerabilities remediated by the CISA KEV Catalog due dates (BOD 22-01)'],
    remediation_steps: [
      'Track CISA KEV Catalog entries affecting the CSO and their per-CVE due dates.',
      'Remediate each by its CISA due date (even if already fully mitigated), per BOD 22-01.',
      'Attach the KEV remediation report.',
    ],
    alternative_satisfiers: [scannerAlt('KEV-prioritized remediation SLA tracking (native KEV enrichment).')],
    nist_controls: ['si-2', 'ra-5'],
    sla: { cadence: 'remediate KEVs by the per-CVE due date in the CISA KEV Catalog (BOD 22-01)' },
    references: [REF.vdr, REF.kev, REF.bod2201],
  },
  'VDR-TFR-MAV': {
    artifacts_required: ['Accepted-vulnerability register: any vuln not (or won\'t be) fully mitigated/remediated within 192 days of evaluation categorized as accepted'],
    remediation_steps: [
      'Track time-since-evaluation for every open vulnerability.',
      'Categorize as an Accepted Vulnerability any not fully mitigated/remediated within 192 days of evaluation.',
      'Maintain the accepted-vuln register.',
    ],
    alternative_satisfiers: [scannerAlt('Auto-aging into "risk accepted" (Wiz/DefectDojo).')],
    nist_controls: ['ca-5', 'ra-5'],
    sla: { calendarDays: 192, cadence: 'mark as accepted any vuln not fully mitigated within 192 days of evaluation' },
    references: [REF.vdr],
  },
  'VDR-TFR-MHR': {
    artifacts_required: ['Monthly, consistent, human-readable vulnerability detection/response activity report to all necessary parties'],
    remediation_steps: [
      'Report detection/response activity to all necessary parties at least monthly.',
      'Use a consistent, human-readable format (companion to the machine feed in VDR-TFR-MRH).',
      'Attach the monthly reports.',
    ],
    alternative_satisfiers: [grcAlt('Trust Center monthly bulletin; Vanta/Drata report export.')],
    nist_controls: ['ca-7', 'pm-31'],
    sla: MONTHLY,
    references: [REF.vdr],
  },
  'VDR-TFR-MRH': {
    artifacts_required: ['Machine-readable historical activity feed (e.g. API) refreshed at least monthly (Low) / every 14 days (Moderate) / every 7 days (High)'],
    remediation_steps: [
      'Publish recent historical detection/response activity in a machine-readable format for automated retrieval.',
      'Refresh persistently: at least monthly (Low) / every 14 days (Moderate) / every 7 days (High).',
      'Attach the feed URL + access-control config.',
    ],
    alternative_satisfiers: [grcAlt('Trust Center API; Vanta/Drata continuous feed; published OSCAL bucket.')],
    nist_controls: ['ca-7', 'pm-31'],
    sla: { calendarDays: 31, cadence: 'refresh machine feed ≥ monthly (Low) / every 14 days (Moderate) / every 7 days (High)' },
    references: [REF.vdr],
  },
  'VDR-TFR-NRI': {
    artifacts_required: ['Incident records: non-internet-reachable LEV with PAIN N5 treated as a security incident until partially mitigated to ≤N4'],
    remediation_steps: [
      'Treat a non-internet-reachable but likely-exploitable vuln with PAIN N5 as a security incident.',
      'Maintain incident status until partially mitigated to N4 or below.',
      'Bridge into the incident-response process.',
    ],
    alternative_satisfiers: [soarAlt('Auto-incident creation (Tines/Torq, PagerDuty).')],
    nist_controls: ['ir-4', 'ir-6', 'ra-5'],
    references: [REF.vdr],
  },
  'VDR-TFR-PCD': {
    artifacts_required: ['Scan-recency evidence for non-drift-prone resources: detection at least every 6 months (Low) / monthly (Moderate, High)'],
    remediation_steps: [
      'Persistently scan all resources not likely to drift.',
      'Meet the recency SLA: at least every 6 months (Low) / monthly (Moderate, High).',
      'Attach the scan-schedule config + last-run log.',
    ],
    alternative_satisfiers: [scannerAlt('Continuous agentless scan (Wiz/Orca); Tenable scheduled scans.')],
    nist_controls: ['ra-5', 'ra-5.2', 'ca-7'],
    sla: { calendarDays: 31, cadence: 'detect non-drift resources ≥ every 6 months (Low) / monthly (Moderate, High)' },
    references: [REF.vdr],
  },
  'VDR-TFR-PDD': {
    artifacts_required: ['Scan-recency evidence for drift-prone resources: detection at least monthly (Low) / every 14 days (Moderate) / every 7 days (High)'],
    remediation_steps: [
      'Persistently scan all resources likely to drift (configs, running software, privileges, processes).',
      'Meet the tighter recency SLA: monthly (Low) / every 14 days (Moderate) / every 7 days (High).',
      'Attach the continuous-scan config.',
    ],
    alternative_satisfiers: [scannerAlt('Continuous scanning; runtime CWPP (CrowdStrike/Lacework).')],
    nist_controls: ['ra-5', 'ra-5.2', 'cm-3', 'ca-7'],
    sla: { calendarDays: 31, cadence: 'detect drift-prone resources ≥ monthly (Low) / every 14 days (Moderate) / every 7 days (High)' },
    references: [REF.vdr],
  },
  'VDR-TFR-PSD': {
    artifacts_required: ['Sample-scan schedule for similar machine-based resources: detection at least every 7 days (Low) / 3 days (Moderate) / daily (High)'],
    remediation_steps: [
      'Persistently detect on representative samples of similar machine-based resources.',
      'Meet the fastest cadence: every 7 days (Low) / 3 days (Moderate) / daily (High).',
      'Attach the sample-scan schedule.',
    ],
    alternative_satisfiers: [scannerAlt('Continuous scanners (Wiz/Orca/Inspector continuous).')],
    nist_controls: ['ra-5', 'ra-5.2'],
    sla: { calendarDays: 7, cadence: 'detect representative samples ≥ every 7 days (Low) / 3 days (Moderate) / daily (High)' },
    references: [REF.vdr],
  },
  'VDR-TFR-PVR': {
    artifacts_required: ['SLA-breach report against the remediation-timeframe matrix (days-from-evaluation by PAIN N2–N5, internet-reachability, and likely-exploitability)'],
    remediation_steps: [
      'Adopt the FedRAMP PVR remediation-timeframe matrix (days from evaluation, varying by PAIN N2–N5, IRV, and LEV).',
      'Reduce each vuln\'s Potential Adverse Impact within the tabled timeframe (e.g. Low N5 IRV+LEV = 4 days; Moderate tightens to 2 days).',
      'Track and report SLA breaches.',
    ],
    alternative_satisfiers: [scannerAlt('SLA engines with custom (FedRAMP) policy tables.')],
    nist_controls: ['si-2', 'ra-5', 'ca-5'],
    sla: { calendarDays: 4, cadence: 'reduce PAIN within the PVR matrix (e.g. Low N5 IRV+LEV = 4 days; Moderate = 2 days)' },
    references: [REF.vdr],
  },
  'VDR-TFR-RMN': {
    artifacts_required: ['Routine-ops remediation log for remaining (below-threshold) vulnerabilities handled during normal patching'],
    remediation_steps: [
      'Mitigate/remediate remaining vulnerabilities (below the PVR thresholds — e.g. N1, low-impact non-LEV) during routine operations.',
      'Track them in the patch-management cadence / backlog burn-down.',
      'Attach the routine-ops remediation log.',
    ],
    alternative_satisfiers: [scannerAlt('Patch-management cadence; backlog burn-down (Wiz/DefectDojo).')],
    nist_controls: ['si-2', 'ra-5'],
    references: [REF.vdr],
  },

  // ════════════════════════════════════════════════════════════════════════
  // AFR — Applicable FedRAMP Requirements (process KSI pointers)
  // ════════════════════════════════════════════════════════════════════════
  'KSI-AFR-ADS': {
    artifacts_required: ['Documented decision + process for sharing authorization data with all necessary parties per the FedRAMP ADS process, run persistently'],
    remediation_steps: [
      'Decide and document how authorization data is shared with all necessary parties per the ADS process.',
      'Implement the sharing surface (Trust Center / USDA Connect) and keep it running.',
      'Cross-reference the ADS-* requirement evidence.',
    ],
    alternative_satisfiers: [trustCenterAlt(), grcAlt('Paramify/Vanta/Drata publish the package.')],
    nist_controls: ['ac-3', 'ac-4', 'au-2', 'au-3', 'au-6', 'ca-2', 'ir-4', 'ra-5', 'sc-8'],
    references: [REF.afr, REF.ads],
  },
  'KSI-AFR-CCM': {
    artifacts_required: ['Plan/process to deliver Ongoing Authorization Reports and Quarterly Reviews to all necessary parties per the CCM process'],
    remediation_steps: [
      'Maintain a ConMon plan covering OAR cadence and Quarterly Reviews.',
      'Deliver them to all necessary parties.',
      'Cross-reference the CCM-OAR-* / CCM-QTR-* evidence.',
    ],
    alternative_satisfiers: [grcAlt('Vanta/Drata/Paramify schedule and send ConMon reports.')],
    nist_controls: ['ca-7', 'ca-7.4'],
    sla: QUARTERLY,
    references: [REF.afr, REF.ccm],
  },
  'KSI-AFR-FSI': {
    artifacts_required: ['Operating FedRAMP Security Inbox receiving critical FedRAMP/government communications per the FSI requirements'],
    remediation_steps: [
      'Operate a security inbox meeting the FedRAMP Security Inbox requirements.',
      'Route it to on-call so urgent messages are handled.',
      'Cross-reference the FSI-CSO-* evidence.',
    ],
    alternative_satisfiers: [pagerDutyAlt('Shared mailbox routed to PagerDuty on-call.'), ticketingAlt()],
    nist_controls: ['ir-6'],
    references: [REF.afr, REF.fsi],
  },
  'KSI-AFR-ICP': {
    artifacts_required: ['Incident-response procedures that integrate FedRAMP\'s Incident Communications Procedures (notification timelines/recipients)'],
    remediation_steps: [
      'Integrate FedRAMP\'s incident notification timelines and recipients into the org\'s incident-response procedures.',
      'Encode the 1-hour reporting SLAs (FedRAMP, agencies, CISA) into escalation runbooks.',
      'Cross-reference the ICP-CSX-* evidence.',
    ],
    alternative_satisfiers: [pagerDutyAlt('Escalation policy referencing FedRAMP notification SLAs.'), soarAlt()],
    nist_controls: ['ir-6', 'ir-6.2'],
    references: [REF.afr, REF.icp],
  },
  'KSI-AFR-MAS': {
    artifacts_required: ['Applied Minimum Assessment Scope identifying and documenting the assessed scope of the cloud service offering'],
    remediation_steps: [
      'Apply the FedRAMP MAS to identify and document the assessed scope of the CSO.',
      'Use a CMDB/CSPM inventory or Terraform state as the boundary source.',
      'Cross-reference the MAS-CSO-* evidence.',
    ],
    alternative_satisfiers: [{
      via: 'CMDB / CSPM asset inventory (Wiz, ServiceNow CMDB) or Terraform state',
      description: 'An authoritative asset inventory or IaC state defines the assessed boundary.',
      evidence_required: ['Asset inventory / IaC state export', 'Documented scope decision'],
      detected: false,
      detection_signals: ['wiz', 'cmdb', 'terraform'],
    }],
    nist_controls: ['ac-1', 'ca-1', 'cm-1', 'pl-2', 'ra-1', 'ra-9', 'sr-2', 'sr-3', 'sr-11'],
    references: [REF.afr, REF.mas],
  },
  'KSI-AFR-PVA': {
    artifacts_required: ['Persistent validation/assessment process per the 20x PVA process, reporting effectiveness/status of security decisions'],
    remediation_steps: [
      'Persistently validate, assess, and report on the effectiveness/status of security decisions per the PVA process.',
      'Drive it from this collector or a continuous-compliance platform.',
      'Cross-reference the PVA-CSX-* evidence.',
    ],
    alternative_satisfiers: [grcAlt('Vanta/Drata/Paramify/SecureFrame drive the validation cycle.')],
    nist_controls: ['ca-7', 'ca-7.6'],
    references: [REF.afr, REF.pva],
  },
  'KSI-AFR-SCG': {
    artifacts_required: ['Secure-by-default configurations + published Secure Configuration Guide for the offering per the SCG process'],
    remediation_steps: [
      'Develop secure-by-default configurations.',
      'Publish secure-configuration guidance to customers.',
      'Cross-reference the SCG-CSO-* / SCG-ENH-* evidence.',
    ],
    alternative_satisfiers: [{
      via: 'CIS-benchmark-aligned hardening guide + CSPM posture export (Wiz, Lacework)',
      description: 'A CIS-aligned guide plus a CSPM posture export evidence secure defaults + published guidance.',
      evidence_required: ['Published guide', 'CSPM posture export'],
      detected: false,
      detection_signals: ['cis benchmark', 'wiz', 'lacework'],
    }],
    nist_controls: ['cm-6', 'cm-7', 'sa-8'],
    references: [REF.afr, REF.scg],
  },
  'KSI-AFR-SCN': {
    artifacts_required: ['Documented significant-change tracking + notification process per the FedRAMP SCN process'],
    remediation_steps: [
      'Determine how significant changes are tracked and how all necessary parties are notified per the SCN process.',
      'Use ITSM change tickets / GRC change-tracking as the ledger.',
      'Cross-reference the SCN-* evidence (categorization, fields, notification windows).',
    ],
    alternative_satisfiers: [ticketingAlt('ServiceNow/Jira change tickets as the notification ledger.'), grcAlt()],
    nist_controls: ['ca-7.4', 'cm-3.4', 'cm-4', 'cm-7.1', 'au-5', 'ca-5', 'ca-7', 'ra-5', 'ra-5.2', 'sa-22', 'si-2', 'si-2.2', 'si-3', 'si-5', 'si-7.7', 'si-10', 'si-11'],
    references: [REF.afr, REF.scn],
  },
  'KSI-AFR-UCM': {
    artifacts_required: ['Documentation that cryptographic modules protecting federal customer data are selected/used per 20x UCM guidance (FIPS-validated / CMVP)'],
    remediation_steps: [
      'Ensure cryptographic modules protecting federal customer data are selected/used per UCM guidance (CMVP-validated).',
      'Capture CMVP cert numbers; document inheritance for subprocessor-handled crypto.',
      'Cross-reference the UCM-CSX-* evidence.',
    ],
    alternative_satisfiers: [cmvpAlt()],
    nist_controls: ['sc-12', 'sc-12.2', 'sc-13', 'sc-8.1'],
    references: [REF.afr, REF.ucm, REF.cmvp],
  },
  'KSI-AFR-VDR': {
    artifacts_required: ['Documented vulnerability-detection and vulnerability-response methodology per the FedRAMP VDR process'],
    remediation_steps: [
      'Document the vulnerability-detection (scanning, threat-intel, disclosure, bug bounty, supply-chain) and vulnerability-response (track→evaluate→mitigate→monitor→remediate→report) methodology.',
      'Wire scanners + a bug-bounty/VDP program as detection sources.',
      'Cross-reference the VDR-* evidence (evaluation, SLAs, reporting).',
    ],
    alternative_satisfiers: [scannerAlt('Wiz/Prisma own the VDR lifecycle.'), bugBountyAlt(), grcAlt()],
    nist_controls: ['ca-7', 'ca-7.6', 'ir-4', 'ir-6', 'ir-6.2', 'ra-3', 'ra-5', 'ra-5.2', 'ra-5.4', 'ra-5.5', 'si-2', 'si-3', 'si-4', 'si-4.7'],
    references: [REF.afr, REF.vdr],
  },
};

/**
 * Look up the playbook for a requirement id, if one is defined.
 */
export function playbookFor(id: string): RequirementPlaybook | undefined {
  return Object.prototype.hasOwnProperty.call(REQUIREMENT_PLAYBOOKS, id)
    ? REQUIREMENT_PLAYBOOKS[id]
    : undefined;
}
