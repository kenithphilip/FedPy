---
slice_id: U.U5
title: Multi-State Breach-Notification Matrix + Per-Jurisdiction Notification-Letter Emitter
loop: U
status: proposed
commit: TBD
completed_date: —
depends_on:
  - U.U2                                  # Privacy-jurisdiction inventory (states/EU/UK applicability map)
  - LOOP-G.G2                             # Incident Communications Procedures (the trigger upstream)
  - M.M4                                  # Privacy incident response classifier (the PII-breach predicate)
  - LOOP-A.A5                             # Ed25519 signing + RFC 3161 timestamping
  - LOOP-A.A4                             # Submission bundler (letters added to bundle)
  - tracker DB (existing)                 # status pane + audit trail
blocks: []
estimated_effort: medium (~5-7 working days for single implementer)
last_updated: 2026-06-07
applicable_conditional: true
condition: When G.G2 or M.M4 classifies an incident as a PII breach affecting individuals in at least one U.S. state, the EU, the UK, or any jurisdiction with a breach-notification regime in U.U1's privacy-jurisdiction inventory. If the M.M4 classifier returns `is_pii_breach: false` AND no covered-entity flag from a sector overlay (LOOP-V HIPAA, LOOP-Y CJIS/IRS) is set, U.U5 is a no-op for the run.
trigger_flag: "--breach-notification-matrix"
trigger_env: CLOUD_EVIDENCE_BREACH_NOTIFICATION_MATRIX
---

# U.U5 — Multi-State Breach-Notification Matrix + Per-Jurisdiction Notification-Letter Emitter

> This slice is the **operational dispatcher** of LOOP-U: U.U1 catalogues
> which jurisdictions apply, U.U2 inventories which residents the CSP
> processes data for, U.U3 owns GLBA, U.U4 owns CCPA/CPRA — but only
> U.U5 produces the actual per-state, per-EU-Member-State, per-UK
> regulatory deliverable that the various breach-notification statutes
> oblige the data controller / data owner to file inside per-jurisdiction
> deadlines that range from 72 hours (GDPR Art. 33 to supervisory
> authority, UK ICO) to 30 calendar days (CA SB-446 amendment effective
> 2026-01-01, NY SHIELD Act) to 60 calendar days (Texas BCC §521.053,
> HHS HIPAA Breach Notification Rule when the CSP is a Business
> Associate). Because the clock arithmetic is fundamentally different
> per jurisdiction (calendar days vs. business days vs. "without undue
> delay" + 72-hour hard cap), the data-element requirements are
> different per jurisdiction, and the recipients are different per
> jurisdiction (state AG, state-specific regulator like NYDFS, CRA,
> DPA, ICO, affected residents), this per-slice doc carries extra rigor:
> longer test matrix (18 tests), expanded risks register (5 risks), and
> a step-by-step algorithm that any future Claude session or human
> implementer can execute without context from this conversation.

## 1. Mission

U.U5 ingests every PII-breach envelope emitted by `M.M4` (canonical path
`out/privacy-breach-classification.json`) and every privacy-classified
incident bundle emitted by `LOOP-G.G2` (`out/incident-communications/
<incident-id>.json`), walks the affected-individual residency map
attached to each envelope (sourced from U.U2's data-residency
inventory), and for each jurisdiction whose residents are affected emits
a per-jurisdiction notification packet consisting of:

1. a **canonical-JSON envelope** describing the notification (one per
   jurisdiction per recipient class — affected-individual letter,
   state-AG report, state-regulator report, CRA report, DPA report);
2. an **OOXML/zip-store `.docx` letter** templated per-jurisdiction with
   the statute-specific headings (CA Civil Code §1798.82's mandatory
   "What Happened / What Information Was Involved / What We Are Doing /
   What You Can Do / For More Information" section structure;
   GDPR Art. 34's "nature of breach + likely consequences + measures"
   structure; HIPAA §164.404's "brief description + types of information
   + steps the individual should take + what the covered entity is
   doing + contact procedures" structure);
3. an **Ed25519-signed** envelope + RFC 3161 timestamp token (LOOP-A.A5);
4. a **tracker DB row** in `breach_notifications` per (incident_id ×
   jurisdiction × recipient_class) with a deadline-countdown timer;
5. **operator notifications** at emit time, T-24h to deadline, and
   T-1h to deadline via the existing `core/notify.ts` (Slack +
   PagerDuty).

The slice does **not** transmit the notifications to any recipient —
REO Rule 4 forbids the system from acting on behalf of the operator on
a regulatory or consumer-facing communication. U.U5 produces the
artifact set, surfaces them in the tracker UI's
`breach-notification-status-pane.tsx` with a live per-jurisdiction
deadline countdown timer, and records every operator action
(transmission timestamp + recipient confirmation + state regulator
acknowledgement receipt id pasted by operator) as a signed audit-log
entry. When any deadline is at risk of being missed, U.U5 escalates:
the T-1-hour-to-deadline notification routes to the PagerDuty
`breach-notification-deadline` service and the tracker UI banner turns
red for that row.

U.U5 also implements the **substitute-notice path** required by several
state statutes (CA Civ Code §1798.82(j); TX BCC §521.053(g); NY GBL
§899-aa(5)(d)) when the cost of providing direct notice exceeds the
statutory threshold, or where the count of affected individuals
exceeds the statute's substitute-notice trigger (typically 500,000),
or where insufficient contact information exists. The substitute
notice path produces a conspicuous website posting + statewide media
notification text package alongside the per-jurisdiction letter
template.

## 2. Authoritative sources

Every URL accessed 2026-06-07. Verbatim quotes appear in Markdown
blockquotes. Where the live Federal or state Government source returned
a non-200 to anonymous fetches, the implementer downloads the page or
PDF to `cloud-evidence/docs/sources/` and re-quotes verbatim from the
local copy.

### 2.1 California Civil Code §1798.82 — Breach notification (the SB-446 30-day amendment, effective 2026-01-01)

URL: https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.82
(accessed 2026-06-07). The 2025 amendment (SB-446) is reported by
multiple secondary sources to take effect January 1, 2026:

> "Companies have 30 calendar days from the date of discovery to notify
> affected California residents. The new law goes into effect on
> January 1, 2026. This was established by SB 446, which replaced the
> previous 'most expedient time possible' standard."
> — Data Protection Report, "California tightens data breach notification
> timelines, imposes 30-day notice requirement" (2025-11);
> https://www.dataprotectionreport.com/2025/11/california-tightens-data-breach-notification-timelines-imposes-30-day-notice-requirement/
> (accessed 2026-06-07).

The mandatory letter structure (operative since the 2016 AB-2828
amendment, retained in the SB-446 revision) prescribes the headings and
typeface:

> "The security breach notification shall be written in plain language,
> shall be titled 'Notice of Data Breach,' and shall present the
> information described under the following headings: 'What Happened,'
> 'What Information Was Involved,' 'What We Are Doing,' 'What You Can
> Do,' and 'For More Information.' The text of the notice and any other
> notice provided pursuant to this section shall be no smaller than
> 10-point type."
> — Cal. Civ. Code §1798.82(d)(1).

The Attorney General sub-deadline for breaches affecting more than 500
California residents (SB-446 adds 15-calendar-day AG notice):

> "For breaches involving over 500 California residents, the amendment
> also requires notice to the California Attorney General's office
> within 15 calendar days of notifying the affected residents."
> — Troutman Pepper Privacy + Cyber + AI, "California Amends Breach
> Notification Statute" (2025-10);
> https://www.troutmanprivacy.com/2025/10/california-amends-breach-notification-statute/
> (accessed 2026-06-07).

Substitute-notice mechanics:

> "Substitute notice shall consist of all of the following:
> (A) Email notice when the person or business has an email address for
> the subject persons.
> (B) Conspicuous posting of the notice on the internet website page of
> the person or business, if the person or business maintains one.
> (C) Notification to major statewide media."
> — Cal. Civ. Code §1798.82(j) (substitute-notice election conditions
> at §1798.82(j)(1)(A)–(C) — cost exceeds $250,000, affected class
> exceeds 500,000, or insufficient contact information).

### 2.2 New York General Business Law §899-aa — SHIELD Act (the 30-day NY clock + 10-day AG report)

URL: https://www.nysenate.gov/legislation/laws/GBS/899-AA (accessed
2026-06-07).

The 2024 amendment (S.2376B / A.836B) imposing the explicit 30-day
clock + DFS notice:

> "Businesses must disclose data breaches affecting New York residents
> within thirty days from the discovery of a breach. If the incident
> affects over five hundred residents of New York, the person or
> business shall provide the written determination to the state attorney
> general within ten days after the determination."
> — Inside Privacy / Covington & Burling, "New York Adopts Amendment to
> the State Data Breach Notification Law" (2025-01);
> https://www.insideprivacy.com/cybersecurity-2/new-york-adopts-amendment-to-the-state-data-breach-notification-law/
> (accessed 2026-06-07).

> "The amendment adds the New York Department of Financial Services
> ('NYDFS') to the list of state regulators that must be notified
> whenever a breach requiring notification to New York residents
> occurs."
> — Inside Privacy / Covington & Burling, same source, accessed
> 2026-06-07.

SHIELD Act definition expansion (relevant for predicate-evaluation
shared with M.M4):

> "The SHIELD Act expands the definition of Private Information, and
> identifiers now include biometric information, and a user name or
> e-mail address, in combination with a password or security question
> and answer, that would permit access to an online account. The SHIELD
> Act expands the definition of 'breach of the security system' to
> include any unauthorized access to Private Information, such as
> viewing, but not obtaining copies of, the Private Information."
> — Proskauer Rose LLP, "The New SHIELD Act Changes Breach Notification
> Rules and Data Security Standards for New Yorkers' Personal
> Information"; https://www.proskauer.com/alert/the-new-shield-act-changes-breach-notification-rules-and-data-security-standards-for-new-yorkers-personal-information
> (accessed 2026-06-07).

### 2.3 Texas Business and Commerce Code §521.053 — 60-day clock + 30-day AG report (HB 4390 amendment)

URL: https://statutes.capitol.texas.gov/GetStatute.aspx?Code=BC&Value=521.053
(accessed 2026-06-07).

> "Disclosure of a data breach must be made without unreasonable delay
> and in each case not later than the 60th day after the date on which
> the person determines that the breach occurred, except as provided by
> Subsection (d) or as necessary to determine the scope of the breach
> and restore the reasonable integrity of the data system."
> — Tex. Bus. & Com. Code §521.053(b-1).

> "A person who is required to disclose or provide notification of a
> breach of system security under this section shall notify the
> attorney general of that breach as soon as practicable and not later
> than the 30th day after the date on which the person determines that
> the breach occurred if the breach involves at least 250 residents of
> this state."
> — Tex. Bus. & Com. Code §521.053(i) (2023 amendment lowering the
> trigger from 250 to 250 and accelerating the AG-notice clock).

The Texas AG hosts a separate public-disclosure portal that publishes
breach details — the operator's submission triggers an automatic
public listing on the AG site, which the U.U5 operator must be aware of
when scheduling internal communications.

### 2.4 GDPR Article 33 — 72-hour supervisory-authority notification

URL: https://gdpr-info.eu/art-33-gdpr/ (accessed 2026-06-07). Canonical
text — the Official Journal text at
https://eur-lex.europa.eu/eli/reg/2016/679/oj is the operative source;
gdpr-info.eu re-publishes verbatim.

> "In the case of a personal data breach, the controller shall without
> undue delay and, where feasible, not later than 72 hours after having
> become aware of it, notify the personal data breach to the supervisory
> authority competent in accordance with Article 55, unless the personal
> data breach is unlikely to result in a risk to the rights and freedoms
> of natural persons. Where the notification to the supervisory
> authority is not made within 72 hours, it shall be accompanied by
> reasons for the delay."
> — GDPR Art. 33(1).

> "The processor shall notify the controller without undue delay after
> becoming aware of a personal data breach."
> — GDPR Art. 33(2).

> "The notification referred to in paragraph 1 shall at least:
> (a) describe the nature of the personal data breach including where
>     possible, the categories and approximate number of data subjects
>     concerned and the categories and approximate number of personal
>     data records concerned;
> (b) communicate the name and contact details of the data protection
>     officer or other contact point where more information can be
>     obtained;
> (c) describe the likely consequences of the personal data breach;
> (d) describe the measures taken or proposed to be taken by the
>     controller to address the personal data breach, including, where
>     appropriate, measures to mitigate its possible adverse effects."
> — GDPR Art. 33(3).

### 2.5 GDPR Article 34 — Communication to the data subject

URL: https://gdpr-info.eu/art-34-gdpr/ (accessed 2026-06-07).

> "When the personal data breach is likely to result in a high risk to
> the rights and freedoms of natural persons, the controller shall
> communicate the personal data breach to the data subject without
> undue delay."
> — GDPR Art. 34(1).

> "The communication to the data subject referred to in paragraph 1 of
> this Article shall describe in clear and plain language the nature of
> the personal data breach and contain at least the information and
> measures referred to in points (b), (c) and (d) of Article 33(3)."
> — GDPR Art. 34(2).

### 2.6 UK GDPR + Data Protection Act 2018 — 72-hour ICO notification

URL: https://ico.org.uk/for-organisations/report-a-breach/personal-data-breach/
(accessed 2026-06-07).

> "You must report a notifiable breach to the ICO without undue delay
> and within 72 hours of when you became aware of it. The 72 hours
> runs continuously — including weekends and bank holidays."
> — ICO, "Personal data breaches: UK GDPR data breach reporting (DPA
> 2018)", accessed 2026-06-07.

> "Part 3 of the DPA 2018 recognises that it will often be impossible
> for you to investigate a breach fully within that time-period and
> allows you to provide information in phases. If you're still
> investigating, you can submit an initial notification within 72 hours
> with the information you have and follow up with details as they
> become available."
> — ICO, "Personal data breaches: a guide";
> https://ico.org.uk/for-organisations/report-a-breach/personal-data-breach/personal-data-breaches-a-guide/
> (accessed 2026-06-07).

> "Failing to notify a breach when required to do so can result in a
> significant fine up to £8.7m or 2 per cent of your global turnover."
> — ICO, same source, accessed 2026-06-07.

### 2.7 EDPB Guidelines 9/2022 — Personal-data-breach notification interpretive guidance

URL: https://www.edpb.europa.eu/system/files/2023-04/edpb_guidelines_202209_personal_data_breach_notification_v2.0_en.pdf
(accessed 2026-06-07; operator mirrors PDF to
`docs/sources/edpb_guidelines_202209_personal_data_breach_notification_v2.0_en.pdf`).

The EDPB clarifies the "awareness" trigger (which sets the 72-hour
clock):

> "A controller should be regarded as having become 'aware' when that
> controller has a reasonable degree of certainty that a security
> incident has occurred that has led to personal data being
> compromised."
> — EDPB Guidelines 9/2022 §II.A.2 ("When does a controller become
> aware?"), accessed 2026-06-07.

And the cross-border one-stop-shop routing (lead-supervisory-authority
mechanic) — relevant because a CSP processing EU data across multiple
Member States files with the lead SA, not all 27:

> "Where a personal data breach takes place in the context of
> cross-border processing and notification is required, the controller
> will need to notify the lead supervisory authority."
> — EDPB Guidelines 9/2022 §II.C ("Cross-border breaches"), accessed
> 2026-06-07.

### 2.8 HIPAA Breach Notification Rule — 45 CFR §164.404 / §164.408

URL: https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-D
(accessed 2026-06-07).

§164.404(b) — individual notification timeline:

> "Except as provided in §164.412, a covered entity shall provide the
> notification required by paragraph (a) of this section without
> unreasonable delay and in no case later than 60 calendar days after
> discovery of a breach."
> — 45 CFR §164.404(b).

§164.408(b) — HHS notification timeline (≥ 500-affected):

> "For breaches of unsecured protected health information involving 500
> or more individuals, a covered entity shall, except as provided in
> §164.412, provide the notification required by paragraph (a) of this
> section contemporaneously with the notice required by §164.404(a)."
> — 45 CFR §164.408(b).

§164.408(c) — HHS notification timeline (< 500-affected):

> "For breaches of unsecured protected health information involving
> less than 500 individuals, a covered entity shall maintain a log or
> other documentation of such breaches and, not later than 60 days
> after the end of each calendar year, provide the notification
> required by paragraph (a) of this section for breaches discovered
> during the preceding calendar year."
> — 45 CFR §164.408(c).

U.U5 produces the HIPAA-overlay artifact set only when LOOP-V's
covered-entity flag is set on the incident envelope; when it is not
set, the HIPAA path is inert.

### 2.9 NAAG state breach-notification-statute index (cross-state matrix authority)

URL: https://www.naag.org/issues/cyber-and-privacy/data-security-and-breach-notification/
(accessed 2026-06-07). The National Association of Attorneys General
maintains a state-by-state index of breach-notification statutes; the
operator mirrors the index to
`cloud-evidence/data/state-breach-notification-statutes.json` and
U.U5's `breach-notification-matrix.ts` keys off the mirrored copy. The
NAAG index is descriptive — the operative source for each state is the
state statute itself (the operator pins the statute URL + last-revised
date in the JSON file).

Per the NAAG index, all 50 states + DC + Puerto Rico + Guam + US Virgin
Islands have breach-notification statutes; U.U5 ships with seed
configurations for the highest-population jurisdictions (CA, NY, TX,
FL, IL, PA, OH, GA, NC, MI) and a generic-fallback template for the
remainder that the operator parameterises in
`state-breach-notification-statutes.json`.

### 2.10 OMB M-17-12 — Federal individual notification framework (for federal-customer parity)

URL: https://www.whitehouse.gov/wp-content/uploads/legacy_drupal_files/omb/memoranda/2017/m-17-12_0.pdf
(accessed 2026-06-07; operator mirrors PDF).

While OMB M-17-12 binds federal agencies (not CSPs directly), the CSP
operating on a federal-customer authorisation boundary inherits the
notification obligations contractually via the agency's SSP and the
DPA / data-handling appendix. U.U5 reads the federal-agency-customer
flag from `org-profile.yaml` and, when set, emits a parallel
"federal-agency notice" packet to the agency Privacy Officer (separate
from the state / EU / UK paths).

> "Agencies must notify affected individuals as expeditiously as
> practicable and without unreasonable delay following the discovery
> of a breach, consistent with the needs of law enforcement and any
> measures necessary to determine the scope of the breach."
> — OMB M-17-12 §VI ("Notification of Individuals"), accessed
> 2026-06-07.

### 2.11 SB-446 (California, 2025) — text amendment confirmation

URL: https://leginfo.legislature.ca.gov/faces/billNavClient.xhtml?bill_id=202520260SB446
(accessed 2026-06-07).

Per secondary sources, SB-446's substantive change is the express
30-calendar-day cap in §1798.82(a):

> "California Civil Code section 1798.82, subdivision (a), is amended
> to require notification 'in the most expedient time possible and
> without unreasonable delay, but in no case later than 30 calendar
> days after the date of discovery of the breach.'"
> — Pillsbury Winthrop Shaw Pittman, "California Imposes New Data
> Breach Notification Requirements";
> https://www.pillsburylaw.com/en/news-and-insights/california-data-breach-notification-requirements.html
> (accessed 2026-06-07).

The implementer **REQUIRES-RESEARCH-CONFIRM** the exact text of the
amended §1798.82(a) once the operative California Civil Code citation
on leginfo.legislature.ca.gov is updated for the 2026 Code edition.
Until that confirmation lands, the U.U5 module ships with the
30-calendar-day value pinned to the SB-446 secondary-source quote, with
a `requires_research_confirm` provenance tag attached.

## 3. Scope

### 3.1 In scope

- Ingestion of the M.M4 `out/privacy-breach-classification.json`
  envelope AND the LOOP-G.G2
  `out/incident-communications/<incident-id>.json` envelope as
  parallel triggers (either alone is sufficient).
- Verification of the upstream Ed25519 signatures via
  `core/sign.ts::verifyEnvelope()`. Failure exits with
  `EnvelopeSignatureInvalidError`.
- Walking the U.U2 data-residency map attached to the M.M4 envelope to
  determine which jurisdictions are affected.
- For each affected jurisdiction, lookup against the
  `breach-notification-matrix.ts` rule table to determine:
  - statute citation + URL;
  - deadline (hours / calendar days / business days);
  - recipient classes required (individual / state AG / state
    regulator / CRA / DPA / ICO / HHS / federal Privacy Officer);
  - data-element requirements for the notice;
  - substitute-notice trigger thresholds (cost / count / contactability);
  - mandatory headings + plain-language requirement (per CA);
  - language-translation requirements (some states require notices in
    the recipient's primary language).
- For each (incident × jurisdiction × recipient_class) triple,
  composition of:
  - canonical JSON envelope per §5.1;
  - OOXML/zip-store `.docx` letter per §5.2;
  - canonical PDF rendering when `letter_format = 'pdf'`
    (operator-config, default = `docx`).
- Ed25519 signing + RFC 3161 timestamping per envelope.
- Tracker DB row insertion into `breach_notifications`.
- Operator notifications at emit, T-24h, and T-1h via `core/notify.ts`.
- Substitute-notice packet generation when CA / TX / NY / IL trigger
  conditions are met.
- Submission-bundle catalogue update via LOOP-A.A4 — the signed JSON +
  `.docx` per (jurisdiction × recipient class) added to the bundle.
- GDPR Art. 33(4) phased-notification support — when initial info is
  partial, an initial envelope is emitted with
  `phase: 'initial'`, and follow-up envelopes with
  `phase: 'follow-up-N'` reference the initial via
  `parent_notification_id`.
- HIPAA HHS-portal artifact emission when LOOP-V's covered-entity flag
  is set (the HHS portal upload format is JSON — U.U5 emits the JSON
  shaped for the HHS Office for Civil Rights breach-portal intake).

### 3.2 Out of scope (NOT in U.U5)

- **Actual transmission of any notification to any recipient.** REO
  Rule 4 forbids the system from acting on behalf of the operator on
  a regulatory or consumer-facing communication. U.U5 produces the
  artifact set; the operator transmits.
- **The PII-breach predicate evaluation.** Owned by `M.M4`. U.U5
  trusts the upstream `is_pii_breach: true` verdict and the affected
  data-element list.
- **The incident triage / classification.** Owned by `LOOP-G.G2`.
- **The privacy-jurisdiction inventory.** Owned by `U.U1` / `U.U2`.
- **GLBA breach-notification.** Owned by `U.U3` (the FTC Safeguards
  Rule 30-day notification path is distinct from the state-statute
  matrix because the recipient is the FTC, not a state AG; U.U3 emits
  the FTC notification under §314.5 — U.U5 does not duplicate).
- **CCPA-specific consumer-rights notifications** (right-to-know,
  right-to-delete responses). Owned by `U.U4`.
- **The agency-Authorizing-Official notification.** The
  `agency_ao_notification` is owned by `LOOP-G.G2`; U.U5 receives the
  signed AO-notice envelope as an input and includes the AO contact
  in the federal-customer-notice packet when the federal-customer flag
  is set.
- **Litigation-hold orchestration.** When General Counsel asserts a
  litigation hold, U.U5 emits an annotation on the envelope
  (`legal_hold_in_effect: true`) but does not implement the hold
  itself — that is an operator + tracker UI workflow.

## 4. Inputs

### 4.1 M.M4 privacy-breach classification envelope (the primary trigger)

Path: `out/privacy-breach-classification.json`. Schema defined in M.M4
§5. U.U5 reads the following fields per envelope:

```ts
interface U5InputClassification {
  schema_version: '1.0.0';
  envelope_id: string;                       // ULID
  incident_id: string;                       // FK to LOOP-G.G2 incident
  classified_at: string;                     // ISO 8601 UTC
  classifier_version: string;
  is_pii_breach: boolean;
  pii_breach_factors: {
    nature_and_sensitivity: 'low' | 'moderate' | 'high';
    likelihood_of_access: 'low' | 'moderate' | 'high';
    type_of_breach: 'confidentiality' | 'integrity' | 'availability' | 'mixed';
    wider_context: 'low' | 'moderate' | 'high';
    ability_to_mitigate_harm: 'low' | 'moderate' | 'high';
  };
  affected_data_elements: Array<
    | 'ssn' | 'driver_license' | 'state_id' | 'financial_account_no'
    | 'payment_card_number' | 'health_info' | 'health_insurance_no'
    | 'login_credentials' | 'biometric' | 'tax_id' | 'passport'
    | 'medical_record_no' | 'mother_maiden_name' | 'date_of_birth'
    | 'demographic_info' | 'employment_record' | 'education_record'
    | 'precise_geolocation' | 'genetic_data' | 'minor_identifier'
  >;
  affected_individual_count_estimate: number;
  affected_individual_residency_map: Array<{   // populated from U.U2
    jurisdiction_code: string;                  // ISO 3166-2 for US states; ISO 3166-1 alpha-2 for EU MS / UK
    count_estimate: number;
    confidence: 'high' | 'moderate' | 'low';
  }>;
  contains_minor_data: boolean;
  contains_health_data: boolean;
  contains_financial_data: boolean;
  contains_biometric: boolean;
  discovery_kind: 'monitoring-alert' | 'third-party-report' | 'self-disclosure';
  discovered_at: string;                       // ISO 8601 UTC
  covered_entity_flags: {                      // populated by sector overlays
    hipaa_business_associate: boolean;
    cjis_data: boolean;
    ferpa_education_record: boolean;
    glba_financial_institution: boolean;
    federal_agency_customer: boolean;
  };
  provenance: { /* M.M4 emitter block */ };
  signature: { /* Ed25519 detached */ };
  rfc3161_timestamp: { /* RFC 3161 token */ };
}
```

U.U5 **MUST** verify the Ed25519 signature against the M.M4 signing
key before consuming. A signature-verification failure exits with
`EnvelopeSignatureInvalidError` and leaves no tracker DB rows behind.

### 4.2 LOOP-G.G2 incident envelope (the secondary trigger)

Path: `out/incident-communications/<incident-id>.json`. U.U5 reads
`incident_id`, `discovered_at`, `incident_summary`, `mitigation_actions`
(initial + ongoing), `csp_pii_breach_factor_evaluation` (which feeds
M.M4 and arrives back attached to the M.M4 envelope), and the
`agency_ao_notification` block (when the federal-customer flag is set).

### 4.3 Operator configuration

Path: `cloud-evidence/config.yaml`:

```yaml
breach_notifications:
  enabled: true
  letter_format: docx                          # | pdf | both
  letter_language_default: en-US
  enable_substitute_notice: true
  substitute_notice_cost_threshold_usd: 250000  # CA Civ Code §1798.82(j)(1)(A)
  substitute_notice_count_threshold: 500000     # CA Civ Code §1798.82(j)(1)(B)
  enable_hipaa_overlay: false                   # set true if LOOP-V flag
  enable_federal_agency_notice: false
  ed25519_signing_key_ref: REQUIRES-OPERATOR-INPUT
  signing_officer:
    name: REQUIRES-OPERATOR-INPUT
    title: REQUIRES-OPERATOR-INPUT
  jurisdictions_file: state-breach-notification-statutes.json
  contacts_file: breach-notification-contacts.yaml
  notification_channels:
    - slack:#privacy-breach-deadlines
    - pagerduty:breach-notification-deadline
```

#### 4.3.1 `state-breach-notification-statutes.json`

```json
{
  "schema_version": "1.0.0",
  "last_synced_naag": "2026-06-07",
  "naag_source_url": "https://www.naag.org/issues/cyber-and-privacy/data-security-and-breach-notification/",
  "jurisdictions": [
    {
      "code": "US-CA",
      "name": "California",
      "statute_citation": "Cal. Civ. Code §1798.82",
      "statute_url": "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.82",
      "deadline_individual": { "unit": "calendar_days", "value": 30, "effective_from": "2026-01-01", "amendment_ref": "SB-446 (2025)" },
      "deadline_ag": { "unit": "calendar_days", "value": 15, "trigger_count": 500 },
      "deadline_cra": null,
      "deadline_regulator": null,
      "mandatory_headings": ["What Happened", "What Information Was Involved", "What We Are Doing", "What You Can Do", "For More Information"],
      "min_font_pt": 10,
      "substitute_notice": {
        "cost_threshold_usd": 250000,
        "count_threshold": 500000,
        "insufficient_contact": true,
        "components": ["email", "website_posting", "statewide_media"]
      },
      "ag_recipient_email_or_portal": "https://oag.ca.gov/ecrime/databreach/report-a-breach",
      "language_requirements": ["en"]
    },
    {
      "code": "US-NY",
      "name": "New York",
      "statute_citation": "N.Y. Gen. Bus. Law §899-aa",
      "statute_url": "https://www.nysenate.gov/legislation/laws/GBS/899-AA",
      "deadline_individual": { "unit": "calendar_days", "value": 30, "effective_from": "2025-03-25", "amendment_ref": "S.2376B / A.836B (2024)" },
      "deadline_ag": { "unit": "calendar_days", "value": 10, "trigger_count": 500 },
      "deadline_regulator": { "unit": "calendar_days", "value": 10, "trigger_count": 500, "recipient": "NYDFS" },
      "deadline_cra": null,
      "mandatory_headings": [],
      "min_font_pt": null,
      "ag_recipient_email_or_portal": "https://ag.ny.gov/internet/data-breach"
    }
  ]
}
```

Additional entries for TX, FL, IL, PA, OH, GA, NC, MI are seeded in
the same file by `scripts/seed-state-breach-statutes.mjs`; the operator
adds remaining jurisdictions as needed and re-signs the file.

#### 4.3.2 `breach-notification-contacts.yaml`

```yaml
schema_version: '1.0.0'
contacts:
  - jurisdiction_code: US-CA
    state_ag_email: dataprivacy@doj.ca.gov
    state_regulator_email: null
    cra_endpoints: []
  - jurisdiction_code: US-NY
    state_ag_email: data.breach@ag.ny.gov
    state_regulator_email: cyber.notifications@dfs.ny.gov   # NYDFS post-2024 amendment
    cra_endpoints: ['equifax', 'experian', 'transunion']
  - jurisdiction_code: EU-DE
    dpa_email: poststelle@bfdi.bund.de
    dpa_portal_url: https://www.bfdi.bund.de/EN/Home/home_node.html
  - jurisdiction_code: GB
    dpa_email: casework@ico.org.uk
    dpa_portal_url: https://ico.org.uk/for-organisations/report-a-breach/
```

### 4.4 Federal holiday calendar reuse

For business-day computations (Texas BCC §521.053(b-1) is calendar
days, but the HIPAA "without unreasonable delay" caveat references
business reasoning), U.U5's `breach-notification-clock.ts` REUSES
`core/section889-clock.ts`'s federal-business-day primitive from
W.W3 — the implementer imports `fedBusinessHoursElapsed()` and
`deadlineFor()` without duplication.

## 5. Outputs

### 5.1 Canonical JSON notification envelope

Path (per jurisdiction × recipient class):
`out/breach-notifications/<incident_id>/<jurisdiction_code>-<recipient_class>-<notification_id>.json`.

```ts
interface BreachNotificationEnvelope {
  schema_version: '1.0.0';
  notification_id: string;                            // ULID
  incident_id: string;
  classification_envelope_ref: { path: string; sha256: string; envelope_id: string };
  generated_at: string;                                // ISO 8601 UTC
  emitted_at: string;                                  // ISO 8601 UTC

  jurisdiction: {
    code: string;                                      // 'US-CA' | 'US-NY' | 'GB' | 'EU-DE' | …
    name: string;
    statute_citation: string;
    statute_url: string;
  };
  recipient_class:
    | 'affected_individual'
    | 'state_attorney_general'
    | 'state_regulator'
    | 'cra'
    | 'eu_dpa'
    | 'uk_ico'
    | 'hhs_ocr'
    | 'federal_agency_privacy_officer';
  phase: 'initial' | 'follow-up' | 'final';
  parent_notification_id?: string;                     // populated for follow-up / final

  discovered_at: string;
  deadline_at: string;                                 // ISO 8601 UTC, computed
  deadline_unit: 'hours' | 'business_days' | 'calendar_days';
  deadline_value: number;
  remaining_at_emit_hours: number;

  affected_individual_count_for_jurisdiction: number;
  affected_data_elements: string[];

  // Statute-specific letter content
  letter: {
    language: string;                                  // BCP-47, e.g. 'en-US' | 'de-DE' | 'fr-FR'
    headings_used: string[];                           // mandatory_headings from statute config
    sections: Array<{
      heading: string;
      body: string;
    }>;
    plain_language_attested: boolean;                  // true when CA §1798.82(d)(1) applies
    min_font_pt: number | null;
  };

  // Substitute notice (where elected)
  substitute_notice?: {
    election_basis: 'cost' | 'count' | 'insufficient_contact';
    cost_estimate_usd?: number;
    components: Array<'email' | 'website_posting' | 'statewide_media'>;
    website_posting_url: string;
    statewide_media_outlets: string[];
  };

  // GDPR Art. 33(3) data elements (populated for EU-MS / UK / DPA recipients)
  gdpr_art_33: {
    nature_of_breach: string;
    categories_of_data_subjects: string[];
    approx_data_subjects_count: number;
    categories_of_records: string[];
    approx_records_count: number;
    contact_point_name: string;
    contact_point_email: string;
    likely_consequences: string;
    measures_taken: string;
    measures_proposed: string;
  } | null;

  // HIPAA §164.404(c) data elements (populated when HIPAA overlay set)
  hipaa_164_404_c: {
    description_of_breach: string;
    types_of_unsecured_phi: string[];
    steps_individuals_should_take: string;
    what_covered_entity_is_doing: string;
    contact_procedures: { phone: string; email: string; website: string; postal: string };
  } | null;

  // Officer attestation
  signing_officer: { name: string; title: string; key_id: string; key_version: string };

  provenance: {
    emitter: 'breach-notification-emitter';
    emitter_version: string;
    emitted_at: string;
    source_calls: Array<{
      kind: 'm4-classification' | 'g2-incident' | 'statutes-json' | 'contacts-yaml' | 'config-yaml' | 'org-profile-yaml';
      path: string;
      sha256: string;
    }>;
    requires_research_confirm: string[];               // statute citations with secondary-source-only quotes
  };
  signature: { alg: 'ed25519'; key_id: string; sig: string };
  rfc3161_timestamp: { tsa_url: string; token: string; received_at: string };

  // Operator transmission audit
  transmission?: {
    transmitted_at: string;
    transmitted_by: string;
    transmission_method: 'postal' | 'email' | 'portal-upload' | 'sms' | 'substitute-website' | 'substitute-media';
    recipient_acknowledgement_id?: string;
  };

  closed_at?: string;
  closed_by?: string;
  closure_justification?: string;
}
```

### 5.2 OOXML/zip-store `.docx` letter

Path: `out/breach-notifications/<incident_id>/<jurisdiction_code>-<recipient_class>-<notification_id>.docx`.

Layout (per jurisdiction template; CA shown):

- **Heading.** "Notice of Data Breach" (CA: mandatory; size = 10pt
  minimum per §1798.82(d)(1)).
- **Five mandatory sections** (CA): "What Happened", "What Information
  Was Involved", "What We Are Doing", "What You Can Do", "For More
  Information". Body content populated from the U.U5 letter sections.
- **Footer.** CSP name + UEI + Privacy Officer contact + state AG
  pointer ("To file a complaint with the California Attorney
  General…").
- **Signature placeholder.** A signed-XML block where the operator
  inserts a wet signature image or the Ed25519 signature receipt id.

The renderer is `core/breach-letter-docx.ts` and reuses the OOXML
helpers from `core/inventory-workbook.ts`. Per-jurisdiction templates
live under `core/breach-letter-templates/<jurisdiction_code>.ts` and
are imported via a dispatch table.

### 5.3 Tracker DB row

Schema (migration `0051_breach_notifications.sql`):

```sql
CREATE TABLE breach_notifications (
  id                                UUID PRIMARY KEY,
  notification_id                   TEXT NOT NULL UNIQUE,
  incident_id                       TEXT NOT NULL,
  classification_envelope_ref       TEXT NOT NULL,
  jurisdiction_code                 TEXT NOT NULL,
  recipient_class                   TEXT NOT NULL,
  phase                             TEXT NOT NULL DEFAULT 'initial',
  parent_notification_id            TEXT,
  statute_citation                  TEXT NOT NULL,
  discovered_at                     TIMESTAMPTZ NOT NULL,
  deadline_at                       TIMESTAMPTZ NOT NULL,
  deadline_unit                     TEXT NOT NULL,
  deadline_value                    INTEGER NOT NULL,
  affected_count                    INTEGER NOT NULL,
  emitted_at                        TIMESTAMPTZ NOT NULL,
  letter_path_json                  TEXT NOT NULL,
  letter_path_docx                  TEXT NOT NULL,
  letter_path_pdf                   TEXT,
  substitute_notice_elected         BOOLEAN NOT NULL DEFAULT FALSE,
  substitute_notice_basis           TEXT,
  status                            TEXT NOT NULL DEFAULT 'emitted',
  transmitted_at                    TIMESTAMPTZ,
  transmitted_by                    TEXT,
  transmission_method               TEXT,
  recipient_acknowledgement_id      TEXT,
  closed_at                         TIMESTAMPTZ,
  closed_by                         TEXT,
  closure_justification             TEXT,
  signing_key_id                    TEXT NOT NULL,
  signing_key_version               TEXT NOT NULL,
  signing_officer_name              TEXT NOT NULL,
  signing_officer_title             TEXT NOT NULL,
  encrypted_at_rest                 BOOLEAN NOT NULL DEFAULT TRUE,
  created_at                        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_breach_notifications_incident_id ON breach_notifications(incident_id);
CREATE INDEX idx_breach_notifications_deadline_at ON breach_notifications(deadline_at);
CREATE INDEX idx_breach_notifications_status ON breach_notifications(status);
CREATE INDEX idx_breach_notifications_jurisdiction ON breach_notifications(jurisdiction_code);
CREATE UNIQUE INDEX idx_breach_notifications_idempotency
  ON breach_notifications(incident_id, jurisdiction_code, recipient_class, phase);
```

### 5.4 Operator notifications

Channel routing (driven by
`config.yaml::breach_notifications.notification_channels`):

- **Emit-time notification.** Slack `#privacy-breach-deadlines`. Title:
  "Breach notification packet emitted for incident `<incident_id>` —
  `<N>` jurisdictions, `<M>` recipient classes, soonest deadline
  `<deadline_at>` (`<jurisdiction_code>`)". Body: per-jurisdiction
  countdown table, link to tracker UI row, link to signed JSON +
  `.docx` files.
- **T-24h-to-deadline notification.** PagerDuty service
  `breach-notification-deadline`. Priority: P2. Per-jurisdiction.
- **T-1-hour-to-deadline notification.** PagerDuty service
  `breach-notification-deadline`. Priority: P1.
- **Transmission-confirmed acknowledgement.** Slack + tracker UI green
  badge.

### 5.5 Submission-bundle entry

New roles registered in `core/submission-bundle.ts::WELL_KNOWN`:

```ts
{ role: 'breach-notification-letter-json',
  filename: 'breach-notifications/**/*.json',
  description: 'Per-jurisdiction privacy breach notification envelope (LOOP-U.U5)' },
{ role: 'breach-notification-letter-docx',
  filename: 'breach-notifications/**/*.docx',
  description: 'OOXML rendering of the per-jurisdiction breach notification letter (LOOP-U.U5)' },
{ role: 'breach-notification-matrix-snapshot',
  filename: 'breach-notifications/_matrix-snapshot.json',
  description: 'Snapshot of the active state-breach-notification-statutes.json + computed deadlines (LOOP-U.U5)' },
```

## 6. Algorithm / Steps

### Phase A — Bootstrap

1. Parse `--breach-notification-matrix` (or env
   `CLOUD_EVIDENCE_BREACH_NOTIFICATION_MATRIX`). No-op if neither set.
2. Load `config.yaml` → `breach_notifications.*`. Load
   `state-breach-notification-statutes.json` and
   `breach-notification-contacts.yaml`. Validate via Ajv. If any
   `REQUIRES-OPERATOR-INPUT` placeholder remains in the signing block,
   exit `2` with `BreachNotificationOperatorConfigMissingError`.
3. Verify Ed25519 signature on `state-breach-notification-statutes.json`.
4. Sign-test the corporate signing key via
   `core/sign.ts::testSign(key_ref)`.

### Phase B — Ingest M.M4 + G.G2

5. Locate `out/privacy-breach-classification.json`. Operator may
   override via `--m4-envelope-path`.
6. Verify M.M4 envelope signature. Failure → exit `2`.
7. If `is_pii_breach: false` AND no covered-entity flag is set, exit
   `0` (no-op).
8. Locate the linked G.G2 incident envelope via
   `classification_envelope_ref.incident_id`. Verify signature.
9. Merge residency-map entries from M.M4 with any covered-entity flags
   from G.G2.

### Phase C — Resolve jurisdictions × recipient classes

10. For each residency-map entry, look up the jurisdiction-row in
    `state-breach-notification-statutes.json`. Missing entries surface
    `REQUIRES-OPERATOR-INPUT` diagnostics and prevent emission for
    that jurisdiction (do not silently skip).
11. For each jurisdiction, compute the recipient-class list:
    - Always: `affected_individual` (unless statute exempts and the
      operator-config flag confirms);
    - `state_attorney_general` when `affected_count >=
      jurisdiction.deadline_ag.trigger_count`;
    - `state_regulator` (e.g. NYDFS for US-NY when `affected_count >=
      500`);
    - `cra` when `affected_count >= 1000` (federal FCRA trigger AND
      state laws — operator confirms);
    - `eu_dpa` when jurisdiction is an EU Member State;
    - `uk_ico` when jurisdiction is GB;
    - `hhs_ocr` when HIPAA overlay flag is set AND `affected_count >=
      500` (immediate path) OR via the annual log path
      (`< 500` aggregated to year-end);
    - `federal_agency_privacy_officer` when federal-customer flag set.

### Phase D — Deadline computation

12. For each (jurisdiction × recipient_class), compute `deadline_at`:
    - `unit = 'hours'` (GDPR / UK GDPR 72h to DPA/ICO): `deadline_at =
      discovered_at + value hours`. Per ICO guidance §2.6, the clock
      runs continuously — no business-day clamping.
    - `unit = 'calendar_days'` (CA 30 / NY 30 / TX 60 / HIPAA 60):
      `deadline_at = discovered_at + value calendar days` (midnight
      local-jurisdiction-time of the deadline-day end).
    - `unit = 'business_days'` (rare; mostly federal-customer
      contractual): use `breach-notification-clock.ts` (the W.W3
      primitive reused).
13. Persist `deadline_at` on the in-memory notification record.

### Phase E — Compose letter content

14. **Letter sections.** Build the per-jurisdiction letter sections
    using:
    - Mandatory headings from the jurisdiction row (CA: 5 headings;
      NY: free-form; GB: GDPR Art. 34 structure).
    - Plain-language template populated from incident summary, data
      elements, mitigation actions, recommended individual actions.
    - When `letter.language` is not the operator default, the
      operator MUST supply a translated body for the jurisdiction's
      official language — surfaced as a
      `REQUIRES-OPERATOR-INPUT` diagnostic if missing.
15. **GDPR Art. 33(3) data block.** Populated for EU MS / UK / DPA
    recipients per §5.1.
16. **HIPAA §164.404(c) data block.** Populated when the HIPAA
    overlay flag is set.
17. **Substitute-notice election.** Evaluated against CA / TX / NY /
    IL thresholds; emit the substitute-notice components when
    triggered.

### Phase F — Sign + timestamp

18. Sign envelope via `core/sign.ts::signEnvelope(env, key_ref)`. Pin
    `signing_officer.key_version` at compose time.
19. Attach RFC 3161 timestamp via
    `core/timestamp.ts::stampEnvelope(env)`. TSA outage → warn (do not
    block); the artifact is still transmissible.

### Phase G — Render `.docx` + (optional) PDF

20. Render OOXML via
    `core/breach-letter-docx.ts::renderLetter(env, template)` where
    `template = core/breach-letter-templates/<jurisdiction_code>.ts`.
21. If `letter_format ∈ {'pdf', 'both'}`, render PDF via the existing
    `core/oscal-pdf.ts` helper.

### Phase H — Persist + notify

22. Insert tracker DB row into `breach_notifications`. Idempotency via
    the unique index on
    `(incident_id, jurisdiction_code, recipient_class, phase)`.
    Encrypt at rest via the existing pgcrypto + KMS data-key flow.
23. Emit emit-time notification via `core/notify.ts::send()` with the
    `breach-notification-emitted` template and the per-jurisdiction
    countdown table.
24. Schedule `T-24h` and `T-1h` to-deadline notifications by inserting
    into `tracker.scheduled_notifications`.

### Phase I — Submission bundle

25. Update `core/submission-bundle.ts` catalogue with the new artifact
    roles per §5.5.

### Phase J — Coverage + log + validation

26. Append `breach_notification_coverage` block to
    `out/inventory-coverage.json` with per-incident emit counts +
    per-jurisdiction deadline-status counts.
27. Emit run-log lines
    `coverage:breach-notifications:<N>-letters-emitted-across-<M>-jurisdictions`.
28. `npm run check:provenance`, `npm run lint:no-stubs`,
    `npm run check:reo`, `npm run typecheck`, and all 18 tests in §8
    must pass.

## 7. Files to create / modify

### Files to CREATE

1. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/breach-notification-matrix.ts`
   — jurisdiction-table lookups; rule-resolution logic; recipient-class
   computation; deadline-unit dispatch. ~350 lines.
2. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/breach-notification-emitter.ts`
   — main orchestrator implementing Phases A–J. ~550 lines.
3. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/breach-letter-docx.ts`
   — OOXML/zip-store renderer; per-jurisdiction template dispatch;
   plain-language attestation; minimum-font enforcement (CA). ~480 lines.
4. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/breach-notification-clock.ts`
   — calendar-day arithmetic + GDPR-72h continuous-clock arithmetic +
   business-day reuse from W.W3. ~220 lines.
5. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/breach-letter-templates/us-ca.ts`
   — California §1798.82-shaped template (5 mandatory headings). ~150
   lines.
6. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/breach-letter-templates/us-ny.ts`
   — NY SHIELD Act template. ~120 lines.
7. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/breach-letter-templates/us-tx.ts`
   — Texas BCC §521.053 template. ~110 lines.
8. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/breach-letter-templates/eu-generic.ts`
   — GDPR Art. 34-shaped template, parameterised by Member State. ~140
   lines.
9. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/breach-letter-templates/gb.ts`
   — UK GDPR / DPA 2018 ICO template. ~120 lines.
10. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/breach-letter-templates/us-hhs.ts`
    — HIPAA §164.404(c) HHS OCR template. ~140 lines.
11. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/state-breach-notification-statutes.json`
    — seeded matrix for CA, NY, TX, FL, IL, PA, OH, GA, NC, MI; signed.
12. `/Users/kenith.philip/FedRAMP 20x/scripts/seed-state-breach-statutes.mjs`
    — idempotent seeder + NAAG-index refresher. ~200 lines.
13. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/db/migrations/0051_breach_notifications.sql`
    — table + indices + scheduled-notification helper.
14. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/breach-notifications.ts`
    — REST API:
    `GET /api/breach-notifications`,
    `GET /api/breach-notifications/:id`,
    `POST /api/breach-notifications/:id/mark-transmitted`,
    `POST /api/breach-notifications/:id/mark-acknowledged`,
    `POST /api/breach-notifications/:id/mark-closed`,
    `POST /api/breach-notifications/:id/elect-substitute-notice`.
    ~340 lines.
15. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/ui/breach-notification-status-pane.tsx`
    — per-jurisdiction countdown panel; deadline color-coding;
    substitute-notice form; transmission-confirm form. ~520 lines.
16. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/breach-notification-contacts.example.yaml`
    — committed example.
17. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/breach-notification-matrix.test.ts`
    — see §8 (matrix-resolution suite).
18. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/breach-notification-emitter.test.ts`
    — see §8 (end-to-end emitter suite).
19. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/breach-letter-docx.test.ts`
    — OOXML round-trip + plain-language attestation tests.
20. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/breach-notifications/`
    — fixtures: M.M4 envelopes (CA-only, multi-state, EU+UK, HIPAA);
    G.G2 incidents; statutes JSON; expected outputs.

### Files to MODIFY

- `core/submission-bundle.ts` — register the 3 new `WELL_KNOWN` roles
  in §5.5.
- `docs/STATUS.md` — add U.U5 status row (initially `pending`; flipped
  by Step 8 of the completion procedure when slice ships).
- `docs/loops/LOOP-U-SPEC.md` — add U.U5 row to status table (when the
  LOOP-U SPEC lands; until then U.U5's spec row is owned by this
  per-slice doc).
- `CHANGELOG.md` — append "Unreleased" entry on slice completion.

## 8. Test specifications

| id | scenario | fixture path | expected | acceptance |
|---|---|---|---|---|
| U5T1 | CA-only PII breach, 200 residents affected | `test/fixtures/breach-notifications/ca-only-200/` | Single CA `affected_individual` letter emitted; NO AG letter (under 500 threshold); deadline = discovered_at + 30 calendar days | letter JSON matches snapshot; deadline within ±1 minute of expected |
| U5T2 | CA-only PII breach, 750 residents | `test/fixtures/breach-notifications/ca-only-750/` | Two letters: `affected_individual` (30-day) and `state_attorney_general` (15-day post-individual) | both letters emitted; AG deadline ≤ individual deadline + 15 calendar days |
| U5T3 | NY-only PII breach, 600 residents | `test/fixtures/breach-notifications/ny-only-600/` | Three letters: individual, NY AG, NYDFS regulator | NYDFS contact populated from `breach-notification-contacts.yaml` |
| U5T4 | TX-only PII breach, 300 residents | `test/fixtures/breach-notifications/tx-only-300/` | Two letters: individual (60-day), TX AG (30-day, triggers at 250) | TX AG triggered because ≥ 250 |
| U5T5 | EU-DE PII breach, 1000 data subjects | `test/fixtures/breach-notifications/eu-de-1000/` | DPA notification with GDPR Art. 33(3) data block populated; deadline = discovered_at + 72 hours (continuous clock, no business-day clamping); data-subject notification per Art. 34 also emitted | deadline computed in UTC, 72 hours exactly; Art. 33(3)(a)–(d) all populated |
| U5T6 | UK PII breach, 1000 data subjects | `test/fixtures/breach-notifications/gb-1000/` | ICO notification + data-subject notification; clock runs continuously through weekend | weekend-spanning discovered_at still yields 72h continuous deadline |
| U5T7 | Multi-state US breach: CA 500, NY 200, TX 100 | `test/fixtures/breach-notifications/multi-us/` | 4 letters: CA individual, CA AG (CA triggers at 500), NY individual, TX individual (under 250, no TX AG) | per-jurisdiction recipient-class computation correct |
| U5T8 | HIPAA covered-entity breach, 700 PHI records | `test/fixtures/breach-notifications/hipaa-700/` | Individual letter (§164.404 60-day) + HHS OCR immediate (≥ 500 trigger) | HIPAA letter uses §164.404(c) data block; HHS OCR contemporaneous |
| U5T9 | HIPAA covered-entity breach, 100 PHI records | `test/fixtures/breach-notifications/hipaa-100/` | Individual letter; HHS OCR record added to annual log (NOT emitted now) | tracker row `phase = 'annual-log-pending'`; deadline = 60 days after calendar-year end |
| U5T10 | CA substitute-notice: 600,000 affected | `test/fixtures/breach-notifications/ca-substitute-count/` | Substitute notice elected per §1798.82(j)(1)(B); 3 components emitted (email, website, statewide media) | `substitute_notice.election_basis = 'count'`; `components.length = 3` |
| U5T11 | CA substitute-notice: cost > $250,000 | `test/fixtures/breach-notifications/ca-substitute-cost/` | Substitute notice elected per §1798.82(j)(1)(A) when `cost_estimate_usd > threshold` | `election_basis = 'cost'` |
| U5T12 | GDPR phased notification: initial within 72h, follow-up later | `test/fixtures/breach-notifications/gdpr-phased/` | Initial envelope with `phase = 'initial'`; later follow-up envelope with `phase = 'follow-up'` and `parent_notification_id` populated | follow-up emitter resolves parent via tracker DB |
| U5T13 | M.M4 envelope signature invalid | `test/fixtures/breach-notifications/sig-invalid/` | Emitter exits `2` with `EnvelopeSignatureInvalidError`; no tracker rows inserted | exit code = 2; `breach_notifications` row count unchanged |
| U5T14 | `is_pii_breach: false` AND no covered-entity flag | `test/fixtures/breach-notifications/no-pii/` | Emitter exits `0` as no-op | exit code = 0; no artifacts; no tracker rows |
| U5T15 | Missing operator config: signing officer is `REQUIRES-OPERATOR-INPUT` | `test/fixtures/breach-notifications/missing-officer/` | Emitter exits `2` with `BreachNotificationOperatorConfigMissingError`; diagnostic names the missing field | exit code = 2; structured error w/ `missing_field` |
| U5T16 | Idempotency: rerun against same incident | `test/fixtures/breach-notifications/idempotent-rerun/` | Second run does NOT emit duplicate letters; tracker row count unchanged | unique index on `(incident_id, jurisdiction_code, recipient_class, phase)` enforced |
| U5T17 | Federal-customer flag set | `test/fixtures/breach-notifications/federal-customer/` | Additional `federal_agency_privacy_officer` letter emitted referencing OMB M-17-12; AO contact from `org-profile.yaml` | extra letter exists with `recipient_class = 'federal_agency_privacy_officer'` |
| U5T18 | CA letter `.docx` enforces 10pt font + 5 mandatory headings | `test/fixtures/breach-notifications/ca-docx-format/` | Parsed OOXML reveals all 5 headings present; smallest `<w:sz w:val=...>` >= 20 (10pt in half-points) | OOXML parser asserts heading presence + font-size invariant |

## 9. Risks

### R-U5-001 — Statute amendments outpace the matrix snapshot

**Severity**: HIGH. State legislatures regularly amend breach
notification statutes (CA SB-446 in 2025, NY S.2376B in 2024, TX HB
4390 in 2023). If the matrix snapshot is stale, U.U5 emits letters
citing wrong deadlines or wrong recipient classes. **Mitigation**:
`scripts/seed-state-breach-statutes.mjs` runs on a quarterly cadence;
each statute entry carries `last_revised_date`; the matrix loader
warns when any entry is > 180 days stale; LOOP-U.U1 owner is responsible
for the quarterly review.

### R-U5-002 — GDPR 72-hour continuous clock crossing weekends

**Severity**: HIGH. Per ICO §2.6 the GDPR 72h clock runs continuously
through weekends and bank holidays. A breach discovered at 18:00 Friday
yields a Monday 18:00 deadline — operators frequently miss this and
expect a Tuesday deadline. **Mitigation**: U.U5 emits an explicit
`continuous_clock: true` flag in the EU / UK notification envelopes;
the tracker UI banner says "GDPR clock runs continuously — weekend
included"; T-24h and T-1h notifications fire even at 03:00 local time.

### R-U5-003 — Substitute-notice trigger misclassified

**Severity**: MODERATE. The substitute-notice election basis (CA:
cost > $250k OR count > 500k OR insufficient contact) is operator-
asserted; if the operator over-claims (e.g. asserts
`insufficient_contact = true` for individuals whose email is on file),
they violate the statute and trigger AG enforcement. **Mitigation**:
U.U5 cross-checks `insufficient_contact` against the M.M4 envelope's
contactable-individuals count; a flagged inconsistency surfaces a
`REQUIRES-OPERATOR-CONFIRMATION` diagnostic before emission.

### R-U5-004 — Multi-Member-State EU breach routing to wrong DPA

**Severity**: HIGH. Per EDPB Guidelines 9/2022 §II.C, cross-border
breaches route to the **lead supervisory authority**, not to all
27 EU DPAs. If U.U5 emits 27 DPA notifications rather than 1 to the
lead, it (a) wastes operator capacity, (b) signals lack of
sophistication, (c) potentially triggers consistency-mechanism review.
**Mitigation**: `breach-notification-matrix.ts` consults the
`lead_supervisory_authority` field on the operator's GDPR Art. 56
registration; when populated, EU notifications route only to the lead;
when not populated, emits a `REQUIRES-OPERATOR-INPUT` diagnostic
prompting the operator to declare the lead SA.

### R-U5-005 — Plain-language attestation drift on auto-generated content

**Severity**: MODERATE. CA Civ Code §1798.82(d)(1) mandates "plain
language" with five mandatory headings. Auto-generated letter bodies
populated from incident-summary fields can lapse into jargon (e.g.
"lateral movement", "credential stuffing"). **Mitigation**: U.U5's
letter composer runs a plain-language linter
(`core/plain-language-lint.ts`) against the populated body before
signing; failed lint sets `plain_language_attested: false` and
surfaces a `REQUIRES-OPERATOR-EDIT` diagnostic in the tracker UI; the
operator either rewrites the body or accepts the lint deficit with
documented justification.

## 10. Open questions

1. **CA SB-446 verbatim text confirmation.** The 30-calendar-day cap
   is sourced from secondary commentary as of 2026-06-07 because the
   leginfo.legislature.ca.gov page may not yet reflect the 2026 Code
   edition. The implementer MUST re-verify the verbatim
   §1798.82(a)/(b) text once the 2026 Code edition is published and
   pin the URL + version date in the matrix JSON. Tracked via
   `requires_research_confirm: ['ca-1798.82(a)-sb446-amendment']`.

2. **Lead supervisory authority for the CSP's EU operations.** The
   operator's GDPR Art. 56 registration determines lead SA. If the
   CSP has not yet registered or has registered with multiple
   inconsistent declarations, U.U5 cannot determine routing. Tracked
   as `REQUIRES-OPERATOR-INPUT: lead_supervisory_authority`.

3. **Federal subcontractor scenario.** When the CSP is a
   subcontractor to a federal prime, does the federal-customer notice
   route to the prime's Privacy Officer or the agency's? Tracked as
   `REQUIRES-OPERATOR-INPUT: federal_subcontract_routing_policy`.

4. **CRA notification threshold.** Federal FCRA §609(e) sets CRA
   notification at 1000 affected; some state statutes set lower
   thresholds (e.g. Massachusetts 1000; New Hampshire any number).
   The 1000 default in §6 Phase C is a conservative federal anchor;
   the operator can override per-jurisdiction.

5. **HIPAA `breach risk assessment` automation.** §164.402's four-
   factor risk assessment is currently performed manually by the
   M.M4 classifier; U.U5 receives the result. Should U.U5 surface
   the four factors back to the operator on the HIPAA letter for
   re-attestation, or trust M.M4? Current design: trust M.M4 and
   include the four factors verbatim in the envelope provenance.

## 11. REQUIRES-OPERATOR-INPUT

| field name | type | validator | UI location | failure mode if missing |
|---|---|---|---|---|
| `signing_officer.name` | string | non-empty, length ≤ 80 | Config: `config.yaml::breach_notifications.signing_officer.name` | Phase A exit `2` |
| `signing_officer.title` | string | non-empty | Config: `config.yaml::breach_notifications.signing_officer.title` | Phase A exit `2` |
| `ed25519_signing_key_ref` | KMS resource arn / GCP resource | regex per cloud | Config: `config.yaml::breach_notifications.ed25519_signing_key_ref` | Phase A exit `2`; sign-test failure |
| `state_ag_email` per jurisdiction | email | RFC 5322 | `breach-notification-contacts.yaml::contacts[].state_ag_email` | Phase C: that jurisdiction's AG letter NOT emitted; diagnostic written |
| `dpa_email` per EU jurisdiction | email | RFC 5322 | Same file | Phase C: that jurisdiction's DPA letter NOT emitted |
| `lead_supervisory_authority` (EU only) | jurisdiction code | enum from EU MS list | Tracker UI > Privacy > Lead SA panel | Phase C: EU notifications fail-safe to ALL DPAs and surface diagnostic |
| `letter.body` per non-default-language jurisdiction | translated string | non-empty | Tracker UI > Breach Notifications > Letter draft | Phase E: `REQUIRES-OPERATOR-INPUT` literal inserted into JSON; letter NOT signed until edited |
| `substitute_notice.election_basis` (operator-confirmed for CA/TX/NY/IL) | enum | one of `cost`/`count`/`insufficient_contact` | Tracker UI form | Phase E: substitute notice NOT elected unless operator confirms |
| `recipient_acknowledgement_id` (post-transmission) | string | non-empty | Tracker UI > Mark Transmitted form | Tracker status remains `transmitted` (not `acknowledged`) until provided |
| `federal_agency_privacy_officer.email` (when federal-customer flag set) | email | RFC 5322 | `org-profile.yaml::federal_customer.privacy_officer_email` | Phase C: federal agency letter NOT emitted |

## 12. Implementation log

| date | session | action | commit | notes |
|---|---|---|---|---|
| 2026-06-07 | wf-uvxyz | Specification authored via FedPy workflow | TBD | — |

## 13. Completion checklist

> Quoted verbatim from `docs/SLICE-COMPLETION-PROCEDURE.md`:
>
> ### Step 1 — Verify the slice is REO-compliant
> Run all three guardrails. They MUST all be green:
> ```bash
> cd cloud-evidence
> npm run typecheck      # no errors
> npm test               # 100% passing (counts must increase by the slice's new tests)
> npm run check:reo      # G1+G2+G3 all green
> ```
>
> ### Step 2 — Update STATUS.md
> Open `cloud-evidence/docs/STATUS.md` and for the slice that just shipped:
> - Change `Status` column from `pending` to `done`
> - Fill `Commit` with the PENDING commit's short hash (you'll know it after step 5)
> - Fill `Date` with today's date (ISO format YYYY-MM-DD)
> - If this was the last slice in a loop, change the loop's title section to indicate "(COMPLETE)"
> - Update the "Overall" section: increment loops-complete, change last-shipped, update next-priority
>
> ### Step 3 — Update the loop's spec doc
> Open `cloud-evidence/docs/loops/LOOP-X-SPEC.md` (where X is your loop letter).
> Find the "Status tracking" section table.
> For your slice row: status=done, commit=<hash>, date=<ISO>.
>
> ### Step 4 — Add CHANGELOG entry
> Open `/Users/kenith.philip/FedRAMP 20x/CHANGELOG.md`.
> Add a new entry at the TOP of "Unreleased":
>
> ### Added — LOOP-X.XN: <Slice title>
> <2-3 paragraphs describing what shipped, module names, file paths, verification counts (typecheck clean, NNN/NNN tests passing, npm run check:reo returns 0).>
>
> ### Step 5 — Commit
> ```bash
> cd /Users/kenith.philip/FedRAMP\ 20x
> git add cloud-evidence/<modified files> cloud-evidence/docs/STATUS.md cloud-evidence/docs/loops/LOOP-X-SPEC.md CHANGELOG.md
> git commit -m "LOOP-X.XN: <slice title>
> <detailed commit message describing the slice>
> Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
> ```
>
> ### Step 6 — Update commit hash in STATUS.md + loop spec
> Now that the commit exists, get its hash:
> ```bash
> git log -1 --format=%h
> ```
> Open STATUS.md + the loop's spec doc — paste the actual commit hash in the rows you updated in step 2+3.
> Amend the commit:
> ```bash
> git add cloud-evidence/docs/STATUS.md cloud-evidence/docs/loops/LOOP-X-SPEC.md
> git commit --amend --no-edit
> ```
>
> ### Step 7 — Push
> ```bash
> git push origin main
> ```
>
> Step 8: After commit lands, append/update the slice row in STATUS.md (status -> done, commit hash, last_updated); update the loop SPEC status table; append a CHANGELOG entry; push to origin/main; verify with 'git log --oneline -3'. Only THEN is the slice closed.
