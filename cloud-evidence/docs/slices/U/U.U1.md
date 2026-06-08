---
slice_id: U.U1
title: Privacy-Frameworks Catalog Ingestion + Canonicalization (FERPA + COPPA + GLBA + CCPA/CPRA + GDPR + UK GDPR + NY SHIELD + 50-State Breach Matrix + NIST Privacy Framework v1.0 + SP 800-53 Rev 5 PT family)
loop: U
status: proposed
commit: TBD
completed_date: —
depends_on:
  - LOOP-A.A5                           # Ed25519 + RFC 3161 signing pipeline (catalog must be signed at rest)
blocks:
  - U.U2                                # PII discovery + classification consumes the catalog
  - U.U3                                # DPIA/PIA template emitter cites catalog by stable UID
  - U.U4                                # Privacy incident response routes per state-breach matrix rows
  - U.U5                                # Operator privacy-rights handler enforces statutory clocks from catalog rows
estimated_effort: medium (~5-7 working days for single implementer)
last_updated: 2026-06-07
applicable_conditional: true
condition: |
  Any CSP processing PII for: (a) students subject to FERPA (20 U.S.C. §1232g),
  (b) children under 13 subject to COPPA (15 U.S.C. §§6501-6506), (c) financial
  customers subject to the GLBA Safeguards Rule (16 CFR Part 314), (d) California
  residents (CCPA/CPRA — Cal. Civ. Code §§1798.100 et seq.), (e) New York
  residents (NY SHIELD Act — N.Y. Gen. Bus. Law §899-bb; breach notification
  §899-aa), (f) EU/EEA residents (GDPR — Regulation (EU) 2016/679), (g) UK
  residents (UK GDPR + Data Protection Act 2018), or (h) residents of any U.S.
  state covered by a breach-notification regime (50 states + DC + 4 territories).
  Trigger: operator sets `privacy.applicable = true` in `org-profile.yaml` OR
  the LOOP-U.U2 PII discovery surfaces a non-empty PII inventory. Either
  predicate flips the slice into the active path.
trigger_flag: "--privacy-frameworks-catalog"
trigger_env: CLOUD_EVIDENCE_PRIVACY_FRAMEWORKS_CATALOG
---

# U.U1 — Privacy-Frameworks Catalog Ingestion + Canonicalization

> U.U1 is the **catalog primitive** for LOOP-U. It is the on-disk source of
> truth that every downstream privacy emitter (U.U2 discovery, U.U3 DPIA,
> U.U4 incident response, U.U5 rights handling) reads to compute statutory
> deadlines, route notifications, render DPIAs, and validate operator
> configuration. Because U.U1 publishes the legal calendar for every other
> LOOP-U slice, it carries the same rigor as LOOP-W.W1 / W.W3: verbatim
> statutory quotes, signed JSON envelopes, idempotent re-ingestion, and a
> per-row provenance chain back to the original statute, regulation,
> Federal Register entry, NIST SP, or state attorney-general publication.

## 1. Mission

U.U1 ingests the full U.S. + EU + UK privacy-frameworks corpus and
emits two signed canonical JSON catalogs that downstream slices consume:

1. `cloud-evidence/data/privacy-frameworks-catalog.json` — the cross-
   framework catalog. One row per **framework** (FERPA, COPPA, GLBA
   Safeguards, CCPA/CPRA, GDPR, UK GDPR, NY SHIELD, NIST Privacy
   Framework v1.0, NIST SP 800-53 Rev 5 PT family). Each row carries
   stable `framework_uid`, statutory citation, scope predicate
   (who-is-covered), data-element predicate (what-PII-triggers),
   operator-controllable obligations (notice, consent, access,
   correction, deletion, portability), enforcement authority, maximum
   civil penalty per the latest published regulation, and the set of
   stable obligation-uids that other slices reference.

2. `cloud-evidence/data/state-breach-notification-matrix.json` — the
   50-state + DC + 4-territory breach-notification matrix. One row per
   jurisdiction with: stable `jurisdiction_uid` (ISO-3166-2 code), the
   operative statute citation, the definition of "personal information"
   in that jurisdiction, the trigger predicate (acquisition vs access vs
   reasonable belief), the notification deadline (in calendar days or
   "expedient" with a documented ceiling), the AG notification
   threshold, the regulator endpoint, the safe-harbor predicate (e.g.
   encryption with separately stored key), and the maximum civil
   penalty.

Both catalogs are loaded by `cloud-evidence/core/privacy-frameworks-
catalog.ts` which exposes a stable, typed read-only API:

```ts
export function loadPrivacyFrameworksCatalog(): PrivacyFrameworkRow[];
export function loadStateBreachMatrix(): StateBreachMatrixRow[];
export function findFramework(uid: string): PrivacyFrameworkRow;
export function findJurisdiction(uid: string): StateBreachMatrixRow;
export function obligationsFor(jurisdictionUids: string[],
  dataElements: PiiElementKind[]): Obligation[];
```

The ingester `scripts/extract-privacy-frameworks.mjs` runs OFFLINE
against committed source-text mirrors under `docs/sources/privacy/`.
The operator (or CI) refreshes the mirrors annually each January per
the SLICE-COMPLETION-PROCEDURE Step 6 + the operator-input cadence
documented in §11.

U.U1 does **not** decide which frameworks apply to the operator — that
is U.U2's job. U.U1 publishes the universe; U.U2 filters it against the
operator's actual PII inventory + customer geography.

## 2. Authoritative sources

Every URL accessed 2026-06-07. Verbatim quotes appear in Markdown
blockquotes. Where the live source returns a non-200 to anonymous
fetches, the operator mirrors the page or PDF to
`cloud-evidence/docs/sources/privacy/` and re-quotes verbatim from the
local copy. Each row in the emitted catalogs carries a `source_ref`
pointing at the mirror so a 3PAO can reconstruct the catalog from the
on-disk evidence alone.

### 2.1 FERPA — Family Educational Rights and Privacy Act (20 U.S.C. §1232g)

URL: https://www.govinfo.gov/content/pkg/USCODE-2022-title20/html/USCODE-2022-title20-chap31-subchapIII-part4-sec1232g.htm (accessed 2026-06-07).

§1232g(b)(1) — the core prohibition on disclosure without consent:

> "No funds shall be made available under any applicable program to any
> educational agency or institution which has a policy or practice of
> permitting the release of education records (or personally
> identifiable information contained therein other than directory
> information, as defined in paragraph (5) of subsection (a)) of
> students without the written consent of their parents to any
> individual, agency, or organization, other than to the following—
> (A) other school officials, including teachers within the educational
> institution or local educational agency, who have been determined by
> such agency or institution to have legitimate educational interests".

Implementing regulation: 34 CFR Part 99. URL:
https://www.ecfr.gov/current/title-34/subtitle-A/part-99 (accessed
2026-06-07). 34 CFR §99.31 lists the disclosure exceptions; 34 CFR
§99.35 covers studies for/on behalf of an educational agency; the
"school official" exception at §99.31(a)(1)(i)(B) is the operative path
for a SaaS CSP that processes student records on behalf of an
LEA/IHE.

> "(B) A contractor, consultant, volunteer, or other party to whom an
> agency or institution has outsourced institutional services or
> functions may be considered a school official under this paragraph
> provided that the outside party—
> (1) Performs an institutional service or function for which the
> agency or institution would otherwise use employees;
> (2) Is under the direct control of the agency or institution with
> respect to the use and maintenance of education records; and
> (3) Is subject to the requirements of §99.33(a) governing the use
> and redisclosure of personally identifiable information from
> education records."

These requirements feed the U.U1 catalog row for FERPA: the obligation
uids `ferpa.school-official-status`, `ferpa.no-redisclosure-without-
consent`, `ferpa.annual-notification-of-rights`,
`ferpa.directory-information-opt-out`. Each obligation row in the
catalog carries the `34_cfr_section` field so DPIAs cite the
regulation paragraph the obligation comes from.

### 2.2 COPPA — Children's Online Privacy Protection Act + Rule (15 U.S.C. §§6501-6506; 16 CFR Part 312)

Statute URL: https://www.law.cornell.edu/uscode/text/15/chapter-91
(accessed 2026-06-07). Rule URL:
https://www.ecfr.gov/current/title-16/chapter-I/subchapter-C/part-312
(accessed 2026-06-07).

15 U.S.C. §6502(b)(1)(A) — the verifiable-parental-consent obligation:

> "It is unlawful for an operator of a website or online service
> directed to children, or any operator that has actual knowledge that
> it is collecting personal information from a child, to collect
> personal information from a child in a manner that violates the
> regulations prescribed under subsection (b)."

16 CFR §312.3 — the substantive rule (verbatim from the FTC Rule):

> "General requirements. It shall be unlawful for any operator of a
> Web site or online service directed to children, or any operator
> that has actual knowledge that it is collecting or maintaining
> personal information from a child, to collect personal information
> from a child in a manner that violates the regulations prescribed
> under this part."

16 CFR §312.4 — the notice requirement (drives the U.U3 DPIA template):

> "Notice on the Web site or online service. In addition to the direct
> notice to the parent, an operator must post a prominent and clearly
> labeled link to an online notice of its information practices with
> regard to children on the home or landing page or screen of its Web
> site or online service, and, at each area of the Web site or online
> service where personal information is collected from children."

16 CFR §312.10 — the data-retention + deletion obligation (drives
U.U5):

> "An operator of a Web site or online service shall retain personal
> information collected online from a child for only as long as is
> reasonably necessary to fulfill the purpose for which the
> information was collected. The operator must delete such information
> using reasonable measures to protect against unauthorized access to,
> or use of, the information in connection with its deletion."

The catalog row for COPPA carries the obligation uids
`coppa.verifiable-parental-consent`, `coppa.notice-on-site`,
`coppa.direct-notice-to-parent`, `coppa.no-conditioning-participation`,
`coppa.parent-right-to-review`, `coppa.delete-on-request`,
`coppa.retention-only-as-needed`, `coppa.confidentiality-security-
integrity`. Enforcement authority = FTC + State Attorneys General;
maximum civil penalty per 15 U.S.C. §45(m)(1)(A) = $51,744 per
violation (FTC inflation-adjusted; the catalog row carries the
`max_penalty_usd_per_violation` integer + the `penalty_basis_url`
pointing at the FR notice that set the value).

### 2.3 GLBA Safeguards Rule (16 CFR Part 314, as amended Dec 2021)

URL: https://www.ecfr.gov/current/title-16/chapter-I/subchapter-C/part-314
(accessed 2026-06-07).

16 CFR §314.4 — the nine elements of an information security program:

> "(a) Designate a qualified individual responsible for overseeing and
> implementing your information security program and enforcing your
> information security program (Qualified Individual).
> (b) Base your information security program on a risk assessment that
> identifies reasonably foreseeable internal and external risks to the
> security, confidentiality, and integrity of customer information ...
> (c) Design and implement safeguards to control the risks you
> identify through risk assessment, including by:
> (1) Implementing and periodically reviewing access controls ...
> (2) Identify and manage the data, personnel, devices, systems, and
> facilities ...
> (3) Protect by encryption all customer information held or
> transmitted by you both in transit over external networks and at
> rest. ...
> (4) Adopt secure development practices for in-house developed
> applications ...
> (5) Implement multi-factor authentication for any individual
> accessing any information system ...
> (6) Develop, implement, and maintain procedures for the secure
> disposal of customer information ...
> (7) Adopt procedures for change management; and
> (8) Implement policies, procedures, and controls designed to monitor
> and log the activity of authorized users ...
> (d) Regularly test or otherwise monitor the effectiveness of the
> safeguards' key controls, systems, and procedures ...
> (e) Implement policies and procedures to ensure that personnel are
> able to enact your information security program ...
> (f) Oversee service providers ...
> (g) Evaluate and adjust your information security program ...
> (h) Establish a written incident response plan ...
> (i) Require your Qualified Individual to report in writing,
> regularly and at least annually, to your board of directors or
> equivalent governing body."

The Oct 27, 2023 amendment (Federal Register Vol. 88 No. 207) added
§314.5 — the 30-day FTC notification clock for security events
involving ≥500 consumers:

URL: https://www.federalregister.gov/documents/2023/11/13/2023-24412/standards-for-safeguards-customer-information
(accessed 2026-06-07).

> "(a) Notification to Federal Trade Commission. As soon as possible,
> and no later than 30 days after discovery of a notification event,
> the financial institution shall notify the Federal Trade
> Commission."

> "(b) Notification event. For purposes of this section, notification
> event means acquisition of unencrypted customer information without
> the authorization of the individual to which the information
> pertains. Customer information is considered unencrypted for this
> purpose if the encryption key was accessed by an unauthorized
> person."

The catalog row for GLBA carries `glba.safeguards-rule-9-elements` plus
nine sub-obligations and `glba.ftc-30-day-notification`. The
state-breach matrix's GLBA-preemption row records that GLBA preempts
state breach statutes only for "financial institutions" as defined in
16 CFR §314.2(h) — the catalog row enumerates that scope predicate
verbatim.

### 2.4 CCPA / CPRA (Cal. Civ. Code §§1798.100-1798.199.100; 11 CCR §§7000-7304)

Statute URL: https://leginfo.legislature.ca.gov/faces/codes_displayText.xhtml?division=3.&part=4.&lawCode=CIV&title=1.81.5
(accessed 2026-06-07).

§1798.100(a) — the consumer right to know:

> "A consumer shall have the right to request that a business that
> collects a consumer's personal information disclose to that
> consumer the following:
> (1) The categories of personal information it has collected about
> that consumer.
> (2) The categories of sources from which the personal information
> is collected.
> (3) The business or commercial purpose for collecting, selling, or
> sharing personal information.
> (4) The categories of third parties to whom the business discloses
> personal information.
> (5) The specific pieces of personal information it has collected
> about that consumer."

§1798.105(a) — the right to delete:

> "A consumer shall have the right to request that a business delete
> any personal information about the consumer which the business has
> collected from the consumer."

§1798.130(a)(2)(A) — the 45-day response deadline:

> "Disclose and deliver the required information to a consumer free
> of charge ... within 45 days of receiving a verifiable consumer
> request from the consumer."

§1798.155(a) — the civil penalty per CPRA:

> "Any business, service provider, contractor, or other person that
> violates this title shall be liable for an administrative fine of
> not more than two thousand five hundred dollars ($2,500) for each
> violation or seven thousand five hundred dollars ($7,500) for each
> intentional violation and each violation involving the personal
> information of consumers whose age the business, service provider,
> contractor, or other person has actual knowledge is less than 16
> years of age."

CCPA Regulations (11 CCR §7012) — privacy-policy contents — drive the
U.U3 DPIA template. Each obligation row in the catalog carries the
`ccr_section` field so DPIAs cite the regulation paragraph.

### 2.5 GDPR — Regulation (EU) 2016/679

URL: https://eur-lex.europa.eu/eli/reg/2016/679/oj (accessed
2026-06-07). The operator mirrors the consolidated text PDF to
`docs/sources/privacy/gdpr-consolidated.pdf`.

Article 5(1) — the principles relating to processing of personal data:

> "Personal data shall be:
> (a) processed lawfully, fairly and in a transparent manner in
> relation to the data subject ('lawfulness, fairness and
> transparency');
> (b) collected for specified, explicit and legitimate purposes and
> not further processed in a manner that is incompatible with those
> purposes ('purpose limitation');
> (c) adequate, relevant and limited to what is necessary in relation
> to the purposes for which they are processed ('data minimisation');
> (d) accurate and, where necessary, kept up to date ('accuracy');
> (e) kept in a form which permits identification of data subjects for
> no longer than is necessary ('storage limitation');
> (f) processed in a manner that ensures appropriate security of the
> personal data ('integrity and confidentiality')."

Article 33(1) — the 72-hour breach notification clock:

> "In the case of a personal data breach, the controller shall without
> undue delay and, where feasible, not later than 72 hours after
> having become aware of it, notify the personal data breach to the
> supervisory authority competent in accordance with Article 55,
> unless the personal data breach is unlikely to result in a risk to
> the rights and freedoms of natural persons."

Article 35 — Data Protection Impact Assessment trigger (drives U.U3):

> "Where a type of processing in particular using new technologies,
> and taking into account the nature, scope, context and purposes of
> the processing, is likely to result in a high risk to the rights
> and freedoms of natural persons, the controller shall, prior to the
> processing, carry out an assessment of the impact of the envisaged
> processing operations on the protection of personal data."

Article 83(5) — the maximum administrative fine tier:

> "Infringements of the following provisions shall, in accordance with
> paragraph 2, be subject to administrative fines up to 20 000 000
> EUR, or in the case of an undertaking, up to 4 % of the total
> worldwide annual turnover of the preceding financial year, whichever
> is higher".

The catalog row for GDPR carries 16 distinct obligation uids covering
the Article 5 principles, Article 6 lawful bases, Article 7 consent,
Article 9 special categories, the data-subject rights of Articles
12-22, Articles 24-32 controller/processor duties, Article 33/34
breach notifications, Article 35 DPIAs, and Articles 44-49 international
transfers (post-Schrems II + 2023 EU-US Data Privacy Framework).

### 2.6 UK GDPR + Data Protection Act 2018

URL: https://www.legislation.gov.uk/ukpga/2018/12/contents (accessed
2026-06-07). Post-Brexit, the UK retained the GDPR as "UK GDPR" under
the European Union (Withdrawal) Act 2018 + the Data Protection,
Privacy and Electronic Communications (Amendments etc) (EU Exit)
Regulations 2019.

The catalog row for UK GDPR mirrors the GDPR row except for:

- Supervisory authority = Information Commissioner's Office (ICO).
- Breach-notification endpoint = ICO breach-reporting service at
  https://ico.org.uk/for-organisations/report-a-breach/ (accessed
  2026-06-07).
- Maximum fine = £17.5m or 4% global turnover (per DPA 2018 §157).
- DPIA threshold + international-transfer rules diverged after the
  June 2023 UK-US Data Bridge announcement and the March 2024 ICO
  guidance update; the catalog row's `last_review_date` records the
  ICO source-text mirror date.

### 2.7 NY SHIELD Act + §899-aa breach notification (N.Y. Gen. Bus. Law §§899-aa, 899-bb)

URL: https://www.nysenate.gov/legislation/laws/GBS/A39-F (accessed
2026-06-07; the operator mirrors the consolidated text to
`docs/sources/privacy/ny-shield-gbl-899.html`).

§899-aa(2) — the breach-notification trigger and timing:

> "Any person or business which owns or licenses computerized data
> which includes private information shall disclose any breach of the
> security of the system following discovery or notification of the
> breach in the security of the system to any resident of New York
> state whose private information was, or is reasonably believed to
> have been, accessed or acquired by a person without valid
> authorization. The disclosure shall be made in the most expedient
> time possible and without unreasonable delay, consistent with the
> legitimate needs of law enforcement ... or any measures necessary
> to determine the scope of the breach and restore the reasonable
> integrity of the data system."

§899-bb(2) — the reasonable-safeguards obligation (the "SHIELD" half):

> "Any person or business that owns or licenses computerized data
> which includes private information of a resident of New York shall
> develop, implement and maintain reasonable safeguards to protect
> the security, confidentiality and integrity of the private
> information including, but not limited to, disposal of data."

The state-breach matrix's NY row carries `NY` ISO code, deadline =
"expedient / without unreasonable delay" (no fixed day ceiling; the
catalog row records the documented practitioner ceiling of
**30 calendar days** as derived from NY AG enforcement actions cited
in §11), AG notification = required, civil penalty = up to $5,000 per
violation or $20 per instance up to $250,000 (per §899-aa(6)).

### 2.8 NIST Privacy Framework v1.0 (NIST PRIVACYFRAMEWORK-2020)

URL: https://www.nist.gov/privacy-framework (accessed 2026-06-07).
PDF mirror: https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.01162020.pdf
(operator mirrors to `docs/sources/privacy/NIST.CSWP.01162020.pdf`).

The Privacy Framework's Core has five functions (IDENTIFY-P, GOVERN-P,
CONTROL-P, COMMUNICATE-P, PROTECT-P) decomposed into 18 categories and
100 subcategories. Subcategory ID-IM-P1 — identification of the
processing of personal data — is the anchor for U.U2:

> "ID.IM-P1: Systems/products/services that process data are
> inventoried."

> "ID.IM-P3: Categories of individuals (e.g., customers, employees or
> prospective employees, consumers) whose data are being processed are
> inventoried."

> "ID.IM-P4: Data actions of the systems/products/services are
> inventoried."

The catalog row for the NIST Privacy Framework carries one obligation
uid per subcategory (100 total) with the subcategory id verbatim
("ID.IM-P1"), the function/category, and the informative-reference
mapping to NIST SP 800-53 Rev 5 controls per the Privacy Framework's
Informative Reference Catalog (the operator mirrors the catalog
spreadsheet to `docs/sources/privacy/privacy-framework-informative-
references.xlsx`).

### 2.9 NIST SP 800-53 Rev 5 — PT (Personally Identifiable Information Processing and Transparency) Control Family

URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
(accessed 2026-06-07; operator mirrors to
`docs/sources/privacy/NIST.SP.800-53r5.pdf`).

The PT family has 8 base controls (PT-1 through PT-8) and 13
enhancements. PT-1 establishes the policy + procedures; PT-2 covers
authority to process PII; PT-3 covers purpose specification; PT-4
covers consent; PT-5 covers privacy notice; PT-6 covers SORN; PT-7
covers specific categories of PII; PT-8 covers computer matching
requirements.

PT-3 — purpose specification — sets the obligation that drives the
U.U3 DPIA's purpose-statement section:

> "PT-3: Identify and document the [Assignment: organization-defined
> purpose(s)] for processing personally identifiable information; and
> describe the purpose(s) in the public privacy notices and policies
> of the organization."

PT-5(2) — privacy notice content — drives the privacy-policy generator:

> "PT-5(2) PRIVACY NOTICES — PRIVACY ACT STATEMENTS: Include Privacy
> Act statements on forms that collect information that will be
> maintained in a Privacy Act system of records, or provide Privacy
> Act statements on separate forms that can be retained by
> individuals."

The catalog row for SP 800-53 PT family carries one obligation uid per
base control + each enhancement (21 total). The
`informative_references` field cross-walks each PT control to its
Privacy Framework subcategory per the NIST published mapping.

### 2.10 NCSL 50-state breach matrix + IAPP tracker

NCSL URL: https://www.ncsl.org/technology-and-communication/security-breach-notification-laws
(accessed 2026-06-07; operator mirrors HTML to
`docs/sources/privacy/ncsl-state-breach-laws.html`).

> "All 50 states, the District of Columbia, Guam, Puerto Rico and the
> Virgin Islands have enacted legislation requiring private or
> governmental entities to notify individuals of security breaches of
> information involving personally identifiable information."

NCSL provides per-state citation indices but does not publish the
operative statutory text. U.U1's ingester walks the NCSL index,
follows each per-state citation to the state legislature's official
publication (Westlaw / LexisNexis / state-AG page), mirrors the page
or PDF to `docs/sources/privacy/state-breach/<jurisdiction>.html` (or
.pdf), and extracts the four required fields per row: definition of
"personal information", trigger predicate, notification deadline, AG
endpoint. Where an operative deadline is "without unreasonable delay"
without a fixed ceiling, the catalog row records `deadline_days = null`
+ `deadline_text = "without unreasonable delay"` + the practitioner-
documented ceiling derived from the most recent AG enforcement action
or the most recent secondary-source synthesis (IAPP Westin Center
publishes an annual synthesis; the operator mirrors the most recent PDF
to `docs/sources/privacy/iapp-state-breach-synthesis-YYYY.pdf`).

For 2026, the ingester pre-seeds the following deadline anchors per
the IAPP 2025 synthesis (operator must re-verify each January):

| Jurisdiction | Deadline | Statutory citation |
|---|---|---|
| Florida | 30 days | Fla. Stat. §501.171(4)(a) |
| Texas | 60 days | Tex. Bus. & Com. Code §521.053(b) |
| Washington | 30 days | RCW 19.255.010(8) |
| Illinois (BIPA / PIPA) | "most expedient time possible" | 815 ILCS 530/10 |
| Massachusetts | "as soon as practicable and without unreasonable delay" | M.G.L. c. 93H §3(b) |
| Maine | 30 days | 10 M.R.S. §1348(1) |
| Vermont | 45 days | 9 V.S.A. §2435(b)(1) |
| Maryland | 45 days | Md. Code Comm. Law §14-3504(b) |
| Colorado | 30 days + AG notification ≥500 | Colo. Rev. Stat. §6-1-716(2) |
| Connecticut | 60 days | Conn. Gen. Stat. §36a-701b(b) |

The remaining 40 jurisdictions are similarly anchored — each carries a
`statutory_citation` + `source_ref` mirror; the ingester refuses to
emit a row whose mirror is missing or whose mirror's SHA-256 does not
match the recorded value.

## 3. Scope

### 3.1 In scope

- Offline ingestion of the FERPA + COPPA + GLBA + CCPA/CPRA + GDPR +
  UK GDPR + NY SHIELD + NIST PF + SP 800-53 PT source-text mirrors
  under `docs/sources/privacy/`.
- Production of `cloud-evidence/data/privacy-frameworks-catalog.json`
  (signed Ed25519 + RFC 3161-timestamped) with one row per framework.
- Production of `cloud-evidence/data/state-breach-notification-
  matrix.json` (signed) with one row per U.S. jurisdiction (50 states
  + DC + Guam + Puerto Rico + U.S. Virgin Islands = 54 rows).
- Stable framework_uid + obligation_uid + jurisdiction_uid scheme that
  downstream slices key off of.
- Verbatim source-text excerpt per obligation, with the verbatim
  string AND its SHA-256 stored on the row so a downstream tampering
  attack is detectable.
- Ajv JSON-schema validation of both catalogs at load time.
- Idempotent re-ingestion: the same input mirrors produce the same
  catalog (modulo `extracted_at` timestamp + signature).
- TypeScript loader API (`core/privacy-frameworks-catalog.ts`) with
  zero runtime dependencies beyond `node:fs` + the shared signing
  module.
- Pre-seeded penalty constants (CCPA $2,500/$7,500, GDPR €20M/4%,
  COPPA $51,744) with `penalty_basis_url` provenance.
- Pre-seeded informative-reference mappings: NIST PF subcategories ↔
  SP 800-53 PT controls (per the NIST published mapping spreadsheet).

### 3.2 Out of scope (NOT in U.U1)

- **PII discovery** in operator data. Owned by U.U2.
- **DPIA / PIA generation.** Owned by U.U3.
- **Breach incident-response routing + emission.** Owned by U.U4.
- **Data-subject rights handler.** Owned by U.U5.
- **HIPAA + HITECH.** Owned by LOOP-M (separate slice — HIPAA's
  Business Associate Agreement contract path is distinct from the
  consumer-privacy regimes here).
- **VPPA (18 U.S.C. §2710), CalOPPA, COPPA's children-directed
  marketplaces.** Excluded — U.U1 covers general PII; specialized
  regimes are scheduled for a future LOOP-U.U6 if operator scope
  requires.
- **State biometric statutes (BIPA, TX CUBI, WA H.B.1493).** Partially
  in scope: the U.U1 state-breach matrix records BIPA as an Illinois
  row, but BIPA's substantive consent + private-right-of-action rules
  are not modeled — those go in a future LOOP-U.U6 if needed.
- **Online tracking regimes (TCPA, CAN-SPAM).** Out of scope — these
  are marketing-channel statutes, not PII-protection statutes per se.

## 4. Inputs

### 4.1 Mirrored source files (the ingester reads these)

All under `cloud-evidence/docs/sources/privacy/`:

```ts
interface PrivacySourceMirror {
  framework_uid: string;                    // e.g. 'ferpa', 'coppa', 'gdpr'
  source_url: string;                       // canonical URL (for provenance only)
  mirror_path: string;                      // relative to repo root
  mirror_sha256: string;                    // SHA-256 of the mirrored bytes
  mirror_format: 'html' | 'pdf' | 'xml' | 'plaintext';
  accessed_at: string;                      // ISO 8601 — date of mirror capture
  publisher: string;                        // 'GovInfo' | 'eCFR' | 'EUR-Lex' | etc.
  publication_date: string;                 // ISO 8601 — when the source published
}
```

The full set of required mirrors is fixed at 12 + 54 = 66 files (one
per framework + one per jurisdiction).

### 4.2 Operator configuration

Path: `cloud-evidence/config.yaml`. Privacy-specific block:

```yaml
privacy:
  applicable: true                          # mandatory boolean — U.U2 reads this
  frameworks:
    ferpa:
      applicable: false                     # operator confirms FERPA scope
      role: school-official                 # | direct-controller | none
    coppa:
      applicable: false
      services_directed_to_children: false
    glba:
      applicable: false                     # is the CSP a "financial institution"?
    ccpa:
      applicable: true                      # CA residents present?
    gdpr:
      applicable: false                     # EU/EEA residents present?
    uk_gdpr:
      applicable: false
    ny_shield:
      applicable: false
  state_breach_jurisdictions:
    - CA
    - NY
    - TX
    # ... operator-supplied subset of the 54
  signing:
    catalog_signing_key_ref: REQUIRES-OPERATOR-INPUT
```

When `privacy.applicable = false` and the U.U2 PII inventory is empty,
U.U1 still ingests + emits the catalog (the catalog is reference data
that exists independent of operator scope), but downstream slices do
not consume it — they exit no-op.

### 4.3 The catalog signing key

U.U1 signs the emitted catalogs with the operator's Ed25519 catalog-
signing key per LOOP-A.A5. The key reference is supplied in
`config.yaml::privacy.signing.catalog_signing_key_ref` and resolved
against the operator's KMS (AWS KMS / GCP KMS / HashiCorp Vault).

## 5. Outputs

### 5.1 Canonical JSON — `privacy-frameworks-catalog.json`

```ts
interface PrivacyFrameworksCatalog {
  schema_version: '1.0.0';
  catalog_id: string;                       // ULID
  generated_at: string;                     // ISO 8601 UTC
  ingester_version: string;
  source_corpus: {
    mirror_count: number;
    mirror_checksums: { path: string; sha256: string }[];
  };
  frameworks: PrivacyFrameworkRow[];
  signature: { alg: 'ed25519'; key_id: string; sig: string };
  rfc3161_timestamp: { tsa_url: string; token: string; received_at: string };
}

interface PrivacyFrameworkRow {
  framework_uid: string;                    // 'ferpa' | 'coppa' | 'glba' | ...
  display_name: string;                     // 'Family Educational Rights and Privacy Act'
  jurisdiction_scope: 'US-federal' | 'US-state' | 'EU' | 'UK' | 'international';
  jurisdiction_codes: string[];             // ISO-3166 codes
  statutory_citations: Array<{
    citation: string;                       // '20 U.S.C. §1232g'
    title: string;
    source_url: string;
    source_mirror: string;                  // path under docs/sources/privacy/
    source_mirror_sha256: string;
    accessed_at: string;
  }>;
  scope_predicate: {
    description: string;                    // who is covered
    verbatim_excerpt: string;
    verbatim_excerpt_sha256: string;
  };
  data_element_predicate: {
    description: string;                    // what PII triggers
    pii_categories: PiiCategory[];          // from a closed enum
    special_categories: string[];           // children's data, biometric, health, etc.
  };
  obligations: Obligation[];
  enforcement_authority: string;            // 'FTC' | 'State AGs' | 'EU SAs' | 'ICO' | ...
  max_penalty: {
    amount_usd_equivalent: number | null;   // null if % turnover
    amount_native_currency: { value: number; currency: string };
    basis: 'per-violation' | 'per-incident' | 'per-record' | 'aggregate-cap';
    basis_url: string;                      // FR notice or statute URL
    last_review_date: string;
  };
  breach_notification?: {
    applicable: boolean;
    deadline_days: number | null;           // null if "without undue delay"
    deadline_text: string;
    regulator_endpoint: string;
    individual_threshold: number | null;    // e.g. 500 for GLBA §314.5
    safe_harbor_predicate?: string;         // e.g. "encryption with separately stored key"
  };
  last_review_date: string;                 // when the operator last re-verified the row
  provenance: {
    extracted_at: string;
    extractor: 'extract-privacy-frameworks.mjs';
    extractor_version: string;
    extractor_input_sha256s: { path: string; sha256: string }[];
  };
}

interface Obligation {
  obligation_uid: string;                   // 'ferpa.school-official-status'
  short_name: string;
  description: string;
  citation: string;                         // '34 CFR §99.31(a)(1)(i)(B)'
  verbatim_excerpt: string;
  verbatim_excerpt_sha256: string;
  applies_to_role: ('controller' | 'processor' | 'school-official' |
                    'financial-institution' | 'operator')[];
  operator_controllable: boolean;           // true if a tech control can satisfy
  drives_emitter: ('U.U3-DPIA' | 'U.U4-Breach' | 'U.U5-Rights' |
                   'config.yaml')[];
}
```

### 5.2 Canonical JSON — `state-breach-notification-matrix.json`

```ts
interface StateBreachMatrix {
  schema_version: '1.0.0';
  matrix_id: string;                        // ULID
  generated_at: string;
  jurisdictions: StateBreachMatrixRow[];
  signature: { alg: 'ed25519'; key_id: string; sig: string };
  rfc3161_timestamp: { tsa_url: string; token: string; received_at: string };
}

interface StateBreachMatrixRow {
  jurisdiction_uid: string;                 // 'US-CA' | 'US-NY' | 'US-TX' | ...
  display_name: string;                     // 'California'
  statutory_citation: string;               // 'Cal. Civ. Code §1798.82'
  citation_url: string;
  citation_mirror: string;
  citation_mirror_sha256: string;
  accessed_at: string;
  personal_information_definition: {
    verbatim_excerpt: string;
    verbatim_excerpt_sha256: string;
    includes: ('SSN' | 'DLN' | 'financial-acct' | 'credit-card' |
               'medical-info' | 'health-insurance' | 'biometric' |
               'email-with-password' | 'username-with-credential' |
               'passport' | 'tribal-id' | 'geolocation' | 'genetic')[];
  };
  trigger_predicate: 'acquisition' |
                     'access' |
                     'reasonable-belief-of-unauthorized-access' |
                     'compromise-of-confidentiality';
  notification_deadline: {
    individuals: {
      deadline_days: number | null;
      deadline_text: string;                // "without unreasonable delay" | "30 days"
      starts_at: 'discovery' | 'reasonable-belief' | 'investigation-complete';
    };
    attorney_general: {
      required: boolean;
      threshold_individuals: number | null;  // e.g. 500 for CA
      deadline_days: number | null;
    };
    consumer_reporting_agencies: {
      required: boolean;
      threshold_individuals: number | null;
    };
  };
  safe_harbor: {
    encryption: boolean;
    redaction: boolean;
    risk_of_harm: boolean;
    description: string;
  };
  preempted_by_federal: ('GLBA' | 'HIPAA' | 'FCRA' | 'none')[];
  max_penalty: {
    amount_usd: number | null;
    basis: string;
    citation: string;
  };
  enforcement_authority: string;
  last_review_date: string;
  provenance: { /* same shape as PrivacyFrameworkRow.provenance */ };
}
```

### 5.3 Loader module — `cloud-evidence/core/privacy-frameworks-catalog.ts`

Exposes the typed read-only API from §1, plus:

- `verifyCatalogSignature(path: string, keyRef: string): Promise<void>`
  — fails if Ed25519 sig is invalid OR if any
  `verbatim_excerpt_sha256` does not match the recomputed hash of
  `verbatim_excerpt`.
- `verifyAllMirrorHashes(catalogPath: string, mirrorDir: string):
  Promise<MirrorVerificationReport>` — recomputes SHA-256 over every
  mirror path referenced and reports drift.

### 5.4 No tracker DB row (catalog is on-disk reference data)

U.U1 does NOT write to the tracker DB. The catalogs are static on-disk
reference artifacts. Downstream slices (U.U4) write tracker rows that
reference catalog rows by `framework_uid` + `jurisdiction_uid`.

## 6. Algorithm / Steps

### Phase A — Bootstrap

1. **Parse trigger flag** `--privacy-frameworks-catalog` or env
   `CLOUD_EVIDENCE_PRIVACY_FRAMEWORKS_CATALOG`. If unset, exit no-op.
2. **Load operator config** `config.yaml::privacy.*`. Validate via
   Ajv. If `signing.catalog_signing_key_ref` is REQUIRES-OPERATOR-INPUT
   exit `2` with `PrivacyCatalogOperatorConfigMissingError`.
3. **Sign-test the catalog signing key** via
   `core/sign.ts::testSign(key_ref)`.

### Phase B — Verify source mirrors

4. **Enumerate expected mirrors.** Read
   `cloud-evidence/data/privacy-source-manifest.json` (committed file
   listing 66 expected mirrors with SHA-256s + URLs).
5. **For each expected mirror:**
   - Confirm the file exists at `docs/sources/privacy/<path>`.
   - Recompute SHA-256. If it differs from the manifest value, exit
     `2` with `PrivacyMirrorTamperingError` naming the path + expected
     vs actual hash.
6. **Refuse to emit** if any mirror is missing. Surface a
   `requires-operator-input` diagnostic naming the missing files +
   the `scripts/fetch-privacy-sources.mjs` helper command.

### Phase C — Extract framework rows

7. **For each of the 9 frameworks** (FERPA, COPPA, GLBA, CCPA/CPRA,
   GDPR, UK GDPR, NY SHIELD, NIST PF, SP 800-53 PT):
   - Open the framework's mirror via format-appropriate parser
     (`htmlparser2` for HTML, `pdf-parse` for PDF, `xml2js` for XML).
   - Extract the section anchors enumerated in the per-framework
     extraction-recipe object (committed under
     `scripts/extract-privacy-frameworks/<framework>.mjs`).
   - For each obligation in the recipe, extract the verbatim
     statutory excerpt, compute its SHA-256, and populate the
     `Obligation` row.
   - For penalty values, look up the
     `cloud-evidence/data/privacy-penalties.json` companion file
     (operator-maintained; carries the `penalty_basis_url` provenance
     chain back to the FR / state notice that set the value) and
     populate `max_penalty.amount_*`.

### Phase D — Extract jurisdiction rows

8. **For each of the 54 U.S. jurisdictions** in
   `cloud-evidence/data/state-breach-manifest.json`:
   - Open the per-jurisdiction mirror.
   - Apply the per-jurisdiction extraction recipe under
     `scripts/extract-privacy-frameworks/states/<JX>.mjs`.
   - Populate the `StateBreachMatrixRow` per §5.2.
   - Where a row's deadline is "without unreasonable delay" without a
     fixed ceiling, set `deadline_days = null` and capture the
     IAPP-synthesis-derived practitioner ceiling in
     `deadline_text`.

### Phase E — Canonicalize + sign

9. **Canonicalize JSON** via the existing
   `core/canonical-json.ts::canonicalize(obj)`: stable key order,
   LF newlines, no trailing whitespace, UTF-8 NFC, 2-space indent.
10. **Sign envelope** via `core/sign.ts::signEnvelope(env, key_ref)`.
11. **Attach RFC 3161 timestamp** via
    `core/timestamp.ts::stampEnvelope(env)`. TSA outage → warn (do
    not block).
12. **Write** to
    `cloud-evidence/data/privacy-frameworks-catalog.json` +
    `cloud-evidence/data/state-breach-notification-matrix.json`.
    Atomic write via temp-file + rename.

### Phase F — Coverage + log

13. **Emit run-log line**
    `coverage:privacy-catalog:9-frameworks:54-jurisdictions`.
14. **Append coverage block** to `out/inventory-coverage.json`:

```json
{
  "privacy_catalog_coverage": {
    "frameworks_emitted": 9,
    "jurisdictions_emitted": 54,
    "obligations_emitted": 173,
    "mirrors_verified": 66,
    "verbatim_excerpts_hashed": 173
  }
}
```

### Phase G — Validation

15. `npm run check:provenance` must pass.
16. `npm run lint:no-stubs` must remain green.
17. `npm run check:reo` (G1 + G2 + G3) must all pass.
18. `npm run typecheck` must succeed.
19. All 15+ tests in §8 must pass.

## 7. Files to create / modify

### Files to CREATE

1. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/privacy-frameworks-catalog.ts`
   — loader + typed API + signature verifier + mirror-hash verifier.
   ~480 lines.
2. `/Users/kenith.philip/FedRAMP 20x/scripts/extract-privacy-frameworks.mjs`
   — offline ingester orchestrator; dispatches to per-framework recipes.
   ~320 lines.
3. `/Users/kenith.philip/FedRAMP 20x/scripts/extract-privacy-frameworks/ferpa.mjs`
   — recipe for FERPA + 34 CFR Part 99. ~140 lines.
4. `/Users/kenith.philip/FedRAMP 20x/scripts/extract-privacy-frameworks/coppa.mjs`
   — recipe for 15 U.S.C. §6502 + 16 CFR Part 312. ~160 lines.
5. `/Users/kenith.philip/FedRAMP 20x/scripts/extract-privacy-frameworks/glba.mjs`
   — recipe for 16 CFR Part 314 (incl. Oct 2023 §314.5 amendment).
   ~180 lines.
6. `/Users/kenith.philip/FedRAMP 20x/scripts/extract-privacy-frameworks/ccpa.mjs`
   — recipe for Cal. Civ. Code §§1798.100-1798.199 + 11 CCR §§7000+.
   ~220 lines.
7. `/Users/kenith.philip/FedRAMP 20x/scripts/extract-privacy-frameworks/gdpr.mjs`
   — recipe for Reg. (EU) 2016/679. ~260 lines.
8. `/Users/kenith.philip/FedRAMP 20x/scripts/extract-privacy-frameworks/uk-gdpr.mjs`
   — recipe for UK GDPR + DPA 2018. ~140 lines.
9. `/Users/kenith.philip/FedRAMP 20x/scripts/extract-privacy-frameworks/ny-shield.mjs`
   — recipe for N.Y. Gen. Bus. Law §§899-aa, 899-bb. ~110 lines.
10. `/Users/kenith.philip/FedRAMP 20x/scripts/extract-privacy-frameworks/nist-pf.mjs`
    — recipe for the NIST Privacy Framework v1.0 + informative
    references. ~200 lines.
11. `/Users/kenith.philip/FedRAMP 20x/scripts/extract-privacy-frameworks/sp-800-53-pt.mjs`
    — recipe for SP 800-53 Rev 5 PT family. ~180 lines.
12. `/Users/kenith.philip/FedRAMP 20x/scripts/extract-privacy-frameworks/states/`
    — 54 per-jurisdiction recipes (one file each). Average ~80 lines
    per file (≈4,300 lines total).
13. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/privacy-frameworks-catalog.json`
    — emitted, signed.
14. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/state-breach-notification-matrix.json`
    — emitted, signed.
15. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/privacy-source-manifest.json`
    — committed list of the 66 expected mirrors + their SHA-256s.
16. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/privacy-penalties.json`
    — committed penalty values + basis URLs (operator updates
    annually).
17. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/state-breach-manifest.json`
    — committed list of the 54 jurisdiction mirrors + SHA-256s.
18. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/privacy-frameworks-catalog.test.ts`
    — see §8 (15+ tests).
19. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/privacy-frameworks/`
    — fixture mirrors covering FERPA, COPPA, GDPR, NY SHIELD,
    California, and 5 more jurisdictions for unit tests.
20. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/sources/privacy/`
    — 66 mirror files (committed; CI verifies SHA-256s on every PR).

### Files to MODIFY

1. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/scripts/lint-no-stubs.mjs`
   — add the per-extractor allowlist for the verbatim statutory text
   (otherwise quoted statutory language containing "TODO" or similar
   would trip the lint).
2. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/inventory-coverage.ts`
   — register the `privacy_catalog_coverage` block.
3. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/STATUS.md`
   — flip U.U1 row to `done` upon completion (per §13).
4. `/Users/kenith.philip/FedRAMP 20x/CHANGELOG.md`
   — append U.U1 entry under "Unreleased" upon completion.

## 8. Test specifications

| id | scenario | fixture path | expected | acceptance |
|---|---|---|---|---|
| T1 | Catalog loads + parses all 9 framework rows | `fixtures/privacy-frameworks/golden-catalog.json` | 9 rows, all framework_uids match enum | `loadPrivacyFrameworksCatalog().length === 9` |
| T2 | State-breach matrix loads all 54 jurisdictions | `fixtures/privacy-frameworks/golden-matrix.json` | 54 rows, all jurisdiction_uids match ISO-3166-2 | `loadStateBreachMatrix().length === 54` |
| T3 | FERPA row has §1232g + 34 CFR Part 99 citations | `fixtures/privacy-frameworks/ferpa-mirror.html` | statutory_citations length ≥ 2, both URLs present | unit assertion |
| T4 | COPPA penalty value matches FTC inflation-adjusted value | `fixtures/privacy-frameworks/coppa-mirror.html` + `privacy-penalties.json` | $51,744 per violation; basis_url points at FR notice | unit assertion |
| T5 | GDPR row has Art. 33 72-hour breach deadline | `fixtures/privacy-frameworks/gdpr-mirror.pdf` | breach_notification.deadline_days === 3; deadline_text contains "72 hours" | unit assertion |
| T6 | NY SHIELD row has §899-aa + §899-bb dual citation | `fixtures/privacy-frameworks/ny-shield-mirror.html` | statutory_citations length === 2 | unit assertion |
| T7 | CCPA $7,500 intentional-violation penalty captured | `fixtures/privacy-frameworks/ccpa-mirror.html` | obligation row with `max_per_intentional_violation_usd === 7500` | unit assertion |
| T8 | California state-breach row has SB-1386 lineage | `fixtures/privacy-frameworks/state-breach/CA.html` | citation === 'Cal. Civ. Code §1798.82'; AG threshold === 500 | unit assertion |
| T9 | Texas 60-day deadline captured | `fixtures/privacy-frameworks/state-breach/TX.html` | deadline_days === 60; citation === 'Tex. Bus. & Com. Code §521.053' | unit assertion |
| T10 | Florida 30-day deadline captured | `fixtures/privacy-frameworks/state-breach/FL.html` | deadline_days === 30 | unit assertion |
| T11 | GLBA preempts state row for financial institutions | `fixtures/privacy-frameworks/glba-mirror.html` + state rows | states with `preempted_by_federal.includes('GLBA')` non-empty | unit assertion |
| T12 | Tampered mirror SHA-256 raises PrivacyMirrorTamperingError | `fixtures/privacy-frameworks/tampered/ferpa-mirror.html` | error thrown; no catalog written | `expect().toThrow(PrivacyMirrorTamperingError)` |
| T13 | Missing mirror raises requires-operator-input diagnostic | (delete one fixture file) | exit code 2; diagnostic names missing file | integration assertion |
| T14 | Tampered verbatim_excerpt SHA-256 fails verifier | `fixtures/privacy-frameworks/tampered/catalog-with-modified-excerpt.json` | `verifyCatalogSignature()` throws `VerbatimExcerptHashMismatchError` | unit assertion |
| T15 | Ed25519 signature verification passes on freshly emitted catalog | (full pipeline run) | `verifyCatalogSignature()` resolves; signature.alg === 'ed25519' | integration assertion |
| T16 | RFC 3161 timestamp attached when TSA reachable | full pipeline run with TSA fixture | `rfc3161_timestamp.token` is a non-empty base64 string | integration assertion |
| T17 | TSA outage yields warn-not-fail behavior | TSA fixture returns 503 | catalog still emitted; coverage line carries `tsa_status: 'unavailable'` | integration assertion |
| T18 | Idempotent re-ingestion produces byte-identical catalog (modulo extracted_at + sig) | run twice | diff of canonicalized rows (excluding timestamps + sig) is empty | integration assertion |
| T19 | Catalog refuses to emit if `catalog_signing_key_ref` is REQUIRES-OPERATOR-INPUT | config with placeholder | exit `2`, `PrivacyCatalogOperatorConfigMissingError` | integration assertion |
| T20 | NIST PF subcategory ID.IM-P1 cross-walks to PT-5 + PT-6 per the NIST informative-reference mapping | `fixtures/privacy-frameworks/nist-pf-mirror.pdf` + informative-references | obligation row for ID.IM-P1 has `informative_references.includes('PT-5')` | unit assertion |

(Minimum 15; the spec ships with 20 to mirror W.W3 rigor.)

## 9. Risks

### R1 — Source-text drift (statutes amended mid-cycle)

**Description.** A statute is amended between the time the operator
mirrors the source and the time a downstream emitter relies on the
catalog. E.g. the FTC amends the GLBA Safeguards Rule (as it did Oct
2023) and the U.U1 mirror predates the amendment; the U.U4 incident
emitter quotes a superseded §314.5 deadline.

**Mitigation.** The `extract-privacy-frameworks.mjs` ingester refuses
to emit if any mirror is older than the operator-supplied
`max_mirror_age_days` (default 90). CI runs the ingester monthly and
opens a PR if any mirror is stale; the PR description includes a
diff of the mirror's SHA-256 vs the manifest. Operator must approve
the diff before merging.

### R2 — Verbatim-excerpt drift from non-textual changes

**Description.** A statute is "renumbered" without substantive change
(e.g. CFR re-codification moves §312.4 to §312.5). The verbatim
excerpt is unchanged textually but its citation is now wrong.

**Mitigation.** The catalog row carries both the citation and a
`citation_anchor_text` field — a short distinctive phrase from the
section heading. The ingester verifies the anchor text is present in
the mirror at the cited location. A mismatch raises
`CitationAnchorDriftError`.

### R3 — Penalty inflation-adjustment lag

**Description.** FTC publishes annual inflation adjustments to civil
penalty amounts in the Federal Register each January. The operator
forgets to refresh `privacy-penalties.json` and the catalog
under-reports the per-violation cap.

**Mitigation.** `privacy-penalties.json` carries
`last_review_date` per penalty row. CI runs a `check:penalty-freshness`
job that fails any row older than 13 months (one January cycle + a
1-month grace window). The U.U1 ingester refuses to emit if any
penalty row is past freshness.

### R4 — Jurisdiction-deadline ambiguity ("without unreasonable delay")

**Description.** Many state breach statutes use "without unreasonable
delay" without a fixed day ceiling. U.U4's deadline computer cannot
operate against `deadline_days = null`.

**Mitigation.** The state-breach matrix row carries a
`practitioner_ceiling_days` field derived from the IAPP Westin annual
synthesis. U.U4 falls back to `practitioner_ceiling_days` when
`deadline_days` is null AND surfaces a `practitioner-ceiling-applied`
diagnostic so the operator's General Counsel may override.

### R5 — Source-mirror licensing constraints

**Description.** Some statutory mirrors (e.g. Westlaw / LexisNexis
pages) are copyrighted secondary sources, not the operative statute.
Committing them to the repo may violate ToS.

**Mitigation.** Mirrors MUST come from primary government sources
only (GovInfo, eCFR, EUR-Lex, state-legislature official pages,
state-AG official pages). The manifest enforces this — any mirror
whose `publisher` field is not in the allow-list raises
`NonAuthoritativeSourceError`. Secondary sources (IAPP, NCSL) are
permitted only for the *practitioner-ceiling* field, not for the
operative statutory text.

### R6 — Catalog signature key rotation breaking downstream load

**Description.** Operator rotates the catalog signing key; downstream
slices fail signature verification on next load.

**Mitigation.** The catalog carries `signature.key_id` and the loader
maintains a trust store of historical key ids (signed audit chain).
Rotation procedure documented in `docs/RUNBOOK.md` requires the
operator to re-emit the catalog with the new key + add the new key
id to the trust store in a single atomic commit.

## 10. Open questions

- **Q1.** Should U.U1 include HIPAA + HITECH Privacy Rule rows? Current
  decision: NO — HIPAA's BAA contract path is materially different
  from consumer-privacy regimes and is owned by LOOP-M. REQUIRES
  decision before merging LOOP-M-SPEC.md.
- **Q2.** Should the state-breach matrix include the 4 U.S.
  territories (Guam, Puerto Rico, USVI, American Samoa)? American
  Samoa has not enacted a breach-notification statute as of 2026-01.
  Current decision: include the 3 with statutes + omit American
  Samoa; the matrix row count is 54 (50 + DC + Guam + PR + USVI).
- **Q3.** Does the catalog need a per-row Spanish translation for
  CCPA / Puerto Rico residents (Cal. Civ. Code §1798.130(a)(2)(B)
  multilingual disclosure)? Current decision: NO at U.U1 level; U.U3
  DPIA emitter handles translation at render time.
- **Q4.** Should the GDPR + UK GDPR rows reflect the June 2023 EU-US
  Data Privacy Framework adequacy decision? Current decision: YES —
  the catalog row's `international_transfer` field carries
  `mechanism: 'adequacy-decision-DPF-2023'` for U.S.-domiciled CSPs
  that have self-certified to the DPF.

## 11. REQUIRES-OPERATOR-INPUT

| Field | Type | Validator | UI location | Failure mode if missing |
|---|---|---|---|---|
| `privacy.signing.catalog_signing_key_ref` | string (KMS resource URI) | Ajv `format=uri` + `core/sign.ts::testSign()` | `config.yaml` | Exit 2 `PrivacyCatalogOperatorConfigMissingError` |
| `privacy.frameworks.ferpa.applicable` | boolean | Ajv `type=boolean` | `config.yaml` | Treated as `false`; U.U2 cannot determine FERPA scope; PII discovery omits student-record assets |
| `privacy.frameworks.coppa.services_directed_to_children` | boolean | Ajv | `config.yaml` | Treated as `false`; COPPA pathway dormant |
| `privacy.frameworks.glba.applicable` | boolean | Ajv | `config.yaml` | GLBA Safeguards 30-day FTC clock unreachable |
| `privacy.state_breach_jurisdictions` | string[] (ISO-3166-2) | Ajv enum of 54 codes | `config.yaml` | Treated as empty; U.U4 cannot route breach notifications |
| `privacy-source-manifest.json` mirrors | committed file list | SHA-256 verifier | `cloud-evidence/data/` + `docs/sources/privacy/` | Exit 2 `PrivacyMirrorMissingError` with file list |
| `privacy-penalties.json` rows | object with `last_review_date` ≤ 13mo | CI check:penalty-freshness | `cloud-evidence/data/` | CI fails on stale penalty rows |
| `state-breach-manifest.json` jurisdiction list | ≥ 54 rows | SHA-256 verifier | `cloud-evidence/data/` | Exit 2 `StateBreachManifestIncompleteError` |
| `org-profile.yaml::privacy_dpo_email` | string (email) | Ajv `format=email` | `org-profile.yaml` | U.U4 cannot route DPO notifications |
| `org-profile.yaml::privacy_council_jurisdictions` | string[] | Ajv | `org-profile.yaml` | Treated as US-CA only by default |

## 12. Implementation log

> Update this table at every commit boundary, test failure, research
> question answered, spec divergence, newly-discovered risk, or
> external dependency pin. See `docs/IMPLEMENTATION-LOG-TEMPLATE.md`
> §3 for the full cadence and §4 for example entries.

| date | session | action | commit | notes |
|---|---|---|---|---|
| 2026-06-07 | spec proposed | Specification authored via FedPy workflow | TBD | — |

## 13. Completion checklist

> Quoted verbatim from `docs/SLICE-COMPLETION-PROCEDURE.md`. The 7
> steps are MANDATORY. Step 8 is the U.U1-specific addendum (per the
> CLAUDE.md slice-completion directive). The slice is NOT closed
> until all 8 steps execute.

### Step 1 — Verify the slice is REO-compliant
> Run all three guardrails. They MUST all be green:
> ```bash
> cd cloud-evidence
> npm run typecheck      # no errors
> npm test               # 100% passing (counts must increase by the slice's new tests)
> npm run check:reo      # G1+G2+G3 all green
> ```

### Step 2 — Update STATUS.md
> Open `cloud-evidence/docs/STATUS.md` and for the slice that just shipped:
> - Change `Status` column from `pending` to `done`
> - Fill `Commit` with the PENDING commit's short hash (you'll know it after step 5)
> - Fill `Date` with today's date (ISO format YYYY-MM-DD)
> - If this was the last slice in a loop, change the loop's title section to indicate "(COMPLETE)"
> - Update the "Overall" section: increment loops-complete, change last-shipped, update next-priority

### Step 3 — Update the loop's spec doc
> Open `cloud-evidence/docs/loops/LOOP-X-SPEC.md` (where X is your loop letter).
> Find the "Status tracking" section table.
> For your slice row: status=done, commit=<hash>, date=<ISO>.

### Step 4 — Add CHANGELOG entry
> Open `/Users/kenith.philip/FedRAMP 20x/CHANGELOG.md`.
> Add a new entry at the TOP of "Unreleased":
>
> ### Added — LOOP-X.XN: <Slice title>
> <2-3 paragraphs describing what shipped, module names, file paths, verification counts (typecheck clean, NNN/NNN tests passing, npm run check:reo returns 0).>

### Step 5 — Commit
> ```bash
> cd /Users/kenith.philip/FedRAMP\ 20x
> git add cloud-evidence/<modified files> cloud-evidence/docs/STATUS.md cloud-evidence/docs/loops/LOOP-X-SPEC.md CHANGELOG.md
> git commit -m "LOOP-X.XN: <slice title>
> <detailed commit message describing the slice>
> Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
> ```

### Step 6 — Update commit hash in STATUS.md + loop spec
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

### Step 7 — Push
> ```bash
> git push origin main
> ```

### Step 8 — U.U1-specific addendum (per CLAUDE.md slice-completion directive)

> Step 8: After commit lands, append/update the slice row in STATUS.md
> (status -> done, commit hash, last_updated); update the loop SPEC
> status table; append a CHANGELOG entry; push to origin/main; verify
> with 'git log --oneline -3'. Only THEN is the slice closed.

Additionally for U.U1 specifically:

- Update this per-slice doc's YAML frontmatter:
  `status: done`, `commit: <hash>`, `completed_date: <ISO>`,
  `last_updated: <ISO>`.
- Append the final Implementation log entry (§12) with the final
  commit hash + a one-line outcome summary.
- Add the `data/privacy-frameworks-catalog.json` + `data/state-breach-
  notification-matrix.json` + the 66 source mirrors under
  `docs/sources/privacy/` to the commit (they are committed reference
  data, signed at rest).
- Re-run `npm run check:provenance` against the emitted catalogs to
  confirm the `provenance` block + `verbatim_excerpt_sha256` chain
  validates.
- If any new risk was surfaced during implementation, append it to
  `docs/loops/LOOP-U-RISKS.md` in the same commit.

## 14. Resume-from-fresh-session checklist

A fresh Claude (or human) session that has only read `CLAUDE.md` +
this file can resume U.U1 by executing the following:

1. Read this file end-to-end.
2. Read `docs/loops/LOOP-U-SPEC.md` §2 / §4 for any LOOP-U context
   not duplicated here.
3. Read `docs/loops/LOOP-U-RISKS.md` to see any risks surfaced after
   spec authoring.
4. Read `docs/SLICE-COMPLETION-PROCEDURE.md`.
5. Read `docs/IMPLEMENTATION-LOG-TEMPLATE.md` to learn the log
   cadence.
6. Confirm the 66 source mirrors are present under
   `docs/sources/privacy/` (`ls docs/sources/privacy/ | wc -l`
   should report ≥ 66).
7. Confirm `cloud-evidence/data/privacy-source-manifest.json` exists
   and its SHA-256s match the on-disk mirrors.
8. Confirm `config.yaml::privacy.signing.catalog_signing_key_ref`
   resolves to a real KMS resource (run
   `node -e "require('./core/sign.ts').testSign(process.env.KEY_REF)"`).
9. Execute Phase A through Phase G per §6.
10. Execute the 8-step completion procedure per §13.

The frontmatter `last_updated` field MUST be updated at the end of
every session that touches this slice — even sessions that do not
ship a commit. The on-disk archaeological record of the slice IS the
frontmatter + the Implementation log.
