# LOOP-U — Risks Register (Privacy Frameworks Crosswalk)

> Live document. Implementing sessions add entries during work; resolved
> risks stay in the file with `status=resolved` + resolution note.
> Severity: high = ship-blocking; med = should fix in-loop; low = file
> as follow-up.

> Authoritative companion to `docs/loops/LOOP-U-SPEC.md` and the
> per-slice docs at `docs/slices/U/U.U[1-N].md`. Read those for context
> before acting on any risk here.

> **CONDITIONAL GATE**: LOOP-U applies when the CSP processes personal
> information of (a) California residents (CCPA / CPRA), (b) EU / EEA
> data subjects (GDPR), (c) children under 13 (COPPA), (d) education
> records under FERPA, (e) "nonpublic personal information" under the
> Gramm-Leach-Bliley Act Safeguards Rule, or (f) any state with a breach-
> notification statute (all 50 states + DC + Puerto Rico + Guam + US
> Virgin Islands as of 2026-06-07). The `--privacy-crosswalk` flag (or
> `CLOUD_EVIDENCE_PRIVACY_CROSSWALK` env var) gates emission. When the
> flag is unset, NONE of the LOOP-U risks below activate. Federal
> agency-customer scope (NIST Privacy Framework / OMB A-130 Appendix II /
> Privacy Act of 1974) is handled by LOOP-M (Privacy Package Extension);
> LOOP-U is the **non-federal commercial overlay** that the CSP must
> ship in addition to LOOP-M when serving commercial customers in the
> in-scope jurisdictions above.

> Last updated: 2026-06-07.

> Companion reading (cross-reference these registers when triaging a
> LOOP-U risk that interacts with another loop):
> - `LOOP-M-RISKS.md` — federal-agency Privacy Package / SORN / DPIA;
>   LOOP-U inherits the privacy taxonomy from LOOP-M.M1.
> - `LOOP-G-RISKS.md` — incident communications; the breach-matrix
>   reporter (U.U5) shares the per-jurisdiction clock model with
>   G.G2.CIRCIA and the §889 1BD clock (W.W3).
> - `LOOP-T-RISKS.md` — SSDF Common Form annual cadence; LOOP-U's
>   GLBA Safeguards Rule annual-update model mirrors T-X12.
> - `LOOP-W-RISKS.md` — federal-business-day arithmetic + holiday
>   calendar reuse for state breach-notification clocks.
> - `LOOP-R-RISKS.md` — cryptographic agility; GDPR Article 32
>   pseudonymisation requires the PQC key lifecycle.

---

## Table of Contents

- [Cross-cutting risks (apply to ALL slices in LOOP-U)](#cross-cutting-risks-apply-to-all-slices-in-loop-u)
  - Jurisdiction drift + scope determination (U-X1..U-X5)
  - Framework-conflict resolution (U-X6..U-X10)
  - DSAR identity verification (U-X11..U-X13)
  - Cross-border transfer mechanism integrity (U-X14..U-X17)
  - Breach-matrix correctness + staleness (U-X18..U-X22)
  - COPPA verifiable parental consent (U-X23..U-X25)
  - FERPA school-official chain (U-X26..U-X28)
  - GLBA Safeguards Rule (U-X29..U-X31)
  - GDPR Article 33 72-hour clock (U-X32..U-X35)
  - Signing / provenance / tracker (U-X36..U-X40)
  - Cross-loop interaction (U-X41..U-X44)
  - Operator burden + auditor expectations (U-X45..U-X48)
- [Per-slice risks](#per-slice-risks)
  - U.U1 — Privacy framework catalog extractor
  - U.U2 — CCPA / CPRA crosswalk + DSAR portal
  - U.U3 — GDPR crosswalk + Article 33 / 34 reporter
  - U.U4 — COPPA verifiable parental consent registry
  - U.U5 — Multi-jurisdiction breach-notification matrix
  - U.U6 — FERPA + GLBA + sectoral overlays
- [External dependencies that may change](#external-dependencies-that-may-change)
- [Resolved risks (historical)](#resolved-risks-historical)
- [Resume-from-fresh-session checklist](#resume-from-fresh-session-checklist)

---

## Cross-cutting risks (apply to ALL slices in LOOP-U)

### U-X1 — Jurisdiction-drift across state CCPA-style laws (Cal / CO / CT / VA / UT / TX / OR / MT / DE / IA / IN / NH / NJ / TN / KY / RI / MN / MD)

- **Description**: As of 2026-06-07 the United States has 19 comprehensive
  state privacy statutes in force (California CPRA, Colorado CPA, Connecticut
  CTDPA, Virginia VCDPA, Utah UCPA, Texas TDPSA, Oregon OCPA, Montana MCDPA,
  Delaware DPDPA, Iowa ICDPA, Indiana ICDPA, New Hampshire NHPA, New Jersey
  NJDPCL, Tennessee TIPA, Kentucky KCDPA, Rhode Island DTPPA, Minnesota
  MCDPA, Maryland MODPA, plus interim 2025-effective laws in MI/PA/MA still
  in conference). Each has a unique combination of: applicability thresholds
  (revenue, record count, sensitive-data processing), opt-out rights
  (sale, share, targeted advertising, profiling for solely-automated
  decisions), data-broker / universal opt-out (GPC) recognition, sensitive-
  data categories (e.g. precise geolocation, biometric, neural data,
  genetic, status as immigrant / undocumented, union membership), and
  enforcement (right of action, AG-only, CPPA in California). A naive
  "single CCPA crosswalk" misses 18 other states' nuances and produces
  false claims that mislead operators.
- **Severity**: high (regulatory exposure; per-state statutory damages
  range up to $7,500/violation in California, $7,500/intentional violation
  in Colorado, $7,500/violation in Connecticut; cumulative exposure across
  state AGs can exceed $50M for a single multi-state breach).
- **Mitigation**: U.U1's catalog records each jurisdiction separately
  with `jurisdiction_code` (ISO 3166-2 sub-region for US states) +
  `statute_name` + `effective_date` + `applicability_thresholds` +
  `consumer_rights[]` + `sensitive_data_categories[]` +
  `private_right_of_action: boolean` + `cure_period_days` +
  `enforcement_authority`. U.U2 emits a per-jurisdiction applicability
  determination (`out/privacy-applicability-<csp>-<jurisdiction>.json`)
  that the operator countersigns. Crosswalk uses a matrix structure not
  a single-dimension list: a CCPA-equivalent "opt-out of sale" right
  maps to 14 of 19 states; "opt-out of targeted advertising" maps to
  16 of 19; "opt-out of profiling" maps to 11 of 19. CHANGELOG entry
  per statute amendment. Operator runbook documents per-state quarterly
  review checkpoint.
- **Status**: open.

### U-X2 — IAPP Westin Research Center tracker staleness vs in-flight state bills

- **Description**: The catalog ships with a frozen view of state privacy
  laws as of `extracted_at`. New state laws are passing at ~3-5 per
  legislative session (2023 added 7, 2024 added 5, 2025 added 4 as of
  2026-06-07). A frozen catalog more than 90 days old will silently miss
  a newly-effective state law. The IAPP Westin Research Center tracker
  (https://iapp.org/resources/article/us-state-privacy-legislation-tracker/)
  is the canonical aggregation but is itself updated only when the IAPP
  staff post — typically 1-2 day lag from legislative action.
- **Severity**: high (silent compliance gap on new state laws).
- **Mitigation**: U.U1 records `catalog_extracted_at` per jurisdiction;
  orchestrator strict mode (`--strict-privacy-catalog`) refuses to run
  if any in-scope jurisdiction's `catalog_extracted_at` is more than
  90 days old. U.U1 cross-references the IAPP tracker + the Future of
  Privacy Forum (FPF) state map + the NCSL state privacy compendium for
  triangulation; mismatch among the three sources triggers a
  `REQUIRES-OPERATOR-INPUT: confirm-state-law-status-<jurisdiction>`
  diagnostic. Quarterly GitHub Actions cron at `0 0 1 */3 *` re-runs
  the extractor + emits CHANGELOG delta. Tracker UI surfaces
  `catalog_age_days` per jurisdiction.
- **Status**: open.

### U-X3 — Applicability-threshold computation requires CSP-internal data (revenue, record count, sensitive-data processing)

- **Description**: CCPA / CPRA applies to businesses meeting any of:
  (a) gross annual revenue > $25M (adjusted for inflation; $26,625,000
  for calendar year 2025), (b) buys / sells / shares personal information
  of ≥100,000 California consumers or households, (c) derives 50% or
  more of annual revenue from selling or sharing personal information.
  Colorado CPA applies at 100,000-consumer threshold (no revenue
  threshold). Virginia VCDPA applies at 100,000-consumer or 25,000-
  consumer-AND-50%-revenue thresholds. Texas TDPSA has no numeric
  threshold but applies to all "businesses conducting business in Texas"
  except small businesses (defined by SBA). A CSP that crosses a
  threshold mid-fiscal-year becomes subject to the statute and faces
  ~12 months of latent non-compliance.
- **Severity**: high (applicability mis-determination = entire compliance
  posture is wrong).
- **Mitigation**: U.U2 carries an `applicability_calculator` that takes
  operator-supplied inputs from `privacy-config.yaml` —
  `annual_gross_revenue_usd`, `consumer_record_counts_by_state[]`,
  `revenue_from_sale_or_share_pct`, `sensitive_data_processed: boolean`
  — and emits a per-jurisdiction applicability determination with
  `applies: boolean` + `applies_via: criterion[]` + `confidence`. Strict
  mode refuses to run without operator-supplied revenue + record counts
  (no defaults — operator MUST supply real numbers). Tracker UI shows
  the running consumer-record count per state from the inventory
  pipeline (LOOP-A.A2) so the operator sees thresholds approaching.
  Quarterly re-evaluation cron. CHANGELOG entry per threshold crossing.
  Runbook documents the per-state threshold table + inflation-adjustment
  rules (CPRA's threshold is adjusted Jan 1 each odd year by CCB).
- **Status**: open.

### U-X4 — Sub-state local privacy ordinances (NYC AI hiring law, San Francisco facial-recognition ban, Illinois BIPA)

- **Description**: Sub-state jurisdictions have enacted privacy
  ordinances that overlay state laws. New York City Local Law 144
  (2023) requires bias audits of automated employment decision tools
  (AEDT). San Francisco's facial-recognition ban (Ord. 107-19) prohibits
  city use of facial recognition. Illinois Biometric Information Privacy
  Act (BIPA, 740 ILCS 14) has a private right of action with statutory
  damages of $1,000 (negligent) to $5,000 (intentional) per violation;
  Illinois courts have read "per scan" broadly, producing nine-figure
  jury verdicts. A state-level catalog misses these.
- **Severity**: med (jurisdiction-specific; high impact for affected
  CSPs).
- **Mitigation**: U.U1's catalog supports a `sub_jurisdiction_overlays[]`
  array per state; ships with seed data for the major overlays (NYC LL
  144, SF facial-recognition, IL BIPA, IL Genetic Information Privacy
  Act, IL AI Video Interview Act, WA HB 1155 My Health My Data,
  CT public-act-22-15 youth-data-broker). Operator extends via
  `privacy-config.yaml sub_jurisdiction_overlays[]`. Runbook
  documents the major overlays. Future enhancement could pull from
  Mintz or Hunton municipal-privacy trackers.
- **Status**: open.

### U-X5 — Tribal jurisdiction privacy laws (Navajo Nation Tribal Privacy Act of 2021, Cherokee Nation HIPAA implementation)

- **Description**: Federally-recognized tribes have inherent sovereignty
  and have begun enacting tribal privacy statutes. Navajo Nation's
  Tribal Privacy Act of 2021 governs tribal data subjects. Cherokee
  Nation has implemented HIPAA-equivalent rules for tribal health
  services. A CSP serving tribal customers (e.g. tribal-government IT
  contracts, Indian Health Service partners) faces tribal-jurisdiction
  compliance not covered by state catalogs.
- **Severity**: low (rare; high for affected CSPs).
- **Mitigation**: U.U1 catalog includes `tribal_jurisdictions[]` array
  with seed data for ~5 tribes with documented privacy statutes (Navajo,
  Cherokee, Choctaw, Chickasaw, Seminole); operator extends via
  `privacy-config.yaml tribal_jurisdictions[]`. Runbook flags tribal
  scope as REQUIRES-OPERATOR-INPUT.
- **Status**: open.

### U-X6 — CCPA-GDPR conflict resolution: data-minimization vs business-purpose

- **Description**: CCPA / CPRA permits collection + use for any
  "business purpose" disclosed at or before collection (Cal. Civ. Code
  §1798.100(a)(2)); GDPR Article 5(1)(c) requires data minimization —
  "limited to what is necessary in relation to the purposes for which
  they are processed". A CSP collecting data lawful under CCPA may
  violate GDPR's stricter minimization standard. A naive crosswalk that
  treats CCPA disclosure as satisfying GDPR will mislead the operator.
- **Severity**: high (regulatory exposure under both regimes).
- **Mitigation**: U.U2 + U.U3 emit conflict-resolution rules per data
  category: when a data category falls under BOTH CCPA + GDPR, the
  stricter of the two governs (GDPR's data minimization). The crosswalk
  matrix per data category records `ccpa_basis`, `gdpr_basis`,
  `effective_governing_rule` (the stricter), and `conflict_rationale`.
  T.T3-style cross-check refuses to mark a data category as "compliant"
  unless the effective rule is satisfied. Operator runbook documents
  the "stricter wins" rule. Adversarial test U.U2-A1 pins a CCPA-
  permitted but GDPR-prohibited use case.
- **Status**: open.

### U-X7 — CCPA "do not sell" vs GDPR "consent for legitimate interest"

- **Description**: CCPA / CPRA defaults to opt-out for "sale" and
  "sharing" of personal information; GDPR Article 6 defaults to opt-in
  for non-contract / non-legal-obligation processing. A CSP applying
  CCPA's opt-out default to EU data subjects violates GDPR; an opt-in
  default applied to California consumers exceeds CCPA requirements
  (and may reduce engagement metrics, which is a business cost).
- **Severity**: high.
- **Mitigation**: U.U2 emits geo-fenced consent strings per data
  subject jurisdiction; U.U3's GDPR module enforces opt-in for EU/EEA
  subjects + CCPA's opt-out for California. The consent string is
  computed at first-touch from the data subject's resolved jurisdiction
  (operator-supplied geolocation via the inventory tag or operator-
  declared subject-jurisdiction field). The crosswalk matrix records
  per-jurisdiction consent-default. Adversarial test U.U2-A2 pins a
  dual-jurisdiction (US-based subject who travels to EU) case.
- **Status**: open.

### U-X8 — Sensitive-personal-information definitional drift (CCPA vs GDPR vs state laws)

- **Description**: CCPA's "sensitive personal information" (§1798.140(ae))
  enumerates 9 categories: SSN/driver's-license/passport/state-ID, account
  log-in + financial-account access creds, precise geolocation, racial
  or ethnic origin, religious or philosophical beliefs, union membership,
  mail/email/text contents not directed to the business, genetic data,
  biometric for unique identification, health information, sex life /
  sexual orientation. GDPR Article 9 "special categories" enumerates
  10 categories overlapping but not identical (no SSN; adds sexual
  orientation explicitly; adds trade-union membership). Connecticut
  adds "status as victim of a crime"; Colorado adds "citizenship or
  immigration status"; Washington's My Health My Data adds "consumer
  health data" defined broadly. A crosswalk that uses a single
  definition misses 5-7 categories per jurisdiction.
- **Severity**: high.
- **Mitigation**: U.U1's catalog records `sensitive_categories[]` per
  jurisdiction with full text from the statute. U.U2 computes a per-data-
  element "sensitivity score" = max(jurisdiction sensitivity flags) and
  treats the data element as sensitive in ALL jurisdictions if it is
  sensitive in any in-scope jurisdiction. Operator override via
  `privacy-config.yaml data_element_sensitivity_overrides[]`. CHANGELOG
  entry per statutory definition change.
- **Status**: open.

### U-X9 — Children-data thresholds (COPPA <13, GDPR Article 8 <16, state laws 13/14/15/16/17/18)

- **Description**: COPPA applies to children under 13. GDPR Article 8
  sets the default age of digital consent at 16 with member-state
  derogations down to 13 (Ireland: 16, France: 15, Germany: 16,
  Spain: 14). California's CCPA opt-in requirement applies to consumers
  13-15 (parental consent for <13). Connecticut: 13. Colorado, Virginia,
  Utah: per Utah/Virginia, 13-15 requires parental consent for selling.
  A CSP serving teens must apply different consent rules per jurisdiction
  per age. Mis-handling: applying COPPA's <13 rule to all jurisdictions
  exempts 13-15-year-olds in California from required opt-in protection.
- **Severity**: high.
- **Mitigation**: U.U4's COPPA registry extends to a multi-jurisdiction
  age-based consent matrix recording per-jurisdiction `digital_consent_
  age_default` + `derogations` + `parental_consent_required_above:
  number`. U.U2 + U.U3 + U.U4 jointly emit per-subject consent rules
  based on age + jurisdiction. Adversarial test U.U4-A3 pins a 14-year-
  old California consumer (CCPA opt-in required; not COPPA-covered).
  Runbook documents the per-jurisdiction matrix.
- **Status**: open.

### U-X10 — Health information overlap (HIPAA vs WA My Health My Data vs state genetic-info laws vs GDPR Article 9)

- **Description**: A CSP processing health-adjacent data faces overlapping
  regimes: HIPAA covers PHI in the hands of covered entities + business
  associates; Washington's My Health My Data Act (effective Mar 2024)
  covers "consumer health data" defined broadly (e.g. menstrual-tracking
  app users are covered even outside HIPAA); state genetic-information
  laws (e.g. CA GIPA, IL GIPA, FL DPB Act) protect genetic data; GDPR
  Article 9(2)(h) requires explicit consent for health data processing.
  A CSP whose product processes step-count data may be unwittingly
  subject to all four regimes for the same data point.
- **Severity**: high.
- **Mitigation**: U.U6 implements a per-data-category overlap matrix
  recording all in-scope regimes per category; precedence rule is
  "all-applicable-laws-must-be-satisfied" (no statute preempts; the
  CSP must comply with all). The matrix surfaces in tracker UI per
  data category. Operator runbook documents the all-applicable-laws
  rule. Cross-references LOOP-M (federal HIPAA-equivalent) +
  LOOP-O (AI/ML health-data governance).
- **Status**: open.

### U-X11 — DSAR identity-verification false-positive (impersonator obtains another consumer's data)

- **Description**: A Data Subject Access Request (DSAR) requires identity
  verification before the CSP discloses the subject's data. False-positive
  ID verification (the requestor is NOT the subject but the CSP discloses)
  is a data breach. Common attack vectors: social engineering of the
  CSP's DSAR support team; SIM-swap to intercept SMS verification codes;
  credential stuffing using leaked credentials; voice deepfake calls
  to the support line. Recent enforcement actions: FTC's Tata Consultancy
  Services consent decree (2023) cited DSAR ID-verification failures
  as a §5 unfair-or-deceptive-practices violation.
- **Severity**: high (statutory breach + ICO/AG/CPPA enforcement).
- **Mitigation**: U.U2's DSAR portal implements multi-factor identity
  verification: (a) email-loop on the subject's account-of-record email;
  (b) authenticator-app TOTP if the subject has one enrolled; (c)
  knowledge-based authentication challenges based on account history
  (last 3 transactions / last login IP / account creation date) — NOT
  using SSN or other static identifiers an attacker can buy; (d) for
  sensitive data categories, an additional out-of-band channel (e.g.
  postal-mail confirmation to address-of-record). Tracker records each
  DSAR with `verification_factors_used[]` + `verification_strength_
  score: 0-1` + the operator-supplied minimum score per data category.
  Strict mode refuses to release data below the threshold. Adversarial
  test U.U2-A4 pins a SIM-swap attack scenario. Runbook documents the
  per-category strength thresholds.
- **Status**: open.

### U-X12 — DSAR identity-verification false-negative (legitimate subject is denied)

- **Description**: An over-aggressive ID-verification posture denies
  legitimate subjects. CPRA §1798.130(a)(2) requires the business to
  verify "in a manner that is reasonable in light of the type of personal
  information requested"; an unreasonable burden is itself a violation.
  GDPR Article 12(2) prohibits "exercise of data subject rights ...
  charged a fee unless requests are manifestly unfounded or excessive";
  a denial requires evidence the request is unfounded. The CPPA has
  asserted that ID-verification posture must be proportionate.
- **Severity**: med.
- **Mitigation**: U.U2's portal tiers verification by data sensitivity:
  low-sensitivity data (subscription preferences, marketing settings) =
  email-loop only; medium = email-loop + KBA; high (financial, health,
  sensitive personal information) = multi-factor + out-of-band. Each
  DSAR records the operator-supplied rationale for the tier assignment.
  Tracker UI surfaces denied DSARs with appeal workflow. Adversarial
  test U.U2-A5 pins a low-sensitivity request denied with high-tier
  verification (operator over-collected for the request).
- **Status**: open.

### U-X13 — DSAR clock miss (45-day CCPA, 1-month GDPR, 90-day extension rules)

- **Description**: CCPA §1798.130(a)(2) requires response "within 45
  days of receiving a verifiable consumer request" with a one-time
  45-day extension on "reasonably necessary" grounds (90 days total).
  GDPR Article 12(3) requires response "without undue delay and in
  any event within one month of receipt", extendable by two months
  "where necessary, taking into account the complexity and number of
  requests" (3 months total). Colorado CPA: 45 days + 45-day extension.
  Virginia VCDPA: 45 days + 45-day extension. A consolidated cross-
  jurisdiction clock that defaults to the longest window risks late
  responses against jurisdictions with shorter clocks; the inverse
  produces avoidable workload.
- **Severity**: high.
- **Mitigation**: U.U2 records per-DSAR `governing_jurisdictions[]`
  resolved from the subject's jurisdiction + the data's
  jurisdiction-of-collection; the clock = min(per-jurisdiction
  windows). Extensions require operator countersign + rationale
  recorded in the tracker; the rationale is surfaced in the response
  to the subject (statutorily required under CPRA §1798.130(a)(2)
  + GDPR Article 12(3)). Tracker UI countdown shows days remaining
  per jurisdiction. Adversarial test U.U2-A6 pins a multi-jurisdiction
  subject with CCPA (45d) + GDPR (1 month) where 1 month = ~30 days
  is the binding constraint. Federal-business-day arithmetic from
  LOOP-W.W3 reused (calendar days, not business days, under both
  CCPA + GDPR — Saturday counts).
- **Status**: open.

### U-X14 — Cross-border transfer mechanism invalidation (Schrems III scenario, SCC re-issuance)

- **Description**: GDPR Article 44+ prohibits transfer of personal data
  outside the EEA absent an adequacy decision, Standard Contractual
  Clauses (SCCs), Binding Corporate Rules (BCRs), or an Article 49
  derogation. The CJEU's Schrems I (2015) invalidated the US-EU Safe
  Harbor; Schrems II (2020) invalidated the EU-US Privacy Shield. The
  EU-US Data Privacy Framework (DPF, July 2023) is the current adequacy
  mechanism for US transfers; a future Schrems III challenge could
  invalidate it on similar grounds (US bulk-surveillance practices).
  The 2021 modernized SCCs replaced the 2010 SCCs; a future SCC re-
  issuance would require re-papering existing transfers.
- **Severity**: high (legal exposure if a transfer mechanism becomes
  invalid mid-engagement).
- **Mitigation**: U.U3 records per-transfer `mechanism: enum('adequacy-
  decision', 'sccs-2021', 'bcrs', 'art-49-derogation', 'dpf-self-
  certified')` + `mechanism_version` + `mechanism_effective_from` +
  `mechanism_last_validated_at` + the legal-counsel signature on
  validity. The orchestrator's strict mode refuses to run if any
  mechanism is more than 365 days from last validation. CHANGELOG entry
  per Schrems-class CJEU ruling. Runbook documents the
  mechanism-invalidation playbook: pause new transfers, evaluate
  alternative mechanism (BCRs / Article 49), notify data subjects per
  GDPR Article 13(1)(f). Cross-references LOOP-R-RISKS (cryptographic
  agility for transit encryption changes).
- **Status**: open.

### U-X15 — Schrems II Transfer Impact Assessment (TIA) staleness

- **Description**: Schrems II requires data exporters to assess on a
  case-by-case basis whether the transfer destination provides
  protections "essentially equivalent" to those under EU law; the TIA
  is the documented assessment. A TIA is not a one-time exercise — it
  must be refreshed when the legal landscape in the destination country
  changes (e.g. new US Executive Order, new FISA §702 reauthorization,
  new sectoral surveillance law). A stale TIA is functionally equivalent
  to no TIA from the supervisory authority's perspective.
- **Severity**: high.
- **Mitigation**: U.U3 carries `transfer_impact_assessments[]` per
  transfer destination with `assessed_at`, `legal_counsel_signature`,
  `next_review_due` (default +12 months), `triggering_events[]` (the
  list of events that would force early refresh). Tracker UI countdown
  shows TIA expiry per transfer. Orchestrator emits warnings at
  T-90, T-30, T-7 days; strict mode refuses to ship at T-0. Runbook
  documents trigger events (CJEU rulings, EU Commission adequacy
  changes, US Executive Orders on surveillance, FISA §702 reauths).
- **Status**: open.

### U-X16 — UK GDPR + Swiss FADP + South Africa POPIA divergence

- **Description**: Post-Brexit, the UK GDPR diverges from EU GDPR in
  small but material ways: the UK Information Commissioner's Office (ICO)
  takes a different posture on legitimate interests; UK adequacy was
  granted by the EU Commission in June 2021 but is subject to periodic
  review. Switzerland's revised Federal Act on Data Protection (FADP,
  effective Sep 2023) introduced new requirements not in GDPR (e.g.
  Swiss Data Protection Officer registration). South Africa's POPIA
  (effective July 2021) has similar structure to GDPR but different
  consent rules. A naive "GDPR covers all" assumption misses these.
- **Severity**: med.
- **Mitigation**: U.U3 records UK GDPR / Swiss FADP / POPIA / Brazil
  LGPD / Japan APPI / Australia Privacy Act as separate
  jurisdiction entries in U.U1's catalog. Crosswalk to GDPR articles
  records divergence per article + per jurisdiction. Operator runbook
  documents each jurisdiction's quirks. CHANGELOG entry per
  jurisdiction's statute amendment.
- **Status**: open.

### U-X17 — Data localization requirements (Russia 242-FZ, China PIPL, India DPDPA, UAE 45/2021)

- **Description**: Several jurisdictions require certain categories of
  personal data to be stored on infrastructure physically located in
  the country. Russia 242-FZ (2015) requires Russian citizens' personal
  data first-collected in Russia to be stored in databases located in
  Russia. China's PIPL (2021) Article 40 + the Cross-Border Data
  Transfer Rules (2023) impose localization + government-review
  requirements above certain thresholds. India's DPDPA (2023, in force
  since 2024) authorizes the Central Government to designate "significant
  data fiduciaries" and impose localization. UAE Federal Law 45/2021
  imposes consent + localization for personal data of UAE residents.
- **Severity**: med (jurisdiction-specific; high for affected CSPs).
- **Mitigation**: U.U3 records `data_localization_requirements[]` per
  jurisdiction with `triggering_data_categories[]` +
  `localization_method: enum('hard-localization', 'data-mirroring',
  'consent-plus-cross-border-transfer-mechanism')` + `enforcement_
  authority`. U.U1 catalog seed includes Russia, China, India, UAE,
  Vietnam, Indonesia, Nigeria. Operator extends. Tracker UI surfaces
  per-jurisdiction localization status. Cross-references LOOP-A.A2
  inventory location tagging.
- **Status**: open.

### U-X18 — Breach-matrix staleness (50-state + DC + territories statutes change every legislative session)

- **Description**: All 50 states + DC + Puerto Rico + Guam + USVI have
  breach-notification statutes. Definitions of "personal information"
  vary (some include only SSN + financial-account; others include
  biometric, medical, online-account credentials, passport, employer
  tax ID, student ID, etc.). Notification windows vary from "without
  unreasonable delay" (most states) to numeric maxima: Florida 30 days,
  Colorado 30 days, Texas 60 days, Maine 30 days, Maryland 45 days,
  Washington 30 days, Vermont 45 days. Substitute-notice thresholds
  (when individual notice is too costly, allowing public-notice
  substitution) vary by state and by per-individual cost. AG notification
  thresholds vary (some at any breach; some at ≥500 / 1,000 / 5,000
  affected residents). A breach-matrix more than 60 days stale will
  silently miss new requirements.
- **Severity**: high (statutory).
- **Mitigation**: U.U5's matrix records per-jurisdiction `definition_of_
  personal_information[]`, `notification_to_individuals_window`,
  `notification_to_ag_window`, `notification_to_ag_threshold_residents`,
  `notification_to_consumer_reporting_agencies_threshold`,
  `substitute_notice_threshold_cost_usd`, `substitute_notice_
  threshold_residents`, `regulator_url`, `effective_date`. Quarterly
  GitHub Actions cron re-runs the extractor. Orchestrator strict mode
  refuses to run with `matrix_extracted_at > 90 days old`. Tracker UI
  surfaces matrix age. Adversarial test U.U5-A1 pins a multi-state
  breach affecting CA + NY + FL with overlapping windows. CHANGELOG
  entry per statute amendment.
- **Status**: open.

### U-X19 — Breach-matrix coverage gaps (territories: PR, GU, VI; non-state US jurisdictions)

- **Description**: Puerto Rico (Act No. 111 of 2005), Guam (Public Law
  35-67), and US Virgin Islands (Title 14 V.I.C. §2208) have breach-
  notification statutes that are frequently omitted from "50-state"
  matrices. Native American tribal jurisdictions may have separate
  notification requirements for tribal members. A CSP processing data
  of territorial or tribal residents must satisfy the relevant
  jurisdiction's requirement.
- **Severity**: med (frequently overlooked).
- **Mitigation**: U.U5's matrix explicitly seeds PR + GU + VI in
  addition to 50 states + DC. Tribal jurisdictions handled via
  U-X5 mitigation. Catalog records `subnational_us_jurisdictions[]`
  array. CHANGELOG entry per addition.
- **Status**: open.

### U-X20 — "Personal information" definition drift across breach statutes vs CCPA-style statutes

- **Description**: A state's CCPA-style statute defines "personal
  information" broadly (e.g. CCPA §1798.140(v) reaches "inferences");
  the same state's BREACH statute defines "personal information"
  narrowly (e.g. CA Civil Code §1798.82(h) reaches SSN + driver's-
  license + account credentials + medical + health-insurance +
  biometric + unique account number + automated license-plate
  recognition + genetic — but NOT inferences). A naive CSP applying
  CCPA's definition to breach-notification triggers will over-notify
  (operationally expensive); applying the breach definition to CCPA
  rights will under-comply (statutory exposure).
- **Severity**: high.
- **Mitigation**: U.U1's catalog records TWO definitions per
  jurisdiction: `pi_consumer_rights_definition` (CCPA-style) +
  `pi_breach_definition` (breach-statute style). U.U2 applies the
  consumer-rights definition; U.U5 applies the breach definition.
  CHANGELOG documents the bifurcation. Adversarial test U.U5-A2
  pins a breach of inferred-data-only (no statutory PI under breach
  definition) where notification is NOT required but CCPA right-to-
  know IS triggered.
- **Status**: open.

### U-X21 — Substitute-notice thresholds vary by per-individual cost

- **Description**: Many state breach statutes permit "substitute
  notice" (public notice + email + state-wide media) when individual
  written notice cost would exceed a per-individual threshold. The
  threshold varies: California $250,000 total / 500,000 affected;
  New York $250,000 / 500,000; Texas $50,000 / 250,000. The CSP must
  document the cost analysis before electing substitute notice; a
  poorly-documented election may be challenged by the AG.
- **Severity**: med.
- **Mitigation**: U.U5 records per-jurisdiction substitute-notice
  thresholds + carries a `substitute_notice_calculator` that takes
  affected-count + estimated-per-individual-cost + emits the eligible
  jurisdictions. Operator countersigns the calculator output. Tracker
  preserves the cost-analysis evidence (operator-supplied vendor
  quotes for printing + postage + call-center). Adversarial test
  U.U5-A3 pins a 300,000-affected breach with substitute notice in
  some states but individual notice in others.
- **Status**: open.

### U-X22 — Encryption-safe-harbor variation (state-by-state on what counts as encrypted)

- **Description**: Most state breach statutes provide a safe harbor
  when the affected data was "encrypted" — but the definition of
  "encrypted" varies. Some states accept any encryption (e.g. AES-128
  with secured keys); others require NIST-approved algorithms; a
  few require specific key-management practices. California Civil
  Code §1798.82(h) defines "encrypted" as "rendered unusable,
  unreadable, or indecipherable to an unauthorized person through a
  security technology or methodology generally accepted in the field
  of information security". Massachusetts Chapter 93H §1 cross-
  references the MA Standards for Protection of Personal Information
  (201 CMR 17.00) which is more prescriptive. A CSP claiming safe
  harbor in one state may not qualify in another.
- **Severity**: med.
- **Mitigation**: U.U5's matrix records `encryption_safe_harbor_
  standard` per jurisdiction with the full text. U.U6 cross-references
  the CSP's cryptographic posture (LOOP-R PQC + control SC-13) against
  the per-jurisdiction standard; a mismatch flags as "encryption-
  safe-harbor-unavailable-<jurisdiction>". The matrix surfaces this
  in tracker UI per affected breach. Cross-references LOOP-R-RISKS.
- **Status**: open.

### U-X23 — COPPA verifiable parental consent (VPC) failure modes

- **Description**: COPPA (15 U.S.C. §6501-6506) + FTC's COPPA Rule
  (16 CFR Part 312) require "verifiable parental consent" before
  collecting personal information from a child under 13. The FTC's
  approved VPC methods (16 CFR §312.5(b)(2)) include: signed consent
  form, credit-card transaction with at least $0.50 charge, toll-free
  number staffed by trained personnel, video-conference with trained
  personnel, government-issued ID verification, knowledge-based-
  authentication questions, facial-recognition (added 2023 Jan, with
  conditions). Failure modes: (a) using a method outside the approved
  list; (b) accepting fake credit-card transactions ($0.50 charges
  with no verification); (c) treating a "click to confirm I am the
  parent" checkbox as VPC (NOT approved); (d) using KBA questions
  the child can answer.
- **Severity**: high (FTC enforcement; statutory damages up to
  $51,744/violation in 2025 per FTC inflation adjustment).
- **Mitigation**: U.U4's VPC registry records per-collection
  `vpc_method: enum(<approved methods>)`, `vpc_evidence_hash`,
  `vpc_obtained_at`, `vpc_obtained_by_parent_id`, `vpc_supporting_
  artifact_uri`. Strict mode refuses to ingest child-data without a
  VPC record. Tracker UI shows VPC counts per child + lifecycle status
  (active, revoked-by-parent, revoked-by-child-becoming-13). Adversarial
  test U.U4-A1 pins the "checkbox-only" VPC scenario (rejection).
  Runbook documents the per-method evidence requirements (e.g.
  credit-card method requires the transaction ID + processor receipt).
- **Status**: open.

### U-X24 — COPPA actual-knowledge vs constructive-knowledge ambiguity

- **Description**: COPPA applies when the operator has "actual knowledge"
  the user is under 13. The FTC has interpreted "actual knowledge"
  broadly — a service "directed to children" is presumed to have
  actual knowledge; a general-audience service may have actual
  knowledge if it collects birth-dates indicating users under 13.
  Constructive-knowledge ambiguity: if a parent emails customer
  support stating "my 11-year-old uses your service", the operator
  arguably gains actual knowledge of that user. A CSP missing the
  constructive-knowledge trigger faces FTC enforcement.
- **Severity**: high.
- **Mitigation**: U.U4 carries a `knowledge_events[]` log capturing
  every signal that could constitute actual knowledge: support-ticket
  mentions of underage children, birth-date inputs indicating <13,
  third-party notifications (school/parent), age-gate failures. The
  log is reviewed weekly by privacy counsel via the tracker UI.
  Adversarial test U.U4-A2 pins the "parent-email-to-support" case.
  Runbook documents the actual/constructive-knowledge analysis flow.
- **Status**: open.

### U-X25 — Child-becomes-13 transition handling

- **Description**: When a child user reaches age 13, COPPA's parental-
  consent requirement no longer applies — but the data collected
  under VPC remains in the CSP's systems. The transition raises
  unresolved questions: does the VPC remain valid? Must the operator
  re-obtain consent from the now-13-year-old? Does the parent retain
  any rights over previously-collected data? FTC guidance is sparse;
  some operators delete + re-collect, others convert the VPC to a
  user-consent record. A mis-handling could be challenged as either
  (a) retaining data beyond VPC scope or (b) treating the now-13
  user as a child without authority.
- **Severity**: med.
- **Mitigation**: U.U4 carries a `child_lifecycle_state: enum('vpc-
  active', 'vpc-revoked-by-parent', 'transition-pending',
  'user-consent-obtained', 'data-deleted')` per child + a transition
  workflow at age 13 that prompts the user (via in-app modal) to
  affirm continued consent. Operator-supplied policy in `privacy-
  config.yaml coppa.transition_policy: enum('delete', 're-consent',
  'convert-vpc-to-user-consent')` controls the default. Tracker UI
  countdown shows children approaching 13. CHANGELOG entry per
  policy change.
- **Status**: open.

### U-X26 — FERPA school-official chain ambiguity

- **Description**: The Family Educational Rights and Privacy Act
  (20 U.S.C. §1232g; 34 CFR Part 99) permits a school to disclose
  "education records" without parental consent to a "school official"
  with a "legitimate educational interest". A SaaS CSP serving K-12
  or higher-ed can qualify as a school official under §99.31(a)(1)(i)(B)
  if the school: (a) outsources institutional services or functions,
  (b) imposes direct control over the contractor's use of education
  records, (c) the contractor only uses records for outsourced purposes,
  (d) the contractor complies with FERPA's redisclosure rules. The
  school-official designation must be written + tied to a specific
  educational function. A CSP that asserts school-official status
  without a written designation faces FERPA exposure flowing through
  the school to the Department of Education.
- **Severity**: high (Department of Education enforcement could
  terminate federal funding to school customers; reputational risk
  to CSP).
- **Mitigation**: U.U6's FERPA module records per-school-customer
  `ferpa_school_official_designation_artifact_uri` (the signed PDF
  from the school), `designation_effective_date`,
  `designation_expiration_date`, `outsourced_functions[]`,
  `redisclosure_policy_uri`. Strict mode refuses to ingest FERPA-
  scoped education records without a designation. Tracker UI surfaces
  designation expiry per school. Adversarial test U.U6-A1 pins an
  ingestion attempt without designation (rejected). Runbook
  documents the standard designation template + the school's review
  process.
- **Status**: open.

### U-X27 — FERPA directory-information opt-out tracking

- **Description**: FERPA §99.37 permits schools to designate certain
  fields as "directory information" disclosable without consent
  (name, address, telephone, email, photograph, date + place of
  birth, major field of study, dates of attendance, degrees + awards
  received, etc.) — UNLESS the parent or eligible student has opted
  out. A CSP serving as a school-official must respect the school's
  per-student opt-out list. A failure to filter directory disclosures
  by opt-out status is a FERPA violation.
- **Severity**: med.
- **Mitigation**: U.U6 records per-student `directory_information_
  opt_out: boolean` + `opt_out_effective_date` synced from the
  school's SIS (Student Information System). U.U6's emit pipeline
  filters out opt-outs before any directory-information disclosure.
  Tracker UI surfaces opt-out counts per school. Adversarial test
  U.U6-A2 pins an attempt to disclose opted-out information
  (rejected).
- **Status**: open.

### U-X28 — FERPA + state student-data laws (NY Ed Law §2-d, CA SOPIPA, IL SOPPA)

- **Description**: Several states have enacted student-data laws
  layered on FERPA. New York Education Law §2-d (the "Parents'
  Bill of Rights") requires NY school-customer CSPs to publish a
  Parents' Bill of Rights + execute a data-privacy-and-security
  contract addendum. California SOPIPA (Cal. Bus. & Prof. Code
  §22584) prohibits operators of K-12 sites/apps/services from
  using student data for targeted advertising. Illinois SOPPA
  (105 ILCS 85) requires breach notification within 30 days of
  determination. A CSP serving multi-state school customers must
  comply with all applicable state student-data laws in addition to
  FERPA.
- **Severity**: med.
- **Mitigation**: U.U6 records per-school-customer `state_student_
  data_laws_applicable[]` derived from the school's jurisdiction.
  Catalog seeds NY §2-d, CA SOPIPA, IL SOPPA, CO HB 19-1130, CT PA
  18-125, WA HB 1495. Operator extends. Tracker UI surfaces per-
  school applicable-law list. Runbook documents per-law disclosure
  + breach requirements.
- **Status**: open.

### U-X29 — GLBA Safeguards Rule annual-update mismatch

- **Description**: The FTC's revised Safeguards Rule (16 CFR Part 314,
  effective Jun 2023 + Dec 2022 amendments) requires "financial
  institutions" (broadly defined under GLBA §509(3)(A) — includes
  many SaaS CSPs that provide financial services or facilitate
  financial transactions for non-bank customers) to (a) designate
  a qualified individual to oversee the Information Security Program,
  (b) conduct annual penetration testing + semi-annual vulnerability
  assessments, (c) maintain a written incident response plan, (d)
  notify the FTC within 30 days of a security event affecting ≥500
  consumers (per the May 2024 amendment effective May 13, 2024),
  (e) report to the Board (or governing body) at least annually on
  the Program's status. The annual-update cadence drifts if the CSP
  doesn't tie the annual review to a fixed calendar event; a missed
  annual review is itself a Safeguards Rule violation.
- **Severity**: high (FTC enforcement; civil-penalty exposure).
- **Mitigation**: U.U6's GLBA module records `glba_program_review_
  cadence: 'annual'` + `last_review_completed_at` + `next_review_due`
  + `board_report_artifact_uri` + `qualified_individual_user_id`.
  Tracker UI countdown at T-60, T-30, T-7, T-0. Strict mode refuses
  to ship if review is overdue. CHANGELOG entry per annual review.
  Cross-references LOOP-T's annual cadence model (T-X12) — both LOOP-T
  + LOOP-U share the annual-review pattern; the reusable primitive is
  `core/annual-review-tracker.ts`.
- **Status**: open.

### U-X30 — GLBA security-event notification 30-day clock (FTC, effective May 2024)

- **Description**: The May 2024 Safeguards Rule amendment requires
  financial institutions to notify the FTC of a "notification event"
  affecting ≥500 consumers within 30 days of discovery. "Notification
  event" is broader than "breach" — includes any "acquisition of
  customer information without the authorization of the individual to
  which the information pertains". The 30-day clock is statutory + no
  extensions are permitted absent an FBI / law-enforcement delay request.
  A missed notification is itself a violation enforceable by the FTC.
- **Severity**: high.
- **Mitigation**: U.U6's GLBA notification reporter integrates with
  U.U5's breach matrix; a breach matching GLBA criteria triggers an
  FTC notification draft (.docx + JSON) within 24h of discovery + a
  countdown to the 30-day deadline. Tracker UI surfaces the deadline
  prominently. Adversarial test U.U6-A3 pins a 600-consumer GLBA
  notification. Runbook documents FTC's CSIRT contact form +
  delayed-notification request procedure (in coordination with FBI).
- **Status**: open.

### U-X31 — GLBA financial-institution scope determination

- **Description**: The FTC's Safeguards Rule applies to "financial
  institutions" as defined by GLBA §509(3)(A) — a definition that
  reaches well beyond banks. Examples of non-obvious financial
  institutions: payroll processors, tax preparers, mortgage brokers,
  collection agencies, check cashers, finder services that connect
  borrowers + lenders, and (under the 2023 amendment) "finders" that
  facilitate payment transactions. A SaaS CSP may inadvertently
  qualify by providing a payment-processing feature or facilitating
  financial product comparisons. Mis-scope = either over-compliance
  (operational burden) or under-compliance (statutory exposure).
- **Severity**: high.
- **Mitigation**: U.U6's GLBA module includes a scope-determination
  questionnaire (16 questions matching the FTC's interpretive
  guidance); operator answers via tracker UI + the system computes
  `is_financial_institution: boolean` + `qualifying_activities[]`.
  Operator counsel countersigns the determination. Runbook
  documents the questionnaire + cites the FTC's "Financial
  Institutions and Customer Information: Complying with the
  Safeguards Rule" (May 2022 + 2023 amendments). Quarterly
  re-evaluation cron.
- **Status**: open.

### U-X32 — GDPR Article 33 72-hour clock miss

- **Description**: GDPR Article 33(1) requires the controller to
  notify the supervisory authority "without undue delay and, where
  feasible, not later than 72 hours after having become aware of"
  a personal-data breach (unless the breach is unlikely to result
  in a risk to data subjects). Article 33(2) requires processors to
  notify the controller "without undue delay". Late notification
  draws supervisory-authority enforcement: GDPR Article 83(4)(a)
  permits administrative fines up to €10 million or 2% of global
  annual turnover for Article 33 violations. The 72-hour clock is
  one of GDPR's hardest deadlines + most-enforced provisions.
- **Severity**: high.
- **Mitigation**: U.U3's reporter implements 72-hour calendar-hour
  arithmetic (NOT business hours — Saturday + holidays count under
  GDPR). Clock starts from `controller_aware_at` (operator-supplied;
  defaults to the breach-detection timestamp from LOOP-G.G2 / CIRCIA
  pipeline). Tracker UI countdown shows hours remaining in subject-
  TZ + UTC. Adversarial test U.U3-A1 pins a Friday-18:00-CET breach
  with deadline at Monday 18:00 CET (no weekend pause). Runbook
  documents the per-EEA-member-state supervisory-authority contact
  table (28 authorities — EU-27 + UK ICO + Iceland + Liechtenstein
  + Norway). Cross-references LOOP-G.G2.CIRCIA (US CISA 72-hour
  clock — similar arithmetic, different anchor authority).
- **Status**: open.

### U-X33 — GDPR Article 34 data-subject notification (when high risk)

- **Description**: GDPR Article 34(1) requires the controller to
  communicate the breach to affected data subjects "without undue
  delay" when the breach is likely to result in a "high risk" to
  rights + freedoms of natural persons. The "high risk" determination
  is a judgment call requiring documentation. Article 34(3)
  exceptions: (a) data was encrypted + key not compromised, (b)
  subsequent measures rendered high risk no longer likely, (c)
  individual notification would involve disproportionate effort (then
  public communication is acceptable). Mis-applying an Article 34(3)
  exception (e.g. claiming encryption when keys were also compromised)
  is itself an enforcement target.
- **Severity**: high.
- **Mitigation**: U.U3's reporter records per-breach `article_34_
  determination: enum('high-risk-individual-notice', 'art-34-3-a-
  encryption-safe-harbor', 'art-34-3-b-subsequent-measures',
  'art-34-3-c-disproportionate-effort-public-notice', 'low-risk-
  no-notice')` + a rationale text field countersigned by the DPO.
  When `art-34-3-a` is claimed, the system cross-references the
  encryption posture (LOOP-R + control SC-13 + SC-28) AND verifies
  key-management posture (was the key in the same blast radius?). A
  failed verification rejects the determination. Adversarial test
  U.U3-A2 pins a same-blast-radius key compromise (encryption
  safe-harbor unavailable).
- **Status**: open.

### U-X34 — GDPR supervisory-authority lead-authority determination (One-Stop-Shop)

- **Description**: GDPR Article 56 establishes a "One-Stop-Shop"
  mechanism: a controller / processor with cross-border processing
  has a "lead supervisory authority" determined by the location of
  the main establishment. A cross-border breach is reported primarily
  to the lead authority, which coordinates with concerned
  authorities. Mis-identifying the lead authority leads to multiple
  separate notifications + creates an impression of fragmented
  compliance. Determining the main establishment can be complex for
  global SaaS CSPs.
- **Severity**: med.
- **Mitigation**: U.U3 records `main_establishment_member_state` +
  `lead_supervisory_authority_id` + `lead_authority_determination_
  rationale_uri` in the CSP profile (operator-supplied, counsel-
  countersigned). The reporter routes the Article 33 notification
  to the lead authority + auto-cc's concerned authorities
  identified by the breach's affected-subject jurisdictions. Runbook
  documents the EDPB's lead-authority guidance (Working Party 29
  Guideline WP244 rev.01 + EDPB Guidelines 8/2022).
- **Status**: open.

### U-X35 — Article 33 records-of-breaches register

- **Description**: GDPR Article 33(5) requires the controller to
  "document any personal data breaches, comprising the facts relating
  to the personal data breach, its effects and the remedial action
  taken". The register is a permanent record subject to supervisory-
  authority inspection. A missing or incomplete register is itself
  a GDPR violation independent of notification timeliness.
- **Severity**: high.
- **Mitigation**: U.U3 emits a signed `out/gdpr-art-33-register.json`
  per fiscal year listing every breach (notifiable + non-notifiable)
  with breach-id, discovery-date, affected-subject-count, data-
  categories, risk-assessment, notification-decisions, remediation-
  actions, lessons-learned. The register is countersigned by the DPO.
  Tracker UI surfaces the register summary. Cross-references LOOP-G's
  incident-response register (LOOP-G shares some incidents with
  GDPR Article 33).
- **Status**: open.

### U-X36 — Tracker Ed25519 signing-key rotation on DSAR + breach records

- **Description**: U.U2 (DSAR records), U.U3 (Article 33 register +
  notification artifacts), U.U4 (VPC registry), U.U5 (breach matrix +
  per-incident notifications), U.U6 (FERPA + GLBA records) all sign
  tracker records with the tracker-resident Ed25519 key. Multi-fiscal-
  year retention is required (GDPR breach register: indefinite;
  COPPA: 1 year minimum after data deletion; FERPA: per-school
  retention schedule). Key rotation without preserving historical
  registry breaks supervisory-authority + DOE inspection trails.
  Same risk class as LOOP-B-X3, LOOP-R-X4, LOOP-S-X6, LOOP-T-X24,
  LOOP-W-X23.
- **Severity**: med.
- **Mitigation**: Tracker exposes `GET /api/sign/public-keys`
  returning historical keys keyed by `key_id`; reader cross-references
  each record's `signing_key_id`. Rotation events written to
  `audit_log`. Inherits the B-X3 fix. Runbook documents quarterly
  rotation procedure.
- **Status**: open.

### U-X37 — Provenance schema drift across new emit artifacts

- **Description**: U.U1 (`privacy-catalog-snapshot-*.json`), U.U2
  (DSAR records + portal manifest), U.U3 (Article 33 register +
  per-breach notifications + TIA records), U.U4 (VPC registry +
  knowledge-events log + child-lifecycle states), U.U5 (per-
  jurisdiction breach matrix + per-incident notification packages),
  U.U6 (FERPA designations + GLBA program reviews + state student-
  data records) all emit with `provenance` blocks per REO Rule 2.6.
  A missed block fails `check:provenance`. Same class as B-X9, R-X9,
  S-X16, T-X21, W-X25.
- **Severity**: high.
- **Mitigation**: Per-slice test verifies provenance via
  `check:provenance`; pattern reused from `core/inventory-coverage.ts`.
  CHANGELOG entry per slice cites provenance contents.
- **Status**: open.

### U-X38 — REO Rule 1.8 `process.env.NODE_ENV === 'test'` branch creep

- **Description**: REO Rule 1.8 prohibits this branch in production
  code. The new privacy-crosswalk infrastructure (catalog extractor,
  DSAR portal, multi-jurisdiction matrix, VPC registry, FERPA
  designation reader, GLBA review tracker) is exactly where developers
  reach for `if (NODE_ENV === 'test')` shortcuts when injection seams
  are tricky. Same class as B-X6, R-X6, S-X15, T-X20, W-X26.
- **Severity**: high (REO violation; CI rejects).
- **Mitigation**: `scripts/lint-no-stubs.mjs` catches the literal;
  tests inject seams via dependency-injected HTTP fetcher + filesystem
  helper + clock helper; CI gate is non-bypassable.
- **Status**: open.

### U-X39 — Repository tampering: catalog + matrix snapshot files

- **Description**: Signed snapshot files
  (`data/privacy-catalog-snapshot-YYYYMMDD.json`,
  `data/breach-matrix-snapshot-YYYYMMDD.json`) live under
  `cloud-evidence/data/`. An attacker with repo-write access could
  swap files with tampered versions that omit a jurisdiction whose
  requirements they want the CSP to ignore. Ed25519 signatures
  catch the swap IF the verifier checks; a silent verifier bypass
  is the risk. Same risk class as W-X24.
- **Severity**: high.
- **Mitigation**: (1) Loader unconditionally verifies the signature
  on every load with no `skip-verify` flag — REO Rule 1 forbids.
  (2) Each snapshot file includes `provenance.git_commit` + the
  prior snapshot's hash → forms a hash chain. (3) CI cron re-verifies
  signatures on every push to main. (4) Signing key in HSM-backed
  location. Adversarial test U.U1-A1 pins corrupted-signature case.
- **Status**: open.

### U-X40 — Submission bundle role count growth

- **Description**: LOOP-U adds 10+ new roles to `submission-bundle.ts:
  WELL_KNOWN`: `privacy-catalog-snapshot-json`,
  `dsar-records-json`, `dsar-portal-manifest-json`,
  `gdpr-art-33-register-json`, `gdpr-art-33-notification-bundle`,
  `transfer-impact-assessment-json`, `coppa-vpc-registry-json`,
  `coppa-knowledge-events-log-json`, `breach-matrix-snapshot-json`,
  `state-breach-notification-bundle`, `ferpa-school-official-
  designations-json`, `glba-safeguards-program-review-json`,
  `glba-ftc-notification-bundle`. Role / filename collisions corrupt
  the bundle. Same class as S-X17, T-X22, W-X27.
- **Severity**: med.
- **Mitigation**: `tests/core/submission-bundle.test.ts` pins the
  full role table; per-slice tests assert presence; CHANGELOG entry
  for the LOOP-U close lists the final inventory.
- **Status**: open.

### U-X41 — Cross-loop dependency: LOOP-M privacy taxonomy

- **Description**: U.U1's catalog extends LOOP-M's federal Privacy
  Package taxonomy (NIST Privacy Framework + OMB A-130 Appendix II).
  If LOOP-M.M1's taxonomy schema changes (e.g. category rename, new
  control mapping), U.U1's extractor silently produces a catalog
  that uses stale keys. Same risk class as W-X36 (subprocessors-
  sheet schema drift).
- **Severity**: med.
- **Mitigation**: U.U1 asserts the expected LOOP-M.M1 taxonomy
  schema version; a schema bump throws a typed error with
  remediation message. CHANGELOG documents cross-loop coupling.
  Cross-references LOOP-M-RISKS.md.
- **Status**: open.

### U-X42 — Cross-loop dependency: LOOP-G.G2.CIRCIA + breach matrix

- **Description**: U.U5's breach matrix shares the incident-discovery
  timestamp + the affected-subject identification logic with LOOP-G.G2
  + the CIRCIA extension. If LOOP-G.G2 records `discovered_at` in a
  different timezone or with different precision than U.U5 expects,
  the 30/45/60-day state clocks + GDPR 72-hour clock + GLBA 30-day
  clock may diverge by hours — material at hour boundaries.
- **Severity**: high.
- **Mitigation**: U.U5 reads LOOP-G.G2's incident record with
  `discovered_at` in UTC + an explicit `discovered_at_tz` for the
  jurisdiction's local presentation. Both loops use the same
  `core/incident-clock.ts` primitive. Cross-loop test pins the
  timestamp handoff. Cross-references LOOP-G-RISKS.md.
- **Status**: open.

### U-X43 — Cross-loop dependency: LOOP-W.W3 federal-business-day arithmetic

- **Description**: Most state breach-notification clocks are calendar-day
  not business-day (e.g. Florida 30 calendar days). But a few are
  measured in business days (e.g. some state insurance-regulator
  variants) + the GLBA notification is "30 calendar days" measured
  from "discovery" which is itself a defined term. The CSP's
  multi-jurisdiction clock module must support BOTH calendar-day +
  business-day arithmetic + jurisdiction-specific definitions of
  "discovery".
- **Severity**: med.
- **Mitigation**: U.U5 reuses LOOP-W.W3's federal-business-day
  arithmetic primitive for business-day jurisdictions + uses calendar-
  day arithmetic for calendar-day jurisdictions. The matrix records
  `clock_basis: enum('calendar-days', 'business-days',
  'without-unreasonable-delay')` per jurisdiction. Adversarial test
  U.U5-A4 pins a calendar-day vs business-day mixed-jurisdiction
  breach. Runbook documents the discovery-definition variations.
- **Status**: open.

### U-X44 — Multi-tenant LOOP-U isolation deferred to LOOP-H.H3

- **Description**: All LOOP-U tracker tables (privacy_catalog,
  dsar_requests, gdpr_breaches, vpc_registry, breach_matrix,
  ferpa_designations, glba_reviews) omit a `tenant_id` column.
  Multi-tenant deployment requires migration in a single cross-loop
  sweep. Same risk class as B-X15, R-X15, S-X21, T-X28, W-X38.
- **Severity**: med (long-tail).
- **Mitigation**: Documented in `LOOP-U-SPEC.md §11 Open Questions`;
  H.H3 spec must enumerate every LOOP-U table; LOOP-U ships in
  single-tenant deployments only (documented in runbook).
- **Status**: open.

### U-X45 — Operator burden: privacy counsel review queue

- **Description**: Multi-jurisdiction privacy compliance creates a
  legal-review queue. Every DSAR response (especially edge cases),
  every Article 34 risk determination, every TIA refresh, every
  GLBA scope determination, every COPPA knowledge-events log review,
  every FERPA school-official designation requires privacy counsel
  review. For a CSP with 19 in-scope state laws + GDPR + COPPA +
  FERPA + GLBA, the review queue can exceed counsel bandwidth +
  produce shortcuts. Same class as T-X17.
- **Severity**: med.
- **Mitigation**: Tracker workflow adds explicit `legal_review_
  status: enum('not-started', 'in-review', 'approved', 'rejected',
  'changes-requested')` + reviewer + completed-at fields for each
  reviewable artifact. UI shows queue length + per-reviewer
  workload + SLA breach warnings. Renderer (U.U3 + U.U5 reports)
  refuses to mark "ready to send" without approved status.
- **Status**: open.

### U-X46 — Auditor expectations: per-jurisdiction posture documentation

- **Description**: Privacy audits (SOC 2 Privacy criteria, ISO 27701
  PIMS, third-party privacy assessments under CCPA's required risk
  assessments) expect per-jurisdiction posture documentation. The
  CSP's CCPA risk assessment is a different artifact from its GDPR
  Article 35 DPIA; both are different from FERPA's annual notice +
  GLBA's program review. Auditors expect to see each artifact + the
  cross-walk demonstrating the CSP didn't satisfy one regime at the
  expense of another.
- **Severity**: med.
- **Mitigation**: U.U6 emits a consolidated per-jurisdiction posture
  report (`out/privacy-jurisdiction-posture-FY<YYYY>.json` +
  `.xlsx` worksheet) summarizing per-jurisdiction obligations + the
  CSP's posture per obligation + cross-walk to other in-scope
  regimes. Auditor receives this as a one-stop reference. Tracker UI
  preview before commit. CHANGELOG entry per annual posture report.
- **Status**: open.

### U-X47 — Privacy-by-design + DPIA timing

- **Description**: GDPR Article 35 requires a Data Protection Impact
  Assessment (DPIA) BEFORE high-risk processing begins. CCPA / CPRA
  Article 1798.185(a)(15) requires similar "risk assessments" with
  the AG's regulatory deadline of Jan 1, 2026 for cybersecurity audits
  + risk assessments (CPPA's December 2024 regulations). Late DPIAs
  (after processing begins) are regulatory exposure even if the
  assessment itself is well-written.
- **Severity**: high.
- **Mitigation**: U.U6 + LOOP-M.M3 (DPIA emitter) integrate via the
  LOOP-U tracker's `processing_activities` table; each new activity
  triggers a DPIA-required check at activity creation, not at first
  data flow. Strict mode refuses to enable a high-risk processing
  activity without an approved DPIA on file. CHANGELOG entry per
  DPIA. Cross-references LOOP-M-RISKS.md.
- **Status**: open.

### U-X48 — Annual privacy training + record-keeping (CCPA, GDPR Article 39, GLBA)

- **Description**: Most major privacy regimes require ongoing privacy
  training for employees handling personal data: CCPA §1798.100(d)
  + the CPPA's implementing regulations require employee training;
  GDPR Article 39(1)(b) requires the DPO to "monitor compliance ...
  including ... raising awareness and training of staff"; GLBA
  Safeguards Rule §314.4(e) requires "security awareness training"
  for personnel. Missed training cycles are documented compliance
  failures.
- **Severity**: med.
- **Mitigation**: U.U6 tracks per-employee training completion
  records + per-program annual cycles; integrates with LOOP-P
  (Insider Threat + PS-family Workforce Security) for the
  employee roster + training-completion ledger. Tracker UI
  countdown shows overdue training per program. Cross-references
  LOOP-P-RISKS.
- **Status**: open.

---

## Per-slice risks

### U.U1 — Privacy Framework Catalog Extractor

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| U.U1-1 | high | State law jurisdiction drift across 19+ statutes (cross-ref U-X1) | Per-jurisdiction catalog rows + quarterly cron + IAPP tracker triangulation | open |
| U.U1-2 | high | IAPP / FPF / NCSL tracker staleness (cross-ref U-X2) | 90-day strict mode + REQUIRES-OPERATOR-INPUT on triangulation mismatch | open |
| U.U1-3 | med | Sub-state local ordinances (NYC LL 144, IL BIPA, SF facial-rec) (cross-ref U-X4) | sub_jurisdiction_overlays[] + seed data + operator extension | open |
| U.U1-4 | low | Tribal jurisdiction privacy laws (cross-ref U-X5) | tribal_jurisdictions[] seed + REQUIRES-OPERATOR-INPUT | open |
| U.U1-5 | high | "Personal information" bifurcation (consumer-rights vs breach) (cross-ref U-X20) | Two definitions per jurisdiction; U.U2 vs U.U5 separation | open |
| U.U1-6 | high | Catalog snapshot file tampering (cross-ref U-X39) | Hash chain + CI re-verify + HSM signing key | open |
| U.U1-7 | high | Catalog provenance loss (signing-key rotation, cross-ref U-X36) | Tracker key registry + signing_key_id per snapshot | open |
| U.U1-8 | med | International framework coverage (UK GDPR + Swiss FADP + Brazil LGPD + India DPDPA + Japan APPI + Australia Privacy Act) (cross-ref U-X16) | Separate jurisdiction entries + per-article divergence tracking | open |
| U.U1-9 | med | Data localization jurisdictions (Russia, China, India, UAE) (cross-ref U-X17) | data_localization_requirements[] per jurisdiction | open |
| U.U1-10 | med | Sensitive-data definitional drift across regimes (cross-ref U-X8) | sensitive_categories[] per jurisdiction; max-sensitivity computation | open |
| U.U1-11 | low | Catalog extractor non-deterministic ordering (PDF/web scrape order varies) | Sort by (jurisdiction_code, statute_section, effective_date) before emit | open |
| U.U1-12 | med | Catalog schema validation drift (operator privacy-config.yaml) | ajv schema in `core/privacy-config-schema.json`; validate on every load | open |
| U.U1-13 | low | First-snapshot bootstrap when no prior snapshot exists | `--first-snapshot` flag opts into emit; CHANGELOG documents bootstrap | open |
| U.U1-14 | med | Catalog record count growth (19 → 25+ states pending legislative action) | Snapshot is JSON-line-delimited; bench at 500 entries < 100ms load | open |
| U.U1-15 | low | English-only at launch (other languages deferred) | Documented in runbook; future enhancement | open |
| U.U1-16 | med | Sectoral-overlay coverage (HIPAA, COPPA, FERPA, GLBA, GDPR Art 9 special categories) | Per-overlay registry with cross-references to U.U6 | open |

### U.U2 — CCPA / CPRA Crosswalk + DSAR Portal

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| U.U2-1 | high | Applicability-threshold mis-computation (cross-ref U-X3) | applicability_calculator + operator-supplied real numbers + quarterly re-eval | open |
| U.U2-2 | high | DSAR identity-verification false-positive (cross-ref U-X11) | Multi-factor verification + verification_strength_score + sensitivity-tiered thresholds | open |
| U.U2-3 | med | DSAR identity-verification false-negative (cross-ref U-X12) | Tiered verification + appeal workflow + adversarial test U.U2-A5 | open |
| U.U2-4 | high | DSAR clock miss across CCPA / GDPR / state laws (cross-ref U-X13) | Per-jurisdiction min-window computation + tracker countdown | open |
| U.U2-5 | high | CCPA-GDPR conflict resolution (data-minimization, cross-ref U-X6) | Stricter-wins rule + conflict matrix per data category | open |
| U.U2-6 | high | Consent-default conflict (CCPA opt-out vs GDPR opt-in) (cross-ref U-X7) | Geo-fenced consent strings + per-subject jurisdiction resolution | open |
| U.U2-7 | med | Global Privacy Control (GPC) signal recognition (CA + CO + CT + others mandate respect) | Browser GPC header parsing + per-jurisdiction respect flag + tracker UI status | open |
| U.U2-8 | med | DSAR portal availability (24x7 expected by regulators) | Tracker uptime SLO + on-call paging | open |
| U.U2-9 | med | DSAR audit trail (every request, action, denial) | Tracker audit_log with Ed25519 signature; cross-ref U-X36 | open |
| U.U2-10 | med | "Limit Use of Sensitive Personal Information" right (CPRA-specific) | Per-data-category sensitivity flag + LUSPI consent gate | open |
| U.U2-11 | low | Right-to-correct workflow (newer than right-to-know/delete) | Correction request flow + verification of corrected data accuracy | open |
| U.U2-12 | med | Right-to-portability format (machine-readable, commonly-used, structured) | Default JSON; XLSX export option; signed envelope | open |
| U.U2-13 | high | Service-provider vs third-party characterization (CCPA contractual carve-outs) | Per-recipient classification in tracker; signed contractual addendum reference | open |
| U.U2-14 | med | Automated decision-making opt-out (CPRA + CT + NJ + others) | ADM detection per business process; opt-out tracking | open |
| U.U2-15 | low | DSAR volume capacity planning | Per-month volume metrics; queue-depth alerting | open |
| U.U2-16 | high | DSAR response template per jurisdiction language | Per-jurisdiction template + counsel review per template version | open |

### U.U3 — GDPR Crosswalk + Article 33 / 34 Reporter

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| U.U3-1 | high | Article 33 72-hour clock miss (cross-ref U-X32) | Calendar-hour arithmetic + tracker countdown + adversarial test U.U3-A1 | open |
| U.U3-2 | high | Article 34 high-risk determination + encryption safe-harbor (cross-ref U-X33) | Determination enum + key-blast-radius check + adversarial test U.U3-A2 | open |
| U.U3-3 | med | Lead supervisory authority determination (cross-ref U-X34) | main_establishment_member_state + lead_authority routing | open |
| U.U3-4 | high | Article 33 records-of-breaches register (cross-ref U-X35) | Per-FY signed register + DPO countersign | open |
| U.U3-5 | high | Cross-border transfer mechanism invalidation (Schrems III) (cross-ref U-X14) | Per-mechanism validation tracking + strict-mode refusal | open |
| U.U3-6 | high | TIA staleness (cross-ref U-X15) | 12-month default + T-90/30/7 warnings + trigger-event monitoring | open |
| U.U3-7 | med | UK GDPR / Swiss FADP divergence (cross-ref U-X16) | Separate jurisdiction entries + per-article divergence | open |
| U.U3-8 | high | Article 30 records-of-processing-activities completeness | RoPA emitter + per-activity ingestion gate; cross-ref U-X47 | open |
| U.U3-9 | med | Joint-controller arrangements (Article 26) | Joint-controller registry + arrangement-document references | open |
| U.U3-10 | med | Processor sub-processor flow-down (Article 28(2-4)) | Sub-processor registry + flow-down contractual evidence | open |
| U.U3-11 | high | Article 22 solely-automated-decision-making rights | ADM inventory + opt-out workflow + explanation generator | open |
| U.U3-12 | med | Article 13 / 14 notice-at-collection completeness | Notice generator with per-jurisdiction language; tracker UI preview | open |
| U.U3-13 | low | EDPB guidance updates (frequent) | Per-guidance review cadence; tracker UI surfaces newest guidance | open |
| U.U3-14 | med | Article 33 supervisory authority per-MS contact table staleness | Quarterly verification cron + REQUIRES-OPERATOR-INPUT on stale contacts | open |
| U.U3-15 | high | Article 33 notification artifact format (per-SA preferences) | Per-SA template + JSON envelope + .docx for paper-only authorities | open |

### U.U4 — COPPA Verifiable Parental Consent Registry

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| U.U4-1 | high | VPC method outside approved list (cross-ref U-X23) | Enum-typed vpc_method + strict mode rejection + runbook | open |
| U.U4-2 | high | Actual-knowledge constructive trigger missed (cross-ref U-X24) | knowledge_events[] log + weekly counsel review + adversarial test | open |
| U.U4-3 | med | Child-becomes-13 transition (cross-ref U-X25) | child_lifecycle_state + transition workflow + operator policy enum | open |
| U.U4-4 | high | Age-based consent matrix (COPPA <13, GDPR <16, state laws 13/14/15/16/17) (cross-ref U-X9) | Per-jurisdiction digital_consent_age + derogations table | open |
| U.U4-5 | high | Direct-notice + verifiable-parental-consent timing (notice BEFORE collection) | Pre-collection consent gate; tracker timeline records notice timestamp | open |
| U.U4-6 | med | Material-change re-consent (e.g. new data category) | Material-change detector (similar to T-X6); re-consent trigger | open |
| U.U4-7 | med | School-authorized COPPA exception (school stands in for parents) | School-authorization artifact + scope limitation + cross-ref U.U6 FERPA | open |
| U.U4-8 | med | Behavioral-advertising prohibition under COPPA | Per-child ad-targeting opt-out + audit trail | open |
| U.U4-9 | high | Data retention "as long as reasonably necessary" + 1-year-minimum after deletion request | Retention enforcement + deletion-request workflow | open |
| U.U4-10 | high | FTC notification of breach affecting children | Breach matrix integration; cross-ref U.U5 + U-X30 | open |
| U.U4-11 | low | Online services "directed to children" determination | FTC's 10-factor test + tracker UI questionnaire + counsel sign-off | open |
| U.U4-12 | med | Third-party plug-in / SDK on child-directed service | Per-SDK COPPA-readiness questionnaire + revocation workflow | open |
| U.U4-13 | low | COPPA Rule amendment cycle (FTC reviews every 10 years; last 2013, expected 2024-2025) | Catalog version pin + amendment-watch cron | open |
| U.U4-14 | med | FTC Safe Harbor program participation | Optional opt-in; per-program compliance evidence | open |
| U.U4-15 | high | Facial-recognition VPC (2023 FTC approval with conditions) | Per-condition verification + adversarial test | open |

### U.U5 — Multi-Jurisdiction Breach-Notification Matrix

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| U.U5-1 | high | Matrix staleness across 50+ jurisdictions (cross-ref U-X18) | Quarterly cron + 90-day strict mode + per-jurisdiction effective_date | open |
| U.U5-2 | med | Territory + tribal coverage gaps (PR/GU/VI + tribal jurisdictions) (cross-ref U-X19) | Explicit seeds + tribal_jurisdictions[] | open |
| U.U5-3 | high | PI-definition bifurcation (breach vs consumer-rights) (cross-ref U-X20) | Two definitions in U.U1; U.U5 uses pi_breach_definition | open |
| U.U5-4 | med | Substitute-notice threshold variation (cross-ref U-X21) | substitute_notice_calculator + per-jurisdiction thresholds + cost evidence | open |
| U.U5-5 | med | Encryption-safe-harbor variation (cross-ref U-X22) | Per-jurisdiction standard + cross-ref LOOP-R cryptographic posture | open |
| U.U5-6 | high | AG-notification thresholds per residents affected | Per-jurisdiction threshold + automatic routing | open |
| U.U5-7 | med | Consumer-reporting-agency notification (FCRA + state) | Per-CRA threshold + bundle generator | open |
| U.U5-8 | high | Calendar-day vs business-day clock per jurisdiction (cross-ref U-X43) | Per-jurisdiction clock_basis enum + reuse LOOP-W.W3 primitive | open |
| U.U5-9 | med | "Without unreasonable delay" interpretation (most states) | Default to shortest numeric window in scope; counsel review for override | open |
| U.U5-10 | high | Multi-jurisdiction breach orchestration (50+ notifications) | Per-incident bundle generator + tracker workflow + SLA monitoring | open |
| U.U5-11 | med | Per-jurisdiction notification language requirements (specific clauses required) | Per-jurisdiction template + counsel review per template version | open |
| U.U5-12 | low | Notification delivery channel (mail, email, in-app, phone) | Per-jurisdiction channel enum + delivery-evidence tracking | open |
| U.U5-13 | med | Regulator URL drift (state AGs reorganize websites) | Per-jurisdiction URL + monthly link-check cron | open |
| U.U5-14 | high | Cross-border breach (US + EU + UK) coordination | Per-region notification orchestrator + lead-SA routing (cross-ref U-X34) | open |
| U.U5-15 | med | Healthcare overlay (HIPAA breach + state breach + GDPR Art 33) | Multi-regime coordination; cross-ref LOOP-M (HIPAA) + U.U6 | open |
| U.U5-16 | high | Incident-discovery timestamp + LOOP-G.G2 handoff (cross-ref U-X42) | Shared `core/incident-clock.ts` + cross-loop test | open |
| U.U5-17 | low | Notification effectiveness audit (delivery rate, recipient confusion) | Post-incident delivery-metrics + recipient-help-line tracking | open |

### U.U6 — FERPA + GLBA + Sectoral Overlays

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| U.U6-1 | high | FERPA school-official chain (cross-ref U-X26) | Signed designation per school + strict-mode ingestion gate | open |
| U.U6-2 | med | FERPA directory-information opt-out (cross-ref U-X27) | Per-student opt-out flag + emit pipeline filter | open |
| U.U6-3 | med | State student-data laws layered on FERPA (cross-ref U-X28) | Per-school applicable-law list + per-law disclosure tracking | open |
| U.U6-4 | high | GLBA Safeguards Rule annual review (cross-ref U-X29) | Annual cadence tracker + T-60/30/7 warnings + cross-ref T-X12 | open |
| U.U6-5 | high | GLBA 30-day notification clock (cross-ref U-X30) | Tracker countdown + automatic notification draft + adversarial test | open |
| U.U6-6 | high | GLBA financial-institution scope (cross-ref U-X31) | Scope questionnaire + counsel sign-off + quarterly re-eval | open |
| U.U6-7 | high | Health information regime overlap (HIPAA, MHMD, GINA, GDPR Art 9) (cross-ref U-X10) | All-applicable-laws-must-be-satisfied rule + per-data-category overlap matrix | open |
| U.U6-8 | med | Annual privacy posture report (cross-ref U-X46) | Per-jurisdiction posture .json + .xlsx + tracker preview | open |
| U.U6-9 | high | DPIA timing (BEFORE high-risk processing) (cross-ref U-X47) | Pre-activation DPIA gate + cross-ref LOOP-M.M3 | open |
| U.U6-10 | med | Annual privacy training (CCPA + GDPR Art 39 + GLBA §314.4(e)) (cross-ref U-X48) | Per-program training tracker + cross-ref LOOP-P | open |
| U.U6-11 | med | GLBA Qualified Individual designation (single accountable person) | Operator-supplied qualified_individual_user_id + tracker enforcement | open |
| U.U6-12 | high | GLBA semi-annual vulnerability assessment + annual pentest | Cross-ref LOOP-E (ConMon) + per-test artifact tracking | open |
| U.U6-13 | low | Auditor walkthrough (SOC 2 Privacy, ISO 27701) preparation | Pre-audit posture export + per-criterion mapping | open |
| U.U6-14 | med | Sectoral overlay maintenance (HIPAA + COPPA + FERPA + GLBA + state) | Quarterly cross-jurisdiction review meeting + counsel sign-off | open |
| U.U6-15 | high | FERPA annual notification to parents/eligible students | Annual notice generator + delivery-evidence tracking | open |

---

## External dependencies that may change

### Federal + state statutory sources

- **CCPA / CPRA + CPPA regulations** — https://oag.ca.gov/privacy/ccpa
  + https://cppa.ca.gov/ — California regulations updated through CPPA
  rulemaking; the Dec 2024 ADMT + cybersecurity audit + risk assessment
  regulations are the most recent material expansion. Quarterly review
  recommended.
- **State privacy law tracker (IAPP Westin Research Center)** —
  https://iapp.org/resources/article/us-state-privacy-legislation-tracker/
  — updated near-real-time during legislative sessions; primary tracker
  for 19 in-force statutes + 25-30 pending bills.
- **Future of Privacy Forum (FPF) state map** —
  https://fpf.org/wp-content/uploads/2024/12/State-Privacy-Map.png
  (refreshed periodically) — secondary triangulation source.
- **National Conference of State Legislatures (NCSL) privacy
  compendium** — https://www.ncsl.org/technology-and-communication/
  consumer-data-privacy — tertiary triangulation source; lags IAPP
  by 1-2 weeks.
- **GDPR + UK GDPR + Swiss FADP** — https://eur-lex.europa.eu/eli/
  reg/2016/679/oj (GDPR) + https://www.gov.uk/data-protection
  (UK ICO) + https://www.edoeb.admin.ch/edoeb/en/home.html (Swiss
  FDPIC) — stable underlying statutes; supervisory-authority guidance
  updated frequently.
- **EDPB guidelines + opinions** — https://www.edpb.europa.eu/
  our-work-tools/our-documents/guidelines_en — issued ~6-12 per year;
  some materially affect compliance posture (e.g. WP 244 rev.01 on
  lead supervisory authority).
- **COPPA Rule (16 CFR Part 312)** — https://www.ftc.gov/legal-library/
  browse/rules/childrens-online-privacy-protection-rule-coppa —
  FTC reviews every ~10 years; 2024-2025 NPRM expected as of
  2026-06-07; CHANGELOG cycle should track.
- **FERPA (20 U.S.C. §1232g; 34 CFR Part 99)** —
  https://studentprivacy.ed.gov/ — Department of Education FPCO
  guidance; PTAC technical guidance refreshed periodically.
- **GLBA Safeguards Rule (16 CFR Part 314)** — https://www.ftc.gov/
  business-guidance/resources/ftc-safeguards-rule-what-your-business-
  needs-know — May 2024 amendment added 30-day FTC notification;
  CHANGELOG should track FTC rulemaking.
- **State breach-notification statutes** — per-state AG websites +
  the National Conference of State Legislatures compendium
  (https://www.ncsl.org/technology-and-communication/security-breach-
  notification-laws) — primary aggregation; quarterly re-extraction
  recommended.

### Standards + frameworks

- **NIST Privacy Framework v1.0 (Jan 2020)** —
  https://www.nist.gov/privacy-framework — federal-side privacy
  taxonomy that LOOP-M.M1 extends; LOOP-U builds on LOOP-M's
  taxonomy.
- **ISO/IEC 27701:2019 PIMS** — international Privacy Information
  Management System; cross-walked to GDPR.
- **AICPA SOC 2 Trust Services Criteria - Privacy** —
  https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-
  greater-than-soc-2 — audit-side criteria for SaaS providers; many
  CSPs hold SOC 2 + need privacy posture mapped.

### Tracker + tooling dependencies

- **`core/privacy-catalog.ts`** — owns the master catalog snapshot
  loader + verifier.
- **`core/dsar-portal.ts`** — DSAR portal backend; includes the
  identity-verification engine + clock arithmetic.
- **`core/gdpr-art-33-reporter.ts`** — GDPR breach-notification
  generator + register manager.
- **`core/coppa-vpc-registry.ts`** — verifiable-parental-consent
  registry; includes the knowledge-events log.
- **`core/breach-matrix.ts`** — multi-jurisdiction breach-notification
  matrix engine.
- **`core/ferpa-designation-reader.ts`** — FERPA school-official
  designation parser + validator.
- **`core/glba-safeguards-tracker.ts`** — GLBA Safeguards Rule
  program-review + notification tracker.
- **`core/incident-clock.ts`** — shared clock primitive across
  LOOP-G + LOOP-U + LOOP-W.
- **`core/annual-review-tracker.ts`** — shared annual cadence
  primitive across LOOP-T + LOOP-U.

---

## Resolved risks (historical)

(none yet — LOOP-U is in proposed state; this section will accumulate
resolved risks as slices ship)

---

## Resume-from-fresh-session checklist

When a fresh session opens to triage a LOOP-U risk:

1. **Read CLAUDE.md** — confirm REO standard + reading-list path.
2. **Read `docs/STATUS.md`** — find the LOOP-U slice status + the
   "Next priority" line.
3. **Read `docs/loops/LOOP-U-SPEC.md`** — for the loop-level mission +
   per-slice cross-references.
4. **Read this file (`docs/loops/LOOP-U-RISKS.md`)** — find the risk
   you are triaging; check `Status:` field for open / resolved /
   in-progress.
5. **Read the affected per-slice doc (`docs/slices/U/U.UN.md`)** for
   implementation context.
6. **Check cross-references** to other loops' risks registers
   (LOOP-M / LOOP-G / LOOP-T / LOOP-W / LOOP-R) for inherited
   patterns.
7. **Update this file** in the same commit as the mitigation: change
   `Status:` to `resolved` + add a `Resolution:` note (mitigation
   commit, validation steps, date).
8. **Update STATUS.md** if the resolution closes an open question
   blocking a slice.
9. **Run** `npm run lint:no-stubs` + `npm run check:provenance` +
   `npm run check:coverage-regression` before commit.
10. **Push to origin/main** + verify with `git log --oneline -3`.

The 7-step SLICE-COMPLETION-PROCEDURE.md applies when the resolution
itself ships a slice; otherwise, this 10-step checklist is the
risk-resolution analog.

---

## Cross-references to other LOOP-X-RISKS files

- **LOOP-M-RISKS.md** — Privacy Package Extension (federal Privacy
  Act + SORN + DPIA); LOOP-U inherits taxonomy.
- **LOOP-G-RISKS.md** — Incident Communications + CIRCIA; shares
  the `incident-clock.ts` primitive + breach-discovery handoff.
- **LOOP-T-RISKS.md** — SSDF Common Form; shares annual-cadence
  primitive (T-X12 ↔ U-X29).
- **LOOP-W-RISKS.md** — Prohibited Vendor Screen; shares federal-
  business-day arithmetic primitive (W-X18 ↔ U-X43).
- **LOOP-R-RISKS.md** — Post-Quantum Cryptography; cryptographic
  posture feeds GDPR Article 34(3)(a) safe-harbor (R-X* ↔ U-X33,
  U-X22).
- **LOOP-B-RISKS.md** — POA&M emitter; LOOP-U privacy gaps surface
  as POA&M items with `risk_category = 'privacy-compliance-gap'`.
- **LOOP-O-RISKS.md** — AI/ML governance; LOOP-U covers automated-
  decision-making opt-outs (CPRA + CT + NJ) layered on LOOP-O's
  AI risk-management.
- **LOOP-P-RISKS.md** — Insider Threat + Workforce Security; LOOP-U
  privacy training requirements (CCPA + GDPR Art 39 + GLBA) integrate
  with LOOP-P's training ledger.
- **LOOP-H-RISKS.md** — Multi-CSO / long-term storage; LOOP-U
  multi-tenant isolation deferred to H.H3 (U-X44).

---

> END OF FILE — LOOP-U-RISKS.md
