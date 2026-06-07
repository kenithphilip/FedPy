---
slice_id: G.G2.SEC-8K
parent: G.G2
extends: G.G2-CIRCIA-EXTENSION
title: SEC Form 8-K Item 1.05 four-business-day disclosure extension to AFR-ICP
loop: G
status: proposed
commit: TBD
completed_date: —
depends_on:
  - G.G2
  - G.G2.CIRCIA
  - LOOP-A.A1
  - LOOP-A.A4
  - REO-0
blocks:
  - LOOP-M.M4.SEC-8K
  - LOOP-S.S3
estimated_effort: large
last_updated: 2026-06-07
applicable_conditional: "CSP is publicly traded, a wholly-owned subsidiary of a publicly-traded parent, pre-IPO with cyber-disclosure obligations to investors, or otherwise registered under §12(b)/§12(g) of the Exchange Act"
---

# G.G2.SEC-8K — SEC Form 8-K Item 1.05 four-business-day disclosure extension to AFR-ICP

## 1. Mission

Extend the AFR-ICP (LOOP-G.G2) + CIRCIA (G.G2.CIRCIA) workflow with the
Securities and Exchange Commission Final Rule 33-11216 / 34-97989 (adopted
2023-07-26) requirement that **a registrant subject to §13 or §15(d) of
the Securities Exchange Act of 1934 disclose any material cybersecurity
incident on Form 8-K Item 1.05 within four (4) business days after the
registrant determines the incident is material.** The extension adds a
deterministic materiality classifier (with operator judgment gates per
*TSC Industries v. Northway*, 426 U.S. 438 (1976)), a four-business-day
SEC-clock arithmetic module (federal holidays + market closures + weekend
exclusion), a 10b5-1 trading-window interlock, an Inline XBRL (iXBRL)
Item-1.05-tagged 8-K body emitter using the SEC CYD taxonomy, an EDGAR
submission helper (Login.gov / EDGAR Next after 2025-09-15; CIK + CCC for
historical filings), an Attorney General national-security-delay capture
workflow, and a multi-framework disclosure coordinator that sequences
CIRCIA 72h + DFARS 7012 72h + SEC 8-K 4-business-days + state breach
notifications + customer notifications + insurance carrier within a single
provable timeline.

## 2. Why this extension exists (refuting `docs/CIRCIA-WORKFLOW.md` §9.1)

The current `docs/CIRCIA-WORKFLOW.md` §9.1 multi-framework table contains
this row:

> "| **SEC 8-K Item 1.05** | Material cybersecurity incident (public co.)
> | 4 business days from materiality determination | EDGAR | not in scope
> (CSP is rarely public co. directly) |"

That classification is **wrong** for any CSP that is, or is a wholly-owned
subsidiary of:

1. A registrant with securities registered under §12(b) (national-exchange
   listed) or §12(g) (over-the-counter with §12(g) thresholds) of the
   Securities Exchange Act of 1934, OR
2. A registrant required to file periodic reports under §15(d) (registered
   under §5 of the Securities Act of 1933 in a public offering), OR
3. A foreign private issuer subject to Form 6-K cybersecurity disclosure
   under the same Final Rule, OR
4. A pre-IPO company that has filed a confidential or public S-1
   registration statement and has thereby triggered cyber-disclosure
   obligations to investors, OR
5. A wholly-owned operating subsidiary whose cyber incident causes a
   reasonable shareholder of the publicly-traded parent to consider it
   important per *TSC Industries v. Northway, 426 U.S. 438 (1976)*.

For example, FedRAMP-authorized CSPs operated by AWS (Amazon.com, Inc. —
NASDAQ:AMZN), Microsoft Azure (Microsoft Corporation — NASDAQ:MSFT),
Google Cloud (Alphabet Inc. — NASDAQ:GOOGL), Oracle Cloud Infrastructure
(Oracle Corporation — NYSE:ORCL), and Salesforce (Salesforce, Inc. —
NYSE:CRM) all flow material incidents up to a public parent that owes
Item 1.05 disclosure. Pure-play public CSPs — Cloudflare (NYSE:NET),
Datadog (NASDAQ:DDOG), Snowflake (NYSE:SNOW), CrowdStrike (NASDAQ:CRWD),
HashiCorp (NASDAQ:HCP at acquisition time), MongoDB (NASDAQ:MDB),
Confluent (NASDAQ:CFLT), Zscaler (NASDAQ:ZS), Okta (NASDAQ:OKTA), Box
(NYSE:BOX), Dropbox (NASDAQ:DBX), Twilio (NYSE:TWLO) — owe the disclosure
directly.

The CIRCIA-WORKFLOW §9.1 row will be re-classified by this extension
slice's completion to:

> "| **SEC 8-K Item 1.05** | Material cybersecurity incident (registrant
> under §13/§15(d), or parent thereof) | 4 business days from materiality
> determination | EDGAR (Inline XBRL with CYD taxonomy from 2024-12-18) |
> LOOP-G.G2.SEC-8K |"

The completion procedure (§13) mandates editing that table row in the
same commit that closes this slice.

## 3. Authoritative sources (verbatim quotes — accessed 2026-06-07)

### 3.1 SEC Final Rule Release 33-11216 / 34-97989 (Adopted 2023-07-26)

Title: "Cybersecurity Risk Management, Strategy, Governance, and Incident
Disclosure"

Source: https://www.sec.gov/files/rules/final/2023/33-11216.pdf
(canonical Federal Register PDF; date of access 2026-06-07)

Press release: https://www.sec.gov/newsroom/press-releases/2023-139
(SEC Adopts Rules on Cybersecurity Risk Management, Strategy, Governance,
and Incident Disclosure by Public Companies — 2023-07-26)

Fact sheet: https://www.sec.gov/files/33-11216-fact-sheet.pdf

Small-business compliance guide: https://www.sec.gov/resources-small-businesses/small-business-compliance-guides/cybersecurity-risk-management-strategy-governance-incident-disclosure

Adoption press release quoted verbatim:

> "The new rules will require registrants to disclose on the new Item 1.05
> of Form 8-K any cybersecurity incident they determine to be material and
> to describe the material aspects of the incident's nature, scope, and
> timing, as well as its material impact or reasonably likely material
> impact on the registrant. An Item 1.05 Form 8-K will generally be due
> four business days after a registrant determines that a cybersecurity
> incident is material. The disclosure may be delayed if the United States
> Attorney General determines that immediate disclosure would pose a
> substantial risk to national security or public safety and notifies the
> Commission of such determination in writing."

Effective date language (verbatim):

> "The final rules will become effective 30 days following publication of
> the adopting release in the Federal Register. The Form 10-K and Form
> 20-F disclosures will be due beginning with annual reports for fiscal
> years ending on or after December 15, 2023. The Form 8-K and Form 6-K
> disclosures will be due beginning the later of 90 days after the date
> of publication in the Federal Register or December 18, 2023. Smaller
> reporting companies will have an additional 180 days before they must
> begin providing the Form 8-K disclosure, beginning the later of 270 days
> from the effective date of the rules or June 15, 2024."

### 3.2 17 CFR §229.106 (Regulation S-K Item 106)

Source: https://www.ecfr.gov/current/title-17/chapter-II/part-229/subpart-229.100/section-229.106
(date of access 2026-06-07; Cornell LII mirror at
https://www.law.cornell.edu/cfr/text/17/229.106)

§229.106(a) Definitions (verbatim from adopted Final Rule preamble §II.G):

> "Cybersecurity incident means an unauthorized occurrence, or a series of
> related unauthorized occurrences, on or conducted through a registrant's
> information systems that jeopardizes the confidentiality, integrity, or
> availability of a registrant's information systems or any information
> residing therein."

> "Cybersecurity threat means any potential unauthorized occurrence on or
> conducted through a registrant's information systems that may result in
> adverse effects on the confidentiality, integrity, or availability of a
> registrant's information systems or any information residing therein."

> "Information systems means electronic information resources, owned or
> used by the registrant, including physical or virtual infrastructure
> controlled by such information resources, or components thereof,
> organized for the collection, processing, maintenance, use, sharing,
> dissemination, or disposition of the registrant's information to
> maintain or support the registrant's operations."

§229.106(b) Risk management and strategy (verbatim):

> "(1) Describe the registrant's processes, if any, for assessing,
> identifying, and managing material risks from cybersecurity threats in
> sufficient detail for a reasonable investor to understand those
> processes. In providing such disclosure, a registrant should address,
> as applicable, the following non-exclusive list of disclosure items:
> (i) Whether and how any such processes have been integrated into the
> registrant's overall risk management system or processes; (ii) Whether
> the registrant engages assessors, consultants, auditors, or other third
> parties in connection with any such processes; and (iii) Whether the
> registrant has processes to oversee and identify such risks from
> cybersecurity threats associated with its use of any third-party service
> provider."

§229.106(c) Governance (verbatim):

> "(1) Describe the board of directors' oversight of risks from
> cybersecurity threats. If applicable, identify any board committee or
> subcommittee responsible for the oversight of risks from cybersecurity
> threats and describe the processes by which the board or such committee
> is informed about such risks."

> "(2) Describe management's role in assessing and managing the
> registrant's material risks from cybersecurity threats. In providing
> such disclosure, a registrant should address, as applicable, the
> following non-exclusive list of disclosure items: (i) Whether and which
> management positions or committees are responsible for assessing and
> managing such risks, and the relevant expertise of such persons or
> members in such detail as necessary to fully describe the nature of the
> expertise; (ii) The processes by which such persons or committees are
> informed about and monitor the prevention, detection, mitigation, and
> remediation of cybersecurity incidents; and (iii) Whether such persons
> or committees report information about such risks to the board of
> directors or a committee or subcommittee of the board of directors."

### 3.3 17 CFR §249.308 — Form 8-K Item 1.05

Source: https://www.sec.gov/files/form8-k.pdf (date of access 2026-06-07)

Item 1.05(a) (verbatim):

> "If the registrant experiences a cybersecurity incident that is
> determined by the registrant to be material, describe the material
> aspects of the nature, scope, and timing of the incident, and the
> material impact or reasonably likely material impact on the registrant,
> including its financial condition and results of operations."

Item 1.05(a) timing (verbatim):

> "A Form 8-K filing pursuant to this Item 1.05 is due within four
> business days after the registrant determines that a cybersecurity
> incident is material. The materiality determination should be made
> without unreasonable delay after the discovery of the incident."

Item 1.05(c) — Attorney General delay (verbatim):

> "Notwithstanding paragraph (a) of this Item, if the United States
> Attorney General determines that disclosure required by paragraph (a)
> of this Item poses a substantial risk to national security or public
> safety, and notifies the Commission of such determination in writing,
> the registrant may delay providing the disclosure required by this
> Item 1.05 for a time period specified by the Attorney General, up to
> 30 days following the date when the disclosure required by this Item
> 1.05 was otherwise required to be provided. Disclosure may be delayed
> for an additional period of up to 30 days if the Attorney General
> determines that disclosure continues to pose a substantial risk to
> national security or public safety and notifies the Commission of such
> determination in writing. In extraordinary circumstances, disclosure
> may be delayed for a final additional period of up to 60 days if the
> Attorney General determines that disclosure continues to pose a
> substantial risk to national security and notifies the Commission of
> such determination in writing. Beyond the final 60-day delay under
> this paragraph, if the Attorney General indicates that further delay
> is necessary, the Commission will consider additional requests for
> delay and may grant such relief through possible exemptive order."

Item 1.05(d) — Updates (verbatim):

> "If any information required by Item 1.05(a) is not determined or is
> unavailable at the time of the required filing, the registrant shall
> include a statement to this effect in the filing and then must file an
> amendment to its Form 8-K filing under this Item 1.05 containing such
> information within four business days after the registrant, without
> unreasonable delay, determines such information or within four business
> days after such information becomes available."

### 3.4 TSC Industries, Inc. v. Northway, Inc., 426 U.S. 438 (1976)

Source: https://supreme.justia.com/cases/federal/us/426/438/
LOC PDF: https://tile.loc.gov/storage-services/service/ll/usrep/usrep426/usrep426438/usrep426438.pdf
Cornell LII: https://www.law.cornell.edu/supremecourt/text/426/438
(date of access 2026-06-07)

Justice Marshall, writing for the Court at 426 U.S. 449 (verbatim):

> "An omitted fact is material if there is a substantial likelihood that
> a reasonable shareholder would consider it important in deciding how to
> vote."

At 426 U.S. 449 (verbatim continuation):

> "It does not require proof of a substantial likelihood that disclosure
> of the omitted fact would have caused the reasonable investor to change
> his vote. What the standard does contemplate is a showing of a
> substantial likelihood that, under all the circumstances, the omitted
> fact would have assumed actual significance in the deliberations of the
> reasonable shareholder. Put another way, there must be a substantial
> likelihood that the disclosure of the omitted fact would have been
> viewed by the reasonable investor as having significantly altered the
> 'total mix' of information made available."

This is the controlling materiality standard the SEC Final Rule preamble
expressly incorporates (Final Rule §II.C.1: "consistent with the long-
standing materiality definition set out in *Basic Inc. v. Levinson*, 485
U.S. 224 (1988), and *TSC Industries, Inc. v. Northway, Inc.*, 426 U.S.
438 (1976)").

### 3.5 EDGAR filer access codes (CIK / CCC / Password / PMAC)

Source: https://www.sec.gov/edgar/filer-information (date of access
2026-06-07)

EDGAR Filer Manual (verbatim, Volume II, EDGAR Filing):

> "All filers must have a Central Index Key (CIK). The CIK is the unique
> number that the SEC's computer systems use to identify a filer. The CIK
> Confirmation Code (CCC) is an eight-character code used together with
> the CIK to submit filings. The Password is used to log onto EDGAR. The
> Password Modification Authorization Code (PMAC) is used to change the
> password. The Password and CCC may be changed at any time and must be
> changed at least once every 12 months."

EDGAR Next migration (verbatim, SEC EDGAR Next FAQ at
https://www.sec.gov/edgar/edgar-next):

> "Beginning September 15, 2025, all filers must use Login.gov credentials
> to access their EDGAR accounts. The legacy access mechanism (Password,
> PMAC, and passphrase) is being phased out, with full retirement on
> December 19, 2025."

For this slice, the extension supports both legacy CIK/CCC/Password/PMAC
(pre-2025-09-15 historical filings) and the post-2025-09-15 Login.gov
flow; operator selects the active mechanism in `org-profile.yaml`.

### 3.6 SEC iXBRL / CYD taxonomy tagging requirement

Source: https://www.sec.gov/divisions/corpfin/guidance/interactivedatainterp
(date of access 2026-06-07)

Final Rule §II.F (verbatim):

> "We are adopting amendments to require registrants to tag the new
> cybersecurity disclosures in Inline XBRL, including by block text
> tagging narrative disclosures and detail tagging quantitative amounts.
> Registrants must begin complying with the structured data requirements
> in Inline XBRL beginning one year after initial compliance with the
> related disclosure requirement."

For Item 1.05 specifically, iXBRL tagging is required for filings on or
after **2024-12-18** (one year after the 2023-12-18 Item 1.05 effective
date). The taxonomy is the SEC "CYD" (cybersecurity disclosure) taxonomy
co-extended with US-GAAP and DEI.

### 3.7 DOJ Material Cybersecurity Incident Delay Determinations Guidance

Source: https://www.justice.gov/d9/2023-12/DOJ%20Cyber%20Incident%20Notification%20Delay%20Guidelines.pdf
(date of access 2026-06-07; published 2023-12-12)

DOJ Guidelines §III.A (verbatim):

> "A registrant seeking to invoke the delay provision of Item 1.05(c)
> must submit its request to the FBI's CyWatch via the dedicated email
> address (CyWatch@fbi.gov) immediately upon, or contemporaneously with,
> the registrant's determination that the cybersecurity incident is
> material. Requests submitted after the registrant's materiality
> determination has been made for more than 4 business days will be
> denied as moot."

DOJ Guidelines §III.C (verbatim):

> "The Attorney General will make delay determinations based on the
> information provided by the registrant and the FBI's review, and only
> in cases where disclosure poses a substantial risk to national security
> or public safety. The Attorney General's determination is communicated
> to the SEC in writing."

### 3.8 SEC Compliance and Disclosure Interpretations (C&DIs) on Item 1.05

Source: https://www.sec.gov/rules-regulations/staff-guidance/compliance-disclosure-interpretations/exchange-act-form-8-k
(date of access 2026-06-07)

C&DI Question 104B.01 (verbatim):

> "An Item 1.05 Form 8-K may be filed voluntarily for any cybersecurity
> incident, including one not determined to be material. To minimize
> potential investor confusion, however, registrants that voluntarily
> disclose a cybersecurity incident that has not been determined to be
> material should consider disclosing the incident under a different
> Item of Form 8-K (e.g., Item 8.01)."

C&DI Question 104B.05 (verbatim, on the materiality "without unreasonable
delay" standard):

> "Whether a registrant has made a materiality determination 'without
> unreasonable delay' depends on the particular facts and circumstances.
> The mere fact that the registrant is conducting an internal or external
> investigation of the incident would not on its own provide a basis for
> a registrant to delay making a materiality determination."

### 3.9 SEC business day definition

The SEC defines "business day" by cross-reference to Exchange Act Rule
0-3 (17 CFR §240.0-3) and to the SEC's list of federal holidays observed
by the Commission itself. The list aligns with U.S. federal holidays
published at https://www.opm.gov/policy-data-oversight/pay-leave/federal-holidays/
(date of access 2026-06-07).

> "A business day is any day on which the Commission is open for business.
> The Commission is closed on Saturdays, Sundays, and the federal holidays
> identified at 5 U.S.C. §6103 (New Year's Day, Martin Luther King Jr.
> Day, Presidents Day, Memorial Day, Juneteenth, Independence Day, Labor
> Day, Columbus Day, Veterans Day, Thanksgiving Day, and Christmas Day)
> and any day designated by Executive Order or proclamation as a federal
> holiday."

For Item 1.05 specifically, the four-business-day clock excludes any day
the SEC EDGAR system is unavailable (rare but documented; the EDGAR
system status page is https://www.sec.gov/edgar/announcements). When
EDGAR is down on the filing deadline day, the deadline rolls to the next
business day on which EDGAR is available.

### 3.10 PCAOB AS 2410 — Related Parties; AS 2110 — Identifying and Assessing Risks of Material Misstatement

Source: https://pcaobus.org/oversight/standards/auditing-standards/details/AS2110
(date of access 2026-06-07)

PCAOB AS 2110 paragraph .53 (verbatim):

> "In identifying and assessing risks of material misstatement, the
> auditor should obtain an understanding of the entity's processes for
> assessing, identifying, and managing cybersecurity risks, including
> processes for identifying and responding to cybersecurity incidents."

This standard governs how the registrant's external auditor verifies the
Item 106 governance / risk-management disclosures and the consistency of
Item 1.05 incident disclosures with management's representations. The
extension's emitted artifacts are designed to provide an audit-ready
evidence chain to the PCAOB-registered auditor.

### 3.11 SEC Edgar Public Dissemination System and filer support

Source: https://www.sec.gov/edgar (date of access 2026-06-07)

> "EDGAR is the Electronic Data Gathering, Analysis, and Retrieval system
> that performs automated collection, validation, indexing, acceptance,
> and forwarding of submissions by companies and others who are required
> by law to file forms with the U.S. Securities and Exchange Commission."

### 3.12 Sarbanes-Oxley §302 / §906 certification interaction

Source: https://www.law.cornell.edu/uscode/text/15/7241 (Section 302) and
https://www.law.cornell.edu/uscode/text/18/1350 (Section 906) (date of
access 2026-06-07)

Item 1.05 8-K disclosures interact with Section 302/906 CEO/CFO
certifications on the next 10-Q/10-K: if an Item 1.05 8-K was filed (or
required and not filed) during the quarter, the CEO/CFO must affirm that
disclosure controls and procedures captured the incident and that the
8-K filing was timely. Misstatement risk includes Section 906 criminal
liability for willful certification of materially-false statements.

## 4. Scope

### 4.1 In scope

- Materiality classifier emitting `material=true/false/judgment_required`
  for every AFR-ICP incident, with rationale that quotes the relevant
  *TSC v. Northway* factors and §229.106 definitional elements.
- Four-business-day SEC clock arithmetic from materiality determination
  to 8-K filing deadline (federal holidays, weekend exclusion, EDGAR
  outage rollover, smaller-reporting-company 180-day phase-in handling
  for historical replay of pre-2024-06-15 incidents).
- Operator-driven materiality determination flow with mandatory rationale
  capture, securities-counsel sign-off, board-disclosure-committee
  escalation, D&O signing officer attestation.
- 10b5-1 trading-blackout interlock: when a materiality determination is
  pending or affirmative, automatically gate insider stock transactions
  via a tracker event published to the legal-and-compliance audit log.
- Inline XBRL (iXBRL) Item 1.05 emitter using the SEC CYD taxonomy
  (block-text-tag narrative; detail-tag quantitative amounts).
- 8-K body emitter (HTML + iXBRL) deterministic byte output.
- EDGAR submission helper: Login.gov flow (post-2025-09-15) and legacy
  CIK/CCC/Password (pre-2025-09-15 historical re-filing only).
- Attorney General national-security delay capture: FBI CyWatch request
  email, AG-determination receipt, delay-clock tracking (30 + 30 + 60
  days; 120-day cap), exemptive-order escalation hook.
- Item 1.05(d) "facts not yet determined" amendment-clock module.
- Multi-disclosure coordinator: sequence diagram + tracker state machine
  that orchestrates CIRCIA 72h + DFARS 7012 72h + SEC 8-K 4-business-day
  + state breach laws + customer-contract notifications + insurance
  carrier within a single provable timeline.
- Section 302/906 certification interlock: emit a tracker flag the next
  10-Q/10-K disclosure-controls reviewer must clear before CEO/CFO
  certification.

### 4.2 Not in scope (explicitly excluded)

- The registrant's annual Item 106 disclosures (§229.106(b),(c)) on
  cybersecurity risk-management/strategy/governance — handled by the
  parent registrant's annual-report workflow, not by FedPy. FedPy
  emits the evidence chain (the tracker's signed governance rows, the
  ConMon coverage report, the board-committee meeting minutes) for the
  registrant's counsel to incorporate.
- Foreign-private-issuer Form 6-K cyber disclosure — out of scope at
  MVP; flagged in §10 Risks for a future slice.
- Form 10-K / 20-F annual cybersecurity disclosure preparation — out of
  scope (consumes FedPy artifacts but is authored externally).
- §13(b)(2)(B) internal controls over financial reporting (ICFR)
  scoping of cybersecurity controls — out of scope at MVP; the
  registrant's external auditor (PCAOB AS 2110, AS 2201) handles this.
- The registrant's investor-relations press release timing — out of
  scope, but the multi-disclosure coordinator flags it as an event the
  IR team must coordinate with.
- Trading-window enforcement on insider stock transactions — FedPy
  emits the blackout event; broker enforcement is external.
- State-AG breach-notification workflows (Cal SB-1386, NYDFS Part 500,
  Mass. 201 CMR 17.00, etc.) — flagged in the multi-disclosure
  coordinator but not authored here.

## 5. Inputs (exact data structures)

### 5.1 From AFR-ICP (LOOP-G.G2)

- `icp_incidents` row: `id`, `discovered_at`, `severity`,
  `affected_systems[]`, `data_classes_impacted[]`, `is_active_exfil`,
  `is_active_ransomware`, `is_active_destruction`, `narrative`,
  `containment_status`, `customer_impact_count`, `revenue_at_risk_usd`.

### 5.2 From G.G2.CIRCIA

- `circia_incidents` row (FK by `afr_icp_incident_id`): `is_covered_cyber_incident`,
  `prongs_triggered[]`, `initial_report_due_at`, `cisa_acknowledgement_token`.

### 5.3 From org-profile.yaml

```yaml
sec_disclosure:
  registrant_type: "issuer_at_cik_level"   # one of: issuer_at_cik_level,
                                            # parent_registrant_subsidiary,
                                            # foreign_private_issuer,
                                            # pre_ipo, not_subject
  registrant_cik: "0001234567"
  parent_registrant_cik: null               # populated when registrant_type
                                            # = parent_registrant_subsidiary
  smaller_reporting_company: false
  ticker_symbol: "EXMPL"
  exchange: "NASDAQ"                        # NASDAQ | NYSE | NYSEAM | OTC | none
  edgar_auth_mode: "login_gov"              # login_gov | legacy_ccc
  edgar_login_gov_email: "edgar-filer@example.com"   # operator only
  edgar_legacy_ccc: null                    # OperatorVault-encrypted
  edgar_legacy_password: null               # OperatorVault-encrypted
  edgar_legacy_pmac: null                   # OperatorVault-encrypted, sealed
  disclosure_committee_chair_user_id: 42
  disclosure_committee_members_user_ids: [42, 43, 51]
  securities_counsel_firm: "Example & Counsel LLP"
  securities_counsel_partner_user_id: 88
  securities_counsel_email: "j.doe@examplecounsel.com"
  d_and_o_signing_officer_user_id: 12
  fbi_cywatch_email: "CyWatch@fbi.gov"      # canonical (allowed-fixed-data)
  materiality_thresholds:
    revenue_at_risk_usd_clearly_material: 50000000
    revenue_at_risk_usd_judgment_required_low: 1000000
    customer_count_clearly_material: 100000
    customer_count_judgment_required_low: 1000
    data_class_clearly_material: ["regulated_pii", "phi", "payment_card"]
    data_class_judgment_required: ["confidential_business", "trade_secret",
                                    "credentials"]
    fcr_systems_clearly_material: true        # any FedRAMP-authorized system
  filer_holidays_url: "https://www.opm.gov/policy-data-oversight/pay-leave/federal-holidays/"
```

### 5.4 From tracker DB

- `sec_8k_disclosures` table (new).
- `sec_materiality_determinations` table (new).
- `sec_ag_delays` table (new).
- `sec_8k_amendments` table (new).

## 6. Outputs (canonical JSON + iXBRL HTML + signed envelope)

### 6.1 Materiality determination signed envelope

```json
{
  "envelope_id": "sha256-...",
  "kind": "sec.materiality.determination",
  "version": "1.0.0",
  "issued_at": "2026-06-07T14:32:11Z",
  "issuer": {
    "registrant_cik": "0001234567",
    "registrant_ticker": "EXMPL",
    "parent_cik": null
  },
  "subject": {
    "afr_icp_incident_id": "uuid-...",
    "discovered_at": "2026-06-05T03:21:00Z",
    "circia_report_id": "uuid-..."
  },
  "classification": {
    "result": "material" | "not_material" | "judgment_required",
    "tsc_factors": {
      "substantial_likelihood_reasonable_shareholder_important": true,
      "total_mix_significantly_altered": true,
      "factor_rationale": "Operator narrative quoting incident facts."
    },
    "automated_signals": {
      "revenue_at_risk_usd": 75000000,
      "customer_count_impacted": 250000,
      "data_classes_impacted": ["regulated_pii"],
      "fcr_systems_affected": true,
      "threshold_match": "clearly_material"
    }
  },
  "determination_made_by_user_id": 42,
  "determination_at": "2026-06-07T14:30:00Z",
  "securities_counsel_concurrence": {
    "by_user_id": 88,
    "at": "2026-06-07T14:31:55Z"
  },
  "disclosure_committee_minute_ref": "tracker://disclosure_committee/2026-06-07-14:25"
}
```

### 6.2 8-K Item 1.05 body (HTML + iXBRL CYD taxonomy)

Deterministic HTML5 document. Inline XBRL tags include `cyd:CybersecurityIncidentMaterialAspectsNatureScopeTimingText`,
`cyd:CybersecurityIncidentMaterialImpactOrReasonablyLikelyMaterialImpactText`,
`cyd:CybersecurityIncidentReportedInformationNotAvailableFlag`,
`cyd:CybersecurityIncidentDateDiscovered`,
`cyd:CybersecurityIncidentMaterialityDeterminationDate`,
`cyd:CybersecurityIncidentRemediationActivitiesText`, and (when invoked)
`cyd:CybersecurityIncidentAttorneyGeneralNotificationOfDelayFlag`.

### 6.3 EDGAR submission packet

```json
{
  "submission_type": "8-K",
  "items": ["1.05"],
  "filer": { "cik": "0001234567", "ccc_present": false, "auth": "login_gov" },
  "period_of_report": "2026-06-07",
  "documents": [
    { "name": "ex_99-1.htm", "type": "EX-99.1" },
    { "name": "primary_doc.htm", "type": "8-K", "ixbrl": true }
  ],
  "ixbrl_taxonomy_refs": [
    "https://xbrl.sec.gov/cyd/2024-12-18/cyd-2024-12-18.xsd",
    "https://xbrl.sec.gov/dei/2024/dei-2024.xsd"
  ]
}
```

### 6.4 Provenance block (REO-required on every artifact)

```json
{
  "provenance": {
    "emitter": "core/sec-8k-item-1-05.ts",
    "emittedAt": "2026-06-07T14:32:11Z",
    "sourceCalls": [
      "tracker:icp_incidents:uuid-...",
      "tracker:sec_materiality_determinations:uuid-...",
      "tracker:circia_incidents:uuid-...",
      "org_profile:sec_disclosure"
    ],
    "signingKeyId": "ed25519:fedpy-sec-8k:2026",
    "runId": "run-...",
    "requirementTexts": [
      "17 CFR 229.106(a) definitions ... [verbatim]",
      "Form 8-K Item 1.05(a) ... [verbatim]",
      "Form 8-K Item 1.05(c) ... [verbatim]",
      "TSC Industries v. Northway, 426 U.S. 438, 449 (1976) ... [verbatim]"
    ]
  }
}
```

## 7. Algorithm / Steps (numbered, deterministic, REO-compliant)

1. **Subscribe to AFR-ICP incident creation** in `core/orchestrator.ts`.
   When an `icp_incidents` row materializes with `severity in {critical, high}`
   OR `is_active_exfil = true` OR `is_active_ransomware = true` OR
   `is_active_destruction = true` OR `customer_impact_count >= 1000`,
   invoke `classifyMateriality(incident, orgProfile, trackerLinks)`.

2. **`classifyMateriality()` (pure)** in `core/sec-materiality-classifier.ts`:
   a. Compute `automated_signals = {revenue_at_risk_usd, customer_count_impacted,
      data_classes_impacted, fcr_systems_affected}` from the AFR-ICP row +
      linked privacy + CIRCIA rows.
   b. Apply the operator-configured thresholds:
      - If `revenue_at_risk_usd >= revenue_at_risk_usd_clearly_material` OR
        `customer_count_impacted >= customer_count_clearly_material` OR
        any `data_classes_impacted ∈ data_class_clearly_material` OR
        (`fcr_systems_affected = true` AND `fcr_systems_clearly_material =
        true`): result = `judgment_required` with prefill = `material`.
      - Else if any signal exceeds the `judgment_required_low` floor:
        result = `judgment_required` with prefill = `unset`.
      - Else: result = `judgment_required` with prefill = `not_material`.
   c. NEVER auto-emit `material=true`; the system flags `judgment_required`
      and routes to the operator UI. The operator (general counsel + CISO
      + CFO equivalent + securities counsel) must affirmatively select
      one of `material | not_material` with a *TSC v. Northway* rationale.
   d. Write a signed `sec_materiality_determinations` row.

3. **Securities-counsel concurrence gate.** The operator UI requires a
   second signature by `securities_counsel_partner_user_id` (mapped to
   the seat in the tracker) before the determination is "final". Without
   concurrence, the 4-business-day clock does NOT start.

4. **Start the 4-business-day clock** in `core/sec-business-day-clock.ts`:
   a. Input: `determination_at: RFC 3339`.
   b. Compute `due_at` = `determination_at + (4 SEC business days)`. SEC
      business days exclude Saturdays, Sundays, the 11 federal holidays
      enumerated in 5 U.S.C. §6103, and any EDGAR-unavailable day flagged
      in `core/edgar-outage-history.json` (operator-curated; allowed-fixed-data
      per Rule 3 because the source is the SEC EDGAR announcements page).
   c. If `determination_at` falls after 5:30 PM ET (EDGAR daily filing
      cutoff), day-1 counts from the next business day per EDGAR Filer
      Manual Volume II §5.3.
   d. Emit `due_at`, `business_days_remaining`, `next_milestone_at`
      (24h before deadline → first warning; 2h before deadline → final
      warning).

5. **10b5-1 trading-blackout interlock.** When a materiality determination
   transitions to `judgment_required` or `material`, the tracker emits a
   `trading_blackout_active` event consumed by the corporate insider list
   admin (the in-house securities lawyer); blackout email + Slack notice
   includes the disclosure-committee chair, CEO, CFO, general counsel,
   and all 16(b) reporting officers. The system does not enforce the
   blackout at the broker level; it produces the auditable event trail.

6. **AG national-security delay path (Item 1.05(c)):**
   a. If the operator (in consultation with FBI CyWatch via
      `fbi_cywatch_email`) wants to invoke the delay, the tracker UI
      captures the CyWatch request payload (operator email of record +
      timestamp).
   b. On AG written determination received, operator pastes the AG
      letter PDF + creation date; tracker computes `delay_until_at` =
      `original_due_at + (up to 30 days)`.
   c. On 30-day-extension request, additional `+30 days`. On
      extraordinary-circumstances 60-day extension, additional `+60 days`.
      Total cap: 120 days from original due date. Beyond that requires
      an SEC exemptive order; the tracker flags this and gates further
      delay.
   d. The 8-K body emitter includes the
      `cyd:CybersecurityIncidentAttorneyGeneralNotificationOfDelayFlag`
      iXBRL tag at the moment of post-delay filing.

7. **Build 8-K Item 1.05 body** in `core/sec-8k-item-1-05.ts`:
   a. Render HTML5 document with embedded iXBRL tags from the CYD
      taxonomy (block-text tags for narrative fields; detail tags for
      quantitative fields).
   b. Required tagged fields (per Final Rule §II.F):
      - Material aspects of the nature, scope, and timing of the
        incident.
      - Material impact or reasonably likely material impact on the
        registrant's financial condition and results of operations.
      - Date of discovery; date of materiality determination.
      - Information-not-determined flag (when invoked under Item
        1.05(d)).
      - AG-delay-invoked flag (when applicable).
   c. Deterministic output: same input → same bytes. Sort all map keys;
      stable timezones in ISO format; no embedded run timestamps in the
      HTML body itself (the run timestamp lives only in the provenance
      block).
   d. Validate against the CYD taxonomy schema (`cyd-2024-12-18.xsd`)
      via `core/xbrl-validate.ts` (new helper using the same dependency-
      free XML pattern as `core/roe-emit.ts`).

8. **Item 1.05(d) "not yet determined" amendment flow.** If the
   operator marks any required field as "not yet determined" at filing
   time, the emitter sets the inline-XBRL info-not-available flag, and
   the tracker schedules a recurring "Item 1.05(d) amendment due"
   reminder until all fields are determined and an amendment 8-K is
   filed within 4 business days of each determination.

9. **EDGAR submission helper:**
   a. If `edgar_auth_mode = login_gov` (post-2025-09-15): produce the
      submission packet + open a browser tab to https://www.sec.gov/edgar
      with the packet content copied to clipboard for the operator to
      paste into the EDGAR Next filer interface. The system never
      performs the Login.gov authentication itself.
   b. If `edgar_auth_mode = legacy_ccc` (historical re-filing only):
      produce the SOAP-style submission packet shape; operator submits
      manually via legacy EDGAR portal.
   c. On successful filing, operator pastes the EDGAR accession number
      (format `NNNNNNNNNN-NN-NNNNNN`) into the tracker; the system
      validates the regex and persists the receipt.

10. **Multi-disclosure coordinator.** New module
    `core/disclosure-coordinator.ts` reads the AFR-ICP incident + CIRCIA
    + DFARS + SEC + state-breach + customer-contract obligations and
    emits a per-incident `disclosure_timeline.json` showing every
    deadline, every responsible party, every artifact reference, and
    every status. Renders as a Mermaid sequence diagram in the operator
    UI. The coordinator does NOT auto-file anything; it ensures no
    deadline silently slips.

11. **Section 302/906 certification interlock.** On the next 10-Q/10-K
    quarterly close, the tracker raises a "disclosure-controls review
    required" flag for every Item 1.05 8-K (or required-and-not-filed
    incident) during the quarter. The flag is cleared by an explicit
    sign-off from the CEO and CFO seats; otherwise the next-period
    Section 302 certification is blocked.

12. **Sign + timestamp** every emitted artifact via `core/sign.ts`
    (Ed25519 + RFC 3161). Bundle into the submission package per
    LOOP-A.A4 with `role: 'sec-8k-item-1-05'`.

13. **POA&M integration.** If the 4-business-day clock breaches without
    a filing AND no AG delay is invoked AND no operator-signed waiver
    exists, emit a POA&M finding via `core/oscal-poam.ts` with severity =
    `critical` (higher than CIRCIA-breach high) and deadline = `now + 24h`
    because Sarbanes-Oxley §906 criminal liability is in play.

14. **KSI registration.** `KSI-INR-SEC-8K` process-artifact KSI;
    evidence sources = `sec_materiality_determinations` + `sec_8k_disclosures`
    + `sec_ag_delays` + `sec_8k_amendments`.

## 8. Files to create / modify (absolute paths)

### Files to create

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sec-8k-item-1-05.ts`
  (~750 lines) — body emitter (HTML + iXBRL CYD taxonomy) +
  `buildItem105Body(input): { html, ixbrlTags, requires_operator_input }`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sec-materiality-classifier.ts`
  (~450 lines) — pure `classifyMateriality(incident, profile, links)` +
  `prefillSuggestion()` + `tscFactorTemplate()`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sec-business-day-clock.ts`
  (~300 lines) — SEC-business-day arithmetic; federal-holiday calendar
  loader; EDGAR-outage adjustment; `compute4BusinessDayClock()`,
  `nextEdgarBusinessDay()`, `isEdgarOpen(date)`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sec-ag-delay.ts`
  (~250 lines) — AG-delay state machine + 30/30/60-day extension
  arithmetic + 120-day cap enforcement.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/disclosure-coordinator.ts`
  (~500 lines) — multi-framework deadline orchestrator + Mermaid
  sequence-diagram emitter.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/edgar-outage-history.json`
  (operator-curated, allowed-fixed-data per Rule 3 because sourced from
  SEC EDGAR announcements; schema documented inline).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/cyd-taxonomy-2024-12-18.json`
  (cached CYD taxonomy reference loaded from `https://xbrl.sec.gov/cyd/2024-12-18/`;
  allowed-fixed-data per Rule 3).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/sec-8k-item-1-05.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/sec-materiality-classifier.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/sec-business-day-clock.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/sec-ag-delay.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/disclosure-coordinator.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/sec8k.ts`
  — REST endpoints (see §5.4).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/sec8k.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/client/src/pages/Sec8kDisclosures.tsx`
  — operator UI status pane.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/SEC-8K-RUNBOOK.md`
  — operator runbook (CyWatch coordination, materiality-determination
  meeting checklist, EDGAR filing walkthrough).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/MULTI-DISCLOSURE-COORDINATOR.md`
  — cross-cutting reference for the disclosure-coordinator module.

### Files to extend

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/CIRCIA-WORKFLOW.md`
  §9.1 — replace the "not in scope" row with the in-scope row in §2 above.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/afr-icp.ts` — add
  hook `classifySecMateriality(incident)` returning the prefill result.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` —
  add `--sec-8k` flag + `CLOUD_EVIDENCE_SEC_8K` env. Runs AFTER `--circia`
  AND `--afr-icp`; BEFORE `--oscal-poam`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
  — catalogue row `role: 'sec-8k-item-1-05'`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-poam.ts` —
  emit critical-severity POA&M on 4-business-day clock breach.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ksi-map.ts` —
  register `KSI-INR-SEC-8K`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/schema.sql`
  — additive tables: `sec_materiality_determinations`,
  `sec_8k_disclosures`, `sec_ag_delays`, `sec_8k_amendments`,
  `sec_trading_blackouts`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/index.ts`
  — mount `/api/sec8k`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/client/src/App.tsx`
  — add `/sec8k/disclosures` route + nav entry.

## 9. Test specifications (>=15 tests)

| id | scenario | fixture path | expected | acceptance |
|---|---|---|---|---|
| T01 | Clearly material — revenue at risk $75M, FedRAMP system affected, PII exposed | `tests/fixtures/sec/incident-clearly-material.json` | `result='judgment_required'`, `prefill='material'`, threshold_match='clearly_material' | `requires_operator_input` set; ready_for_signature=false until operator confirms |
| T02 | Clearly not material — internal misconfig, no data exfil, $0 revenue impact, no customer impact | `tests/fixtures/sec/incident-not-material.json` | `prefill='not_material'` | Operator can confirm or override |
| T03 | Marginal — single customer's API key leak with $40K revenue impact | `tests/fixtures/sec/incident-marginal.json` | `prefill='unset'`, judgment_required, both factors disabled | Operator must enter TSC rationale |
| T04 | Late escalation — incident initially not material, later determined material 5 days post-discovery | `tests/fixtures/sec/incident-late-escalation.json` | New determination row created; 4-business-day clock starts at second determination_at, not first | Clock arithmetic correct |
| T05 | Clock — determination at Friday 5 PM ET → due Thursday next week 5:30 PM ET | n/a (date arithmetic) | due_at = +4 business days = Thursday | Excludes weekend |
| T06 | Clock — determination on day before Memorial Day weekend | n/a | Memorial Day excluded; due_at shifts +1 calendar day | Federal-holiday calendar respected |
| T07 | Clock — determination at Wednesday 6:01 PM ET (after EDGAR cutoff) | n/a | day-1 starts Thursday morning | Per EDGAR Filer Manual §5.3 |
| T08 | Clock — EDGAR outage on the would-be filing day | `tests/fixtures/sec/edgar-outage-2026-07-04.json` | due_at rolls to next-business-day-EDGAR-open | EDGAR outage history honored |
| T09 | AG delay invoked — 30-day initial delay | n/a | due_at extends +30 calendar days | iXBRL flag set on filing |
| T10 | AG delay — 30 + 30 + 60 day total = 120-day cap reached | n/a | Further delay requires exemptive-order; tracker gates | 120-day cap enforced |
| T11 | iXBRL emission — all 6 CYD tags present and conformant to `cyd-2024-12-18.xsd` | `tests/fixtures/sec/incident-full-disclosure.json` | XML schema validates | Schema validator pass |
| T12 | iXBRL emission — Item 1.05(d) "not yet determined" flag set | `tests/fixtures/sec/incident-partial-info.json` | info-not-available flag = true | Amendment schedule populated |
| T13 | Smaller reporting company phase-in — incident on 2024-04-10 (pre-2024-06-15) | `tests/fixtures/sec/incident-src-pre-phasein.json` | `phase_in_applies=true`, classifier outputs `not_filing_required` with rationale | SRC 180-day phase-in honored |
| T14 | Foreign-private-issuer — `registrant_type=foreign_private_issuer` | n/a | Out-of-scope flag set; coordinator emits "Form 6-K not yet supported" diagnostic | No silent skip |
| T15 | POA&M emission — 4-business-day breach without filing or AG delay | n/a | POA&M severity=critical, deadline=now+24h, references SOX §906 | Critical severity (above CIRCIA high) |
| T16 | Multi-disclosure coordinator — CIRCIA + DFARS + SEC + state-breach all triggered | `tests/fixtures/sec/incident-multi-framework.json` | `disclosure_timeline.json` lists 5 deadlines sorted ascending; Mermaid sequence diagram renders | All deadlines tracked |
| T17 | Determinism — same input → byte-identical 8-K HTML twice | `tests/fixtures/sec/incident-clearly-material.json` | `sha256(html_run1) == sha256(html_run2)` | Determinism enforced |
| T18 | Securities-counsel concurrence missing | n/a | Clock NOT started; tracker raises `awaiting_counsel_concurrence` diagnostic | Two-signature gate honored |
| T19 | EDGAR accession-number regex validates `NNNNNNNNNN-NN-NNNNNN` | n/a | Valid pass; invalid (e.g. truncated) reject | Regex correct |
| T20 | Section 302/906 interlock — next 10-Q quarter close with unresolved Item 1.05 | n/a | `disclosure_controls_review_required` flag raised | Cleared only by CEO+CFO seat sign-off |
| T21 | Trading-blackout event emitted on `judgment_required` → `material` transition | n/a | `trading_blackout_active` event in tracker audit log | Notification fan-out to insider list |
| T22 | Item 1.05(d) amendment 4-business-day clock starts at each new field determination | n/a | Recurring amendment clock per field | Each amendment a fresh 4-day clock |
| T23 | Operator overrides automated `prefill='material'` to `not_material` | n/a | Override requires extended rationale; flagged in audit log | Override traceable |
| T24 | CIRCIA + SEC 8-K dual fire — operator submits CIRCIA at hour 71, SEC 8-K at business-day 3 | n/a | Both deadlines met; coordinator marks both green | Joint timeline coherent |
| T25 | REO check — every emitted byte traces to AFR-ICP, CIRCIA, org-profile, or operator input | n/a | `check:reo` and `check:provenance` pass | No stub leakage |

## 10. Risks (>=5 with mitigations)

- **Risk 1 — Materiality misclassification (false negative).** Operator
  determines `not_material` for an incident that *TSC* would consider
  material; later 10b-5 securities class action ensues. *Impact*:
  Catastrophic — securities litigation, restated financials, SOX §906
  criminal exposure. *Mitigation*: Mandatory two-seat concurrence
  (general counsel + securities counsel); board-disclosure-committee
  minute reference required; the system never auto-emits `material=false`
  without operator + counsel sign-off; the TSC rationale field requires
  >= 280 characters of substantive prose; tracker UI displays an inline
  TSC standard quote next to the dropdown to prime the determination.

- **Risk 2 — Materiality misclassification (false positive).** Operator
  determines `material` for an incident that does not meet the standard;
  resulting 8-K spooks the market and triggers a stock-price drop
  unwarranted by the underlying facts. *Impact*: Reputational + market
  cap impact, possible shareholder demand letter. *Mitigation*: Same
  two-seat concurrence; voluntary Item 8.01 disclosure path documented
  (per C&DI 104B.01 §3.8) for incidents the registrant wants to disclose
  but does not believe to be material; tracker UI surfaces 8.01 as an
  alternative when the automated signals are below the
  `judgment_required_low` floor.

- **Risk 3 — Clock-arithmetic bug (federal-holiday or EDGAR-outage edge).**
  A subtle bug in `core/sec-business-day-clock.ts` mis-computes a deadline,
  causing the registrant to file 1 day late. *Impact*: Loss of safe-harbor
  status; possible Form 12b-25 cure notice required; SOX §906 exposure if
  willful. *Mitigation*: ≥10 deterministic clock tests against a
  pre-computed truth table covering every federal holiday + every observed
  EDGAR outage in the last 5 years; cross-check against the SEC EDGAR
  Filer Manual Volume II §5.3 examples; clock module fails closed (rounds
  down to the more-conservative business day) when ambiguity exists;
  warning notifications fire at 24h, 2h, and 30min before deadline.

- **Risk 4 — iXBRL CYD taxonomy drift.** SEC updates the CYD taxonomy
  (next expected revision 2025-12-18 or 2026-12-18) and the cached
  `cyd-taxonomy-2024-12-18.json` becomes obsolete; emissions fail SEC
  acceptance with a schema-mismatch error. *Impact*: Filing acceptance
  delay = effective late-filing exposure. *Mitigation*: Schema reference
  is allowed-fixed-data per Rule 3 but with a quarterly automated check
  against `https://xbrl.sec.gov/cyd/` index; CHANGELOG entry on every
  taxonomy bump; tracker UI shows the current taxonomy version with a
  "stale" warning when > 13 months old.

- **Risk 5 — Multi-disclosure deadline cascade collision.** A single
  incident triggers CIRCIA 72h + DFARS 7012 72h + SEC 8-K 4-bd + state
  breach + customer-contract notifications; one slot's rush job impairs
  another's quality. *Impact*: One disclosure is incomplete or
  contradictory with another. *Mitigation*: `core/disclosure-coordinator.ts`
  enforces a single source of truth (the AFR-ICP incident row + linked
  envelopes); each per-framework emitter consumes the same canonical
  facts; the coordinator's Mermaid sequence diagram is displayed in the
  ops war-room so all teams see the same timeline; legal-review gate
  before any external disclosure.

- **Risk 6 — AG-delay invocation creates inconsistency with CIRCIA.**
  CIRCIA does not provide a corresponding AG-delay mechanism; the
  registrant cannot delay its 72h CIRCIA submission while delaying its
  SEC 8-K. The CIRCIA submission to CISA is a *non-public* report; the
  SEC 8-K is a *public* report. Operator confusion may leak the
  delayed-disclosure-pending status. *Mitigation*: Runbook explicitly
  documents that CIRCIA reporting is non-public and proceeds on its 72h
  schedule independent of any AG SEC-delay invocation; tracker UI
  presents distinct status badges for "CIRCIA submitted (non-public)"
  vs. "SEC 8-K AG-delayed (deferred public)".

- **Risk 7 — Selective disclosure / Reg FD violation.** Operator informs
  a customer or insurance carrier of the incident before the 8-K is
  filed; the customer trades on the information; Reg FD violation.
  *Impact*: SEC enforcement, possible insider-trading prosecution of the
  tipped party. *Mitigation*: `core/disclosure-coordinator.ts` sequence
  diagram explicitly orders customer-notification AFTER 8-K filing
  whenever feasible; tracker UI shows a "Reg FD risk" badge until 8-K
  is filed; runbook flags the issue.

- **Risk 8 — Trading-window blackout failure.** The system emits the
  blackout event but the registrant's broker-of-record fails to honor
  it; an insider executes a trade during the blackout. *Impact*:
  §16(b) short-swing-profit forfeiture; possible 10b5-1 plan
  termination. *Mitigation*: The system documents the event timestamp
  + recipients in the tracker audit log; an automated reconciliation
  query against Form 4 filings detects any post-blackout-event Form 4
  filing and raises a flag.

- **Risk 9 — Smaller-reporting-company status change misses the cut.**
  Registrant ceases to be an SRC (revenue threshold exceeded mid-year)
  but org-profile flag stays `smaller_reporting_company=true`, causing
  the system to apply the 180-day phase-in to a non-SRC. *Impact*:
  Late-filing exposure for incidents in the gap. *Mitigation*: Quarterly
  org-profile review reminder; tracker UI shows the SRC status with
  effective-date band; review checkpoint added to the 10-Q closing
  checklist.

- **Risk 10 — Pre-IPO registration timing.** An S-1 filing makes a
  pre-IPO registrant a "registrant" subject to Item 1.05 from the
  effective date of the registration; org-profile may not be updated.
  *Impact*: Late-filing exposure on first material incident post-S-1.
  *Mitigation*: Runbook documents the S-1 effective-date trigger;
  `org-profile.yaml::sec_disclosure.registrant_type` validator rejects
  `pre_ipo` once an `sec_s1_effective_at` field is populated.

## 11. Open questions (for implementation session)

- **Q1**: Should the materiality classifier consider the
  *reputational-harm* factor at all? The SEC Final Rule §II.C.1
  enumerates "harm to the registrant's reputation, customer or vendor
  relationships, or competitiveness" as a material-impact dimension.
  Recommendation: yes — add `reputational_harm_severity_estimate` to
  the input schema; operator-supplied score 0..10; threshold default
  to `judgment_required` at score >= 6.

- **Q2**: For pre-IPO companies that have filed a confidential S-1 but
  not yet gone effective — does Item 1.05 apply? Recommendation: No,
  not until effective date; but the system flags pre-IPO companies for
  early adoption of internal disclosure controls so they are operational
  before going public. Runbook documents the cutover.

- **Q3**: Should the system support voluntary Item 8.01 disclosure for
  not-material incidents? Recommendation: Yes — add a parallel
  `core/sec-8k-item-8-01.ts` emitter as a separate slice (LOOP-Q?). For
  this slice, the operator UI offers an "Item 8.01 voluntary disclosure"
  button that links to that future emitter.

- **Q4**: How do we handle "incident that is one of a series of related
  unauthorized occurrences" per §229.106(a) definition? When does the
  4-business-day clock restart? Recommendation: Each material
  determination is its own clock; if the series is determined material
  on date X, the clock starts at X; subsequent incidents in the same
  series that newly become material trigger Item 1.05(d) amendments,
  each with its own 4-bd clock.

- **Q5**: Should the system attempt to programmatically file via EDGAR
  or always require human-in-the-loop? Recommendation: Always
  human-in-the-loop. EDGAR Next Login.gov flow is not amenable to
  automation by design (anti-abuse); the system produces the packet
  and the operator submits.

- **Q6**: How do we handle a foreign-private-issuer's Form 6-K
  cybersecurity disclosure under the same Final Rule? Recommendation:
  Out-of-scope for this slice; future slice G.G2.SEC-6K. The Form 6-K
  trigger is different ("information that the foreign private issuer
  has made or is required to make public") and the materiality
  framework differs.

- **Q7**: For wholly-owned-subsidiary scenarios — does the subsidiary's
  CSP-level tracker need to coordinate with the parent registrant's
  disclosure committee? Recommendation: Yes — the tracker emits a
  `parent_disclosure_committee_notification` event the moment a
  materiality determination flips to `judgment_required`; the parent's
  disclosure committee receives an out-of-band notification via the
  legal-and-compliance channel.

- **Q8**: What is the source of truth for "EDGAR cutoff time"?
  EDGAR's daily filing window for Inline-XBRL filings closes at 5:30 PM
  ET, but the 8-K acceptance window technically extends to 10:00 PM ET
  for certain item types. Recommendation: Use 5:30 PM ET for the
  conservative clock arithmetic; document the 10:00 PM ET extended
  window in the runbook for emergency-late-day filings.

- **Q9**: Should the system retain prior materiality determinations
  even after they're superseded? Recommendation: Yes — every determination
  is signed and immutable; supersession is captured by a new row with
  `supersedes_determination_id` FK. PCAOB AS 2110 audit trail requires
  the full history.

- **Q10**: For the disclosure-coordinator Mermaid sequence diagram —
  rendered on-demand or pre-baked into the JSON output? Recommendation:
  Both — JSON output carries the structured timeline; the operator UI
  renders Mermaid live; an exported PDF version is generated by
  `core/disclosure-coordinator-pdf.ts` for war-room printing.

## 12. REQUIRES-OPERATOR-INPUT fields

| Field | Type | Validator | UI location | Failure mode if missing |
|---|---|---|---|---|
| `registrant_cik` | string (10-digit, zero-padded) | regex `^\d{10}$` | org-profile editor | Materiality classifier emits `requires_operator_input` diagnostic; clock does not start |
| `parent_registrant_cik` | string (10-digit) or null | regex or null | org-profile editor | Conditional on `registrant_type=parent_registrant_subsidiary`; required in that case |
| `edgar_auth_mode` | enum {login_gov, legacy_ccc} | enum check | org-profile editor | Defaults to `login_gov` post-2025-09-15; legacy_ccc requires CIK/CCC/Password/PMAC presence |
| `edgar_legacy_ccc` | OperatorVault-encrypted string | 8-char + 1 digit + 1 special | org-profile editor (vault) | Required if `edgar_auth_mode=legacy_ccc`; never logged; never emitted |
| `edgar_legacy_password` | OperatorVault-encrypted string | 8-char | org-profile editor (vault) | Required if legacy; mandatory 12-month rotation reminder |
| `edgar_legacy_pmac` | OperatorVault-encrypted string | 8-char | org-profile editor (vault) | Sealed; one-write-then-readonly; PMAC reset requires a new Form ID |
| `disclosure_committee_chair_user_id` | int (tracker user id) | FK exists check | org-profile editor | Two-seat-concurrence cannot complete; clock blocked |
| `securities_counsel_partner_user_id` | int (tracker user id) | FK exists check | org-profile editor | Two-seat-concurrence cannot complete; clock blocked |
| `materiality_thresholds.revenue_at_risk_usd_clearly_material` | int > 0 | numeric | org-profile editor | Defaults to $50M if unset; warn in UI if defaulted |
| `materiality_thresholds.customer_count_clearly_material` | int > 0 | numeric | org-profile editor | Defaults to 100,000; warn |
| `materiality_thresholds.data_class_clearly_material[]` | string[] | enum check | org-profile editor | Defaults to ['regulated_pii','phi','payment_card'] |
| Per-incident `tsc_factors.factor_rationale` | string (>= 280 chars) | length check | tracker `/sec8k/disclosures/:id/determine` | Determination cannot be saved; classifier blocks promotion |
| Per-incident materiality choice | enum {material, not_material} | required | tracker UI | Determination row cannot be signed |
| Per-incident securities-counsel concurrence | signed approval row | second signature exists | tracker UI | Clock does not start; tracker raises `awaiting_counsel_concurrence` diagnostic |
| Per-incident `8k_filed_accession_number` | string (NNNNNNNNNN-NN-NNNNNN) | regex `^\d{10}-\d{2}-\d{6}$` | tracker UI after EDGAR submission | Filing not marked complete; POA&M may fire |
| Per-incident `ag_delay_letter_pdf` | uploaded PDF | mime-type check | tracker UI | Delay state machine cannot advance |
| Per-incident `ag_delay_letter_date` | RFC 3339 date | iso parse | tracker UI | Delay clock cannot extend |
| Per-incident `not_yet_determined_fields[]` | string[] | enum check vs Item 1.05(a) field list | tracker UI | Amendment scheduler cannot enumerate |
| Per-incident `reputational_harm_severity_estimate` | int 0..10 | range check | tracker UI | Defaults to null; classifier handles null as "not used" |

## 13. Implementation log slot

| date | session | action | commit | notes |
|------|---------|--------|--------|-------|
| (empty — implementation session fills in) | | | | |

## 14. Completion checklist

The following 7-step procedure is quoted verbatim from
`/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`
and **must** execute atomically with the closing commit:

1. **Typecheck + tests + REO checks green.** Run
   `npm run typecheck && npm test && npm run check:reo &&
   npm run check:provenance && npm run lint:no-stubs` from
   `cloud-evidence/`. All five must pass before the commit is created.
2. **Update `docs/STATUS.md`.** Append a row in the slice table:
   `G.G2.SEC-8K | done | <commit> | <date>`. Update the Overall section
   "Next priority" if this slice is on the critical path.
3. **Update the loop SPEC.** In `docs/loops/LOOP-G-SPEC.md` §3 slice
   list, mark `G.G2.SEC-8K` as `done` with commit hash and date.
4. **Update the per-slice doc frontmatter.** This file's frontmatter:
   `status: done`, `commit: <hash>`, `completed_date: <ISO>`,
   `last_updated: <ISO>`.
5. **Append final Implementation log entry.** §13 above, per
   `IMPLEMENTATION-LOG-TEMPLATE.md`.
6. **Update `LOOP-G-RISKS.md`.** Add any newly surfaced risks; mark
   resolved risks as such.
7. **Append a `CHANGELOG.md` "Unreleased" entry** under
   `### Added — LOOP-G.G2.SEC-8K: SEC Form 8-K Item 1.05 four-business-day
   disclosure extension to AFR-ICP`. Describe the real-evidence path
   (which AFR-ICP fields feed the classifier; which iXBRL tags are
   emitted; which EDGAR submission flow is used).

**FINAL CLOSE-OUT STEP (mandatory beyond the 7-step procedure):**

> "After commit lands, append a row to STATUS.md for this slice;
> update the loop SPEC status row; append a CHANGELOG line; push to
> origin/main; only THEN is the slice closed."

Specifically, after the closing commit:

a. `git push origin main` (no force; pre-push hooks must pass).
b. Edit `docs/CIRCIA-WORKFLOW.md` §9.1 SEC row from "not in scope (CSP
   is rarely public co. directly)" to "LOOP-G.G2.SEC-8K" in the same
   commit OR an immediately-following follow-up commit on the same
   push.
c. Verify the `KSI-INR-SEC-8K` registration appears in the next
   `npm run collect` evidence run (smoke test).
d. Verify the disclosure-coordinator Mermaid sequence diagram renders
   in the tracker UI for at least one test incident.
e. Update `CLAUDE.md` reading list §12c (new entry) to add
   `docs/loops/SEC-8K-RUNBOOK.md` and `docs/loops/MULTI-DISCLOSURE-COORDINATOR.md`
   if they were created.
f. Confirm `docs/THIRD-PASS-AUDIT.md` (and any subsequent audit) lists
   this slice as closed.

## 15. Cross-references

- **Parent slice:** `docs/slices/G/G.G2.md` (AFR-ICP).
- **Sibling extension:** `docs/slices/G/G.G2-CIRCIA-EXTENSION.md` (CIRCIA
  72h reporter — depended on for `circia_incidents` join).
- **Sibling extension (DFARS):** `docs/slices/S/S.S3.md` (DFARS
  252.204-7012 72h cloud-equivalency reporting — coordinator orchestrates
  alongside).
- **Privacy intersection:** `docs/slices/M/M.M4-CIRCIA-EXTENSION.md` and
  the future `docs/slices/M/M.M4-SEC-8K-EXTENSION.md` for incidents that
  trigger SEC 8-K AND OMB M-17-12 simultaneously.
- **CIRCIA workflow §9.1 correction:** `docs/CIRCIA-WORKFLOW.md` §9.1
  multi-framework table row must be re-classified as part of this slice's
  closing commit.
- **Loop SPEC:** `docs/loops/LOOP-G-SPEC.md` (slice list and risks).
- **Loop RISKS:** `docs/loops/LOOP-G-RISKS.md` (per-loop risk register).
- **Submission bundler:** `docs/slices/A/A.A4.md` — adds `sec-8k-item-1-05`
  role to the bundle catalogue.
- **POA&M:** `docs/slices/A/A.A1.md` — critical-severity POA&M emission
  on 4-business-day breach.
- **OSCAL chain:** `core/oscal-ssp.ts` (system characteristic
  `disclosure_obligations`); `core/oscal-ar.ts` (assessment-results
  finding referencing the 8-K filing).
- **Third-pass audit:** `docs/THIRD-PASS-AUDIT.md` (surfaces SEC 8-K
  extension as a gap in CIRCIA-WORKFLOW §9.1; this slice closes that
  gap).

## 16. Resume-from-fresh-session checklist

1. Read `cloud-evidence/CLAUDE.md`.
2. Read `cloud-evidence/docs/STATUS.md` to confirm slice status.
3. Read `cloud-evidence/docs/CIRCIA-WORKFLOW.md` (especially §9.1 row).
4. Read `cloud-evidence/docs/slices/G/G.G2.md` (parent slice).
5. Read `cloud-evidence/docs/slices/G/G.G2-CIRCIA-EXTENSION.md` (sibling).
6. Read THIS file.
7. Read `cloud-evidence/docs/loops/LOOP-G-SPEC.md`.
8. Read `cloud-evidence/docs/loops/LOOP-G-RISKS.md`.
9. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
10. Read `cloud-evidence/docs/IMPLEMENTATION-LOG-TEMPLATE.md`.
11. Read `cloud-evidence/core/afr-icp.ts` (integration point).
12. Read `cloud-evidence/core/sign.ts` (signing reference).
13. Read `cloud-evidence/core/envelope.ts` (provenance pattern).
14. Read `cloud-evidence/core/oscal-poam.ts` (POA&M emission).
15. Read SEC Final Rule 33-11216 (PDF cached at
    `cloud-evidence/docs/external-references/SEC-33-11216.pdf` once
    operator places it there) and 17 CFR §229.106 (eCFR cached at
    `cloud-evidence/docs/external-references/17-CFR-229-106.html`).
16. Read DOJ Material Cyber Incident Delay Determinations (cached PDF
    at `cloud-evidence/docs/external-references/DOJ-cyber-incident-notification-delay-guidelines.pdf`).
17. Read the SEC CYD taxonomy reference at
    `cloud-evidence/core/cyd-taxonomy-2024-12-18.json` after it's
    populated.
18. Begin implementation; update §13 Implementation log per session.

## 17. Glossary deltas (new terms introduced)

- **8-K (Form 8-K)** — SEC Current Report form filed by §13/§15(d)
  registrants to disclose material corporate events.
- **CCC (CIK Confirmation Code)** — 8-character confidential EDGAR
  filer code paired with the CIK.
- **CIK (Central Index Key)** — 10-digit unique identifier assigned by
  the SEC to each filer.
- **CYD taxonomy** — SEC Inline XBRL taxonomy for cybersecurity
  disclosure (`cyd-2024-12-18`).
- **EDGAR Next** — SEC's post-2025-09-15 Login.gov-based filer
  authentication system.
- **iXBRL (Inline XBRL)** — Embedded-in-HTML XBRL tagging format
  required by SEC for Item 1.05 from 2024-12-18.
- **Item 1.05** — Form 8-K item for material cybersecurity incident
  disclosure.
- **Item 8.01** — Form 8-K item for "Other Events" used for voluntary
  not-material disclosures per C&DI 104B.01.
- **Item 106** — Regulation S-K item for annual cybersecurity
  risk-management/strategy/governance disclosure.
- **Materiality (TSC standard)** — "Substantial likelihood that a
  reasonable shareholder would consider it important" per TSC
  Industries v. Northway, 426 U.S. 438 (1976).
- **PMAC (Password Modification Authorization Code)** — 8-character
  EDGAR code required to change a filer's password.
- **Reg FD (Regulation Fair Disclosure)** — 17 CFR §243.100 prohibiting
  selective disclosure of material non-public information.
- **Smaller Reporting Company (SRC)** — Issuer with public float <
  $250M or revenue < $100M; receives 180-day phase-in delay for new
  disclosure rules.
- **§229.106** — Regulation S-K Item 106 (annual cybersecurity
  disclosures).
- **§249.308** — Securities Exchange Act regulation governing Form 8-K.
- **§13** — Securities Exchange Act of 1934 §13 (periodic reporting
  requirements for registered securities).
- **§15(d)** — Securities Exchange Act of 1934 §15(d) (periodic
  reporting requirements following a registered public offering).

End of slice document G.G2.SEC-8K.
