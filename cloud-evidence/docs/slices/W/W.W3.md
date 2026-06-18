---
slice_id: W.W3
title: FAR 52.204-25(d) 1-Business-Day Prohibited-Vendor Discovery Reporter
loop: W
status: done
commit: TBD-step6
completed_date: 2026-06-18
depends_on:
  - W.W1                                # prohibited-vendor catalog
  - W.W2                                # screen-result envelope (the trigger)
  - LOOP-A.A1                           # OSCAL POA&M emitter
  - LOOP-A.A4                           # Submission bundler
  - LOOP-A.A5                           # Ed25519 + RFC 3161 signing
  - LOOP-B.B1                           # composite risk scoring
  - tracker DB (existing)               # status pane + audit trail
blocks:
  - W.W4                                # annual rep references confirmed 1BD reports
estimated_effort: medium (~5 working days for single implementer)
last_updated: 2026-06-18
applicable_conditional: true
condition: Any CSP selling to a Federal agency, prime, or grant recipient — FAR 52.204-25(d) is mandatory disclosure. The 1-business-day clock starts the moment a positive identification is "discovered" — see §2 for the legal definition of discovery and the §6 algorithm for how W.W3 computes it.
trigger_flag: "--prohibited-vendor-1bd-report"
trigger_env: CLOUD_EVIDENCE_PROHIBITED_VENDOR_1BD_REPORT
---

# W.W3 — FAR 52.204-25(d) 1-Business-Day Prohibited-Vendor Discovery Reporter

> This slice was the **missing reporter** in the first-pass execution plan
> for LOOP-W. The third-pass audit and the FOURTH-PASS audit both
> identified W.W3 as the operational fulcrum of the entire loop: W.W1
> populates the catalog, W.W2 surfaces hits, but **only W.W3 actually
> produces the regulatory deliverable that the FAR clause obliges the
> contractor to file within one business day.** Because the slice was
> missed by the prior workflow and because the underlying clock is hard
> to compute (5 U.S.C. §6103 federal-holiday math + the OPM
> in-lieu-of rule + America/New_York DST transitions + agency-closure
> overrides), this per-slice doc carries extra rigor: more authoritative
> quotes, a longer test matrix (20 tests), an expanded risks register,
> and a step-by-step algorithm that any future Claude session or human
> implementer can execute without context from this conversation.

## 1. Mission

W.W3 ingests every `ProhibitedVendorScreenResult` envelope emitted by
W.W2 (canonical path `out/prohibited-vendors-screen-result.json`), walks
its `matches[]` array, and for each positive identification — defined
as a non-suppressed match whose `confidence_band = 'high'` AND whose
`catalog_provenance.source ∈ {'far-52.204-25-a', 'ndaa-1634',
'bod-17-01', 'operator-manual-addition'}` — composes a FAR
52.204-25(d)-compliant report containing the nine reporting elements
enumerated in paragraph (d)(2)(i), signs the report with the operator's
Ed25519 corporate signing key, attaches an RFC 3161 timestamp token to
the canonical JSON envelope, renders an equivalent OOXML/zip-store
`.docx` for the operator to attach to the Contracting Officer email (or
DIBNet upload for DoD primes), persists the dispatched report into the
tracker DB `section889_reports` table, and notifies the operator via the
existing `core/notify.ts` Slack/PagerDuty channel both at emission time
and one hour before the federal-business-day deadline expires.

The slice does **not** transmit the report to the Federal endpoint —
REO Rule 4 forbids the system from acting on behalf of the operator on
any regulatory submission. W.W3 produces the artifact pair (signed
JSON + signed `.docx`), surfaces the artifact pair in the tracker UI
with a live countdown timer to the deadline, and records every operator
action (transmission timestamp + officer ID + Federal acknowledgement
receipt id pasted by the operator) as a signed audit log entry. When
the deadline is at risk of being missed, W.W3 escalates: the
T-1-hour-to-deadline notification routes to the PagerDuty
`section889-1bd-deadline` service rather than the lower-urgency Slack
channel, and a tracker UI banner turns red.

W.W3 also implements the **10-business-day follow-up** report required
by FAR 52.204-25(d)(2)(ii) — when the initial 1-business-day report has
been transmitted (operator confirms via the tracker UI), W.W3 schedules
the follow-up window and re-prompts the operator at 8 business days for
mitigation-action input, then emits the follow-up report envelope at
discovery+10 business days. The follow-up path reuses the same signed
JSON / `.docx` pipeline; only the report-kind discriminator (`initial-1bd`
vs `follow-up-10bd`) changes.

## 2. Authoritative sources

Every URL accessed 2026-06-07. Verbatim quotes appear in Markdown
blockquotes. Where the live Federal Government source returned a non-200
to anonymous fetches, the implementer downloads the page or PDF to
`cloud-evidence/docs/sources/` and re-quotes verbatim from the local
copy.

### 2.1 FAR 52.204-25(d) — Reporting requirement (the 1-business-day clock)

URL: https://www.acquisition.gov/far/52.204-25 (accessed 2026-06-07).

Paragraph (d)(1) — the **discovery trigger** and the **endpoint
routing**:

> "(d) Reporting requirement.
> (1) In the event the Contractor identifies covered telecommunications
> equipment or services used as a substantial or essential component of
> any system, or as critical technology as part of any system, during
> contract performance, or the Contractor is notified of such by a
> subcontractor at any tier or by any other source, the Contractor shall
> report the information in paragraph (d)(2) of this clause to the
> Contracting Officer, unless elsewhere in this contract are established
> procedures for reporting the information; in the case of the Department
> of Defense, the Contractor shall report to the website at
> https://dibnet.dod.mil. For indefinite delivery contracts, the
> Contractor shall report to the Contracting Officer for the indefinite
> delivery contract and the Contracting Officer(s) for any affected
> order or, in the case of the Department of Defense, identify both the
> indefinite delivery contract and any affected orders in the report
> provided at https://dibnet.dod.mil."

The clause does **two** things that materially shape W.W3:

1. The trigger is "the Contractor identifies ... OR ... is notified ...".
   Identification is the moment the W.W2 screen-run surfaces a positive
   ID; notification is the moment the operator pastes an inbound
   third-party report into the tracker UI's "Inbound notification"
   panel. Both create the same envelope shape (`discovered_at` carries
   the trigger timestamp; `discovery_kind ∈ {'screen-run',
   'subcontractor-notification', 'other-source'}`).
2. The endpoint is **per-contract**: for civilian agencies, the
   Contracting Officer (one email per contract); for DoD, the central
   DIBNet portal. W.W3 emits one `.docx` per affected contract so the
   operator can attach to the right email, plus one roll-up `.docx` for
   the CSP CISO internal sign-off.

Paragraph (d)(2)(i) — the **initial report content** (the nine data
elements due within 1 business day):

> "(2) The Contractor shall report the following information pursuant
> to paragraph (d)(1) of this clause—
> (i) Within one business day from the date of such identification or
> notification: The contract number; the order number(s), if applicable;
> supplier name; supplier unique entity identifier (if known); supplier
> Commercial and Government Entity (CAGE) code (if known); brand; model
> number (original equipment manufacturer number, manufacturer part
> number, or wholesaler number); item description; and any readily
> available information about mitigation actions undertaken or
> recommended."

These nine elements are pre-populated on the W.W2 match record's
`far_52_204_25_d_data_elements` field (see W.W2.md §5.1). W.W3 reads
that field, defaults missing items to the literal string
`REQUIRES-OPERATOR-INPUT`, and refuses to emit the report (or, for less
critical fields like `supplier_uei`, emits with the placeholder marked
in red on the `.docx` and tagged for operator completion) per the
field-by-field rules in §11.

Paragraph (d)(2)(ii) — the **follow-up report content** (additional
mitigation information due within 10 business days):

> "(ii) Within 10 business days of submitting the information in
> paragraph (d)(2)(i) of this clause: Any further available information
> about mitigation actions undertaken or recommended. In addition, the
> Contractor shall describe the efforts it undertook to prevent use or
> submission of covered telecommunications equipment or services, and
> any additional efforts that will be incorporated to prevent future use
> or submission of covered telecommunications equipment or services."

Paragraph (d)(1) also embeds the **subcontractor cascade** via
paragraph (e):

> "(e) The Contractor shall insert the substance of this clause,
> including this paragraph (e), in all subcontracts and other
> contractual instruments, including subcontracts for the acquisition
> of commercial products or commercial services."

When the CSP is itself a subcontractor (the FedPy operator's customer
relationship is sub-to-prime), the W.W3 report flows up to the prime's
Contracting Officer rather than directly to the Federal CO. The
operator configures the upward routing in `section889-contacts.yaml`
(see §11).

### 2.2 FAR 52.204-25(a) — Definitions (the "covered" predicate)

URL: https://www.acquisition.gov/far/52.204-25 (accessed 2026-06-07).

> "Covered telecommunications equipment or services means—
> (1) Telecommunications equipment produced by Huawei Technologies
> Company or ZTE Corporation (or any subsidiary or affiliate of such
> entities);
> (2) For the purpose of public safety, security of Government
> facilities, physical security surveillance of critical infrastructure,
> and other national security purposes, video surveillance and
> telecommunications equipment produced by Hytera Communications
> Corporation, Hangzhou Hikvision Digital Technology Company, or Dahua
> Technology Company (or any subsidiary or affiliate of such entities);
> (3) Telecommunications or video surveillance services provided by such
> entities or using such equipment; or
> (4) Telecommunications or video surveillance equipment or services
> produced or provided by an entity that the Secretary of Defense, in
> consultation with the Director of the National Intelligence or the
> Director of the Federal Bureau of Investigation, reasonably believes
> to be an entity owned or controlled by, or otherwise connected to,
> the government of a covered foreign country."

> "Substantial or essential component means any component necessary for
> the proper function or performance of a piece of equipment, system,
> or service."

> "Critical technology means—
> (1) Defense articles or defense services included on the United
> States Munitions List ...;
> (2) Items included on the Commerce Control List ...;
> (3) Specially designed and prepared nuclear equipment, parts and
> components, materials, software, and technology ...;
> (4) Nuclear facilities, equipment, and material ...;
> (5) Select agents and toxins ...; or
> (6) Emerging and foundational technologies controlled pursuant to
> section 1758 of the Export Control Reform Act of 2018 (50 U.S.C.
> 4817)."

W.W3 ingests these definitions transitively via the W.W2 match record's
`catalog_provenance.source` discriminator. The reporter does not
re-evaluate the predicate; W.W2 has already made the "is this a
covered entity" determination using the W.W1 catalog. W.W3 trusts the
upstream verdict and focuses on report composition + clock arithmetic.

### 2.3 FAR 4.2105 — Solicitation provision and contract clauses

URL: https://www.acquisition.gov/far/4.2105 (accessed 2026-06-07).

> "(a) Insert the provision 52.204-24, Representation Regarding Certain
> Telecommunications and Video Surveillance Services or Equipment, in
> all solicitations issued on or after August 13, 2020, and resultant
> contracts.
> (b) Insert the clause at 52.204-25, Prohibition on Contracting for
> Certain Telecommunications and Video Surveillance Services or
> Equipment, in all solicitations issued on or after August 13, 2020,
> and resultant contracts, including solicitations and contracts for
> the acquisition of commercial products and commercial services.
> (c) Insert the provision 52.204-26, Covered Telecommunications
> Equipment or Services — Representation, in all solicitations, except
> for solicitations under personal services contracts with individuals."

FAR 4.2105(b) is what makes 52.204-25 (and therefore (d)'s 1-business-
day reporting clock) **universal** for the FedPy operator population.
W.W3 has no exit gate based on agency identity.

### 2.4 NDAA FY2019 §889(f)(2), (f)(3) — Statutory authority

URL: https://www.congress.gov/115/plaws/publ232/PLAW-115publ232.pdf
(accessed 2026-06-07; operator mirrors to
`docs/sources/PLAW-115publ232.pdf`).

§889(f)(2) — covered telecommunications equipment or services:

> "(2) COVERED TELECOMMUNICATIONS EQUIPMENT OR SERVICES.—The term
> 'covered telecommunications equipment or services' means any of the
> following:
> (A) Telecommunications equipment produced by Huawei Technologies
> Company or ZTE Corporation (or any subsidiary or affiliate of such
> entities).
> (B) For the purpose of public safety, security of Government
> facilities, physical security surveillance of critical infrastructure,
> and other national security purposes, video surveillance and
> telecommunications equipment produced by Hytera Communications
> Corporation, Hangzhou Hikvision Digital Technology Company, or Dahua
> Technology Company (or any subsidiary or affiliate of such entities).
> (C) Telecommunications or video surveillance services provided by
> such entities or using such equipment.
> (D) Telecommunications or video surveillance equipment or services
> produced or provided by an entity that the Secretary of Defense, in
> consultation with the Director of National Intelligence or the
> Director of the Federal Bureau of Investigation, reasonably believes
> to be an entity owned or controlled by, or otherwise connected to,
> the government of a covered foreign country."

§889(f)(3) — covered foreign country:

> "(3) COVERED FOREIGN COUNTRY.—The term 'covered foreign country' means
> the People's Republic of China."

The W.W3 JSON envelope's `statutory_basis[]` field carries the array of
authorities cited for each finding. For a Huawei hit, the array is
`['far-52.204-25-a-1', 'ndaa-2019-sec-889-f-2-A']`. For Hytera/Hikvision/
Dahua hits, `['far-52.204-25-a-2', 'ndaa-2019-sec-889-f-2-B']`. The
`.docx` body cites both authorities verbatim — under §11's
field-validation rules the operator confirms before transmission.

### 2.5 NDAA FY2018 §1634 — Kaspersky prohibition

URL: https://www.congress.gov/bill/115th-congress/house-bill/2810/text
(operator mirrors to `docs/sources/PLAW-115publ91.pdf`; the §1634 text
appears in Pub. L. 115-91, Div A, Title XVI).

> "Sec. 1634. Prohibition on use of products and services developed or
> provided by Kaspersky Lab.
> (a) Prohibition. — No department, agency, organization, or other
> element of the Federal Government shall use, whether directly or
> through work with or on behalf of another department, agency,
> organization, or element of the Federal Government, any hardware,
> software, or services developed or provided, in whole or in part, by—
> (1) Kaspersky Lab (or any successor entity);
> (2) any entity that controls, is controlled by, or is under common
> control with Kaspersky Lab; or
> (3) any entity of which Kaspersky Lab has a majority ownership.
> (b) Effective Date. — The prohibition under subsection (a) shall take
> effect on October 1, 2018."

§1634 is **not** the FAR 52.204-25(d) reporting regime — it predates it
— but DHS BOD 17-01 (cited next) directs Federal information systems
to remove Kaspersky products, and the FedPy operator's downstream
obligation to a Federal customer is operationally identical to a §889
finding. **W.W3 reports a Kaspersky hit under the FAR 52.204-25(d)
framework** (because that is the live regulatory regime post-2020 and
the operator's Contracting Officer expects to see the report in that
shape), but tags the envelope `statutory_basis[]` to include
`'ndaa-2018-sec-1634'` and `'dhs-bod-17-01'` for traceability.

### 2.6 DHS BOD 17-01 — Kaspersky removal directive

URL: https://www.cisa.gov/binding-operational-directive-17-01 (accessed
2026-06-07; the operator mirrors HTML to `docs/sources/bod-17-01.html`).

> "Removal of Kaspersky-branded Products. After careful consideration
> of available information and consultation with interagency partners,
> the Acting Secretary of Homeland Security has determined that the
> information security risks presented by the use of Kaspersky products
> on federal information systems are significant and compelling. This
> Binding Operational Directive (BOD) directs Federal Executive Branch
> departments and agencies to identify any use or presence of Kaspersky
> products on their information systems, to develop and furnish to DHS
> a detailed plan of action to remove and discontinue present and
> future use of all Kaspersky-branded products, and to begin to
> implement the plan."

Issued 2017-09-13. Identification within 30 days; plan within 60 days;
removal within 90 days. The 30-day identification window has long
expired for any continuing presence; W.W3's 1-business-day clock applies
to any **new** discovery of Kaspersky in the CSP environment that
surfaces today.

### 2.7 DoD/GSA/NASA Joint FAR Council — implementation guidance

URL: https://www.acquisition.gov/Section-889-Policies (accessed
2026-06-07; operator mirrors).

The Joint FAR Council issued two final rules implementing §889 into the
FAR:

1. **FAR Final Rule (Part A) — Federal Register Vol. 84, No. 156,
   2019-08-13.** URL:
   https://www.federalregister.gov/documents/2019/08/13/2019-17201/federal-acquisition-regulation-prohibition-on-contracting-for-certain-telecommunications-and-video
   (accessed 2026-06-07). The rule effective date is 2019-08-13 for §889
   Part A (procurement). The FR preamble at §III.B clarifies the
   reporting timing:

> "Within one business day from the date of such identification or
> notification, the contractor shall provide the contracting officer
> with the information specified in the clause; and within 10 business
> days of submitting the initial report, the contractor shall provide
> any further available information about mitigation actions."

2. **FAR Final Rule (Part B) — Federal Register Vol. 85, No. 135,
   2020-07-14.** URL:
   https://www.federalregister.gov/documents/2020/07/14/2020-15293/federal-acquisition-regulation-prohibition-on-contracting-with-entities-using-certain
   (accessed 2026-06-07). The rule effective date is 2020-08-13 for §889
   Part B (use). The FR preamble at §IV.A clarifies that the "1 business
   day" is **a federal-government business day, computed in the
   contractor's local business hours but excluding federal holidays
   under 5 U.S.C. §6103.** The implementer treats this as instructive
   guidance — the operative regulatory text is FAR 52.204-25(d) itself,
   which simply says "one business day"; the FR preamble fleshes out the
   Joint FAR Council's intent.

### 2.8 OPM Federal Holidays page

URL: https://www.opm.gov/policy-data-oversight/pay-leave/federal-holidays/
(accessed 2026-06-07). The OPM page enumerates the current federal
holiday calendar:

> "Federal law (5 U.S.C. §6103) establishes the following public
> holidays for Federal employees. Please note that most Federal
> employees work on a Monday through Friday schedule. For those
> employees, when a holiday falls on a nonworkday — Saturday or Sunday
> — the holiday usually is observed on Monday (if the holiday falls on
> Sunday) or Friday (if the holiday falls on Saturday)."

The current 11 federal holidays (per OPM 2026 calendar):

> "1. New Year's Day — Thursday, January 1
> 2. Birthday of Martin Luther King, Jr. — Monday, January 19
> 3. Washington's Birthday — Monday, February 16
> 4. Memorial Day — Monday, May 25
> 5. Juneteenth National Independence Day — Friday, June 19
> 6. Independence Day — Friday, July 3 (observed for July 4 Saturday)
> 7. Labor Day — Monday, September 7
> 8. Columbus Day — Monday, October 12
> 9. Veterans Day — Wednesday, November 11
> 10. Thanksgiving Day — Thursday, November 26
> 11. Christmas Day — Friday, December 25"

(Note: the calendar for 2026 listed above reflects an illustrative
mapping — the operator MUST run `scripts/fetch-opm-holidays.mjs` to
pull the live OPM page each January and produce the
`cloud-evidence/data/federal-holidays-YYYY.json` file. The W.W3 clock
module loads the JSON file at runtime; no holiday is hard-coded in
the production module.)

The "in-lieu-of" rule (5 U.S.C. §6103(c)) — when a holiday falls on a
Sunday, the next Monday is observed; when on a Saturday, the preceding
Friday — is implemented in `core/section889-clock.ts` and tested in
T16 / T17 of §8.

### 2.9 DHS Section 889 Reporting Memo / endpoint format

The DHS Office of the Chief Procurement Officer was reported (in
secondary acquisition literature circa 2024) to be coordinating a
DHS-wide §889 reporting intake — distinct from the DoD DIBNet portal.
**The implementer MUST verify the existence and exact format of this
endpoint before W.W3 ships.** Status: **REQUIRES-RESEARCH**.

Until verified, W.W3's default civilian-agency path is the FAR-clause
default: email the report to the Contracting Officer of each affected
contract. The operator-supplied `section889-contacts.yaml` (see §11)
maps `contract_number → contracting_officer_email`. When the CO
address is unknown, W.W3 surfaces a `REQUIRES-OPERATOR-INPUT`
diagnostic before emit.

For DoD primes, the endpoint is unambiguous:

> "in the case of the Department of Defense, the Contractor shall
> report to the website at https://dibnet.dod.mil."

W.W3 emits the §889 report shape (not the DFARS 7012 Incident
Collection Format that LOOP-S.S2 emits). The two flows share the
DIBNet portal but use distinct schemas; LOOP-W and LOOP-S reporters
each tag their envelopes with `report_type` so the DIBNet portal can
route correctly.

### 2.10 5 U.S.C. §6103 — Federal holidays (statutory)

URL: https://www.govinfo.gov/content/pkg/USCODE-2022-title5/html/USCODE-2022-title5-partIII-subpartE-chap61-sec6103.htm
(accessed 2026-06-07).

> "(a) The following are legal public holidays:
> New Year's Day, January 1.
> Birthday of Martin Luther King, Jr., the third Monday in January.
> Washington's Birthday, the third Monday in February.
> Memorial Day, the last Monday in May.
> Juneteenth National Independence Day, June 19.
> Independence Day, July 4.
> Labor Day, the first Monday in September.
> Columbus Day, the second Monday in October.
> Veterans Day, November 11.
> Thanksgiving Day, the fourth Thursday in November.
> Christmas Day, December 25."

> "(b) For the purpose of statutes relating to pay and leave of
> employees, with respect to a legal public holiday set forth in
> subsection (a)—
> (1) Instead of a holiday that occurs on a Saturday, the Friday
> immediately before is a legal public holiday; and
> (2) Instead of a holiday that occurs on a Sunday, the Monday
> immediately after is a legal public holiday."

This is the canonical statutory source for the federal-holiday
calendar. The OPM page is the operational interpretation; the statute
binds.

### 2.11 Federal Acquisition Institute — "Business Day" guidance

URL: https://www.fai.gov (accessed 2026-06-07; operator searches for
the live "business day" definition page). For FAR purposes, a
"business day" is conventionally interpreted as a federal-government
business day in the National Capital Region (Washington, DC) time
zone — i.e. **America/New_York**, Monday–Friday 09:00–17:00 ET,
excluding the 11 federal holidays under 5 U.S.C. §6103 and any
agency-closure days proclaimed by the President under §6103(c).

The implementer **REQUIRES-RESEARCH-CONFIRM** with the operator's
General Counsel that the FedPy convention is America/New_York rather
than the operator's local timezone. Until confirmed, the default
configuration is `federal_business_hours_tz: America/New_York`; the
operator may override to `operator_local` via the §11 configuration.

## 3. Scope

### 3.1 In scope

- Ingestion of `out/prohibited-vendors-screen-result.json` envelopes
  produced by W.W2.
- For each non-suppressed match with
  `confidence_band = 'high'` and a Section 889 / Kaspersky /
  operator-addition `catalog_provenance.source`, composition of:
  - one canonical JSON report envelope per affected contract;
  - one OOXML/zip-store `.docx` per affected contract for operator
    transmission;
  - one roll-up `.docx` for internal CISO sign-off and tracker DB.
- Federal-business-day clock arithmetic via
  `core/section889-clock.ts`, including:
  - 8 federal business hours per business day (09:00–17:00 ET);
  - exclusion of Saturdays, Sundays, and all 11 federal holidays
    under 5 U.S.C. §6103;
  - OPM in-lieu-of rule for Saturday/Sunday-falling holidays;
  - DST transitions (March/November) computed via IANA tzdata;
  - agency-closure-day operator override
    (`section889-agency-closures.yaml`).
- Both Section 889 Part A (procurement) and Part B (use)
  identifications.
- Both prime-contract and subcontract reporting — when the CSP is a
  subcontractor, the operator maps the upward CO routing in
  `section889-contacts.yaml`.
- Ed25519 signing of the JSON envelope via the existing
  `core/sign.ts` pipeline (LOOP-A.A5).
- RFC 3161 timestamp token attachment via the existing
  `core/timestamp.ts`.
- Tracker DB `section889_reports` row insertion.
- Operator notification at emission time AND at T-1-hour-to-deadline
  via the existing `core/notify.ts` (Slack + PagerDuty).
- POA&M item linkage (one POA&M item per match, owner: W.W2; W.W3
  back-references the POA&M item UUID on its envelope).
- Submission-bundle catalogue update via LOOP-A.A4 — the signed
  JSON + `.docx` per affected contract are added to the bundle.
- 10-business-day follow-up report emission (FAR 52.204-25(d)(2)(ii))
  after the operator confirms transmission of the initial 1BD report.

### 3.2 Out of scope (NOT in W.W3)

- **Actual transmission to the Federal endpoint.** REO Rule 4
  forbids the system from acting on behalf of the operator on a
  regulatory submission. W.W3 emits the artifact; the operator
  transmits.
- **The annual FAR 52.204-26 representation.** Owned by W.W4.
- **NDAA §1634 Kaspersky-specific reporting under a separate
  statutory regime.** If a parallel §1634 reporting regime is ever
  identified (none currently published), it would belong in a
  separate slice. W.W3 reports Kaspersky hits under the FAR
  52.204-25(d) framework — the live operative regulation — with the
  `statutory_basis[]` array citing both authorities for traceability.
- **The W.W2 screen itself.** Owned by W.W2.
- **The catalog ingestion.** Owned by W.W1.
- **Waiver tracking under FAR 4.2104.** A separate "LOOP-W-Waivers"
  could implement this; for now W.W3 surfaces a "waiver_id" field on
  the report envelope that the operator may fill if an active ODNI
  waiver exists.
- **DFARS 252.204-7012 cyber-incident reporting.** Owned by LOOP-S.
  The two reporters share the DIBNet portal but use distinct
  schemas; they do not share code beyond the federal-business-day
  clock primitive.
- **SBOM / OCI walking.** Owned by W.W2. W.W3 trusts the upstream
  match record's `surface` discriminator and the catalog
  provenance.

## 4. Inputs

### 4.1 W.W2 screen-result envelope (the trigger)

Path: `out/prohibited-vendors-screen-result.json`. Schema defined in
W.W2.md §5.1. W.W3 reads the following fields per envelope:

```ts
interface W3InputContract {
  schema_version: '1.0.0';
  run_id: string;
  started_at: string;
  completed_at: string;
  catalog_snapshot_ref: {
    path: string;
    sha256: string;
    generated_at: string;
    age_hours: number;
    is_stale: boolean;
  };
  matches: ProhibitedVendorMatch[];        // see W.W2.md §5.1
  reportable_under_far_52_204_25_d: boolean;
  reportable_under_ndaa_1634: boolean;
  provenance: { /* W.W2 emitter block */ };
  signature: { /* Ed25519 detached */ };
  rfc3161_timestamp: { /* RFC 3161 token */ };
}
```

W.W3 **MUST** verify the W.W2 envelope's Ed25519 signature against the
W.W2 signing key before consuming it. A signature-verification failure
exits the W.W3 process with `EnvelopeSignatureInvalidError` and the
process leaves no tracker DB rows behind.

### 4.2 W.W1 catalog snapshot reference + commit hash

W.W3 does not re-load the catalog — it propagates the
`catalog_snapshot_ref` field from the W.W2 envelope into the report
envelope's `provenance.catalog_snapshot` block so a 3PAO can reconstruct
the exact catalog version that surfaced the hit.

### 4.3 Operator configuration

Path: `cloud-evidence/config.yaml` plus three additional files
discovered relative to it:

```yaml
section_889:
  reporting:
    # Default endpoint type — dictates clock semantics + .docx template.
    default_endpoint_type: civilian-co-email  # | dod-dibnet
    federal_business_hours_tz: America/New_York
    business_hours: { start: "09:00", end: "17:00" }
    # 10-business-day follow-up window enabled by default per (d)(2)(ii)
    follow_up_10bd_enabled: true
    # Annual-rep amendment policy when a 1BD report is confirmed transmitted
    annual_rep_amendment_policy: manual  # | auto-mark | none
    # Notification channels for emit + T-1-hour
    notification_channels:
      - slack:#fedramp-section889
      - pagerduty:section889-1bd-deadline
  signing:
    corporate_signing_officer_name: REQUIRES-OPERATOR-INPUT
    corporate_signing_officer_title: REQUIRES-OPERATOR-INPUT
    ed25519_signing_key_ref: REQUIRES-OPERATOR-INPUT
  contacts_file: section889-contacts.yaml
  closures_file: section889-agency-closures.yaml
```

#### 4.3.1 `section889-contacts.yaml`

```yaml
schema_version: '1.0.0'
contracts:
  - contract_number: 47QFCA22F0001
    agency: GSA
    contracting_officer_email: co@gsa.gov
    prime_contractor_uei: ABCDEF1234567       # null if CSP is the prime
    cage_code: 1A2B3
  - contract_number: HQ0034-22-F-0005
    agency: DoD
    endpoint_type: dod-dibnet
    contracting_officer_email: co@dla.mil      # used for cc only; DIBNet is primary
```

#### 4.3.2 `section889-agency-closures.yaml`

```yaml
schema_version: '1.0.0'
# Operator-supplied agency-closure days proclaimed by the President under
# 5 U.S.C. §6103(c) that are NOT in OPM's 11-holiday list (e.g. a one-off
# Inauguration-Day-equivalent closure). The implementer commits the
# baseline OPM list separately in cloud-evidence/data/federal-holidays-YYYY.json.
closures_2026:
  - date: 2026-01-20
    reason: Inauguration Day (DC government employees)
    applies_to_federal_business_hours: true
```

### 4.4 Federal holiday calendar

Path: `cloud-evidence/data/federal-holidays-YYYY.json` (one per
calendar year). Schema:

```json
{
  "schema_version": "1.0.0",
  "year": 2026,
  "source": "OPM Federal Holidays page",
  "source_url": "https://www.opm.gov/policy-data-oversight/pay-leave/federal-holidays/",
  "extracted_at": "2026-01-02T15:00:00Z",
  "holidays": [
    { "date": "2026-01-01", "name": "New Year's Day", "observed_for": "2026-01-01" },
    { "date": "2026-01-19", "name": "Birthday of Martin Luther King, Jr.", "observed_for": "2026-01-19" },
    { "date": "2026-02-16", "name": "Washington's Birthday", "observed_for": "2026-02-16" },
    { "date": "2026-05-25", "name": "Memorial Day", "observed_for": "2026-05-25" },
    { "date": "2026-06-19", "name": "Juneteenth National Independence Day", "observed_for": "2026-06-19" },
    { "date": "2026-07-03", "name": "Independence Day (observed)", "observed_for": "2026-07-04" },
    { "date": "2026-09-07", "name": "Labor Day", "observed_for": "2026-09-07" },
    { "date": "2026-10-12", "name": "Columbus Day", "observed_for": "2026-10-12" },
    { "date": "2026-11-11", "name": "Veterans Day", "observed_for": "2026-11-11" },
    { "date": "2026-11-26", "name": "Thanksgiving Day", "observed_for": "2026-11-26" },
    { "date": "2026-12-25", "name": "Christmas Day", "observed_for": "2026-12-25" }
  ],
  "signature": { /* Ed25519 detached, populated by core/sign.ts */ }
}
```

The implementer runs `scripts/fetch-opm-holidays.mjs` in the first
working week of January each year to refresh the file; the file is
signed; the W.W3 clock module verifies the signature on load.

### 4.5 Discovery-time timestamp

The trigger timestamp — the moment the 1-business-day clock starts —
is sourced from the W.W2 match record's `discovered_at` field. Per
FAR 52.204-25(d)(1), discovery is when the Contractor "identifies"
the covered equipment or is "notified" by a subcontractor.

For a screen-run-driven discovery (`discovery_kind = 'screen-run'`),
`discovered_at = match.discovered_at` which equals the W.W2 run's
`completed_at`. For an inbound-notification discovery
(`discovery_kind = 'subcontractor-notification' | 'other-source'`),
the operator pastes the inbound timestamp into the tracker UI's
"Inbound Notification" panel; the tracker round-trips the timestamp
into a synthetic W.W2 match record and stamps `discovered_at = <pasted>`.

## 5. Outputs

### 5.1 Canonical JSON report envelope

Path (per affected contract):
`out/section889-1bd-reports/<contract_number>-<report_id>.json`.

```ts
interface Section8891bdReport {
  schema_version: '1.0.0';
  report_id: string;                                  // ULID
  report_kind: 'initial-1bd' | 'follow-up-10bd';
  generated_at: string;                                // ISO 8601 UTC
  emitted_at: string;                                  // ISO 8601 UTC
  csp_name: string;
  csp_uei: string;
  csp_cage_code: string;

  // Linkage upstream
  source_screen_envelope_ref: {
    path: string;
    sha256: string;
    run_id: string;
  };
  source_match_id: string;                             // FK to W.W2 match
  catalog_snapshot_ref: {
    path: string;
    sha256: string;
    generated_at: string;
  };
  poam_item_uuid: string;                              // back-ref to W.W2 POA&M emit

  // The 9 FAR 52.204-25(d)(2)(i) elements
  far_d_2_i: {
    contract_number: string;
    order_numbers: string[];
    supplier_name: string;
    supplier_uei: string | 'REQUIRES-OPERATOR-INPUT';
    supplier_cage_code: string | 'REQUIRES-OPERATOR-INPUT';
    brand: string;
    model_number: string;
    item_description: string;
    mitigation_actions: string;                        // 'REQUIRES-OPERATOR-INPUT' for initial if not yet captured
  };

  // The (d)(2)(ii) follow-up content (populated on report_kind='follow-up-10bd')
  far_d_2_ii?: {
    additional_mitigation_actions: string;
    prevention_efforts_undertaken: string;
    future_prevention_efforts: string;
  };

  // Discovery + clock
  discovered_at: string;                                // ISO 8601 UTC
  discovery_kind: 'screen-run' | 'subcontractor-notification' | 'other-source';
  federal_business_hours_tz: 'America/New_York' | string;
  deadline_at: string;                                  // ISO 8601 UTC, computed
  business_hours_remaining_at_emit: number;
  business_hours_remaining_at_deadline_warning: number;

  // Routing
  endpoint_type: 'civilian-co-email' | 'dod-dibnet';
  contracting_officer_email?: string;                   // civilian only
  dibnet_url?: 'https://dibnet.dod.mil/';               // DoD only
  is_subcontract_report: boolean;
  prime_contractor_uei?: string;                        // when CSP is a sub

  // Statutory citation
  statutory_basis: Array<
    | 'far-52.204-25-a-1'         // Huawei/ZTE
    | 'far-52.204-25-a-2'         // Hytera/Hikvision/Dahua
    | 'far-52.204-25-a-3'         // services using
    | 'far-52.204-25-a-4'         // SecDef-designated
    | 'ndaa-2019-sec-889-f-2-A'
    | 'ndaa-2019-sec-889-f-2-B'
    | 'ndaa-2019-sec-889-f-2-C'
    | 'ndaa-2019-sec-889-f-2-D'
    | 'ndaa-2018-sec-1634'        // Kaspersky
    | 'dhs-bod-17-01'             // Kaspersky operational
    | 'operator-addition'
  >;
  waiver_id?: string;                                   // operator-supplied if waivered

  // Officer attestation
  signing_officer: {
    name: string;
    title: string;
    key_id: string;                                     // KMS resource ARN / GCP resource
    key_version: string;                                // pinned at emit
  };

  // Provenance + signature
  provenance: {
    emitter: 'section889-1bd-reporter';
    emitter_version: string;
    emitted_at: string;
    source_calls: Array<{
      kind: 'w2-screen-envelope' | 'contacts-yaml' | 'closures-yaml' |
            'holidays-json' | 'config-yaml' | 'org-profile-yaml';
      path: string;
      sha256: string;
    }>;
  };
  signature: {                                          // populated by core/sign.ts
    alg: 'ed25519';
    key_id: string;
    sig: string;                                        // base64
  };
  rfc3161_timestamp: {                                  // populated by core/timestamp.ts
    tsa_url: string;
    token: string;                                      // base64
    received_at: string;
  };

  // Operator transmission audit
  transmission?: {
    transmitted_at: string;
    transmitted_by: string;
    transmission_method: 'email' | 'dibnet-upload' | 'other';
    federal_acknowledgement_receipt_id?: string;        // pasted by operator
  };

  // Closure
  closed_at?: string;
  closed_by?: string;
  closure_justification?: string;
}
```

### 5.2 OOXML/zip-store `.docx` report

Path: `out/section889-1bd-reports/<contract_number>-<report_id>.docx`.

Layout:

- **Cover page.** "FAR 52.204-25(d) Initial 1-Business-Day Report" or
  "FAR 52.204-25(d)(2)(ii) 10-Business-Day Follow-up Report". CSP
  name + UEI + CAGE. Contract number. Discovery date + deadline date.
  Officer name + title placeholder.
- **Summary table.** Rows: supplier_name, brand, model_number,
  item_description, surface where detected, confidence.
- **Per-finding section.** One section per affected catalog entry:
  - Verbatim quote of the relevant FAR 52.204-25(a) paragraph;
  - Verbatim quote of the operative NDAA §889 paragraph;
  - For Kaspersky, the §1634 + BOD 17-01 paragraphs;
  - The W.W2 match path.
- **Remediation status block.** Mitigation actions undertaken /
  recommended; due date for follow-up report; CSP CISO contact.
- **Attestation block.** "I attest under penalty of 18 U.S.C. §1001
  that the information in this report is, to the best of my
  knowledge, accurate and complete as of the date below."; signature
  line; printed name; title; date.
- **Signature placeholder.** A signed-XML block (or a placeholder
  `<w:bookmarkStart/>` region) where the operator inserts a wet
  signature image or the Ed25519 signature receipt id.

The renderer is `core/section889-report-docx.ts` and reuses the OOXML
helpers from `core/inventory-workbook.ts` (zip-store, document.xml,
styles.xml, numbering.xml).

### 5.3 POA&M item linkage

W.W2 emits the POA&M item (one per match). W.W3 does **not** create
new POA&M items; it back-references the item via `poam_item_uuid` on
the report envelope and, when the operator confirms transmission via
the tracker UI, updates the POA&M item's `remediation-tracking` block
to record the transmission timestamp and the federal acknowledgement
receipt id. The POA&M update goes through the existing
`core/oscal-poam.ts::updatePoamItem(...)` API.

### 5.4 Tracker DB row

Schema (migration `0042_section889_reports.sql`):

```sql
CREATE TABLE section889_reports (
  id                            UUID PRIMARY KEY,
  run_id                        TEXT NOT NULL,                   -- W.W2 run that surfaced the hit
  report_id                     TEXT NOT NULL UNIQUE,
  screen_envelope_ref           TEXT NOT NULL,                   -- path to W.W2 envelope
  match_id                      TEXT NOT NULL,                   -- FK to W.W2 match
  catalog_uid                   TEXT NOT NULL,
  vendor_name                   TEXT NOT NULL,
  finding_kind                  TEXT NOT NULL,                   -- subprocessor|sbom|oci|inventory
  contract_number               TEXT NOT NULL,
  agency                        TEXT,
  endpoint_type                 TEXT NOT NULL,                   -- civilian-co-email|dod-dibnet
  is_subcontract_report         BOOLEAN NOT NULL DEFAULT FALSE,
  discovery_kind                TEXT NOT NULL,
  discovered_at                 TIMESTAMPTZ NOT NULL,
  deadline_at                   TIMESTAMPTZ NOT NULL,
  report_kind                   TEXT NOT NULL,                   -- initial-1bd|follow-up-10bd
  follow_up_due_at              TIMESTAMPTZ,
  emitted_at                    TIMESTAMPTZ NOT NULL,
  report_path_json              TEXT NOT NULL,
  report_path_docx              TEXT NOT NULL,
  poam_item_uuid                TEXT,
  status                        TEXT NOT NULL DEFAULT 'emitted', -- emitted|transmitted|acknowledged|follow-up-due|follow-up-emitted|closed
  transmitted_at                TIMESTAMPTZ,
  transmitted_by                TEXT,
  transmission_method           TEXT,
  federal_acknowledgement_receipt_id TEXT,
  closed_at                     TIMESTAMPTZ,
  closed_by                     TEXT,
  closure_justification         TEXT,
  signing_key_id                TEXT NOT NULL,
  signing_key_version           TEXT NOT NULL,
  signing_officer_name          TEXT NOT NULL,
  signing_officer_title         TEXT NOT NULL,
  encrypted_at_rest             BOOLEAN NOT NULL DEFAULT TRUE,
  created_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_section889_reports_run_id ON section889_reports(run_id);
CREATE INDEX idx_section889_reports_deadline_at ON section889_reports(deadline_at);
CREATE INDEX idx_section889_reports_status ON section889_reports(status);
CREATE UNIQUE INDEX idx_section889_reports_idempotency
  ON section889_reports(run_id, match_id, contract_number, report_kind);
```

### 5.5 Operator notifications

Channel routing (driven by `config.yaml::section_889.reporting.notification_channels`):

- **Emit-time notification.** Slack `#fedramp-section889`. Title:
  "FAR 52.204-25(d) 1BD report emitted for <vendor> on contract
  <contract_number>". Body: deadline (with countdown), link to
  tracker UI row, link to signed JSON + `.docx`.
- **T-1-hour-to-deadline notification.** PagerDuty service
  `section889-1bd-deadline`. Priority: P2 (urgent). Routes to the
  on-call CISO + Compliance Director. The PagerDuty payload includes
  the tracker UI URL and the operator-action instructions.
- **Follow-up due notification.** Slack at T-2-business-days before
  the 10-business-day follow-up deadline; PagerDuty at T-1-hour.
- **Transmission-confirmed acknowledgement.** Slack + tracker UI
  green badge.

All notifications flow through `core/notify.ts` (existing). The W.W3
extension is a new template module
`core/section889-report-notification.ts` that holds the message bodies
and reads the deadline / countdown from the tracker DB row.

### 5.6 Submission-bundle entry

The signed JSON + `.docx` per affected contract are added to the
submission bundle via `core/submission-bundle.ts`'s `WELL_KNOWN`
registry. New roles:

```ts
{ role: 'section889-1bd-report-json',
  filename: 'section889-1bd-reports/*.json',
  description: 'FAR 52.204-25(d) initial 1-business-day prohibited-vendor discovery report (LOOP-W.W3)' },
{ role: 'section889-1bd-report-docx',
  filename: 'section889-1bd-reports/*.docx',
  description: 'OOXML rendering of the FAR 52.204-25(d) initial 1BD report (LOOP-W.W3)' },
{ role: 'section889-10bd-followup-json',
  filename: 'section889-10bd-followups/*.json',
  description: 'FAR 52.204-25(d)(2)(ii) 10-business-day follow-up report (LOOP-W.W3)' },
{ role: 'section889-10bd-followup-docx',
  filename: 'section889-10bd-followups/*.docx',
  description: 'OOXML rendering of the FAR 52.204-25(d)(2)(ii) follow-up report (LOOP-W.W3)' },
```

## 6. Algorithm / Steps

### Phase A — Bootstrap

1. **Parse CLI flag** `--prohibited-vendor-1bd-report` (or env
   `CLOUD_EVIDENCE_PROHIBITED_VENDOR_1BD_REPORT`). If neither set,
   the W.W3 module is a no-op for the orchestrator run.
2. **Load operator configuration.** Read `config.yaml` →
   `section_889.*`. Load `section889-contacts.yaml` and
   `section889-agency-closures.yaml`. Validate via Ajv. If any
   `REQUIRES-OPERATOR-INPUT` placeholder remains in the signing
   block, exit `2` with the `Section889OperatorConfigMissingError`.
3. **Load federal holiday calendar.** Read
   `cloud-evidence/data/federal-holidays-YYYY.json` for the current
   year AND the next year (so deadlines computed in December roll
   correctly into January). Verify the Ed25519 signature on each
   file. If a file is missing or its signature fails, exit `2`.
4. **Sign-test the corporate signing key.** Call
   `core/sign.ts::testSign(key_ref)` against the configured KMS
   resource to verify the operator has signing-rights at startup.
   Failure → exit `2`.

### Phase B — Ingest W.W2 envelope

5. **Locate the W.W2 envelope.** Default path
   `out/prohibited-vendors-screen-result.json`. Operator may
   override via `--w2-envelope-path <path>`.
6. **Verify W.W2 envelope signature.** Call
   `core/sign.ts::verifyEnvelope(path, key_ref)` against the W.W2
   signing key. Failure → exit `2` with
   `EnvelopeSignatureInvalidError`. Leave no tracker DB rows behind.
7. **Verify RFC 3161 timestamp token** on the W.W2 envelope. Failure
   → warn (do not exit) — the operator may be in a TSA-offline
   environment; the warning surfaces in the report `provenance` block.
8. **Filter matches.** Build the reportable-matches list:
   `m.suppressed = false`
   AND `m.confidence_band = 'high'`
   AND `m.catalog_provenance.source ∈ {'far-52.204-25-a',
        'ndaa-1634', 'bod-17-01', 'operator-manual-addition'}`.
9. **De-dupe vs already-reported.** For each candidate match, query
   `section889_reports` with idempotency key
   `(run_id, match_id, contract_number, 'initial-1bd')`. If a row
   exists, skip (do not emit duplicate report).

### Phase C — Federal-business-day clock

10. **Compute deadline.** For each candidate match:
    ```
    function fedBusinessHoursElapsed(start: ISO8601, now: ISO8601): number {
      // step through hour boundaries; skip Sat, Sun, federal holidays;
      // load holiday set from cloud-evidence/data/federal-holidays-YYYY.json;
      // business hours = Mon-Fri 09:00-17:00 ET (default); 8 hours/day;
      // honour agency_closures.yaml for one-off proclaimed days;
      // honour DST by computing in America/New_York via IANA tzdata.
      let elapsed = 0;
      let cursor = clampToBusinessHour(start);
      while (cursor < now) {
        const next = nextBusinessBoundary(cursor);
        if (next > now) {
          elapsed += hoursBetween(cursor, now);
          break;
        }
        elapsed += hoursBetween(cursor, next);
        cursor = nextBusinessOpen(next);
      }
      return elapsed;
    }
    function deadlineFor(discoveryTs: ISO8601): ISO8601 {
      // 1 federal business day = 8 federal business hours
      let cursor = clampToBusinessHour(discoveryTs);
      let remaining = 8;
      while (remaining > 0) {
        const next = endOfBusinessDay(cursor);   // 17:00 ET
        const hoursAvailable = hoursBetween(cursor, next);
        if (hoursAvailable >= remaining) {
          return addHours(cursor, remaining);
        }
        remaining -= hoursAvailable;
        cursor = nextBusinessOpen(next);          // skip nights/weekends/holidays
      }
      throw new Error('unreachable');
    }
    ```
11. **Persist deadline** on the match record as `deadline_at`.

### Phase D — Compose report

12. **Resolve contracts to report against.** For each match, the set
    of affected contracts is:
    - When the operator has tagged the match with one or more
      contract numbers via the tracker UI's "contract scope" panel
      → use the operator's explicit list;
    - Otherwise → use all contracts in `section889-contacts.yaml`
      (the FAR-default conservative posture: report to every CO,
      because the clause does not narrow scope and the contractor
      must err on the side of over-reporting).
13. **Compose JSON envelope** per (match × contract) pair, following
    the §5.1 schema. Populate the 9 (d)(2)(i) elements from the
    match record's `far_52_204_25_d_data_elements`. Fields the W.W2
    match could not populate (typically `supplier_uei`,
    `supplier_cage_code`) carry the literal string
    `REQUIRES-OPERATOR-INPUT`; the `.docx` highlights them in red.
14. **Sign envelope** via `core/sign.ts::signEnvelope(env, key_ref)`.
    Pin `signing_officer.key_version` at compose time so mid-deadline
    key rotation does not invalidate the report.
15. **Attach RFC 3161 timestamp token** via
    `core/timestamp.ts::stampEnvelope(env)`. TSA outage → warn (do
    not block); the report can still be transmitted, and the TST is
    added asynchronously when the TSA returns.

### Phase E — Render `.docx`

16. **Render OOXML/zip-store `.docx`** via
    `core/section889-report-docx.ts::renderReport(env, layout)`.
    Layout per §5.2. Signed-XML block placeholder reserved for
    operator wet-signature image or signature receipt id.

### Phase F — Persist + notify

17. **Insert tracker DB row** into `section889_reports`. Idempotency
    via the unique index on
    `(run_id, match_id, contract_number, report_kind)`. Status =
    `emitted`. Encrypt the report content at rest via the existing
    tracker DB pgcrypto + KMS data-key envelope flow.
18. **Update POA&M item.** Call
    `core/oscal-poam.ts::updatePoamItem(poam_item_uuid, {
      remediation_tracking: { events: [{ kind: '1bd-report-emitted',
      report_id, deadline_at }] }
    })`.
19. **Emit emit-time notification** via
    `core/notify.ts::send(channels, template)` with the
    `section889-1bd-emitted` template and the deadline countdown.
20. **Schedule T-1-hour-to-deadline notification.** Insert a row
    into the existing `tracker.scheduled_notifications` table with
    `fire_at = deadline_at - 1h` and template
    `section889-1bd-deadline-soon`. The tracker's notification daemon
    fires it.

### Phase G — Submission bundle

21. **Update submission-bundle catalogue.** Call
    `core/submission-bundle.ts::registerArtifact(role, path)` for
    each emitted JSON + `.docx` against the new roles in §5.6.
    LOOP-A.A4 runs as usual at orchestrator end; the new artifacts
    flow into the bundle automatically.

### Phase H — Coverage + log

22. **Append coverage section.** Extend
    `out/inventory-coverage.json` with a `section889_1bd_coverage`
    block:
    ```json
    {
      "reports_emitted_this_run": 3,
      "reports_already_present": 0,
      "deadline_breached_at_emit": 0,
      "follow_ups_due_within_48h": 1
    }
    ```
23. **Emit run log** with `coverage:section889-1bd:<N>-reports-emitted`
    line.

### Phase I — 10-business-day follow-up scheduling

24. **For each initial report just emitted**, schedule a follow-up
    work item in the tracker:
    - `fire_at = discovered_at + 10 federal business days`
    - On fire, the tracker UI prompts the operator for the
      additional mitigation narrative (FAR 52.204-25(d)(2)(ii)
      content);
    - When the operator submits, W.W3's follow-up emitter composes a
      second JSON + `.docx` pair with `report_kind = 'follow-up-10bd'`
      and links to the initial report via `source_initial_report_id`.

### Phase J — Validation

25. `npm run check:provenance` must pass for the new envelope shape.
26. `npm run lint:no-stubs` must remain green.
27. `npm run check:reo` (G1 + G2 + G3) must all pass.
28. `npm run typecheck` must succeed.
29. All 20 tests in §8 must pass.

## 7. Files to create / modify

### Files to CREATE

1. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/section889-1bd-reporter.ts`
   — main module orchestrating Phases A–I. ~600 lines.
2. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/section889-clock.ts`
   — federal-business-hour computation; loads OPM holiday calendar;
   honours agency closures; America/New_York DST via IANA tzdata.
   ~400 lines.
3. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/section889-report-json.ts`
   — canonical JSON envelope emitter; stable key order; LF newlines;
   no trailing whitespace. ~250 lines.
4. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/section889-report-docx.ts`
   — OOXML/zip-store renderer; cover page, summary table, per-finding
   section, attestation block, signature placeholder. ~450 lines.
5. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/section889-report-notification.ts`
   — Slack + PagerDuty templates; reads deadline / countdown from
   tracker DB row. ~200 lines.
6. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/section889-contacts.ts`
   — Ajv-validated loader for `section889-contacts.yaml`. ~120 lines.
7. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/section889-closures.ts`
   — Ajv-validated loader for `section889-agency-closures.yaml`. ~80
   lines.
8. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/federal-holidays-2026.json`
   — initial seed for 2026; signed.
9. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/federal-holidays-2027.json`
   — pre-seeded for end-of-year deadline rollovers; signed.
10. `/Users/kenith.philip/FedRAMP 20x/scripts/fetch-opm-holidays.mjs`
    — annual OPM page extractor; emits the signed JSON; idempotent;
    re-runnable. ~180 lines.
11. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/db/migrations/0042_section889_reports.sql`
    — `CREATE TABLE` + indices + `scheduled_notifications` row insert
    helper.
12. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/section889-reports.ts`
    — REST API: `GET /api/section889-reports`,
    `GET /api/section889-reports/:id`,
    `POST /api/section889-reports/:id/mark-transmitted`,
    `POST /api/section889-reports/:id/mark-acknowledged`,
    `POST /api/section889-reports/:id/mark-closed`,
    `POST /api/section889-reports/:id/submit-follow-up`. ~320 lines.
13. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/ui/section889-status-pane.tsx`
    — status panel; countdown timer to deadline; signed-bundle
    download link; transmission-confirm form; follow-up narrative
    form. ~500 lines.
14. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/section889-contacts.example.yaml`
    — committed example with documented schema.
15. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/section889-agency-closures.example.yaml`
    — committed example.
16. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/section889-1bd-reporter.test.ts`
    — see §8 (20 tests).
17. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/section889-clock.test.ts`
    — federal-business-day arithmetic test suite.
18. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/section889-report-json.test.ts`
    — JSON envelope schema + signing tests.
19. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/section889-report-docx.test.ts`
    — `.docx` OOXML round-trip tests.
20. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/section889-1bd/`
    — fixtures: W.W2 envelope fixtures (Huawei hit, Kaspersky hit,
    multiple-simultaneous hits); contacts YAML; closures YAML;
    holidays JSON for 2026; expected report JSON outputs.

### Files to EXTEND

21. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`
    — new flag `--prohibited-vendor-1bd-report` + env
    `CLOUD_EVIDENCE_PROHIBITED_VENDOR_1BD_REPORT`; runs AFTER W.W2 in
    the orchestrator order; passes its outputs to LOOP-A.A4 bundler.
22. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
    — `WELL_KNOWN` adds the four new roles in §5.6.
23. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/inventory-coverage.ts`
    — extend with `section889_1bd_coverage` section.
24. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-poam.ts`
    — extend `updatePoamItem(...)` to accept a structured
    `remediation_tracking.events[]` so W.W3 can log
    `1bd-report-emitted`, `1bd-report-transmitted`,
    `1bd-report-acknowledged`, `10bd-follow-up-emitted`.
25. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/notify.ts`
    — extend to read the W.W3 templates from
    `core/section889-report-notification.ts`.

## 8. Test specifications

| id   | scenario | fixture path | expected | acceptance |
|------|----------|--------------|----------|------------|
| T1   | Positive ID surfaced Wed 10:00 ET (no holidays); deadline = Thu 10:00 ET | `tests/fixtures/section889-1bd/w2-envelope-wed-1000.json` | `deadline_at = 2026-06-11T10:00:00-04:00` | clock.test.ts asserts exact ISO8601; reporter inserts row with that deadline |
| T2   | Positive ID surfaced Fri 16:00 ET; deadline rolls to Mon 16:00 ET (1h remaining at COB Mon) | `tests/fixtures/section889-1bd/w2-envelope-fri-1600.json` | `deadline_at = 2026-06-15T16:00:00-04:00` | clock.test.ts asserts; weekend skip verified |
| T3   | Positive ID surfaced Christmas Eve (Dec 24) 14:00 ET; Dec 25 is observed Christmas; deadline rolls past holiday | `tests/fixtures/section889-1bd/w2-envelope-xmas-eve.json` | `deadline_at = 2026-12-28T14:00:00-05:00` | clock skips Fri Dec 25 holiday + Sat Dec 26 + Sun Dec 27 |
| T4   | Positive ID surfaced when next-business-day is also a holiday (e.g. New Year's Eve Dec 31 14:00 + observed New Year's Day on Fri Jan 1 2027) | `tests/fixtures/section889-1bd/w2-envelope-nye.json` | `deadline_at = 2027-01-04T14:00:00-05:00` (Monday) | clock honours back-to-back holiday rollover |
| T5   | Dedupe — same (run_id, match_id, contract_number, 'initial-1bd') only emits once | `tests/fixtures/section889-1bd/w2-envelope-dedupe.json` + pre-seeded DB row | Second invocation logs `coverage:section889-1bd:duplicate-skipped:1` and emits zero new artifacts | DB row count unchanged |
| T6   | Section 889 Part A hit (telecom vendor Huawei in subprocessor sheet) | `tests/fixtures/section889-1bd/w2-envelope-huawei-subprocessor.json` | Envelope `statutory_basis = ['far-52.204-25-a-1','ndaa-2019-sec-889-f-2-A']`; `.docx` quotes (a)(1) verbatim | report-json.test.ts schema match |
| T7   | Section 889 Part B hit (use of covered equipment from OCI publisher = Hytera) | `tests/fixtures/section889-1bd/w2-envelope-hytera-oci.json` | Envelope `statutory_basis = ['far-52.204-25-a-2','ndaa-2019-sec-889-f-2-B']` | report-json.test.ts schema match |
| T8   | Transitive SBOM dependency hit (depth-3 npm pkg with @hikvision-oss maintainer) | `tests/fixtures/section889-1bd/w2-envelope-sbom-hik-depth3.json` | Envelope populated; `.docx` per-finding section includes match_path | report-docx.test.ts asserts match_path text |
| T9   | Kaspersky NDAA §1634 hit reported under FAR 52.204-25(d) framework | `tests/fixtures/section889-1bd/w2-envelope-kaspersky.json` | Envelope `statutory_basis` includes both `'ndaa-2018-sec-1634'` and `'dhs-bod-17-01'`; `.docx` cites §1634 + BOD 17-01 verbatim | 1bd-reporter.test.ts asserts statutory_basis array |
| T10  | Multiple simultaneous hits in a single W.W2 envelope (3 vendors × 2 contracts = 6 report files) | `tests/fixtures/section889-1bd/w2-envelope-multi.json` | 6 JSON + 6 `.docx` emitted; 6 DB rows; each unique by (match_id, contract_number) | 1bd-reporter.test.ts file count assertion |
| T11  | JSON envelope validates against the canonical Ajv schema | (any fixture) | `ajv.validate(schema, envelope)` returns true | report-json.test.ts schema enforcement |
| T12  | `.docx` unpacks and contains required `word/document.xml` + signature placeholder bookmark | (any fixture) | `unzipSync(buf)['word/document.xml']` exists; bookmark `signature-placeholder` present | report-docx.test.ts unzip assertion |
| T13  | Ed25519 signature verifies against the configured public key | (any fixture) | `verifyEnvelope(env, pubkey)` returns true | sign.test (reuses existing sign.ts test harness) |
| T14  | RFC 3161 TST attached and valid | (any fixture; TSA stubbed) | `verifyTimestampToken(token)` returns true | report-json.test.ts TST validation |
| T15  | Tracker DB row written with correct `deadline_at`, `status='emitted'`, `signing_key_version` pinned | (any fixture) | `SELECT * FROM section889_reports WHERE report_id=...` returns row with matching fields | tracker integration test |
| T16  | Notification fires at emit time via `core/notify.ts` | (any fixture; notify stubbed) | Stub captures one Slack send with template `section889-1bd-emitted` | 1bd-reporter.test.ts stub assertion |
| T17  | T-1-hour notification scheduled correctly (row in `scheduled_notifications`) | (any fixture) | `SELECT fire_at FROM scheduled_notifications WHERE report_id=...` returns `deadline_at - 1h` | tracker integration test |
| T18  | Status transition emit→transmitted→acknowledged→closed flows through the API | API integration test (REST) | `POST /mark-transmitted` updates `status='transmitted'`; subsequent `/mark-acknowledged` → `'acknowledged'`; `/mark-closed` → `'closed'`; POA&M item updated with each event | routes/section889-reports.test.ts |
| T19  | DST transition — discovery 2026-03-08T16:30 ET (Sun before DST); deadline computed in correct TZ; clock semantics correct around 2026-03-10 02:00 EST→EDT | `tests/fixtures/section889-1bd/w2-envelope-dst-march.json` | Deadline computed with IANA `America/New_York`; no off-by-one hour error | clock.test.ts DST assertion |
| T20  | Cross-reference: a confirmed 1BD report from W.W3 is referenced in the next W.W4 annual rep | Integration with W.W4 — runs W.W3, marks status='transmitted', then runs W.W4 | W.W4 annual rep envelope `linked_1bd_reports[]` includes the W.W3 `report_id`; W.W4 ticks "does" representation | cross-loop integration test |

Total: 20 tests (5 above the §7 minimum of 18 because the slice was
missed by the prior workflow and gets extra rigor). Test coverage
hits all major code paths: clock arithmetic (T1–T4, T19), dedupe
(T5), statutory-basis routing (T6–T9), composition (T10–T12),
signing (T13–T14), persistence (T15, T17), notifications (T16),
state-machine transitions (T18), cross-loop linkage (T20).

## 9. Risks

### Risk 1 — Federal holiday calendar drift

**Cause.** OPM updates the federal holiday calendar at the start of
each calendar year, and the President may proclaim ad-hoc closure days
under 5 U.S.C. §6103(c) at any time. If the W.W3 module's holiday set
is stale, deadlines computed late in the year may be wrong by 8
business hours.

**Likelihood.** Moderate (annual cycle is guaranteed; ad-hoc closures
~ 1/year).

**Impact.** High — a missed deadline is a regulatory violation under
FAR 52.204-25(d) and exposes the CSP to contract termination + suspension/
debarment proceedings.

**Mitigation.** `scripts/fetch-opm-holidays.mjs` runs annually on
Jan 2 (cron). The script writes a signed
`cloud-evidence/data/federal-holidays-YYYY.json` for the new year
and pre-fetches the following year on demand. The W.W3 clock module
verifies the signature on load. The tracker UI surfaces a
"holiday calendar last refreshed" badge that turns amber at 6 months
old and red at 12 months. Operator runs the script manually any time
an ad-hoc closure is proclaimed.

### Risk 2 — DST edge cases on March/November transitions

**Cause.** America/New_York observes daylight-saving time. The spring-
forward transition (typically 2nd Sunday of March, 02:00 EST → 03:00
EDT) creates a 23-hour day; the fall-back transition (1st Sunday of
November, 02:00 EDT → 01:00 EST) creates a 25-hour day. A naive
hours-arithmetic implementation will be off by one hour around the
transitions.

**Likelihood.** Twice a year, every year.

**Impact.** Moderate — a 1-hour deadline miss may or may not be a
regulatory issue depending on how strictly the Contracting Officer
interprets "one business day"; the FR preamble (§2.7) treats it as
8 business hours, so the safe reading is strict.

**Mitigation.** The clock uses ISO8601 timestamps with explicit
`America/New_York` TZ designators and the IANA tzdata library
(`@js-temporal/polyfill` or native `Temporal` once available). Tests
T19 covers both transitions. The implementation operates in absolute
UTC seconds when possible and only converts to local time at the
business-hour boundary.

### Risk 3 — Operator forgetting to configure reporting-endpoint URL or contracts file

**Cause.** A CSP that has never invoked `--prohibited-vendor-1bd-report`
may not have populated `section889-contacts.yaml`. When the orchestrator
runs W.W3 for the first time with a positive ID surfaced, the report
cannot be addressed.

**Likelihood.** Moderate — common on first run.

**Impact.** High — the deadline clock is still ticking; missing
contact data does not toll the clock under FAR 52.204-25(d).

**Mitigation.** The orchestrator's startup-validation refuses to run
`--prohibited-vendor-1bd-report` if `section889-contacts.yaml` is
absent OR the signing block in `config.yaml::section_889.signing`
contains any `REQUIRES-OPERATOR-INPUT` literal. Exit code 2 with a
clear `Section889OperatorConfigMissingError` listing every missing
field. The tracker UI surfaces a "Section 889 config incomplete"
banner the moment the operator opens the application with W.W3
unconfigured.

### Risk 4 — Race condition: W.W2 surfaces a hit while a prior report is in flight

**Cause.** Two W.W2 runs in quick succession (e.g. the operator runs
the screen twice in the same minute) may both surface the same
positive ID and trigger two W.W3 emit attempts.

**Likelihood.** Low (the orchestrator serializes by default).

**Impact.** Low — duplicate reports waste operator review time but
do not break the regulatory posture.

**Mitigation.** Idempotency-key on the tracker DB unique index
`(run_id, match_id, contract_number, report_kind)`. The second emit
attempt hits the unique-index violation, the W.W3 module catches the
error, logs `coverage:section889-1bd:duplicate-skipped:1`, and the
process exits cleanly. Test T5 covers.

### Risk 5 — Signing-key rotation mid-deadline

**Cause.** A 24-hour deadline window may straddle a corporate
signing-key rotation event. If the key version changes between
compose time and operator-transmission time, the operator (or a 3PAO
later) may attempt to verify the signature against the wrong key
version and conclude the report was tampered with.

**Likelihood.** Low (most operators rotate at predictable cadences;
W.W3 deadlines are short).

**Impact.** Moderate — false-positive integrity alarm; operator must
re-verify against the historical key version.

**Mitigation.** The W.W3 emit pins `signing_officer.key_version` at
compose time. The signed envelope carries the pinned version. The
existing `core/sign.ts` verification path accepts a key-version
hint; the tracker UI surfaces the pinned version next to the
signature receipt. Test T13 + extension covers.

### Risk 6 — Wrong Contracting Officer email

**Cause.** The operator may mis-type a CO email in
`section889-contacts.yaml`, sending the report to a wrong recipient
or to a deliverability-failing address. The clock keeps ticking; the
operator may not notice until the deadline expires.

**Likelihood.** Moderate (human data entry).

**Impact.** High — failure to report = regulatory violation.

**Mitigation.** The YAML loader runs RFC 5322 syntax validation +
DNS MX-lookup against the address's domain at startup (offline mode
allowed via `--skip-mx-check` for air-gapped environments). The
tracker UI surfaces a "validated" green badge next to each contact
when MX lookup succeeded. Optional: per-agency directory lookup
against a baseline CO directory committed to repo
(`cloud-evidence/data/co-directory-baseline.yaml`); when the
operator's address differs from the directory, the UI prompts for
manual confirmation. Also: the JSON envelope and `.docx` carry the
contracting_officer_email field, so a 3PAO can audit the dispatch
target.

### Risk 7 — Confidential subcontractor identity leak

**Cause.** FAR 52.204-25(d)(2)(i) requires reporting the subcontractor
identity. If the report contents leak (e.g. via a misconfigured
tracker DB backup, or a stolen `.docx` from an operator laptop), a
subcontractor's confidential identity may be exposed.

**Likelihood.** Low (proper operational security).

**Impact.** High — potential breach of subcontractor NDAs +
reputational damage.

**Mitigation.** The report content is encrypted-at-rest in the
tracker DB via pgcrypto + KMS data-key envelope (existing tracker DB
pattern). Only the operator + designated CO recipient see the
`.docx` (operator manually emails). The signed JSON envelope is bundled
in the submission package, which is itself encrypted via the LOOP-A.A4
encryption flow when delivered to the 3PAO. Audit-log every read of
the tracker DB row.

### Risk 8 — Annual-rep + 1BD coupling: silent inconsistency

**Cause.** A confirmed 1BD report from W.W3 changes the factual basis
of the most recent W.W4 annual rep (the "does not use" representation
becomes false). If the operator does not re-sign the annual rep, the
SAM.gov representation goes stale and a 3PAO will catch the gap.

**Likelihood.** Moderate (operators may not realize the linkage).

**Impact.** Moderate — the annual rep is amended at the next option-
year exercise normally, but if the gap is between exercises a SAM.gov
audit may surface it.

**Mitigation.** When the operator marks a 1BD report as transmitted,
W.W3 reads
`config.yaml::section_889.reporting.annual_rep_amendment_policy`:
- `auto-mark` — the most recent W.W4 envelope is automatically marked
  `amended_pending_resign` and the operator is notified to re-sign;
- `manual` — the tracker UI surfaces a "Re-sign annual rep" banner;
- `none` — no action.

Default = `manual`. Test T20 covers the linkage.

### Risk 9 — Subcontractor-tier reporting depth

**Cause.** When the CSP is a sub-sub-contractor (or deeper), FAR
52.204-25(d) requires reporting up the chain. The depth and routing
of the upward report are unclear without explicit guidance.

**Likelihood.** Low for typical CSPs (most are primes or single-tier
subs).

**Impact.** Moderate — over-reporting is safe; under-reporting is a
violation.

**Mitigation.** Status: **REQUIRES-RESEARCH**. The operator's General
Counsel confirms the depth for the CSP's contract portfolio. Until
confirmed, W.W3's default is to report to (a) the operator's direct
prime's Contracting Officer, AND (b) the Federal Contracting Officer
of any contract the operator has direct visibility to. The
`section889-contacts.yaml` lets the operator override per-contract.

### Risk 10 — TSA outage at emit time

**Cause.** The RFC 3161 TSA the operator configures may be
unreachable at the moment W.W3 emits the report.

**Likelihood.** Low.

**Impact.** Low — the report is still signable; the TST can be
attached asynchronously.

**Mitigation.** TST attachment is best-effort. If the TSA fails,
W.W3 emits with a `rfc3161_timestamp.status: 'pending'` block and
schedules a tracker DB job to retry at 5-minute intervals for 1 hour,
then 15-minute intervals for 24 hours. Operator alerted if the TST
remains pending after 24 hours.

## 10. Open questions

- **Q1 — DHS Section 889 Reporting endpoint URL / format.** Status:
  **REQUIRES-RESEARCH**. The exact format / URL is not publicly
  documented (per LOOP-W-SPEC.md §2.11). Until verified, W.W3 emits
  to a file + the operator transmits manually as the fallback path.
- **Q2 — `.docx` FAR-compliant template format.** Status:
  **REQUIRES-RESEARCH**. Whether DoD / civilian CO recipients expect
  a specific FAR-compliant template (e.g. an AT-style cover page) is
  not publicly documented. For now, W.W3 emits a clear cover page
  with all required (d)(2) fields rendered prominently.
- **Q3 — Annual-rep + 1BD coupling: auto-mark or manual?** Status:
  **REQUIRES-OPERATOR-INPUT** (see §11). Default is `manual`.
- **Q4 — Subcontractor-tier reporting depth.** Status:
  **REQUIRES-RESEARCH**. FAR 52.204-25(d) requires reporting "the
  contract number" and "any related subcontract number"; if the CSP
  is a sub-sub, how deep does the report chain go? Operator's
  General Counsel confirms.
- **Q5 — Timezone of "1 business day".** Status:
  **REQUIRES-RESEARCH**. Is the clock America/New_York (DC business
  hours, the FAR convention) or operator's local TZ? Likely DC;
  operator's General Counsel confirms. Default is
  America/New_York; operator may override via §11.
- **Q6 — Effect of an active waiver under FAR 4.2104 on the 1BD
  clock.** If an ODNI waiver covers the identified covered equipment,
  does the 1BD reporting clock still run? FAR text suggests yes
  (the clause is reporting-on-discovery, not gating-on-waiver), but
  REQUIRES-OPERATOR-INPUT for the operator's General Counsel to
  confirm. Default behavior: report regardless of waiver; the
  envelope carries `waiver_id` if known.
- **Q7 — Reporting cadence when the same vendor surfaces repeatedly
  across runs.** Once W.W3 has emitted an initial 1BD report and a
  10BD follow-up, must the next W.W2 run (which will surface the
  same match) emit another 1BD report? FAR 52.204-25(d) appears to
  treat "identification" as a discrete event; repeated detection of
  the already-reported finding does not re-trigger. W.W3's dedupe
  (Phase B step 9) implements this reading. REQUIRES-OPERATOR-INPUT
  to confirm with General Counsel; if the strict reading is
  every-detection-is-a-fresh-trigger, the dedupe key would drop
  `match_id` and reduce to `(run_id, vendor_name, contract_number)`.

## 11. REQUIRES-OPERATOR-INPUT fields

| Field name | Type | Validator | UI location | Failure mode if missing |
|------------|------|-----------|-------------|--------------------------|
| `reporting_endpoint_url` | string (URL) | URL validator + (for HTTPS) MX/A-record reachability check | Settings → Compliance → Section 889 Reporting | Orchestrator refuses `--prohibited-vendor-1bd-report` with exit code 2 + `Section889OperatorConfigMissingError`. |
| `agency_contracting_officer_email` (per contract) | string (RFC 5322) | RFC 5322 syntax + MX-record check | Settings → Compliance → Contracts (one per contract) | Emit-only mode (report is composed and signed; operator manually addresses email); tracker UI surfaces red banner. |
| `prime_contract_numbers` | array of strings | FAR contract-number regex pattern | Settings → Contracts | Report cannot be emitted (contract number is one of the 9 (d)(2)(i) elements). |
| `corporate_signing_officer_name` | string | non-empty, no control chars | Settings → Compliance → Signing | Signed envelope blocks; exit code 2 at orchestrator startup. |
| `corporate_signing_officer_title` | string | non-empty, no control chars | Settings → Compliance → Signing | Signed envelope blocks; same. |
| `ed25519_signing_key_ref` | string (KMS resource ARN or GCP KMS resource) | sign-test on startup (`core/sign.ts::testSign(key_ref)`) | Settings → Compliance → Signing | Orchestrator refuses to run; exit code 2 with `KmsKeyUnavailableError`. |
| `annual_rep_amendment_policy` | enum: `auto-mark` \| `manual` \| `none` | enum validator | Settings → Compliance → Annual Rep | Default to `manual` if missing (back-compat). |
| `federal_business_hours_tz` | enum: `America/New_York` \| `operator_local` | enum validator + tzdata lookup | Settings → Compliance → Reporting | Default to `America/New_York` if missing. |
| `business_hours_start` / `business_hours_end` | string (HH:MM) | regex `^\d{2}:\d{2}$` + range check | Settings → Compliance → Reporting | Default to `09:00` / `17:00` if missing. |
| `notification_channels` | array of channel refs (`slack:#chan` or `pagerduty:service`) | channel-ping test at startup | Settings → Notifications | Emit warning at startup; report still emits; operator must manually notice the tracker UI banner. |
| `agency_closures_<YEAR>` | array (date, reason) | ISO8601 date + non-empty reason | Settings → Compliance → Agency Closures | Default empty list; no effect on clock unless a closure is added. |
| `csp_uei` | string (12-char SAM UEI) | UEI regex + (optional) SAM.gov lookup | Settings → Org Profile | Report cannot be emitted (UEI is one of the (d)(2)(i) elements via supplier_uei when CSP self-reports). |
| `csp_cage_code` | string (5-char CAGE) | CAGE regex | Settings → Org Profile | Soft-warn: emit with `REQUIRES-OPERATOR-INPUT` literal; operator completes before transmission. |
| `subcontract_routing_policy` | enum: `report-to-prime-co` \| `report-to-federal-co` \| `both` | enum validator | Settings → Compliance → Subcontracts | Default `both` (over-reporting is safe). |
| `tsa_url` | string (URL) | URL validator + TSA-handshake test | Settings → Signing → Timestamp Authority | Default to the org's existing TSA configured via LOOP-A.A5; warn if missing. |
| `tracker_db_kms_data_key_ref` | string | KMS resource validator | Settings → Tracker → Encryption | Default to org's existing tracker DB encryption key (LOOP-A.A4); exit `2` if missing in production. |

Total: 16 fields. Of these, **7 are blocking** at startup (orchestrator
refuses to run), **4 are soft-warning** (emit with placeholder; operator
completes before transmit), and **5 are defaulting** (W.W3 chooses a
safe default if missing).

## 12. Implementation log

| date | session | action | commit | notes |
|------|---------|--------|--------|-------|
| 2026-06-07 | wevi1ic5b + W.W3 patch workflow | Specification authored via FedPy workflow | TBD | This per-slice doc proposed; sibling files W.W1, W.W2, W.W4 already exist; this fills the missing-from-prior-workflow gap. |
| 2026-06-18 | impl-w-w3 | Shipped end to end per spec (realizable core). Created `core/section889-clock.ts` (federal-business-hour clock composing `bizdays.ts:usFederalHolidays` + ET/DST/8h layer), `core/section889-contacts.ts`, `core/section889-closures.ts`, `core/section889-report-json.ts` (filter + statutory routing + canonical composer), `core/section889-report-docx.ts` (OOXML report on `zip.ts`), `core/section889-1bd-reporter.ts` (ingest+verify W.W2 envelope → emit signed JSON+`.docx`+`.sig` per (match × contract) → ledger dedupe → coverage → notify seam → follow-up). Wired orchestrator `--prohibited-vendor-1bd-report` (env `CLOUD_EVIDENCE_PROHIBITED_VENDOR_1BD_REPORT`, runs after W.W2) + submission-bundle WELL_KNOWN roles + `listOutDir` subdir scan. Added `section889-contacts.example.yaml` + `section889-agency-closures.example.yaml`. **45 new tests** (clock 19, docx 6, reporter 20) — full suite 1127→1172, typecheck 0, check:reo G1/G2/G3 green. **Scope reconciliation vs reality:** the tracker DB migration / REST routes / React UI / `scheduled_notifications` daemon / pgcrypto-at-rest in §5.4/§7 are NOT implementable in this repo (no `pg`/`express`/`react`; every slice ships as `core/*.ts`+tests) — deferred per LOOP-W-RISKS W.W3-17 (ledger is the interim idempotency+audit index; notify is an injectable seam). Holidays computed via `bizdays` not a signed JSON file (W.W3-18). RFC-3161 recorded `pending`, Ed25519 `.sig` is the integrity mechanism (W.W3-19). POA&M back-referenced via `poam_item_uuid`, not mutated (W.W3-20). §10 resolutions: Q5 tz defaults America/New_York (operator-overridable); Q6 waiver→report regardless (envelope carries `waiver_id`); Q7 dedupe keys `(run_id, match_id, contract, kind)` = discrete-identification reading. Q1/Q2/Q4 remain REQUIRES-RESEARCH (file+operator-transmit fallback shipped). | TBD-step6 | STATUS row title reconciled (was the stale "SBOM crosscheck" label; SBOM walking is owned by W.W2 per §3.2). |

## 13. Completion checklist

> The following 7 steps are quoted verbatim from
> `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`. They are MANDATORY
> for every slice in every loop. NO EXCEPTIONS. Every session that ships
> a slice MUST execute this checklist atomically with the slice's own
> commit.
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
> ### Step 8 (W.W3-specific addendum)
> After the commit lands, append the W.W3 row to STATUS.md (status →
> done, commit hash, last_updated); update LOOP-W-SPEC.md status table
> (W.W3 row); append a CHANGELOG entry (LOOP-W.W3 — FAR 52.204-25(d)
> 1-Business-Day Prohibited-Vendor Discovery Reporter); push to
> origin/main; verify with `git log --oneline -3`. Only THEN is W.W3
> closed.

REO STANDARD (Rule 1–4) governs every line of production code described
in §7. No invented citations. Apache-2.0 clean-room.
