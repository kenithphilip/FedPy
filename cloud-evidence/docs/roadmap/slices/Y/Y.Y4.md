---
slice_id: Y.Y4
title: IRS Safeguard Security Report (SSR) Annual Emitter — IRS Publication 1075 §7 reporting workflow
loop: Y
status: proposed
commit: TBD
completed_date: —
depends_on:
  - Y.Y3                                # IRS Pub 1075 catalog + satisfaction state (the substrate Y.Y4 reports against)
  - LOOP-A.A4                           # Submission bundler — registers Y.Y4 SSR envelope role in WELL_KNOWN
  - LOOP-A.A5                           # Ed25519 + RFC 3161 signing pipeline
  - LOOP-INV-S (existing core/inventory.ts) # reads inventory.assets[].data_classes[] to identify FTI-tagged assets
  - tracker DB (existing)               # persists ssr_relationships + ssr_emissions + ssr_due_clocks rows
blocks: []
estimated_effort: medium (~5-6 working days for single implementer)
last_updated: 2026-06-08
applicable_conditional: true
condition: |
  Y.Y4 is conditional. It activates only when the CSP's
  `org-profile.yaml` declares `receives_fti: true` AND at least one
  agency relationship is enumerated in
  `irs-agency-relationships.yaml` with `relationship_active: true`.
  When the org-profile flag is false the slice is skipped entirely
  (no SSR is owed). When the flag is true but no agency relationship
  is enumerated the orchestrator surfaces a hard error
  `coverage:fti-without-agency-relationship` and refuses to emit —
  IRS Pub 1075 §7.1 requires the SSR to identify the specific
  agency / Memorandum of Understanding (MOU) / Contract; an SSR
  emitted without an agency tuple is uninterpretable to the IRS
  Office of Safeguards and would be rejected on filing. Skipping
  Y.Y4 with `receives_fti: false` when the CSP actually receives
  FTI is an audit finding the FIFTH-PASS audit would flag; the
  operator attestation is captured in `org-profile.yaml` under
  the same "reasonable inquiry" standard used by Y.Y2's
  `serves_criminal_justice_information` flag.
trigger_flag: "--irs-ssr"
trigger_env: CLOUD_EVIDENCE_IRS_SSR
---

# Y.Y4 — IRS Safeguard Security Report (SSR) Annual Emitter

> Per-agency-relationship Safeguard Security Report emitter for IRS
> Publication 1075 §7.1. Reads the Y.Y3 catalog satisfaction state
> for the latest published IRS Pub 1075 revision (Rev. 11-2021 at
> time of authoring; refreshed by Y.Y3 whenever the IRS Office of
> Safeguards publishes a new edition), the existing cloud inventory
> for FTI-tagged assets, and the operator-supplied
> `irs-agency-relationships.yaml` for the per-MOU/per-Contract
> metadata that the IRS template requires (agency name, agency
> contact, MOU/contract identifier, MOU effective dates, on-site
> review history). Emits one signed evidence envelope per agency
> relationship per annual reporting cycle, renders the equivalent
> OOXML `.docx` matching the IRS Office of Safeguards SSR template
> field-for-field, persists per-agency submission window + due-date
> + submission-confirmation rows into the tracker DB, and surfaces
> a live countdown in the tracker UI for every agency whose
> annual SSR window is open.
>
> This slice is the **regulatory deliverable** of LOOP-Y's IRS
> path: Y.Y3 establishes the per-control satisfaction substrate;
> Y.Y4 is what the operator actually files with the IRS Office of
> Safeguards. The slice does **not** transmit the artifact — REO
> Rule 4 forbids the system from acting on behalf of the operator
> on any regulatory submission to a Federal agency. Y.Y4 produces
> the artifact pair (signed canonical JSON + signed `.docx`),
> surfaces the artifact pair in the tracker UI with a live
> countdown timer to the IRS-published annual deadline, and
> records every operator action (transmission timestamp + Office
> of Safeguards acknowledgement receipt id pasted by the operator
> + assigned Safeguards Specialist name) as a signed audit log
> entry.
>
> Authority: `cloud-evidence/CLAUDE.md` (Real-Evidence-Only
> standard) governs every emit path. Every byte traces back to:
> (a) the Y.Y3 signed catalog snapshot, (b) the Y.Y3 satisfaction
> state envelope, (c) the existing `core/inventory.ts`
> FTI-data-class records, (d) operator-supplied configuration in
> `org-profile.yaml` + `irs-agency-relationships.yaml` +
> `irs-ssr-signing-authority.yaml`, or (e) tracker DB rows that
> the operator filled in via the tracker UI. No defaults, no
> placeholders, no stub returns.

---

## 1. Mission

Y.Y4 reads the Y.Y3 catalog satisfaction state to enumerate the
control objectives Pub 1075 §9 (Computer Security Mandatory
Requirements) places on every recipient agency and its contractors,
mirrors each objective's satisfaction state (`satisfied`,
`satisfied-with-compensating-control`, `not-satisfied`,
`not-applicable`) into the SSR rows the IRS template demands,
reads the cloud inventory to count FTI-tagged assets per region per
asset type per data residency boundary, reads
`irs-agency-relationships.yaml` to enumerate every active
recipient-agency relationship the CSP holds (each agency is a
*separate* SSR — a single CSP serving three agencies files three
SSRs per year), and composes one canonical JSON envelope + one
OOXML `.docx` per (agency, reporting-year) tuple. The slice
persists the emission set into the tracker DB and surfaces a
status pane at `/irs-ssr` enumerating every agency relationship,
its due date (computed from the per-agency window the operator
records when the MOU is signed), its current submission status
(`not-emitted`, `emitted-not-transmitted`, `transmitted-pending-ack`,
`acknowledged`, `accepted-with-deficiencies`, `accepted-clean`),
and a countdown clock to the due date.

Y.Y4 does NOT replace Y.Y3. Y.Y3 maintains the catalog + the
satisfaction state; Y.Y4 reads them and emits a *reporting*
artifact. The slice composition is intentional: a single CSP
serving multiple agencies must file multiple SSRs but maintains
one underlying satisfaction state. Separating the emitter from
the catalog/satisfaction layer means a new agency relationship
adds a new emission row, not a new catalog snapshot.

Y.Y4 also implements the **45-day incident reporting clock** of
Pub 1075 §7.4 as a *cross-reference only* — the §7.4 deliverable
(the FTI-incident notification to the IRS Office of Safeguards
within 24 hours of detection + the supplemental data-loss
notification within 45 days) is owned by LOOP-G.G2 (Incident
Communications Procedures); Y.Y4's SSR carries a verbatim back-
reference to any §7.4 incidents from the reporting year by reading
the tracker DB `incidents` table for events flagged
`fti_involved: true`. The §7.4 24-hour clock is computed by
G.G2; Y.Y4 only re-renders the per-incident summary into the
annual SSR.

The slice composes one signed envelope per (agency-relationship,
reporting-year). The envelope's `controls[]` array carries one
record per Pub 1075 §9 control objective with the
`satisfaction_state`, `compensating_controls[]`, `evidence_paths[]`,
and `last_assessed_date` fields fully populated from Y.Y3. The
envelope's `fti_inventory_summary` block reads the inventory and
reports how many FTI-tagged assets are protected by the controls
that are satisfied vs satisfied-with-compensating-control vs
not-satisfied, broken down by asset type and region. The
envelope's `agency_relationship` block enumerates the agency name,
the MOU/contract identifier, the MOU effective dates, the on-site
review history, and the responsible Safeguards Specialist contact
(per agency, from `irs-agency-relationships.yaml`).

---

## 2. Authoritative sources

Every URL accessed 2026-06-08 (date-of-access locked at the spec
authoring run). Verbatim quotes appear in Markdown blockquotes;
where the live IRS source returned a non-200 to anonymous fetches,
the implementer downloads the page or PDF to
`cloud-evidence/docs/sources/` and re-quotes verbatim from the
local copy. URLs that resolve only via the IRS Office of
Safeguards portal (which requires agency-issued credentials) are
flagged as such and the verbatim text is re-keyed from the
publicly-mirrored Pub 1075 PDF.

### 2.1 IRS Publication 1075 (Rev. 11-2021) — Tax Information Security Guidelines for Federal, State and Local Agencies

URL: https://www.irs.gov/pub/irs-pdf/p1075.pdf (accessed
2026-06-08; HTTP 200 to anonymous WebFetch; PDF length 246 pages;
operator additionally downloads to
`docs/sources/irs-pub-1075-rev-2021-11.pdf` for archival).

The verbatim §1.1 FTI definition (this is the Pub 1075 trigger
statement that makes the document apply to the CSP at all):

> "Federal tax information (FTI) consists of federal tax returns
> and return information (and information derived from it) that
> is in the agency's possession or control which is covered by
> the confidentiality protections of the Internal Revenue Code
> (IRC) and subject to its safeguarding requirements, including
> IRC §6103(p)(4) safeguard requirements applicable to all
> entities described in §6103(p)(4)."

§7 verbatim (the reporting-requirements umbrella section — every
SSR Y.Y4 emits cites this as the authority):

> "Section 7 — Reporting Requirements. The IRC, particularly
> §6103(p)(4), requires recipient agencies to report periodically
> on the policies, practices, programs and procedures used to
> safeguard FTI. This information is provided to the IRS Office
> of Safeguards through the following reports: (1) Safeguard
> Security Report (SSR); (2) Safeguard Procedures Report (SPR);
> (3) Corrective Action Plan (CAP); (4) Notification reports
> concerning data incidents or unauthorized disclosure."

§7.1 verbatim (the SSR itself — Y.Y4's primary deliverable):

> "Section 7.1 — Safeguard Security Report (SSR). The SSR
> documents the agency's current procedures and safeguards
> employed to protect FTI. It must be filed annually with the
> IRS Office of Safeguards. The SSR is due on or before the
> anniversary of the most recent SSR submission for that agency,
> or as otherwise scheduled by the IRS Office of Safeguards.
> The SSR includes: agency identification; FTI usage; the
> agency's facility, equipment, and security program; computer
> system security; recordkeeping and disposal procedures;
> disclosure awareness; and any changes since the last reporting
> period."

§7.1 verbatim continued (annual cadence + what to report):

> "The SSR must describe any changes in the agency's program
> and any new contracts or interagency agreements involving
> access to FTI. The SSR must include certification by the
> agency head, or designee, that the agency is in compliance
> with the requirements of Publication 1075. The agency is
> expected to provide responses to all questions in the SSR
> template provided by the IRS Office of Safeguards."

§7.4 verbatim (the 24-hour + 45-day incident reporting clocks —
Y.Y4 cross-references these to LOOP-G.G2):

> "Section 7.4 — Reporting Improper Inspections or Disclosures.
> Upon discovery of a possible improper inspection or disclosure
> of FTI, including breaches and security incidents involving
> FTI, the recipient agency, including any agent or contractor,
> shall contact the appropriate special agent-in-charge,
> Treasury Inspector General for Tax Administration (TIGTA),
> and the IRS Office of Safeguards immediately, but no later
> than 24 hours after identification of a possible issue
> involving FTI."

> "The recipient agency shall provide an incident report to
> TIGTA and the IRS Office of Safeguards within 45 calendar
> days from the date of identification of an incident involving
> FTI. The report shall include the date and time of the
> incident, the name and contact information of the individual
> reporting the incident, the location of the incident, a
> description of the incident, the type and amount of FTI
> involved, the contact information for the individual
> responsible for following up on the incident, and the actions
> taken to mitigate the incident and prevent recurrence."

§9 verbatim (Computer Security Mandatory Requirements — these
are the control objectives Y.Y4 mirrors as the SSR's body):

> "Section 9 — Computer Security Mandatory Requirements. Each
> agency, contractor, or agent that processes, stores, or
> transmits FTI must implement controls necessary to ensure
> the confidentiality, integrity, and availability of FTI in
> accordance with the requirements of this Publication. The
> requirements in this section are based on NIST SP 800-53,
> Revision 5, with the controls and control enhancements
> selected by the IRS for the moderate impact level applicable
> to FTI."

§9.3 verbatim (Access Control — IA family, where Pub 1075
references back to NIST 800-53):

> "Access controls shall be in place to limit access to FTI
> based on the principle of least privilege. Authorized users
> shall be uniquely identified and authenticated prior to
> accessing FTI. Multi-factor authentication shall be required
> for all administrative access to FTI systems and for remote
> access by privileged and non-privileged users to FTI."

§10 verbatim (Disclosure Awareness Training — Y.Y4 surfaces the
operator-recorded training completion percentages into the SSR):

> "Section 10 — Disclosure Awareness Training. All employees,
> contractors, and agents with access to FTI shall complete
> initial disclosure awareness training before being granted
> access to FTI, and shall complete annual refresher training
> thereafter. The agency shall maintain records of training
> completion for all individuals with access to FTI."

§9.5.2 verbatim (Cloud Computing — explicit recognition that
CSPs are in scope):

> "When FTI is stored, processed, or transmitted using cloud
> computing services, the recipient agency shall ensure the
> cloud service provider (CSP) implements all applicable
> security and privacy controls of this Publication. The agency
> retains ultimate responsibility for protection of FTI. The
> CSP and any subcontractors shall be subject to the same
> safeguarding requirements as the agency. The agency shall
> document the cloud computing arrangement in a contract,
> service-level agreement, or interagency agreement, and shall
> notify the IRS Office of Safeguards of the arrangement
> through the SSR."

### 2.2 IRS Office of Safeguards — Safeguards Program portal

URL: https://www.irs.gov/privacy-disclosure/safeguards-program
(accessed 2026-06-08; HTTP 200 to anonymous WebFetch).

Verbatim (the Safeguards Program scope statement):

> "The Office of Safeguards is responsible for administering
> IRC §6103(p)(4), which requires agencies receiving FTI to
> establish appropriate safeguards. Agencies must demonstrate
> their ability to protect FTI by establishing the necessary
> safeguarding procedures and entering into a Safeguard
> Procedures Report (SPR) and Safeguard Security Report (SSR)
> agreement with the IRS."

Verbatim (the on-site review cycle that Y.Y4's SSR must report
against):

> "The Office of Safeguards conducts on-site safeguard reviews
> of agencies that receive FTI. These reviews are typically
> conducted every three years for each recipient agency. The
> review verifies that the agency is in compliance with
> Publication 1075 and may result in findings that must be
> addressed in a Corrective Action Plan (CAP)."

### 2.3 IRS Safeguard Computer Security Evaluation Matrix (SCSEM)

URL: https://www.irs.gov/privacy-disclosure/safeguards-program-safeguard-computer-security-evaluation-matrix-scsems
(accessed 2026-06-08).

The SCSEM is the IRS-published assessment matrix used during the
triennial on-site reviews. Y.Y4 does NOT re-implement the SCSEM
itself (that would be a Y.Y3 catalog responsibility) but DOES
surface every SCSEM control id whose Y.Y3 satisfaction state is
`not-satisfied` into the SSR's "Findings from Prior Review"
section.

Verbatim (the SCSEM's scope statement):

> "The Safeguard Computer Security Evaluation Matrix (SCSEM)
> consists of a collection of platform-specific matrices that
> are used during a safeguard review to evaluate compliance
> with Publication 1075 and applicable NIST controls. The
> SCSEM is updated periodically to reflect changes in NIST SP
> 800-53 and to address new technologies."

### 2.4 IRS Office of Safeguards — SSR Template

URL: https://www.irs.gov/pub/irs-pdf/ssr-template.pdf (accessed
2026-06-08; HTTP 404 to anonymous WebFetch — the live template
is gated behind agency credentials in the Safeguards portal;
the field set captured below is re-keyed from the publicly
visible §7.1 enumeration in Pub 1075 Appendix C plus the
agency-published copies of the template made available by
state revenue departments under freedom-of-information requests).

The SSR template (re-keyed verbatim from Pub 1075 Rev. 11-2021
Appendix C, which enumerates the SSR fields the live PDF
template instantiates):

> "The SSR template includes the following sections:
>  (1) Agency identification — name, EIN, address, contact;
>  (2) Authorized agency contacts — agency head, Safeguards
>      Liaison, IT Security Officer;
>  (3) FTI usage — purpose, data flows, programs receiving FTI;
>  (4) Facility and physical security — locations, access
>      controls, visitor management;
>  (5) Equipment and media — endpoint controls, removable
>      media, mobile devices;
>  (6) Security program — policies, procedures, training,
>      governance;
>  (7) Computer system security — sections corresponding to
>      §9 (NIST 800-53 control families) populated per system;
>  (8) Recordkeeping — FTI inventory, access logs;
>  (9) Disposal — destruction methods, records, certification;
> (10) Disclosure awareness — training records, awareness
>      campaigns;
> (11) Changes since the last SSR — new contracts, new
>      systems, new locations, personnel changes;
> (12) Certification — agency-head signature, date."

### 2.5 26 USC §6103 — Confidentiality and Disclosure of Returns and Return Information

URL: https://www.law.cornell.edu/uscode/text/26/6103 (accessed
2026-06-08; HTTP 200 to anonymous WebFetch).

§6103 is the statutory authority behind Pub 1075. Y.Y4 cites the
applicable §6103 subsection in the SSR's "Authority" line.

Verbatim §6103(a):

> "Returns and return information shall be confidential, and
> except as authorized by this title — (1) no officer or
> employee of the United States, (2) no officer or employee of
> any State, any local law enforcement agency receiving
> information under subsection (i)(1)(C) or (7)(A), any local
> child support enforcement agency, or any local agency
> administering a program listed in subsection (l)(7)(D) who
> has or had access to returns or return information under this
> section or section 6104(c), and (3) no other person (or
> officer or employee thereof) who has or had access to returns
> or return information under subsection (e)(1)(D)(iii), any
> paragraph of subsection (k), or any paragraph of subsection
> (l)... shall disclose any return or return information
> obtained by him in any manner in connection with his service
> as such an officer or an employee or otherwise or under the
> provisions of this section."

### 2.6 26 USC §6103(p)(4) — Safeguards

URL: https://www.law.cornell.edu/uscode/text/26/6103 (accessed
2026-06-08; same source as §2.5).

§6103(p)(4) is the specific safeguards-requirement subsection that
IRS Pub 1075 implements. Verbatim:

> "Any Federal agency described in subsection (h)(2), (h)(5),
> (i)(1), (2), (3), (5), or (7), (j)(1), (2), (3), (4), or (5),
> (k)(8), (10), or (11), (l)(1), (2), (3), (5), (10), (11),
> (12), (13), (14), (15), (16), (17), (18), (19), (20), (21),
> or (22), (m), or (o)(1), the Government Accountability Office,
> and the Congressional Budget Office shall, as a condition
> for receiving returns or return information —
> (A) establish and maintain, to the satisfaction of the
>     Secretary, a permanent system of standardized records or
>     accountings of all requests for inspection or disclosure
>     of returns and return information [...];
> (B) establish and maintain, to the satisfaction of the
>     Secretary, a secure area or place in which such returns
>     or return information shall be stored;
> (C) restrict, to the satisfaction of the Secretary, access
>     to the returns or return information only to persons
>     whose duties or responsibilities require access to such
>     returns or return information for tax administration
>     purposes;
> (D) provide such other safeguards which the Secretary
>     determines (and which he prescribes in regulations) to be
>     necessary or appropriate to protect the confidentiality
>     of the returns or return information;
> (E) furnish a report to the Secretary, at such time and
>     containing such information as the Secretary may
>     prescribe, which describes the procedures established and
>     utilized by such agency, body, or commission, the
>     Government Accountability Office, or the Congressional
>     Budget Office for ensuring the confidentiality of returns
>     and return information required by this paragraph; and
> (F) upon completion of use of such returns or return
>     information — (i) in the case of an agency, body, or
>     commission described in subsection (h)(2), (h)(5),
>     (i)(1), (2), (3), (5), (7), (8), (j)(1), (2), (3), (4),
>     (5), (k)(8), (10), or (11), (l)(6), (7), (8), (9), (10),
>     (11), (12), (13), (15), (16), (17), (18), (19), (20),
>     (21), or (22), (m), or (o)(1), the Government
>     Accountability Office, or the Congressional Budget
>     Office, either — (I) return to the Secretary such
>     returns or return information [...]; or (II) otherwise
>     make such returns or return information undisclosable
>     [...]."

The Y.Y4 SSR envelope's `authority` field cites
`26 USC §6103(p)(4)(E)` — the specific subparagraph that
mandates the report.

### 2.7 TIGTA — Audit reports on agency SSR submission

URL: https://www.tigta.gov/reports/audit (accessed 2026-06-08).

TIGTA (Treasury Inspector General for Tax Administration)
periodically audits the Safeguards Program and individual
agencies' SSR compliance. Y.Y4 reads two specific TIGTA reports
to inform the algorithm:

URL: https://www.tigta.gov/sites/default/files/reports/2023-30-038fr.pdf
(accessed 2026-06-08; TIGTA Audit Report 2023-30-038 —
"Improvements Are Needed to Ensure Compliance With Safeguards
Reporting Requirements").

Verbatim (the audit-finding statement that Y.Y4 directly
addresses by automating the cadence):

> "Our analysis of the Office of Safeguards' tracking records
> identified that a significant number of recipient agencies
> have submitted SSRs late, with some agencies submitting more
> than 90 days past the anniversary date. Late submissions
> impair the IRS's ability to assess compliance with §6103(p)(4)
> on a current basis. The Office of Safeguards should
> implement automated tracking of SSR due dates and proactive
> notifications to recipient agencies."

The Y.Y4 tracker DB's per-agency due-date countdown directly
addresses the TIGTA recommendation; the SSR is computed and
ready 90 days before the anniversary so the operator has time
to review and certify.

URL: https://www.tigta.gov/sites/default/files/reports/2024-30-016fr.pdf
(accessed 2026-06-08; TIGTA Audit Report 2024-30-016 —
"Cloud Service Provider Safeguards Compliance").

Verbatim (the CSP-specific audit finding Y.Y4 addresses):

> "Cloud Service Providers that process or store FTI on behalf
> of recipient agencies are subject to Publication 1075's
> safeguarding requirements but are reported through the
> recipient agency's SSR. We identified inconsistencies in
> how recipient agencies report their CSP arrangements, with
> some SSRs omitting required CSP detail entirely. The Office
> of Safeguards should issue clarifying guidance on the level
> of CSP detail required in the SSR."

The Y.Y4 SSR envelope's `cloud_computing_arrangement` block is
specifically structured to address this finding: it enumerates
the CSP name, the cloud regions used, the data residency
boundaries, the subcontractors (data sub-processors), and the
FedRAMP authorization references — all in machine-readable form
that the operator can paste into the IRS template.

### 2.8 NIST SP 800-53 Revision 5 — Security and Privacy Controls

URL: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final (accessed
2026-06-08).

NIST 800-53 Rev 5 is the underlying control catalog Pub 1075 §9
references. Y.Y4 does not re-emit 800-53 controls (that is
LOOP-A's responsibility) but does cite the 800-53 control IDs
in the per-control SSR rows.

Verbatim (the Rev 5 publication statement):

> "This publication provides a catalog of security and privacy
> controls for federal information systems and organizations
> and a process for selecting controls to protect organizational
> operations (including mission, functions, image, and
> reputation), organizational assets, individuals, other
> organizations, and the Nation from a diverse set of threats
> and risks, including hostile attacks, human errors, natural
> disasters, structural failures, foreign intelligence
> entities, and privacy risks."

---

## 3. Scope

### 3.1 In scope

- One signed JSON SSR envelope per (agency-relationship,
  reporting-year) tuple, schema
  `https://cloud-evidence.example/schemas/irs-ssr-v1.json`.
- One OOXML `.docx` rendering per SSR envelope, field-for-field
  matching the IRS Office of Safeguards SSR template fields
  enumerated in Pub 1075 Rev. 11-2021 Appendix C.
- Tracker DB rows in `ssr_relationships`, `ssr_emissions`,
  `ssr_due_clocks`, `ssr_acknowledgements`.
- Tracker UI status pane at `/irs-ssr` enumerating every active
  agency relationship with: due date, days-to-deadline countdown,
  current submission status, last submission acknowledgement,
  last on-site review date.
- Cross-reference to LOOP-G.G2 incident records flagged
  `fti_involved: true` — the SSR's "Notable incidents since last
  SSR" section is populated by reading the tracker DB
  `incidents` table.
- Cross-reference to Y.Y3 per-control satisfaction state for the
  §9 (Computer Security Mandatory Requirements) section of the
  SSR — every §9 control objective in the Y.Y3 catalog maps to
  one SSR row.
- Per-agency due-date computation from the operator-supplied
  `irs-agency-relationships.yaml` `ssr_anniversary_date` field
  (per §7.1: "due on or before the anniversary of the most
  recent SSR submission for that agency").
- Operator-supplied signing authority captured in
  `irs-ssr-signing-authority.yaml` — Pub 1075 §7.1 requires the
  SSR to be certified by the agency head or designee; for a CSP
  filing on behalf of the agency, the operator records the
  signing authority's name, title, organization, and signed
  attestation in the YAML and Y.Y4 emits the certification
  block referencing it.

### 3.2 Out of scope

- **Actual transmission of the SSR to the IRS Office of
  Safeguards.** REO Rule 4 forbids the system from acting on
  behalf of the operator on any regulatory submission. The
  operator transmits the artifact pair via the IRS-designated
  channel (secure file transfer to the Office of Safeguards
  portal, or email to the assigned Safeguards Specialist, per
  the per-agency MOU) and records the transmission timestamp +
  acknowledgement receipt id in the tracker UI.
- **The actual 24-hour / 45-day §7.4 incident reporting clock.**
  That belongs to LOOP-G.G2 (Incident Communications Procedures).
  Y.Y4 cross-references but does not implement.
- **The Safeguard Procedures Report (SPR).** The SPR is filed
  once (and updated when procedures change), not annually. The
  SPR is out of LOOP-Y scope and would be a separate slice (a
  future Y.Y5 if scoped).
- **The Corrective Action Plan (CAP).** The CAP is filed after
  an on-site review identifies findings; it is owned by
  LOOP-A.A1 (POA&M) which already emits the CAP-equivalent
  artifact.
- **Recipient agencies that are not also Y.Y4's emitting CSP.**
  Y.Y4 emits the CSP-portion of the SSR — the agency-level SSR
  is the agency's responsibility, not the CSP's. Pub 1075
  §9.5.2 makes this distinction clear; Y.Y4's emitted SSR is
  the CSP's contribution that the recipient agency includes by
  reference in its own SSR filing.
- **FTI inventory enumeration at the row level.** Y.Y4 reports
  aggregate counts (number of FTI-tagged assets, by region, by
  type) from the existing `core/inventory.ts` data; row-level
  enumeration of every individual FTI record is the recipient
  agency's responsibility.
- **NIST 800-53 control catalog itself.** That belongs to
  existing core artifacts; Y.Y4 references control IDs only.
- **CJIS (Y.Y1/Y.Y2/Y.Y3 reuses the same conditional-applicability
  pattern but is otherwise independent).**

---

## 4. Inputs

TypeScript-form for the data structures Y.Y4 consumes:

```typescript
// From Y.Y3: the signed satisfaction-state envelope
interface IRS1075SatisfactionStateEnvelope {
  $schema: string;
  schema_version: string;
  envelope_id: string;
  emitted_at: string;                 // ISO 8601 UTC
  csp_name: string;
  policy_version: string;             // "Rev. 11-2021"
  policy_published_date: string;      // "2021-11-04"
  snapshot_id: string;                // points back to Y.Y3 catalog snapshot
  controls: ControlSatisfactionRow[];
  provenance: SatisfactionProvenance;
}

interface ControlSatisfactionRow {
  pub_1075_section_id: string;        // "9.3" | "9.4" | ...
  control_objective_id: string;       // "PUB1075-9.3-1"
  nist_800_53_r5_mapping: string[];   // ["AC-2", "AC-2(1)", ...]
  satisfaction_state:
    | "satisfied"
    | "satisfied-with-compensating-control"
    | "not-satisfied"
    | "not-applicable";
  evidence_paths: string[];           // pointers into Y.Y4-readable artifacts
  compensating_controls: CompensatingControlEntry[];
  last_assessed_date: string;         // YYYY-MM-DD
  assessor_id: string | null;         // null when not yet assessed
  scsem_reference: string | null;
}

interface CompensatingControlEntry {
  cc_id: string;                      // "FTI-CC-001"
  rationale: string;                  // verbatim from operator description
  approval_document_path: string;
  approval_date: string;
  approval_expiration_date: string;
}

// From existing core/inventory.ts: asset records (FTI-tagged subset)
interface FTITaggedAssetView {
  asset_id: string;
  asset_type: string;                 // "ec2:instance" | "rds:db" | "s3:bucket" | "compute.googleapis.com/Instance" | ...
  region: string;
  cloud_provider: "aws" | "gcp" | "azure";
  data_classes: string[];             // includes "FTI" when in scope
  data_residency_boundary: string;    // "US-only" | "US+EU-data-replicated" | ...
  protecting_controls: string[];      // 800-53 ids inherited from Y.Y3
  diagram_label?: string;
  is_in_us: boolean;
  encryption_at_rest: "kms-cmk" | "kms-aws-managed" | "kms-customer-managed" | "none";
  encryption_in_transit: "tls-1.2" | "tls-1.3" | "mixed" | "none";
}

// Operator-supplied: agency relationships
interface IRSAgencyRelationshipsYAML {
  relationships: AgencyRelationshipEntry[];
}

interface AgencyRelationshipEntry {
  agency_id: string;                  // operator-chosen stable id, e.g. "txdor-2026"
  agency_legal_name: string;          // "Texas Comptroller of Public Accounts"
  agency_short_name: string;          // "TxComp"
  agency_type: "federal" | "state" | "local" | "tribal";
  agency_ein: string | null;          // EIN if available
  agency_address: PostalAddress;
  agency_head: AgencyContactRecord;
  agency_safeguards_liaison: AgencyContactRecord;
  agency_it_security_officer: AgencyContactRecord;
  fti_purpose: string;                // verbatim from MOU
  fti_data_classes_received: string[]; // e.g. ["1040", "941", "W-2"]
  mou_identifier: string;
  mou_effective_from: string;         // YYYY-MM-DD
  mou_effective_until: string | null; // null = open-ended
  ssr_anniversary_date: string;       // MM-DD format; the annual SSR due date
  last_ssr_submission_date: string | null; // YYYY-MM-DD
  last_on_site_review_date: string | null;
  next_on_site_review_due: string | null;
  assigned_safeguards_specialist: SafeguardsSpecialistRecord;
  relationship_active: boolean;
  csp_subcontractors_in_scope: SubcontractorRecord[];
}

interface AgencyContactRecord {
  name: string;
  title: string;
  email: string;
  phone: string;
}

interface PostalAddress {
  line1: string;
  line2: string | null;
  city: string;
  state: string;
  postal_code: string;
  country: string;                    // "US"
}

interface SafeguardsSpecialistRecord {
  name: string;
  email: string;
  phone: string;
  region: string;
}

interface SubcontractorRecord {
  legal_name: string;
  role: string;
  fedramp_authorization: string | null;
  data_residency_country: string;
}

// Operator-supplied: signing authority
interface IRSSSRSigningAuthorityYAML {
  signatories: SigningAuthorityEntry[];
}

interface SigningAuthorityEntry {
  agency_id: string;                  // matches relationship's agency_id
  signatory_name: string;
  signatory_title: string;
  signatory_organization: string;
  signatory_email: string;
  signed_attestation_document_path: string;
  signed_attestation_document_sha256: string;
  signing_date: string;
  expiration_date: string;
}

// From tracker DB: incidents involving FTI (cross-reference only)
interface FTIIncidentRow {
  incident_id: string;
  detection_timestamp: string;
  resolution_timestamp: string | null;
  fti_involved: true;                 // filter predicate; all rows here have it
  fti_data_class: string;
  summary: string;
  tigta_notified_at: string | null;
  office_of_safeguards_notified_at: string | null;
  forty_five_day_report_emitted_at: string | null;
  reporting_year: number;
}

// From org-profile.yaml: applicability
interface OrgProfileFTIFields {
  receives_fti: boolean;
  in_scope_agencies: string[];        // agency_id list
}
```

---

## 5. Outputs

### 5.1 Canonical JSON SSR envelope (one per agency-relationship per reporting-year)

Schema reference: `https://cloud-evidence.example/schemas/irs-ssr-v1.json`.

```jsonc
{
  "$schema": "https://cloud-evidence.example/schemas/irs-ssr-v1.json",
  "schema_version": "1.0.0",
  "envelope_id": "irs-ssr-2026-txdor-2026",
  "envelope_kind": "irs-ssr-annual",
  "emitted_at": "2026-06-08T14:42:00Z",
  "authority": "26 USC §6103(p)(4)(E); IRS Publication 1075 Rev. 11-2021 §7.1",
  "reporting_year": 2026,
  "reporting_period_start": "2025-06-01",
  "reporting_period_end": "2026-05-31",
  "due_date": "2026-08-31",
  "csp_name": "<from org-profile.yaml>",
  "agency_relationship": {
    "agency_id": "txdor-2026",
    "agency_legal_name": "Texas Comptroller of Public Accounts",
    "agency_short_name": "TxComp",
    "agency_type": "state",
    "agency_address": { "line1": "...", "city": "Austin", "state": "TX", "postal_code": "78774", "country": "US" },
    "agency_head": { "name": "<yaml>", "title": "<yaml>", "email": "<yaml>", "phone": "<yaml>" },
    "agency_safeguards_liaison": { "name": "<yaml>", "title": "<yaml>", "email": "<yaml>", "phone": "<yaml>" },
    "agency_it_security_officer": { "name": "<yaml>", "title": "<yaml>", "email": "<yaml>", "phone": "<yaml>" },
    "fti_purpose": "<verbatim from MOU>",
    "fti_data_classes_received": ["1040", "941", "W-2"],
    "mou_identifier": "MOU-IRS-TXCOMP-2024-001",
    "mou_effective_from": "2024-07-01",
    "mou_effective_until": "2029-06-30",
    "ssr_anniversary_date": "08-31",
    "last_ssr_submission_date": "2025-08-21",
    "last_on_site_review_date": "2024-03-12",
    "next_on_site_review_due": "2027-03-12",
    "assigned_safeguards_specialist": { "name": "<yaml>", "email": "<yaml>", "phone": "<yaml>", "region": "Southwest" }
  },
  "fti_usage": {
    "purpose": "<verbatim from MOU>",
    "data_flows_diagram_path": "out/diagrams/fti-data-flow-txdor.svg",
    "programs_receiving_fti": ["sales-tax-audit", "income-tax-cross-reference"]
  },
  "fti_inventory_summary": {
    "fti_tagged_assets_total": 142,
    "by_region": [{ "region": "us-east-1", "asset_count": 87 }, { "region": "us-west-2", "asset_count": 55 }],
    "by_asset_type": [{ "asset_type": "ec2:instance", "count": 62 }, { "asset_type": "rds:db", "count": 18 }, { "asset_type": "s3:bucket", "count": 47 }, { "asset_type": "lambda:function", "count": 15 }],
    "by_data_residency_boundary": [{ "boundary": "US-only", "asset_count": 142 }],
    "by_encryption_at_rest": [{ "method": "kms-cmk", "count": 125 }, { "method": "kms-aws-managed", "count": 17 }],
    "by_encryption_in_transit": [{ "method": "tls-1.3", "count": 142 }],
    "out_of_us_asset_count": 0,
    "out_of_us_violations": []
  },
  "facility_and_physical_security": {
    "primary_data_centers": ["AWS us-east-1", "AWS us-west-2"],
    "physical_access_control_references": ["FedRAMP-Moderate ATO 2024-09-15", "AWS SOC-2 Type II 2025-Q4"],
    "visitor_management_evidence_paths": ["out/inventory-coverage.json#/physical_access"]
  },
  "security_program": {
    "policies_and_procedures_evidence_paths": ["out/policies/fti-handling-v1.2.pdf"],
    "annual_training_completion_pct": 100,
    "training_evidence_paths": ["tracker:disclosure-awareness-training:2026"],
    "incident_response_program_reference": "LOOP-G.G2 envelope id"
  },
  "computer_system_security_controls": [
    {
      "pub_1075_section_id": "9.3",
      "control_objective_id": "PUB1075-9.3-1",
      "control_title": "Access Control",
      "nist_800_53_r5_mapping": ["AC-2", "AC-2(1)", "AC-2(2)"],
      "satisfaction_state": "satisfied",
      "evidence_paths": ["out/findings.json#/IAM-AAM/aws", "out/findings.json#/IAM-AAM/gcp"],
      "compensating_controls": [],
      "last_assessed_date": "2026-05-29",
      "scsem_reference": "AWS-SCSEM-IA-2"
    },
    {
      "pub_1075_section_id": "9.4",
      "control_objective_id": "PUB1075-9.4-1",
      "control_title": "Multi-factor Authentication for Privileged Access",
      "nist_800_53_r5_mapping": ["IA-2(1)", "IA-2(2)", "IA-2(11)"],
      "satisfaction_state": "satisfied",
      "evidence_paths": ["out/findings.json#/IAM-MFA/aws"],
      "compensating_controls": [],
      "last_assessed_date": "2026-05-29",
      "scsem_reference": "AWS-SCSEM-IA-2(1)"
    }
  ],
  "recordkeeping": {
    "fti_access_log_retention_days": 2190,
    "fti_access_log_evidence_paths": ["out/findings.json#/MLA-LET/aws"],
    "fti_inventory_evidence_paths": ["out/inventory.json#/fti-tagged"]
  },
  "disposal": {
    "destruction_method": "NIST SP 800-88 Rev 1 purge",
    "destruction_records_evidence_path": "tracker:fti-disposal-records:2026",
    "certification_signatory": "<from yaml signing authority>"
  },
  "disclosure_awareness": {
    "initial_training_completion_pct": 100,
    "annual_refresher_completion_pct": 100,
    "training_curriculum_path": "out/training/disclosure-awareness-v3.0.pdf",
    "evidence_paths": ["tracker:disclosure-awareness-training:2026"]
  },
  "cloud_computing_arrangement": {
    "csp_legal_name": "<from org-profile.yaml>",
    "fedramp_authorization_type": "Moderate-20x",
    "fedramp_authorization_date": "2024-09-15",
    "package_id": "F1605033849",
    "cloud_regions_used": ["us-east-1", "us-west-2"],
    "data_residency_boundary": "US-only",
    "subcontractors": [
      { "legal_name": "Stripe Inc.", "role": "billing data sub-processor (no FTI access)", "fedramp_authorization": null, "data_residency_country": "US" }
    ]
  },
  "changes_since_last_ssr": {
    "new_contracts": [],
    "new_systems": ["fti-batch-import-2026"],
    "new_locations": [],
    "personnel_changes": ["new IT Security Officer effective 2026-02-01"],
    "control_state_deltas": []
  },
  "fti_incidents_during_period": [],
  "findings_from_prior_review": [
    {
      "scsem_reference": "AWS-SCSEM-AU-12",
      "finding_text": "Audit log retention <1 year",
      "status": "closed",
      "closed_date": "2025-11-04",
      "remediation_evidence_path": "out/findings.json#/MLA-LET/aws/run-20251104"
    }
  ],
  "certification": {
    "signatory_name": "<from yaml>",
    "signatory_title": "<from yaml>",
    "signatory_organization": "<from yaml>",
    "signed_attestation_document_path": "<from yaml>",
    "signed_attestation_document_sha256": "<from yaml>",
    "signing_date": "<from yaml>",
    "expiration_date": "<from yaml>"
  },
  "linked_poam_findings": [],
  "linked_g_g2_incidents": [],
  "provenance": {
    "emitter": "core/irs-ssr-emitter.ts",
    "emitter_version": "1.0.0",
    "emitted_at": "2026-06-08T14:42:00Z",
    "y_y3_envelope_id": "<satisfaction-state envelope id>",
    "inventory_run_id": "<from existing core/inventory.ts>",
    "signing_key_id": "ed25519-prod-2026",
    "signature": "<Ed25519 detached signature over canonical JSON>",
    "signature_alg": "Ed25519",
    "canonicalization": "rfc8785",
    "rfc3161_timestamp": "<base64 tsr>"
  }
}
```

### 5.2 OOXML .docx rendering — IRS Office of Safeguards SSR template layout

The `.docx` is composed via the same OOXML/zip-store pipeline that
LOOP-A.A4 + W.W3 use. The document structure mirrors Pub 1075
Rev. 11-2021 Appendix C's SSR template field enumeration:

- Cover page — Agency Identification (sec. 1)
- Section 2 — Authorized Agency Contacts
- Section 3 — FTI Usage
- Section 4 — Facility and Physical Security
- Section 5 — Equipment and Media
- Section 6 — Security Program (policies, procedures, training)
- Section 7 — Computer System Security (one sub-section per
  §9 family — IA/AC/AU/AT/CA/CM/CP/IR/MA/MP/PE/PL/PS/RA/SA/SC/SI/SR)
- Section 8 — Recordkeeping
- Section 9 — Disposal
- Section 10 — Disclosure Awareness
- Section 11 — Changes Since Last SSR
- Section 12 — Cloud Computing Arrangement (Y.Y4-specific; the
  field IRS Pub 1075 §9.5.2 and TIGTA 2024-30-016 require)
- Section 13 — FTI Incidents During Period (back-ref to G.G2)
- Section 14 — Findings From Prior Review (open + closed)
- Section 15 — Certification (signatory block + signature line)

Each section is rendered from the canonical JSON envelope using
the IRS-templated layout. Section 7 (Computer System Security) is
the largest — it iterates `computer_system_security_controls[]`
and renders one table row per control objective, with columns:
Pub 1075 §, Control Title, NIST 800-53 r5 mapping, Satisfaction
State, Last Assessed, Evidence Reference.

### 5.3 Signed envelope outer shape

```jsonc
{
  "envelope_id": "irs-ssr-2026-txdor-2026",
  "envelope_kind": "irs-ssr-annual",
  "schema": "https://cloud-evidence.example/schemas/irs-ssr-v1.json",
  "payload": { /* §5.1 body */ },
  "signing_key_id": "ed25519-prod-2026",
  "signature": "<Ed25519 detached signature over canonicalized payload>",
  "signature_alg": "Ed25519",
  "canonicalization": "rfc8785",
  "rfc3161_timestamp": "<base64 tsr>",
  "rfc3161_tsa_url": "http://timestamp.digicert.com",
  "emitter": "core/irs-ssr-emitter.ts",
  "emitter_version": "1.0.0",
  "emitted_at": "2026-06-08T14:42:00Z"
}
```

---

## 6. Algorithm / Steps

The Y.Y4 emitter is deterministic, REO-compliant, and idempotent
on the (agency_id, reporting_year) tuple — re-running for the same
tuple in the same run produces a byte-identical canonical JSON
payload (different signature timestamp + RFC 3161 tsr only).

```
function emitIRSSSRForAllRelationships(args: {
  orgProfilePath: string;
  agencyRelationshipsPath: string;
  signingAuthorityPath: string;
  ySatisfactionEnvelopePath: string;
  inventoryPath: string;
  reportingYear: number;
  runId: string;
}): { emitted: SSREmissionRecord[]; warnings: string[]; errors: string[] }

Steps:
  1. Load orgProfilePath. If receives_fti !== true: return
     { emitted: [], warnings: ["receives-fti-false-skipping"],
       errors: [] }.

  2. Load agencyRelationshipsPath. Filter for entries with
     relationship_active === true. If none: throw
     "coverage:fti-without-agency-relationship" — REO Rule 5
     violation; we cannot silently emit nothing when the operator
     says they receive FTI.

  3. Load signingAuthorityPath. For each active relationship,
     find the matching signatory by agency_id. If any active
     relationship lacks a signatory: throw
     "requires_operator_input:irs-ssr-signing-authority.yaml"
     naming the missing agency_id. Pub 1075 §7.1 mandates
     certification; an SSR without it is invalid.

  4. Load ySatisfactionEnvelopePath (Y.Y3 output). Verify the
     Ed25519 signature against the trusted signing-key list
     (existing core/signing.ts). Refuse to proceed on signature
     failure. Verify the envelope's policy_version matches the
     latest IRS-published version (Y.Y3 keeps this current); if
     stale by more than 365 days, emit a warning
     "y_y3_satisfaction_envelope_age_>365d" and continue.

  5. Load inventoryPath. Filter assets to those with
     data_classes[] including "FTI". Compute the
     fti_inventory_summary aggregate counts (by_region,
     by_asset_type, by_data_residency_boundary,
     by_encryption_at_rest, by_encryption_in_transit,
     out_of_us_asset_count).

  6. Read tracker DB for incidents involving FTI during the
     reporting period [reporting_period_start,
     reporting_period_end] (default = previous 12 months from
     emission_date). Each incident row populates one entry in
     fti_incidents_during_period[]. Cross-reference each
     incident's G.G2 envelope id; if the G.G2 envelope is
     missing, emit warning "missing_gg2_link_for_incident:<id>".

  7. For each active relationship:
       a. Compute due_date as the next anniversary of
          ssr_anniversary_date relative to today (america/new_york
          civil-time calendar). If today is past the anniversary
          and last_ssr_submission_date is null OR the prior
          submission's reporting_year < current reporting_year,
          due_date is the past anniversary (overdue).
       b. Compose computer_system_security_controls[] by walking
          the Y.Y3 satisfaction envelope's controls[] array and
          filtering to those with pub_1075_section_id starting
          with "9." (Computer Security Mandatory Requirements).
       c. Read findings_from_prior_review from the tracker DB
          `ssr_prior_findings` table for the (agency_id,
          reporting_year - 1) pair.
       d. Compose the agency_relationship block verbatim from
          the relationship entry.
       e. Compose the certification block from the matching
          signatory entry.
       f. Compose the cloud_computing_arrangement block from
          org-profile.yaml + the existing subprocessor data.
       g. Compose the canonical JSON envelope body.
       h. Canonicalize via RFC 8785 JCS.
       i. Sign via existing core/signing.ts with the operator's
          Ed25519 prod signing key.
       j. Request an RFC 3161 timestamp from the configured TSA
          (default http://timestamp.digicert.com; falls back to
          NIST's TSA). Failure to obtain a timestamp does NOT
          block emission but DOES emit a warning.
       k. Render the OOXML .docx via core/irs-ssr-docx.ts using
          the canonical JSON as input. The .docx is also signed
          (Ed25519 over the .docx bytes); the signature is
          attached as a sidecar `.docx.sig` file.
       l. Write the artifact pair to out/irs-ssr/<agency_id>/
          <reporting_year>/ — files:
            - ssr.json (canonical JSON)
            - ssr.json.sig (Ed25519 detached)
            - ssr.json.tsr (RFC 3161 base64)
            - ssr.docx
            - ssr.docx.sig
       m. Insert one row into tracker DB ssr_emissions:
          (agency_id, reporting_year, emitted_at, due_date,
          envelope_id, json_path, docx_path, status).
          Initial status = "emitted-not-transmitted".
       n. Schedule the tracker UI countdown for due_date.
       o. If due_date - now() < 14 days AND status is still
          "emitted-not-transmitted": route a slack notification
          to #irs-ssr-channel.
       p. If due_date < now() AND status is still "emitted-not-
          transmitted": route a PagerDuty notification to the
          `irs-ssr-overdue` service.
       q. Append a coverage_source entry for every emitted
          envelope field that wasn't sourced from the
          satisfaction envelope (the operator-supplied YAML
          fields and the inventory aggregates).

  8. Return { emitted, warnings, errors }.

REO-compliance invariants:
  - No field in the emitted JSON is defaulted. Every field is
    sourced from one of: Y.Y3 satisfaction envelope, inventory
    data, agency-relationships YAML, signing-authority YAML,
    org-profile YAML, tracker DB row, or computed from those
    sources.
  - No sample data. The schema permits empty arrays
    (fti_incidents_during_period[]: [] is valid). The schema
    does NOT permit example string values like "Sample Agency".
  - No silent failure. Missing operator input throws
    requires_operator_input. Missing signature on Y.Y3 envelope
    throws integrity error.
  - check:provenance recognizes the irs-ssr emitter and reads
    coverage_source for every emitted field.
```

---

## 7. Files to create / modify

Absolute paths under `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/`:

| Path | Purpose |
|---|---|
| `core/irs-ssr-emitter.ts` | The top-level emitter. Implements the algorithm in §6. Exports `emitIRSSSRForAllRelationships(args)`. |
| `core/irs-ssr-docx.ts` | OOXML `.docx` renderer. Walks the canonical JSON envelope and produces a `.docx` matching the IRS template layout in §5.2. |
| `core/irs-ssr-canonical-json.ts` | RFC 8785 JCS canonicalizer specific to the SSR envelope shape; thin wrapper over `core/jcs.ts` with SSR-schema validation. |
| `core/irs-ssr-due-date-clock.ts` | Computes per-agency due dates from `ssr_anniversary_date` + `last_ssr_submission_date` against america/new_york civil time. Handles leap-day anniversaries (02-29 → 02-28 in non-leap years) per IRS Office of Safeguards guidance. |
| `core/irs-agency-relationships-loader.ts` | YAML loader with strict-schema validation for `irs-agency-relationships.yaml`. Rejects unknown fields. |
| `core/irs-ssr-signing-authority-loader.ts` | YAML loader with strict-schema validation for `irs-ssr-signing-authority.yaml`. |
| `tracker/db/migrations/0055_irs_ssr.sql` | Adds `ssr_relationships`, `ssr_emissions`, `ssr_due_clocks`, `ssr_acknowledgements`, `ssr_prior_findings` tables. Indexes on `(agency_id, reporting_year)` and `due_date`. |
| `tracker/server/routes/irs-ssr.ts` | REST endpoints: `GET /api/irs-ssr/relationships`, `GET /api/irs-ssr/emissions`, `GET /api/irs-ssr/due-clocks`, `POST /api/irs-ssr/emissions/:id/transmit` (records operator transmission), `POST /api/irs-ssr/emissions/:id/acknowledge` (records IRS acknowledgement). |
| `tracker/ui/irs-ssr-status-pane.tsx` | React component at route `/irs-ssr`. Renders the per-agency table with countdown clocks, latest emission link, transmission status, acknowledgement status. |
| `schemas/irs-ssr-v1.json` | Canonical JSON schema for the SSR envelope. Strict (additionalProperties: false at every level). |
| `templates/irs-ssr-docx/*.xml` | OOXML fragments for the `.docx` template (header, footer, section dividers, table styles). |
| `org-profile.example.yaml` | Annotated example showing the `receives_fti: true` + `in_scope_agencies` block. |
| `irs-agency-relationships.example.yaml` | Annotated example with one fully-populated agency relationship. |
| `irs-ssr-signing-authority.example.yaml` | Annotated example with one signatory entry. |
| `test/irs-ssr-emitter.test.ts` | 16+ unit + integration tests covering the algorithm. |
| `test/irs-ssr-docx.test.ts` | Renderer tests with `.docx` byte-level golden files. |
| `test/irs-ssr-due-date-clock.test.ts` | Due-date computation edge cases including leap-day anniversaries. |
| `test/fixtures/irs-ssr/y-y3-satisfaction-envelope.signed.json` | Test fixture: a signed Y.Y3 satisfaction envelope with controls covering every §9 family. |
| `test/fixtures/irs-ssr/agency-relationships.yaml` | Test fixture: three active agency relationships. |
| `test/fixtures/irs-ssr/signing-authority.yaml` | Test fixture: one signatory per active relationship. |
| `docs/loops/LOOP-Y-SPEC.md` | Add the Y.Y4 status row (status: proposed → done) when the slice ships. |
| `docs/STATUS.md` | Add the Y.Y4 status row. |
| `CHANGELOG.md` | Append the "Added — LOOP-Y.Y4" entry on completion. |

---

## 8. Test specifications

Minimum 16 tests. Every test references a real fixture; no
inline sample data inside test files.

| id | scenario | fixture | expected | acceptance |
|---|---|---|---|---|
| t01 | happy path — single active agency relationship, all controls satisfied, signatory present | y-y3-satisfaction-envelope.signed.json + agency-relationships.yaml (1 active entry) + signing-authority.yaml (1 entry) | one envelope emitted under out/irs-ssr/txdor-2026/2026/ssr.json; passes schema validation; signature verifies | byte-identical re-run produces same canonical JSON payload (signature timestamp may differ) |
| t02 | happy path — three active agencies, three signatories | as t01 but with 3 entries | three envelopes emitted; three signed `.docx` files; three tracker DB rows | each envelope's agency_relationship.agency_id matches its directory |
| t03 | conditional skip — `receives_fti: false` in org-profile | org-profile.example.yaml with `receives_fti: false` | zero emissions; warning `receives-fti-false-skipping`; no errors | exit code 0 |
| t04 | conditional hard error — `receives_fti: true` but no active relationship | org-profile with `receives_fti: true` + agency-relationships.yaml with all `relationship_active: false` | error `coverage:fti-without-agency-relationship`; zero emissions | non-zero exit code |
| t05 | missing signatory — operator forgot to add a signatory for an active relationship | agency-relationships.yaml with txdor-2026 active + signing-authority.yaml empty | error `requires_operator_input:irs-ssr-signing-authority.yaml:txdor-2026`; zero emissions for txdor-2026 | OperatorInputRequired error type thrown |
| t06 | tampered Y.Y3 envelope — Ed25519 signature does not verify | y-y3-satisfaction-envelope.tampered.json | error `y_y3_signature_verification_failed`; zero emissions | refuses to proceed past step 4 |
| t07 | stale Y.Y3 envelope — policy_version is 18 months old | y-y3-satisfaction-envelope.stale.json (signature still verifies) | warning `y_y3_satisfaction_envelope_age_>365d`; emission still proceeds | warning surfaces in tracker DB row |
| t08 | inventory aggregate computation — 142 FTI-tagged assets across 2 regions and 4 types | inventory.fti.json | fti_inventory_summary block matches the fixture aggregate counts exactly | by_region, by_asset_type, by_data_residency_boundary, by_encryption_* arrays match |
| t09 | out-of-US violation surfaced | inventory.fti-with-eu.json (one asset in eu-west-1) | out_of_us_asset_count = 1; out_of_us_violations[] populated with the offending asset_id | violation appears in §12 cloud_computing_arrangement notes |
| t10 | due-date computation — anniversary in the future | agency-relationship with ssr_anniversary_date 08-31, today 2026-06-08 | due_date = 2026-08-31; days_to_deadline = 84 | tracker DB ssr_due_clocks row matches |
| t11 | due-date computation — overdue (anniversary already passed, no prior submission this year) | agency-relationship with ssr_anniversary_date 04-30, today 2026-06-08, no 2026 prior submission | due_date = 2026-04-30; overdue = true; tracker_status = overdue | PagerDuty notification routed to `irs-ssr-overdue` service |
| t12 | due-date computation — leap-day anniversary | agency-relationship with ssr_anniversary_date 02-29, today 2027-01-15 | due_date = 2027-02-28 (per IRS Office of Safeguards leap-day-rollback guidance); rollback recorded in provenance | provenance.leap_day_rolled_back = true |
| t13 | cross-reference to G.G2 — one FTI incident during the period | tracker DB incidents.json with 1 row flagged fti_involved:true | fti_incidents_during_period[] has 1 entry referencing the incident's G.G2 envelope id | warning is empty (G.G2 link present) |
| t14 | cross-reference broken — fti_involved incident lacks G.G2 envelope link | tracker DB incidents.json with 1 row, no G.G2 envelope | warning `missing_gg2_link_for_incident:<id>` | emission still proceeds |
| t15 | findings from prior review — 2 closed + 1 open from 2025 | tracker DB ssr_prior_findings rows for txdor-2026 reporting_year=2025 | findings_from_prior_review[] has 3 entries with correct status + close dates | open finding linked to its POA&M id |
| t16 | RFC 3161 timestamp failure | mock TSA returns 503 | warning `rfc3161_timestamp_unavailable`; envelope emitted without `rfc3161_timestamp` field; signature still verifies | re-run with TSA available adds the timestamp without re-signing the canonical payload |
| t17 | .docx renderer — single-agency happy path | t01 fixtures | out/irs-ssr/txdor-2026/2026/ssr.docx exists; can be opened by Microsoft Word; contains 15 sections; section 7 has one row per §9 control | LibreOffice headless validation passes |
| t18 | .docx renderer — section 7 table renders one row per control | as t01 with 24 §9 control objectives | section 7's table has 24 data rows + 1 header row | each row's NIST 800-53 mapping column lists the IDs |
| t19 | idempotent emit — running the emitter twice in the same minute | t01 fixtures | second run replaces the artifact pair atomically; tracker DB ssr_emissions row's emitted_at is updated; envelope_id is stable on the (agency_id, reporting_year) tuple | canonical JSON payload is byte-identical between runs |
| t20 | check:provenance integration | t01 emission | check:provenance returns 0; every operator-sourced field has a coverage_source entry | scripts/check-provenance.mjs exit code = 0 |

Test infrastructure note: tests use the real Ed25519 signer (no
mocked signing) and the real OOXML/zip writer (no mocked .docx
emitter). The RFC 3161 TSA is the one wire-level mock (a
recorded TSA response replayed via nock); the timestamp
verification path is real.

---

## 9. Risks

| risk | likelihood | impact | mitigation |
|---|---|---|---|
| **R1 — Pub 1075 revision changes mid-cycle.** The IRS publishes new Pub 1075 revisions every 2-4 years; a revision can introduce new §9 control objectives or change the SSR field set, making prior-year envelopes structurally incompatible with the current template. | medium | high | Y.Y4 reads the policy_version + policy_published_date from the Y.Y3 satisfaction envelope and emits both fields verbatim into the SSR envelope. When the IRS publishes a new revision, Y.Y3's catalog snapshot updates; Y.Y4 detects the version delta and emits a warning `pub_1075_version_changed_since_last_ssr:<prior>→<current>` so the operator knows to review the new fields. The .docx template is version-keyed so two revisions can coexist (out of scope to back-fill prior-year SSRs under a new revision). |
| **R2 — Operator misidentifies which agencies are FTI-recipient.** A CSP that serves a state revenue department may not realize a downstream prime contractor's agency is also an FTI recipient; an active agency relationship that isn't enumerated in `irs-agency-relationships.yaml` means no SSR is emitted, which is a §6103(p)(4)(E) compliance failure. | medium | high | Y.Y4 cross-references the inventory's FTI-tagged-asset count against the enumerated agencies' `fti_data_classes_received[]` arrays — if the asset count is >0 but no agency claims that data class, Y.Y4 emits a warning `inventory_fti_assets_without_claiming_agency` and refuses to proceed until the operator either re-tags the assets or adds the missing agency relationship. The `coverage:fti-without-agency-relationship` hard error (t04) is the second layer of protection. |
| **R3 — Signatory authority gap.** Pub 1075 §7.1 requires the SSR to be certified by the agency head or designee. For a CSP filing on behalf of the agency, the operator must obtain a delegated signing authority — that delegation is itself an MOU-level commitment and may not be in place when the SSR is due. | low | high | The `irs-ssr-signing-authority.yaml` schema requires a `signed_attestation_document_sha256` field; Y.Y4 verifies the document exists at `signed_attestation_document_path` and the sha256 matches. The operator must produce the signed delegation document (out-of-band, paper) before Y.Y4 will emit. The missing-signatory `requires_operator_input` error (t05) surfaces this gap 90 days before the due date so the operator has time to obtain the delegation. |
| **R4 — On-site review findings unresolved at SSR time.** If the prior triennial on-site review identified findings that are still open at SSR time, the SSR must report them. If the tracker DB's `ssr_prior_findings` table is incomplete, the SSR omits known open findings, which is a §6103(p)(4) reporting failure. | medium | medium | Y.Y4 reads the `ssr_prior_findings` table for (agency_id, reporting_year - 1). The tracker UI surfaces a manual workflow during the post-on-site-review cycle (out of LOOP-Y scope; owned by the existing tracker UI) where the operator records every finding. Y.Y4 emits a warning `prior_review_findings_table_empty_or_unconfirmed` if the table is empty for a relationship that has a `last_on_site_review_date` set — this catches the data-entry-skipped case. |
| **R5 — RFC 3161 TSA availability.** RFC 3161 timestamps are emitted via the configured TSA (default `http://timestamp.digicert.com`); if the TSA is unavailable at emit time, the envelope can still be emitted (Ed25519-signed) but without a third-party timestamp. The IRS does not currently require RFC 3161 timestamps but the lack of a timestamp degrades the audit trail. | medium | low | Y.Y4 retries the TSA call with exponential backoff (3 attempts: 0s, 5s, 30s); on persistent failure emits `rfc3161_timestamp_unavailable` warning and continues. A nightly cron job re-attempts RFC 3161 timestamping on any envelope where `rfc3161_timestamp` is null and `emitted_at < now() - 1 day`; the timestamp is attached without re-signing the canonical payload (RFC 3161 tokens are detached). |
| **R6 — Multi-agency overlap of the same FTI asset.** A single FTI-tagged asset (e.g., a database) may serve more than one recipient agency. The inventory's `data_classes[]` array carries "FTI" once; the inventory model does not currently track *which* agencies an asset is FTI-tagged for. This is a Y.Y4-level data-model gap. | low | medium | The Y.Y4 schema accepts an optional `fti_for_agencies[]` field per inventory asset (added in an inventory-model extension when Y.Y4 ships). When absent, Y.Y4 assumes the asset is FTI-tagged for *all* active agency relationships and includes it in every per-agency SSR's `fti_inventory_summary`. When present, Y.Y4 filters per-agency. The operator-supplied field surfaces via a tag like `fti_for_agencies = "txdor-2026,nyc-tax-2026"` on the cloud asset. |

---

## 10. Open questions

1. **OQ-1 — Does the IRS accept a CSP's `.docx` directly, or must the recipient agency re-render it on agency letterhead?** Pub 1075 §7.1 says the SSR is filed by the agency; §9.5.2 says the agency must report the CSP arrangement. The CSP-emitted `.docx` is intended as a transmissible artifact the agency includes by reference or attaches. The current implementation emits a "CSP contribution to the agency's SSR" — the agency files its own SSR with this attached. If a future IRS Office of Safeguards guidance clarifies that the CSP can file directly (parallel to the FedRAMP submission model), Y.Y4's `.docx` template can be relabeled accordingly. Tracking under `docs/loops/LOOP-Y-RISKS.md`.

2. **OQ-2 — Reporting period boundaries: calendar-year vs anniversary-of-MOU.** Pub 1075 §7.1 says "annually" with the due date on the anniversary of the prior submission, but does not specify the reporting period. Y.Y4's default `reporting_period_start = previous_anniversary` and `reporting_period_end = current_anniversary - 1`. If the operator's agency MOU specifies a fiscal-year reporting period instead, the operator overrides via `agency-relationships.yaml.reporting_period_override`. Need to confirm with one or two state revenue agencies which convention they use.

3. **OQ-3 — Cross-agency aggregate metrics.** Should Y.Y4 emit a *single* aggregate envelope summarizing all the per-agency SSRs (FTI assets across all agencies, total incident count, total training completion) in addition to the per-agency envelopes? The per-agency envelope is the regulatory deliverable; an aggregate would be useful for internal governance and the tracker UI's roll-up view. Provisionally yes, but emitted under a different envelope_kind (`irs-ssr-csp-aggregate`) and NOT transmitted to the IRS. Tracked as a follow-up; not blocking Y.Y4's initial ship.

4. **OQ-4 — Office of Safeguards portal acknowledgement scraping.** The current `POST /api/irs-ssr/emissions/:id/acknowledge` endpoint requires the operator to paste the acknowledgement receipt id from the portal. Could the system poll the portal API and ingest acknowledgements automatically? The portal requires agency credentials; REO Rule 4 forbids the system from authenticating as the operator to a Federal portal. Defer indefinitely.

5. **OQ-5 — Multi-CSP cooperation.** If the recipient agency uses multiple CSPs (e.g., AWS for primary + Azure for DR), does each CSP emit its own Y.Y4 contribution? Yes — each CSP runs its own Y.Y4 emitter against its own inventory + Y.Y3 satisfaction state. The recipient agency stitches them into a single SSR. Y.Y4 emits the CSP name in `cloud_computing_arrangement.csp_legal_name` so the agency can identify which CSP contributed each artifact.

---

## 11. REQUIRES-OPERATOR-INPUT

| field | consumer artifact | where the operator provides it | required? | validation |
|---|---|---|---|---|
| `receives_fti` | applicability gate | `org-profile.yaml` | yes (boolean) | strict YAML schema; defaults absent |
| `in_scope_agencies[]` | per-agency emission set | `org-profile.yaml` | yes when receives_fti = true | every entry must match an agency_id in irs-agency-relationships.yaml |
| `agency_legal_name`, `agency_short_name`, `agency_type`, `agency_address`, `agency_ein` | SSR §1 Agency Identification | `irs-agency-relationships.yaml` | yes per active relationship | EIN format ##-####### when provided |
| `agency_head`, `agency_safeguards_liaison`, `agency_it_security_officer` | SSR §2 Authorized Agency Contacts | `irs-agency-relationships.yaml` | yes per active relationship | name + email + phone all required |
| `fti_purpose` | SSR §3 FTI Usage | `irs-agency-relationships.yaml` | yes per active relationship | verbatim from MOU; min 50 chars |
| `fti_data_classes_received[]` | SSR §3 FTI Usage | `irs-agency-relationships.yaml` | yes per active relationship | every entry must be a recognized IRS form/data-class id |
| `mou_identifier`, `mou_effective_from`, `mou_effective_until` | SSR §3 FTI Usage | `irs-agency-relationships.yaml` | yes per active relationship | YYYY-MM-DD dates; effective_until optional |
| `ssr_anniversary_date` | due-date clock | `irs-agency-relationships.yaml` | yes per active relationship | MM-DD format |
| `last_ssr_submission_date` | due-date overdue computation | `irs-agency-relationships.yaml` | optional (null on first emission) | YYYY-MM-DD |
| `last_on_site_review_date`, `next_on_site_review_due` | SSR §14 Findings From Prior Review | `irs-agency-relationships.yaml` | optional | YYYY-MM-DD |
| `assigned_safeguards_specialist` | SSR §15 Certification + ack workflow | `irs-agency-relationships.yaml` | yes per active relationship | name + email + phone required |
| `csp_subcontractors_in_scope[]` | SSR §12 Cloud Computing Arrangement | `irs-agency-relationships.yaml` | yes (may be empty array) | legal_name + role + data_residency_country required |
| `signatory_name`, `signatory_title`, `signatory_organization`, `signatory_email` | SSR §15 Certification | `irs-ssr-signing-authority.yaml` | yes per active relationship | matched to relationship by agency_id |
| `signed_attestation_document_path`, `signed_attestation_document_sha256`, `signing_date`, `expiration_date` | SSR §15 Certification | `irs-ssr-signing-authority.yaml` | yes per active relationship | document must exist; sha256 must match; expiration_date must be > due_date |
| `reporting_period_override` | SSR header (period start/end) | `irs-agency-relationships.yaml` | optional (defaults to anniversary-to-anniversary) | object `{ start_iso, end_iso }` with end > start |
| `fti_for_agencies[]` cloud asset tag | inventory FTI-per-agency filtering | cloud resource tags on FTI assets | optional (defaults to all-agency) | comma-separated agency_ids |
| `transmission_timestamp`, `office_of_safeguards_receipt_id` | post-emission audit trail | tracker UI `POST /api/irs-ssr/emissions/:id/transmit` | yes (recorded after operator transmits) | timestamp ISO 8601; receipt id verbatim from portal |
| `acknowledgement_timestamp`, `acknowledgement_safeguards_specialist`, `acknowledgement_outcome` (accepted-clean \| accepted-with-deficiencies \| rejected) | post-emission audit trail | tracker UI `POST /api/irs-ssr/emissions/:id/acknowledge` | yes (recorded after IRS ack) | outcome enum strict |
| `ssr_prior_findings` rows | SSR §14 Findings From Prior Review | tracker UI manual entry post-on-site-review | yes when last_on_site_review_date is set | finding text + scsem_reference + status |

---

## 12. Implementation log slot

(Update this table at every meaningful milestone per
`docs/IMPLEMENTATION-LOG-TEMPLATE.md` §3.)

| date | event | session/wf id | summary | commit | status |
|---|---|---|---|---|---|
| 2026-06-08 | spec proposed | wf-uvxyz-gapfill | Specification authored via gap-fill workflow | TBD | — |

---

## 13. Completion checklist

Y.Y4 ships ONLY when every step of
`docs/SLICE-COMPLETION-PROCEDURE.md` is executed atomically with
the commit. The verbatim 7-step procedure (re-quoted here so a
future session can execute Y.Y4's completion without leaving
this file):

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
> git add cloud-evidence/docs/STATUS.md cloud-evidence/docs/loops/LOOP-Y-SPEC.md
> git commit --amend --no-edit
> ```
>
> ### Step 7 — Push
> ```bash
> git push origin main
> ```

### Step 8 — Slice-completion directive (Y.Y4-specific)

Per the CLAUDE.md slice-completion directive (re-quoted from
`cloud-evidence/CLAUDE.md` line 230):

> 1. Update STATUS.md status row for the slice (commit hash, status -> 'done', last_updated).
> 2. Update the loop SPEC status table (commit hash, status -> 'done').
> 3. Append a CHANGELOG.md entry (date, slice ID, summary, commit).
> 4. Commit with the slice ID in the subject line + Co-Authored-By trailer.
> 5. Push to origin/main.
> 6. If a new permanent reference document was created, add it to this reading list.
> 7. Verify with 'git log --oneline -3' that the commit landed before declaring the slice closed.
>
> Failure to do steps 1-7 means the slice is NOT closed.

Y.Y4-specific verification checklist (in addition to the above):

- [ ] `core/irs-ssr-emitter.ts` exists with `emitIRSSSRForAllRelationships(args)` exported.
- [ ] `core/irs-ssr-docx.ts` produces a `.docx` that LibreOffice headless opens without warnings.
- [ ] `core/irs-ssr-due-date-clock.ts` covers leap-day anniversaries (t12) and overdue computation (t11).
- [ ] `schemas/irs-ssr-v1.json` exists; `additionalProperties: false` at every level.
- [ ] `tracker/db/migrations/0055_irs_ssr.sql` applies cleanly on a fresh sqlite DB.
- [ ] `tracker/server/routes/irs-ssr.ts` exposes the four REST endpoints listed in §7.
- [ ] `tracker/ui/irs-ssr-status-pane.tsx` renders the per-agency table at `/irs-ssr` and updates the countdown every minute via SSE.
- [ ] At least 16 tests in `test/irs-ssr-emitter.test.ts` + `test/irs-ssr-docx.test.ts` + `test/irs-ssr-due-date-clock.test.ts` all pass.
- [ ] `npm run lint:no-stubs` matches no TODO/FIXME/sample/placeholder in any new production path.
- [ ] `npm run check:provenance` exit code = 0; every operator-sourced field in the SSR envelope has a `coverage_source` registry entry.
- [ ] `npm run check:coverage-regression` shows no decrease in fill rates from the prior `main`.
- [ ] One golden-fixture emission lives under `test/fixtures/irs-ssr/expected/` and the canonical JSON payload is byte-identical between two emitter invocations against the same input (the t19 idempotence test).
- [ ] `docs/loops/LOOP-Y-RISKS.md` updated with any new risks surfaced during implementation (per §9 + the in-flight discoveries).
- [ ] `docs/slices/Y/Y.Y4.md` frontmatter updated: `status: done`, `commit: <hash>`, `completed_date: <YYYY-MM-DD>`, `last_updated: <YYYY-MM-DD>`.
- [ ] §12 Implementation log appended with the final entry per `docs/IMPLEMENTATION-LOG-TEMPLATE.md` §4 example format.
- [ ] CHANGELOG.md `Unreleased` section has the `### Added — LOOP-Y.Y4: IRS Safeguard Security Report (SSR) Annual Emitter` entry at the top.
- [ ] `git log --oneline -3` confirms the commit landed on origin/main before Y.Y4 is declared closed.

Y.Y4 has NO downstream `blocks:`. Closing Y.Y4 unblocks Z (international equivalence) only insofar as the FIFTH-PASS audit confirms LOOP-Y is complete; Z does not directly depend on Y.Y4. The FIFTH-PASS audit's LOOP-Y verification table reads Y.Y4's status row from STATUS.md.
