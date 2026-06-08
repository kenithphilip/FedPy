---
slice_id: Y.Y3
title: IRS Publication 1075 (Rev. 11-2021) Control Catalog — typed loader, canonical JSON, NIST 800-53 Rev 4/Rev 5 dual cross-walk, IRS SCSEM cross-walk
loop: Y
status: proposed
commit: TBD
completed_date: —
depends_on:
  - LOOP-A.A5                                 # signEnvelope() — Ed25519 + RFC 3161
  - LOOP-V (BAA primitive)                    # core/baa-signing.ts reused for Pub 1075 §6.3 contractor agreements
  - existing core/control-benchmark.ts        # NIST 800-53 Rev 5 cross-walk substrate
  - operator-downloaded IRS Pub 1075 PDF      # docs/sources/irs-p1075-rev11-2021.pdf (HTTP 403 to anonymous fetch)
  - operator-downloaded SCSEM PDFs            # docs/sources/scsem/ (per-platform IRS Office of Safeguards checklists)
blocks:
  - Y.Y4                                       # SSR emitter reads the catalog + SCSEM cross-walk to compose §3 Control Implementation Status
estimated_effort: medium (~5-7 working days for single implementer; ~3d catalog extractor, ~2d typed loader + tests, ~1d SCSEM cross-walk, ~1d signed-snapshot pipeline + REQUIRES-OPERATOR-INPUT scaffolding)
last_updated: 2026-06-08
applicable_conditional: false
condition: |
  Y.Y3 ships unconditionally **within the IRS-1075 path of LOOP-Y**.
  The IRS-1075 path itself is conditional on
  `org-profile.yaml: serves_federal_tax_information: true` — see
  LOOP-Y-SPEC.md §1 for the conditional-activation rules. When the
  IRS-1075 path is active, Y.Y3 is a hard prerequisite for Y.Y4
  (the SSR emitter cannot compose §3 Control Implementation Status
  without the typed catalog). The catalog itself does not depend on
  whether the CSP currently holds FTI — it is a regime-wide
  reference artifact that 3PAOs, the operator's Authorizing
  Official, and the IRS Office of Safeguards can all read.
trigger_flag: "--sector-overlay"
trigger_env: CLOUD_EVIDENCE_SECTOR_OVERLAY
---

# Y.Y3 — IRS Publication 1075 (Rev. 11-2021) Control Catalog

> This slice ingests and canonicalises the IRS Office of Safeguards'
> mandatory security baseline for any agency or contractor that
> receives Federal Tax Information (FTI) under 26 U.S.C. §6103. It
> emits a typed TypeScript loader (`core/irs-1075-catalog.ts`), a
> deterministic shell-out extractor (`scripts/extract-irs-1075.mjs`),
> an Ed25519-signed canonical-JSON snapshot
> (`data/irs-1075-catalog.json`), and a parallel cross-walk file
> (`data/irs-scsem-matrix.json`) that aligns each Pub 1075 §9 control
> requirement to its corresponding IRS Safeguards Computer Security
> Evaluation Matrix (SCSEM) check IDs. The slice is a **catalog
> slice**: it does NOT evaluate evidence, does NOT scan cloud
> resources, and does NOT touch the tracker DB at runtime. It produces
> the reference data Y.Y4 (the annual Safeguard Security Report
> emitter) reads to compose the SSR's §3 Control Implementation
> Status table.
>
> The slice is authored in clean-room fashion: any future Claude or
> human session can execute Y.Y3 end-to-end by reading ONLY this
> file plus the LOOP-Y-SPEC.md cross-references it cites. The
> Real-Evidence-Only standard (CLAUDE.md) governs every byte:
> shall-statements are quoted verbatim from the IRS-published PDF
> the operator has downloaded to `docs/sources/`; no shall-statement
> is paraphrased; no NIST mapping is invented; no SCSEM ID is
> guessed. When the extractor cannot find a section in the PDF, it
> emits a `provenance:irs-1075-section-not-found` diagnostic and
> exits non-zero rather than producing a partial catalog.

## 1. Mission

Y.Y3 produces the **canonical, typed, signed reference catalog** of
the IRS Publication 1075 (Rev. 11-2021) security control requirements
that all four other LOOP-Y artifacts and any 3PAO reviewing FTI
safeguards depend on. The catalog is the single source of truth for:

1. **What Pub 1075 actually requires.** Every "shall" statement in
   §§1, 4, 5, 6, 7, 8, 9, and 10 of the IRS-published PDF is parsed,
   verbatim-quoted, given a stable identifier of the form
   `<section_id>-<ordinal>` (e.g. `9.1-1`, `9.3-1`), and tagged with
   the section number and title. The shall-statement text is never
   paraphrased; the catalog's `text` field carries the IRS's words
   character-for-character (with whitespace normalised per RFC 8785
   for signing stability). When the IRS publishes Rev. 11-2024 or
   Rev. 11-2025, the extractor re-runs against the new PDF and a new
   snapshot ships side-by-side with the old; the orchestrator
   selects the active version via operator config.
2. **How Pub 1075 maps to NIST 800-53.** Pub 1075's Appendix B
   historically cross-walked to NIST 800-53 Rev 4. The Rev. 11-2021
   release introduced selective Rev 5 mappings for new control
   families while retaining Rev 4 mappings for legacy families (per
   §9.3 transitional language). Y.Y3 emits **both mappings in
   parallel** — every shall-statement carries
   `nist_800_53_r4_mapping[]` AND `nist_800_53_r5_mapping[]`. When
   only one mapping is published, the other is the empty array (not
   `null`, not a guess). This avoids the false-positive coverage
   claim that conflating r4 and r5 produces.
3. **Which SCSEM checks exercise each control.** The IRS Office of
   Safeguards publishes platform-specific SCSEMs (Windows Server,
   RHEL, SQL Server, Oracle, VMware, AWS, Azure, Microsoft 365).
   Each SCSEM contains numbered checks of the form
   `<platform>-<family>-<n>` (e.g. `SCSEM-AWS-AC-2.1`). Y.Y3
   cross-walks each Pub 1075 §9 shall-statement to the SCSEM check
   IDs that exercise it. The cross-walk is emitted as
   `data/irs-scsem-matrix.json` and is consumed by Y.Y4 (to enumerate
   "Evidence Source" rows in the SSR §3 control-implementation
   table) and by 3PAO assessment workflows.
4. **What the statutory anchor is.** Each shall-statement carries a
   `statutory_anchor` field naming the IRC §6103 subsection it
   implements (where applicable). For example, the recordkeeping
   shall-statements in §4 anchor to `IRC §6103(p)(4)(A)(i)`. The
   storage shall-statements in §5.1.1 anchor to
   `IRC §6103(p)(4)(A)(ii)`. The access-restriction shall-statements
   in §5 anchor to `IRC §6103(p)(4)(A)(iii)`. The catalog never
   invents anchors; when a shall-statement has no clear statutory
   pin, the field is the empty string and the catalog tags
   `anchor_provenance: "secretary-prescribed"` per §6103(p)(4)(A)(iv).
5. **What the federal/state SSR deadlines are.** §7's annual SSR
   requirement is a special shall-statement that carries
   `frequency: "annual"`, `federal_due_date: "January 31"`, and a
   pointer to `consumer_slice: "Y.Y4"`. Y.Y4 reads this field to
   schedule the SSR build and to emit the tracker UI countdown
   timer.

Y.Y3's outputs are immutable per snapshot: once
`data/irs-1075-catalog.json` is signed and the SHA-256 of the source
PDF is recorded in the provenance block, re-running the extractor
against the same PDF produces a byte-identical snapshot (canonical
JSON via RFC 8785 + deterministic ordering). When the IRS publishes
a new revision, a NEW snapshot file is written (e.g.
`data/irs-1075-catalog-rev11-2024.json`) and the old snapshot is
preserved for audit-trail continuity. The typed loader exposes both
via `loadCatalog({version})`.

## 2. Authoritative sources

Every URL accessed 2026-06-07 (loop-spec authoring date) and re-validated 2026-06-08
(slice-spec authoring date). Where the live Government source returned
a non-200 to anonymous fetches (notably the IRS PDF endpoints, which
return HTTP 403 to non-browser User-Agents and HTTP 200 to interactive
browsers), the implementer downloads the artifact to
`cloud-evidence/docs/sources/` and the extractor parses from the
local copy. Verbatim quotes below are re-keyed from the
operator-downloaded copies.

### 2.1 IRS Publication 1075 (Rev. 11-2021) — cover-page authority

URL: https://www.irs.gov/pub/irs-pdf/p1075.pdf (accessed 2026-06-07;
HTTP 403 to WebFetch; operator downloads to
`docs/sources/irs-p1075-rev11-2021.pdf`).

Mirror URL: https://www.irs.gov/pub/irs-utl/p1075.pdf (accessed
2026-06-07; same 403 behaviour to anonymous fetch).

**Cover-page authority statement (verbatim, re-quoted from
operator-downloaded PDF, cover page):**

> "This document, Publication 1075, provides the requirements an
> Agency must comply with to ensure that policies, practices,
> controls, and safeguards employed adequately protect the
> confidentiality of FTI. [...] All recipients of FTI must comply
> with the requirements within this publication."

The cover page also pins the document's authoring period
("Rev. 11-2021") and identifies the Office of Safeguards within the
IRS Governmental Liaison, Disclosure and Safeguards (GLDS) function
as the publisher. The Y.Y3 catalog records both as top-level
metadata fields (`policy_version: "rev-11-2021"`,
`policy_published_date: "2021-11-01"`).

### 2.2 IRS Pub 1075 §1.1 — Definition of FTI

URL: https://www.irs.gov/pub/irs-pdf/p1075.pdf §1.1 (accessed
2026-06-07; operator-downloaded copy).

**§1.1 — Federal Tax Information (verbatim):**

> "Federal Tax Information (FTI) is any return or return information
> received from the IRS or secondary source, such as Social
> Security Administration (SSA), Federal Office of Child Support
> Enforcement (OCSE), Bureau of the Fiscal Service (BFS), or
> Centers for Medicare and Medicaid Services (CMS). FTI includes
> any information created by the recipient that is derived from
> federal return or return information received from the IRS or
> obtained through an authorized secondary source."

The Y.Y3 catalog records this verbatim text as the seed of the
`data_class: "FTI"` definition the inventory module consumes when
operators tag assets.

### 2.3 IRS Pub 1075 §4 — Recordkeeping Requirements

URL: https://www.irs.gov/pub/irs-pdf/p1075.pdf §4 (accessed
2026-06-07).

**§4 — Recordkeeping (verbatim):**

> "Under IRC §6103(p)(4)(A), all agencies that receive FTI must
> establish a permanent system of standardized records of all
> requests for inspection or disclosure of FTI. [...] The agency
> shall maintain a log of receipts, distribution, and disposal of
> FTI. [...] These records shall be retained for a period of 5
> years or 3 years after completion of an audit, whichever is
> longer."

The Y.Y3 catalog emits two shall-statements from this paragraph:
the recordkeeping requirement (`id: "4-1"`,
`statutory_anchor: "IRC §6103(p)(4)(A)(i)"`) and the retention
requirement (`id: "4-2"`, `retention_years: 5`,
`retention_extension_post_audit: 3`).

### 2.4 IRS Pub 1075 §5 — Restricting Access (with §5.1.1 Storage)

URL: https://www.irs.gov/pub/irs-pdf/p1075.pdf §5 (accessed
2026-06-07).

**§5 — Restricting Access (verbatim):**

> "Access to FTI shall be limited to those individuals whose duties
> or responsibilities require access. Individuals shall only be
> granted access to FTI to perform their official duties [...].
> Access shall be reviewed at least annually."

**§5.1.1 — Secure Storage (verbatim):**

> "FTI shall be stored in a manner that precludes unauthorized
> access. Two barriers of protection (e.g. a locked container
> within a locked room) shall protect FTI from unauthorized access
> when not in use."

The two-barriers requirement is the Pub 1075 hallmark for physical
storage; for cloud-only deployments the IRS Office of Safeguards
treats the FedRAMP authorization boundary as one barrier and the
tenant isolation enforced by the cloud provider's IAM as the
second (per the IRS HTML annotation cited in §2.10 below).

### 2.5 IRS Pub 1075 §6.3 — Contractor Access

URL: https://www.irs.gov/pub/irs-pdf/p1075.pdf §6.3 (accessed
2026-06-07).

**§6.3 — Contractor Access (verbatim):**

> "The agency shall ensure that contractors and subcontractors with
> access to FTI are bound by the same confidentiality requirements
> as the agency. The agency shall include in any contract or
> agreement involving access to FTI a clause requiring the
> contractor to comply with the safeguarding requirements of IRC
> §6103 and Publication 1075."

The Y.Y3 catalog tags this shall-statement with
`consumer_slice: "Y.Y4"` and `consumer_primitive: "baa-signing.ts"`
because Y.Y4's SSR emitter uses the LOOP-V BAA-signing primitive
(generalised for any regime) to attach contractor agreement
references to the SSR's §5 (Attachments) section.

### 2.6 IRS Pub 1075 §7 — Reporting Requirements (the annual SSR)

URL: https://www.irs.gov/privacy-disclosure/safeguard-security-report
(accessed 2026-06-07).

**Annual SSR mandate (verbatim, re-keyed from operator-fetched HTML):**

> "The SSR submission and all associated attachments must be updated
> and submitted annually [...] An SSR must be submitted annually per
> section 2.E.4.3 of Pub 1075, even for agencies with a Safeguard
> review scheduled."

**Scope (verbatim):**

> "Agencies are required to submit an annual SSR encompassing any
> changes that impact the protection of FTI, including new data
> exchange agreements and new computer equipment, systems, or
> applications (hardware or software)."

**Template handling (verbatim):**

> "Do not start a new SSR using a blank template; use the accepted
> SSR template that was returned to your agency with the previous
> year's acceptance letter for submission."

**Submission process (verbatim):**

> "Submit via Secure Data Transfer when available or secure email
> to safeguardreports@irs.gov."

**Federal-agency due date (verbatim):**

> "The SSR is due January 31 for federal agencies covering the
> Jan. 1 – Dec. 31 reporting period."

The Y.Y3 catalog stores all five verbatim quotes in the
`shall_statements` for §7 and tags them
`consumer_slice: "Y.Y4"`. Y.Y4 reads these to populate the SSR
cover-page metadata and to drive the tracker UI countdown timer
(green > 60d, yellow 30-60d, orange 7-30d, red < 7d).

### 2.7 IRS Pub 1075 §8 — Disposing of FTI

URL: https://www.irs.gov/pub/irs-pdf/p1075.pdf §8 (accessed
2026-06-07).

**§8 — Disposal (verbatim):**

> "FTI shall be destroyed when no longer required. Destruction
> shall be conducted in a manner that renders the FTI unreadable
> and irreproducible. Acceptable methods include: cross-cut
> shredding (1 mm × 5 mm or smaller); incineration; pulverization;
> degaussing; or secure overwrite (for electronic media) using a
> NIST SP 800-88 Rev 1-compliant procedure."

The Y.Y3 catalog emits this as `id: "8-1"` with
`nist_800_53_r5_mapping: ["MP-6", "MP-6(1)", "MP-6(2)"]` and
`external_reference: "NIST SP 800-88 Rev 1"`.

### 2.8 IRS Pub 1075 §9.1 — Encryption Requirements

URL: https://www.irs.gov/privacy-disclosure/encryption-requirements-of-publication-1075
(accessed 2026-06-07; IRS HTML annotation page that re-publishes
the §9.1 normative text with operational guidance).

**§9.1 — Encryption (verbatim, re-keyed from IRS HTML):**

> "The software or hardware that performs the encryption algorithm
> must meet the latest FIPS 140 standards."

> "The information system protects the confidentiality of
> transmitted information [...] agencies must implement the latest
> FIPS 140 cryptographic mechanisms to prevent unauthorized
> disclosure of FTI."

> "Encryption is not currently required for FTI while it resides on
> a system [...] that is dedicated to receiving, processing,
> storing or transmitting FTI [...] if physically secure behind two
> locked barriers. However, FTI must be encrypted at rest in
> FedRAMP-certified, vendor operated cloud computing environments."

> "The organization establishes and manages cryptographic keys
> using automated mechanisms with supporting procedures or manual
> procedures."

The fourth quote is the operational hook for Y.Y4's encryption-floor
cross-check: every cloud-resident FTI-tagged asset MUST be
encrypted at rest with a FIPS 140-validated module. The catalog
emits two shall-statements (`9.1-1` for the FIPS-140 floor, `9.1-2`
for the cloud-at-rest requirement) with
`nist_800_53_r5_mapping: ["SC-13", "SC-28", "SC-28(1)"]`.

### 2.9 IRS Pub 1075 §9.3 — Audit and Accountability

URL: https://www.irs.gov/pub/irs-pdf/p1075.pdf §9.3 (accessed
2026-06-07).

**§9.3 — Audit and Accountability (verbatim):**

> "All systems that receive, process, store, or transmit FTI shall
> be configured to generate audit records of events including:
> successful and failed logon events; privileged user activity;
> access to FTI; modification of access controls; system startup
> and shutdown; and audit log access. Audit records shall be
> retained for a minimum of 7 years."

The 7-year retention is **stricter than** both FedRAMP Moderate
AU-11 (1 year online-or-archive) and CJIS §5.4.7 (365 days
minimum). The Y.Y3 catalog encodes this with
`retention_years: 7` and adds an `overlap_notes` block that names
the FedRAMP and CJIS comparators. Y.Y4's POA&M-emitter consumes
the comparator block to escalate severity when a mixed-CJI+FTI
asset uses < 7-year retention.

### 2.10 IRS Pub 1075 §10 — Disclosure Awareness Training

URL: https://www.irs.gov/pub/irs-pdf/p1075.pdf §10 (accessed
2026-06-07).

**§10 — Disclosure Awareness Training (verbatim):**

> "All personnel with access to FTI shall complete Disclosure
> Awareness Training before being granted access. Training shall
> be repeated annually. Records of training completion shall be
> maintained for 5 years."

The Y.Y3 catalog emits this as `id: "10-1"` with
`nist_800_53_r5_mapping: ["AT-2", "AT-3", "AT-4"]` and
`retention_years_training_records: 5`. Y.Y4 cross-references the
training-records retention against the tracker DB's training-log
table; mismatches generate POA&M findings under AT-4.

### 2.11 26 U.S.C. §6103 — Statutory Authority

URL: https://www.law.cornell.edu/uscode/text/26/6103 (accessed
2026-06-07; Cornell LII mirror of the Office of the Law Revision
Counsel's prelim text).

Mirror: https://uscode.house.gov/view.xhtml?req=granuleid%3AUSC-prelim-title26-section6103
(accessed 2026-06-07).

**§6103(a) — General Rule (verbatim):**

> "Returns and return information shall be confidential, and except
> as authorized by this title — (1) no officer or employee of the
> United States [...] shall disclose any return or return
> information obtained by him in any manner in connection with his
> service as such an officer or an employee or otherwise or under
> the provisions of this section."

**§6103(p)(4) — Safeguarding requirements (verbatim):**

> "(p)(4) Safeguards. — Any Federal agency [...] shall, as a
> condition for receiving returns or return information —
> (A) establish and maintain, to the satisfaction of the
> Secretary —
> (i) a permanent system of standardized records with respect to
> any request, the reason for such request, and the date of such
> request made by or of it and any disclosure of return or return
> information made by or to it;
> (ii) a secure area or place in which such returns or return
> information shall be stored;
> (iii) restrictions on access to such returns or return information
> as may be necessary to prevent unauthorized disclosure;
> (iv) such other safeguards as the Secretary determines (and which
> he prescribes in regulations) to be necessary or appropriate to
> protect the confidentiality of the returns or return information."

**§6103(p)(4)(D) — Triennial review (verbatim):**

> "[The agency shall] agree to conduct an on-site review every 3
> years (or a mid-point review in the case of contracts or
> agreements of less than 3 years in duration) of each contractor
> or other agent to determine compliance with such requirements."

The Y.Y3 catalog stores these verbatim quotes at the top of the
`statutory_authority` block; every shall-statement that traces to
a §6103 subsection records the pin in its `statutory_anchor` field.

### 2.12 IRS Safeguards Program — SCSEM landing page

URL: https://www.irs.gov/privacy-disclosure/safeguards-program
(accessed 2026-06-07; HTML page that links to per-platform SCSEM
PDFs and aggregates current-version metadata).

The page describes the SCSEM family (verbatim):

> "The Safeguards Computer Security Evaluation Matrices (SCSEMs)
> are tools used by Safeguards reviewers to assess the
> implementation of FTI security and privacy controls during
> on-site reviews. SCSEMs exist for major operating systems,
> databases, virtualization platforms, cloud environments, and
> applications."

The Y.Y3 catalog's `scsem_index[]` entries are populated from this
page (one entry per linked PDF), and the extractor parses each
linked PDF to populate `data/irs-scsem-matrix.json` with the
per-check cross-walk to Pub 1075 §9 shall-statements.

### 2.13 IRS IRM 11.3.36 — Safeguard Review Program

URL: https://www.irs.gov/irm/part11/irm_11-003-036 (accessed
2026-06-07).

The Internal Revenue Manual section 11.3.36 documents the
operational procedures the Office of Safeguards follows when
conducting on-site reviews and processing SSRs. Relevant quote
(verbatim):

> "The Office of Safeguards uses the Safeguards Computer Security
> Evaluation Matrices (SCSEMs) during on-site reviews to evaluate
> the agency's implementation of the controls required by Pub
> 1075. SCSEMs are updated periodically and the most current
> version applies."

The "most current version applies" clause is the operational reason
the Y.Y3 extractor pins `scsem_published_date` per SCSEM and the
typed loader exposes `loadCurrentScsemForPlatform(platform)` so
Y.Y4 always reads the latest applicable SCSEM at SSR-build time.

### 2.14 IRS Safeguards Technical Assistance — Contractor procedures

URL: https://www.irs.gov/privacy-disclosure/safeguards-technical-assistance-policy-and-procedures-involving-a-contractor
(accessed 2026-06-07).

This page documents the IRS Office of Safeguards' expectations for
contractor procurement and oversight when contractors access FTI.
Relevant quote (verbatim):

> "Prior to procuring services from a contractor that will have
> access to FTI, the agency must request approval from the IRS
> Office of Safeguards by submitting a 45-day notification. The
> notification must include the contractor name, scope of work,
> and a copy of the proposed contract language demonstrating
> compliance with Pub 1075 §6.3."

The Y.Y3 catalog tags §6.3 with
`operator_workflow: "45-day-pre-procurement-notification"` so the
tracker UI can surface a reminder when the operator records a new
subprocessor in `contractor_agreements.yaml`.

### 2.15 NIST SP 800-53 Rev 5 — baseline cross-walk substrate

URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
(accessed 2026-06-07).

Pub 1075's NIST 800-53 cross-walk lives in Appendix B (Rev 4) and
the §9 sub-sections (selective Rev 5). The Y.Y3 catalog uses
NIST 800-53 Rev 5 control identifiers (AC-, AT-, AU-, etc.) as the
canonical control-ID space; Rev 4 mappings are stored in a
parallel field. The existing `core/control-benchmark.ts` exposes
the Rev 5 control catalog as TypeScript constants; the Y.Y3
loader validates that every NIST mapping in
`data/irs-1075-catalog.json` resolves to a known Rev 5 control ID.

### 2.16 NIST SP 800-88 Rev 1 — Media Sanitization (external reference for §8)

URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r1.pdf
(accessed 2026-06-07).

Pub 1075 §8 references NIST SP 800-88 Rev 1 for electronic-media
sanitization. The Y.Y3 catalog stores the reference as an
`external_reference` on the §8 shall-statements; the typed loader
exposes `getExternalReferences(statementId)` so 3PAO workflows
can resolve the cross-reference.

### 2.17 FIPS 140-3 standard (external reference for §9.1)

URL: https://csrc.nist.gov/publications/detail/fips/140/3/final
(accessed 2026-06-07).

The §9.1 encryption shall-statements reference "the latest FIPS
140 standards" — Y.Y3 records the current standard as FIPS 140-3
(the successor to FIPS 140-2; effective for new modules since
2020) and stores both names so legacy module validations remain
discoverable.

### 2.18 IRS Pub 1075 — Microsoft compliance reference (non-authoritative)

URL: https://learn.microsoft.com/en-us/compliance/regulatory/offering-irs-1075
(accessed 2026-06-07).

This page is a Microsoft commercial restatement of Pub 1075. It is
included **only** as a sanity-check reference to detect drift in
the Y.Y3 extractor's interpretation of §9 sub-sections; it is
**never** quoted verbatim in the catalog, never used to derive
shall-statement text, and never used to set NIST mappings. The
authoritative source is always the operator-downloaded IRS PDF.

## 3. Scope

### 3.1 In scope

- Extraction of every "shall" statement from IRS Pub 1075 (Rev.
  11-2021) §§1, 4, 5, 6, 7, 8, 9, and 10 (the substantive
  requirements sections) from the operator-downloaded PDF.
- Verbatim retention of the shall-statement text (whitespace
  normalised per RFC 8785).
- Stable identifier assignment of the form `<section>-<ordinal>`
  (e.g. `9.1-1`, `9.3-1`, `5.1.1-1`).
- Section-and-title metadata for every shall-statement.
- Statutory-anchor mapping to IRC §6103 subsections where the IRS
  text makes the pin explicit (§§4, 5.1.1, 6.3, 9.3 are
  explicitly anchored).
- NIST 800-53 Rev 4 mapping (from Pub 1075 Appendix B) per
  shall-statement.
- NIST 800-53 Rev 5 mapping (from Pub 1075 §9 sub-sections and
  cross-walk to existing `core/control-benchmark.ts`) per
  shall-statement.
- IRS SCSEM cross-walk: for every Pub 1075 §9 shall-statement,
  enumerate the SCSEM check IDs (per platform) that exercise it.
- Catalog totals (sections, shall-statements, NIST mappings,
  SCSEM checks).
- Ed25519 signature over canonical-JSON serialization (RFC 8785)
  of the catalog snapshot, with provenance block recording the
  source PDF's SHA-256 and the extractor version.
- Typed TypeScript loader (`core/irs-1075-catalog.ts`) exposing
  `loadCatalog()`, `getShallStatement(id)`,
  `getStatementsBySection(sectionId)`,
  `getStatementsByNistControl(controlId, {revision: 4 | 5})`,
  `getScsemChecksForStatement(statementId, {platform})`,
  `getCurrentScsemForPlatform(platform)`,
  `verifyCatalogSignature(catalog)`,
  `getStatutoryAnchorMap()`.
- Test fixtures + test specifications (≥ 15) covering extraction,
  signature, snapshot reload, NIST cross-walk, SCSEM cross-walk,
  versioning, REQUIRES-OPERATOR-INPUT diagnostics.
- REQUIRES-OPERATOR-INPUT scaffolding for the source-PDF path,
  the SCSEM directory, and the SHA-256 checksum of the IRS-
  published PDF.

### 3.2 Out of scope

- Evidence evaluation (whether the CSP's encryption meets §9.1
  is Y.Y4's job, not Y.Y3's).
- Tracker DB writes at runtime (Y.Y3 emits files only).
- Auto-submission to the IRS Office of Safeguards (REO Rule 4
  forbids).
- Per-asset FTI tagging (inventory module owns the `data_classes`
  taxonomy).
- The triennial on-site Safeguard Review workflow (out of
  LOOP-Y scope per LOOP-Y-SPEC.md §1.3).
- State Department of Revenue overlays (operator-supplied; not
  bundled).
- The CJIS Security Policy v5.9.5 catalog (Y.Y1's job).
- The annual SSR build (Y.Y4's job).
- The §6.3 contractor-agreement signing primitive itself
  (reused from LOOP-V's `core/baa-signing.ts`; Y.Y3 only records
  the catalog reference).

## 4. Inputs

The Y.Y3 extractor and loader read the following inputs. Every
input is either an operator-supplied file (validated by the
REQUIRES-OPERATOR-INPUT scaffolding) or a Government-published
artifact (validated against a recorded SHA-256 checksum). No
network calls happen at extract-time after the initial
operator-driven download.

```typescript
/** Path + checksum of the operator-downloaded IRS Pub 1075 PDF. */
export interface Pub1075SourceInput {
  /** Absolute filesystem path. Default: docs/sources/irs-p1075-rev11-2021.pdf */
  pdfPath: string;
  /** Operator-supplied SHA-256 of the IRS-published PDF.
   *  Validates against actual file SHA-256 at extract-time. */
  expectedSha256: string;
  /** Optional: the IRS-published revision label.
   *  Default derived from cover page; override for forensics. */
  policyVersionLabel?: string;
  /** Optional: the publication date as printed on the cover page.
   *  ISO 8601 date. */
  policyPublishedDate?: string;
}

/** Directory of operator-downloaded SCSEM PDFs. */
export interface ScsemSourceInput {
  /** Absolute filesystem path to a directory containing per-platform
   *  SCSEM PDFs named SCSEM_<platform>_<version>.pdf */
  scsemDir: string;
  /** Optional per-platform whitelist; when omitted all PDFs are read. */
  platforms?: string[];
}

/** Operator-supplied snapshot identity + signing key reference. */
export interface SnapshotIdentity {
  /** ISO 8601 timestamp of snapshot creation; default = now(). */
  snapshotAt?: string;
  /** Signing key identifier resolved by core/sign.ts. */
  signingKeyId: string;
  /** Optional override of the snapshot-id pattern. */
  snapshotIdOverride?: string;
}

/** Aggregated input to the extractor. */
export interface ExtractorInput {
  pub1075: Pub1075SourceInput;
  scsem: ScsemSourceInput;
  identity: SnapshotIdentity;
}
```

### 4.1 Input provenance

| Input | Source | Validator | When required |
|---|---|---|---|
| `Pub1075SourceInput.pdfPath` | operator download from irs.gov | file exists; readable; > 1 MiB | always (extractor entry) |
| `Pub1075SourceInput.expectedSha256` | operator records from `shasum -a 256 p1075.pdf` after the download | matches actual SHA-256 of `pdfPath`; raises `provenance:irs-1075-pdf-sha-mismatch` on drift | always |
| `Pub1075SourceInput.policyVersionLabel` | cover page of the PDF | regex `^rev-\d{1,2}-\d{4}$` | optional (auto-detected) |
| `ScsemSourceInput.scsemDir` | operator downloads from irs.gov/privacy-disclosure/safeguards-program | directory exists; ≥ 1 SCSEM PDF inside | always (Y.Y3 declines to emit a partial cross-walk) |
| `ScsemSourceInput.platforms` | operator config | each platform string matches `^[A-Za-z0-9][A-Za-z0-9 \-]*$` | optional |
| `SnapshotIdentity.signingKeyId` | LOOP-A.A5 key registry | resolves to a non-expired Ed25519 key | always |

## 5. Outputs

### 5.1 `data/irs-1075-catalog.json` — canonical signed snapshot

```jsonc
{
  "$schema": "https://cloud-evidence.example/schemas/irs-1075-catalog-v1.json",
  "schema_version": "1.0.0",
  "snapshot_id": "irs-1075-rev11-2021-20260608T120000Z",
  "snapshot_date": "2026-06-08",
  "snapshot_at": "2026-06-08T12:00:00Z",
  "policy_version": "rev-11-2021",
  "policy_published_date": "2021-11-01",
  "statutory_authority": {
    "primary": "26 U.S.C. § 6103(p)(4)",
    "verbatim_text": "<verbatim §6103(p)(4) text — see §2.11>",
    "secondary": ["IRC §6103(a)", "IRC §6103(p)(4)(D)"]
  },
  "csp_name": "<from org-profile.yaml>",
  "sections": [
    {
      "id": "1.1",
      "title": "Federal Tax Information",
      "shall_statements": [
        {
          "id": "1.1-1",
          "text": "<verbatim FTI-definition text — see §2.2>",
          "kind": "definition",
          "statutory_anchor": "IRC §6103(b)(2)",
          "nist_800_53_r4_mapping": [],
          "nist_800_53_r5_mapping": [],
          "scsem_check_ids": [],
          "consumer_slice": null
        }
      ]
    },
    {
      "id": "4",
      "title": "Recordkeeping Requirements",
      "shall_statements": [
        {
          "id": "4-1",
          "text": "<verbatim §4 recordkeeping text — see §2.3>",
          "kind": "requirement",
          "statutory_anchor": "IRC §6103(p)(4)(A)(i)",
          "nist_800_53_r4_mapping": ["AU-2", "AU-3", "AU-12"],
          "nist_800_53_r5_mapping": ["AU-2", "AU-3", "AU-12"],
          "scsem_check_ids": ["SCSEM-AWS-AU-2.1", "SCSEM-AWS-AU-3.1", "SCSEM-Azure-AU-2.1"],
          "retention_years": 5,
          "retention_extension_post_audit": 3
        }
      ]
    },
    {
      "id": "5.1.1",
      "title": "Secure Storage",
      "shall_statements": [
        {
          "id": "5.1.1-1",
          "text": "<verbatim two-barriers text — see §2.4>",
          "kind": "requirement",
          "statutory_anchor": "IRC §6103(p)(4)(A)(ii)",
          "nist_800_53_r5_mapping": ["PE-3", "PE-4", "SC-28"],
          "scsem_check_ids": ["SCSEM-AWS-PE-3.1"]
        }
      ]
    },
    {
      "id": "6.3",
      "title": "Contractor Access",
      "shall_statements": [
        {
          "id": "6.3-1",
          "text": "<verbatim §6.3 text — see §2.5>",
          "kind": "requirement",
          "statutory_anchor": "IRC §6103(n)",
          "nist_800_53_r5_mapping": ["SA-9", "PS-7"],
          "consumer_slice": "Y.Y4",
          "consumer_primitive": "baa-signing.ts",
          "operator_workflow": "45-day-pre-procurement-notification"
        }
      ]
    },
    {
      "id": "7",
      "title": "Reporting Requirements",
      "shall_statements": [
        {
          "id": "7-SSR-annual",
          "text": "<verbatim annual-SSR text — see §2.6>",
          "kind": "reporting",
          "frequency": "annual",
          "federal_due_date": "January 31",
          "consumer_slice": "Y.Y4"
        }
      ]
    },
    {
      "id": "8",
      "title": "Disposing of FTI",
      "shall_statements": [
        {
          "id": "8-1",
          "text": "<verbatim §8 destruction text — see §2.7>",
          "kind": "requirement",
          "statutory_anchor": "IRC §6103(p)(4)(A)(iv)",
          "nist_800_53_r5_mapping": ["MP-6", "MP-6(1)", "MP-6(2)"],
          "external_reference": "NIST SP 800-88 Rev 1"
        }
      ]
    },
    {
      "id": "9.1",
      "title": "Encryption",
      "shall_statements": [
        {
          "id": "9.1-1",
          "text": "The software or hardware that performs the encryption algorithm must meet the latest FIPS 140 standards.",
          "kind": "requirement",
          "nist_800_53_r5_mapping": ["SC-13"],
          "scsem_check_ids": ["SCSEM-AWS-SC-13.1", "SCSEM-Azure-SC-13.1"],
          "fips_floor": "FIPS 140-3",
          "external_reference": "FIPS 140-3"
        },
        {
          "id": "9.1-2",
          "text": "FTI must be encrypted at rest in FedRAMP-certified, vendor operated cloud computing environments.",
          "kind": "requirement",
          "nist_800_53_r5_mapping": ["SC-28", "SC-28(1)"],
          "scsem_check_ids": ["SCSEM-AWS-SC-28.1", "SCSEM-Azure-SC-28.1"],
          "consumer_slice": "Y.Y4"
        }
      ]
    },
    {
      "id": "9.3",
      "title": "Audit and Accountability",
      "shall_statements": [
        {
          "id": "9.3-1",
          "text": "<verbatim §9.3 audit text — see §2.9>",
          "kind": "requirement",
          "statutory_anchor": "IRC §6103(p)(4)(A)(i)",
          "nist_800_53_r5_mapping": ["AU-11"],
          "retention_years": 7,
          "overlap_notes": {
            "fedramp_moderate": "AU-11 1 year online-or-archive — IRS 1075 stricter at 7 years",
            "cjis_5_4_7": "CJIS audit retention 365 days minimum — IRS 1075 stricter; mixed-CJI+FTI CSPs adopt 7-year floor"
          }
        }
      ]
    },
    {
      "id": "10",
      "title": "Disclosure Awareness Training",
      "shall_statements": [
        {
          "id": "10-1",
          "text": "<verbatim §10 training text — see §2.10>",
          "kind": "requirement",
          "nist_800_53_r5_mapping": ["AT-2", "AT-3", "AT-4"],
          "retention_years_training_records": 5
        }
      ]
    }
  ],
  "scsem_index": [
    {
      "platform": "AWS",
      "scsem_url": "https://www.irs.gov/pub/irs-utl/SCSEM_AWS.pdf",
      "scsem_published_date": "2024-05-01",
      "check_count": 215,
      "local_path": "docs/sources/scsem/SCSEM_AWS.pdf"
    },
    {
      "platform": "Azure",
      "scsem_url": "https://www.irs.gov/pub/irs-utl/SCSEM_Azure.pdf",
      "scsem_published_date": "2024-05-01",
      "check_count": 198,
      "local_path": "docs/sources/scsem/SCSEM_Azure.pdf"
    },
    {
      "platform": "Windows Server 2022",
      "scsem_url": "https://www.irs.gov/pub/irs-utl/SCSEM_Windows2022.pdf",
      "scsem_published_date": "2024-03-01",
      "check_count": 312,
      "local_path": "docs/sources/scsem/SCSEM_Windows2022.pdf"
    },
    {
      "platform": "RHEL 9",
      "scsem_url": "https://www.irs.gov/pub/irs-utl/SCSEM_RHEL9.pdf",
      "scsem_published_date": "2024-03-01",
      "check_count": 287,
      "local_path": "docs/sources/scsem/SCSEM_RHEL9.pdf"
    }
  ],
  "totals": {
    "sections": 9,
    "shall_statements": 0,
    "nist_r4_unique_mappings": 0,
    "nist_r5_unique_mappings": 0,
    "scsem_unique_checks": 0,
    "platforms_indexed": 4
  },
  "provenance": {
    "emitter": "scripts/extract-irs-1075.mjs",
    "emitter_version": "1.0.0",
    "emitted_at": "2026-06-08T12:05:00Z",
    "source_pdf_path": "docs/sources/irs-p1075-rev11-2021.pdf",
    "source_pdf_sha256": "<sha256 of IRS-published PDF>",
    "scsem_dir": "docs/sources/scsem/",
    "scsem_dir_sha256": "<sha256 of tarball of scsem dir>",
    "signing_key_id": "ed25519-prod-2026",
    "signature": "<Ed25519 detached signature over canonical JSON>",
    "signature_alg": "Ed25519",
    "canonicalization": "rfc8785",
    "rfc3161_token": "<base64 RFC 3161 timestamp token (if --rfc3161-enabled)>"
  }
}
```

### 5.2 `data/irs-scsem-matrix.json` — SCSEM cross-walk

```jsonc
{
  "$schema": "https://cloud-evidence.example/schemas/irs-scsem-matrix-v1.json",
  "schema_version": "1.0.0",
  "snapshot_id": "irs-scsem-matrix-20260608T120000Z",
  "snapshot_at": "2026-06-08T12:00:00Z",
  "linked_catalog_snapshot_id": "irs-1075-rev11-2021-20260608T120000Z",
  "checks": [
    {
      "scsem_id": "SCSEM-AWS-SC-13.1",
      "platform": "AWS",
      "title": "Verify encryption module is FIPS 140 validated",
      "scsem_section": "SC-13",
      "scsem_check_number": "1",
      "linked_pub1075_statements": ["9.1-1"],
      "evidence_collection_hint": "Read KMS key spec; assert SYMMETRIC_DEFAULT + FIPS-140 endpoint",
      "scsem_pdf_path": "docs/sources/scsem/SCSEM_AWS.pdf",
      "scsem_pdf_page": 47
    },
    {
      "scsem_id": "SCSEM-AWS-AU-11.1",
      "platform": "AWS",
      "title": "Verify audit log retention >= 7 years for FTI-tagged systems",
      "scsem_section": "AU-11",
      "scsem_check_number": "1",
      "linked_pub1075_statements": ["9.3-1"],
      "evidence_collection_hint": "CloudTrail trail retention + S3 lifecycle policy",
      "scsem_pdf_path": "docs/sources/scsem/SCSEM_AWS.pdf",
      "scsem_pdf_page": 113
    }
  ],
  "totals": {
    "checks_total": 0,
    "checks_per_platform": {"AWS": 0, "Azure": 0, "Windows Server 2022": 0, "RHEL 9": 0},
    "pub1075_statements_with_at_least_one_check": 0,
    "pub1075_statements_with_no_check": 0
  },
  "provenance": {
    "emitter": "scripts/extract-irs-1075.mjs#cross-walk",
    "emitter_version": "1.0.0",
    "emitted_at": "2026-06-08T12:05:00Z",
    "signing_key_id": "ed25519-prod-2026",
    "signature": "<Ed25519 detached>",
    "canonicalization": "rfc8785"
  }
}
```

### 5.3 Typed loader API surface (`core/irs-1075-catalog.ts`)

```typescript
export interface Irs1075Catalog {
  schemaVersion: string;
  snapshotId: string;
  snapshotAt: string;
  policyVersion: string;        // e.g. "rev-11-2021"
  policyPublishedDate: string;  // ISO date
  statutoryAuthority: {
    primary: string;
    verbatimText: string;
    secondary: string[];
  };
  sections: Pub1075Section[];
  scsemIndex: ScsemIndexEntry[];
  totals: Pub1075Totals;
  provenance: CatalogProvenance;
}

export interface Pub1075Section {
  id: string;                   // "4", "5.1.1", "9.1", "9.3"
  title: string;
  shallStatements: Pub1075ShallStatement[];
}

export interface Pub1075ShallStatement {
  id: string;                   // "9.1-1"
  text: string;                 // VERBATIM from PDF
  kind: 'definition' | 'requirement' | 'reporting' | 'metadata';
  statutoryAnchor?: string;     // "IRC §6103(p)(4)(A)(i)"
  nist80053R4Mapping: string[]; // ["AU-2","AU-3"] — empty array if none published
  nist80053R5Mapping: string[]; // ["AU-2","AU-3","AU-12"]
  scsemCheckIds: string[];      // ["SCSEM-AWS-SC-13.1"]
  retentionYears?: number;
  retentionYearsTrainingRecords?: number;
  retentionExtensionPostAudit?: number;
  fipsFloor?: string;           // "FIPS 140-3"
  externalReference?: string;   // "NIST SP 800-88 Rev 1"
  frequency?: 'annual' | 'triennial' | 'on-event';
  federalDueDate?: string;
  consumerSlice?: string;       // "Y.Y4"
  consumerPrimitive?: string;
  operatorWorkflow?: string;
  overlapNotes?: Record<string, string>;
}

export interface ScsemIndexEntry {
  platform: string;
  scsemUrl: string;
  scsemPublishedDate: string;
  checkCount: number;
  localPath: string;
}

export interface Pub1075Totals {
  sections: number;
  shallStatements: number;
  nistR4UniqueMappings: number;
  nistR5UniqueMappings: number;
  scsemUniqueChecks: number;
  platformsIndexed: number;
}

export interface CatalogProvenance {
  emitter: string;
  emitterVersion: string;
  emittedAt: string;
  sourcePdfPath: string;
  sourcePdfSha256: string;
  scsemDir: string;
  scsemDirSha256: string;
  signingKeyId: string;
  signature: string;
  signatureAlg: 'Ed25519';
  canonicalization: 'rfc8785';
  rfc3161Token?: string;
}

/** Load the catalog from disk; verifies the Ed25519 signature.
 *  Throws Provenance error on signature failure. */
export function loadCatalog(options?: { version?: string }): Irs1075Catalog;

export function getShallStatement(catalog: Irs1075Catalog, id: string):
  Pub1075ShallStatement | undefined;

export function getStatementsBySection(catalog: Irs1075Catalog, sectionId: string):
  Pub1075ShallStatement[];

export function getStatementsByNistControl(
  catalog: Irs1075Catalog,
  controlId: string,
  options: { revision: 4 | 5 }
): Pub1075ShallStatement[];

export function getScsemChecksForStatement(
  catalog: Irs1075Catalog,
  statementId: string,
  options?: { platform?: string }
): string[];

export function getCurrentScsemForPlatform(
  catalog: Irs1075Catalog,
  platform: string
): ScsemIndexEntry | undefined;

export function verifyCatalogSignature(catalog: Irs1075Catalog): true;

export function getStatutoryAnchorMap(catalog: Irs1075Catalog):
  Record<string, string[]>;   // anchor → [statement IDs]
```

### 5.4 Diagnostic output

The extractor emits the following structured diagnostics on stderr
(JSON-per-line, pino-compatible) so the orchestrator and the CI
guardrails can pick them up:

| Code | Severity | Meaning | Exit |
|---|---|---|---|
| `provenance:irs-1075-pdf-missing` | error | `pdfPath` does not exist | 2 |
| `provenance:irs-1075-pdf-sha-mismatch` | error | actual SHA-256 != `expectedSha256` | 2 |
| `provenance:irs-1075-section-not-found` | error | a section anchor regex did not match in the PDF text-layer | 2 |
| `provenance:scsem-dir-missing` | error | SCSEM directory does not exist | 2 |
| `provenance:scsem-dir-empty` | warning | SCSEM dir exists but contains 0 PDFs | 0 (catalog still emitted, cross-walk empty) |
| `provenance:nist-mapping-unknown-r5` | warning | a NIST mapping references a control ID not in `core/control-benchmark.ts` | 0 |
| `provenance:nist-mapping-unknown-r4` | warning | a NIST r4 mapping references an unknown control ID | 0 |
| `provenance:scsem-check-orphan` | warning | a SCSEM check ID is not linked to any shall-statement | 0 |
| `coverage:irs-1075-shall-statements` | info | totals row | 0 |

## 6. Algorithm / Steps

The extractor runs deterministically. Given the same source PDF
SHA-256, the same SCSEM PDFs, and the same signing key, two runs
on different machines at different times produce byte-identical
outputs (canonical-JSON serialization per RFC 8785).

1. **Resolve operator config.**
   1.1. Read `Pub1075SourceInput.pdfPath` from
        `IRS_1075_PDF_PATH` env or CLI `--irs-1075-pdf=<path>`.
   1.2. Read `Pub1075SourceInput.expectedSha256` from
        `IRS_1075_PDF_SHA256` env or `--irs-1075-pdf-sha256=<hex>`.
   1.3. Read `ScsemSourceInput.scsemDir` from
        `IRS_SCSEM_DIR` env or `--irs-scsem-dir=<path>`.
   1.4. Resolve signing-key id via existing
        `core/sign.ts::resolveSigningKey()`.

2. **Validate inputs.**
   2.1. `fs.access(pdfPath)`; on failure emit
        `provenance:irs-1075-pdf-missing` and exit 2.
   2.2. Stream-hash the PDF with SHA-256; compare to
        `expectedSha256`. On mismatch emit
        `provenance:irs-1075-pdf-sha-mismatch` and exit 2.
   2.3. `fs.access(scsemDir)`; on failure emit
        `provenance:scsem-dir-missing` and exit 2. (Tracker UI
        prompts operator to download SCSEMs.)
   2.4. List SCSEM PDFs (`SCSEM_*.pdf`); if 0, emit
        `provenance:scsem-dir-empty` (warning) and continue.

3. **Parse the Pub 1075 PDF text layer.**
   3.1. Use `pdf-parse` (or equivalent text-layer extractor) to
        produce a per-page array of strings.
   3.2. For each top-level section in {§1, §4, §5, §6, §7, §8, §9,
        §10}, locate the section anchor via a heading regex of
        the form `^\s*(?:Section\s+)?<id>\s+[A-Z]`. On miss for a
        mandatory section, emit
        `provenance:irs-1075-section-not-found` (error) and
        exit 2.
   3.3. Within each section, locate sub-section anchors (e.g.
        §1.1, §5.1.1, §6.3, §9.1, §9.3) and extract the
        sub-section body text.

4. **Enumerate shall-statements.**
   4.1. For each section / sub-section body, split into sentences
        and select sentences containing `shall` (case-insensitive,
        with word-boundary). Excluded: sentences that appear inside
        figure captions or table-of-contents lines.
   4.2. Concatenate adjacent shall-bearing clauses that form a
        single regulatory directive (heuristic: split only on
        sentence-final punctuation outside parentheses or
        enumerated lists).
   4.3. Assign stable IDs `<section_id>-<ordinal>` starting at 1
        per section. Preserve the source order in the PDF.

5. **Apply statutory anchors.**
   5.1. Walk a hand-curated `statutoryAnchorMap` (kept in
        `scripts/extract-irs-1075.mjs` as a typed constant; the
        map's contents are an audit-traceable interpretation of
        the IRS PDF and are pinned in §2.11 above):
        - `4-*`        → `IRC §6103(p)(4)(A)(i)`
        - `5.1.1-*`    → `IRC §6103(p)(4)(A)(ii)`
        - `5-* (non-storage)` → `IRC §6103(p)(4)(A)(iii)`
        - `6.3-*`      → `IRC §6103(n)`
        - `8-*`        → `IRC §6103(p)(4)(A)(iv)` (secretary-prescribed)
        - `9.3-*`      → `IRC §6103(p)(4)(A)(i)` (recordkeeping flavour)
        - default      → empty string + `anchor_provenance: "secretary-prescribed"`
   5.2. Apply the map to each shall-statement; statements outside
        the map carry an empty `statutoryAnchor`.

6. **Apply NIST 800-53 mappings.**
   6.1. Walk a hand-curated `nistR4Map` and `nistR5Map`; entries
        are sourced from Pub 1075 Appendix B (Rev 4) and from §9
        cross-walk text (Rev 5).
   6.2. Each map entry is `<statement_id> → string[]` of canonical
        Rev 4/Rev 5 control IDs (e.g. `["AU-2","AU-3","AU-12"]`).
   6.3. For every mapping, validate the control ID resolves in
        `core/control-benchmark.ts`. On miss emit
        `provenance:nist-mapping-unknown-r5` (or `r4`) warning;
        keep the mapping in the catalog with a `validated: false`
        sub-field.

7. **Parse SCSEMs and cross-walk to shall-statements.**
   7.1. For each SCSEM PDF in `scsemDir`, extract text layer and
        enumerate checks of the form
        `<platform>-<family>-<n>.<sub>` (e.g. `AWS-AC-2.1`).
   7.2. Build the `scsemIndex[]` with one entry per SCSEM PDF
        (platform name from filename; published-date from
        first-page metadata; check_count from §7.1 enumeration).
   7.3. For each check, derive the linked Pub 1075 shall-
        statement(s) using a hand-curated `scsemLinkageMap`
        (typed constant in extractor) keyed on
        `<platform>-<family>-<n>.<sub>` → `[shall_statement_id]`.
        The map is the audit-traceable interpretation of the
        SCSEM-to-Pub-1075 cross-walk and is pinned to the IRS
        Office of Safeguards published SCSEMs (which carry their
        own §-numbered Pub 1075 references on each check row).
   7.4. Emit `data/irs-scsem-matrix.json` with the full check
        catalogue.

8. **Compute totals.**
   8.1. `sections`: count of distinct section IDs.
   8.2. `shall_statements`: total count.
   8.3. `nist_r4_unique_mappings`: union over `nist_800_53_r4_mapping[]`.
   8.4. `nist_r5_unique_mappings`: union over `nist_800_53_r5_mapping[]`.
   8.5. `scsem_unique_checks`: count of distinct `scsem_id` in
        `data/irs-scsem-matrix.json`.
   8.6. `platforms_indexed`: count of `scsemIndex[]`.

9. **Canonicalise + sign.**
   9.1. Serialize catalog object with RFC 8785 JCS (deterministic
        key ordering, no insignificant whitespace).
   9.2. Compute Ed25519 detached signature over the canonical bytes
        using `core/sign.ts::signEnvelope({key, payload})`.
   9.3. Optionally fetch an RFC 3161 timestamp token (when
        `--rfc3161-enabled` is set in the run config) and embed
        in `provenance.rfc3161_token`.
   9.4. Write `data/irs-1075-catalog.json` and
        `data/irs-scsem-matrix.json` atomically (write to
        `.tmp` + rename).

10. **Emit coverage diagnostic.**
    10.1. Log a single `coverage:irs-1075-shall-statements` line
          with totals.
    10.2. Exit 0.

11. **Typed loader contract (runtime).**
    11.1. `loadCatalog()` reads `data/irs-1075-catalog.json`,
          calls `verifyCatalogSignature()`, and returns the
          parsed object.
    11.2. On signature mismatch, throws a typed
          `CatalogSignatureError` and the orchestrator emits
          `provenance:irs-1075-catalog-signature-invalid` and
          exits non-zero.
    11.3. Lookup functions (`getShallStatement`, etc.) are O(1)
          via lazy-built index maps.

## 7. Files to create / modify

| Path (absolute under `/Users/kenith.philip/FedRAMP 20x/`) | Status | Purpose |
|---|---|---|
| `cloud-evidence/core/irs-1075-catalog.ts` | create | Typed loader + lookup functions + signature verifier |
| `cloud-evidence/scripts/extract-irs-1075.mjs` | create | One-shot extractor; deterministic; re-runnable |
| `cloud-evidence/data/irs-1075-catalog.json` | create (emitted) | Canonical signed snapshot; checked into git |
| `cloud-evidence/data/irs-scsem-matrix.json` | create (emitted) | SCSEM cross-walk; checked into git |
| `cloud-evidence/test/irs-1075-catalog.test.ts` | create | ≥ 15 unit + integration tests |
| `cloud-evidence/test/fixtures/irs-1075/p1075-rev11-2021-sample.pdf` | create | minimal text-layer fixture for offline test runs |
| `cloud-evidence/test/fixtures/irs-1075/scsem/SCSEM_AWS_sample.pdf` | create | minimal SCSEM fixture |
| `cloud-evidence/test/fixtures/irs-1075/expected-catalog.json` | create | golden snapshot for round-trip tests |
| `cloud-evidence/test/fixtures/irs-1075/expected-scsem-matrix.json` | create | golden snapshot for cross-walk |
| `cloud-evidence/docs/sources/irs-p1075-rev11-2021.pdf` | operator-supplied | source PDF (gitignored) |
| `cloud-evidence/docs/sources/scsem/SCSEM_*.pdf` | operator-supplied | per-platform SCSEM PDFs (gitignored) |
| `cloud-evidence/docs/sources/.gitignore` | modify | ignore PDFs but commit a README pointer |
| `cloud-evidence/docs/sources/README.md` | create | document how the operator downloads + records SHA-256 of IRS PDFs |
| `cloud-evidence/.env.local.example` | modify | add `IRS_1075_PDF_PATH=`, `IRS_1075_PDF_SHA256=`, `IRS_SCSEM_DIR=` |
| `cloud-evidence/package.json` | modify | add `scripts.extract:irs-1075` invoking the extractor |
| `cloud-evidence/docs/STATUS.md` | modify (on completion) | flip Y.Y3 row to `done` + commit hash |
| `cloud-evidence/docs/loops/LOOP-Y-SPEC.md` | modify (on completion) | flip Y.Y3 §12 row to `done` |
| `cloud-evidence/docs/slices/Y/Y.Y3.md` | modify (on completion) | frontmatter `status: done` + Implementation log entry |
| `cloud-evidence/docs/loops/LOOP-Y-RISKS.md` | modify (if new risks surface) | append any newly-identified risk |
| `cloud-evidence/CHANGELOG.md` | modify (on completion) | append `Unreleased` entry |
| `cloud-evidence/core/submission-bundle.ts` (`WELL_KNOWN`) | modify | register `data/irs-1075-catalog.json` + `data/irs-scsem-matrix.json` as bundler roles |

## 8. Test specifications

| id | scenario | fixture path | expected | acceptance |
|---|---|---|---|---|
| T-Y3-01 | Extractor refuses to run when source PDF is missing | (no fixture) | exit 2, stderr contains `provenance:irs-1075-pdf-missing` | exit code + log line |
| T-Y3-02 | Extractor refuses on SHA-256 mismatch | `test/fixtures/irs-1075/p1075-rev11-2021-sample.pdf` + wrong SHA | exit 2, stderr contains `provenance:irs-1075-pdf-sha-mismatch` | exit code + log line |
| T-Y3-03 | Extractor parses §4 recordkeeping requirement verbatim | sample PDF | `catalog.sections[id="4"].shall_statements[0].text` equals the §2.3 verbatim quote (whitespace-normalised) | string-equal under RFC 8785 normalisation |
| T-Y3-04 | Extractor parses §5.1.1 two-barriers requirement verbatim | sample PDF | `5.1.1-1.text` equals §2.4 verbatim quote | string-equal |
| T-Y3-05 | Extractor parses §6.3 contractor clause verbatim | sample PDF | `6.3-1.text` equals §2.5 verbatim quote | string-equal |
| T-Y3-06 | Extractor parses §9.1-1 FIPS-140 requirement verbatim | sample PDF | `9.1-1.text` equals §2.8 first verbatim quote | string-equal |
| T-Y3-07 | Extractor parses §9.1-2 cloud-at-rest requirement verbatim | sample PDF | `9.1-2.text` equals §2.8 third verbatim quote | string-equal |
| T-Y3-08 | Extractor parses §9.3 7-year retention verbatim | sample PDF | `9.3-1.text` equals §2.9 verbatim quote AND `retention_years === 7` | string-equal + field-equal |
| T-Y3-09 | Extractor parses §10 training requirement + 5-year retention | sample PDF | `10-1.retention_years_training_records === 5` | field-equal |
| T-Y3-10 | NIST 800-53 Rev 5 mappings validate against `core/control-benchmark.ts` | sample PDF | every entry in every `nist_800_53_r5_mapping[]` resolves; zero warnings | warning count = 0 |
| T-Y3-11 | Catalog signature verifies | round-trip the emitted JSON | `verifyCatalogSignature(catalog)` returns `true` | function returns true |
| T-Y3-12 | Signature mismatch is detected | mutate one byte of the catalog JSON | `verifyCatalogSignature(catalog)` throws `CatalogSignatureError` | exception caught |
| T-Y3-13 | Snapshot is byte-deterministic across runs | run extractor twice on same inputs | `sha256(catalog_run1) === sha256(catalog_run2)` | hash-equal |
| T-Y3-14 | SCSEM cross-walk: every linked check resolves to a known statement | sample SCSEM + catalog | for every check in `scsem_matrix.checks[]`, `linked_pub1075_statements[]` ⊂ catalog statement IDs | set-subset assertion |
| T-Y3-15 | SCSEM cross-walk: orphan check raises warning | inject orphan check in fixture | extractor logs `provenance:scsem-check-orphan` warning | log assertion |
| T-Y3-16 | `getStatementsByNistControl("AU-11", {revision: 5})` returns §9.3-1 | catalog | result includes statement `id === "9.3-1"` | array contains |
| T-Y3-17 | `getStatementsByNistControl("AU-2", {revision: 4})` returns §4-1 | catalog | result includes `4-1` | array contains |
| T-Y3-18 | `getScsemChecksForStatement("9.1-1", {platform: "AWS"})` returns AWS SC-13 check | catalog + matrix | result includes `SCSEM-AWS-SC-13.1` | array contains |
| T-Y3-19 | `getStatutoryAnchorMap()` returns IRC §6103(p)(4)(A)(i) → [4-1, 9.3-1] | catalog | map[`IRC §6103(p)(4)(A)(i)`] is a superset of `["4-1","9.3-1"]` | set assertion |
| T-Y3-20 | Versioning: two snapshots with different `policy_version` coexist | fixture rev-11-2021 + fixture rev-11-2024 | `loadCatalog({version: "rev-11-2021"})` and `loadCatalog({version: "rev-11-2024"})` both succeed and return distinct objects | object identity differs |
| T-Y3-21 | REQUIRES-OPERATOR-INPUT diagnostic on missing `IRS_SCSEM_DIR` | unset env | exit 2 with `provenance:scsem-dir-missing` | exit code + log line |
| T-Y3-22 | Statutory anchor present for §6.3 maps to IRC §6103(n) | catalog | `getShallStatement("6.3-1").statutoryAnchor === "IRC §6103(n)"` | field-equal |
| T-Y3-23 | `overlap_notes` on §9.3 mentions both FedRAMP and CJIS | catalog | `getShallStatement("9.3-1").overlapNotes.fedramp_moderate` and `.cjis_5_4_7` are non-empty | non-empty assertion |

(23 tests; exceeds the 15-test minimum. Each test runs against
fixture PDFs that ship in the test directory; no network calls.)

## 9. Risks

The full LOOP-Y risks register lives at
`cloud-evidence/docs/loops/LOOP-Y-RISKS.md`. The Y.Y3-specific
risks below are the subset the slice introduces or owns.

### R-Y3-01 — Source-PDF text-layer extraction errors (HIGH)

**Risk.** The IRS Pub 1075 PDF is a Government-produced document
whose text layer is generally clean but can carry OCR errors,
mis-ligatured characters (`shall` rendered as `sliall`), or
broken across columns. A failed text-layer extraction yields a
catalog with missing or malformed shall-statements.

**Mitigation.**
- The extractor verifies the file's SHA-256 against the
  operator-recorded checksum **before** parsing — this catches
  the most common error mode (the operator downloads a corrupted
  PDF).
- The extractor requires every mandatory section (§1, §4, §5,
  §6, §7, §8, §9, §10) to be present; if any section anchor
  regex misses, the extractor exits non-zero rather than
  producing a partial catalog.
- Test fixtures include a known-good text-layer fixture so
  CI catches extractor regressions.
- If a future Pub 1075 revision changes the heading format, the
  section-anchor regex is the single point of update.

### R-Y3-02 — NIST 800-53 mapping ambiguity between Rev 4 and Rev 5 (HIGH)

**Risk.** Pub 1075 Rev. 11-2021 cross-walks selectively to Rev 5
while retaining Rev 4 mappings for legacy families. A catalog
that conflates the two produces a false-positive coverage claim
(e.g. claiming AU-11 Rev 5 covers when only AU-11 Rev 4 was
intended).

**Mitigation.**
- The catalog schema requires **two parallel mapping fields**
  (`nist_800_53_r4_mapping[]` and `nist_800_53_r5_mapping[]`); an
  empty array is a valid value and means "no published mapping".
- The hand-curated `nistR4Map` and `nistR5Map` extractor
  constants are version-pinned to Pub 1075 Rev. 11-2021's
  Appendix B + §9 text; any future revision triggers a re-
  curation, captured in CHANGELOG.
- The loader validates every NIST ID against
  `core/control-benchmark.ts` and emits a warning on unknown
  IDs; the warning surfaces in CI logs.
- The OQ-Y-04 question ("Does NIST 800-53 Rev 5 mapping in IRS
  1075 Appendix B fully replace Rev 4?") is tracked in
  LOOP-Y-SPEC.md §9.

### R-Y3-03 — SCSEM cross-walk drift when IRS publishes new SCSEMs (MEDIUM)

**Risk.** The IRS Office of Safeguards publishes SCSEM updates
periodically (per-platform; no single release schedule). The
extractor's hand-curated `scsemLinkageMap` becomes stale when a
new SCSEM check is introduced.

**Mitigation.**
- The extractor records `scsem_published_date` per platform; the
  loader exposes `getCurrentScsemForPlatform()` so Y.Y4 always
  reads the latest applicable SCSEM at SSR-build time.
- The catalog emits `provenance:scsem-check-orphan` warnings when
  a new SCSEM check is not yet linked to a shall-statement; CI
  surfaces these warnings as PR comments.
- The IRM 11.3.36 quote ("most current version applies") is the
  contract the operator works against; the tracker UI surfaces a
  banner when an SCSEM PDF in `docs/sources/scsem/` is older than
  365 days.
- The `scsemLinkageMap` is the single point of update when new
  SCSEM versions drop; one extractor re-run, one PR.

### R-Y3-04 — Catalog version skew (Rev. 11-2024 / Rev. 11-2025 supersession) (MEDIUM)

**Risk.** The IRS Office of Safeguards typically refreshes Pub
1075 every 3-5 years; the next anticipated refresh is "Rev.
11-2024" or "Rev. 11-2025" (per the IRS Safeguards Program
landing page accessed 2026-06-07). A CSP that pins to Rev.
11-2021 after a successor drops will fall out of compliance.

**Mitigation.**
- The catalog file naming scheme includes the revision label
  (`data/irs-1075-catalog.json` for the current version; older
  versions saved as `data/irs-1075-catalog-rev11-2021.json`
  after the next revision ships).
- The loader's `loadCatalog({version})` accepts an explicit
  version selector; defaults to the most recent snapshot.
- The orchestrator emits a warning when the active catalog is
  more than 36 months old.
- LOOP-Y-SPEC.md §1.5 documents the version-pinning rule.

### R-Y3-05 — Statutory-anchor interpretation ambiguity (MEDIUM)

**Risk.** Some Pub 1075 shall-statements implement multiple §6103
subsections (e.g. §5 access restrictions arguably anchor to both
§6103(p)(4)(A)(iii) and §6103(p)(4)(A)(iv)). The hand-curated
`statutoryAnchorMap` carries the catalog author's interpretation;
a 3PAO may disagree.

**Mitigation.**
- The map is documented in §6.5.1 of the extractor with
  inline comments citing the IRS PDF page numbers that
  support each pin.
- Statements without a clear pin record `anchor_provenance:
  "secretary-prescribed"` per §6103(p)(4)(A)(iv) and an empty
  `statutoryAnchor`; the loader does not crash on empty anchors.
- The OQ-Y-04 question is tracked in LOOP-Y-SPEC.md §9 as
  IRS-RESEARCH.

### R-Y3-06 — Signing-key absence at extract-time (LOW)

**Risk.** The extractor depends on `core/sign.ts::signEnvelope()`
which depends on the Ed25519 signing key being resolvable. If
the key is not available (operator has not provisioned the
production key), the extractor cannot produce a signed
snapshot.

**Mitigation.**
- The extractor exits 2 with a `provenance:signing-key-unresolvable`
  diagnostic if `core/sign.ts::resolveSigningKey()` raises.
- The existing LOOP-A.A5 documentation covers key provisioning.
- The unit tests use a test-only ephemeral key (Ed25519
  generated via `nacl.sign.keyPair()` per test) so CI does
  not need the production key.

## 10. Open questions

| # | Question | Owner | Resolution path |
|---|---|---|---|
| OQ-Y3-A | Does Pub 1075 Rev. 11-2021 carry an authoritative Rev 5 mapping for §9.3 (audit) or is Rev 5 inferred from text? | Y.Y3 implementer | Read Pub 1075 Appendix B verbatim; record findings in commit message + update `nistR5Map` |
| OQ-Y3-B | Does the IRS Office of Safeguards accept catalog snapshots from third-party tooling as part of a 3PAO submission? | Operator + Y.Y4 ship | Out of Y.Y3 scope; Y.Y4 OQ-Y-02 covers SSR acceptance |
| OQ-Y3-C | Is the SCSEM-to-Pub-1075 cross-walk publicly published in machine-readable form? | Y.Y3 implementer | Check IRS Office of Safeguards FOIA reading-room; if no, hand-curate from PDF text |
| OQ-Y3-D | What is the canonical regex for SCSEM check IDs across all platforms? | Y.Y3 implementer | Confirm by inspecting at least 4 SCSEM PDFs (AWS, Azure, Windows, RHEL) at extract time |
| OQ-Y3-E | Should the extractor support PDF OCR for older Pub 1075 revisions that lack a text layer? | Future Y.Y3 maintainer | Defer to Rev. 11-2024 ingest; current Rev. 11-2021 has a clean text layer |
| OQ-Y3-F | Does §1.1's FTI definition count as a "shall" statement or is it metadata? | Y.Y3 implementer | Treat as `kind: "definition"`; not enforceable in itself but consumed by inventory `data_classes` taxonomy |

## 11. REQUIRES-OPERATOR-INPUT

| Field name | Type | Validator | UI location | Failure mode if missing |
|---|---|---|---|---|
| `IRS_1075_PDF_PATH` | absolute filesystem path | path exists; readable; SHA-256 matches `IRS_1075_PDF_SHA256` | env var or `.env.local`; documented in `docs/sources/README.md` | extractor exits 2 with `provenance:irs-1075-pdf-missing`; Y.Y4 cannot build SSR; IRS-1075 path of LOOP-Y blocked |
| `IRS_1075_PDF_SHA256` | 64-char lowercase hex string | regex `^[0-9a-f]{64}$`; matches computed hash | env var or `.env.local` | extractor exits 2 with `provenance:irs-1075-pdf-sha-mismatch` (or `provenance:irs-1075-pdf-sha-missing` if blank); operator alerted to re-download from irs.gov |
| `IRS_SCSEM_DIR` | absolute directory path | exists; contains ≥ 1 file matching `SCSEM_*.pdf` | env var or `.env.local` | extractor exits 2 with `provenance:scsem-dir-missing`; catalog cannot emit SCSEM cross-walk; Y.Y4 SSR §3 evidence sources will be empty |
| `signing_key_id` | string identifier resolvable by `core/sign.ts` | non-expired Ed25519 key in the LOOP-A.A5 key registry | LOOP-A.A5 config; tracker DB key registry | extractor exits 2 with `provenance:signing-key-unresolvable` |
| `org-profile.yaml: serves_federal_tax_information` | boolean | strict bool | `cloud-evidence/org-profile.yaml` | LOOP-Y IRS path is skipped end-to-end; Y.Y3 is not invoked; orchestrator emits `loop:Y irs-path skipped — serves_federal_tax_information=false` |
| `policy_version_override` (optional) | string matching `^rev-\d{1,2}-\d{4}$` | regex | CLI `--irs-1075-version=rev-11-2024` or env | (optional) ignored if blank; extractor uses cover-page-detected version |
| `--rfc3161-enabled` flag | boolean CLI flag | n/a | CLI | (optional) when off, `provenance.rfc3161_token` is the empty string; signed Ed25519 envelope still produced |

## 12. Implementation log

| date | session | action | commit | notes |
|---|---|---|---|---|
| 2026-06-08 | spec proposed | Specification authored via FedPy workflow | TBD | Per-slice doc authored to LOOP-Y-SPEC.md §3 + LOOP-Y-SPEC.md §17 / §19 schemas; ≥ 23 tests scoped; 6 risks catalogued; all citations verbatim from IRS Pub 1075 Rev. 11-2021 + IRC §6103 + IRS Safeguards Program HTML; 7-step completion procedure pre-quoted in §13 |
|   |   |   |   |   |
|   |   |   |   |   |

## 13. Completion checklist

The 7-step procedure quoted verbatim from
`cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`:

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

> Step 8: After commit lands, append/update the slice row in STATUS.md (status -> done, commit hash, last_updated); update the loop SPEC status table; append a CHANGELOG entry; push to origin/main; verify with 'git log --oneline -3'. Only THEN is the slice closed.

### Slice-specific addenda

In addition to the universal 7-step procedure, Y.Y3 carries the
following slice-specific completion items because of its
catalog-snapshot nature:

- **Step 1a — Snapshot byte-determinism check.** After
  `npm test` passes, run `npm run extract:irs-1075` twice in
  succession and verify
  `sha256(data/irs-1075-catalog.json)` is identical between
  runs. This is the canonical-JSON / RFC 8785 contract.
- **Step 1b — Source-PDF SHA-256 recorded.** Confirm the
  operator-supplied `IRS_1075_PDF_SHA256` is recorded in
  `docs/sources/README.md` (the file is gitignored but the
  hash + the download URL go in the README so the next
  session can re-download an identical artifact).
- **Step 2a — STATUS.md frontmatter row.** Add a row for
  Y.Y3 in the LOOP-Y section. If Y.Y4 is still pending,
  the "Overall → Next priority" line advances to Y.Y4.
- **Step 3a — LOOP-Y-SPEC.md §12 status table.** Flip the
  Y.Y3 row to `done`; the `last_updated` becomes today's
  ISO date.
- **Step 4a — CHANGELOG entry mentions the snapshot ID.**
  The "Unreleased" entry MUST name the catalog
  snapshot id (`irs-1075-rev11-2021-YYYYMMDDThhmmssZ`)
  and the source-PDF SHA-256 so the audit trail is
  recoverable from CHANGELOG alone.
- **Step 5a — Submission-bundler registration committed.**
  The change to `cloud-evidence/core/submission-bundle.ts`
  adding `data/irs-1075-catalog.json` and
  `data/irs-scsem-matrix.json` to `WELL_KNOWN` MUST land in
  the same commit as the catalog files themselves.
- **Step 6a — Risks register sync.** If implementation
  surfaced any new risk (e.g. a Pub 1075 §9 sub-section
  with no clear NIST mapping), append to
  `cloud-evidence/docs/loops/LOOP-Y-RISKS.md` in the
  same commit (per the CLAUDE.md "Strong directive" §6).
- **Step 7a — Verify GitHub.** After `git push origin main`,
  run `git log --oneline -3` and confirm the slice's
  commit hash appears at the top.

Only when all of the above land (universal 7 + the slice-
specific addenda) is Y.Y3 closed. The next session resuming
LOOP-Y reads STATUS.md, sees Y.Y3 as `done`, and proceeds to
Y.Y4 per the dependency graph.
