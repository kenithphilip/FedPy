---
slice_id: Z.Z2
title: ISO 27001 Statement of Applicability (SoA) Emitter — clause 6.1.3(d) canonical .docx + signed JSON envelope
loop: Z
status: proposed
commit: TBD
completed_date: —
depends_on:
  - Z.Z1                                # ISO/IEC 27001:2022 Annex A catalog snapshot + NIST OLIR + FedRAMP Moderate crosswalk
  - LOOP-B                              # Risk register — populates clause 6.1.3(d) inclusion/exclusion justifications
  - LOOP-A.A4                           # Submission bundler — adds SoA .docx + .json + .sig to the bundle catalogue
  - LOOP-A.A5                           # Signing pipeline (Ed25519 + RFC 3161 + RFC 8785 canonicalization)
  - tracker DB (existing)               # persists iso_27001_soa + iso_27001_soa_controls rows + signed audit log
  - existing core/oscal-ssp-docx.ts     # OOXML / zip-store helpers (document.xml, styles.xml, numbering.xml, [Content_Types].xml)
  - existing core/oscal-poam.ts         # POA&M emitter — Z.Z2 emits one "ISO Control Gap" finding per non-applied / partially-implemented control
blocks: []
estimated_effort: medium (~5-7 working days for single implementer)
last_updated: 2026-06-08
applicable_conditional: false
condition: |
  Z.Z2 inherits Z.Z1's conditional gating verbatim. It activates when the
  CSP's `org-profile.yaml` declares `seeks_iso_27001: true` (alias of
  `--international-equivalence` for the LOOP-Z orchestrator gate). When the
  flag is false the slice is skipped entirely; the orchestrator emits a
  one-line `coverage:skipped:Z.Z2:not-applicable` line and exits clean.
  When the flag is true but the Z.Z1 catalog snapshot has not been emitted
  in the past 90 days, Z.Z2 refuses to emit and surfaces a
  `coverage:miss:Z.Z2:catalog-stale` diagnostic naming the missing
  snapshot file. The SoA is the single most-frequently-audited artifact
  in the ISO certification cycle (Stage 1 documentation review consumes
  it directly), so stale catalogs cannot back a current SoA.
trigger_flag: "--iso-z-z2"
trigger_env: CLOUD_EVIDENCE_Z_Z2
---

# Z.Z2 — ISO 27001 Statement of Applicability (SoA) Emitter

> The Statement of Applicability is **the single most-cited artefact in an
> ISO 27001:2022 certification audit**. Clause 6.1.3(d) makes the SoA a
> mandatory deliverable — it is the only ISMS document required to be
> "produced" by name in the normative text of the standard. A
> certification body's Stage 1 documentation review reads the SoA first
> and uses it to scope the Stage 2 on-site audit; the Stage 2 audit
> evidence is keyed back to SoA control rows; the surveillance audit
> samples SoA rows year-over-year; the recertification audit at year 3
> re-reads the SoA in full. If the SoA is wrong, missing controls, or
> uses copy-pasted boilerplate justifications, the audit fails on Day 1.
>
> Z.Z2 emits the SoA in two reciprocal forms:
>
> 1. **Canonical JSON envelope** — machine-readable, RFC 8785
>    canonicalized, Ed25519-signed, RFC 3161 timestamped. This is the
>    artefact LOOP-Q.Q1 (Marketplace) consumes to publish the
>    "ISO 27001 certified" badge; it is also what the EUCS submission
>    package (Z.Z5) bundles as machine-readable evidence.
> 2. **OOXML `.docx`** — the canonical layout the certification body's
>    auditor reads (control ID column, name, applicable Y/N,
>    justification, implementation status, evidence reference). The
>    layout matches the de-facto template used across all major
>    certification bodies (BSI, DNV, TÜV SÜD, Lloyd's Register,
>    Schellman, A-LIGN, Coalfire-ISO).
>
> Per `cloud-evidence/CLAUDE.md` Rule 4 the operator transmits the SoA to
> the certification body; Z.Z2 produces the artefact pair, the tracker
> captures the transmission timestamp + officer ID + acknowledgement
> reference, and the signed audit log records every operator action.

---

## 1. Mission

Z.Z2 reads the Z.Z1 catalog snapshot (`data/iso-27001-2022-annex-a.json`),
joins each of the 93 Annex A controls against the operator's risk-treatment
decisions captured in the LOOP-B risk register and against the implementation
evidence collected by the existing cloud-evidence collectors (LOOP-A through
LOOP-W), and emits the canonical Statement of Applicability per ISO/IEC
27001:2022 clause 6.1.3(d). For every Annex A control the SoA carries five
required fields per clause 6.1.3(d): (1) the control identifier (A.5.1
through A.8.34), (2) the canonical short name, (3) the applicability
disposition (`applicable` / `not-applicable`), (4) the implementation status
(`implemented` / `partially-implemented` / `planned` / `not-applicable`), and
(5) the justification text. The justification is REQUIRED for both inclusion
and exclusion — clause 6.1.3(d)(4) is explicit that exclusions must be
justified. Z.Z2 refuses to emit a SoA with any control whose justification
field is unset.

The slice composes the JSON envelope first, validates it against the JSON
Schema `https://cloud-evidence.example/schemas/iso-27001-soa-v1.json`, then
renders the .docx using the existing OOXML zip-store helpers from
`core/oscal-ssp-docx.ts`. The .docx layout is the canonical SoA table
shape (one row per Annex A control across all four themes
Organizational / People / Physical / Technological), preceded by a cover
page with the CSP name, ISMS scope statement, ISMS boundary diagram
reference, SoA version, SoA date, SoA author (Information Security
Manager), SoA approver (top management per clause 5.1), and the verbatim
clause 6.1.3(d) reference. After the SoA table the .docx carries an
appendix enumerating the upstream evidence (Z.Z3 27017 cloud overlay,
Z.Z4 27018 PII processor, Z.Z5 27701 PIMS, and the cross-loop evidence
catalogue from LOOP-T SSDF, LOOP-R PQC, LOOP-W prohibited-vendor, etc.).

Z.Z2 also emits OSCAL POA&M items via the existing `core/oscal-poam.ts`
for every control whose implementation status is `partially-implemented`
or `planned`. The finding template `ISO-CONTROL-GAP` carries the
control ID, the gap description (from the risk register row), the
remediation timeline, the responsible owner, and a composite risk
score from LOOP-B.B1. The POA&M items flow into the standard FedRAMP
POA&M chain so the CSP's compliance team can manage ISO-driven
remediation alongside FedRAMP-driven remediation in a single backlog.

The slice persists the SoA into the tracker DB `iso_27001_soa` table
(one row per SoA emission) and one row per Annex A control into
`iso_27001_soa_controls`. The tracker UI surfaces a per-SoA review +
sign-off page at `/iso-soa/<soa_id>` with a per-control drill-down, a
read view of the linked risk-register rows, a read view of the linked
upstream evidence, and an operator action to record top-management
sign-off (per clause 5.1) and certification-body submission. Each
operator action flows through the existing signed audit log.

The slice deliberately does NOT redistribute the verbatim ISO 27001 or
27002 control text — ISO standards are copyrighted (CHF 138 to CHF 198
per standard) and Apache-2.0 redistribution is prohibited. Z.Z2 carries
the publicly-available facts (control IDs, canonical short names,
NIST 800-53 cross-references, FedRAMP Moderate cross-references) and
references the ISO standard by canonical URL (e.g.
https://www.iso.org/standard/27001 for 27001:2022) so the certification
body's auditor can consult their organization's licensed copy for full
implementation guidance. This is the same approach used by every
ISO-adjacent compliance tool (GoComply, OneTrust, AuditBoard, Drata).

---

## 2. Authoritative sources

Every URL accessed 2026-06-08. Verbatim quotes appear in Markdown
blockquotes. Where the ISO source is paywalled (most ISO standards
are), the implementer quotes the publicly-available preview pages and
the publicly-available NIST OLIR informative mapping. Where the ENISA
or EUR-Lex source is freely available, the implementer quotes verbatim
from the official journal of record.

### 2.1 ISO/IEC 27001:2022 — clause 6.1.3(d) (the normative SoA mandate)

URL: https://www.iso.org/standard/27001 (accessed 2026-06-08).
Status: Published 2022-10. Withdrew the 2013 edition; transition period
for 2013 certificates ended 2025-10-31. All new and renewed
certifications must reference the 2022 edition.

Publicly-available preview text from ISO's standard page describing the
SoA requirement (re-quoted from the operator's licensed copy where the
preview cuts off; this excerpt is the operative one for Z.Z2):

> "The organization shall: ... (d) produce a Statement of Applicability
> that contains: the necessary controls (see 6.1.3 b) and c)) and
> justification for their inclusion; whether the necessary controls are
> implemented or not; and the justification for excluding any of the
> Annex A controls."

The clause 6.1.3(d) text is the legal source of every Z.Z2 design
decision. Three facts are normatively required for every control row:

1. **The "necessary controls"** — every Annex A control is in scope by
   default; exclusion requires justification. Z.Z2 enumerates all 93
   controls; the operator sets `applicable=false` only with a
   justification.
2. **Implementation status** — whether the control is implemented or
   not. Z.Z2 maps this to a four-value enum
   (`implemented` / `partially-implemented` / `planned` / `not-applicable`).
3. **Justification text** — required for both inclusion AND exclusion.
   Z.Z2 refuses to emit a SoA row with an empty justification.

Additionally, clause 6.1.3 sub-paragraph (e) requires the operator to
formulate a risk-treatment plan and sub-paragraph (f) requires the
operator to obtain risk-owner approval. Z.Z2 cross-references both via
the LOOP-B risk register row's `treatment_plan_uid` and
`risk_owner_approval_uid` fields.

Clause 4.3 (Scope of the ISMS) is also normatively required and is the
header of the SoA `.docx` cover page:

> "The organization shall determine the boundaries and applicability of
> the information security management system to establish its scope. ...
> The scope shall be available as documented information."

Z.Z2's `.docx` cover page carries the operator-supplied scope statement
verbatim from `org-profile.yaml::iso_27001.isms_scope_statement`.

### 2.2 ISO/IEC 27001:2022 — Annex A (the 93 controls)

Annex A is the reference control set the SoA enumerates. Per the
publicly-available ISO 27001:2022 Annex A summary:

> "The information security controls listed in Annex A are derived from
> ISO/IEC 27002:2022 and aligned with it. The list is not exhaustive
> and an organization could consider additional control objectives and
> controls if needed."

The 93 controls are organized into 4 themes:

| Theme | Range | Count | Theme name (canonical) |
|---|---|---|---|
| A.5 | A.5.1 – A.5.37 | 37 | Organizational controls |
| A.6 | A.6.1 – A.6.8 | 8 | People controls |
| A.7 | A.7.1 – A.7.14 | 14 | Physical controls |
| A.8 | A.8.1 – A.8.34 | 34 | Technological controls |
| **Total** | | **93** | |

Z.Z2 enumerates all 93 in the SoA, even controls marked
`not-applicable`. The certification body explicitly checks that the SoA
covers all 93 (clause 6.1.3(d)(c): "compare the controls determined in
6.1.3 b) above with those in Annex A and verify that no necessary
controls have been omitted").

### 2.3 ISO/IEC 27002:2022 — Information security controls (code of practice)

URL: https://www.iso.org/standard/27002 (accessed 2026-06-08).
Status: Published 2022-02. Provides implementation guidance for the
93 controls referenced by 27001:2022 Annex A.

Publicly-available preview text:

> "This document provides a reference set of generic information
> security controls including implementation guidance. This document is
> designed to be used by organizations: a) within the context of an
> information security management system (ISMS) based on ISO/IEC 27001;
> b) for implementing information security controls based on
> internationally recognized best practices; c) for developing
> organization-specific information security management guidelines."

27002:2022 introduces a 5-attribute classification scheme per control
(the 2013 edition had only a single "category" attribute). Z.Z2's SoA
.docx surfaces three of the five attributes per row (the operator's
licensed 27002 copy carries the full set):

| Attribute | Values | Used in Z.Z2 |
|---|---|---|
| Control type | Preventive / Detective / Corrective | Yes — surfaced as a SoA column |
| Information security properties | Confidentiality / Integrity / Availability | Yes — surfaced as a SoA column |
| Cybersecurity concepts | Identify / Protect / Detect / Respond / Recover | Yes — surfaced as a SoA column |
| Operational capabilities | Governance, Asset management, ... | Not surfaced in default SoA |
| Security domains | Governance and ecosystem, Protection, Defence, Resilience | Not surfaced in default SoA |

The Cybersecurity Concepts attribute aligns 27002 with NIST CSF v2.0;
Z.Z2 exposes this on every SoA row so the auditor can trace
27002 ↔ NIST CSF without referencing a separate crosswalk.

### 2.4 ISO/IEC 27017:2015 — Code of practice for cloud-services security

URL: https://www.iso.org/standard/43757 (accessed 2026-06-08).
Status: Published 2015-12. Supplements 27002 with cloud-specific
implementation guidance + adds 7 cloud-specific controls in the
`CLD.*` namespace.

Publicly-available preview text (paraphrased from ISO's standard page):

> "This Recommendation | International Standard provides guidelines for
> information security controls applicable to the provision and use of
> cloud services by providing: additional implementation guidance for
> relevant controls specified in ISO/IEC 27002; additional controls
> with implementation guidance that specifically relate to cloud
> services."

Z.Z2 references 27017 evidence (emitted by Z.Z3) for the 37 augmented
27002 controls and for the 7 cloud-specific CLD.* controls. The SoA
`.docx` carries a separate appendix table listing the CLD.* controls
that the certification body audits separately if the operator's ISMS
scope claims 27017 certification (a separate certificate from the
27001 certificate, though usually issued by the same body in a single
audit cycle).

### 2.5 ISO/IEC 27018:2019 — PII protection in public cloud

URL: https://www.iso.org/standard/76559 (accessed 2026-06-08).
Status: Published 2019-01 (second edition). Supplements 27002 with
PII-protection guidance for public-cloud CSPs acting as PII
processors.

Publicly-available preview text:

> "This document establishes commonly accepted control objectives,
> controls and guidelines for implementing measures to protect
> Personally Identifiable Information (PII) in line with the privacy
> principles in ISO/IEC 29100 for the public cloud computing
> environment. In particular, this document specifies guidelines based
> on ISO/IEC 27002, taking into consideration the regulatory
> requirements for the protection of PII which might be applicable
> within the context of the information security risk environment(s)
> of a provider of public cloud services."

Z.Z2 references 27018 evidence (emitted by Z.Z4) for the 11 PII-specific
control areas (consent and choice, purpose legitimacy, collection
limitation, data minimization, etc.) and for the 27002 augmentations.

### 2.6 ISO/IEC 27701:2019 — Privacy Information Management System (PIMS)

URL: https://www.iso.org/standard/71670 (accessed 2026-06-08).
Status: Published 2019-08. Extends 27001 + 27002 with a Privacy
Information Management System.

Publicly-available preview text:

> "This document specifies requirements and provides guidance for
> establishing, implementing, maintaining and continually improving a
> Privacy Information Management System (PIMS) in the form of an
> extension to ISO/IEC 27001 and ISO/IEC 27002 for privacy management
> within the context of the organization."

Z.Z2 cross-references 27701 evidence (emitted by Z.Z5) for the privacy-
management overlay; the SoA carries a per-control flag
`pims_applies: bool` and, when true, references the 27701 Annex A
(PII Controller) or Annex B (PII Processor) control identifier alongside
the 27001 control row.

### 2.7 ENISA EUCS Candidate Scheme

URL: https://www.enisa.europa.eu/topics/certification/cybersecurity-certification-framework/eucs
(accessed 2026-06-08).
Status: Candidate scheme published 2020; draft updated through 2024;
awaiting European Commission adoption.

Verbatim from the ENISA EUCS factsheet (publicly available):

> "The European Union Cybersecurity Certification Scheme on Cloud
> Services (EUCS) is a candidate cybersecurity certification scheme
> that aims to harmonize the security of cloud services in the EU. It
> covers Infrastructure as a Service (IaaS), Platform as a Service
> (PaaS), and Software as a Service (SaaS) cloud services. The scheme
> defines three assurance levels — Basic, Substantial, and High — and
> a set of security objectives and requirements that cloud service
> providers must meet to obtain certification at each level."

EUCS Substantial level requires the operator to submit a Statement of
Applicability that references all relevant 27001 Annex A controls plus
the 27017 cloud-overlay controls; EUCS High level adds 27018 + 27701.
Z.Z2's SoA is the input to the Z.Z5 EUCS submission package; the SoA
carries the `eucs_level: 'basic' | 'substantial' | 'high'` field
selected by the operator.

### 2.8 EU Cybersecurity Act — Regulation (EU) 2019/881

URL: https://eur-lex.europa.eu/eli/reg/2019/881/oj (accessed 2026-06-08).
Status: In force since 2019-06-27.

Verbatim from EUR-Lex Article 56(1):

> "The certification of ICT products, ICT services and ICT processes
> shall be voluntary, unless otherwise specified by Union law or
> Member State law."

Verbatim from EUR-Lex Article 49(1):

> "ENISA shall prepare a candidate European cybersecurity certification
> scheme, hereinafter the 'candidate scheme', following a request by
> the Commission or, after consulting the ECCG, on its own initiative."

The Regulation establishes the legal basis on which the ENISA EUCS
Candidate Scheme transitions from candidate to adopted. Z.Z2's SoA is
the upstream artefact for Z.Z5's EUCS submission package; the
adoption of EUCS as a delegated act will make the EUCS submission
mandatory for EU public-sector cloud procurement.

### 2.9 NIST OLIR — ISO 27001 ↔ NIST 800-53 Rev 5 informative crosswalk

URL: https://csrc.nist.gov/projects/olir (accessed 2026-06-08).
Status: Active NIST programme. The NIST Online Informative References
publishes one-way informative mappings between cybersecurity documents.

Verbatim from the OLIR program page:

> "The National Online Informative References Program is a NIST effort
> to facilitate subject matter experts (SMEs) in defining standardized
> online informative references (OLIRs) between elements of their
> cybersecurity, privacy, and workforce documents and elements of
> other cybersecurity, privacy, and workforce documents. OLIRs are
> simple, structured, and machine-readable, allowing them to be easily
> shared and consumed."

Z.Z2 carries the OLIR-published per-control relationship type (subset /
equivalent / intersect / superset / no_relationship) per the upstream
Z.Z1 catalog snapshot. The SoA `.docx` surfaces the relationship type
alongside the NIST 800-53 control reference per row.

### 2.10 ISO/IEC 17021-1:2015 — Audit methodology for management systems

URL: https://www.iso.org/standard/61651 (accessed 2026-06-08).
Status: Published 2015-06.

Publicly-available preview text:

> "This document contains principles and requirements for the
> competence, consistency and impartiality of bodies providing audit
> and certification of all types of management systems. Certification
> bodies operating to this document need not offer all types of
> management system certification."

17021-1 is the meta-standard governing how a certification body
performs the audit. Z.Z2's SoA `.docx` layout is matched to the
Stage 1 documentation review pattern described in 17021-1 §9.3
(adequacy of documented information). The certification body's
auditor reads the SoA cover page (scope), reads the SoA table (control
applicability + justification + implementation status), confirms the
referenced upstream evidence exists, and approves Stage 2 audit
scoping based on the SoA.

### 2.11 ISO/IEC 27006:2015 (+ Amd 2020) — Requirements for ISMS certification bodies

URL: https://www.iso.org/standard/62313 (accessed 2026-06-08).
Status: Published 2015-09 with 2020 amendment.

Publicly-available preview text:

> "This document supplements ISO/IEC 17021-1. It primarily augments the
> requirements of ISO/IEC 17021-1 to include the certification of an
> information security management system (ISMS). It specifies
> requirements and provides guidance for bodies providing audit and
> certification of an information security management system (ISMS),
> in addition to the requirements contained within ISO/IEC 17021-1 and
> ISO/IEC 27001."

27006 governs the ISMS-specific certification-body requirements
(competence of ISMS auditors, audit-day computation per CSP size,
recertification cadence). Z.Z2 does not consume 27006 directly but the
SoA `.docx` includes the operator's selected certification body's
accreditation reference (operator-supplied via
`org-profile.yaml::iso_27001.certification_body`) so the auditor's
accreditation chain is documented in the SoA.

### 2.12 ISO/IEC 27005:2018 — Information security risk management

URL: https://www.iso.org/standard/75281 (accessed 2026-06-08).
Status: Published 2018-07. 2022 revision pending publication.

Publicly-available preview text:

> "This document provides guidelines for information security risk
> management. This document supports the general concepts specified in
> ISO/IEC 27001 and is designed to assist the satisfactory
> implementation of information security based on a risk management
> approach."

27005 is the methodology reference for the ISMS risk-management process
required by clause 6.1.2. Z.Z2 reads the LOOP-B risk register (which is
27005-aligned per LOOP-B's design) and joins each risk-register row to
the Annex A controls it drives via the row's
`treatment_controls[]` field. The SoA inclusion justification is
sourced from the joined risk-register row's `treatment_rationale`.

---

## 3. Scope

### 3.1 In scope

- Read Z.Z1 catalog snapshot (`data/iso-27001-2022-annex-a.json`) +
  verify Ed25519 signature.
- Read LOOP-B risk register (tracker DB) + join each risk row to the
  Annex A controls it drives.
- Read upstream evidence indices from Z.Z3 (27017 cloud overlay),
  Z.Z4 (27018 PII processor), Z.Z5 (27701 PIMS — when ready),
  LOOP-T (SSDF Common Form), LOOP-R (PQC inventory), LOOP-W
  (prohibited-vendor catalog), LOOP-A.A1 (POA&M items currently open),
  and existing cloud-evidence collector outputs (KSI evidence files
  under `out/`).
- Compose the canonical JSON SoA envelope conforming to the schema
  `https://cloud-evidence.example/schemas/iso-27001-soa-v1.json`.
- RFC 8785 canonicalize + Ed25519 sign + RFC 3161 timestamp via the
  existing pipeline.
- Render the OOXML `.docx` SoA report via the existing zip-store
  helpers; one master table per Annex A theme; appendix per upstream
  evidence source.
- Persist into tracker DB `iso_27001_soa` + `iso_27001_soa_controls`
  tables (one row per Annex A control per SoA emission).
- Emit OSCAL POA&M items for `partially-implemented` and `planned`
  rows via `core/oscal-poam.ts` (finding template `ISO-CONTROL-GAP`).
- Register the SoA artefact triple (.json + .docx + .sig) into the
  LOOP-A.A4 submission bundle `WELL_KNOWN` registry.
- Surface the SoA review + sign-off page at `/iso-soa/<soa_id>` in the
  tracker UI (status pane component included in this slice).

### 3.2 Out of scope

- **Auto-submission to a certification body.** REO Rule 4 forbids the
  system from acting on behalf of the operator on a regulatory or
  contractual submission. The operator transmits the SoA; the tracker
  captures the transmission timestamp + officer ID + acknowledgement
  reference.
- **The ISO 27001 certification audit itself.** The certification body
  performs Stage 1 documentation review + Stage 2 onsite/virtual audit
  per ISO/IEC 17021-1. Z.Z2 emits the SoA the body consumes; it does
  NOT perform the audit.
- **27017 / 27018 / 27701 emission.** Each is owned by a sibling slice
  (Z.Z3 / Z.Z4 / Z.Z5). Z.Z2 references their outputs in the SoA
  appendix but does NOT generate them.
- **Top-management sign-off automation.** Clause 5.1 requires top-
  management commitment; the SoA is signed by the operator's top
  management (typically CISO + CEO). The tracker captures the
  sign-off as an operator action; Z.Z2 does not auto-sign on behalf
  of management.
- **Risk-register row creation.** LOOP-B.B1 owns risk-register row
  creation. Z.Z2 reads rows; it does not create or modify them.
- **Verbatim ISO 27001 / 27002 control text redistribution.** ISO
  standards are copyrighted. Z.Z2 carries control IDs + canonical
  short names + crosswalk references only.
- **EUCS submission package assembly.** Owned by Z.Z5. Z.Z2 emits the
  SoA that feeds the EUCS package; the package assembly is Z.Z5's
  responsibility.
- **Common Criteria (ISO/IEC 15408) certification.** Different scope
  (product-evaluation framework). Out of LOOP-Z entirely.
- **ISO/IEC 22301 BCMS.** Sibling management-system standard; not
  covered by LOOP-Z.

---

## 4. Inputs

TypeScript-form for the data structures Z.Z2 consumes:

```typescript
// From Z.Z1: the signed catalog snapshot
interface ISO27001CatalogSnapshot {
  $schema: string;
  schema_version: string;
  snapshot_id: string;
  snapshot_date: string;             // YYYY-MM-DD
  standard_edition: '2022';
  policy_published_date: '2022-10-25';
  policy_effective_date: '2025-10-31';   // legacy transition deadline
  csp_name: string;
  themes: AnnexATheme[];
  control_count: 93;
  provenance: SnapshotProvenance;
  signature: Ed25519Signature;
  rfc3161_timestamp: RFC3161Token;
}

interface AnnexATheme {
  theme_id: 'A.5' | 'A.6' | 'A.7' | 'A.8';
  theme_name: 'Organizational controls' | 'People controls' |
              'Physical controls' | 'Technological controls';
  controls: AnnexAControl[];
}

interface AnnexAControl {
  control_id: string;                 // 'A.5.1' through 'A.8.34'
  control_short_name: string;         // 'Policies for information security'
  iso_27002_clause_ref: string;       // '27002:2022 §5.1'
  attributes: {
    control_type: ('Preventive' | 'Detective' | 'Corrective')[];
    information_security_properties: ('Confidentiality' | 'Integrity' | 'Availability')[];
    cybersecurity_concepts: ('Identify' | 'Protect' | 'Detect' | 'Respond' | 'Recover')[];
  };
  nist_800_53_rev5_mapping: {
    control_ids: string[];            // e.g. ['AC-2', 'AC-3']
    olir_relationship: 'subset' | 'equivalent' | 'intersect' | 'superset' | 'no_relationship';
    olir_source_url: string;
  };
  fedramp_moderate_ksi_mapping: string[];   // e.g. ['IAM-MFA']
  legacy_27001_2013_mapping?: string;       // for transition audits
}

// From LOOP-B: risk register row (one-to-many with Annex A controls)
interface RiskRegisterRow {
  risk_uid: string;                   // ULID
  risk_title: string;
  risk_description: string;
  inherent_score: number;             // 0-25 per LOOP-B.B1
  residual_score: number;
  treatment_option: 'mitigate' | 'transfer' | 'avoid' | 'accept';
  treatment_rationale: string;        // becomes part of SoA justification
  treatment_controls: string[];       // Annex A control IDs e.g. ['A.5.1','A.8.3']
  treatment_plan_uid: string;
  risk_owner_approval: {
    approver: string;
    approval_date: string;
    approval_artefact_path: string;
  };
  pims_relevance?: 'controller' | 'processor' | 'both' | 'none';
}

// Operator configuration
interface ISO27001OrgProfile {
  iso_27001: {
    seeks_iso_27001: boolean;
    isms_scope_statement: string;     // verbatim — appears on SoA cover page
    isms_boundary_diagram_ref: string;// path to LOOP-D output
    certification_body: {
      name: string;                   // 'BSI' | 'DNV' | 'TÜV SÜD' | ...
      accreditation_body: string;     // 'UKAS' | 'ANAB' | 'DAkkS'
      accreditation_reference: string;
      audit_cycle: 'initial' | 'surveillance-year-1' | 'surveillance-year-2' | 'recertification';
    };
    soa_author: {                     // ISMS Manager per clause 5.3
      name: string;
      title: string;
      email: string;
    };
    soa_approver: {                   // Top management per clause 5.1
      name: string;
      title: string;
      email: string;
    };
    eucs_level?: 'basic' | 'substantial' | 'high';
    pims_in_scope: boolean;           // triggers 27701 cross-reference
    cloud_overlay_in_scope: boolean;  // triggers 27017 cross-reference
    pii_processor_in_scope: boolean;  // triggers 27018 cross-reference
    signing_key_ref: string;          // KMS resource for SoA envelope sig
  };
}

// Per-control operator decisions (cjis-soa-decisions.yaml equivalent)
interface ISOSoADecisionsYAML {
  schema_version: '1.0.0';
  controls: SoAControlDecision[];
}

interface SoAControlDecision {
  control_id: string;
  applicable: boolean;
  implementation_status: 'implemented' | 'partially-implemented' | 'planned' | 'not-applicable';
  inclusion_justification: string;    // required when applicable=true
  exclusion_justification: string;    // required when applicable=false
  implementation_evidence_refs: EvidenceRef[];
  remediation_plan_ref?: string;      // when partially-implemented or planned
  responsible_owner: string;          // org role; cross-walked to RACI
  last_review_date: string;
}

interface EvidenceRef {
  source_loop: 'A' | 'B' | 'D' | 'E' | 'F' | 'G' | 'INV' | 'KSI' |
               'T' | 'R' | 'U' | 'V' | 'W' | 'X' | 'Y' | 'Z';
  artefact_path: string;              // e.g. 'out/ssdf-common-form.json'
  artefact_sha256: string;
  artefact_signed: boolean;
  reference_text: string;             // human-readable pointer
}
```

---

## 5. Outputs

### 5.1 Canonical JSON evidence envelope (the SoA)

Schema reference: `https://cloud-evidence.example/schemas/iso-27001-soa-v1.json`.

Path: `out/iso-27001-soa-<cspname>-<YYYY-MM-DD>.json`.

```jsonc
{
  "$schema": "https://cloud-evidence.example/schemas/iso-27001-soa-v1.json",
  "schema_version": "1.0.0",
  "soa_id": "iso-27001-soa-2026-06-08-acme-saas-001",
  "soa_version": "1.0.0",
  "soa_date": "2026-06-08",
  "csp_name": "Acme SaaS Inc",
  "isms_scope_statement": "<verbatim from org-profile.yaml>",
  "isms_boundary_diagram_ref": "out/diagrams/isms-boundary-2026-06-08.svg",
  "standard_edition": "ISO/IEC 27001:2022",
  "standard_url": "https://www.iso.org/standard/27001",
  "catalog_snapshot_ref": {
    "path": "data/iso-27001-2022-annex-a.json",
    "sha256": "...",
    "snapshot_id": "iso-27001-2022-snapshot-20260601",
    "verified_signature": true
  },
  "eucs_level": "substantial",
  "pims_in_scope": true,
  "cloud_overlay_in_scope": true,
  "pii_processor_in_scope": true,
  "controls": [
    {
      "control_id": "A.5.1",
      "control_short_name": "Policies for information security",
      "theme": "Organizational controls",
      "applicable": true,
      "implementation_status": "implemented",
      "inclusion_justification": "Required to demonstrate top-management commitment per clause 5.1; underpins every other Annex A control.",
      "exclusion_justification": null,
      "implementation_evidence_refs": [
        {
          "source_loop": "C",
          "artefact_path": "out/policy-pack/information-security-policy.docx",
          "artefact_sha256": "...",
          "artefact_signed": true,
          "reference_text": "Master Information Security Policy v3.2, approved 2026-04-15"
        }
      ],
      "risk_register_refs": ["risk-01HXYZ..."],
      "nist_800_53_rev5_refs": ["PM-1", "PL-1"],
      "fedramp_moderate_ksi_refs": ["CSX-SUM"],
      "olir_relationship": "subset",
      "attributes": {
        "control_type": ["Preventive"],
        "information_security_properties": ["Confidentiality", "Integrity", "Availability"],
        "cybersecurity_concepts": ["Identify"]
      },
      "responsible_owner": "CISO",
      "last_review_date": "2026-04-15",
      "pims_cross_ref": null
    },
    {
      "control_id": "A.5.7",
      "control_short_name": "Threat intelligence",
      "theme": "Organizational controls",
      "applicable": false,
      "implementation_status": "not-applicable",
      "inclusion_justification": null,
      "exclusion_justification": "CSP consumes threat intel exclusively via the upstream cloud provider's managed service (AWS GuardDuty + Inspector; GCP Security Command Center); no internal threat-intel function or subscription. Operator confirms via attestation 2026-04-20 that the dependency is monitored and renewal of the cloud-provider contract is annual.",
      "implementation_evidence_refs": [],
      "risk_register_refs": [],
      "nist_800_53_rev5_refs": ["SI-5", "PM-16"],
      "fedramp_moderate_ksi_refs": [],
      "olir_relationship": "intersect",
      "attributes": {
        "control_type": ["Detective", "Corrective"],
        "information_security_properties": ["Confidentiality", "Integrity"],
        "cybersecurity_concepts": ["Identify", "Detect"]
      },
      "responsible_owner": "CISO",
      "last_review_date": "2026-04-20",
      "pims_cross_ref": null
    }
    // ... 91 more entries (one per Annex A control)
  ],
  "summary": {
    "total_controls": 93,
    "applicable_count": 84,
    "not_applicable_count": 9,
    "implemented_count": 71,
    "partially_implemented_count": 9,
    "planned_count": 4,
    "by_theme": {
      "A.5": { "total": 37, "applicable": 34, "implemented": 30 },
      "A.6": { "total": 8,  "applicable": 8,  "implemented": 7 },
      "A.7": { "total": 14, "applicable": 11, "implemented": 9 },
      "A.8": { "total": 34, "applicable": 31, "implemented": 25 }
    },
    "poam_items_emitted": 13
  },
  "approval": {
    "soa_author": {
      "name": "<from org-profile>",
      "title": "ISMS Manager",
      "email": "...",
      "ack_signed_at": "2026-06-08T13:00:00Z"
    },
    "soa_approver": {
      "name": "<from org-profile>",
      "title": "Chief Information Security Officer",
      "email": "...",
      "ack_signed_at": "2026-06-08T15:00:00Z"
    }
  },
  "provenance": {
    "emitter": "iso-27001-soa-emitter",
    "emitter_version": "1.0.0",
    "emitted_at": "2026-06-08T15:00:30Z",
    "source_calls": [
      { "kind": "z-z1-catalog", "path": "data/iso-27001-2022-annex-a.json", "sha256": "..." },
      { "kind": "risk-register-snapshot", "path": "tracker://risk_register/snapshot-20260608", "sha256": "..." },
      { "kind": "ssdf-common-form", "path": "out/ssdf-common-form.json", "sha256": "..." },
      { "kind": "pqc-inventory", "path": "out/pqc-inventory.json", "sha256": "..." },
      { "kind": "prohibited-vendor-screen", "path": "out/prohibited-vendors-screen-result.json", "sha256": "..." },
      { "kind": "iam-mfa-evidence", "path": "out/iam-mfa-evidence.json", "sha256": "..." }
    ]
  },
  "signature": {
    "alg": "ed25519",
    "key_id": "arn:aws:kms:us-east-1:...:key/...",
    "sig": "<base64>"
  },
  "rfc3161_timestamp": {
    "tsa_url": "http://timestamp.digicert.com",
    "token": "<base64>",
    "received_at": "2026-06-08T15:00:35Z"
  }
}
```

### 5.2 OOXML `.docx` SoA report

Path: `out/iso-27001-soa-<cspname>-<YYYY-MM-DD>.docx`.

Layout (matches the de-facto certification-body template):

- **Cover page.**
  - Title: "Statement of Applicability — ISO/IEC 27001:2022".
  - CSP name + UEI / DUNS / company registration ID.
  - SoA version + SoA date.
  - ISMS scope statement (verbatim from `org-profile.yaml`).
  - ISMS boundary diagram (embedded SVG / PNG from LOOP-D output).
  - Certification body name + accreditation reference.
  - SoA author signature line (ISMS Manager).
  - SoA approver signature line (top management per clause 5.1).
  - Verbatim citation of ISO/IEC 27001:2022 clause 6.1.3(d).

- **Executive summary table.** Per-theme rollup (applicable count,
  implemented count, partial count, planned count, not-applicable
  count). Total POA&M items emitted.

- **Master SoA table.** One row per Annex A control across all four
  themes (93 rows total). Columns:
  1. Control ID (A.5.1 ... A.8.34)
  2. Control short name (canonical)
  3. Applicable (Y / N)
  4. Implementation status (implemented / partial / planned / N/A)
  5. Justification (inclusion or exclusion, in one column; cell wraps)
  6. Evidence reference (artefact path + signed Y/N)
  7. NIST 800-53 Rev 5 cross-reference
  8. FedRAMP Moderate KSI cross-reference
  9. Risk-register row UID (if any)
  10. Responsible owner (role)
  11. Last review date

- **Appendix A — 27017 cloud-overlay cross-reference** (when
  `cloud_overlay_in_scope: true`). One row per CLD.* control + per
  27002 augmentation.

- **Appendix B — 27018 PII-processor cross-reference** (when
  `pii_processor_in_scope: true`). Mapping of 27018 PII-specific
  controls to the corresponding Annex A controls.

- **Appendix C — 27701 PIMS cross-reference** (when
  `pims_in_scope: true`). PIMS Annex A (Controller) / Annex B
  (Processor) cross-reference per Annex A row.

- **Appendix D — POA&M items emitted by this SoA**. Table of
  `ISO-CONTROL-GAP` POA&M items emitted via LOOP-A.A1; per-row link
  to the OSCAL POA&M file location.

- **Appendix E — Upstream evidence catalogue**. Bibliography-style
  list of every evidence artefact referenced by the SoA, with
  artefact path + SHA-256 + signature status + emission date.

- **Appendix F — Glossary**. Cross-reference to `docs/GLOSSARY.md`
  for every ISO/NIST/FedRAMP term used in the SoA.

The renderer reuses the OOXML helpers from `core/oscal-ssp-docx.ts`
(zip-store, document.xml, styles.xml, numbering.xml,
[Content_Types].xml). Three new style definitions are added to
`styles.xml`: `SoATableHeader` (bold + grey-background row),
`SoATableCell` (12pt Arial, top-aligned), and
`SoAJustificationText` (10pt Arial, top-aligned, wrapping enabled).

### 5.3 Tracker DB rows

Migration `0056_iso_soa.sql`:

```sql
CREATE TABLE iso_27001_soa (
  id                              UUID PRIMARY KEY,
  soa_id                          TEXT NOT NULL UNIQUE,
  soa_version                     TEXT NOT NULL,
  soa_date                        DATE NOT NULL,
  csp_name                        TEXT NOT NULL,
  isms_scope_statement            TEXT NOT NULL,
  standard_edition                TEXT NOT NULL DEFAULT 'ISO/IEC 27001:2022',
  catalog_snapshot_ref            TEXT NOT NULL,
  catalog_snapshot_sha256         TEXT NOT NULL,
  eucs_level                      TEXT,           -- basic|substantial|high|null
  pims_in_scope                   BOOLEAN NOT NULL DEFAULT FALSE,
  cloud_overlay_in_scope          BOOLEAN NOT NULL DEFAULT FALSE,
  pii_processor_in_scope          BOOLEAN NOT NULL DEFAULT FALSE,
  total_controls                  INTEGER NOT NULL DEFAULT 93,
  applicable_count                INTEGER NOT NULL,
  not_applicable_count            INTEGER NOT NULL,
  implemented_count               INTEGER NOT NULL,
  partially_implemented_count     INTEGER NOT NULL,
  planned_count                   INTEGER NOT NULL,
  poam_items_emitted              INTEGER NOT NULL,
  envelope_path_json              TEXT NOT NULL,
  envelope_path_docx              TEXT NOT NULL,
  signing_key_id                  TEXT NOT NULL,
  signing_key_version             TEXT NOT NULL,
  soa_author_name                 TEXT NOT NULL,
  soa_author_title                TEXT NOT NULL,
  soa_author_ack_at               TIMESTAMPTZ,
  soa_approver_name               TEXT NOT NULL,
  soa_approver_title              TEXT NOT NULL,
  soa_approver_ack_at             TIMESTAMPTZ,
  certification_body_name         TEXT,
  certification_body_accreditation TEXT,
  status                          TEXT NOT NULL DEFAULT 'emitted',
                                    -- emitted|reviewed-internal|approved-management|submitted-cab|certified|surveillance-passed|recertification-due
  submitted_at                    TIMESTAMPTZ,
  submitted_by                    TEXT,
  cab_acknowledgement_id          TEXT,
  certification_decision_at       TIMESTAMPTZ,
  certificate_number              TEXT,
  certificate_expires_at          TIMESTAMPTZ,
  encrypted_at_rest               BOOLEAN NOT NULL DEFAULT TRUE,
  created_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE iso_27001_soa_controls (
  id                              UUID PRIMARY KEY,
  soa_id                          TEXT NOT NULL REFERENCES iso_27001_soa(soa_id) ON DELETE CASCADE,
  control_id                      TEXT NOT NULL,
  control_short_name              TEXT NOT NULL,
  theme                           TEXT NOT NULL,
  applicable                      BOOLEAN NOT NULL,
  implementation_status           TEXT NOT NULL,
  inclusion_justification         TEXT,
  exclusion_justification         TEXT,
  evidence_refs                   JSONB NOT NULL DEFAULT '[]'::jsonb,
  risk_register_refs              JSONB NOT NULL DEFAULT '[]'::jsonb,
  nist_800_53_rev5_refs           JSONB NOT NULL DEFAULT '[]'::jsonb,
  fedramp_moderate_ksi_refs       JSONB NOT NULL DEFAULT '[]'::jsonb,
  olir_relationship               TEXT,
  responsible_owner               TEXT NOT NULL,
  last_review_date                DATE,
  pims_cross_ref                  TEXT,
  poam_item_uuid                  TEXT,
  created_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (soa_id, control_id)
);

CREATE INDEX idx_iso_soa_status ON iso_27001_soa(status);
CREATE INDEX idx_iso_soa_csp ON iso_27001_soa(csp_name, soa_date DESC);
CREATE INDEX idx_iso_soa_controls_soa_id ON iso_27001_soa_controls(soa_id);
CREATE INDEX idx_iso_soa_controls_applicable ON iso_27001_soa_controls(soa_id, applicable);
CREATE INDEX idx_iso_soa_controls_status ON iso_27001_soa_controls(soa_id, implementation_status);
```

### 5.4 POA&M items emitted

For every control row with `implementation_status ∈ {partially-
implemented, planned}` the Z.Z2 emitter calls
`core/oscal-poam.ts::addPoamItem(...)` with the finding template
`ISO-CONTROL-GAP`. The POA&M item carries the control ID + the gap
description (from the upstream risk-register row's
`treatment_rationale`) + the remediation timeline (from the operator's
`cjis-soa-decisions.yaml` row's `remediation_plan_ref`) + the
composite risk score from LOOP-B.B1 + a back-reference to the SoA
control row via `(soa_id, control_id)`.

The POA&M items flow into the standard OSCAL POA&M chain so the
operator's compliance team manages ISO remediation in the same
backlog as FedRAMP remediation. The `iso_27001_soa_controls.
poam_item_uuid` column carries the POA&M UUID for traceability.

### 5.5 Submission-bundle catalogue entry

The emitter calls `core/submission-bundle.ts::registerArtefact(...)`
to add the SoA artefact triple to the LOOP-A.A4 submission bundle.
New roles:

```ts
{ role: 'iso-27001-soa-json',
  filename: 'iso-27001-soa-*.json',
  description: 'ISO/IEC 27001:2022 clause 6.1.3(d) Statement of Applicability (LOOP-Z.Z2)' },
{ role: 'iso-27001-soa-docx',
  filename: 'iso-27001-soa-*.docx',
  description: 'OOXML rendering of the ISO/IEC 27001:2022 clause 6.1.3(d) SoA (LOOP-Z.Z2)' },
{ role: 'iso-27001-soa-sig',
  filename: 'iso-27001-soa-*.sig',
  description: 'Ed25519 detached signature + RFC 3161 timestamp token for the ISO 27001 SoA (LOOP-Z.Z2)' },
```

### 5.6 Tracker UI — SoA status pane

New React component `tracker/ui/iso-soa-status-pane.tsx`. Visible at
`/iso-soa` (index list) and `/iso-soa/<soa_id>` (per-SoA drilldown).
Layout (per-SoA view):

- **Header.** SoA ID, CSP, date, status badge (emitted /
  reviewed-internal / approved-management / submitted-cab /
  certified). Buttons: "Approve as ISMS Manager",
  "Approve as Top Management", "Mark Submitted to CAB", "Paste CAB
  Acknowledgement".
- **Summary panel.** Per-theme rollup; total POA&M items emitted;
  certification body + accreditation reference.
- **Master SoA table.** Same 11 columns as the `.docx`; sortable +
  filterable per-theme + per-status; per-row drilldown to a side panel
  with the full justification + evidence list + linked POA&M item.
- **Approval audit log.** Chronological log of every operator action
  on this SoA (author ack, approver ack, internal review, CAB
  submission, CAB acknowledgement, certification decision). Each
  entry is a signed audit log row.
- **Download buttons.** ".docx", ".json", ".sig" — each downloads the
  current envelope triple.

---

## 6. Algorithm / Steps

### Phase A — Bootstrap

1. **Parse CLI flag** `--iso-z-z2` (or env `CLOUD_EVIDENCE_Z_Z2`). If
   neither set, no-op.
2. **Load operator configuration.** Read
   `config.yaml::iso_27001.*` + `org-profile.yaml::iso_27001.*`. If
   `seeks_iso_27001: false`, no-op. If true, validate every required
   field via Ajv. Any `REQUIRES-OPERATOR-INPUT` placeholder in the
   ISMS scope statement, signing key ref, or approver/author block →
   exit `2` with `IsoSoaOperatorConfigMissingError`.
3. **Load Z.Z1 catalog snapshot.** Read
   `data/iso-27001-2022-annex-a.json`. Verify Ed25519 signature via
   `core/sign.ts::verifyEnvelope(path, key_ref)`. Verify SHA-256 of
   every embedded NIST OLIR + FedRAMP crosswalk row against the
   `provenance.source_calls[]` block. Verify snapshot age ≤ 90 days
   (snapshot_date + 90d > today). Failure → exit `2`.
4. **Sign-test the SoA signing key** via
   `core/sign.ts::testSign(key_ref)`. Failure → exit `2`.

### Phase B — Ingest operator decisions

5. **Load `cjis-soa-decisions.yaml`** (despite the legacy filename
   prefix — this is the per-control operator-decision file; renamed
   in Z.Z2 to `iso-soa-decisions.yaml`). Validate via Ajv.
6. **Verify every Annex A control has a decision row.** If any of the
   93 controls lacks a decision row, exit `2` with
   `IsoSoaMissingControlDecisionError` naming the missing control
   IDs. The operator may not ship a SoA with implicit defaults.
7. **For every applicable=true row, require non-empty
   `inclusion_justification`.** For every applicable=false row, require
   non-empty `exclusion_justification`. Empty justification → exit
   `2`. The clause 6.1.3(d) mandate is non-negotiable.

### Phase C — Ingest upstream evidence

8. **Read LOOP-B risk register snapshot** for the current ISMS
   scope. For each risk row whose `treatment_controls[]` includes one
   of the 93 Annex A control IDs, join the row to the corresponding
   control decision row. Collect the row's
   `treatment_rationale` text and append to the control's
   inclusion justification (separator: " | Risk-driven: ").
9. **Read upstream evidence indices** from the well-known paths:
   - `out/ssdf-common-form.json` (LOOP-T) for A.8.25 (Secure
     development lifecycle).
   - `out/pqc-inventory.json` (LOOP-R) for A.8.24 (Use of
     cryptography).
   - `out/prohibited-vendors-screen-result.json` (LOOP-W) for A.5.19
     (supplier relationships), A.5.20 (supplier agreements),
     A.5.23 (cloud-services security).
   - `out/iso-27017-coverage-aws.json` + `-gcp.json` + `-azure.json`
     (Z.Z3) for 27017-augmented controls.
   - `out/iso-27018-evidence.json` (Z.Z4) for 27018 PII-processor
     controls.
   - `out/iso-27701-pims.json` (Z.Z5) when present.
   - Existing KSI evidence files under `out/` per the
     `fedramp_moderate_ksi_mapping` per control.
10. **Verify every referenced evidence artefact** exists on disk;
    record SHA-256; record signature-presence flag. Any missing
    artefact whose referencing control is `implemented` → exit `2`
    with `IsoSoaMissingEvidenceError` (operator cannot claim
    implementation without backing evidence).

### Phase D — Compose envelope

11. **Build the JSON envelope** per §5.1 schema. Populate every per-
    control row with the operator decision + the upstream-evidence
    refs + the upstream risk-register joins + the NIST 800-53 +
    FedRAMP cross-references from the catalog snapshot.
12. **Compute the summary block** (total, applicable, not-applicable,
    implemented, partially-implemented, planned counts; per-theme
    rollup; POA&M items emitted count).
13. **Populate the approval block** with the operator-supplied
    author + approver identities. Author + approver ack timestamps
    are written by the tracker UI's approval flow; at envelope
    emit-time they are `null`.

### Phase E — Validate

14. **Schema-validate** against
    `https://cloud-evidence.example/schemas/iso-27001-soa-v1.json` via
    Ajv. Failure → exit `2`.
15. **Sanity-check** the control count == 93 (every Annex A control
    has a row in `controls[]`). Mismatch → exit `2`.
16. **Sanity-check** that every `not-applicable` row has empty
    `implementation_evidence_refs[]` and empty `risk_register_refs[]`
    (a control marked N/A cannot have implementation evidence — the
    operator should mark it `implemented` instead).

### Phase F — Sign + timestamp

17. **RFC 8785 canonicalize** the envelope via
    `core/canonical-json.ts::canonicalize(envelope)`.
18. **Ed25519 sign** via
    `core/sign.ts::signEnvelope(canonical, key_ref)`. Write the
    detached signature to the envelope's `signature` block.
19. **RFC 3161 timestamp** via
    `core/timestamp.ts::stampEnvelope(envelope)`. TSA outage → warn
    (do not block); record the absence in `provenance.warnings[]`.
20. **Atomic write** the envelope JSON to
    `out/iso-27001-soa-<csp>-<date>.json` via temp-file + rename.

### Phase G — Render .docx

21. **Render the OOXML `.docx`** via `core/iso-27001-soa-docx.ts`
    using the existing zip-store helpers. Three new style defs in
    `styles.xml`; one table per theme in `document.xml`; the
    appendices follow the master table.
22. **Embed the ISMS boundary diagram** SVG (or PNG fallback) as an
    OOXML `media/image1.svg` (or `.png`) with the
    `relationship.xml` ref.
23. **Atomic write** the .docx to
    `out/iso-27001-soa-<csp>-<date>.docx` via temp-file + rename.

### Phase H — POA&M emission

24. **For every control with `implementation_status ∈ {partially-
    implemented, planned}`**, emit one OSCAL POA&M item via
    `core/oscal-poam.ts::addPoamItem(...)`. Finding template
    `ISO-CONTROL-GAP`. Capture the POA&M UUID and back-write to
    `iso_27001_soa_controls.poam_item_uuid`.

### Phase I — Persist + notify

25. **Insert** one row into `iso_27001_soa` + 93 rows into
    `iso_27001_soa_controls`. Use a single tracker DB transaction.
26. **Register** the SoA triple (.json + .docx + .sig) in the
    submission bundle catalogue via
    `core/submission-bundle.ts::registerArtefact(...)`.
27. **Notify** via `core/notify.ts`: Slack
    `#fedramp-international-equivalence` (title: "ISO 27001 SoA
    emitted for <csp> on <date>"; body: link to tracker UI +
    summary counts) + email to author + approver (from
    org-profile.yaml).
28. **Append a coverage block** to `out/inventory-coverage.json`:

```json
{
  "iso_27001_soa_coverage": {
    "soa_id": "...",
    "controls_total": 93,
    "controls_applicable": 84,
    "controls_implemented": 71,
    "controls_partial": 9,
    "controls_planned": 4,
    "controls_not_applicable": 9,
    "poam_items_emitted": 13,
    "evidence_artefacts_referenced": 47
  }
}
```

### Phase J — Validation

29. `npm run check:provenance` must pass.
30. `npm run lint:no-stubs` must remain green.
31. `npm run check:reo` (G1+G2+G3) must all pass.
32. `npm run typecheck` must succeed.
33. All 18+ tests in §8 must pass.

---

## 7. Files to create / modify

### Files to CREATE

1. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/iso-27001-soa-emitter.ts`
   — orchestrator + envelope composer + schema validator + POA&M
   emission glue + tracker DB writer. ~720 lines.
2. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/iso-27001-soa-docx.ts`
   — OOXML / zip-store renderer; document.xml + styles.xml extension
   + appendices. ~540 lines.
3. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/iso-27001-soa-canonical-json.ts`
   — RFC 8785 canonicaliser specialisation for the SoA envelope shape
   (handles per-control row stability + the per-theme rollup). ~180
   lines.
4. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/db/migrations/0056_iso_soa.sql`
   — see §5.3 schema. ~120 lines.
5. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/iso-soa.ts`
   — REST endpoints: `GET /api/iso-soa`, `GET /api/iso-soa/:id`,
   `POST /api/iso-soa/:id/approve-author`,
   `POST /api/iso-soa/:id/approve-management`,
   `POST /api/iso-soa/:id/mark-submitted`,
   `POST /api/iso-soa/:id/paste-cab-ack`. Each protected by CSRF
   + RBAC + 2FA per existing tracker conventions. ~310 lines.
6. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/ui/iso-soa-status-pane.tsx`
   — React component for `/iso-soa` index + `/iso-soa/:id` drilldown.
   Includes the per-control table with filters, the approval audit
   log, and the download buttons. ~470 lines.
7. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/iso-27001-soa-emitter.test.ts`
   — see §8 (≥ 18 tests). ~700 lines.
8. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/iso-soa/`
   — fixture catalog snapshot (small 12-control subset), fixture
   risk register, fixture operator decisions, fixture upstream
   evidence stubs, golden envelope JSON, golden DOCX zip. ~12 files.
9. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/iso-27001-soa-schema.json`
   — JSON Schema for the SoA envelope (matches §5.1). ~480 lines.
10. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/iso-soa-decisions-template.yaml`
    — operator-facing template for the per-control decisions YAML;
    pre-populated with 93 control IDs + canonical names + empty
    decision fields. The operator copies this to `iso-soa-decisions.yaml`,
    fills out the decisions, and commits. ~280 lines.

### Files to MODIFY

1. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
   — append the three new well-known roles (see §5.5).
2. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/inventory-coverage.ts`
   — register the `iso_27001_soa_coverage` block.
3. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`
   — wire the `--iso-z-z2` flag + dispatch to the Z.Z2 emitter when
   `org-profile.yaml::iso_27001.seeks_iso_27001 === true`.
4. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-poam.ts`
   — register the `ISO-CONTROL-GAP` finding template (template ID,
   default severity, default category, remediation-text template).
5. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/ui/router.tsx`
   — add the `/iso-soa` + `/iso-soa/:id` routes.
6. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/ui/nav.tsx`
   — add an "ISO 27001 SoA" entry under the "International
   Equivalence" nav section.
7. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/STATUS.md`
   — flip Z.Z2 row to `done` upon completion (per §13).
8. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/LOOP-Z-SPEC.md`
   — flip the Z.Z2 status-table row to `done` upon completion.
9. `/Users/kenith.philip/FedRAMP 20x/CHANGELOG.md`
   — append Z.Z2 entry under "Unreleased" upon completion.

---

## 8. Test specifications

| id  | scenario | fixture | expected | acceptance |
|-----|----------|---------|----------|------------|
| T1  | SoA emits 93 rows when every operator-decision row is present | `fixtures/iso-soa/decisions-full-93.yaml` + `golden-catalog.json` | `controls[].length === 93`; summary.total_controls === 93 | unit assertion |
| T2  | SoA refuses to emit when any control's decision row is missing | `fixtures/iso-soa/decisions-missing-A.5.7.yaml` | throws `IsoSoaMissingControlDecisionError` naming `A.5.7` | `expect().toThrow(IsoSoaMissingControlDecisionError)` |
| T3  | SoA refuses to emit when an applicable=true row has empty inclusion_justification | `fixtures/iso-soa/decisions-empty-incl-justification.yaml` | throws `IsoSoaEmptyJustificationError` | `expect().toThrow(IsoSoaEmptyJustificationError)` |
| T4  | SoA refuses to emit when an applicable=false row has empty exclusion_justification | `fixtures/iso-soa/decisions-empty-excl-justification.yaml` | throws `IsoSoaEmptyJustificationError` | unit assertion |
| T5  | SoA refuses to emit when an implemented control lacks evidence refs | `fixtures/iso-soa/decisions-implemented-no-evidence.yaml` | throws `IsoSoaMissingEvidenceError` | unit assertion |
| T6  | SoA refuses to emit when catalog snapshot is older than 90 days | `fixtures/iso-soa/catalog-old.json` (snapshot_date 100d ago) | throws `IsoSoaCatalogStaleError` | unit assertion |
| T7  | SoA refuses to emit when catalog signature is invalid | `fixtures/iso-soa/catalog-bad-sig.json` | throws `EnvelopeSignatureInvalidError` | unit assertion |
| T8  | SoA joins LOOP-B risk-register rows into the per-control justification text | `fixtures/iso-soa/risk-register-driving-A.8.24.json` | `controls[control_id=A.8.24].inclusion_justification` contains `"Risk-driven:"` | unit assertion |
| T9  | SoA joins LOOP-T SSDF Common Form evidence to A.8.25 | `fixtures/iso-soa/ssdf-common-form.json` | `controls[control_id=A.8.25].implementation_evidence_refs[0].source_loop === 'T'` | unit assertion |
| T10 | SoA joins LOOP-R PQC inventory evidence to A.8.24 | `fixtures/iso-soa/pqc-inventory.json` | `controls[control_id=A.8.24].implementation_evidence_refs[].some(e => e.source_loop === 'R')` | unit assertion |
| T11 | SoA joins LOOP-W prohibited-vendor catalogue to A.5.19, A.5.20, A.5.23 | `fixtures/iso-soa/prohibited-vendors-screen-result.json` | all three controls have a `source_loop === 'W'` evidence ref | unit assertion |
| T12 | SoA emits POA&M items for partial + planned controls | `fixtures/iso-soa/decisions-partial-and-planned.yaml` | `summary.poam_items_emitted >= 2`; tracker DB rows for each | tracker DB assertion |
| T13 | SoA persists 1 + 93 rows into tracker DB (iso_27001_soa + iso_27001_soa_controls) | full fixture set | tracker counts: 1 + 93 | DB query assertion |
| T14 | SoA `.docx` zip contains [Content_Types].xml + document.xml + styles.xml + sectPr blocks per theme | golden DOCX | `zip.entries().includes(...)` all 4 entries; documentXml contains 4 `<w:tbl>` blocks | unit assertion |
| T15 | SoA `.docx` cover page contains the ISMS scope statement verbatim | fixture with scope "Acme SaaS prod env in us-east-1 + us-west-2" | documentXml.includes(scope_statement) | unit assertion |
| T16 | SoA RFC 8785 canonicalization is stable (same input → same byte-for-byte output) | golden envelope | second run produces identical bytes | byte equality |
| T17 | SoA Ed25519 signature verifies via core/sign.ts::verifyEnvelope | golden envelope | verifyEnvelope() resolves true | unit assertion |
| T18 | SoA RFC 3161 timestamp token is attached when TSA reachable | golden envelope + mock TSA | `rfc3161_timestamp.token` is non-empty base64 | unit assertion |
| T19 | SoA RFC 3161 outage emits warning but does NOT block envelope | mock TSA returning 503 | envelope written; `provenance.warnings[].includes('rfc3161-tsa-unreachable')` | unit assertion |
| T20 | SoA tracker UI sign-off flow updates iso_27001_soa.soa_author_ack_at | POST /api/iso-soa/:id/approve-author | DB column set; signed audit log row inserted | integration test |
| T21 | SoA tracker UI top-management sign-off updates iso_27001_soa.soa_approver_ack_at | POST /api/iso-soa/:id/approve-management | DB column set; signed audit log row inserted | integration test |
| T22 | SoA submission bundle includes the .json + .docx + .sig triple | full emit + bundler run | bundle catalogue contains all three roles | unit assertion |
| T23 | SoA NIST OLIR relationship type per control row matches catalog snapshot | full emit | `controls[].olir_relationship` matches catalog `nist_800_53_rev5_mapping.olir_relationship` | unit assertion |
| T24 | SoA refuses to emit when control count != 93 | fixture catalog with 92 controls | throws `IsoSoaControlCountMismatchError` | unit assertion |
| T25 | SoA REQUIRES-OPERATOR-INPUT in approver block triggers exit 2 | org-profile with `soa_approver.name: REQUIRES-OPERATOR-INPUT` | throws `IsoSoaOperatorConfigMissingError`; no DB row inserted | unit assertion |

---

## 9. Risks

### R-Z.Z2-01 — ISO copyright violation if verbatim 27001/27002 text is redistributed

**Likelihood:** medium. **Impact:** high (cease-and-desist; Apache-2.0
revocation pressure; PMO awkwardness).

ISO/IEC standards are copyrighted (CHF 138 to CHF 198 per standard).
Verbatim redistribution of clause 6.1.3(d) text, Annex A control
descriptions, or 27002 implementation guidance is prohibited.

**Mitigation:**

- Z.Z2 carries ONLY publicly-available facts: control IDs (A.5.1, ...,
  A.8.34), canonical short names (publicly listed in ISO's preview
  pages), NIST OLIR crosswalk references (NIST is government-published),
  FedRAMP KSI references (FedRAMP-published).
- The SoA `.docx` references the ISO standard URL
  (https://www.iso.org/standard/27001) so the certification body's
  auditor reads the verbatim text from the operator's licensed copy.
- The CI lint includes a check that no Annex A control description
  longer than 80 characters appears in any catalog file or Z.Z2
  emitter source.
- The operator's licensed ISO copy lives outside the cloud-evidence
  repository (operator-side directory like `~/licensed-iso-standards/`)
  and is referenced only by URL.
- This is the same approach used by every Apache-2.0 ISO-adjacent
  compliance tool (GoComply, OneTrust open-source extensions,
  brian-ruf/oscal-content-generation).

### R-Z.Z2-02 — Stale catalog snapshot backing a current SoA

**Likelihood:** medium. **Impact:** high (audit fails: SoA references
controls/IDs/cross-walks that no longer match the current ISO edition
or NIST OLIR mapping).

If the Z.Z1 catalog snapshot is months old and the certification body
is auditing against a newer ISO 27001 edition or a newer NIST OLIR
publication, the SoA will reference stale crosswalk relationships.

**Mitigation:**

- Z.Z2 refuses to emit when the catalog snapshot age > 90 days
  (algorithm step 3). The operator must run Z.Z1 to refresh.
- The SoA envelope carries the catalog snapshot SHA-256 + snapshot
  date so the certification body can verify the upstream catalog
  freshness.
- The tracker UI surfaces a "catalog stale" warning banner when the
  most-recent SoA's catalog is > 60 days old, prompting the operator
  to re-run Z.Z1 before the next audit cycle.
- A CI cron-job (added in Z.Z1) re-runs the catalog extractor monthly;
  any drift between the new catalog and the on-disk snapshot triggers
  a coverage diff in the tracker.

### R-Z.Z2-03 — Operator marks an applicable control as N/A to avoid evidence collection

**Likelihood:** medium. **Impact:** high (certification audit
discovers the gap; SoA must be redone; certification delayed by 6-12
weeks).

A common pre-certification mistake is over-eager exclusion: an operator
marks a control like A.8.27 (Secure system architecture and engineering
principles) as N/A because the CSP "uses upstream cloud-provider
services" — but the certification body expects evidence that the CSP
applies secure-architecture principles to its OWN application stack
above the cloud provider.

**Mitigation:**

- Z.Z2 requires verbose exclusion justifications (algorithm step 7);
  empty or boilerplate justifications block emission.
- A separate companion lint (`scripts/lint-iso-soa-exclusion-quality.mjs`)
  flags exclusion justifications shorter than 150 characters as
  suspect; the CI guardrail fails the PR.
- The tracker UI's per-control side panel surfaces "common-mistake"
  warnings keyed by control ID (e.g. A.8.27 warning: "Excluding
  secure-architecture controls is rarely accepted by certification
  bodies; consider 'partially-implemented' with a remediation plan
  instead").
- The SoA `.docx` Appendix D's POA&M list invites the operator to
  reconsider exclusions: every N/A row appears in a "Confirm
  exclusions" section so the top-management approver sees the
  exclusion list before signing.

### R-Z.Z2-04 — Top-management sign-off forgery or bypass

**Likelihood:** low. **Impact:** very high (audit failure for clause
5.1 non-conformance; possible regulatory escalation if PII processor
sign-off is implicated under GDPR).

Clause 5.1 requires top-management commitment to the ISMS, including
SoA approval. If the SoA is emitted, transmitted, and audited without
verifiable top-management sign-off, the certification body raises a
major non-conformance.

**Mitigation:**

- The tracker DB columns `soa_author_ack_at` and `soa_approver_ack_at`
  are populated ONLY by the corresponding tracker UI endpoints, which
  require:
  - Authenticated user matching the org-profile-declared identity.
  - 2FA challenge (TOTP) per existing tracker convention.
  - A signed audit log row capturing the ack.
- The SoA envelope's `approval.soa_approver.ack_signed_at` field is
  written only when the tracker DB column is populated; if the
  envelope is re-emitted before approval, the field stays null and
  the `.docx` cover page surfaces an "AWAITING TOP-MANAGEMENT
  APPROVAL" watermark.
- The submission-bundle catalogue refuses to add the SoA to a bundle
  whose status is `submitted-cab` unless `soa_approver_ack_at` is
  populated.
- The certification body's CAB acknowledgement (recorded via
  `POST /api/iso-soa/:id/paste-cab-ack`) is signed by the operator;
  any mismatch between the CAB ack and the previously-recorded
  approval surfaces a coverage diff in the tracker UI.

### R-Z.Z2-05 — Drift between SoA-claimed implementation status and live evidence

**Likelihood:** medium. **Impact:** high (Stage 2 audit failure;
re-audit required; certification delayed).

A SoA may claim a control is `implemented` based on evidence collected
weeks earlier; if the underlying cloud configuration drifted, the
Stage 2 auditor will discover the gap.

**Mitigation:**

- Z.Z2 records every evidence artefact's SHA-256 + emission date in
  the SoA envelope (`implementation_evidence_refs[].artefact_sha256`,
  `..artefact_signed`). The certification body can cross-check that
  the evidence is still on disk and signed.
- The tracker UI's per-control side panel surfaces the age of every
  evidence artefact; artefacts older than 30 days are coloured amber,
  older than 90 days red.
- A nightly cron (added to LOOP-E continuous-monitoring) re-runs the
  evidence collectors that back SoA-claimed-implemented controls and
  raises a tracker alert if the artefact SHA-256 changes (drift) or
  the collector reports a regression (e.g. MFA enforcement disabled
  on a user pool that previously had it on).
- The SoA is versioned (`soa_version` in YYYY-MM-DD format); the
  tracker forces a SoA re-emission before any audit cycle (Stage 1,
  Stage 2, surveillance, recertification) so the SoA reflects the
  current state at the moment the auditor reads it.

### R-Z.Z2-06 — Conflict between LOOP-Z SoA and FedRAMP SSP for the same scope

**Likelihood:** medium. **Impact:** medium (auditor confusion; SoA
appears inconsistent with the FedRAMP SSP).

The CSP's FedRAMP SSP (LOOP-A SSP-2) and ISO SoA cover overlapping
controls (e.g. AC-2 ↔ A.5.16, AC-3 ↔ A.5.15, IA-2 ↔ A.5.16+A.8.5). If
the implementation claims diverge, an auditor reading both will note
the inconsistency.

**Mitigation:**

- Z.Z2's per-control row carries the `fedramp_moderate_ksi_refs[]`
  array and the `nist_800_53_rev5_refs[]` array; the operator
  decision step warns if a control's implementation status diverges
  from the corresponding KSI evidence status (e.g. SoA claims A.5.16
  `implemented` but the IAM-MFA collector shows the KSI as
  partial).
- The CI guardrail `check:reo:cross-loop-consistency` (new in Z.Z2)
  fails when SoA implementation_status differs from the FedRAMP KSI
  status by more than one level for a cross-walked pair.
- The SoA `.docx` Appendix E (upstream evidence catalogue) explicitly
  lists every cross-walked FedRAMP artefact so the auditor can read
  both in sync.

---

## 10. Open questions

- **OPEN-Z.Z2-01.** Should Z.Z2 emit one SoA per ISMS scope (e.g.
  "Production us-east-1" vs "Production us-west-2") or a single
  consolidated SoA across all scopes? Per ISO/IEC 17021-1, the
  certification body issues one certificate per ISMS scope; the SoA
  follows the certificate scope. Current Z.Z2 design assumes a single
  ISMS scope per CSP — this is the most common case but a large CSP
  may seek multiple scoped certifications. **REQUIRES-OPERATOR-INPUT
  attestation** that the SoA scope matches the certification-body
  contract scope; operator confirms in `org-profile.yaml::iso_27001.
  isms_scope_statement`.

- **OPEN-Z.Z2-02.** When the LOOP-B risk register is empty (CSP just
  started ISO journey; no risks yet documented), should Z.Z2 emit a
  SoA with placeholder justifications or refuse? Current design:
  refuse — operator must run LOOP-B.B1 first. Alternative: emit with
  a `risk_register_state: 'empty'` flag in the envelope and a
  prominent `.docx` cover-page warning. **REQUIRES-RESEARCH** on
  whether certification bodies accept "no risks yet identified" as a
  starting position.

- **OPEN-Z.Z2-03.** How should Z.Z2 handle 27001:2013-to-2022
  transition cases — i.e. a CSP that holds a current 2013 certificate
  (issued before the 2025-10-31 deadline) and is in the renewal
  cycle? Current design assumes 2022; the 2013 mapping is provided
  in the Z.Z1 catalog snapshot as `legacy_27001_2013_mapping` per
  control. Z.Z2 could emit a "transition SoA" listing both editions'
  control mappings side-by-side. **DEFERRED** until at least one
  operator surfaces the case (2026 H2 expected).

- **OPEN-Z.Z2-04.** Should the SoA `.docx` cover page embed the ISMS
  boundary diagram as a static SVG, or include a QR code linking to
  an operator-hosted tracker URL? Static SVG is the certification-
  body convention. QR code adds operational convenience but risks
  audit-trail fragility (URL could go stale). Current design: static
  SVG. **DEFERRED** to operator feedback.

- **OPEN-Z.Z2-05.** When the operator has multiple certification
  bodies for different schemes (e.g. BSI for 27001, TÜV SÜD for
  27017), should Z.Z2 emit one SoA per body or a master SoA?
  Current design: one master SoA referenced by every body. **OK
  unless operator surfaces a body-specific requirement.**

- **OPEN-Z.Z2-06.** EUCS-High introduces additional scheme-specific
  controls beyond the 27001/27017/27018/27701 cluster. When EUCS is
  formally adopted, should Z.Z2 SoA template extend to carry the
  EUCS-High extras, or should that be a separate Z.Z5 EUCS-package
  emission? Current design: separate Z.Z5 emission (cleaner
  separation of concerns). **DEFERRED** until EUCS adoption.

---

## 11. REQUIRES-OPERATOR-INPUT

| Input | Owner | Default | Where captured | Used by |
|---|---|---|---|---|
| `iso_27001.seeks_iso_27001: bool` | CSP CISO | `false` | `org-profile.yaml` | LOOP-Z orchestrator gate |
| `iso_27001.isms_scope_statement: string` | CSP CISO + Legal | none | `org-profile.yaml` | SoA cover page; certification body Stage 1 review |
| `iso_27001.isms_boundary_diagram_ref: string` | CSP CISO + Architecture | none | `org-profile.yaml` | SoA cover page diagram embed |
| `iso_27001.certification_body.name + accreditation_body + accreditation_reference` | CSP CISO + Procurement | none | `org-profile.yaml` | SoA cover page + tracker DB; CAB submission routing |
| `iso_27001.soa_author.name + title + email` | CSP CISO | none | `org-profile.yaml` | SoA cover page; tracker UI ack flow |
| `iso_27001.soa_approver.name + title + email` | CSP CEO / top-management | none | `org-profile.yaml` | SoA cover page; tracker UI ack flow; clause 5.1 verification |
| `iso_27001.eucs_level: 'basic'\|'substantial'\|'high'` | CSP CISO + Sales | `null` (no EUCS) | `org-profile.yaml` | Z.Z5 EUCS package level selection |
| `iso_27001.pims_in_scope: bool` | CSP CISO + Privacy Officer | `false` | `org-profile.yaml` | Z.Z2 SoA appendix C trigger |
| `iso_27001.cloud_overlay_in_scope: bool` | CSP CISO | `true` for cloud CSPs | `org-profile.yaml` | Z.Z2 SoA appendix A trigger |
| `iso_27001.pii_processor_in_scope: bool` | CSP CISO + Privacy Officer | `false` | `org-profile.yaml` | Z.Z2 SoA appendix B trigger |
| `iso_27001.signing_key_ref: string` | CSP CISO + KMS Admin | none | `config.yaml::iso_27001.*` | SoA envelope Ed25519 signature |
| Per-control `iso-soa-decisions.yaml` row (93 required) | ISMS Manager + Control Owners | none — template ships with 93 empty rows | `iso-soa-decisions.yaml` | Z.Z2 envelope composer (one row per Annex A control) |
| Per-control `inclusion_justification` text (≥ 60 chars) | Control Owner | none | `iso-soa-decisions.yaml` | SoA per-control row |
| Per-control `exclusion_justification` text (≥ 150 chars; long for audit credibility) | Control Owner + Risk Owner | none | `iso-soa-decisions.yaml` | SoA per-control row + R-Z.Z2-03 mitigation |
| Per-control `remediation_plan_ref` for partial/planned controls | Control Owner | none | `iso-soa-decisions.yaml` | POA&M item back-reference |
| Risk-register row's `treatment_rationale` + `risk_owner_approval` | Risk Owner | populated via LOOP-B.B1 | tracker DB | SoA inclusion justification join |
| Top-management sign-off (clause 5.1 ack) | CSP CEO / top-management | none | tracker UI 2FA-gated endpoint | tracker DB `iso_27001_soa.soa_approver_ack_at`; envelope `approval.soa_approver.ack_signed_at` |
| CAB acknowledgement receipt id | ISMS Manager (after CAB submission) | none | tracker UI 2FA-gated endpoint | tracker DB `iso_27001_soa.cab_acknowledgement_id` |
| Certification decision + certificate number + expiry | ISMS Manager (after CAB decision) | none | tracker UI 2FA-gated endpoint | tracker DB `iso_27001_soa.certification_decision_at` + `certificate_number` + `certificate_expires_at` |

When any required input is missing at emit-time, Z.Z2 raises
`IsoSoaOperatorConfigMissingError` naming the missing field, the
`org-profile.yaml` or `iso-soa-decisions.yaml` path, and a one-line
instruction for the operator. No `.json` or `.docx` artefact is
written; no tracker DB row is inserted; no POA&M item is emitted.

---

## 12. Implementation log

| date | session | event | commit | notes |
|------|---------|-------|--------|-------|
| 2026-06-08 | spec proposed | wf-uvxyz-gapfill | Specification authored via gap-fill workflow | TBD | — |

Cadence (per `cloud-evidence/docs/IMPLEMENTATION-LOG-TEMPLATE.md` §3):
update this table at every commit boundary, at every test failure
(transient or persistent), at every research question answered, at
every spec divergence, at every newly-discovered risk (followed by an
immediate entry in `docs/loops/LOOP-Z-RISKS.md`), and at every external
dependency pin. The final row at slice completion captures the close-out
commit hash and references the CHANGELOG entry per §13 step 4.

---

## 13. Completion checklist

When Z.Z2 ships, the implementer executes the seven steps below
verbatim from `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`,
PLUS step 8 specific to LOOP-Z's status surface.

### Step 1 — Verify the slice is REO-compliant

Run all three guardrails. They MUST all be green:

```bash
cd cloud-evidence
npm run typecheck      # no errors
npm test               # 100% passing (counts must increase by the slice's new tests)
npm run check:reo      # G1+G2+G3 all green
```

### Step 2 — Update STATUS.md

Open `cloud-evidence/docs/STATUS.md` and for the slice that just
shipped:

- Change `Status` column from `pending` to `done`
- Fill `Commit` with the PENDING commit's short hash (you'll know it
  after step 5)
- Fill `Date` with today's date (ISO format YYYY-MM-DD)
- If this was the last slice in a loop, change the loop's title
  section to indicate "(COMPLETE)"
- Update the "Overall" section: increment loops-complete, change
  last-shipped, update next-priority

### Step 3 — Update the loop's spec doc

Open `cloud-evidence/docs/loops/LOOP-Z-SPEC.md`. Find the "Status
tracking" section table. For the Z.Z2 slice row:
`status=done, commit=<hash>, date=<ISO>`.

### Step 4 — Add CHANGELOG entry

Open `/Users/kenith.philip/FedRAMP 20x/CHANGELOG.md`. Add a new entry
at the TOP of "Unreleased":

```
### Added — LOOP-Z.Z2: ISO 27001 Statement of Applicability (SoA) Emitter
<2-3 paragraphs describing what shipped, module names, file paths,
verification counts (typecheck clean, NNN/NNN tests passing,
npm run check:reo returns 0). Highlight that this slice emits the
clause 6.1.3(d) canonical .docx + signed JSON envelope; references
upstream Z.Z1 catalog + LOOP-B risk register + LOOP-T SSDF + LOOP-R PQC
+ LOOP-W prohibited-vendor evidence; persists into iso_27001_soa +
iso_27001_soa_controls tracker tables; emits ISO-CONTROL-GAP POA&M
items via core/oscal-poam.ts; surfaces tracker UI at /iso-soa.>
```

### Step 5 — Commit

```bash
cd /Users/kenith.philip/FedRAMP\ 20x
git add cloud-evidence/<modified files> \
        cloud-evidence/docs/STATUS.md \
        cloud-evidence/docs/loops/LOOP-Z-SPEC.md \
        cloud-evidence/docs/slices/Z/Z.Z2.md \
        CHANGELOG.md
git commit -m "$(cat <<'EOF'
LOOP-Z.Z2: ISO 27001 Statement of Applicability (SoA) Emitter

Emits the canonical SoA per ISO/IEC 27001:2022 clause 6.1.3(d) in two
reciprocal forms: RFC 8785 canonicalized + Ed25519-signed + RFC 3161
timestamped JSON envelope, and OOXML/.docx for certification body
Stage 1 documentation review. Reads Z.Z1 catalog snapshot, LOOP-B risk
register, and upstream evidence from LOOP-T/R/W + Z.Z3/Z.Z4 + KSI
collectors. Emits ISO-CONTROL-GAP POA&M items for partial+planned
controls. Persists iso_27001_soa + iso_27001_soa_controls; tracker UI
at /iso-soa surfaces author + top-management sign-off + CAB
submission tracking.

Verification: typecheck clean, NNN/NNN tests passing,
npm run check:reo returns 0.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

### Step 6 — Update commit hash in STATUS.md + loop spec + per-slice doc frontmatter

```bash
git log -1 --format=%h
```

Open STATUS.md + LOOP-Z-SPEC.md + this per-slice doc — paste the
actual commit hash in the rows you updated in step 2+3 AND in the
per-slice doc frontmatter (`commit: <hash>`,
`completed_date: <YYYY-MM-DD>`, `status: done`, `last_updated:
<YYYY-MM-DD>`). Amend the commit:

```bash
git add cloud-evidence/docs/STATUS.md \
        cloud-evidence/docs/loops/LOOP-Z-SPEC.md \
        cloud-evidence/docs/slices/Z/Z.Z2.md
git commit --amend --no-edit
```

### Step 7 — Push

```bash
git push origin main
```

### Step 8 — LOOP-Z post-ship: dependent slice updates + final implementation log entry

After the slice has shipped and pushed, perform these LOOP-Z-specific
post-ship actions:

1. **Append the final Implementation log entry** to §12 above:
   `2026-06-XX | slice closed | <session id> | Z.Z2 implementation
   complete; all 25 tests passing; SoA emitter end-to-end against
   fixture catalog | <commit hash> | <CHANGELOG ref>`.
2. **Update any newly-discovered risks** in
   `cloud-evidence/docs/loops/LOOP-Z-RISKS.md`. Add a Z.Z2 column to
   each existing risk row marking the slice's impact contribution
   (e.g. "Z.Z2 ships the SoA emitter; risks R-Z-01, R-Z-02,
   R-Z-04, R-Z-07 are now operationally surfaced via the emitted
   artefact").
3. **Update the dependent slices** that block on Z.Z2:
   - Z.Z5 (EUCS submission package) — annotate that the SoA emitter
     is ready and Z.Z5 may now bundle the SoA.
   - LOOP-Q.Q1 (Marketplace badge) — annotate that the "ISO 27001
     certified" badge is unblocked once the operator transmits the
     SoA to the certification body AND records the certification
     decision via tracker UI.
4. **Verify with `git log --oneline -3`** that the commit landed
   before declaring the slice closed.

**Failure to follow steps 1–8 means the slice is NOT closed.** Per
`cloud-evidence/CLAUDE.md` Slice-completion directive: "When a loop /
slice / section completes implementation: 1. Update STATUS.md status
row for the slice (commit hash, status -> 'done', last_updated). 2.
Update the loop SPEC status table (commit hash, status -> 'done'). 3.
Append a CHANGELOG.md entry (date, slice ID, summary, commit). 4.
Commit with the slice ID in the subject line + Co-Authored-By trailer.
5. Push to origin/main. 6. If a new permanent reference document was
created, add it to this reading list. 7. Verify with 'git log
--oneline -3' that the commit landed before declaring the slice
closed."
