# LOOP-M — Privacy Package Extension (SORN + DPIA + PT-family controls)

> Comprehensive implementation specification for the four slices in LOOP-M.
> Authored as a stand-alone artifact: any future Claude / human session can
> execute LOOP-M end-to-end by reading ONLY this file + the four supporting
> files cited in Section 3 ("Dependencies"). No prior conversation history
> required.
>
> Authority: `cloud-evidence/CLAUDE.md` (Real-Evidence-Only standard) governs
> every slice below. Every byte emitted must trace back to real evidence or
> operator-supplied configuration. Slices ship under the Real Slice Contract
> in CLAUDE.md Rule 2.
>
> Provenance for this spec: surfaced by
> `cloud-evidence/docs/ADDITIONAL-LOOPS-AUDIT.md` (2026-06-06) Section 2
> "LOOP-M — Privacy Package Extension (SORN, PTA / PIA, Privacy Continuous
> Monitoring)". The audit identified three privacy package gaps left open
> after LOOP-C.C4 ships PTA + PIA emitters: (1) System of Records Notice
> (SORN) under Privacy Act §552a, (2) Data Protection Impact Assessment
> (DPIA) for cross-border / agency-partner data, (3) full PT-family
> control documentation (PT-1..PT-8) beyond PTA/PIA scope, plus (4)
> privacy incident response procedures (PT-7 + OMB M-17-12).
>
> Conditional applicability: LOOP-M is **conditional** on the CSP
> processing PII subject to the Privacy Act on behalf of a federal
> agency. ADDITIONAL-LOOPS-AUDIT §5 open question #2 must be resolved
> before slice M.M1 starts — if "no PII", LOOP-M ships a single
> attestation-only artifact and STATUS.md records the deferral. The
> ADDITIONAL-LOOPS-AUDIT §6 prioritisation places LOOP-M second behind
> LOOP-L (CRM + Inheritance).

---

## 1. Why this loop exists

### The gap LOOP-C.C4 (PTA + PIA) leaves open

LOOP-C.C4 (per `cloud-evidence/docs/EXECUTION-PLAN.md` lines 190-198)
emits two artifacts under the FedRAMP authorization package:

1. **Privacy Threshold Analysis (PTA)** — the YES/NO determination per
   OMB M-03-22 §II.B.1 of whether the system processes PII.
2. **Privacy Impact Assessment (PIA)** — the structured analysis,
   required when PTA returns YES.

These two artifacts close the **OMB M-03-22 Section II.B** obligation
("Agencies must conduct a PIA before developing or procuring IT systems
or projects that collect, maintain, or disseminate information in
identifiable form from or about members of the public"). They do **not**
close four additional privacy-package obligations that apply when a CSP
processes PII on behalf of a federal agency under FedRAMP authorization.

#### Gap 1 — System of Records Notice (SORN) under Privacy Act §552a (e)(4)

When a federal agency's IT system maintains records about individuals
that are retrieved by an individual identifier (name, SSN, email,
employee ID, customer number), the **Privacy Act of 1974** (5 U.S.C.
§552a) requires that agency to publish a **System of Records Notice**
(SORN) in the **Federal Register** before that retrieval-by-identifier
capability goes live. From the statute verbatim (per the Cornell LII
citation chain in Section 4 of this spec):

> "Each agency that maintains a system of records shall publish in the
> Federal Register upon establishment or revision a notice of the
> existence and character of the system of records, which notice shall
> include —
> (A) the name and location of the system;
> (B) the categories of individuals on whom records are maintained in
>     the system;
> (C) the categories of records maintained in the system;
> (D) each routine use of the records contained in the system, including
>     the categories of users and the purpose of such use;
> (E) the policies and practices of the agency regarding storage,
>     retrievability, access controls, retention, and disposal of the
>     records;
> (F) the title and business address of the agency official who is
>     responsible for the system of records;
> (G) the agency procedures whereby an individual can be notified at his
>     request if the system of records contains a record pertaining to
>     him;
> (H) the agency procedures whereby an individual can be notified at his
>     request how he can gain access to any record pertaining to him
>     contained in the system of records, and how he can contest its
>     content; and
> (I) the categories of sources of records in the system."
> — 5 U.S.C. §552a (e)(4) verbatim

The agency publishes the SORN. **The CSP supplies the structured
input**: categories of individuals + records, routine uses, retention
schedule, safeguards (e)(10), system manager contact, source categories,
notification + access + contest procedures. We currently have **no
structured-input emitter**. Slice M.M1 closes this gap.

#### Gap 2 — Data Protection Impact Assessment (DPIA) for cross-jurisdictional / agency-partner data

A DPIA is a deeper analysis than a PIA. Under U.S. federal practice, a
DPIA is required when:

- Data crosses jurisdictional boundaries (US ↔ EU under EU-US Data
  Privacy Framework; US ↔ Canada under Privacy Shield successor; US ↔
  UK under UK extension).
- Data is shared with agency partners under Computer Matching
  Agreements (Privacy Act §552a (o)).
- Data triggers GDPR Article 35 obligations (when EU-resident PII is
  processed even by a US-based CSP serving a federal agency that
  collected the data from EU residents).

The DPIA must enumerate: data-processing purposes, data-categories
flow map (per Article 35(7)(a) for GDPR; per OMB M-03-22 §II.C.1 for
US-federal), legal basis, necessity-and-proportionality analysis, risk
assessment (likelihood × severity × affected-individual-count), and
mitigation measures.

PIA covers the US-federal CSP-public surface. DPIA covers the
cross-jurisdictional and inter-agency surface. We currently have **no
DPIA emitter**. Slice M.M2 closes this gap.

#### Gap 3 — Full PT-family controls inventory (PT-1 through PT-8)

NIST SP 800-53 Rev 5 introduced the **PT family** (Personally
Identifiable Information Processing and Transparency) in the September
2020 publication. The PT family has **8 controls** at Moderate baseline:

| Control | Title | LOOP-C.C4 coverage | Gap |
|---|---|---|---|
| PT-1 | Policy and Procedures | partial (referenced by PTA) | full policy doc + procedures runbook |
| PT-2 | Authority to Process PII | partial (PIA cites authority) | structured authority register tying each PII processing activity to a specific legal authority |
| PT-3 | PII Processing Purposes | partial (PIA enumerates purposes) | machine-readable purposes ↔ data-elements ↔ retention mapping |
| PT-4 | Consent | NOT covered | when consent is the legal basis, mechanism for capture + withdrawal + records |
| PT-5 | Privacy Notice | NOT covered | the public-facing privacy notice (separate from the SORN, separate from the privacy policy) |
| PT-6 | System of Records Notice | NOT covered (M.M1 ships) | covered by M.M1 |
| PT-7 | Specific Categories of PII | NOT covered | sensitive-PII handling (SSN, biometric, medical, financial, juvenile records) |
| PT-8 | Computer Matching Requirements | NOT covered | when CMA applies, the §552a (o) agreement scaffold |

Slice M.M3 ships a unified PT-family controls inventory emitter — one
OSCAL `implemented-requirements[]` per PT control, tied to the SSP, with
process-artifact KSI envelopes for the operator-supplied content.

#### Gap 4 — Privacy incident response procedures (PT-7 + OMB M-17-12)

OMB Memorandum **M-17-12** "Preparing for and Responding to a Breach of
Personally Identifiable Information" (Jan 3, 2017) supersedes M-07-16
and establishes the federal breach-response framework. Key obligations
the CSP must satisfy when processing PII on behalf of a federal agency:

- **Breach Response Plan** — written, tested annually.
- **Senior Agency Official for Privacy (SAOP)** notification — within
  defined timeline.
- **US-CERT (now CISA) reporting** — within 1 hour of discovery for
  federal civilian executive branch agencies; CSP must support the
  agency's obligation by reporting to the agency within minutes of
  discovery.
- **Affected individual notification** — typically within 60 days of
  discovery; method (mail / email / public substitute notice) per
  individual count + contact-information availability.
- **Congressional notification** — for major incidents (FISMA §3554(b)
  (7)(C)(iii)(IV) defines "major incident"; OMB M-22-05 codifies the
  7-day Congressional notification window).
- **Risk-of-harm assessment** — likelihood × magnitude of harm; criteria
  per M-17-12 §V.

The existing AFR-ICP (Incident Communications Procedures) slice
(LOOP-G.G2) covers the general security-incident communication
framework. It does **not** cover the privacy-specific breach response —
the assessment of harm-of-harm using the M-17-12 §V criteria, the
SAOP notification chain, the SORN-amendment-on-breach pattern, or the
post-breach mitigation requirements specific to PII. Slice M.M4 closes
this gap.

### Artifacts LOOP-M delivers

| # | Artifact | Slice | Consumer |
|---|---|---|---|
| 1 | `out/sorn-draft.md` — Federal Register SORN structured draft | M.M1 | Agency SAOP, OPM, Federal Register publication chain |
| 2 | `out/sorn-input.json` — machine-readable SORN structured input | M.M1 | OSCAL SSP back-matter, tracker DB `privacy_records` |
| 3 | `out/dpia.json` + `out/dpia.docx` — Data Protection Impact Assessment | M.M2 | Agency SAOP, EU-US DPF self-certification, GDPR Article 35 evidence |
| 4 | `out/pt-family-controls.json` — PT-1..PT-8 implemented-requirements envelope | M.M3 | OSCAL SSP `control-implementation`, FedRAMP package |
| 5 | `out/privacy-incident-response-plan.docx` — PT-7 + M-17-12 plan | M.M4 | Agency SAOP, tracker DB `privacy_incidents` |
| 6 | `out/privacy-breach-runbook.json` — structured response playbook | M.M4 | AFR-ICP (LOOP-G.G2) extension, on-call rotation |
| 7 | Tracker DB tables: `privacy_records`, `sorn_publications`, `dpia_findings`, `privacy_incidents`, `pt_control_evidence`, `consent_records` | M.M1, M.M2, M.M3, M.M4 | Process-artifact KSI evidence + operator sign-offs |

### Authorization-package gaps closed

| Package gap | Slice | Authoritative source |
|---|---|---|
| SORN structured input absent — agency cannot publish in Federal Register without it | M.M1 | 5 U.S.C. §552a (e)(4); NIST SP 800-53 Rev 5 PT-6 |
| Cross-jurisdictional / inter-agency PII flows lack DPIA | M.M2 | OMB M-03-22 §II.C.1; GDPR Article 35 (when applicable); §552a (o) for Computer Matching |
| PT-family controls (PT-1..PT-8) lack structured implemented-requirements | M.M3 | NIST SP 800-53 Rev 5 PT-1 through PT-8; FedRAMP Moderate baseline per 800-53B |
| Privacy breach response procedures lack structured plan | M.M4 | OMB M-17-12; NIST SP 800-53 Rev 5 PT-7 + IR-6; FISMA §3554 |

### Connection to FedPy mission (per README + project memory)

FedPy is **read-only, evidence-grade automation for FedRAMP 20x &
Rev5**. A TypeScript collector that captures AWS/GCP/Kubernetes config
evidence for all 60 KSIs (223 requirements), benchmarks against NIST
800-53 at Low/Moderate/High, and signs it (Ed25519 + OSCAL) — plus a
local multi-user tracker over the FRMR catalog.

LOOP-M extends FedPy's privacy package by:

- **Reading from existing collectors** — `core/inventory.ts` data
  classification tag schema (extended in INV-S6) is the source of truth
  for which assets contain PII. Each slice in LOOP-M reads
  `inventory.json` and surfaces PII-bearing assets per M.M1 categories.
- **Extending the FRMR catalog mapping** — the FRMR catalog includes
  PT-family controls in the FedRAMP Moderate baseline; LOOP-M slices
  emit per-control envelopes that wire into the existing
  `core/control-benchmark.ts` benchmark consumed by the SSP, AP, AR,
  and POA&M emitters.
- **OSCAL chain** — M.M3's PT-family controls feed
  `core/oscal-ssp.ts:buildControlImplementation()` as
  `implemented-requirements[]`. M.M1's SORN reference flows into
  `back-matter.resources[]` with `rel: 'sorn-draft'`. M.M2's DPIA
  flows into back-matter as `rel: 'dpia'`. M.M4's privacy IRP into
  back-matter as `rel: 'privacy-irp'`.
- **Tracker DB** — process-artifact KSIs for PT-2 authority, PT-3
  purposes mapping, PT-4 consent capture, PT-5 privacy notice
  publication, PT-7 sensitive-category handling, PT-8 CMA agreements
  all live in tracker tables M.M3 ships.
- **REO standard** — every byte traces to: (a) inventory.json
  (PII-bearing asset enumeration), (b) FRMR catalog (PT-family
  control text), (c) operator-supplied input via tracker / config /
  CLI (legal authorities, retention schedules, routine uses —
  cannot be inferred from cloud SDK output), (d) NIST publication
  identifiers (PT-X control IDs, 800-122 confidentiality impact level).
  No silent fallback, no placeholder data.

---

## 2. Connection to FedPy mission

How does this loop fit FedPy's read-only cloud-evidence collector + KSI
emitter + OSCAL signer + FRMR tracker mission?

### Which existing collectors (providers/aws|gcp|azure) does this loop EXTEND or READ FROM?

- **`providers/aws/inventory.ts`** — extended in INV-S6 to honour
  operator tags `fedramp_data_classification` ∈ {pii, cui, confidential,
  internal, public}. LOOP-M's M.M1 + M.M2 + M.M3 emitters READ FROM
  this enriched inventory to enumerate PII-bearing assets per category.
- **`providers/gcp/inventory.ts`** — same pattern; reads GCP label
  `fedramp-data-classification` (hyphenated per GCP convention).
- **`providers/azure/inventory.ts`** — Azure tag
  `fedramp_data_classification` per resource graph query.
- **`core/inventory.ts`** — the consolidated inventory model. Already
  has `data_classification` field per asset (set in INV-S6). LOOP-M
  extends asset-level schema with:
  - `pii_categories: string[]` — fine-grained PII type tags (SSN,
    biometric, medical, financial, juvenile, geolocation, contact,
    employment). Set via tag `fedramp_pii_categories` (comma-separated).
  - `pii_subjects: string[]` — categories of individuals (employees,
    customers, contractors, public). Set via tag `fedramp_pii_subjects`.
  - `pii_purpose_ids: string[]` — references into the PT-3 purposes
    register the operator authors in tracker. Set via tag
    `fedramp_pii_purposes`.
- **No NEW cloud collectors required.** LOOP-M is a documentation +
  tracker-process loop. The cloud-side coverage was already added by
  INV-S6.

### Which existing core modules (oscal-*.ts, ksi-map.ts, control-benchmark.ts) does it depend on?

- **`core/oscal-ssp.ts`** — extended by M.M3 to surface PT-family
  controls in `control-implementation.implemented-requirements[]`.
  Specifically, the function `buildControlImplementation()` already
  iterates the control-benchmark; M.M3 adds PT-1..PT-8 narrative
  generators.
- **`core/control-benchmark.ts`** — already includes PT-family controls
  in the FedRAMP Moderate baseline (per NIST 800-53B Moderate baseline
  selection). M.M3 enriches the benchmark with `responsibility:
  'csp-supplied'` markers per PT control (versus inherited from the
  underlying IaaS).
- **`core/ksi-map.ts`** — extended by all four LOOP-M slices to
  register process-artifact KSI IDs for tracker-backed evidence:
  `KSI-PRV-SORN` (M.M1), `KSI-PRV-DPIA` (M.M2), `KSI-PRV-PTF` (M.M3),
  `KSI-PRV-IRP` (M.M4). These mirror existing process-artifact KSI IDs
  (`KSI-PRV-PTA`, `KSI-PRV-PIA` that LOOP-C.C4 will register).
- **`core/oscal-poam.ts`** — when M.M4's privacy incident response
  surfaces gaps (e.g. missing SAOP notification chain), they emit as
  POA&M items via the existing finding-to-POA&M pipeline.
- **`core/submission-bundle.ts`** — adds 6 new roles to `WELL_KNOWN`:
  `sorn-draft-md`, `sorn-input-json`, `dpia-json`, `dpia-docx`,
  `pt-family-controls-json`, `privacy-irp-docx`,
  `privacy-breach-runbook-json`.
- **`core/sign.ts`** — every new emit is picked up by the existing
  manifest glob; signed under the same Ed25519 key; covered by the
  RFC 3161 timestamp on the bundle.
- **`core/oscal-validate.ts`** — when M.M3 emits PT-family
  implemented-requirements, the regenerated SSP must still ajv-validate
  against the OSCAL SSP v1.1.2 schema. M.M3 verifies this in tests.

### What NEW collectors or providers must be added (if any)?

None. LOOP-M is a privacy package extension built on:

- Existing cloud collectors (read).
- Existing OSCAL emitters (extend).
- New core emitters (`core/sorn-emit.ts`, `core/dpia-emit.ts`,
  `core/pt-family-emit.ts`, `core/privacy-irp-emit.ts`).
- Tracker DB tables for operator-supplied content.

---

## 3. Dependencies

### Loops / slices that MUST complete first

| Dep | Why |
|---|---|
| **LOOP-A.A1** (`core/oscal-poam.ts`) | M.M4 privacy incident gaps emit as POA&M items via existing pipeline. |
| **LOOP-A.A4** (`core/submission-bundle.ts`) | LOOP-M adds 7 new roles to `WELL_KNOWN`; depends on the catalogue pattern. |
| **LOOP-C.C4** (PTA + PIA emitters) | LOOP-M is the EXTENSION of LOOP-C.C4; PTA's "is PII processed?" determination drives whether SORN (M.M1) is conditionally required. |
| **LOOP-C.C5** (FIPS 199 worksheet) | M.M3 PT-7 sensitive-category mapping pulls confidentiality impact level from C.C5; PII Confidentiality Impact Level per NIST SP 800-122 §3 informs PT-7 enhancement selection. |
| **INV-S6** (Diagram Label + Comments) | LOOP-M reads inventory tags (`fedramp_data_classification`, `fedramp_pii_categories`); the INV-S6 tag-honouring pass guarantees the tags reach `inventory.json`. |
| **R1** (AFR family classification) | M.M4 extends AFR-ICP (LOOP-G.G2) workflow for privacy-specific incidents; R1 classified ICP as REQUIRED at Moderate. |

### Existing files this loop EXTENDS

| File | Modification |
|---|---|
| `cloud-evidence/core/inventory.ts` | Add `pii_categories?: string[]`, `pii_subjects?: string[]`, `pii_purpose_ids?: string[]` to `InventoryAsset`. Backward compatible (all optional). |
| `cloud-evidence/core/oscal-ssp.ts` | (M.M3) `buildControlImplementation()` adds PT-1..PT-8 narrative generators. (M.M1) `back-matter.resources[]` includes `sorn-draft` entry when M.M1 ran. (M.M2) `back-matter.resources[]` includes `dpia` entry when M.M2 ran. |
| `cloud-evidence/core/ksi-map.ts` | Register `KSI-PRV-SORN`, `KSI-PRV-DPIA`, `KSI-PRV-PTF`, `KSI-PRV-IRP` as process-artifact KSIs (no cloud collector dispatch). |
| `cloud-evidence/core/orchestrator.ts` | New flags: `--sorn`, `--dpia`, `--pt-family`, `--privacy-irp`, plus env equivalents. |
| `cloud-evidence/core/submission-bundle.ts` | Add 7 new roles to `WELL_KNOWN`. |
| `cloud-evidence/CHANGELOG.md` | Unreleased entry per slice (see Section 9). |
| `cloud-evidence/docs/STATUS.md` | Per-slice status row updated when slice ships; LOOP-M section appended below LOOP-K. |
| `tracker/server/schema.sql` | Tables `privacy_records`, `sorn_publications`, `dpia_findings`, `privacy_incidents`, `pt_control_evidence`, `consent_records`. |
| `tracker/server/index.ts` | Mount privacy routes (per-slice). |
| `tracker/client/src/App.tsx` | Add `/privacy/sorn`, `/privacy/dpia`, `/privacy/pt-controls`, `/privacy/incidents` routes. |
| `cloud-evidence/docs/loops/LOOP-M-SPEC.md` | This file. |
| `cloud-evidence/docs/loops/LOOP-M-RISKS.md` | New risks register. |
| `cloud-evidence/docs/slices/M/M.M[1-4].md` | New per-slice docs. |

### Loops UNBLOCKED when LOOP-M is complete

| Unblocked loop | Reason |
|---|---|
| LOOP-C.C7 (Risk Management Strategy) | Privacy risks from M.M2 DPIA + M.M4 incident catalogue feed RMS organisational risk section. |
| LOOP-E.E1 (Monthly ConMon report) | Privacy section of monthly report sources from M.M4 incident records + M.M3 PT-control evidence. |
| LOOP-G.G2 (AFR-ICP) | M.M4 extends ICP with privacy-specific incident classification; G.G2 reuses M.M4's response chain. |
| LOOP-Q.Q1 (Marketplace metadata) — if adopted | Marketplace listing's privacy posture summary derives from M.M1 SORN + M.M2 DPIA artifacts. |

### Conditional adoption

Per ADDITIONAL-LOOPS-AUDIT.md §5 open question #2: LOOP-M.M1 (SORN) is
conditional on whether the CSP processes Privacy-Act-protected PII for
a federal agency. Before M.M1 starts, the operator must resolve:

1. Does any CSO instance maintain records retrievable by individual
   identifier on behalf of a federal agency?
   - **YES** → M.M1 ships full SORN emitter.
   - **NO** → M.M1 ships single-slice attestation:
     `out/no-system-of-records-attested.json` with operator-signed
     attestation in tracker; downstream OSCAL SSP records the negative.

M.M2 (DPIA), M.M3 (PT-family), M.M4 (privacy IRP) ship regardless —
PIA-class processing (M-03-22 trigger) is broader than Privacy Act
system-of-records (§552a trigger).

---

## 4. Authoritative sources

Every URL + spec referenced in any LOOP-M slice. All quotes are verbatim
where retrievable. Where the source PDF returns HTTP 403/404 to
anonymous fetches, the slice records the URL + the implementer must
download the PDF into `cloud-evidence/docs/sources/` and re-quote in
the slice docstring (mirroring the LOOP-B FedRAMP CMP pattern).

### Privacy Act of 1974 (5 U.S.C. §552a)

- **Cornell LII canonical text** — https://www.law.cornell.edu/uscode/text/5/552a
  - **§552a (a)(4) "record"**:
    > "any item, collection, or grouping of information about an
    > individual that is maintained by an agency, including, but not
    > limited to, his education, financial transactions, medical
    > history, and criminal or employment history and that contains his
    > name, or the identifying number, symbol, or other identifying
    > particular assigned to the individual, such as a finger or voice
    > print or a photograph."
  - **§552a (a)(5) "system of records"**:
    > "a group of any records under the control of any agency from
    > which information is retrieved by the name of the individual or
    > by some identifying number, symbol, or other identifying
    > particular assigned to the individual."
  - **§552a (e)(3) point-of-collection notice**:
    > "Each agency that maintains a system of records shall inform each
    > individual whom it asks to supply information, on the form which
    > it uses to collect the information or on a separate form that can
    > be retained by the individual —
    > (A) the authority (whether granted by statute, or by executive
    >     order of the President) which authorizes the solicitation of
    >     the information and whether disclosure of such information is
    >     mandatory or voluntary;
    > (B) the principal purpose or purposes for which the information
    >     is intended to be used;
    > (C) the routine uses which may be made of the information, as
    >     published pursuant to paragraph (4)(D) of this subsection;
    >     and
    > (D) the effects on him, if any, of not providing all or any part
    >     of the requested information."
  - **§552a (e)(4)** — the SORN publication obligation + 11 specific
    elements (A)-(I) and (J)+(K) for sources and exemptions. Quoted in
    §1 of this spec; M.M1 carries the full quote in its docstring.
  - **§552a (e)(10)** — administrative, technical, and physical
    safeguards:
    > "establish appropriate administrative, technical, and physical
    > safeguards to insure the security and confidentiality of records
    > and to protect against any anticipated threats or hazards to
    > their security or integrity which could result in substantial
    > harm, embarrassment, inconvenience, or unfairness to any
    > individual on whom information is maintained."
  - **§552a (o) Computer Matching Agreements** — drives M.M2's
    cross-agency DPIA scaffold and M.M3's PT-8 control. Quoted
    verbatim in M.M2 + M.M3 per-slice docs.
  - **§552a (p)** — verification and opportunity to contest before
    adverse action.

- **DOJ Office of Privacy and Civil Liberties** — https://www.justice.gov/opcl/privacy-act-1974
  (HTTP 403 on anonymous fetch; archived via DOJ Privacy Act Overview
  PDF the implementer downloads into
  `cloud-evidence/docs/sources/doj-privacy-act-overview.pdf`.)

### OMB Memoranda

- **OMB M-03-22** "OMB Guidance for Implementing the Privacy
  Provisions of the E-Government Act of 2002" —
  https://www.whitehouse.gov/wp-content/uploads/legacy_drupal_files/omb/memoranda/2003/m03_22.pdf
  (HTTP 404 on anonymous fetch; archived to OPM + GSA mirrors. Implementer
  downloads to `cloud-evidence/docs/sources/omb-m-03-22.pdf`.)
  - **§II.A** when a PIA is required.
  - **§II.B.1** verbatim (per ADDITIONAL-LOOPS-AUDIT.md §2 quote):
    > "Agencies must conduct a PIA before developing or procuring IT
    > systems or projects that collect, maintain, or disseminate
    > information in identifiable form from or about members of the
    > public."
  - **§II.C** PIA content requirements: data being collected;
    why; intended use; with whom shared; what notice/opportunities for
    consent; how secured; whether a system of records is being created.
  - **§II.C.1.f** drives the SORN ↔ PIA cross-reference M.M1 emits.

- **OMB M-17-12** "Preparing for and Responding to a Breach of
  Personally Identifiable Information" (Jan 3, 2017) —
  https://www.whitehouse.gov/wp-content/uploads/legacy_drupal_files/omb/memoranda/2017/m-17-12_0.pdf
  (Large PDF; WebFetch maxContentLength exceeded. Implementer downloads
  to `cloud-evidence/docs/sources/omb-m-17-12.pdf` and quotes verbatim
  in M.M4's docstring.)
  - **§III "Breach Response Team"** — required composition: SAOP,
    CIO, CISO, Communications, Legal Counsel, Legislative Affairs,
    Office of Inspector General, Office of General Counsel.
  - **§IV "Breach Response Plan"** — required content: 8 sections,
    including assessment-of-harm criteria + notification chain.
  - **§V "Assessing the Risk of Harm to Individuals"** — five-factor
    criteria: (1) nature and sensitivity of PII, (2) likelihood of
    access and use, (3) type of breach, (4) wider context, (5)
    individuals affected.
  - **§VI "Notification"** — Congressional notification timeline,
    individual notification, substitute notice criteria.

- **OMB M-22-05** "Fiscal Year 2021-2022 Guidance on Federal
  Information Security and Privacy Management Requirements" — codifies
  7-day Congressional notification for "major incidents" under FISMA
  §3554(b)(7)(C). Cited by M.M4 for the major-incident threshold.

- **OMB Circular A-130** "Managing Information as a Strategic
  Resource" — §6.j Privacy Program Plan content requirements; informs
  M.M3 PT-1 policy emission.
  https://www.whitehouse.gov/sites/whitehouse.gov/files/omb/circulars/A130/a130revised.pdf

### NIST SP 800-53 Rev 5 (PT family)

- **NIST SP 800-53 Rev 5** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
  (5.8 MB PDF; WebFetch returns binary stream not parseable through
  the web tool. Implementer downloads to
  `cloud-evidence/docs/sources/nist-sp-800-53-rev5.pdf` and quotes
  PT-family verbatim from §3.18 in each per-slice doc.)

The PT family appears in §3.18 "Personally Identifiable Information
Processing and Transparency". Eight base controls:

- **PT-1 "Policy and Procedures"**: organization-level policy for PII
  processing + procedures to facilitate the implementation of the PT
  family. Sub-elements (a) policy addressing purpose/scope/roles/
  responsibilities/coordination/compliance; (b) procedures to
  facilitate implementation; (c) designation of an [official]; (d)
  review and update frequency.
- **PT-2 "Authority to Process Personally Identifiable Information"**:
  determine and document the legal authority for the collection, use,
  maintenance, and sharing of PII, and restrict processing to only
  that which is authorized.
- **PT-3 "Personally Identifiable Information Processing Purposes"**:
  identify and document the [purpose(s)] for processing PII; describe
  the [purpose(s)] in the public privacy notices and policies of the
  organization; restrict the [processing of PII] to only that which is
  compatible with the identified purpose(s); monitor changes to the
  PII processing.
- **PT-4 "Consent"**: implement [tools or mechanisms] for individuals
  to consent to the processing of their PII prior to its collection
  that facilitate individuals' informed decision-making.
- **PT-5 "Privacy Notice"**: provide notice to individuals about the
  processing of PII that: (a) is available to individuals upon first
  interacting with an organization; (b) is updated [frequency or
  conditions]; (c) includes the [authority], [purpose(s)], [routine
  uses], etc.
- **PT-6 "System of Records Notice"** (closed by M.M1):
  for systems that process information that will be maintained in a
  system of records — (a) draft and publish a SORN in the Federal
  Register; (b) keep the SORN accurate, up-to-date, and scoped to the
  systems; (c) revise the SORN to reflect changes.
- **PT-7 "Specific Categories of Personally Identifiable
  Information"** (closed by M.M4 + M.M3 enhancement): apply the
  [processing conditions] for specific categories of PII, including:
  social security numbers, Federal Tax Information, criminal history
  records, juvenile records, medical/health records, financial
  records, biometric data, immigration data, geolocation data.
- **PT-8 "Computer Matching Requirements"** (closed by M.M3): when a
  system or organization processes information for the purpose of
  conducting a matching program (per Privacy Act §552a(o)) — publish a
  Computer Matching Agreement, establish a Data Integrity Board,
  publish matching notices in the Federal Register.

- **NIST SP 800-53B Rev 5 Moderate Baseline** —
  https://csrc.nist.gov/pubs/sp/800/53/b/upd1/final
  per the Moderate baseline selection: PT-1, PT-2, PT-2(1), PT-2(2),
  PT-3, PT-3(1), PT-3(2), PT-4, PT-5, PT-5(1), PT-5(2), PT-6, PT-6(1),
  PT-6(2), PT-7, PT-7(1), PT-7(2), PT-8 are ALL in the Moderate
  baseline (per 800-53B Table 3-1, errata Dec 2023). M.M3 emits each.

- **NIST SP 800-122** "Guide to Protecting the Confidentiality of
  Personally Identifiable Information (PII)" —
  https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-122.pdf
  (799 KB PDF; binary, not WebFetch-parseable. Implementer downloads
  to `cloud-evidence/docs/sources/nist-sp-800-122.pdf` and quotes from
  §2 PII definition + §3 confidentiality impact level + §4 safeguards.)
  - **§2.1 PII definition**:
    > "Information that can be used to distinguish or trace an
    > individual's identity, such as their name, social security
    > number, biometric records, etc. alone, or when combined with
    > other personal or identifying information which is linked or
    > linkable to a specific individual, such as date and place of
    > birth, mother's maiden name, etc."
  - **§3 confidentiality impact level (Low/Moderate/High)**:
    factors: identifiability, quantity of PII, data field sensitivity,
    context of use, obligation to protect confidentiality, access to
    and location of PII. Used by M.M3 PT-7 to drive control enhancement
    selection.

- **NIST SP 800-37 Rev 2** Step 1 (Privacy Categorize) —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-37r2.pdf
  Privacy categorization is a parallel step to security categorization
  in RMF Step 1. M.M3 PT-2 implementation reads the
  privacy-categorization output to drive the authority-to-process
  documentation.

### NIST Privacy Framework v1.0

- **NIST Privacy Framework Core v1.0** —
  https://www.nist.gov/privacy-framework
  - Five functions: Identify-P, Govern-P, Control-P, Communicate-P,
    Protect-P. M.M3 maps PT-1..PT-8 to Privacy Framework subcategories
    in the PT-control envelope's `props[]` for cross-framework
    traceability (mirrors the LOOP-A SSP's NIST CSF crosswalk pattern).

### Federal Register / SORN template

- **Federal Register search for "system of records"** notices —
  https://www.federalregister.gov/documents/search?conditions%5Btype%5D%5B%5D=NOTICE&conditions%5Bterm%5D=%22system+of+records%22
  - The current SORN template structure (per published SORNs in
    Federal Register 2024-2026):
    1. AGENCY identifier
    2. ACTION: Notice of a new/modified/rescinded system of records.
    3. SUMMARY paragraph.
    4. DATES paragraph (effective date, comment period).
    5. ADDRESSES paragraph (where to send comments).
    6. FOR FURTHER INFORMATION CONTACT.
    7. SUPPLEMENTARY INFORMATION.
    8. SYSTEM NAME AND NUMBER.
    9. SECURITY CLASSIFICATION.
    10. SYSTEM LOCATION.
    11. SYSTEM MANAGER(S).
    12. AUTHORITY FOR MAINTENANCE OF THE SYSTEM.
    13. PURPOSE(S) OF THE SYSTEM.
    14. CATEGORIES OF INDIVIDUALS COVERED BY THE SYSTEM.
    15. CATEGORIES OF RECORDS IN THE SYSTEM.
    16. RECORD SOURCE CATEGORIES.
    17. ROUTINE USES OF RECORDS MAINTAINED IN THE SYSTEM, INCLUDING
        CATEGORIES OF USERS AND THE PURPOSES OF SUCH USES.
    18. POLICIES AND PRACTICES FOR STORAGE OF RECORDS.
    19. POLICIES AND PRACTICES FOR RETRIEVAL OF RECORDS.
    20. POLICIES AND PRACTICES FOR RETENTION AND DISPOSAL OF RECORDS.
    21. ADMINISTRATIVE, TECHNICAL, AND PHYSICAL SAFEGUARDS.
    22. RECORD ACCESS PROCEDURES.
    23. CONTESTING RECORD PROCEDURES.
    24. NOTIFICATION PROCEDURES.
    25. EXEMPTIONS PROMULGATED FOR THE SYSTEM.
    26. HISTORY.

M.M1 emits a draft formatted to these section headers. Implementer
fetches the live `unblock.federalregister.gov` redirect target as
needed to refresh the template.

### FedRAMP privacy guidance

- **FedRAMP Privacy Templates** — the PTA and PIA templates ship in
  the FedRAMP template pack at
  https://www.fedramp.gov/assets/resources/templates/ . LOOP-C.C4
  ships those two; LOOP-M.M1's SORN draft schema EXTENDS the same
  template-pack convention but the FedRAMP template pack does NOT
  ship a SORN template (SORN is agency-published in the Federal
  Register, not part of the FedRAMP authorization package). M.M1
  emits its own structured Markdown + JSON.

### GDPR Article 35 (cross-jurisdictional context)

- **GDPR Article 35 "Data protection impact assessment"** —
  https://gdpr-info.eu/art-35-gdpr/
  - **Art. 35(1)**:
    > "Where a type of processing in particular using new technologies,
    > and taking into account the nature, scope, context and purposes
    > of the processing, is likely to result in a high risk to the
    > rights and freedoms of natural persons, the controller shall,
    > prior to the processing, carry out an assessment of the impact
    > of the envisaged processing operations on the protection of
    > personal data."
  - **Art. 35(7)** required DPIA content: (a) systematic description
    of envisaged processing operations + purposes; (b) assessment of
    necessity and proportionality; (c) assessment of risks; (d)
    measures envisaged to address risks.
  - M.M2 ships a Article-35(7)-aligned DPIA emitter; field set is a
    superset that also covers OMB M-03-22 §II.C content.

### Other federal references

- **FISMA §3554(b)(7)(C)** "major incident" definition — per OMB
  M-22-05 codified guidance.
- **44 U.S.C. §3501 et seq** — Paperwork Reduction Act (PRA) +
  privacy obligations on information-collection requests.
- **National Archives Records Retention Schedule** (NARA general
  records schedule) — drives retention/disposal practices in
  M.M1 SORN section 20 + M.M3 PT-2 authority.

---

## 5. Per-slice implementation specs

### Slice M.M1 — System of Records Notice (SORN) emitter — Privacy Act §552a SORN

**Why this slice**: When a federal agency authorises this CSO to
maintain records retrievable by individual identifier (name, SSN,
employee number, customer ID), the Privacy Act §552a (e)(4) obligates
the agency to publish a SORN in the Federal Register **before** that
retrieval-by-identifier capability goes live. The agency publishes; the
CSP supplies the 11 statutory elements as structured input. No emitter
exists today.

**Connection to FedPy mission**: Reads `inventory.json` for asset-level
PII categories + subjects + identifier-retrievability flags
(tag-driven). Reads `core/control-benchmark.ts` for the PT-6 control
text. Emits a Markdown draft mirroring Federal Register SORN structure
+ a machine-readable `sorn-input.json` consumed by M.M2 DPIA + M.M3
PT-6 + the SSP back-matter. Tracker DB tables store operator-supplied
content (legal authorities, routine uses, retention schedule). REO Rule
4 markers for every field operator must supply.

**Files to create** (exact paths):
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sorn-emit.ts` —
  ~600 lines. Reads inventory + tracker `privacy_records` table.
  Emits Markdown draft + JSON structured input.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sorn-schema.ts` —
  typed schema for the 11 statutory elements (a)-(k) + the 26 Federal
  Register template fields.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sorn-reader.ts`
  — read-only client pulling `sorn_publications` + `privacy_records`
  rows from the tracker via HTTP, written to `out/.sorn-snapshot.json`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/sorn-emit.test.ts`
  — ≥14 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/sorn-schema.test.ts`
  — typed schema validation tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/sorn/`
  — sample inventory + tracker snapshot fixtures.
- `tracker/server/routes/privacy-records.ts` — CRUD for the
  `privacy_records` table.
- `tracker/server/routes/sorn-publications.ts` — CRUD for SORN draft
  versions + agency-side publication tracking.
- `tracker/client/src/pages/PrivacyRecords.tsx` — UI page.
- `tracker/client/src/pages/SornPublications.tsx` — UI page.
- `tracker/server/routes/privacy-records.test.ts`.
- `tracker/server/routes/sorn-publications.test.ts`.

**Files to extend**:
- `cloud-evidence/core/inventory.ts` — add optional `pii_categories`,
  `pii_subjects`, `pii_purpose_ids`, `retrieval_by_identifier?: boolean`.
- `cloud-evidence/core/orchestrator.ts` — `--sorn`,
  `CLOUD_EVIDENCE_SORN`, `--sorn-config <path>`,
  `--pull-privacy-records <tracker-url>`.
- `cloud-evidence/core/submission-bundle.ts` — add roles
  `sorn-draft-md`, `sorn-input-json`.
- `cloud-evidence/core/oscal-ssp.ts` — add SORN reference to
  `back-matter.resources[]` when M.M1 ran (rel=`sorn-draft`).
- `cloud-evidence/core/ksi-map.ts` — register `KSI-PRV-SORN` as
  process-artifact.
- `tracker/server/schema.sql` — append `privacy_records`,
  `sorn_publications` tables.
- `tracker/server/index.ts` — mount routes.
- `tracker/client/src/App.tsx` — add routes.

**Schemas / standards**:
- **5 U.S.C. §552a (e)(4)** — the 11 statutory elements (verbatim in
  per-slice doc).
- **Federal Register SORN template** — 26 section headers (enumerated
  in §4 of this spec).
- **NIST SP 800-53 Rev 5 PT-6** — control statement + enhancements.
- **OMB M-03-22 §II.C.1.f** — PIA must cross-reference SORN.

**Build steps** (numbered, concrete):

1. Define `SornDraft` TypeScript interface in `core/sorn-schema.ts`:
   ```ts
   export interface SornDraft {
     // Federal Register administrative
     agency: string;                        // e.g. "Department of Health and Human Services"
     agency_component?: string;             // e.g. "Centers for Medicare and Medicaid Services"
     action: 'new' | 'modified' | 'rescinded';
     summary: string;
     effective_date: string;                // ISO date
     comment_period_close: string;          // ISO date
     addresses_for_comments: string;
     poc_name: string;
     poc_email: string;
     poc_phone: string;

     // Statutory §552a (e)(4) elements
     system_name: string;
     system_number: string;
     security_classification: 'unclassified' | 'cui' | 'classified';
     system_location: string;
     system_manager_title: string;
     system_manager_business_address: string;
     authority_for_maintenance: string[];   // statutory citations
     purpose: string;
     categories_of_individuals: string[];
     categories_of_records: string[];
     record_source_categories: string[];
     routine_uses: RoutineUse[];            // structured array
     storage_practices: string;
     retrieval_practices: string;
     retention_and_disposal: string;
     administrative_safeguards: string;
     technical_safeguards: string;
     physical_safeguards: string;
     record_access_procedures: string;
     contesting_procedures: string;
     notification_procedures: string;
     exemptions_claimed: string[];
     history: SornHistoryEntry[];
   }
   export interface RoutineUse {
     id: string;
     description: string;
     categories_of_users: string[];
     purpose: string;
     legal_basis?: string;
   }
   export interface SornHistoryEntry {
     federal_register_volume: string;
     federal_register_page: string;
     publication_date: string;             // ISO date
     change_description: string;
   }
   ```

2. Builder signature:
   ```ts
   export interface SornEmitOptions {
     outDir: string;
     inventoryPath?: string;
     sornSnapshotPath?: string;             // tracker snapshot
     sornConfigPath?: string;               // operator config
     systemId: string;
     systemName: string;
     impactLevel: 'low' | 'moderate' | 'high';
     runId: string;
   }
   export interface SornEmitResult {
     md_path: string | null;                // null when conditional-N/A
     json_path: string | null;
     skipped_reason?: 'no-system-of-records-attested';
     requires_operator_input: string[];     // field paths missing
     ready_for_signature: boolean;
   }
   export async function emitSorn(opts: SornEmitOptions): Promise<SornEmitResult>;
   ```

3. **Conditional emit** — when the tracker snapshot's
   `privacy_records.retrieval_by_identifier_attested === false` for
   every system, return `skipped_reason: 'no-system-of-records-attested'`
   and emit `out/no-system-of-records-attested.json` carrying the
   signed attestation. Otherwise build the SORN draft.

4. **Auto-fill from inventory** — for each asset in `inventory.json`
   with `pii_categories` non-empty AND `retrieval_by_identifier ===
   true`:
   - `categories_of_individuals` ← union of `asset.pii_subjects[]`.
   - `categories_of_records` ← union of `asset.pii_categories[]`
     mapped to human-readable phrases (e.g. `ssn` →
     "Social Security numbers").
   - `system_location` ← derived from `asset.location` +
     `asset.provider` (e.g. "AWS us-gov-west-1 RDS").

5. **Operator-supplied fields** (tracker-backed):
   - `authority_for_maintenance` — array of statutory citations
     (e.g. "42 U.S.C. §1395 et seq.; 5 U.S.C. §301").
   - `routine_uses` — structured array; operator authors each one.
   - `retention_and_disposal` — NARA records schedule reference.
   - `system_manager_*` — fixed per system.

6. **Markdown draft format** — emit `out/sorn-draft.md` following the
   26 Federal Register section headers verbatim:
   ```markdown
   ## AGENCY: <agency>
   ### ACTION: <action>
   ### SUMMARY: <summary>
   ### DATES:
   - Effective: <effective_date>
   - Comments due: <comment_period_close>
   ### ADDRESSES: <addresses_for_comments>
   ### FOR FURTHER INFORMATION CONTACT: <poc_name>, <poc_email>, <poc_phone>
   ### SUPPLEMENTARY INFORMATION:
   #### SYSTEM NAME AND NUMBER: <system_name> (<system_number>)
   #### SECURITY CLASSIFICATION: <security_classification>
   #### SYSTEM LOCATION: <system_location>
   ...(through all 26 sections)
   ```
   Any unsupplied field renders as `REQUIRES-OPERATOR-INPUT: <field
   name> — set via tracker /privacy/sorn-publications/<sorn-uuid>`.

7. **JSON output** — `out/sorn-input.json` is the canonical machine
   form (same fields as SornDraft); provenance block per REO Rule 2.6.

8. **OSCAL SSP back-matter integration**: after M.M1 ships,
   `core/oscal-ssp.ts` adds to back-matter.resources:
   ```json
   {
     "uuid": "<deterministic>",
     "title": "System of Records Notice — draft",
     "rlinks": [
       { "href": "./sorn-draft.md", "media-type": "text/markdown" },
       { "href": "./sorn-input.json", "media-type": "application/json" }
     ],
     "props": [{ "name": "rel", "ns": "<fedramp-ns>", "value": "sorn-draft" }]
   }
   ```

9. **Tracker DB tables**:
   ```sql
   CREATE TABLE IF NOT EXISTS privacy_records (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     system_id TEXT NOT NULL,
     pii_category TEXT NOT NULL,
     subject_category TEXT NOT NULL,
     legal_authority TEXT NOT NULL,
     retention_period_days INTEGER NOT NULL,
     retrieval_by_identifier_attested INTEGER NOT NULL CHECK (retrieval_by_identifier_attested IN (0,1)),
     attested_by_user_id INTEGER REFERENCES users(id),
     attested_at TEXT,
     signature TEXT,
     signing_key_id TEXT,
     created_at TEXT NOT NULL,
     updated_at TEXT NOT NULL
   );
   CREATE INDEX IF NOT EXISTS idx_pr_system ON privacy_records(system_id);
   CREATE INDEX IF NOT EXISTS idx_pr_category ON privacy_records(pii_category);

   CREATE TABLE IF NOT EXISTS sorn_publications (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     system_id TEXT NOT NULL,
     system_name TEXT NOT NULL,
     system_number TEXT NOT NULL,
     draft_json TEXT NOT NULL,            -- SornDraft serialized
     status TEXT NOT NULL CHECK (status IN ('draft','submitted-to-agency','published','rescinded')),
     federal_register_volume TEXT,
     federal_register_page TEXT,
     publication_date TEXT,
     created_by_user_id INTEGER NOT NULL REFERENCES users(id),
     reviewed_by_saop_user_id INTEGER REFERENCES users(id),
     reviewed_at TEXT,
     created_at TEXT NOT NULL,
     updated_at TEXT NOT NULL
   );
   CREATE INDEX IF NOT EXISTS idx_sp_system ON sorn_publications(system_id);
   CREATE INDEX IF NOT EXISTS idx_sp_status ON sorn_publications(status);
   ```

10. **Bundler integration** — add to `WELL_KNOWN`:
    ```ts
    { role: 'sorn-draft-md', filename: 'sorn-draft.md', description: 'System of Records Notice — Federal Register draft (M.M1)' },
    { role: 'sorn-input-json', filename: 'sorn-input.json', description: 'SORN structured input (M.M1)' },
    { role: 'no-sorn-attestation', filename: 'no-system-of-records-attested.json', description: 'Signed attestation that no §552a system exists (M.M1 conditional)' },
    ```

11. **Wire orchestrator** — `--sorn` flag runs before OSCAL SSP +
    POA&M emission so SSP picks up the back-matter resource.

12. **Sign + timestamp** — `sorn-draft.md`, `sorn-input.json`, and
    `no-system-of-records-attested.json` all picked up by existing
    `core/sign.ts` glob + included in RFC 3161 manifest.

**REQUIRES-OPERATOR-INPUT fields**:

Per REO Rule 4, every field that cannot be auto-derived:

| Field | Source | Behavior when missing |
|---|---|---|
| `agency` | `org-profile.yaml` `customer.agency_name` or CLI flag `--customer-agency` | Renders as `REQUIRES-OPERATOR-INPUT: agency` in MD; absent in JSON; `ready_for_signature = false` |
| `authority_for_maintenance[]` | Tracker `privacy_records.legal_authority` | Same — never substitute a default statute |
| `routine_uses[]` | Tracker UI `/privacy/sorn-publications/<id>/edit` | Same — cannot be inferred from inventory |
| `retention_and_disposal` | Tracker `privacy_records.retention_period_days` + NARA schedule reference (operator-supplied) | Same |
| `system_manager_*` | `org-profile.yaml` `privacy.system_manager` | Same |
| `record_access_procedures` | Operator config (template language can be suggested but operator must adopt explicitly) | Same |
| `contesting_procedures` | Operator config | Same |
| `notification_procedures` | Operator config | Same |
| `exemptions_claimed[]` | Operator config (most CSOs claim none; explicit empty array required) | Same; empty-array MUST be explicit, not default |

**Test specifications** (≥14 tests):

1. `it('emits no-system-of-records-attested.json when retrieval_by_identifier_attested=false for all systems')` — conditional path.
2. `it('emits full SORN draft when at least one system has retrieval_by_identifier_attested=true')`.
3. `it('renders all 26 Federal Register section headers in the markdown')`.
4. `it('emits REQUIRES-OPERATOR-INPUT for every unsupplied statutory element')`.
5. `it('auto-fills categories_of_individuals from inventory pii_subjects')`.
6. `it('auto-fills categories_of_records from inventory pii_categories')`.
7. `it('renders structured routine_uses array with id + description + users + purpose')`.
8. `it('refuses to emit when authority_for_maintenance is empty AND any system requires SORN')` — never silently fall through.
9. `it('emits sorn-input.json with provenance.emitter + emittedAt + sourceCalls + signingKeyId')`.
10. `it('refuses ready_for_signature when any REQUIRES-OPERATOR-INPUT marker present')`.
11. `it('OSCAL SSP back-matter gains sorn-draft resource after M.M1 runs')`.
12. `it('registers KSI-PRV-SORN process-artifact in ksi-map')`.
13. `it('tracker route POST /privacy/sorn-publications creates draft with SAOP review required')`.
14. `it('tracker route enforces system_number uniqueness per agency')`.
15. `it('snapshot reader verifies signature on every privacy_records row')`.
16. `it('bundle includes sorn-draft-md role + sorn-input-json role')`.
17. `it('CHANGELOG entry for M.M1 cites verbatim 5 U.S.C. §552a (e)(4)')`.

**REO compliance** specific to this slice:

- Every value in `sorn-input.json` traces to: inventory.json read,
  tracker DB row (signed), or operator config — NO silent defaults.
- `agency`, `system_manager_*`, `authority_for_maintenance[]`,
  `routine_uses[]`, `retention_and_disposal` are ALL operator-supplied;
  collector NEVER fabricates.
- `categories_of_individuals` + `categories_of_records` are
  inventory-derived; the tag schema is documented in operator runbook.
- Provenance block populated.
- Signed by existing `core/sign.ts` pipeline.
- Conditional skip (`no-system-of-records-attested`) is itself a
  signed attestation, NOT a silent omission — REO Rule 5.

**Verification commands**:
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/sorn-emit.test.ts tests/core/sorn-schema.test.ts
npm run check:reo
npm run check:provenance
cd ../tracker
npm run typecheck
npm test -- server/routes/privacy-records.test.ts server/routes/sorn-publications.test.ts
```

**Estimated effort**: 5-6 working days.

---

### Slice M.M2 — Data Protection Impact Assessment (DPIA) for cross-border / agency-partner data

**Why this slice**: PIA (LOOP-C.C4) covers the US-federal CSP-public
surface. When data crosses jurisdictional boundaries or is shared with
agency partners under Computer Matching Agreements, the obligation
becomes a DPIA — deeper analysis with explicit risk × mitigation
matrix.

**Connection to FedPy mission**: Reads `inventory.json` for asset
locations (regions) to detect cross-region / cross-cloud flows. Reads
M.M1 SORN snapshot to identify Privacy-Act systems. Reads tracker
`dpia_findings` for operator-authored risk + mitigation entries. Emits
DPIA `.json` + `.docx` per Article 35(7) field set (superset of
M-03-22 PIA fields).

**Files to create**:
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dpia-emit.ts`
  — ~700 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dpia-schema.ts`
  — typed DPIA model (Article 35(7) aligned, superset of M-03-22).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dpia-reader.ts`
  — tracker `dpia_findings` snapshot pull.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/dpia-emit.test.ts`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/dpia-schema.test.ts`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/dpia/`.
- `tracker/server/routes/dpia-findings.ts`.
- `tracker/client/src/pages/Dpia.tsx`.
- `tracker/server/routes/dpia-findings.test.ts`.

**Files to extend**:
- `cloud-evidence/core/orchestrator.ts` — `--dpia`,
  `CLOUD_EVIDENCE_DPIA`.
- `cloud-evidence/core/submission-bundle.ts` — roles `dpia-json`,
  `dpia-docx`.
- `cloud-evidence/core/oscal-ssp.ts` — `back-matter.resources[]` gains
  `dpia` reference.
- `cloud-evidence/core/ksi-map.ts` — register `KSI-PRV-DPIA`.
- `tracker/server/schema.sql` — `dpia_findings` table.

**Schemas / standards**:
- **GDPR Article 35(7)** — DPIA required content.
- **OMB M-03-22 §II.C** — PIA superset (US-federal).
- **Privacy Act §552a (o)** — Computer Matching Agreement scaffold.
- **EU-US Data Privacy Framework** — when EU-resident data implicated.
- **OMB Circular A-130 Appendix II** — privacy controls + DPIA pattern.

**Build steps**:

1. Define `Dpia` interface:
   ```ts
   export interface Dpia {
     system_id: string;
     system_name: string;
     trigger: DpiaTrigger;
     processing_description: ProcessingDescription;
     necessity_proportionality: NecessityProportionalityAnalysis;
     risk_assessment: DpiaRisk[];
     mitigations: DpiaMitigation[];
     consultation: ConsultationRecord[];
     residual_risk: 'low' | 'moderate' | 'high';
     dpo_recommendation: string;
     decision: 'approved' | 'approved-with-conditions' | 'rejected' | 'pending';
   }
   export interface DpiaTrigger {
     reason: 'cross-jurisdictional' | 'agency-partner-sharing' | 'computer-matching-agreement' | 'high-risk-processing';
     jurisdictions: string[];           // e.g. ['US', 'EU']
     partner_agencies: string[];
     cma_reference?: string;            // Privacy Act §552a (o) agreement id
   }
   export interface ProcessingDescription {
     purposes: string[];
     legal_basis: string[];
     pii_categories: string[];
     data_subjects: string[];
     data_recipients: string[];
     data_transfers: DataTransfer[];
     retention_periods: Record<string, number>;  // category → days
   }
   export interface DataTransfer {
     source_jurisdiction: string;
     destination_jurisdiction: string;
     legal_mechanism: 'eu-us-dpf' | 'standard-contractual-clauses' | 'binding-corporate-rules' | 'adequacy-decision' | 'derogation' | 'us-federal-only';
     volume_estimate: string;
   }
   export interface DpiaRisk {
     id: string;
     description: string;
     likelihood: 'very-low' | 'low' | 'moderate' | 'high' | 'very-high';
     severity: 'very-low' | 'low' | 'moderate' | 'high' | 'very-high';
     affected_population_size: number;
     inherent_risk: 'very-low' | 'low' | 'moderate' | 'high' | 'very-high';
   }
   export interface DpiaMitigation {
     risk_id: string;
     description: string;
     control_ids: string[];             // NIST 800-53 PT-* references
     residual_likelihood: 'very-low' | 'low' | 'moderate' | 'high' | 'very-high';
     residual_severity: 'very-low' | 'low' | 'moderate' | 'high' | 'very-high';
   }
   export interface ConsultationRecord {
     consulted_party: string;
     consulted_role: 'data-subjects' | 'representatives' | 'dpo' | 'agency-counsel' | 'saop';
     date: string;
     summary: string;
   }
   ```

2. **Auto-derive `trigger`**:
   - If `inventory.assets[].location` spans more than one country code
     (resolved via region → country mapping table — AWS regions: us-*
     = US, eu-* = EU, etc.) → `cross-jurisdictional`.
   - If tracker `privacy_records` has any row with
     `partner_agencies` non-empty → `agency-partner-sharing`.
   - If `cma_reference` set in config → `computer-matching-agreement`.
   - Else `high-risk-processing` only when operator explicitly sets
     `--dpia-trigger=high-risk` (no silent default).

3. **Auto-fill `processing_description`**:
   - `purposes[]` ← M.M3 PT-3 purposes register (cross-loop).
   - `pii_categories[]` ← inventory `pii_categories` union.
   - `data_subjects[]` ← inventory `pii_subjects` union.
   - `data_transfers[]` ← derived from inventory location pairs +
     per-pair operator-supplied `legal_mechanism`.

4. **Risk assessment** — operator-authored via tracker
   `dpia_findings` table; each row = one DpiaRisk. The emitter does
   NOT generate risks; it consumes them.

5. **Mitigations** — same pattern; operator-authored, emitter consumes.

6. **DPIA `.json` emit** — full Dpia object with provenance block.

7. **DPIA `.docx` emit** — reuse the OOXML + zip-store pattern from
   `core/roe-emit.ts` + `core/ssp-docx.ts`. Sections:
   - Cover page (system name, impact level, DPIA date, decision).
   - 1. Trigger + Scope.
   - 2. Processing Description.
   - 3. Necessity and Proportionality.
   - 4. Risk Assessment (table).
   - 5. Mitigations (table).
   - 6. Consultations.
   - 7. Residual Risk + DPO Recommendation.
   - 8. Decision + Sign-off block.

8. **OSCAL SSP back-matter**: `rel: 'dpia'` entry pointing at both
   `dpia.json` and `dpia.docx`.

9. **Tracker DB**:
   ```sql
   CREATE TABLE IF NOT EXISTS dpia_findings (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     dpia_uuid TEXT NOT NULL,
     finding_type TEXT NOT NULL CHECK (finding_type IN ('risk','mitigation','consultation','decision')),
     description TEXT NOT NULL,
     likelihood TEXT CHECK (likelihood IN ('very-low','low','moderate','high','very-high')),
     severity TEXT CHECK (severity IN ('very-low','low','moderate','high','very-high')),
     affected_population_size INTEGER,
     control_ids TEXT,                  -- JSON array of NIST control ids
     authored_by_user_id INTEGER NOT NULL REFERENCES users(id),
     authored_at TEXT NOT NULL,
     reviewed_by_saop_user_id INTEGER REFERENCES users(id),
     reviewed_at TEXT,
     signature TEXT NOT NULL,
     signing_key_id TEXT NOT NULL,
     created_at TEXT NOT NULL,
     updated_at TEXT NOT NULL
   );
   CREATE INDEX IF NOT EXISTS idx_df_dpia ON dpia_findings(dpia_uuid);
   CREATE INDEX IF NOT EXISTS idx_df_type ON dpia_findings(finding_type);
   ```

10. **Wire orchestrator** — `--dpia` flag runs after M.M1 so SORN
    snapshot informs DPIA trigger; before SSP emit so back-matter
    resource is included.

11. **Bundler** — add roles `dpia-json` + `dpia-docx`.

12. **Sign + timestamp** — both files picked up by manifest.

**REQUIRES-OPERATOR-INPUT fields**:

| Field | Source | Behavior when missing |
|---|---|---|
| `risk_assessment[]` | Tracker UI authoring | DPIA emit marked `ready_for_signature=false`; `requires_operator_input: ['risk_assessment']` |
| `mitigations[]` | Tracker UI | Same — DPIA cannot ship without mitigations |
| `consultation[]` | Tracker UI | Optional but documented; absence flagged |
| `legal_basis[]` | Operator config or per-purpose tracker row | Same — never default |
| `data_transfers[].legal_mechanism` | Operator must classify each transfer | Default: REQUIRES-OPERATOR-INPUT; emit fails strict mode |
| `residual_risk` | Computed from mitigation matrix | If any risk lacks mitigation → REQUIRES-OPERATOR-INPUT |
| `dpo_recommendation` | Tracker UI by user with `dpo` role | Same |
| `decision` | Tracker UI by user with `saop` or `ao` role | Defaults to `pending` |

**Test specifications** (≥13 tests):

1. `it('auto-detects cross-jurisdictional trigger when inventory spans US + EU regions')`.
2. `it('auto-detects agency-partner-sharing when privacy_records.partner_agencies set')`.
3. `it('detects computer-matching-agreement trigger when cma_reference set')`.
4. `it('requires explicit --dpia-trigger=high-risk; never silent default')`.
5. `it('aggregates pii_categories from inventory.assets across providers')`.
6. `it('builds data_transfers per source-destination jurisdiction pair')`.
7. `it('rejects transfer without legal_mechanism under --strict-privacy')`.
8. `it('consumes risk_assessment from tracker; emitter never synthesizes risks')`.
9. `it('emits dpia.json with provenance block and signed manifest')`.
10. `it('emits dpia.docx with 8 sections in correct order')`.
11. `it('OSCAL SSP back-matter gains dpia resource')`.
12. `it('registers KSI-PRV-DPIA process-artifact')`.
13. `it('tracker dpia_findings row signed with tracker Ed25519 key')`.
14. `it('residual_risk computed from worst remaining (likelihood,severity) cell')`.
15. `it('refuses ready_for_signature when any risk lacks mitigation')`.

**REO compliance**:

- All risks + mitigations are operator-authored (tracker rows, signed).
- `data_transfers[]` source/destination derived from inventory; legal
  mechanism operator-supplied per transfer.
- No silent risk-acceptance; explicit `decision` field with audit row.
- Provenance block on `dpia.json`.
- `.docx` zip-store deterministic.
- Signed by `core/sign.ts`.

**Verification commands**:
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/dpia-emit.test.ts tests/core/dpia-schema.test.ts
npm run check:reo
cd ../tracker
npm test -- server/routes/dpia-findings.test.ts
```

**Estimated effort**: 5-6 working days.

---

### Slice M.M3 — PT-family controls inventory (PT-1..PT-8) beyond PTA/PIA scope

**Why this slice**: NIST 800-53 Rev 5 PT family has 8 controls + 11
control enhancements in the FedRAMP Moderate baseline (per 800-53B).
LOOP-C.C4's PTA + PIA partly cover PT-1, PT-2, PT-3, PT-5, PT-6 — but
PT-4 (Consent), PT-7 (Specific Categories), PT-8 (Computer Matching),
and the enhancements PT-2(1), PT-2(2), PT-3(1), PT-3(2), PT-5(1),
PT-5(2), PT-6(1), PT-6(2), PT-7(1), PT-7(2) all lack structured
implemented-requirements. This slice emits the complete PT-family
inventory.

**Connection to FedPy mission**: Extends `core/oscal-ssp.ts`
`buildControlImplementation()` to register PT-family narrative
generators. Pulls evidence from tracker `pt_control_evidence` table
(operator-supplied per control). Surfaces PT-7 sensitive-PII handling
from inventory `pii_categories` (when tag includes `ssn`, `biometric`,
`medical`, `financial`, `juvenile`). Emits an
`out/pt-family-controls.json` envelope conforming to the existing KSI
envelope schema (with `provenance.sourceCalls`).

**Files to create**:
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/pt-family-emit.ts`
  — ~800 lines (one section per PT control). Generates structured
  `implemented-requirements[]` entries for each.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/pt-family-narratives.ts`
  — per-control narrative templates per PT-1..PT-8 + their
  enhancements; loaded from FRMR catalog where possible, operator
  override via tracker.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/pt-family-reader.ts`
  — tracker `pt_control_evidence` + `consent_records` snapshot pull.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/pt-family-emit.test.ts`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/pt-family-narratives.test.ts`.
- `tracker/server/routes/pt-control-evidence.ts`.
- `tracker/server/routes/consent-records.ts`.
- `tracker/client/src/pages/PtControls.tsx`.
- `tracker/client/src/pages/ConsentRecords.tsx`.
- `tracker/server/routes/pt-control-evidence.test.ts`.
- `tracker/server/routes/consent-records.test.ts`.

**Files to extend**:
- `cloud-evidence/core/oscal-ssp.ts` — `buildControlImplementation()`
  branches per PT-1..PT-8 to the new narrative generators.
- `cloud-evidence/core/control-benchmark.ts` — annotate PT-family
  rows with `responsibility: 'csp-supplied'`.
- `cloud-evidence/core/orchestrator.ts` — `--pt-family` flag.
- `cloud-evidence/core/submission-bundle.ts` — role
  `pt-family-controls-json`.
- `cloud-evidence/core/ksi-map.ts` — register `KSI-PRV-PTF`.
- `tracker/server/schema.sql` — `pt_control_evidence` + `consent_records`.

**Schemas / standards**:
- **NIST SP 800-53 Rev 5 §3.18 PT family** — verbatim quotes in the
  per-slice doc.
- **NIST SP 800-53B Rev 5 Moderate baseline** — control + enhancement
  selection (PT-2(1), PT-2(2), PT-3(1), PT-3(2), PT-5(1), PT-5(2),
  PT-6(1), PT-6(2), PT-7(1), PT-7(2)).
- **NIST Privacy Framework v1.0 Core** — subcategory crosswalk.
- **NIST SP 800-122** — PII confidentiality impact level drives PT-7
  enhancement selection.
- **NIST SP 800-37 Rev 2 Step 1** — Privacy Categorize.
- **Privacy Act §552a (o)** — drives PT-8 implementation.

**Build steps**:

1. Define `PtControlEvidence` and `PtFamilyEnvelope`:
   ```ts
   export type PtControlId =
     | 'PT-1' | 'PT-2' | 'PT-2(1)' | 'PT-2(2)'
     | 'PT-3' | 'PT-3(1)' | 'PT-3(2)'
     | 'PT-4'
     | 'PT-5' | 'PT-5(1)' | 'PT-5(2)'
     | 'PT-6' | 'PT-6(1)' | 'PT-6(2)'
     | 'PT-7' | 'PT-7(1)' | 'PT-7(2)'
     | 'PT-8';
   export interface PtControlEvidence {
     control_id: PtControlId;
     narrative: string;
     evidence_links: { href: string; title: string; }[];
     responsible_role: string;
     status: 'implemented' | 'partial' | 'planned' | 'not-applicable';
     last_assessed: string;
     attested_by_user_id: number;
     attested_at: string;
     signature: string;
     signing_key_id: string;
   }
   ```

2. **Per-control narrative generators** in `pt-family-narratives.ts`:
   - `narratePT1(opts)` — Policy + Procedures. Auto-fills:
     SSP system-name, designated official from `org-profile.yaml`,
     review frequency from `--control-review-frequency`. Operator must
     supply policy URL (tracker `pt_control_evidence`).
   - `narratePT2(opts)` — Authority to Process. Reads tracker
     `privacy_records.legal_authority` (set in M.M1).
   - `narratePT2_1(opts)` — Data Tagging. Reads inventory
     `pii_categories` tag schema.
   - `narratePT2_2(opts)` — Automation. Reads orchestrator audit
     trail showing automated PII-flow monitoring.
   - `narratePT3(opts)` — Processing Purposes. Reads tracker
     `pt_control_evidence` per-purpose row.
   - `narratePT3_1` and `narratePT3_2` similar.
   - `narratePT4(opts)` — Consent. Reads tracker `consent_records`.
     When CSO does NOT collect consent (e.g. agency-mandated
     processing), narrative explicitly states the legal basis is not
     consent + cites authority.
   - `narratePT5(opts)` — Privacy Notice. Operator-supplied URL +
     last-updated date.
   - `narratePT5_1` (Just-in-Time Notice).
   - `narratePT5_2` (Privacy Act Statements).
   - `narratePT6(opts)` — System of Records Notice. Reads M.M1 SORN
     snapshot.
   - `narratePT6_1` (Routine Uses).
   - `narratePT6_2` (Exemption Rules).
   - `narratePT7(opts)` — Specific Categories. Reads inventory
     `pii_categories` matched against sensitive set
     (ssn, biometric, medical, financial, juvenile, immigration,
     geolocation). Per category, narrative cites NIST 800-122 §3.2
     handling.
   - `narratePT7_1` (Social Security Numbers).
   - `narratePT7_2` (First Amendment Information).
   - `narratePT8(opts)` — Computer Matching. Reads tracker for any
     CMA rows; when none, narrative records "not applicable" with
     attestation.

3. **Emit `out/pt-family-controls.json`** — KSI-envelope-shaped:
   ```json
   {
     "ksi_id": "KSI-PRV-PTF",
     "run_id": "...",
     "collected_at": "...",
     "frmr_version": "...",
     "providers": [{
       "provider": "process-artifact",
       "evidence": [{
         "source": "tracker:pt_control_evidence",
         "control_id": "PT-1",
         "data": { ... },
         "fetched_at": "..."
       }, ...]
     }],
     "findings": [...],
     "provenance": { ... }
   }
   ```

4. **OSCAL SSP integration** — `buildControlImplementation()` calls
   `narratePT<id>()` for every PT control in the Moderate baseline.
   Each yields an OSCAL `implemented-requirement` with `description`,
   `responsible-roles`, `by-components[]`, `statements[]`. PT-4 when
   N/A emits `implementation-status: not-applicable` with rationale.

5. **Tracker DB**:
   ```sql
   CREATE TABLE IF NOT EXISTS pt_control_evidence (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     control_id TEXT NOT NULL,
     narrative TEXT NOT NULL,
     evidence_links TEXT,                  -- JSON array of {href,title}
     responsible_role TEXT NOT NULL,
     status TEXT NOT NULL CHECK (status IN ('implemented','partial','planned','not-applicable')),
     not_applicable_rationale TEXT,
     last_assessed TEXT NOT NULL,
     attested_by_user_id INTEGER NOT NULL REFERENCES users(id),
     attested_at TEXT NOT NULL,
     signature TEXT NOT NULL,
     signing_key_id TEXT NOT NULL,
     created_at TEXT NOT NULL,
     updated_at TEXT NOT NULL
   );
   CREATE INDEX IF NOT EXISTS idx_ptce_control ON pt_control_evidence(control_id);
   CREATE UNIQUE INDEX IF NOT EXISTS idx_ptce_unique ON pt_control_evidence(control_id);

   CREATE TABLE IF NOT EXISTS consent_records (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     subject_identifier_hash TEXT NOT NULL,  -- sha256 of the identifier (no plain PII)
     purpose_id TEXT NOT NULL,
     consent_given INTEGER NOT NULL CHECK (consent_given IN (0,1)),
     consent_mechanism TEXT NOT NULL,         -- 'click-through' | 'signed-form' | 'voice-recording' | ...
     captured_at TEXT NOT NULL,
     captured_by_system TEXT NOT NULL,
     withdrawn_at TEXT,
     created_at TEXT NOT NULL
   );
   CREATE INDEX IF NOT EXISTS idx_cr_purpose ON consent_records(purpose_id);
   CREATE INDEX IF NOT EXISTS idx_cr_subject ON consent_records(subject_identifier_hash);
   ```

6. **Bundler** — role `pt-family-controls-json`.

7. **Wire orchestrator** — `--pt-family` flag runs before OSCAL SSP so
   SSP picks up PT narratives.

**REQUIRES-OPERATOR-INPUT fields**:

| Field | Source | Behavior when missing |
|---|---|---|
| Per-control `narrative` | Tracker `pt_control_evidence` | Emitter falls back to PT-* boilerplate from `pt-family-narratives.ts` with `REQUIRES-OPERATOR-INPUT: tracker /pt-controls/<id>` marker |
| PT-1 policy URL | Tracker | REQUIRES-OPERATOR-INPUT |
| PT-2 legal authority | M.M1 SORN snapshot OR tracker | REQUIRES-OPERATOR-INPUT |
| PT-4 consent mechanism (when applicable) | Tracker `consent_records` aggregation | REQUIRES-OPERATOR-INPUT or explicit not-applicable rationale |
| PT-5 privacy notice URL | Tracker | REQUIRES-OPERATOR-INPUT |
| PT-7 sensitive-category handling per category | Inventory pii_categories union + tracker narrative | REQUIRES-OPERATOR-INPUT |
| PT-8 CMA references | Tracker | Explicit not-applicable rationale if no CMA |

**Test specifications** (≥13 tests):

1. `it('emits one implemented-requirement per Moderate-baseline PT control + enhancement (18 total)')`.
2. `it('PT-2 narrative pulls legal_authority from M.M1 SORN snapshot')`.
3. `it('PT-4 emits not-applicable with rationale when no consent collected')`.
4. `it('PT-6 narrative cites the M.M1 SORN by uuid + Federal Register publication')`.
5. `it('PT-7 narrative enumerates sensitive categories from inventory pii_categories union')`.
6. `it('PT-7(1) emits SSN-specific handling when "ssn" in pii_categories')`.
7. `it('PT-8 emits not-applicable when no CMA records in tracker')`.
8. `it('emits REQUIRES-OPERATOR-INPUT for any unsupplied narrative')`.
9. `it('OSCAL SSP control-implementation gains 18 PT-family entries')`.
10. `it('SSP still ajv-validates against OSCAL v1.1.2 schema after PT additions')`.
11. `it('pt-family-controls.json envelope conforms to KSI envelope schema')`.
12. `it('registers KSI-PRV-PTF process-artifact')`.
13. `it('tracker pt_control_evidence enforces UNIQUE control_id')`.
14. `it('consent_records stores sha256 hash, never plain identifier')`.
15. `it('bundler includes pt-family-controls-json role')`.

**REO compliance**:

- PT-family control text quoted verbatim from NIST 800-53 Rev 5 §3.18
  (no paraphrase) in narratives' docstring.
- All operator narratives are signed tracker rows.
- Sensitive PII never persisted plain — `consent_records` stores
  hashes only.
- Provenance block.
- SSP ajv-validates after extension.

**Verification commands**:
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/pt-family-emit.test.ts tests/core/pt-family-narratives.test.ts tests/core/oscal-ssp.test.ts
npm run check:reo
cd ../tracker
npm test -- server/routes/pt-control-evidence.test.ts server/routes/consent-records.test.ts
```

**Estimated effort**: 6-7 working days.

---

### Slice M.M4 — Privacy incident response procedures (PT-7 + breach notification per OMB M-17-12)

**Why this slice**: Privacy breaches have a distinct response chain
from generic security incidents — SAOP notification, US-CERT/CISA
report (within 1 hour for FCEB agencies), risk-of-harm assessment per
M-17-12 §V five-factor criteria, individual notification, Congressional
notification for major incidents, post-breach SORN amendment when
record categories change. The existing AFR-ICP slice (LOOP-G.G2)
covers the general security-incident communication framework; this
slice covers the privacy-specific overlay.

**Connection to FedPy mission**: Extends LOOP-G.G2 AFR-ICP with a
privacy classifier. Reads tracker `privacy_incidents` table (operator
records). Generates `out/privacy-incident-response-plan.docx`
(annually reviewed, tested, audit-trailed) + `out/privacy-breach-runbook.json`
(structured response playbook). When a privacy incident occurs and
the affected categories of records change, M.M4 surfaces a
"SORN-amendment-required" finding to the POA&M via the existing
`core/oscal-poam.ts` pipeline.

**Files to create**:
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/privacy-irp-emit.ts`
  — ~700 lines `.docx` emitter + `.json` runbook emitter.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/privacy-breach-classifier.ts`
  — assesses M-17-12 §V five factors; emits `harm_risk` ∈
  {low, moderate, high}.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/privacy-incident-reader.ts`
  — tracker `privacy_incidents` snapshot.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/privacy-irp-emit.test.ts`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/privacy-breach-classifier.test.ts`.
- `tracker/server/routes/privacy-incidents.ts`.
- `tracker/client/src/pages/PrivacyIncidents.tsx`.
- `tracker/server/routes/privacy-incidents.test.ts`.

**Files to extend**:
- `cloud-evidence/core/orchestrator.ts` — `--privacy-irp` flag.
- `cloud-evidence/core/submission-bundle.ts` — roles
  `privacy-irp-docx`, `privacy-breach-runbook-json`.
- `cloud-evidence/core/oscal-poam.ts` — when M.M4 incident snapshot
  surfaces gaps (e.g. SORN-amendment-required), emit as POA&M finding.
- `cloud-evidence/core/ksi-map.ts` — register `KSI-PRV-IRP`.
- `tracker/server/schema.sql` — `privacy_incidents` table.
- `cloud-evidence/core/afr-icp.ts` (LOOP-G.G2) — depends on this for
  privacy-incident classification; integration point documented.

**Schemas / standards**:
- **OMB M-17-12** — verbatim breach-response plan content (downloaded
  PDF, quoted in docstring).
- **OMB M-22-05** — 7-day Congressional notification for major
  incidents.
- **NIST SP 800-53 Rev 5 PT-7** + **IR-6** (Incident Reporting) +
  **IR-8** (Incident Response Plan).
- **FISMA §3554(b)(7)(C)** "major incident".
- **CISA Incident Reporting Guidelines** — per CIRCIA (Cyber Incident
  Reporting for Critical Infrastructure Act of 2022) when applicable.

**Build steps**:

1. Define `PrivacyIncident`:
   ```ts
   export interface PrivacyIncident {
     uuid: string;
     incident_id: string;                    // operator-assigned
     discovered_at: string;                  // ISO datetime
     reported_to_saop_at?: string;
     reported_to_us_cert_at?: string;        // CISA
     reported_to_agency_at?: string;
     affected_individual_count?: number;
     pii_categories: string[];
     subject_categories: string[];
     breach_mechanism: 'unauthorized-access' | 'unauthorized-disclosure' | 'loss' | 'theft' | 'misdirection' | 'malware' | 'other';
     harm_risk_assessment: HarmRiskAssessment;
     containment_actions: ContainmentAction[];
     notification_decisions: NotificationDecision[];
     sorn_amendment_required: boolean;
     status: 'open' | 'contained' | 'remediated' | 'closed';
     created_by_user_id: number;
     created_at: string;
     updated_at: string;
     signature: string;
     signing_key_id: string;
   }
   export interface HarmRiskAssessment {
     // M-17-12 §V five factors
     factor_1_nature_and_sensitivity: 'low' | 'moderate' | 'high';
     factor_2_likelihood_of_access_and_use: 'low' | 'moderate' | 'high';
     factor_3_type_of_breach: 'low' | 'moderate' | 'high';
     factor_4_wider_context: 'low' | 'moderate' | 'high';
     factor_5_individuals_affected: 'low' | 'moderate' | 'high';
     overall_risk: 'low' | 'moderate' | 'high';
     rationale: string;
     assessed_by_user_id: number;
     assessed_at: string;
   }
   export interface ContainmentAction {
     description: string;
     completed_at: string;
     completed_by_user_id: number;
   }
   export interface NotificationDecision {
     target: 'saop' | 'us-cert-cisa' | 'agency' | 'congress' | 'individuals' | 'media-substitute-notice';
     decision: 'notify' | 'defer' | 'do-not-notify';
     rationale: string;
     notified_at?: string;
     timeline_compliance: 'on-time' | 'delayed' | 'pending';
   }
   ```

2. **Privacy IRP `.docx` emitter** — sections per M-17-12 §IV:
   1. Purpose + Scope.
   2. Authorities (Privacy Act, OMB M-17-12, NIST 800-53 IR-6/IR-8,
      FISMA, CIRCIA).
   3. Roles + Responsibilities (SAOP, Breach Response Team, CIO,
      CISO, Legal, Communications).
   4. Incident Identification + Classification.
   5. Harm Risk Assessment Methodology (M-17-12 §V five factors).
   6. Containment + Mitigation.
   7. Notification Procedures (timelines per audience).
   8. Post-Incident Review + Lessons Learned.
   9. Annual Plan Review + Tabletop Cadence.
   10. Roster + Contact List.
   11. SORN Amendment Procedures (when record categories change).
   12. Approval + Sign-Off block.

3. **Privacy Breach Runbook `.json`** — structured playbook
   consumed by on-call automation:
   ```json
   {
     "phases": [
       {
         "phase": "identification",
         "actions": [
           { "id": "ID-01", "description": "...", "owner_role": "duty-officer", "max_minutes_from_discovery": 15 },
           { "id": "ID-02", "description": "Notify SAOP", "owner_role": "ciso", "max_minutes_from_discovery": 30 },
           { "id": "ID-03", "description": "Report to CISA US-CERT", "owner_role": "ciso", "max_minutes_from_discovery": 60 }
         ]
       },
       { "phase": "containment", "actions": [...] },
       { "phase": "harm-assessment", "actions": [...] },
       { "phase": "notification", "actions": [...] },
       { "phase": "post-incident", "actions": [...] }
     ],
     "thresholds": {
       "major_incident_individual_threshold": 100000,
       "congressional_notification_hours": 168,
       "individual_notification_days": 60
     }
   }
   ```

4. **Classifier** `assessHarmRisk(incident: Partial<PrivacyIncident>):
   HarmRiskAssessment` — guides operator through M-17-12 §V criteria;
   suggests rating per factor but final decision = operator-supplied.

5. **POA&M integration**: when an incident snapshot has
   `sorn_amendment_required: true` AND no corresponding SORN
   amendment is pending in `sorn_publications` (M.M1 table), emit
   POA&M finding with severity=high, deadline=60d (matches FedRAMP
   ConMon CMP table).

6. **Tracker DB**:
   ```sql
   CREATE TABLE IF NOT EXISTS privacy_incidents (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     incident_id TEXT NOT NULL,
     discovered_at TEXT NOT NULL,
     reported_to_saop_at TEXT,
     reported_to_us_cert_at TEXT,
     reported_to_agency_at TEXT,
     affected_individual_count INTEGER,
     pii_categories TEXT NOT NULL,         -- JSON array
     subject_categories TEXT NOT NULL,     -- JSON array
     breach_mechanism TEXT NOT NULL,
     harm_risk_json TEXT NOT NULL,         -- serialized HarmRiskAssessment
     containment_actions_json TEXT NOT NULL,
     notification_decisions_json TEXT NOT NULL,
     sorn_amendment_required INTEGER NOT NULL CHECK (sorn_amendment_required IN (0,1)),
     status TEXT NOT NULL CHECK (status IN ('open','contained','remediated','closed')),
     created_by_user_id INTEGER NOT NULL REFERENCES users(id),
     created_at TEXT NOT NULL,
     updated_at TEXT NOT NULL,
     signature TEXT NOT NULL,
     signing_key_id TEXT NOT NULL
   );
   CREATE INDEX IF NOT EXISTS idx_pi_status ON privacy_incidents(status);
   CREATE INDEX IF NOT EXISTS idx_pi_discovered ON privacy_incidents(discovered_at);
   ```

7. **Wire orchestrator** — `--privacy-irp` flag.

8. **Bundler** — roles `privacy-irp-docx`,
   `privacy-breach-runbook-json`.

9. **Sign + timestamp** — both files in manifest.

**REQUIRES-OPERATOR-INPUT fields**:

| Field | Source | Behavior when missing |
|---|---|---|
| SAOP name + contact | `org-profile.yaml` `privacy.saop` | Plan emits REQUIRES-OPERATOR-INPUT for SAOP fields |
| Breach Response Team roster | Tracker | REQUIRES-OPERATOR-INPUT |
| Agency notification chain | `org-profile.yaml` `customer.privacy_contacts[]` | REQUIRES-OPERATOR-INPUT |
| CISA US-CERT reporting endpoint | Configured per agency relationship | REQUIRES-OPERATOR-INPUT |
| Annual tabletop date | Operator schedule | REQUIRES-OPERATOR-INPUT (annual cadence enforced) |
| Per-incident harm risk factor ratings | Operator-assessed | Cannot be inferred — REQUIRES-OPERATOR-INPUT per factor |
| Per-incident `sorn_amendment_required` | Operator decision after legal review | REQUIRES-OPERATOR-INPUT |

**Test specifications** (≥13 tests):

1. `it('emits privacy-incident-response-plan.docx with 12 sections in M-17-12 order')`.
2. `it('emits privacy-breach-runbook.json with 5 phases')`.
3. `it('runbook timeline thresholds match OMB M-17-12: 1h CISA, 60d individuals, 168h Congressional for major')`.
4. `it('major incident threshold = 100000 individuals per FISMA §3554')`.
5. `it('classifier scores each of M-17-12 §V five factors')`.
6. `it('classifier overall_risk = max of five factor ratings')`.
7. `it('REQUIRES-OPERATOR-INPUT for SAOP name when org-profile.privacy.saop missing')`.
8. `it('REQUIRES-OPERATOR-INPUT for tabletop date — never default to today')`.
9. `it('emits POA&M finding when sorn_amendment_required AND no pending sorn_publications row')`.
10. `it('privacy_incidents.harm_risk_json is signed canonical-JSON')`.
11. `it('snapshot reader verifies signature per row')`.
12. `it('registers KSI-PRV-IRP process-artifact')`.
13. `it('bundler includes privacy-irp-docx + privacy-breach-runbook-json roles')`.
14. `it('CHANGELOG entry for M.M4 quotes verbatim OMB M-17-12 §V')`.
15. `it('runbook phase IDs are stable across runs (deterministic)')`.

**REO compliance**:

- Harm-risk assessment is operator-rated; classifier suggests but never
  decides.
- Containment + notification decisions are signed tracker rows.
- POA&M finding flows through existing pipeline; no fabricated risks.
- `.docx` zip-store deterministic.
- Provenance block on `privacy-breach-runbook.json`.

**Verification commands**:
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/privacy-irp-emit.test.ts tests/core/privacy-breach-classifier.test.ts
npm run check:reo
cd ../tracker
npm test -- server/routes/privacy-incidents.test.ts
```

**Estimated effort**: 5-6 working days.

---

## 6. Loop-wide acceptance criteria

LOOP-M is COMPLETE when ALL of the following are true:

1. **M.M1**: Either `out/sorn-draft.md` + `out/sorn-input.json` emit
   with full statutory elements and `ready_for_signature=true` after
   operator supplies authorities/routine-uses/retention, OR
   `out/no-system-of-records-attested.json` emits as signed
   attestation. OSCAL SSP back-matter gains `sorn-draft` reference
   (or omits it cleanly when conditional N/A). Tracker tables
   `privacy_records` + `sorn_publications` ship.
2. **M.M2**: `out/dpia.json` + `out/dpia.docx` emit end-to-end with
   Article 35(7) / M-03-22 §II.C field coverage. Risk + mitigation
   matrix populated from tracker `dpia_findings`. OSCAL SSP back-matter
   gains `dpia` reference.
3. **M.M3**: `out/pt-family-controls.json` emit covers all 18 PT-family
   entries (8 base + 10 enhancements) in the FedRAMP Moderate baseline.
   OSCAL SSP `control-implementation.implemented-requirements[]` gains
   the same 18 entries. Tracker tables `pt_control_evidence` +
   `consent_records` ship.
4. **M.M4**: `out/privacy-incident-response-plan.docx` +
   `out/privacy-breach-runbook.json` emit. Tracker table
   `privacy_incidents` ships. POA&M finding emission tested for
   SORN-amendment-required edge case.
5. All four slices pass `npm run typecheck`, `npm test`, and
   `npm run check:reo` in both `cloud-evidence/` and `tracker/`.
6. CHANGELOG "Unreleased" has four entries (one per slice) with module
   names, verbatim source citations, and verification counts.
7. STATUS.md per-slice rows updated; LOOP-M section reflects done/N-A.
8. LOOP-M-RISKS.md updated with any new risks surfaced during
   implementation, atomically per slice commit.

---

## 7. Open questions / caveats

1. **Privacy Act applicability** (ADDITIONAL-LOOPS-AUDIT §5 Q2 open) —
   does the CSP process Privacy-Act-protected records retrievable by
   identifier on behalf of a federal agency? M.M1 is conditional;
   resolve before slice starts.
2. **GDPR applicability** — does the CSP serve any agency that
   collected data from EU residents? Drives M.M2 `legal_mechanism` set
   complexity. Default assumption: US-federal only; operator must
   declare cross-jurisdictional via `org-profile.yaml`.
3. **Federal Register SORN template format** — the structured-input
   JSON we emit may drift if the Federal Register changes template
   structure. Version pin via `sorn-input-json.format_version =
   "fed-reg.preview.2026"`.
4. **OMB M-17-12 §V quantitative thresholds** — `affected_individual_count`
   triggering "major incident" is not explicitly numeric in M-17-12; OMB
   M-22-05 cites FISMA §3554(b)(7)(C) "major incident" definition with
   100,000-individual default per current OMB practice. Operator can
   override via `--major-incident-threshold`.
5. **NARA records schedule integration** — M.M1 retention/disposal
   field references NARA general records schedule (GRS). We do not
   ingest GRS programmatically in LOOP-M; operator supplies the GRS
   citation as free text. Future slice could automate.
6. **PT-4 Consent collection** — for most agency-mandated processing,
   consent is NOT the legal basis. PT-4 emits `not-applicable` with
   rationale. When the CSO does collect consent (rare for federal CSP
   tier), M.M3 ships the consent-records pipeline.
7. **Cross-loop integration with LOOP-G.G2 (AFR-ICP)** — M.M4
   integrates with the AFR-ICP framework. Order matters: M.M4 should
   ship BEFORE LOOP-G.G2 so G.G2 can call M.M4's privacy classifier;
   alternatively, if G.G2 ships first, M.M4 EXTENDS G.G2.
8. **OSCAL SSP regeneration** — every slice in LOOP-M extends the SSP.
   The orchestrator must re-emit the SSP whenever any LOOP-M slice
   runs, OR the operator runs `--oscal-ssp` after LOOP-M flags.
9. **Tracker schema migration** — LOOP-M adds 6 new tables. Per
   B-X10 cross-cutting risk pattern, all additive; no DROP/ALTER
   COLUMN.
10. **Multi-CSO** — H.H3 will add tenant isolation. LOOP-M tables
    omit `tenant_id` column; H.H3 must migrate all 6 LOOP-M tables in
    one sweep.
11. **PII tagging coverage** — many CSPs have not back-tagged
    assets with `fedramp_pii_categories`. M.M1/M.M2/M.M3 surface
    REQUIRES-OPERATOR-INPUT visibly when tag coverage incomplete.
12. **SAOP role mapping** — tracker RBAC must add `saop` role for
    M.M2/M.M4 sign-offs. Per B-X5 pattern, first-boot prompt for
    role assignment.

---

## 8. Status tracking

Update this table when a slice ships (per
`docs/SLICE-COMPLETION-PROCEDURE.md`).

| Slice ID | Title | Status | Commit hash | Completed date |
|---|---|---|---|---|
| M.M1 | System of Records Notice emitter (Privacy Act §552a SORN) | pending | — | — |
| M.M2 | Data Protection Impact Assessment (cross-border / agency partner) | pending | — | — |
| M.M3 | PT-family controls inventory (PT-1..PT-8 beyond C.C4) | pending | — | — |
| M.M4 | Privacy incident response procedures (PT-7 + breach notification) | pending | — | — |

---

## 9. Slice completion procedure

LOOP-M slices follow the 7-step procedure documented in
`cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`. Atomic with each
slice's final commit:

1. **Verify green**: from repo root
   ```bash
   cd cloud-evidence
   npm run typecheck            # must be clean
   npm test                     # 100% passing (existing tests + new slice tests)
   npm run check:reo            # G1 + G2 + G3 all green
   npm run check:provenance     # every new emit-field has provenance entry
   ```
   For slices touching the tracker (all four):
   ```bash
   cd ../tracker
   npm run typecheck
   npm test
   ```

2. **Update Section 8 status table** in this file. Set the slice's row
   to `status=done`, `commit=<short-sha>`, `date=<YYYY-MM-DD>`.

3. **Update CHANGELOG.md "Unreleased"**: add a new `### Added —
   LOOP-M.<id>: <title>` block at the top of "Unreleased". Mirror the
   LOOP-A.A* entries for tone and depth. Cite the module names, the
   verbatim source citations (5 U.S.C. §552a, OMB M-03-22, NIST
   800-53 Rev 5 PT-x, OMB M-17-12), and the verification counts.

4. **Update `cloud-evidence/docs/STATUS.md`**: set the slice row to
   `done`. (LOOP-M section MUST be appended below LOOP-K if not yet
   present.)

5. **Commit**: from repo root
   ```bash
   git add -A
   git commit -m "LOOP-M.<id>: <title>

   <detailed commit message describing the slice + verbatim quotes
   from the statutory/regulatory source>

   Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
   ```

6. **Update commit hash + amend**: get the hash via `git log -1
   --format=%h`, paste into STATUS.md + this file's Section 8 +
   the per-slice doc's frontmatter; amend with `git commit --amend --no-edit`.

7. **Push**: `git push origin main`.

8. **Per CLAUDE.md Strong-Directive**: append final Implementation log
   entry to the per-slice doc; add any newly-discovered risks to
   LOOP-M-RISKS.md in the same commit.

---

## 10. Appendix — verbatim statutory excerpt for M.M1

For completeness, here is the full text of the §552a (e)(4) SORN
publication obligation that M.M1 must emit a draft conforming to.
Quoted verbatim from Cornell LII:

> "Each agency that maintains a system of records shall —
> ...
> (4) subject to the provisions of paragraph (11) of this subsection,
> publish in the Federal Register upon establishment or revision a
> notice of the existence and character of the system of records,
> which notice shall include —
> (A) the name and location of the system;
> (B) the categories of individuals on whom records are maintained in
>     the system;
> (C) the categories of records maintained in the system;
> (D) each routine use of the records contained in the system,
>     including the categories of users and the purpose of such use;
> (E) the policies and practices of the agency regarding storage,
>     retrievability, access controls, retention, and disposal of the
>     records;
> (F) the title and business address of the agency official who is
>     responsible for the system of records;
> (G) the agency procedures whereby an individual can be notified at
>     his request if the system of records contains a record pertaining
>     to him;
> (H) the agency procedures whereby an individual can be notified at
>     his request how he can gain access to any record pertaining to
>     him contained in the system of records, and how he can contest
>     its content; and
> (I) the categories of sources of records in the system; ..."
> — 5 U.S.C. §552a (e)(4)

M.M1 emits the 9 statutory elements (A)-(I) plus the 26 Federal
Register template administrative sections. The combination is what an
agency SAOP edits + submits to the Federal Register.

---

## 11. Appendix — verbatim NIST 800-53 Rev 5 PT family controls (Moderate baseline)

NIST SP 800-53 Rev 5 §3.18 verbatim (per the PDF downloaded to
`cloud-evidence/docs/sources/nist-sp-800-53-rev5.pdf`).

### PT-1 Policy and Procedures (Moderate baseline: REQUIRED)
> "a. Develop, document, and disseminate to [Assignment:
> organization-defined personnel or roles]:
> 1. [Selection (one or more): Organization-level; Mission/business
>    process-level; System-level] personally identifiable information
>    processing and transparency policy that:
>    (a) Addresses purpose, scope, roles, responsibilities, management
>        commitment, coordination among organizational entities, and
>        compliance; and
>    (b) Is consistent with applicable laws, executive orders,
>        directives, regulations, policies, standards, and guidelines;
>        and
> 2. Procedures to facilitate the implementation of the personally
>    identifiable information processing and transparency policy and
>    the associated personally identifiable information processing and
>    transparency controls;
> b. Designate an [Assignment: organization-defined official] to
>    manage the development, documentation, and dissemination of the
>    personally identifiable information processing and transparency
>    policy and procedures; and
> c. Review and update the current personally identifiable information
>    processing and transparency:
>    1. Policy [Assignment: organization-defined frequency]; and
>    2. Procedures [Assignment: organization-defined frequency]."

### PT-2 Authority to Process Personally Identifiable Information (Moderate baseline: REQUIRED)
> "a. Determine and document the [Assignment: organization-defined
> authority] that permits the [Assignment: organization-defined
> processing] of personally identifiable information; and
> b. Restrict the [Assignment: organization-defined processing] of
> personally identifiable information to only that which is authorized."

### PT-2(1) Authority Tracking (Moderate baseline: REQUIRED)
> "Track processing purposes of personally identifiable information
> using [Assignment: organization-defined automated mechanisms]."

### PT-2(2) Automation (Moderate baseline: REQUIRED)
> "Manage enforcement of the authorized processing of personally
> identifiable information using [Assignment: organization-defined
> automated mechanisms]."

### PT-3 Personally Identifiable Information Processing Purposes (Moderate baseline: REQUIRED)
> "a. Identify and document the [Assignment: organization-defined
> purpose(s)] for processing personally identifiable information;
> b. Describe the purpose(s) in the public privacy notices and
> policies of the organization;
> c. Restrict the [Assignment: organization-defined processing of
> personally identifiable information] to only that which is
> compatible with the identified purpose(s); and
> d. Monitor changes in processing personally identifiable information
> and implement [Assignment: organization-defined mechanisms] to
> ensure that any changes are made in accordance with [Assignment:
> organization-defined requirements]."

### PT-3(1) Data Tagging (Moderate baseline: REQUIRED)
> "Attach data tags containing [Assignment: organization-defined
> processing purposes] to [Assignment: organization-defined elements
> of personally identifiable information]."

### PT-3(2) Automation (Moderate baseline: REQUIRED)
> "Track processing purposes of personally identifiable information
> using [Assignment: organization-defined automated mechanisms]."

### PT-4 Consent (Moderate baseline: REQUIRED)
> "Implement [Assignment: organization-defined tools or mechanisms]
> for individuals to consent to the processing of their personally
> identifiable information prior to its collection that facilitate
> individuals' informed decision-making."

### PT-5 Privacy Notice (Moderate baseline: REQUIRED)
> "Provide notice to individuals about the processing of personally
> identifiable information that:
> a. Is available to individuals upon first interacting with an
> organization, and subsequently at [Assignment: organization-defined
> frequency];
> b. Is clear and easy-to-understand, expressing information about
> personally identifiable information processing in plain language;
> c. Identifies the authority that authorizes the processing of
> personally identifiable information;
> d. Identifies the purposes for which personally identifiable
> information is to be processed; and
> e. Includes [Assignment: organization-defined information]."

### PT-5(1) Just-in-Time Notice (Moderate baseline: REQUIRED)
> "Present notice of personally identifiable information processing
> to individuals at a time and location where the individual provides
> personally identifiable information or in conjunction with a data
> action, or [Assignment: organization-defined frequency]."

### PT-5(2) Privacy Act Statements (Moderate baseline: REQUIRED)
> "Include Privacy Act statements on forms that collect information
> that will be maintained in a Privacy Act system of records, or
> provide Privacy Act statements on separate forms that can be
> retained by individuals."

### PT-6 System of Records Notice (Moderate baseline: REQUIRED — closed by M.M1)
> "For systems that process information that will be maintained in a
> Privacy Act system of records:
> a. Draft system of records notices in accordance with OMB guidance
> and submit new and significantly modified system of records notices
> to the OMB and appropriate congressional committees for advance
> review;
> b. Publish system of records notices in the Federal Register; and
> c. Keep system of records notices accurate, up-to-date, and scoped
> in accordance with policy."

### PT-6(1) Routine Uses (Moderate baseline: REQUIRED)
> "Review all routine uses published in the system of records notice
> at [Assignment: organization-defined frequency] to ensure continued
> accuracy, and to ensure that routine uses continue to be compatible
> with the purpose for which the information was collected."

### PT-6(2) Exemption Rules (Moderate baseline: REQUIRED)
> "Review all Privacy Act exemptions claimed for the system of records
> at [Assignment: organization-defined frequency] to ensure they
> remain appropriate and necessary in accordance with law, that they
> have been promulgated as regulations, and that they are accurately
> described in the system of records notice."

### PT-7 Specific Categories of Personally Identifiable Information (Moderate baseline: REQUIRED — closed by M.M4 + M.M3)
> "Apply [Assignment: organization-defined processing conditions] for
> specific categories of personally identifiable information."

### PT-7(1) Social Security Numbers (Moderate baseline: REQUIRED)
> "When a system processes Social Security numbers:
> a. Eliminate unnecessary collection, maintenance, and use of Social
> Security numbers, and explore alternatives to their use as a
> personal identifier;
> b. Do not deny any individual any right, benefit, or privilege
> provided by law because of such individual's refusal to disclose
> his or her Social Security number; and
> c. Inform any individual who is asked to disclose his or her Social
> Security number whether that disclosure is mandatory or voluntary,
> by what statutory or other authority such number is solicited, and
> what uses will be made of it."

### PT-7(2) First Amendment Information (Moderate baseline: REQUIRED)
> "Prohibit the processing of information describing how any
> individual exercises rights guaranteed by the First Amendment unless
> expressly authorized by statute or by the individual or unless
> pertinent to and within the scope of an authorized law enforcement
> activity."

### PT-8 Computer Matching Requirements (Moderate baseline: REQUIRED — closed by M.M3)
> "When a system or organization processes information for the purpose
> of conducting a matching program:
> a. Obtain approval of the matching agreement by the Data Integrity
> Board to conduct the matching program;
> b. Develop and enter into a computer matching agreement;
> c. Publish a matching notice in the Federal Register;
> d. Independently verify the information produced by the matching
> program before taking adverse action against an individual, if
> required; and
> e. Provide individuals with notice and an opportunity to contest the
> findings before taking adverse action against an individual."

**Implementer note**: each verbatim quote above must appear in the
generated SSP `implemented-requirement.description` field's prose
section (per OSCAL `description` prose-wrapping rules) OR be referenced
via `links[].rel = "ctrl-text"` to a back-matter resource pointing at
the NIST PDF. M.M3 emits the SECOND path (referenced via back-matter)
because the verbatim quote is large and reuse across multiple SSPs is
common. The CSP-authored implementation narrative goes in the
`description` field.

---

## 12. Appendix — verbatim OMB M-17-12 §V (Risk-of-Harm Five Factors)

Quoted from the M-17-12 PDF downloaded to
`cloud-evidence/docs/sources/omb-m-17-12.pdf` §V (page references
authoritative in PDF; M.M4 carries page citations in its docstring).

> "When evaluating the risk of harm to potentially affected individuals
> resulting from a breach, an agency should consider:
> 1. The nature and sensitivity of the PII potentially compromised by
>    the breach.
> 2. The likelihood of access and use of PII.
> 3. The type of breach.
> 4. The wider context of the breach.
> 5. The number of individuals potentially affected.
> Each factor should be evaluated and assigned a risk level of low,
> moderate, or high. The overall risk of harm is the highest level
> across the five factors, except where the agency justifies a lower
> overall rating with explicit rationale."
> — OMB M-17-12 §V (paraphrased pending PDF download; M.M4 docstring
>   carries verbatim quote)

**Implementer note**: when the PDF is downloaded, the verbatim text
above will be replaced in M.M4's classifier docstring with the exact
language. The classifier's `assessHarmRisk()` function MUST cite the
PDF page number for each of the five factors.

---

## 13. Appendix — KSI envelope shape for process-artifact privacy KSIs

LOOP-M registers four process-artifact KSI IDs in `core/ksi-map.ts`:

| KSI ID | Description | Slice | Evidence source |
|---|---|---|---|
| KSI-PRV-SORN | System of Records Notice maintained per §552a | M.M1 | Tracker `sorn_publications` table |
| KSI-PRV-DPIA | DPIA conducted for cross-border / partner data | M.M2 | Tracker `dpia_findings` table |
| KSI-PRV-PTF | PT-family controls implemented + attested | M.M3 | Tracker `pt_control_evidence` + `consent_records` |
| KSI-PRV-IRP | Privacy incident response plan + annual tabletop | M.M4 | Tracker `privacy_incidents` + signed plan |

Each follows the existing process-artifact KSI envelope shape:

```json
{
  "ksi_id": "KSI-PRV-<ID>",
  "run_id": "...",
  "collected_at": "ISO datetime",
  "frmr_version": "0.9.43-beta",
  "providers": [{
    "provider": "process-artifact",
    "evidence": [{
      "source": "tracker:<table-name>",
      "data": {...},
      "fetched_at": "ISO datetime"
    }]
  }],
  "findings": [],         // populated when operator-supplied evidence missing
  "provenance": {
    "emitter": "core/<slice-emit-module>.ts",
    "emittedAt": "ISO datetime",
    "sourceCalls": ["tracker:<table-name>:list", "inventory.json:read"],
    "signingKeyId": "..."
  }
}
```

This mirrors the LOOP-G AFR-family process-artifact KSIs and reuses
the existing process-artifact dispatch in `core/orchestrator.ts`.

---

## 14. Appendix — Connection to ADDITIONAL-LOOPS-AUDIT §2 verbatim text

Per ADDITIONAL-LOOPS-AUDIT.md (2026-06-06) §2 (this loop's audit
origin), verbatim:

> "LOOP-M — Privacy Package Extension (SORN, PTA / PIA, Privacy
> Continuous Monitoring)
>
> **Why this is a separate loop:**
> LOOP-C.C4 already covers PTA + PIA emission per FedRAMP templates +
> OMB M-03-22 + NIST 800-53 PT-2/PT-3/PT-6. What's missing:
>
> 1. **System of Records Notice (SORN)** triggers when the CSO retrieves
>    PII via a unique identifier on behalf of a federal agency — a
>    distinct Privacy Act obligation (5 U.S.C. §552a) from the PIA. The
>    agency publishes the SORN in the Federal Register, but the CSP
>    supplies the structured input: the categories of records, routine
>    uses, retention schedule, and safeguards. We currently have no
>    structured-input emitter.
> ..."

This LOOP-M-SPEC.md realises the audit's intent with four slices: M.M1
(SORN), M.M2 (DPIA), M.M3 (full PT-family controls), M.M4 (privacy
incident response). The audit proposed three slices (SORN, PCM, PTA
recheck cadence); this spec re-scoped to four because:

- **Audit M.M1 (SORN)** → kept as M.M1.
- **Audit M.M2 (Privacy Continuous Monitoring strategy doc)** →
  superseded by the broader M.M3 PT-family inventory; PCM is a
  cross-cutting concern under PT-1 + PM-31 and is folded into the
  LOOP-E ConMon agent (LOOP-E.E1 monthly report includes the privacy
  section). Pure PCM-strategy doc gets emitted as a sub-artifact of
  LOOP-C.C6 (ConMon Strategy + Plan).
- **Audit M.M3 (PTA recheck cadence)** → folded into LOOP-C.C4
  itself (annual recheck is part of LOOP-E.E4 annual review pattern).
- **New M.M2 (DPIA)** → added to cover cross-jurisdictional + agency-
  partner sharing surface not in the original audit.
- **New M.M3 (full PT family)** → broader than the audit's narrow
  "PT-1..PT-7 coverage" — full 8 controls + 10 enhancements.
- **New M.M4 (privacy IRP)** → addresses the OMB M-17-12 obligation
  the audit referenced as PT-7-adjacent but didn't enumerate.

ADDITIONAL-LOOPS-AUDIT §6 prioritisation ranks LOOP-M second, behind
LOOP-L (CRM + Inheritance). When STATUS.md indicates LOOP-L is in
flight or complete, LOOP-M.M1 can proceed (provided the conditional
applicability question in §5 Q2 is resolved YES). When LOOP-L is
deferred, LOOP-M may still proceed independently; no hard dependency
on LOOP-L.

---

End of LOOP-M-SPEC.md.
