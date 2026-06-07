---
slice_id: T.T3
title: CISA Self-Attestation Common Form (OMB 1670-0052) PDF emitter
loop: T
status: proposed
commit: TBD
completed_date: —
depends_on: [T.T1, T.T2, "operator corporate identifiers (config.yaml ssdf.producer block)"]
blocks: [T.T4]
estimated_effort: medium
last_updated: 2026-06-07
applicable_conditional: "any CSP delivering software (including cloud-based application services, firmware, applications, operating systems, or products containing software) to federal agencies subject to OMB M-22-18 / OMB M-23-16; remains useful as an optional artifact under OMB M-26-05's risk-based regime when agencies request the Common Form"
---

# T.T3 — CISA Self-Attestation Common Form (OMB 1670-0052) PDF emitter

## 1. Mission

Generate, deterministically and from real evidence, the **CISA Secure Software
Development Attestation Common Form** (OMB Control Number 1670-0052,
expiration date 03/31/2027) as an unsigned canonical PDF, using the same
dependency-free OOXML/zip-store pattern already proven in the LOOP-C document
template pack and `core/inventory-workbook.ts`. The emitted PDF is bit-for-bit
reproducible across runs (deterministic timestamps, sorted-key JSON shadow,
canonical font metadata), validates as PDF/A-3b where feasible, populates
every required field from operator-supplied SSDF producer configuration and
from the `core/ssdf-practice-map.ts` / `core/ssdf-evidence-bind.ts` artifacts
emitted by T.T1 + T.T2, and is the exact document a corporate officer of the
software producer would sign and submit to a federal agency under the
Memorandum-M-22-18-as-amended-by-M-23-16 regime (or attach to a risk-tier
package the agency requests under the successor M-26-05 risk-based regime).
T.T3 emits the unsigned PDF only; physical signature, electronic signature
binding, and submission via the CISA Repository for Software Attestation and
Artifacts (RSAA) are handled by T.T4.

## 2. Authoritative sources (verbatim quotes, source URL, accessed 2026-06-07)

### 2.1 OMB M-22-18 — Enhancing the Security of the Software Supply Chain through Secure Software Development Practices

- Source: Office of Management and Budget, Memorandum M-22-18, September 14, 2022.
- URL (primary record / commentary): https://www.cisa.gov/secure-software-attestation-form
- URL (memorandum text via federal agency mirror): https://www.transportation.gov/mission/office-secretary/office-chief-information-officer/secure-software-development-attestation
- Date of access: 2026-06-07
- Verbatim excerpt (paraphrasing core requirement from agency-of-record mirrors and the NIST cross-reference page, see §2.5):

> "Federal agencies must only use software provided by software producers
> who can attest to complying with the Government-specified secure software
> development practices, as described in the NIST Guidance."

- Verbatim definition (carried forward by CISA Common Form Instructions; see §2.4):

> "For purposes of this memorandum, the term 'software' includes firmware,
> operating systems, applications, and application services (e.g.,
> cloud-based software), as well as products containing software."

### 2.2 OMB M-23-16 — Update to Memorandum M-22-18

- Source: Office of Management and Budget, Memorandum M-23-16, June 9, 2023.
- URL (commentary record): https://www.crowell.com/en/insights/client-alerts/softening-the-blow-omb-extends-software-supply-chain-security-deadline-and-clarifies-scope
- URL (Federal Register companion): https://www.federalregister.gov/documents/2023/11/16/2023-25251/agency-information-collection-activities-request-for-comment-on-secure-software-development
- Date of access: 2026-06-07
- Verbatim excerpts (from public-record summaries of the memorandum):

> "Agencies must collect attestation forms for critical software (as defined
> in OMB Memorandum M-21-30) three months after the common form is approved
> by OMB and must collect attestation forms for all other software within
> six months."

> "Agencies will not have to collect attestations from third-party software
> components that are incorporated into software end products."

> "Agency chief information officers (CIOs) [have] the authority to
> designate software developed by federal contractors as 'agency-developed.'"

### 2.3 Executive Order 14028 — Improving the Nation's Cybersecurity

- Source: The White House, EO 14028, May 12, 2021.
- URL: https://www.nist.gov/itl/executive-order-14028-improving-nations-cybersecurity/software-security-supply-chains-attesting
- Date of access: 2026-06-07
- Verbatim excerpt (from NIST's published EO 14028 software supply chain page):

> "The security and integrity of 'critical software' — software that
> performs functions critical to trust (such as affording or requiring
> elevated system privileges or direct access to networking and computing
> resources) — is a particular concern."

> Section 4(e) of EO 14028 directs NIST to "issue guidance identifying
> practices that enhance the security of the software supply chain."

### 2.4 CISA Secure Software Development Attestation Common Form (OMB 1670-0052)

- Source: Cybersecurity and Infrastructure Security Agency (CISA),
  "Secure Software Development Attestation Form,"
  OMB Control Number 1670-0052, Expiration Date 03/31/2027,
  released March 11, 2024 (final), revised 2024-04 / 2024-05.
- URLs:
  - Resource page: https://www.cisa.gov/resources-tools/resources/secure-software-development-attestation-form
  - Form PDF (CISA): https://www.cisa.gov/sites/default/files/2024-04/Self_Attestation_Common_Form_FINAL_508c.pdf
  - Form PDF (US DOT mirror): https://www.transportation.gov/sites/dot.gov/files/2024-05/Self_Attestation_Common_Form_05242024_FINAL_508c.pdf
  - Form PDF (GSA-customized mirror): https://www.gsa.gov/system/files/2024-05/GSA7700-24.pdf
  - OMB Information Collection record: https://omb.report/omb/1670-0052
- Date of access: 2026-06-07
- Verbatim excerpts (from CISA-published descriptive text and OMB record):

> "This attestation identifies the minimum secure software development
> requirements a software producer must meet, and attest to meeting,
> before their software subject to the requirements of M-22-18 may be
> used by Federal agencies."

> "This form fulfills the minimum requirements set forth by OMB in M-22-18,
> as amended by M-23-16."

> "OMB Control #: 1670-0052, Expiration Date: 03/31/2027."

- Verbatim attestation practices (paraphrased from the form as published; CSP
  implementer MUST download the FINAL_508c.pdf locally to
  `docs/sources/cisa-common-form-1670-0052.pdf` and paste the exact section-
  by-section text into `core/ssdf-common-form.ts` docstring before ship):

> Practice 1 — "The software was developed and built in secure environments."
> The producer attests that those environments are secured by, at a minimum,
> the following actions:
> 1.a — separating and protecting each environment involved in developing
>   and building software;
> 1.b — regularly logging, monitoring, and auditing trust relationships used
>   for authorization and access (i) to any software development and build
>   environments, and (ii) among components within each environment;
> 1.c — enforcing multi-factor authentication and conditional access across
>   the environments relevant to developing and building software in a manner
>   that minimizes security risk;
> 1.d — taking consistent and reasonable steps to document as well as
>   minimize use or inclusion of software products that create undue risk
>   within the environments used to develop and build software;
> 1.e — encrypting sensitive data, such as credentials, to the extent
>   practicable and based on risk;
> 1.f — implementing defensive cybersecurity practices, including continuous
>   monitoring of operations and alerts and, as necessary, responding to
>   suspected and confirmed cyber incidents.

> Practice 2 — "The software producer has made a good-faith effort to
> maintain trusted source code supply chains by employing automated tools or
> comparable processes to address the security of internal code and
> third-party components and manage related vulnerabilities."

> Practice 3 — "The software producer maintains provenance for internal
> code and third-party components incorporated into the software to the
> greatest extent feasible."

> Practice 4 — "The software producer employed automated tools or
> comparable processes that check for security vulnerabilities. In
> addition: (a) the producer operated these processes on an ongoing basis
> and, at a minimum, prior to product, version, or update releases; and
> (b) the producer has a policy or process to address discovered security
> vulnerabilities prior to product release; and (c) the producer operates
> a vulnerability disclosure program and accepts, reviews, and addresses
> disclosed software vulnerabilities in a timely fashion."

- Verbatim signature-block language (from form template):

> "I, the undersigned, hereby attest under penalty of perjury, by signing
> this form on behalf of the company, that the company satisfies the
> requirements identified in Section II of this form for all software
> covered by the scope of this attestation."

### 2.5 NIST SP 800-218 — Secure Software Development Framework (SSDF) Version 1.1

- Source: National Institute of Standards and Technology, NIST SP 800-218,
  February 2022.
- URL: https://csrc.nist.gov/pubs/sp/800/218/final
- Date of access: 2026-06-07
- Verbatim excerpts (from NIST CSRC publication record and project page):

> "Few software development life cycle (SDLC) models explicitly address
> software security in detail, so secure software development practices
> usually need to be added to and integrated with each SDLC model. The
> Secure Software Development Framework (SSDF), a core set of high-level
> secure software development practices that can be integrated into each
> SDLC implementation, fulfills this need."

> SSDF v1.1 organizes practices into four groups:
> "Prepare the Organization (PO)" — "Ensure that the organization's
> people, processes, and technology are prepared to perform secure
> software development at the organization level;"
> "Protect the Software (PS)" — "Protect all components of the software
> from tampering and unauthorized access;"
> "Produce Well-Secured Software (PW)" — "Produce well-secured software
> with minimal security vulnerabilities in its releases;"
> "Respond to Vulnerabilities (RV)" — "Identify residual vulnerabilities
> in software releases and respond appropriately to address those
> vulnerabilities and prevent similar ones from occurring in the future."

- SSDF v1.1 practice identifiers used by T.T3 cross-references:
  PO.1.1, PO.1.2, PO.1.3, PO.2.1, PO.2.2, PO.2.3, PO.3.1, PO.3.2, PO.3.3,
  PO.4.1, PO.4.2, PO.5.1, PO.5.2; PS.1.1, PS.2.1, PS.3.1, PS.3.2;
  PW.1.1, PW.1.2, PW.1.3, PW.2.1, PW.4.1, PW.4.4, PW.5.1, PW.6.1, PW.6.2,
  PW.7.1, PW.7.2, PW.8.1, PW.8.2, PW.9.1, PW.9.2;
  RV.1.1, RV.1.2, RV.1.3, RV.2.1, RV.2.2, RV.3.1, RV.3.2, RV.3.3, RV.3.4.

### 2.6 NIST SP 800-218A — Secure Software Development Practices for Generative AI and Dual-Use Foundation Models

- Source: NIST SP 800-218A (Initial Public Draft April 2024; Final July 26, 2024).
- URL: https://csrc.nist.gov/pubs/sp/800/218/a/final
- Date of access: 2026-06-07
- Verbatim excerpts:

> "This document augments the secure software development practices and
> tasks defined in Secure Software Development Framework (SSDF) version 1.1
> by adding practices, tasks, recommendations, considerations, notes, and
> informative references that are specific to AI model development
> throughout the software development life cycle."

> "These additions are documented in the form of an SSDF Community Profile
> to support Executive Order (EO) 14110, Safe, Secure, and Trustworthy
> Development and Use of Artificial Intelligence, which tasked NIST with
> 'developing a companion resource to the [SSDF] to incorporate secure
> development practices for generative AI and for dual-use foundation
> models.'"

> "This Community Profile is intended to be useful to the producers of AI
> models, the producers of AI systems that use those models, and the
> acquirers of those AI systems."

### 2.7 OMB M-26-05 — Adopting a Risk-Based Approach to Software and Hardware Security

- Source: Office of Management and Budget, Memorandum M-26-05, January 23, 2026.
- URL: https://www.whitehouse.gov/wp-content/uploads/2026/01/M-26-05-Adopting-a-Risk-based-Approach-to-Software-and-Hardware-Security.pdf
- URL (commentary record): https://www.insidegovernmentcontracts.com/2026/02/omb-rescinds-the-common-form-secure-software-attestation-requirement/
- Date of access: 2026-06-07
- Verbatim excerpts (from public-record summaries; implementer downloads the
  M-26-05 PDF to `docs/sources/omb-m-26-05.pdf` and pastes verbatim §III text
  into the `core/ssdf-common-form.ts` docstring):

> "M-22-18 and M-23-16 imposed 'unproven and burdensome software accounting
> processes that prioritized compliance over genuine security investments.'"
> — OMB Director Russell T. Vought, as quoted in Memorandum M-26-05.

> "Agencies shall continue to maintain a complete inventory of software and
> hardware and develop software and hardware assurance policies and
> processes that match their risk determinations and mission needs."

> "Agencies may choose to use the government-wide secure software
> development resources developed under M-22-18, such as the Secure
> Software Development Attestation Form."

### 2.8 CISA Repository for Software Attestation and Artifacts (RSAA)

- Source: CISA, "CISA Publishes Repository for Software Attestation and
  Artifacts," March 2024.
- URL: https://www.cisa.gov/news-events/news/cisa-publishes-repository-software-attestation-and-artifacts
- Date of access: 2026-06-07
- Used by T.T4 (downstream slice) for submission; T.T3 emits an artifact
  that conforms to the RSAA's accepted upload schema (single-PDF, ≤25 MB,
  PDF/A-3b preferred, fillable form fields permitted but not required).

## 3. Scope

### 3.1 In scope

- Reading the SSDF practice map emitted by T.T1
  (`out/ssdf-practice-map.json`) plus the evidence binding emitted by T.T2
  (`out/ssdf-evidence-binding.json`).
- Reading the operator's producer block from
  `cloud-evidence/config.yaml` (`ssdf.producer.*`) — see §11 REQUIRES-
  OPERATOR-INPUT for the field set.
- Emitting the unsigned PDF at `out/cisa-common-form-1670-0052.pdf` plus
  a sidecar canonical JSON at `out/cisa-common-form-1670-0052.json`
  (sorted-key, no whitespace; serves as REO provenance shadow).
- Filling all of: producer name, address, point-of-contact, scope of
  attestation (product list with versions, derived from T.T1 + T.T2),
  the four Practice 1 / 2 / 3 / 4 attestation boxes (with operator-
  declared "comply with conditions / cannot comply with conditions"
  selectors backed by T.T2 evidence), POA&M identifiers when "cannot
  comply with conditions" is selected (sourced from
  `out/poam.json` LOOP-A.A1 emitter), signature block (left blank for
  human signature), date field (left blank), and the OMB control
  number / expiration footer.
- Computing the SSDF-practice-coverage roll-up that operators read in the
  margin / appendix of the PDF: per CISA Practice (1.a–1.f, 2, 3, 4),
  list the underlying SSDF v1.1 practice IDs (PO/PS/PW/RV) and the
  satisfaction status from T.T2.
- PDF/A-3b conformance where the OOXML/zip-store pattern permits;
  graceful fallback to plain PDF 1.7 when PDF/A-3b font embedding cannot
  be satisfied without a third-party dependency.

### 3.2 Explicitly NOT in scope

- Electronic signature binding (PAdES, Adobe-signed, DocuSign). T.T4 handles
  signature embedding + RSAA submission.
- 3PAO assessment of SSDF practices (the form supports either self-
  attestation or 3PAO-issued letter; T.T3 emits the self-attestation form;
  3PAO letter path is a distinct artifact emitted by LOOP-F.F4).
- Sub-component attestation (M-23-16 explicitly excluded third-party
  components from the attestation requirement; T.T3 enforces this exclusion
  via the scope-of-attestation builder).
- Agency-specific addenda (some agencies, e.g., DOE, attach addenda to the
  Common Form). T.T3 emits the base form only; agency addenda are a
  separate emit path (out of scope for LOOP-T).
- NIST SP 800-218A (AI SSDF Community Profile) practice attestation as a
  formal sub-form. T.T3 records the operator's voluntary disclosure of
  800-218A coverage in an appendix when `ssdf.producer.ai_profile = true`
  in config.yaml; this is not a Common-Form field and is clearly labeled
  as informational.

## 4. Inputs

### 4.1 Operator-supplied configuration (`config.yaml`)

```yaml
ssdf:
  producer:
    legal_name: "Acme CSP, Inc."
    dba_name: "Acme Cloud"             # optional
    address:
      street: "123 Main St"
      city: "Reston"
      state: "VA"
      postal_code: "20190"
      country: "US"
    point_of_contact:
      name: "Jane Doe"
      title: "Chief Information Security Officer"
      email: "jane.doe@acme.example"
      phone: "+1-703-555-0100"
    signatory:
      name: "John Smith"
      title: "Chief Executive Officer"
      # signature_image_path: "secrets/signature.png"   # OPTIONAL — T.T4 only
    scope_of_attestation:
      # exact product list operator is attesting to; T.T3 cross-checks
      # against T.T1 ssdf-practice-map.json
      products:
        - name: "Acme Cloud Evidence Platform"
          version: "2026.6.1"
          cpe: "cpe:2.3:a:acme:cloud_evidence_platform:2026.6.1:*:*:*:*:*:*:*"
        - name: "Acme Cloud Tracker"
          version: "1.4.0"
          cpe: "cpe:2.3:a:acme:cloud_tracker:1.4.0:*:*:*:*:*:*:*"
    third_party_assessor:                # optional, not used by T.T3
      organization: null
      certificate_id: null
    ai_profile: false                    # opt-in 800-218A informational appendix
    poam_reference_overrides: {}         # optional per-practice POA&M override
```

### 4.2 Inputs from upstream slices

- `out/ssdf-practice-map.json` (T.T1): per-product SSDF v1.1 practice ID
  list with status ∈ {implemented, partially-implemented, not-implemented,
  not-applicable} plus per-practice evidence references.
- `out/ssdf-evidence-binding.json` (T.T2): the canonical evidence-binding
  manifest joining each SSDF practice ID to one or more
  `(envelope_path, observation_uuid, finding_id)` triples.
- `out/poam.json` (LOOP-A.A1): canonical OSCAL POA&M, used when the
  operator selects "cannot comply with conditions" for any Practice 1.a–
  1.f / 2 / 3 / 4 box; the POA&M item UUIDs flow into the PDF.
- `docs/sources/cisa-common-form-1670-0052.pdf` (committed; downloaded
  copy of the FINAL_508c.pdf — REQUIRED for verbatim attestation-text
  fidelity at ship time; bytes hashed and the hash recorded in
  provenance).

### 4.3 Constants (Rule 3 — allowed fixed data)

- OMB Control Number string: `1670-0052`.
- Expiration date string: `03/31/2027`.
- Form title string: `Secure Software Development Attestation Common Form`.
- Practice 1 / 2 / 3 / 4 attestation headings — sourced verbatim from §2.4.
- SSDF practice ID list (PO/PS/PW/RV with sub-IDs) — sourced from NIST SP
  800-218 Table 1; allowed under Rule 3 ("NIST control IDs +
  identifiers").

## 5. Outputs

### 5.1 PDF artifact — `out/cisa-common-form-1670-0052.pdf`

- Layout: single-document, US Letter (8.5×11 in), 1-inch margins, 11-pt
  serif body (Times-Roman PostScript Type 1 embedded via PDF/A-3b
  required-fonts profile when feasible; falls back to Times-Roman
  reference + ToUnicode CMap for canonicalization).
- Pages:
  - **Page 1** — Form header (CISA / OMB logos rendered as embedded PDF
    XObjects sourced from `docs/assets/cisa-logo.pdf` + `docs/assets/
    omb-seal.pdf`; logos hashed + recorded in provenance), title, OMB
    control + expiration footer, Section I (Producer Information): legal
    name, DBA, address, point-of-contact name/title/email/phone, scope
    of attestation table (product, version, CPE).
  - **Page 2** — Section II (Attestation): the four Practice 1 / 2 / 3 /
    4 paragraphs reproduced verbatim from §2.4; "comply / cannot comply
    with conditions" radio fields (rendered as XObject form fields, plus
    a flattened-text fallback line printing the operator's selection).
    When "cannot comply with conditions" is selected, an inline POA&M
    item identifier list follows immediately.
  - **Page 3** — Section III (Signatory): signatory name, title,
    signature line (blank for human signature), date line (blank).
  - **Page 4 (Appendix A)** — SSDF v1.1 practice coverage roll-up: a
    table with columns (CISA Practice, SSDF v1.1 IDs, # implemented,
    # partially-implemented, # not-implemented, # N/A).
  - **Page 5 (Appendix B, when `ai_profile: true`)** — SP 800-218A
    Community Profile informational coverage, with the heading
    "Informational only — not a requirement of OMB 1670-0052."

### 5.2 Sidecar canonical JSON — `out/cisa-common-form-1670-0052.json`

- Sorted-key (RFC 8785 JSON canonicalization, same canonicalization
  primitive as LOOP-A.A1), no whitespace; serves as the REO provenance
  shadow that the PDF emitter populates from. Schema:

```ts
interface CisaCommonFormCanonical {
  schema: 'https://cisa.gov/forms/1670-0052#v2024-03';
  omb_control_number: '1670-0052';
  expiration_date: '03/31/2027';
  emittedAt: string;                    // ISO 8601, frozen via runId
  producer: {
    legal_name: string;
    dba_name: string | null;
    address: {
      street: string; city: string; state: string;
      postal_code: string; country: string;
    };
    point_of_contact: {
      name: string; title: string; email: string; phone: string;
    };
    signatory: { name: string; title: string };
    scope_of_attestation: {
      products: Array<{ name: string; version: string; cpe?: string }>;
    };
  };
  attestations: {
    practice_1_secure_environments: {
      a_separating_environments: PracticeBox;
      b_logging_monitoring_auditing: PracticeBox;
      c_mfa_conditional_access: PracticeBox;
      d_minimize_undue_risk_products: PracticeBox;
      e_encryption_sensitive_data: PracticeBox;
      f_defensive_cybersecurity: PracticeBox;
    };
    practice_2_trusted_supply_chains: PracticeBox;
    practice_3_data_provenance: PracticeBox;
    practice_4_automated_vulnerability_tools: {
      header: PracticeBox;
      a_ongoing_pre_release: PracticeBox;
      b_policy_address_vulnerabilities: PracticeBox;
      c_vulnerability_disclosure_program: PracticeBox;
    };
  };
  ssdf_coverage_rollup: Array<{
    cisa_practice: string;               // "1.a" .. "4.c"
    ssdf_v1_1_ids: string[];             // ["PO.5.1", "PO.5.2", ...]
    implemented: number;
    partially_implemented: number;
    not_implemented: number;
    not_applicable: number;
  }>;
  poam_references: Array<{
    cisa_practice: string;
    poam_item_uuids: string[];
  }>;
  ai_profile_appendix?: {
    enabled: boolean;
    sp_800_218a_practices: Array<{ id: string; status: string }>;
  };
  provenance: {
    emitter: 'ssdf-common-form-pdf';
    emittedAt: string;
    sourceCalls: Array<{ kind: string; path: string; sha256: string }>;
    signingKeyId: string;
    common_form_pdf_template_sha256: string;
  };
}

interface PracticeBox {
  selection: 'comply' | 'comply-with-conditions' | 'cannot-comply' | 'not-yet-determined';
  ssdf_v1_1_ids: string[];
  evidence_observation_uuids: string[];
  poam_item_uuids: string[];
  source: 'ssdf-evidence-binding' | 'operator-config' | 'REQUIRES-OPERATOR-INPUT';
}
```

### 5.3 Signed envelope structure

- The PDF + sidecar JSON are added to the existing signing-glob list in
  `core/sign.ts`. Each file's SHA-256 + Ed25519 signature lands in
  `out/manifest.json`. RFC 3161 timestamp covers the manifest as before.
  T.T4 reads both the PDF and the sidecar JSON; T.T4's PAdES embedding
  step does NOT change the canonical JSON, so the sidecar remains the
  REO authority on what was emitted.

### 5.4 Coverage report contribution

- `out/inventory-coverage.json` gains the metric
  `ssdf_common_form_fill_rate` = (# of populated Section I + II + III
  required fields) / (# of total required fields). Baseline established
  on first emission; CI G2 (`check:coverage-regression`) fails on
  subsequent decreases. The metric is per-product when multiple products
  are listed in `scope_of_attestation`.

## 6. Algorithm / Steps (numbered, deterministic, REO-compliant)

1. **Boot + read inputs.** `emitSsdfCommonForm(opts)` reads:
   - `config.yaml` → `ssdf.producer.*`. Validates with the Zod schema in
     `core/ssdf-common-form.ts:CommonFormConfigSchema`. Throws typed
     `MissingOperatorInputError` listing every absent required field on
     first encounter (no silent defaulting).
   - `out/ssdf-practice-map.json` (T.T1). Validates against
     `core/ssdf-practice-map.ts:PracticeMapSchema`.
   - `out/ssdf-evidence-binding.json` (T.T2). Validates against
     `core/ssdf-evidence-bind.ts:EvidenceBindingSchema`.
   - `out/poam.json` (LOOP-A.A1) IF any practice is "cannot-comply".
   - `docs/sources/cisa-common-form-1670-0052.pdf` SHA-256 (recorded in
     provenance; CI fails if hash drifts without an explicit
     `--accept-new-template-hash` flag).
2. **Build canonical JSON.** Project the inputs into
   `CisaCommonFormCanonical` per §5.2. For each `PracticeBox`:
   - Look up the SSDF v1.1 IDs that map to that CISA practice (lookup
     table in `core/ssdf-common-form.ts:CISA_PRACTICE_TO_SSDF`; see
     §6.5).
   - For each SSDF ID, read the per-practice status from
     `ssdf-evidence-binding.json`.
   - Compute the box's `selection`:
     - All implemented → `comply`.
     - Mixed (some implemented + some partially) → `comply-with-conditions`.
     - All `not-implemented` → `cannot-comply` AND POA&M IDs MUST be
       present; if not, throw `MissingPoamReferenceError`.
     - Any `not-yet-determined` → `not-yet-determined` (REO-Rule-1.5:
       no silent fallback).
3. **Roll-up.** For each CISA practice, count
   (implemented, partially-implemented, not-implemented, not-applicable)
   across its SSDF IDs; persist in `ssdf_coverage_rollup`.
4. **POA&M binding.** When `selection ∈ {cannot-comply, comply-with-conditions}`,
   walk the POA&M JSON for items whose `related-observations[]` reference
   any observation_uuid in the practice's evidence chain; collect the
   `poam-item.uuid` set into `poam_references[]` + the practice's
   `poam_item_uuids[]`.
5. **AI profile appendix (optional).** When `ssdf.producer.ai_profile`
   is `true`, read `out/ssdf-practice-map.json` for any `sp_800_218a_*`
   entries; populate `ai_profile_appendix.sp_800_218a_practices[]`.
6. **Canonical JSON emit.** Serialize to RFC 8785 JCS, write
   `out/cisa-common-form-1670-0052.json`. SHA-256 computed.
7. **PDF emit (deterministic).** `emitCommonFormPdf(canonical, opts)` in
   `core/ssdf-common-form-pdf.ts`:
   - Uses the OOXML/zip-store dependency-free pattern from
     `core/inventory-workbook.ts` adapted to PDF stream emission. The
     emitter constructs PDF objects (catalog, page tree, page, font,
     content stream, XObject form fields, info, ID, xref, trailer)
     by direct byte assembly. All randomness sources are deterministic
     (run-ID-seeded; `/ID` array generated from SHA-256 of canonical
     JSON; `/CreationDate` and `/ModDate` set to canonical
     `emittedAt`).
   - Embeds Times-Roman as a Type 1 reference with ToUnicode CMap (no
     binary font file shipped; bytes 100% reproducible).
   - Logos (`cisa-logo.pdf`, `omb-seal.pdf`) referenced as XObjects;
     their bytes are committed under `docs/assets/` and their SHA-256
     hashes recorded in provenance.
   - PDF/A-3b conformance attempted; if the emitter detects PDF/A-3b
     would require an actual TrueType font file (which the zip-store
     pattern cannot ship without a binary dependency), the emitter
     falls back to PDF 1.7 with a recorded `provenance.pdfa_b_attempted
     = false` line; CI does not fail this fallback (it is an
     intentional, documented degradation under the dependency-free
     constraint).
   - Form fields (CISA practice checkboxes, signature field, date
     field) are emitted as PDF AcroForm fields where possible; when
     PDF/A-3b mode forbids AcroForm, the fields are rendered as
     flattened text annotations.
8. **Determinism check.** After emit, the emitter re-runs the byte-
   emission against an in-memory ZipCRC and compares to a prior run's
   SHA-256 when the run-ID is held constant. CI test
   `ssdf-common-form.test.ts` runs the emitter twice with frozen
   inputs and asserts byte-identity.
9. **Sign + timestamp.** PDF + sidecar JSON are appended to
   `core/sign.ts`'s `WELL_KNOWN_SIGNING_GLOBS`; Ed25519 sign + RFC
   3161 timestamp run as for every other artifact.
10. **Submission-bundle wiring.** `core/submission-bundle.ts:WELL_KNOWN`
    gains:
    ```ts
    { role: 'ssdf-common-form-pdf', filename: 'cisa-common-form-1670-0052.pdf',
      description: 'CISA Secure Software Development Attestation Common Form (OMB 1670-0052) (LOOP-T.T3)' },
    { role: 'ssdf-common-form-json', filename: 'cisa-common-form-1670-0052.json',
      description: 'Canonical JSON shadow of the OMB 1670-0052 PDF (LOOP-T.T3)' },
    ```
11. **Coverage update.** Append `ssdf_common_form_fill_rate` per product
    to `out/inventory-coverage.json` via the existing
    `core/inventory-coverage.ts:appendMetric()` API.
12. **Validation pass.**
    - `npm run check:provenance` — the canonical JSON's provenance block
      MUST list all eight sourceCalls (config.yaml, practice-map,
      evidence-binding, poam, cisa template PDF, cisa-logo asset,
      omb-seal asset, ssdf-coverage rollup table fixture).
    - `npm run lint:no-stubs` — no forbidden tokens.
    - `npm run check:coverage-regression` — `ssdf_common_form_fill_rate`
      baseline established on first run.

### 6.5 CISA Practice → SSDF v1.1 mapping table (the lookup the algorithm reads)

| CISA practice | SSDF v1.1 IDs mapped (illustrative; final list pinned at ship in `core/ssdf-common-form.ts:CISA_PRACTICE_TO_SSDF` after the implementer cross-checks against NIST SP 800-218 Table 1) |
|---|---|
| 1.a separating environments | PO.5.1, PO.5.2 |
| 1.b logging/monitoring/auditing | PO.3.2, PO.3.3, PS.1.1 |
| 1.c MFA + conditional access | PO.5.1, PO.5.2, PO.3.3 |
| 1.d minimize undue-risk products | PO.1.3, PW.4.1, PW.4.4 |
| 1.e encryption of sensitive data | PO.5.1, PS.1.1, PS.2.1 |
| 1.f defensive cybersecurity | PO.3.2, RV.1.1, RV.1.2, RV.1.3 |
| 2 trusted source code supply chains | PO.1.1, PW.4.1, PW.4.4, PS.3.1, PS.3.2 |
| 3 data provenance | PS.3.2, PW.4.1, PW.4.4 |
| 4 automated vulnerability tools (header) | PO.4.1, PW.7.1, PW.7.2, PW.8.1, PW.8.2 |
| 4.a ongoing + pre-release | PW.7.1, PW.8.1 |
| 4.b policy to address vulnerabilities | RV.2.1, RV.2.2 |
| 4.c vulnerability disclosure program | RV.1.3, RV.2.1 |

## 7. Files to create / modify

### Files to create

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ssdf-common-form.ts`
  — pure aggregator + canonical-JSON builder. Defines
  `CommonFormConfigSchema`, `CisaCommonFormCanonical`, `PracticeBox`,
  `CISA_PRACTICE_TO_SSDF` constant table. ~520 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ssdf-common-form-pdf.ts`
  — deterministic PDF byte emitter (OOXML/zip-store-style direct byte
  assembly, ported to PDF object stream emission). ~640 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/ssdf-common-form.test.ts`
  — ≥15 unit + integration tests (see §8). ~480 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/ssdf-common-form-pdf.test.ts`
  — PDF determinism + structure tests (≥6 tests). ~220 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/ssdf-common-form/`
  — fixture set:
  - `config.minimal.yaml` (fully-populated, comply-everywhere case)
  - `config.cannot-comply.yaml` (Practice 4 cannot-comply with POA&M ref)
  - `config.ai-profile.yaml` (ai_profile: true)
  - `practice-map.minimal.json`, `evidence-binding.minimal.json`,
    `poam.minimal.json`
  - `expected.canonical.json` (golden file for determinism test)
  - `expected.sha256` (golden PDF byte-hash for determinism test)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/sources/cisa-common-form-1670-0052.pdf`
  — downloaded copy of the FINAL_508c.pdf (≤2 MB; committed; hash
  recorded in `docs/sources/SOURCES.md` and in the emitter's
  provenance).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/assets/cisa-logo.pdf`
  — extracted CISA logo as a 1-page minimal PDF (or PDF XObject); used as
  inline image in §5.1 Page 1.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/assets/omb-seal.pdf`
  — extracted OMB seal as a 1-page minimal PDF; used as inline image.

### Files to modify

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
  — append the two `WELL_KNOWN` entries documented in §6 step 10.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sign.ts`
  — append `cisa-common-form-1670-0052.{pdf,json}` to the signing glob.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`
  — add the `--ssdf-common-form` flag (env
  `CLOUD_EVIDENCE_SSDF_COMMON_FORM`); invoke `emitSsdfCommonForm()`
  AFTER T.T2 evidence binding emit and AFTER LOOP-A.A1 POA&M emit.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/inventory-coverage.ts`
  — register `ssdf_common_form_fill_rate` per-product metric.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/scripts/check-provenance.mjs`
  — extend the allowlist for the new `ssdf-common-form-pdf` emitter.

## 8. Test specifications

| # | id | scenario | fixture path | expected | acceptance |
|---|---|---|---|---|---|
| 1 | T3-T01 | builds canonical JSON from minimal happy-path config (all practices comply) | `test/fixtures/ssdf-common-form/config.minimal.yaml` + `practice-map.minimal.json` + `evidence-binding.minimal.json` | canonical JSON deep-equals `expected.canonical.json`; every PracticeBox.selection == `comply` | strict deep-equal on the SORTED-key JSON; no missing fields |
| 2 | T3-T02 | builds canonical JSON from cannot-comply config (Practice 4 cannot-comply with POA&M ref) | `config.cannot-comply.yaml` | Practice-4.header.selection == `cannot-comply`; poam_references contains exactly the 2 fixture POA&M item UUIDs | length(poam_references[0].poam_item_uuids) == 2; values match the fixture |
| 3 | T3-T03 | throws MissingPoamReferenceError when cannot-comply selected but no POA&M reference exists | `config.cannot-comply.yaml` + empty `poam.minimal.json` | function throws `MissingPoamReferenceError` with message naming the practice | error class is exact match; message contains the practice id |
| 4 | T3-T04 | throws MissingOperatorInputError when `producer.legal_name` is absent | `config.partial.yaml` (legal_name removed) | function throws `MissingOperatorInputError` listing `ssdf.producer.legal_name` | error message contains the field path verbatim |
| 5 | T3-T05 | rolls up Practice 1 coverage with mixed implemented/partial/not-impl across SSDF IDs | `config.mixed.yaml` | `ssdf_coverage_rollup` row for `1.a` has implemented=1, partially_implemented=1, not_implemented=0 | strict numeric equality |
| 6 | T3-T06 | sets selection=`comply-with-conditions` when SSDF IDs are mixed implemented + partially | `config.mixed.yaml` | Practice-1.a.selection == `comply-with-conditions` | string equality |
| 7 | T3-T07 | sets selection=`not-yet-determined` when any underlying SSDF ID is `not-yet-determined` | `config.undetermined.yaml` | Practice-1.b.selection == `not-yet-determined`; no silent fallback to `comply` | strict; REO-Rule-1.5 guardrail asserted |
| 8 | T3-T08 | honors `ai_profile: true` and populates Appendix B (page 5) | `config.ai-profile.yaml` + `practice-map.ai.json` | canonical JSON includes `ai_profile_appendix.enabled == true` and ≥1 entry under `sp_800_218a_practices` | length(sp_800_218a_practices) > 0 |
| 9 | T3-T09 | omits Appendix B page when `ai_profile: false` | `config.minimal.yaml` | canonical JSON has `ai_profile_appendix === undefined`; PDF page count == 4 | page count from `pdf-parse` round-trip == 4 |
| 10 | T3-T10 | PDF emit is byte-deterministic across two runs with identical inputs + runId | `config.minimal.yaml` | SHA-256(out/cisa-common-form-1670-0052.pdf) == golden `expected.sha256` on both runs | hash equality across two consecutive emit calls |
| 11 | T3-T11 | PDF emit produces a US Letter, 4-page document (no AI profile) | `config.minimal.yaml` | parsed PDF page size == 612×792 pt; page count == 4 | `pdf-parse` round-trip |
| 12 | T3-T12 | PDF includes OMB Control Number `1670-0052` footer on every page | `config.minimal.yaml` | every page's content stream contains the string `1670-0052` | substring match on each parsed page |
| 13 | T3-T13 | PDF embeds Producer legal_name verbatim on Section I | `config.minimal.yaml` (Acme CSP, Inc.) | parsed page 1 text contains `Acme CSP, Inc.` | substring match |
| 14 | T3-T14 | PDF includes verbatim Practice 1.a heading text from CISA template | `config.minimal.yaml` | page 2 text contains the verbatim sub-string `separating and protecting each environment involved in developing and building software` | substring match |
| 15 | T3-T15 | PDF includes verbatim Practice 4 attestation statement on page 2 | `config.minimal.yaml` | page 2 text contains `The software producer employed automated tools or comparable processes that check for security vulnerabilities` | substring match |
| 16 | T3-T16 | sidecar JSON is RFC 8785 JCS canonical (sorted keys, no whitespace) | `config.minimal.yaml` | re-canonicalizing the emitted JSON via JCS returns the byte-identical input | byte-equal on round-trip |
| 17 | T3-T17 | submission-bundle records the PDF + JSON with correct roles | `config.minimal.yaml` | `out/submission-bundle.json` has entries with `role == 'ssdf-common-form-pdf'` and `role == 'ssdf-common-form-json'` | exact role string match; description references LOOP-T.T3 |
| 18 | T3-T18 | inventory-coverage report includes `ssdf_common_form_fill_rate` per product | `config.two-products.yaml` | `out/inventory-coverage.json` has two entries under `ssdf_common_form_fill_rate`, one per product | length == 2; each ∈ [0, 1] |
| 19 | T3-T19 | provenance block lists template SHA-256 + every sourceCall path | `config.minimal.yaml` | canonical JSON `provenance.sourceCalls[]` has ≥7 entries including `cisa-common-form-1670-0052.pdf` with non-empty `sha256` | length(sourceCalls) ≥ 7; sha256 not empty |
| 20 | T3-T20 | Ed25519 signature in `out/manifest.json` covers the PDF + JSON | `config.minimal.yaml` | `out/manifest.json` lists both files with verifiable Ed25519 signatures over the file SHA-256 | signature verify == true |
| 21 | T3-T21 | OMB Control Number is the constant string `1670-0052` (REO Rule 3 exception) | (any) | the emitted JSON's `omb_control_number === '1670-0052'` | strict equality |
| 22 | T3-T22 | --ssdf-common-form flag triggers emit; absence does not emit | `config.minimal.yaml` (run with + without flag) | with flag: file exists; without: file absent | filesystem presence test |
| 23 | T3-T23 | scope_of_attestation product list cross-checks against T.T1 practice-map (mismatch errors) | `config.mismatch.yaml` (product not in T.T1) | function throws `ScopeMismatchError` naming the missing product | error class + message match |

(23 specs satisfies the minimum 15 raised for this batch.)

## 9. Risks

| # | risk | likelihood | impact | mitigation |
|---|---|---|---|---|
| 1 | CISA updates the Common Form (e.g. new sub-practice 1.g), changing the layout and required fields. The OMB 1670-0052 record expires 03/31/2027 and may be renewed with edits. | medium | high (emitted PDF would not satisfy submission requirements) | Template SHA-256 pinned in provenance; CI fails if the in-repo template hash drifts without `--accept-new-template-hash`. Quarterly cron checks the CISA RSAA / cisa.gov page for revision notices; on detection, a documented migration runbook updates the template + the CISA_PRACTICE_TO_SSDF mapping + tests. |
| 2 | OMB M-26-05 (Jan 23, 2026) rescinded the Common Form as a mandatory collection. The Common Form is now optional, and individual agencies may adopt tailored alternatives. | confirmed | medium (T.T3 remains useful but is no longer universally required) | T.T3 is gated by the `--ssdf-common-form` flag (default off). Documentation notes M-26-05's risk-based regime; the PDF is emitted on operator request OR when an agency contract specifically requires the Common Form. T.T1 + T.T2 (SSDF practice map + evidence binding) remain useful regardless of M-26-05 because they support the risk-tier package agencies now build under M-26-05. |
| 3 | Deterministic PDF emission without a third-party PDF library risks subtle non-determinism (e.g. floating-point coordinate drift, ZIP entry ordering for embedded XObjects, font subset ordering). | medium | high (CI test T3-T10 would flake) | Floating-point coordinates emitted as fixed-point integers (1/72-inch units, integer math). XObject ordering and PDF object ID assignment are explicitly seeded by content-stream order, not insertion order. `/ID` array deterministically derived from canonical JSON SHA-256. CI runs T3-T10 with two consecutive emits + asserts byte-identity; if flakes, a follow-up risk-register entry tracks the non-determinism source. |
| 4 | PDF/A-3b conformance is hard without an actual embedded TrueType font; falling back to plain PDF 1.7 could fail certain agencies' archival ingest rules. | medium | medium | The fallback is documented in the provenance block (`pdfa_b_attempted: false`). Operator runbook lists the (rare) agencies known to require PDF/A-3b; in those cases the operator runs `npm run pdf:fonts:embed` (out of LOOP-T scope) which downloads a Liberty Mono / Liberty Serif font set under SIL OFL and embeds. T.T3 itself remains dependency-free. |
| 5 | NIST SP 800-218 Rev 2 (currently a draft, csrc.nist.gov/pubs/sp/800/218/r1/ipd as of 2024) may renumber practices (PO/PS/PW/RV → new IDs). | low | medium | The `CISA_PRACTICE_TO_SSDF` map is keyed on the SSDF v1.1 IDs ONLY. A v1.2 / v2 transition would ship as a versioned constant (`CISA_PRACTICE_TO_SSDF_V12`), selectable via `ssdf.framework_version` in config.yaml. |
| 6 | Operator forgets to download the CISA template PDF, causing template SHA-256 mismatch on first run. | high | low (loud error) | Emitter raises `MissingTemplateError` with the exact wget command to fetch the template into `docs/sources/cisa-common-form-1670-0052.pdf`. CHANGELOG entry for T.T3 reminds operators. |
| 7 | The 800-218A AI Profile appendix could confuse a non-AI software producer if their config has `ai_profile: true` set in error. | low | low | The appendix is labeled "Informational only — not a requirement of OMB 1670-0052"; emitter logs `ssdf:ai-profile-enabled` info when populated; CHANGELOG documents that ai_profile is optional. |
| 8 | Form's signature field is left blank for a human; downstream T.T4 must not silently re-emit T.T3's PDF or the unsigned PDF could circulate. | medium | high | T.T3's emitted PDF has the run-ID in `/ID` and in its filename suffix when `--ssdf-common-form-unsigned-suffix` is set; T.T4 emits to a distinct filename (`out/cisa-common-form-1670-0052.signed.pdf`) and never overwrites T.T3's artifact. |

## 10. Open questions

- **Q1**: Should T.T3 generate a separate PDF per product when
  `scope_of_attestation.products[]` length > 1, or one PDF covering all
  products in a single attestation? Recommend: one PDF with a multi-row
  product table in Section I, since the Common Form's free-text scope
  field permits enumeration. Operator override via
  `ssdf.producer.scope_of_attestation.per_product_pdf: true` could split.
- **Q2**: PDF/A-3b vs PDF/A-2b vs plain PDF 1.7 — which to default to?
  Recommend: try PDF/A-3b without font embedding (acceptable if CISA
  RSAA does not enforce font embedding); fall back to PDF 1.7 cleanly;
  log the fallback.
- **Q3**: Should T.T3 emit a `.txt` plain-text shadow alongside the PDF
  + JSON for grep-friendliness during 3PAO review? Recommend: yes,
  optional, controlled by `--ssdf-common-form-emit-txt`; deterministic;
  not part of the submission-bundle but signed alongside.
- **Q4**: When `OMB M-26-05` is in effect (post-Jan 2026), should T.T3
  emit a header banner on Page 1 of the PDF reading "This form is being
  submitted voluntarily under the M-26-05 risk-based regime"?
  Recommend: yes, opt-in via `ssdf.producer.m26_05_banner: true`; defaults
  to off to preserve historical CISA Common Form fidelity.
- **Q5**: 3PAO-letter alternative — should T.T3 detect when a 3PAO letter
  is present and emit a sidecar attestation pointing to it (rather than
  the self-attestation form)? Recommend: defer to LOOP-F.F4 (3PAO
  attestation letter emitter); T.T3 logs `ssdf:3pao-letter-detected` info
  when found.
- **Q6**: Should the SSDF coverage roll-up (Appendix A) be emitted as a
  separate signed artifact too (so the rollup can be referenced
  independently of the form)? Recommend: yes, emit
  `out/ssdf-coverage-rollup.json` as a sibling artifact, also signed.

## 11. REQUIRES-OPERATOR-INPUT fields

Per REO Rule 4, every operator-supplied field, with validator + UI
location + failure mode:

| field name | type | validator | UI location | failure mode if missing |
|---|---|---|---|---|
| `ssdf.producer.legal_name` | string | non-empty, ≤200 chars | `config.yaml` | `MissingOperatorInputError`: emitter throws on first call; lists the exact YAML path. |
| `ssdf.producer.dba_name` | string \| null | ≤200 chars when present | `config.yaml` | Defaults to `null`; emitter does not throw; PDF omits the "DBA" line. |
| `ssdf.producer.address.street` | string | non-empty | `config.yaml` | `MissingOperatorInputError`. |
| `ssdf.producer.address.city` | string | non-empty | `config.yaml` | `MissingOperatorInputError`. |
| `ssdf.producer.address.state` | string | 2-char US state or full country name | `config.yaml` | `MissingOperatorInputError`. |
| `ssdf.producer.address.postal_code` | string | non-empty | `config.yaml` | `MissingOperatorInputError`. |
| `ssdf.producer.address.country` | string | ISO 3166-1 alpha-2 | `config.yaml` | Defaults to `US`; warns at emit. |
| `ssdf.producer.point_of_contact.name` | string | non-empty | `config.yaml` | `MissingOperatorInputError`. |
| `ssdf.producer.point_of_contact.title` | string | non-empty | `config.yaml` | `MissingOperatorInputError`. |
| `ssdf.producer.point_of_contact.email` | string | RFC 5322 email | `config.yaml` | `MissingOperatorInputError`; format check throws `InvalidEmailFormatError`. |
| `ssdf.producer.point_of_contact.phone` | string | E.164 | `config.yaml` | `MissingOperatorInputError`; format check throws `InvalidPhoneFormatError`. |
| `ssdf.producer.signatory.name` | string | non-empty | `config.yaml` | `MissingOperatorInputError`. |
| `ssdf.producer.signatory.title` | string | non-empty | `config.yaml` | `MissingOperatorInputError`. |
| `ssdf.producer.scope_of_attestation.products[]` | list | ≥1 entry; each has name + version | `config.yaml` | `MissingOperatorInputError`. |
| `ssdf.producer.scope_of_attestation.products[].cpe` | string | CPE 2.3 format | `config.yaml` | Defaults to absent; PDF omits the CPE column for that row. |
| `ssdf.producer.ai_profile` | boolean | true/false | `config.yaml` | Defaults to `false`; no Appendix B emitted. |
| `ssdf.producer.poam_reference_overrides{}` | map | keys ∈ practice IDs; values: POA&M item UUID lists | `config.yaml` | Defaults to empty `{}`; auto-derivation from T.T2 binding used. |
| Practice selection (per CISA practice 1.a..4.c) | derived | from T.T2 evidence binding | (computed) | Auto-derived; operator never sets directly; throws `MissingPracticeMapError` if T.T1/T.T2 output absent. |
| Signature field (image / PAdES) | image \| signed-PAdES | (handled by T.T4) | T.T4 | T.T3 leaves blank; never auto-fills. |
| Signature date | ISO date | (handled by T.T4) | T.T4 | T.T3 leaves blank. |

## 12. Implementation log

| date | session | action | commit | notes |
|---|---|---|---|---|
|     |         |        |        |       |

(Implementing session appends rows per `docs/IMPLEMENTATION-LOG-TEMPLATE.md`.
Every milestone, test failure, source-pin, schema-divergence, and risk-
register update gets a row.)

## 13. Completion checklist

The 7-step procedure from `docs/SLICE-COMPLETION-PROCEDURE.md`, quoted verbatim:

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

**Final step (mandatory for T.T3):**
After commit lands, append a row to `cloud-evidence/docs/STATUS.md` for this
slice; update the LOOP-T SPEC status row; append a CHANGELOG line; push to
`origin/main`; only THEN is the slice closed.

## Resume-from-fresh-session checklist

If a session opens with ONLY this file as context:

1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. Read `cloud-evidence/docs/loops/LOOP-T-SPEC.md` §1 (Mission & scope) +
   §2 (Statutory & regulatory drivers — M-22-18 + M-23-16 + EO 14028 +
   M-26-05) + §3 (Slice list — T.T1, T.T2, T.T3, T.T4, T.T5).
3. Read `cloud-evidence/docs/loops/LOOP-T-RISKS.md` for cross-cutting
   loop risks beyond the slice-local risks in §9.
4. Read `cloud-evidence/docs/slices/T/T.T1.md` and
   `cloud-evidence/docs/slices/T/T.T2.md` to understand the inputs
   (`out/ssdf-practice-map.json` and `out/ssdf-evidence-binding.json`)
   that T.T3 consumes.
5. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the
   mandatory 7-step commit pattern.
6. Read `cloud-evidence/docs/IMPLEMENTATION-LOG-TEMPLATE.md` — the
   format you write into §12 above.
7. Read `cloud-evidence/core/inventory-workbook.ts` end-to-end — that's
   the dependency-free OOXML/zip-store pattern that
   `core/ssdf-common-form-pdf.ts` adapts to PDF emission.
8. Read `cloud-evidence/core/sign.ts` + `core/submission-bundle.ts` —
   you will append two entries to each per §6 steps 9–10.
9. Confirm `docs/sources/cisa-common-form-1670-0052.pdf` exists locally;
   if not, download from
   https://www.cisa.gov/sites/default/files/2024-04/Self_Attestation_Common_Form_FINAL_508c.pdf
   (or the US DOT mirror) before running the emitter.
10. Confirm `docs/sources/omb-m-26-05.pdf` exists; if not, download from
    https://www.whitehouse.gov/wp-content/uploads/2026/01/M-26-05-Adopting-a-Risk-based-Approach-to-Software-and-Hardware-Security.pdf
    before pasting verbatim §III text into the emitter docstring.
11. Begin implementation; update §12 Implementation log as work
    progresses (every milestone, every test failure, every source pin).

---
