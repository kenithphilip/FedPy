---
slice_id: T.T2
title: Per-Practice Evidence Aggregator + Satisfaction Matrix
loop: T
status: proposed
commit: TBD
completed_date: —
applicable_conditional: true
condition: any CSP delivering software to federal agencies subject to OMB M-22-18 / M-23-16 (or a post-M-26-05 agency tailored regime), OR a CSP whose DoD-prime customers consume LOOP-S.S1 equivalency artefacts that incorporate the SSDF satisfaction matrix as a sub-substrate
trigger_flag: "--ssdf-attestation"
trigger_env: CLOUD_EVIDENCE_SSDF_ATTESTATION
depends_on:
  - T.T1
  - LOOP-B.B1
  - LOOP-J.J2
  - LOOP-J.J3
  - "existing KSI evidence envelopes (LOOPs B through K)"
  - "core/envelope.ts (signed evidence envelope reader)"
  - "core/risk-score.ts (composite risk reader)"
  - "core/sbom.ts (SBOM reports)"
  - "core/cosign-verify.ts (build-pipeline attestation state)"
blocks:
  - T.T3
  - T.T4
estimated_effort: medium (5-6 working days)
last_updated: 2026-06-07
---

# T.T2 — Per-Practice Evidence Aggregator + Satisfaction Matrix

> Aggregate per-practice evidence by reading existing Key Security Indicator
> (KSI) evidence envelopes from LOOP-B through LOOP-K (plus LOOP-J supply-chain
> registers, LOOP-B risk scores, and SBOM / cosign verification state) and emit
> a per-practice × per-task satisfaction matrix with evidence pointers. The
> matrix is the data backbone of the CISA Common Form (T.T3) and the OMB
> M-22-18 paragraph III.E POA&M safety valve. T.T2 ships under the
> Real-Evidence-Only (REO) standard — every "satisfied" cell traces to at
> least one real, signed KSI envelope; every gap is surfaced as
> `requires-operator-input`.

## 1. Mission

T.T2's mission is to **join the SSDF catalogue produced by T.T1 with the
real evidence already collected by every prior loop** so that the
producer's posture against every SSDF practice and every SSDF task is
visible in a single canonical artefact. The producer's corporate officer
relies on this matrix to truthfully sign the CISA Common Form; a 3PAO or
federal-agency contracting officer relies on it to audit the attestation.

Concretely, T.T2:

1. **Loads the SSDF practices catalogue** emitted by T.T1
   (`data/ssdf-800-218-v1.1.json`) — 19 practices, 43 tasks, each with a
   `crosswalk_800_53_r5: string[]` field (Rev 5 control IDs the task
   maps to) and a `crosswalk_ksi: string[]` field (FedRAMP KSI IDs the
   task maps to).
2. **Walks the on-disk corpus of signed KSI evidence envelopes** under
   `out/ksi-evidence/*.json` (LOOPs B through K all emit envelopes
   through `core/envelope.ts`). Each envelope carries `ksi_id`,
   `evidence[]`, `findings[]`, `provenance`, and an Ed25519 signature.
3. **Reads four ancillary inputs**:
   - LOOP-B.B1 composite risk register (`out/risk-register.json`) →
     per-practice open-risk delta.
   - LOOP-J.J2 subprocessor inventory (`out/subprocessors.json`) →
     PO.1 / PW.4 organisational-scope evidence (the producer's
     third-party developer-tool subprocessors).
   - LOOP-J.J3 supply-chain risk register
     (`out/supply-chain-risk-register.json`) → PW.4 third-party
     component evidence.
   - LOOP-E.E2 SBOM reports + LOOP-J.J3.b cosign verification state
     (`out/sbom/*.json`, `out/cosign-verify.json`) → PS.2.1 / PW.6
     build-pipeline evidence.
4. **For each SSDF task**, computes:
   - `status` ∈ {`satisfied`, `partially-satisfied`, `not-satisfied`,
     `not-assessed`, `requires-operator-input`}
   - `evidence_pointers[]` — typed pointers (KSI envelope hash, OSCAL
     observation UUID, POA&M item UUID, SBOM report path, cosign
     verification result UUID, subprocessor inventory entry id, tracker
     process-artefact UUID)
   - `risk_score` — composite risk read from LOOP-B.B1 if any
     contributing risk-register row references the same evidence
   - `provenance` — sourceCalls listing every file path read, sha256
     digest, signature key id
5. **Rolls up to per-practice satisfaction** via the documented
   roll-up function (Algorithm §6): the practice status is the worst
   contributing task status with a `partially-satisfied` overlay when
   tasks are mixed.
6. **Emits two artefacts**:
   - `out/ssdf-satisfaction-matrix.json` — canonical JSON, signed via
     `core/sign.ts`, timestamped via `core/timestamp.ts`.
   - `out/ssdf-satisfaction-matrix.xlsx` — operator-readable workbook
     emitted via the existing OOXML/zip-store helper pattern used by
     `core/inventory-workbook.ts` (no new dependency).

T.T2 is a **pure aggregator**: it collects, joins, computes, emits. It
does not perform new evidence collection (that work belongs to LOOPs B
through K and to LOOP-J / LOOP-O). Every byte of the matrix traces back
to a real input file, and the provenance block lists every input path.

## 2. Authoritative sources (with verbatim quoted excerpts)

All sources accessed on **2026-06-07**. Where the published HTML/PDF
returned a non-200 status to the implementation session's WebFetch
attempt, the quoted text is taken from a CISA / OMB / NIST-authored
synthesis or the published Federal Register entry indexed on the same
date; the slice's implementation step (§6) records the SHA-256 of the
local source PDF before the slice ships.

### 2.1 Executive Order 14028 — Improving the Nation's Cybersecurity

- **Citation**: Executive Office of the President, Executive Order 14028,
  "Improving the Nation's Cybersecurity", May 12, 2021.
- **URL (pinned)**: https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/
- **Date of access**: 2026-06-07.
- **§4(e) — verbatim**:

  > "Within 90 days of the date of this order, the Secretary of Commerce
  > acting through the Director of NIST, in consultation with the heads
  > of such agencies as the Director of NIST deems appropriate, shall
  > issue guidance identifying practices that enhance the security of the
  > software supply chain. Such guidance may include standards,
  > procedures, or criteria regarding: (i) secure software development
  > environments, including such actions as: (A) using administratively
  > separate build environments; (B) auditing trust relationships;
  > (C) establishing multi-factor, risk-based authentication and
  > conditional access across the enterprise; ..."

- **§4(n) — verbatim**:

  > "Within 1 year of the date of this order, the Secretary of Homeland
  > Security, in consultation with the Attorney General, the Director of
  > the Office of Management and Budget, and the heads of such other
  > agencies as the Secretary deems appropriate, shall recommend to the
  > FAR Council contract language requiring suppliers of software
  > available for purchase by agencies to comply with, and attest to
  > complying with, any requirements issued pursuant to subsections (g)
  > through (k) of this section."

  EO 14028 §4(n) is the statutory taproot for the M-22-18 attestation
  obligation that T.T2's matrix substantiates. The matrix is the producer-
  side evidence base that lets the producer truthfully attest.

### 2.2 OMB Memorandum M-22-18 — Enhancing the Security of the Software Supply Chain through Secure Software Development Practices

- **Citation**: OMB, Memorandum M-22-18, "Enhancing the Security of the
  Software Supply Chain through Secure Software Development Practices",
  September 14, 2022.
- **URL (pinned)**: https://www.whitehouse.gov/wp-content/uploads/2022/09/M-22-18.pdf
- **Date of access**: 2026-06-07 (PDF anonymous fetch returned HTTP 404;
  the implementer downloads to
  `cloud-evidence/docs/sources/omb-m-22-18.pdf` and records the SHA-256
  before T.T2 ships).
- **Paragraph II (scope) — verbatim from publicly cited text**:

  > "This memorandum requires agencies to only use software provided by
  > software producers who can attest to complying with the
  > Government-specified secure software development practices, as
  > described in the NIST Guidance. Software subject to this memorandum
  > includes software developed after the effective date of this
  > memorandum, as well as existing software that is modified by major
  > version changes (e.g., using a semantic versioning schema of
  > Major.Minor.Patch, the software version number goes from 2.5 to 3.0)
  > after the effective date of this memorandum."

- **Paragraph III.E (POA&M safety valve) — verbatim**:

  > "In lieu of providing the required attestation in full, software
  > producers may identify those practices to which they cannot attest,
  > document practices they have in place to mitigate associated risks,
  > and provide an agency with a Plan of Action and Milestones (POA&M)."

  This is the source of the `requires-operator-input` /
  `not-satisfied` cells in T.T2's matrix flowing into T.T3's POA&M
  companion document. Without T.T2's per-task gap surfacing, the
  producer cannot cleanly enumerate the practices that need to land in
  the POA&M.

- **Paragraph III.D (third-party software)**:

  > "Where a software producer uses software produced by a third party
  > on which the producer relies, the third-party software producer
  > should provide an attestation; however, the software producer
  > remains responsible for the security of the third-party software."

  T.T2 reads LOOP-J.J2 / LOOP-J.J3 outputs precisely to honour this
  flow-down: third-party evidence enters as evidence pointers but the
  producer's own assertion is the matrix entry.

### 2.3 OMB Memorandum M-23-16 — Update to M-22-18

- **Citation**: OMB, Memorandum M-23-16, "Update to Memorandum M-22-18,
  Enhancing the Security of the Software Supply Chain through Secure
  Software Development Practices", June 9, 2023.
- **URL (pinned)**: https://www.whitehouse.gov/wp-content/uploads/2023/06/M-23-16-Update-to-M-22-18-Enhancing-Software-Supply-Chain-Security.pdf
- **Date of access**: 2026-06-07 (PDF download required;
  `docs/sources/omb-m-23-16.pdf`).
- **Paragraph II (Common Form anchor) — verbatim**:

  > "OMB and CISA, in consultation with agencies and other stakeholders,
  > have developed a standard self-attestation common form, to be used
  > by Federal agencies."

  T.T2 produces the satisfaction matrix that backs Section III of the
  Common Form (the four attestation statements). Without the matrix,
  Section III cannot be defended at audit.

### 2.4 NIST SP 800-218 v1.1 — Secure Software Development Framework

- **Citation**: NIST CSRC, Special Publication 800-218 v1.1, "Secure
  Software Development Framework (SSDF) Version 1.1: Recommendations
  for Mitigating the Risk of Software Vulnerabilities", February 2022.
- **URL (pinned)**: https://csrc.nist.gov/pubs/sp/800/218/final
- **PDF URL (pinned)**: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf
- **Excel companion (pinned)**: https://csrc.nist.gov/CSRC/media/Publications/sp/800-218/final/documents/NIST.SP.800-218.Table.xlsx
- **Date of access**: 2026-06-07 (PDF 722 KB confirmed; companion .xlsx
  consumed by T.T1's extractor; T.T2 reads the catalogue T.T1 emits).
- **Section 2 (practice-group definitions) — verbatim**:

  > "Prepare the Organization (PO): Organizations should ensure that
  > their people, processes, and technology are prepared to perform
  > secure software development at the organization level. Many
  > organizations will find some PO practices also applicable to
  > subsets of their software development, like individual development
  > groups or projects."

  > "Protect the Software (PS): Organizations should protect all
  > components of their software from tampering and unauthorized
  > access."

  > "Produce Well-Secured Software (PW): Organizations should produce
  > well-secured software with minimal security vulnerabilities in its
  > releases."

  > "Respond to Vulnerabilities (RV): Organizations should identify
  > residual vulnerabilities in their software releases and respond
  > appropriately to address those vulnerabilities and prevent similar
  > ones from occurring in the future."

  T.T2's matrix is organised primarily by practice group, then by
  practice, then by task — matching the catalogue's structure.

- **Task statement examples — verbatim from the published catalogue
  (subject to T.T1's extractor SHA-256 pin)**:

  > "PO.1.1 — Identify and document all security requirements for the
  > organization's software development infrastructures and processes,
  > and maintain the requirements over time."

  > "PS.1.1 — Store all forms of code — including source code,
  > executable code, and configuration-as-code — based on the principle
  > of least privilege so that only authorized personnel, tools,
  > services, etc. have access."

  > "PW.7.1 — Determine whether code review (a person directly looks at
  > the code to find issues) and/or code analysis (tools are used to
  > find issues in code, either in a fully automated way or in
  > conjunction with a person) should be used, as defined by the
  > organization."

  > "RV.1.1 — Gather information from software acquirers, users, and
  > public sources on potential vulnerabilities in the software and
  > third-party components that the software uses, and investigate all
  > credible reports."

  Each task is one row of the satisfaction matrix; T.T1's
  `crosswalk_ksi[]` field is the join key against the on-disk KSI
  evidence corpus.

### 2.5 NIST SP 800-218A — Secure Software Development Practices for Generative AI and Dual-Use Foundation Models

- **Citation**: NIST CSRC, Special Publication 800-218A, final published
  July 26, 2024.
- **URL (pinned)**: https://csrc.nist.gov/pubs/sp/800/218/a/final
- **PDF URL (pinned)**: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf
- **Date of access**: 2026-06-07.
- **Abstract — verbatim**:

  > "This document augments the secure software development practices
  > and tasks defined in SP 800-218, Secure Software Development
  > Framework (SSDF) Version 1.1. The augmentations are specific to AI
  > model development throughout the software development life cycle."

  T.T2's matrix is augmented by T.T5 when a product's
  `model_card.ai_use_case` is non-empty — the AI augmenter attaches
  800-218A tasks to the matching practice rows.

### 2.6 CISA Secure Software Development Attestation Common Form (OMB Control 1670-0052)

- **Citation**: CISA + OMB, "Secure Software Development Attestation
  Form", finalised March 11, 2024. OMB Control No. 1670-0052.
- **URL (pinned)**: https://www.cisa.gov/resources-tools/resources/secure-software-development-attestation-form
- **Form PDF (pinned)**: https://www.cisa.gov/sites/default/files/2024-04/Self_Attestation_Common_Form_FINAL_508c.pdf
- **Date of access**: 2026-06-07 (HTTP 403 to anonymous fetch; the
  implementer downloads to `docs/sources/cisa-common-form.pdf` and
  records the SHA-256).
- **Section III.1 (secure environment attestation) — verbatim**:

  > "The software was developed and built in secure environments. Those
  > environments were secured by the following actions, at a minimum:
  > (a) separating and protecting each environment involved in
  > developing and building software;
  > (b) regularly logging, monitoring, and auditing trust relationships
  > used for authorization and access (i) to any software development
  > and build environments; and (ii) among components within each
  > environment;
  > (c) enforcing multi-factor authentication and conditional access
  > across the environments relevant to developing and building software
  > in a manner that minimizes security risk;
  > (d) taking consistent and reasonable steps to document as well as
  > minimize use or inclusion of software products that create undue
  > risk within the environments used to develop and build software;
  > (e) encrypting sensitive data, such as credentials, to the extent
  > practicable and based on risk;
  > (f) implementing defensive cyber security practices, including
  > continuous monitoring of operations and alerts and, as necessary,
  > responding to suspected and confirmed cyber incidents."

  T.T2's matrix maps clause-by-clause to SSDF PO.5.\*, PS.1.\*,
  PO.3.\*, and PO.4.\*; the per-clause evidence pointer set is the
  audit-trail substrate the producer presents when defending the
  Section III.1 signature.

- **Section III.2 (trusted source-code supply chain) — verbatim**:

  > "The software producer has made a good-faith effort to maintain
  > trusted source code supply chains by employing automated tools or
  > comparable processes to address the security of internal code and
  > third-party components and manage related vulnerabilities."

  Maps to PW.4.\* + PS.2.\*; T.T2's matrix joins the LOOP-J.J3 register
  + SBOM-cosign state to these rows.

- **Section III.3 (provenance) — verbatim**:

  > "The software producer maintains provenance for internal code and
  > third-party components incorporated into the software to the
  > greatest extent feasible."

  Maps to PS.3.\* + PW.4.\*; T.T2 surfaces SBOM presence + cosign
  verification + Rekor entry references as the evidence chain.

- **Section III.4 (vulnerability management) — verbatim**:

  > "The software producer employed automated tools or comparable
  > processes that check for security vulnerabilities. In addition: (a)
  > the software producer operated these processes on an ongoing basis
  > and, at a minimum, prior to product, version, or update release;
  > (b) the software producer has a policy or process to address
  > discovered security vulnerabilities prior to product release; and
  > (c) the software producer operates a vulnerability disclosure
  > program and accepts, reviews, and addresses disclosed software
  > vulnerabilities in a timely fashion and according to any timelines
  > specified in the vulnerability disclosure program or applicable
  > policies."

  Maps to RV.1.\* + RV.2.\* + PW.7.\* + PW.8.\*; T.T2 reads the LOOP-E
  / LOOP-F vulnerability-management evidence envelopes for these rows.

### 2.7 NIST IR 8397 — Guidelines on Minimum Standards for Developer Verification of Software

- **Citation**: NIST IR 8397, October 2021.
- **URL (pinned)**: https://csrc.nist.gov/pubs/ir/8397/final
- **Date of access**: 2026-06-07.
- **Relevance**: IR 8397 enumerates the minimum verification techniques
  (static analysis, code review, dependency scanning, fuzzing) that
  satisfy SSDF PW.7 / PW.8. T.T2's evidence pointers for those
  practices cite the IR 8397 technique class so a 3PAO can trace each
  cell to the technique.

### 2.8 CISA Repository for Software Attestations and Artefacts (RSAA)

- **Citation**: CISA, "Repository for Software Attestations and
  Artefacts (RSAA)", March 18, 2024.
- **URL (pinned)**: https://www.cisa.gov/resources-tools/services/repository-software-attestations-and-artifacts-rsaa
- **User Guide PDF (pinned)**: https://www.cisa.gov/sites/default/files/2024-03/CISA_RSAA_User_Guide_18_March_2024.pdf
- **Date of access**: 2026-06-07.
- **Relevance to T.T2**: RSAA consumers (federal agency reviewers)
  will look at the satisfaction matrix that backs the Common Form;
  T.T2's matrix shape is sized to RSAA's reviewer needs (per-practice
  view + drill-down to evidence pointer).

## 3. Scope

### In scope

- Loading the T.T1 SSDF catalogue (`data/ssdf-800-218-v1.1.json`).
- Walking `out/ksi-evidence/*.json` (every signed KSI envelope) and
  joining each task's `crosswalk_ksi[]` to the envelope corpus by
  `ksi_id`.
- Walking `out/ssp-components.json` (LOOP-A) and joining each task's
  `crosswalk_800_53_r5[]` to component-mapped controls — this provides
  the **secondary** join path when a task has no KSI crosswalk (e.g.
  organisational-policy practices).
- Reading LOOP-B risk register, LOOP-J subprocessor + supply-chain risk
  registers, SBOM reports, cosign verification state.
- Computing per-task status, per-task evidence pointers, per-task risk
  delta.
- Rolling up to per-practice satisfaction.
- Emitting `out/ssdf-satisfaction-matrix.json` (signed + timestamped)
  and `out/ssdf-satisfaction-matrix.xlsx` (operator-readable workbook).
- Honouring the REO standard: every `satisfied` cell traces to a real
  signed envelope; every gap is `requires-operator-input`; never
  `silent-pass`.

### Out of scope

- Rendering the CISA Common Form PDF (T.T3 owns).
- Emitting the OSCAL POA&M companion (T.T3 owns).
- Tracker-DB per-agency submission registry (T.T4 owns).
- 800-218A AI extension augmentation (T.T5 owns; T.T2 emits a stable
  hook that T.T5 attaches to without modifying T.T2 sources).
- Collecting new evidence from cloud SDKs (LOOPs B through K own).
- Acting on behalf of the producer's officer (REO Rule 1 prohibition
  #6; T.T2 emits matrices, not signatures).

## 4. Inputs (exact data structures, schema references)

T.T2 reads the following input files; every read is recorded in
`provenance.sourceCalls[]` with path + sha256 + signature key id.

| # | Input file | Producer | Required? | Schema reference |
|---|---|---|---|---|
| 1 | `data/ssdf-800-218-v1.1.json` | T.T1 catalogue | required | T.T1 `SsdfCatalog` |
| 2 | `out/ksi-evidence/*.json` (1..N) | LOOPs B..K via `core/envelope.ts` | required (≥1 envelope) | `KsiEvidenceEnvelope` (existing) |
| 3 | `out/ssp-components.json` | LOOP-A SSP emitter | required | OSCAL SSP v1.1.2 |
| 4 | `out/risk-register.json` | LOOP-B.B1 | optional (falls through if absent) | LOOP-B `RiskRegister` |
| 5 | `out/subprocessors.json` | LOOP-J.J2 | optional | LOOP-J `SubprocessorInventory` |
| 6 | `out/supply-chain-risk-register.json` | LOOP-J.J3 | optional | LOOP-J `SupplyChainRegister` |
| 7 | `out/sbom/*.json` (1..N) | LOOP-E.E2 | optional | CycloneDX / SPDX |
| 8 | `out/cosign-verify.json` | LOOP-J.J3.b (engineering attestation) | optional | LOOP-J cosign verification result |
| 9 | `out/control-benchmark.json` | benchmark emitter (existing) | optional | `ControlBenchmark` |
| 10 | `out/poam.json` | LOOP-A.A1 | optional | OSCAL POA&M v1.1.2 |
| 11 | `tracker.db` | tracker | required when T.T1 catalogue has tracker-only tasks | Tracker process-artefact rows |
| 12 | `config.yaml` (`ssdf` section) | operator | required | T.T2 `SsdfMatrixConfig` (defined §5) |

When an optional file is absent, the matrix flags the affected
practice / task with the diagnostic `coverage:partial — <input>`
in the provenance block; the cell status is computed from whatever
inputs are present.

### Input shape — `KsiEvidenceEnvelope` (existing, reused unchanged)

```ts
export interface KsiEvidenceEnvelope {
  ksi_id: string;                   // "KSI-IAM-MFA"
  collected_at: string;             // ISO 8601
  provider: 'aws' | 'gcp' | 'azure';
  evidence: Array<{
    kind: string;                   // "iam-policy", "cloudtrail-event", ...
    source_call: { sdk: string; api: string; resource_arn: string };
    sha256: string;
    bytes: number;
    storage_uri: string;
  }>;
  findings: Array<{
    finding_id: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    title: string;
    description: string;
  }>;
  provenance: { signing_key_id: string; timestamp_rfc3161: string };
  signature: { algorithm: 'ed25519'; signer: string; signature: string };
}
```

T.T2 reads `ksi_id` (join key), `provenance.signing_key_id`,
`provenance.timestamp_rfc3161`, and a small projection of `evidence[]`
(specifically `evidence[].source_call.api` + `evidence[].sha256` for
the matrix's `evidence_pointers[].evidence_sha256`).

### Input shape — T.T1 `SsdfCatalog` (depends_on)

```ts
export interface SsdfCatalog {
  source: { sp: '800-218'; version: '1.1'; publication_date: '2022-02';
            pdf_sha256: string; xlsx_sha256: string };
  practice_groups: Array<{ id: 'PO' | 'PS' | 'PW' | 'RV'; name: string;
                          statement: string }>;
  practices: Array<{
    id: string;                     // "PO.1"
    group: 'PO' | 'PS' | 'PW' | 'RV';
    name: string;
    outcome: string;                // NIST-published outcome statement
    tasks: Array<{
      id: string;                   // "PO.1.1"
      statement: string;            // verbatim
      crosswalk_800_53_r5: string[];
      crosswalk_ksi: string[];      // ["KSI-IAM-MFA", "KSI-IAM-ELP", ...]
      crosswalk_common_form_clause: string[];  // ["III.1.c", ...]
      requires_process_artefact: boolean;
    }>;
  }>;
}
```

The catalogue is loaded once at startup; T.T2 asserts the published
counts (19 practices, 43 tasks, 4 groups).

### Input shape — `SsdfMatrixConfig` (operator-supplied, in `config.yaml`)

```yaml
ssdf:
  regime: m-22-18-mandatory | m-23-16-extended | m-26-05-tailored | post-m-26-05-future
  products:
    - id: csp-platform-2026
      name: "Acme CSP Platform"
      ai_enabled: false
      critical_software: false
      applicability_evidence:                # required; at least one
        - kind: contract
          contract_id: "GS-35F-1234A"
          customer: "GSA"
        - kind: agency-tailoring
          regime: m-26-05-tailored
          agency: "DOE"
      major_version_pattern: '^(\d+)\.0\.0$'
  ksi_to_product_map:                        # optional override
    KSI-IAM-MFA: [csp-platform-2026]
    KSI-CSX-LOG: [csp-platform-2026]
```

T.T2's matrix is emitted **once per product**; the `ksi_to_product_map`
allows the operator to scope KSI evidence to specific products when a
shared platform serves multiple product attestations.

## 5. Outputs (canonical JSON, .xlsx layout, provenance, signed envelope)

### 5.1 Canonical JSON — `out/ssdf-satisfaction-matrix.json`

```ts
export interface SsdfSatisfactionMatrix {
  schema_version: '1.0';
  matrix_id: string;                // uuid v4, deterministic per run
  generated_at: string;             // ISO 8601
  csp_name: string;
  product: {
    id: string;                     // "csp-platform-2026"
    name: string;
    ai_enabled: boolean;
    critical_software: boolean;
  };
  catalogue_source: {
    sp: '800-218';
    version: '1.1';
    publication_date: '2022-02';
    pdf_sha256: string;
    xlsx_sha256: string;
  };
  totals: {
    practices: number;              // expect 19
    tasks: number;                  // expect 43
    practices_by_status: Record<PracticeStatus, number>;
    tasks_by_status: Record<TaskStatus, number>;
  };
  practices: SsdfPracticeRow[];
  provenance: ProvenanceBlock;
}

export type TaskStatus =
  | 'satisfied'
  | 'partially-satisfied'
  | 'not-satisfied'
  | 'not-assessed'
  | 'requires-operator-input';

export type PracticeStatus = TaskStatus; // identical enum

export interface SsdfPracticeRow {
  id: string;                       // "PO.1"
  group: 'PO' | 'PS' | 'PW' | 'RV';
  name: string;
  outcome: string;
  status: PracticeStatus;
  open_risk_score: number | null;   // composite from LOOP-B.B1; null if absent
  tasks: SsdfTaskRow[];
}

export interface SsdfTaskRow {
  id: string;                       // "PO.1.1"
  statement: string;
  status: TaskStatus;
  crosswalk_800_53_r5: string[];
  crosswalk_ksi: string[];
  crosswalk_common_form_clause: string[];
  evidence_pointers: SsdfEvidencePointer[];
  diagnostics: string[];            // e.g. ["coverage:partial: cosign-verify.json absent"]
}

export type SsdfEvidencePointer =
  | { kind: 'ksi-envelope'; ksi_id: string; envelope_sha256: string;
      signing_key_id: string; timestamp_rfc3161: string;
      source_path: string }
  | { kind: 'oscal-observation'; observation_uuid: string;
      source_path: string }
  | { kind: 'oscal-poam-item'; poam_item_uuid: string;
      source_path: string }
  | { kind: 'sbom'; sbom_format: 'cyclonedx' | 'spdx';
      sbom_sha256: string; source_path: string }
  | { kind: 'cosign-verify'; subject_digest: string;
      rekor_log_index: number | null; source_path: string }
  | { kind: 'subprocessor-inventory'; subprocessor_id: string;
      source_path: string }
  | { kind: 'supply-chain-risk-register-row'; row_id: string;
      source_path: string }
  | { kind: 'tracker-artefact'; artefact_uuid: string;
      tracker_uri: string };
```

### 5.2 Provenance block (REO Rule 2.6)

```ts
export interface ProvenanceBlock {
  emitter: 'ssdf-evidence-aggregator';
  emitter_version: string;          // semver
  emitted_at: string;
  source_calls: Array<{
    kind: 'ssdf-catalog' | 'ksi-envelope' | 'risk-register'
          | 'subprocessor-inventory' | 'supply-chain-risk-register'
          | 'sbom' | 'cosign-verify' | 'control-benchmark'
          | 'oscal-poam' | 'ssp-components' | 'tracker';
    path: string;
    sha256: string;
    signature_verified: boolean;    // true if signed envelope verified
  }>;
  signing_key_id: string;
  timestamp_rfc3161: string;
}
```

### 5.3 XLSX layout — `out/ssdf-satisfaction-matrix.xlsx`

Two worksheets:

**Sheet 1 — "Per-Task Matrix"** (one row per SSDF task, 43 rows + header):
| Col | Header | Source |
|---|---|---|
| A | Group | Practice group (PO/PS/PW/RV) |
| B | Practice ID | "PO.1" |
| C | Practice Name | NIST published name |
| D | Task ID | "PO.1.1" |
| E | Task Statement | verbatim from catalogue |
| F | Status | TaskStatus enum value |
| G | 800-53 r5 Controls | comma-joined |
| H | KSI IDs | comma-joined |
| I | Common Form Clause(s) | comma-joined (e.g. "III.1.c") |
| J | Evidence Pointer Count | integer |
| K | Evidence Pointer Summary | semicolon-joined "kind:source_path" |
| L | Diagnostics | semicolon-joined |
| M | Open Risk (B.1 composite) | numeric or "n/a" |

**Sheet 2 — "Per-Practice Summary"** (one row per SSDF practice, 19 rows
+ header):
| Col | Header | Source |
|---|---|---|
| A | Group | PO/PS/PW/RV |
| B | Practice ID | "PO.1" |
| C | Practice Name | NIST published name |
| D | Outcome | verbatim |
| E | Practice Status | rolled-up status |
| F | Task Count | integer |
| G | Tasks Satisfied | integer |
| H | Tasks Partially Satisfied | integer |
| I | Tasks Not Satisfied | integer |
| J | Tasks Not Assessed | integer |
| K | Tasks Requires Operator Input | integer |
| L | Practice Open Risk Score | numeric |

Header rows are bold + frozen; column widths match the existing
`core/inventory-workbook.ts` styling helpers (no new dependency).

### 5.4 Signed envelope structure

Both JSON and xlsx outputs flow through the existing signing pipeline
in `core/sign.ts`:

```jsonc
{
  "artefact": "out/ssdf-satisfaction-matrix.json",
  "sha256": "<hex>",
  "signature": {
    "algorithm": "ed25519",
    "signer": "fedpy-evidence-bot",
    "signing_key_id": "<key-id>",
    "signature": "<base64>"
  },
  "timestamp_rfc3161": {
    "tsa_url": "<tsa>",
    "timestamp_token": "<base64>"
  }
}
```

The manifest entry sits in `out/manifest.json` alongside every other
emitted artefact.

## 6. Algorithm / Steps (numbered, deterministic, REO-compliant)

T.T2 is implemented as a pure function from typed inputs to typed
outputs. The implementation MUST be deterministic — given the same
inputs, the matrix's `matrix_id` (uuid v5 over the canonical JSON of
inputs), per-task `status`, per-task `evidence_pointers[]`, and totals
are identical.

### Step 1 — Load and validate the SSDF catalogue

1. Read `data/ssdf-800-218-v1.1.json`.
2. Assert `catalogue.source.pdf_sha256` matches
   `docs/sources/nist-sp-800-218.sha256` (the pinned NIST hash). On
   mismatch, throw `SsdfCatalogTamperError`.
3. Assert `practices.length === 19` and the union of
   `practices.flatMap(p => p.tasks).length === 43`.
4. Assert every task carries `crosswalk_800_53_r5: string[]` AND
   `crosswalk_ksi: string[]` (the join keys). Empty arrays are
   permitted (some PO tasks have no KSI crosswalk and rely on
   process-artefact tracker rows).

### Step 2 — Load operator config

1. Read `config.yaml`'s `ssdf` block. Validate against the
   `SsdfMatrixConfig` schema (ajv-driven).
2. Resolve the per-product matrix to emit. If multiple products are
   configured, the orchestrator calls T.T2 once per product.
3. Honour `ksi_to_product_map` overrides if present.

### Step 3 — Walk the KSI evidence corpus

1. Glob `out/ksi-evidence/*.json`.
2. For each file:
   - Verify the envelope's Ed25519 signature via
     `core/envelope.verify()`.
   - On signature failure, raise `EnvelopeSignatureError` (FATAL —
     T.T2 refuses to ship a matrix with unverifiable evidence).
   - Otherwise, index the envelope by `ksi_id`.
3. Build `ksiByEnvelope: Map<string, KsiEvidenceEnvelope[]>` (a single
   KSI may have multiple envelopes across providers / time).

### Step 4 — Load ancillary inputs

For each optional input file (LOOP-B risk register, LOOP-J inventories
+ register, SBOM reports, cosign verify state, OSCAL POA&M, OSCAL SSP
components, control benchmark):

1. If file exists, parse + validate against published schema.
2. If absent, log `coverage:partial — <input>` diagnostic; continue.
3. Build typed indices for cross-referencing in step 5.

### Step 5 — Build per-task evidence-pointer set

For each `task` in `catalogue.practices.flatMap(p => p.tasks)`:

1. Initialise `evidencePointers: SsdfEvidencePointer[] = []`.
2. For each `ksi_id` in `task.crosswalk_ksi`:
   - Look up envelopes in `ksiByEnvelope.get(ksi_id)`.
   - For each envelope, push pointer
     `{ kind: 'ksi-envelope', ksi_id, envelope_sha256, signing_key_id,
        timestamp_rfc3161, source_path }`.
3. If `task.crosswalk_800_53_r5` is non-empty AND we have OSCAL POA&M
   loaded:
   - For each control id, look up POA&M observations whose
     `related-observations[].subject-refs[]` reference the control.
   - Push `{ kind: 'oscal-observation', observation_uuid, source_path }`.
   - For each POA&M item whose `related-observations[]` matches, push
     `{ kind: 'oscal-poam-item', poam_item_uuid, source_path }`.
4. If `task.id` matches the documented PS.2 / PW.6 set AND SBOM /
   cosign-verify are loaded:
   - For each SBOM report, push `{ kind: 'sbom', sbom_format, sbom_sha256,
     source_path }`.
   - For each cosign verification result, push `{ kind: 'cosign-verify',
     subject_digest, rekor_log_index, source_path }`.
5. If `task.id` matches PO.1 / PW.4 AND subprocessor inventory loaded:
   - For each subprocessor whose `roles[]` intersects with developer-tool
     roles, push `{ kind: 'subprocessor-inventory', subprocessor_id,
     source_path }`.
6. If `task.id` matches PW.4 AND supply-chain risk register loaded:
   - For each register row, push `{ kind: 'supply-chain-risk-register-row',
     row_id, source_path }`.
7. If `task.requires_process_artefact` AND tracker is loaded:
   - Query `tracker.process_artefacts` for rows whose `ssdf_task_id`
     matches. Push `{ kind: 'tracker-artefact', artefact_uuid,
     tracker_uri }`.

### Step 6 — Compute per-task status

Given the evidence-pointer set built in step 5:

```text
if (task.crosswalk_ksi.length === 0 AND task.requires_process_artefact AND
    no tracker-artefact pointer):
  status = 'requires-operator-input'
elif (evidencePointers.length === 0):
  status = 'requires-operator-input'             # REO Rule: never silent-pass
elif (any ksi-envelope pointer carries a finding with severity 'high' or
      'critical'):
  status = 'not-satisfied'
elif (any pointer is a POA&M item):
  status = 'partially-satisfied'                 # there is an open POA&M
elif (all ksi-envelope pointers verified AND no high/critical findings AND
      no open POA&M reference):
  status = 'satisfied'
else:
  status = 'not-assessed'                        # mixed / inconclusive
```

The status function is pure; tests pin every branch (see §8).

### Step 7 — Compute per-task open-risk score

If `out/risk-register.json` is loaded:

1. For each evidence pointer of kind `ksi-envelope`, look up the
   composite risk score in the register keyed by `ksi_id`.
2. The task's `open_risk_score = max(risk_scores)`.

If absent or no contributing pointer carries a risk score, the field
is `null`.

### Step 8 — Roll up per-practice

For each practice in the catalogue:

1. Compute `practice.tasks_by_status: Record<TaskStatus, number>`.
2. Practice-level status is the worst contributing task status, with
   `partially-satisfied` overlaid when tasks are mixed:

```text
if (tasks_by_status.not-satisfied > 0):
  status = 'not-satisfied'
elif (tasks_by_status.requires-operator-input > 0):
  status = 'requires-operator-input'
elif (tasks_by_status.not-assessed > 0):
  status = 'not-assessed'
elif (tasks_by_status.partially-satisfied > 0):
  status = 'partially-satisfied'
else:
  status = 'satisfied'
```

3. Practice-level open-risk score = `max(task.open_risk_score)` skipping
   `null`s.

### Step 9 — Compute totals and assemble the matrix

1. `totals.practices = 19`, `totals.tasks = 43`.
2. `totals.practices_by_status = countBy(practices, 'status')`.
3. `totals.tasks_by_status = countBy(flatTasks, 'status')`.

### Step 10 — Emit `ssdf-satisfaction-matrix.json` + sign + timestamp

1. Canonicalise the matrix JSON via `core/canonical-json.ts` (sorted
   keys, no whitespace).
2. Compute SHA-256.
3. Sign via `core/sign.ts` (Ed25519).
4. Timestamp via `core/timestamp.ts` (RFC 3161).
5. Append to `out/manifest.json`.

### Step 11 — Emit `ssdf-satisfaction-matrix.xlsx`

1. Build OOXML/zip-store workbook via the existing
   `core/xlsx-helpers.ts` pattern (no new dependency).
2. Write sheet 1 (per-task) and sheet 2 (per-practice summary) per §5.3.
3. Sign + timestamp identically to the JSON.

### Step 12 — Coverage diagnostics

If any practice carries
`status === 'requires-operator-input' || status === 'not-assessed'`,
log a `coverage:miss` line per practice with the task ids and
suggested remediation (e.g. "PO.1.1 — capture process artefact under
tracker; visit /ssdf/process-artefacts/PO.1.1").

### Step 13 — Validate against REO guardrails

Before exiting:

1. `npm run check:ssdf-no-silent-pass` MUST pass (every `satisfied` row
   has `evidence_pointers.length > 0`).
2. `npm run check:provenance` MUST pass (provenance block on JSON).
3. `npm run lint:no-stubs` MUST be clean.

## 7. Files to create / modify (absolute paths)

### Create

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ssdf-evidence-aggregator.ts`
  — pure aggregator module. ~640 lines. Exports
  `buildSsdfSatisfactionMatrix(): Promise<SsdfSatisfactionMatrix>`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ssdf-satisfaction-matrix.ts`
  — matrix typedef + canonicalisation + JSON / xlsx emitters. ~420
  lines. Exports `emitSatisfactionMatrix()` (writes JSON), `emitSatisfactionMatrixXlsx()`
  (writes xlsx).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/ssdf-evidence-aggregator.test.ts`
  — unit + integration tests. ≥15 tests per §8.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/ssdf-satisfaction-matrix.test.ts`
  — xlsx renderer tests. ≥5 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/ssdf/`
  — fixture corpus: sample catalogue, sample envelope corpus, sample
  POA&M, sample subprocessor inventory, sample SBOM, sample cosign
  state, sample risk register; expected matrix JSON for golden tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/scripts/check-ssdf-no-silent-pass.mjs`
  — REO guardrail: asserts every `satisfied` row has ≥1 evidence
  pointer.

### Modify

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`
  — when `--ssdf-attestation` flag is set (or
  `CLOUD_EVIDENCE_SSDF_ATTESTATION=true`), after the catalogue is
  loaded (T.T1) AND after every per-loop emitter has run (B..K), call
  `buildSsdfSatisfactionMatrix()` per product in
  `ssdf.products[]`. Persist resulting JSON + xlsx via the existing
  artefact-writer flow.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
  — add two `WELL_KNOWN` roles:
  - `ssdf-satisfaction-matrix-json` → `ssdf-satisfaction-matrix.json`
  - `ssdf-satisfaction-matrix-xlsx` → `ssdf-satisfaction-matrix.xlsx`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/package.json`
  — add `check:ssdf-no-silent-pass` script entry; wire into
  `check:reo` aggregate target.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/CHANGELOG.md` —
  "Unreleased" → `### Added — LOOP-T.T2: …` block.

## 8. Test specifications (≥15)

Fixtures live under
`/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/ssdf/`.

| id | scenario | fixture path | expected | acceptance |
|---|---|---|---|---|
| T2-1 | load T.T1 catalogue and assert published counts | `fixtures/ssdf/catalogue/ssdf-800-218-v1.1.json` | 19 practices, 43 tasks, 4 groups | `matrix.totals.practices === 19 && matrix.totals.tasks === 43` |
| T2-2 | reject catalogue whose `pdf_sha256` does not match the pinned hash | `fixtures/ssdf/catalogue/tampered.json` | throw `SsdfCatalogTamperError` | error message includes both hashes |
| T2-3 | join one task to one verified KSI envelope ⇒ status `satisfied` | `fixtures/ssdf/case-satisfied/` | `tasks[PO.5.1].status === 'satisfied'` | exactly 1 `ksi-envelope` pointer |
| T2-4 | task with `high`-severity finding ⇒ status `not-satisfied` | `fixtures/ssdf/case-not-satisfied/` | `tasks[PW.7.1].status === 'not-satisfied'` | finding propagates into pointer set |
| T2-5 | task with open POA&M item ⇒ status `partially-satisfied` | `fixtures/ssdf/case-partial/` | `tasks[RV.1.1].status === 'partially-satisfied'` | one `oscal-poam-item` pointer |
| T2-6 | task with no evidence pointers ⇒ status `requires-operator-input` (no silent pass) | `fixtures/ssdf/case-no-evidence/` | `tasks[PO.1.1].status === 'requires-operator-input'` | `evidence_pointers.length === 0`, status set, REO guardrail green |
| T2-7 | per-practice roll-up: any `not-satisfied` task ⇒ practice `not-satisfied` | `fixtures/ssdf/case-rollup-worst/` | `practices[PW.7].status === 'not-satisfied'` | logic in step 8 verified |
| T2-8 | per-practice roll-up: tasks mixed satisfied + partially ⇒ practice `partially-satisfied` | `fixtures/ssdf/case-rollup-mixed/` | `practices[RV.1].status === 'partially-satisfied'` | per-practice counts populated |
| T2-9 | per-practice roll-up: all satisfied ⇒ practice `satisfied` | `fixtures/ssdf/case-rollup-all-satisfied/` | `practices[PS.2].status === 'satisfied'` | counts: all satisfied, others 0 |
| T2-10 | refuse to ingest envelope with bad signature | `fixtures/ssdf/case-bad-sig/` | throw `EnvelopeSignatureError` | error names the offending file |
| T2-11 | attach SBOM + cosign pointers when present for PS.2 / PW.6 tasks | `fixtures/ssdf/case-sbom-cosign/` | pointers of kinds `sbom`, `cosign-verify` appear | one of each, paths recorded |
| T2-12 | attach subprocessor + supply-chain register pointers for PW.4 / PO.1 | `fixtures/ssdf/case-subproc-scrm/` | pointers of kinds `subprocessor-inventory`, `supply-chain-risk-register-row` appear | source paths recorded |
| T2-13 | emit `coverage:partial` diagnostic when LOOP-B risk register absent | `fixtures/ssdf/case-no-risk-register/` | diagnostic appears in log + provenance | matrix still emitted; risk scores `null` |
| T2-14 | emit deterministic `matrix_id` (uuid v5 over canonical input JSON) for identical inputs | `fixtures/ssdf/case-determinism/` | two runs ⇒ same `matrix_id` | byte-equal canonical JSON |
| T2-15 | provenance block lists every source file read with sha256 | `fixtures/ssdf/case-provenance/` | `provenance.source_calls[].sha256` defined for each entry | sourceCalls non-empty |
| T2-16 | xlsx sheet 1 has 43 task rows + header; sheet 2 has 19 practice rows + header | `fixtures/ssdf/case-xlsx/` | SheetJS round-trip count match | round-trip read confirms row counts |
| T2-17 | xlsx column M ("Open Risk") populated for tasks with composite score | `fixtures/ssdf/case-xlsx-risk/` | column M numeric for ≥1 row | round-trip confirms cell value |
| T2-18 | per-product scoping: `ksi_to_product_map` excludes KSI for a product ⇒ pointer absent from that product's matrix | `fixtures/ssdf/case-product-scope/` | KSI envelope not in matrix B but present in matrix A | two matrices produced; diff verified |
| T2-19 | orchestrator emits matrix only when `--ssdf-attestation` set (off by default) | `fixtures/ssdf/orchestrator-off/` | no `ssdf-satisfaction-matrix.json` in `out/` | smoke run without flag |
| T2-20 | `--ssdf-attestation` honours `CLOUD_EVIDENCE_SSDF_ATTESTATION=true` env | `fixtures/ssdf/orchestrator-env/` | matrix emitted under env-driven trigger | env-only run produces matrix |
| T2-21 | check:ssdf-no-silent-pass refuses to certify a matrix whose `satisfied` row has zero pointers | `fixtures/ssdf/regression-silent-pass.json` | guardrail exits non-zero | error message names task id |
| T2-22 | integration: end-to-end run with full LOOPs B..K envelope corpus → matrix → signed bundle → unbundle → verify | `fixtures/ssdf/integration-e2e/` | round-trip verify succeeds | bundle contains both `WELL_KNOWN` roles |
| T2-23 | cross-loop: T.T2 matrix consumed by S.S1's NIST 800-171 crosswalk for SR (supply-chain) requirements | `fixtures/ssdf/integration-loop-s/` | S.S1 reads matrix without parse error | S.S1's crosswalk includes T.T2 evidence pointers |
| T2-24 | catalogue task with empty `crosswalk_ksi[]` and `requires_process_artefact: true` AND missing tracker row ⇒ status `requires-operator-input` with tracker-link diagnostic | `fixtures/ssdf/case-process-artefact-missing/` | task status + diagnostic recorded | diagnostic message references `/ssdf/process-artefacts/<task_id>` |

Minimum **24 tests** authored; 15 is the floor, this slice exceeds.

## 9. Risks (≥4)

### T2-R1 — Catalogue / envelope schema drift (severity HIGH)

- **Risk**: T.T1 publishes a catalogue revision with new tasks or
  renamed fields; T.T2 reads stale fields and crashes or silently
  drops evidence.
- **Detection**: T.T1's catalogue carries a `schema_version` field; T.T2
  asserts compatibility on load.
- **Mitigation**: pin `schema_version` in code; on mismatch, T.T2 fails
  fast with `SsdfCatalogSchemaMismatchError`. Bump T.T2's
  `emitter_version` when consuming a new catalogue version.
- **Residual exposure**: low — T.T1 owns the catalogue and ships
  versioned; the type-system enforces structural compatibility at
  compile time.

### T2-R2 — Silent pass on missing evidence (severity HIGH; REO-critical)

- **Risk**: A task with `crosswalk_ksi: []` (e.g. PO.2.1, an
  organisational-policy practice) might be inadvertently marked
  `satisfied` because the algorithm has no evidence to invalidate.
  This is the canonical REO-violation pattern.
- **Detection**: REO guardrail
  `npm run check:ssdf-no-silent-pass` asserts every `satisfied` row has
  ≥1 evidence pointer.
- **Mitigation**: Algorithm step 6 explicitly checks
  `evidencePointers.length === 0 ⇒ 'requires-operator-input'` BEFORE
  any pass branch fires. Tests T2-6, T2-21, and T2-24 pin this.
- **Residual exposure**: zero — guardrail blocks CI; tests block
  regressions.

### T2-R3 — Per-product cross-contamination (severity MEDIUM)

- **Risk**: When a CSP runs T.T2 for multiple products, KSI evidence
  from product A is misattributed to product B (shared platform KSIs
  legitimately apply to both; product-specific KSIs do not).
- **Detection**: Fixture corpus includes a two-product run; tests T2-18
  pin per-product scoping.
- **Mitigation**: `SsdfMatrixConfig.ksi_to_product_map` allows
  per-product KSI scoping. Default behaviour: all KSI envelopes apply
  to all products (the CSP's posture is platform-wide); the operator
  may override per product.
- **Residual exposure**: low — operator review of per-product matrices
  catches mismatches.

### T2-R4 — Envelope signature verification failure under offline runs

- **Risk**: A producer running T.T2 in an offline / air-gapped
  environment may not have current TSA / CA bundles; envelope
  verification fails on cert-chain validation.
- **Detection**: `EnvelopeSignatureError` raised in step 3.
- **Mitigation**: T.T2 reads the locally-pinned trust store at
  `tracker/storage/trust/ca-bundle.pem` and the locally-cached TSA
  responses; the verification step is offline-safe when these are
  current.
- **Residual exposure**: low — air-gapped runs document the trust
  store refresh as an operational prerequisite.

### T2-R5 — POA&M overlap double-count (severity MEDIUM)

- **Risk**: An open POA&M item for a Rev 5 control referenced by
  multiple tasks (e.g. AC-2 referenced by PO.5.1 + PS.1.1) gets
  pushed as a pointer to both tasks; the matrix double-attributes the
  same evidence.
- **Detection**: Test T2-11 pins single-attribution per pointer kind.
- **Mitigation**: Pointer set is task-scoped, not matrix-global; the
  same POA&M item appearing on two tasks is **correct behaviour** —
  the POA&M genuinely contributes to both. The matrix's `totals` are
  computed from per-task statuses, not from raw pointer counts, so
  there is no double-count in the totals. The xlsx column J ("Evidence
  Pointer Count") is per-task; the audit-trail consumer can verify by
  inspecting paths.
- **Residual exposure**: zero — by design.

### T2-R6 — Catalogue task statement encoding mismatch (severity LOW)

- **Risk**: T.T1's catalogue extractor produces task statements with
  one Unicode normalisation (NFC); T.T3's PDF renderer expects another
  (NFKC). Statements render incorrectly in the PDF.
- **Detection**: Cross-loop integration test
  `tests/integration/loop-t-ssdf-roundtrip.test.ts` verifies catalogue
  text equals PDF text.
- **Mitigation**: All textual transit in T.T2 is NFC; T.T3 normalises
  inbound to NFC before rendering.
- **Residual exposure**: low.

## 10. Open questions

1. **Q-T2-1**: When a task's `crosswalk_ksi[]` contains a KSI that LOOPs
   B..K have not yet implemented (e.g. a planned KSI), should T.T2
   silently skip the unresolvable join or emit a diagnostic? **Proposed
   resolution**: emit `coverage:partial — unknown-ksi:<id>` diagnostic
   AND treat the task as if the KSI is absent (no pointer added). This
   surfaces the planning gap without blocking the matrix.
2. **Q-T2-2**: Should the matrix include cross-product evidence — i.e.
   KSI envelopes from a shared platform that legitimately apply to
   multiple products? **Proposed resolution**: yes, by default; the
   operator overrides via `ksi_to_product_map`. A future T.T2 extension
   could honour per-KSI tags `applies_to: [product_id, ...]` on the
   envelope itself.
3. **Q-T2-3**: How does T.T2 handle tasks whose evidence is partially
   tracker-resident and partially KSI-resident? **Proposed resolution**:
   pointers of both kinds appear in `evidence_pointers[]`; the
   roll-up logic in step 6 treats them uniformly (a single pointer of
   any kind is sufficient for the algorithm's `length > 0` branch).
4. **Q-T2-4**: The matrix carries no human signature; T.T3 packages it
   into the Common Form which is signed by the producer's officer.
   Should T.T2 emit an "interim signature" by the build-system key?
   **Proposed resolution**: yes — every emitted artefact rides the
   Ed25519 + RFC 3161 pipeline regardless. The interim signature
   verifies *machine integrity from emit to consumer*; the Common Form
   PDF carries the producer's officer signature for *producer
   attestation to the agency*.
5. **Q-T2-5**: How does T.T2 handle a future SP 800-218 Rev 2 (currently
   IPD)? **Proposed resolution**: T.T1's extractor regenerates the
   catalogue; T.T2 honours the new `schema_version`; the matrix's
   `catalogue_source.version` field records which revision the run
   used. Multiple revisions can be emitted in parallel (one matrix
   each) during transition.

## 11. REQUIRES-OPERATOR-INPUT fields

| Field name | Type | Validator | UI location | Failure mode if missing |
|---|---|---|---|---|
| `ssdf.regime` | enum (`m-22-18-mandatory`/`m-23-16-extended`/`m-26-05-tailored`/`post-m-26-05-future`) | ajv schema in `config-schema.ts` | tracker → `/ssdf/products` settings | T.T2 exits 0 with `coverage:skipped — ssdf-regime-unset`; matrix not emitted |
| `ssdf.products[].id` | string (slug) | ajv pattern `^[a-z0-9-]+$` | tracker → `/ssdf/products/new` | T.T2 refuses to emit for product without id |
| `ssdf.products[].applicability_evidence[]` | array of `{ kind, contract_id?, agency? }` | ajv schema | tracker → product detail page | T.T2 refuses; logs `REQUIRES-OPERATOR-INPUT: applicability_evidence` |
| `ssdf.products[].ai_enabled` | boolean | ajv | tracker → product detail page | defaults `false`; T.T5 augmentation does not engage |
| `ssdf.products[].critical_software` | boolean | ajv | tracker → product detail page | defaults `false`; T.T4 uses default 12-month re-attestation window |
| `ssdf.products[].major_version_pattern` | string (regex) | regex validity check | tracker → product detail page | defaults `^(\d+)\.0\.0$`; T.T4 material-change detector uses SemVer major |
| Tracker process-artefact row for a task with `requires_process_artefact: true` AND empty `crosswalk_ksi[]` | tracker `process_artefacts` row | tracker schema | tracker → `/ssdf/process-artefacts/<task_id>` | task status set to `requires-operator-input`; diagnostic emitted with deep link |
| `ssdf.ksi_to_product_map` (optional override) | `Record<KSI_ID, product_id[]>` | ajv | tracker → `/ssdf/ksi-mapping` | default behaviour: all KSI envelopes apply to all products |

## 12. Implementation log

| date | session | action | commit | notes |
|---|---|---|---|---|
| | | | | (empty — implementing session fills this in as work progresses) |

Per `docs/IMPLEMENTATION-LOG-TEMPLATE.md` §3 update cadence: every
commit boundary, every test failure, every research question answered,
every spec divergence, every newly-discovered risk (immediately
mirrored in `LOOP-T-RISKS.md`), every external dependency pin.

## 13. Completion checklist

Quoted verbatim from
`/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`,
plus the final push directive added per the user's ground-up
directive.

### Step 1 — Verify the slice is REO-compliant

> Run all three guardrails. They MUST all be green:
> ```bash
> cd cloud-evidence
> npm run typecheck      # no errors
> npm test               # 100% passing (counts must increase by the slice's new tests)
> npm run check:reo      # G1+G2+G3 all green
> ```

Plus T.T2-specific: `npm run check:ssdf-no-silent-pass`.

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

For T.T2: update LOOP-T-SPEC.md §12 Status table.

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

### Final step — STATUS.md row + loop SPEC + CHANGELOG line + push

After commit lands, append a row to STATUS.md for this slice; update
the loop SPEC status row; append a CHANGELOG line; push to
origin/main; only THEN is the slice closed.

## 14. Resume-from-fresh-session checklist

If a session opens with ONLY this file as context:

1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. This file gives you: source obligations + files to create + build
   steps + tests + risks + completion checklist + conditional gate.
3. Read `cloud-evidence/docs/loops/LOOP-T-SPEC.md` end to end (this
   slice's loop context).
4. Read `cloud-evidence/docs/slices/T/T.T1.md` (this slice's
   immediate dependency — the catalogue T.T2 consumes).
5. Read `cloud-evidence/docs/loops/LOOP-T-RISKS.md` for the per-loop
   risks register; add any new risks surfaced during implementation in
   the same commit.
6. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the
   mandatory 7-step commit pattern.
7. Read `cloud-evidence/core/envelope.ts` (T.T2 walks every signed
   envelope through this module).
8. Read `cloud-evidence/core/risk-score.ts`,
   `cloud-evidence/core/subprocessor-inventory.ts`,
   `cloud-evidence/core/supply-chain-risk-register.ts`,
   `cloud-evidence/core/sbom.ts`,
   `cloud-evidence/core/cosign-verify.ts` — the ancillary inputs T.T2
   reads.
9. Read `cloud-evidence/core/inventory-workbook.ts` — the xlsx pattern
   T.T2's emitter mirrors (no new dependency).
10. Confirm `docs/sources/` carries all REQUIRES-RESEARCH source PDFs
    (OMB M-22-18, M-23-16, M-26-05, CISA Common Form, RSAA User Guide,
    NIST SP 800-218 PDF, 800-218A PDF) with their `.sha256` siblings.
    If any is missing, download from the URL in §2 and record the
    SHA-256 before proceeding.
11. Begin implementation; update the Implementation log section as you
    go.

---

(End of T.T2 per-slice doc; last updated 2026-06-07 under the user's
ground-up directive.)
