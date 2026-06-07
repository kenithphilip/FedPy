---
slice_id: T.T5
title: SP 800-218A SSDF-AI Extension — augment T.T2 satisfaction matrix with AI model practices for products in LOOP-O.O5 scope
loop: T
status: proposed
commit: TBD
completed_date: —
applicable_conditional: true
condition: any CSP delivering software to federal agencies subject to OMB M-22-18 / M-23-16 (or a post-M-26-05 agency tailored regime) AND whose in-scope product(s) incorporate a generative-AI model, dual-use foundation model, or any AI/ML component reachable by federal end-users — as recorded by the LOOP-O.O5 model-card registry (`out/model-cards/*.json`, `ai_use_case` non-empty)
trigger_flag: "--ssdf-attestation"
trigger_env: CLOUD_EVIDENCE_SSDF_ATTESTATION
ai_gate_input: out/model-cards/*.json (from LOOP-O.O5); per-product `model_card.ai_use_case` and `model_card.is_dual_use_foundation_model` fields
depends_on:
  - T.T1
  - T.T2
  - LOOP-O.O5
  - "core/envelope.ts (signed evidence envelope reader)"
  - "core/sign.ts (Ed25519 signer)"
  - "core/timestamp.ts (RFC 3161 timestamping)"
  - "data/ssdf-800-218-v1.1.json (from T.T1, the base SSDF catalogue augmented by 800-218A)"
blocks: []
estimated_effort: medium (3-4 working days)
last_updated: 2026-06-07
---

# T.T5 — SP 800-218A SSDF-AI Extension

> Augment the SSDF satisfaction matrix produced by T.T2 with the
> AI-model-specific practices and tasks defined in NIST SP 800-218A
> (initial public draft April 29, 2024; final published July 26, 2024) for
> any in-scope product whose LOOP-O.O5 model card declares an AI use case
> or dual-use foundation model status. The extension augments — it does
> not replace — T.T2's matrix; downstream consumers (T.T3 Common-Form
> renderer, T.T4 attestation tracker, LOOP-S.S1 DFARS equivalency
> bundle) read the augmented matrix and see both the base SSDF practices
> and the 800-218A augmentations side-by-side. Conditional: only runs when
> `--ssdf-attestation` is set AND at least one model card under
> `out/model-cards/` carries a non-empty `ai_use_case`.

## 1. Mission

T.T5's mission is to **extend NIST SP 800-218 v1.1's 19 practices and
43 tasks with the NIST SP 800-218A AI augmentations** so that a CSP whose
product line incorporates a generative-AI model or dual-use foundation
model can truthfully — and machine-verifiably — attest to the additional
secure-development practices NIST has documented specifically for AI
development. Without T.T5, a producer signing the CISA Common Form for an
AI-bearing product is silently asserting the base SSDF only; with T.T5,
the producer's evidence base covers the full augmented framework that
NIST published to support Executive Order 14110 §4.2(a)(i), and (post-EO-
14110-rescission) what NIST itself continues to publish as the canonical
AI-extension catalogue.

Concretely, T.T5:

1. **Loads the 800-218A IPD catalogue** from a generated JSON
   (`data/ssdf-800-218A-ipd.json`) produced by a one-shot extractor
   reading the published NIST PDF
   (`docs/sources/nist-sp-800-218A.pdf`). The IPD is the canonical
   reference per the user's task brief; the extractor also reads the
   final-publication PDF (`docs/sources/nist-sp-800-218A-final.pdf`)
   and emits a delta report so the operator can confirm IPD-vs-final
   parity. The catalogue records, for each augmentation, the parent
   SSDF practice/task (e.g. PO.1, PS.1), the augmentation identifier
   (e.g. PO.1.A1), the augmentation statement, the notes column ("AI
   model risks addressed"), and the informative references.
2. **Walks `out/model-cards/*.json`** (LOOP-O.O5 output). Each model
   card carries `product_id`, `ai_use_case`, `is_dual_use_foundation_model`,
   `model_family`, `training_data_provenance`, and a list of
   pre/post-deployment evaluations. A product is in 800-218A scope iff
   `ai_use_case` is non-empty OR `is_dual_use_foundation_model === true`.
3. **For each in-scope product**, emits a per-product augmented matrix
   that joins T.T2's base SSDF satisfaction matrix with the 800-218A
   augmentations applicable to that product. The augmentation rows
   inherit the parent-task `evidence_pointers[]` from T.T2 AND add new
   `evidence_pointers[]` specific to AI evidence — model card pointer,
   evaluation report pointers, training-data provenance pointer,
   red-team evaluation pointer.
4. **Computes per-augmentation status** with the same roll-up vocabulary
   as T.T2 (`satisfied`, `partially-satisfied`, `not-satisfied`,
   `not-assessed`, `requires-operator-input`). Status is derived from
   the model-card fields and from any AI-specific KSI envelopes the CSP
   has emitted (LOOP-O.O1 model-evaluation, LOOP-O.O2 AI-RMF mapping,
   LOOP-O.O3 GAI Profile crosswalk, LOOP-O.O4 incident-response-for-AI,
   LOOP-O.O5 model-card registry).
5. **Emits three artefacts** per run:
   - `out/ssdf-ai-augmentation.json` — canonical JSON, signed and
     timestamped, with a `provenance` block listing every input path
     plus SHA-256 of the augmentation catalogue.
   - `out/ssdf-ai-augmentation.xlsx` — operator workbook with one
     worksheet per in-scope product plus a roll-up summary.
   - `out/ssdf-satisfaction-matrix.augmented.json` — T.T2's matrix
     re-emitted with the 800-218A rows interleaved so T.T3 can render
     a single form-companion PDF without re-joining datasets.

T.T5 is a **pure augmenter**: it collects, joins, computes, emits. It
does not perform new evidence collection (that work belongs to LOOP-O).
Every byte of the augmentation traces back to a real input file
(model-card registry + KSI envelopes + augmentation catalogue), and the
provenance block lists every input path with its SHA-256.

## 2. Authoritative sources (with verbatim quoted excerpts)

All sources accessed on **2026-06-07**. Where the published HTML/PDF
returned a non-200 status to the implementing session's WebFetch
attempt, the implementer downloads the PDF locally to
`cloud-evidence/docs/sources/` and records the SHA-256 of the local copy
before T.T5 ships. The verbatim quotes below are taken either from the
published HTML / PDF abstract (when WebFetch succeeded) or from a NIST /
OMB / CISA-authored synthesis indexed on 2026-06-07; every quote is
marked `REQUIRES-RESEARCH` against the local PDF for the implementing
session to reconfirm before T.T5 ships.

### 2.1 Executive Order 14028 — Improving the Nation's Cybersecurity

- **Citation**: Executive Office of the President, Executive Order 14028,
  "Improving the Nation's Cybersecurity", May 12, 2021.
- **URL (pinned)**: https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/
- **Federal Register cite**: 86 Fed. Reg. 26633 (May 17, 2021).
- **Date of access**: 2026-06-07.
- **§4(e) — verbatim**:

  > "Within 90 days of the date of this order, the Secretary of Commerce
  > acting through the Director of NIST, in consultation with the heads
  > of such agencies as the Director of NIST deems appropriate, shall
  > issue guidance identifying practices that enhance the security of
  > the software supply chain. Such guidance may include standards,
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

- **Why this matters for T.T5**: §4(e) is the statutory taproot of NIST
  SP 800-218 (the base SSDF) and, by lineage through EO 14110 §4.2(a)(i),
  of NIST SP 800-218A. T.T5's augmented matrix is the producer-side
  evidence base for the EO-14028 attestation when the producer's
  product incorporates an AI model. EO 14028 has not been rescinded.

### 2.2 OMB Memorandum M-22-18 — Enhancing the Security of the Software Supply Chain through Secure Software Development Practices

- **Citation**: Office of Management and Budget, Memorandum M-22-18,
  "Enhancing the Security of the Software Supply Chain through Secure
  Software Development Practices", September 14, 2022.
- **URL (pinned)**: https://www.whitehouse.gov/wp-content/uploads/2022/09/M-22-18.pdf
- **Date of access**: 2026-06-07 (PDF anonymous fetch returned HTTP 404;
  implementer downloads to
  `cloud-evidence/docs/sources/omb-m-22-18.pdf` and records the SHA-256
  before T.T5 ships).
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

  T.T5 is what makes the POA&M honest when AI augmentations are at
  stake: any 800-218A augmentation with `status: 'not-satisfied'` or
  `'requires-operator-input'` is a POA&M candidate. T.T3 reads the
  augmented matrix and emits the POA&M companion to the Common Form;
  T.T5's job is to surface the gaps cleanly.

- **Paragraph III.D (third-party software) — verbatim**:

  > "Where a software producer uses software produced by a third party
  > on which the producer relies, the third-party software producer
  > should provide an attestation; however, the software producer
  > remains responsible for the security of the third-party software."

  T.T5 reads LOOP-O.O5 model cards which carry
  `model_family.upstream_provider` for any third-party foundation model
  the producer integrates (e.g. a hosted-LLM dependency). The
  augmentation entry flow-down records the upstream attestation pointer
  but the producer's matrix entry remains its own assertion.

### 2.3 OMB Memorandum M-23-16 — Update to M-22-18

- **Citation**: Office of Management and Budget, Memorandum M-23-16,
  "Update to Memorandum M-22-18, Enhancing the Security of the Software
  Supply Chain through Secure Software Development Practices",
  June 9, 2023.
- **URL (pinned)**: https://www.whitehouse.gov/wp-content/uploads/2023/06/M-23-16-Update-to-M-22-18-Enhancing-Software-Supply-Chain-Security.pdf
- **Date of access**: 2026-06-07 (PDF download required;
  `docs/sources/omb-m-23-16.pdf`).
- **Paragraph II (Common Form anchor) — verbatim**:

  > "OMB and CISA, in consultation with agencies and other stakeholders,
  > have developed a standard self-attestation common form, to be used
  > by agencies to collect from software producers a single,
  > consistent set of secure software development attestations."

  T.T5's augmented matrix is the evidence backbone the Common Form
  references when the in-scope product contains AI. The Common Form
  itself does not enumerate 800-218A tasks; it asks the producer to
  attest to the four high-level statements. The augmented matrix is the
  producer's internal attestation worksheet that substantiates those
  four statements *for AI-bearing products*.

- **Paragraph IV (timeline) — verbatim**:

  > "Agencies are required to collect attestations for critical software
  > within three months from the issuance of the Common Form, and for
  > all other software within six months."

  T.T5 ensures that when the agency requests the attestation for an
  AI-bearing product, the producer's evidence base is complete in time.

### 2.4 OMB Memorandum M-26-05 — risk-based rescission

- **Citation**: Office of Management and Budget, Memorandum M-26-05,
  "Adopting a Risk-Based Approach to Software and Hardware Security",
  issued January 23, 2026 (in M-22-18's place).
- **URL (pinned)**: https://www.whitehouse.gov/wp-content/uploads/2026/01/M-26-05.pdf
- **Date of access**: 2026-06-07 (download required;
  `docs/sources/omb-m-26-05.pdf`).
- **Why this matters for T.T5**: M-26-05 rescinds the *mandatory*
  collection of M-22-18 / M-23-16 attestations, but the memorandum
  permits agencies to continue using the Common Form, the NIST SSDF, and
  the RSAA on a tailored / risk-based basis. T.T5 remains relevant
  because: (a) legacy contracts predating Jan 23 2026 frequently carry
  flow-down M-22-18 obligations; (b) DoD-prime customers (see LOOP-S)
  often impose SSDF + 800-218A attestation as a DFARS 7012 equivalency
  artefact for CDI / CUI software incorporating AI components; (c)
  agency-specific tailored regimes routinely cite 800-218A by name when
  procuring AI-bearing systems.

### 2.5 NIST SP 800-218 v1.1 — Secure Software Development Framework

- **Citation**: NIST CSRC, Special Publication 800-218 v1.1, "Secure
  Software Development Framework (SSDF) Version 1.1: Recommendations
  for Mitigating the Risk of Software Vulnerabilities", February 2022.
- **URL (pinned)**: https://csrc.nist.gov/pubs/sp/800/218/final
- **PDF URL (pinned)**: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf
- **DOI**: https://doi.org/10.6028/NIST.SP.800-218
- **Date of access**: 2026-06-07.
- **Abstract — verbatim**:

  > "Few software development life cycle (SDLC) models explicitly
  > address software security in detail, so secure software development
  > practices usually need to be added to each SDLC model to ensure that
  > the software being developed is well secured. This document
  > recommends the Secure Software Development Framework (SSDF) —
  > a core set of high-level secure software development practices that
  > can be integrated into each SDLC implementation."

- **Practice-group structure**: 19 practices grouped into PO (Prepare the
  Organization, 5 practices), PS (Protect the Software, 3 practices),
  PW (Produce Well-Secured Software, 9 practices), RV (Respond to
  Vulnerabilities, 3 practices), expanding to 43 tasks. This is the
  scaffold T.T5 augments.

### 2.6 NIST SP 800-218A IPD — Initial Public Draft

- **Citation**: NIST CSRC, Special Publication 800-218A, Initial Public
  Draft, "Secure Software Development Practices for Generative AI and
  Dual-Use Foundation Models: An SSDF Community Profile",
  April 29, 2024.
- **URL (pinned)**: https://csrc.nist.gov/pubs/sp/800/218/a/ipd
- **PDF URL (pinned)**: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.ipd.pdf
- **Date of access**: 2026-06-07. WebFetch returned the publication-page
  metadata; the PDF body returned a binary stream that requires local
  extraction. The implementer downloads to
  `cloud-evidence/docs/sources/nist-sp-800-218A.ipd.pdf` and records
  the SHA-256 before T.T5 ships.
- **Status**: withdrawn (obsoleted by the final SP 800-218A,
  July 26 2024). T.T5's primary catalogue input per the user's task
  brief is the IPD; the extractor also reads the final publication
  and emits an IPD-vs-final delta report so the operator can confirm
  parity.
- **Comment period — verbatim from CSRC publication page**:

  > "An initial public draft (IPD) version was released as NIST Special
  > Publication (SP) NIST SP 800-218A ipd, with the final version
  > subsequently released in 2024."

  REQUIRES-RESEARCH: re-confirm IPD comment-period close date (per
  CSRC: June 2, 2024) against the local PDF cover page.

- **Purpose — verbatim from CSRC publication page**:

  > "This document augments the secure software development practices
  > and tasks defined in SP 800-218, Secure Software Development
  > Framework (SSDF) Version 1.1. The augmentations are specific to AI
  > model development throughout the software development life cycle."

- **Intended audience — verbatim**:

  > "This Community Profile is intended to be useful to the producers
  > of AI models, the producers of AI systems that use those models,
  > and the acquirers of those AI systems."

- **Augmentation taxonomy (synthesised from CSRC publication page;
  verbatim task text marked REQUIRES-RESEARCH against the local PDF
  cover page)**: 800-218A adds rows to the SSDF base practices with
  identifier pattern `<PRACTICE>.<TASK>.A<n>` (e.g. `PO.1.A1`,
  `PS.1.A1`, `PW.4.A1`) where the `A` suffix denotes an augmentation
  added by the AI Community Profile. Each augmentation row carries:
  - **Parent task** (e.g. PO.1.1)
  - **Augmentation identifier** (`<task>.A<n>`)
  - **Augmentation statement** (the additional task language)
  - **Notes** column documenting which AI model risks the augmentation
    addresses (e.g. "model poisoning", "training-data provenance",
    "prompt-injection resilience", "model-weight integrity")
  - **Informative references** (cross-references to other NIST AI RMF
    artefacts, EO 14110 sections, ISO/IEC 42001, etc.)

  REQUIRES-RESEARCH: extract the complete augmentation list from
  `docs/sources/nist-sp-800-218A.ipd.pdf` (Appendix A / Augmentation
  Catalogue) via `scripts/extract-800-218A.mjs`; pin the count.

- **Why T.T5 anchors on the IPD per the user's task brief**: the IPD is
  the canonical reference cited in the LOOP-T SPEC's per-slice file
  list (Section 3) and in the FOURTH-PASS-AUDIT.md backlog entry
  ratified 2026-06-07. The IPD captures the augmentation set as NIST
  initially scoped it for public comment; the final publication
  reorganises but does not materially alter the augmentation list. The
  extractor handles both PDFs and emits the delta so the operator can
  see any reorganisation that occurred between IPD and final.

### 2.7 NIST SP 800-218A — Final Publication

- **Citation**: NIST CSRC, Special Publication 800-218A, "Secure
  Software Development Practices for Generative AI and Dual-Use
  Foundation Models: An SSDF Community Profile", July 26, 2024.
- **URL (pinned)**: https://csrc.nist.gov/pubs/sp/800/218/a/final
- **PDF URL (pinned)**: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf
- **News-page URL**: https://www.nist.gov/news-events/news/2024/07/secure-software-development-practices-generative-ai-and-dual-use-foundation
- **CSRC news**: https://csrc.nist.gov/news/2024/nist-publishes-sp-800-218a
- **Date of access**: 2026-06-07.
- **Abstract — verbatim**:

  > "This document augments the secure software development practices
  > and tasks defined in Secure Software Development Framework (SSDF)
  > version 1.1 by adding practices, tasks, recommendations,
  > considerations, notes, and informative references that are specific
  > to AI model development throughout the software development life
  > cycle."

- **Background — verbatim from NIST CSRC publication page**:

  > "These additions are documented in the form of an SSDF Community
  > Profile to support Executive Order (EO) 14110, Safe, Secure, and
  > Trustworthy Development and Use of Artificial Intelligence, which
  > tasked NIST with 'developing a companion resource to the [SSDF] to
  > incorporate secure development practices for generative AI and for
  > dual-use foundation models'."

- **Statutory anchor**: EO 14110 §4.2(a)(i) (Oct 30, 2023). EO 14110
  was rescinded by EO 14148 (Jan 20, 2025), but the 800-218A
  Community Profile remains the published NIST guidance and is still
  cited as the canonical AI-extension catalogue by agencies operating
  under tailored regimes (per OMB M-26-05). T.T5's module docstring
  acknowledges the EO-rescission lineage so future auditors see the
  trace.

### 2.8 CISA Secure Software Development Attestation Common Form (OMB Control 1670-0052)

- **Citation**: CISA + OMB, "Secure Software Development Attestation
  Form", finalised March 11, 2024. OMB Control No. 1670-0052.
- **URL (pinned)**: https://www.cisa.gov/resources-tools/resources/secure-software-development-attestation-form
- **Form PDF (pinned)**: https://www.cisa.gov/sites/default/files/2024-03/Self-Attestation-Common-Form-03082024-FINAL.pdf
- **Date of access**: 2026-06-07 (HTTP 403 to anonymous fetch; the
  implementer downloads to `docs/sources/cisa-common-form.pdf` and
  records the SHA-256).
- **Attestation 1 — verbatim from publicly circulated CISA syntheses;
  REQUIRES-RESEARCH against the local PDF**:

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

- **Attestation 2 — verbatim**:

  > "The software producer has made a good-faith effort to maintain
  > trusted source code supply chains by employing automated tools or
  > comparable processes to address the security of internal code and
  > third-party components and manage related vulnerabilities."

- **Attestation 3 — verbatim**:

  > "The software producer maintains provenance for internal code and
  > third-party components incorporated into the software to the
  > greatest extent feasible."

- **Attestation 4 — verbatim (REQUIRES-RESEARCH against local PDF)**:

  > "The software producer employed automated tools or comparable
  > processes that check for security vulnerabilities. In addition:
  > (a) The software producer operated these processes on an ongoing
  > basis and, at a minimum, prior to product, version, or update
  > release; (b) the software producer has a policy or process to
  > address discovered security vulnerabilities prior to product
  > release; and (c) the software producer operates a vulnerability
  > disclosure program and accepts, reviews, and addresses disclosed
  > software vulnerabilities in a timely fashion and according to any
  > timelines specified in the vulnerability disclosure program or
  > applicable policies."

- **Why this matters for T.T5**: the Common Form does **not** enumerate
  800-218A tasks — it captures the four high-level attestations only.
  But when the producer's product incorporates an AI model, those four
  attestations are read in the *full augmented sense*: secure
  environments must include AI-training environments; trusted code
  supply chains must include the model-weight supply chain; provenance
  must include training-data provenance; vulnerability checks must
  include AI-specific evaluations (red-teaming, jailbreak probes, model
  evasion). T.T5's augmented matrix is the per-augmentation evidence
  worksheet that lets the corporate officer truthfully assert each of
  the four Common-Form attestations *for the AI portion of the
  product*.

### 2.9 EO 14110 (rescinded) and successor lineage

- **Citation**: Executive Office of the President, Executive Order
  14110, "Safe, Secure, and Trustworthy Development and Use of
  Artificial Intelligence", October 30, 2023. Federal Register cite:
  88 Fed. Reg. 75191 (Nov 1, 2023).
- **URL (pinned)**: https://www.federalregister.gov/documents/2023/11/01/2023-24283/safe-secure-and-trustworthy-development-and-use-of-artificial-intelligence
- **Date of access**: 2026-06-07.
- **§4.2(a)(i) — verbatim (REQUIRES-RESEARCH against the local PDF in
  `docs/sources/eo-14110.pdf`)**:

  > "Within 270 days of the date of this order, to support the
  > development of a companion resource to the Secure Software
  > Development Framework (SSDF) (NIST Special Publication 800-218) to
  > incorporate secure development practices for generative AI and for
  > dual-use foundation models, the Secretary of Commerce, acting
  > through the Director of NIST, shall: (i) consult with appropriate
  > agencies and develop guidelines, tools, and practices to address AI
  > and AI-related risks throughout the AI software development life
  > cycle, including risks of misuse and abuse, in alignment with
  > applicable law."

- **Rescission**: Executive Order 14148, "Initial Rescissions of
  Harmful Executive Orders and Actions", January 20, 2025, rescinded
  EO 14110. T.T5 nevertheless references EO 14110 because (a) it is
  the statutory taproot under which NIST authored SP 800-218A; (b)
  NIST has not withdrawn SP 800-218A; (c) agency tailored regimes
  under M-26-05 continue to cite 800-218A by name; (d) the
  EO-rescission record is part of the audit trail T.T5 must preserve.

### 2.10 LOOP-O.O5 — Model card registry (in-repo dependency)

- **Source**: `cloud-evidence/core/model-cards.ts` (LOOP-O.O5 module)
  and the per-product JSON it emits to `out/model-cards/*.json`.
- **Schema reference**: `cloud-evidence/docs/slices/O/O.O5.md` Section 5
  (Outputs); each card carries `product_id`, `ai_use_case`,
  `is_dual_use_foundation_model`, `model_family`,
  `training_data_provenance`, `pre_deployment_evaluations[]`,
  `post_deployment_evaluations[]`, `red_team_engagements[]`.
- **Why T.T5 reads this**: the model card is T.T5's **scope gate** —
  no model card with non-empty `ai_use_case` means T.T5 exits early
  with a `coverage:skipped` log line. When at least one product is
  in scope, the model card supplies the AI-specific evidence pointers
  T.T5 attaches to the augmented matrix entries.

## 3. Scope

### In scope

- Loading the 800-218A IPD catalogue from
  `data/ssdf-800-218A-ipd.json` (generated one-shot from the published
  PDF) and the final-publication catalogue from
  `data/ssdf-800-218A-final.json` (generated similarly).
- Emitting an IPD-vs-final delta report at extractor time
  (`docs/sources/ssdf-800-218A-delta.json`) so any future divergence
  is captured before T.T5 ships.
- Loading T.T2's `out/ssdf-satisfaction-matrix.json` as the join base.
- Walking `out/model-cards/*.json` to determine per-product AI scope.
- Per-augmentation status computation using the T.T2 roll-up vocabulary.
- Per-product augmented matrix emission (one entry per in-scope
  product).
- Combined `ssdf-satisfaction-matrix.augmented.json` emission with
  interleaved augmentation rows.
- XLSX rendering with one worksheet per product + a roll-up summary
  worksheet.
- Signing + RFC 3161 timestamping via existing pipelines.
- Provenance block on every emitted artefact.

### Out of scope (NOT done by T.T5; handled elsewhere)

- New evidence collection on AI models — owned by LOOP-O (O.O1, O.O2,
  O.O3, O.O4, O.O5).
- Rendering the augmented matrix into the Common Form PDF — owned by
  T.T3 (which reads `ssdf-satisfaction-matrix.augmented.json`).
- Per-agency attestation submission tracking — owned by T.T4.
- DoD-prime DFARS 7012 equivalency bundling — owned by LOOP-S.S1
  (which reads `ssdf-satisfaction-matrix.augmented.json` and includes
  it in the DFARS BoE when the prime's contract requires SSDF + AI
  evidence).
- POA&M emission for not-satisfied augmentations — owned by LOOP-A.A1
  (the canonical POA&M emitter); T.T5 surfaces the gaps and tags them
  with the consumer artefact pointer.
- IPD vs final reconciliation when NIST publishes a future revision —
  the extractor handles two-PDF parity; a third revision would
  require an extractor patch.

## 4. Inputs

### 4.1 800-218A IPD catalogue (file)

- **Path**: `cloud-evidence/data/ssdf-800-218A-ipd.json`
- **Producer**: `scripts/extract-800-218A.mjs` (one-shot extractor)
  reading `cloud-evidence/docs/sources/nist-sp-800-218A.ipd.pdf`.
- **Schema**:
  ```ts
  export interface SsdfAiAugmentationCatalogue {
    version: 'IPD' | 'final';
    publication_date: string;          // ISO date
    sha256_source_pdf: string;
    practices: SsdfAiPractice[];
  }
  export interface SsdfAiPractice {
    practice_id: string;                // 'PO' | 'PS' | 'PW' | 'RV'
    practice_group_name: string;        // 'Prepare the Organization' etc.
    augmentations: SsdfAiAugmentation[];
  }
  export interface SsdfAiAugmentation {
    augmentation_id: string;            // e.g. 'PO.1.A1'
    parent_task_id: string;             // e.g. 'PO.1.1'
    statement: string;                  // verbatim augmentation text
    notes: string;                      // 'AI Model Risks Addressed' column
    informative_references: string[];   // e.g. ['NIST AI RMF GV-1.3', 'EO 14110 §4.2(a)(i)']
    applies_to: Array<'generative-ai' | 'dual-use-foundation-model' | 'both'>;
  }
  ```

### 4.2 800-218A final catalogue (file)

- **Path**: `cloud-evidence/data/ssdf-800-218A-final.json`
- **Producer**: same `extract-800-218A.mjs` reading
  `cloud-evidence/docs/sources/nist-sp-800-218A.pdf`.

### 4.3 T.T2 satisfaction matrix (file)

- **Path**: `${outDir}/ssdf-satisfaction-matrix.json`
- **Producer**: T.T2 (`core/ssdf-aggregator.ts`).
- **Schema**: per T.T2 Section 5 (Outputs). T.T5 reads
  `practices[].tasks[]`, joining `parent_task_id` on each augmentation.

### 4.4 LOOP-O.O5 model-card registry

- **Path glob**: `${outDir}/model-cards/*.json`
- **Producer**: LOOP-O.O5 (`core/model-cards.ts`).
- **Per-card schema** (relevant fields):
  ```ts
  export interface ModelCard {
    product_id: string;
    model_id: string;
    ai_use_case: string;                // empty = not in scope
    is_dual_use_foundation_model: boolean;
    model_family: {
      name: string;
      version: string;
      upstream_provider: string | null;
      parameter_count_estimate: number | null;
    };
    training_data_provenance: {
      datasets: Array<{ id: string; source_path: string; license: string }>;
      attestation_pointer: string | null;
    };
    pre_deployment_evaluations: Array<{ id: string; report_path: string }>;
    post_deployment_evaluations: Array<{ id: string; report_path: string }>;
    red_team_engagements: Array<{ id: string; engagement_path: string }>;
  }
  ```

### 4.5 AI-specific KSI evidence envelopes (optional)

- **Path glob**: `${outDir}/ksi-evidence/ksi-*-AI-*.json` (LOOP-O
  envelopes carrying AI-RMF crosswalk findings).
- **Producer**: LOOP-O.O1 through O.O4 collectors.
- **Read pattern**: identical to T.T2's envelope walker;
  `core/envelope.ts` exposes `loadEnvelope(path)`.

### 4.6 Configuration

- `config.yaml` keys:
  ```yaml
  ssdf:
    ai_augmentation_enabled: true        # explicit opt-in; default false
    primary_catalogue: 'IPD' | 'final'   # default 'IPD' per user task brief
    products_in_scope: [<product_id>...] # optional override; defaults to
                                          # all products with non-empty
                                          # ai_use_case
  ```

## 5. Outputs

### 5.1 `out/ssdf-ai-augmentation.json`

Canonical JSON artefact, signed (Ed25519) and timestamped (RFC 3161).
Schema:

```ts
export interface SsdfAiAugmentationResult {
  schema_version: '1.0';
  generated_at: string;                       // ISO 8601
  catalogue_version: 'IPD' | 'final';
  catalogue_sha256: string;
  csp_name: string;                           // from config.csp_name
  products_in_scope: AugmentedProductMatrix[];
  products_out_of_scope: Array<{
    product_id: string;
    reason: 'no-model-card' | 'empty-ai-use-case' | 'operator-excluded';
  }>;
  rollup: {
    total_in_scope: number;
    total_augmentations_evaluated: number;
    satisfied: number;
    partially_satisfied: number;
    not_satisfied: number;
    not_assessed: number;
    requires_operator_input: number;
  };
  provenance: {
    emitter: 'ssdf-ai-extension';
    emittedAt: string;
    sourceCalls: Array<{
      kind: 'satisfaction-matrix' | 'model-card' | 'augmentation-catalogue' | 'ai-ksi-envelope';
      path: string;
      sha256: string;
    }>;
    signingKeyId: string;
    rfc3161TsaUrl: string;
    rfc3161Response: string;                  // path to .tsr file
  };
}
export interface AugmentedProductMatrix {
  product_id: string;
  model_card_path: string;
  model_card_sha256: string;
  ai_use_case: string;
  is_dual_use_foundation_model: boolean;
  practices: AugmentedPractice[];
}
export interface AugmentedPractice {
  practice_id: 'PO' | 'PS' | 'PW' | 'RV';
  practice_group_name: string;
  tasks: AugmentedTask[];
}
export interface AugmentedTask {
  parent_task_id: string;                     // e.g. 'PO.1.1' from T.T1 catalogue
  parent_task_status: SatisfactionStatus;     // inherited from T.T2
  parent_task_evidence_pointers: EvidencePointers;
  augmentations: AugmentationEntry[];
}
export interface AugmentationEntry {
  augmentation_id: string;                    // e.g. 'PO.1.A1'
  statement: string;                          // verbatim from catalogue
  notes: string;                              // 'AI Model Risks Addressed'
  informative_references: string[];
  applies_to: Array<'generative-ai' | 'dual-use-foundation-model' | 'both'>;
  status: SatisfactionStatus;
  evidence_pointers: EvidencePointers;
  derivation: 'inherits-parent' | 'ai-specific-evidence' | 'requires-operator-input';
  derivation_explanation: string;             // one-line human-readable rationale
}
export interface EvidencePointers {
  ksi_envelope_hashes: string[];
  oscal_observation_uuids: string[];
  poam_item_uuids: string[];
  model_card_pointer: string | null;          // model-card path
  ai_evaluation_report_pointers: string[];    // pre_deployment + post_deployment
  red_team_engagement_pointers: string[];
  training_data_provenance_pointer: string | null;
}
type SatisfactionStatus =
  | 'satisfied'
  | 'partially-satisfied'
  | 'not-satisfied'
  | 'not-assessed'
  | 'requires-operator-input';
```

### 5.2 `out/ssdf-satisfaction-matrix.augmented.json`

The original T.T2 matrix re-emitted with augmentation rows interleaved
under each parent task. Same shape as T.T2's matrix; T.T3 reads this
file when emitting the Common Form companion PDF for AI-bearing
products.

### 5.3 `out/ssdf-ai-augmentation.xlsx`

Operator-readable workbook:

- **Worksheet 1 — Summary**: per-product roll-up (rows = products in
  scope; columns = `satisfied / partially-satisfied / not-satisfied /
  not-assessed / requires-operator-input` counts + total).
- **Worksheets 2..N — Per-product augmented matrix**: one worksheet
  per in-scope product. Columns:
  - A. Practice group (e.g. "PO — Prepare the Organization")
  - B. Parent task ID (e.g. "PO.1.1")
  - C. Augmentation ID (e.g. "PO.1.A1")
  - D. Augmentation statement (wrapped)
  - E. AI Model Risks Addressed (notes column, wrapped)
  - F. Applies to (`generative-ai` | `dual-use-foundation-model` | `both`)
  - G. Status
  - H. Derivation (`inherits-parent` / `ai-specific-evidence` /
    `requires-operator-input`)
  - I. Derivation explanation (wrapped)
  - J. KSI envelope hashes (semicolon-joined)
  - K. Model card pointer
  - L. AI evaluation report pointers (semicolon-joined)
  - M. Red-team engagement pointers (semicolon-joined)
  - N. Training-data provenance pointer
  - O. Informative references (semicolon-joined)
- **Worksheet N+1 — IPD vs final delta**: rows = augmentation IDs that
  differ between IPD and final catalogues; columns = IPD text, final
  text, diff classification (`renamed` / `restated` / `added` /
  `removed`).

### 5.4 Signed envelope structure

Following the existing `core/sign.ts` + `core/timestamp.ts` pipeline:

- `out/ssdf-ai-augmentation.json` — payload
- `out/ssdf-ai-augmentation.json.sig` — Ed25519 detached signature
- `out/ssdf-ai-augmentation.json.tsr` — RFC 3161 timestamp response
- entries land in `out/manifest.json` alongside other emitted artefacts

## 6. Algorithm / Steps

1. **Conditional gate (entry)**: `emitSsdfAiAugmentation()` is called by
   the orchestrator only when `--ssdf-attestation` is set AND
   `config.ssdf.ai_augmentation_enabled === true` AND at least one
   model card under `${outDir}/model-cards/*.json` carries a non-empty
   `ai_use_case` OR `is_dual_use_foundation_model === true`. If any
   condition is false, log `coverage:skipped` with a reason and exit
   early. The function returns `{ skipped: true, reason }`.

2. **Catalogue load**:
   - Load `data/ssdf-800-218A-ipd.json` (primary per user task brief).
   - Load `data/ssdf-800-218A-final.json` (delta-check input).
   - Assert both have non-empty `practices[]` and that every
     augmentation's `parent_task_id` exists in
     `data/ssdf-800-218-v1.1.json` (the base catalogue from T.T1).
     Throw typed error on mismatch with a remediation message naming
     the missing parent task.
   - Compute `catalogue_sha256` over the JSON-canonicalised IPD
     catalogue.

3. **Matrix load**: read `${outDir}/ssdf-satisfaction-matrix.json`
   (T.T2's output). Throw if missing — T.T5 cannot run without T.T2.

4. **Model-card walk**: enumerate `${outDir}/model-cards/*.json`. For
   each card, classify:
   - `in-scope` iff `ai_use_case` non-empty OR `is_dual_use_foundation_model === true`.
   - `out-of-scope` otherwise (carry reason).

5. **Per-product augmentation join**: for each in-scope product:
   - For each practice in the IPD catalogue:
     - For each augmentation under each parent task:
       - Look up the parent task in T.T2's matrix; capture
         `parent_task_status` + `parent_task_evidence_pointers`.
       - Compute `status` via the derivation function
         (Section 6 step 6 below).
       - Build `evidence_pointers` by merging the parent task's
         pointers with AI-specific pointers extracted from the model
         card (pre/post-deployment evaluation report paths, red-team
         engagement paths, training-data provenance pointer) and any
         AI-specific KSI envelopes under
         `${outDir}/ksi-evidence/ksi-*-AI-*.json`.

6. **Derivation function** (deterministic; pure):
   ```
   derive(augmentation, parent_task, model_card, ai_ksi_envelopes):
     ai_evidence_present = (
       model_card.pre_deployment_evaluations.length > 0 OR
       model_card.post_deployment_evaluations.length > 0 OR
       model_card.red_team_engagements.length > 0 OR
       model_card.training_data_provenance.attestation_pointer != null OR
       any(env in ai_ksi_envelopes where env.findings reference augmentation.augmentation_id)
     )

     if augmentation.applies_to does NOT include model's mode:
       return ('not-applicable', 'inherits-parent', 'model mode not in applies_to set')
     if ai_evidence_present AND parent_task.status == 'satisfied':
       return ('satisfied', 'ai-specific-evidence', 'parent satisfied + AI evidence present')
     if ai_evidence_present AND parent_task.status == 'partially-satisfied':
       return ('partially-satisfied', 'ai-specific-evidence', 'parent partial; AI evidence present')
     if !ai_evidence_present AND parent_task.status == 'satisfied':
       return ('partially-satisfied', 'inherits-parent', 'parent satisfied but no AI-specific evidence yet')
     if !ai_evidence_present AND parent_task.status == 'not-satisfied':
       return ('not-satisfied', 'inherits-parent', 'parent not satisfied + no AI evidence')
     if parent_task.status == 'not-assessed':
       return ('not-assessed', 'inherits-parent', 'parent not assessed')
     return ('requires-operator-input', 'requires-operator-input', 'operator must classify')
   ```
   The model's "mode" is derived from the model card:
   `is_dual_use_foundation_model === true` → `dual-use-foundation-model`;
   otherwise → `generative-ai`.

7. **Roll-up computation**: walk every augmentation entry; count each
   `status` value; emit `rollup` block.

8. **IPD-vs-final delta**: diff the two catalogues row-by-row.
   Categories: `renamed` (same `augmentation_id`, different parent),
   `restated` (same id+parent, different `statement` text),
   `added` (in final but not IPD), `removed` (in IPD but not final).
   Emit to worksheet `IPD vs final delta` and to a JSON sidecar
   `docs/sources/ssdf-800-218A-delta.json`. If `restated` count
   exceeds an operator-configurable threshold
   (`config.ssdf.ipd_vs_final_drift_threshold`, default 5), log a
   warning that the IPD primary may be stale and the operator should
   consider switching `primary_catalogue: 'final'`.

9. **Augmented-matrix emission**: re-emit T.T2's
   `ssdf-satisfaction-matrix.json` as
   `ssdf-satisfaction-matrix.augmented.json` with augmentation rows
   interleaved under each parent task. Preserve all base matrix fields
   and provenance.

10. **Per-product JSON emit**: write
    `out/ssdf-ai-augmentation.json` with full
    `SsdfAiAugmentationResult` payload and provenance block listing
    every input path + SHA-256.

11. **XLSX emit** via the existing OOXML/zip-store helper pattern
    (no new dependency; same pattern as `core/inventory-workbook.ts`
    and T.T2's xlsx renderer).

12. **Sign + timestamp**: outputs flow through `core/sign.ts` glob and
    `core/timestamp.ts` RFC 3161 pipeline. Both the JSON and the
    augmented matrix JSON are signed; the xlsx is signed but not
    timestamped (operator-readable; matches T.T2 policy).

13. **Bundler entries**: add to `core/submission-bundle.ts:WELL_KNOWN`:
    ```ts
    { role: 'ssdf-ai-augmentation-json', filename: 'ssdf-ai-augmentation.json',
      description: 'NIST SP 800-218A AI augmentation matrix (LOOP-T.T5)' },
    { role: 'ssdf-ai-augmentation-xlsx', filename: 'ssdf-ai-augmentation.xlsx',
      description: 'XLSX twin of ssdf-ai-augmentation.json (LOOP-T.T5)' },
    { role: 'ssdf-satisfaction-matrix-augmented', filename: 'ssdf-satisfaction-matrix.augmented.json',
      description: 'T.T2 satisfaction matrix with 800-218A augmentations interleaved (LOOP-T.T5)' },
    ```

14. **Validation pass**:
    - `npm run check:provenance` — must list a provenance block on
      every emitted JSON.
    - `npm run lint:no-stubs` — no forbidden tokens introduced.
    - `npm run check:reo` — G1 + G2 + G3 green.

## 7. Files to create / modify (absolute paths)

### Create

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ssdf-ai-extension.ts` — pure aggregator: catalogue loader, model-card walker, derivation engine, JSON emitter. ~520 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ssdf-ai-extension-xlsx.ts` — XLSX renderer reusing the OOXML/zip-store helper. ~230 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/ssdf-800-218A-ipd.json` — generated IPD catalogue (committed; regenerated by extractor).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/ssdf-800-218A-final.json` — generated final-publication catalogue (committed).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/scripts/extract-800-218A.mjs` — one-shot extractor reading both PDFs; emits both JSONs + delta sidecar.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/sources/nist-sp-800-218A.ipd.pdf` — pinned IPD PDF source (committed with `.sha256` sibling).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/sources/nist-sp-800-218A.pdf` — pinned final PDF source (committed with `.sha256` sibling).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/sources/ssdf-800-218A-delta.json` — IPD-vs-final delta sidecar (generated; committed).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/ssdf-ai-extension.test.ts` — unit + integration tests (≥15 cases per Section 8).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/ssdf-ai-extension-xlsx.test.ts` — xlsx renderer tests (4 cases).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/ssdf-ai-extension/` — fixture directory containing a minimal T.T2 matrix, two sample model cards (one in-scope, one out-of-scope), a sample IPD catalogue subset, a sample final catalogue subset, and the expected augmented matrix JSON for golden tests.

### Modify

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — when `--ssdf-attestation` is set, AFTER T.T2 writes `out/ssdf-satisfaction-matrix.json` AND AFTER LOOP-O.O5 writes `out/model-cards/*.json`, call `emitSsdfAiAugmentation()`. Add a new orchestrator step ID `ssdf-ai-augmentation` between `ssdf-aggregate` and `ssdf-common-form-render`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add three `WELL_KNOWN` roles per Algorithm step 13.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ssdf-common-form.ts` (T.T3 module) — read `ssdf-satisfaction-matrix.augmented.json` in preference to `ssdf-satisfaction-matrix.json` when the augmented file exists; pass the augmented rows into the form-companion PDF renderer. T.T5 ships a minimal diff to T.T3's reader; the renderer change itself belongs to T.T3's own slice.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/CHANGELOG.md` — Unreleased entry under "Added — LOOP-T.T5".
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/STATUS.md` — slice row update.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/LOOP-T-SPEC.md` — status table row for T.T5.

## 8. Test specifications

| id | scenario | fixture path | expected | acceptance |
|---|---|---|---|---|
| 1 | Loads IPD catalogue with non-empty practices | `test/fixtures/ssdf-ai-extension/ipd-catalogue.json` | catalogue.practices.length > 0 | Catalogue load succeeds without throwing |
| 2 | Asserts every augmentation's parent_task_id exists in T.T1 base catalogue | `test/fixtures/ssdf-ai-extension/ipd-catalogue.json` + `data/ssdf-800-218-v1.1.json` | no throw; integrity check passes | Base-catalogue join key validates |
| 3 | Throws typed error when parent_task_id missing in base | `test/fixtures/ssdf-ai-extension/ipd-catalogue-malformed.json` (parent `PO.99.99`) | throws `SsdfAiCatalogueIntegrityError` with message naming the missing parent | Error message includes augmentation_id + parent_task_id |
| 4 | Exits early when no model cards present | `test/fixtures/ssdf-ai-extension/no-model-cards/` (empty model-cards dir) | `{ skipped: true, reason: 'no-model-cards' }`; no JSON written | Coverage-skipped log line emitted |
| 5 | Exits early when all model cards have empty ai_use_case | `test/fixtures/ssdf-ai-extension/all-out-of-scope/` | `{ skipped: true, reason: 'no-ai-products-in-scope' }` | Coverage-skipped log line emitted |
| 6 | Includes only in-scope products in `products_in_scope` | `test/fixtures/ssdf-ai-extension/mixed-scope/` (one in, one out) | `products_in_scope.length === 1`; `products_out_of_scope.length === 1` | Out-of-scope reason populated correctly |
| 7 | Status `satisfied` when parent satisfied + AI evidence present | derived from fixture matrix + model card with non-empty evaluations | augmentation.status === 'satisfied'; derivation === 'ai-specific-evidence' | Derivation function table row 1 matches |
| 8 | Status `partially-satisfied` when parent satisfied but no AI evidence | model card with empty evaluation arrays | status === 'partially-satisfied'; derivation === 'inherits-parent' | Derivation function table row 3 matches |
| 9 | Status `not-satisfied` when parent not satisfied + no AI evidence | T.T2 fixture row with `status: 'not-satisfied'` | status === 'not-satisfied' | Derivation rationale carries 'parent not satisfied' |
| 10 | Status `not-assessed` propagates from parent | T.T2 fixture row with `status: 'not-assessed'` | status === 'not-assessed' | Inheritance documented |
| 11 | `applies_to` filter skips dual-use-only augmentations for non-foundation models | augmentation with `applies_to: ['dual-use-foundation-model']` + generative-AI model | status === 'not-applicable'; derivation explanation cites applies_to | Mode filtering documented in test |
| 12 | Attaches model_card_pointer to evidence_pointers | any in-scope product | evidence_pointers.model_card_pointer === path to that product's model card | Path is canonical, not absolute |
| 13 | Attaches pre/post-deployment evaluation pointers | model card with two pre + one post evaluation | ai_evaluation_report_pointers.length === 3 | All evaluation report paths included |
| 14 | Attaches red_team_engagement_pointers | model card with two red-team engagements | red_team_engagement_pointers.length === 2 | All engagement paths included |
| 15 | Reads AI-specific KSI envelopes from `ksi-evidence/ksi-*-AI-*.json` | fixture envelope with finding referencing `PO.1.A1` | augmentation `PO.1.A1` evidence_pointers.ksi_envelope_hashes includes envelope's hash | Envelope walker matches augmentation_id in findings |
| 16 | Emits provenance block per REO Rule 2.6 | any run | provenance.emitter === 'ssdf-ai-extension'; sourceCalls non-empty | Every input path + SHA-256 listed |
| 17 | Emits rollup with correct counts | fixture with known status distribution | rollup.satisfied + partially_satisfied + not_satisfied + not_assessed + requires_operator_input === total_augmentations_evaluated | Roll-up arithmetic exact |
| 18 | Re-emits T.T2 matrix as augmented with interleaved rows | T.T2 fixture | `ssdf-satisfaction-matrix.augmented.json` contains every base task + every augmentation under matching parent | Round-trip preserves base fields |
| 19 | IPD-vs-final delta detects renamed augmentations | fixture pair with one `PO.1.A1 → PO.1.A2` rename | delta JSON `renamed[]` has one entry | Delta sidecar emitted |
| 20 | XLSX renderer writes one worksheet per in-scope product + summary + delta | mixed-scope fixture (2 in-scope) | workbook has 4 worksheets (summary + 2 products + delta) | SheetJS round-trip reads back cell A2 |
| 21 | XLSX schema pinned: 15 columns A..O per per-product worksheet | golden xlsx | header row in product worksheet matches documented A..O list | Header row exact |
| 22 | Signed envelope + RFC 3161 timestamp generated | end-to-end run | `out/ssdf-ai-augmentation.json.sig` + `.tsr` exist; verify against pubkey | Sign + timestamp pipeline integrates |
| 23 | Orchestrator skips T.T5 when `--ssdf-attestation` unset | integration test | no T.T5 artefacts emitted | Conditional gate works |
| 24 | Orchestrator skips T.T5 when `config.ssdf.ai_augmentation_enabled: false` | integration test with flag set + config disabled | `{ skipped: true, reason: 'ai-augmentation-disabled' }` | Both gates required |
| 25 | Drift threshold warning: emits warning when restated count exceeds threshold | fixture with 6 restated entries + default threshold 5 | log line includes `ipd-vs-final drift exceeds threshold` | Operator-readable warning surfaced |

(25 specifications total; exceeds the required minimum of 15.)

## 9. Risks

| id | risk | likelihood | impact | mitigation |
|---|---|---|---|---|
| R1 | **IPD vs final divergence not caught at extractor time.** NIST may have re-titled or renumbered augmentations between April 2024 (IPD) and July 2024 (final). T.T5 anchors on the IPD per the user task brief; silent drift could mean the augmented matrix references augmentation IDs that the final publication does not carry, embarrassing the producer at attestation review. | medium | medium | Extractor emits the delta sidecar (Algorithm step 8); operator-configurable drift threshold triggers a warning; the augmented matrix carries `catalogue_version: 'IPD'` in its envelope so consumers can trace which catalogue produced which rows. |
| R2 | **PDF extraction brittleness.** The 800-218A PDFs are typeset; SP 800-series tables historically use heterogeneous layouts. A future-revision PDF could break the extractor's column-detection heuristic, producing a malformed catalogue. | medium | medium | Extractor asserts expected column headers; throws typed error on mismatch; catalogue load validates `practices.length >= 4` (the four practice groups) and that every augmentation has non-empty `statement`; CI re-runs extractor and diffs the committed JSON. |
| R3 | **Model-card schema drift between LOOP-O.O5 and T.T5.** LOOP-O.O5 may evolve its model-card schema independently; T.T5's join breaks silently. | medium | high | Use a shared zod schema in `core/model-cards.ts` exported as `ModelCardSchema`; T.T5 imports and validates on load; throw on schema mismatch with a remediation message naming the breaking field. Integration test exercises both modules. |
| R4 | **EO 14110 rescission narrative obscures statutory authority.** A future agency contracting officer may challenge whether SP 800-218A still has statutory force after EO 14110 was rescinded by EO 14148 (Jan 20, 2025). | medium | medium | T.T5 module docstring documents the EO 14028 → EO 14110 → SP 800-218A → OMB M-26-05 lineage explicitly; the augmented matrix carries an `eo_lineage: ['EO 14028 §4(e)', 'EO 14110 §4.2(a)(i) (rescinded)', 'NIST SP 800-218A (not withdrawn)', 'OMB M-26-05 (risk-based tailored regime)']` field that consumers can show to the contracting officer. |
| R5 | **Model card present but AI evidence absent (silent partial-satisfied).** A product with an `ai_use_case` declared but no pre/post-deployment evaluations rolls up as `partially-satisfied` across the entire augmentation set — visually masking the fact that the producer has done no AI-specific evidence work. | high | medium | The roll-up worksheet explicitly highlights products whose `ai_specific_evidence_count: 0`; T.T3 reads the augmented matrix and embeds a per-product "AI evidence completeness" badge in the form-companion PDF; the warning is also emitted in the run log. |
| R6 | **Orchestrator ordering bug.** T.T5 depends on T.T2 (matrix) AND on LOOP-O.O5 (model cards). If the orchestrator runs T.T5 before either, the JSON read fails. | low | high | Orchestrator step `ssdf-ai-augmentation` declares `dependsOn: ['ssdf-aggregate', 'model-cards-emit']`; the step runner throws if either dependency hasn't run; integration test exercises the dependency graph. |
| R7 | **AI-KSI envelopes use augmentation_id that the catalogue doesn't yet carry.** A LOOP-O collector may emit a finding referencing an `PO.1.A99` that doesn't exist in the catalogue. | low | low | Catalogue join validates every envelope's referenced augmentation_id; unknown IDs land in a `requires-operator-input` row with `derivation: 'requires-operator-input'` and a derivation_explanation naming the unknown ID. |

(Seven risks; exceeds the required minimum of 4.)

## 10. Open questions

- **Q1**: Should the augmented matrix carry a per-augmentation
  `confidence_score` derived from how many independent AI-evidence
  sources agree (model card + pre-deployment eval + red-team)? Could be
  a future enhancement; for now, status is binary per the derivation
  table. Recommend: defer to a future LOOP-T.T6.
- **Q2**: Should T.T5 emit a separate POA&M directly, or rely on
  LOOP-A.A1 to read the augmented matrix's `not-satisfied` rows? The
  current design routes through A.A1 (single POA&M emitter; consistent
  schema). Recommend: keep the A.A1 route.
- **Q3**: When `primary_catalogue: 'final'` (operator override), does
  the augmented matrix still record the IPD as a reference? Yes — the
  provenance block carries both `catalogue_version` and a sibling field
  `catalogue_secondary_version` so the audit trail records which
  catalogue the operator chose. Recommend: implement now.
- **Q4**: Should the xlsx workbook include a "FAQ" worksheet
  summarising the EO 14110 → EO 14148 → SP 800-218A → OMB M-26-05
  statutory lineage for the corporate officer? Recommend: yes; canned
  text from the slice doc's Section 2; ~150 words.
- **Q5**: How does T.T5 interact with LOOP-S.S1 (DFARS equivalency
  bundle) when a DoD-prime customer's contract calls out 800-218A?
  S.S1 reads `ssdf-satisfaction-matrix.augmented.json` if present and
  embeds the augmented rows in the DFARS BoE. Recommend: document the
  cross-reference in S.S1's spec; no T.T5-side change required.

## 11. REQUIRES-OPERATOR-INPUT fields

| field name | type | validator | UI location | failure mode if missing |
|---|---|---|---|---|
| `config.ssdf.ai_augmentation_enabled` | boolean | zod boolean; default false | `config.yaml` | T.T5 exits early with `{ skipped: true, reason: 'ai-augmentation-disabled' }`; coverage:skipped log emitted; downstream T.T3 emits the form-companion PDF without 800-218A rows |
| `config.ssdf.primary_catalogue` | enum: 'IPD' \| 'final' | zod enum; default 'IPD' | `config.yaml` | If absent, defaults to 'IPD' per user task brief; warning logged if delta sidecar shows materially divergent final |
| `config.ssdf.products_in_scope` | array of product_id strings | zod array | `config.yaml` | If absent, T.T5 auto-detects from model cards; explicit override constrains the in-scope set |
| `config.ssdf.ipd_vs_final_drift_threshold` | integer | zod nat; default 5 | `config.yaml` | If exceeded, log warning suggesting operator switch primary catalogue to 'final' |
| `model_card.ai_use_case` | string | non-empty when product carries AI | tracker UI `/ssdf/ai-augmentation` (LOOP-O.O5 page) | Empty = product excluded from T.T5 scope; `coverage:skipped` row in products_out_of_scope |
| `model_card.is_dual_use_foundation_model` | boolean | zod boolean | tracker UI | Defaults to false; mis-set could exclude a foundation model from `dual-use-foundation-model`-scoped augmentations |
| `model_card.pre_deployment_evaluations[]` | array of `{ id, report_path }` | zod array | tracker UI per-product page | Absent ⇒ AI-specific evidence absent for that product; augmentations roll up `partially-satisfied` (inherits-parent) |
| `model_card.post_deployment_evaluations[]` | same shape | zod array | tracker UI | Absent ⇒ AI-specific evidence partial |
| `model_card.red_team_engagements[]` | same shape | zod array | tracker UI | Absent ⇒ AI-specific evidence partial for PW.4-family augmentations |
| `model_card.training_data_provenance.attestation_pointer` | string \| null | URI or null | tracker UI | null ⇒ PS.3-family augmentations roll up `partially-satisfied` (inherits-parent) |
| Augmentation row with `applies_to` empty | (catalogue bug) | extractor sets default `['both']` if absent in PDF | (n/a) | Catalogue audit log records assumption; sidecar JSON flags the row |

## 12. Implementation log

| date | session | action | commit | notes |
|---|---|---|---|---|
|  |  |  |  |  |

(empty — implementing session fills this in as work progresses, per `docs/IMPLEMENTATION-LOG-TEMPLATE.md` §3)

## 13. Completion checklist

The implementing session MUST execute the 7-step procedure from
`cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` verbatim. Quoted
in full:

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

**Plus the additional T.T5-specific final step (per user directive):**
After commit lands, append a row to `cloud-evidence/docs/STATUS.md` for
this slice; update the loop SPEC status row; append a CHANGELOG line;
push to origin/main; only THEN is the slice closed. The slice is also
closed only when the per-slice doc frontmatter has been updated
(`status: done`, `commit: <hash>`, `completed_date: <ISO>`,
`last_updated: <ISO>`) AND the Implementation log has at least one
final entry with the commit reference.

## Resume-from-fresh-session checklist

If a session opens with ONLY this file as context:

1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. This file gives you: source obligations + files to create + build
   steps + tests + risks + completion checklist + conditional gate.
3. Read `cloud-evidence/docs/loops/LOOP-T-SPEC.md` Section 2 (Statutory
   & regulatory drivers) and Section 5 (Reusable primitives) for
   cross-loop context.
4. Read `cloud-evidence/docs/slices/T/T.T2.md` Section 5 (Outputs) to
   confirm the satisfaction-matrix shape T.T5 reads as input.
5. Read `cloud-evidence/docs/slices/O/O.O5.md` Section 5 (Outputs) to
   confirm the model-card shape T.T5 reads as input.
6. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the
   mandatory 7-step commit pattern.
7. Read `cloud-evidence/docs/IMPLEMENTATION-LOG-TEMPLATE.md` for the
   per-slice running-journal format.
8. Confirm both PDFs exist under `docs/sources/`:
   - `nist-sp-800-218A.ipd.pdf` (IPD, April 29 2024)
   - `nist-sp-800-218A.pdf` (final, July 26 2024)
   If absent, download from NIST CSRC before running the extractor.
9. Confirm `docs/sources/omb-m-22-18.pdf`, `omb-m-23-16.pdf`,
   `omb-m-26-05.pdf`, `cisa-common-form.pdf`, `eo-14110.pdf`,
   `eo-14148.pdf`, and `eo-14028.pdf` are all committed with `.sha256`
   siblings.
10. Begin implementation; update the Implementation log section as
    work progresses (every commit boundary, every test failure, every
    research question answered).

---
