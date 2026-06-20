---
loop_id: T
title: NIST SSDF self-attestation via CISA Self-Attestation Common Form (corporate procurement gate)
status: pending
applicable_conditional: true
condition: CSP sells software to ANY federal agency (civilian or defense) under a contract that references OMB M-22-18 / M-23-16 — including legacy contracts entered before OMB M-26-05 (Jan 23 2026) rescinded the mandatory common-form requirement. Agencies that elect, post-M-26-05, to continue using the Common Form on a tailored / risk-based basis also bring the CSP into scope.
trigger_flag: "--ssdf-attestation"
trigger_env: CLOUD_EVIDENCE_SSDF_ATTESTATION
depends_on: [LOOP-A.A1, LOOP-A.A2, LOOP-A.A3, LOOP-A.A4, LOOP-B.B1, LOOP-J.J3, LOOP-O.O5]
blocks: []
estimated_effort: 4 weeks (single implementer)
last_updated: 2026-06-07
---

# LOOP-T — NIST SSDF self-attestation via the CISA Self-Attestation Common Form

> Comprehensive implementation specification for the five slices in LOOP-T.
> Authored as a stand-alone artifact: any future Claude / human session can
> execute LOOP-T end-to-end by reading ONLY this file + the five supporting
> per-slice files cited in Section 3 ("Slice list"). No prior conversation
> history required.
>
> Authority: `cloud-evidence/CLAUDE.md` (Real-Evidence-Only standard) governs
> every slice below. Every byte emitted must trace back to real evidence or
> operator-supplied configuration. Slices ship under the Real Slice Contract
> in CLAUDE.md Rule 2.
>
> **APPLICABILITY NOTE — read first.** OMB Memorandum M-26-05 (January 23,
> 2026) rescinded the mandatory M-22-18 / M-23-16 Common Form collection
> requirement. LOOP-T is nevertheless implemented because (a) M-26-05
> explicitly permits agencies to continue using the Common Form, the NIST
> SSDF, and the RSAA on a tailored / risk-based basis; (b) legacy federal
> contracts entered before January 23 2026 frequently contain incorporated
> M-22-18 / M-23-16 obligations whose flow-down to the CSP persists
> through the term of the contract; (c) DoD-prime customers (see LOOP-S)
> often impose SSDF attestation as an equivalency artefact for CDI / CUI
> software; (d) FedRAMP package consumers and 3PAOs treat the SSDF
> attestation as a *de facto* readiness artefact independent of OMB's
> mandate. The slice emits the artefact in its canonical unsigned PDF
> form; the operator's corporate officer applies a digital signature
> outside the toolchain (REO Rule 1: no fake cryptographic operations).

---

## 1. Mission & scope (what makes this loop distinct from neighbors)

### What LOOP-T produces and why

LOOP-T builds the **corporate-officer-signed Secure Software Development
Self-Attestation Common Form** (CISA Common Form, OMB Control No.
1670-0052) — the procurement gate every federal agency customer expects
from a software producer when that producer's product is in scope for
OMB M-22-18 (Sep 14 2022), M-23-16 (Jun 9 2023), or any post-rescission
agency tailoring under M-26-05 (Jan 23 2026). The Common Form is the
"single page" outward face of a much larger compliance substrate: the
producer's implementation of the **NIST SP 800-218 v1.1 Secure Software
Development Framework (SSDF)** — 19 practices and 43 tasks across four
practice groups (Prepare the Organization, Protect the Software, Produce
Well-Secured Software, Respond to Vulnerabilities) — plus the
**NIST SP 800-218A** Community Profile augmentations for generative AI /
dual-use foundation models, finalised Jul 26 2024.

The form is one PDF; the substrate is an organisation-wide set of
practices. LOOP-T's purpose is to:

1. **Catalogue the SSDF practices and tasks** as a typed, machine-readable
   catalogue (T.T1).
2. **Aggregate per-practice evidence** by walking the KSI evidence
   envelopes shipped by LOOPs B through K (T.T2).
3. **Render the Common Form** as a canonical, unsigned PDF that the
   corporate officer signs out-of-band (T.T3).
4. **Track per-agency submissions** and annual re-attestation cadence,
   detecting material changes that require interim re-attestation (T.T4).
5. **Apply the 800-218A AI augmentations** for any in-scope AI/ML product
   line, feeding off LOOP-O.O5 model-card evidence (T.T5).

### Distinction from LOOP-J.J3.b (engineering supply-chain attestations)

LOOP-T is **NOT** the engineering supply-chain attestation work that LOOP
J.J3.b ships. The two artefacts live in different planes of the
compliance picture and **both are required**; neither substitutes for the
other.

| Dimension | LOOP-J.J3.b (engineering attestation) | LOOP-T (corporate attestation) |
|---|---|---|
| Statutory anchor | EO 14028 §4(e), NTIA SBOM Minimum Elements, SLSA L3, NIST SP 800-204D | OMB M-22-18 / M-23-16, NIST SP 800-218, CISA Common Form 1670-0052 |
| Signer | The build pipeline (machine: Sigstore / Fulcio short-lived cert, ambient OIDC identity) | Named corporate officer (CEO / CISO / VP Engineering) — a natural person |
| Artefact form | `cosign` signature blob + Rekor transparency-log entry + `intoto-statement.json` (SLSA Provenance v1 predicate) | Single-document signed PDF (Common Form) + Body-of-Evidence attachments + Plan of Action and Milestones (POA&M) where applicable |
| Cadence | Per-build (every CI run) | Per-product, annual (or upon material change), per-agency |
| Submission path | Rekor public log; consumed by agency software-bill-of-materials ingest | CISA Repository for Software Attestations and Artefacts (RSAA) at https://rsaa.cisa.gov/ for federal civilian; agency-specific portals for DoD; both pulled in M-26-05 voluntary regime |
| Verifying party | Any consumer (`cosign verify --certificate-identity`, Rekor proof) | Procurement / contracting officer at the federal agency |
| Failure mode | Build fails / cosign verification fails / Rekor entry missing | Form rejected; contract award withheld; existing contract paused under POA&M |
| What it attests | This *individual binary* came from this source tree on this commit | The *producer organisation* implements the SSDF practices behind every product the agency uses |
| Repository of record | Sigstore Rekor (public log) | CISA RSAA (federal repository) + producer's internal compliance archive |

A producer ships LOOP-J.J3.b artefacts every build (continuous,
machine-driven) AND LOOP-T artefacts annually per product (discrete,
human-signed). Both flow into the agency's software supply-chain
authorisation decision. A 3PAO performing an equivalency or FedRAMP
assessment will look for BOTH.

### Why this loop is its own loop (not folded into LOOP-J)

J.J3.b's threat model is binary-level forgery, dependency-substitution,
and provenance bypass. LOOP-T's threat model is *organisational*
self-attestation: did the producer's people, processes, environments,
and tools actually implement the SSDF practices? The two are answered by
different evidence types — runtime cryptographic proofs for J.J3.b,
organisation-wide policies + per-practice KSI evidence for LOOP-T. They
also have different consumers (CI/CD vs procurement) and different
failure recoveries (rebuild vs re-attest). Folding them together would
mask the corporate-officer signature obligation behind the engineering
detail, which is exactly the gap M-22-18 was designed to close.

### Artefacts LOOP-T delivers

| # | Artefact | Source slice | Consumer |
|---|---|---|---|
| 1 | `core/ssdf-practices-catalog.ts` + `data/ssdf-800-218-v1.1.json` — typed catalogue of 19 SSDF practices and 43 tasks with NIST 800-53 Rev 5 + FedRAMP KSI crosswalk | T.T1 | T.T2, T.T3, T.T5, third-party catalog consumers |
| 2 | `scripts/extract-ssdf-practices.mjs` — one-shot extractor from the NIST SP 800-218 v1.1 PDF + the published Excel companion table | T.T1 | T.T1 (re-runnable when NIST updates 800-218) |
| 3 | `core/ssdf-evidence-aggregator.ts` + `core/ssdf-satisfaction-matrix.ts` — per-practice evidence aggregator + satisfaction matrix | T.T2 | T.T3, T.T4, 3PAO inspectors, RSAA reviewer |
| 4 | `out/ssdf-satisfaction-matrix.json` + `.xlsx` — per-practice × per-task satisfaction matrix with evidence pointers | T.T2 | Internal review, 3PAO, RSAA |
| 5 | `core/ssdf-common-form.ts` + `core/ssdf-common-form-pdf.ts` — Common Form canonical-PDF emitter | T.T3 | Operator (signs); CISA RSAA; agency procurement |
| 6 | `out/ssdf-common-form-{product}-{fiscal-year}.pdf` — unsigned canonical PDF of the Common Form | T.T3 | Operator signs digitally, submits via RSAA / agency portal |
| 7 | `core/ssdf-annual-attestation.ts` + `core/ssdf-material-change-detector.ts` — annual cadence + material-change re-attestation trigger | T.T4 | Tracker DB; UI status pane; operator |
| 8 | Tracker pages `/ssdf/attestations`, `/ssdf/products` — per-agency submission registry + product registry | T.T4 | Operator, AO, internal compliance |
| 9 | `core/ssdf-ai-extension.ts` + `data/ssdf-800-218A-final.json` — SP 800-218A augmentation catalogue + per-product applicability | T.T5 | T.T2 (extends matrix when AI applies); LOOP-O.O5 |
| 10 | Tracker page `/ssdf/ai-augmentation` — per-AI-product augmentation worksheet | T.T5 | Operator; LOOP-O reviewers |

### Authorisation-package gaps closed

| Package gap | Slice | Authoritative source |
|---|---|---|
| No machine-readable SSDF practices catalogue | T.T1 | NIST SP 800-218 v1.1, Feb 2022 |
| No per-practice evidence aggregator joining KSI evidence to SSDF tasks | T.T2 | NIST SP 800-218 v1.1; CISA Common Form Section IV "Practices Attested" |
| No CISA Common Form emitter (the corporate-officer-signed PDF) | T.T3 | OMB M-22-18 §III; OMB M-23-16 §III; CISA Common Form OMB 1670-0052 |
| No per-agency annual re-attestation tracker | T.T4 | OMB M-23-16 §III timeline; agency tailoring under M-26-05 |
| No SSDF-AI extension covering generative AI / dual-use foundation models | T.T5 | NIST SP 800-218A, Jul 26 2024 (final) |

---

## 2. Statutory & regulatory drivers (with verbatim source quotes)

Every URL + spec referenced in any LOOP-T slice. All quotes are verbatim
where retrievable through the implementation session's WebFetch /
WebSearch path on **2026-06-07**. Where a primary source returns
HTTP 403 / 404 to anonymous fetches, the slice docstring records the URL
and the implementer downloads the PDF to
`cloud-evidence/docs/sources/` and re-quotes verbatim in the relevant
slice doc — those fetch-bound sources are flagged
`REQUIRES-RESEARCH: download-pdf-and-confirm-text`.

### Executive Order 14028 — Improving the Nation's Cybersecurity

- **Source:** White House, Executive Order 14028, May 12, 2021.
- **URL (pinned):** https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/
- **Date of access:** 2026-06-07.
- **§4(e) — verbatim** (publicly available text):

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

  REQUIRES-RESEARCH: confirm remaining clauses (B)-(K) verbatim from
  WhiteHouse.gov direct text once URL responds; mirror in
  `docs/sources/eo-14028.md`.

- **§4(f) — verbatim** (publicly available text):

  > "Within 60 days of the date of this order, the Secretary of Commerce,
  > in coordination with the Assistant Secretary for Communications and
  > Information and the Administrator of the National Telecommunications
  > and Information Administration, shall publish minimum elements for a
  > Software Bill of Materials (SBOM)."

- **§4(n) — verbatim** (publicly available text):

  > "Within 1 year of the date of this order, the Secretary of Homeland
  > Security, in consultation with the Attorney General, the Director of
  > the Office of Management and Budget, and the heads of such other
  > agencies as the Secretary deems appropriate, shall recommend to the
  > FAR Council contract language requiring suppliers of software
  > available for purchase by agencies to comply with, and attest to
  > complying with, any requirements issued pursuant to subsections
  > (g) through (k) of this section."

  Section 4(n) is the statutory taproot of the M-22-18 self-attestation
  obligation: the EO directed DHS to recommend FAR Council language
  requiring attestation; OMB M-22-18 then implemented that direction
  pending FAR Council action.

### OMB Memorandum M-22-18 — Enhancing the Security of the Software Supply Chain through Secure Software Development Practices

- **Source:** OMB, Memorandum M-22-18, September 14, 2022.
- **URL (pinned):** https://www.whitehouse.gov/wp-content/uploads/2022/09/M-22-18.pdf
- **Date of access:** 2026-06-07 (PDF returned HTTP 404 to anonymous
  fetch; the implementer downloads the PDF to
  `cloud-evidence/docs/sources/omb-m-22-18.pdf` before T.T3 ships).
- **Scope (paragraph II) — publicly summarised; verbatim quote pending
  PDF download:**

  > "This memorandum requires agencies to only use software provided by
  > software producers who can attest to complying with the Government-
  > specified secure software development practices, as described in the
  > NIST Guidance. Software subject to this memorandum includes software
  > developed after the effective date of this memorandum, as well as
  > existing software that is modified by major version changes ... after
  > the effective date of this memorandum."

  REQUIRES-RESEARCH: confirm verbatim against
  `docs/sources/omb-m-22-18.pdf` paragraph II.

- **Timeline (paragraphs III.B.2-4) — publicly reported deadlines
  (verbatim quote pending PDF):**

  Per multiple legal-firm syntheses indexed on 2026-06-07
  (Crowell & Moring, Wiley Law, Inside Government Contracts) and the
  Federal Register collection notice 2023-25251:

  > "Within 90 days, agencies must inventory all software subject to the
  > Memorandum; within 120 days, agencies will have developed a process
  > to communicate requirements to vendors and ensure that vendor
  > attestation letters can be collected in a central agency system;
  > within 180 days, agencies must assess training needs and develop
  > plans for the review and validation of attestation documents; within
  > 270 days for critical software and within 365 days for all others,
  > agencies will require self-attestations from all software producers."

- **Plan of Action and Milestones (POA&M) safety valve (paragraph
  III.E):**

  > "In lieu of providing the required attestation in full, software
  > producers may identify those practices to which they cannot attest,
  > document practices they have in place to mitigate associated risks,
  > and provide an agency with a Plan of Action and Milestones (POA&M)."

  REQUIRES-RESEARCH: confirm exact wording from PDF paragraph III.E.

- **Third-party software (paragraph III.D):** producers may rely on
  attestations from their third-party suppliers, but the producer
  remains the attesting party to the agency — the producer "owns" the
  attestation regardless of upstream code provenance.

### OMB Memorandum M-23-16 — Update to M-22-18

- **Source:** OMB, Memorandum M-23-16, June 9, 2023.
- **URL (pinned):** https://www.whitehouse.gov/wp-content/uploads/2023/06/M-23-16-Update-to-M-22-18-Enhancing-Software-Supply-Chain-Security.pdf
- **Date of access:** 2026-06-07 (PDF returned HTTP 404 to anonymous
  fetch; the implementer downloads to
  `docs/sources/omb-m-23-16.pdf` before T.T3 ships).
- **Extended timeline (paragraph II):**

  > "For critical software, agencies must collect attestations no later
  > than three months after the common form is finalized; for other
  > software subject to M-22-18, agencies must collect attestations no
  > later than six months after the common form is approved."

  REQUIRES-RESEARCH: confirm verbatim from PDF.

- **Common Form requirement (paragraph III):**

  > "OMB and CISA, in consultation with agencies and other stakeholders,
  > have developed a standard self-attestation common form, to be used
  > by Federal agencies."

  REQUIRES-RESEARCH: confirm verbatim from PDF.

- **Critical vs. non-critical software:** M-23-16 preserves M-22-18's
  reliance on the NIST "EO-critical software" definition; for purposes
  of LOOP-T, the operator declares per product whether it meets the
  critical-software definition (a free-form configuration field in
  `ssdf-config.yaml`).

### OMB Memorandum M-26-05 — Adopting a Risk-based Approach to Software and Hardware Security

- **Source:** OMB, Memorandum M-26-05, January 23, 2026.
- **URL (pinned, pending official posting):** https://www.whitehouse.gov/wp-content/uploads/2026/01/M-26-05.pdf
- **Date of access:** 2026-06-07.
- **Effect on M-22-18 / M-23-16:** rescinds the mandatory Common Form
  collection requirement; preserves the underlying inventory obligation;
  permits agencies to elect, on a tailored / risk-based basis, to
  continue using the Common Form, the SSDF, the NIST resources, and the
  RSAA.
- **Verbatim quote (from Inside Government Contracts, Feb 2026
  synthesis, accessed 2026-06-07):**

  > "M-26-05 does not prohibit agencies from using resources developed
  > under M-22-18; agencies can still choose to use the Common Form,
  > along with the NIST secure software development standards and other
  > NIST resources, as part of such a tailored approach."

  REQUIRES-RESEARCH: replace with verbatim text from
  `docs/sources/omb-m-26-05.pdf` once download succeeds.
- **Why LOOP-T still ships under M-26-05:** see the applicability note
  in the loop header. The CSP that participates in (a) any legacy
  contract whose flow-down clauses incorporate M-22-18 / M-23-16, (b)
  any agency tailoring post-M-26-05 that elects the Common Form, or
  (c) any DoD-prime customer reading the Common Form as an equivalency
  artefact — must continue to emit the Common Form.

### NIST SP 800-218 v1.1 — Secure Software Development Framework

- **Source:** NIST CSRC, Special Publication 800-218, "Secure Software
  Development Framework (SSDF) Version 1.1: Recommendations for
  Mitigating the Risk of Software Vulnerabilities", February 2022.
- **URL (pinned):** https://csrc.nist.gov/pubs/sp/800/218/final
- **PDF URL (pinned):** https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf
- **Date of access:** 2026-06-07 (PDF fetched 722 KB to local cache;
  binary stream parsed as application/pdf; implementer must download
  to `docs/sources/nist-sp-800-218.pdf` for textual verbatim extraction
  in T.T1).
- **Four practice groups (verbatim group names, as published in NIST SP
  800-218 §2):**

  > "Prepare the Organization (PO): Organizations should ensure that their
  > people, processes, and technology are prepared to perform secure
  > software development at the organization level. Many organizations
  > will find some PO practices also applicable to subsets of their
  > software development, like individual development groups or
  > projects."

  > "Protect the Software (PS): Organizations should protect all
  > components of their software from tampering and unauthorized access."

  > "Produce Well-Secured Software (PW): Organizations should produce
  > well-secured software with minimal security vulnerabilities in its
  > releases."

  > "Respond to Vulnerabilities (RV): Organizations should identify
  > residual vulnerabilities in their software releases and respond
  > appropriately to address those vulnerabilities and prevent similar
  > ones from occurring in the future."

  REQUIRES-RESEARCH: verbatim group-level paragraphs above re-confirmed
  against `docs/sources/nist-sp-800-218.pdf` §2 in T.T1 extraction.

- **Task statements — verbatim text marked REQUIRES-RESEARCH until
  T.T1's extractor parses the PDF or the published Excel companion
  (`SP 800-218 Table in Excel (xlsx)`):**

  - **PO.1.1** — "Identify and document all security requirements for
    the organization's software development infrastructures and
    processes, and maintain the requirements over time."
    REQUIRES-RESEARCH: re-confirm verbatim from PDF.
  - **PO.5.1** — "Separate and protect each environment involved in
    software development."
    REQUIRES-RESEARCH: re-confirm verbatim from PDF.
  - **PS.1.1** — "Store all forms of code — including source code,
    executable code, and configuration-as-code — based on the principle
    of least privilege so that only authorized personnel, tools,
    services, etc. have access."
    REQUIRES-RESEARCH: re-confirm verbatim from PDF.
  - **PS.2.1** — "Make software integrity verification information
    available to software acquirers."
    REQUIRES-RESEARCH: re-confirm verbatim from PDF.
  - **PS.3.1** — "Securely archive the necessary files and supporting
    data (e.g., integrity verification information, provenance data) to
    be retained for each software release."
    REQUIRES-RESEARCH: re-confirm verbatim from PDF.
  - **PW.1.1** — "Use forms of risk modeling — such as threat modeling,
    attack modeling, or attack surface mapping — to help assess the
    security risk for the software."
    REQUIRES-RESEARCH: re-confirm verbatim from PDF.
  - **PW.4.1** — "Acquire and maintain well-secured software components
    (e.g., software libraries, modules, middleware, frameworks) from
    commercial, open-source, and other third-party developers for use
    by the organization's software."
    REQUIRES-RESEARCH: re-confirm verbatim from PDF.
  - **PW.6.1** — "Use compiler, interpreter, and build tools that offer
    features to improve executable security."
    REQUIRES-RESEARCH: re-confirm verbatim from PDF.
  - **PW.7.1** — "Determine whether code review (a person directly looks
    at the code to find issues) and/or code analysis (tools are used to
    find issues in code, either in a fully automated way or in
    conjunction with a person) should be used, as defined by the
    organization."
    REQUIRES-RESEARCH: re-confirm verbatim from PDF.
  - **PW.8.1** — "Determine whether executable code testing should be
    performed to find vulnerabilities not identified by previous
    reviews, analysis, or testing and, if so, which types of testing
    should be used."
    REQUIRES-RESEARCH: re-confirm verbatim from PDF.
  - **RV.1.1** — "Gather information from software acquirers, users,
    and public sources on potential vulnerabilities in the software and
    third-party components that the software uses, and investigate all
    credible reports."
    REQUIRES-RESEARCH: re-confirm verbatim from PDF.
  - **RV.1.2** — "Review, analyze, and/or test the software's code to
    identify or confirm the presence of previously undetected
    vulnerabilities."
    REQUIRES-RESEARCH: re-confirm verbatim from PDF.
  - **RV.2.1** — "Analyze each vulnerability to gather sufficient
    information about risk to plan its remediation or other risk
    response."
    REQUIRES-RESEARCH: re-confirm verbatim from PDF.
  - **RV.3.1** — "Analyze identified vulnerabilities to determine their
    root causes."
    REQUIRES-RESEARCH: re-confirm verbatim from PDF.

- **Why this matters for LOOP-T:** the Common Form (T.T3) declares the
  producer "follows secure development practices and tasks, which are
  in alignment with [NIST] SP 800-218". The four attestations on the
  form map, per CISA's published instruction, to 17 of the 19 SSDF
  practices and 31 of the 43 tasks. T.T2's satisfaction matrix is the
  per-task evidence backbone of that mapping.

### NIST SP 800-218A — Secure Software Development Practices for Generative AI and Dual-Use Foundation Models: An SSDF Community Profile

- **Source:** NIST CSRC, Special Publication 800-218A, "Secure Software
  Development Practices for Generative AI and Dual-Use Foundation
  Models: An SSDF Community Profile", final published July 26, 2024.
- **URL (pinned):** https://csrc.nist.gov/pubs/sp/800/218/a/final
- **PDF URL (pinned):** https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf
- **Date of access:** 2026-06-07.
- **Purpose (verbatim from NIST publication-page abstract):**

  > "This document augments the secure software development practices
  > and tasks defined in SP 800-218, Secure Software Development
  > Framework (SSDF) Version 1.1. The augmentations are specific to AI
  > model development throughout the software development life cycle."

  REQUIRES-RESEARCH: confirm against the published PDF abstract.

- **Statutory anchor:** EO 14110 (Oct 30 2023), "Safe, Secure, and
  Trustworthy Development and Use of Artificial Intelligence", which
  tasked NIST with "developing a companion resource to the [SSDF] to
  incorporate secure development practices for generative AI and for
  dual-use foundation models". (EO 14110 was rescinded by EO 14148 in
  Jan 2025, but the 800-218A Community Profile remains the published
  NIST guidance and is referenced in T.T5 because it is the only
  authoritative AI-extension catalogue. T.T5's docstring acknowledges
  the EO-rescission lineage.)
- **Why this matters for LOOP-T:** any product that incorporates a
  generative-AI model or dual-use foundation model — including products
  in scope for LOOP-O.O5 model cards — triggers T.T5's augmentation
  worksheet on top of T.T2's SSDF satisfaction matrix.

### CISA Secure Software Development Attestation Common Form

- **Source:** CISA + OMB, "Secure Software Development Attestation Form",
  finalised March 11, 2024.
- **URL (pinned):** https://www.cisa.gov/resources-tools/resources/secure-software-development-attestation-form
- **Form PDF (pinned):** https://www.cisa.gov/sites/default/files/2024-04/Self_Attestation_Common_Form_FINAL_508c.pdf
- **OMB Control Number:** 1670-0052
- **Date of access:** 2026-06-07 (page returned HTTP 403 to anonymous
  fetch; implementer downloads to
  `docs/sources/cisa-common-form.pdf` before T.T3 ships).
- **Form structure (publicly summarised; verbatim text marked
  REQUIRES-RESEARCH):**
  - **Section I — Software Producer Information:** company name, address,
    DUNS / UEI, point of contact (name, title, email, phone),
    OMB control number, expiration date.
  - **Section II — Software Information:** product name, version,
    description, whether the product is "EO-critical software", whether
    the attestation covers a single product or a product line.
  - **Section III — Attestation Statements (the four attestations).**
  - **Section IV — Signature.**
- **Attestation language (the four attestations) — paraphrased from
  the publicly-circulated CISA + counsel-firm syntheses; verbatim text
  marked REQUIRES-RESEARCH against
  `docs/sources/cisa-common-form.pdf`:**

  > "1. The software was developed and built in secure environments.
  > Those environments were secured by the following actions, at a
  > minimum:
  > (a) separating and protecting each environment involved in
  > developing and building software;
  > (b) regularly logging, monitoring, and auditing trust
  > relationships used for authorization and access (i) to any software
  > development and build environments; and (ii) among components within
  > each environment;
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

  > "2. The software producer has made a good-faith effort to maintain
  > trusted source code supply chains by employing automated tools or
  > comparable processes to address the security of internal code and
  > third-party components and manage related vulnerabilities."

  > "3. The software producer maintains provenance for internal code and
  > third-party components incorporated into the software to the
  > greatest extent feasible."

  > "4. The software producer employed automated tools or comparable
  > processes that check for security vulnerabilities. In addition:
  > (a) the software producer operated these processes on an ongoing
  > basis and, at a minimum, prior to product, version, or update
  > release; and
  > (b) the software producer has a policy or process to address
  > discovered security vulnerabilities prior to product release; and
  > (c) the software producer operates a vulnerability disclosure
  > program and accepts, reviews, and addresses disclosed software
  > vulnerabilities in a timely fashion and according to any timelines
  > specified in the vulnerability disclosure program or applicable
  > policies."

  REQUIRES-RESEARCH: re-confirm all four attestations verbatim from
  `docs/sources/cisa-common-form.pdf` Sections III.1-III.4.

- **Signature block (Section IV) — publicly summarised:** "I [Name],
  [Title], attest under penalty of perjury that all of the statements
  above are true and accurate to the best of my knowledge"; signed by
  a "Chief Executive Officer or designee" of the software producer (an
  officer whose role gives them authority to bind the company).
- **SSDF mapping (CISA published instructions, paraphrased):** the four
  attestations collectively address 17 of the 19 SSDF practices and 31
  of the 43 tasks; T.T2's satisfaction matrix preserves the explicit
  mapping per practice / task so the attestation can be defended at
  audit.

### CISA Repository for Software Attestations and Artefacts (RSAA)

- **Source:** CISA, "Repository for Software Attestations and Artefacts
  (RSAA)", March 18, 2024.
- **URL (pinned):** https://www.cisa.gov/resources-tools/services/repository-software-attestations-and-artifacts-rsaa
- **User Guide PDF (pinned):** https://www.cisa.gov/sites/default/files/2024-03/CISA_RSAA_User_Guide_18_March_2024.pdf
- **Date of access:** 2026-06-07.
- **Purpose:** repository application where federal agencies and software
  producers store and retrieve attestation forms and supporting
  artefacts. Producers submit the signed Common Form via the RSAA;
  agencies retrieve from the RSAA.
- **Verbatim purpose statement (paraphrased from User Guide page 1):**

  > "The RSAA serves to satisfy the requirements set forth in M-22-18
  > and M-23-16. The RSAA application serves as a repository for all
  > software producers' Attestations."

  REQUIRES-RESEARCH: re-confirm from
  `docs/sources/cisa-rsaa-user-guide.pdf`.

- **LOOP-T's relationship to the RSAA:** LOOP-T emits the unsigned
  canonical PDF that the operator signs and uploads to RSAA. LOOP-T
  does **not** auto-submit (REO Rule 4 — human action). T.T4's tracker
  registry records the per-product RSAA submission identifier so the
  next-cycle re-attestation can chain forward.

### NIST IR 8397 — Guidelines on Minimum Standards for Developer Verification of Software

- **Source:** NIST IR 8397, October 2021.
- **URL (pinned):** https://csrc.nist.gov/pubs/ir/8397/final
- **Date of access:** 2026-06-07.
- **Relevance to LOOP-T:** IR 8397 specifies the minimum verification
  techniques (static analysis, code review, dependency scanning,
  fuzzing) that satisfy SSDF practices PW.7 and PW.8. T.T2 cites IR
  8397 in the docstring for the PW.7.1 / PW.8.1 evidence aggregator so
  that a 3PAO can trace each evidence pointer back to the IR 8397
  technique.

### NIST SP 800-161 Rev 1 — Cybersecurity Supply Chain Risk Management Practices for Systems and Organizations

- **Source:** NIST SP 800-161 Revision 1, May 2022.
- **URL (pinned):** https://csrc.nist.gov/pubs/sp/800/161/r1/final
- **Date of access:** 2026-06-07.
- **Relevance to LOOP-T:** 800-161r1 is the parent C-SCRM publication
  to which SSDF feeds. LOOP-J.J3 emits the 800-161 Tier-3 supplier-risk
  register; LOOP-T.T2's per-practice aggregator cross-references the
  J.J3 register for PW.4 (third-party components) and PO.1 (security
  requirements for the development infrastructure).

### CISA Software Acquisition Guide for Government Enterprise Consumers

- **Source:** CISA, "Software Acquisition Guide for Government
  Enterprise Consumers", 2024.
- **URL (pinned):** https://www.cisa.gov/resources-tools/resources/software-acquisition-guide-government-enterprise-consumers
- **Date of access:** 2026-06-07.
- **Relevance to LOOP-T:** the Acquisition Guide is the agency-side
  companion to the Common Form; T.T3 cites it in the Common Form
  cover-letter template so the operator's submission anchors to the
  same procurement-language vocabulary the agency uses to evaluate.

### 32 CFR Part 236 / DFARS 252.204-7012 (cross-reference only)

LOOP-T does not directly invoke 32 CFR Part 236 or DFARS 252.204-7012;
LOOP-S handles DFARS equivalency for DoD-prime customers. T.T2's
satisfaction-matrix evidence is consumed by LOOP-S.S1 as a substrate
when the CSP is a DoD-prime customer.

---

## 3. Slice list (table)

| id | title | status | commit | dependencies | estimated_effort |
|---|---|---|---|---|---|
| T.T1 | SSDF Practices Inventory (catalogue + extractor) | done | `9bbbcd1` (2026-06-10) | LOOP-A.A1, LOOP-A.A4 | 4-5 working days |
| T.T2 | Per-Practice Evidence Aggregator + Satisfaction Matrix | done | `<TBD-step6>` (2026-06-20) | T.T1, LOOP-B.B1, LOOP-J.J2, LOOP-J.J3, KSI envelopes from LOOPs B-K | 5-6 working days |
| T.T3 | CISA Common Form Generator (unsigned canonical PDF) | pending | — | T.T2, LOOP-A.A4 (bundler) | 5-6 working days |
| T.T4 | Annual Re-Attestation Workflow + Material-Change Detector | pending | — | T.T3, Tracker DB | 4-5 working days |
| T.T5 | SP 800-218A SSDF-AI Extension | pending | — | T.T2, LOOP-O.O5 | 3-4 working days |

Total estimated effort: **21-26 working days** (≈ 4 weeks) for a single
implementer.

Per-slice deep-context docs live under
`/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/slices/T/T.T1.md`,
`...T.T2.md`, `...T.T3.md`, `...T.T4.md`, `...T.T5.md`. Each per-slice
doc carries the YAML frontmatter, 13-section structure, 15+ tests, 4+
risks, implementation-log slot, and 7-step completion checklist
mandated by the user's ground-up directive (2026-06-07).

---

## 4. Authoritative sources (full list with URLs)

All sources are dated **2026-06-07**. Each source is cited verbatim in
Section 2; this section is the URL index for quick re-lookup. Sources
flagged `REQUIRES-RESEARCH` need a PDF download to confirm verbatim
text before the dependent slice ships.

| # | Source | URL | Status |
|---|---|---|---|
| 1 | EO 14028, May 12 2021 | https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/ | REQUIRES-RESEARCH (confirm §4(e),(f),(n) verbatim) |
| 2 | OMB M-22-18, Sep 14 2022 | https://www.whitehouse.gov/wp-content/uploads/2022/09/M-22-18.pdf | REQUIRES-RESEARCH (PDF download) |
| 3 | OMB M-23-16, Jun 9 2023 | https://www.whitehouse.gov/wp-content/uploads/2023/06/M-23-16-Update-to-M-22-18-Enhancing-Software-Supply-Chain-Security.pdf | REQUIRES-RESEARCH (PDF download) |
| 4 | OMB M-26-05, Jan 23 2026 | https://www.whitehouse.gov/wp-content/uploads/2026/01/M-26-05.pdf | REQUIRES-RESEARCH (PDF download) |
| 5 | NIST SP 800-218 v1.1, Feb 2022 | https://csrc.nist.gov/pubs/sp/800/218/final | confirmed page; PDF downloaded 722 KB; T.T1 extractor parses it |
| 6 | NIST SP 800-218 v1.1 PDF | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf | PDF download (722 KB) confirmed |
| 7 | NIST SP 800-218 Excel companion | https://csrc.nist.gov/CSRC/media/Publications/sp/800-218/final/documents/NIST.SP.800-218.Table.xlsx | T.T1 extractor consumes |
| 8 | NIST SP 800-218A, Jul 26 2024 (final) | https://csrc.nist.gov/pubs/sp/800/218/a/final | confirmed |
| 9 | NIST SP 800-218A PDF | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf | T.T5 extractor consumes |
| 10 | CISA Common Form page | https://www.cisa.gov/resources-tools/resources/secure-software-development-attestation-form | REQUIRES-RESEARCH (403 to anon) |
| 11 | CISA Common Form PDF | https://www.cisa.gov/sites/default/files/2024-04/Self_Attestation_Common_Form_FINAL_508c.pdf | REQUIRES-RESEARCH (download) |
| 12 | CISA RSAA service page | https://www.cisa.gov/resources-tools/services/repository-software-attestations-and-artifacts-rsaa | confirmed |
| 13 | CISA RSAA User Guide PDF | https://www.cisa.gov/sites/default/files/2024-03/CISA_RSAA_User_Guide_18_March_2024.pdf | REQUIRES-RESEARCH (download) |
| 14 | NIST IR 8397, Oct 2021 | https://csrc.nist.gov/pubs/ir/8397/final | confirmed |
| 15 | NIST SP 800-161r1, May 2022 | https://csrc.nist.gov/pubs/sp/800/161/r1/final | confirmed |
| 16 | CISA Software Acquisition Guide for Government Enterprise Consumers | https://www.cisa.gov/resources-tools/resources/software-acquisition-guide-government-enterprise-consumers | confirmed |
| 17 | Federal Register collection notice 2023-25251 (Common Form) | https://www.federalregister.gov/documents/2023/11/16/2023-25251/agency-information-collection-activities-request-for-comment-on-secure-software-development | confirmed |
| 18 | NIST SSDF project page | https://csrc.nist.gov/projects/ssdf | confirmed |
| 19 | Inside Government Contracts, "OMB Rescinds the 'Common Form' Secure Software Attestation Requirement", Feb 2026 | https://www.insidegovernmentcontracts.com/2026/02/omb-rescinds-the-common-form-secure-software-attestation-requirement/ | confirmed |
| 20 | Wiley Law, "OMB Rescinds Secure Software Development Mandate in Favor of a Risk-Based Approach" | https://www.wiley.law/alert-OMB-Rescinds-Secure-Software-Development-Mandate-in-Favor-of-a-Risk-Based-Approach | confirmed |

---

## 5. Reusable primitives (modules from other loops this depends on)

LOOP-T composes existing FedPy primitives rather than re-implementing.
The table below lists every imported / extended module by source loop.

| Primitive | Source loop / file | How LOOP-T uses it |
|---|---|---|
| KSI envelope reader (`core/envelope.ts`) | LOOP-B foundation | T.T2 walks every `KsiEvidenceEnvelope` for per-KSI provenance + signed manifest references |
| OSCAL POA&M emitter (`core/oscal-poam.ts`) | LOOP-A.A1 | T.T3 emits an OSCAL POA&M companion document for any practice the producer cannot fully attest to (M-22-18 paragraph III.E safety valve) |
| Submission bundler (`core/submission-bundle.ts`) | LOOP-A.A4 | T.T3 adds 4 new roles (`ssdf-common-form-pdf`, `ssdf-satisfaction-matrix-json`, `ssdf-satisfaction-matrix-xlsx`, `ssdf-poam-companion-json`) to the `WELL_KNOWN` catalogue |
| Risk score (`core/risk-score.ts`) | LOOP-B.B1 | T.T2 reads composite risk scores per practice so the matrix's "open risk" column reflects current LOOP-B state |
| Subprocessor inventory (`core/subprocessor-inventory.ts`) | LOOP-J.J2 | T.T2 reads subprocessor inventory for PO.1 / PW.4 evidence pointers |
| Supply-chain risk register (`core/supply-chain-risk-register.ts`) | LOOP-J.J3 | T.T2 reads the J.J3 register for PW.4 (third-party components) evidence |
| SBOM reports (`core/sbom.ts`) | E.2 SBOM depth | T.T2 reads SBOM-cosign verification state for PS.2 / PW.4 evidence |
| Cosign verification + Rekor entries (`core/cosign-verify.ts`) | LOOP-J.J3.b (engineering attestation) | T.T2 reads cosign verification state to cross-reference PS.2.1 + PW.6 evidence; **does NOT replace the engineering attestation** (see §1 distinction) |
| OSCAL SSP emitter (`core/oscal-ssp.ts`) | SSP-1 | T.T3 cross-references SSP component-uuid for "Software Information" Section II |
| Tracker DB (`tracker/server/schema.sql`) | tracker baseline | T.T4 introduces tables `ssdf_products`, `ssdf_attestation_submissions`, `ssdf_practice_overrides`, `ssdf_material_change_events` |
| Tracker UI scaffolding | tracker baseline | T.T4 + T.T5 add four pages: `/ssdf/products`, `/ssdf/attestations`, `/ssdf/material-changes`, `/ssdf/ai-augmentation` |
| Signing pipeline (`core/sign.ts`) | LOOP-B B.1 | T.T3 emits the unsigned canonical PDF through the existing signing glob; the producer's corporate-officer wet/digital signature is **out-of-band** (operator action, REO Rule 1) — but the canonical PDF itself rides the existing Ed25519 + RFC 3161 chain so its integrity from emit to operator signing is verifiable |
| Model card emitter (`core/model-cards.ts`) | LOOP-O.O5 | T.T5 reads model-card-flagged products to determine 800-218A applicability |
| Document Template Pack (`core/docx-helpers.ts`) | LOOP-C | T.T3's PDF emitter reuses OOXML/zip-store layout helpers (pdf-lib-style; see T.T3 build steps) |
| Provenance check (`core/provenance.ts`) | REO guardrail | T.T2 + T.T3 emit `provenance` blocks on every JSON output |

---

## 6. Data flow diagram (Mermaid)

```mermaid
flowchart TD
  subgraph T1[T.T1 — SSDF Practices Inventory]
    nist218pdf["NIST SP 800-218 v1.1 PDF<br/>(docs/sources/nist-sp-800-218.pdf)"]
    nist218xlsx["NIST SP 800-218 Excel companion<br/>(docs/sources/NIST.SP.800-218.Table.xlsx)"]
    extractor["scripts/extract-ssdf-practices.mjs"]
    catalog["data/ssdf-800-218-v1.1.json<br/>(19 practices, 43 tasks,<br/>800-53r5 + KSI crosswalk)"]
    nist218pdf --> extractor
    nist218xlsx --> extractor
    extractor --> catalog
  end

  subgraph T2[T.T2 — Per-Practice Evidence Aggregator]
    ksi["KSI envelopes (LOOPs B-K)<br/>out/ksi-evidence/*.json"]
    poam["OSCAL POA&M<br/>out/poam.json"]
    risk["LOOP-B risk-score<br/>out/risk-register.json"]
    sbom["SBOM reports<br/>out/sbom/*.json"]
    subproc["Subprocessor inventory<br/>out/subprocessors.json"]
    scrm["Supply-chain risk register<br/>out/supply-chain-risk-register.json"]
    cosign["Cosign verification<br/>out/cosign-verify.json"]
    catalog --> aggregator["core/ssdf-evidence-aggregator.ts"]
    ksi --> aggregator
    poam --> aggregator
    risk --> aggregator
    sbom --> aggregator
    subproc --> aggregator
    scrm --> aggregator
    cosign --> aggregator
    aggregator --> matrix["core/ssdf-satisfaction-matrix.ts"]
    matrix --> matjson["out/ssdf-satisfaction-matrix.json"]
    matrix --> matxlsx["out/ssdf-satisfaction-matrix.xlsx"]
  end

  subgraph T5[T.T5 — SSDF-AI Extension]
    ai218["NIST SP 800-218A PDF<br/>(docs/sources/nist-sp-800-218A.pdf)"]
    aiextractor["scripts/extract-ssdf-ai-practices.mjs"]
    aicatalog["data/ssdf-800-218A-final.json"]
    modelcards["LOOP-O.O5 model cards<br/>out/model-cards/*.json"]
    ai218 --> aiextractor
    aiextractor --> aicatalog
    aicatalog --> aiaugmenter["core/ssdf-ai-extension.ts"]
    modelcards --> aiaugmenter
    matrix --> aiaugmenter
    aiaugmenter --> aimatrix["out/ssdf-ai-satisfaction-matrix.json"]
  end

  subgraph T3[T.T3 — CISA Common Form Generator]
    cfg["ssdf-config.yaml<br/>(product list, officer, OMB ctrl#)"]
    matrix --> formgen["core/ssdf-common-form.ts"]
    cfg --> formgen
    formgen --> pdfemit["core/ssdf-common-form-pdf.ts"]
    pdfemit --> formpdf["out/ssdf-common-form-{product}-{fy}.pdf<br/>(unsigned canonical)"]
    formgen --> poamcomp["out/ssdf-poam-companion.json<br/>(OSCAL POA&M for un-attestable practices)"]
  end

  subgraph T4[T.T4 — Annual Re-Attestation Workflow]
    tracker["Tracker DB<br/>ssdf_products / ssdf_attestation_submissions"]
    matchange["core/ssdf-material-change-detector.ts"]
    annual["core/ssdf-annual-attestation.ts"]
    formpdf --> tracker
    matchange --> tracker
    annual --> tracker
    matrix --> matchange
    tracker --> ui["tracker UI<br/>/ssdf/products /ssdf/attestations<br/>/ssdf/material-changes /ssdf/ai-augmentation"]
  end

  subgraph signing[Sign + Bundle (LOOP-A.A4)]
    formpdf --> sign["core/sign.ts<br/>(Ed25519 + RFC 3161)"]
    matjson --> sign
    matxlsx --> sign
    poamcomp --> sign
    aimatrix --> sign
    sign --> bundle["core/submission-bundle.ts<br/>+4 roles to WELL_KNOWN"]
    bundle --> archive["submission-bundle.tar.gz"]
  end

  archive --> operator((Operator: officer signs PDF;<br/>uploads to CISA RSAA))
```

The diagram captures the load-bearing data flow: NIST documents are
extracted into typed catalogues (T.T1, T.T5); KSI evidence is
aggregated into a per-practice satisfaction matrix (T.T2); the matrix
plus per-product config drives the Common Form PDF + POA&M companion
(T.T3); tracker DB persists per-agency submission state and
material-change events (T.T4); and the signed bundle is the unit the
operator submits.

---

## 7. Test strategy (per-slice + integration + adversarial cases)

### Per-slice coverage targets

| Slice | Unit tests | Integration tests | Adversarial / negative tests | Min total |
|---|---|---|---|---|
| T.T1 | 10 | 3 | 2 | 15 |
| T.T2 | 9 | 4 | 3 | 16 |
| T.T3 | 10 | 3 | 3 | 16 |
| T.T4 | 9 | 4 | 3 | 16 |
| T.T5 | 9 | 3 | 3 | 15 |

Every per-slice doc carries a 15+-row test table per the spec
requirement (raised from the prior 12-test floor for this batch). The
per-slice tables enumerate `id | scenario | fixture path | expected |
acceptance` for each test. Cross-cutting integration tests live under
`/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/integration/ssdf-attestation.test.ts`.

### Adversarial cases (every slice MUST cover)

1. **Catalogue tampering** (T.T1): the extractor refuses to parse a PDF
   whose SHA-256 does not match the pinned value in
   `docs/sources/nist-sp-800-218.sha256` — protects against silent
   NIST republication overriding the catalogue.
2. **Missing per-task evidence** (T.T2): an evidence aggregator asked
   about a practice with zero contributing KSI envelopes emits status
   `requires-operator-input` and surfaces the gap in the satisfaction
   matrix; the test pins the exact JSON shape so a 3PAO can grep it.
3. **POA&M coverage** (T.T3): when one or more SSDF practices fall to
   `not-satisfied`, T.T3 MUST emit an accompanying POA&M companion
   document with one `poam-item` per unsatisfied practice; the test
   forces a `not-satisfied` practice and asserts the companion JSON
   exists and includes the practice ID in `props[]`.
4. **Annual cadence** (T.T4): a submission whose `submitted_at` is more
   than 365 days old marks the next `due_at`; the test wind-clock
   advances past the due date and asserts the tracker UI surfaces a
   `due_now` state.
5. **Material change** (T.T4): when the SSDF satisfaction matrix
   changes (a practice flips from `satisfied` to `not-satisfied`), the
   material-change detector emits a tracker event tagged
   `material_change_kind = practice_regression`; the test forces such a
   regression and asserts the event fires.
6. **AI augmentation gating** (T.T5): when `product.ai_enabled = false`,
   the 800-218A augmenter MUST exit early without emitting; when
   `product.ai_enabled = true`, the augmenter MUST attach the 800-218A
   per-practice augmentations to the matrix. Tests cover both branches.
7. **Officer authority** (T.T3): when `ssdf-config.yaml` declares a
   signing officer whose `role` is not in the allowlist (`CEO`,
   `President`, `CISO`, `CTO`, `VP-Engineering`, `Chief Compliance
   Officer`, or `designee` with a documented designation letter), the
   PDF emitter exits with `REQUIRES-OPERATOR-INPUT: officer-role-not-permitted`.

### Property-based tests (T.T2, T.T3)

- For any random valid SSDF satisfaction matrix, the Common Form PDF
  emitter MUST produce a PDF whose canonical bytes are deterministic
  given the same input (no embedded timestamps from the renderer; the
  RFC 3161 timestamp lives outside the PDF in the LOOP-B B.2 manifest).
- For any random valid catalogue + evidence pair, the satisfaction
  matrix's totals MUST equal the sum of per-practice statuses
  (no double-counting; no orphan practices).

### Cross-loop integration tests

- End-to-end run from KSI evidence collection → satisfaction matrix →
  Common Form PDF → signing → submission-bundle tar.gz → unbundle →
  verify (under `tests/integration/ssdf-attestation.test.ts`).
- Co-existence with LOOP-J.J3.b: the same product's cosign +
  attestation artefacts AND Common Form PDF coexist in the bundle
  archive without role collisions (asserted in
  `tests/integration/loop-j-loop-t-coexistence.test.ts`).
- Co-existence with LOOP-S equivalency: T.T2's matrix is consumed by
  S.S1's NIST 800-171 crosswalk; the joint test verifies both
  artefacts ship without practice-evidence double-claim.

### REO guardrail tests (every slice)

- `npm run lint:no-stubs` MUST be clean: no `TODO` / `FIXME` /
  placeholder strings on production paths.
- `npm run check:provenance` MUST be clean: every emitted JSON has a
  `provenance` block.
- `npm run check:coverage-regression` MUST be clean: the
  ssdf-coverage report's fill rate does not drop versus `main`.

---

## 8. Risks summary (reference RISKS file; brief per-category breakdown)

The full per-loop risks register lives at
`/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/LOOP-T-RISKS.md`.
This section is the executive summary; per-slice risks (4+ per slice)
live in the per-slice docs.

### Category A — Regulatory volatility (highest urgency)

- **T-R-A1**: M-26-05 (Jan 23 2026) rescinded the mandatory Common Form
  collection requirement. **Mitigation**: LOOP-T ships anyway because
  legacy contracts + agency tailoring + LOOP-S equivalency still
  require it; `ssdf-config.yaml` declares per-agency applicability;
  `--ssdf-attestation` flag default is `off` and the emitter exits 0
  with a `coverage:skipped` log line when not applicable. **Residual
  exposure**: zero — the slice ships dormant when not needed.
- **T-R-A2**: NIST may publish SP 800-218 Rev 2 (currently in draft as
  SP 800-218 r1 IPD, Jun 2025 announcement). **Mitigation**: T.T1's
  extractor is schema-driven and idempotent; revision bump triggers a
  one-shot re-extract; the catalogue file is version-pinned.
- **T-R-A3**: FAR Council ultimately publishes a FAR clause supplanting
  the OMB memoranda's attestation language. **Mitigation**: T.T3's
  PDF renderer is template-driven; new template lands as a new
  rendering profile; existing template retained for legacy contracts.

### Category B — Evidence completeness (high urgency)

- **T-R-B1**: A producer in scope for OMB M-22-18 has fewer than 17 of
  the 19 SSDF practices covered by KSI evidence. **Mitigation**: T.T2's
  matrix surfaces every gap; POA&M companion (T.T3) provides the
  M-22-18 paragraph III.E safety valve.
- **T-R-B2**: Per-practice evidence depends on tracker / process
  artefacts the operator has not yet captured. **Mitigation**:
  `requires-operator-input` propagation; tracker UI flags every gap.

### Category C — Cryptographic / signing exposure (medium)

- **T-R-C1**: The Common Form requires a *natural-person* signature
  with penalty-of-perjury attestation. **Mitigation**: REO Rule 1 — the
  toolchain emits an unsigned canonical PDF; the operator signs via a
  qualified digital signature outside the toolchain; the tracker
  records the signed-PDF SHA-256 + signer identity for chain-of-custody.

### Category D — Tracker / UI scale (medium)

- **T-R-D1**: A producer with 100+ federal agency customers maintains
  100+ active per-agency submissions; the UI must scale. **Mitigation**:
  paginated list view; per-agency filter; CSV export.

### Category E — AI extension applicability (medium)

- **T-R-E1**: Operator misclassifies a product as AI / non-AI.
  **Mitigation**: T.T5 reads LOOP-O.O5's model-card registry as the
  authoritative AI scope source; explicit override in `ssdf-config.yaml`
  is logged.

(See LOOP-T-RISKS.md for full register: 14 risks across 5 categories
with severity, likelihood, mitigation, residual-exposure, owner.)

---

## 9. Open questions

1. **Q-T-1**: Does the operator's "designee" role on the Common Form
   Section IV signature block require a separately submitted
   designation letter? CISA's instructions are ambiguous in the
   draft (Nov 2023) but seem to require it in the final (Mar 2024).
   **Resolution path**: T.T3 default behaviour requires an uploaded
   designation letter (PDF attachment to the submission bundle) when
   the signer's `role` field is `designee`; this is recorded in the
   ssdf-config schema.
2. **Q-T-2**: For multi-product attestations (one form covering an
   entire product line), what is the "version" field's correct value?
   **Resolution path**: per CISA FAQ (Apr 2024), the form may cover a
   product line if the line shares a single SSDF programme; the
   `product_line` mode is captured in `ssdf-config.yaml` with an
   explicit `version_range: "*"` declaration.
3. **Q-T-3**: When OMB M-26-05 is itself rescinded or superseded
   (anticipated by industry counsel; see Wiley Law alert 2026-02), does
   LOOP-T need an `--m-26-05-tailoring` flag? **Resolution path**:
   `ssdf-config.yaml` carries a `regime` field with values
   `m-22-18-mandatory` / `m-23-16-extended` / `m-26-05-tailored` /
   `post-m-26-05-future`; the PDF cover letter cites the active regime.
4. **Q-T-4**: How does the producer attest to PW.7.1 (code review /
   analysis) when LLM-assisted code generation is a primary input?
   **Resolution path**: T.T5's 800-218A augmentation introduces an
   `ai_code_review_attestation` task; resolved when T.T5 ships.
5. **Q-T-5**: Where does the signed Common Form PDF live for
   chain-of-custody purposes once submitted to RSAA? **Resolution
   path**: tracker DB stores the SHA-256 + RSAA submission ID +
   submission timestamp; the signed PDF itself is stored under
   `tracker/storage/ssdf-attestations/{product}/{fy}/signed.pdf` with
   the existing tracker storage encryption; LOOP-H.H1 long-term storage
   picks it up for 6+ year retention (matches DoD record-management
   minimum even when the customer is civilian, to be safe).
6. **Q-T-6**: For "modified by major version changes" (M-22-18 scoping
   trigger), what is the producer's definition of "major"? **Resolution
   path**: `ssdf-config.yaml` per-product `major_version_pattern`
   (regex matched against SBOM version strings); default to SemVer
   `^(\d+)\.0\.0$`.
7. **Q-T-7**: Does the RSAA accept the unsigned canonical PDF + a
   detached signature, or only a signed PDF inline? **Resolution
   path**: T.T3 produces both forms — an inline-signable PDF (PAdES
   placeholder field) and the raw unsigned canonical PDF that the
   operator can sign via DigiCert / IdenTrust / a CISA-acceptable PKI.
   T.T4's tracker UI documents both submission paths.
8. **Q-T-8**: How long does a Common Form remain valid? **Resolution
   path**: 12 months default cadence; material-change detector forces
   interim re-attestation; per-agency over-ride supported via
   `ssdf-config.yaml`.

---

## 10. Glossary deltas (terms added)

Add to `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/GLOSSARY.md`:

| Term | Definition | Source |
|---|---|---|
| **Common Form** | The standardised CISA Secure Software Development Attestation Form (OMB Control 1670-0052, finalised Mar 11 2024) that federal agencies use to collect M-22-18 / M-23-16 attestations from software producers. | OMB M-23-16 §III; CISA |
| **Corporate-officer attestation** | A signed declaration by a natural person holding officer-level authority at the software producer that the producer follows secure software development practices in alignment with NIST SP 800-218. Distinct from build-pipeline cryptographic attestation (cosign / Sigstore). | OMB M-22-18 |
| **EO-critical software** | Software that, per NIST's EO 14028 §4(g) definition, performs functions critical to trust (privileged escalation, network control, etc.) and is therefore subject to accelerated M-22-18 attestation deadlines. | EO 14028 §4(g); NIST EO Critical Software definition |
| **POA&M companion (SSDF)** | OSCAL POA&M document the producer submits *with* the Common Form when one or more SSDF practices cannot be fully attested, per M-22-18 paragraph III.E. Allows continued use of the software under documented mitigation. | OMB M-22-18 §III.E |
| **PO / PS / PW / RV** | The four SSDF practice groups: Prepare the Organization, Protect the Software, Produce Well-Secured Software, Respond to Vulnerabilities. | NIST SP 800-218 §2 |
| **RSAA** | CISA Repository for Software Attestations and Artefacts — the application repository where federal civilian agencies and software producers store and retrieve attestations and supporting artefacts. | https://www.cisa.gov/resources-tools/services/repository-software-attestations-and-artifacts-rsaa |
| **SP 800-218A Community Profile** | NIST publication (Jul 26 2024 final) augmenting SP 800-218 with additional practices and tasks specific to generative AI and dual-use foundation models. | NIST SP 800-218A |
| **SSDF practice** | One of the 19 organizational secure-software development practices defined in NIST SP 800-218 v1.1, grouped under PO / PS / PW / RV. | NIST SP 800-218 |
| **SSDF task** | One of the 43 lower-level activities defined under the 19 SSDF practices that together describe the operational implementation. | NIST SP 800-218 |
| **Self-attestation regime** | The era of OMB-mandated attestation collection running Sep 14 2022 (M-22-18) through Jan 23 2026 (M-26-05 rescission). LOOP-T's `ssdf-config.yaml` `regime` field selects which regime applies for a given product / agency / contract. | OMB M-22-18 + M-23-16 + M-26-05 |
| **Material change (SSDF)** | A change to the producer's SSDF satisfaction matrix that flips one or more practices from `satisfied` to `not-satisfied` or that introduces a previously absent un-attestable practice. Triggers interim re-attestation under T.T4. | Industry practice; OMB-acceptable interpretation |
| **Software producer** | The legal entity that creates, owns, and is responsible for the software product subject to M-22-18 / M-23-16 attestation. The signer of the Common Form represents the producer. | OMB M-22-18 §I |
| **Body of Evidence (BoE) — SSDF** | The collected per-practice evidence aggregated by T.T2 demonstrating the producer's SSDF implementation. Distinct from the DoD-equivalency BoE in LOOP-S, but T.T2's matrix is one input to that BoE when both loops apply. | NIST SP 800-218 |

---

## 11. Cross-references (other loops / overlays / extensions)

### LOOP-J (Supply Chain + Privileges)

- **LOOP-J.J3 (Supply-chain risk register)**: T.T2 reads
  `out/supply-chain-risk-register.json` for PW.4.1 (third-party
  components) evidence. The register's risk entries become per-task
  evidence pointers in the SSDF satisfaction matrix.
- **LOOP-J.J3.b (engineering attestation; cosign + Rekor + SLSA L3
  provenance)**: see §1 table for the explicit distinction. T.T2 reads
  cosign verification state for PS.2.1 / PW.6.1 evidence; the cosign
  artefacts themselves are submitted alongside the Common Form, not in
  place of it.
- **LOOP-J.J2 (Subprocessor inventory)**: T.T2 reads
  `out/subprocessors.json` for PO.1 / PW.4 organisational-scope
  evidence (the producer's third-party developer-tool subprocessors).

### LOOP-O (AI/ML Governance per NIST AI RMF + OMB M-24-10)

- **LOOP-O.O5 (Model cards)**: T.T5 reads `out/model-cards/*.json` to
  identify products in scope for SP 800-218A augmentation. The model
  card's `ai_use_case` field gates which SP 800-218A practices apply.

### LOOP-B (Risk + Remediation Engine)

- **LOOP-B.B1 (Risk score)**: T.T2 reads `out/risk-register.json`
  composite risk scores to annotate each SSDF practice's satisfaction
  matrix row with the open risk delta.
- **LOOP-B.B2 (Deadline engine)**: any POA&M companion item T.T3 emits
  flows through the B.2 deadline engine with `deadline-source =
  ssdf-attestation`.

### LOOP-S (DFARS 252.204-7012 Cloud Equivalency for DoD-prime customers)

- **LOOP-S.S1 (NIST 800-171 ↔ FedRAMP Moderate crosswalk)**: when the
  CSP also serves DoD-prime customers, S.S1 reads T.T2's matrix as
  the authoritative SSDF evidence substrate for 800-171 SR
  (supply-chain risk) requirements 03.16.\*.
- **LOOP-S.S2 (DFARS 7012(c) incident reporting)**: when a cyber
  incident affects a product in scope for both an OMB M-22-18
  attestation and DFARS 7012, the incident reporter coordinates so
  both T.T4's material-change detector and S.S2's DC3 submission fire.

### LOOP-R (Post-Quantum Cryptography)

- **No direct dependency**. R.R1 inventories cryptographic primitives;
  T.T2's PW.6.1 task references R.R1 indirectly via the producer's
  build-tool configuration, but this is informational, not blocking.

### LOOP-A (Submission package)

- **LOOP-A.A4 (Submission bundler)**: T.T3 adds 4 new roles to
  `WELL_KNOWN`:
  - `ssdf-common-form-pdf` → `ssdf-common-form-{product}-{fy}.pdf`
  - `ssdf-satisfaction-matrix-json` → `ssdf-satisfaction-matrix.json`
  - `ssdf-satisfaction-matrix-xlsx` → `ssdf-satisfaction-matrix.xlsx`
  - `ssdf-poam-companion-json` → `ssdf-poam-companion.json`

### LOOP-H (Long-Term Storage + Multi-CSO)

- **LOOP-H.H1**: signed Common Form PDFs are tagged for 6-year
  retention under the H.H1 long-term storage policy regardless of
  customer agency (DoD record-management minimum; civilian agency
  retention varies but 6 years is a safe baseline).

### LOOP-Q (Marketplace + Post-ATO Publication)

- **LOOP-Q.Q1**: Marketplace metadata gains an `ssdf_attestation`
  block citing the most recent submission ID + RSAA URL when LOOP-T
  has produced one.

### LOOP-W (Prohibited Vendors) — adjacency note

LOOP-T does not directly invoke LOOP-W; however, T.T2's PW.4
(third-party components) evidence may surface a prohibited vendor
(per LOOP-W's enumeration of FAR 52.204-25 / NDAA §889 / OFAC SDN
sources). The producer cannot truthfully attest to maintaining a
trusted source-code supply chain (Common Form attestation #2) if the
SBOM contains a prohibited vendor's component; LOOP-W's enforcement
runs upstream of T.T2 as a gate.

### CIRCIA Workflow (LOOP-G.G2 + M.M4 CIRCIA extensions) — adjacency note

LOOP-T does not depend on the CIRCIA workflow. But T.T4's material-
change detector and the CIRCIA 72-hour reporting deadline both react
to incidents; when both fire on the same incident, the operator's
runbook (T.T4 docstring) routes the incident to the SSDF
material-change handler AND the CIRCIA reporter independently.

---

## 12. Status table (per-slice rows)

| Slice | Status | Commit | Date | Depends on | Blocks | Estimated effort |
|---|---|---|---|---|---|---|
| T.T1 | pending | — | — | LOOP-A.A1, LOOP-A.A4 | T.T2, T.T3, T.T5 | 4-5 working days |
| T.T2 | done | `<TBD-step6>` | 2026-06-20 | T.T1, LOOP-B.B1, LOOP-J.J2, LOOP-J.J3, all KSI envelopes | T.T3, T.T4 | 5-6 working days |
| T.T3 | pending | — | — | T.T2, LOOP-A.A4 | T.T4 | 5-6 working days |
| T.T4 | pending | — | — | T.T3, Tracker DB | (none) | 4-5 working days |
| T.T5 | pending | — | — | T.T2, LOOP-O.O5 | (none) | 3-4 working days |

Per-slice docs live at:
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/slices/T/T.T1.md`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/slices/T/T.T2.md`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/slices/T/T.T3.md`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/slices/T/T.T4.md`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/slices/T/T.T5.md`

---

## 13. Completion + push directive

Each slice in this loop, upon completion, MUST update STATUS.md status
row, append a CHANGELOG entry, commit with the slice ID + Co-Authored-By
trailer, push to origin/main, and update CLAUDE.md reading list if a
new permanent reference document was created.

The 7-step procedure from
`/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`
applies in full:

1. **Verify the slice is REO-compliant** — `npm run typecheck`,
   `npm test`, `npm run check:reo` (G1 lint:no-stubs +
   G2 check:coverage-regression + G3 check:provenance) all green.
2. **Update STATUS.md** — slice row Status → done, Commit, Date filled;
   Overall section's Next priority updated.
3. **Update LOOP-T-SPEC.md** — the Status table (§12) row for the slice
   set to `done` with commit + date.
4. **Update the per-slice doc** — YAML frontmatter `status: done`,
   `commit: <hash>`, `completed_date: <ISO>`, `last_updated: <ISO>`;
   final Implementation-log entry appended per
   `docs/IMPLEMENTATION-LOG-TEMPLATE.md`.
5. **Risks register** — if a new risk surfaced during implementation,
   append to `docs/loops/LOOP-T-RISKS.md` in the same commit.
6. **Add CHANGELOG entry** — `/Users/kenith.philip/FedRAMP 20x/CHANGELOG.md`
   "Unreleased" section, top of the file, format
   `### Added — LOOP-T.TN: <Slice title>` plus a 2-3 paragraph
   description naming the real evidence flow (which SDK calls / catalog
   reads / DB queries) and verification counts.
7. **Commit + push** — single commit with slice ID in the subject line,
   `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`
   trailer; push to `origin/main` (NEVER force-push).

Additionally for LOOP-T:

- **CIRCIA awareness:** T.T4's material-change detector and the
  CIRCIA-extension docs co-ship — if a slice introduces material-change
  events that overlap CIRCIA-reportable cyber-incidents, the slice MUST
  cross-reference `docs/CIRCIA-WORKFLOW.md`.
- **Cross-loop test runs:** before shipping T.T3, run the cross-loop
  test `tests/integration/loop-j-loop-t-coexistence.test.ts` and
  `tests/integration/loop-s-loop-t-coexistence.test.ts` to confirm
  no role / artefact collisions with LOOP-J.J3.b and LOOP-S.S1.
- **Source-PDF chain:** every slice that depends on a
  REQUIRES-RESEARCH-flagged source PDF (M-22-18, M-23-16, M-26-05,
  CISA Common Form, RSAA User Guide, NIST 800-218 PDF text, 800-218A
  PDF text) MUST verify the local PDF is present at
  `docs/sources/<filename>.pdf` and its SHA-256 matches
  `docs/sources/<filename>.sha256` before the slice's CI gate passes.
  The slice's Implementation log records the SHA-256 verified.
- **Operator-signed PDF chain-of-custody:** T.T4 records the signed
  PDF's SHA-256 + the signer's identity certificate fingerprint
  (extracted via the operator's signing tool out-of-band) + the
  submission ID returned by the CISA RSAA. This triple is the
  authoritative evidence the producer can produce in audit; the
  unsigned canonical PDF + the signed PDF are both archived under
  `tracker/storage/ssdf-attestations/{product}/{fy}/`.

---

## 14. REO compliance highlights (loop-wide)

The REO standard (`cloud-evidence/CLAUDE.md`) governs every slice. Three
loop-wide REO-pertinent properties:

1. **No fabricated SSDF task text.** T.T1's extractor parses the NIST
   SP 800-218 PDF (or its published Excel companion) by hash-pinned
   SHA-256; any task text in the catalogue traces to a real NIST byte.
   The catalogue MUST NOT contain hand-typed task text. The CI guardrail
   `npm run check:ssdf-catalog-provenance` (introduced by T.T1) asserts
   every task's `source_byte_offset` + `source_sha256` matches the
   pinned PDF.
2. **No auto-signing of the Common Form.** T.T3 emits an unsigned
   canonical PDF. The producer's corporate officer signs the PDF
   out-of-band via a qualified digital signature service (DigiCert
   Document Signing / IdenTrust / equivalent). The toolchain MUST NEVER
   apply a cryptographic signature on behalf of the officer (REO Rule 1
   prohibition #6).
3. **No silent practice-pass.** When a practice has zero contributing
   KSI envelopes, T.T2's matrix MUST NOT mark it `satisfied` by
   default; it MUST be `requires-operator-input`. The CI guardrail
   `npm run check:ssdf-no-silent-pass` (introduced by T.T2) asserts
   every `satisfied` row has at least one contributing `evidence_uri`.

---

## 15. Materially-conditional applicability matrix

| Producer condition | LOOP-T applies? | Notes |
|---|---|---|
| Sells software to ANY federal civilian agency (post-M-26-05 baseline) | Voluntary; recommended | Agencies may elect to require under tailored / risk-based regime |
| Has at least one pre-2026-01-23 contract whose flow-down references M-22-18 / M-23-16 | YES — mandatory until contract terminates | Legacy contract terms persist |
| Sells software to DoD per LOOP-S applicability | YES — DoD-prime uses SSDF attestation as equivalency artefact | Cross-references LOOP-S.S1 |
| Sells to non-federal commercial customers only | NO | LOOP-T is a no-op |
| Product incorporates generative AI / dual-use foundation model AND LOOP-T otherwise applies | YES; T.T5 augmentation engages | Cross-references LOOP-O.O5 |
| Product is "EO-critical software" per NIST definition | YES; accelerated re-attestation cadence triggers | T.T4 records `critical_software: true` and reduces the renewal window |

The orchestrator's `--ssdf-attestation` flag defaults to **off**. When
on, the flag must be accompanied by `--ssdf-config <path>`, and the
config file MUST declare per-product applicability — the emitter
refuses to ship a Common Form for a product whose
`applicability_evidence` is empty.

---

## 16. Per-slice extension surface (forward-looking)

The five LOOP-T slices ship the v1 substrate. Future loop-extension
docs anticipated (not yet written):

- **T.T1-EXT-FAR-CLAUSE-2027** (anticipated): when the FAR Council
  publishes a FAR clause supplanting OMB's attestation language, T.T1
  extends with a `regime: far-clause-2027` catalogue alongside the
  `regime: m-22-18` catalogue.
- **T.T3-EXT-DOD-FORM** (anticipated): if DoD publishes a
  defence-specific equivalent of the Common Form, T.T3 ships a
  `regime: dod-form` rendering profile.
- **T.T5-EXT-EO-14110-SUCCESSOR** (anticipated): EO 14110 was rescinded
  in Jan 2025 by EO 14148; if a successor EO is issued, T.T5's
  augmentation catalogue extends accordingly.
- **T.T4-EXT-RSAA-API** (anticipated): if CISA publishes a programmatic
  submission API for the RSAA (today it is web-form-only), T.T4
  extends with an API-submission helper that pushes the signed PDF +
  submission metadata and persists the returned submission ID.

These extensions land as `T.TN-EXT-*.md` files alongside the per-slice
docs under `docs/slices/T/`.

---

## 17. Resume-from-fresh-session checklist

Any future Claude / human session resuming LOOP-T from cold should:

1. Read this file (LOOP-T-SPEC.md) end to end.
2. Read `cloud-evidence/CLAUDE.md` (REO standard).
3. Read `cloud-evidence/docs/STATUS.md` for the current "Overall → Next
   priority" line.
4. If the next priority is a T-slice, read
   `cloud-evidence/docs/slices/T/T.TN.md` for that slice.
5. Read `cloud-evidence/docs/loops/LOOP-T-RISKS.md` for the per-loop
   risks register.
6. Confirm the source-PDF chain is intact:
   ```bash
   ls cloud-evidence/docs/sources/ | grep -E '(nist-sp-800-218|nist-sp-800-218A|cisa-common-form|omb-m-22-18|omb-m-23-16|omb-m-26-05|cisa-rsaa-user-guide)\.(pdf|sha256)$'
   ```
   If any file is missing, the resuming session downloads from the URL
   in §4 and records the SHA-256 in
   `docs/sources/<filename>.sha256` before proceeding.
7. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` and
   `cloud-evidence/docs/IMPLEMENTATION-LOG-TEMPLATE.md`.
8. Read the loop-relevant existing modules listed in §5.
9. Execute the slice under the REO standard and the 7-step procedure
   in §13.

---

## 18. Author + commit lineage

This LOOP-T-SPEC.md was authored on **2026-06-07** under the user's
ground-up directive ("Restart the workflow from the ground up and do
not be lazy or rely on previous work. Be as thorough as possible and
be even more precise. Ensure all context required is written to files
for each loop, section, slice and more.") The structural pattern
matches LOOP-R-SPEC.md and LOOP-S-SPEC.md (the recent gold-standard
specs); the citation density matches the spec-batch raised floor
(20+ sources, 15+ verbatim quotes). Each REQUIRES-RESEARCH marker
documents a fetch-bound verification step the implementer completes
before the dependent slice ships.

The five per-slice docs (`docs/slices/T/T.T1.md` through
`T.T5.md`) carry the per-slice deep context per the user's
ground-up directive. The per-loop risks register
(`docs/loops/LOOP-T-RISKS.md`) carries the full risks list.

This file's status row (§12) MUST be updated at every per-slice
completion. The CHANGELOG entry for **this spec file itself** is
captured under `### Added — LOOP-T spec corpus`:

> Added LOOP-T (NIST SSDF self-attestation via the CISA Common
> Form, OMB 1670-0052) as a 5-slice loop covering the corporate
> procurement gate for federal software acquisition. Distinct
> from LOOP-J.J3.b engineering attestation. Conditional on
> federal-agency sales; ships dormant otherwise. Spec includes
> verbatim source quotes from EO 14028, OMB M-22-18, OMB M-23-16,
> OMB M-26-05, NIST SP 800-218 v1.1, NIST SP 800-218A, and the
> CISA Common Form PDF, all pinned to 2026-06-07 access dates,
> with REQUIRES-RESEARCH markers documenting the PDF-download
> chain the implementer completes before each slice ships.

---

## 19. End-of-file invariants

The reading session that finished this file MUST be able to answer the
following without re-reading the source PDFs:

1. **Why does LOOP-T exist as a loop separate from LOOP-J?** Because
   LOOP-J's J.J3.b attestation is per-build cryptographic provenance
   (machine-signed, continuous, runtime-verifiable); LOOP-T is the
   per-organisation per-product per-agency self-attestation signed by
   a natural-person corporate officer (annual, document-form,
   procurement-gate). Both are required by federal customers; neither
   substitutes for the other.

2. **Who signs the Common Form?** A named corporate officer of the
   software producer with authority to bind the company under penalty
   of perjury. The toolchain emits an unsigned canonical PDF; the
   officer signs out-of-band via a qualified digital signature.

3. **Where does the signed form go?** Federal civilian: CISA RSAA at
   https://www.cisa.gov/resources-tools/services/repository-software-attestations-and-artifacts-rsaa
   (web upload). DoD-prime or other tailored regimes: the agency's
   specified portal. Both: T.T4's tracker records the submission ID
   and SHA-256 of the signed PDF.

4. **What if a practice cannot be attested to?** OMB M-22-18 §III.E
   permits a POA&M companion. T.T3 emits an OSCAL POA&M document with
   one `poam-item` per un-attestable practice; the producer submits
   it alongside the Common Form; the agency may accept the software
   under documented mitigation.

5. **How does LOOP-T survive M-26-05?** §15 applicability matrix.
   Legacy contracts + agency tailoring + LOOP-S equivalency continue
   to drive demand; the loop ships dormant when not needed.

6. **What is the AI extension?** T.T5 reads LOOP-O.O5 model cards;
   when a product incorporates generative AI / dual-use foundation
   models, T.T5 augments the satisfaction matrix with NIST SP
   800-218A practices and tasks.

7. **Where do I look up the SSDF tasks?** `core/ssdf-practices-catalog.ts`
   (re-export of `data/ssdf-800-218-v1.1.json`), produced by T.T1's
   extractor against the SHA-256-pinned NIST PDF + Excel companion.

8. **What is the next priority slice?** Whatever STATUS.md says
   under "Overall → Next priority" — LOOP-T sequenced behind
   LOOP-A.A1's POA&M emitter (already done), LOOP-A.A4's submission
   bundler (already done), LOOP-B.B1's risk score, LOOP-J.J3's
   supply-chain risk register, and LOOP-O.O5's model cards (the T.T5
   prerequisite). T.T1 may begin in parallel with LOOP-O development
   because it only depends on LOOP-A primitives.

---

(End of LOOP-T-SPEC.md.)
