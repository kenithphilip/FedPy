---
slice_id: V.V2
title: Business Associate Agreement (BAA) Tracker + HHS-Sample-BAA Template Emitter + 60-Day Renewal Detector
loop: V
status: proposed
commit: TBD
completed_date: —
depends_on:
  - V.V1                                # HIPAA Security Rule canonical catalog (provides §164.314(a) BA-contract-content standard verbatim)
  - LOOP-A.A4                           # tracker DB (existing schema migrations infrastructure + atomic-write + KMS envelope encryption)
  - LOOP-A.A5                           # Ed25519 + RFC 3161 signing primitive (every emitted BAA template + every renewal-due envelope is signed)
blocks:
  - V.V3                                # Breach-Notification triage references the BAA registry to route BA→CE notifications
estimated_effort: medium (~5-7 working days for single implementer)
last_updated: 2026-06-07
applicable_conditional: true
condition: Any CSP acting as a HIPAA Business Associate (BA) of a Covered Entity (CE) — i.e. the CSP creates, receives, maintains, or transmits Electronic Protected Health Information (ePHI) on behalf of a Covered Entity per 45 CFR §164.502(e). A Business Associate Agreement (BAA) is mandatory under 45 CFR §164.502(e) AND §164.504(e); operating as a BA without an executed BAA is itself a direct HHS-OCR enforcement exposure under HITECH §13408 (42 U.S.C. §17938). The applicability gate is the operator-supplied `compliance.hipaa.role` field in `config.yaml` (`business-associate | covered-entity | none`); when `none`, V.V2 is a no-op for the orchestrator run.
trigger_flag: "--baa-tracker"
trigger_env: CLOUD_EVIDENCE_BAA_TRACKER
---

# V.V2 — Business Associate Agreement (BAA) Tracker + HHS-Sample-BAA Template Emitter + 60-Day Renewal Detector

> V.V2 is the **operational BAA-lifecycle slice** for LOOP-V. While V.V1
> ingests the HIPAA Security Rule catalog (the authoritative spec corpus
> for the rule itself), V.V2 manages the **contractual artefacts that
> instantiate the rule** for every Covered Entity (CE) relationship a
> CSP holds. Every BAA the CSP executes, every BAA amendment, every BAA
> termination, every downstream-subcontractor BAA flow-down, and every
> 60-day renewal-due notification flows through this slice. Because a
> missing or stale BAA is a **direct HHS-OCR enforcement target** under
> HITECH §13408 — independent of any actual breach — this doc carries
> extra rigor on registry-drift detection, pre/post-Omnibus template
> classification, conduit-exception triage, and renewal-clock arithmetic.

## 1. Mission

V.V2 maintains a **canonical, signed, audit-logged registry** of every
Business Associate Agreement (BAA) the CSP has executed with a Covered
Entity (CE) or with a downstream BA (when the CSP itself acts as a BA
to another BA per 45 CFR §164.308(b)(2)). The registry is the
authoritative source-of-truth for: (a) **which CEs the CSP has a
contractual relationship with**, (b) **what the contractual scope is**
(production / staging / pre-production; full PHI vs Limited Data Set vs
de-identified), (c) **the executed-at + last-amended-at + expires-at +
renewal-due-at dates**, (d) **the template-era classification**
(pre-Omnibus-2013 vs post-Omnibus-2013 vs post-2025-NPRM), (e) **the
downstream-subcontractor BAA flow-down inventory** per ePHI-touching
subprocessor, (f) **the CE-side notification routing contacts** used by
V.V3's breach-notification triage, and (g) **the BAA-termination
disposition** (PHI returned / destroyed / retained-with-protections per
§164.504(e)(2)(ii)(I)).

The slice ALSO emits a **canonical BAA template** — a signed `.docx` and
canonical-JSON pair — derived verbatim from the HHS-published "Sample
Business Associate Agreement Provisions" page (see §2.5) and cross-
validated against 45 CFR §164.504(e)(2)'s required contractual elements.
The emitted template is **a starting point for operator legal counsel**,
not an auto-signed contract: per REO Rule 4, the system never substitutes
operator judgment on contract terms. The emitter's output bundles the
HHS verbatim sample, a JSON-Schema-validated metadata header (CE name,
CE legal address, CSP legal address, effective date, etc.), and an
explicit `legal_review_required: true` flag in the canonical JSON so a
downstream consumer cannot mistake the template for an executed contract.

The slice runs a **60-day renewal-due detector** as a daily cron (the
orchestrator's existing `tracker.scheduled_cron` table). For every BAA
with `renewal_due_at` within the next 60 calendar days, the detector
emits a signed `out/baa-renewal-due-YYYYMMDD-<ce_id>.json` envelope, an
operator notification (Slack + tracker UI banner; PagerDuty escalation
at T-7-days), and a placeholder POA&M item via the existing LOOP-A.A1
emitter so the renewal status is tracked alongside other compliance
items. The 60-day threshold is operator-configurable (default 60; minimum
30; maximum 180) but defaults to 60 to align with industry contract-
renewal practice for healthcare BAAs (HHS does not specify a renewal
clock — BAAs may be perpetual unless the contract specifies a term — but
most CE customers in practice require renewals on 1-year, 2-year, or
3-year cycles documented in the contract itself).

V.V2 does **not** auto-execute contracts, auto-sign on behalf of
operator legal counsel, auto-transmit BAAs to CEs, or auto-amend
executed contracts. Every operator action (BAA intake, renewal
confirmation, termination filing, downstream-BAA registration) goes
through the tracker UI with WebAuthn/PIV signed audit-log entries
(reuses the LOOP-A.A1 audit-log pattern). The registry is **append-only**
(every state transition creates a new immutable version row with
`prior_version_hash` forming a hash-chain per BAA) so an HHS-OCR
auditor reviewing the trail can prove no retroactive edits occurred.

## 2. Authoritative sources

Every URL accessed 2026-06-07. Verbatim quotes appear in Markdown
blockquotes. Where the live Federal Government source returned a
non-200 to anonymous fetches (eCFR + hhs.gov return 302/403 to
unauthenticated harness fetches), the implementer mirrors the page or
PDF to `cloud-evidence/docs/sources/` and re-quotes verbatim from the
local copy. Where Cornell Legal Information Institute (LII) mirrors
the same CFR text under a CC-licensed structure, the quote also names
the LII URL for triangulation.

### 2.1 45 CFR §164.502(e) — Disclosures to Business Associates (the gate that requires a BAA)

eCFR URL: https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-E/section-164.502
(accessed 2026-06-07; redirects to unblock.federalregister.gov — operator
mirrors to `docs/sources/45-cfr-164-502.pdf`).
LII mirror URL: https://www.law.cornell.edu/cfr/text/45/164.502
(accessed 2026-06-07, returns 200).

§164.502(e)(1)(i) — Standard: Disclosures to business associates:

> "A covered entity may disclose protected health information to a
> business associate and may allow a business associate to create,
> receive, maintain, or transmit protected health information on its
> behalf, if the covered entity obtains satisfactory assurances, in
> accordance with §164.504(e), that the business associate will
> appropriately safeguard the information."

§164.502(e)(2) — Implementation specification: Documentation:

> "The satisfactory assurances required by paragraph (e)(1) of this
> section must be documented through a written contract or other
> written agreement or arrangement with the business associate that
> meets the applicable requirements of §164.504(e)."

This is the **constitutive predicate** for V.V2: any CSP touching ePHI
on behalf of a CE MUST have a documented written agreement that meets
§164.504(e). V.V2's registry is the operator's evidence chain that the
predicate is satisfied for every CE relationship.

### 2.2 45 CFR §164.504(e) — Business associate contracts (the required contractual elements)

eCFR URL: https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-E/section-164.504
(accessed 2026-06-07; operator mirrors to `docs/sources/45-cfr-164-504.pdf`).
LII mirror URL: https://www.law.cornell.edu/cfr/text/45/164.504
(accessed 2026-06-07, returns 200).

§164.504(e)(1)(i) — Standard: Business associate contracts:

> "The contract or other arrangement required by §164.502(e)(2) must
> meet the requirements of paragraph (e)(2), (e)(3), or (e)(5) of this
> section, as applicable."

§164.504(e)(1)(ii) — Required action by the covered entity when it knows
of a material breach by the BA:

> "A covered entity is not in compliance with the standards in
> §164.502(e) and paragraph (e) of this section, if the covered entity
> knew of a pattern of activity or practice of the business associate
> that constituted a material breach or violation of the business
> associate's obligation under the contract or other arrangement,
> unless the covered entity took reasonable steps to cure the breach
> or end the violation, as applicable, and, if such steps were
> unsuccessful, terminated the contract or arrangement, if feasible."

§164.504(e)(2)(i) — Implementation specification — required contractual
elements (the **content checklist** that V.V2's template emitter pins to):

> "The contract between a covered entity and a business associate
> must: ... (A) Establish the permitted and required uses and
> disclosures of protected health information by the business
> associate; (B) Provide that the business associate will not use or
> further disclose the information other than as permitted or required
> by the contract or as required by law; ... (C) Require the business
> associate to ... (1) Not use or further disclose the information
> other than as permitted or required by the contract or as required
> by law; (2) Use appropriate safeguards and, in the case of electronic
> protected health information, comply with subpart C of this part to
> prevent use or disclosure of the information other than as provided
> for by its contract; (3) Report to the covered entity any use or
> disclosure of the information not provided for by its contract of
> which it becomes aware, including breaches of unsecured protected
> health information as required by §164.410; ... (D) At termination
> of the contract, if feasible, return or destroy all protected health
> information received from, or created or received by the business
> associate on behalf of, the covered entity that the business
> associate still maintains in any form and retain no copies of such
> information or, if such return or destruction is not feasible,
> extend the protections of the contract to the information and limit
> further uses and disclosures to those purposes that make the return
> or destruction of the information infeasible."

§164.504(e)(2)(ii)(I) — the **return-or-destroy-at-termination** clause
(drives the V.V2 registry's `termination_disposition` enum):

> "At termination of the contract, if feasible, return or destroy all
> protected health information received from, or created or received
> by the business associate on behalf of, the covered entity that the
> business associate still maintains in any form and retain no copies
> of such information or, if such return or destruction is not
> feasible, extend the protections of the contract to the information
> and limit further uses and disclosures to those purposes that make
> the return or destruction of the information infeasible."

§164.504(e)(3) — Implementation specifications: Other arrangements (the
exception for government-to-government MOUs, statutory-mandate
performers, and Limited Data Set DUAs):

> "If a covered entity and its business associate are both governmental
> entities ... the covered entity is in compliance with paragraph
> (e)(1) of this section, if (A) It enters into a memorandum of
> understanding with the business associate that contains terms that
> accomplish the objectives of paragraph (e)(2) of this section; or
> (B) Other law (including regulations adopted by the covered entity
> or its business associate) contains requirements applicable to the
> business associate that accomplish the objectives of paragraph
> (e)(2) of this section."

The §164.504(e)(2)(i) verbatim text is **mandatory payload** in the
V.V2 template emitter's `.docx` output — every emitted template surfaces
those clauses verbatim so the operator's legal counsel can verify
nothing was dropped during template generation.

### 2.3 45 CFR §164.314(a) — Organizational requirements (the Security Rule's BAA-content overlay)

URL: https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.314
(accessed 2026-06-07; operator mirrors via V.V1's ingestion to
`cloud-evidence/data/hipaa-security-rule-catalog.json`).

§164.314(a)(2)(i) — Implementation specification: Business Associate
Contracts (Required) — the verbatim text already captured in V.V1's
catalog under `HSR.164.314.a.2.i`:

> "(2) Implementation specifications (Required):
> (i) Business associate contracts. The contract must provide that the
> business associate will—
> (A) Comply with the applicable requirements of this subpart;
> (B) In accordance with §164.308(b)(2), ensure that any
> subcontractors that create, receive, maintain, or transmit electronic
> protected health information on behalf of the business associate
> agree to comply with the applicable requirements of this subpart by
> entering into a contract or other arrangement that complies with this
> section; and
> (C) Report to the covered entity any security incident of which it
> becomes aware, including breaches of unsecured protected health
> information as required by §164.410."

V.V2 reads V.V1's signed catalog at startup, extracts `HSR.164.314.a.2.i`'s
verbatim text, and embeds it in the emitted template's "Required
Security Rule Provisions" section so the Security-Rule-derived
contractual elements appear alongside the Privacy-Rule-derived
§164.504(e) elements. The cross-reference is what makes the template
"complete enough for legal review" rather than "only the Privacy Rule
half".

### 2.4 45 CFR §164.308(b) — Business Associate Contracts and Other Arrangements (workforce-side BA-with-BA standard)

URL: https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308
(accessed 2026-06-07; in V.V1's catalog as `HSR.164.308.b`).

§164.308(b)(1) — Standard:

> "(b)(1) Business associate contracts and other arrangements. A
> covered entity may permit a business associate to create, receive,
> maintain, or transmit electronic protected health information on the
> covered entity's behalf only if the covered entity obtains
> satisfactory assurances, in accordance with §164.314(a), that the
> business associate will appropriately safeguard the information.
> A covered entity is not required to obtain such satisfactory
> assurances from a business associate that is a subcontractor."

§164.308(b)(2) — the **downstream BAA flow-down** rule:

> "(2) A business associate may permit a business associate that is a
> subcontractor to create, receive, maintain, or transmit electronic
> protected health information on its behalf only if the business
> associate obtains satisfactory assurances, in accordance with
> §164.314(a), that the subcontractor will appropriately safeguard the
> information."

This subcontractor flow-down is **the entire reason V.V2 maintains a
`downstream_baas[]` array per primary-CE relationship**. Every
ePHI-touching subprocessor on the CSP side requires a downstream BAA;
absence is a direct §164.308(b)(2) violation and a HITECH §13408
enforcement target.

### 2.5 HHS Sample Business Associate Agreement Provisions (the canonical template source)

URL: https://www.hhs.gov/hipaa/for-professionals/covered-entities/sample-business-associate-agreement-provisions/index.html
(accessed 2026-06-07; returns 200 to anonymous fetches as of access
date; operator mirrors to `docs/sources/hhs-sample-baa-provisions.html`
on first run and pins the SHA-256 in the V.V2 template emitter so
future-run HHS-page revisions surface a diff warning).

Introductory paragraph (HHS):

> "Sample Business Associate Agreement Provisions. (Published January
> 25, 2013) Introduction. A 'business associate' is a person or entity,
> other than a member of the workforce of a covered entity, who
> performs functions or activities on behalf of, or provides certain
> services to, a covered entity that involve access by the business
> associate to protected health information. A 'business associate'
> also is a subcontractor that creates, receives, maintains, or
> transmits protected health information on behalf of another business
> associate."

HHS verbatim "Permitted Uses and Disclosures" provision (excerpted —
operator must mirror the full HHS page for the complete language):

> "Permitted Uses and Disclosures by Business Associate. Business
> Associate may only use or disclose protected health information as
> necessary to perform the services set forth in [the Services
> Agreement / Business Associate Agreement] [Insert Specific Uses and
> Disclosures Permitted by Business Associate]. Business Associate may
> use or disclose protected health information as required by law."

HHS verbatim "Obligations and Activities of Business Associate"
provision (excerpted):

> "Business Associate agrees to: (a) Not use or disclose protected
> health information other than as permitted or required by the
> Agreement or as required by law; (b) Use appropriate safeguards, and
> comply with Subpart C of 45 CFR Part 164 with respect to electronic
> protected health information, to prevent use or disclosure of
> protected health information other than as provided for by the
> Agreement; (c) Report to covered entity any use or disclosure of
> protected health information not provided for by the Agreement of
> which it becomes aware, including breaches of unsecured protected
> health information as required at 45 CFR 164.410, and any security
> incident of which it becomes aware."

HHS verbatim "Term and Termination" provision (excerpted):

> "Term. The Term of this Agreement shall be effective as of [Insert
> Effective Date], and shall terminate on [Insert Termination Date or
> Event] or on the date covered entity terminates for cause as
> authorized in paragraph (b) of this Section, whichever is sooner.
> Termination for Cause. Business associate authorizes termination of
> this Agreement by covered entity, if covered entity determines
> business associate has violated a material term of the Agreement
> [and business associate has not cured the breach or ended the
> violation within the time specified by covered entity]."

The V.V2 template emitter writes this verbatim text as a verbatim block
in the emitted `.docx`, with the bracketed insertion points
(`[Insert Effective Date]`, `[Insert Termination Date or Event]`, etc.)
preserved exactly so legal counsel sees what HHS published rather than
a paraphrase. The emitter populates the bracketed metadata from the
operator's tracker DB intake form when known (e.g. Effective Date) and
leaves `REQUIRES-OPERATOR-INPUT` for fields that must come from the
final contract negotiation.

### 2.6 HHS Omnibus Final Rule — 78 FR 5566 (2013-01-25) — the BAA-content modernization

URL: https://www.federalregister.gov/documents/2013/01/25/2013-01073/modifications-to-the-hipaa-privacy-security-enforcement-and-breach-notification-rules-under-the
(accessed 2026-06-07; operator mirrors to
`docs/sources/78-fr-5566-omnibus-final-rule.pdf`).

The Omnibus Final Rule (effective 2013-09-23) materially expanded the
§164.504(e) BAA content requirements — specifically adding the
downstream-subcontractor flow-down requirement (§164.308(b)(2)) and the
direct-applicability of the Security Rule to BAs (§164.502(a)(3)). BAAs
executed before 2013-09-23 may not contain the Omnibus-required clauses;
LOOP-V-RISKS V-X2 catalogs this as a high-severity risk. V.V2's registry
classifies each BAA's `template_era` as one of `pre-omnibus-2013`,
`post-omnibus-2013`, `post-2025-nprm`, or `unknown`.

> "The Omnibus Final Rule modifies the HIPAA Privacy, Security,
> Enforcement, and Breach Notification Rules under the Health
> Information Technology for Economic and Clinical Health (HITECH)
> Act and the Genetic Information Nondiscrimination Act (GINA);
> other modifications to the HIPAA Rules. ... Among other changes,
> the final rule: ... Makes business associates of covered entities
> directly liable for compliance with certain of the HIPAA Privacy
> and Security Rules' requirements; ... Expands the requirements for
> notification of breaches of unsecured protected health information
> under the HIPAA Breach Notification Rule, originally promulgated
> in 2009 under the HITECH Act."

### 2.7 HITECH Act §13408 — Direct BA enforcement (42 U.S.C. §17938)

URL: https://www.congress.gov/111/plaws/publ5/PLAW-111publ5.pdf
(accessed 2026-06-07; operator mirrors to
`docs/sources/PLAW-111publ5-hitech.pdf`).

HITECH §13408 made BAs directly liable for HHS-OCR enforcement
penalties — pre-HITECH, only the CE was the regulated entity:

> "SEC. 13408. APPLICATION OF SECURITY PROVISIONS AND PENALTIES TO
> BUSINESS ASSOCIATES OF COVERED ENTITIES. Sections 164.308, 164.310,
> 164.312, and 164.316 of title 45, Code of Federal Regulations, shall
> apply to a business associate of a covered entity in the same manner
> that such sections apply to the covered entity. ... The additional
> requirements of this title that relate to security and that are made
> applicable with respect to covered entities shall also be
> applicable to such a business associate and shall be incorporated
> into the business associate agreement between the business associate
> and the covered entity."

V.V2's tracker-UI "Why a BAA matters" panel cites §13408 verbatim so the
operator understands the **direct enforcement consequence** of a
missing or stale BAA — not just a contractual gap.

### 2.8 HHS Cloud Computing Guidance (October 2016) — Cloud Service Providers as BAs

URL: https://www.hhs.gov/hipaa/for-professionals/special-topics/health-information-technology/cloud-computing/index.html
(accessed 2026-06-07).

> "When a covered entity engages the services of a CSP to create,
> receive, maintain, or transmit ePHI (such as to process and/or store
> ePHI), on its behalf, the CSP is a business associate under HIPAA.
> Further, when a business associate subcontracts with a CSP to
> create, receive, maintain, or transmit ePHI on its behalf, the CSP
> subcontractor itself is a business associate. This is true even if
> the CSP processes or stores only encrypted ePHI and lacks an
> encryption key for the data. Lacking an encryption key does not
> exempt a CSP from business associate status and obligations under
> the HIPAA Rules. As a result, the covered entity (or business
> associate) and the CSP must enter into a HIPAA-compliant business
> associate agreement (BAA), and the CSP is both contractually liable
> for meeting the terms of the BAA and directly liable for compliance
> with the applicable requirements of the HIPAA Rules."

This HHS guidance defeats the **conduit-exception** loophole: a CSP
processing or storing ePHI is a BA even with customer-held encryption
keys. LOOP-V-RISKS V-X5 catalogs the conduit-misclassification risk;
V.V2's BAA-intake wizard surfaces this guidance verbatim before allowing
the operator to mark a CSP-customer relationship as "conduit-exempt"
(which V.V2 refuses unless the operator's legal counsel signs a
narrative justification linked to the specific CSP service offering).

### 2.9 OMB / HHS reference — HHS-OCR Resolution Agreements citing missing BAAs

URL: https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/agreements/index.html
(accessed 2026-06-07).

Selected enforcement narrative — HHS-OCR's 2016 resolution agreement
with **North Memorial Health Care of Minnesota** ($1.55M penalty) cited
the **absence of a BAA with a contractor** as a primary finding:

> "North Memorial failed to have in place a Business Associate
> Agreement [with Accretive Health] ... in violation of 45 CFR
> §164.502(e) and §164.308(b)(3)."

(HHS-OCR press release, accessed via
https://www.hhs.gov/about/news/2016/03/16/business-associate-agreement-makes-difference.html,
2026-06-07; operator mirrors to `docs/sources/hhs-press-2016-03-16.html`.)

V.V2's `data/hhs-ocr-baa-enforcement-cases.json` is a cached snapshot of
the public HHS-OCR resolution agreement narratives that specifically
cite BAA-related findings; the tracker UI surfaces these as
"comparable benchmarks" on every BAA detail page so an operator
opening a stale BAA sees what HHS has penalized in comparable
fact-patterns.

### 2.10 OCR Audit Protocol — Audit Inquiry §164.502(e)/.504(e) BAA-inventory expectation

URL: https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/audit/protocol-current/index.html
(accessed 2026-06-07).

The OCR Audit Protocol enumerates the **specific evidence categories**
HHS expects a CE or BA to produce within 30 days of audit-initiation
notice. For BAAs, the protocol entry under §164.504(e) reads:

> "Audit Inquiry: Does the covered entity have a business associate
> contract with each business associate as required by 45 CFR
> §164.504(e)? Establish and uniformly apply procedures and processes
> that identify all relationships involving covered functions, [or]
> subject to the implementation specifications for documentation."

V.V2's `out/baa-ocr-audit-package-YYYYMMDD.zip` bundles every active
BAA record with: the contract PDF (operator-uploaded), the
template-era classification, the executed-at + renewal-due-at +
termination-status timeline, the downstream-BAA inventory per
ePHI-touching subprocessor, and the audit-log hash chain proving no
retroactive edits. The bundle is produced by the `core/baa-tracker.ts`
emitter on operator-demand from the tracker UI or via the CLI flag
`--baa-ocr-audit-package`.

### 2.11 FedRAMP-HIPAA Inheritance — FedRAMP 20x KSI evidence reuse

URL (FedRAMP Roadmap): https://www.fedramp.gov/
(accessed 2026-06-07).

V.V2's BAA-template emitter records that **for the operator's specific
service offering, the underlying IaaS provider (AWS / GCP / Azure)
already holds an executed BAA with the operator** (the so-called
"upstream BAA"). The operator's BAA with the IaaS provider is itself a
V.V2 registry row (`relationship_kind: 'upstream-iaas-baa'`). The
template emitter cross-references the upstream BAA in the operator's
own emitted-to-CE template so the CE sees the full chain:
CE → operator (via this BAA) → IaaS provider (via upstream BAA).

### 2.12 HHS HIPAA Security Rule NPRM 2025-01-06 (90 FR 898) — Pending BAA-content changes

URL: https://www.federalregister.gov/documents/2025/01/06/2024-30983/hipaa-security-rule-to-strengthen-the-cybersecurity-of-electronic-protected-health-information
(accessed 2026-06-07; operator mirrors to
`docs/sources/hipaa-nprm-2025-01-06.html`).

The NPRM proposes adding to §164.314(a)(2)(i) explicit requirements
that BAs verify deployment of (i) multi-factor authentication for ePHI
access, (ii) encryption-at-rest and encryption-in-transit, (iii) annual
compliance audits, and (iv) network-segmentation/asset-inventory
attestations. V.V2 surfaces these as `pending_baa_amendments[]` in
every registry row's metadata so the operator can pre-emptively plan
amendments; on NPRM finalization, V.V2 promotes the pending block to
the active template-era classification (`post-2025-nprm`).

## 3. Scope

### 3.1 In scope

- **BAA registry CRUD** — operator intake of a BAA (PDF upload + metadata
  form), edit (creates a new immutable version row), termination
  (records `termination_status` + `termination_disposition`).
- **Dual-source reconciliation** — `baa-registry.yaml` (operator
  committed to repo) AND quarterly CMS export
  (`inputs/cms-baa-export-YYYYQN.json`); reconciliation report emitted
  to `out/baa-reconciliation-YYYYQN.json`. (LOOP-V-RISKS V-X1.)
- **Template-era classification** — every BAA tagged `pre-omnibus-2013 |
  post-omnibus-2013 | post-2025-nprm | unknown` with `last_amended_at`
  enabling the renewer to detect stale-template cases. (LOOP-V-RISKS V-X2.)
- **Downstream BAA flow-down inventory** — joins against the existing
  LOOP-W subprocessor sheet's `ephi_touching: bool` column; missing
  downstream BAAs surface `REQUIRES-OPERATOR-INPUT` diagnostics.
  (LOOP-V-RISKS V-X3.)
- **Hybrid-entity / OHCA component routing** — registry models
  `ce_organizational_form: enum('single-ce','hybrid-entity','ohca-member',
  'affiliated-ce')` + per-component notification routing list.
  (LOOP-V-RISKS V-X4.)
- **Conduit-exception triage** — intake wizard refuses to accept
  conduit classification without operator-counsel narrative + HHS-2016-
  guidance acknowledgement. (LOOP-V-RISKS V-X5.)
- **Termination disposition tracking** — `termination_status: enum
  ('active','expired-phi-returned','expired-phi-destroyed',
  'expired-phi-retained-with-protections')` + evidence URL. (LOOP-V-RISKS
  V-X6.)
- **HHS-Sample-BAA template emitter** — signed canonical-JSON + signed
  OOXML/zip-store `.docx` derived verbatim from HHS sample-provisions
  page; metadata header populated from operator config.
- **60-day renewal-due detector** — daily cron emits signed
  `out/baa-renewal-due-YYYYMMDD-<ce_id>.json` + operator
  notification (Slack at T-60d, T-30d, T-14d; PagerDuty at T-7d).
- **OCR Audit Package bundler** — `out/baa-ocr-audit-package-YYYYMMDD.zip`
  bundles every active BAA + supporting evidence.
- **Append-only registry (hash-chain audit log)** — every state
  transition creates a new version row with `prior_version_hash`
  forming a hash chain; reuses LOOP-A.A1 audit-log pattern.
- **POA&M cascade** — every renewal-due + every missing-downstream-BAA
  emits a placeholder POA&M item via LOOP-A.A1.

### 3.2 Out of scope (NOT in V.V2)

- **Auto-execution / auto-signing of contracts.** V.V2 NEVER auto-signs
  on behalf of operator legal counsel (REO Rule 4).
- **Auto-transmission of BAAs to CEs.** Tracker UI offers download +
  email-draft, but operator transmits via their own legal-ops workflow.
- **Auto-amendment of executed contracts.** Operators may upload
  amendments + new versions; V.V2 versions them in the registry.
- **PHI classification in operator's data lake** — handled by a future
  V.V4 ePHI tagger; V.V2 reads the LOOP-W subprocessor sheet's pre-
  existing `ephi_touching` boolean only.
- **Breach notification triage** — handled by V.V3 (consumes V.V2's
  registry for BA→CE notification routing).
- **HIPAA Security Rule evidence collection** — handled by V.V1 (V.V2
  reads V.V1's signed catalog for §164.314(a) verbatim text).
- **HITRUST CSF crosswalk** — out of scope for V.V2; tracked under
  a future LOOP-V follow-up.
- **State-law BAA preemption analysis** — out of scope; LOOP-U tracks
  state privacy/preemption.

## 4. Inputs

### 4.1 Operator BAA intake form (tracker UI → tracker DB)

```ts
interface BAAIntakeForm {
  // Identification
  ce_legal_name: string;                              // "ExampleHealth System, Inc."
  ce_legal_address: string;                           // single-line address for contract
  ce_primary_contact: {
    name: string;
    title: string;
    email: string;
    phone: string;
  };
  ce_breach_notification_contact: {                   // used by V.V3 for BA→CE notifications
    name: string;
    title: string;
    email: string;
    phone: string;
    pgp_fingerprint_or_smime_cert?: string;          // optional encrypted-email channel
  };
  ce_organizational_form: 'single-ce' | 'hybrid-entity' |
                          'ohca-member' | 'affiliated-ce';
  ce_components?: Array<{                             // populated only when ce_organizational_form = 'hybrid-entity' | 'ohca-member'
    component_name: string;
    component_contact: { name: string; email: string; phone: string };
  }>;

  // Contract metadata
  baa_pdf_upload: { file_sha256: string; file_path: string; file_bytes: number };
  baa_executed_at: string;                            // ISO 8601 date (YYYY-MM-DD)
  baa_effective_at: string;                           // ISO 8601 date
  baa_term_kind: 'fixed-term' | 'perpetual-until-terminated' | 'auto-renew';
  baa_term_duration_months?: number;                  // only when baa_term_kind = 'fixed-term'
  baa_renewal_due_at?: string;                        // ISO 8601 date; computed if fixed-term
  baa_last_amended_at?: string;                       // ISO 8601 date; null if never amended
  baa_template_era: 'pre-omnibus-2013' | 'post-omnibus-2013' |
                    'post-2025-nprm' | 'unknown';
  baa_template_source: 'hhs-sample' | 'ce-supplied' |
                       'csp-supplied-template' | 'mutually-negotiated' |
                       'unknown';

  // Scope
  baa_scope: 'production' | 'staging' | 'pre-production' | 'production+staging';
  baa_phi_categories: Array<'full-phi' | 'limited-data-set' | 'de-identified'>;
  baa_services_covered: string;                        // free-text description of what services touch ePHI

  // Conduit-exception triage (LOOP-V-RISKS V-X5)
  baa_conduit_classification?: {
    operator_claims_conduit: boolean;
    if_true_narrative: string;                        // min 250 chars when operator_claims_conduit=true
    operator_legal_counsel_signed_off_at: string;     // ISO 8601 datetime
    operator_legal_counsel_name: string;
    operator_legal_counsel_title: string;
    hhs_2016_guidance_acknowledged_at: string;        // ISO 8601 datetime
  };

  // Downstream-BAA flow-down (LOOP-V-RISKS V-X3)
  downstream_baas: Array<{
    subprocessor_name: string;
    subprocessor_uei?: string;
    subprocessor_role: string;                        // e.g. "log aggregation", "analytics", "ML inference"
    downstream_baa_executed_at: string;
    downstream_baa_renewal_due_at?: string;
    downstream_baa_pdf_upload: { file_sha256: string; file_path: string };
  }>;

  // Operator audit-log fields
  intake_by_operator_id: string;                      // operator user UUID
  intake_at: string;                                  // ISO 8601 datetime
  webauthn_signature: string;                         // base64 WebAuthn assertion
}
```

### 4.2 Quarterly CMS export (operator-supplied; LOOP-V-RISKS V-X1)

```ts
interface CMSBAAExport {
  export_period: 'YYYYQN';                            // e.g. '2026Q2'
  export_at: string;                                  // ISO 8601
  source_system: 'docusign-clm' | 'ironclad' | 'conga' | 'sharepoint' | 'other';
  records: Array<{
    cms_record_id: string;                            // external CMS UUID
    ce_legal_name: string;
    contract_type: string;                            // e.g. 'Business Associate Agreement', 'Master Services Agreement Addendum'
    executed_at: string;
    effective_at: string;
    expires_at?: string;
    status: 'active' | 'expired' | 'terminated';
    pdf_url_or_path: string;
  }>;
}
```

V.V2's reconciler joins CMS records to registry rows by `ce_legal_name`
normalization (lowercase, strip punctuation, strip common suffixes
like "Inc.", "LLC", "Corp."); fuzzy matches surface as
`REQUIRES-OPERATOR-INPUT: baa-fuzzy-match-<cms_record_id>` for
operator confirmation.

### 4.3 LOOP-W subprocessor sheet input (for downstream-BAA inventory)

```ts
interface SubprocessorSheetRow {
  subprocessor_name: string;
  subprocessor_role: string;
  ephi_touching: boolean;                             // operator-set on subprocessors sheet
  is_iaas_provider: boolean;                          // AWS / GCP / Azure → upstream-BAA flow
  contract_url: string;
}
```

For every row with `ephi_touching = true`, V.V2 asserts a matching
`downstream_baas[]` entry in at least one active BAA's record.

### 4.4 V.V1 signed catalog input

```ts
interface V1CatalogRef {
  catalog_path: 'cloud-evidence/data/hipaa-security-rule-catalog.json';
  catalog_sha256: string;
  catalog_signature_verified: boolean;
}
```

V.V2's template emitter reads V.V1's catalog for the
`HSR.164.314.a.2.i` verbatim text + the `HSR.164.308.b` verbatim text +
the catalog's `general_rules.required_vs_addressable_text_verbatim` so
the emitted template surfaces the Security Rule provisions verbatim
alongside the Privacy Rule §164.504(e) provisions.

### 4.5 Operator config gate

```yaml
compliance:
  hipaa:
    role: business-associate                          # business-associate | covered-entity | none
    baa_tracker:
      renewal_alert_threshold_days: 60                # 30-180; default 60
      pagerduty_escalation_threshold_days: 7
      cms_export_quarterly_path: inputs/cms-baa-export-2026Q2.json
      ocr_audit_package_output_path: out/baa-ocr-audit-package-{date}.zip
    signing_key_ref: aws-kms://us-east-1/<key-uuid>   # KMS resource for V.V2 emit signing
```

## 5. Outputs

### 5.1 Canonical BAA registry envelope

Path: `out/baa-registry-snapshot-YYYYMMDD.json` (snapshot per orchestrator
run) AND `cloud-evidence/data/baa-registry-current.json` (live pointer to
latest snapshot).

```ts
interface BAARegistrySnapshot {
  schema_version: '1.0.0';
  snapshot_id: string;                                // ULID
  snapshot_at: string;                                // ISO 8601 UTC
  csp_legal_name: string;
  csp_legal_address: string;
  records: BAARegistryRecord[];
  reconciliation: {
    cms_export_period?: string;
    cms_records_seen: number;
    registry_records_seen: number;
    in_cms_not_in_registry: string[];                 // ce_legal_name list
    in_registry_not_in_cms: string[];
    fuzzy_match_review_required: Array<{
      cms_record_id: string;
      candidate_registry_record_id: string;
      similarity_score: number;
    }>;
  };
  signature: { alg: 'ed25519'; key_id: string; sig: string };
  rfc3161_timestamp: { tsa_url: string; token: string; received_at: string };
}

interface BAARegistryRecord {
  record_id: string;                                  // ULID
  version_seq: number;                                // monotonically increasing per record
  prior_version_hash?: string;                        // SHA-256 of prior version row's canonical JSON; null for version 1
  ce_legal_name: string;
  ce_legal_address: string;
  ce_primary_contact: { name: string; title: string; email: string; phone: string };
  ce_breach_notification_contact: { name: string; title: string; email: string; phone: string; pgp_fingerprint_or_smime_cert?: string };
  ce_organizational_form: 'single-ce' | 'hybrid-entity' | 'ohca-member' | 'affiliated-ce';
  ce_components?: Array<{ component_name: string; component_contact: { name: string; email: string; phone: string } }>;
  baa_executed_at: string;
  baa_effective_at: string;
  baa_term_kind: 'fixed-term' | 'perpetual-until-terminated' | 'auto-renew';
  baa_term_duration_months?: number;
  baa_renewal_due_at?: string;
  baa_last_amended_at?: string;
  baa_template_era: 'pre-omnibus-2013' | 'post-omnibus-2013' | 'post-2025-nprm' | 'unknown';
  baa_template_source: 'hhs-sample' | 'ce-supplied' | 'csp-supplied-template' | 'mutually-negotiated' | 'unknown';
  baa_scope: 'production' | 'staging' | 'pre-production' | 'production+staging';
  baa_phi_categories: Array<'full-phi' | 'limited-data-set' | 'de-identified'>;
  baa_services_covered: string;
  baa_conduit_classification?: {
    operator_claims_conduit: boolean;
    narrative: string;
    operator_legal_counsel_signed_off_at: string;
    operator_legal_counsel_name: string;
    operator_legal_counsel_title: string;
    hhs_2016_guidance_acknowledged_at: string;
  };
  downstream_baas: Array<{
    subprocessor_name: string;
    subprocessor_uei?: string;
    subprocessor_role: string;
    downstream_baa_executed_at: string;
    downstream_baa_renewal_due_at?: string;
    downstream_baa_pdf_sha256: string;
  }>;
  termination_status: 'active' | 'expired-phi-returned' | 'expired-phi-destroyed' | 'expired-phi-retained-with-protections';
  termination_disposition?: { disposition_evidence_url?: string; disposition_narrative?: string; disposition_at?: string };
  audit: {
    intake_by_operator_id: string;
    intake_at: string;
    webauthn_signature: string;
    version_state_transition_log: Array<{
      from_version_seq: number;
      to_version_seq: number;
      transition_kind: 'amend' | 'renew' | 'terminate' | 'metadata-correction';
      change_reason: string;
      transition_at: string;
      transition_by_operator_id: string;
    }>;
  };
  pending_baa_amendments?: Array<{
    nprm_url: string;
    nprm_publication_date: string;
    expected_finalization_window: string;
    proposed_changes_summary: string;
  }>;
}
```

### 5.2 BAA template emitter outputs (OOXML/zip-store + canonical JSON)

For an operator who initiates a "Generate BAA template for new CE
relationship" workflow:

- `out/baa-template-<ce_short_name>-<YYYYMMDD>.docx` — signed OOXML
  template, verbatim HHS sample provisions, bracketed insertion points
  preserved, Security Rule cross-reference block, operator-counsel
  review banner on cover page.
- `out/baa-template-<ce_short_name>-<YYYYMMDD>.json` — canonical-JSON
  envelope describing the template metadata + verbatim provision
  bodies + a `legal_review_required: true` flag.

```ts
interface BAATemplateEnvelope {
  schema_version: '1.0.0';
  envelope_id: string;
  template_for_ce_legal_name: string;
  template_for_csp_legal_name: string;
  generated_at: string;
  source_provisions: {
    hhs_sample_url: string;                           // pinned URL
    hhs_sample_fetched_at: string;
    hhs_sample_sha256: string;
  };
  provisions: Array<{
    provision_id: string;                             // e.g. 'permitted-uses-and-disclosures'
    provision_title: string;
    provision_verbatim_text: string;
    cfr_citation: string;
    is_required_by_cfr: boolean;
  }>;
  security_rule_provisions_from_v1_catalog: Array<{
    catalog_id: string;                               // e.g. 'HSR.164.314.a.2.i'
    citation: string;
    verbatim_text: string;
  }>;
  upstream_baa_chain?: Array<{
    relationship_kind: 'upstream-iaas-baa';
    upstream_provider: 'aws' | 'gcp' | 'azure';
    upstream_baa_executed_at: string;
    upstream_baa_pdf_sha256: string;
  }>;
  metadata_placeholders: Array<{
    placeholder_key: string;                          // e.g. 'EFFECTIVE_DATE'
    populated: boolean;
    value?: string;
  }>;
  legal_review_required: true;                        // always true
  signature: { alg: 'ed25519'; key_id: string; sig: string };
  rfc3161_timestamp: { tsa_url: string; token: string; received_at: string };
}
```

### 5.3 60-day renewal-due envelope

Path: `out/baa-renewal-due-YYYYMMDD-<record_id>.json`.

```ts
interface BAARenewalDueEnvelope {
  schema_version: '1.0.0';
  envelope_id: string;
  detected_at: string;
  record_id: string;
  ce_legal_name: string;
  renewal_due_at: string;
  days_until_due: number;                             // 1-60
  severity: 'info' | 'warning' | 'urgent';            // info: 31-60; warning: 8-30; urgent: 0-7
  notification_routing: {
    slack_channel: string;
    pagerduty_service?: string;                       // populated only when severity = 'urgent'
    tracker_ui_banner_kind: 'amber' | 'red';
  };
  poam_item_uuid: string;                             // LOOP-A.A1 placeholder POA&M item
  signature: { alg: 'ed25519'; key_id: string; sig: string };
}
```

### 5.4 Reconciliation report

Path: `out/baa-reconciliation-YYYYQN.json` (per quarter).

Same structure as `BAARegistrySnapshot.reconciliation` block but
emitted as a stand-alone signed artifact.

### 5.5 OCR audit package

Path: `out/baa-ocr-audit-package-YYYYMMDD.zip` containing:

- `manifest.json` — list of every active BAA record + downstream BAA
  + termination disposition record.
- `baas/<record_id>/contract.pdf` — operator-uploaded contract PDF.
- `baas/<record_id>/metadata.json` — registry metadata.
- `baas/<record_id>/version-history.json` — full hash-chain audit log.
- `downstream-baas/<subprocessor>/<baa.pdf>` — every downstream BAA.
- `reconciliation/baa-reconciliation-YYYYQN.json` — latest reconciliation.
- `cover-letter.docx` — operator-narrated cover letter naming HHS-OCR
  case number + audit-inquiry text quoted from §2.10.
- `manifest.signature` — Ed25519 signature over the manifest.
- `manifest.timestamp` — RFC 3161 token.

### 5.6 Tracker DB schema (migration `0052_baa_registry.sql`)

```sql
CREATE TABLE baa_records (
  id                        UUID PRIMARY KEY,
  record_id                 TEXT NOT NULL UNIQUE,                -- ULID (stable across versions)
  version_seq               INTEGER NOT NULL,
  prior_version_hash        TEXT,                                -- SHA-256 of prior canonical JSON; null for v1
  ce_legal_name             TEXT NOT NULL,
  ce_legal_address          TEXT NOT NULL,
  ce_organizational_form    TEXT NOT NULL,
  baa_executed_at           DATE NOT NULL,
  baa_effective_at          DATE NOT NULL,
  baa_term_kind             TEXT NOT NULL,
  baa_renewal_due_at        DATE,
  baa_last_amended_at       DATE,
  baa_template_era          TEXT NOT NULL,
  baa_template_source       TEXT NOT NULL,
  baa_scope                 TEXT NOT NULL,
  baa_phi_categories        JSONB NOT NULL,                      -- array
  baa_services_covered      TEXT NOT NULL,
  baa_conduit_classification JSONB,                              -- nullable
  termination_status        TEXT NOT NULL DEFAULT 'active',
  termination_disposition   JSONB,                               -- nullable
  ce_contacts               JSONB NOT NULL,                      -- nested struct: primary + breach + components
  pending_baa_amendments    JSONB,                               -- array
  baa_pdf_sha256            TEXT NOT NULL,
  baa_pdf_storage_path      TEXT NOT NULL,
  intake_by_operator_id     TEXT NOT NULL,
  intake_at                 TIMESTAMPTZ NOT NULL,
  webauthn_signature        TEXT NOT NULL,
  encrypted_at_rest         BOOLEAN NOT NULL DEFAULT TRUE,
  created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (record_id, version_seq)
);
CREATE INDEX idx_baa_records_record_id        ON baa_records(record_id);
CREATE INDEX idx_baa_records_renewal_due_at   ON baa_records(baa_renewal_due_at);
CREATE INDEX idx_baa_records_termination_status ON baa_records(termination_status);
CREATE INDEX idx_baa_records_template_era      ON baa_records(baa_template_era);

CREATE TABLE baa_downstream_baas (
  id                         UUID PRIMARY KEY,
  parent_record_id           TEXT NOT NULL,                       -- FK to baa_records.record_id
  parent_version_seq         INTEGER NOT NULL,
  subprocessor_name          TEXT NOT NULL,
  subprocessor_uei           TEXT,
  subprocessor_role          TEXT NOT NULL,
  downstream_baa_executed_at DATE NOT NULL,
  downstream_baa_renewal_due_at DATE,
  downstream_baa_pdf_sha256  TEXT NOT NULL,
  downstream_baa_pdf_storage_path TEXT NOT NULL,
  created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (parent_record_id, parent_version_seq, subprocessor_name)
);
CREATE INDEX idx_baa_downstream_subprocessor_name
  ON baa_downstream_baas(subprocessor_name);

CREATE TABLE baa_renewal_alerts (
  id                  UUID PRIMARY KEY,
  record_id           TEXT NOT NULL,
  detected_at         TIMESTAMPTZ NOT NULL,
  renewal_due_at      DATE NOT NULL,
  severity            TEXT NOT NULL,                              -- info | warning | urgent
  notification_sent_at TIMESTAMPTZ,
  poam_item_uuid      TEXT,
  envelope_path       TEXT NOT NULL,
  UNIQUE (record_id, detected_at)
);
```

## 6. Algorithm / Steps

### Phase A — Bootstrap

1. **Parse CLI flag** `--baa-tracker` (or env `CLOUD_EVIDENCE_BAA_TRACKER`).
   If neither set, exit 0 (no-op).
2. **Check operator config gate.** Read
   `config.yaml::compliance.hipaa.role`. If `none`, exit 0 and log
   `LOOP-V.V2 skipped — operator-config role=none`.
3. **Sign-test the signing key.** Call
   `core/sign.ts::testSign(key_ref)` to verify operator KMS signing
   rights. Failure → exit 2.
4. **Load V.V1 catalog.** Read
   `cloud-evidence/data/hipaa-security-rule-catalog.json`; verify
   Ed25519 signature; cache `HSR.164.314.a.2.i`, `HSR.164.308.b`
   verbatim text. Failure → exit 2 with `V1CatalogSignatureInvalidError`.

### Phase B — Registry load + reconciliation

5. **Load registry from tracker DB.** Query `baa_records` for all
   rows where `(record_id, version_seq) = MAX(version_seq) per
   record_id` (latest version per record). Materialize as
   `BAARegistryRecord[]`.
6. **Load CMS quarterly export** (if path configured + file exists).
   Parse via Ajv-validated schema. If file mtime > 95 days old,
   surface warning `cms-export-stale`.
7. **Reconcile.** Normalize `ce_legal_name` on both sides (lowercase,
   strip "Inc."|"LLC"|"Corp."|"PLLC"|punctuation, collapse whitespace).
   Build sets `in_cms_not_in_registry` and `in_registry_not_in_cms`.
   For close-but-not-exact name matches, compute Levenshtein
   similarity ≥ 0.85 → flag as fuzzy-match candidates.
8. **Emit reconciliation diagnostics.** For each unmatched CMS record:
   emit `REQUIRES-OPERATOR-INPUT: baa-drift-<cms_record_id>` to the
   orchestrator log + the tracker UI banner.

### Phase C — Renewal detection

9. **Iterate active records.** For each record where
   `termination_status = 'active' AND baa_renewal_due_at IS NOT NULL`:
   compute `days_until_due = baa_renewal_due_at - today` (calendar
   days; UTC).
10. **Classify severity.** `info` for 31-60 days; `warning` for 8-30;
    `urgent` for 0-7. Beyond 60 → skip (not yet due). Past 0 (overdue)
    → severity `urgent` AND additionally emit
    `baa-renewal-overdue-<record_id>` to PagerDuty.
11. **Idempotency check.** Query `baa_renewal_alerts` with
    `(record_id, detected_at::date = today)`; if a row exists, skip
    (already alerted today).
12. **Emit renewal-due envelope.** Canonical-JSON per §5.3; sign +
    timestamp; write to `out/baa-renewal-due-YYYYMMDD-<record_id>.json`.
13. **Create placeholder POA&M item.** Call
    `core/oscal-poam.ts::createPoamItem({ kind: 'baa-renewal-due',
    record_id, due_at: renewal_due_at, severity })`. Persist
    `poam_item_uuid` back to `baa_renewal_alerts`.
14. **Notify.** Slack at all severities; PagerDuty additionally at
    `urgent`. Tracker UI banner amber at `warning`+; red at `urgent`.

### Phase D — Downstream-BAA flow-down validation

15. **Load subprocessor sheet** via existing
    `core/subprocessors-sheet.ts`. Filter rows with
    `ephi_touching = true` AND `is_iaas_provider = false` (IaaS-
    upstream is a separate flow).
16. **For each ePHI-touching subprocessor**, search the latest
    version of every active BAA record's `downstream_baas[]` for
    a matching `subprocessor_name`. If absent: emit
    `REQUIRES-OPERATOR-INPUT: missing-downstream-baa-<subprocessor>`
    diagnostic + tracker UI badge + placeholder POA&M item via
    LOOP-A.A1.
17. **For each downstream BAA with `downstream_baa_renewal_due_at`
    within next 60 days**, ALSO emit a renewal-due envelope (the
    cascade extends to subprocessor BAAs).

### Phase E — Template emit (on-demand, not scheduled)

18. **Operator initiates** "Generate BAA template" workflow via
    tracker UI → invokes `core/baa-template-emitter.ts::emitTemplate
    ({ ce_legal_name, ce_legal_address, csp_legal_name, csp_legal_
    address, intended_effective_at })`.
19. **Load HHS sample provisions** from
    `docs/sources/hhs-sample-baa-provisions.html` (operator-mirrored
    on first run). Verify SHA-256 against pinned hash; mismatch →
    surface warning `hhs-sample-page-changed` (do not block; operator
    may re-mirror).
20. **Compose JSON envelope** per §5.2; populate
    `provisions[]` from the parsed HHS page; populate
    `security_rule_provisions_from_v1_catalog[]` from V.V1 cached
    catalog; populate `upstream_baa_chain[]` from registry records
    with `relationship_kind: 'upstream-iaas-baa'`.
21. **Render `.docx`** via `core/baa-template-emitter.ts` (OOXML/zip-
    store; reuses helpers from `core/inventory-workbook.ts`). Cover
    page surfaces "FOR LEGAL REVIEW ONLY — DO NOT EXECUTE" banner +
    HHS-2016 cloud-guidance acknowledgement block + verbatim
    `legal_review_required: true` flag.
22. **Sign + timestamp** envelope (canonical-JSON AND `.docx` content
    hash). Write both artifacts to `out/`.
23. **Tracker UI** surfaces download links + emits Slack
    notification `baa-template-emitted-<ce_short_name>`.

### Phase F — OCR audit package emit (on-demand)

24. **Operator initiates** "Generate OCR audit package" via tracker
    UI or CLI flag `--baa-ocr-audit-package`.
25. **Build manifest** enumerating every active BAA + downstream BAA +
    termination disposition + reconciliation report.
26. **Pack zip** with the structure in §5.5. Sign manifest. Write
    `out/baa-ocr-audit-package-YYYYMMDD.zip`.
27. **Surface in tracker UI** with download link + audit-inquiry
    cover letter pre-populated from §2.10 verbatim text.

### Phase G — Persist + bundle

28. **Append snapshot** to `out/baa-registry-snapshot-YYYYMMDD.json`
    and update `cloud-evidence/data/baa-registry-current.json` pointer.
29. **Register with submission bundle** via
    `core/submission-bundle.ts::registerArtifact` for the new role
    `baa-registry-snapshot-json` so LOOP-A.A4 picks it up.
30. **Emit run log** to `out/baa-tracker-run.log` capturing: registry
    record count, reconciliation deltas, renewals alerted, missing
    downstream-BAA count, template emits, audit-package emits.

## 7. Files to create / modify

Absolute paths under `/Users/kenith.philip/FedRAMP 20x/`:

### Files to CREATE

1. `cloud-evidence/core/baa-tracker.ts` — main module orchestrating
   Phases A-D + G. ~700 lines. Exports: `loadRegistry()`,
   `reconcileWithCMS()`, `detectRenewals()`, `validateDownstreamBAAs()`,
   `emitSnapshot()`, `bundleOCRAuditPackage()`.
2. `cloud-evidence/core/baa-template-emitter.ts` — OOXML + canonical-JSON
   template emitter (Phase E). ~500 lines. Uses
   `inventory-workbook.ts` zip-store helpers.
3. `cloud-evidence/core/baa-types.ts` — TypeScript interfaces shared by
   V.V2 + V.V3 (BAARegistryRecord, BAATemplateEnvelope,
   BAARenewalDueEnvelope, CMSBAAExport, etc.). ~250 lines.
4. `cloud-evidence/core/baa-reconciler.ts` — name-normalization +
   Levenshtein-similarity reconciliation logic. ~200 lines.
5. `cloud-evidence/core/baa-renewal-clock.ts` — calendar-day arithmetic
   for renewal-due detection (UTC; no DST traps). ~150 lines.
6. `cloud-evidence/tracker/db/migrations/0052_baa_registry.sql` —
   schema per §5.6 + indexes + KMS-envelope-encryption setup.
7. `cloud-evidence/tracker/ui/baa-status-pane.tsx` — React panel:
   per-record detail view, version history timeline, renewal countdown
   timer, downstream-BAA inventory list, conduit-classification banner,
   "Generate template" button, "Generate audit package" button,
   reconciliation drift indicator. ~600 lines.
8. `cloud-evidence/tracker/server/routes/baa-records.ts` — REST API:
   `GET /api/baa-records`, `GET /api/baa-records/:record_id`,
   `POST /api/baa-records` (intake), `POST /api/baa-records/:record_id/amend`,
   `POST /api/baa-records/:record_id/terminate`,
   `POST /api/baa-records/:record_id/renew`,
   `GET /api/baa-records/:record_id/version-history`,
   `POST /api/baa-records/template/generate`,
   `POST /api/baa-records/ocr-audit-package/generate`. ~400 lines.
9. `cloud-evidence/scripts/extract-hhs-sample-baa.mjs` — operator-run
   helper that fetches the HHS sample-provisions page, mirrors locally,
   computes SHA-256, updates the pinned hash constant. ~150 lines.
10. `cloud-evidence/data/baa-registry-current.json` — live pointer
    file (replaced atomically by Phase G).
11. `cloud-evidence/data/hhs-ocr-baa-enforcement-cases.json` —
    cached snapshot of HHS-OCR resolution agreements citing
    BAA-related findings (operator refreshes quarterly via
    `extract-ocr-resolution-agreements.mjs` from LOOP-V-RISKS V-X25).
12. `cloud-evidence/docs/sources/hhs-sample-baa-provisions.html` —
    operator-mirrored HHS page (one-time + on-change).
13. `cloud-evidence/docs/sources/45-cfr-164-502.pdf` — operator-
    mirrored CFR section.
14. `cloud-evidence/docs/sources/45-cfr-164-504.pdf` — operator-
    mirrored CFR section.
15. `cloud-evidence/docs/sources/78-fr-5566-omnibus-final-rule.pdf` —
    operator-mirrored Omnibus FR notice.
16. `cloud-evidence/docs/sources/PLAW-111publ5-hitech.pdf` — operator-
    mirrored HITECH Act PDF.
17. `cloud-evidence/test/baa-tracker.test.ts` — main test suite
    (see §8; 18+ tests).
18. `cloud-evidence/test/baa-template-emitter.test.ts` — template
    emitter unit tests.
19. `cloud-evidence/test/baa-reconciler.test.ts` — name-normalization
    + similarity tests.
20. `cloud-evidence/test/fixtures/baa-tracker/` — fixtures: BAA
    intake forms, CMS exports, V.V1 catalog snippets, HHS sample HTML.

### Files to EXTEND

21. `cloud-evidence/core/orchestrator.ts` — new flag `--baa-tracker`
    + env `CLOUD_EVIDENCE_BAA_TRACKER`; new flag
    `--baa-ocr-audit-package` for on-demand audit-package emit; runs
    AFTER V.V1 in orchestrator order.
22. `cloud-evidence/core/submission-bundle.ts` — `WELL_KNOWN` adds
    roles: `baa-registry-snapshot-json`, `baa-template-json`,
    `baa-template-docx`, `baa-renewal-due-json`,
    `baa-ocr-audit-package-zip`, `baa-reconciliation-quarterly-json`.
23. `cloud-evidence/core/oscal-poam.ts` — extend `createPoamItem(...)`
    to accept the `kind: 'baa-renewal-due'` and
    `kind: 'missing-downstream-baa'` discriminators.
24. `cloud-evidence/core/notify.ts` — extend with templates:
    `baa-renewal-due-info`, `baa-renewal-due-warning`,
    `baa-renewal-due-urgent`, `baa-renewal-overdue`,
    `baa-template-emitted`, `baa-reconciliation-drift-detected`,
    `baa-conduit-classification-flagged-for-review`,
    `missing-downstream-baa`.
25. `cloud-evidence/docs/STATUS.md` — V.V2 row updated to `done` at
    slice close.
26. `cloud-evidence/docs/loops/LOOP-V-SPEC.md` — V.V2 row in status
    table updated.
27. `CHANGELOG.md` — Unreleased entry appended.

## 8. Test specifications

| id | scenario | fixture path | expected | acceptance |
|---|---|---|---|---|
| T-V2-01 | Happy-path BAA intake — operator POSTs a complete intake form, registry row created at version_seq=1, hash-chain initialized with `prior_version_hash=null` | `test/fixtures/baa-tracker/intake-happy-path.json` | `baa_records` row exists with `version_seq=1`; `prior_version_hash IS NULL`; snapshot envelope contains the new record | DB row exists + envelope canonical-JSON validates |
| T-V2-02 | Amendment flow — second intake against existing record creates `version_seq=2` with `prior_version_hash = sha256(v1-canonical-json)` | `test/fixtures/baa-tracker/intake-then-amend.json` | `baa_records` has 2 rows for the same `record_id`; v2's `prior_version_hash` matches v1's computed hash | Hash-chain verification passes; immutable v1 unchanged |
| T-V2-03 | Termination — operator marks BAA terminated with disposition `expired-phi-destroyed` + evidence URL | `test/fixtures/baa-tracker/terminate-destroyed.json` | `termination_status='expired-phi-destroyed'`; `termination_disposition.disposition_evidence_url` set; version_seq incremented; audit trail records transition | DB state + audit log |
| T-V2-04 | Renewal detection — BAA with `renewal_due_at = today+45` triggers `info` severity alert + Slack notification | `test/fixtures/baa-tracker/renewal-due-45d.json` | `baa_renewal_alerts` row inserted with `severity='info'`; Slack stub captures `baa-renewal-due-info` template | Stub assertion + DB row |
| T-V2-05 | Renewal detection urgent — BAA with `renewal_due_at = today+5` triggers `urgent` severity + PagerDuty escalation | `test/fixtures/baa-tracker/renewal-due-5d.json` | `severity='urgent'`; PagerDuty stub captures escalation | Stub assertion |
| T-V2-06 | Renewal idempotency — running detector twice in one day for same record emits one alert | (same fixture; two runs) | `baa_renewal_alerts` rows = 1, not 2 | Row count |
| T-V2-07 | Overdue BAA — `renewal_due_at` already passed → `urgent` severity AND additional `baa-renewal-overdue` PagerDuty incident | `test/fixtures/baa-tracker/renewal-overdue.json` | Both alerts emitted | Two PagerDuty calls captured |
| T-V2-08 | CMS reconciliation — CMS export has CE not in registry → `REQUIRES-OPERATOR-INPUT: baa-drift-<id>` diagnostic | `test/fixtures/baa-tracker/cms-export-drift.json` | Reconciliation report's `in_cms_not_in_registry` includes the missing CE; orchestrator log contains the diagnostic | Reconciliation envelope assertion |
| T-V2-09 | CMS reconciliation fuzzy match — CMS has "Example Health LLC", registry has "Example Health, L.L.C." → similarity ≥ 0.85 → fuzzy-match candidate flagged | `test/fixtures/baa-tracker/cms-export-fuzzy.json` | `fuzzy_match_review_required[]` non-empty | Array length ≥ 1 |
| T-V2-10 | Downstream-BAA missing — subprocessor sheet has `ephi_touching=true` for "VendorX" but no BAA references VendorX → diagnostic emitted | `test/fixtures/baa-tracker/missing-downstream-baa.json` + subprocessor sheet fixture | Diagnostic emitted; placeholder POA&M item created via LOOP-A.A1 | LOOP-A.A1 stub assertion + log assertion |
| T-V2-11 | Pre-Omnibus template flag — BAA with `baa_executed_at = 2012-06-01` AND `baa_last_amended_at = null` → `template_era='pre-omnibus-2013'` + `requires_amendment=true` UI badge | `test/fixtures/baa-tracker/pre-omnibus-baa.json` | Registry record has classification; tracker UI surfaces badge | UI render assertion |
| T-V2-12 | Conduit-classification refusal — intake with `operator_claims_conduit=true` BUT missing `if_true_narrative` or counsel sign-off → intake rejected with `ConduitClassificationIncompleteError` | `test/fixtures/baa-tracker/conduit-incomplete.json` | Intake returns 422; no row created | Error code |
| T-V2-13 | Template emit — canonical JSON + `.docx` produced; both signed; HHS verbatim provisions present; `legal_review_required=true` | (any fixture) | `BAATemplateEnvelope.provisions[*].provision_verbatim_text` non-empty + matches HHS pinned hash; `.docx` unpacks with bookmark `legal-review-banner` | OOXML unzip assertion + JSON schema |
| T-V2-14 | Template emit pulls V.V1 catalog Security-Rule provisions — `HSR.164.314.a.2.i` verbatim text embedded in template envelope | `test/fixtures/baa-tracker/template-emit-with-v1.json` + V.V1 fixture catalog | `security_rule_provisions_from_v1_catalog[]` contains entry with `catalog_id='HSR.164.314.a.2.i'` and verbatim text | Array element match |
| T-V2-15 | HHS sample page hash mismatch — pinned hash differs from current `docs/sources/hhs-sample-baa-provisions.html` → emit warning `hhs-sample-page-changed`; do NOT block emit | (modify fixture) | Warning logged; template still emitted | Log capture |
| T-V2-16 | Ed25519 signature round-trip — snapshot envelope verifies against configured pubkey | (any fixture) | `verifyEnvelope(env, pubkey) === true` | Boolean |
| T-V2-17 | Signature tampering rejection — flipping any byte invalidates signature | mutated emit | `verifyEnvelope` throws `EnvelopeSignatureInvalidError` | Exception |
| T-V2-18 | OCR audit package — zip contains manifest + contract PDF + version history + reconciliation report + signed manifest | `test/fixtures/baa-tracker/audit-package-input.json` | `unzipSync(buf)` enumerates all expected paths; `manifest.signature` verifies | Path enumeration + signature |
| T-V2-19 | Hybrid-entity routing — BAA with `ce_organizational_form='hybrid-entity'` AND 2 `ce_components[]` → V.V3 routing pulls per-component contacts (cross-loop integration smoke test) | `test/fixtures/baa-tracker/hybrid-entity.json` | V.V3 routing helper resolves both component contacts | Cross-loop assertion |
| T-V2-20 | Append-only enforcement — attempting to UPDATE an existing `baa_records` row directly (bypassing the version-seq pattern) fails at DB layer | (direct SQL update) | UPDATE returns error from CHECK constraint or trigger | DB error |
| T-V2-21 | Operator config gate — `compliance.hipaa.role='none'` makes V.V2 a no-op | n/a | Exit 0 with log `LOOP-V.V2 skipped` | Exit code + log |
| T-V2-22 | Reconciliation report stale CMS export — file mtime > 95 days → warning `cms-export-stale` surfaced | (synthetic stale fixture) | Warning in log | Log assertion |
| T-V2-23 | Downstream-BAA renewal-due cascade — downstream BAA's `renewal_due_at = today+10` → cascade emits its own renewal-due envelope | `test/fixtures/baa-tracker/downstream-renewal-due.json` | Envelope emitted for downstream BAA | File-exists assertion |
| T-V2-24 | NPRM-pending annotation — V.V1 catalog has `pending_amendments[]` → V.V2 propagates to every active registry record's `pending_baa_amendments[]` | (any fixture; V.V1 with NPRM block) | All active records have `pending_baa_amendments` populated | Array equality |
| T-V2-25 | Upstream IaaS BAA chain — operator's BAA with AWS is loaded as `relationship_kind='upstream-iaas-baa'`; emitted templates include `upstream_baa_chain[]` referencing it | `test/fixtures/baa-tracker/upstream-aws-baa.json` | Template envelope `upstream_baa_chain[]` contains AWS entry | Array assertion |

Total: 25 tests (10 above the §7 minimum of 15 because the slice is the
operational fulcrum of LOOP-V's contractual chain; missing tests cascade
to V.V3's notification routing and to the OCR audit package's
defensibility).

## 9. Risks

| id | risk | likelihood | impact | mitigation |
|---|---|---|---|---|
| R-V2-01 | **Registry drift between legal CMS and tracker** — legal team executes new BAAs in DocuSign CLM / Ironclad / Conga / SharePoint but the tracker is never updated; V.V2's registry under-counts and V.V3's breach-notification routing misses CEs (LOOP-V-RISKS V-X1). | high | high (legal + contractual + breach-notification gap) | Dual-source reconciliation (registry YAML + quarterly CMS export); reconciliation report emitted to `out/baa-reconciliation-YYYYQN.json`; tracker UI surfaces "BAAs in registry vs CMS" delta count on every LOOP-V dashboard page; `REQUIRES-OPERATOR-INPUT` diagnostic per missing CE; quarterly cron runs reconciler automatically |
| R-V2-02 | **Pre-Omnibus-2013 BAAs still in force** — a CSP with a 12-year-old BAA may be partially out of compliance; the contract text may NOT contain Omnibus-required clauses (downstream-subcontractor flow-down, individual access rights, breach-notification deadlines) (LOOP-V-RISKS V-X2). | medium | high (regulatory compliance gap) | Registry schema includes `template_era` enum; reconciler flags `pre-omnibus-2013` records with `requires_amendment=true`; tracker UI surfaces "Amendment required" badge with a link to the §164.504(e) audit-inquiry text; runbook documents the HHS sample-provisions amendment workflow; quarterly review report includes a `pre_omnibus_baas_pending_amendment[]` array |
| R-V2-03 | **Downstream-subcontractor BAA flow-down gaps** — under §164.308(b)(2) and §164.502(e)(1)(ii), every ePHI-touching subprocessor requires a downstream BAA; absence is a direct §13408 enforcement exposure (LOOP-V-RISKS V-X3). | high | high (direct enforcement exposure) | V.V2 joins against `core/subprocessors-sheet.ts` (`ephi_touching=true` rows); emits `REQUIRES-OPERATOR-INPUT: missing-downstream-baa-<subprocessor>` diagnostic; placeholder POA&M item via LOOP-A.A1; tracker UI shows a per-subprocessor missing-BAA matrix on the LOOP-V dashboard; cross-loop integration test asserts every ePHI-touching subprocessor maps to a downstream-BAA record |
| R-V2-04 | **Conduit-exception misapplication** — operator may incorrectly self-classify as a "conduit" (per 78 FR 5571 + HHS FAQ Aug 2013) to avoid BAA burden, but HHS Cloud Computing Guidance 2016 clarifies CSPs are BAs even with customer-held encryption keys (LOOP-V-RISKS V-X5). | medium | high (no BAA → direct enforcement exposure) | BAA-intake wizard refuses to accept conduit classification unless operator legal counsel signs structured narrative referencing HHS-2016 guidance verbatim; runbook quotes the 2016 guidance; V.V2 emits `coverage:skipped-conduit-claim` diagnostic + flags for legal review; tracker UI surfaces a "Why conduit-exception is hard to claim" panel |
| R-V2-05 | **Renewal-due clock arithmetic ambiguity** — the HIPAA Privacy Rule does not specify a renewal cadence; renewal cadence is contract-specific; misreading the contract's `term` clause (fixed-term vs perpetual vs auto-renew) → wrong `baa_renewal_due_at` → missed alerts. | medium | medium (operator may miss a contractual renewal window even if HIPAA itself does not impose one) | Intake form has explicit `baa_term_kind` enum + `baa_term_duration_months` (only when fixed-term); operator must enter `baa_renewal_due_at` explicitly for non-fixed-term contracts; UI surfaces the entered value with a "Verify with executed contract" prompt; tracker UI banner amber when `baa_renewal_due_at IS NULL` and `baa_term_kind != 'perpetual-until-terminated'` |
| R-V2-06 | **HHS sample-provisions page revision** — HHS may revise the sample-BAA-provisions page (last published 2013-01-25 but HHS may republish in response to the 2025 NPRM finalization); V.V2's pinned SHA-256 will mismatch and the template emit will surface a warning. | low | low (warning, not block) | Pinned SHA-256 stored in `core/baa-template-emitter.ts`; mismatch surfaces `hhs-sample-page-changed` warning; operator re-runs `scripts/extract-hhs-sample-baa.mjs` to re-mirror + re-pin; CHANGELOG entry per revision; runbook documents the re-pin workflow |
| R-V2-07 | **Hybrid-entity / OHCA component-routing misroute** — a single CE legal entity may have multiple "components" with different CIO/Privacy-Officer contacts; a naive registry that treats one CE = one routing target will misroute V.V3 breach notifications (LOOP-V-RISKS V-X4). | medium | medium (wrong notification recipient delays CE's own clock) | Registry models `ce_organizational_form` + `ce_components[]` with per-component `notification_routing[]`; intake form surfaces an explicit "Is this CE a hybrid entity or OHCA member?" question; UI surfaces all component contacts on the BAA detail page; cross-loop integration test (T-V2-19) asserts V.V3 routing pulls per-component contacts |
| R-V2-08 | **BAA-termination-disposition evidence missing** — operator marks a BAA terminated without uploading return/destruction evidence; later breach in retained data exposes CSP to enforcement (LOOP-V-RISKS V-X6). | medium | medium (downstream enforcement risk in retained-PHI cases) | Termination flow REQUIRES `termination_disposition.disposition_evidence_url` OR `disposition_narrative`; cannot mark a record terminated without one; quarterly reconciliation report surfaces terminated BAAs lacking disposition evidence; tracker UI surfaces "Disposition evidence required" badge; runbook documents the certificate-of-destruction workflow |
| R-V2-09 | **Append-only-bypass attempt** — a developer or operator may attempt to UPDATE a `baa_records` row in place (e.g. to fix a typo), bypassing the version-seq immutability + hash chain → audit log loses integrity. | low | high (HHS-OCR auditor finds the gap) | DB-layer enforcement: trigger or CHECK constraint prevents UPDATE on `baa_records.{version_seq, prior_version_hash, ce_legal_name, baa_executed_at, baa_effective_at}`; tracker server's `routes/baa-records.ts` route NEVER calls UPDATE — only INSERT (creates new version row); test T-V2-20 pins; code-review checklist for any future migration includes "no direct UPDATE on baa_records" |
| R-V2-10 | **NPRM finalization horizon** — HHS NPRM (90 FR 898, 2025-01-06) proposes material changes to §164.314(a) BA-content requirements; on finalization, every active BAA's `template_era` becomes stale until amended; V.V2 must surface this transition (LOOP-V-RISKS V-X19). | high | high (operator could miss federally-required BAA-content changes) | V.V2's registry record schema carries `pending_baa_amendments[]` propagated from V.V1's catalog; tracker UI surfaces "NPRM finalization pending" banner; daily cron checks Federal Register API for the NPRM RIN (0945-AA22); on Final-Rule publication, V.V2 promotes pending block to active and force-blocks new BAA template emits until operator confirms template-era update |

## 10. Open questions

- **Q-V2-01.** Should V.V2 expose a public-facing "Trust Page" listing
  CEs with active BAAs (with operator opt-in per CE)? Some CSPs publish
  this for marketing purposes. **Tentative decision: out of scope for
  V.V2; carry as a future enhancement; if operator wants to publish,
  they can export the registry snapshot and curate manually.**
- **Q-V2-02.** Should V.V2 integrate with operator's CRM (Salesforce /
  HubSpot) to auto-flag prospects requiring BAAs? **Tentative decision:
  out of scope; LOOP-V is compliance-side, not sales-ops; future
  integration via LOOP-V.V6 or similar.**
- **Q-V2-03.** Does V.V2 need to support amendment-only flows (e.g.
  operator amends a single clause without re-executing the full BAA)?
  **Tentative decision: yes, via the `amend` API route — creates a new
  version row with `transition_kind='amend'` AND `change_reason`
  narrative; PDF upload optional (operator may attach just the
  amendment addendum).**
- **Q-V2-04.** Should V.V2 auto-generate a "BAA renewal letter" `.docx`
  for the operator to send to the CE? **REQUIRES-RESEARCH** — pattern
  varies per CE customer; tentative decision: provide a generic
  template optionally, but the operator's legal-ops team typically
  uses their own template.
- **Q-V2-05.** Does V.V2 need to handle **Data Use Agreements (DUAs)**
  for Limited Data Sets per §164.514(e)? **Tentative decision: yes —
  the schema's `relationship_kind` enum extends to include
  `data-use-agreement-lds` so DUA records coexist with BAA records;
  V.V4's ePHI tagger surfaces LDS datasets and routes them to DUA
  records rather than full BAAs (per LOOP-V-RISKS V-X31).**

## 11. REQUIRES-OPERATOR-INPUT

| field name | type | validator | UI location | failure mode if missing |
|---|---|---|---|---|
| `compliance.hipaa.role` | enum | `['business-associate','covered-entity','none']` | `config.yaml` + tracker DB Settings → HIPAA tab | V.V2 exits 2 if value missing AND `--baa-tracker` flag set; otherwise exits 0 (no-op) |
| `compliance.hipaa.baa_tracker.renewal_alert_threshold_days` | integer | 30 ≤ value ≤ 180 | `config.yaml` | Defaults to 60 if missing; warning logged |
| `compliance.hipaa.baa_tracker.cms_export_quarterly_path` | path (optional) | file exists if provided | `config.yaml` | If missing, reconciler runs single-source mode (registry only) and emits warning `cms-export-not-configured` |
| `compliance.hipaa.signing_key_ref` | string | KMS-resource ARN/URI parseable by `core/sign.ts` | `config.yaml` | V.V2 exits 2 with `BAASigningKeyMissingError` at startup sign-test |
| `ce_legal_name` per BAA intake | string | non-empty | tracker UI BAA intake form | Intake POST returns 422 |
| `ce_legal_address` per BAA intake | string | non-empty | tracker UI BAA intake form | Intake 422 |
| `ce_primary_contact.{name,title,email,phone}` | object | email regex; phone E.164 | tracker UI BAA intake form | Intake 422 |
| `ce_breach_notification_contact.{name,title,email,phone}` | object | email regex; phone E.164 | tracker UI BAA intake form | Intake 422 (this contact powers V.V3's BA→CE notification) |
| `baa_executed_at`, `baa_effective_at` | date | ISO 8601; `baa_effective_at >= baa_executed_at` | tracker UI BAA intake form | Intake 422 |
| `baa_term_kind` | enum | `['fixed-term','perpetual-until-terminated','auto-renew']` | tracker UI BAA intake form | Intake 422 |
| `baa_renewal_due_at` | date (conditional) | required when `baa_term_kind='fixed-term'` | tracker UI BAA intake form | Intake 422 if missing in fixed-term case |
| `baa_template_era` | enum | `['pre-omnibus-2013','post-omnibus-2013','post-2025-nprm','unknown']` | tracker UI BAA intake form | Default `unknown` with warning |
| `baa_pdf_upload` | object | PDF mime; SHA-256 computed server-side; size ≤ 50MB | tracker UI file upload | Intake 422 |
| `baa_conduit_classification.*` (if claimed) | object | `if_true_narrative ≥ 250 chars`; counsel sign-off populated | tracker UI BAA intake form | Intake 422 with `ConduitClassificationIncompleteError` |
| `downstream_baas[].*` | array | each entry requires `subprocessor_name`, `downstream_baa_executed_at`, `downstream_baa_pdf_sha256` | tracker UI BAA intake form (downstream BAA section) | Intake 422 |
| `termination_disposition` (on terminate) | object | `disposition_evidence_url` OR `disposition_narrative` required | tracker UI terminate flow | API returns 422 |

## 12. Implementation log

| date | session | action | commit | notes |
|---|---|---|---|---|
| 2026-06-07 | spec proposed | wf-uvxyz | Specification authored via FedPy workflow | TBD | — |

## 13. Completion checklist

The following 7-step procedure is quoted verbatim from
`docs/SLICE-COMPLETION-PROCEDURE.md`. The implementer MUST execute
ALL 7 steps atomically with the slice-closing commit.

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
