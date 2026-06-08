---
slice_id: V.V1
title: HIPAA Security Rule Catalog Ingestion + Canonicalization (45 CFR §164.302-318)
loop: V
status: proposed
commit: TBD
completed_date: —
depends_on:
  - LOOP-A.A5                           # Ed25519 + RFC 3161 signing primitive
blocks:
  - V.V2                                # HIPAA evidence emitter relies on this catalog
  - V.V3                                # 800-66 Rev 2 implementation-guidance overlay relies on this catalog
  - V.V4                                # HITRUST CSF crosswalk relies on the canonical Security Rule structure
  - V.V5                                # Breach-Notification triage references catalog standard IDs
estimated_effort: medium (~5-7 working days for single implementer)
last_updated: 2026-06-07
applicable_conditional: true
condition: Any CSP acting as a HIPAA Business Associate (BA) or Covered Entity (CE) — i.e. the CSP creates, receives, maintains, or transmits Electronic Protected Health Information (ePHI) on behalf of a Covered Entity per 45 CFR §164.502(e). FedPy operators serving healthcare-payer, provider, clearinghouse, or healthcare-SaaS customers under a Business Associate Agreement (BAA) are in scope. The applicability gate is the operator-supplied `compliance.hipaa.role` field in `config.yaml` (`business-associate | covered-entity | none`); when `none`, V.V1 is a no-op for the orchestrator run.
trigger_flag: "--hipaa-security-rule-catalog"
trigger_env: CLOUD_EVIDENCE_HIPAA_SECURITY_RULE_CATALOG
---

# V.V1 — HIPAA Security Rule Catalog Ingestion + Canonicalization

> V.V1 is the **foundation** slice for LOOP-V. Every downstream slice
> (V.V2 emits HIPAA-Security-Rule-aligned evidence, V.V3 layers NIST SP
> 800-66 Rev 2 implementation guidance on top, V.V4 produces a HITRUST
> CSF crosswalk, V.V5 implements Breach-Notification-Rule triage)
> consumes this slice's canonical JSON output. If the catalog is
> wrong, every downstream artifact is wrong, so this doc carries extra
> verbatim citations from the Code of Federal Regulations, the HHS OCR
> guidance pages, NIST SP 800-66 Rev 2, and the FedRAMP /
> HIPAA crosswalk artifacts published by NIST. Every standard,
> implementation specification, and Required-vs-Addressable flag traces
> back to a verbatim quote from 45 CFR §164.302-318.

## 1. Mission

V.V1 ingests the **HIPAA Security Rule** (45 CFR Part 164, Subpart C —
§§164.302 through 164.318) from the authoritative Office of the
Federal Register electronic CFR (eCFR) endpoint, parses every
**standard** (e.g. §164.308(a)(1) Security Management Process) and
every **implementation specification** under each standard (e.g.
§164.308(a)(1)(ii)(A) Risk Analysis), preserves the
**Required vs Addressable** disposition (45 CFR §164.306(d)), captures
the **general rules** that govern flexibility of approach
(§164.306(b)), produces a deterministic canonical JSON catalog
(`cloud-evidence/data/hipaa-security-rule-catalog.json`) with a
schema-pinned shape, an Ed25519 signature, and an RFC 3161 timestamp,
and exposes the catalog to downstream slices via a typed TypeScript
loader (`cloud-evidence/core/hipaa-security-rule-catalog.ts`).

The slice additionally produces a **bidirectional crosswalk** to NIST
SP 800-53 Rev 5 controls and to FedRAMP Moderate baseline parameter
IDs, sourced from **NIST SP 800-66 Rev 2 Appendix F** (the published
HIPAA Security Rule → 800-53 Rev 5 mapping that NIST released in
February 2024). The crosswalk is the bridge that lets a FedPy
operator already running FedRAMP-Moderate evidence collection re-use
the existing AWS / GCP / Azure cloud findings to populate HIPAA
Security Rule evidence rows in V.V2 — without re-running collectors.

V.V1 does **not** ingest the HIPAA Privacy Rule (45 CFR §§164.500-534)
nor the Breach Notification Rule (§§164.400-414); those are out of
scope for V.V1 and handled by V.V3 and V.V5 respectively. V.V1 also
does **not** ingest the HIPAA Enforcement Rule (45 CFR Part 160,
Subpart C-E). Catalogs are emitted as canonical JSON with byte-stable
key ordering (RFC 8785 JCS) so the SHA-256 of the catalog is the
authoritative content hash used by every downstream consumer for
provenance tracking.

The slice runs once per quarter at minimum (the eCFR is a live
document; HHS amends the Security Rule under formal rulemaking and
the **HHS Notice of Proposed Rulemaking issued 2024-12-27 / 2025-01-06
Federal Register publication** proposed material changes to §164.308,
§164.310, §164.312, and §164.316 that, if finalized, will require
re-ingestion). The operator schedules the re-ingestion via the
existing tracker UI cron pane; the orchestrator surfaces a
`catalog-stale` warning when the catalog's `extracted_at` is more than
90 days old.

## 2. Authoritative sources

Every URL accessed 2026-06-07. Verbatim quotes appear in Markdown
blockquotes. Where the live Federal Government source returned a
non-200 to anonymous fetches, the implementer downloads the page or
PDF to `cloud-evidence/docs/sources/` and re-quotes verbatim from the
local copy.

### 2.1 45 CFR §164.302 — Applicability (the gate)

URL: https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.302
(accessed 2026-06-07).

> "§ 164.302 Applicability.
> A covered entity or business associate must comply with the
> applicable standards, implementation specifications, and requirements
> of this subpart with respect to electronic protected health
> information of a covered entity."

This single sentence is what makes V.V1 conditional. The applicability
gate in this slice's frontmatter (`compliance.hipaa.role ∈
{business-associate, covered-entity, none}`) is the operational
implementation of §164.302's "covered entity or business associate"
predicate.

### 2.2 45 CFR §164.304 — Definitions (the term lexicon)

URL: https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.304
(accessed 2026-06-07).

Selected verbatim definitions that the catalog preserves verbatim in
its `definitions[]` block:

> "Administrative safeguards are administrative actions, and policies
> and procedures, to manage the selection, development, implementation,
> and maintenance of security measures to protect electronic protected
> health information and to manage the conduct of the covered entity's
> or business associate's workforce in relation to the protection of
> that information."

> "Physical safeguards are physical measures, policies, and procedures
> to protect a covered entity's or business associate's electronic
> information systems and related buildings and equipment, from natural
> and environmental hazards, and unauthorized intrusion."

> "Technical safeguards means the technology and the policy and
> procedures for its use that protect electronic protected health
> information and control access to it."

These three definitions are why the catalog has top-level groupings
`administrative_safeguards`, `physical_safeguards`, and
`technical_safeguards` aligned with §164.308, §164.310, and §164.312
respectively. The catalog preserves the verbatim definition text in
`catalog.definitions[]` so downstream renderers (V.V2's `.docx`
emitter) can quote-cite when referenced.

### 2.3 45 CFR §164.306 — Security standards: General rules

URL: https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.306
(accessed 2026-06-07). This section governs **how** Required vs
Addressable specifications are operationalized — the most
operationally consequential paragraph in the entire Security Rule.

§164.306(a) — General requirements:

> "(a) General requirements. Covered entities and business associates
> must do the following:
> (1) Ensure the confidentiality, integrity, and availability of all
> electronic protected health information the covered entity or
> business associate creates, receives, maintains, or transmits.
> (2) Protect against any reasonably anticipated threats or hazards to
> the security or integrity of such information.
> (3) Protect against any reasonably anticipated uses or disclosures of
> such information that are not permitted or required under subpart E
> of this part.
> (4) Ensure compliance with this subpart by its workforce."

§164.306(b) — Flexibility of approach (this is what licenses the
"Addressable" disposition):

> "(b)(1) Covered entities and business associates may use any security
> measures that allow the covered entity or business associate to
> reasonably and appropriately implement the standards and
> implementation specifications as specified in this subpart.
> (2) In deciding which security measures to use, a covered entity or
> business associate must take into account the following factors:
> (i) The size, complexity, and capabilities of the covered entity or
> business associate.
> (ii) The covered entity's or the business associate's technical
> infrastructure, hardware, and software security capabilities.
> (iii) The costs of security measures.
> (iv) The probability and criticality of potential risks to electronic
> protected health information."

§164.306(d) — Implementation specifications (the **Required vs
Addressable** rule):

> "(d) Implementation specifications. In this subpart:
> (1) Implementation specifications are required or addressable. If an
> implementation specification is required, the word 'Required' appears
> in parentheses after the title of the implementation specification.
> If an implementation specification is addressable, the word
> 'Addressable' appears in parentheses after the title of the
> implementation specification.
> (2) When a standard adopted in §164.308, §164.310, §164.312,
> §164.314, or §164.316 includes required implementation
> specifications, a covered entity or business associate must implement
> the implementation specifications.
> (3) When a standard adopted in §164.308, §164.310, §164.312,
> §164.314, or §164.316 includes addressable implementation
> specifications, a covered entity or business associate must—
> (i) Assess whether each implementation specification is a reasonable
> and appropriate safeguard in its environment, when analyzed with
> reference to the likely contribution to protecting electronic
> protected health information; and
> (ii) As applicable to the covered entity or business associate—
> (A) Implement the implementation specification if reasonable and
> appropriate; or
> (B) If implementing the implementation specification is not
> reasonable and appropriate—
> (1) Document why it would not be reasonable and appropriate to
> implement the implementation specification; and
> (2) Implement an equivalent alternative measure if reasonable and
> appropriate."

The verbatim §164.306(d) text is **mandatory** payload in every
emitted V.V2 evidence envelope's `addressable_handling_basis[]`
metadata block — when V.V2 emits evidence for an Addressable spec, it
quotes §164.306(d)(3)(ii)(B) to document the operator's reasoning if
the spec is not implemented. V.V1 surfaces the verbatim quote as
`catalog.general_rules.flexibility_text` for downstream emitters.

### 2.4 45 CFR §164.308 — Administrative safeguards

URL: https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308
(accessed 2026-06-07).

§164.308 contains 9 **standards** with 22 **implementation
specifications** (some Required, some Addressable). V.V1 ingests each
one verbatim. Example — the first standard:

> "(a) A covered entity or business associate must, in accordance with
> §164.306:
> (1)(i) Standard: Security management process. Implement policies and
> procedures to prevent, detect, contain, and correct security
> violations.
> (ii) Implementation specifications:
> (A) Risk analysis (Required). Conduct an accurate and thorough
> assessment of the potential risks and vulnerabilities to the
> confidentiality, integrity, and availability of electronic protected
> health information held by the covered entity or business associate.
> (B) Risk management (Required). Implement security measures
> sufficient to reduce risks and vulnerabilities to a reasonable and
> appropriate level to comply with §164.306(a).
> (C) Sanction policy (Required). Apply appropriate sanctions against
> workforce members who fail to comply with the security policies and
> procedures of the covered entity or business associate.
> (D) Information system activity review (Required). Implement
> procedures to regularly review records of information system activity,
> such as audit logs, access reports, and security incident tracking
> reports."

The catalog assigns each spec a stable **catalog identifier** of the
form `HSR.<section>.<standard>.<spec>` (e.g.
`HSR.164.308.a.1.ii.A` for Risk Analysis), the **disposition** flag
(`required` vs `addressable`), the **verbatim text** of the spec, and
the **citation** (e.g. `45 CFR §164.308(a)(1)(ii)(A)`).

### 2.5 45 CFR §164.310 — Physical safeguards

URL: https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.310
(accessed 2026-06-07).

§164.310 contains 4 standards with 10 implementation specifications.
Verbatim excerpt — the first standard:

> "(a)(1) Standard: Facility access controls. Implement policies and
> procedures to limit physical access to its electronic information
> systems and the facility or facilities in which they are housed,
> while ensuring that properly authorized access is allowed.
> (2) Implementation specifications:
> (i) Contingency operations (Addressable). Establish (and implement as
> needed) procedures that allow facility access in support of
> restoration of lost data under the disaster recovery plan and
> emergency mode operations plan in the event of an emergency.
> (ii) Facility security plan (Addressable). Implement policies and
> procedures to safeguard the facility and the equipment therein from
> unauthorized physical access, tampering, and theft.
> (iii) Access control and validation procedures (Addressable).
> Implement procedures to control and validate a person's access to
> facilities based on their role or function, including visitor control,
> and control of access to software programs for testing and revision.
> (iv) Maintenance records (Addressable). Implement policies and
> procedures to document repairs and modifications to the physical
> components of a facility which are related to security (for example,
> hardware, walls, doors, and locks)."

The catalog tags physical safeguards with
`group: 'physical_safeguards'`. For CSPs operating wholly in IaaS
(no owned data-center), V.V2's evidence emitter inherits the bulk of
physical safeguards from the **AWS / GCP / Azure FedRAMP package**
under a customer-responsibility-matrix entry — the catalog's
`fedramp_inheritance_hint` field surfaces that hint to V.V2.

### 2.6 45 CFR §164.312 — Technical safeguards

URL: https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312
(accessed 2026-06-07).

§164.312 contains 5 standards with 9 implementation specifications.
Verbatim excerpt — the access control standard (the most
operationally cited safeguard):

> "(a)(1) Standard: Access control. Implement technical policies and
> procedures for electronic information systems that maintain
> electronic protected health information to allow access only to those
> persons or software programs that have been granted access rights as
> specified in §164.308(a)(4).
> (2) Implementation specifications:
> (i) Unique user identification (Required). Assign a unique name
> and/or number for identifying and tracking user identity.
> (ii) Emergency access procedure (Required). Establish (and implement
> as needed) procedures for obtaining necessary electronic protected
> health information during an emergency.
> (iii) Automatic logoff (Addressable). Implement electronic procedures
> that terminate an electronic session after a predetermined time of
> inactivity.
> (iv) Encryption and decryption (Addressable). Implement a mechanism
> to encrypt and decrypt electronic protected health information."

The Encryption/Decryption Addressable spec is the single most-cited
"Addressable doesn't mean optional" example in HIPAA enforcement
literature; V.V2's evidence emitter for this spec defaults to
producing the §164.306(d)(3)(ii)(B)(2) "equivalent alternative
measure" narrative when AWS KMS / GCP CMEK / Azure Key Vault is
**not** configured.

§164.312(e)(1) — Transmission Security standard:

> "(e)(1) Standard: Transmission security. Implement technical
> security measures to guard against unauthorized access to electronic
> protected health information that is being transmitted over an
> electronic communications network.
> (2) Implementation specifications:
> (i) Integrity controls (Addressable). Implement security measures to
> ensure that electronically transmitted electronic protected health
> information is not improperly modified without detection until
> disposed of.
> (ii) Encryption (Addressable). Implement a mechanism to encrypt
> electronic protected health information whenever deemed appropriate."

### 2.7 45 CFR §164.314 — Organizational requirements

URL: https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.314
(accessed 2026-06-07).

§164.314 contains 2 standards — Business Associate Contracts and
Requirements for Group Health Plans — with 6 implementation
specifications. The BAA standard verbatim:

> "(a)(1) Standard: Business associate contracts or other arrangements.
> The contract or other arrangement required by §164.308(b)(3) must
> meet the requirements of paragraph (a)(2)(i), (a)(2)(ii), or
> (a)(2)(iii) of this section, as applicable.
> (2) Implementation specifications (Required):
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

§164.314(a)(2)(i)(C) is the **BA security-incident-report-to-CE
clause**, which V.V5's Breach-Notification triage flow surfaces as
its primary "downstream BAA notification" trigger.

### 2.8 45 CFR §164.316 — Policies and procedures and documentation requirements

URL: https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.316
(accessed 2026-06-07). The documentation-retention rule:

> "(b)(1) Standard: Documentation.
> (i) Maintain the policies and procedures implemented to comply with
> this subpart in written (which may be electronic) form; and
> (ii) If an action, activity or assessment is required by this subpart
> to be documented, maintain a written (which may be electronic) record
> of the action, activity, or assessment.
> (2) Implementation specifications:
> (i) Time limit (Required). Retain the documentation required by
> paragraph (b)(1) of this section for 6 years from the date of its
> creation or the date when it last was in effect, whichever is later.
> (ii) Availability (Required). Make documentation available to those
> persons responsible for implementing the procedures to which the
> documentation pertains.
> (iii) Updates (Required). Review documentation periodically, and
> update as needed, in response to environmental or operational changes
> affecting the security of the electronic protected health information."

The 6-year retention requirement is what drives the V.V2 evidence
emitter's default retention configuration — every emitted HIPAA
evidence envelope carries a `retention_until` field computed as
`emitted_at + 6 years` per §164.316(b)(2)(i).

### 2.9 NIST SP 800-66 Rev 2 — Implementing the HIPAA Security Rule

URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-66r2.pdf
(accessed 2026-06-07; operator mirrors to
`docs/sources/NIST.SP.800-66r2.pdf`). Published 2024-02-14.

Abstract (NIST SP 800-66 Rev 2, page iii):

> "The Health Insurance Portability and Accountability Act (HIPAA)
> Security Rule (Security Rule) establishes a national set of minimum
> security standards for protecting all electronic protected health
> information (ePHI) that a covered entity and business associate (as
> defined by the Security Rule) create, receive, maintain, or transmit.
> The Security Rule requires covered entities and business associates
> to implement reasonable and appropriate administrative, physical,
> and technical safeguards to protect the confidentiality, integrity,
> and availability of ePHI. This publication provides practical
> guidance and resources that can be used by covered entities and
> business associates of all sizes to safeguard ePHI and better
> understand the security concepts discussed in the HIPAA Security
> Rule. This publication is intended as guidance only."

NIST SP 800-66 Rev 2 Appendix F — the **HIPAA Security Rule
Crosswalk to NIST Cybersecurity Framework Subcategories and SP 800-53
Rev. 5 Security Controls** — is V.V1's authoritative source for the
catalog's `nist_800_53_rev5_crosswalk[]` field. The crosswalk is
**directional**: Appendix F maps each HIPAA implementation
specification to a set of 800-53 Rev 5 control IDs that "address" the
specification. V.V1 inverts the table at build time so a downstream
consumer can ask "for AC-2 (Account Management), which HIPAA specs
does it satisfy?" as well as the forward direction.

### 2.10 HHS HIPAA Security Rule landing page

URL: https://www.hhs.gov/hipaa/for-professionals/security/index.html
(accessed 2026-06-07).

> "The HIPAA Security Rule establishes national standards to protect
> individuals' electronic personal health information that is created,
> received, used, or maintained by a covered entity. The Security Rule
> requires appropriate administrative, physical and technical
> safeguards to ensure the confidentiality, integrity, and security of
> electronic protected health information."

This HHS page is the authoritative summary; V.V1 records its URL +
fetch timestamp in `catalog.source_provenance[]` so a 3PAO reviewing
the catalog can verify the HHS-confirmed scope.

### 2.11 HHS Notice of Proposed Rulemaking (2024-12-27 / 2025-01-06 FR publication)

URL: https://www.federalregister.gov/documents/2025/01/06/2024-30983/hipaa-security-rule-to-strengthen-the-cybersecurity-of-electronic-protected-health-information
(accessed 2026-06-07; operator mirrors PDF + HTML to
`docs/sources/`).

Status as of 2026-06-07: **proposed rule, not yet finalized**. The
NPRM proposes material changes to §164.308 (adds explicit asset
inventory and network map requirements), §164.312 (mandates
multi-factor authentication and encryption-at-rest for ePHI),
§164.316 (adds annual compliance audit requirement). V.V1's catalog
tracks the proposed amendments in a parallel
`pending_amendments[]` block — they are **not** emitted as live
catalog entries (the final rule has not been published in the CFR)
but they are visible to downstream consumers so the operator can
pre-emptively plan implementation. When the final rule is published,
the V.V1 re-ingestion run promotes the pending amendments into the
active catalog and surfaces a CHANGELOG entry.

> "Today, the Department of Health and Human Services (HHS or
> Department), through the Office for Civil Rights (OCR), publishes
> this notice of proposed rulemaking (NPRM) to modify the Security
> Standards for the Protection of Electronic Protected Health
> Information (Security Rule) under the Health Insurance Portability
> and Accountability Act of 1996 (HIPAA), as amended by the Health
> Information Technology for Economic and Clinical Health Act of 2009
> (HITECH Act). The proposed modifications would better align the
> Security Rule with modern best practices in cybersecurity and
> address known cybersecurity threats."

The NPRM also notes the 60-day public-comment window (closed
2025-03-07) and the typical HHS-OCR finalization timeline of
12-18 months from comment-period close. V.V1 sets
`pending_amendments[].expected_finalization_window` to "Q1-Q3 2026"
with `confidence: 'moderate'`.

### 2.12 HHS Office for Civil Rights Compliance & Enforcement page

URL: https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/index.html
(accessed 2026-06-07).

> "OCR enforces the HIPAA Privacy, Security, and Breach Notification
> Rules, and may take action on complaints filed with OCR, performs
> compliance reviews, and conducts education and outreach to foster
> compliance with the Rules' requirements."

V.V1 surfaces the HHS-OCR complaint-portal URL
(https://ocrportal.hhs.gov/ocr/smartscreen/main.jsf) in the catalog's
`enforcement.complaint_portal_url` field so V.V5 can include it in
the operator's incident-response runbook.

## 3. Scope

### 3.1 In scope

- Ingestion of **45 CFR §§164.302 through 164.318** verbatim from the
  eCFR (live) into a canonical JSON structure.
- Preservation of the **standard / implementation specification**
  hierarchy with stable catalog identifiers.
- Preservation of the **Required vs Addressable** disposition flag on
  every implementation specification.
- Preservation of the **§164.304 definitions** as `catalog.definitions[]`.
- Preservation of the **§164.306 general rules** (CIA mandate +
  flexibility-of-approach text) as `catalog.general_rules`.
- Construction of the **NIST 800-53 Rev 5 crosswalk** sourced from
  NIST SP 800-66 Rev 2 Appendix F, bidirectional.
- Construction of the **FedRAMP Moderate baseline crosswalk** by
  intersecting the 800-53 Rev 5 crosswalk with the FedRAMP Moderate
  parameter IDs (sourced from the already-ingested
  `data/fedramp-moderate-baseline.json` produced by an earlier slice).
- Tracking of the **HHS NPRM 2025-01-06 pending amendments** in a
  parallel `pending_amendments[]` block.
- Canonical-JSON emit (RFC 8785 JCS), Ed25519 signature, RFC 3161
  timestamp on the emitted artifact.
- Provenance block recording every source URL + fetch timestamp +
  SHA-256 of the fetched bytes.
- Failed-fetch handling: V.V1 fails closed (exit 2) rather than emit
  a partial catalog.

### 3.2 Out of scope (NOT in V.V1)

- The **HIPAA Privacy Rule** (45 CFR §§164.500-534) — handled by V.V3.
- The **Breach Notification Rule** (45 CFR §§164.400-414) — handled
  by V.V5.
- The **HIPAA Enforcement Rule** (45 CFR Part 160 Subpart C-E) —
  V.V1 cites the OCR enforcement page but does not ingest the
  enforcement-procedure catalog.
- The **HITRUST CSF crosswalk** — handled by V.V4 (downstream consumer
  of this slice's catalog).
- Evidence collection from cloud providers against HIPAA specs —
  handled by V.V2.
- **Operator-organization-specific implementations** (e.g. "we use
  AWS KMS for the encryption Addressable") — these flow through V.V2
  and the tracker DB, not the catalog.
- **State-law preemption analysis** — out of scope; some states have
  stricter health-privacy laws (CA CMIA, TX HB300) which are tracked
  in LOOP-U not LOOP-V.

## 4. Inputs

### 4.1 eCFR fetch input

V.V1's extractor script (`scripts/extract-hipaa-security-rule.mjs`)
fetches the following endpoints, with retry + exponential backoff
implemented via the existing `core/retry.ts`:

```ts
interface ECFRFetchInput {
  base_url: 'https://www.ecfr.gov';
  sections: Array<{
    cfr_citation: string;       // e.g. '45 CFR §164.302'
    endpoint: string;           // e.g. '/api/versioner/v1/full/2026-06-07/title-45.xml?subtitle=A&chapter=C&part=164&subpart=C&section=164.302'
    fallback_endpoint: string;  // HTML scrape URL if XML API rate-limited
    expected_min_bytes: number;
  }>;
  user_agent: string;           // e.g. 'fedpy-cloud-evidence/1.0 (HIPAA Security Rule catalog ingest)'
  max_retries: 5;
  backoff_base_ms: 2000;
}
```

The eCFR API returns XML; the extractor uses `fast-xml-parser` (an
existing dependency from the OSCAL pipeline) to walk the structure
tree and pluck out `<DIV5>` / `<DIV6>` / `<DIV7>` elements that
correspond to the standard / implementation-specification levels.

### 4.2 NIST SP 800-66 Rev 2 Appendix F input

```ts
interface NIST80066Rev2AppendixFInput {
  source_pdf_path: string;            // local mirror after one-time download
  source_pdf_sha256: string;
  table_locator: {
    page_start: 73;                   // page 73 of NIST.SP.800-66r2.pdf
    page_end: 88;
    table_caption: string;            // 'Crosswalk between the HIPAA Security Rule and NIST Cybersecurity Framework Subcategories and NIST SP 800-53 Rev. 5 controls'
  };
  extracted_at: string;               // ISO 8601 UTC
}
```

The Appendix F table is extracted via `pdf-parse` (an existing
dependency); the extractor implements the table-parse heuristic
documented inline in `scripts/extract-hipaa-security-rule.mjs` §3.

### 4.3 FedRAMP Moderate baseline input

```ts
interface FedRAMPModerateInput {
  catalog_path: 'cloud-evidence/data/fedramp-moderate-baseline.json';
  catalog_sha256: string;
  schema_version: '1.0.0';
}
```

V.V1 reads the FedRAMP Moderate baseline (produced by an earlier
slice) to intersect with the NIST 800-53 crosswalk and tag each
crosswalk entry with `is_in_fedramp_moderate: boolean`.

### 4.4 Operator config gate

```yaml
compliance:
  hipaa:
    role: business-associate          # business-associate | covered-entity | none
    baa_inventory:
      - covered_entity_name: ExampleHealthcare LLC
        baa_signed_date: 2025-04-01
        baa_renewal_due: 2026-04-01
        scope: production
    addressable_handling_defaults:
      # Per §164.306(d)(3), the operator pre-declares the disposition basis
      # for each Addressable spec to streamline V.V2 evidence emission.
      automatic_logoff: implement
      encryption_at_rest: implement
      encryption_in_transit: implement
      contingency_operations: equivalent-alternative
      facility_security_plan: inherit-from-aws-fedramp
```

## 5. Outputs

### 5.1 Canonical JSON catalog

Path: `cloud-evidence/data/hipaa-security-rule-catalog.json`.

```ts
interface HIPAASecurityRuleCatalog {
  schema_version: '1.0.0';
  catalog_id: 'hipaa-security-rule-45-cfr-164-302-318';
  catalog_title: 'HIPAA Security Rule (45 CFR §§164.302-318)';
  cfr_revision_date: string;                       // e.g. '2024-12-30'
  extracted_at: string;                            // ISO 8601 UTC
  applicability_text_verbatim: string;             // §164.302 verbatim
  definitions: Array<{
    term: string;
    verbatim_text: string;
    citation: string;                              // '45 CFR §164.304'
  }>;
  general_rules: {
    cia_mandate_verbatim: string;                  // §164.306(a) verbatim
    flexibility_factors_verbatim: string;          // §164.306(b) verbatim
    required_vs_addressable_text_verbatim: string; // §164.306(d) verbatim
  };
  groups: {
    administrative_safeguards: HIPAAGroup;         // §164.308
    physical_safeguards: HIPAAGroup;               // §164.310
    technical_safeguards: HIPAAGroup;              // §164.312
    organizational_requirements: HIPAAGroup;       // §164.314
    policies_procedures_documentation: HIPAAGroup; // §164.316
  };
  pending_amendments: Array<{
    nprm_url: string;
    nprm_publication_date: string;
    expected_finalization_window: string;
    proposed_changes_summary: string;
  }>;
  enforcement: {
    hhs_ocr_complaint_portal_url: string;
    hhs_security_rule_landing_url: string;
  };
  source_provenance: Array<{
    source_kind: 'ecfr-xml' | 'nist-800-66-rev2-pdf' | 'hhs-html' | 'fedramp-moderate-baseline';
    url_or_path: string;
    fetched_at: string;
    sha256_of_bytes: string;
    bytes_size: number;
  }>;
  signature: { alg: 'ed25519'; key_id: string; sig: string };
  rfc3161_timestamp: { tsa_url: string; token: string; received_at: string };
}

interface HIPAAGroup {
  cfr_section: string;                             // '45 CFR §164.308'
  group_title: string;                             // 'Administrative safeguards'
  group_definition_verbatim: string;               // pulled from §164.304
  standards: HIPAAStandard[];
}

interface HIPAAStandard {
  catalog_id: string;                              // e.g. 'HSR.164.308.a.1'
  citation: string;                                // '45 CFR §164.308(a)(1)'
  standard_title: string;                          // 'Security management process'
  standard_text_verbatim: string;
  implementation_specifications: HIPAAImplSpec[];
}

interface HIPAAImplSpec {
  catalog_id: string;                              // e.g. 'HSR.164.308.a.1.ii.A'
  citation: string;                                // '45 CFR §164.308(a)(1)(ii)(A)'
  spec_title: string;                              // 'Risk analysis'
  spec_text_verbatim: string;
  disposition: 'required' | 'addressable';
  nist_800_53_rev5_crosswalk: string[];            // e.g. ['RA-3','CA-2','PM-9']
  nist_csf_subcategories: string[];                // e.g. ['ID.RA-1','ID.RA-3']
  fedramp_moderate_alignment: Array<{
    control_id: string;
    parameter_id: string;
    is_in_baseline: boolean;
  }>;
  fedramp_inheritance_hint: 'csp-implemented' | 'customer-implemented' |
                            'shared' | 'inherited-from-iaas-provider';
}
```

### 5.2 TypeScript loader module

Path: `cloud-evidence/core/hipaa-security-rule-catalog.ts`. Exports:

```ts
export function loadHIPAASecurityRuleCatalog(): HIPAASecurityRuleCatalog;
export function getStandard(catalogId: string): HIPAAStandard;
export function getImplSpec(catalogId: string): HIPAAImplSpec;
export function getSpecsByDisposition(d: 'required' | 'addressable'): HIPAAImplSpec[];
export function getSpecsForNIST800_53Control(controlId: string): HIPAAImplSpec[];
export function getNIST800_53ControlsForSpec(specId: string): string[];
export function catalogSHA256(): string;
export function isCatalogStale(maxAgeDays?: number): boolean;
```

All loader functions verify the Ed25519 signature on first load and
throw `CatalogSignatureInvalidError` on mismatch. Catalog is cached
in-process after successful signature verification.

### 5.3 Provenance entry for downstream consumers

V.V2's evidence emitter and V.V4's HITRUST crosswalk emit a
`hipaa_security_rule_catalog_provenance` block in every output
artifact:

```ts
interface HIPAACatalogProvenance {
  catalog_path: string;
  catalog_sha256: string;
  catalog_extracted_at: string;
  catalog_signature_verified: boolean;
}
```

## 6. Algorithm / Steps

### Phase A — Bootstrap

1. **Parse CLI flag** `--hipaa-security-rule-catalog` (or env
   `CLOUD_EVIDENCE_HIPAA_SECURITY_RULE_CATALOG`). If neither set,
   exit 0 (no-op).
2. **Check operator config gate.** Read
   `config.yaml::compliance.hipaa.role`. If `none`, exit 0 and log
   `LOOP-V skipped — operator-config role=none`.
3. **Verify dependency catalogs.** Read
   `data/fedramp-moderate-baseline.json` and verify its Ed25519
   signature. Failure → exit 2 with
   `FedRAMPModerateBaselineSignatureInvalidError`.
4. **Sign-test the signing key.** Call
   `core/sign.ts::testSign(key_ref)` to verify operator's KMS
   signing-rights at startup. Failure → exit 2.

### Phase B — Fetch + parse 45 CFR §§164.302-318

5. **Fetch each CFR section** via the eCFR XML API
   (`/api/versioner/v1/full/<date>/title-45.xml`). On 5xx or
   network error, retry 5x with exponential backoff (2s, 4s, 8s,
   16s, 32s). On final failure, fall back to HTML scrape of the
   public eCFR page. On both-failure, exit 2 with
   `ECFRFetchFailedError`.
6. **SHA-256 each fetched payload** and record in
   `catalog.source_provenance[]`.
7. **Parse XML** via `fast-xml-parser`. Walk `<DIV5>` (section) →
   `<DIV6>` (standard) → `<DIV7>` (implementation specification).
8. **Extract disposition.** For each implementation spec, scan the
   verbatim title text for the parenthesized `(Required)` or
   `(Addressable)` token. Per §164.306(d)(1), exactly one of the
   two **MUST** appear; absence is a parse error (exit 2 with
   `HIPAASpecDispositionMissingError`).
9. **Assign catalog identifiers** of the form
   `HSR.<section>.<paragraph-tree>` using a deterministic walker.
   Cross-check that no two specs share the same catalog ID;
   collision is a parse error.
10. **Cross-validate spec count.** The catalog SHOULD have:
    - §164.308: 9 standards, 22 implementation specifications;
    - §164.310: 4 standards, 10 implementation specifications;
    - §164.312: 5 standards, 9 implementation specifications;
    - §164.314: 2 standards, 6 implementation specifications;
    - §164.316: 1 standard, 3 implementation specifications.
    These counts are sourced from NIST SP 800-66 Rev 2 Table 2 and
    are spec-pinned in the test `T-V1-09`. Deviation triggers
    warning (CFR may have been amended); >2 missing triggers
    error.

### Phase C — Crosswalk construction

11. **Load NIST SP 800-66 Rev 2 Appendix F** PDF table via
    `pdf-parse`. Walk each row; extract the HIPAA-spec citation
    (column 1), the NIST CSF subcategories (column 2), the
    800-53 Rev 5 controls (column 3).
12. **Join Appendix F rows** to V.V1 catalog specs by citation
    string match. Unjoinable rows produce a warning logged to
    `catalog.crosswalk_warnings[]` (does not exit).
13. **Build inverse index** `nist_800_53 → hipaa_specs[]` for the
    loader's `getSpecsForNIST800_53Control()` function.
14. **Intersect with FedRAMP Moderate baseline.** For each
    crosswalk entry's 800-53 control list, set
    `fedramp_moderate_alignment[].is_in_baseline = true` when the
    control is in the FedRAMP Moderate parameter set.

### Phase D — Pending amendments

15. **Read NPRM source file** `docs/sources/hipaa-nprm-2025-01-06.html`
    (operator-mirrored on first run). Extract the proposed-changes
    summary section. Populate `catalog.pending_amendments[0]` with
    the URL, publication date, and expected finalization window.
16. **Diff pending amendments** vs previous catalog (if exists). New
    amendments since last extraction surface in the orchestrator
    run summary as `INFO: <N> new HIPAA NPRM amendments detected`.

### Phase E — Canonicalize + sign

17. **Sort all keys recursively** per RFC 8785 (JCS) canonical JSON.
18. **Emit catalog bytes** to a temp file (`atomic-write` pattern —
    write to `<final-path>.tmp` then `fs.renameSync`).
19. **Compute SHA-256** of emitted bytes; embed in
    `provenance.self_sha256` field.
20. **Sign** via `core/sign.ts::signFile(path, key_ref)`. Append
    Ed25519 detached signature in `signature` block.
21. **RFC 3161 timestamp** via `core/timestamp.ts::stampFile(path)`.
    Append token in `rfc3161_timestamp` block.

### Phase F — Persist + announce

22. **Write final catalog** to
    `cloud-evidence/data/hipaa-security-rule-catalog.json`.
23. **Emit run log** to `out/hipaa-security-rule-catalog-run.log`
    capturing: fetch URLs + sizes, parse counts (standards / specs),
    crosswalk join warnings, sign+timestamp success.
24. **Append CHANGELOG entry** (the slice-completion procedure
    handles this; the extractor does not auto-mutate CHANGELOG).
25. **Surface `catalog-stale` warning** when re-run on an existing
    catalog and `extracted_at > 90 days ago`.

## 7. Files to create / modify

Absolute paths under `/Users/kenith.philip/FedRAMP 20x/`:

- `cloud-evidence/core/hipaa-security-rule-catalog.ts` — typed
  loader + accessors + signature verification.
- `cloud-evidence/core/hipaa-catalog-types.ts` — TypeScript
  interfaces shared by V.V1..V.V5.
- `cloud-evidence/scripts/extract-hipaa-security-rule.mjs` — eCFR
  fetcher + parser + crosswalk builder + signer/timestamper.
- `cloud-evidence/data/hipaa-security-rule-catalog.json` —
  canonical-JSON catalog (committed to repo, refreshed quarterly).
- `cloud-evidence/test/hipaa-security-rule-catalog.test.ts` — test
  suite (see §8).
- `cloud-evidence/test/fixtures/hipaa-ecfr-sample.xml` — fixed
  fixture for offline parser tests.
- `cloud-evidence/test/fixtures/nist-800-66-rev2-appendix-f-sample.json`
  — extracted Appendix F table fixture.
- `cloud-evidence/docs/sources/NIST.SP.800-66r2.pdf` — one-time
  operator-mirrored NIST PDF.
- `cloud-evidence/docs/sources/hipaa-nprm-2025-01-06.html` — NPRM
  mirror.
- `cloud-evidence/docs/STATUS.md` — V.V1 row updated to `done` at
  slice close.
- `cloud-evidence/docs/loops/LOOP-V-SPEC.md` — V.V1 row in status
  table updated.
- `CHANGELOG.md` — Unreleased entry appended.

## 8. Test specifications

| id | scenario | fixture path | expected | acceptance |
|---|---|---|---|---|
| T-V1-01 | Happy-path ingest from fixture XML produces a catalog with all 5 groups present | `test/fixtures/hipaa-ecfr-sample.xml` | `catalog.groups.{administrative,physical,technical,organizational,documentation}_safeguards` all populated | All five group keys exist; standards array non-empty in each |
| T-V1-02 | Required vs Addressable disposition parsed correctly | `test/fixtures/hipaa-ecfr-sample.xml` | `HSR.164.308.a.1.ii.A.disposition === 'required'`; `HSR.164.310.a.2.i.disposition === 'addressable'` | Spec disposition flags match the verbatim CFR text |
| T-V1-03 | Catalog ID stability (regression) — IDs are deterministic across runs | (live fetch with seed) | Two consecutive runs produce identical `catalog_id`s for every spec | `JSON.stringify(idsRun1) === JSON.stringify(idsRun2)` |
| T-V1-04 | RFC 8785 JCS canonical-JSON output is byte-stable | `test/fixtures/golden-hipaa-catalog.json` | Emitted bytes match the golden file SHA-256 | `sha256(emitted) === goldenSHA256` |
| T-V1-05 | Ed25519 signature round-trip — sign + verify succeeds | n/a | `verifyEnvelope(emitted, pubkey) === true` | Boolean true |
| T-V1-06 | Signature-tampering rejection — flipping any byte invalidates the signature | mutated emit | `verifyEnvelope()` throws `CatalogSignatureInvalidError` | Exception thrown |
| T-V1-07 | Crosswalk forward direction — `getNIST800_53ControlsForSpec('HSR.164.308.a.1.ii.A')` returns `['RA-3','CA-2','PM-9']` (per 800-66r2 Appendix F) | `test/fixtures/nist-800-66-rev2-appendix-f-sample.json` | Array equality | Set-equal (order-independent) |
| T-V1-08 | Crosswalk inverse direction — `getSpecsForNIST800_53Control('AC-2')` returns at least one HIPAA spec | (same fixture) | Non-empty array | `result.length >= 1` |
| T-V1-09 | Spec count validation — admin=22, physical=10, technical=9, organizational=6, documentation=3 | `test/fixtures/hipaa-ecfr-sample.xml` | Counts match | Equality |
| T-V1-10 | Missing disposition is a parse error | `test/fixtures/hipaa-ecfr-bad-no-disposition.xml` | Extractor throws `HIPAASpecDispositionMissingError` | Exception thrown |
| T-V1-11 | Catalog ID collision is a parse error | `test/fixtures/hipaa-ecfr-bad-collision.xml` | Extractor throws `HIPAACatalogIdCollisionError` | Exception thrown |
| T-V1-12 | Verbatim definitions extracted — `administrative_safeguards` definition matches §164.304 verbatim | `test/fixtures/hipaa-ecfr-sample.xml` | `catalog.definitions[i].verbatim_text` === expected verbatim string | String equality |
| T-V1-13 | §164.306(d) verbatim text preserved in `general_rules.required_vs_addressable_text_verbatim` | (same fixture) | String equality vs golden expected | Equality |
| T-V1-14 | Pending amendments populated from NPRM source | `test/fixtures/hipaa-nprm-2025-01-06-sample.html` | `catalog.pending_amendments[0].nprm_url` === expected URL | URL equality |
| T-V1-15 | Catalog-stale warning fires when `extracted_at` > 90 days ago | (synthetic catalog with old `extracted_at`) | `isCatalogStale()` returns `true`; orchestrator log contains `catalog-stale` warning | Boolean + log assertion |
| T-V1-16 | FedRAMP Moderate intersection — `fedramp_moderate_alignment[].is_in_baseline` set correctly for AC-2 (in baseline) and AC-25 (not in baseline) | `test/fixtures/fedramp-moderate-baseline-sample.json` | AC-2 → `true`, AC-25 → `false` | Per-row equality |
| T-V1-17 | eCFR fetch failure with all 5 retries exhausted exits with `ECFRFetchFailedError` | mock 5xx-everywhere transport | Extractor exits non-zero with named error | Exception thrown |
| T-V1-18 | Provenance block — `source_provenance[]` records SHA-256 + byte size of every fetched payload | (live fixture) | Each entry has non-empty `sha256_of_bytes` + `bytes_size > 0` | Non-empty + positive |
| T-V1-19 | Operator-config gate — `compliance.hipaa.role = 'none'` makes the slice a no-op | n/a | Exit 0 with log `LOOP-V skipped` | Exit code + log assertion |
| T-V1-20 | Cached load — second call to `loadHIPAASecurityRuleCatalog()` returns the same object instance without re-reading disk | n/a | `cat1 === cat2` (reference equality) | Identity check |

## 9. Risks

| id | risk | likelihood | impact | mitigation |
|---|---|---|---|---|
| R-V1-01 | The eCFR XML structure may change between quarterly refreshes (HHS amends Subpart C; element nesting shifts). The parser hard-codes the `<DIV5>/<DIV6>/<DIV7>` hierarchy and would silently miss new elements. | medium | high (downstream artifacts emit stale catalog) | T-V1-09 spec-count test fails fast; parser logs a structured warning when an unknown `<DIV*>` is encountered; quarterly re-ingestion job runs in CI and a humans review the diff before merge |
| R-V1-02 | NIST SP 800-66 Rev 2 Appendix F PDF table extraction via `pdf-parse` is heuristic — table column boundaries may shift if NIST republishes a typeset PDF. | medium | medium (crosswalk gaps degrade V.V2 evidence linkage) | Hand-extracted golden fixture in `test/fixtures/`; PDF parse warnings surface in `catalog.crosswalk_warnings[]`; nightly CI job re-runs extraction and fails on diff |
| R-V1-03 | HHS NPRM 2025-01-06 may be finalized (Final Rule) before V.V1's next quarterly run, leaving downstream consumers with an outdated catalog. | high | high (operator could miss a federally-required new spec) | Operator dashboard surfaces "HHS Final Rule pending" warning; tracker DB cron polls the Federal Register API daily for the NPRM RIN (0945-AA22); on Final Rule publication, the orchestrator banner turns red and force-blocks V.V2 emits until V.V1 re-ingests |
| R-V1-04 | Catalog signing key compromise — if the key used to sign `hipaa-security-rule-catalog.json` is exposed, an attacker could substitute a tampered catalog and the V.V1 loader would still accept it. | low | critical (every HIPAA evidence envelope would inherit the tampered catalog provenance) | Key stored in operator KMS (AWS/GCP/Azure KMS) with strict IAM; key rotation policy documented in V.V1 operator runbook; catalog SHA-256 mirrored to a tamper-evident transparency log (CT-style) per LOOP-Z roadmap |
| R-V1-05 | eCFR API rate limit (200 req/min anonymous) may throttle quarterly re-ingestion if multiple operators run concurrently. | low | low (retry/backoff handles it; worst case the run takes 30 minutes instead of 30 seconds) | Operator may supply an eCFR API token in `config.yaml::ecfr.api_token` for higher rate limit; extractor caches by `cfr_revision_date` so unchanged sections are not re-fetched |
| R-V1-06 | FedRAMP Moderate baseline may be re-published (FedRAMP PMO updates the parameter set) between V.V1 runs, causing `fedramp_moderate_alignment[].is_in_baseline` flags to go stale. | medium | low (V.V1's quarterly re-ingestion picks up the update; the flag is informational not blocking) | V.V1 checks the FedRAMP baseline's `extracted_at` field; if > 90 days old, surfaces `INFO: FedRAMP Moderate baseline stale — re-ingest before HIPAA catalog refresh` |

## 10. Open questions

- **Q-V1-01.** Should V.V1 also ingest 45 CFR §164.318 (the
  Subpart-C compliance dates section)? It is historical — all
  compliance dates are in the past — but a 3PAO reviewing the
  artifact may expect a complete §§164.302-318 ingest. **Tentative
  decision: yes, include for completeness; mark all spec compliance
  dates as `historical: true`.** Confirm with operator legal team.
- **Q-V1-02.** When the HHS NPRM is finalized, should V.V1 ingest
  pre-effective-date entries (i.e. specs that are in the Final Rule
  but not yet in force)? **Tentative decision: yes, mark them
  `effective_at: <date>` and surface a `not-yet-effective` flag so
  downstream consumers handle them differently.**
- **Q-V1-03.** Does NIST plan to publish 800-66 Rev 3? The Rev 2
  was published 2024-02; a typical NIST SP revision cycle is 3-5
  years. V.V1 should detect a Rev 3 publication and fail-warn until
  the operator manually upgrades the crosswalk source.
  **REQUIRES-RESEARCH.**
- **Q-V1-04.** Should the `nist_csf_subcategories[]` field track
  CSF 1.1 or CSF 2.0? NIST 800-66 Rev 2 was authored against CSF
  1.1 but CSF 2.0 was finalized 2024-02-26. **Tentative decision:
  preserve the CSF 1.1 subcategory IDs from 800-66 Rev 2 Appendix F
  as-is, and add a parallel `nist_csf_2_0_subcategories[]` field
  populated via the NIST-published CSF 1.1 → 2.0 mapping.**

## 11. REQUIRES-OPERATOR-INPUT

| field name | type | validator | UI location | failure mode if missing |
|---|---|---|---|---|
| `compliance.hipaa.role` | enum | `['business-associate','covered-entity','none']` | `config.yaml` (committed) + tracker DB Settings → HIPAA tab | V.V1 exits 2 if value missing AND `--hipaa-security-rule-catalog` flag set; otherwise exits 0 (no-op) |
| `compliance.hipaa.baa_inventory[]` | array | non-empty when role = `business-associate` | tracker DB BAA Manager page | V.V2 emits warning at evidence time; V.V1 itself does not require this for catalog ingestion |
| `compliance.hipaa.signing_key_ref` | string | KMS-resource ARN/URI parseable by `core/sign.ts` | `config.yaml` | V.V1 exits 2 with `HIPAASigningKeyMissingError` at startup sign-test |
| `compliance.hipaa.ecfr_api_token` | string (optional) | non-empty string when present | `config.yaml` (operator-supplied) | V.V1 proceeds without auth; rate limit may be hit |
| `compliance.hipaa.fedramp_moderate_baseline_path` | path | file exists + signature verifies | `config.yaml` | V.V1 exits 2 with `FedRAMPModerateBaselineMissingError` |
| `compliance.hipaa.nist_800_66_pdf_path` | path | file exists + SHA-256 matches published NIST hash | `config.yaml` + operator-mirrored under `docs/sources/` | V.V1 exits 2 with `NIST80066PDFMissingError` (one-time-operator-action) |
| `compliance.hipaa.addressable_handling_defaults` | object | each key is a recognized Addressable spec catalog ID; value ∈ `{implement, document-not-implement, equivalent-alternative, inherit-from-iaas-provider}` | tracker DB HIPAA Addressable Defaults page | V.V1 logs warning per missing default; V.V2 falls back to `equivalent-alternative` at evidence time |

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
