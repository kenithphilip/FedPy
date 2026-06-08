---
loop_id: Z
title: International Equivalence — ISO/IEC 27001:2022 + 27017:2015 + 27018:2019 + 27701:2019 + ENISA EUCS Candidate Scheme
status: pending
applicable_conditional: true
condition: CSP serves customers, partners, regulators, or supply-chain counterparties outside the United States, OR seeks to satisfy a non-U.S. equivalence demand (EU Cloud Services Regulation, UK G-Cloud, Japan ISMAP, Australia IRAP, GCC Common Assurance Framework, Singapore MTCS, India CERT-In) that recognises ISO/IEC 27001 + cloud / privacy add-ons. LOOP-Z is also triggered when an enterprise customer's procurement questionnaire references ISO/IEC 27001:2022 certification, or when a managed-service customer demands a Statement of Applicability (SoA) as a contract artifact. LOOP-Z is NOT triggered when the CSP serves U.S.-Federal customers only AND has no commercial / international book of business.
trigger_flag: "--international-equivalence"
trigger_env: CLOUD_EVIDENCE_INTERNATIONAL_EQUIVALENCE
depends_on:
  - LOOP-A.A4   # Submission bundler — SoA + EUCS submission package + 27017/27018/27701 evidence land in the bundle catalogue
  - LOOP-A.A5   # Signing pipeline (Ed25519 + RFC 3161) — all five Z slices flow through signEnvelope
  - LOOP-B.B1   # Risk scoring + risk register — Z.Z2 SoA emitter reads the risk register to populate clause 6.1.3(d) justifications
  - LOOP-U.U1   # Privacy frameworks crosswalk — Z.Z4 (27018 PII Processor) and Z.Z5 (27701 PIMS) link to LOOP-U's GDPR / CCPA mappings
  - LOOP-V.V1   # HIPAA crosswalk — Z.Z4 (27018) overlaps with PHI processing where the CSP serves a Healthcare-covered entity
  - LOOP-INV-S  # Inventory + Coverage Contract — Z.Z3 (27017) reads inventory tags to compute per-cloud control coverage
  - core/control-benchmark.ts # NIST 800-53 Rev 5 — Z.Z1 crosswalks Annex A controls to 800-53 control families
  - data/frmr-ksi-catalog.json # FedRAMP 20x KSI catalog — Z.Z1 includes a third column for FedRAMP Moderate
blocks:
  - LOOP-Q.Q1   # Marketplace metadata — Q.Q1 surfaces "ISO 27001 certified" + "EUCS Substantial" badges once Z.Z2 and Z.Z5 sign off
estimated_effort: 6 weeks (single implementer; Z.Z1 ~ 7 days, Z.Z2 ~ 7 days, Z.Z3 ~ 6 days, Z.Z4 ~ 5 days, Z.Z5 ~ 7 days)
last_updated: 2026-06-07
---

# LOOP-Z — International Equivalence (ISO/IEC 27001:2022 + 27017:2015 + 27018:2019 + 27701:2019 + ENISA EUCS Candidate Scheme)

> Comprehensive implementation specification for the five slices in LOOP-Z.
> Authored as a stand-alone artifact: any future Claude / human session can
> execute LOOP-Z end-to-end by reading ONLY this file + the five supporting
> per-slice docs cited in §3. No prior conversation history required.
>
> Authority: `cloud-evidence/CLAUDE.md` (Real-Evidence-Only standard) governs
> every slice below. Every byte emitted must trace back to real evidence (a
> real control-mapping fixture, a real risk-register row from the tracker DB,
> a real live cloud-inventory enumeration, or operator-supplied configuration).
> Slices ship under the Real Slice Contract in CLAUDE.md Rule 2.
>
> LOOP-Z is **conditional**: it fires only when the CSP serves non-U.S.
> customers or seeks international equivalence. The orchestrator gates LOOP-Z
> behind `--international-equivalence` (or `CLOUD_EVIDENCE_INTERNATIONAL_EQUIVALENCE=1`).
> When triggered, LOOP-Z is *additive* to the FedRAMP 20x submission — it
> does NOT replace the FedRAMP package. The two artefact universes co-exist:
> FedRAMP 20x for the U.S. Federal agency consumer; LOOP-Z for the ISO
> certification body, the ENISA EUCS conformity-assessment body, the
> commercial international customer, or the supply-chain counterparty.

---

## 1. Mission & scope

### 1.1 Why LOOP-Z exists (the audit story)

The first three audit passes (`docs/ADDITIONAL-LOOPS-AUDIT.md`,
`docs/SECOND-PASS-AUDIT.md`, `docs/THIRD-PASS-AUDIT.md`) focused
entirely on U.S. Federal compliance obligations. The fourth-pass audit
(`docs/FOURTH-PASS-AUDIT.md`, 2026-06-07) surfaced LOOP-Z as the
highest-priority **international-equivalence gap** because:

1. **FedRAMP authorization does not satisfy ISO/IEC 27001 directly.**
   FedRAMP 20x is a U.S. Federal-Government scheme based on NIST SP
   800-53 Rev 5 + 800-53B baselines + FedRAMP-specific KSIs. ISO/IEC
   27001:2022 is a private-sector / international scheme based on a
   risk-driven Information Security Management System (ISMS) with a
   93-control Annex A. The two overlap heavily — but they are NOT
   reciprocal. A FedRAMP-authorized CSP that wants to sell to an EU
   enterprise customer or a Japanese government agency is asked for
   ISO/IEC 27001:2022 certification, an ISO/IEC 27017:2015 cloud
   extension, an ISO/IEC 27018:2019 PII-processor extension, and
   increasingly an ISO/IEC 27701:2019 PIMS extension. None of those is
   automatic from a FedRAMP authorization.

2. **NIST OLIR provides an informative mapping — not an emit pipeline.**
   The NIST Online Informative References (OLIR) program at
   https://csrc.nist.gov/projects/olir publishes a one-way informative
   crosswalk from ISO/IEC 27001 → NIST 800-53. The OLIR mapping is
   useful for analysts; it is NOT a Statement of Applicability emitter,
   it does NOT produce per-control evidence, it does NOT produce the
   ISO clause 6.1.3(d) justifications, and it does NOT cover 27017 /
   27018 / 27701. LOOP-Z closes those gaps by emitting a full SoA + the
   per-control evidence + the per-cloud overlay + the PII / PIMS
   extensions + the EUCS submission package.

3. **The ENISA EUCS Candidate Scheme will likely become mandatory for
   EU public-sector cloud customers.** The EU Cybersecurity Act
   (Regulation 2019/881) established the EU Cybersecurity Certification
   Framework. ENISA published the EUCS Candidate Scheme in 2024; the
   European Commission is expected to adopt it as a delegated act in
   2026-2027. Once adopted, EU public-sector cloud customers will be
   able to demand EUCS Basic / Substantial / High assurance certification
   from their cloud-service suppliers. A CSP that ships to EU customers
   without an EUCS package will be procurement-gated.

4. **ISO/IEC 27001:2022 transitioned the control set from 114 controls
   (2013 edition) to 93 controls organized into 4 themes**
   (Organizational, People, Physical, Technological). The transition
   deadline for legacy 27001:2013 certificates was 2025-10-31, after
   which only 27001:2022 certificates are accepted. LOOP-Z targets
   27001:2022; the legacy 2013 mapping is informative only.

5. **Per-cloud overlay (27017) and PII processor (27018) controls are
   NOT subsumed by FedRAMP.** ISO/IEC 27017:2015 adds cloud-specific
   implementation guidance (CLD.6.3.1 through CLD.12.4.5) — controls
   like "Shared roles and responsibilities within a cloud computing
   environment" or "Removal of cloud service customer assets" that
   FedRAMP simply does not address as discrete controls. ISO/IEC
   27018:2019 adds PII-processor controls that, while overlapping with
   FedRAMP Privacy Overlay, are framed for the GDPR Article 28 processor
   role rather than the U.S. Privacy Act §552a role.

6. **ISO/IEC 27701:2019 establishes a PIMS (Privacy Information
   Management System).** PIMS is the ISMS-with-privacy structural
   pattern, splitting controls into "PII Controller" obligations and
   "PII Processor" obligations. CSPs are almost always PII Processors
   (per Article 28 GDPR); their large-enterprise customers are PII
   Controllers. The 27701 PIMS extension is the *international*
   answer to GDPR Article 28 + Article 32 requirements.

### 1.2 What LOOP-Z delivers

| # | Artifact | Slice | Consumer |
|---|---|---|---|
| 1 | `core/iso-27001-2022-catalog.ts` — typed loader for all 93 Annex A controls organised by theme (Organizational, People, Physical, Technological) | Z.Z1 | Z.Z2, Z.Z3, Z.Z4, Z.Z5; third-party analysts |
| 2 | `data/iso-27001-2022-annex-a.json` — canonical JSON of the 93 Annex A controls + per-control crosswalk to NIST 800-53 Rev 5 + FedRAMP Moderate + 27001:2013 legacy mapping | Z.Z1 | All downstream slices + external consumers |
| 3 | `scripts/extract-iso-27001-2022.mjs` — extractor for the Annex A control set + ISMS clauses 4–10 | Z.Z1 | Operator + CI cron when ISO publishes a new edition |
| 4 | `core/iso-27001-soa-emitter.ts` — emits the canonical Statement of Applicability (clause 6.1.3(d)) — list of all 93 controls with "applicable / not applicable" + justification + implementation status | Z.Z2 | Z.Z2's `.docx` renderer; certification body; internal-audit |
| 5 | `core/iso-27001-soa-docx.ts` — OOXML (`.docx`) renderer for the SoA — reproduces the canonical SoA layout (control ID, control name, applicable, justification, implementation status, evidence reference) | Z.Z2 | Certification body, AO, internal-audit |
| 6 | `out/iso-27001-soa-{cspname}-{date}.docx` + `.json` + `.sig` — signed SoA artefact | Z.Z2 | Operator submits to certification body; bundled in submission package |
| 7 | `core/iso-27017-mapper.ts` — per-cloud (AWS / GCP / Azure) implementation guidance + evidence collection for each cloud-specific control CLD.6.3.1 through CLD.12.4.5 | Z.Z3 | Z.Z2 SoA emitter + certification body + internal-audit |
| 8 | `data/iso-27017-controls.json` — canonical JSON of the 7 cloud-specific extension controls + 37 augmented 27002 controls (per the 27017 mapping table) | Z.Z3 | Z.Z3 mapper + Z.Z2 SoA emitter |
| 9 | `core/iso-27018-mapper.ts` — PII-processor-specific extension controls + integration with LOOP-U privacy framework crosswalk | Z.Z4 | Z.Z2 SoA emitter + Z.Z5 PIMS emitter + LOOP-U |
| 10 | `data/iso-27018-controls.json` — canonical JSON of the 27018:2019 PII-processor controls (the 14 PII-specific extensions + the 27002-based augmentations) | Z.Z4 | Z.Z4 mapper + Z.Z2 SoA emitter |
| 11 | `core/iso-27701-pims.ts` — PIMS extension to the ISMS — splits PII Controller vs PII Processor controls; references the 27001 ISMS clauses + the 27002 control set | Z.Z5 | Certification body; internal-audit |
| 12 | `core/enisa-eucs-mapper.ts` — mapper from ISO 27001/27017/27018/27701 + FedRAMP Moderate to EUCS Basic / Substantial / High assurance levels | Z.Z5 | Z.Z5 EUCS submission package + EU conformity-assessment body |
| 13 | `core/eucs-submission-package.ts` — packages the EUCS conformity-assessment submission: SoA + Annex A controls evidence + assurance-level declaration + scope statement + conformity-assessment body identification | Z.Z5 | EU conformity-assessment body |
| 14 | `out/eucs-submission-package-{cspname}-{level}-{date}.zip` — Ed25519-signed package | Z.Z5 | Operator submits to EU conformity-assessment body |
| 15 | Tracker DB tables `iso_27001_soa`, `iso_27001_soa_controls`, `iso_27017_coverage`, `iso_27018_pii_controls`, `iso_27701_pims_scope`, `eucs_submissions` | Z.Z2 + Z.Z3 + Z.Z4 + Z.Z5 | Tracker UI + audit |
| 16 | Tracker UI: SoA review + sign-off page; per-cloud overlay coverage page; PIMS scope-management page; EUCS submission review page | Z.Z2 + Z.Z3 + Z.Z4 + Z.Z5 | Operator |
| 17 | POA&M finding template "ISO Control Gap" emitted via existing `core/oscal-poam.ts` | Z.Z2 + Z.Z3 + Z.Z4 + Z.Z5 | OSCAL chain |

### 1.3 What LOOP-Z does NOT do (scope guard)

- **LOOP-Z does not auto-submit to a certification body or EU
  conformity-assessment body.** REO Rule 4 forbids the system from
  acting on behalf of the operator on a regulatory submission. The
  tracker captures the operator's submission action (timestamp +
  officer ID + submission receipt id pasted from the body's
  acknowledgement) as an audit trail.
- **LOOP-Z does not perform the certification audit itself.** An ISO
  certification audit (Stage 1 documentation review + Stage 2 audit) is
  performed by an accredited certification body (per ISO/IEC 17021-1
  + 27006). LOOP-Z emits the artefacts the certification body consumes;
  it does NOT perform the audit. Likewise, EUCS conformity assessment
  is performed by an accredited Conformity Assessment Body (CAB)
  identified by ENISA / EU member-state National Cybersecurity
  Certification Authority (NCCA). LOOP-Z emits the package; the CAB
  performs the assessment.
- **LOOP-Z does not address Common Criteria (ISO/IEC 15408) certification.**
  Common Criteria is a product-evaluation framework (different scope:
  evaluates a single security product / TOE, not the organisation's
  ISMS). Out of LOOP-Z scope.
- **LOOP-Z does not address ISO/IEC 22301 (Business Continuity Management
  Systems).** ISO 22301 is a sibling ISO management-system standard,
  often paired with 27001. A future "LOOP-BCMS" could add 22301; LOOP-Z
  stays focused on the information-security + privacy + cloud +
  EU-certification cluster.
- **LOOP-Z does not address ISO/IEC 27005 (information security risk
  management).** 27005 is referenced by LOOP-B (Risk Engine); LOOP-Z
  relies on LOOP-B's risk register to populate clause 6.1.3(d)
  justifications.
- **LOOP-Z does not address national-government-equivalency schemes
  beyond ENISA EUCS.** Japan's ISMAP, Australia's IRAP, Singapore's
  MTCS, India's CERT-In, the GCC Common Assurance Framework, and the
  UAE Cybersecurity Council's CSCF are equivalent international
  government schemes that the CSP may need to pursue. LOOP-Z's catalog
  + SoA emitter are reusable foundations for those schemes (most are
  ISO-derived), but no per-scheme emitter ships in LOOP-Z. A future
  "LOOP-ISMAP" / "LOOP-IRAP" extension can be added.
- **LOOP-Z does not handle PCI DSS, SOC 2, HITRUST, or SOC 3.** Those
  are private-sector / industry-specific schemes handled either by
  separate loops (LOOP-V for HIPAA / HITRUST, LOOP-U for COPPA / FERPA
  / GLBA / privacy) or by separate future loops (PCI DSS).

### 1.4 How LOOP-Z is distinct from neighbour loops

| Neighbour | Distinction |
|---|---|
| **LOOP-B (Risk Engine)** | LOOP-B owns the organisation-wide risk register + risk-scoring. Z.Z2 SoA emitter *consumes* the risk register to populate clause 6.1.3(d) justifications ("why is this Annex A control applicable / not applicable?"). LOOP-Z does NOT duplicate LOOP-B's risk-register; it reads from it. |
| **LOOP-U (Privacy Frameworks Crosswalk)** | LOOP-U owns the GDPR / CCPA / FERPA / COPPA / GLBA crosswalk to NIST 800-53 + FedRAMP. Z.Z4 (ISO 27018) and Z.Z5 (ISO 27701 PIMS) overlap with LOOP-U on GDPR Article 28 (processor) obligations. LOOP-U's crosswalk is the *NIST-side* mapping; LOOP-Z's mapping is the *ISO-side* mapping. The two are reciprocal and cross-referenced. |
| **LOOP-V (Healthcare Overlay — HIPAA + HITRUST)** | LOOP-V owns HIPAA Security Rule + HITRUST CSF. ISO 27018 overlaps with HIPAA when a CSP processes PHI: 27018 frames the PII protection in the GDPR Article 28 processor role; HIPAA frames the same protection in the BAA covered-entity role. Z.Z4 emits the 27018 PII Processor view; LOOP-V emits the HIPAA Business Associate view. Both are required when serving an international healthcare customer. |
| **LOOP-INV-S (Inventory + Coverage Contract)** | LOOP-INV-S owns the cloud-inventory fact-base. Z.Z3 (ISO 27017 per-cloud overlay) reads inventory tags to compute per-cloud control coverage. LOOP-Z does NOT discover cloud assets; LOOP-INV-S does. |
| **LOOP-T (NIST SSDF / CISA Common Form)** | LOOP-T emits the corporate SSDF attestation. ISO 27001 Annex A 8.25 ("Secure development lifecycle") overlaps with the SSDF; Z.Z2 SoA references LOOP-T's SSDF Common Form as evidence for A.8.25. |
| **LOOP-W (Prohibited-Vendor Screening)** | LOOP-W's catalog of prohibited entities affects ISO 27001 Annex A 5.19 ("Information security in supplier relationships") + A.5.20 ("Addressing information security within supplier agreements") + A.5.23 ("Information security for use of cloud services"). Z.Z2 SoA cites LOOP-W as evidence for those controls. |
| **LOOP-R (Post-Quantum Cryptography)** | LOOP-R's PQC migration affects ISO 27001 Annex A 8.24 ("Use of cryptography"). Z.Z2 SoA cites LOOP-R as evidence for A.8.24. |
| **LOOP-Q (Marketplace + Post-ATO Publication)** | Q.Q1 publishes the FedRAMP Marketplace listing. When Z.Z2 has emitted a current SoA and Z.Z5 has emitted a current EUCS submission, Q.Q1 surfaces "ISO 27001 certified" + "EUCS Substantial certified" badges with the URLs of the signed envelopes. |

### 1.5 Authoritative scope guard (REO-locked)

LOOP-Z's catalogs are derived from:

1. The published ISO/IEC 27001:2022 standard — Annex A control list,
   ISMS clauses 4–10, the normative requirements.
2. The published ISO/IEC 27002:2022 standard — the 93 controls with
   implementation guidance.
3. The published ISO/IEC 27017:2015 standard — cloud-specific control
   extensions.
4. The published ISO/IEC 27018:2019 standard — PII-processor controls.
5. The published ISO/IEC 27701:2019 standard — PIMS clauses and PII
   Controller / PII Processor split.
6. The published ENISA EUCS Candidate Scheme (March 2024 draft, or the
   adopted version when the EU Commission ratifies).
7. NIST OLIR informative crosswalk (ISO 27001 ↔ NIST 800-53).

Because ISO/IEC standards are copyrighted by ISO (CHF 138 to CHF 198
per standard), the **full text** of the standards is NOT redistributable
in LOOP-Z. The catalog JSON files include:

- Control IDs (e.g. A.5.1, A.8.24, CLD.6.3.1) — these are not
  copyrightable (control identifiers are facts).
- Short control names (e.g. "Policies for information security",
  "Use of cryptography") — these are short factual labels.
- Per-control crosswalk references to NIST 800-53 + FedRAMP — derived
  factual mapping.
- Implementation status field (applicable / not applicable / partial).
- Justification text — operator-supplied, paraphrased per LOOP-Z's
  authoring guidance.
- A reference URL to ISO's standard page (e.g.
  https://www.iso.org/standard/27001) so the user can purchase or
  consult their organization's licensed copy.

LOOP-Z **does not** redistribute verbatim ISO text. The operator must
maintain their own licensed copy of the relevant ISO standards. LOOP-Z
emits the *artefacts* (SoA, EUCS package) that reference ISO controls
by ID; the substantive ISO control text remains in the licensed
standard the operator paid for.

This is the same approach used by every ISO-adjacent compliance tool
(GoComply, brian-ruf/oscal-content-generation, etc.) and preserves
Apache-2.0 redistribution.

---

## 2. Statutory & regulatory drivers (verbatim quotes; pinned URLs)

Every URL accessed 2026-06-07. Where the ISO source is paywalled (most
ISO standards are), the implementer references the ISO standard's
canonical URL + the publicly-available preview pages + the publicly-
available NIST OLIR informative mapping for the structural cross-
reference. Where the ENISA source is freely available, the implementer
quotes verbatim.

### 2.1 ISO/IEC 27001:2022 — Information security management systems — Requirements

URL: https://www.iso.org/standard/27001 (accessed 2026-06-07).
Status: Published October 2022. Withdrew the 2013 edition; transition
period ended 2025-10-31 for all previously-issued 27001:2013
certifications.

Publicly-available structural facts (from ISO's preview pages and
publicly-available secondary sources):

> "This document specifies the requirements for establishing,
> implementing, maintaining and continually improving an information
> security management system within the context of the organization.
> This document also includes requirements for the assessment and
> treatment of information security risks tailored to the needs of the
> organization. The requirements set out in this document are generic
> and are intended to be applicable to all organizations, regardless of
> type, size or nature. Excluding any of the requirements specified in
> Clauses 4 to 10 is not acceptable when an organization claims
> conformity to this document."

The ISMS clauses (4 through 10) are normative and required:

| Clause | Title | Mandatory? |
|---|---|---|
| 4 | Context of the organization (understanding the organization + context + interested parties + scope of the ISMS) | yes |
| 5 | Leadership (top-management commitment + policy + roles, responsibilities, authorities) | yes |
| 6 | Planning (actions to address risks and opportunities + ISMS objectives) | yes |
| 6.1.3 | Information security risk treatment — REQUIRES a Statement of Applicability | yes |
| 7 | Support (resources + competence + awareness + communication + documented information) | yes |
| 8 | Operation (operational planning + risk assessment + risk treatment) | yes |
| 9 | Performance evaluation (monitoring + internal audit + management review) | yes |
| 10 | Improvement (nonconformity + corrective action + continual improvement) | yes |

Clause 6.1.3 specifically requires the SoA, quoted from publicly-
available preview text:

> "The organization shall: (a) define and apply an information security
> risk treatment process to: (1) select appropriate information
> security risk treatment options, taking account of the risk
> assessment results; (2) determine all controls that are necessary to
> implement the information security risk treatment option(s) chosen;
> (3) compare the controls determined in 6.1.3 b) above with those in
> Annex A and verify that no necessary controls have been omitted;
> (4) produce a Statement of Applicability that contains: the necessary
> controls and justification for inclusions; whether the necessary
> controls are implemented or not; and the justification for exclusions
> of any of the Annex A controls;
> (5) formulate an information security risk treatment plan; and
> (6) obtain risk owners' approval of the information security risk
> treatment plan and acceptance of the residual information security
> risks. The organization shall retain documented information about the
> information security risk treatment process."

Annex A is the reference set of 93 controls organized into 4 themes
(per ISO/IEC 27001:2022 Annex A):

| Theme | Controls | Count |
|---|---|---|
| A.5 — Organizational | A.5.1 through A.5.37 | 37 |
| A.6 — People | A.6.1 through A.6.8 | 8 |
| A.7 — Physical | A.7.1 through A.7.14 | 14 |
| A.8 — Technological | A.8.1 through A.8.34 | 34 |
| **Total** | | **93** |

LOOP-Z's Z.Z1 catalogs all 93 controls by their canonical control ID +
canonical short name. The implementer pulls the ID + name list from
the publicly-available ISO 27001 Annex A preview page; the operator's
licensed copy is consulted for full implementation guidance.

### 2.2 ISO/IEC 27002:2022 — Information security controls (code of practice)

URL: https://www.iso.org/standard/27002 (accessed 2026-06-07).
Status: Published February 2022. Provides implementation guidance for
the 93 controls referenced by 27001:2022 Annex A. 27001 references the
controls *as a list*; 27002 elaborates the *implementation*.

Publicly-available structural fact:

> "This document provides a reference set of generic information
> security controls including implementation guidance. This document is
> designed to be used by organizations: (a) within the context of an
> information security management system (ISMS) based on ISO/IEC
> 27001; (b) for implementing information security controls based on
> internationally recognized best practices; (c) for developing
> organization-specific information security management guidelines."

Each control has five attribute dimensions (a structural change from
27002:2013):

| Attribute | Values |
|---|---|
| Control type | Preventive / Detective / Corrective |
| Information security properties | Confidentiality / Integrity / Availability |
| Cybersecurity concepts | Identify / Protect / Detect / Respond / Recover (NIST CSF alignment) |
| Operational capabilities | Governance, Asset management, Information protection, Human resource security, Physical security, System and network security, Application security, Secure configuration, Identity and access management, Threat and vulnerability management, Continuity, Supplier relationships security, Legal and compliance, Information security event management, Information security assurance |
| Security domains | Governance and ecosystem, Protection, Defence, Resilience |

Z.Z1's catalog includes all five attribute dimensions per control. The
attribute table is the bridge between 27001/27002 and NIST CSF +
NIST 800-53.

### 2.3 ISO/IEC 27017:2015 — Code of practice for information security controls based on ISO/IEC 27002 for cloud services

URL: https://www.iso.org/standard/27017 (accessed 2026-06-07).
Status: Published December 2015 (no 2022 reissue yet; reissue pending).
27017 supplements 27002 with cloud-specific guidance + adds 7 cloud-
specific controls in a new namespace `CLD.*`.

The 7 cloud-specific controls (publicly-summarised from ISO's preview
page + secondary academic sources):

| Control ID | Title (canonical short name) |
|---|---|
| CLD.6.3.1 | Shared roles and responsibilities within a cloud computing environment |
| CLD.8.1.5 | Removal of cloud service customer assets |
| CLD.9.5.1 | Segregation in virtual computing environments |
| CLD.9.5.2 | Virtual machine hardening |
| CLD.12.1.5 | Administrator's operational security |
| CLD.12.4.5 | Monitoring of cloud services |
| CLD.13.1.4 | Alignment of security management for virtual and physical networks |

Additionally, 27017 augments approximately 37 of the 27002 controls
with cloud-specific implementation guidance. The augmentation table
maps each 27002 control to either: (a) "applies without modification",
(b) "applies with cloud-specific guidance" (the 37 augmented controls),
or (c) "responsibility split between cloud service provider (CSP) and
cloud service customer (CSC)".

The shared-responsibility split is the key consumable. For each
augmented control, 27017 specifies which obligations land on the CSP
and which land on the CSC. LOOP-Z's Z.Z3 emits the per-cloud
implementation per CSP-side control (AWS / GCP / Azure) and explicitly
notes the CSC-side obligations the customer must perform.

> ISO 27017 publicly-available preview text (paraphrased from ISO's
> standard summary page): "This Recommendation | International Standard
> provides guidelines for information security controls applicable to
> the provision and use of cloud services by providing: additional
> implementation guidance for relevant controls specified in ISO/IEC
> 27002; additional controls with implementation guidance that
> specifically relate to cloud services."

### 2.4 ISO/IEC 27018:2019 — Code of practice for protection of personally identifiable information (PII) in public clouds acting as PII processors

URL: https://www.iso.org/standard/76559 (accessed 2026-06-07).
Status: Published January 2019 (second edition; first published 2014).
27018 supplements 27002 with PII-protection guidance specifically for
public-cloud CSPs acting as PII processors (GDPR Article 28 role).

The 11 publicly-acknowledged PII-specific controls (per ISO's preview
summary + secondary academic sources):

| PII control area | Short summary |
|---|---|
| Consent and choice | CSP must facilitate PII Controller's ability to support data subject consent and choice |
| Purpose legitimacy and specification | PII must be processed only for the purposes specified by the PII Controller |
| Collection limitation | PII collection limited to what is necessary |
| Data minimization | PII processed limited to what is necessary |
| Use, retention, and disclosure limitation | Retention + disclosure aligned with PII Controller's documented instructions |
| Accuracy and quality | Mechanisms for the PII Controller to correct PII |
| Openness, transparency, and notice | Disclosure of sub-processors used; disclosure of countries where PII is processed |
| Individual participation and access | Mechanisms supporting data subject access requests |
| Accountability | Audit programme; incident notification; PII breach notification |
| Information security | Technical + organisational measures |
| PII processor's privacy compliance | Compliance with applicable PII protection legislation |

Plus the augmentation of the 27002 controls with PII-processor-specific
guidance. The 27018 specification overlaps significantly with GDPR
Articles 25, 28, 32, 33, 34, and 35.

ISO 27018 publicly-available preview text (paraphrased):

> "This document establishes commonly accepted control objectives,
> controls and guidelines for implementing measures to protect
> Personally Identifiable Information (PII) in line with the privacy
> principles in ISO/IEC 29100 for the public cloud computing
> environment. In particular, this document specifies guidelines based
> on ISO/IEC 27002, taking into consideration the regulatory
> requirements for the protection of PII which might be applicable
> within the context of the information security risk environment(s)
> of a provider of public cloud services."

### 2.5 ISO/IEC 27701:2019 — Privacy Information Management System (PIMS)

URL: https://www.iso.org/standard/71670 (accessed 2026-06-07).
Status: Published August 2019. Extends ISO/IEC 27001 + ISO/IEC 27002
with a Privacy Information Management System.

The PIMS structure follows the ISMS structure (clauses 4–10) with
privacy-specific augmentations. Additionally, 27701 introduces a
critical structural split: every PIMS control is annotated as
applicable to **PII Controllers**, **PII Processors**, or both.

> "This document specifies requirements and provides guidance for
> establishing, implementing, maintaining and continually improving a
> Privacy Information Management System (PIMS) in the form of an
> extension to ISO/IEC 27001 and ISO/IEC 27002 for privacy management
> within the context of the organization."

27701's normative annexes (Annex A and Annex B) are the operational
heart of PIMS:

- **Annex A** — additional PIMS-specific controls for PII Controllers.
- **Annex B** — additional PIMS-specific controls for PII Processors.

Most CSPs are PII Processors (Annex B applies). Their large-enterprise
customers are PII Controllers (Annex A applies). When the CSP processes
its own employee PII (HR records, etc.), the CSP is also a PII
Controller for that subset — so both annexes typically apply in some
slice of the operation.

> ISO 27701 publicly-available preview text (paraphrased): "It is the
> intent of this document to enable an organization to provide
> evidence of its compliance with various privacy legislations, in
> particular the General Data Protection Regulation (GDPR), but is not
> limited to GDPR. Specifically, it provides requirements and guidance
> for both organizations holding the role of PII controllers (Annex A)
> and those acting as PII processors (Annex B)."

GDPR cross-reference: 27701 Annex F provides a mapping from 27701
controls to GDPR Articles. The mapping covers Articles 5, 6, 7, 8, 12,
13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 24, 25, 26, 27, 28, 29, 30, 31,
32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
50.

### 2.6 ENISA EUCS Candidate Scheme (Cloud Services)

URL: https://www.enisa.europa.eu/topics/certification/cybersecurity-certification-framework/eucs
(accessed 2026-06-07).
Status: Candidate scheme published by ENISA in 2020; draft updated
through 2024; awaiting European Commission adoption as a delegated
act under EU Cybersecurity Act (Regulation 2019/881).

The EUCS scheme establishes three assurance levels:

| Level | Risk coverage | Audit type |
|---|---|---|
| Basic | Low risk to processed data | Self-assessment + light review by CAB |
| Substantial | Moderate risk | Independent CAB review with formal audit |
| High | High risk (national-security-adjacent) | Independent CAB review with stringent technical audit + penetration testing |

> ENISA publicly-available text (from the ENISA EUCS factsheet):
> "The European Union Cybersecurity Certification Scheme on Cloud
> Services (EUCS) is a candidate cybersecurity certification scheme
> that aims to harmonize the security of cloud services in the EU. It
> covers Infrastructure as a Service (IaaS), Platform as a Service
> (PaaS), and Software as a Service (SaaS) cloud services. The scheme
> defines three assurance levels — Basic, Substantial, and High — and
> a set of security objectives and requirements that cloud service
> providers must meet to obtain certification at each level."

Regulatory anchor — EU Cybersecurity Act (Regulation (EU) 2019/881):

> Regulation (EU) 2019/881 Article 56 (publicly-available from EUR-Lex
> https://eur-lex.europa.eu/eli/reg/2019/881/oj):
> "European cybersecurity certification schemes shall be drawn up in a
> manner that promotes high standards of cybersecurity, taking into
> account, where appropriate, international standards, including ISO
> standards. European cybersecurity certification schemes may
> specifically provide for one or more of the following levels of
> assurance for ICT products, ICT services and ICT processes: 'basic',
> 'substantial' and 'high'."

The EUCS assurance levels map approximately to ISO 27001 +
ISO 27017 + 27018 + 27701 evidence sets:

| EUCS Level | Required evidence |
|---|---|
| Basic | ISO 27001 Annex A (subset) + self-attestation |
| Substantial | ISO 27001 Annex A (full) + ISO 27017 (cloud overlay) + independent CAB audit |
| High | ISO 27001 + 27017 + 27018 + 27701 + independent CAB audit + penetration testing |

LOOP-Z's Z.Z5 emits the EUCS submission package keyed to the assurance
level requested. The operator chooses the level via the
`--eucs-level=basic|substantial|high` flag; default is "substantial"
(the most common requested level for commercial cloud customers).

### 2.7 NIST OLIR — ISO 27001 → NIST 800-53 mapping

URL: https://csrc.nist.gov/projects/olir (accessed 2026-06-07).
Status: ongoing NIST programme. Multiple OLIR-published mappings cover
ISO 27001 ↔ NIST 800-53 / CSF / Privacy Framework.

> NIST publicly-available text (from the OLIR program page):
> "The National Online Informative References Program is a NIST
> effort to facilitate subject matter experts (SMEs) in defining
> standardized online informative references (OLIRs) between elements
> of their cybersecurity, privacy, and workforce documents and elements
> of other cybersecurity, privacy, and workforce documents. OLIRs are
> simple, structured, and machine-readable, allowing them to be easily
> shared and consumed."

The OLIR ISO 27001:2022 ↔ NIST 800-53 Rev 5 mapping is the canonical
*informative* reference LOOP-Z's Z.Z1 catalog crosswalks against. The
implementer fetches the OLIR-published Excel / JSON crosswalk and
encodes it as the `nist_800_53_rev5` field per Annex A control row.

The OLIR mapping is one-way (ISO → NIST). Each Annex A control maps to
zero, one, or many NIST 800-53 controls; the relationship is one of:
- `subset` — ISO control is fully covered by the NIST control(s).
- `equivalent` — ISO control == NIST control (rare).
- `intersect` — partial overlap.
- `superset` — ISO control covers more than the NIST control(s).
- `no_relationship` — no semantic overlap (rare; mostly for the
  organisational ISMS clauses).

Z.Z1's catalog stores the relationship type per pairing.

### 2.8 ISO/IEC 17021-1:2015 — Conformity assessment for management system certification (audit methodology)

URL: https://www.iso.org/standard/61651 (accessed 2026-06-07).
Status: Published June 2015 (latest edition).

17021-1 governs **how** certification bodies audit and certify
management systems. It's not consumed by LOOP-Z directly but is the
audit-methodology cross-reference for the certification body's Stage 1
+ Stage 2 audit cycle. LOOP-Z's SoA emitter outputs in the form that
the Stage 1 documentation review consumes; the Stage 2 audit is
performed in the CSP's environment by the CAB.

Key audit-cycle facts (from publicly-available CAB documentation):

| Phase | Activity | Duration |
|---|---|---|
| Pre-application | CAB scope determination | weeks |
| Stage 1 audit | Documentation review (SoA + ISMS docs) | 1–3 days |
| Stage 2 audit | Onsite / virtual evidence audit | 1–10 days depending on CSP scope |
| Certification decision | Independent review by CAB's certification committee | 1–4 weeks |
| Surveillance | Annual review for 3 years | 1–2 days/year |
| Recertification | Full re-audit at year 3 | 1–10 days |

LOOP-Z's tracker DB carries the certification lifecycle state so the
operator can track Stage 1 / Stage 2 / surveillance / recertification.

### 2.9 ISO/IEC 27006:2015 (+ Amd 2020) — Requirements for bodies providing audit and certification of ISMS

URL: https://www.iso.org/standard/62313 (accessed 2026-06-07).
Status: Published September 2015 (latest amendment 2020).

27006 is the **CAB-side accreditation** standard — CABs themselves are
audited against 27006 by national accreditation bodies (UKAS, ANAB,
DAkkS, etc.) to maintain their ISO/IEC 17021-1-derived accreditation.
LOOP-Z does not consume 27006 directly but references it so the
operator can verify their CAB's accreditation chain.

> Publicly-available 27006 abstract: "This document supplements
> ISO/IEC 17021-1. It primarily augments the requirements of ISO/IEC
> 17021-1 to include the certification of an information security
> management system (ISMS). It specifies requirements and provides
> guidance for bodies providing audit and certification of an
> information security management system (ISMS), in addition to the
> requirements contained within ISO/IEC 17021-1 and ISO/IEC 27001."

### 2.10 ISMAP (Japan) — Information system Security Management and Assessment Program

URL: https://www.ismap.go.jp/en/ (accessed 2026-06-07).
Status: Operational since June 2020. Mandatory for Japanese government
cloud procurement.

ISMAP is the Japanese-government equivalent of FedRAMP. ISMAP's
control set is heavily ISO 27001 + 27017 + Japanese government
additions. CSPs serving Japanese government must obtain ISMAP
registration; LOOP-Z's catalogs (especially Z.Z3's 27017 mapping) are
the foundation for ISMAP submission.

> Publicly-available ISMAP English summary: "ISMAP is the registration
> system that pre-evaluates and registers cloud services that have met
> the security requirements required by the Government of Japan for
> use in government information systems. ISMAP aims to ensure the
> security of government information systems and to facilitate the
> smooth introduction of cloud services."

LOOP-Z does NOT emit an ISMAP package directly (out of scope; future
LOOP-ISMAP extension); however, the Z.Z1 + Z.Z3 catalogs are the
reusable foundation for ISMAP.

### 2.11 IRAP (Australia) — Information Security Registered Assessors Program

URL: https://www.cyber.gov.au/about-us/about-asd-and-acsc/about-irap
(accessed 2026-06-07).
Status: Operational. Mandatory for Australian government cloud
procurement at OFFICIAL: Sensitive, PROTECTED, SECRET, and TOP
SECRET classifications.

IRAP is the Australian-government cloud-procurement scheme based on
the Australian Cyber Security Centre (ACSC) Information Security
Manual (ISM). The ISM is largely ISO 27001-aligned with Australian
government additions. CSPs serving Australian government obtain IRAP
assessment; LOOP-Z's catalogs are the foundation for IRAP submission.

> Publicly-available IRAP description: "The Information Security
> Registered Assessors Program (IRAP) is a way to assist Australian
> Government entities to determine whether the appropriate controls
> are in place and meet the relevant assurance requirements."

LOOP-Z does NOT emit an IRAP package directly (out of scope; future
LOOP-IRAP extension); the Z.Z1 + Z.Z3 catalogs are the reusable
foundation.

### 2.12 GDPR — General Data Protection Regulation (EU 2016/679)

URL: https://eur-lex.europa.eu/eli/reg/2016/679/oj (accessed 2026-06-07).
Status: In force since 25 May 2018.

GDPR is the EU's privacy regulation. ISO 27018 + 27701 are the
ISO-side compliance pathway for GDPR Articles 28 + 32 + 33 + 34.
LOOP-Z's Z.Z4 + Z.Z5 reference GDPR Articles by number.

> GDPR Article 28(1) (verbatim from EUR-Lex):
> "Where processing is to be carried out on behalf of a controller,
> the controller shall use only processors providing sufficient
> guarantees to implement appropriate technical and organisational
> measures in such a manner that processing will meet the requirements
> of this Regulation and ensure the protection of the rights of the
> data subject."

> GDPR Article 32(1) (verbatim from EUR-Lex):
> "Taking into account the state of the art, the costs of
> implementation and the nature, scope, context and purposes of
> processing as well as the risk of varying likelihood and severity
> for the rights and freedoms of natural persons, the controller and
> the processor shall implement appropriate technical and
> organisational measures to ensure a level of security appropriate to
> the risk."

GDPR Article 32(1) is the source-text for ISO 27018 Annex A
augmentation; many 27018-PII-specific controls trace to Article 32.

### 2.13 EU Cybersecurity Act — Regulation (EU) 2019/881

URL: https://eur-lex.europa.eu/eli/reg/2019/881/oj (accessed 2026-06-07).
Status: In force since 27 June 2019.

The EU Cybersecurity Act establishes the EU Cybersecurity Certification
Framework. EUCS is one of three schemes ENISA is developing under this
framework (the others: EUCC for ICT products, EU5G for 5G).

> Article 49(1) (verbatim from EUR-Lex):
> "ENISA shall prepare a candidate European cybersecurity certification
> scheme, hereinafter the 'candidate scheme', following a request by
> the Commission or, after consulting the ECCG, on its own initiative."

> Article 56(1) (verbatim from EUR-Lex):
> "The certification of ICT products, ICT services and ICT processes
> shall be voluntary, unless otherwise specified by Union law or
> Member State law."

The "voluntary unless otherwise specified" clause is the basis on which
ENISA-published draft EUCS prepares to become **mandatory** for EU
public-sector cloud procurement; the EU Commission's delegated act
will move EUCS from candidate to adopted.

---

## 3. Slice list

| id   | title                                                                     | status  | commit | depends_on (within LOOP-Z) | also depends_on (external)                                                                                                                                                                                                     | estimated_effort |
|------|---------------------------------------------------------------------------|---------|--------|----------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------|
| Z.Z1 | ISO/IEC 27001:2022 Annex A Crosswalk (catalog + NIST OLIR + FedRAMP)      | pending | TBD    | —                          | NIST OLIR; existing `core/control-benchmark.ts`; `data/frmr-ksi-catalog.json`                                                                                                                                                  | medium (~7d)     |
| Z.Z2 | ISO 27001 Statement of Applicability (SoA) Emitter + signed `.docx` + `.json` | pending | TBD    | Z.Z1                       | LOOP-A.A4 (bundler); LOOP-A.A5 (signing); LOOP-B.B1 (risk register); existing `core/oscal-ssp-docx.ts` OOXML helpers                                                                                                          | medium (~7d)     |
| Z.Z3 | ISO/IEC 27017:2015 Cloud Controls + per-cloud overlay                     | pending | TBD    | Z.Z1                       | LOOP-INV-S (inventory + coverage); existing AWS / GCP / Azure providers; existing `core/inventory.ts`; existing `core/inventory-coverage.ts`                                                                                  | medium (~6d)     |
| Z.Z4 | ISO/IEC 27018:2019 PII Processor Controls                                 | pending | TBD    | Z.Z1, Z.Z3                 | LOOP-U.U1 (privacy crosswalk); LOOP-V.V1 (HIPAA crosswalk); existing tracker DB; LOOP-M (privacy package)                                                                                                                      | medium (~5d)     |
| Z.Z5 | ISO/IEC 27701 PIMS + ENISA EUCS Candidate Scheme submission package        | pending | TBD    | Z.Z1, Z.Z2, Z.Z3, Z.Z4     | LOOP-A.A4 (bundler); LOOP-A.A5 (signing); LOOP-U (privacy); LOOP-Q.Q1 (Marketplace badge)                                                                                                                                       | large (~7d)      |

Per-slice docs (each ≥ 800 lines, per the per-slice gold standard):

- `cloud-evidence/docs/slices/Z/Z.Z1.md`
- `cloud-evidence/docs/slices/Z/Z.Z2.md`
- `cloud-evidence/docs/slices/Z/Z.Z3.md`
- `cloud-evidence/docs/slices/Z/Z.Z4.md`
- `cloud-evidence/docs/slices/Z/Z.Z5.md`

---

## 4. Authoritative sources (full list)

| # | Source | URL | Accessed | Form |
|---|---|---|---|---|
| 1 | ISO/IEC 27001:2022 | https://www.iso.org/standard/27001 | 2026-06-07 | Paid standard (preview + bibliographic metadata public) |
| 2 | ISO/IEC 27002:2022 | https://www.iso.org/standard/27002 | 2026-06-07 | Paid standard |
| 3 | ISO/IEC 27017:2015 | https://www.iso.org/standard/43757 | 2026-06-07 | Paid standard |
| 4 | ISO/IEC 27018:2019 | https://www.iso.org/standard/76559 | 2026-06-07 | Paid standard |
| 5 | ISO/IEC 27701:2019 | https://www.iso.org/standard/71670 | 2026-06-07 | Paid standard |
| 6 | ISO/IEC 17021-1:2015 | https://www.iso.org/standard/61651 | 2026-06-07 | Paid standard |
| 7 | ISO/IEC 27006:2015 | https://www.iso.org/standard/62313 | 2026-06-07 | Paid standard |
| 8 | ISO/IEC 27005:2018 (risk management; referenced) | https://www.iso.org/standard/75281 | 2026-06-07 | Paid standard |
| 9 | ISO/IEC 29100:2011 (privacy framework; referenced) | https://www.iso.org/standard/45123 | 2026-06-07 | Paid standard (also publicly available via ISO/IEC publicly-available standards programme) |
| 10 | ENISA EUCS Candidate Scheme (factsheet) | https://www.enisa.europa.eu/topics/certification/cybersecurity-certification-framework/eucs | 2026-06-07 | HTML page + PDF |
| 11 | EU Cybersecurity Act — Regulation (EU) 2019/881 | https://eur-lex.europa.eu/eli/reg/2019/881/oj | 2026-06-07 | HTML / PDF (EUR-Lex) |
| 12 | GDPR — Regulation (EU) 2016/679 | https://eur-lex.europa.eu/eli/reg/2016/679/oj | 2026-06-07 | HTML / PDF (EUR-Lex) |
| 13 | NIST OLIR ISO 27001 ↔ NIST 800-53 Rev 5 mapping | https://csrc.nist.gov/projects/olir | 2026-06-07 | HTML / Excel / JSON |
| 14 | NIST SP 800-53 Rev 5 (full catalog) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf | 2026-06-07 | PDF |
| 15 | NIST Cybersecurity Framework (CSF) v2.0 | https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf | 2026-06-07 | PDF |
| 16 | ISMAP — Information system Security Management and Assessment Program | https://www.ismap.go.jp/en/ | 2026-06-07 | HTML (Japanese gov) |
| 17 | IRAP — ASD/ACSC Australian assessor program | https://www.cyber.gov.au/about-us/about-asd-and-acsc/about-irap | 2026-06-07 | HTML (Australian gov) |
| 18 | ANAB — ANSI National Accreditation Board | https://anab.ansi.org/ | 2026-06-07 | HTML (US national accreditation body) |
| 19 | UKAS — United Kingdom Accreditation Service | https://www.ukas.com/ | 2026-06-07 | HTML (UK national accreditation body) |
| 20 | DAkkS — Deutsche Akkreditierungsstelle | https://www.dakks.de/en/ | 2026-06-07 | HTML (German national accreditation body) |
| 21 | ENISA — Cybersecurity Certification Framework page | https://www.enisa.europa.eu/topics/certification/cybersecurity-certification-framework | 2026-06-07 | HTML |
| 22 | European Commission — EU Cybersecurity Strategy | https://digital-strategy.ec.europa.eu/en/policies/cybersecurity-strategy | 2026-06-07 | HTML |
| 23 | Article 29 Working Party — GDPR guidance documents (now EDPB) | https://edpb.europa.eu/edpb_en | 2026-06-07 | HTML |
| 24 | UK ICO — Information Commissioner's Office (UK-GDPR successor authority) | https://ico.org.uk/ | 2026-06-07 | HTML |
| 25 | NIST Privacy Framework v1.0 | https://www.nist.gov/privacy-framework | 2026-06-07 | HTML / PDF |
| 26 | FedRAMP Marketplace | https://marketplace.fedramp.gov/ | 2026-06-07 | HTML |
| 27 | Cloud Security Alliance (CSA) STAR Registry | https://cloudsecurityalliance.org/star | 2026-06-07 | HTML (CSA STAR overlay; CSP self-attestation against CSA Cloud Controls Matrix; ISO-aligned) |
| 28 | Cloud Controls Matrix (CCM) v4 (CSA) | https://cloudsecurityalliance.org/research/cloud-controls-matrix | 2026-06-07 | HTML + Excel |

All sources are publicly available or describable via public preview
data. The full ISO standard PDFs are NOT redistributed by LOOP-Z;
operator obtains their own licensed copy. All EUR-Lex GDPR + EUCA
quotes are verbatim from the EU's official journal of record.

---

## 5. Reusable primitives (modules from other loops this loop depends on)

| Primitive | Owner loop | Use in LOOP-Z |
|---|---|---|
| `core/sign.ts` (Ed25519 + manifest builder) | LOOP-A.A5 / B.1 | All five Z slices flow outputs through `signEnvelope()` before write |
| `core/oscal-ssp-docx.ts` (OOXML emitter pattern) | existing SSP-2 | Z.Z2 reuses the OOXML pattern for the SoA `.docx`; Z.Z5 reuses for the EUCS package's submission cover document |
| `core/submission-bundle.ts` (`WELL_KNOWN` catalogue) | LOOP-A.A4 | Z.Z2 + Z.Z3 + Z.Z4 + Z.Z5 add roles; Z.Z2 SoA is bundled for the certification body |
| `core/envelope.ts` (provider blocks, signed envelope schema) | LOOP-A | All Z slices reuse the envelope shape |
| `core/risk-score.ts` + risk register | LOOP-B.B1 | Z.Z2 SoA reads risk register rows for clause 6.1.3(d) justifications |
| `core/control-benchmark.ts` (NIST 800-53 Rev 5) | existing | Z.Z1's crosswalk references this benchmark; each Annex A control row carries `nist_800_53_rev5` mapping |
| `data/frmr-ksi-catalog.json` | existing FRMR import | Z.Z1 includes a third column for FedRAMP Moderate KSI mapping |
| `core/inventory.ts` + `core/inventory-coverage.ts` | existing INV-P1 + INV-S1 | Z.Z3 reads inventory + coverage to compute per-cloud control coverage |
| `core/oscal-poam.ts` (POA&M emitter) | LOOP-A.A1 | Z.Z2 + Z.Z3 + Z.Z4 + Z.Z5 emit "ISO Control Gap" POA&M findings per gap |
| `core/csv-export.ts` + `core/html-report.ts` | existing | Z.Z2's SoA report + Z.Z3's per-cloud coverage report reuse the export utilities |
| LOOP-U privacy crosswalk fixtures | LOOP-U.U1 | Z.Z4 (27018) reads LOOP-U for GDPR / CCPA framework alignment |
| LOOP-V HIPAA crosswalk fixtures | LOOP-V.V1 | Z.Z4 (27018) cross-references LOOP-V for healthcare-PHI processor overlap |
| LOOP-T SSDF Common Form | LOOP-T.T3 | Z.Z2 SoA cites LOOP-T as evidence for A.8.25 (Secure development lifecycle) |
| LOOP-W prohibited-vendor catalog | LOOP-W.W1 | Z.Z2 SoA cites LOOP-W as evidence for A.5.19 + A.5.20 + A.5.23 |
| LOOP-R PQC inventory | LOOP-R | Z.Z2 SoA cites LOOP-R as evidence for A.8.24 (Use of cryptography) |
| Tracker DB pool + signed audit log | existing | Z.Z2 + Z.Z3 + Z.Z4 + Z.Z5 persist sign-off records in tracker DB |

---

## 6. Data flow diagram

```mermaid
flowchart TD
    subgraph Inputs[Inputs - standards catalogs + cross-loop evidence]
        ISO27001[ISO/IEC 27001:2022 Annex A 93 controls]
        ISO27002[ISO/IEC 27002:2022 implementation guidance]
        ISO27017[ISO/IEC 27017:2015 cloud overlay]
        ISO27018[ISO/IEC 27018:2019 PII Processor]
        ISO27701[ISO/IEC 27701:2019 PIMS]
        EUCS[ENISA EUCS Candidate Scheme]
        OLIR[NIST OLIR ISO 27001 to NIST 800-53 Rev 5]
        FRMR[(data/frmr-ksi-catalog.json)]
        BENCH[(core/control-benchmark.ts NIST 800-53)]
        RISKREG[(LOOP-B risk register)]
        INV[(LOOP-INV-S inventory + coverage)]
        LOOPU[(LOOP-U privacy crosswalk)]
        LOOPV[(LOOP-V HIPAA crosswalk)]
        LOOPT[(LOOP-T SSDF Common Form)]
        LOOPW[(LOOP-W prohibited-vendor catalog)]
        LOOPR[(LOOP-R PQC inventory)]
    end

    subgraph Z1[Slice Z.Z1 - ISO 27001 Annex A Crosswalk]
        EXT[scripts/extract-iso-27001-2022.mjs]
        NORM[normalize control rows + crosswalk join]
        SIGN1[sign catalog snapshot Ed25519]
        SNAP1[(data/iso-27001-2022-annex-a.json)]
        CAT1[core/iso-27001-2022-catalog.ts loader]
    end

    ISO27001 --> EXT
    ISO27002 --> EXT
    OLIR --> EXT
    FRMR --> EXT
    BENCH --> EXT
    EXT --> NORM --> SIGN1 --> SNAP1 --> CAT1

    subgraph Z2[Slice Z.Z2 - Statement of Applicability]
        SOA[core/iso-27001-soa-emitter.ts]
        SOADOCX[core/iso-27001-soa-docx.ts]
        SOAJSON[out/iso-27001-soa-*.json]
        SOADOCXOUT[out/iso-27001-soa-*.docx]
        SOASIG[out/iso-27001-soa-*.sig]
        POAM2[POA&M ISO Control Gap]
    end

    CAT1 --> SOA
    RISKREG --> SOA
    LOOPT --> SOA
    LOOPW --> SOA
    LOOPR --> SOA
    SOA --> SOADOCX
    SOA --> SOAJSON
    SOADOCX --> SOADOCXOUT
    SOA --> SOASIG
    SOA --> POAM2

    subgraph Z3[Slice Z.Z3 - ISO 27017 Cloud Overlay]
        ISO27017MAP[core/iso-27017-mapper.ts]
        ISO27017JSON[(data/iso-27017-controls.json)]
        Z3COV[out/iso-27017-coverage-aws.json + -gcp.json + -azure.json]
    end

    ISO27017 --> ISO27017MAP
    ISO27017JSON --> ISO27017MAP
    INV --> ISO27017MAP
    ISO27017MAP --> Z3COV
    Z3COV --> SOA

    subgraph Z4[Slice Z.Z4 - ISO 27018 PII Processor]
        ISO27018MAP[core/iso-27018-mapper.ts]
        ISO27018JSON[(data/iso-27018-controls.json)]
        Z4OUT[out/iso-27018-evidence.json]
    end

    ISO27018 --> ISO27018MAP
    ISO27018JSON --> ISO27018MAP
    LOOPU --> ISO27018MAP
    LOOPV --> ISO27018MAP
    ISO27018MAP --> Z4OUT
    Z4OUT --> SOA

    subgraph Z5[Slice Z.Z5 - ISO 27701 PIMS + EUCS submission]
        PIMS[core/iso-27701-pims.ts]
        EUCSMAP[core/enisa-eucs-mapper.ts]
        EUCSPKG[core/eucs-submission-package.ts]
        PIMSOUT[out/iso-27701-pims.json]
        EUCSOUT[out/eucs-submission-package-{level}.zip]
    end

    ISO27701 --> PIMS
    EUCS --> EUCSMAP
    SOA --> PIMS
    Z4OUT --> PIMS
    PIMS --> PIMSOUT
    PIMSOUT --> EUCSPKG
    SOAJSON --> EUCSPKG
    Z3COV --> EUCSPKG
    Z4OUT --> EUCSPKG
    EUCSMAP --> EUCSPKG
    EUCSPKG --> EUCSOUT

    subgraph Out[Outputs - submitted by operator]
        CAB[ISO Certification Body Stage 1 + Stage 2]
        EUCAB[EU Conformity Assessment Body for EUCS]
        MKT[Q.Q1 Marketplace badge ISO 27001 + EUCS Substantial]
    end

    SOADOCXOUT -.operator submits to.-> CAB
    SOAJSON -.bundled.-> CAB
    EUCSOUT -.operator submits to.-> EUCAB
    SOAJSON --> MKT
    EUCSOUT --> MKT
```

---

## 7. Test strategy

### 7.1 Per-slice tests

| Slice | Min tests | Surface |
|---|---|---|
| Z.Z1 | 16 | catalog extraction, 93-control round trip, NIST 800-53 crosswalk join, FedRAMP KSI crosswalk join, theme partitioning (4 themes), attribute dimensions (5 per control), legacy 27001:2013 mapping, signature, snapshot reload |
| Z.Z2 | 18 | SoA emitter populates all 93 rows, risk-register lookup populates justifications, "applicable / not applicable" decision logic, SoA `.docx` OOXML round trip, signed envelope, evidence-reference linking (LOOP-T / LOOP-W / LOOP-R), gap detection -> POA&M emit |
| Z.Z3 | 15 | per-cloud (AWS/GCP/Azure) control coverage computation, CLD.* control emission, shared-responsibility-split table, inventory-driven evidence, augmented 27002 control resolution, REQUIRES-OPERATOR-INPUT on missing cloud |
| Z.Z4 | 15 | PII-processor control coverage, GDPR Article 28/32/33/34 crosswalk, LOOP-U integration test, LOOP-V cross-reference test, signed envelope, sub-processor disclosure |
| Z.Z5 | 18 | PIMS PII Controller / PII Processor split, EUCS Basic / Substantial / High level packaging, EUCS submission ZIP integrity, ZIP signed envelope, GDPR Article references, Marketplace badge integration |

### 7.2 Cross-slice integration tests

| Test | Scenario | Expected outcome |
|---|---|---|
| INT-Z1 | End-to-end: Z.Z1 emits catalog → Z.Z2 emits SoA → all 93 controls present | SoA control_count == 93; SoA hash stable across reruns |
| INT-Z2 | End-to-end: Z.Z1 + Z.Z3 → Z.Z2 SoA references CLD.* controls when scope includes cloud services | SoA's `cloud_overlay` section non-empty; CLD.6.3.1 through CLD.13.1.4 present |
| INT-Z3 | End-to-end: Z.Z1 + Z.Z3 + Z.Z4 → Z.Z2 SoA + Z.Z5 PIMS → EUCS Substantial package | EUCS ZIP includes SoA + 27017 coverage + 27018 evidence + PIMS scope statement |
| INT-Z4 | EUCS level=High → required artifacts complete (27001 + 27017 + 27018 + 27701 + pentest reference) | Package validates; missing pentest reference emits REQUIRES-OPERATOR-INPUT |
| INT-Z5 | Risk register row marked "accepted" → SoA justifications cite risk_id + acceptance_date | SoA row's `justification` field includes the risk_id; tracker shows reciprocal link |
| INT-Z6 | Q.Q1 Marketplace integration: Z.Z2 SoA signed + Z.Z5 EUCS submitted → Marketplace surfaces both badges | Q.Q1 reads tracker DB, emits both badges with envelope URLs |

### 7.3 Adversarial cases (these MUST appear in the test suite)

| Adversarial scenario | Why it matters | Slice expected behaviour |
|---|---|---|
| **A1 — All-93-controls "applicable" exclusion attempt.** Operator tries to mark every Annex A control as "not applicable" to skip the audit. | ISO 27001 clause 6.1.3(d) requires *justification* for exclusion; blanket exclusion is non-conformant. | Z.Z2 emitter validates that exclusion has non-empty justification + cites a risk-register row + operator-officer attestation; blanket exclusion without justification rejected with diagnostic. |
| **A2 — Control mapped to NIST 800-53 with no corresponding FedRAMP KSI.** | The crosswalk must support partial coverage. | Z.Z1's row carries `fedramp_ksi: null` with `note: "no direct FedRAMP KSI overlap"`; the row still emits. |
| **A3 — Conflicting OLIR relationship types in source mapping.** Two OLIR entries for the same Annex A control with different relationship types (e.g. one "subset" + one "intersect"). | OLIR can carry multiple records per source-target pair. | Z.Z1 normaliser merges by taking the most-specific relationship; surfaces a `coverage:olir-conflict` log line. |
| **A4 — Operator-supplied EUCS level mismatched against evidence.** Operator requests EUCS Substantial but missing 27017 evidence. | EUCS Substantial requires 27017 by default. | Z.Z5 packager rejects with REQUIRES-OPERATOR-INPUT diagnostic: "EUCS Substantial requires ISO/IEC 27017 evidence — Z.Z3 has not been run for cloud_provider X". |
| **A5 — SoA `.docx` round-trip integrity.** Open in Word, save, re-open in LOOP-Z reader. | OOXML round-trip is a common failure mode. | Z.Z2's emitter writes Word-stable structures (uses the existing SSP-2 OOXML helper) + verifies SHA-256 round trip on save; reject diagnostic on drift. |
| **A6 — Multi-tenant 27017 CLD.9.5.1 segregation gap.** Cloud inventory shows a shared VPC across tenants. | CLD.9.5.1 (Segregation in virtual computing environments) is foundational. | Z.Z3's mapper inspects inventory `tenant_isolation` tags; absence → POA&M item "CLD.9.5.1 gap"; SoA marks `partial`. |
| **A7 — 27018 sub-processor disclosure gap.** Sub-processor sheet has a new entry not yet disclosed to PII Controllers. | 27018 Annex A control "Transparency in disclosure of sub-processors" is foundational. | Z.Z4's mapper compares the subprocessors-sheet against the previously-disclosed list; new entries surface as `coverage:undisclosed-subprocessor`; POA&M item emitted. |
| **A8 — 27701 PIMS scope statement omits geographic boundaries.** | PIMS scope drives the certification scope; geographic boundaries determine which jurisdictions apply (EU vs non-EU). | Z.Z5's PIMS emitter requires `scope.geographic_boundaries` field; REQUIRES-OPERATOR-INPUT if missing. |
| **A9 — EUCS scheme update (post-adoption).** The EU Commission ratifies EUCS with a different control set than the 2024 draft. | LOOP-Z's mapping is fixed at extraction time. | Z.Z5's catalog includes a `enisa_version` field; loader refuses to package if version is stale (>180 days); operator re-runs `scripts/extract-enisa-eucs.mjs` to refresh. |
| **A10 — Multi-region scope with conflicting laws.** Operator processes EU PII in U.S. and Asia regions. | GDPR has data-transfer restrictions (Chapter V); the PIMS must address. | Z.Z5's PIMS emitter requires `data_transfers[]` field listing each destination + lawful basis (SCC / adequacy decision / BCR / Article 49 derogation); REQUIRES-OPERATOR-INPUT if missing for any non-EU region. |
| **A11 — NIST 800-53 control deprecated in next Rev.** | NIST 800-53 Rev 6 may retire some controls. | Z.Z1's loader carries `nist_rev` field; future Rev mapping is additive; orchestrator emits `coverage:control-deprecated` for any Annex A control whose mapped 800-53 control has been retired. |
| **A12 — Operator overrides "applicable" status without justification.** | clause 6.1.3(d) requires *both* applicable+implementation and *justification*. | Z.Z2 emitter enforces both: `applicable=true` REQUIRES `justification`; cannot emit otherwise. |

---

## 8. Risks summary

The full risks register lives at
`cloud-evidence/docs/loops/LOOP-Z-RISKS.md`. The per-category headline:

| Category | Risk count | Highest-severity items |
|---|---|---|
| **Authoritative-source drift** | 4 | ISO publishes new edition of 27001 (e.g. 27001:2027); EUCS scheme adopted with different control set; OLIR mapping schema change; GDPR amendment by EU |
| **Catalog correctness** | 5 | Annex A control ID renaming; NIST OLIR relationship-type ambiguity; FedRAMP KSI crosswalk drift; 27017 augmentation-table completeness; 27018 PII-control set evolution |
| **Certification-body alignment** | 3 | CAB rejects the SoA format; CAB requires additional evidence not in LOOP-Z's emit; Stage 1 / Stage 2 audit cycle delays |
| **EUCS adoption uncertainty** | 3 | EUCS not yet adopted by EU Commission; assurance-level definitions change at adoption; ENISA scheme amended pre-adoption |
| **Privacy-framework alignment** | 4 | GDPR Article 28 sub-processor flow-down; CCPA / CPRA consumer-rights overlap; FERPA / COPPA / GLBA per-jurisdiction friction; data-residency cross-jurisdiction obligations |
| **Operator-input** | 4 | Missing risk-register population; missing scope statement; missing officer signature; missing data_transfers list |
| **Submission ecosystem** | 3 | CAB portal change; EU NCCA portal change; ISMAP / IRAP / similar non-EU government-cloud scheme integration |
| **Cross-loop dependency** | 3 | LOOP-B risk-register changes; LOOP-INV-S inventory schema change; LOOP-U privacy-framework fixtures schema change |
| **Legal / regulatory** | 3 | EU data-transfer regime changes (post-Schrems); UK-GDPR divergence; APAC privacy laws (Australia Privacy Act amendments; Japan APPI updates) |

Total: 32 risks tracked in the register. The register file template is
the same one used for LOOP-W-RISKS.md.

---

## 9. Open questions

The following questions are unresolved as of 2026-06-07 and must be
closed before the corresponding slice ships:

| # | Question | Affects | Status |
|---|---|---|---|
| OQ-Z-01 | Does the ENISA EUCS scheme final adoption (post-2024 candidate) change the assurance-level boundaries (Basic / Substantial / High)? | Z.Z5 | OPERATOR-RESEARCH — implementer monitors EU Commission OJ and re-fetches `scripts/extract-enisa-eucs.mjs` when adoption announced |
| OQ-Z-02 | Is the operator's CAB accredited under ISO/IEC 27006 (ISMS-specific) or only 17021-1 (generic management systems)? | Z.Z2 | OPERATOR-RESEARCH — CSP confirms with CAB before Stage 1 audit; tracker records the accreditation chain |
| OQ-Z-03 | Does the CSP scope include personal data of EU data subjects (triggering GDPR + 27018 + 27701)? | Z.Z4, Z.Z5 | OPERATOR-INPUT — operator declares via `org-profile.yaml.gdpr_in_scope: true | false` |
| OQ-Z-04 | Does the CSP serve any Japanese / Australian / Singaporean government customers (triggering ISMAP / IRAP / MTCS)? | Future LOOP-ISMAP / LOOP-IRAP | OPERATOR-INPUT — operator declares; LOOP-Z emits the foundation; per-country emitters are out of scope |
| OQ-Z-05 | What is the canonical SoA format the CAB accepts? | Z.Z2 | OPERATOR-RESEARCH — most CABs accept the ISO 27001 Annex SL-derived layout; some demand their proprietary spreadsheet. Z.Z2 emits both `.docx` (Annex SL) and `.json` (canonical) for translation |
| OQ-Z-06 | How does LOOP-Z's SoA handle "ISO 27001:2013 → ISO 27001:2022" transition for orgs with legacy certificates? | Z.Z1 | DEFERRED — transition deadline 2025-10-31 has passed; LOOP-Z targets 27001:2022 only; legacy mapping informative |
| OQ-Z-07 | What is the operator's CAB review schedule (annual surveillance + 3-year recertification)? | Z.Z2 tracker UI | OPERATOR-INPUT — operator schedules in tracker UI; reminders emitted by tracker |
| OQ-Z-08 | Does LOOP-Z need to interlock with LOOP-V (HIPAA) for international healthcare cloud customers? | Z.Z4 | CONFIRMED — Z.Z4 cross-references LOOP-V.V1 for PHI cross-overlap; LOOP-V is the U.S.-HIPAA-side view; Z.Z4 is the ISO/27018-side view |
| OQ-Z-09 | What's the policy on operator overrides of the NIST OLIR crosswalk? | Z.Z1 | DOCUMENTED — operator can add overrides via `iso-27001-overrides.yaml` (separate from the NIST OLIR mapping); operator overrides are merged with `provenance: operator` |
| OQ-Z-10 | Does LOOP-Z's Z.Z2 SoA require operator-officer sign-off before bundling? | Z.Z2 | YES — REO Rule 4 + clause 6.1.3 require documented operator approval; tracker UI sign-off page captures the signature |

---

## 10. Glossary deltas

The following terms are added by LOOP-Z to `docs/GLOSSARY.md`:

| Term | Definition |
|---|---|
| **ISMS** | Information Security Management System — the documented set of policies, procedures, controls, and processes an organization uses to manage information security risk; the substrate of ISO/IEC 27001. |
| **PIMS** | Privacy Information Management System — an extension to the ISMS for managing personal-data processing risk; the substrate of ISO/IEC 27701. |
| **SoA** | Statement of Applicability — the documented list per ISO/IEC 27001 clause 6.1.3(d) of all Annex A controls, whether each is applicable to the organization, the justification for inclusion/exclusion, and the implementation status. |
| **Annex A** | The reference set of 93 information-security controls in ISO/IEC 27001:2022 organised into 4 themes (Organizational, People, Physical, Technological). |
| **CLD.* controls** | Cloud-specific controls in ISO/IEC 27017:2015 namespace (CLD.6.3.1 through CLD.13.1.4); 7 cloud-specific controls distinct from the 27002 base set. |
| **PII Controller** | Per ISO/IEC 27701 + GDPR Article 4(7): the entity that determines the purposes and means of processing personal data. |
| **PII Processor** | Per ISO/IEC 27701 + GDPR Article 4(8): the entity that processes personal data on behalf of the PII Controller. |
| **CAB** | Conformity Assessment Body — the accredited body that audits and certifies the CSP's ISMS / PIMS against ISO/IEC 27001 / 27701; or that performs EUCS conformity assessment. |
| **NCCA** | National Cybersecurity Certification Authority — the EU member-state authority designated under the EU Cybersecurity Act to oversee EU cybersecurity certification on its territory. |
| **EUCS** | EU Cybersecurity Certification Scheme on Cloud Services — the ENISA-developed cloud-services certification scheme under the EU Cybersecurity Act. |
| **EU Cybersecurity Act** | Regulation (EU) 2019/881 establishing the EU Cybersecurity Certification Framework + giving ENISA a permanent mandate. |
| **OLIR** | NIST Online Informative References program — publishes one-way informative crosswalks between cybersecurity / privacy / workforce documents. |
| **ISMAP** | Information system Security Management and Assessment Program — Japanese-government cloud-procurement scheme; ISO-aligned. |
| **IRAP** | Information Security Registered Assessors Program — Australian-government cloud-procurement scheme. |
| **CSA STAR** | Cloud Security Alliance Security, Trust, Assurance, and Risk registry — CSP self-attestation overlay against the CSA Cloud Controls Matrix (CCM). |
| **CCM** | Cloud Controls Matrix — the CSA's cybersecurity control framework for cloud computing; ISO-derived; cross-mapped to ISO 27001 + NIST 800-53. |
| **Stage 1 / Stage 2 audit** | The two-phase ISO certification audit: Stage 1 is the documentation review (SoA + ISMS docs); Stage 2 is the on-site / virtual evidence audit. |
| **Surveillance audit** | The annual review performed during the 3-year ISO certificate cycle. |
| **Recertification** | The full re-audit at year 3 of the ISO certificate cycle. |
| **Shared responsibility model** | The split of security obligations between cloud service provider (CSP) and cloud service customer (CSC); referenced extensively in ISO/IEC 27017. |
| **Article 28 (GDPR)** | The GDPR article governing data processing on behalf of a PII Controller by a PII Processor. |
| **Article 32 (GDPR)** | The GDPR article requiring the controller and processor to implement appropriate technical and organisational measures to ensure security of processing. |
| **Schrems II** | CJEU decision (C-311/18, July 2020) invalidating the EU-U.S. Privacy Shield + imposing additional safeguards for SCC-based data transfers; relevant to PIMS data-transfer documentation. |

---

## 11. Cross-references

### 11.1 Dependency graph edges to add (`docs/DEPENDENCY-GRAPH.md`)

```
LOOP-Z.Z1 → (no upstream within LOOP-Z; depends on NIST OLIR + frmr-ksi-catalog + control-benchmark)
LOOP-Z.Z2 ← LOOP-Z.Z1, LOOP-B.B1 (risk register), LOOP-A.A4, LOOP-A.A5, LOOP-T.T3, LOOP-W.W1, LOOP-R
LOOP-Z.Z3 ← LOOP-Z.Z1, LOOP-INV-S (inventory + coverage)
LOOP-Z.Z4 ← LOOP-Z.Z1, LOOP-Z.Z3, LOOP-U.U1 (privacy crosswalk), LOOP-V.V1 (HIPAA)
LOOP-Z.Z5 ← LOOP-Z.Z1, LOOP-Z.Z2, LOOP-Z.Z3, LOOP-Z.Z4, LOOP-A.A4, LOOP-A.A5
LOOP-Q.Q1 ← LOOP-Z.Z2 + LOOP-Z.Z5  (Marketplace "ISO 27001 certified" + "EUCS Substantial" badges)
```

### 11.2 Loops impacted

| Other loop | How LOOP-Z affects it |
|---|---|
| **LOOP-B (Risk + Remediation)** | LOOP-B's risk register populates Z.Z2 SoA justifications for clause 6.1.3(d). When Z.Z2 marks a control "not applicable", it must cite a risk-register row + risk_owner + acceptance_date. |
| **LOOP-U (Privacy Frameworks Crosswalk)** | LOOP-U owns GDPR / CCPA / FERPA / COPPA / GLBA crosswalk to NIST 800-53. Z.Z4 (27018) and Z.Z5 (27701) consume LOOP-U for the GDPR-side mapping. |
| **LOOP-V (Healthcare Overlay)** | LOOP-V owns HIPAA + HITRUST. Z.Z4 cross-references LOOP-V for PHI-processor overlap with 27018 PII-processor controls. |
| **LOOP-INV-S (Inventory + Coverage)** | Z.Z3 reads inventory + coverage to compute per-cloud control coverage. INV-S coverage contract must include 27017 CLD.* control coverage as a top-level dimension. |
| **LOOP-T (NIST SSDF / CISA Common Form)** | Z.Z2 SoA cites LOOP-T's SSDF Common Form as evidence for A.8.25 (Secure development lifecycle) + A.8.28 (Secure coding) + A.8.29 (Security testing in development and acceptance). |
| **LOOP-W (Prohibited-Vendor Screening)** | Z.Z2 SoA cites LOOP-W for A.5.19 (Information security in supplier relationships), A.5.20 (Addressing information security within supplier agreements), and A.5.23 (Information security for use of cloud services). |
| **LOOP-R (Post-Quantum Cryptography)** | Z.Z2 SoA cites LOOP-R for A.8.24 (Use of cryptography) and A.8.1 (User endpoint devices) where PQC-impacted. |
| **LOOP-Q (Marketplace + Post-ATO Publication)** | Q.Q1 surfaces "ISO 27001 certified" + "EUCS Substantial certified" badges with the signed envelope URLs from Z.Z2 / Z.Z5. |
| **LOOP-X (Zero Trust — OMB M-22-09 / 800-207)** | LOOP-X overlaps with ISO 27001 Annex A 5.15 (Access control) + A.8.2 (Privileged access rights) + A.8.5 (Secure authentication). Z.Z2 SoA cites LOOP-X evidence where ZT pillars are implemented. |
| **LOOP-Y (Sector Overlays — CJIS + IRS Pub 1075)** | LOOP-Y overlaps with ISO 27001 for U.S.-government sector overlays. Independent of LOOP-Z's international focus; co-exists. |
| **LOOP-S (DFARS 252.204-7012)** | Independent; no direct dependency. |
| **LOOP-M (Privacy package, SORN, DPIA)** | Z.Z4 + Z.Z5 cross-reference LOOP-M for U.S. Federal-side privacy artifacts (DPIA, SORN). Where the CSP processes EU + U.S. data, both LOOP-M (U.S. side) and LOOP-Z (EU side via 27018/27701) co-exist. |

### 11.3 Extensions outside the loop

- **`tracker/server/routes/iso.ts`** — REST surface added in Z.Z2 / Z.Z3 / Z.Z4 / Z.Z5.
- **`tracker/client/src/pages/ISO.tsx`** — UI surface added in Z.Z2 (SoA review), Z.Z3 (per-cloud coverage), Z.Z5 (EUCS submission).
- **CSA STAR overlay (out of LOOP-Z; potential future)** — Cloud Security Alliance's STAR registry consumes CSA CCM-format self-attestations. LOOP-Z's Z.Z1 catalog could be extended to crosswalk CCM v4 controls; a future LOOP-Z2 could emit CSA STAR Level 1 self-attestations.
- **CSF v2 mapping** — NIST Cybersecurity Framework v2.0 (Feb 2024) has its own informative crosswalk to ISO 27001 via the OLIR programme. Z.Z1's catalog includes a CSF mapping column.

---

## 12. Status table (per-slice)

| Slice | Status | Last updated | Commit | Notes |
|---|---|---|---|---|
| Z.Z1 — ISO/IEC 27001:2022 Annex A Crosswalk | pending | 2026-06-07 | — | Catalog of 93 controls + NIST 800-53 + FedRAMP KSI crosswalk; signed Ed25519 |
| Z.Z2 — ISO 27001 Statement of Applicability Emitter | pending | 2026-06-07 | — | Depends on Z.Z1 + LOOP-B risk register; emits `.docx` + signed `.json` |
| Z.Z3 — ISO/IEC 27017:2015 Cloud Controls | pending | 2026-06-07 | — | Depends on Z.Z1 + LOOP-INV-S; per-cloud (AWS/GCP/Azure) coverage |
| Z.Z4 — ISO/IEC 27018:2019 PII Processor Controls | pending | 2026-06-07 | — | Depends on Z.Z1 + Z.Z3 + LOOP-U + LOOP-V |
| Z.Z5 — ISO/IEC 27701 PIMS + ENISA EUCS submission package | pending | 2026-06-07 | — | Depends on all Z prior + LOOP-A.A4/A5 |

---

## 13. Completion + push directive (NON-NEGOTIABLE)

> **Each slice in this loop, upon completion, MUST update STATUS.md
> status row, append a CHANGELOG entry, commit with the slice ID +
> Co-Authored-By trailer, push to origin/main, and update CLAUDE.md
> reading list if a new permanent reference document was created.**

In long form, the 7-step procedure from
`cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` applies verbatim:

1. Run `npm run typecheck && npm test && npm run check:reo && npm run check:provenance && npm run lint:no-stubs`. ALL must be green BEFORE any commit.
2. Update `cloud-evidence/docs/STATUS.md` — the per-slice row (status, commit, completed_date) AND the "Overall → Next priority" line.
3. Update `cloud-evidence/docs/loops/LOOP-Z-SPEC.md` (this file) — the slice's row in §12.
4. Update `cloud-evidence/docs/slices/Z/Z.ZN.md` frontmatter (status, commit, completed_date, last_updated) AND append the final Implementation log entry.
5. Append a `cloud-evidence/CHANGELOG.md` "Unreleased" entry naming the slice, the real evidence path, and the new artifacts.
6. Append any newly-discovered risks to `cloud-evidence/docs/loops/LOOP-Z-RISKS.md` in the same commit.
7. `git add` only the files you intentionally changed (NEVER use `-A` blanket). Commit with message:
   ```
   feat(Z.ZN): <short description>

   Slice: Z.ZN <slice title>
   Loop: LOOP-Z
   Evidence: <describe real-evidence path>

   Co-Authored-By: Claude <noreply@anthropic.com>
   ```
8. `git push origin main` after pre-commit hooks pass.
9. Confirm the GitHub Action CI guardrails pass (lint:no-stubs, check:coverage-regression, check:provenance).

After the commit lands and CI is green, append a row to STATUS.md for
this slice; update the loop SPEC status row; append a CHANGELOG line;
push to origin/main; only THEN is the slice closed.

---

## 14. REQUIRES-OPERATOR-INPUT registry (loop-wide aggregation)

The complete per-field operator-input list lives in each per-slice doc.
Loop-wide aggregation:

| Field | Slice | Type | Validator | UI location | Failure mode if missing |
|---|---|---|---|---|---|
| `iso_27001_scope_statement` | Z.Z2 | string ≤ 4000 chars | non-empty + operator-attested | tracker UI / `iso-scope.yaml` | SoA emit blocked; REQUIRES-OPERATOR-INPUT diagnostic |
| `iso_27001_overrides.yaml` | Z.Z1 | YAML | schema-valid | `cloud-evidence/` | Operator overrides skipped; NIST OLIR mapping used as-is |
| `cab_name`, `cab_accreditation_id`, `cab_country` | Z.Z2 | strings | non-empty + ANAB/UKAS/DAkkS lookup | tracker UI sign-off page | Marketplace badge not surfaced; SoA can still emit (informative) |
| `iso_certificate_number`, `iso_certificate_date`, `iso_certificate_expiry` | Z.Z2 | strings | non-empty after Stage 2 closure | tracker UI | Q.Q1 badge not surfaced |
| `org_pii_role` | Z.Z4, Z.Z5 | enum: "controller", "processor", "both" | non-empty | `org-profile.yaml` | Z.Z4 + Z.Z5 default to "processor" with REQUIRES-OPERATOR-CONFIRM |
| `gdpr_in_scope` | Z.Z4, Z.Z5 | boolean | required when serving EU data subjects | `org-profile.yaml` | Z.Z5 EUCS submission blocked; SoA + 27017 still ship |
| `data_transfers` | Z.Z5 | YAML array of {destination_country, lawful_basis, scc_version} | RFC-3166 country codes | `cloud-evidence/data-transfers.yaml` | EUCS submission blocked when gdpr_in_scope=true |
| `eucs_level` | Z.Z5 | enum: "basic", "substantial", "high" | required | CLI flag / `org-profile.yaml` | EUCS package emit blocked |
| `eucs_pentest_report_path` | Z.Z5 (level=high only) | file path | file exists + ≤ 12 months old | `org-profile.yaml` | EUCS High blocked; downgrade to Substantial allowed via operator confirmation |
| `pims_scope_statement`, `pims_scope_geographic_boundaries`, `pims_scope_categories_of_pii` | Z.Z5 | strings + arrays | non-empty | tracker UI | PIMS emit blocked |
| `27017_shared_responsibility_overrides.yaml` | Z.Z3 | YAML | schema-valid | `cloud-evidence/` | Defaults from 27017 standard applied; operator override flagged with `provenance: operator` |
| `27018_sub_processor_disclosure.yaml` | Z.Z4 | YAML | mirrors `subprocessors-sheet` + adds disclosure_date per row | `cloud-evidence/` | Z.Z4 emit blocked when GDPR_in_scope=true |
| `risk_register_completeness` | Z.Z2 | derived | tracker DB query; ≥ 1 risk per "not applicable" SoA row | tracker UI | Z.Z2 emit blocked with `coverage:risk-register-incomplete` |

---

## 15. Implementation log slot (loop-wide)

| Date | Session | Action | Commit | Notes |
|---|---|---|---|---|
| 2026-06-07 | initial-spec | LOOP-Z-SPEC.md authored from FOURTH-PASS-AUDIT.md priority | — | Loop opened; Z.Z1..Z.Z5 status=pending |
| | | | | |
| | | | | |
| | | | | |

(Appended per-slice; per-slice docs carry their own per-slice
Implementation log slots.)

---

## 16. ISO 27001:2022 Annex A — control-theme matrix (canonical 93-control structure)

For LOOP-Z's Z.Z1 catalog, the 93 Annex A controls are organized into 4
themes. The following table is the complete enumeration (control IDs +
canonical short names) for the operator's reference. **Full control
implementation guidance is in the operator's licensed copy of ISO/IEC
27002:2022.**

### 16.1 A.5 — Organizational controls (37 controls)

| ID | Short name |
|---|---|
| A.5.1 | Policies for information security |
| A.5.2 | Information security roles and responsibilities |
| A.5.3 | Segregation of duties |
| A.5.4 | Management responsibilities |
| A.5.5 | Contact with authorities |
| A.5.6 | Contact with special interest groups |
| A.5.7 | Threat intelligence |
| A.5.8 | Information security in project management |
| A.5.9 | Inventory of information and other associated assets |
| A.5.10 | Acceptable use of information and other associated assets |
| A.5.11 | Return of assets |
| A.5.12 | Classification of information |
| A.5.13 | Labelling of information |
| A.5.14 | Information transfer |
| A.5.15 | Access control |
| A.5.16 | Identity management |
| A.5.17 | Authentication information |
| A.5.18 | Access rights |
| A.5.19 | Information security in supplier relationships |
| A.5.20 | Addressing information security within supplier agreements |
| A.5.21 | Managing information security in the ICT supply chain |
| A.5.22 | Monitoring, review and change management of supplier services |
| A.5.23 | Information security for use of cloud services |
| A.5.24 | Information security incident management planning and preparation |
| A.5.25 | Assessment and decision on information security events |
| A.5.26 | Response to information security incidents |
| A.5.27 | Learning from information security incidents |
| A.5.28 | Collection of evidence |
| A.5.29 | Information security during disruption |
| A.5.30 | ICT readiness for business continuity |
| A.5.31 | Legal, statutory, regulatory and contractual requirements |
| A.5.32 | Intellectual property rights |
| A.5.33 | Protection of records |
| A.5.34 | Privacy and protection of PII |
| A.5.35 | Independent review of information security |
| A.5.36 | Compliance with policies, rules and standards for information security |
| A.5.37 | Documented operating procedures |

### 16.2 A.6 — People controls (8 controls)

| ID | Short name |
|---|---|
| A.6.1 | Screening |
| A.6.2 | Terms and conditions of employment |
| A.6.3 | Information security awareness, education and training |
| A.6.4 | Disciplinary process |
| A.6.5 | Responsibilities after termination or change of employment |
| A.6.6 | Confidentiality or non-disclosure agreements |
| A.6.7 | Remote working |
| A.6.8 | Information security event reporting |

### 16.3 A.7 — Physical controls (14 controls)

| ID | Short name |
|---|---|
| A.7.1 | Physical security perimeters |
| A.7.2 | Physical entry |
| A.7.3 | Securing offices, rooms and facilities |
| A.7.4 | Physical security monitoring |
| A.7.5 | Protecting against physical and environmental threats |
| A.7.6 | Working in secure areas |
| A.7.7 | Clear desk and clear screen |
| A.7.8 | Equipment siting and protection |
| A.7.9 | Security of assets off-premises |
| A.7.10 | Storage media |
| A.7.11 | Supporting utilities |
| A.7.12 | Cabling security |
| A.7.13 | Equipment maintenance |
| A.7.14 | Secure disposal or re-use of equipment |

### 16.4 A.8 — Technological controls (34 controls)

| ID | Short name |
|---|---|
| A.8.1 | User endpoint devices |
| A.8.2 | Privileged access rights |
| A.8.3 | Information access restriction |
| A.8.4 | Access to source code |
| A.8.5 | Secure authentication |
| A.8.6 | Capacity management |
| A.8.7 | Protection against malware |
| A.8.8 | Management of technical vulnerabilities |
| A.8.9 | Configuration management |
| A.8.10 | Information deletion |
| A.8.11 | Data masking |
| A.8.12 | Data leakage prevention |
| A.8.13 | Information backup |
| A.8.14 | Redundancy of information processing facilities |
| A.8.15 | Logging |
| A.8.16 | Monitoring activities |
| A.8.17 | Clock synchronization |
| A.8.18 | Use of privileged utility programs |
| A.8.19 | Installation of software on operational systems |
| A.8.20 | Networks security |
| A.8.21 | Security of network services |
| A.8.22 | Segregation of networks |
| A.8.23 | Web filtering |
| A.8.24 | Use of cryptography |
| A.8.25 | Secure development lifecycle |
| A.8.26 | Application security requirements |
| A.8.27 | Secure system architecture and engineering principles |
| A.8.28 | Secure coding |
| A.8.29 | Security testing in development and acceptance |
| A.8.30 | Outsourced development |
| A.8.31 | Separation of development, test and production environments |
| A.8.32 | Change management |
| A.8.33 | Test information |
| A.8.34 | Protection of information systems during audit testing |

**Total: 93 controls** (37 + 8 + 14 + 34 = 93). Z.Z1's catalog row
count MUST equal 93 (validated by a test).

### 16.5 11 new controls in 27001:2022 (compared with 27001:2013)

ISO/IEC 27001:2022 introduced 11 new controls that did not exist in
27001:2013:

| ID | Short name |
|---|---|
| A.5.7 | Threat intelligence |
| A.5.23 | Information security for use of cloud services |
| A.5.30 | ICT readiness for business continuity |
| A.7.4 | Physical security monitoring |
| A.8.9 | Configuration management |
| A.8.10 | Information deletion |
| A.8.11 | Data masking |
| A.8.12 | Data leakage prevention |
| A.8.16 | Monitoring activities |
| A.8.23 | Web filtering |
| A.8.28 | Secure coding |

Z.Z1's catalog tags these as `is_new_in_2022: true`. For organisations
transitioning from 27001:2013 → 27001:2022, the SoA emitter highlights
these 11 controls as requiring fresh evidence collection.

---

## 17. ISO 27001:2022 Annex A — control catalog schema (Z.Z1's output)

```jsonc
{
  "$schema": "https://cloud-evidence.example/schemas/iso-27001-2022-annex-a-v1.json",
  "schema_version": "1.0.0",
  "snapshot_id": "iso-27001-2022-annex-a-20260607T120000Z",
  "snapshot_date": "2026-06-07",
  "snapshot_at": "2026-06-07T12:00:00Z",
  "csp_name": "<from org-profile.yaml>",
  "iso_edition": "ISO/IEC 27001:2022",
  "iso_publish_date": "2022-10",
  "themes": [
    {"id": "A.5", "name": "Organizational controls", "control_count": 37},
    {"id": "A.6", "name": "People controls", "control_count": 8},
    {"id": "A.7", "name": "Physical controls", "control_count": 14},
    {"id": "A.8", "name": "Technological controls", "control_count": 34}
  ],
  "controls": [
    {
      "control_id": "A.5.1",
      "control_short_name": "Policies for information security",
      "theme": "A.5",
      "is_new_in_2022": false,
      "legacy_2013_mapping": "A.5.1.1, A.5.1.2",
      "attributes": {
        "control_type": ["Preventive"],
        "information_security_properties": ["Confidentiality", "Integrity", "Availability"],
        "cybersecurity_concepts": ["Identify", "Protect"],
        "operational_capabilities": ["Governance"],
        "security_domains": ["Governance and ecosystem"]
      },
      "crosswalk_nist_800_53_rev5": [
        {"control_id": "PM-1", "relationship_type": "subset"},
        {"control_id": "AC-1", "relationship_type": "intersect"}
      ],
      "crosswalk_fedramp_ksi": [
        {"ksi_id": "AFR-DRP", "relationship_type": "intersect"}
      ],
      "crosswalk_nist_csf_v2": [
        {"function": "GV", "category": "GV.PO", "subcategory": "GV.PO-01"}
      ],
      "evidence_references": []      // populated by Z.Z2 from cross-loop evidence
    },
    // ... 92 more rows
  ],
  "totals": {
    "controls": 93,
    "new_in_2022": 11,
    "by_theme": {
      "A.5": 37,
      "A.6": 8,
      "A.7": 14,
      "A.8": 34
    }
  },
  "provenance": {
    "emitter": "scripts/extract-iso-27001-2022.mjs",
    "emitter_version": "1.0.0",
    "emitted_at": "2026-06-07T12:05:00Z",
    "source_iso_purchase_date": "<operator-supplied>",
    "olir_mapping_id": "<NIST OLIR mapping identifier>",
    "olir_mapping_date": "<NIST OLIR mapping date>",
    "signing_key_id": "ed25519-prod-2026",
    "signature": "<Ed25519 detached signature over canonical JSON>",
    "signature_alg": "Ed25519",
    "canonicalization": "rfc8785"
  }
}
```

---

## 18. SoA schema (Z.Z2's output)

```jsonc
{
  "$schema": "https://cloud-evidence.example/schemas/iso-27001-soa-v1.json",
  "schema_version": "1.0.0",
  "soa_id": "soa-2026-06-07-001",
  "csp_name": "<from org-profile>",
  "iso_edition": "ISO/IEC 27001:2022",
  "scope_statement": "<from iso-scope.yaml>",
  "scope_geographic_boundaries": ["US", "EU", "JP"],
  "scope_organizational_boundaries": "<from iso-scope.yaml>",
  "scope_information_assets": ["customer-data", "production-systems", "..."],
  "version": "1.0.0",
  "effective_date": "2026-06-07",
  "next_review_date": "2027-06-07",
  "cab_name": "<from operator>",
  "cab_accreditation_id": "<from operator>",
  "cab_country": "<from operator>",
  "iso_certificate_status": "draft | submitted | stage-1-complete | stage-2-complete | certified | recertification-due | expired",
  "iso_certificate_number": null,
  "iso_certificate_date": null,
  "iso_certificate_expiry": null,
  "controls": [
    {
      "control_id": "A.5.1",
      "control_short_name": "Policies for information security",
      "applicable": true,
      "justification": "Foundational ISMS requirement; organization maintains an Information Security Policy approved by top management, reviewed annually, communicated to all personnel.",
      "implementation_status": "implemented | partial | planned | not_implemented",
      "implementation_date": "2024-01-15",
      "responsible_role": "CISO",
      "evidence_references": [
        {"type": "ssp", "url": "...", "hash": "sha256:..."},
        {"type": "policy-doc", "url": "...", "hash": "sha256:..."}
      ],
      "risk_register_links": [
        {"risk_id": "RISK-2026-001", "risk_owner": "CISO", "acceptance_date": null}
      ],
      "crosswalk_loop_evidence": [
        {"loop": "LOOP-A", "slice": "A.A5", "artifact_role": "soa-bundle"}
      ]
    }
    // ... 92 more rows
  ],
  "cloud_overlay": {
    "applicable": true,
    "iso_27017_evidence_ref": "iso-27017-coverage-{cspname}.json",
    "cld_controls_status": {
      "CLD.6.3.1": "implemented",
      "CLD.8.1.5": "implemented",
      "CLD.9.5.1": "implemented",
      "CLD.9.5.2": "partial",
      "CLD.12.1.5": "implemented",
      "CLD.12.4.5": "implemented",
      "CLD.13.1.4": "implemented"
    }
  },
  "pii_extension": {
    "applicable": true,
    "iso_27018_evidence_ref": "iso-27018-evidence-{cspname}.json",
    "iso_27701_evidence_ref": "iso-27701-pims-{cspname}.json"
  },
  "officer_attestation": {
    "officer_name": "<operator>",
    "officer_title": "<operator>",
    "officer_email": "<operator>",
    "attested_at": "2026-06-29T15:00:00Z",
    "attestation_text": "I attest that the foregoing Statement of Applicability accurately reflects the organization's selected controls, their applicability, and the rationale for inclusion or exclusion of each Annex A control, in accordance with ISO/IEC 27001:2022 clause 6.1.3(d).",
    "signature_alg": "Ed25519-detached",
    "signature": "<operator-signed>"
  },
  "provenance": {
    "emitter": "core/iso-27001-soa-emitter.ts",
    "emitter_version": "1.0.0",
    "emitted_at": "2026-06-29T15:01:00Z",
    "catalog_snapshot_id": "iso-27001-2022-annex-a-20260607T120000Z",
    "risk_register_snapshot_id": "risk-register-20260629T150000Z",
    "signing_key_id": "ed25519-prod-2026",
    "signature": "<Ed25519 detached over canonical JSON>",
    "canonicalization": "rfc8785"
  }
}
```

The SoA `.docx` companion reproduces the canonical SoA layout
(per ISO 27001 Annex SL conventions) and is generated by a
deterministic OOXML emitter reusing `core/oscal-ssp-docx.ts` patterns.

---

## 19. 27017 per-cloud coverage schema (Z.Z3's output)

```jsonc
{
  "$schema": "https://cloud-evidence.example/schemas/iso-27017-coverage-v1.json",
  "schema_version": "1.0.0",
  "coverage_id": "iso-27017-coverage-2026-06-07-001",
  "csp_name": "<from org-profile>",
  "cloud_provider": "aws | gcp | azure | multi",
  "scope_clouds": ["aws", "gcp", "azure"],
  "controls": [
    {
      "control_id": "CLD.6.3.1",
      "control_short_name": "Shared roles and responsibilities within a cloud computing environment",
      "csp_obligation": "implemented",
      "csc_obligation": "documented",
      "shared_responsibility_split": {
        "csp_responsibilities": [
          "Define the boundary between CSP-managed and CSC-managed responsibilities",
          "Publish the shared-responsibility matrix to customers",
          "Update the matrix when service offerings change"
        ],
        "csc_responsibilities": [
          "Acknowledge receipt of the shared-responsibility matrix",
          "Implement controls for the CSC-side responsibilities",
          "Notify the CSP when customer-side incidents may affect CSP services"
        ]
      },
      "evidence_references": [
        {"type": "shared-responsibility-matrix", "url": "...", "hash": "sha256:..."}
      ],
      "per_cloud_status": {
        "aws": {"status": "implemented", "evidence_inventory_ref": "..."},
        "gcp": {"status": "implemented", "evidence_inventory_ref": "..."},
        "azure": {"status": "partial", "evidence_inventory_ref": "...", "gap_notes": "Defender for Cloud secure-score evidence pending"}
      }
    }
    // ... 6 more CLD.* controls
  ],
  "augmented_27002_controls": [
    {
      "control_id": "A.5.10",
      "augmentation_status": "applies_with_cloud_guidance",
      "cloud_specific_guidance_implemented": true,
      "evidence_reference": "..."
    }
    // ... 36 more augmented 27002 controls
  ],
  "provenance": {
    "emitter": "core/iso-27017-mapper.ts",
    "emitter_version": "1.0.0",
    "emitted_at": "2026-06-07T15:00:00Z",
    "inventory_snapshot_id": "<from LOOP-INV-S>",
    "signing_key_id": "ed25519-prod-2026",
    "signature": "<Ed25519 detached>",
    "canonicalization": "rfc8785"
  }
}
```

---

## 20. 27018 PII Processor evidence schema (Z.Z4's output)

```jsonc
{
  "$schema": "https://cloud-evidence.example/schemas/iso-27018-evidence-v1.json",
  "schema_version": "1.0.0",
  "evidence_id": "iso-27018-evidence-2026-06-07-001",
  "csp_name": "<from org-profile>",
  "csp_role": "pii_processor",
  "scope_of_pii_processing": "<operator-supplied description>",
  "categories_of_pii": ["contact-info", "billing-info", "professional-credentials", "..."],
  "pii_controllers_served": [
    {"controller_name": "<operator>", "data_processing_agreement_ref": "..."}
  ],
  "sub_processors": [
    {"sub_processor_name": "<operator>", "purpose": "...", "disclosed_at": "2024-03-15", "country_of_processing": "US"}
    // ... pulled from subprocessors-sheet
  ],
  "controls": [
    {
      "iso_27018_area": "Consent and choice",
      "csp_obligation": "facilitate PII Controller's ability to support data subject consent",
      "implementation_status": "implemented",
      "evidence_references": ["..."],
      "gdpr_articles": ["6", "7"]
    },
    {
      "iso_27018_area": "Purpose legitimacy and specification",
      "csp_obligation": "process PII only for purposes specified by PII Controller",
      "implementation_status": "implemented",
      "evidence_references": ["..."],
      "gdpr_articles": ["5(1)(b)", "6"]
    }
    // ... 9 more 27018-specific control rows
  ],
  "augmented_27002_controls_pii": [
    {
      "control_id": "A.5.34",
      "27018_pii_guidance_implemented": true,
      "evidence_reference": "..."
    }
    // ... other PII-augmented 27002 controls
  ],
  "incident_history": [
    {"incident_id": "<from tracker DB>", "severity": "low | moderate | high", "pii_breach": "true | false"}
  ],
  "provenance": {
    "emitter": "core/iso-27018-mapper.ts",
    "emitter_version": "1.0.0",
    "emitted_at": "2026-06-07T16:00:00Z",
    "loop_u_crosswalk_ref": "<LOOP-U.U1 snapshot id>",
    "loop_v_crosswalk_ref": "<LOOP-V.V1 snapshot id>",
    "subprocessors_sheet_snapshot_id": "<existing>",
    "signing_key_id": "ed25519-prod-2026",
    "signature": "<Ed25519 detached>",
    "canonicalization": "rfc8785"
  }
}
```

---

## 21. 27701 PIMS + EUCS submission package schemas (Z.Z5's outputs)

### 21.1 PIMS schema

```jsonc
{
  "$schema": "https://cloud-evidence.example/schemas/iso-27701-pims-v1.json",
  "schema_version": "1.0.0",
  "pims_id": "iso-27701-pims-2026-06-07-001",
  "csp_name": "<from org-profile>",
  "pims_scope": {
    "scope_statement": "<operator-supplied>",
    "geographic_boundaries": ["US", "EU-27", "JP", "AU"],
    "pims_role": "pii_controller | pii_processor | both",
    "categories_of_pii": ["contact-info", "professional-credentials", "..."],
    "pii_controllers_served_count": 142,
    "pii_processors_engaged_count": 18
  },
  "annex_a_controllers": [
    {"pims_control_id": "A.7.2", "applicable": true, "evidence_reference": "..."}
    // ... PIMS Annex A controls (PII Controllers)
  ],
  "annex_b_processors": [
    {"pims_control_id": "B.8.5", "applicable": true, "evidence_reference": "..."}
    // ... PIMS Annex B controls (PII Processors)
  ],
  "gdpr_article_mapping": [
    {"gdpr_article": "Article 5", "pims_controls": ["B.7.4", "A.7.4.1"]}
    // ... GDPR-side article references
  ],
  "data_transfers": [
    {
      "destination_country": "US",
      "transfer_mechanism": "Standard Contractual Clauses (SCC) — Module 2 (controller-to-processor)",
      "scc_version": "2021/914",
      "adequacy_decision": false,
      "supplementary_measures": "<operator-supplied — encryption + pseudonymization + access controls>",
      "last_review_date": "2026-01-15"
    }
    // ... per non-EU destination
  ],
  "incident_register_reference": "<from tracker DB>",
  "dpia_register_reference": "<from LOOP-M.M3>",
  "officer_attestation": {
    "officer_name": "<DPO or equivalent>",
    "officer_title": "Data Protection Officer",
    "officer_email": "<operator>",
    "attested_at": "...",
    "signature_alg": "Ed25519-detached",
    "signature": "..."
  },
  "provenance": {
    "emitter": "core/iso-27701-pims.ts",
    "emitter_version": "1.0.0",
    "emitted_at": "...",
    "soa_ref": "soa-2026-06-07-001",
    "iso_27018_ref": "iso-27018-evidence-2026-06-07-001",
    "signing_key_id": "ed25519-prod-2026",
    "signature": "...",
    "canonicalization": "rfc8785"
  }
}
```

### 21.2 EUCS submission package schema

```jsonc
{
  "$schema": "https://cloud-evidence.example/schemas/eucs-submission-v1.json",
  "schema_version": "1.0.0",
  "submission_id": "eucs-submission-2026-06-07-001",
  "csp_name": "<from org-profile>",
  "eucs_level": "basic | substantial | high",
  "service_offering": {
    "service_name": "<operator>",
    "service_url": "<operator>",
    "service_models": ["IaaS", "PaaS", "SaaS"],
    "deployment_models": ["public", "hybrid"],
    "data_processing_locations": ["EU-27", "US"]
  },
  "scope_statement": "<operator-supplied>",
  "cab_assignment": {
    "cab_name": "<operator>",
    "cab_country": "DE | FR | ...",
    "ncca_supervising_country": "DE | FR | ..."
  },
  "evidence_artifacts": {
    "iso_27001_soa": "ref to signed SoA envelope",
    "iso_27017_coverage": "ref to signed coverage envelope",
    "iso_27018_evidence": "ref to signed evidence envelope",
    "iso_27701_pims": "ref to signed PIMS envelope",
    "pentest_report": "ref to operator-supplied pentest (high-only)",
    "supplementary_policies": [
      "incident-response-plan", "data-protection-impact-assessment-set", "..."
    ]
  },
  "assurance_level_self_declaration": {
    "level_requested": "substantial",
    "evidence_completeness": "complete | gaps",
    "operator_attestation": "I declare that the evidence submitted in this package is complete and accurate for the EUCS Substantial assurance level."
  },
  "officer_attestation": {
    "officer_name": "<operator>",
    "officer_title": "<operator>",
    "officer_email": "<operator>",
    "attested_at": "...",
    "signature_alg": "Ed25519-detached",
    "signature": "..."
  },
  "provenance": {
    "emitter": "core/eucs-submission-package.ts",
    "emitter_version": "1.0.0",
    "emitted_at": "...",
    "enisa_scheme_version": "candidate-2024-03",
    "signing_key_id": "ed25519-prod-2026",
    "signature": "...",
    "canonicalization": "rfc8785"
  }
}
```

The submission package is bundled as a ZIP file
`out/eucs-submission-package-{cspname}-{level}-{date}.zip` containing:

- `MANIFEST.json` — the submission schema above
- `iso-27001-soa-*.docx` + `.json` + `.sig`
- `iso-27017-coverage-*.json` + `.sig`
- `iso-27018-evidence-*.json` + `.sig`
- `iso-27701-pims-*.json` + `.sig`
- `pentest-report.pdf` (high-only; operator-supplied)
- `supplementary-policies/` directory
- `README.md` — submission cover document with operator's contact info
  + scope statement + EUCS level + CAB / NCCA references

---

## 22. Tracker DB schema additions

```sql
-- Z.Z1 additions (catalog metadata only; canonical catalog lives in data/iso-27001-2022-annex-a.json)
CREATE TABLE IF NOT EXISTS iso_27001_catalog_snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  snapshot_id TEXT NOT NULL UNIQUE,
  snapshot_date TEXT NOT NULL,
  iso_edition TEXT NOT NULL DEFAULT 'ISO/IEC 27001:2022',
  control_count INTEGER NOT NULL,
  signature_b64 TEXT NOT NULL,
  signing_key_id TEXT NOT NULL
);

-- Z.Z2 additions
CREATE TABLE IF NOT EXISTS iso_27001_soa (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT NOT NULL UNIQUE,
  version TEXT NOT NULL,
  effective_date TEXT NOT NULL,
  next_review_date TEXT NOT NULL,
  scope_statement TEXT NOT NULL,
  scope_geographic_boundaries TEXT NOT NULL,
  scope_organizational_boundaries TEXT,
  cab_name TEXT,
  cab_accreditation_id TEXT,
  cab_country TEXT,
  iso_certificate_status TEXT NOT NULL DEFAULT 'draft'
    CHECK (iso_certificate_status IN
      ('draft','submitted','stage-1-complete','stage-2-complete',
       'certified','recertification-due','expired')),
  iso_certificate_number TEXT,
  iso_certificate_date TEXT,
  iso_certificate_expiry TEXT,
  catalog_snapshot_id TEXT NOT NULL,
  soa_json_sha256 TEXT NOT NULL,
  soa_docx_sha256 TEXT NOT NULL,
  officer_user_id INTEGER REFERENCES users(id),
  officer_signed_at TEXT,
  officer_signature_b64 TEXT
);

CREATE TABLE IF NOT EXISTS iso_27001_soa_controls (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  soa_id INTEGER NOT NULL REFERENCES iso_27001_soa(id),
  control_id TEXT NOT NULL,
  applicable INTEGER NOT NULL CHECK (applicable IN (0,1)),
  justification TEXT NOT NULL,
  implementation_status TEXT NOT NULL
    CHECK (implementation_status IN
      ('implemented','partial','planned','not_implemented')),
  implementation_date TEXT,
  responsible_role TEXT,
  raw_json TEXT NOT NULL,
  UNIQUE(soa_id, control_id)
);

CREATE INDEX IF NOT EXISTS idx_soa_controls_soa ON iso_27001_soa_controls(soa_id);
CREATE INDEX IF NOT EXISTS idx_soa_controls_control ON iso_27001_soa_controls(control_id);

-- Z.Z3 additions
CREATE TABLE IF NOT EXISTS iso_27017_coverage (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT NOT NULL UNIQUE,
  cloud_provider TEXT NOT NULL CHECK (cloud_provider IN ('aws','gcp','azure','multi')),
  generated_at TEXT NOT NULL,
  controls_total INTEGER NOT NULL,
  controls_implemented INTEGER NOT NULL,
  controls_partial INTEGER NOT NULL,
  controls_not_implemented INTEGER NOT NULL,
  coverage_json_sha256 TEXT NOT NULL,
  signature_b64 TEXT NOT NULL
);

-- Z.Z4 additions
CREATE TABLE IF NOT EXISTS iso_27018_pii_controls (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT NOT NULL UNIQUE,
  generated_at TEXT NOT NULL,
  csp_role TEXT NOT NULL DEFAULT 'pii_processor' CHECK (csp_role IN ('pii_controller','pii_processor','both')),
  evidence_json_sha256 TEXT NOT NULL,
  signature_b64 TEXT NOT NULL
);

-- Z.Z5 additions
CREATE TABLE IF NOT EXISTS iso_27701_pims_scope (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT NOT NULL UNIQUE,
  scope_statement TEXT NOT NULL,
  geographic_boundaries TEXT NOT NULL,    -- comma-separated ISO-3166 country codes
  pims_role TEXT NOT NULL CHECK (pims_role IN ('pii_controller','pii_processor','both')),
  pims_json_sha256 TEXT NOT NULL,
  signature_b64 TEXT NOT NULL,
  officer_user_id INTEGER REFERENCES users(id),
  officer_signed_at TEXT
);

CREATE TABLE IF NOT EXISTS eucs_submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT NOT NULL UNIQUE,
  eucs_level TEXT NOT NULL CHECK (eucs_level IN ('basic','substantial','high')),
  service_offering TEXT NOT NULL,
  scope_statement TEXT NOT NULL,
  cab_name TEXT,
  cab_country TEXT,
  ncca_supervising_country TEXT,
  package_zip_sha256 TEXT NOT NULL,
  signature_b64 TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft'
    CHECK (status IN ('draft','signed','submitted','assessed','certified','recertification-due','expired')),
  submitted_at TEXT,
  submission_receipt TEXT,
  certificate_id TEXT,
  certificate_date TEXT,
  certificate_expiry TEXT,
  officer_user_id INTEGER REFERENCES users(id),
  officer_signed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_eucs_status ON eucs_submissions(status);
```

REST endpoints (mounted by tracker `index.ts`):

```
GET    /api/iso/catalog                            — current Annex A catalog
GET    /api/iso/soa                                — list SoAs (versions)
GET    /api/iso/soa/:uuid                          — one SoA + its 93 control rows
POST   /api/iso/soa                                — draft a new SoA from current catalog + risk register
PATCH  /api/iso/soa/:uuid/controls/:control_id     — operator edits applicability/justification per row
POST   /api/iso/soa/:uuid/sign                     — officer signs SoA hash
POST   /api/iso/soa/:uuid/submit                   — record CAB submission receipt
GET    /api/iso/27017/coverage                     — per-cloud overlay coverage report
GET    /api/iso/27018/evidence                     — 27018 PII Processor evidence
GET    /api/iso/27701/pims                         — PIMS scope + Annex A/B controls
POST   /api/iso/27701/pims                         — draft PIMS
POST   /api/iso/27701/pims/:uuid/sign              — DPO signs
GET    /api/eucs/submissions                       — list EUCS submission packages
POST   /api/eucs/submissions                       — draft new EUCS submission at requested level
POST   /api/eucs/submissions/:uuid/package         — bundle the ZIP
POST   /api/eucs/submissions/:uuid/sign            — officer signs the ZIP
POST   /api/eucs/submissions/:uuid/submit          — record CAB submission receipt
```

UI surfaces (`tracker/client/src/pages/ISO.tsx`):

- SoA review page — 93 rows in a virtualised table with theme grouping
  + per-row inline edit for applicable / justification / implementation
  status + bulk-import from cross-loop evidence.
- Per-cloud overlay coverage page — AWS / GCP / Azure tabs with CLD.*
  controls + augmented 27002 status.
- 27018 evidence page — categories of PII + sub-processor disclosure
  + GDPR Article mapping.
- 27701 PIMS scope + Annex A/B controls page.
- EUCS submission page — level selector + evidence checklist + officer
  sign-off + submission receipt capture.
- Certification lifecycle page — Stage 1 / Stage 2 / certified /
  surveillance / recertification timeline.

---

## 23. Bundler `WELL_KNOWN` additions

```ts
{ role: 'iso-27001-catalog', filename: 'iso-27001-2022-annex-a.json',
  description: 'ISO/IEC 27001:2022 Annex A 93-control catalog + NIST 800-53 + FedRAMP crosswalk (LOOP-Z.Z1)' },
{ role: 'iso-27001-soa-json', filename: 'iso-27001-soa.json',
  description: 'Signed ISO/IEC 27001:2022 Statement of Applicability (LOOP-Z.Z2)' },
{ role: 'iso-27001-soa-docx', filename: 'iso-27001-soa.docx',
  description: '.docx rendering of ISO/IEC 27001:2022 Statement of Applicability (LOOP-Z.Z2)' },
{ role: 'iso-27017-coverage', filename: 'iso-27017-coverage.json',
  description: 'ISO/IEC 27017:2015 cloud-overlay coverage report (LOOP-Z.Z3)' },
{ role: 'iso-27018-evidence', filename: 'iso-27018-evidence.json',
  description: 'ISO/IEC 27018:2019 PII Processor evidence (LOOP-Z.Z4)' },
{ role: 'iso-27701-pims', filename: 'iso-27701-pims.json',
  description: 'ISO/IEC 27701:2019 PIMS document (LOOP-Z.Z5)' },
{ role: 'eucs-submission-package', filename: 'eucs-submission-package.zip',
  description: 'Signed EUCS submission package at the requested assurance level (LOOP-Z.Z5)' },
```

---

## 24. Standards-source refresh cadence

| Source | Refresh cadence | LOOP-Z trigger |
|---|---|---|
| ISO/IEC 27001:2022 | Per ISO update cycle (typically 5-7 years between editions) | Operator-driven; ISO publishes errata or new editions; Z.Z1 re-runs |
| ISO/IEC 27002:2022 | Same as 27001 | Operator-driven |
| ISO/IEC 27017:2015 | Reissue pending (rumoured 2027-2028) | Operator-driven |
| ISO/IEC 27018:2019 | Reissue pending | Operator-driven |
| ISO/IEC 27701:2019 | Possible alignment with 27001:2022 in next revision | Operator-driven |
| ENISA EUCS Candidate | EU Commission adoption pending; expected 2026-2027 | LOOP-Z monitors EUR-Lex OJ; operator re-runs `scripts/extract-enisa-eucs.mjs` |
| NIST OLIR mapping | Per NIST update cadence | LOOP-Z monitors csrc.nist.gov; operator re-runs `scripts/extract-iso-27001-2022.mjs` |
| GDPR | Per EU regulatory amendment | EUR-Lex monitoring; operator re-runs |

Stale catalog (older than 365 days) triggers a `coverage:stale` log
entry; strict mode exits non-zero.

---

## 25. Logging & telemetry policy (REO-compliant)

Z.Z1 through Z.Z5 emit structured log lines (via the existing pino
logger). The fields are:

| Field | Meaning |
|---|---|
| `slice` | `Z.Z1` / `Z.Z2` / `Z.Z3` / `Z.Z4` / `Z.Z5` |
| `event` | `catalog:emit` / `soa:emit` / `coverage:compute` / `pii:emit` / `pims:emit` / `eucs:package` / `eucs:sign` / `cab:submit` |
| `run_id` | UUID for the orchestrator run |
| `evidence_path` | the file the event traces to |
| `control_id` | when applicable |
| `severity` | log severity (info / warn / error) |

Log entries are forwarded to the existing SIEM push (LOOP-F.F3 OCSF
format) when configured. They MUST NOT contain redistributed ISO text
(licensed copyright); only structural metadata (control IDs, counts,
status, hashes).

---

## 26. Apache-2.0 clean-room provenance

LOOP-Z's redistributed catalogs include:

- ISO/IEC control IDs (A.5.1, A.8.24, CLD.6.3.1, etc.) — facts; not
  copyrightable.
- ISO/IEC control short names — short factual labels; assumed fair-use
  for naming the control by its canonical identifier.
- NIST 800-53 control mappings — public-domain (NIST publications).
- NIST OLIR crosswalk — public-domain.
- FedRAMP KSI mappings — public-domain.
- EUCS scheme structure — ENISA publication; openly available.
- GDPR / EU Cybersecurity Act references — EU official journal of
  record; freely redistributable.

LOOP-Z does NOT redistribute:

- The full text of ISO/IEC 27001 / 27002 / 27017 / 27018 / 27701
  control descriptions (the operator's licensed copy is consulted).
- The full text of any non-public ENISA EUCS work-in-progress draft.

This is the same approach used by GoComply/oscalkit, NIST's own OLIR
program, and CSA's CCM cross-mapping — all of which reference ISO
controls by ID without redistributing the licensed standard text.

The `iso-27001-overrides.yaml` operator-supplied additions are
operator-licensed; LOOP-Z neither demands nor encodes a particular
upstream license. Operator carries the responsibility for their own
overrides.

---

## 27. Performance envelope

LOOP-Z must complete within these wall-clock budgets on a default
runner (8 vCPU, 16 GB RAM):

| Slice | Phase | Budget |
|---|---|---|
| Z.Z1 | Catalog extract + crosswalk join | ≤ 90 sec |
| Z.Z1 | Sign + write snapshot | ≤ 5 sec |
| Z.Z2 | SoA emit (93 controls) + risk-register join | ≤ 60 sec |
| Z.Z2 | SoA `.docx` OOXML render | ≤ 10 sec |
| Z.Z3 | Per-cloud coverage compute (per provider) | ≤ 90 sec per provider; total ≤ 5 min for all three |
| Z.Z4 | 27018 evidence emit | ≤ 30 sec |
| Z.Z5 | PIMS emit | ≤ 30 sec |
| Z.Z5 | EUCS package ZIP build | ≤ 15 sec |

Total LOOP-Z execution: ≤ 10 min for a typical large SaaS CSP with
AWS + GCP + Azure presence + EU + U.S. + APAC scope.

---

## 28. Versioning

The catalog snapshot schema is versioned independently from the SoA /
27017 coverage / 27018 evidence / PIMS / EUCS submission schemas, all
under `cloud-evidence/schemas/`:

- `iso-27001-2022-annex-a-v1.json` — catalog
- `iso-27001-soa-v1.json` — SoA
- `iso-27017-coverage-v1.json` — 27017 coverage
- `iso-27018-evidence-v1.json` — 27018 evidence
- `iso-27701-pims-v1.json` — PIMS
- `eucs-submission-v1.json` — EUCS submission

Schema v2 will be introduced if (a) ISO publishes a new edition of any
constituent standard, (b) ENISA adopts EUCS with structural changes,
(c) NIST OLIR mapping schema changes substantively, or (d) cosign /
Rekor adds a new attestation field. Schema v1 is forward-compatible
with additive-only changes.

---

## 29. End-to-end happy path (a worked example)

A SaaS CSP "ExampleCorp" runs the FedPy orchestrator on 2026-06-07
with `--international-equivalence --eucs-level=substantial`. ExampleCorp
has 3 EU enterprise customers, 2 Japanese-government RFP submissions
pending, and a multi-cloud (AWS + GCP + Azure) deployment.

1. **Orchestrator step 1** — `node cli.js --collect --bundle-submission
   --international-equivalence --eucs-level=substantial`
2. **Z.Z1** runs `scripts/extract-iso-27001-2022.mjs`:
   - Loads `data/iso-27001-2022-annex-a.json` (committed pre-extracted
     ID + short-name list).
   - Joins with `core/control-benchmark.ts` to populate NIST 800-53
     crosswalk per control.
   - Joins with `data/frmr-ksi-catalog.json` to populate FedRAMP KSI
     crosswalk.
   - Loads NIST OLIR informative mapping JSON (operator-supplied or
     auto-fetched from csrc.nist.gov when available).
   - Loads operator overrides from `iso-27001-overrides.yaml` (empty
     for ExampleCorp).
   - Ed25519 signature applied. Catalog snapshot written.
3. **Z.Z2** drafts the SoA:
   - Reads catalog (93 controls).
   - Reads LOOP-B risk register (12 active risks, 3 accepted).
   - For each control, looks up cross-loop evidence: LOOP-T (SSDF),
     LOOP-W (prohibited-vendor screening), LOOP-R (PQC).
   - Default applicability: all 93 controls are applicable to a
     SaaS CSP serving enterprise customers.
   - Implementation status: 78 implemented, 11 partial, 4 planned.
   - Operator (CISO, Jane Doe) opens the tracker SoA review page,
     reviews each row, edits justifications, signs (TOTP-protected
     operator key).
   - `.docx` + signed `.json` emitted.
4. **Z.Z3** computes per-cloud coverage:
   - Reads `core/inventory.ts` for AWS / GCP / Azure inventory.
   - For each CLD.* control (7 total), checks evidence in inventory
     (segregation tags, customer-asset-removal evidence, etc.).
   - For each augmented 27002 control (37 total), checks per-cloud
     implementation status.
   - Emits 3 coverage reports: `iso-27017-coverage-aws.json`,
     `iso-27017-coverage-gcp.json`, `iso-27017-coverage-azure.json`.
5. **Z.Z4** emits 27018 evidence:
   - Reads `core/subprocessors-sheet.ts` for sub-processor list.
   - Joins with LOOP-U privacy crosswalk (GDPR Articles).
   - Emits `iso-27018-evidence.json` with 11 PII-control rows + 18
     sub-processors disclosed.
6. **Z.Z5** emits PIMS + EUCS package:
   - Reads SoA + 27017 coverage + 27018 evidence.
   - Operator (DPO, Charlotte Müller) opens the PIMS scope page,
     enters: geographic_boundaries = ["EU-27", "US", "JP"],
     pims_role = "pii_processor", categories_of_pii = [...].
   - Data-transfers section: enters SCC-based transfers for the US
     destination (since EU-US transfers require SCC + supplementary
     measures post-Schrems II).
   - PIMS Annex A controls (controllers) + Annex B controls
     (processors) populated.
   - DPO signs PIMS document.
   - EUCS submission package: operator selects level=substantial.
   - Z.Z5 packager bundles ZIP: MANIFEST.json + SoA `.docx` + `.json` +
     `.sig` + 27017 coverage × 3 cloud providers + 27018 evidence +
     PIMS + README.md.
   - Operator (CISO) signs the ZIP.
7. **Bundler**: A.A4 picks up all new roles in the submission bundle.
   The 3PAO + the CAB both receive parallel copies.
8. **Operator submission step (manual)**:
   - SoA `.docx` + signed `.json` emailed to the CAB for Stage 1 audit
     scheduling → receipt id captured in tracker.
   - EUCS ZIP uploaded to EU NCCA portal (operator-supplied URL) →
     receipt id captured.
9. **Q.Q1**: Marketplace badge update — "ISO 27001:2022 Certification
   in Progress (Stage 1 scheduled 2026-08-15)" + "EUCS Substantial
   Submitted 2026-06-29".

The full end-to-end flow takes ~ 8 min of orchestrator time + ~ 90 min
of operator review time (SoA per-row justification editing is the
longest manual step). All artifacts are signed, timestamped, and ready
for the CAB.

---

## 30. Risk-acceptance & operator-override policy

When a positive match in LOOP-Z is identified between a Federal-published
constraint (e.g. LOOP-W prohibited vendor in the supply-chain Annex A
control A.5.21) and the CSP's operations, the operator:

1. Opens the affected control in the tracker SoA review page.
2. Selects "implementation_status = partial" and adds a justification
   citing the risk-register row.
3. Links the risk-register entry's `risk_id` (created in LOOP-B) and
   the planned remediation deadline.
4. The narrative + the operator's signed attestation is persisted as
   evidence; the SoA emits with `partial` status. POA&M item emitted.

This is REO-compliant: no automation makes the exemption decision; the
operator does, with audit trail.

CAB-side acceptance criteria for "partial" controls vary by CAB; some
CABs accept partial controls in the Stage 1 review and revisit in
Stage 2; others require closure before Stage 2. The CAB-side
acceptance is captured in `iso_27001_soa.iso_certificate_status`
field transitions.

---

## 31. Edge cases (additional, beyond §7.3 adversarial cases)

**E1.** Catalog reissued mid-flight. ISO publishes 27001:2027
mid-quarter. LOOP-Z's catalog snapshot includes `iso_edition` field;
loader refuses to operate on a stale edition once operator confirms
the upgrade.

**E2.** Operator runs LOOP-Z in an air-gapped environment where ISO
preview pages are unreachable. The catalog is committed pre-extracted
(`data/iso-27001-2022-annex-a.json`) so no Internet access is required
for the extractor. The operator's local copy of the licensed standard
is consulted for full control text.

**E3.** A discovered "not applicable" control conflicts with a risk
register row that requires the control. The SoA emitter detects the
conflict (control marked "not applicable" but risk register references
the control as a mitigation) and emits diagnostic
`coverage:soa-risk-conflict`; orchestrator exits non-zero. Operator
must resolve.

**E4.** A single Annex A control maps to multiple NIST 800-53
controls with mixed relationship types. Z.Z1's loader stores all
mappings; the SoA emitter uses the most-restrictive (smallest)
relationship type for evidence-completeness checks.

**E5.** SoA signature corrupted in storage. The loader refuses to
operate. The orchestrator exits non-zero. Operator investigates:
usually a key-rotation event without a new SoA emission.

**E6.** Operator marks all 93 controls "implemented" without
evidence references. Z.Z2 emitter requires at least one
evidence_reference per "implemented" control; emits REQUIRES-OPERATOR-INPUT
for each empty row.

**E7.** A LOOP-V HIPAA breach reference also surfaces as a 27018 PII
breach. The two incidents are cross-referenced via `incident_id`. The
GDPR Article 33/34 breach-notification timer (72 hours) is much
shorter than HIPAA's 60-day timer; the GDPR timer expires first.
LOOP-Z's PIMS emitter pulls the latest GDPR-aligned breach-history
from the tracker DB.

**E8.** Operator changes the EUCS level mid-stream (substantial →
high). The package's `eucs_level` field changes; the evidence
checklist re-runs; pentest_report is now REQUIRED; submission blocked
until pentest evidence supplied.

**E9.** CAB accreditation expires during the certification cycle. The
tracker DB carries `cab_accreditation_expiry` field; UI surfaces a
warning when within 60 days of expiry; SoA emit continues but
operator is reminded.

**E10.** Multi-cloud deployment with one cloud missing CLD.9.5.1
(virtual segregation) evidence. Z.Z3 emits the partial-coverage report;
SoA's `cloud_overlay.cld_controls_status.CLD.9.5.1` reflects "partial";
POA&M item emitted for the affected cloud.

---

## 32. Final completion gate (loop-level)

LOOP-Z is "done" when ALL of:

1. ✅ All five slices' tests pass.
2. ✅ All five slices' artifacts are in the submission bundle catalogue.
3. ✅ The first catalog snapshot has been emitted and verified
   (control_count == 93).
4. ✅ A simulated end-to-end run (with fixture risk-register +
   fixture inventory) produces a valid SoA + valid 27017 coverage
   reports for all 3 cloud providers + valid 27018 evidence + valid
   PIMS + a valid EUCS Substantial submission package.
5. ✅ STATUS.md, CHANGELOG.md, LOOP-Z-SPEC.md (this file),
   LOOP-Z-RISKS.md, and the five per-slice docs are all consistent.
6. ✅ The dependency-graph edge additions are in DEPENDENCY-GRAPH.md.
7. ✅ The glossary deltas are in GLOSSARY.md.
8. ✅ The FIFTH-PASS-AUDIT.md confirms no remaining LOOP-Z gaps.

---

## 33. Cross-loop coordination — when do Z + U + V co-fire?

| Discovery scenario | Z fires? | U fires? | V fires? | Cross-reference required? |
|---|---|---|---|---|
| Pure U.S. Federal customer; no commercial / international book | NO | NO (FedRAMP Privacy Overlay covers; LOOP-M handles) | YES if HIPAA-covered customer | LOOP-M only |
| Pure commercial; no EU; no healthcare | YES (Z.Z1 + Z.Z2; optional Z.Z3) | NO | NO | n/a |
| Commercial + EU enterprise customer (no PHI) | YES (all five Z slices) | YES (LOOP-U GDPR-side) | NO | cross-reference Z.Z4/Z.Z5 ↔ LOOP-U |
| Commercial + EU enterprise + HIPAA-covered customer | YES (all five Z slices) | YES (LOOP-U GDPR + LOOP-U HIPAA crosswalk) | YES (LOOP-V HIPAA Security Rule) | three-way cross-reference Z.Z4 ↔ LOOP-U ↔ LOOP-V |
| EU public-sector customer demanding EUCS Substantial | YES (Z.Z5 EUCS submission required) | YES | depends | EUCS submission cites all evidence |
| Japanese government customer demanding ISMAP | YES (Z.Z1 + Z.Z2 + Z.Z3 as foundation; future LOOP-ISMAP extension takes over) | depends | depends | LOOP-Z is the upstream catalog |

LOOP-Z's PIMS emitter consults the tracker for any open LOOP-U
privacy-incident referencing the same `incident_id` and embeds the
LOOP-U incident UUID in the PIMS `incident_register_reference[]`
field. LOOP-U's emitter does the reciprocal embedding on its side.

---

## 34. Resume-from-fresh-session checklist

A new Claude / human session opening LOOP-Z must, in order:

1. Read this file (LOOP-Z-SPEC.md) in full.
2. Read `cloud-evidence/CLAUDE.md` for the REO standard.
3. Read `cloud-evidence/docs/STATUS.md` to find the next slice (line
   "Overall → Next priority").
4. Read `cloud-evidence/docs/loops/LOOP-Z-RISKS.md`.
5. Read the relevant `cloud-evidence/docs/slices/Z/Z.ZN.md` for the
   slice in question — full per-slice context lives there.
6. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
7. Read `cloud-evidence/docs/IMPLEMENTATION-LOG-TEMPLATE.md`.
8. Execute the slice under the REO standard.
9. Follow the 7-step completion procedure atomically with the final
   commit, then push to origin/main.

No prior conversation history is required. This file plus the cited
per-slice doc is sufficient.

---

## 35. Source-quote re-affirmation (for CAB trust)

Every verbatim quote of public-domain text in this file (ENISA EUCS
factsheet, EU Cybersecurity Act, GDPR, NIST OLIR program description)
came from an officially-published source URL accessed 2026-06-07. The
implementer of any slice MUST re-fetch the cited URL at slice-
implementation time and confirm the quote is unchanged. If a quote
has changed (e.g. EU adopts EUCS as a delegated act, GDPR is amended,
NIST OLIR updates schema), the implementer:

1. Captures the new verbatim text in
   `cloud-evidence/docs/sources/<source>-YYYYMMDD.txt`.
2. Updates the relevant per-slice doc with the new quote.
3. Updates LOOP-Z-RISKS.md with the change.
4. Updates this SPEC's §2 in the same commit.
5. Updates CHANGELOG.md noting the standards change.

This is the "authoritative-source drift" risk category from §8. It's
why LOOP-Z's risks register has it as a named category.

For ISO-licensed text (27001, 27002, 27017, 27018, 27701), the
implementer relies on the operator's licensed copy of the standard;
LOOP-Z does not redistribute the licensed text. The implementer
confirms the control IDs + canonical short names are unchanged
against the operator's licensed copy.

---

## 36. ISMAP / IRAP / national-government scheme reuse map

LOOP-Z's catalog + SoA + per-cloud overlay are the foundation for
several non-EU government-cloud schemes. The following table summarises
the reuse pattern; per-scheme emitters are out of LOOP-Z's scope and
are deferred to future loops.

| Scheme | Country | LOOP-Z reuse | Specific additions needed (future loop) |
|---|---|---|---|
| ISMAP | Japan | Z.Z1 + Z.Z3 + Z.Z4 catalog reused; SoA format ISMAP-specific | Japanese-government additions: GBOM (Generation Based Operations Maturity), JIS Q 27017 alignment, ISMAP-specific control IDs (a-prefixed) |
| IRAP | Australia | Z.Z1 + Z.Z3 + Z.Z4 catalog reused; ISM control mapping | ISM (Information Security Manual) control IDs; OFFICIAL: Sensitive / PROTECTED / SECRET / TOP SECRET classification levels |
| MTCS | Singapore | Z.Z1 + Z.Z3 + Z.Z4 catalog reused | MTCS-specific cloud-security level (CSL) mapping (Level 1 / Level 2 / Level 3) |
| CSCF (UAE) | UAE | Z.Z1 + Z.Z3 + Z.Z4 catalog reused | UAE Cybersecurity Council CSCF control mapping |
| K-ISMS-P | South Korea | Z.Z1 + Z.Z3 + Z.Z4 + Z.Z5 reused; Korean privacy alignment | K-ISMS-P specific control mapping + PIPA (Personal Information Protection Act) alignment |
| CCCS Medium Cloud (Canada) | Canada | Z.Z1 + Z.Z3 reused; CCCS-specific controls overlay | CCCS Cloud Profile (ITSG-33 + ITSG-22) mapping |
| CERT-In (India) | India | Z.Z1 reused; CERT-In incident-reporting overlay | CERT-In specific incident-reporting cadence (6-hour rule) — extension to LOOP-G.G2 |

Operators serving any of these markets can re-use LOOP-Z's catalog
+ SoA as a foundation, then layer the country-specific additions in a
follow-on loop. This pattern preserves LOOP-Z's scope discipline (EU
EUCS only) while making the catalog re-usable.

---

## 37. CSA STAR + Cloud Controls Matrix reuse (deferred)

The Cloud Security Alliance's STAR Registry consumes CSA Cloud Controls
Matrix (CCM) v4 self-attestations. CCM v4 is heavily ISO-aligned and
includes a published cross-reference to ISO/IEC 27001 + 27017 + 27018.
A CSP serving the public cloud market often emits a CSA STAR Level 1
self-attestation in addition to (or instead of) ISO certification.

LOOP-Z does NOT emit a CSA STAR self-attestation directly; however,
the Z.Z1 catalog includes a `crosswalk_csa_ccm_v4` field per Annex A
control row (informative; operator-supplied or auto-fetched from CSA's
published cross-reference table).

A future LOOP-Z2 ("CSA STAR + CCM Self-Attestation") could emit:

- CSA CCM v4 self-attestation in canonical JSON
- CSA CAIQ (Consensus Assessments Initiative Questionnaire) responses
- CSA STAR Registry submission package

These are deferred. LOOP-Z's catalog is the foundation; the emitter
is not in scope.

---

## 38. Concluding notes

LOOP-Z exists because the U.S.-Federal compliance suite (FedRAMP +
NIST 800-53) does not, by itself, satisfy the international-equivalence
demands a SaaS CSP faces in the global marketplace. The FOURTH-PASS-AUDIT.md
surfaced this as the highest-priority international gap. LOOP-Z closes
it with five slices:

- **Z.Z1** — the ISO 27001:2022 Annex A control catalog substrate +
  NIST 800-53 + FedRAMP KSI crosswalk.
- **Z.Z2** — the Statement of Applicability emitter per clause 6.1.3(d).
- **Z.Z3** — the per-cloud (AWS / GCP / Azure) overlay per ISO/IEC 27017.
- **Z.Z4** — the PII-processor evidence per ISO/IEC 27018:2019.
- **Z.Z5** — the PIMS document per ISO/IEC 27701 + the ENISA EUCS
  Candidate Scheme submission package.

Together these slices give FedPy a complete, REO-compliant, signed-
and-traceable, international-equivalence pipeline. Every byte traces
to a standards-published source (with the ISO-copyright caveat
described in §1.5) or to operator-supplied configuration. Every
emission is operator-reviewed before submission. Every artifact is
part of the submission bundle the CAB sees.

The catalog + SoA + per-cloud overlay are reusable foundations for
ISMAP, IRAP, MTCS, CSCF, K-ISMS-P, CCCS, and CERT-In — future loops
can layer country-specific additions on top.

Open the Z.Z1 per-slice doc to begin.
