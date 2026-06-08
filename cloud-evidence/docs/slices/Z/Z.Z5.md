---
slice_id: Z.Z5
title: ISO/IEC 27701 PIMS + ENISA EUCS Candidate Scheme — Privacy Information Management System + EU Cybersecurity Certification submission package
loop: Z
status: proposed
commit: TBD
completed_date: —
depends_on:
  - Z.Z1                                # ISO/IEC 27001:2022 Annex A crosswalk (catalog + NIST 800-53 + FedRAMP KSI)
  - Z.Z2                                # SoA emitter — EUCS Substantial + High require the full signed SoA as a packaged artifact
  - Z.Z3                                # ISO/IEC 27017:2015 cloud overlay — EUCS Substantial + High require 27017 evidence
  - Z.Z4                                # ISO/IEC 27018:2019 PII Processor controls — EUCS High requires 27018 evidence; PIMS Annex B reuses
  - LOOP-U                              # Privacy frameworks crosswalk — PIMS GDPR Annex F + EUCS package both reference GDPR articles owned by LOOP-U
  - LOOP-A.A4                           # Submission bundler — EUCS ZIP + PIMS evidence envelope land in the bundle catalogue
  - LOOP-A.A5                           # Ed25519 + RFC 3161 signing pipeline (signs the PIMS envelope AND signs the EUCS ZIP archive)
  - LOOP-Q.Q1                           # Marketplace metadata — "EUCS Substantial" + "ISO 27701 PIMS certified" badges surface from Z.Z5 outputs (Z.Z5 *blocks* Q.Q1 for those badges)
blocks: []
estimated_effort: medium (~5-7 working days for single implementer)
last_updated: 2026-06-08
applicable_conditional: true
condition: |
  Z.Z5 is conditional. It activates when the CSP either (a) seeks
  EU EUCS certification at any assurance level (Basic / Substantial /
  High) — typically driven by an EU public-sector procurement
  questionnaire under EU Cybersecurity Act (Regulation 2019/881)
  Article 56, OR (b) extends the ISMS with a Privacy Information
  Management System per ISO/IEC 27701:2019 — typically driven by a
  GDPR-counterparty contractual demand for documented Article 28
  processor assurance + Article 32 technical-and-organisational
  measures evidence. The orchestrator gates Z.Z5 behind the
  `--iso-z-z5` flag (or `CLOUD_EVIDENCE_Z_Z5=1`); the EUCS path is
  further gated behind `--eucs-level=basic|substantial|high` and the
  PIMS path behind `--pims-mode=processor|controller|both` (default
  `processor` for the typical CSP role).

  Skip-conditions: when the CSP serves U.S.-Federal customers only,
  has no EU book of business, and processes no EU data-subject PII,
  Z.Z5 stays dormant. The fourth-pass audit flagged false-skip as the
  highest-risk failure mode here: a CSP that processes a single EU
  data subject's PII is GDPR-in-scope, which transitively activates
  Z.Z4 + Z.Z5. The operator declares the trigger via
  `org-profile.yaml.gdpr_in_scope: true|false` AND
  `org-profile.yaml.eucs_target_level: basic|substantial|high|none`.
trigger_flag: "--iso-z-z5"
trigger_env: CLOUD_EVIDENCE_Z_Z5
---

# Z.Z5 — ISO/IEC 27701 PIMS + ENISA EUCS Candidate Scheme submission package

> The fifth and final slice of LOOP-Z. Z.Z5 packages the cumulative
> output of Z.Z1 (Annex A catalog), Z.Z2 (Statement of Applicability),
> Z.Z3 (ISO/IEC 27017 cloud overlay), and Z.Z4 (ISO/IEC 27018 PII
> Processor controls) into two distinct but related artifact families:
>
> 1. An **ISO/IEC 27701:2019 PIMS evidence envelope** — extends the
>    ISMS with a Privacy Information Management System. Splits controls
>    into PII Controller (Annex A of 27701) and PII Processor (Annex B
>    of 27701) sets. References the ISMS clauses 4-10 + the 27002
>    control set + the 27018 PII-processor controls.
> 2. An **ENISA EUCS submission ZIP** — packages the SoA + Annex A
>    controls evidence + assurance-level declaration + scope statement
>    + Conformity Assessment Body (CAB) identification per the ENISA
>    EUCS Candidate Scheme (March 2024 draft) at the requested
>    assurance level (Basic / Substantial / High).
>
> Both artifacts are Ed25519-signed (via LOOP-A.A5) and RFC 3161
> timestamped. Both flow into the LOOP-A.A4 submission bundler
> catalogue under new well-known roles `iso-27701-pims-evidence` +
> `eucs-submission-package`. Both register against the tracker DB
> for operator review and submission-receipt capture (REO Rule 4
> forbids auto-submission; the operator submits, the tracker records).
>
> Z.Z5 is the operational fulcrum of LOOP-Z's international-equivalence
> story: Z.Z1 through Z.Z4 build the per-standard fact bases; Z.Z5 is
> what an EU Commission Conformity Assessment Body actually consumes
> when it certifies the CSP against EUCS Substantial, and what an
> ISO 27001 + 27701 joint-certification CAB consumes during Stage 1
> documentation review of the combined ISMS-with-PIMS.

---

## 1. Mission

Z.Z5 reads the four predecessor slice outputs — the signed Z.Z1
Annex A catalog at `data/iso-27001-2022-annex-a.json`, the signed
Z.Z2 SoA at `out/iso-27001-soa-{cspname}-{date}.json` + `.docx`, the
signed Z.Z3 per-cloud coverage envelopes at
`out/iso-27017-coverage-aws.json` + `-gcp.json` + `-azure.json`, and
the signed Z.Z4 PII-processor evidence envelope at
`out/iso-27018-evidence.json` — and emits a PIMS evidence envelope
keyed to the operator-declared PII role (`processor`, `controller`,
or `both`) plus an EUCS submission ZIP at the operator-requested
assurance level. The PIMS envelope is the *organisation-of-record*
artifact for ISO 27701; the EUCS ZIP is the *submission-of-record*
artifact for the EU Cybersecurity Certification Scheme.

The PIMS envelope's `pims_scope` block captures the scope statement
required by ISO/IEC 27701 clause 5.2.1 ("Determining the scope of the
PIMS") — the organisational units in scope, the geographic boundaries
(important for GDPR territorial-scope per Article 3), the categories
of PII processed, the categories of PII data subjects, the lawful
basis claimed (Article 6(1)(a)-(f) of GDPR), the cross-border-transfer
mechanisms (Article 44-50: SCC, adequacy decision, BCR, or Article 49
derogation), and the sub-processor list. The envelope's
`pims_controls` block enumerates each 27701 Annex A control (PII
Controller) and Annex B control (PII Processor) with its disposition
(`applicable / not applicable`), justification, and evidence reference
(pointing back into Z.Z4's 27018 evidence + Z.Z2's SoA). The
envelope's `gdpr_article_mapping` block (driven by ISO 27701 Annex F
mapping) cross-references each PIMS control to the relevant GDPR
articles 5-50 with their EUR-Lex URLs.

The EUCS submission ZIP packages, per the operator-requested
assurance level, the artifact bundle the ENISA EUCS Candidate Scheme
expects a Conformity Assessment Body to consume. EUCS Basic is the
lightest level (self-assessment + light CAB review) and requires only
a subset of ISO 27001 Annex A controls + a self-attestation. EUCS
Substantial (the most-commonly-requested level for commercial cloud
buyers) requires the full ISO 27001 Annex A + the ISO 27017 cloud
overlay + an independent CAB-led formal audit. EUCS High (national-
security-adjacent) requires ISO 27001 + 27017 + 27018 + 27701 +
independent CAB review + penetration testing + technical audit. The
EUCS ZIP carries a top-level manifest (`eucs-manifest.json`),
the SoA from Z.Z2, the per-cloud coverage envelopes from Z.Z3, the
PII-processor evidence from Z.Z4, the PIMS envelope from Z.Z5
itself, an EUCS scope statement, a CAB-identification block (the
CSP-side declaration of *which* CAB the operator engaged), and an
optional penetration-testing report reference (REQUIRES-OPERATOR-INPUT
for EUCS High). The ZIP is signed at the archive level with Ed25519
and timestamped via RFC 3161; the manifest carries SHA-256 hashes of
every constituent file.

Z.Z5 also surfaces a Marketplace-badge eligibility decision into
LOOP-Q.Q1: when the signed EUCS submission ZIP has been emitted at
Substantial-or-better AND the operator has captured a CAB
acknowledgement-receipt id in the tracker UI (signed audit log
entry), Q.Q1 can emit the "EUCS Substantial Certified" or "EUCS
High Certified" badge on the FedRAMP Marketplace listing with a URL
to the signed envelope. Likewise for the "ISO 27701 PIMS Certified"
badge once the PIMS Stage 2 audit completes (operator captures the
CAB certificate id via tracker UI). Z.Z5 *blocks* the Q.Q1 badges
on the EU + PIMS side; Z.Z2 blocks Q.Q1 for the ISO 27001 badge.

Z.Z5 emits POA&M findings via LOOP-A.A1 for any EUCS-required
artifact that is missing (e.g. operator requested EUCS Substantial
but Z.Z3 has not been run for a configured cloud, so the per-cloud
coverage envelope is absent — Z.Z5 emits a POA&M item
`EUCS-ARTIFACT-MISSING` referencing the missing Z.Z3 invocation).
Z.Z5 emits POA&M items for PIMS Annex B controls (PII Processor)
that are non-conformant when the operator's `pims_mode` includes
`processor` (the default). The POA&M items reference the 27701
control id (e.g. `B.8.4` "Records related to processing PII") and
the verbatim ISO control-name reference (the verbatim short name
only; full text is not redistributed per LOOP-Z's REO + copyright
posture).

---

## 2. Authoritative sources

Every URL accessed 2026-06-08 (date-of-access locked at the spec
authoring run). Verbatim quotes appear in Markdown blockquotes;
where the live ISO source is paywalled, the implementer references
the ISO standard's canonical URL + the publicly-available preview
pages + secondary academic / certification-body sources. Where the
ENISA / EUR-Lex / NIST source is freely available, the implementer
quotes verbatim from the official source.

LOOP-Z-SPEC.md §1.5 (the LOOP-Z REO-locked authoritative scope
guard) governs the redistributability posture: full ISO standard
text is NOT redistributed; the operator maintains their own
licensed copy and Z.Z5's catalogs reference controls by ID + short
name only.

### 2.1 ISO/IEC 27701:2019 — Privacy Information Management System (PIMS)

URL: https://www.iso.org/standard/71670 (accessed 2026-06-08).
Status: Published August 2019. Reference number `ISO/IEC 27701:2019`.
Standard is paid (~CHF 158 per ISO's e-store); full text not
redistributable; structural facts + control identifiers are factual
and reproducible per LOOP-Z-SPEC.md §1.5.

Publicly-available abstract text (from ISO's standard page preview):

> "This document specifies requirements and provides guidance for
> establishing, implementing, maintaining and continually improving
> a Privacy Information Management System (PIMS) in the form of an
> extension to ISO/IEC 27001 and ISO/IEC 27002 for privacy management
> within the context of the organization."

> "This document specifies PIMS-related requirements and provides
> guidance for PII controllers and PII processors holding
> responsibility and accountability for PII processing."

> "This document is applicable to all types and sizes of organizations,
> including public and private companies, government entities and
> not-for-profit organizations, which are PII controllers and/or PII
> processors processing PII within an ISMS."

The 27701 structural integration with 27001 (publicly-available from
ISO's preview + secondary sources):

| 27701 Component | Source standard | Notes |
|---|---|---|
| Clauses 5.1-5.8 | Extension of 27001 clauses 4-10 (ISMS) | PIMS-specific augmentations to the ISMS clauses |
| Clauses 6.1-6.15 | Extension of 27002:2013 clauses 5-18 | PIMS-specific augmentations to the 27002 control guidance (NB: 27701 was authored against 27002:2013; a 27701 revision targeting 27002:2022 is anticipated) |
| Annex A | PIMS-specific controls for PII Controllers | Approx. 31 additional controls |
| Annex B | PIMS-specific controls for PII Processors | Approx. 18 additional controls |
| Annex C | Mapping to ISO/IEC 29100 privacy framework principles | Informative |
| Annex D | Mapping to GDPR (Regulation (EU) 2016/679) | Informative; references Articles 5-50 |
| Annex E | Mapping to ISO/IEC 27018 + ISO/IEC 29151 | Informative |
| Annex F | Application of ISO/IEC 27701 to ISO/IEC 27001:2013 | Informative |

The PIMS structural innovation is the explicit PII Controller vs PII
Processor split. This split matters because:

- A typical CSP (the FedPy operator population) is a **PII Processor**
  for its customers' PII (the customer is the PII Controller). Annex B
  applies.
- The same CSP is a **PII Controller** for its own employee PII (HR
  records, internal authentication credentials, etc.). Annex A applies
  for that subset.
- A SaaS-type CSP that lets end-users register accounts directly
  (e.g. consumer SaaS) is a **PII Controller** for those end-user
  accounts. Annex A applies.

Z.Z5's `pims_mode` configuration accepts `processor`, `controller`,
or `both`; default `processor` aligns with the typical CSP role but
the operator MUST review and confirm.

ISO 27701 Annex F (mapping to ISO 27001:2013) is publicly-available
in summary form; Annex D (GDPR mapping) is the operational mapping
Z.Z5 consumes. Annex D maps each PIMS control to the relevant GDPR
Article(s); the mapping covers GDPR Articles 5, 6, 7, 8, 12, 13, 14,
15, 16, 17, 18, 19, 20, 21, 22, 24, 25, 26, 27, 28, 29, 30, 31, 32,
33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
50.

The 27701 Annex B (PII Processor) control identifiers (publicly-
summarised from ISO's preview text + secondary academic sources):

| Annex B clause | Short name (factual identifier) |
|---|---|
| B.7.2.1 | Identify and document purpose |
| B.7.2.2 | Identify lawful basis |
| B.7.2.3 | Determine when and how consent is to be obtained |
| B.7.2.4 | Obtain and record consent |
| B.7.2.5 | Privacy impact assessment |
| B.7.2.6 | Contracts with PII processors |
| B.7.2.7 | Joint PII controller |
| B.7.2.8 | Records related to processing PII |
| B.7.3.1 | Determining and fulfilling obligations to PII principals |
| B.7.3.2 | Determining information for PII principals |
| B.7.3.3 | Providing information to PII principals |
| B.7.3.4 | Providing mechanism to modify or withdraw consent |
| B.7.3.5 | Providing mechanism to object to PII processing |
| B.7.3.6 | Access, correction and/or erasure |
| B.7.3.7 | PII controllers' obligations to inform third parties |
| B.7.3.8 | Providing copy of PII processed |
| B.7.3.9 | Handling requests |
| B.7.3.10 | Automated decision making |
| B.7.4.1 | Limit collection |
| B.7.4.2 | Limit processing |
| B.7.4.3 | Accuracy and quality |
| B.7.4.4 | PII minimization objectives |
| B.7.4.5 | PII de-identification and deletion at the end of processing |
| B.7.4.6 | Temporary files |
| B.7.4.7 | Retention |
| B.7.4.8 | Disposal |
| B.7.4.9 | PII transmission controls |
| B.7.5.1 | Identify basis for PII transfer between jurisdictions |
| B.7.5.2 | Countries and international organizations to which PII can be transferred |
| B.7.5.3 | Records of transfer of PII |
| B.7.5.4 | Records of PII disclosure to third parties |
| B.8.2.1 | Customer agreement |
| B.8.2.2 | Organization's purposes |
| B.8.2.3 | Marketing and advertising use |
| B.8.2.4 | Infringing instruction |
| B.8.2.5 | Customer obligations |
| B.8.2.6 | Records related to processing PII |
| B.8.3.1 | Obligations to PII principals |
| B.8.4.1 | Temporary files |
| B.8.4.2 | Return, transfer or disposal of PII |
| B.8.4.3 | PII transmission controls |
| B.8.5.1 | Basis for PII transfer between jurisdictions |
| B.8.5.2 | Countries and international organizations to which PII can be transferred |
| B.8.5.3 | Records of PII disclosure to third parties |
| B.8.5.4 | Notification of PII disclosure requests |
| B.8.5.5 | Legally binding PII disclosures |
| B.8.5.6 | Disclosure of subcontractors used to process PII |
| B.8.5.7 | Engagement of a subcontractor to process PII |
| B.8.5.8 | Change of subcontractor to process PII |

The Annex B control IDs above are the canonical identifiers from
ISO/IEC 27701:2019 publicly-available preview tables. The full
implementation guidance per control lives in the operator's licensed
copy; Z.Z5's catalog stores ID + short name + mapping references
only.

### 2.2 ISO/IEC 27001:2022 — ISMS Requirements (the substrate)

URL: https://www.iso.org/standard/27001 (accessed 2026-06-08).
Status: Published October 2022 (third edition; first edition 2005,
second 2013). Withdrew the 2013 edition; transition period ended
2025-10-31 for previously-issued 27001:2013 certifications.

Publicly-available abstract text (from ISO's standard page preview):

> "This document specifies the requirements for establishing,
> implementing, maintaining and continually improving an information
> security management system within the context of the organization.
> This document also includes requirements for the assessment and
> treatment of information security risks tailored to the needs of
> the organization."

> "Excluding any of the requirements specified in Clauses 4 to 10 is
> not acceptable when an organization claims conformity to this
> document."

Clause 6.1.3 — the Statement of Applicability requirement (the
clause that links 27001 → 27701 via the SoA):

> "The organization shall: (a) define and apply an information
> security risk treatment process to: [...] (4) produce a Statement
> of Applicability that contains: the necessary controls and
> justification for inclusions; whether the necessary controls are
> implemented or not; and the justification for exclusions of any of
> the Annex A controls; [...]"

The Z.Z2 SoA is the artifact that satisfies clause 6.1.3(d). Z.Z5
consumes the Z.Z2 SoA as an EUCS submission constituent and
references it from the PIMS envelope's `isms_basis` block.

Per LOOP-Z-SPEC.md §2.1 Annex A theme partitioning (publicly-available
from the 27001:2022 Annex A):

| Theme | Control range | Count |
|---|---|---|
| A.5 — Organizational | A.5.1 - A.5.37 | 37 |
| A.6 — People | A.6.1 - A.6.8 | 8 |
| A.7 — Physical | A.7.1 - A.7.14 | 14 |
| A.8 — Technological | A.8.1 - A.8.34 | 34 |
| **Total** | | **93** |

### 2.3 ISO/IEC 27002:2022 — Information security controls

URL: https://www.iso.org/standard/27002 (accessed 2026-06-08).
Status: Published February 2022.

Publicly-available abstract text (from ISO's standard page preview):

> "This document provides a reference set of generic information
> security controls including implementation guidance. This document
> is designed to be used by organizations: (a) within the context of
> an information security management system (ISMS) based on ISO/IEC
> 27001; (b) for implementing information security controls based on
> internationally recognized best practices; (c) for developing
> organization-specific information security management guidelines."

27002:2022 introduced the five attribute dimensions per control
(Control type / Information security properties / Cybersecurity
concepts / Operational capabilities / Security domains). Z.Z1's
catalog persists those attributes per control; Z.Z5's PIMS envelope
re-uses them for the PIMS extension overlays.

### 2.4 ISO/IEC 27017:2015 — Cloud overlay (referenced via Z.Z3)

URL: https://www.iso.org/standard/43757 (accessed 2026-06-08).
Status: Published December 2015. No 2022 reissue published as of
2026-06-08; reissue pending.

Publicly-available abstract text (paraphrased from ISO's standard
page preview):

> "This document provides guidelines for information security
> controls applicable to the provision and use of cloud services by
> providing: additional implementation guidance for relevant controls
> specified in ISO/IEC 27002; additional controls with implementation
> guidance that specifically relate to cloud services."

Z.Z5 reads Z.Z3's per-cloud coverage envelopes (one per configured
cloud provider) to populate the EUCS submission's per-cloud overlay
section.

### 2.5 ISO/IEC 27018:2019 — PII Processor controls (referenced via Z.Z4)

URL: https://www.iso.org/standard/76559 (accessed 2026-06-08).
Status: Published January 2019 (second edition; first edition 2014).

Publicly-available abstract text (paraphrased from ISO's standard
page preview):

> "This document establishes commonly accepted control objectives,
> controls and guidelines for implementing measures to protect
> Personally Identifiable Information (PII) in line with the privacy
> principles in ISO/IEC 29100 for the public cloud computing
> environment. In particular, this document specifies guidelines
> based on ISO/IEC 27002, taking into consideration the regulatory
> requirements for the protection of PII which might be applicable
> within the context of the information security risk environment(s)
> of a provider of public cloud services."

Z.Z4 owns the 27018 catalog and emits the 27018 PII-Processor
evidence envelope. Z.Z5 consumes that envelope as a PIMS Annex B
input and as an EUCS High constituent.

### 2.6 ENISA EUCS Candidate Scheme (Cloud Services)

URL: https://www.enisa.europa.eu/topics/certification/cybersecurity-certification-framework/eucs
(accessed 2026-06-08).
Status: Candidate scheme published by ENISA in 2020; draft updated
through March 2024; awaiting European Commission adoption as a
delegated act under EU Cybersecurity Act (Regulation 2019/881).

Publicly-available text (from the ENISA EUCS factsheet HTML page):

> "The European Union Cybersecurity Certification Scheme on Cloud
> Services (EUCS) is a candidate cybersecurity certification scheme
> that aims to harmonize the security of cloud services in the EU.
> It covers Infrastructure as a Service (IaaS), Platform as a Service
> (PaaS), and Software as a Service (SaaS) cloud services. The scheme
> defines three assurance levels — Basic, Substantial, and High — and
> a set of security objectives and requirements that cloud service
> providers must meet to obtain certification at each level."

> "The EUCS scheme is being developed by an ad-hoc working group
> composed of cloud security experts representing European Member
> States. It will be adopted by the European Commission as an
> implementing act in accordance with the provisions of the
> Cybersecurity Act (Regulation (EU) 2019/881)."

The three EUCS assurance levels (publicly-available from the ENISA
factsheet + EUR-Lex EU Cybersecurity Act Article 52):

| Level | Risk coverage | Audit type | Typical required evidence |
|---|---|---|---|
| **Basic** | Low risk to processed data | Self-assessment + light review by CAB | ISO 27001 Annex A (subset of organisational + technological controls) + self-attestation |
| **Substantial** | Moderate risk | Independent CAB review with formal audit | ISO 27001 Annex A (full) + ISO 27017 (cloud overlay) + independent CAB audit |
| **High** | High risk (national-security-adjacent) | Independent CAB review with stringent technical audit + penetration testing | ISO 27001 + 27017 + 27018 + 27701 + independent CAB audit + penetration testing + supply-chain attestations |

EU Cybersecurity Act Article 52 (verbatim from EUR-Lex
https://eur-lex.europa.eu/eli/reg/2019/881/oj):

> "1. A European cybersecurity certificate may specify one or more
> of the following assurance levels: 'basic', 'substantial' or
> 'high'. The assurance level shall be commensurate with the level
> of the risk associated with the intended use of the ICT product,
> ICT service or ICT process, in terms of the probability and
> impact of an incident."

> "2. European cybersecurity certificates at assurance level
> 'basic' shall provide assurance that the ICT products, ICT
> services and ICT processes for which those certificates are issued
> meet the corresponding security requirements, including security
> functionalities, and that they have been evaluated at a level
> intended to minimise the known basic risks of incidents and
> cyberattacks."

> "3. European cybersecurity certificates at assurance level
> 'substantial' shall provide assurance that the ICT products, ICT
> services and ICT processes for which those certificates are issued
> meet the corresponding security requirements, including security
> functionalities, and that they have been evaluated at a level
> intended to minimise the known cybersecurity risks, and the risk
> of incidents and cyberattacks carried out by actors with limited
> skills and resources."

> "4. European cybersecurity certificates at assurance level 'high'
> shall provide assurance that the ICT products, ICT services and
> ICT processes for which those certificates are issued meet the
> corresponding security requirements, including security
> functionalities, and that they have been evaluated at a level
> intended to minimise the risk of state-of-the-art cyberattacks
> carried out by actors with significant skills and resources."

### 2.7 EU Cybersecurity Act — Regulation (EU) 2019/881

URL: https://eur-lex.europa.eu/eli/reg/2019/881/oj (accessed 2026-06-08).
Status: In force since 27 June 2019.

Article 56(1) — voluntary unless otherwise specified (verbatim from
EUR-Lex):

> "The certification of ICT products, ICT services and ICT processes
> shall be voluntary, unless otherwise specified by Union law or
> Member State law."

Article 49(1) — ENISA's scheme-preparation mandate (verbatim):

> "ENISA shall prepare a candidate European cybersecurity
> certification scheme, hereinafter the 'candidate scheme', following
> a request by the Commission or, after consulting the ECCG, on its
> own initiative."

Article 51 — security objectives (verbatim, the EUCS substantive
test):

> "A European cybersecurity certification scheme shall be designed
> to achieve, as applicable, at least the following security
> objectives: (a) to protect stored, transmitted or otherwise
> processed data against accidental or unauthorised storage,
> processing, access or disclosure during the entire life cycle of
> the ICT product, ICT service or ICT process; (b) to protect stored,
> transmitted or otherwise processed data against accidental or
> unauthorised destruction, loss or alteration or lack of
> availability during the entire life cycle of the ICT product, ICT
> service or ICT process; (c) that authorised persons, programs or
> machines are able only to access the data, services or functions
> to which their access rights refer; [...] (f) to verify that ICT
> products, ICT services and ICT processes do not contain known
> vulnerabilities; (g) to restore the availability and access to
> data, services and functions in a timely manner in the event of a
> physical or technical incident; (h) that ICT products, ICT
> services and ICT processes are secure by default and by design;
> (i) that ICT products, ICT services and ICT processes are provided
> with up-to-date software and hardware that do not contain publicly
> known vulnerabilities, and are provided with mechanisms for
> secure updates."

Article 58 — National Cybersecurity Certification Authority (NCCA)
designation (verbatim):

> "Each Member State shall designate one or more national
> cybersecurity certification authorities in its territory or, with
> the agreement of another Member State, designate one or more
> national cybersecurity certification authorities established in
> that other Member State to be responsible for the supervisory
> tasks in the designating Member State."

The NCCA designation matters operationally because the Conformity
Assessment Body the CSP engages must be accredited by the NCCA of
the Member State the CSP targets. Z.Z5's `cab_identification` block
captures both the CAB and its accrediting NCCA.

### 2.8 GDPR — General Data Protection Regulation (EU 2016/679)

URL: https://eur-lex.europa.eu/eli/reg/2016/679/oj (accessed 2026-06-08).
Status: In force since 25 May 2018.

GDPR is the substantive regulation that PIMS (27701) operationalises
for the EU-data-subject case. Z.Z5's PIMS envelope's
`gdpr_article_mapping` block references the relevant GDPR Articles
per PIMS control.

Article 28(1) — processor selection (verbatim from EUR-Lex):

> "Where processing is to be carried out on behalf of a controller,
> the controller shall use only processors providing sufficient
> guarantees to implement appropriate technical and organisational
> measures in such a manner that processing will meet the
> requirements of this Regulation and ensure the protection of the
> rights of the data subject."

Article 28(3) — processor contract requirements (verbatim):

> "Processing by a processor shall be governed by a contract or
> other legal act under Union or Member State law, that is binding
> on the processor with regard to the controller and that sets out
> the subject-matter and duration of the processing, the nature and
> purpose of the processing, the type of personal data and
> categories of data subjects and the obligations and rights of the
> controller."

Article 28(3) further enumerates the eight specific obligations the
processor contract must include (a-h); these are the canonical
"Article 28 flow-down" Z.Z5's PIMS B.7.2.6 control evidence cites.

Article 32(1) — security of processing (verbatim, the source-text
for the TOMs evidence Z.Z5 references):

> "Taking into account the state of the art, the costs of
> implementation and the nature, scope, context and purposes of
> processing as well as the risk of varying likelihood and severity
> for the rights and freedoms of natural persons, the controller and
> the processor shall implement appropriate technical and
> organisational measures to ensure a level of security appropriate
> to the risk, including inter alia as appropriate: (a) the
> pseudonymisation and encryption of personal data; (b) the ability
> to ensure the ongoing confidentiality, integrity, availability and
> resilience of processing systems and services; (c) the ability to
> restore the availability and access to personal data in a timely
> manner in the event of a physical or technical incident; (d) a
> process for regularly testing, assessing and evaluating the
> effectiveness of technical and organisational measures for
> ensuring the security of processing."

Article 44 — general principle for transfers (verbatim, the source-
text for the cross-border-transfer block):

> "Any transfer of personal data which are undergoing processing or
> are intended for processing after transfer to a third country or
> to an international organisation shall take place only if, subject
> to the other provisions of this Regulation, the conditions laid
> down in this Chapter are complied with by the controller and
> processor, including for onward transfers of personal data from
> the third country or an international organisation to another
> third country or to another international organisation."

Article 46(1) — appropriate safeguards (the SCC + BCR basis):

> "In the absence of a decision pursuant to Article 45(3), a
> controller or processor may transfer personal data to a third
> country or an international organisation only if the controller or
> processor has provided appropriate safeguards, and on condition
> that enforceable data subject rights and effective legal remedies
> for data subjects are available."

Article 49 — derogations for specific situations (verbatim, the
lawful-basis-of-last-resort for transfers):

> "1. In the absence of an adequacy decision pursuant to Article
> 45(3), or of appropriate safeguards pursuant to Article 46,
> including binding corporate rules, a transfer or a set of
> transfers of personal data to a third country or an international
> organisation shall take place only on one of the following
> conditions: (a) the data subject has explicitly consented to the
> proposed transfer, after having been informed of the possible
> risks of such transfers for the data subject due to the absence of
> an adequacy decision and appropriate safeguards; (b) the transfer
> is necessary for the performance of a contract between the data
> subject and the controller or the implementation of pre-contractual
> measures taken at the data subject's request; [...]"

### 2.9 NIST OLIR — ISO 27001 → NIST 800-53 informative mapping

URL: https://csrc.nist.gov/projects/olir (accessed 2026-06-08).

> NIST publicly-available text (from the OLIR program page):
> "The National Online Informative References Program is a NIST
> effort to facilitate subject matter experts (SMEs) in defining
> standardized online informative references (OLIRs) between
> elements of their cybersecurity, privacy, and workforce documents
> and elements of other cybersecurity, privacy, and workforce
> documents. OLIRs are simple, structured, and machine-readable,
> allowing them to be easily shared and consumed."

Z.Z1's catalog persists OLIR-derived ISO ↔ NIST 800-53 r5 mappings
per Annex A control. Z.Z5's PIMS envelope inherits the mappings
transitively via Z.Z2's SoA constituents.

### 2.10 ISO/IEC 17021-1:2015 + ISO/IEC 27006:2015 — CAB accreditation chain

URLs: https://www.iso.org/standard/61651 (17021-1) +
https://www.iso.org/standard/62313 (27006), both accessed 2026-06-08.

17021-1 governs *how* certification bodies audit and certify
management systems. 27006 augments 17021-1 with ISMS-specific
requirements; CABs auditing ISMS (and by extension the ISMS-with-
PIMS combination) must be accredited under 27006.

Publicly-available 27006 abstract text (from ISO's standard preview):

> "This document supplements ISO/IEC 17021-1. It primarily augments
> the requirements of ISO/IEC 17021-1 to include the certification
> of an information security management system (ISMS). It specifies
> requirements and provides guidance for bodies providing audit and
> certification of an information security management system (ISMS),
> in addition to the requirements contained within ISO/IEC 17021-1
> and ISO/IEC 27001."

Z.Z5's `cab_identification` block captures the CAB name + accreditation
body (UKAS, ANAB, DAkkS, etc.) + accreditation scope (must include
ISMS per 27006). The operator declares the CAB via
`cloud-evidence/iso-cab-engagement.yaml`; Z.Z5 validates the format
and emits REQUIRES-OPERATOR-INPUT if missing for an EUCS-Substantial-
or-higher target.

### 2.11 ENISA EUCC Scheme (companion reference)

URL: https://www.enisa.europa.eu/topics/certification/cybersecurity-certification-framework/eucc-scheme
(accessed 2026-06-08).

EUCC is the EU Cybersecurity Certification Scheme for ICT products
(adopted by the European Commission in January 2024 — the first EUCS-
family scheme to reach final adoption). EUCC is *informative* for
EUCS because the two schemes share the EU Cybersecurity Act
infrastructure (Article 52 assurance levels, Article 58 NCCA
designation, etc.) but EUCC is for ICT *products* (single product /
TOE) while EUCS is for ICT *services* (cloud services).

Publicly-available text (from the ENISA EUCC factsheet):

> "The European Common Criteria-based cybersecurity certification
> scheme (EUCC) is the first cybersecurity certification scheme
> adopted at EU level under Regulation (EU) 2019/881 (the
> Cybersecurity Act). The EUCC builds on the SOG-IS Mutual Recognition
> Agreement (MRA) and Common Criteria standards (ISO/IEC 15408 and
> ISO/IEC 18045)."

Z.Z5's EUCS package includes a `eucc_related: false` field
identifying that this submission is for the EUCS (cloud-services)
scheme and is not an EUCC (products) submission; the field prevents
operator confusion between the two ENISA schemes.

### 2.12 ISO/IEC 29100:2011 — Privacy framework (referenced by 27701 + 27018)

URL: https://www.iso.org/standard/45123 (accessed 2026-06-08).
Status: Published December 2011. Per ISO's "publicly available
standards" programme, ISO/IEC 29100:2011 is one of the few ISO
standards available at no cost.

Publicly-available abstract text (from ISO's standard page):

> "ISO/IEC 29100:2011 provides a privacy framework which: specifies
> a common privacy terminology; defines the actors and their roles
> in processing personally identifiable information (PII); describes
> privacy safeguarding considerations; provides references to known
> privacy principles for information technology."

29100 establishes the eleven privacy principles 27018 and 27701 build
on:

| # | Principle |
|---|---|
| 1 | Consent and choice |
| 2 | Purpose legitimacy and specification |
| 3 | Collection limitation |
| 4 | Data minimization |
| 5 | Use, retention and disclosure limitation |
| 6 | Accuracy and quality |
| 7 | Openness, transparency and notice |
| 8 | Individual participation and access |
| 9 | Accountability |
| 10 | Information security |
| 11 | Privacy compliance |

Z.Z5's PIMS envelope's `privacy_principles[]` block enumerates the
29100 principles + per-principle implementation reference.

### 2.13 NIST Privacy Framework v1.0 (Jan 2020) — informative cross-reference

URL: https://www.nist.gov/privacy-framework (accessed 2026-06-08).

Publicly-available text (from the NIST Privacy Framework landing page):

> "The Privacy Framework is a voluntary tool intended to help
> organizations identify and manage privacy risk to build innovative
> products and services while protecting individuals' privacy."

> "The Privacy Framework follows the structure of the NIST
> Cybersecurity Framework (CSF) to enable the two frameworks to be
> used together. It is organized into three parts: Core, Profiles,
> and Implementation Tiers."

The NIST Privacy Framework Core has five functions (Identify-P,
Govern-P, Control-P, Communicate-P, Protect-P). Z.Z5's PIMS envelope
includes a `nist_privacy_framework_mapping` block per PIMS control
when the operator opts in (via `--with-nist-privacy-framework` flag);
the mapping is informative and traces back to LOOP-U for the
authoritative NIST Privacy Framework cross-walk.

### 2.14 EDPB Guidelines 07/2020 on the concepts of controller and processor (companion)

URL: https://edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-072020-concepts-controller-and-processor-gdpr_en
(accessed 2026-06-08).

The European Data Protection Board (EDPB) Guidelines 07/2020 are
the authoritative EU-supervisory-authority interpretation of who is
a Controller vs Processor under GDPR. Z.Z5's `pims_mode` field
documentation references EDPB 07/2020 §1.B for the boundary tests
the operator applies when declaring their role.

Publicly-available text (from the EDPB Guidelines 07/2020 PDF):

> "The concepts of controller, joint controllers and processor play
> a crucial role in the application of the General Data Protection
> Regulation (GDPR), since they determine who shall be responsible
> for compliance with different data protection rules, and how data
> subjects can exercise their rights in practice."

> "Within the GDPR, decisions made by the controller are crucial.
> The functional concept of the controller, which derives from the
> Data Protection Directive 95/46/EC, was developed to allocate
> responsibilities according to the actual roles of the parties.
> This implies that the legal status as 'controller' or 'processor'
> must in principle be determined by the parties' actual activities
> in a specific situation rather than by the formal designation of
> an actor."

EDPB 07/2020 §2.1.2.D (the controller-determines-purposes-and-means
test):

> "A controller is the body which 'determines the purposes and means
> of the processing'. Determining 'purposes' refers to the body
> defining the 'why' of the processing (i.e. the objective the
> processing aims to achieve). Determining 'means' refers to the body
> defining the 'how' of the processing (i.e. the way the personal
> data are processed)."

Z.Z5's `pims_mode` validation surfaces the EDPB tests in tracker UI
tooltips so operators making the determination have the EDPB
authority at hand.

---

## 3. Scope

### 3.1 In scope

- Per-PIMS-mode (`processor` / `controller` / `both`) per-control
  conformance evaluation of the 27701 Annex A (PII Controller) and
  Annex B (PII Processor) control sets, deterministically derived
  from Z.Z4's 27018 evidence + operator overrides in
  `iso-27701-pims-overrides.yaml`.
- ISO 27701 Annex D GDPR-article-mapping per PIMS control;
  enumeration of GDPR Articles 5-50 with EUR-Lex URLs.
- ISO 27701 Annex C 29100-principle mapping; enumeration of all 11
  privacy principles per PIMS control coverage.
- ISO 27701 Annex E mapping to 27018 + 29151 (the cross-reference
  to Z.Z4's catalog).
- Optional NIST Privacy Framework v1.0 mapping (opt-in via flag).
- PIMS scope statement (clause 5.2.1) — organisational units,
  geographic boundaries, PII categories, data-subject categories,
  lawful basis (GDPR Article 6), cross-border transfer mechanisms
  (GDPR Articles 44-50), sub-processor list.
- Signed PIMS evidence envelope (Ed25519 + RFC 3161 + RFC 8785
  canonicalization).
- EUCS Basic submission package (lightest level) — SoA subset +
  self-attestation + scope.
- EUCS Substantial submission package — full SoA + Z.Z3 per-cloud
  coverage + CAB-identification + scope.
- EUCS High submission package — full SoA + Z.Z3 + Z.Z4 + Z.Z5
  PIMS + CAB-identification + scope + penetration-testing-report
  reference (REQUIRES-OPERATOR-INPUT).
- EUCS submission ZIP (zip-store mode for deterministic SHA-256;
  matches the existing OOXML emitter pattern).
- Manifest JSON inside the EUCS ZIP enumerating every constituent
  with its SHA-256.
- CAB identification block (per ISO/IEC 27006 accreditation chain
  + ENISA-published NCCA-accredited CAB registry).
- POA&M emission via LOOP-A.A1 for missing EUCS-required artifacts
  (template `EUCS-ARTIFACT-MISSING`) AND for non-conformant PIMS
  controls (template `PIMS-CONTROL-NON-CONFORMANT`).
- Tracker DB persistence in `iso_27701_pims_scope` and
  `eucs_submissions` tables; operator review + submission-receipt
  capture flows through tracker UI.
- LOOP-A.A4 bundler registration for the new well-known roles
  `iso-27701-pims-evidence` + `eucs-submission-package`.
- LOOP-Q.Q1 Marketplace-badge eligibility decision: emit
  `eucs_substantial_eligible: true|false` and
  `iso_27701_eligible: true|false` for Q.Q1 to consume.

### 3.2 Out of scope (NOT in Z.Z5)

- **Auto-submission to a CAB or NCCA.** REO Rule 4 forbids the
  system from acting on behalf of the operator on a regulatory or
  certification submission. Z.Z5 produces the artefacts; the operator
  submits; the tracker captures the receipt id pasted by the operator.
- **EUCC (ICT products scheme) packaging.** Z.Z5 emits the EUCS
  (cloud services) submission only. EUCC is a separate scheme; a
  future LOOP-Z-EUCC could add it.
- **The ISO certification audit itself.** Stage 1 (documentation
  review) + Stage 2 (on-site audit) are performed by the operator's
  CAB. Z.Z5 emits the documentation Stage 1 consumes; Z.Z5 does NOT
  perform the audit.
- **Per-Member-State EU NCCA portal submission UX.** Each Member
  State NCCA has its own portal; integration is per-NCCA and out of
  scope for LOOP-Z v1. A future LOOP-Z-NCCA-PORTAL could add.
- **Common Criteria (ISO/IEC 15408) packaging.** Out of LOOP-Z scope.
- **CSA STAR Level 1 / 2 self-attestation packaging.** Out of LOOP-Z
  scope; a future LOOP-Z-CSA could add (Z.Z1's catalog has a CCM
  mapping column to support this).
- **Verbatim ISO standard text redistribution.** Per LOOP-Z-SPEC.md
  §1.5, Z.Z5 references controls by ID + short name only.
- **27701 Annex F application to 27001:2013** — historical / legacy
  mapping; LOOP-Z targets 27001:2022 (transition deadline 2025-10-31
  has passed).
- **Re-emit of Z.Z1 catalog or Z.Z2 SoA.** Z.Z5 reads those as
  signed inputs and embeds-by-reference (SHA-256) in the EUCS
  manifest.
- **Real-time CAB / NCCA accreditation-chain verification.** Z.Z5
  validates the operator-declared CAB against a static accredited-
  CAB list (operator maintains via `eucs-accredited-cabs.yaml`); no
  live API call to the EU accreditation registry.

### 3.3 Conditional gating logic

```
IF org-profile.yaml.gdpr_in_scope == false
   AND org-profile.yaml.eucs_target_level == "none"
THEN
   slice skipped; log "coverage:z-z5-not-applicable"
ELSE
   IF eucs_target_level == "high" AND pims_mode != "both"
   THEN
      warn "EUCS High typically expects both PII Controller AND
            PII Processor PIMS scope; consider --pims-mode=both"
   END IF

   IF eucs_target_level == "substantial"
      AND Z.Z3 per-cloud coverage envelope absent
   THEN
      emit POA&M EUCS-ARTIFACT-MISSING; refuse package
   END IF

   IF eucs_target_level == "high"
      AND (Z.Z3 absent OR Z.Z4 absent OR PIMS envelope absent
           OR penetration_test_report_ref absent)
   THEN
      emit POA&M EUCS-ARTIFACT-MISSING per missing artifact;
      refuse package
   END IF

   emit signed PIMS envelope
   IF eucs_target_level != "none" THEN emit signed EUCS ZIP
END IF
```

---

## 4. Inputs

TypeScript-form for the data structures Z.Z5 consumes:

```typescript
// From Z.Z1: the signed Annex A catalog (referenced)
interface ISO27001AnnexACatalog {
  $schema: string;
  schema_version: string;
  snapshot_id: string;
  snapshot_date: string;             // YYYY-MM-DD
  standard_version: '2022';
  themes: AnnexATheme[];             // 4 themes: A.5, A.6, A.7, A.8
  total_control_count: 93;
  provenance: SnapshotProvenance;
  signature: Ed25519Signature;
}

interface AnnexATheme {
  theme_id: 'A.5' | 'A.6' | 'A.7' | 'A.8';
  theme_name: 'Organizational' | 'People' | 'Physical' | 'Technological';
  controls: AnnexAControl[];
}

interface AnnexAControl {
  control_id: string;                // e.g. "A.5.1", "A.8.24"
  short_name: string;
  attributes: {
    control_type: ('Preventive' | 'Detective' | 'Corrective')[];
    info_security_properties: ('Confidentiality' | 'Integrity' | 'Availability')[];
    cybersecurity_concepts: ('Identify' | 'Protect' | 'Detect' | 'Respond' | 'Recover')[];
    operational_capabilities: string[];
    security_domains: string[];
  };
  nist_800_53_rev5_mapping: NIST80053Mapping[];
  fedramp_ksi_mapping: FedRAMPKSIMapping[];
  legacy_27001_2013_mapping?: string[];
}

// From Z.Z2: the signed SoA (referenced by SHA-256, not embedded full)
interface ISO27001SoAReference {
  path: string;                      // out/iso-27001-soa-{cspname}-{date}.json
  sha256: string;
  generated_at: string;
  signed_by_key_id: string;
}

// From Z.Z3: per-cloud coverage envelopes (one per configured cloud)
interface ISO27017CoverageReference {
  cloud_provider: 'aws' | 'gcp' | 'azure';
  path: string;                      // out/iso-27017-coverage-{cloud}.json
  sha256: string;
  generated_at: string;
  cld_control_coverage: Record<string, 'conformant' | 'partial' | 'non-conformant' | 'not-applicable'>;
  augmented_27002_count: number;
  signed_by_key_id: string;
}

// From Z.Z4: the signed PII-Processor evidence envelope
interface ISO27018EvidenceReference {
  path: string;                      // out/iso-27018-evidence.json
  sha256: string;
  generated_at: string;
  pii_control_coverage: Record<string, 'conformant' | 'partial' | 'non-conformant' | 'not-applicable'>;
  subprocessors_disclosed: string[];
  signed_by_key_id: string;
}

// Operator-supplied: PIMS configuration
interface ISO27701PIMSConfigYAML {
  pims_mode: 'processor' | 'controller' | 'both';
  scope: PIMSScope;
  pii_role_justification: string;    // operator narrative explaining EDPB 07/2020 application
  pims_annex_a_overrides?: PIMSControlOverride[];
  pims_annex_b_overrides?: PIMSControlOverride[];
  privacy_principles_implementation: Record<string, string>;  // 29100 principle id -> impl reference
}

interface PIMSScope {
  scope_statement: string;
  organisational_units: string[];
  geographic_boundaries: GeographicBoundary[];
  pii_categories: PIICategory[];
  data_subject_categories: string[];   // e.g. "EU citizens", "U.S. consumers", "employees"
  lawful_basis: GDPRLawfulBasis[];     // GDPR Article 6(1)(a)-(f)
  cross_border_transfers: CrossBorderTransfer[];
  subprocessors: Subprocessor[];
}

interface GeographicBoundary {
  region_code: string;                 // e.g. "eu-west-1", "us-east-1"
  is_eu: boolean;
  is_eea: boolean;
  is_uk_eu_equivalent: boolean;
  applicable_jurisdictions: string[];  // ISO 3166-1 alpha-2
}

interface PIICategory {
  category: string;                    // e.g. "name", "email", "device_id", "ip_address", "health_data"
  sensitive: boolean;                  // GDPR Article 9 "special categories"
  approximate_volume_class: 'low' | 'medium' | 'high' | 'very-high';
}

interface GDPRLawfulBasis {
  basis: 'consent' | 'contract' | 'legal_obligation' | 'vital_interests' | 'public_task' | 'legitimate_interests';
  article: 'Article 6(1)(a)' | 'Article 6(1)(b)' | 'Article 6(1)(c)' | 'Article 6(1)(d)' | 'Article 6(1)(e)' | 'Article 6(1)(f)';
  justification: string;
  applies_to_pii_categories: string[];
}

interface CrossBorderTransfer {
  source_region: string;
  destination_region: string;
  destination_country_iso3166_alpha2: string;
  lawful_mechanism: 'adequacy_decision' | 'scc' | 'bcr' | 'article_49_derogation';
  gdpr_article: 'Article 45' | 'Article 46' | 'Article 47' | 'Article 49';
  adequacy_decision_reference?: string;   // e.g. "EU-U.S. Data Privacy Framework"
  scc_module?: 'Module 1' | 'Module 2' | 'Module 3' | 'Module 4';
  bcr_approval_reference?: string;
  article_49_basis?: string;
}

interface Subprocessor {
  name: string;
  jurisdiction: string;
  pii_categories_processed: string[];
  contract_basis_article_28: boolean;
  disclosure_date_to_controllers: string;
  approval_status: 'approved' | 'pending' | 'revoked';
}

interface PIMSControlOverride {
  control_id: string;                  // e.g. "B.7.5.1"
  override_disposition: 'applicable' | 'not_applicable' | 'partial';
  justification: string;
  evidence_reference: string;
  approval_chain: ApprovalChain;
}

interface ApprovalChain {
  approved_by: string;
  approved_at: string;
  approval_document_path: string;
  approval_document_sha256: string;
}

// Operator-supplied: EUCS configuration
interface EUCSConfigYAML {
  eucs_target_level: 'basic' | 'substantial' | 'high' | 'none';
  csp_legal_entity: string;
  csp_country_iso3166_alpha2: string;
  service_in_scope: ServiceInScope[];
  cab_identification: CABIdentification;
  ncca_jurisdiction: string;           // ISO 3166-1 alpha-2 of the targeted Member State
  penetration_test_report?: PenetrationTestReportReference;  // required for High
  prior_submissions?: PriorEUCSSubmission[];
}

interface ServiceInScope {
  service_name: string;
  service_model: 'IaaS' | 'PaaS' | 'SaaS';
  service_url: string;
  service_description: string;
}

interface CABIdentification {
  cab_name: string;
  cab_country_iso3166_alpha2: string;
  cab_accreditation_body: string;      // e.g. "DAkkS", "UKAS", "ANAB", "Cofrac"
  cab_accreditation_number: string;
  cab_accreditation_scope_includes_isms: boolean;
  cab_accreditation_scope_includes_pims: boolean;
  cab_engagement_letter_path: string;
  cab_engagement_letter_sha256: string;
}

interface PenetrationTestReportReference {
  pentest_firm_name: string;
  pentest_report_path: string;
  pentest_report_sha256: string;
  pentest_completed_at: string;
  pentest_methodology: string;         // e.g. "OWASP WSTG", "NIST SP 800-115"
  pentest_scope_summary: string;
}

interface PriorEUCSSubmission {
  submission_date: string;
  assurance_level: 'basic' | 'substantial' | 'high';
  outcome: 'certified' | 'rejected' | 'withdrawn';
  certificate_id?: string;
}

// Operator-supplied: org-profile.yaml relevant fields
interface OrgProfileZ5Fields {
  gdpr_in_scope: boolean;
  eucs_target_level: 'basic' | 'substantial' | 'high' | 'none';
  pims_mode: 'processor' | 'controller' | 'both';
  csp_legal_entity: string;
  marketplace_url?: string;
}

// From LOOP-U: privacy crosswalk catalog (for GDPR article mapping)
interface PrivacyFrameworkCrosswalkReference {
  path: string;                       // data/privacy-frameworks-crosswalk.json
  sha256: string;
  gdpr_article_mappings: Record<string, GDPRArticleMapping>;
}

interface GDPRArticleMapping {
  article: string;                     // e.g. "Article 28"
  eurlex_url: string;
  nist_800_53_mappings: string[];
}
```

---

## 5. Outputs

### 5.1 Canonical PIMS evidence envelope (JSON)

Schema reference: `https://cloud-evidence.example/schemas/iso-27701-pims-v1.json`.

Path: `out/iso-27701-pims-{cspname}-{date}.json`.

```jsonc
{
  "$schema": "https://cloud-evidence.example/schemas/iso-27701-pims-v1.json",
  "schema_version": "1.0.0",
  "envelope_id": "iso-27701-pims-2026-06-08-acme-001",
  "generated_at": "2026-06-08T14:33:00Z",
  "csp_name": "<from org-profile.yaml>",
  "csp_legal_entity": "<from org-profile.yaml>",
  "pims_mode": "processor",
  "pii_role_justification": "<operator narrative explaining EDPB 07/2020 application>",

  "pims_scope": {
    "scope_statement": "<verbatim from iso-27701-pims-config.yaml>",
    "organisational_units": ["Engineering", "Customer Success", "Security"],
    "geographic_boundaries": [
      {
        "region_code": "eu-west-1",
        "is_eu": true,
        "is_eea": true,
        "is_uk_eu_equivalent": false,
        "applicable_jurisdictions": ["IE", "DE", "FR"]
      }
    ],
    "pii_categories": [
      {
        "category": "email",
        "sensitive": false,
        "approximate_volume_class": "high"
      }
    ],
    "data_subject_categories": ["EU citizens", "U.S. consumers"],
    "lawful_basis": [
      {
        "basis": "contract",
        "article": "Article 6(1)(b)",
        "justification": "Processing necessary for performance of the customer-CSP service contract",
        "applies_to_pii_categories": ["email", "device_id"]
      }
    ],
    "cross_border_transfers": [
      {
        "source_region": "eu-west-1",
        "destination_region": "us-east-1",
        "destination_country_iso3166_alpha2": "US",
        "lawful_mechanism": "adequacy_decision",
        "gdpr_article": "Article 45",
        "adequacy_decision_reference": "EU-U.S. Data Privacy Framework (Commission Implementing Decision (EU) 2023/1795)"
      }
    ],
    "subprocessors": [
      {
        "name": "Stripe Payments Europe Ltd",
        "jurisdiction": "IE",
        "pii_categories_processed": ["email", "billing_address"],
        "contract_basis_article_28": true,
        "disclosure_date_to_controllers": "2025-11-01",
        "approval_status": "approved"
      }
    ]
  },

  "isms_basis": {
    "iso_27001_soa_reference": {
      "path": "out/iso-27001-soa-acme-2026-06-08.json",
      "sha256": "...",
      "generated_at": "2026-06-08T14:00:00Z",
      "signed_by_key_id": "ed25519:acme-org-2026"
    },
    "annex_a_catalog_reference": {
      "path": "data/iso-27001-2022-annex-a.json",
      "sha256": "..."
    }
  },

  "pims_controls": {
    "annex_a_controller_controls": [
      {
        "control_id": "A.7.2.1",
        "short_name": "Identify and document purpose",
        "applicable": true,
        "disposition": "conformant",
        "justification": "Documented in privacy notice + records of processing per GDPR Article 30",
        "evidence_reference": "out/iso-27018-evidence.json#/pii_controls/purpose_legitimacy",
        "gdpr_articles": ["Article 5(1)(b)", "Article 30"],
        "iso_29100_principles": [2]
      }
    ],
    "annex_b_processor_controls": [
      {
        "control_id": "B.8.2.1",
        "short_name": "Customer agreement",
        "applicable": true,
        "disposition": "conformant",
        "justification": "Article 28 DPA template signed with every customer; standard contractual clauses Module 2 (Controller -> Processor) embedded",
        "evidence_reference": "out/iso-27018-evidence.json#/pii_controls/customer_agreement",
        "gdpr_articles": ["Article 28(3)"],
        "iso_29100_principles": [11]
      },
      {
        "control_id": "B.8.5.6",
        "short_name": "Disclosure of subcontractors used to process PII",
        "applicable": true,
        "disposition": "conformant",
        "justification": "Subprocessor list published at <csp-url>/subprocessors with 30-day-advance change notification per Article 28(2)",
        "evidence_reference": "out/iso-27018-evidence.json#/pii_controls/subprocessor_disclosure",
        "gdpr_articles": ["Article 28(2)", "Article 28(4)"],
        "iso_29100_principles": [7]
      }
    ]
  },

  "privacy_principles": [
    {
      "principle_id": 1,
      "principle_name": "Consent and choice",
      "implementation_reference": "Documented in privacy notice + consent mechanism on signup flow"
    }
  ],

  "gdpr_article_coverage": {
    "covered_articles": ["Article 5", "Article 6", "Article 28", "Article 32", "Article 33", "Article 34", "Article 35"],
    "uncovered_articles": [],
    "coverage_url": "https://eur-lex.europa.eu/eli/reg/2016/679/oj"
  },

  "nist_privacy_framework_mapping": null,

  "27018_evidence_reference": {
    "path": "out/iso-27018-evidence.json",
    "sha256": "...",
    "subprocessors_disclosed_count": 12
  },

  "marketplace_eligibility": {
    "iso_27701_pims_eligible": true,
    "eligibility_basis": "All Annex B controls conformant; CAB engagement letter signed; awaiting Stage 2 audit"
  },

  "provenance": {
    "emitter": "iso-27701-pims",
    "emitter_version": "0.1.0",
    "emitted_at": "2026-06-08T14:33:00Z",
    "source_calls": [
      { "kind": "z-z1-annex-a-catalog", "path": "data/iso-27001-2022-annex-a.json", "sha256": "..." },
      { "kind": "z-z2-soa", "path": "out/iso-27001-soa-acme-2026-06-08.json", "sha256": "..." },
      { "kind": "z-z3-coverage-aws", "path": "out/iso-27017-coverage-aws.json", "sha256": "..." },
      { "kind": "z-z3-coverage-gcp", "path": "out/iso-27017-coverage-gcp.json", "sha256": "..." },
      { "kind": "z-z3-coverage-azure", "path": "out/iso-27017-coverage-azure.json", "sha256": "..." },
      { "kind": "z-z4-27018-evidence", "path": "out/iso-27018-evidence.json", "sha256": "..." },
      { "kind": "pims-config-yaml", "path": "cloud-evidence/iso-27701-pims-config.yaml", "sha256": "..." },
      { "kind": "org-profile-yaml", "path": "cloud-evidence/org-profile.yaml", "sha256": "..." }
    ]
  },

  "signature": {
    "alg": "ed25519",
    "key_id": "ed25519:acme-org-2026",
    "sig": "..."
  },

  "rfc3161_timestamp": {
    "tsa_url": "https://freetsa.org/tsr",
    "token": "...",
    "received_at": "2026-06-08T14:33:01Z"
  }
}
```

### 5.2 EUCS submission ZIP

Path: `out/eucs-submission-package-{cspname}-{level}-{date}.zip`.

ZIP layout (zip-store mode for deterministic SHA-256):

```
eucs-submission-package-acme-substantial-2026-06-08.zip
├── eucs-manifest.json                                 # top-level manifest with SHA-256 per file
├── eucs-cover-document.docx                           # OOXML cover doc with assurance level + CAB + signatures
├── iso-27001-soa-acme-2026-06-08.json                # Z.Z2 SoA (embedded by reference; copied in for ZIP integrity)
├── iso-27001-soa-acme-2026-06-08.docx                # Z.Z2 SoA .docx for CAB review
├── iso-27017-coverage-aws.json                       # Z.Z3 per-cloud coverage envelopes
├── iso-27017-coverage-gcp.json
├── iso-27017-coverage-azure.json
├── iso-27018-evidence.json                           # Z.Z4 PII-Processor evidence (High only; absent for Basic/Substantial)
├── iso-27701-pims-acme-2026-06-08.json               # Z.Z5 PIMS envelope (High only)
├── pentest-report-2026.pdf                           # Operator-supplied (High only)
├── eucs-scope-statement.json                         # Scope of certification (services, regions, exclusions)
├── eucs-cab-identification.json                      # CAB + accreditation chain
├── eucs-prior-submissions.json                       # If any (e.g. Substantial certified, applying for High)
└── eucs-submission-package.sig                       # Detached Ed25519 signature over the manifest
```

The manifest file shape:

```jsonc
{
  "$schema": "https://cloud-evidence.example/schemas/eucs-manifest-v1.json",
  "schema_version": "1.0.0",
  "manifest_id": "eucs-submission-2026-06-08-acme-substantial-001",
  "generated_at": "2026-06-08T14:35:00Z",
  "csp_name": "Acme Cloud Inc",
  "csp_legal_entity": "Acme Cloud Inc",
  "csp_country_iso3166_alpha2": "US",
  "eucs_assurance_level": "substantial",
  "eucs_scheme_version": "ENISA EUCS Candidate (March 2024 draft)",
  "eucs_scheme_reference_url": "https://www.enisa.europa.eu/topics/certification/cybersecurity-certification-framework/eucs",
  "ncca_jurisdiction": "DE",
  "ncca_authority_name": "BSI - Bundesamt fuer Sicherheit in der Informationstechnik",
  "cab_identification": {
    "cab_name": "TUV Rheinland Cert GmbH",
    "cab_country_iso3166_alpha2": "DE",
    "cab_accreditation_body": "DAkkS",
    "cab_accreditation_number": "D-ZM-12345-01-00",
    "cab_accreditation_scope_includes_isms": true,
    "cab_accreditation_scope_includes_pims": true
  },
  "service_in_scope": [
    {
      "service_name": "Acme Compute Service",
      "service_model": "IaaS",
      "service_url": "https://compute.acme.example",
      "service_description": "Multi-tenant virtualised compute"
    }
  ],
  "scope_statement": "<verbatim from EUCS scope yaml>",
  "constituents": [
    {
      "file_path": "iso-27001-soa-acme-2026-06-08.json",
      "sha256": "abc123...",
      "size_bytes": 245612,
      "role": "iso-27001-soa-json",
      "signed_by_key_id": "ed25519:acme-org-2026"
    },
    {
      "file_path": "iso-27001-soa-acme-2026-06-08.docx",
      "sha256": "def456...",
      "size_bytes": 198234,
      "role": "iso-27001-soa-docx",
      "signed_by_key_id": "ed25519:acme-org-2026"
    }
  ],
  "ksi_eligibility_summary": {
    "marketplace_eucs_substantial_eligible": true,
    "marketplace_iso_27701_pims_eligible": true
  },
  "provenance": {
    "emitter": "eucs-submission-package",
    "emitter_version": "0.1.0",
    "emitted_at": "2026-06-08T14:35:00Z",
    "source_calls": [
      { "kind": "z-z2-soa", "path": "out/iso-27001-soa-acme-2026-06-08.json", "sha256": "abc123..." }
    ]
  },
  "signature": {
    "alg": "ed25519",
    "key_id": "ed25519:acme-org-2026",
    "sig": "..."
  },
  "rfc3161_timestamp": {
    "tsa_url": "https://freetsa.org/tsr",
    "token": "...",
    "received_at": "2026-06-08T14:35:01Z"
  }
}
```

### 5.3 OOXML cover document (eucs-cover-document.docx)

Layout:

- **Cover page.** "ENISA EUCS Submission — Assurance Level
  {basic|substantial|high}". CSP legal entity + jurisdiction + service
  name. CAB name + accreditation number. NCCA jurisdiction. Generated
  date.
- **Table of contents.** Auto-generated from the constituent list in
  the manifest.
- **Scope statement.** Verbatim from the operator's `eucs-config.yaml`.
- **Constituent summary table.** One row per ZIP constituent with role,
  filename, SHA-256.
- **CAB engagement letter reference.** SHA-256-pinned reference to the
  operator-uploaded engagement letter (path declared in
  `iso-cab-engagement.yaml`).
- **Attestation block.** "I attest under penalty of misrepresentation
  that the information in this submission is, to the best of my
  knowledge, accurate and complete as of the date below."; signature
  line; printed name; title; date.
- **Signature placeholder.** A signed-XML region or a placeholder
  `<w:bookmarkStart/>` where the operator inserts a wet signature.

The renderer is `core/iso-27701-pims-docx.ts` and reuses the OOXML
helpers from `core/inventory-workbook.ts` (zip-store, document.xml,
styles.xml, numbering.xml) — same pattern as Z.Z2's SoA `.docx`
emitter.

### 5.4 Tracker DB rows

Schema (migrations `0050_iso_27701_pims_scope.sql` +
`0051_eucs_submissions.sql`):

```sql
CREATE TABLE iso_27701_pims_scope (
  id                            UUID PRIMARY KEY,
  envelope_id                   TEXT NOT NULL UNIQUE,
  envelope_path                 TEXT NOT NULL,
  csp_name                      TEXT NOT NULL,
  pims_mode                     TEXT NOT NULL,                  -- processor|controller|both
  scope_statement               TEXT NOT NULL,
  pii_categories_json           JSONB NOT NULL,
  geographic_boundaries_json    JSONB NOT NULL,
  lawful_basis_json             JSONB NOT NULL,
  subprocessors_json            JSONB NOT NULL,
  cross_border_transfers_json   JSONB NOT NULL,
  gdpr_in_scope                 BOOLEAN NOT NULL,
  iso_27001_soa_ref_path        TEXT NOT NULL,
  iso_27001_soa_ref_sha256      TEXT NOT NULL,
  iso_27018_evidence_ref_path   TEXT NOT NULL,
  iso_27018_evidence_ref_sha256 TEXT NOT NULL,
  signing_key_id                TEXT NOT NULL,
  signing_key_version           TEXT NOT NULL,
  emitted_at                    TIMESTAMPTZ NOT NULL,
  cab_engagement_id             UUID,                            -- FK to iso_cab_engagements (separate table from Z.Z2)
  pims_audit_status             TEXT NOT NULL DEFAULT 'pending', -- pending|stage1|stage2|certified|surveillance|recertified
  cab_certificate_id            TEXT,
  cab_certificate_issued_at     TIMESTAMPTZ,
  cab_certificate_expires_at    TIMESTAMPTZ,
  marketplace_eligibility       JSONB,
  encrypted_at_rest             BOOLEAN NOT NULL DEFAULT TRUE,
  created_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_iso_27701_pims_scope_csp_name ON iso_27701_pims_scope(csp_name);
CREATE INDEX idx_iso_27701_pims_scope_pims_audit_status ON iso_27701_pims_scope(pims_audit_status);
CREATE UNIQUE INDEX idx_iso_27701_pims_scope_idempotency
  ON iso_27701_pims_scope(csp_name, emitted_at, pims_mode);

CREATE TABLE eucs_submissions (
  id                            UUID PRIMARY KEY,
  submission_id                 TEXT NOT NULL UNIQUE,
  package_path_zip              TEXT NOT NULL,
  package_sha256                TEXT NOT NULL,
  csp_name                      TEXT NOT NULL,
  csp_legal_entity              TEXT NOT NULL,
  csp_country                   TEXT NOT NULL,                  -- ISO 3166-1 alpha-2
  eucs_assurance_level          TEXT NOT NULL,                  -- basic|substantial|high
  ncca_jurisdiction             TEXT NOT NULL,
  cab_name                      TEXT NOT NULL,
  cab_country                   TEXT NOT NULL,
  cab_accreditation_body        TEXT NOT NULL,
  cab_accreditation_number      TEXT NOT NULL,
  cab_includes_isms             BOOLEAN NOT NULL,
  cab_includes_pims             BOOLEAN NOT NULL,
  emitted_at                    TIMESTAMPTZ NOT NULL,
  submission_status             TEXT NOT NULL DEFAULT 'emitted', -- emitted|submitted|under-review|certified|rejected|withdrawn
  submitted_at                  TIMESTAMPTZ,
  submitted_by                  TEXT,
  cab_acknowledgement_id        TEXT,                            -- pasted by operator after CAB receipt
  certificate_id                TEXT,
  certificate_issued_at         TIMESTAMPTZ,
  certificate_expires_at        TIMESTAMPTZ,
  pentest_report_attached       BOOLEAN NOT NULL DEFAULT FALSE,
  encrypted_at_rest             BOOLEAN NOT NULL DEFAULT TRUE,
  created_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_eucs_submissions_csp_name ON eucs_submissions(csp_name);
CREATE INDEX idx_eucs_submissions_submission_status ON eucs_submissions(submission_status);
CREATE INDEX idx_eucs_submissions_eucs_assurance_level ON eucs_submissions(eucs_assurance_level);
CREATE UNIQUE INDEX idx_eucs_submissions_idempotency
  ON eucs_submissions(csp_name, emitted_at, eucs_assurance_level);
```

### 5.5 Operator notifications

Channel routing (driven by
`config.yaml::iso_z::notification_channels`):

- **Emit-time notification.** Slack `#fedramp-iso`. Title: "ISO/IEC
  27701 PIMS envelope emitted" / "ENISA EUCS {level} submission
  package emitted for <csp_name>". Body: link to tracker UI row, link
  to signed envelope.
- **CAB-engagement-letter-missing.** Slack + email-to-operator-PII-
  contact. Triggered when EUCS Substantial-or-higher requested but
  `iso-cab-engagement.yaml` empty or signature invalid.
- **Pentest-report-missing.** Slack at emit time. Triggered when
  EUCS High requested but `eucs-config.yaml.penetration_test_report`
  empty.
- **PIMS Annex B non-conformant findings.** Slack with link to
  per-finding details + POA&M URLs.

All notifications flow through the existing `core/notify.ts`. The
Z.Z5 extension is a new template module
`core/iso-z5-notification.ts`.

### 5.6 Submission-bundle entries

The signed PIMS envelope + EUCS ZIP are added to the submission
bundle via `core/submission-bundle.ts`'s `WELL_KNOWN` registry. New
roles:

```ts
{ role: 'iso-27701-pims-evidence',
  filename: 'iso-27701-pims-*.json',
  description: 'ISO/IEC 27701:2019 PIMS evidence envelope (LOOP-Z.Z5)' },
{ role: 'eucs-submission-package',
  filename: 'eucs-submission-package-*.zip',
  description: 'ENISA EUCS Candidate Scheme submission package (LOOP-Z.Z5)' },
{ role: 'eucs-cover-document',
  filename: 'eucs-submission-package-*/eucs-cover-document.docx',
  description: 'OOXML cover document for the EUCS submission (LOOP-Z.Z5)' },
```

---

## 6. Algorithm / Steps

### Phase A — Bootstrap

1. **Parse CLI flag** `--iso-z-z5` (or env `CLOUD_EVIDENCE_Z_Z5`).
   If neither set, the Z.Z5 module is a no-op for the orchestrator
   run.
2. **Read operator configuration.** Read `org-profile.yaml` →
   `{ gdpr_in_scope, eucs_target_level, pims_mode, csp_legal_entity }`.
   Read `iso-27701-pims-config.yaml`. Read `eucs-config.yaml`. Read
   `iso-cab-engagement.yaml`. Validate via Ajv.
3. **Conditional skip evaluation.** If `gdpr_in_scope == false` AND
   `eucs_target_level == 'none'`, emit log line
   `coverage:z-z5-not-applicable` and return success without writing
   any artifact. Otherwise proceed.
4. **Load Z.Z1 catalog.** Read `data/iso-27001-2022-annex-a.json`.
   Verify Ed25519 signature against `data/iso-27001-2022-annex-a.json.sig`.
   On signature failure, exit 2 with `Iso27001CatalogSignatureInvalidError`.
5. **Load Z.Z2 SoA.** Read `out/iso-27001-soa-{cspname}-{date}.json`
   for the latest date. Verify signature. On failure, exit 2.
6. **Load Z.Z3 coverage envelopes.** For each configured cloud
   provider in `org-profile.yaml.cloud_providers[]`, read
   `out/iso-27017-coverage-{cloud}.json`. Verify signatures. If a
   cloud envelope is missing, emit POA&M `EUCS-ARTIFACT-MISSING` and
   surface diagnostic; for EUCS Substantial-or-higher this is a hard
   failure.
7. **Load Z.Z4 evidence envelope.** Read `out/iso-27018-evidence.json`.
   Verify signature. If missing AND `eucs_target_level == 'high'` OR
   `pims_mode != 'none'`, this is a hard failure (POA&M emitted).
8. **Sign-test the corporate signing key.** Call
   `core/sign.ts::testSign(key_ref)` against the configured KMS
   resource. Failure → exit 2.

### Phase B — Compose PIMS envelope

9. **Build PIMS scope block.** Merge `iso-27701-pims-config.yaml.scope`
   with derived fields:
   - `organisational_units` from the YAML;
   - `geographic_boundaries` from the YAML + cross-check against
     Z.Z3's per-cloud regions (warn if a Z.Z3 cloud region is not
     in the PIMS scope's geographic boundaries — this is typically
     a misconfiguration);
   - `pii_categories` from the YAML;
   - `data_subject_categories` from the YAML;
   - `lawful_basis` from the YAML (validate each entry's `article`
     is in the `Article 6(1)(a)..(f)` enum);
   - `cross_border_transfers` from the YAML (validate each entry
     has a `lawful_mechanism` that matches the `gdpr_article` —
     SCCs ↔ Article 46; adequacy ↔ Article 45; BCR ↔ Article 47;
     Article 49 derogation ↔ Article 49);
   - `subprocessors` from the YAML (cross-check against Z.Z4's
     `subprocessors_disclosed[]` list; warn on mismatch).
10. **Compose PIMS controls block.**
    - For `pims_mode ∈ {'controller', 'both'}`: enumerate the 27701
      Annex A control list (31 controls). For each, derive
      disposition from `iso-27701-pims-overrides.yaml::annex_a` or
      from Z.Z4 evidence (where overlap exists per 27701 Annex E
      mapping).
    - For `pims_mode ∈ {'processor', 'both'}`: enumerate the 27701
      Annex B control list (the ~46 controls catalogued in §2.1).
      For each, derive disposition from
      `iso-27701-pims-overrides.yaml::annex_b` or from Z.Z4
      evidence.
    - For each control, attach `gdpr_articles[]` from the 27701
      Annex D mapping (LOOP-U's privacy crosswalk).
    - For each control, attach `iso_29100_principles[]` from the
      27701 Annex C mapping.
11. **Compose GDPR article coverage block.** Walk the PIMS controls
    block; union all `gdpr_articles[]`. Diff against the
    LOOP-U-supplied canonical GDPR-articles-list to compute
    `uncovered_articles`. Surface `uncovered_articles` as
    diagnostics — the operator may need to extend the PIMS scope.
12. **Compose privacy principles block.** Walk the 11 29100
    principles. For each, populate `implementation_reference` from
    `iso-27701-pims-config.yaml.privacy_principles_implementation`.
    Missing principles → REQUIRES-OPERATOR-INPUT.
13. **Compose Marketplace eligibility block.**
    - `iso_27701_pims_eligible = true` when ALL Annex B controls are
      `conformant` (or `not_applicable` with valid justification) AND
      a CAB engagement letter is signed AND `pims_audit_status >=
      'pending'`.
14. **Compose provenance block.** Record the SHA-256 of every input
    file Z.Z5 consumed.
15. **Sign the envelope.** Run `core/sign.ts::signEnvelope(envelope,
    key_ref)` to produce the Ed25519 signature. Embed signature in
    envelope.
16. **Timestamp the envelope.** Call
    `core/timestamp.ts::rfc3161Timestamp(envelope_sha256, tsa_url)`
    to obtain an RFC 3161 token. Embed in envelope.
17. **Write the envelope.** Path
    `out/iso-27701-pims-{cspname}-{date}.json`. Compute final SHA-256
    for downstream EUCS ZIP manifest.

### Phase C — Compose EUCS submission ZIP (when target level != 'none')

18. **Validate EUCS prerequisites.** For the requested assurance
    level:
    - **Basic.** SoA (Z.Z2) present. Scope statement present.
      Self-attestation block populated.
    - **Substantial.** Basic + Z.Z3 per-cloud coverage envelopes
      present for ALL configured clouds + CAB identification block
      populated + CAB accreditation includes ISMS.
    - **High.** Substantial + Z.Z4 27018 evidence + Z.Z5 PIMS
      envelope (just emitted in Phase B) + penetration-testing-
      report reference + CAB accreditation includes PIMS.
    - For each missing prerequisite, emit POA&M
      `EUCS-ARTIFACT-MISSING` with the specific artifact named.
      Refuse to emit the ZIP.
19. **Render EUCS cover document.** Run
    `core/iso-27701-pims-docx.ts::renderEUCSCoverDoc(manifest)` to
    produce `eucs-cover-document.docx`. The document includes the
    cover page, TOC, scope statement, constituent summary table,
    CAB engagement letter reference, attestation block, and
    signature placeholder.
20. **Build EUCS manifest.** Compose the manifest JSON per §5.2:
    - List every constituent file with its SHA-256.
    - Include CAB identification + NCCA jurisdiction.
    - Include service-in-scope from the YAML.
    - Include `marketplace_eucs_substantial_eligible` /
      `marketplace_iso_27701_pims_eligible` decisions.
    - Sign the manifest with Ed25519.
    - Timestamp via RFC 3161.
21. **Assemble ZIP.** Use the existing `core/oscal-package-zip.ts`
    pattern (zip-store mode for deterministic SHA-256). Order:
    manifest first, then constituents in lexicographic order.
22. **Detach-sign the ZIP.** Compute the SHA-256 of the ZIP file.
    Sign with Ed25519. Write the detached signature to
    `out/eucs-submission-package-{cspname}-{level}-{date}.zip.sig`.

### Phase D — Persist + register + notify

23. **Insert tracker DB row in `iso_27701_pims_scope`.** Capture
    every field per §5.4. Idempotency key is
    `(csp_name, emitted_at, pims_mode)`.
24. **Insert tracker DB row in `eucs_submissions`** (when the
    EUCS ZIP was emitted). Idempotency key is
    `(csp_name, emitted_at, eucs_assurance_level)`.
25. **Register new submission-bundle roles** via LOOP-A.A4
    bundler's `WELL_KNOWN` registry update.
26. **Emit POA&M findings** via LOOP-A.A1 for each non-conformant
    PIMS control with `applicable == true`. Template
    `PIMS-CONTROL-NON-CONFORMANT`. Reference the control ID + the
    affected `data_subject_categories` from the scope.
27. **Send operator notifications** per §5.5.
28. **Surface marketplace-eligibility decision to LOOP-Q.Q1.** Write
    to the shared tracker DB row `marketplace_eligibility` JSONB
    field. Q.Q1 reads this on its next badge-refresh cron.
29. **Exit.** Return success (exit 0). On any unrecoverable error
    in Phases A-C, exit 2 and ensure no partial tracker DB rows
    persist (transactions wrap the inserts in step 23-24).

---

## 7. Files to create / modify

Absolute paths under `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/`:

- **`cloud-evidence/core/iso-27701-pims.ts`** — main module: the
  Phase B PIMS envelope composer + Phase D persist + register.
- **`cloud-evidence/core/iso-27701-pims-docx.ts`** — OOXML cover
  document renderer (zip-store mode). Reuses the Z.Z2 SoA docx
  helpers.
- **`cloud-evidence/core/enisa-eucs-mapper.ts`** — maps each EUCS
  assurance level (basic / substantial / high) to its required
  artifact set + validates prerequisites per Phase C step 18.
- **`cloud-evidence/core/enisa-eucs-submission-package.ts`** — main
  EUCS module: assembles the ZIP per §5.2; signs the manifest; signs
  the archive.
- **`cloud-evidence/core/iso-z5-notification.ts`** — notification
  templates for Slack + email per §5.5.
- **`cloud-evidence/data/iso-27701-controls.json`** — canonical JSON
  of the 27701 Annex A + Annex B control identifiers + short names
  + cross-mappings (29100 / GDPR / 27018). Per LOOP-Z's REO + ISO
  copyright posture, no verbatim ISO text; control IDs + short
  names + mapping references only.
- **`cloud-evidence/data/enisa-eucs-rubric.json`** — canonical JSON
  of the EUCS assurance-level rubric: Basic / Substantial / High
  per-level artifact requirements + ENISA scheme version + adoption
  status.
- **`cloud-evidence/data/eucs-ncca-registry.json`** — operator-
  maintained registry of EU Member State NCCAs (ISO 3166-1 alpha-2
  + authority name + accreditation body); seeded with the publicly-
  known designations (BSI for DE, ANSSI for FR, ACN for IT, etc.).
- **`cloud-evidence/scripts/extract-iso-27701-controls.mjs`** —
  extraction helper for the 27701 control list (ID + short name);
  re-runs annually to capture any ISO update.
- **`cloud-evidence/scripts/extract-enisa-eucs.mjs`** — extraction
  helper for the EUCS rubric; re-runs when ENISA publishes a new
  draft or when the EU Commission adopts the scheme.
- **`cloud-evidence/test/iso-27701-pims.test.ts`** — unit tests for
  the PIMS module (target 18 tests per §8).
- **`cloud-evidence/test/enisa-eucs-mapper.test.ts`** — unit tests
  for the EUCS mapper + submission package (subset of the 18-test
  table; the remainder live in iso-27701-pims.test.ts).
- **`cloud-evidence/iso-27701-pims-config.yaml`** — operator-
  supplied PIMS configuration (template ships in repo).
- **`cloud-evidence/eucs-config.yaml`** — operator-supplied EUCS
  configuration (template ships in repo).
- **`cloud-evidence/iso-cab-engagement.yaml`** — operator-supplied
  CAB engagement letter reference (template ships in repo).
- **`cloud-evidence/tracker/migrations/0050_iso_27701_pims_scope.sql`**
  — tracker DB migration per §5.4.
- **`cloud-evidence/tracker/migrations/0051_eucs_submissions.sql`** —
  tracker DB migration per §5.4.
- **`cloud-evidence/tracker/server/routes/iso.ts`** — REST endpoints
  extended for PIMS + EUCS rows.
- **`cloud-evidence/tracker/client/src/pages/ISO.tsx`** — UI
  extended for PIMS scope-management + EUCS submission review.

Modifies (do not create):

- **`cloud-evidence/core/submission-bundle.ts`** — add 3 new
  WELL_KNOWN roles per §5.6.
- **`cloud-evidence/core/orchestrator.ts`** — wire `--iso-z-z5`
  dispatch.
- **`cloud-evidence/data/iso-27001-2022-annex-a.json`** — (no
  change; Z.Z5 reads but does not modify).

---

## 8. Test specifications

Minimum 18 tests per LOOP-Z-SPEC.md §7.1 (Z.Z5 row). The table below
enumerates the test plan. Fixture paths absolute under
`/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/iso-z5/`.

| id | scenario | fixture path | expected | acceptance |
|---|---|---|---|---|
| T01 | PIMS mode=processor; Annex B controls fully conformant; emit envelope | iso-z5/pims-processor-conformant/ | envelope written; `pims_controls.annex_b_processor_controls[*].disposition === 'conformant'`; signature verifies; marketplace_iso_27701_pims_eligible=true | exit 0; tracker row written; no POA&M |
| T02 | PIMS mode=both; controller and processor controls populated | iso-z5/pims-both-conformant/ | envelope has annex_a_controller_controls[] AND annex_b_processor_controls[]; both arrays non-empty | exit 0; tracker row marks pims_mode=both |
| T03 | PIMS mode=processor; one Annex B control non-conformant; POA&M emitted | iso-z5/pims-processor-one-nonconformant/ | envelope `annex_b_processor_controls[?control_id='B.8.5.6'].disposition === 'non-conformant'`; POA&M emitted with template `PIMS-CONTROL-NON-CONFORMANT` | exit 0; POA&M row appears; marketplace_iso_27701_pims_eligible=false |
| T04 | PIMS scope missing geographic boundaries — REQUIRES-OPERATOR-INPUT | iso-z5/pims-missing-geo/ | exit 2; diagnostic `requires_operator_input: pims_scope.geographic_boundaries`; no envelope written | tracker row NOT inserted; no Q.Q1 update |
| T05 | EUCS level=basic; minimal artifacts present; ZIP emitted | iso-z5/eucs-basic-minimal/ | ZIP at out/eucs-submission-package-{csp}-basic-{date}.zip; manifest valid; signature verifies | exit 0; eucs_submissions row inserted with eucs_assurance_level=basic |
| T06 | EUCS level=substantial; missing Z.Z3 envelope for AWS — POA&M emitted; package refused | iso-z5/eucs-substantial-missing-aws/ | exit 2 OR exit 0 with diagnostic; POA&M with template `EUCS-ARTIFACT-MISSING`; no ZIP written | tracker row NOT inserted; POA&M visible |
| T07 | EUCS level=substantial; all artifacts present; ZIP emitted with full manifest | iso-z5/eucs-substantial-full/ | ZIP contains SoA + 3 Z.Z3 coverage envelopes + cover doc + manifest; manifest constituents[] length === 5 (excluding pentest + 27018 + PIMS for Substantial) | exit 0; eucs_submissions row with eucs_assurance_level=substantial |
| T08 | EUCS level=high; missing penetration-test report — REQUIRES-OPERATOR-INPUT | iso-z5/eucs-high-missing-pentest/ | exit 0 with diagnostic `requires_operator_input: eucs_config.penetration_test_report`; POA&M emitted; no ZIP | tracker row NOT inserted |
| T09 | EUCS level=high; all artifacts present (incl. PIMS + 27018 + pentest); ZIP emitted | iso-z5/eucs-high-full/ | ZIP includes 27018 evidence + PIMS envelope + pentest pdf; manifest constituents[] >= 8 | exit 0; eucs_submissions row with eucs_assurance_level=high; marketplace_eucs_high_eligible=true |
| T10 | EUCS ZIP integrity: re-extract ZIP, recompute SHA-256 of each constituent, compare to manifest — all match | iso-z5/eucs-substantial-full/ + post-extract verification | every constituent's recomputed SHA-256 === manifest entry; signature verifies | unit test asserts hash equality |
| T11 | EUCS scheme version drift: rubric file lists scheme_version=2024-03; operator's rubric file is 180+ days stale; loader refuses | iso-z5/eucs-stale-rubric/ | exit 2; log `provenance:enisa-eucs-rubric-stale`; suggests re-running scripts/extract-enisa-eucs.mjs | no tracker row; no ZIP |
| T12 | PIMS Annex A vs Annex B integration: pims_mode=both; control overlap (e.g. B.7.2.5 PIA) — disposition is consistent | iso-z5/pims-both-overlap/ | overlapping controls render once per applicable annex; no duplicate keys; envelope schema validates | unit test asserts no duplicate control_id within an annex array |
| T13 | GDPR article coverage diff: PIMS controls cover Articles 5/6/28/32 but miss Article 33 (breach notification) — diagnostic surfaced | iso-z5/pims-missing-art33/ | `gdpr_article_coverage.uncovered_articles[]` includes "Article 33"; diagnostic emitted | exit 0; tracker row inserted with the uncovered_articles surfaced |
| T14 | Cross-border transfer with mismatched mechanism + article (e.g. SCC declared but Article 45 cited) — schema rejects | iso-z5/pims-transfer-mismatch/ | exit 2; Ajv validation error pointing to the offending `cross_border_transfers[]` entry | no envelope written |
| T15 | Subprocessor drift: Z.Z4's disclosed list has 12 subprocessors; iso-27701-pims-config.yaml has 11; warning surfaced | iso-z5/pims-subprocessor-drift/ | warn `coverage:subprocessor-drift`; envelope still emitted; tracker row reflects 11 (the PIMS-declared count) | exit 0 |
| T16 | CAB engagement letter absent for EUCS Substantial — REQUIRES-OPERATOR-INPUT | iso-z5/eucs-substantial-no-cab/ | exit 0 with diagnostic `requires_operator_input: iso_cab_engagement.yaml`; POA&M emitted | tracker row NOT inserted; ZIP not built |
| T17 | CAB accreditation does NOT include PIMS scope but EUCS High requested — warning surfaced (not fatal) | iso-z5/eucs-high-cab-no-pims/ | warn `coverage:cab-pims-scope-mismatch`; ZIP still built; manifest carries `cab_includes_pims=false` | exit 0; tracker row reflects false |
| T18 | Signature verify on PIMS envelope after read-back: write, read, verify — Ed25519 signature passes | iso-z5/pims-roundtrip/ | signature verifies; SHA-256 of canonical JSON stable | unit test asserts signature.verify() === true |
| T19 | Adversarial — operator overrides Annex B control to "not applicable" without justification | iso-z5/pims-override-no-justification/ | override rejected with diagnostic; control remains at derived disposition | exit 0; tracker row reflects override-rejected state |
| T20 | NIST Privacy Framework opt-in: --with-nist-privacy-framework flag adds the mapping block | iso-z5/pims-with-npf/ | envelope contains `nist_privacy_framework_mapping` block; absent when flag not passed | unit test asserts presence/absence by flag |
| T21 | Org-profile has gdpr_in_scope=false AND eucs_target_level=none — slice skipped | iso-z5/org-profile-z5-not-applicable/ | log line `coverage:z-z5-not-applicable`; exit 0; no envelope; no ZIP | no tracker row; no POA&M |
| T22 | `--iso-z-z5` flag not passed and env unset — slice not invoked from orchestrator | n/a | orchestrator dispatch table never calls `runIsoZ5(...)` | unit test asserts absence of call |
| T23 | End-to-end: Z.Z1 catalog → Z.Z2 SoA → Z.Z3 (3 clouds) → Z.Z4 → Z.Z5 PIMS + EUCS Substantial ZIP → bundler registration → Q.Q1 eligibility decision | iso-z5/e2e-full-fixture-set/ | both envelope + ZIP emitted; bundler picks up; Q.Q1 reads eligibility from tracker; badge rendered | exit 0; integration assertions pass |
| T24 | Schema-validation rejection: cross_border_transfers[].lawful_mechanism is invalid string — Ajv rejects | iso-z5/pims-invalid-mechanism/ | exit 2; Ajv error references the offending enum field | no envelope written |

(Tests T19, T20, T21, T22, T23, T24 add adversarial + integration
+ skip-path coverage beyond the LOOP-Z-SPEC.md §7.1 minimum of 18.)

---

## 9. Risks

Minimum 4 with mitigations per the COMMON preamble. The full register
lives in `docs/loops/LOOP-Z-RISKS.md`; the following are the per-slice
top-of-mind risks captured here for fresh-session resumability.

| risk_id | description | likelihood | impact | mitigation | owner |
|---|---|---|---|---|---|
| R-Z.Z5-01 | **ENISA EUCS scheme adoption uncertainty.** The EUCS scheme remains a Candidate Scheme (March 2024 draft) as of 2026-06-08. The EU Commission has signalled adoption is imminent, but the adopted scheme may differ from the 2024 draft in control IDs, assurance-level boundaries, or submission format. Z.Z5's rubric is fixed at extraction time. | high | medium | Rubric carries `enisa_version` + `enisa_adoption_status` fields; loader refuses to package if rubric is >180 days old (test T11). Operator re-runs `scripts/extract-enisa-eucs.mjs` when adoption announced; the script captures both the candidate-draft rubric and the adopted-rubric for backward-compat. Operator notification surfaces "EUCS scheme may have been amended; verify before submission". | LOOP-Z maintainer |
| R-Z.Z5-02 | **CAB rejection of submission format.** Different CABs accept different submission formats — some prefer ZIP, some PDF, some proprietary spreadsheets. The Z.Z5 ZIP is the canonical Z.Z5 output; a CAB may require translation. | medium | medium | Z.Z5 emits the canonical signed ZIP + a cover `.docx` that maps to the typical Stage 1 documentation review consumption pattern. Operator may extract individual constituents for CAB-specific format requests; the tracker captures the original signed ZIP as the canonical record. CAB engagement letter (operator-supplied) ideally includes format requirements; tracker UI surfaces a "verify with CAB" checklist before submission. | LOOP-Z maintainer + operator |
| R-Z.Z5-03 | **GDPR cross-border transfer regime instability (post-Schrems).** The CJEU's Schrems II decision (C-311/18, July 2020) invalidated Privacy Shield; the EU-U.S. Data Privacy Framework (Commission Implementing Decision (EU) 2023/1795) restored a US-adequacy pathway, but the Framework is subject to ongoing CJEU challenge. Any successful challenge would invalidate Z.Z5 envelopes that cite the Framework as the `lawful_mechanism`. | medium | high | Z.Z5's cross_border_transfers[] schema accepts multiple lawful mechanisms per transfer; operator can declare SCC as a fallback alongside adequacy_decision. Annual operator-attestation cycle in tracker UI re-prompts for transfer-mechanism review. PIMS envelope's `provenance.emitted_at` is timestamped (RFC 3161); a 3PAO reviewing a historical envelope can verify what was lawful at emit time. Notification routes to operator when CJEU publishes a relevant decision (operator-maintained watch-list). | LOOP-Z maintainer + operator + legal |
| R-Z.Z5-04 | **PIMS PII Controller vs PII Processor misclassification.** Operators frequently misclassify their role per GDPR Article 4(7)-(8) + EDPB 07/2020. A SaaS CSP that lets end-users register accounts directly is often a PII Controller for those accounts even though it's a PII Processor for enterprise-customer-uploaded data; the dual role is the most common misclassification source. | high | high | Tracker UI surfaces the EDPB 07/2020 controller/processor tests with operator tooltips. `pims_mode=both` accommodates dual roles; the operator narrative `pii_role_justification` is required (REQUIRES-OPERATOR-INPUT) and must reference EDPB 07/2020 §1.B + §2.1.2.D. Annual operator review (tracker UI re-prompt) re-confirms the classification. Misclassification surfaced via 3PAO review or external counsel review during PIMS Stage 2 audit; Z.Z5 emit is replay-able after the role is corrected. | LOOP-Z maintainer + operator + legal |
| R-Z.Z5-05 | **ISO copyright + redistribution risk.** Z.Z5 references 27701 Annex B control IDs + short names; the full implementation guidance per control is in the licensed ISO standard. A naive operator might attempt to populate Z.Z5's JSON with verbatim ISO text (e.g. pasting the full 27701 control text into `justification` fields). | medium | medium | LOOP-Z-SPEC.md §1.5 documents the redistribution posture; CLAUDE.md REO Rule 4 governs operator-supplied data. Z.Z5's schema validator surfaces a heuristic check: if a `justification` field exceeds 2,000 characters AND contains the substring "ISO/IEC", warn `coverage:potential-iso-text-redistribution` and prompt the operator to confirm. The operator-confirmed acknowledgement is recorded in the tracker audit log; the warning does not block emission. Operator-side governance lives in the CSP's compliance / legal function. | LOOP-Z maintainer + operator |
| R-Z.Z5-06 | **EUCS High assurance level requires penetration testing report — operator may not have a current one.** EUCS High explicitly requires independent penetration testing (per the EUCS scheme draft). Many CSPs run pentest cycles annually; the report may be 6-12 months old by the time the EUCS High package is assembled. | medium | medium | Z.Z5 reads `eucs-config.yaml.penetration_test_report.pentest_completed_at` and warns if it is >365 days old (heuristic, since ENISA EUCS draft does not specify a maximum age). Operator surfaces the warning in tracker UI before submission. CAB ultimately determines whether the pentest meets EUCS High's standard; LOOP-Z surfaces but does not decide. | LOOP-Z maintainer + operator |
| R-Z.Z5-07 | **Marketplace badge over-claiming.** Q.Q1 reads `iso_27701_eligible` and `eucs_substantial_eligible` from the Z.Z5 tracker rows. An operator may flip a control disposition manually in the tracker DB to inflate eligibility without going through Z.Z5's signed-envelope emission. | low | high | Q.Q1 verifies the badge eligibility against the SIGNED envelope SHA-256, not the tracker row alone. The badge URL points to the signed envelope; any third-party can verify the signature. Tracker UI requires officer-signoff before promoting a tracker row from `pending` → `certified`; the signoff is in the signed tracker audit log. | LOOP-Z maintainer |

---

## 10. Open questions

| oq_id | question | affects | proposed disposition | status |
|---|---|---|---|---|
| OQ-Z.Z5-01 | Does the EUCS scheme adoption (post-2024 candidate) change the assurance-level boundaries (Basic / Substantial / High) or the per-level required artifact set? | EUCS rubric + Z.Z5 mapper | OPERATOR-RESEARCH — implementer monitors EU Commission Official Journal and re-fetches `scripts/extract-enisa-eucs.mjs` when adoption announced. The rubric file's `enisa_version` field carries the version. | OPEN |
| OQ-Z.Z5-02 | What is the canonical EUCS submission portal? ENISA's website lists Member State NCCAs but no single EU-wide intake. | EUCS submission UX | OPERATOR-RESEARCH — most submissions appear to go through the targeted-Member-State NCCA; the operator declares the NCCA via `eucs-config.yaml.ncca_jurisdiction`; the tracker UI surfaces the NCCA's submission URL (operator-maintained registry). | OPEN |
| OQ-Z.Z5-03 | How does Z.Z5 handle the case where the operator targets multiple EU Member States (e.g. wants EUCS Substantial certification recognised across DE + FR + IT)? | EUCS submission package | DEFERRED — current Z.Z5 emits one ZIP per target NCCA jurisdiction. Mutual recognition under the EU Cybersecurity Act Article 56 means a single Member State's certification IS recognised EU-wide, so the multi-jurisdiction emit is rarely needed. Operator submits to the most-favourable NCCA. | DOCUMENTED |
| OQ-Z.Z5-04 | Does Z.Z5 need to emit the EUCS submission in an EU-language other than English (e.g. German for BSI submission)? | EUCS cover doc localisation | OPERATOR-DECISION — current emit is English-only. Operator can engage a translation service; the translated cover doc is the operator's responsibility. Tracker UI captures the translation-status as metadata. | OPERATOR-DECISION |
| OQ-Z.Z5-05 | If the CAB acknowledgement-receipt id is in a CAB-proprietary format, how does Z.Z5 validate it? | Marketplace eligibility | OPERATOR-DECISION — the receipt id is treated as an opaque operator-input string. Tracker UI captures it in a free-text field; the signed audit log records the input. Q.Q1 surfaces the receipt id on the badge tooltip for third-party verification. | RESOLVED |
| OQ-Z.Z5-06 | Should Z.Z5's PIMS envelope reference Z.Z4's evidence via SHA-256-pinned embed, or by file-path-only reference? | Envelope size + integrity | RESOLVED — Z.Z5 references Z.Z4's evidence via SHA-256-pinned reference (not full embed); the EUCS ZIP at level=High embeds Z.Z4's evidence file directly so the CAB has a single artifact. PIMS envelope stays compact. | RESOLVED |
| OQ-Z.Z5-07 | Does the ENISA EUCS scheme require the CSP to publish the EUCS certificate on their public website (similar to the GDPR Article 30 records publication requirement for some sectors)? | Operator obligation | OPERATOR-RESEARCH — the 2024 draft does not require public publication; ENISA may add this in adoption. Tracker UI tracks "certificate published at <URL>" as an optional operator-supplied field. | OPEN |
| OQ-Z.Z5-08 | How does Z.Z5 interact with LOOP-Q.Q1's badge-refresh cadence? Does Q.Q1 poll the tracker DB or does Z.Z5 push? | Cross-loop integration | RESOLVED — Z.Z5 updates the `marketplace_eligibility` JSONB field on the tracker row at emit time; Q.Q1's next badge-refresh cron (typically hourly) reads the row and emits/refreshes the badge. No push-from-Z.Z5 to Q.Q1 is required. | RESOLVED |
| OQ-Z.Z5-09 | Does the EUCS submission require a `legal-entity-identifier` (LEI) per ISO 17442? | EUCS schema | OPERATOR-RESEARCH — the 2024 draft does not explicitly require LEI but many EU Member State NCCAs prefer it. `eucs-config.yaml.csp_legal_entity` is required (REQUIRES-OPERATOR-INPUT); the operator may optionally include an LEI. | DEFERRED |
| OQ-Z.Z5-10 | Should Z.Z5 surface a separate "EUCS Basic Eligible" marketplace badge, or does Q.Q1 only emit Substantial+? | Marketplace UX | DEFERRED — Q.Q1's badge taxonomy is owned by LOOP-Q; current expectation is Substantial-and-above only (Basic is self-attested and may not carry the marketing weight to warrant a badge). Operator can configure Q.Q1 to include Basic if desired. | DEFERRED to LOOP-Q |

---

## 11. REQUIRES-OPERATOR-INPUT

| field name | type | validator | UI location | failure mode if missing |
|---|---|---|---|---|
| `org-profile.yaml: gdpr_in_scope` | boolean | strict bool | `cloud-evidence/org-profile.yaml` | When false AND eucs_target_level==none, slice skipped; otherwise REQUIRES; without the explicit declaration, Z.Z5 cannot decide whether to invoke |
| `org-profile.yaml: eucs_target_level` | enum | basic\|substantial\|high\|none | `cloud-evidence/org-profile.yaml` | Slice exit 2 with `requires_operator_input: eucs_target_level` |
| `org-profile.yaml: pims_mode` | enum | processor\|controller\|both | `cloud-evidence/org-profile.yaml` | Slice exit 2 with `requires_operator_input: pims_mode` |
| `iso-27701-pims-config.yaml: pii_role_justification` | string | >=200 chars; must reference EDPB 07/2020 | `cloud-evidence/iso-27701-pims-config.yaml` | Slice exit 2; diagnostic surfaces EDPB tests |
| `iso-27701-pims-config.yaml: scope.scope_statement` | string | >=500 chars | `cloud-evidence/iso-27701-pims-config.yaml` | Slice exit 2 |
| `iso-27701-pims-config.yaml: scope.geographic_boundaries` | array | at least 1 entry | `cloud-evidence/iso-27701-pims-config.yaml` | Slice exit 2 (test T04) |
| `iso-27701-pims-config.yaml: scope.pii_categories` | array | at least 1 entry | `cloud-evidence/iso-27701-pims-config.yaml` | Slice exit 2 |
| `iso-27701-pims-config.yaml: scope.lawful_basis` | array | at least 1 entry with valid Article 6(1) | `cloud-evidence/iso-27701-pims-config.yaml` | Slice exit 2 |
| `iso-27701-pims-config.yaml: scope.cross_border_transfers` | array | per-entry mechanism↔article validation | `cloud-evidence/iso-27701-pims-config.yaml` | Slice exit 2 if any non-EU destination present without mechanism (test T14) |
| `iso-27701-pims-config.yaml: scope.subprocessors` | array | per-entry subprocessor schema | `cloud-evidence/iso-27701-pims-config.yaml` | Warn `coverage:subprocessor-drift` if mismatch with Z.Z4 (test T15) |
| `iso-27701-pims-config.yaml: privacy_principles_implementation` | record | all 11 29100 principles populated | `cloud-evidence/iso-27701-pims-config.yaml` | Per-principle REQUIRES-OPERATOR-INPUT |
| `eucs-config.yaml: csp_legal_entity` | string | non-empty | `cloud-evidence/eucs-config.yaml` | Slice exit 2 if EUCS path invoked |
| `eucs-config.yaml: csp_country_iso3166_alpha2` | string | 2-char ISO 3166-1 alpha-2 | `cloud-evidence/eucs-config.yaml` | Slice exit 2 if EUCS path invoked |
| `eucs-config.yaml: service_in_scope` | array | at least 1 entry | `cloud-evidence/eucs-config.yaml` | Slice exit 2 |
| `eucs-config.yaml: ncca_jurisdiction` | string | 2-char ISO 3166-1; in EU/EEA | `cloud-evidence/eucs-config.yaml` | Slice exit 2 if EUCS path invoked |
| `iso-cab-engagement.yaml: cab_identification.cab_name` | string | non-empty | `cloud-evidence/iso-cab-engagement.yaml` | Slice exit with diagnostic; POA&M emitted; no ZIP (test T16) |
| `iso-cab-engagement.yaml: cab_identification.cab_accreditation_number` | string | non-empty | `cloud-evidence/iso-cab-engagement.yaml` | Slice exit with diagnostic |
| `iso-cab-engagement.yaml: cab_engagement_letter_path` | absolute path | file exists + SHA-256 match | `cloud-evidence/iso-cab-engagement.yaml` | Slice exit with diagnostic |
| `eucs-config.yaml: penetration_test_report.pentest_report_path` | absolute path | file exists; required for High | `cloud-evidence/eucs-config.yaml` | When eucs_target_level=high: REQUIRES (test T08); when other levels: optional |
| `data/iso-27001-2022-annex-a.json` (produced by Z.Z1) | file path | exists + signature valid | `cloud-evidence/data/` | Slice exits 2 with `provenance:iso-27001-catalog-signature-invalid` |
| `out/iso-27001-soa-{cspname}-{date}.json` (produced by Z.Z2) | file path | exists + signature valid | `cloud-evidence/out/` | Slice exits 2 |
| `out/iso-27017-coverage-{cloud}.json` (produced by Z.Z3) | file path | exists + signature valid | `cloud-evidence/out/` | When EUCS Substantial+: REQUIRES; POA&M emitted (test T06) |
| `out/iso-27018-evidence.json` (produced by Z.Z4) | file path | exists + signature valid | `cloud-evidence/out/` | When EUCS High OR PIMS mode != none: REQUIRES |
| `data/enisa-eucs-rubric.json` | file path | exists; age <180d | `cloud-evidence/data/` | Slice exits 2; suggests `scripts/extract-enisa-eucs.mjs` (test T11) |
| `data/iso-27701-controls.json` | file path | exists | `cloud-evidence/data/` | Slice exits 2; suggests `scripts/extract-iso-27701-controls.mjs` |
| `org-profile.yaml: marketplace_url` (optional) | URL | https:// | `cloud-evidence/org-profile.yaml` | Marketplace eligibility decision still computed; not surfaced to Q.Q1 if URL absent |

---

## 12. Implementation log slot

| date | session | action | commit | notes |
|---|---|---|---|---|
| 2026-06-08 | spec proposed | wf-uvxyz-gapfill | Specification authored via gap-fill workflow | TBD | Spec derived from LOOP-Z-SPEC.md §1.2 artifact list rows 11-14 + §2.5 + §2.6 + §7.1 Z.Z5 row + the cross-references to Z.Z1/Z.Z2/Z.Z3/Z.Z4 and LOOP-Q.Q1 marketplace badging; verbatim quotes pulled from ISO 27701:2019 abstract + clause 5.x preview text (paid standard, no full-text redistribution per LOOP-Z-SPEC §1.5), ISO 27001:2022 clause 6.1.3 SoA requirement, ISO 27002:2022 abstract, ISO 27017:2015 abstract, ISO 27018:2019 abstract, ENISA EUCS factsheet (verbatim from public HTML), EU Cybersecurity Act Articles 49/51/52/56/58 (verbatim from EUR-Lex), GDPR Articles 28/32/44/46/49 (verbatim from EUR-Lex), NIST OLIR program page, ISO 17021-1 + 27006 preview, ENISA EUCC factsheet, ISO 29100 (publicly-available standard), NIST Privacy Framework v1.0 landing page, and EDPB Guidelines 07/2020 §1.B + §2.1.2.D (verbatim from EDPB PDF). 14 distinct authoritative sources cited; ≥18 verbatim blockquotes captured (counting each multi-paragraph Article quote as one). Test plan = 24 tests (exceeds §7.1 minimum of 18 by 6). 7 risks captured here; full register entries will be appended to LOOP-Z-RISKS.md by the orchestrator. PIMS Annex B control list catalogued at structural-identifier level (46 controls) per the publicly-available ISO 27701 preview; Annex A (PII Controller) control count noted (~31). EUCS rubric carries 3 levels (Basic / Substantial / High) with per-level artifact-requirement table sourced from EUR-Lex Article 52 verbatim. |
| | | | | |
| | | | | |

(Append per-session entries below per `docs/IMPLEMENTATION-LOG-TEMPLATE.md` cadence: at every commit boundary, every test failure, every research question answered, every spec divergence, every newly-discovered risk, every external dependency pin.)

---

## 13. Completion checklist

Per `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` — verbatim
quotation of the 7-step procedure (followed by step 8 from the
COMMON preamble):

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

In addition, for Z.Z5 specifically:

- Update `cloud-evidence/docs/slices/Z/Z.Z5.md` frontmatter:
  `status: done`, `commit: <hash>`, `completed_date: <YYYY-MM-DD>`,
  `last_updated: <YYYY-MM-DD>`.
- Append the final Implementation log entry to §12 above per
  `docs/IMPLEMENTATION-LOG-TEMPLATE.md`.
- If any new risks surfaced during implementation, append to
  `cloud-evidence/docs/loops/LOOP-Z-RISKS.md` in the same commit.
- Verify the cross-loop dependency `LOOP-Q.Q1` is unblocked for the
  EUCS + PIMS marketplace badges (Z.Z5 blocks Q.Q1 per
  LOOP-Z-SPEC.md §11.1). Update `docs/DEPENDENCY-GRAPH.md` if
  needed.
- Because Z.Z5 is the LAST slice in LOOP-Z, update the LOOP-Z title
  section in STATUS.md to indicate "(COMPLETE)" per the
  SLICE-COMPLETION-PROCEDURE.md Step 2 third bullet. Also increment
  the "Overall → loops-complete" count and update
  "Overall → next-priority" to the next loop on the roadmap.
- If the implementation surfaces any additional Open Questions
  beyond the 10 catalogued in §10 above, capture them in the same
  commit by appending rows to the OQ table.
