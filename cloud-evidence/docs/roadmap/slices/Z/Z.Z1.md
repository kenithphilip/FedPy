---
slice_id: Z.Z1
title: ISO/IEC 27001:2022 Annex A Control Catalog + Crosswalk to NIST 800-53 Rev 5 + FedRAMP Moderate
loop: Z
status: proposed
commit: TBD
completed_date: —
depends_on:
  - LOOP-A.A5                           # Ed25519 + RFC 3161 + RFC 8785 canonicalization signing primitive
blocks:
  - Z.Z2                                # SoA emitter consumes the canonical catalog + crosswalk
  - Z.Z3                                # ISO/IEC 27017 cloud overlay attaches to Z.Z1 control IDs
  - Z.Z4                                # ISO/IEC 27018 PII processor extension references Z.Z1 baseline controls
  - Z.Z5                                # ISO/IEC 27701 PIMS + ENISA EUCS package inherit Z.Z1 catalog
estimated_effort: medium (~5-7 working days for single implementer)
last_updated: 2026-06-08
applicable_conditional: false
condition: |
  Z.Z1 is conditional on LOOP-Z's outer trigger. LOOP-Z fires when the
  CSP seeks ISO/IEC 27001:2022 certification in addition to a FedRAMP
  authorization — a common pattern for CSPs that also serve international
  enterprise customers, EU public-sector customers (via the forthcoming
  ENISA EUCS scheme), UK G-Cloud customers, Japan ISMAP customers,
  Australia IRAP customers, GCC Common-Assurance-Framework customers,
  Singapore MTCS customers, or India CERT-In customers. The slice's
  applicability gate is the operator-supplied `compliance.iso_27001.seek_certification`
  field in `org-profile.yaml` (one of `true | planning | false`). When
  the field is `false`, Z.Z1 is a no-op for the orchestrator run. When
  `planning`, Z.Z1 still runs (so the operator can preview the SoA shape
  + the per-control crosswalk) but Z.Z2/Z.Z3/Z.Z4/Z.Z5 are gated to
  `true`. When `true`, all five Z slices run and the SoA / 27017 overlay /
  27018 PII processor / 27701 PIMS / EUCS submission package are emitted.
  Z.Z1 itself is *also* runnable as a stand-alone analyst tool: a third-
  party analyst with no ISO certification ambition can run `Z.Z1`
  unconditionally to obtain the ISO 27001:2022 → NIST 800-53 Rev 5 →
  FedRAMP Moderate three-way crosswalk for use in their own
  cross-framework reasoning.
trigger_flag: "--iso-z-z1"
trigger_env: CLOUD_EVIDENCE_Z_Z1
---

# Z.Z1 — ISO/IEC 27001:2022 Annex A Control Catalog + Crosswalk to NIST 800-53 Rev 5 + FedRAMP Moderate

> Z.Z1 is the **foundation** slice for LOOP-Z. Every downstream slice
> (Z.Z2 emits the Statement of Applicability, Z.Z3 attaches the ISO/IEC
> 27017 cloud overlay, Z.Z4 layers the 27018 PII-processor extensions,
> Z.Z5 emits the 27701 PIMS + ENISA EUCS submission package) reads this
> slice's canonical JSON output. If the catalog is wrong, every
> downstream artifact is wrong. So this doc carries extra verbatim
> citations from the ISO/IEC 27001:2022 standard's publicly-available
> preview pages, the publicly-available ISO/IEC 27002:2022 attribute
> table, the ISO/IEC 27017:2015 + 27018:2019 + 27701:2019 preview pages,
> the ENISA EUCS Candidate Scheme draft (which is freely available), the
> EU Cybersecurity Act (Regulation (EU) 2019/881) which is freely
> available on EUR-Lex, and the NIST Online Informative References
> (OLIR) programme that publishes the one-way ISO 27001 → NIST 800-53
> informative mapping. Every control ID, theme assignment, attribute
> dimension, and crosswalk row traces back to a published source.
>
> Authority: `cloud-evidence/CLAUDE.md` (Real-Evidence-Only standard)
> governs every emit path. Every byte traces back to: (a) the publicly-
> available ISO 27001/27002 preview text + ISO's bibliographic record,
> (b) the publicly-available ISO 27017/27018/27701 preview text + ISO
> bibliographic record, (c) the freely-available ENISA EUCS draft, (d)
> the NIST OLIR mapping JSON downloaded from the OLIR programme
> endpoint, (e) the existing `data/frmr-ksi-catalog.json` for the
> FedRAMP-Moderate column, or (f) operator-supplied overrides committed
> to `cloud-evidence/data/iso-27001-overrides.yaml`. No defaults, no
> placeholders, no stub returns. Where the ISO source is paywalled (most
> ISO standards are), the implementer references the publicly-available
> preview page + ISO's bibliographic record + the NIST OLIR informative
> mapping; the operator's licensed copy of the standard is consulted
> only for full implementation guidance and is NOT redistributed by this
> codebase.

---

## 1. Mission

Z.Z1 ingests the **ISO/IEC 27001:2022 Annex A control set** — all 93
controls organised into 4 themes (Organizational A.5.* with 37
controls, People A.6.* with 8 controls, Physical A.7.* with 14
controls, Technological A.8.* with 34 controls) — plus the ISMS clauses
4 through 10 (Context of the organization, Leadership, Planning,
Support, Operation, Performance evaluation, Improvement), preserves the
**theme classification**, captures the **five attribute dimensions**
that ISO/IEC 27002:2022 attaches to each control (Control type,
Information security properties, Cybersecurity concepts, Operational
capabilities, Security domains), produces a deterministic canonical
JSON catalog (`cloud-evidence/data/iso-27001-2022-annex-a.json`) with a
schema-pinned shape, an Ed25519 signature, and an RFC 3161 timestamp,
and exposes the catalog to downstream slices via a typed TypeScript
loader (`cloud-evidence/core/iso-27001-2022-catalog.ts`).

The slice additionally produces a **three-way crosswalk** to:

1. **NIST 800-53 Rev 5** controls — sourced from the NIST Online
   Informative References (OLIR) programme's ISO/IEC 27001 → NIST
   800-53 Rev 5 mapping (one-way informative crosswalk). The OLIR
   mapping is a JSON record carrying source-control ID + target-control
   ID + a relationship type (`subset_of | superset_of | equivalent |
   intersects | not_related`). Z.Z1 normalises the OLIR output and
   stores the relationship type alongside the target ID.
2. **FedRAMP Moderate** baseline parameter IDs — sourced from the
   existing `data/frmr-ksi-catalog.json` (the FedRAMP 20x KSI catalog).
   The crosswalk identifies, for each Annex A control, the set of
   FedRAMP Moderate KSIs whose 800-53 parameter set intersects the
   OLIR-mapped 800-53 controls. This is the bridge that lets a FedPy
   operator already running FedRAMP-Moderate evidence collection
   inherit the technical evidence into the SoA without re-running
   collectors.
3. **ISO/IEC 27001:2013 legacy controls** — sourced from the publicly-
   available ISO 27001:2013→2022 transition mapping table (published
   informally during the 2022 release; reproduced in secondary
   academic + auditor sources). The legacy mapping is *informative
   only* — the transition deadline ended 2025-10-31 and the 2013
   edition is no longer accepted by certification bodies — but the
   mapping is useful for orgs that previously held a 27001:2013
   certificate and need to demonstrate continuity in their internal
   audit programme.

Z.Z1 does **not** ingest the ISO/IEC 27017:2015 cloud-extension controls
(those are handled by Z.Z3), the ISO/IEC 27018:2019 PII-processor
controls (Z.Z4), the ISO/IEC 27701:2019 PIMS extension (Z.Z5), or the
EUCS assurance-level mapping (Z.Z5). Z.Z1's catalog is the **27001 core
+ 27002 attributes + crosswalks** only.

Catalogs are emitted as canonical JSON with byte-stable key ordering
(RFC 8785 JCS) so the SHA-256 of the catalog is the authoritative
content hash used by every downstream consumer for provenance tracking.
The signature is detached Ed25519 over the JCS-canonicalized bytes; the
RFC 3161 token is over the same bytes. Both the signature and the
token are stored alongside the catalog JSON in the same directory.

The slice runs once per release of ISO/IEC 27001 (the standard is on
a multi-year revision cycle; the next major reissue is unlikely before
2030 at the earliest) and once per release of the NIST OLIR mapping
JSON (the OLIR programme updates mappings as 800-53 revises; 800-53
Rev 6 is currently in draft, so a Rev 5 → Rev 6 mapping refresh is
expected within the LOOP-Z 12-month window). The operator schedules
the re-ingestion via the existing tracker UI cron pane; the
orchestrator surfaces a `catalog-stale` warning when the catalog's
`extracted_at` is more than 365 days old OR when the NIST OLIR mapping
endpoint reports a `last-modified` newer than the catalog's
`olir_extracted_at`.

The slice's outputs are consumed by Z.Z2 (SoA emitter, which reads
every control + applicability metadata), Z.Z3 (the 27017 overlay
attaches augmented-control records to a subset of Z.Z1 controls), Z.Z4
(the 27018 PII-processor overlay attaches PII-specific implementation
guidance to ~14 baseline Annex A controls), Z.Z5 (the 27701 PIMS
extension + the EUCS submission package both inherit the entire 93-
control set verbatim), and by any third-party analyst tool that needs
the canonical three-way crosswalk JSON.

---

## 2. Authoritative sources

Every URL accessed 2026-06-08. Verbatim quotes appear in Markdown
blockquotes. Where an ISO standard is paywalled, the implementer
quotes only the publicly-available preview text and the publicly-
available bibliographic record; the licensed full standard is
consulted by the operator's compliance team and is NOT redistributed
by this codebase. Where the source is freely available (NIST OLIR,
ENISA EUCS draft, EUR-Lex EU Cybersecurity Act), the implementer
quotes verbatim from the live source URL.

### 2.1 ISO/IEC 27001:2022 — Information security management systems — Requirements

URL: https://www.iso.org/standard/27001 (accessed 2026-06-08).
Status: Published October 2022. Withdrew the 2013 edition. Transition
period for previously-issued 27001:2013 certifications ended 2025-10-31.
Approximate licensing fee: CHF 138 (Swiss francs) for the full PDF.

Publicly-available scope statement from the ISO preview page:

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

The seven normative ISMS clauses (4 through 10) are required for any
27001 conformance claim:

| Clause | Title | Mandatory? |
|---|---|---|
| 4 | Context of the organization (4.1 understanding the org + context, 4.2 understanding interested parties' needs and expectations, 4.3 determining the scope of the ISMS, 4.4 ISMS) | yes |
| 5 | Leadership (5.1 leadership and commitment, 5.2 policy, 5.3 organizational roles, responsibilities and authorities) | yes |
| 6 | Planning (6.1 actions to address risks and opportunities, 6.1.2 information security risk assessment, 6.1.3 information security risk treatment — **requires SoA**, 6.2 information security objectives, 6.3 planning of changes) | yes |
| 7 | Support (7.1 resources, 7.2 competence, 7.3 awareness, 7.4 communication, 7.5 documented information) | yes |
| 8 | Operation (8.1 operational planning and control, 8.2 information security risk assessment, 8.3 information security risk treatment) | yes |
| 9 | Performance evaluation (9.1 monitoring/measurement/analysis/evaluation, 9.2 internal audit, 9.3 management review) | yes |
| 10 | Improvement (10.1 continual improvement, 10.2 nonconformity and corrective action) | yes |

Clause 6.1.3 — the source of the Statement of Applicability requirement
that Z.Z2 emits — is quoted verbatim from the publicly-available preview
text (re-keyed from the ISO standard's free preview pages):

> "The organization shall define and apply an information security risk
> treatment process to:
> (a) select appropriate information security risk treatment options,
> taking account of the risk assessment results;
> (b) determine all controls that are necessary to implement the
> information security risk treatment option(s) chosen;
> (c) compare the controls determined in 6.1.3 b) above with those in
> Annex A and verify that no necessary controls have been omitted;
> (d) produce a Statement of Applicability that contains: the necessary
> controls (see 6.1.3 b) and c)) and justification for inclusions,
> whether the necessary controls are implemented or not, and the
> justification for exclusions of any of the Annex A controls;
> (e) formulate an information security risk treatment plan; and
> (f) obtain risk owners' approval of the information security risk
> treatment plan and acceptance of the residual information security
> risks. The organization shall retain documented information about the
> information security risk treatment process."

**Annex A — Reference control set.** The Annex A reference set contains
93 controls organised into 4 themes. The theme + control count
breakdown is:

| Theme | Range | Count |
|---|---|---|
| A.5 — Organizational controls | A.5.1 through A.5.37 | 37 |
| A.6 — People controls | A.6.1 through A.6.8 | 8 |
| A.7 — Physical controls | A.7.1 through A.7.14 | 14 |
| A.8 — Technological controls | A.8.1 through A.8.34 | 34 |
| **Total** | — | **93** |

Z.Z1's `data/iso-27001-2022-annex-a.json` catalogs all 93 controls by
canonical control ID (e.g. `A.5.1`, `A.8.24`) + canonical short title
(e.g. "Policies for information security", "Use of cryptography"). The
implementer pulls the canonical ID + short-title list from the
publicly-available ISO Annex A preview page (which prints the index of
the 93 controls without full implementation guidance). The operator's
licensed copy is consulted to verify each entry; any operator-detected
discrepancy is committed to `data/iso-27001-overrides.yaml` and merged
at load time with `provenance: operator-correction`.

### 2.2 ISO/IEC 27002:2022 — Information security controls (code of practice)

URL: https://www.iso.org/standard/27002 (accessed 2026-06-08).
Status: Published February 2022. Provides implementation guidance for
the 93 controls referenced by 27001:2022 Annex A. 27001 references the
controls *as a list*; 27002 elaborates the *implementation*.

Publicly-available scope statement:

> "This document provides a reference set of generic information
> security controls including implementation guidance. This document is
> designed to be used by organizations: a) within the context of an
> information security management system (ISMS) based on ISO/IEC 27001;
> b) for implementing information security controls based on
> internationally recognized best practices; and c) for developing
> organization-specific information security management guidelines."

Each control in 27002:2022 carries **five attribute dimensions** (a
structural change from 27002:2013 that 27002:2022 introduces; the
attribute table is the bridge between 27001/27002 and NIST CSF +
NIST 800-53):

| Attribute dimension | Allowed values |
|---|---|
| Control type | `#Preventive`, `#Detective`, `#Corrective` |
| Information security properties | `#Confidentiality`, `#Integrity`, `#Availability` |
| Cybersecurity concepts | `#Identify`, `#Protect`, `#Detect`, `#Respond`, `#Recover` (NIST CSF alignment) |
| Operational capabilities | `#Governance`, `#Asset_management`, `#Information_protection`, `#Human_resource_security`, `#Physical_security`, `#System_and_network_security`, `#Application_security`, `#Secure_configuration`, `#Identity_and_access_management`, `#Threat_and_vulnerability_management`, `#Continuity`, `#Supplier_relationships_security`, `#Legal_and_compliance`, `#Information_security_event_management`, `#Information_security_assurance` |
| Security domains | `#Governance_and_Ecosystem`, `#Protection`, `#Defence`, `#Resilience` |

Z.Z1's per-control row carries all five dimensions as JSON arrays. The
attribute values are seeded from the publicly-available 27002:2022
preview pages + the publicly-available cross-references published by
secondary academic sources (BSI, NIST CSF mapping projects, OLIR
records). The operator's licensed copy is consulted to verify; any
discrepancy is committed to `iso-27001-overrides.yaml`.

### 2.3 ISO/IEC 27017:2015 — Cloud services code of practice

URL: https://www.iso.org/standard/27017 (accessed 2026-06-08).
Status: Published December 2015. No 2022 reissue yet (reissue is
expected mid-2026 to align the cloud overlay with the new 27002:2022
attribute model). 27017 supplements 27002 with cloud-specific guidance
+ adds 7 cloud-specific controls in a new namespace `CLD.*`.

Publicly-available scope statement (paraphrased from ISO's preview;
verbatim quote re-keyed from the free preview pages):

> "This Recommendation | International Standard provides guidelines for
> information security controls applicable to the provision and use of
> cloud services by providing: additional implementation guidance for
> relevant controls specified in ISO/IEC 27002; additional controls
> with implementation guidance that specifically relate to cloud
> services. This Recommendation | International Standard provides
> controls and implementation guidance for both cloud service providers
> and cloud service customers."

The 7 cloud-specific controls (publicly-summarised from ISO's preview
page + secondary academic sources):

| Control ID | Title |
|---|---|
| CLD.6.3.1 | Shared roles and responsibilities within a cloud computing environment |
| CLD.8.1.5 | Removal of cloud service customer assets |
| CLD.9.5.1 | Segregation in virtual computing environments |
| CLD.9.5.2 | Virtual machine hardening |
| CLD.12.1.5 | Administrator's operational security |
| CLD.12.4.5 | Monitoring of cloud services |
| CLD.13.1.4 | Alignment of security management for virtual and physical networks |

Z.Z1 stores the CLD.* IDs as cross-references on the JSON envelope's
`see_also` block (the full CLD.* records are emitted by Z.Z3). The
shared-responsibility split — for each augmented 27002 control, 27017
specifies which obligations land on the CSP and which on the CSC — is
consumed by Z.Z3 and **not** by Z.Z1.

### 2.4 ISO/IEC 27018:2019 — PII protection in public clouds (PII processor)

URL: https://www.iso.org/standard/76559 (accessed 2026-06-08).
Status: Published January 2019 (second edition; first published 2014).
27018 supplements 27002 with PII-protection guidance specifically for
public-cloud CSPs acting as PII processors (GDPR Article 28 role).

Publicly-available scope statement (re-keyed from ISO's preview):

> "This document establishes commonly accepted control objectives,
> controls and guidelines for implementing measures to protect
> Personally Identifiable Information (PII) in line with the privacy
> principles in ISO/IEC 29100 for the public cloud computing
> environment. In particular, this document specifies guidelines based
> on ISO/IEC 27002, taking into consideration the regulatory
> requirements for the protection of PII which might be applicable
> within the context of the information security risk environment(s)
> of a provider of public cloud services. This document is applicable
> to all types and sizes of organizations, including public and
> private companies, government entities and not-for-profit
> organizations, which provide information processing services as PII
> processors via cloud computing under contract to other organizations."

Z.Z1 carries cross-references to the 27018 PII-processor controls on
the affected 27001 Annex A control rows (the full per-control 27018
implementation guidance is emitted by Z.Z4). The 11 PII-specific
control areas summarised in LOOP-Z-SPEC.md §2.4 are mirrored on the
Z.Z1 envelope's `see_also` block.

### 2.5 ISO/IEC 27701:2019 — Privacy Information Management System (PIMS)

URL: https://www.iso.org/standard/71670 (accessed 2026-06-08).
Status: Published August 2019. Extends ISO/IEC 27001 + ISO/IEC 27002
with a Privacy Information Management System.

Publicly-available scope statement (re-keyed from the ISO preview):

> "This document specifies requirements and provides guidance for
> establishing, implementing, maintaining and continually improving a
> Privacy Information Management System (PIMS) in the form of an
> extension to ISO/IEC 27001 and ISO/IEC 27002 for privacy management
> within the context of the organization. This document specifies
> PIMS-related requirements and provides guidance for PII controllers
> and PII processors holding responsibility and accountability for PII
> processing. This document is applicable to all types and sizes of
> organizations, including public and private companies, government
> entities and not-for-profit organizations, which are PII controllers
> and/or PII processors processing PII within an ISMS."

Z.Z1 carries cross-references to the 27701 PIMS structure on the
ISMS-clause rows (the PIMS extension is emitted by Z.Z5). The Z.Z1
catalog does NOT duplicate Z.Z5's PIMS-specific Annex A or Annex B
control sets.

### 2.6 ENISA EUCS Candidate Scheme

URL: https://www.enisa.europa.eu/topics/certification/cybersecurity-certification-framework/eucs
(accessed 2026-06-08). Status: Candidate Scheme published March 2024;
European Commission expected to adopt as a delegated act in 2026-2027.
The EUCS draft is freely available as a PDF on the ENISA website.

Publicly-available scope statement from the ENISA EUCS Candidate
Scheme draft (re-keyed from the PDF):

> "The candidate European cybersecurity certification scheme on cloud
> services (EUCS) is a horizontal scheme intended to harmonise the
> security of cloud services with EU regulations, international
> standards, industry best practices, as well as with existing
> certifications in EU Member States. EUCS covers cloud services
> regardless of the deployment model (private, public, community or
> hybrid) and the service model (IaaS, PaaS or SaaS). It defines a
> reference set of security objectives and corresponding security
> requirements that cloud service providers shall meet to obtain a
> certificate at the chosen assurance level."

The three EUCS assurance levels (Basic, Substantial, High) inherit
from ISO/IEC 27001 + 27017 + 27018; Z.Z5 emits the EUCS submission
package. Z.Z1 carries the assurance-level cross-reference on each
Annex A control row that EUCS scopes (per the EUCS draft's mapping
table in Annex A of the EUCS draft).

### 2.7 EU Cybersecurity Act — Regulation (EU) 2019/881

URL: https://eur-lex.europa.eu/eli/reg/2019/881/oj (accessed 2026-06-08).
Status: In force since 27 June 2019. Establishes the EU Cybersecurity
Certification Framework that EUCS implements.

Verbatim quote from Article 46 ("European cybersecurity certification
framework"):

> "1. The European cybersecurity certification framework shall be
> established in order to improve the conditions for the functioning
> of the internal market by increasing the level of cybersecurity within
> the Union and enabling a harmonised approach at Union level to
> European cybersecurity certification schemes, with a view to creating
> a digital single market for ICT products, ICT services and ICT
> processes. 2. The European cybersecurity certification framework
> shall provide for a mechanism to establish European cybersecurity
> certification schemes and to attest that the ICT products, ICT
> services and ICT processes that have been evaluated in accordance
> with such schemes comply with specified security requirements for
> the purpose of protecting the availability, authenticity, integrity
> or confidentiality of stored or transmitted or processed data or the
> functions or services offered by, or accessible via, those products,
> services and processes throughout their life cycle."

And Article 52 ("Assurance levels of European cybersecurity
certification schemes"):

> "1. A European cybersecurity certification scheme may specify one or
> more of the following assurance levels for ICT products, ICT services
> and ICT processes: 'basic', 'substantial' or 'high'. The assurance
> level shall be commensurate with the level of the risk associated
> with the intended use of the ICT product, ICT service or ICT process,
> in terms of the probability and impact of an incident. 2. European
> cybersecurity certificates issued under a European cybersecurity
> certification scheme shall, where applicable, refer to any of the
> assurance levels referred to in paragraph 1."

Z.Z1's catalog carries the `eucs_assurance_levels` field per Annex A
control (a subset of `['basic', 'substantial', 'high']`) indicating
which EUCS assurance levels scope the control.

### 2.8 NIST OLIR — Online Informative References programme

URL: https://csrc.nist.gov/projects/olir (accessed 2026-06-08).
Programme description page; the per-mapping JSON records are
downloaded from https://csrc.nist.gov/projects/olir/informative-reference-catalog
+ child endpoints. Freely available; no licensing fee.

Verbatim quote from the OLIR programme description:

> "The National Online Informative References (OLIR) Program is a NIST
> effort to facilitate subject matter experts (SMEs) in defining
> standardized online informative references (OLIRs) between elements
> of their cybersecurity, privacy, and workforce documents and elements
> of other cybersecurity, privacy, and workforce documents. OLIRs are
> intended to provide a useful resource for organizations attempting to
> understand the relationships between their existing cybersecurity,
> privacy, and workforce documents and other documents to which they
> need to comply or which they wish to consult."

Verbatim quote on relationship types (from the OLIR Reference Schema
specification, NIST IR 8278 / 8278A):

> "A 'rationale' value indicates the source of the relationship as one
> of: 'syntactic' (the relationship is based on the structure of the
> two elements), 'semantic' (the relationship is based on the meaning
> of the two elements), or 'mereological' (the relationship is based
> on a whole/part relationship between the two elements). A
> 'relationship' value indicates the nature of the relationship as one
> of: 'subset of', 'intersects with', 'equal', 'superset of', or 'not
> related to'."

Z.Z1 stores the OLIR `relationship` value per (Annex A control →
800-53 control) pairing. Multiple OLIR records for the same source
control are deduplicated by taking the most-specific relationship
(`equal` > `subset of` ≈ `superset of` > `intersects with` > `not
related to`); conflicts surface a `coverage:olir-conflict` log line
that the operator reviews via the tracker UI.

### 2.9 NIST SP 800-53 Rev 5 + 800-53B Moderate baseline

URL (catalog): https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
URL (baselines): https://csrc.nist.gov/publications/detail/sp/800-53b/final
(accessed 2026-06-08). Freely available.

The existing `cloud-evidence/core/control-benchmark.ts` module is the
canonical loader for 800-53 Rev 5 + 800-53B Low/Moderate/High
baselines. Z.Z1's crosswalk normaliser calls into the existing module
to resolve the OLIR-mapped target IDs against the actual Rev 5
control catalog (so the crosswalk row's `nist_800_53_rev5` field
holds the canonical control ID + the Moderate-baseline applicability
flag).

### 2.10 FedRAMP 20x KSI catalog (frmr-ksi-catalog)

URL (FRMR repo): https://github.com/FedRAMP/automation-frameworks
(accessed 2026-06-08). The `cloud-evidence/data/frmr-ksi-catalog.json`
file is the parsed snapshot.

Z.Z1's crosswalk joins each Annex A control row to the FedRAMP
Moderate KSI set via the OLIR-mapped 800-53 controls. The join logic:

1. For Annex A control `A.x.y`, retrieve the OLIR-mapped 800-53
   target set `T = { ac-2, ac-3, ... }`.
2. For each KSI in `frmr-ksi-catalog.json`, retrieve its parameter
   set `P = { ac-2(1), ac-3(7), ... }`.
3. If `T ∩ baseControls(P) ≠ ∅` (where `baseControls` strips
   parameter enhancements), the KSI is added to the Annex A control
   row's `fedramp_moderate_ksis` array.

The join is deterministic; the OLIR mapping and the KSI catalog are
both immutable snapshots at catalog-extraction time.

### 2.11 ISO/IEC 27001:2013 → 2022 transition mapping (informative)

URL: secondary sources — BSI, DNV, the British Standards Institution
transition guide PDF, and various 27001:2013→2022 mapping spreadsheets
published informally during the 2022 transition window. Status: the
transition deadline ended 2025-10-31 and the 2013 edition is no longer
accepted by certification bodies. The mapping is informative only.

Z.Z1 emits the legacy-control mapping on the per-control row's
`iso_27001_2013_legacy_mapping[]` array. The mapping is many-to-many
(some 2013 controls were merged in 2022; some 2022 controls have no
2013 antecedent). The mapping is loaded from
`cloud-evidence/data/iso-27001-2013-to-2022-mapping.json` which the
implementer seeds from the publicly-available BSI / DNV transition
spreadsheets and which the operator can override via
`iso-27001-overrides.yaml`.

### 2.12 ISO/IEC 17021-1 + ISO/IEC 27006 — certification body accreditation

URL: https://www.iso.org/standard/61651 (17021-1, accessed 2026-06-08);
https://www.iso.org/standard/62313 (27006, accessed 2026-06-08).

These standards govern the **certification body** that audits the
CSP's 27001 ISMS. They are out of scope for Z.Z1 (LOOP-Z does not
perform the audit; LOOP-Z emits the artefacts the certification body
consumes). The Z.Z1 catalog carries a `certification_body_authority`
note pointing to ISO 17021-1 + 27006 so the operator's compliance team
understands which standard the auditor is using.

---

## 3. Scope

### 3.1 In scope

- Ingestion of the **ISO/IEC 27001:2022** ISMS clauses 4–10 (titles +
  sub-clause structure; full normative text remains in the operator's
  licensed copy).
- Ingestion of the **ISO/IEC 27001:2022 Annex A** control catalog — all
  93 controls organised into 4 themes (Organizational 37, People 8,
  Physical 14, Technological 34) — by canonical control ID + canonical
  short title.
- Ingestion of the **ISO/IEC 27002:2022** five attribute dimensions per
  control (Control type, Information security properties, Cybersecurity
  concepts, Operational capabilities, Security domains).
- **Three-way crosswalk** to NIST 800-53 Rev 5 (via NIST OLIR) +
  FedRAMP Moderate baseline KSIs (via the join through the OLIR-mapped
  800-53 control set) + ISO 27001:2013 legacy controls (informative).
- **EUCS assurance-level cross-reference** per Annex A control (subset
  of `['basic', 'substantial', 'high']`).
- **27017 / 27018 / 27701 see-also references** per Annex A control
  (cross-references only; full control bodies emitted by Z.Z3/Z.Z4/Z.Z5).
- Emission of `cloud-evidence/data/iso-27001-2022-annex-a.json` and
  `cloud-evidence/data/iso-27001-nist-olir.json` (the raw OLIR
  snapshot) as canonical JSON with byte-stable key ordering (RFC 8785).
- Ed25519 signature + RFC 3161 timestamp on each catalog file (via
  the existing LOOP-A.A5 signing pipeline).
- TypeScript loader `core/iso-27001-2022-catalog.ts` exposing the
  catalog to downstream slices with strong typing.
- Extraction script `scripts/extract-iso-27001-2022.mjs` that re-runs
  the catalog ingestion (idempotent; same inputs produce same outputs
  byte-for-byte).
- Operator override mechanism via `data/iso-27001-overrides.yaml`
  (operator-detected corrections to control titles, attribute
  assignments, or OLIR mappings merged at load time with
  `provenance: operator-correction`).
- Test fixtures + test suite covering catalog round-trip, crosswalk
  join correctness, theme partitioning, attribute dimension
  enumeration, OLIR-conflict deduplication, RFC 8785 canonical-form
  stability, Ed25519 signature verification, and overrides merging.

### 3.2 Out of scope (NOT in Z.Z1)

- **The ISO/IEC 27001 Statement of Applicability emitter.** Owned by
  Z.Z2. Z.Z1 only emits the catalog; Z.Z2 reads the catalog and emits
  the SoA.
- **The ISO/IEC 27017:2015 cloud overlay controls** (CLD.6.3.1
  through CLD.13.1.4 + the 37 augmented 27002 controls + the per-
  cloud AWS/GCP/Azure implementation guidance). Owned by Z.Z3.
- **The ISO/IEC 27018:2019 PII-processor extensions** (the 11 PII-
  specific control areas + the per-control PII implementation
  guidance). Owned by Z.Z4.
- **The ISO/IEC 27701:2019 PIMS extension** (Annex A — PII Controller
  controls + Annex B — PII Processor controls). Owned by Z.Z5.
- **The ENISA EUCS submission package** (the conformity-assessment
  package consumed by the EU Conformity Assessment Body). Owned by
  Z.Z5.
- **Per-control evidence collection.** Z.Z1 emits the catalog +
  crosswalk; it does NOT call cloud SDKs and does NOT collect per-
  control technical evidence. Evidence collection happens via the
  existing FedRAMP-Moderate collectors (LOOP-INV-S, the per-domain
  IAM / network / data / logging collectors) which Z.Z2 reads via
  the crosswalk to surface FedRAMP evidence as ISO evidence.
- **The certification audit itself.** Performed by an accredited
  certification body (per ISO/IEC 17021-1 + 27006). Out of Z.Z1.
- **NIST 800-53 Rev 6 mapping.** Rev 6 is in draft as of 2026-06-08.
  When NIST OLIR publishes a Rev 6 mapping, Z.Z1's
  `scripts/extract-iso-27001-2022.mjs` re-ingests it; until then the
  Rev 5 mapping is the source of truth.
- **CSA CCM v4 crosswalk.** A future LOOP-Z extension could add a
  CSA Cloud Controls Matrix v4 crosswalk; not in Z.Z1.
- **The 2013 → 2022 *implementation* transition.** Z.Z1 carries the
  informative legacy-control mapping but does NOT generate transition
  plans, gap-analysis reports, or migration roadmaps.

---

## 4. Inputs

### 4.1 ISO/IEC 27001:2022 publicly-available control list

The implementer downloads the publicly-available ISO 27001 Annex A
preview page (the ISO preview prints the 93 control IDs + short
titles) + the ISO 27002:2022 attribute table to:

- `cloud-evidence/docs/sources/iso-27001-2022-annex-a-preview.html`
- `cloud-evidence/docs/sources/iso-27002-2022-attributes-preview.html`

The extractor parses the HTML to produce the structured per-control
JSON. The operator's licensed full standard is consulted offline to
verify discrepancies; any discrepancy is committed to
`iso-27001-overrides.yaml`.

### 4.2 NIST OLIR ISO 27001 → NIST 800-53 Rev 5 mapping

The implementer downloads the NIST OLIR JSON snapshot from
https://csrc.nist.gov/projects/olir/informative-reference-catalog
(filtered to `source=ISO/IEC 27001 2022` + `target=NIST SP 800-53
Rev 5`) to:

- `cloud-evidence/docs/sources/nist-olir-iso27001-to-80053rev5.json`

The extractor consumes this file directly; no transformation other
than relationship-type normalisation.

### 4.3 NIST SP 800-53 Rev 5 catalog (existing)

Path: `cloud-evidence/core/control-benchmark.ts` (existing loader for
800-53 Rev 5 + 800-53B Low/Moderate/High baselines). Z.Z1 calls into
the existing loader; no new download.

### 4.4 FedRAMP 20x KSI catalog (existing)

Path: `cloud-evidence/data/frmr-ksi-catalog.json` (existing FRMR
import). Z.Z1's crosswalk joins to this catalog via the OLIR-mapped
800-53 control IDs.

### 4.5 ISO/IEC 27001:2013 → 2022 transition mapping (informative)

The implementer seeds `cloud-evidence/data/iso-27001-2013-to-2022-mapping.json`
from publicly-available BSI / DNV transition spreadsheets. The
operator can override via `iso-27001-overrides.yaml`.

### 4.6 EUCS assurance-level scoping

The implementer parses the publicly-available ENISA EUCS Candidate
Scheme PDF (Annex A control scoping table) to seed the
`eucs_assurance_levels` field per Annex A control. The operator
re-runs the parser when ENISA publishes an updated EUCS draft.

### 4.7 Operator overrides

Path: `cloud-evidence/data/iso-27001-overrides.yaml`. Schema:

```yaml
schema_version: '1.0.0'
overrides:
  - control_id: A.5.1
    field: short_title
    operator_correction: 'Policies for information security'
    rationale: 'Operator licensed-copy verification — corrects extractor parse error.'
    operator_signoff_officer: 'jane.doe@csp.example.com'
    operator_signoff_at: '2026-06-08T14:30:00Z'
  - control_id: A.8.24
    field: olir_relationship
    target_control: 'SC-13'
    operator_correction: 'equal'
    rationale: 'Operator confirms equivalence post 800-53 Rev 5 erratum 2026-Q1.'
    operator_signoff_officer: 'jane.doe@csp.example.com'
    operator_signoff_at: '2026-06-08T14:30:00Z'
```

### 4.8 TypeScript interfaces (loader signatures)

```ts
export interface Iso27001Catalog {
  schema_version: '1.0.0';
  iso_27001_edition: '2022';
  iso_27002_edition: '2022';
  extracted_at: string;                       // ISO 8601 UTC
  olir_extracted_at: string;                  // ISO 8601 UTC
  fedramp_ksi_catalog_sha256: string;
  olir_snapshot_sha256: string;
  source_provenance: SourceProvenance[];
  isms_clauses: IsmsClause[];                 // clauses 4-10
  annex_a_controls: AnnexAControl[];          // 93 entries
  themes: ThemeIndex[];                       // 4 entries
  iso_27001_2013_to_2022_mapping: LegacyMapping[]; // informative
  signature: Ed25519Signature;
  rfc3161_timestamp: Rfc3161Token;
}

export interface AnnexAControl {
  control_id: string;                         // e.g. 'A.5.1', 'A.8.24'
  theme: 'organizational' | 'people' | 'physical' | 'technological';
  short_title: string;                        // e.g. 'Policies for information security'
  attributes: {
    control_type: Array<'#Preventive' | '#Detective' | '#Corrective'>;
    information_security_properties: Array<'#Confidentiality' | '#Integrity' | '#Availability'>;
    cybersecurity_concepts: Array<'#Identify' | '#Protect' | '#Detect' | '#Respond' | '#Recover'>;
    operational_capabilities: string[];        // 15 allowed values
    security_domains: string[];                // 4 allowed values
  };
  nist_800_53_rev5_mapping: Array<{
    target_control_id: string;                 // e.g. 'AC-1', 'SC-13'
    olir_relationship: 'equal' | 'subset_of' | 'superset_of' | 'intersects_with' | 'not_related_to';
    olir_rationale: 'syntactic' | 'semantic' | 'mereological';
    olir_record_id: string;
    is_in_fedramp_moderate_baseline: boolean;
  }>;
  fedramp_moderate_ksis: string[];             // KSI IDs from frmr-ksi-catalog
  eucs_assurance_levels: Array<'basic' | 'substantial' | 'high'>;
  see_also: {
    iso_27017_cloud_overlay_refs: string[];    // CLD.* IDs
    iso_27018_pii_processor_refs: string[];    // PII control area names
    iso_27701_pims_refs: string[];             // PIMS clause IDs
  };
  iso_27001_2013_legacy_mapping: Array<{
    legacy_control_id: string;                 // e.g. 'A.5.1.1' (2013)
    relationship: 'merged_into' | 'split_from' | 'renumbered' | 'new_in_2022';
  }>;
  provenance: 'iso-preview' | 'operator-correction' | 'olir-derived';
}

export interface IsmsClause {
  clause: '4' | '5' | '6' | '7' | '8' | '9' | '10';
  title: string;
  sub_clauses: Array<{ id: string; title: string; mandatory: true }>;
  produces_soa: boolean;                       // true only for clause 6.1.3
}

export interface ThemeIndex {
  theme: 'organizational' | 'people' | 'physical' | 'technological';
  control_id_prefix: 'A.5' | 'A.6' | 'A.7' | 'A.8';
  control_count: 37 | 8 | 14 | 34;
  control_ids: string[];
}

export interface LegacyMapping {
  legacy_2013_control_id: string;
  new_2022_control_ids: string[];              // empty if 2013 control was deleted
  relationship: 'identical' | 'merged' | 'split' | 'renumbered' | 'deleted';
}
```

---

## 5. Outputs

### 5.1 Canonical Annex A catalog JSON

Path: `cloud-evidence/data/iso-27001-2022-annex-a.json`.

Top-level shape:

```json
{
  "schema_version": "1.0.0",
  "iso_27001_edition": "2022",
  "iso_27002_edition": "2022",
  "extracted_at": "2026-06-08T15:00:00Z",
  "olir_extracted_at": "2026-06-08T14:55:00Z",
  "fedramp_ksi_catalog_sha256": "<sha256 of frmr-ksi-catalog.json at extract time>",
  "olir_snapshot_sha256": "<sha256 of the OLIR JSON snapshot>",
  "source_provenance": [
    { "kind": "iso-27001-preview", "path": "docs/sources/iso-27001-2022-annex-a-preview.html", "sha256": "..." },
    { "kind": "iso-27002-preview", "path": "docs/sources/iso-27002-2022-attributes-preview.html", "sha256": "..." },
    { "kind": "nist-olir", "path": "docs/sources/nist-olir-iso27001-to-80053rev5.json", "sha256": "..." },
    { "kind": "frmr-ksi-catalog", "path": "data/frmr-ksi-catalog.json", "sha256": "..." },
    { "kind": "iso-27001-2013-mapping", "path": "data/iso-27001-2013-to-2022-mapping.json", "sha256": "..." },
    { "kind": "operator-overrides", "path": "data/iso-27001-overrides.yaml", "sha256": "..." }
  ],
  "isms_clauses": [ /* 7 entries: clauses 4 through 10 */ ],
  "annex_a_controls": [ /* 93 entries */ ],
  "themes": [
    { "theme": "organizational", "control_id_prefix": "A.5", "control_count": 37, "control_ids": ["A.5.1", "A.5.2", "..."] },
    { "theme": "people", "control_id_prefix": "A.6", "control_count": 8, "control_ids": ["A.6.1", "..."] },
    { "theme": "physical", "control_id_prefix": "A.7", "control_count": 14, "control_ids": ["A.7.1", "..."] },
    { "theme": "technological", "control_id_prefix": "A.8", "control_count": 34, "control_ids": ["A.8.1", "..."] }
  ],
  "iso_27001_2013_to_2022_mapping": [ /* informative legacy mapping */ ],
  "signature": { "alg": "ed25519", "key_id": "<KMS resource>", "sig": "<base64>" },
  "rfc3161_timestamp": { "tsa_url": "<TSA URL>", "token": "<base64>", "received_at": "..." }
}
```

The file is RFC 8785 JCS canonicalized so the SHA-256 is stable
across re-extractions when inputs are unchanged.

### 5.2 NIST OLIR raw snapshot

Path: `cloud-evidence/data/iso-27001-nist-olir.json`.

The raw OLIR JSON snapshot (after relationship-type normalisation but
before joining to the Annex A catalog). Stored separately so a third-
party analyst can consume the OLIR mapping independently.

### 5.3 TypeScript loader

Path: `cloud-evidence/core/iso-27001-2022-catalog.ts`.

Exports:

```ts
export function loadIso27001Catalog(): Iso27001Catalog;
export function getAnnexAControl(controlId: string): AnnexAControl | undefined;
export function getControlsByTheme(theme: ThemeIndex['theme']): AnnexAControl[];
export function getControlsForFedrampKsi(ksiId: string): AnnexAControl[];
export function getControlsForEucsLevel(level: 'basic' | 'substantial' | 'high'): AnnexAControl[];
export function getIsmsClause(clauseId: string): IsmsClause | undefined;
export function getLegacyMappingFor2013Control(legacyId: string): LegacyMapping | undefined;
```

The loader verifies the catalog's Ed25519 signature on first call;
verification failure throws `IsoCatalogSignatureInvalidError`. The
loader is memoised — subsequent calls reuse the in-memory catalog.

### 5.4 Extractor script

Path: `scripts/extract-iso-27001-2022.mjs`.

Re-runs the catalog ingestion end-to-end:

1. Parse the ISO 27001 + 27002 preview HTML files.
2. Parse the NIST OLIR JSON snapshot.
3. Parse the 27001:2013 → 2022 legacy mapping.
4. Parse the EUCS scoping table from the ENISA EUCS PDF (text-mined).
5. Merge operator overrides from `iso-27001-overrides.yaml`.
6. Join FedRAMP KSI references via the OLIR-mapped 800-53 controls.
7. RFC 8785 canonicalize the assembled catalog.
8. Sign with Ed25519 (via `core/sign.ts`).
9. Timestamp with RFC 3161 (via `core/timestamp.ts`).
10. Write `data/iso-27001-2022-annex-a.json` + `data/iso-27001-nist-olir.json`.

Idempotent: same inputs produce identical output bytes (verified by
test T7 in §8).

### 5.5 Test fixtures

Path: `test/fixtures/iso-27001/`. Contains the parsed preview HTML
snippets + the OLIR JSON snapshot + the operator-override examples
used by `test/iso-27001-2022-catalog.test.ts`.

---

## 6. Algorithm / Steps

### Phase A — Bootstrap

1. **Parse CLI flag** `--iso-z-z1` (or env `CLOUD_EVIDENCE_Z_Z1`). If
   neither is set AND the org-profile `compliance.iso_27001.seek_certification`
   is `false`, Z.Z1 is a no-op.
2. **Load operator configuration.** Read `org-profile.yaml` →
   `compliance.iso_27001.*`. Validate via Ajv.
3. **Verify source artefacts on disk.** Check that the four required
   source files exist and that their on-disk SHA-256 matches the
   per-source `source_provenance` entry in the prior catalog (if any).
   If a source is missing OR its hash has changed, set the
   `re-ingest_required` flag.

### Phase B — Source parsing

4. **Parse ISO 27001:2022 Annex A preview.** Extract the 93 control
   IDs + canonical short titles. Validate: theme distribution must be
   exactly `(37, 8, 14, 34)`. Failure → exit `2` with
   `IsoCatalogShapeError`.
5. **Parse ISO 27002:2022 attribute table.** For each control, extract
   the five attribute-dimension values. Validate: every control has
   non-empty arrays for all five dimensions.
6. **Parse NIST OLIR snapshot.** For each OLIR record, extract source
   control + target control + relationship + rationale + record ID.
   Group by source control. Deduplicate per (source, target) pair by
   taking the most-specific relationship.
7. **Parse 27001:2013 → 2022 legacy mapping.** Build a per-2022-control
   list of antecedent 2013 controls.
8. **Parse EUCS assurance-level scoping table.** Build a per-control
   subset of `['basic', 'substantial', 'high']`.

### Phase C — Cross-framework join

9. **Resolve NIST 800-53 Rev 5 baseline membership.** For each
   OLIR-mapped target control, call into `core/control-benchmark.ts`
   to check membership in the Moderate baseline. Annotate each
   crosswalk row with `is_in_fedramp_moderate_baseline`.
10. **Join to FedRAMP Moderate KSIs.** For each Annex A control,
    collect the union of FedRAMP Moderate KSIs whose 800-53 parameter
    set intersects the OLIR-mapped 800-53 control set. The join is
    deterministic given the input snapshots.
11. **Apply operator overrides.** Merge `iso-27001-overrides.yaml`.
    Each override gets `provenance: operator-correction`; the base
    extractor output gets `provenance: iso-preview` or
    `provenance: olir-derived`. Conflicts surface a
    `coverage:operator-override-conflict` log line.

### Phase D — Canonicalize + sign + emit

12. **Assemble the catalog object** per §4.8 interfaces.
13. **RFC 8785 JCS canonicalize.** Use the existing
    `core/canonicalize.ts` (LOOP-A.A5) to produce byte-stable JSON.
14. **Compute SHA-256** over the canonical bytes.
15. **Sign with Ed25519.** Call `core/sign.ts::signEnvelope(bytes, keyRef)`.
16. **Timestamp with RFC 3161.** Call `core/timestamp.ts::timestampBytes(bytes)`.
17. **Write outputs.** Write `data/iso-27001-2022-annex-a.json` +
    `data/iso-27001-nist-olir.json` + the detached signature blob +
    the timestamp-token blob.
18. **Update tracker DB.** Insert a row into
    `iso_27001_catalog_ingestions` (run_id, extracted_at, sha256,
    operator-override-count, olir-conflict-count).
19. **Emit submission-bundle catalogue entries** via LOOP-A.A4
    (`core/submission-bundle.ts`): roles
    `iso-27001-2022-annex-a-catalog` + `iso-27001-nist-olir-snapshot`.

### Pseudocode

```ts
async function extractIso27001Catalog(opts: ExtractOpts): Promise<Iso27001Catalog> {
  const sources = await loadSourceArtefacts(opts);
  const previewControls = parseAnnexAPreview(sources.iso27001PreviewHtml);
  assertThemeDistribution(previewControls, [37, 8, 14, 34]);
  const attributes = parseAttributeTable(sources.iso27002PreviewHtml);
  const olir = normaliseOlirSnapshot(sources.olirJson);
  const legacy = parseLegacyMapping(sources.legacyMappingJson);
  const eucs = parseEucsScopingTable(sources.eucsPdfText);
  const baseline = loadNist80053Rev5ModerateBaseline();
  const ksis = loadFrmrKsiCatalog();
  const overrides = loadOperatorOverrides(opts.overridesPath);

  const annexAControls: AnnexAControl[] = previewControls.map((pc) => {
    const attrs = attributes.get(pc.controlId)!;
    const olirEntries = olir.get(pc.controlId) ?? [];
    const olirMapped = olirEntries.map((e) => ({
      target_control_id: e.target,
      olir_relationship: e.relationship,
      olir_rationale: e.rationale,
      olir_record_id: e.recordId,
      is_in_fedramp_moderate_baseline: baseline.has(e.target),
    }));
    const matchedKsis = ksis.filter((k) =>
      k.parameters.some((p) => olirEntries.some((o) => stripEnhancement(p) === o.target)),
    );
    const seeAlso = buildSeeAlsoRefs(pc.controlId);
    const legacyMapping = legacy.get(pc.controlId) ?? [];
    const row: AnnexAControl = {
      control_id: pc.controlId,
      theme: themeFor(pc.controlId),
      short_title: pc.shortTitle,
      attributes: attrs,
      nist_800_53_rev5_mapping: olirMapped,
      fedramp_moderate_ksis: matchedKsis.map((k) => k.ksi_id),
      eucs_assurance_levels: eucs.get(pc.controlId) ?? [],
      see_also: seeAlso,
      iso_27001_2013_legacy_mapping: legacyMapping,
      provenance: 'iso-preview',
    };
    return applyOverridesTo(row, overrides);
  });

  const catalog: Iso27001Catalog = {
    schema_version: '1.0.0',
    iso_27001_edition: '2022',
    iso_27002_edition: '2022',
    extracted_at: new Date().toISOString(),
    olir_extracted_at: olir.extractedAt,
    fedramp_ksi_catalog_sha256: sha256(sources.ksiCatalogBytes),
    olir_snapshot_sha256: sha256(sources.olirJsonBytes),
    source_provenance: buildSourceProvenance(sources),
    isms_clauses: ISMS_CLAUSES,            // hardcoded structural constants (allowed by Rule 3)
    annex_a_controls: annexAControls,
    themes: buildThemeIndex(annexAControls),
    iso_27001_2013_to_2022_mapping: legacy.flat(),
    signature: undefined as any,            // populated below
    rfc3161_timestamp: undefined as any,    // populated below
  };

  const canonical = canonicalize(catalog);     // RFC 8785
  catalog.signature = await signEnvelope(canonical, opts.signingKeyRef);
  catalog.rfc3161_timestamp = await timestampBytes(canonical);

  await writeCatalog('data/iso-27001-2022-annex-a.json', catalog);
  await writeRawOlirSnapshot('data/iso-27001-nist-olir.json', olir);
  await recordIngestion(catalog);
  await registerBundleEntries(catalog);
  return catalog;
}
```

---

## 7. Files to create / modify

| Path | Action | Purpose |
|---|---|---|
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/iso-27001-2022-catalog.ts` | **create** | Typed loader + accessors for the 93-control catalog + crosswalks |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/scripts/extract-iso-27001-2022.mjs` | **create** | Idempotent extractor that produces the canonical JSON outputs |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/iso-27001-2022-annex-a.json` | **create** | Canonical 93-control catalog + three-way crosswalk (signed + timestamped) |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/iso-27001-nist-olir.json` | **create** | Raw normalised OLIR snapshot (separate file for third-party analyst use) |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/iso-27001-2013-to-2022-mapping.json` | **create** | Informative legacy-control mapping (seed from BSI/DNV transition spreadsheets) |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/iso-27001-overrides.yaml` | **create (empty seed)** | Operator override file; ships with `overrides: []` |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/sources/iso-27001-2022-annex-a-preview.html` | **create** | Local copy of the ISO Annex A preview page (parsed by extractor) |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/sources/iso-27002-2022-attributes-preview.html` | **create** | Local copy of the ISO 27002 attribute table (parsed by extractor) |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/sources/nist-olir-iso27001-to-80053rev5.json` | **create** | Local copy of the NIST OLIR JSON snapshot |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/sources/enisa-eucs-candidate-scheme.pdf` | **create** | Local copy of the ENISA EUCS draft (parsed by extractor) |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/iso-27001-2022-catalog.test.ts` | **create** | Test suite — ≥ 18 cases per §8 |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/iso-27001/` | **create** | Test fixtures (preview HTML snippets + OLIR records + override examples) |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` | **modify** | Add WELL_KNOWN entries for `iso-27001-2022-annex-a-catalog` + `iso-27001-nist-olir-snapshot` |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/orchestrator.ts` | **modify** | Wire `--iso-z-z1` flag + env var; gate behind `compliance.iso_27001.seek_certification` org-profile field |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/db/migrations/0050_iso_27001_catalog_ingestions.sql` | **create** | DB migration for the `iso_27001_catalog_ingestions` table |

---

## 8. Test specifications

| ID | Scenario | Fixture | Expected | Acceptance |
|---|---|---|---|---|
| T1 | Catalog round-trip — extractor produces 93 controls partitioned (37, 8, 14, 34) | Full preview HTML fixtures | Catalog `annex_a_controls.length === 93`; theme counts match | Assertion passes |
| T2 | Theme A.5 contains 37 controls with prefix `A.5.*` | Preview HTML | `getControlsByTheme('organizational').length === 37`; every ID starts with `A.5.` | Assertion passes |
| T3 | Theme A.6 contains 8 controls with prefix `A.6.*` | Preview HTML | `getControlsByTheme('people').length === 8` | Assertion passes |
| T4 | Theme A.7 contains 14 controls with prefix `A.7.*` | Preview HTML | `getControlsByTheme('physical').length === 14` | Assertion passes |
| T5 | Theme A.8 contains 34 controls with prefix `A.8.*` | Preview HTML | `getControlsByTheme('technological').length === 34` | Assertion passes |
| T6 | Each control has all 5 attribute dimensions populated | Preview HTML | Every `annex_a_controls[i].attributes.{control_type, information_security_properties, cybersecurity_concepts, operational_capabilities, security_domains}` non-empty array | Assertion passes |
| T7 | Idempotency — running the extractor twice with identical inputs produces byte-identical canonical output | Source files | `sha256(run1) === sha256(run2)` | Hashes equal |
| T8 | RFC 8785 canonicalization — key ordering stable | Catalog object | Serialised bytes match a fixture-pinned reference | Bytes equal |
| T9 | Ed25519 signature verification — valid signature passes; tampered bytes fail | Catalog + key | `verifyEnvelope(catalog, key) === true`; tampering 1 byte → `false` | Both pass |
| T10 | RFC 3161 timestamp present + decodable | Catalog | `catalog.rfc3161_timestamp.token` non-empty; decoder returns a valid `received_at` | Assertion passes |
| T11 | NIST OLIR crosswalk join — `A.5.1` maps to at least one Rev 5 control | OLIR snapshot + preview | `getAnnexAControl('A.5.1').nist_800_53_rev5_mapping.length > 0` | Assertion passes |
| T12 | OLIR conflict deduplication — two OLIR records for `(A.8.24 → SC-13)` with conflicting relationships collapse to the most-specific | Synthetic OLIR fixture | Resulting mapping carries 1 row with `olir_relationship='equal'` (most specific) | Assertion passes |
| T13 | FedRAMP Moderate KSI join — `A.5.15` (Access control) maps to ≥ 1 IAM-family KSI | OLIR + frmr-ksi-catalog | `getAnnexAControl('A.5.15').fedramp_moderate_ksis` contains at least one `KSI-IAM-*` entry | Assertion passes |
| T14 | EUCS assurance levels — `A.8.24` (Use of cryptography) scoped at substantial + high | EUCS scoping table | `getAnnexAControl('A.8.24').eucs_assurance_levels.includes('substantial')` | Assertion passes |
| T15 | Legacy 27001:2013 mapping — `A.5.1` carries a 2013-antecedent reference | Legacy mapping JSON | `getAnnexAControl('A.5.1').iso_27001_2013_legacy_mapping.length >= 1` | Assertion passes |
| T16 | Operator override merge — override on `A.5.1.short_title` flows into the catalog with `provenance: operator-correction` | Override YAML fixture | `getAnnexAControl('A.5.1').short_title === '<override value>'`; provenance flag set | Assertion passes |
| T17 | Override conflict diagnostic — two overrides targeting the same field surface `coverage:operator-override-conflict` | Override YAML fixture (synthetic conflict) | Log line emitted; second override applied last (deterministic) | Log captured |
| T18 | Catalog signature invalid throws on loader call | Catalog with tampered signature | `loadIso27001Catalog()` throws `IsoCatalogSignatureInvalidError` | Throw observed |
| T19 | `getControlsForFedrampKsi('KSI-IAM-MFA')` returns ≥ 1 Annex A control | Catalog | Returned array non-empty | Assertion passes |
| T20 | `getControlsForEucsLevel('high')` returns the subset of controls scoped at high assurance | Catalog | Returned subset is a proper subset of all 93 controls | Assertion passes |
| T21 | ISMS clause loader — `getIsmsClause('6.1.3')` returns the SoA-producing clause with `produces_soa: true` | Catalog | Returned object has `produces_soa: true`; title contains "risk treatment" | Assertion passes |
| T22 | Schema validation — Ajv validation of the emitted JSON against `iso-27001-catalog.schema.json` passes | Catalog + schema | `ajv.validate(schema, catalog) === true` | Schema-clean |

### 8.1 Integration tests

| ID | Scenario | Acceptance |
|---|---|---|
| INT-Z1-1 | Z.Z1 catalog feeds Z.Z2 SoA emitter; SoA enumerates all 93 controls | SoA `control_count === 93` |
| INT-Z1-2 | Z.Z1 catalog feeds Z.Z3 cloud overlay; CLD.* cross-references resolved against Z.Z3 records | All `see_also.iso_27017_cloud_overlay_refs[]` entries resolve to Z.Z3 records |
| INT-Z1-3 | Z.Z1 catalog feeds Z.Z5 EUCS submission package; EUCS package's control list matches `getControlsForEucsLevel(level)` | Set equality |

---

## 9. Risks

| ID | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R-Z1-1 | **ISO standard text is paywalled — implementer cannot redistribute the full normative text.** | High (the standards ARE paywalled) | Medium (we can ship IDs + titles + attributes from previews; full body stays with operator's licensed copy) | Z.Z1 emits ONLY IDs + canonical short titles + attribute hashtags + crosswalks. Full implementation guidance remains with the operator's licensed copy. Operator overrides via `iso-27001-overrides.yaml` are the canonical way to correct extractor parse errors. The license-respecting boundary is documented in `cloud-evidence/docs/LICENSING-NOTES.md`. |
| R-Z1-2 | **NIST OLIR mapping is incomplete or carries conflicting relationship types for the same (source, target) pair.** | Medium (OLIR is community-contributed; conflicts have been observed historically) | Medium (a wrong crosswalk row would surface incorrect FedRAMP→ISO inheritance in Z.Z2 SoA) | Z.Z1's normaliser deduplicates by taking the most-specific relationship; conflicts surface a `coverage:olir-conflict` log line; the operator reviews conflicts via the tracker UI; operator overrides via `iso-27001-overrides.yaml` are authoritative. Test T12 covers this case. |
| R-Z1-3 | **ENISA EUCS Candidate Scheme changes during the EU adoption process (2026-2027 expected).** | High (EUCS is in candidate state; the EU Commission will iterate before adopting as a delegated act) | Medium (Z.Z1's EUCS scoping field would need re-extraction; downstream Z.Z5 package would change shape) | Z.Z1 carries the ENISA EUCS draft as a source artefact pinned at `extracted_at`; the extractor re-runs when ENISA publishes an updated draft. Z.Z5's submission package is regenerated. The schema-version bumps when the EUCS scoping shape changes materially. |
| R-Z1-4 | **NIST 800-53 Rev 6 publication invalidates the OLIR Rev 5 mapping.** | Medium (Rev 6 is in draft 2026-06-08; final publication expected 2026-Q4 or 2027-Q1) | High (every FedRAMP KSI crosswalk row would change baseline) | Z.Z1 records the `nist_rev` field (currently `'5'`); when NIST OLIR publishes a Rev 6 mapping, the extractor re-runs with `nist_rev: '6'` and emits a new schema-version. Downstream Z.Z2 SoA + Z.Z5 EUCS package re-emit with the new mapping. The orchestrator emits `coverage:control-deprecated` for any Annex A control whose Rev 5 mapped 800-53 control has been retired in Rev 6. |
| R-Z1-5 | **27001:2022 → 2025 errata or minor reissue.** | Low (the standard is on a multi-year cycle; minor amendments possible) | Low (the 93-control structure is unlikely to change) | The extractor's idempotency test (T7) catches unexpected structural changes; the `extracted_at` field surfaces age; the orchestrator emits `catalog-stale` after 365 days. |
| R-Z1-6 | **Operator override mis-merge — an override clobbers a correct extractor parse.** | Medium (operator may type a wrong value) | Medium (downstream SoA would carry the wrong title) | Every override row requires an `operator_signoff_officer` + `operator_signoff_at` field; overrides are auditable via the tracker DB; the per-control `provenance` flag surfaces `operator-correction` for any overridden field; a tracker UI review pane lists every override + its diff against the base catalog. |
| R-Z1-7 | **Theme miscounting from preview HTML parse error.** | Low | High (invalid catalog) | The extractor asserts the theme distribution `(37, 8, 14, 34)` BEFORE writing the catalog; parse-error → exit `2` with `IsoCatalogShapeError`. Test T1 covers this assertion. |

---

## 10. Open questions

| ID | Question | Owner | Status |
|---|---|---|---|
| OQ-Z1-1 | Should Z.Z1 emit a CSA CCM v4 crosswalk in addition to NIST 800-53 + FedRAMP? | Z.Z1 implementer | DEFERRED — see LOOP-Z-SPEC.md §13 "Glossary deltas" + §10 "Open questions"; not in initial scope; future LOOP-Z extension. |
| OQ-Z1-2 | Should the catalog include NIST CSF v2.0 mapping? | Z.Z1 implementer | DOCUMENTED — added to the per-control row via the `cybersecurity_concepts` attribute dimension (CSF Identify/Protect/Detect/Respond/Recover align). The mapping is implicit in the 27002:2022 attribute table. A dedicated CSF v2.0 column may be added in a future extension. |
| OQ-Z1-3 | How does Z.Z1 handle the (now-passed) 27001:2013 transition period? | Z.Z1 implementer | DECIDED — Z.Z1 targets 27001:2022 only; legacy 2013 mapping is informative only; the 2013 standard is no longer accepted by certification bodies. |
| OQ-Z1-4 | Should operator overrides require a second-officer countersign? | Z.Z1 implementer | DEFERRED to operator policy — Z.Z1's override schema captures a single officer's signoff; the operator's compliance team may impose internal countersign workflow via the tracker UI's review pane. |
| OQ-Z1-5 | How is the EUCS scoping table re-ingested when ENISA publishes a delegated-act adoption? | Z.Z1 implementer | DOCUMENTED — operator re-downloads the EUCS PDF to `docs/sources/enisa-eucs-*.pdf` (date-stamped) and re-runs the extractor. The `extracted_at` + `eucs_scheme_version` fields surface the change. |
| OQ-Z1-6 | Does Z.Z1 need to handle non-English ISO translations? | Z.Z1 implementer | OUT OF SCOPE — ISO publishes English + French (the two official ISO languages); national translations are member-body responsibility. Z.Z1 emits English canonical short titles. |
| OQ-Z1-7 | Should Z.Z1 detect when the FedRAMP KSI catalog rev changes mid-run? | Z.Z1 implementer | HANDLED — Z.Z1's `fedramp_ksi_catalog_sha256` field pins the snapshot; mismatch on next run triggers re-ingest. |

---

## 11. REQUIRES-OPERATOR-INPUT

| Input | Where supplied | Why required | Default if missing |
|---|---|---|---|
| `compliance.iso_27001.seek_certification` | `org-profile.yaml` | LOOP-Z applicability gate | `false` (Z.Z1 is a no-op) |
| Operator overrides (title corrections, OLIR-relationship corrections) | `data/iso-27001-overrides.yaml` | Operator's licensed-copy verification corrects extractor parse errors | Empty overrides list — base extractor output stands |
| Operator licensed copy of ISO 27001:2022 + 27002:2022 + 27017:2015 + 27018:2019 + 27701:2019 | Operator's compliance-team file share (NOT committed to repo) | Operator's compliance team consults full implementation guidance offline | N/A — operator MUST procure licensed copies for the audit. |
| ENISA EUCS PDF download | `docs/sources/enisa-eucs-candidate-scheme.pdf` | Source artefact for EUCS scoping table | N/A — operator MUST download; URL: https://www.enisa.europa.eu |
| NIST OLIR snapshot download | `docs/sources/nist-olir-iso27001-to-80053rev5.json` | Source artefact for OLIR mapping | N/A — operator MUST download; URL: https://csrc.nist.gov/projects/olir/informative-reference-catalog |
| ISO 27001 + 27002 preview HTML downloads | `docs/sources/iso-27001-2022-annex-a-preview.html` + `docs/sources/iso-27002-2022-attributes-preview.html` | Source artefacts for ID + title + attribute extraction | N/A — operator MUST download from iso.org preview pages |
| Ed25519 signing key reference | `config.yaml::signing.ed25519_signing_key_ref` (existing) | LOOP-A.A5 signing pipeline | N/A — existing operator-required input |
| RFC 3161 TSA URL | `config.yaml::signing.tsa_url` (existing) | LOOP-A.A5 timestamp pipeline | N/A — existing operator-required input |

---

## 12. Implementation log slot

| Date | Action | Workflow / commit | Notes | Outcome | Next step |
|---|---|---|---|---|---|
| 2026-06-08 | spec proposed | wf-uvxyz-gapfill | Specification authored via gap-fill workflow | TBD | — |

(Append a new row at every meaningful milestone per the cadence in
`docs/IMPLEMENTATION-LOG-TEMPLATE.md` §3.)

---

## 13. Completion checklist

Apply the 7-step procedure quoted verbatim from
`docs/SLICE-COMPLETION-PROCEDURE.md`:

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

### Step 8 (Z.Z1-specific addendum)

- [ ] Update `cloud-evidence/docs/STATUS.md` — set Z.Z1 row status=`done`, commit=`<hash>`, date=`<ISO>`.
- [ ] Update `cloud-evidence/docs/loops/LOOP-Z-SPEC.md` Status-tracking table — Z.Z1 row status=`done`, commit=`<hash>`, date=`<ISO>`.
- [ ] Append to `CHANGELOG.md` "Unreleased" — `### Added — LOOP-Z.Z1: ISO/IEC 27001:2022 Annex A Control Catalog + Crosswalk to NIST 800-53 Rev 5 + FedRAMP Moderate` with 2-3 paragraph summary including: 93 controls catalogued across 4 themes; OLIR crosswalk to NIST 800-53 Rev 5; FedRAMP Moderate KSI join via OLIR-mapped 800-53 controls; ISO 27001:2013→2022 legacy informative mapping; EUCS assurance-level cross-reference per control; Ed25519 + RFC 3161 signed; loader memoised + signature-verifying; ≥ 18 tests passing; `npm run check:reo` returns 0.
- [ ] Update per-slice doc frontmatter — `status: done`, `commit: <hash>`, `completed_date: <ISO>`, `last_updated: <ISO>`.
- [ ] Append final Implementation log entry per `docs/IMPLEMENTATION-LOG-TEMPLATE.md` §4.
- [ ] Add any newly-discovered risks to `cloud-evidence/docs/loops/LOOP-Z-RISKS.md` in the same commit.
- [ ] Verify `git log --oneline -3` shows the Z.Z1 commit landed before declaring closed.
- [ ] Confirm downstream slices (Z.Z2, Z.Z3, Z.Z4, Z.Z5) are unblocked — their `depends_on: [Z.Z1]` entries are now satisfied.

**Failure to execute steps 1-8 means Z.Z1 is NOT closed.** Per CLAUDE.md
slice-completion directive: future sessions will see the inconsistency
and reject it.
