---
slice_id: Z.Z3
title: ISO/IEC 27017:2015 Cloud Controls — per-cloud (AWS/GCP/Azure) CLD.* control evidence + augmented 27002 implementation guidance + shared-responsibility table
loop: Z
status: proposed
commit: TBD
completed_date: —
depends_on:
  - Z.Z1                                # ISO/IEC 27001:2022 Annex A catalog + NIST OLIR + FedRAMP KSI crosswalk; provides the catalog snapshot loader Z.Z3 augments with cloud overlays
  - LOOP-INV-S                          # Inventory + Coverage Contract; Z.Z3 reads inventory tags (tenant_isolation, hypervisor, virtual-network-id, monitoring_target, admin_account_id) to compute per-cloud CLD.* control coverage
  - existing providers/aws/inventory.ts # AWS reference-architecture audit + Resource Graph discovery
  - existing providers/gcp/inventory.ts # GCP organisation discovery + Cloud Asset Inventory
  - existing providers/azure/inventory.ts # Azure Resource Graph discovery + reference-architecture audit
  - existing core/inventory.ts          # canonical inventory model that carries data_classes[] + tenant_isolation + virtual_network_id tags
  - existing core/inventory-coverage.ts # coverage contract — Z.Z3 increments per-cloud control-coverage counters
  - LOOP-A.A1                           # OSCAL POA&M v1.1.2 emitter — Z.Z3 emits "ISO 27017 CLD.* Gap" findings via the existing emitter
  - LOOP-A.A4                           # Submission bundler — Z.Z3 registers three new WELL_KNOWN roles (per-cloud coverage JSON + per-cloud .docx supplement)
  - LOOP-A.A5                           # Signing pipeline (Ed25519 + RFC 3161 + RFC 8785 canonicalization) — every Z.Z3 emit flows through signEnvelope()
blocks:
  - Z.Z2                                # ISO 27001 Statement of Applicability emitter — Z.Z2 reads Z.Z3's per-cloud coverage to populate Annex A controls that 27017 augments and to surface CLD.* controls in the SoA's cloud_overlay section
  - Z.Z5                                # EUCS submission package — EUCS Substantial requires 27017 evidence by default; Z.Z5 packager refuses to build at Substantial+ without a Z.Z3 envelope per in-scope cloud
estimated_effort: medium (~5-7 working days for single implementer)
last_updated: 2026-06-08
applicable_conditional: false
condition: |
  Z.Z3 is unconditional within LOOP-Z. When LOOP-Z fires
  (`--international-equivalence` or `CLOUD_EVIDENCE_INTERNATIONAL_EQUIVALENCE=1`),
  Z.Z3 runs against every cloud provider the operator has configured
  in `cloud-evidence/config.yaml` (AWS / GCP / Azure). If the CSP
  claims cloud-specific 27017 controls in addition to 27001 (which
  is the default for any LOOP-Z run — ISO 27017 is the cloud overlay
  for ISO 27001 and EUCS Substantial requires it), Z.Z3 emits one
  signed envelope per cloud provider per evaluation run. If the CSP
  is a single-cloud SaaS, Z.Z3 emits exactly one envelope. If the
  CSP is multi-cloud, Z.Z3 emits one envelope per provider plus a
  combined cross-cloud rollup ingested by Z.Z2's SoA. The trigger
  flag below is an explicit opt-out / opt-in beyond the LOOP-Z gate
  for operators who want to evaluate 27017 separately (e.g. while
  Z.Z2 SoA is still in operator review).
trigger_flag: "--iso-z-z3"
trigger_env: CLOUD_EVIDENCE_Z_Z3
---

# Z.Z3 — ISO/IEC 27017:2015 Cloud Controls (per-cloud overlay)

> Per-cloud-provider (AWS / GCP / Azure) implementation-guidance and
> evidence-collection layer for the seven cloud-specific extension
> controls defined in ISO/IEC 27017:2015 (`CLD.6.3.1`, `CLD.8.1.5`,
> `CLD.9.5.1`, `CLD.9.5.2`, `CLD.12.1.5`, `CLD.12.4.5`, `CLD.13.1.4`)
> plus the approximately 37 ISO/IEC 27002:2022 controls that 27017
> augments with cloud-specific implementation guidance. Reads the Z.Z1
> catalog snapshot for the 27001:2022 Annex A control list, reads the
> Z.Z3-owned `data/iso-27017-controls.json` catalog for the CLD.*
> controls + augmentation table, reads the existing inventory module
> (`core/inventory.ts`) for cloud-asset facts (tenant isolation,
> hypervisor type, virtual-network IDs, monitoring targets, admin
> account IDs), and emits one signed evidence envelope per cloud
> provider per evaluation run.
>
> This slice is the **cloud-specific operational layer** that turns
> a generic ISO 27001 ISMS into something the EU EUCS Conformity
> Assessment Body, the ISMAP-J assessor, the IRAP-AU assessor, and
> the commercial international customer all expect to see. ISO 27001
> certification *without* a 27017 cloud overlay is increasingly
> rejected for any CSP doing IaaS / PaaS / SaaS business
> internationally. Z.Z3 closes that gap with a deterministic,
> REO-compliant evidence pipeline.
>
> Authority: `cloud-evidence/CLAUDE.md` (Real-Evidence-Only standard)
> governs every emit path. Every byte traces back to: (a) the Z.Z1
> signed catalog snapshot for 27001:2022 Annex A controls + the Z.Z3
> own catalog snapshot for the 27017 CLD.* and augmentation set, (b)
> a live read-only SDK call against AWS / GCP / Azure (Resource Graph,
> Cloud Asset Inventory, KMS, IAM, Monitor, CloudTrail / Cloud Audit
> Logs, Storage / S3, VPC / VNet, etc.) executed through the
> existing read-only Proxy guardrails, (c) the existing
> `core/inventory.ts` canonical inventory records with their
> `data_classes[]`, `tenant_isolation`, `virtual_network_id`,
> `admin_account_id`, `hypervisor_type`, and `diagram_label` tags,
> or (d) operator-supplied configuration in `org-profile.yaml`,
> `iso-27017-csc-csp-overrides.yaml`, or `cloud-evidence/config.yaml`.
> No defaults, no placeholders, no stub returns.

---

## 1. Mission

Z.Z3 reads the Z.Z1 catalog snapshot for the ISO/IEC 27001:2022 Annex
A control list (93 controls) and the Z.Z3-owned `data/iso-27017-
controls.json` catalog snapshot for the seven cloud-specific extension
controls (CLD.6.3.1 through CLD.13.1.4) plus the augmentation table
that maps approximately 37 ISO/IEC 27002:2022 controls to their
cloud-specific implementation guidance and shared-responsibility split
between cloud service provider (CSP) and cloud service customer (CSC).
For every cloud provider configured in `cloud-evidence/config.yaml`
(AWS, GCP, Azure), Z.Z3 runs a provider-specific evidence collector
(`providers/aws/iso-27017.ts`, `providers/gcp/iso-27017.ts`,
`providers/azure/iso-27017.ts`) that calls the relevant read-only
SDK APIs, queries the inventory module for already-collected facts,
and produces a per-cloud per-control conformance decision:
`conformant`, `conformant-with-caveat`, `non-conformant`, or
`not-applicable`. The decision is deterministic and traceable; it
uses the lookup logic in `core/iso-27017-mapper.ts` (the cross-cloud
orchestrator) and the per-cloud collectors.

The slice composes one signed evidence envelope per (cloud-provider,
evaluation-run) tuple. The envelope's `cld_controls[]` array carries
one record per CLD.* control with the `cld_id`, `cld_short_name`,
`cld_type` (`csp-only`, `csc-only`, `shared`), `disposition`,
`disposition_rationale`, `evidence_calls[]` (the array of SDK calls
that produced the underlying facts), `inventory_asset_refs[]` (the
inventory IDs of every asset the decision touched), and
`provenance.nist_800_53_r5_mapping[]` cross-walked via the Z.Z1
OLIR-derived mapping. The envelope's `augmented_27002[]` array carries
one record per augmented 27002 control with the same shape but with
an additional `csp_obligations[]` and `csc_obligations[]` arrays
derived from the 27017 augmentation table. The envelope's
`cross_cloud_rollup` block (emitted only when the operator runs more
than one provider in a single evaluation run) consolidates the per-
cloud decisions into a single SoA-ready overlay for Z.Z2 to consume.

Z.Z3 also emits one OOXML / zip-store `.docx` supplement per cloud
provider — a brief 5-to-15-page Word document that names every CLD.*
control, names the cloud-provider service(s) that implement it, and
includes the verbatim shared-responsibility split per 27017's
augmentation table. The `.docx` supplement is the artefact the
operator attaches to the ISO certification body's Stage 1
documentation review or the EU EUCS Conformity Assessment Body's
substantive review. The renderer is `core/iso-27017-supplement-
docx.ts` and reuses the existing OOXML helpers from
`core/oscal-ssp-docx.ts` and `core/inventory-workbook.ts` (zip-store,
document.xml, styles.xml, numbering.xml).

Z.Z3 persists every per-cloud evaluation into the tracker DB
`iso_27017_coverage` table (one row per evaluation run per cloud
provider) and one row per (run, cloud, cld_control) into
`iso_27017_cld_decisions`. The tracker UI surfaces a per-cloud
27017 coverage dashboard at `/iso-27017/<cloud>` with the per-
control conformance status, the SDK calls that produced the
evidence, and the shared-responsibility split that the operator
must communicate to their CSCs. Operator review actions (approving
a non-conformant disposition's compensating-control override, marking
a CLD.* gap as remediated, sharing an envelope with a CAB) flow
through the existing tracker signed audit log.

Z.Z3 does NOT replace `core/inventory.ts` or the per-provider
inventory collectors. Z.Z3 *reads* the inventory's already-collected
facts and *augments* them with a 27017-specific conformance decision
layer. When the inventory does not yet carry a fact Z.Z3 needs (e.g.
a `tenant_isolation` tag that the operator has not yet attached to
their cloud resources), Z.Z3 emits a `REQUIRES-OPERATOR-INPUT`
diagnostic per asset and degrades the per-control decision to
`conformant-with-caveat` or `non-conformant` per the §11 table; the
slice does NOT silently treat missing data as conformant.

---

## 2. Authoritative sources

Every URL accessed 2026-06-08 (date-of-access locked at the spec
authoring run). Verbatim quotes appear in Markdown blockquotes; where
the live ISO source is paywalled (most ISO standards are; ISO/IEC
27017:2015 was CHF 138 at access time), the implementer references
the standard's publicly-available ISO preview page + the NIST OLIR
informative mapping + the publicly-available cloud-provider
documentation for the SDK / API surface the collector reads against.
Cloud-provider documentation URLs are cited for the SDK / API
surface the collector reads against; the provider docs are not
"authoritative" for ISO 27017 conformance but ARE authoritative for
the data shape the collector parses. The Z.Z1 spec
(`docs/slices/Z/Z.Z1.md`) and LOOP-Z SPEC (`docs/loops/LOOP-Z-SPEC.md`)
have additional sources covering the parent 27001 / 27002 / 27018 /
27701 corpus; Z.Z3's sources below are the subset directly required
to author the 27017 cloud overlay implementation.

### 2.1 ISO/IEC 27017:2015 — Code of practice for information security controls based on ISO/IEC 27002 for cloud services

URL: https://www.iso.org/standard/43757 (accessed 2026-06-08).
Status: Published December 2015 (first edition). No 2022 reissue at
access time; ISO has signalled a 27017 reissue is in development but
no draft has been circulated through ISO/IEC JTC 1/SC 27.

27017 supplements ISO/IEC 27002 with cloud-specific implementation
guidance and adds 7 cloud-specific controls in a new namespace
`CLD.*`. The standard is structured to be read alongside 27002 — each
of the approximately 37 augmented controls is presented as "this is
the 27002 control text [reference]; this is the cloud-specific
implementation guidance".

Publicly-available preview text (from ISO's standard summary page,
accessed 2026-06-08):

> "This Recommendation | International Standard provides guidelines
> for information security controls applicable to the provision and
> use of cloud services by providing: additional implementation
> guidance for relevant controls specified in ISO/IEC 27002;
> additional controls with implementation guidance that specifically
> relate to cloud services."

The 7 cloud-specific controls (verbatim short names from ISO's
publicly-available preview page; the full implementation guidance
requires the licensed standard):

> "CLD.6.3.1 — Shared roles and responsibilities within a cloud
> computing environment."

> "CLD.8.1.5 — Removal of cloud service customer assets."

> "CLD.9.5.1 — Segregation in virtual computing environments."

> "CLD.9.5.2 — Virtual machine hardening."

> "CLD.12.1.5 — Administrator's operational security."

> "CLD.12.4.5 — Monitoring of cloud services."

> "CLD.13.1.4 — Alignment of security management for virtual and
> physical networks."

The shared-responsibility split is the operational consumable. For
each augmented 27002 control and for each CLD.* control, 27017
specifies which obligations land on the CSP and which land on the
CSC. Z.Z3's `data/iso-27017-controls.json` catalog encodes the
shared-responsibility split per control (see §4.2 for the catalog
schema). The 27017 spec organises this guidance through repeated
"Cloud service provider" and "Cloud service customer" sub-sections
under each augmented control's implementation guidance block.

The implementer pulls the public control IDs + short names from the
publicly-available ISO preview pages and from the NIST OLIR informa-
tive mapping; the operator consults their licensed standard for the
full implementation-guidance prose. Z.Z3 emits the *control IDs*,
the *short names*, and the *shared-responsibility split fact*; the
substantive ISO control text remains in the licensed standard the
operator paid for.

### 2.2 ISO/IEC 27002:2022 — Information security controls (the augmented baseline)

URL: https://www.iso.org/standard/27002 (accessed 2026-06-08).
Status: Published February 2022 (latest edition; supersedes
27002:2013). Provides implementation guidance for the 93 controls
referenced by 27001:2022 Annex A.

ISO/IEC 27017:2015 was authored against ISO/IEC 27002:2013 (the
prior 27002 edition). With the 27002:2022 reorganisation (the
133-control 2013 set collapsed into 93 controls organised into 4
themes — Organizational, People, Physical, Technological), the
27017 augmentation table requires re-derivation against the new
93-control set. Until ISO publishes the 27017 reissue, the
operator and the certification body work from a derived mapping
table that reconciles 27017:2015's 2013-keyed augmentations to the
2022-keyed controls. Z.Z3 ships this derived mapping as part of
`data/iso-27017-controls.json` with a `derivation_source` field
documenting whether each augmentation row is direct (from 27017
itself) or derived (from the implementer's reconciliation against
27002:2022).

Publicly-available preview text from ISO's standard summary page
(accessed 2026-06-08):

> "This document provides a reference set of generic information
> security controls including implementation guidance. This document
> is designed to be used by organizations: (a) within the context of
> an information security management system (ISMS) based on
> ISO/IEC 27001; (b) for implementing information security controls
> based on internationally recognized best practices; (c) for
> developing organization-specific information security management
> guidelines."

The five attribute dimensions per 27002:2022 control (control type,
information-security properties, cybersecurity concepts, operational
capabilities, security domains) are carried forward into Z.Z3's
catalog where they apply to the augmented controls — the augmented
control's row inherits the attributes from the parent 27002:2022
control plus a Z.Z3-added `cloud_augmentation` attribute that
captures whether the augmentation is "csp-only", "csc-only", or
"shared".

### 2.3 ISO/IEC 27001:2022 — Annex A (the parent control set)

URL: https://www.iso.org/standard/27001 (accessed 2026-06-08).
Status: Published October 2022. Z.Z1 ships the catalog snapshot of
Annex A's 93 controls; Z.Z3 reads that snapshot to obtain the
canonical control IDs the augmentation table maps against.

Publicly-available preview text:

> "This document specifies the requirements for establishing,
> implementing, maintaining and continually improving an information
> security management system within the context of the organization.
> This document also includes requirements for the assessment and
> treatment of information security risks tailored to the needs of
> the organization. The requirements set out in this document are
> generic and are intended to be applicable to all organizations,
> regardless of type, size or nature. Excluding any of the
> requirements specified in Clauses 4 to 10 is not acceptable when
> an organization claims conformity to this document."

The Annex A control list (themes, IDs, counts) is documented in
LOOP-Z-SPEC.md §2.1. Z.Z3 does NOT redistribute the Annex A control
text; Z.Z3 reads the Z.Z1 snapshot for the control IDs + short names.

### 2.4 ENISA EUCS Candidate Scheme — 27017-derived security objectives

URL: https://www.enisa.europa.eu/topics/certification/cybersecurity-certification-framework/eucs
(accessed 2026-06-08).
Status: Candidate scheme published by ENISA in 2020; draft updated
through 2024; awaiting European Commission adoption as a delegated
act under EU Cybersecurity Act (Regulation 2019/881).

The EUCS scheme's security objectives are heavily derived from ISO
27017 + 27018 + ISO 27002:2022 + the existing C5 (Germany) and
SecNumCloud (France) national schemes. EUCS Substantial requires
the 27017 cloud overlay; EUCS High requires 27017 + 27018 + 27701 +
penetration testing.

Publicly-available text from the ENISA EUCS factsheet:

> "The European Union Cybersecurity Certification Scheme on Cloud
> Services (EUCS) is a candidate cybersecurity certification scheme
> that aims to harmonize the security of cloud services in the EU.
> It covers Infrastructure as a Service (IaaS), Platform as a
> Service (PaaS), and Software as a Service (SaaS) cloud services.
> The scheme defines three assurance levels — Basic, Substantial,
> and High — and a set of security objectives and requirements that
> cloud service providers must meet to obtain certification at each
> level."

The 27017-derived EUCS security objectives that Z.Z3's per-control
evidence supports include (publicly-summarised from the ENISA
factsheet + the EU Cybersecurity Act Article 51 objectives):

> "Cloud services shall be designed and operated in a way that
> achieves the security objectives specified in Article 51 of the
> Cybersecurity Act, including: confidentiality, integrity, and
> availability; protection against accidental or unauthorized
> storage, processing, access, disclosure, destruction, loss, or
> alteration during the entire life cycle of the data; possibility
> to verify the persons, programmes or machines that have access to
> certain data, services or functions."

### 2.5 EU Cybersecurity Act — Regulation (EU) 2019/881 (the EUCS authority)

URL: https://eur-lex.europa.eu/eli/reg/2019/881/oj (accessed
2026-06-08).
Status: In force since 27 June 2019. Establishes the EU
Cybersecurity Certification Framework under which EUCS is being
developed.

Article 51 (verbatim from EUR-Lex; the security-objectives anchor
that EUCS — and indirectly Z.Z3 — implements):

> "Article 51 — Security objectives of European cybersecurity
> certification schemes. A European cybersecurity certification
> scheme shall be designed to achieve, as applicable, at least the
> following security objectives:
> (a) to protect stored, transmitted or otherwise processed data
> against accidental or unauthorised storage, processing, access or
> disclosure during the entire life cycle of the ICT product, ICT
> service or ICT process;
> (b) to protect stored, transmitted or otherwise processed data
> against accidental or unauthorised destruction, loss or alteration
> or lack of availability during the entire life cycle of the ICT
> product, ICT service or ICT process;
> (c) that authorised persons, programs or machines are able only to
> access the data, services or functions to which their access
> rights refer;
> (d) to identify and document known dependencies and
> vulnerabilities;
> (e) to record which data, services or functions have been
> accessed, used or otherwise processed, at what times and by whom;
> (f) to make it possible to check which data, services or functions
> have been accessed, used or otherwise processed, at what times
> and by whom;
> (g) to verify that ICT products, ICT services and ICT processes
> do not contain known vulnerabilities;
> (h) to restore the availability and access to data, services and
> functions in a timely manner in the event of a physical or
> technical incident;
> (i) that ICT products, ICT services and ICT processes are secure
> by default and by design;
> (j) that ICT products, ICT services and ICT processes are provided
> with up-to-date software and hardware that do not contain
> publicly known vulnerabilities, and are provided with mechanisms
> for secure updates."

Article 56(1):

> "The certification of ICT products, ICT services and ICT processes
> shall be voluntary, unless otherwise specified by Union law or
> Member State law."

Z.Z3's per-control evidence supports objectives (a) through (j) for
the cloud-services-specific surface. The mapping from CLD.* controls
to Article 51 objectives is encoded in `data/iso-27017-controls.json`
under each control's `eucs_article_51_mapping[]` field.

### 2.6 NIST OLIR — ISO/IEC 27017 ↔ NIST 800-53 Rev 5 informative mapping

URL: https://csrc.nist.gov/projects/olir (accessed 2026-06-08).
Status: ongoing NIST programme. The OLIR programme publishes
informative crosswalks between cybersecurity reference documents;
the published mappings include ISO 27001:2022 ↔ NIST 800-53 Rev 5,
ISO 27002:2022 ↔ NIST 800-53 Rev 5, and (partially) ISO 27017:2015
↔ NIST 800-53 Rev 5 augmentation entries.

Publicly-available NIST text from the OLIR program page:

> "The National Online Informative References Program is a NIST
> effort to facilitate subject matter experts (SMEs) in defining
> standardized online informative references (OLIRs) between
> elements of their cybersecurity, privacy, and workforce documents
> and elements of other cybersecurity, privacy, and workforce
> documents. OLIRs are simple, structured, and machine-readable,
> allowing them to be easily shared and consumed."

The OLIR mapping is one-way (ISO → NIST). For Z.Z3's CLD.* controls,
the canonical NIST 800-53 Rev 5 mappings (per the OLIR informative
crosswalk + Z.Z3 implementer review) are:

| CLD control | Primary NIST 800-53 Rev 5 mapping | Relationship |
|---|---|---|
| CLD.6.3.1 — Shared roles | PL-8, SA-9, PS-7 | superset |
| CLD.8.1.5 — Removal of customer assets | MP-6, SC-28, AC-4 | intersect |
| CLD.9.5.1 — Segregation in virtual computing environments | SC-2, SC-7, SC-39 | intersect |
| CLD.9.5.2 — Virtual machine hardening | CM-2, CM-6, CM-7 | subset |
| CLD.12.1.5 — Administrator's operational security | AC-2(7), AC-6(5), AU-6(5) | subset |
| CLD.12.4.5 — Monitoring of cloud services | AU-2, AU-12, SI-4 | superset |
| CLD.13.1.4 — Alignment of security management for virtual and physical networks | SC-7, SC-32, SC-39 | intersect |

The "relationship" column uses the OLIR programme's standard set
(`subset`, `equivalent`, `intersect`, `superset`, `no_relationship`);
Z.Z3's catalog stores the relationship type per pairing.

### 2.7 NIST SP 800-53 Rev 5 — control catalog (the NIST-side anchor)

URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
(accessed 2026-06-08).
Status: Published September 2020 (with 2023 errata).

Z.Z3 uses 800-53 Rev 5 as the NIST-side anchor for the OLIR
mappings. The relevant Rev 5 control families for the CLD.* mappings
are SC (System and Communications Protection), CM (Configuration
Management), AC (Access Control), AU (Audit and Accountability),
MP (Media Protection), PL (Planning), PS (Personnel Security), SA
(System and Services Acquisition), and SI (System and Information
Integrity).

Verbatim (SC-7 — Boundary Protection — the primary NIST anchor for
CLD.9.5.1 and CLD.13.1.4):

> "Boundary Protection. Control: a. Monitor and control
> communications at the external managed interfaces to the system
> and at key internal managed interfaces within the system; b.
> Implement subnetworks for publicly accessible system components
> that are physically or logically separated from internal
> organizational networks; and c. Connect to external networks or
> systems only through managed interfaces consisting of boundary
> protection devices arranged in accordance with an organizational
> security architecture."

Verbatim (CM-2 — Baseline Configuration — the primary NIST anchor
for CLD.9.5.2 — Virtual machine hardening):

> "Baseline Configuration. Control: a. Develop, document, and
> maintain under configuration control, a current baseline
> configuration of the system; and b. Review and update the
> baseline configuration of the system: 1. [Assignment:
> organization-defined frequency]; 2. When required due to
> [Assignment: organization-defined circumstances]; and 3. When
> system components are installed or upgraded."

Verbatim (AU-12 — Audit Record Generation — the primary NIST anchor
for CLD.12.4.5 — Monitoring of cloud services):

> "Audit Record Generation. Control: a. Provide audit record
> generation capability for the event types the system is capable
> of auditing as defined in AU-2a on [Assignment:
> organization-defined system components]; b. Allow [Assignment:
> organization-defined personnel or roles] to select the event
> types that are to be logged by specific components of the system;
> and c. Generate audit records for the event types defined in
> AU-2c that include the audit record content defined in AU-3."

### 2.8 ISO/IEC 27018:2019 — PII processor controls (Z.Z4 sibling)

URL: https://www.iso.org/standard/76559 (accessed 2026-06-08).
Status: Published January 2019 (second edition).

Z.Z3 cross-references 27018 at the catalog level only — when a
CLD.* control overlaps with a 27018 PII-processor control (e.g.
CLD.8.1.5 — Removal of cloud service customer assets — overlaps
with 27018's "Use, retention, and disclosure limitation"
augmentation), Z.Z3's `data/iso-27017-controls.json` carries an
`iso_27018_overlap[]` field listing the overlapping 27018 control
IDs. The substantive 27018 evidence emission is owned by Z.Z4;
Z.Z3 *references* the overlap so the SoA (Z.Z2) can present a
unified view.

Publicly-available preview text:

> "This document establishes commonly accepted control objectives,
> controls and guidelines for implementing measures to protect
> Personally Identifiable Information (PII) in line with the privacy
> principles in ISO/IEC 29100 for the public cloud computing
> environment. In particular, this document specifies guidelines
> based on ISO/IEC 27002, taking into consideration the regulatory
> requirements for the protection of PII which might be applicable
> within the context of the information security risk environment(s)
> of a provider of public cloud services."

### 2.9 ISO/IEC 27701:2019 — PIMS extension (Z.Z5 sibling; downstream consumer)

URL: https://www.iso.org/standard/71670 (accessed 2026-06-08).
Status: Published August 2019.

27701 extends the ISMS pattern with a Privacy Information Management
System. Z.Z3's per-cloud CLD.* evidence is consumed by Z.Z5 when
building the EUCS submission package: every CLD.* control with a
27018 overlap propagates through to the PIMS scope's "PII Processor"
clause.

Publicly-available preview text:

> "This document specifies requirements and provides guidance for
> establishing, implementing, maintaining and continually improving
> a Privacy Information Management System (PIMS) in the form of an
> extension to ISO/IEC 27001 and ISO/IEC 27002 for privacy
> management within the context of the organization."

### 2.10 AWS — read-only SDK APIs Z.Z3's AWS provider calls

Z.Z3's `providers/aws/iso-27017.ts` collector reads from the
following AWS APIs (all read-only; all already wrapped by the
existing read-only Proxy guardrails in `core/auth/aws.ts` +
`core/readonly-guardrail-aws.ts`):

- **AWS Organizations** — ListAccounts, DescribeOrganization,
  ListPoliciesForTarget. Used by CLD.6.3.1 (shared roles) to
  enumerate the org structure and confirm SCPs that segregate the
  CSP's accounts from the customer-deployed accounts.
- **AWS IAM** — GetAccountSummary, ListRoles, ListUsers,
  GetAccountAuthorizationDetails, SimulatePrincipalPolicy. Used by
  CLD.6.3.1 + CLD.12.1.5 to enumerate admin roles and confirm
  separation of CSP-side admin roles from CSC-managed roles.
- **AWS EC2** — DescribeInstances, DescribeImages, DescribeVpcs,
  DescribeSubnets, DescribeSecurityGroups, DescribeNetworkAcls,
  DescribeVpcEndpoints. Used by CLD.9.5.1 (segregation in virtual
  computing) + CLD.9.5.2 (VM hardening) + CLD.13.1.4 (virtual /
  physical network alignment).
- **AWS S3** — ListBuckets, GetBucketEncryption, GetBucketPolicy,
  GetBucketLifecycleConfiguration, GetBucketVersioning. Used by
  CLD.8.1.5 (removal of customer assets) to confirm lifecycle
  policies and deletion-on-account-closure controls.
- **AWS KMS** — ListKeys, DescribeKey, GetKeyPolicy. Used by
  CLD.8.1.5 (cryptographic erasure pathway for customer assets) +
  CLD.9.5.1 (per-tenant KMS key segregation).
- **AWS CloudTrail** — DescribeTrails, GetTrailStatus, GetEventSelectors,
  GetInsightSelectors. Used by CLD.12.4.5 (monitoring of cloud
  services) to confirm CloudTrail org-wide log delivery is enabled.
- **AWS CloudWatch** — DescribeAlarms, ListMetrics. Used by
  CLD.12.4.5 to confirm operational-security alarms exist for the
  CSP-side admin events.
- **AWS Config** — DescribeConfigurationRecorders, DescribeDeliveryChannels,
  DescribeConfigRules. Used by CLD.9.5.2 (configuration drift
  detection on VMs).
- **AWS Inspector v2** — ListFindings, ListCoverage. Used by
  CLD.9.5.2 (VM hardening — vulnerability evidence).
- **AWS Macie / GuardDuty** — GetMacieSession, GetDetector,
  ListFindings. Used by CLD.12.4.5 (monitoring of cloud services).

URL (canonical AWS API reference index): https://docs.aws.amazon.com/sdkforjavascriptv3/
(accessed 2026-06-08). The implementer pins specific API URLs per
collector in code comments.

### 2.11 GCP — read-only SDK APIs Z.Z3's GCP provider calls

Z.Z3's `providers/gcp/iso-27017.ts` collector reads from the
following GCP APIs (all read-only; all wrapped by the existing
read-only Proxy guardrails in `core/auth/gcp.ts` +
`core/readonly-guardrail-gcp.ts`):

- **GCP Resource Manager** — projects.list, folders.list,
  organizations.get. Used by CLD.6.3.1 (shared roles) to enumerate
  the org hierarchy.
- **GCP IAM** — projects.getIamPolicy, projects.testIamPermissions,
  organizations.getIamPolicy. Used by CLD.6.3.1 + CLD.12.1.5.
- **GCP Compute Engine** — instances.list, instances.get,
  networks.list, subnetworks.list, firewalls.list. Used by
  CLD.9.5.1 + CLD.9.5.2 + CLD.13.1.4.
- **GCP Cloud Storage** — buckets.list, buckets.get,
  buckets.getIamPolicy. Used by CLD.8.1.5.
- **GCP KMS** — keyRings.list, cryptoKeys.list,
  cryptoKeys.getIamPolicy. Used by CLD.8.1.5 + CLD.9.5.1.
- **GCP Cloud Asset Inventory** — assets.searchAllResources,
  assets.searchAllIamPolicies. Used as the org-wide enumeration
  backbone for inventory facts not yet captured in `core/inventory.ts`.
- **GCP Cloud Audit Logs / Cloud Logging** — logs.list,
  sinks.list, exclusions.list. Used by CLD.12.4.5.
- **GCP Cloud Monitoring** — alertPolicies.list,
  uptimeCheckConfigs.list. Used by CLD.12.4.5.
- **GCP Security Command Center** — findings.list, sources.list.
  Used by CLD.9.5.2 (VM hardening) + CLD.12.4.5 (monitoring).
- **GCP VPC Service Controls** — accessPolicies.list,
  servicePerimeters.list. Used by CLD.9.5.1 + CLD.13.1.4
  (segregation + virtual/physical network alignment).

URL (canonical GCP API reference index): https://cloud.google.com/apis
(accessed 2026-06-08). The implementer pins specific API URLs per
collector in code comments.

### 2.12 Azure — read-only SDK APIs Z.Z3's Azure provider calls

Z.Z3's `providers/azure/iso-27017.ts` collector reads from the
following Azure APIs (all read-only; all wrapped by the existing
read-only Proxy guardrails in `core/auth/azure.ts` +
`core/readonly-guardrail-azure.ts`):

- **Azure Resource Graph** — query. Used as the cross-subscription
  enumeration backbone (the same backbone the existing
  `providers/azure/inventory.ts` uses).
- **Microsoft Graph** — directoryRoles.list, roleAssignments.list,
  groups.list. Used by CLD.6.3.1 (shared roles) + CLD.12.1.5.
- **Azure RBAC** — roleAssignments.list, roleDefinitions.list. Used
  by CLD.6.3.1 + CLD.12.1.5.
- **Azure Compute** — virtualMachines.list, virtualMachines.get,
  images.list, disks.list. Used by CLD.9.5.1 + CLD.9.5.2.
- **Azure Networking** — virtualNetworks.list, subnets.list,
  networkSecurityGroups.list, networkInterfaces.list,
  privateEndpoints.list. Used by CLD.9.5.1 + CLD.13.1.4.
- **Azure Storage** — storageAccounts.list, blobContainers.list,
  encryptionScopes.list. Used by CLD.8.1.5.
- **Azure Key Vault** — vaults.list, keys.list, secrets.list,
  certificates.list. Used by CLD.8.1.5 + CLD.9.5.1.
- **Azure Monitor** — diagnosticSettings.list,
  metricAlerts.list, activityLogAlerts.list. Used by CLD.12.4.5.
- **Microsoft Defender for Cloud** — assessments.list,
  recommendations.list, secureScores.list. Used by CLD.9.5.2 +
  CLD.12.4.5.
- **Azure Policy** — policyAssignments.list, policyDefinitions.list,
  policySetDefinitions.list. Used by CLD.9.5.2 (configuration
  baselines) + CLD.13.1.4 (network policies).

URL (canonical Azure REST API index): https://learn.microsoft.com/en-us/rest/api/azure/
(accessed 2026-06-08). The implementer pins specific API URLs per
collector in code comments.

### 2.13 Cloud Security Alliance — Cloud Controls Matrix (CCM) v4 (cross-reference)

URL: https://cloudsecurityalliance.org/research/cloud-controls-matrix
(accessed 2026-06-08).
Status: CCM v4 published 2021; v4.0.10 latest revision at access
time.

CCM is the CSA's industry-standard cloud-controls catalog,
explicitly aligned to ISO 27017 + 27018 + the major cloud security
schemes (FedRAMP, EUCS, C5, SecNumCloud, ISMAP, IRAP). Z.Z3
cross-references CCM v4 control IDs per CLD.* control in
`data/iso-27017-controls.json` under each control's `ccm_v4_mapping[]`
field. The CCM mapping is an additional informative reference for
the CSA STAR Registry path that some operators pursue alongside ISO
27001 + 27017.

Publicly-available CSA text:

> "The Cloud Controls Matrix (CCM) is a cybersecurity control
> framework for cloud computing. It is composed of 197 control
> objectives that are structured in 17 domains covering all key
> aspects of the cloud technology."

### 2.14 NIST SP 800-145 — The NIST Definition of Cloud Computing

URL: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-145.pdf
(accessed 2026-06-08).
Status: Published September 2011 (definitive NIST cloud definition).

Z.Z3 uses 800-145 as the authoritative definition of "cloud service"
+ "cloud service provider" + "cloud service customer" + "service
model (IaaS/PaaS/SaaS)" + "deployment model (Public/Private/
Community/Hybrid)" — the same terminology 27017 uses throughout.

Verbatim:

> "Cloud computing is a model for enabling ubiquitous, convenient,
> on-demand network access to a shared pool of configurable
> computing resources (e.g., networks, servers, storage,
> applications, and services) that can be rapidly provisioned and
> released with minimal management effort or service provider
> interaction. This cloud model is composed of five essential
> characteristics, three service models, and four deployment
> models."

> "Essential Characteristics: On-demand self-service. Broad network
> access. Resource pooling. Rapid elasticity. Measured service."

> "Service Models: Software as a Service (SaaS). Platform as a
> Service (PaaS). Infrastructure as a Service (IaaS)."

The service-model fact is consumed by Z.Z3's `data/iso-27017-
controls.json` under each control's `applicable_service_models[]`
field — e.g. CLD.9.5.2 (VM hardening) is applicable only when the
CSP offers IaaS or PaaS-with-customer-VMs (not pure SaaS).

---

## 3. Scope

### 3.1 In scope

- Per-cloud-provider (AWS / GCP / Azure) implementation of evidence
  collection for each ISO/IEC 27017:2015 CLD.* extension control:
  - CLD.6.3.1 — Shared roles and responsibilities within a cloud
    computing environment
  - CLD.8.1.5 — Removal of cloud service customer assets
  - CLD.9.5.1 — Segregation in virtual computing environments
  - CLD.9.5.2 — Virtual machine hardening
  - CLD.12.1.5 — Administrator's operational security
  - CLD.12.4.5 — Monitoring of cloud services
  - CLD.13.1.4 — Alignment of security management for virtual and
    physical networks
- Per-cloud-provider implementation of evidence collection for the
  approximately 37 ISO/IEC 27002:2022 controls that 27017 augments
  with cloud-specific implementation guidance (full list encoded in
  `data/iso-27017-controls.json`).
- The shared-responsibility split table: each augmented control's
  obligations divided between CSP and CSC, encoded in the catalog
  JSON and surfaced in the per-cloud `.docx` supplement.
- Cross-cloud rollup envelope for multi-cloud CSPs: when more than
  one provider is configured, Z.Z3 emits a fourth envelope that
  consolidates the per-cloud decisions into a single SoA-ready
  overlay.
- Per-cloud OOXML / zip-store `.docx` supplement (5-to-15 pages)
  reusing the existing OOXML helpers.
- Tracker DB persistence: `iso_27017_coverage` (one row per
  evaluation run per cloud) + `iso_27017_cld_decisions` (one row
  per (run, cloud, cld_control)).
- POA&M emission via LOOP-A.A1 for every non-conformant decision
  not covered by an operator-documented compensating control
  override (`iso-27017-csc-csp-overrides.yaml`).
- Ed25519 signing + RFC 3161 timestamp + RFC 8785 JSON
  canonicalization per envelope.
- Submission-bundle entry: Z.Z3 registers three new WELL_KNOWN
  roles in `core/submission-bundle.ts` (per-cloud coverage JSON,
  per-cloud `.docx` supplement, cross-cloud rollup JSON).
- ENISA EUCS Article 51 objective mapping per control (informative;
  consumed by Z.Z5 EUCS packager).
- NIST 800-53 Rev 5 cross-walk per control (via the Z.Z1 OLIR
  mapping + Z.Z3 implementer review for the CLD.* controls).
- CCM v4 cross-reference per control (informative).
- ISO 27018 overlap reference per control (informative; Z.Z4
  emits the substantive 27018 evidence).
- Operator override pathway: `iso-27017-csc-csp-overrides.yaml`
  for compensating controls + documented exceptions; the override
  flows through with `provenance: operator` per CLAUDE.md Rule 4.

### 3.2 Out of scope

- **Direct submission to ISO certification body or EU EUCS Conformity
  Assessment Body.** Per CLAUDE.md Rule 4 the operator submits;
  Z.Z3 produces the artefact and the tracker captures the submission
  receipt.
- **The ISO 27001 ISMS clauses 4-10 evaluation.** Those are owned by
  Z.Z2 (Statement of Applicability emitter). Z.Z3 emits *control-
  level* evidence; Z.Z2 emits the ISMS-clause-level documentation.
- **PII-processor-specific evidence (27018).** Owned by Z.Z4. Z.Z3
  references the overlap at the catalog level; Z.Z4 emits the
  substantive 27018 evidence.
- **PIMS scope statement + EUCS package assembly.** Owned by Z.Z5.
  Z.Z3 emits the per-cloud envelope that Z.Z5 consumes.
- **Inventory discovery itself.** Owned by `core/inventory.ts` and
  the per-provider inventory collectors (LOOP-INV-S). Z.Z3 reads
  the already-discovered inventory; Z.Z3 does NOT re-discover
  cloud resources.
- **27001 Annex A control evaluation (the 93 controls).** Owned by
  Z.Z2 (SoA emitter). Z.Z3 emits the 27017 *augmentation* layer on
  top of the Annex A controls Z.Z2 evaluates.
- **The Z.Z1 catalog extraction itself.** Owned by Z.Z1. Z.Z3 reads
  the signed catalog snapshot Z.Z1 emits.
- **Risk-register population.** Owned by LOOP-B.B1. Z.Z3 reads the
  risk register only to populate the `risk_register_refs[]` field
  on the envelope when an operator override cites a risk ID.
- **CSC-side evidence collection.** Z.Z3 emits the CSP-side
  obligations and lists the CSC-side obligations the customer must
  perform; Z.Z3 does NOT collect evidence on behalf of the
  customer (it cannot — the customer's environment is not in the
  CSP's read-only Proxy scope).
- **Penetration-testing reports.** EUCS High requires pentest
  evidence; Z.Z5 surfaces a REQUIRES-OPERATOR-INPUT for that
  artefact. Z.Z3 does not emit pentest evidence.
- **National-government-equivalency schemes (ISMAP, IRAP, MTCS,
  CERT-In).** Z.Z3's catalog is the reusable foundation; per-scheme
  emitters are future work.

---

## 4. Inputs

### 4.1 Z.Z1 catalog snapshot (the 27001:2022 Annex A control list)

Path: `data/iso-27001-2022-annex-a.json` (emitted + signed by Z.Z1).

```typescript
interface ISO27001CatalogSnapshot {
  $schema: 'https://cloud-evidence.example/schemas/iso-27001-2022-catalog-v1.json';
  schema_version: '1.0.0';
  snapshot_id: string;                  // ULID; pinned per extraction run
  snapshot_date: string;                // YYYY-MM-DD
  iso_edition: '2022';
  control_count: 93;
  themes: ISO27001Theme[];              // A.5, A.6, A.7, A.8
  controls: ISO27001AnnexAControl[];    // 93 entries
  nist_olir_version: string;            // OLIR mapping version pinned at extraction
  provenance: SnapshotProvenance;
  signature: Ed25519Signature;
  rfc3161_timestamp: RFC3161Token;
}

interface ISO27001AnnexAControl {
  control_id: string;                   // e.g. "A.8.24"
  short_name: string;                   // e.g. "Use of cryptography"
  theme: 'organizational' | 'people' | 'physical' | 'technological';
  attributes: ISO27002Attributes;       // 5 attribute dimensions
  nist_800_53_r5_mapping: NIST80053Mapping[];
  fedramp_ksi_mapping?: string[];       // FedRAMP Moderate KSI IDs
  iso_27001_2013_legacy_mapping?: string[];
}
```

Z.Z3 reads this snapshot to obtain the canonical Annex A control IDs
+ short names. Z.Z3 verifies the snapshot's Ed25519 signature on load;
verification failure exits the Z.Z3 process with
`CatalogSignatureInvalidError` and leaves no tracker DB rows behind.

### 4.2 Z.Z3-owned catalog: `data/iso-27017-controls.json`

The Z.Z3 spec ships its own catalog snapshot covering (a) the 7 CLD.*
controls and (b) the augmentation table for the approximately 37
27002:2022 controls 27017 augments. Schema:

```typescript
interface ISO27017CatalogSnapshot {
  $schema: 'https://cloud-evidence.example/schemas/iso-27017-2015-catalog-v1.json';
  schema_version: '1.0.0';
  snapshot_id: string;                  // ULID
  snapshot_date: string;                // YYYY-MM-DD
  iso_edition: '2015';
  cld_control_count: 7;
  augmented_control_count: 37;          // approximate; exact count documented in extraction notes
  cld_controls: ISO27017CLDControl[];   // 7 entries
  augmented_controls: ISO27017AugmentedControl[];  // ~37 entries
  derivation_source: '27017:2015-vs-27002:2013-original' | 'implementer-reconciliation-to-27002:2022';
  reconciliation_notes_path?: string;   // when derivation_source is reconciliation
  provenance: SnapshotProvenance;
  signature: Ed25519Signature;
  rfc3161_timestamp: RFC3161Token;
}

interface ISO27017CLDControl {
  cld_id: string;                       // "CLD.6.3.1"
  short_name: string;
  csp_or_csc_or_shared: 'csp' | 'csc' | 'shared';
  applicable_service_models: Array<'IaaS' | 'PaaS' | 'SaaS'>;
  applicable_deployment_models: Array<'Public' | 'Private' | 'Community' | 'Hybrid'>;
  nist_800_53_r5_mapping: NIST80053Mapping[];
  ccm_v4_mapping?: string[];            // CSA CCM v4 control IDs
  iso_27018_overlap?: string[];         // 27018 control IDs that overlap
  eucs_article_51_mapping: Array<'a'|'b'|'c'|'d'|'e'|'f'|'g'|'h'|'i'|'j'>;
  csp_obligations: ObligationItem[];
  csc_obligations: ObligationItem[];
  evidence_strategy: Array<EvidenceStrategyItem>;
}

interface ISO27017AugmentedControl {
  iso_27002_control_id: string;         // canonical 27002:2022 control ID
  iso_27002_short_name: string;
  augmentation_type: 'cloud-implementation-guidance-only' | 'csp-csc-split' | 'csp-only-addition' | 'csc-only-addition';
  csp_obligations: ObligationItem[];
  csc_obligations: ObligationItem[];
  evidence_strategy: Array<EvidenceStrategyItem>;
  iso_27018_overlap?: string[];
}

interface ObligationItem {
  obligation_id: string;
  text_paraphrase: string;              // operator-paraphrased, NOT verbatim ISO
  obligation_kind: 'document' | 'configure' | 'monitor' | 'restrict' | 'log' | 'audit';
}

interface EvidenceStrategyItem {
  provider: 'aws' | 'gcp' | 'azure' | 'all';
  sdk_call: string;                     // canonical API method name
  evidence_kind: 'configuration-fact' | 'inventory-fact' | 'audit-log-presence' | 'policy-presence' | 'enrolment-count';
  expected_value_predicate: string;     // e.g. "encryption.algorithm == 'AES-256'"
}
```

### 4.3 Operator configuration

Path: `cloud-evidence/config.yaml` (top-level) plus two additional
files discovered relative to it:

```yaml
international_equivalence:
  iso_27017:
    in_scope_clouds:
      - aws
      - gcp
      - azure
    iso_certification_body:
      name: REQUIRES-OPERATOR-INPUT
      accreditation_chain: REQUIRES-OPERATOR-INPUT
      address: REQUIRES-OPERATOR-INPUT
    overrides_file: iso-27017-csc-csp-overrides.yaml
    rollup_required: true                # emit cross-cloud rollup when len(in_scope_clouds) > 1
```

#### 4.3.1 `iso-27017-csc-csp-overrides.yaml` (operator-supplied)

```yaml
schema_version: '1.0.0'
overrides:
  - override_id: ISO27017-CSP-001
    cld_or_augmented_control_id: CLD.9.5.1
    cloud_provider: aws
    scope_predicate:
      asset_filter: "data_classes ⊇ ['public-marketing']"
      tenant_id: null                    # null = applies to all tenants
    disposition_override: conformant-via-compensating-control
    rationale: |
      AWS shared VPC across tenants is acceptable for public-marketing
      data only; tenant_isolation is enforced at the application
      layer per ISMS risk-treatment plan RTP-2026-014.
    risk_register_ref: RTP-2026-014
    operator_officer_attestation:
      name: REQUIRES-OPERATOR-INPUT
      title: REQUIRES-OPERATOR-INPUT
      attestation_date: REQUIRES-OPERATOR-INPUT
    effective_from: 2026-06-01
    effective_until: 2027-06-01
```

#### 4.3.2 `org-profile.yaml` (relevant fields read by Z.Z3)

```yaml
csp_name: REQUIRES-OPERATOR-INPUT
csp_legal_entity: REQUIRES-OPERATOR-INPUT
csp_uei: REQUIRES-OPERATOR-INPUT
service_models_offered:
  - IaaS
  - PaaS
deployment_models_offered:
  - Public
in_scope_clouds:
  - aws
  - gcp
  - azure
gdpr_in_scope: true
```

### 4.4 Inventory + coverage facts (from `core/inventory.ts`)

Z.Z3 reads the existing inventory model for already-collected asset
facts; the relevant fields per asset are:

```typescript
interface InventoryAsset {
  asset_id: string;
  asset_type: string;
  cloud_provider: 'aws' | 'gcp' | 'azure';
  region: string;
  data_classes: string[];               // includes "CJI", "PHI", "PII", "PUBLIC-MARKETING" etc.
  tenant_isolation: 'dedicated' | 'shared-with-encryption' | 'shared-without-encryption' | 'unknown';
  virtual_network_id?: string;
  admin_account_id?: string;
  hypervisor_type?: string;
  encryption_at_rest?: 'AES-256-GCM' | 'AES-256-CBC' | 'CMK-customer-managed' | 'CMK-cloud-managed' | 'none';
  monitoring_target?: string;
  diagram_label?: string;
  collected_at: string;
}
```

Missing fields trigger Z.Z3's `REQUIRES-OPERATOR-INPUT` diagnostic per
asset; the per-control disposition degrades per §11.

### 4.5 Risk register (from LOOP-B.B1)

Z.Z3 reads the risk register only when an override cites a risk ID.
Schema (per LOOP-B.B1):

```typescript
interface RiskRegisterRow {
  risk_id: string;                      // "RTP-2026-014"
  risk_title: string;
  likelihood: 'low' | 'moderate' | 'high';
  impact: 'low' | 'moderate' | 'high';
  treatment_decision: 'mitigate' | 'transfer' | 'accept' | 'avoid';
  acceptance_owner?: string;
  acceptance_date?: string;
  acceptance_expiration?: string;
  related_controls: string[];           // ISO + NIST control IDs
}
```

---

## 5. Outputs

### 5.1 Canonical JSON evidence envelope (one per cloud provider per run)

Path: `out/iso-27017-coverage-<provider>-<run_id>.json` (one per
provider per evaluation run).

```jsonc
{
  "$schema": "https://cloud-evidence.example/schemas/iso-27017-coverage-v1.json",
  "schema_version": "1.0.0",
  "evaluation_id": "iso-27017-eval-2026-06-08-aws-001",
  "evaluated_at": "2026-06-08T14:33:00Z",
  "evaluation_run_id": "run-20260608-1430Z",
  "csp_name": "<from org-profile.yaml>",
  "cloud_provider": "aws",
  "iso_27017_catalog_snapshot_ref": {
    "path": "data/iso-27017-controls.json",
    "sha256": "<sha256>",
    "snapshot_id": "iso-27017-2015-20260608T120000Z",
    "snapshot_date": "2026-06-08",
    "derivation_source": "implementer-reconciliation-to-27002:2022"
  },
  "iso_27001_catalog_snapshot_ref": {
    "path": "data/iso-27001-2022-annex-a.json",
    "sha256": "<sha256>",
    "snapshot_id": "iso-27001-2022-20260607T120000Z"
  },
  "service_models_in_scope": ["IaaS", "PaaS"],
  "deployment_models_in_scope": ["Public"],
  "cld_controls": [
    {
      "cld_id": "CLD.6.3.1",
      "short_name": "Shared roles and responsibilities within a cloud computing environment",
      "csp_or_csc_or_shared": "shared",
      "disposition": "conformant",
      "disposition_rationale": "AWS Organizations with SCP segregating CSP-side and CSC-side accounts; documented shared-responsibility matrix at <url>; admin role enumeration shows 100% of CSP-admin roles assumed only by CSP-side principals.",
      "csp_obligations_met": ["O-6.3.1-CSP-1", "O-6.3.1-CSP-2", "O-6.3.1-CSP-3"],
      "csc_obligations_documented": ["O-6.3.1-CSC-1", "O-6.3.1-CSC-2"],
      "evidence_calls": [
        {
          "sdk_call": "AWS Organizations:ListAccounts",
          "called_at": "2026-06-08T14:33:01Z",
          "result_hash_sha256": "<sha256>"
        },
        {
          "sdk_call": "AWS IAM:GetAccountAuthorizationDetails",
          "called_at": "2026-06-08T14:33:05Z",
          "result_hash_sha256": "<sha256>"
        }
      ],
      "inventory_asset_refs": ["aws:org:o-abc123", "aws:account:111122223333"],
      "nist_800_53_r5_mapping": [
        { "control_id": "PL-8", "relationship": "superset" },
        { "control_id": "SA-9", "relationship": "superset" },
        { "control_id": "PS-7", "relationship": "superset" }
      ],
      "eucs_article_51_mapping": ["c", "e", "f"],
      "ccm_v4_mapping": ["GRC-04", "STA-03"],
      "iso_27018_overlap": [],
      "compensating_control_override": null
    }
    // ... CLD.8.1.5, CLD.9.5.1, CLD.9.5.2, CLD.12.1.5, CLD.12.4.5, CLD.13.1.4
  ],
  "augmented_27002_controls": [
    {
      "iso_27002_control_id": "A.5.23",
      "iso_27002_short_name": "Information security for use of cloud services",
      "augmentation_type": "csp-csc-split",
      "disposition": "conformant",
      "csp_obligations_met": ["..."],
      "csc_obligations_documented": ["..."],
      "evidence_calls": ["..."],
      "inventory_asset_refs": ["..."]
    }
    // ... ~36 more
  ],
  "rollup_summary": {
    "cld_total": 7,
    "cld_conformant": 6,
    "cld_conformant_with_caveat": 1,
    "cld_non_conformant": 0,
    "cld_not_applicable": 0,
    "cld_conformant_via_compensating_control": 0,
    "augmented_total": 37,
    "augmented_conformant": 35,
    "augmented_conformant_with_caveat": 2,
    "augmented_non_conformant": 0,
    "augmented_not_applicable": 0
  },
  "requires_operator_input": [
    {
      "field": "iso_certification_body.name",
      "consumer_artifact": "Stage 1 documentation cover sheet",
      "operator_input_pathway": "config.yaml::international_equivalence.iso_27017.iso_certification_body.name"
    }
  ],
  "provenance": {
    "emitter": "iso-27017-mapper",
    "emitter_version": "<from package.json>",
    "emitted_at": "2026-06-08T14:33:00Z",
    "source_calls": [
      { "kind": "iso-27017-catalog", "path": "data/iso-27017-controls.json", "sha256": "<sha256>" },
      { "kind": "iso-27001-catalog", "path": "data/iso-27001-2022-annex-a.json", "sha256": "<sha256>" },
      { "kind": "config-yaml", "path": "cloud-evidence/config.yaml", "sha256": "<sha256>" },
      { "kind": "org-profile-yaml", "path": "cloud-evidence/org-profile.yaml", "sha256": "<sha256>" },
      { "kind": "iso-27017-overrides-yaml", "path": "iso-27017-csc-csp-overrides.yaml", "sha256": "<sha256>" },
      { "kind": "inventory", "path": "out/inventory.json", "sha256": "<sha256>" }
    ]
  },
  "signature": {
    "alg": "ed25519",
    "key_id": "<KMS resource id>",
    "sig": "<base64>"
  },
  "rfc3161_timestamp": {
    "tsa_url": "<TSA url>",
    "token": "<base64>",
    "received_at": "2026-06-08T14:33:10Z"
  }
}
```

### 5.2 Cross-cloud rollup envelope (one per evaluation run when len(in_scope_clouds) > 1)

Path: `out/iso-27017-coverage-rollup-<run_id>.json`. Schema mirrors
5.1 but with `cloud_provider: 'rollup'` and per-control rollup
dispositions computed by taking the worst-case across the per-cloud
envelopes (e.g. if AWS is conformant but Azure is non-conformant for
CLD.9.5.1, the rollup is non-conformant for CLD.9.5.1). The rollup
envelope's `cloud_provider_envelopes[]` field lists the per-cloud
envelope paths + sha256s so Z.Z2 SoA can traverse to the per-cloud
detail.

### 5.3 Per-cloud OOXML `.docx` supplement

Path: `out/iso-27017-supplement-<provider>-<run_id>.docx` (one per
provider per evaluation run).

Layout (5-to-15 pages):

- **Cover page.** "ISO/IEC 27017:2015 Cloud Overlay Supplement —
  <CSP Name> — <Cloud Provider> — <Evaluation Date>". CSP name +
  UEI + ISO certification body. Service models in scope; deployment
  models in scope.
- **Catalog snapshot reference.** Z.Z3-owned catalog snapshot ID +
  Z.Z1 27001 catalog snapshot ID + derivation source note.
- **Per-CLD-control section** (7 sections, one per CLD.* control):
  - Control ID + short name
  - csp/csc/shared discriminator
  - Disposition + rationale (1-3 paragraphs)
  - Shared-responsibility split table (CSP obligations vs CSC
    obligations) — paraphrased per LOOP-Z authoring guidance
  - Evidence calls table (SDK call + called_at + result sha256)
  - NIST 800-53 Rev 5 mapping table
  - Compensating-control override (when present)
- **Per-augmented-27002-control section** (37 sections, condensed):
  - Control ID + short name + augmentation type
  - Disposition + 1-paragraph rationale
  - CSP / CSC obligations split (table)
  - Evidence reference (link to envelope JSON)
- **Rollup summary section.** Tables matching the JSON envelope's
  `rollup_summary` block.
- **REQUIRES-OPERATOR-INPUT section.** One row per outstanding
  operator-input field.
- **Signature placeholder.** Operator-officer attestation block;
  signature line; date.

The renderer is `core/iso-27017-supplement-docx.ts` and reuses the
OOXML helpers from `core/oscal-ssp-docx.ts`.

### 5.4 Tracker DB rows

Schema (migration `0048_iso_27017_coverage.sql`):

```sql
CREATE TABLE iso_27017_coverage (
  id                          UUID PRIMARY KEY,
  run_id                      TEXT NOT NULL,
  evaluation_id               TEXT NOT NULL UNIQUE,
  csp_name                    TEXT NOT NULL,
  cloud_provider              TEXT NOT NULL,             -- aws|gcp|azure|rollup
  catalog_snapshot_id         TEXT NOT NULL,
  iso_27001_snapshot_id       TEXT NOT NULL,
  evaluated_at                TIMESTAMPTZ NOT NULL,
  service_models              TEXT[] NOT NULL,
  deployment_models           TEXT[] NOT NULL,
  rollup_cld_conformant       INTEGER NOT NULL DEFAULT 0,
  rollup_cld_caveat           INTEGER NOT NULL DEFAULT 0,
  rollup_cld_nonconformant    INTEGER NOT NULL DEFAULT 0,
  rollup_cld_not_applicable   INTEGER NOT NULL DEFAULT 0,
  rollup_cld_via_compensating INTEGER NOT NULL DEFAULT 0,
  rollup_aug_conformant       INTEGER NOT NULL DEFAULT 0,
  rollup_aug_caveat           INTEGER NOT NULL DEFAULT 0,
  rollup_aug_nonconformant    INTEGER NOT NULL DEFAULT 0,
  rollup_aug_not_applicable   INTEGER NOT NULL DEFAULT 0,
  envelope_json_path          TEXT NOT NULL,
  envelope_docx_path          TEXT,                       -- null for rollup
  signing_key_id              TEXT NOT NULL,
  signing_key_version         TEXT NOT NULL,
  encrypted_at_rest           BOOLEAN NOT NULL DEFAULT TRUE,
  created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_iso_27017_coverage_idempotency
  ON iso_27017_coverage(run_id, cloud_provider);

CREATE TABLE iso_27017_cld_decisions (
  id                          UUID PRIMARY KEY,
  coverage_id                 UUID NOT NULL REFERENCES iso_27017_coverage(id) ON DELETE CASCADE,
  control_id                  TEXT NOT NULL,              -- "CLD.6.3.1" or "A.5.23"
  control_kind                TEXT NOT NULL,              -- 'cld' | 'augmented'
  disposition                 TEXT NOT NULL,              -- conformant|conformant-with-caveat|non-conformant|not-applicable|conformant-via-compensating-control
  disposition_rationale       TEXT NOT NULL,
  compensating_control_id     TEXT,
  compensating_control_cso    TEXT,
  poam_item_uuid              TEXT,                       -- back-ref to POA&M when disposition is non-conformant
  created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_iso_27017_cld_decisions_coverage ON iso_27017_cld_decisions(coverage_id);
CREATE INDEX idx_iso_27017_cld_decisions_control ON iso_27017_cld_decisions(control_id);
```

### 5.5 Submission-bundle entries

Z.Z3 registers three new WELL_KNOWN roles in `core/submission-bundle.ts`:

```typescript
{ role: 'iso-27017-coverage-json',
  filename: 'iso-27017-coverage-{provider}-{run_id}.json',
  description: 'ISO/IEC 27017:2015 per-cloud control coverage envelope (Z.Z3)' },
{ role: 'iso-27017-supplement-docx',
  filename: 'iso-27017-supplement-{provider}-{run_id}.docx',
  description: 'OOXML supplement enumerating CLD.* controls + augmented 27002 controls per cloud (Z.Z3)' },
{ role: 'iso-27017-coverage-rollup-json',
  filename: 'iso-27017-coverage-rollup-{run_id}.json',
  description: 'Cross-cloud rollup ISO 27017 coverage envelope (Z.Z3; emitted when len(in_scope_clouds) > 1)' },
```

### 5.6 POA&M item linkage

For every CLD.* or augmented control with `disposition: non-conformant`
that is NOT covered by an operator-documented compensating-control
override, Z.Z3 emits a POA&M item via the existing
`core/oscal-poam.ts::emitPoamItem(...)` API using the finding template
`ISO-27017-CONTROL-GAP`. The POA&M item includes:

- The control ID (CLD.* or 27002 augmented)
- The verbatim short name + the implementer-paraphrased
  shared-responsibility note
- The affected cloud provider + affected inventory asset IDs
- The recommended remediation (per control; pulled from the catalog)
- A composite risk score from `core/risk-score.ts` (LOOP-B.B1)

The POA&M item UUID is back-referenced into the
`iso_27017_cld_decisions.poam_item_uuid` column for traceability.

---

## 6. Algorithm / Steps

### Phase A — Bootstrap

1. **Parse CLI flag** `--iso-z-z3` (or env `CLOUD_EVIDENCE_Z_Z3`).
   Also accept the LOOP-Z gate `--international-equivalence` as
   sufficient. If neither set, the Z.Z3 module is a no-op for the
   orchestrator run.

2. **Load operator configuration.** Read
   `cloud-evidence/config.yaml` → `international_equivalence.iso_27017.*`.
   Load `iso-27017-csc-csp-overrides.yaml` (if path configured).
   Load `org-profile.yaml`. Validate via Ajv. If any
   `REQUIRES-OPERATOR-INPUT` placeholder remains in fields Z.Z3
   strictly requires (the iso_certification_body block is needed
   only for the `.docx` cover page — placeholder OK with a flagged
   diagnostic; the in_scope_clouds list is strictly required), exit
   `2` with `ISO27017OperatorConfigMissingError`.

3. **Load Z.Z1 27001:2022 Annex A catalog snapshot.** Read
   `data/iso-27001-2022-annex-a.json`. Verify the Ed25519 signature.
   If verification fails, exit `2` with
   `CatalogSignatureInvalidError`.

4. **Load Z.Z3's own 27017 catalog snapshot.** Read
   `data/iso-27017-controls.json`. Verify the Ed25519 signature.
   Failure → exit `2`.

5. **Sign-test the corporate signing key.** Call
   `core/sign.ts::testSign(key_ref)` against the configured KMS
   resource to verify operator has signing rights at startup.
   Failure → exit `2`.

6. **Load already-collected inventory.** Read `out/inventory.json`.
   When the inventory's `collected_at` is older than 24h, warn the
   operator (do not exit — the operator may run Z.Z3 against a
   recent inventory snapshot as part of a documentation rehearsal).

### Phase B — Per-cloud collection

7. **For each cloud provider in `in_scope_clouds[]`**, invoke the
   provider-specific collector:
   - AWS: `providers/aws/iso-27017.ts::collectISO27017(cfg, inventory, catalog)`
   - GCP: `providers/gcp/iso-27017.ts::collectISO27017(cfg, inventory, catalog)`
   - Azure: `providers/azure/iso-27017.ts::collectISO27017(cfg, inventory, catalog)`

   Each collector:
   - For each CLD.* control: execute the catalog's
     `evidence_strategy[]` entries (the SDK calls) through the
     read-only Proxy + record each call's result_hash_sha256 in
     the envelope's `evidence_calls[]` array.
   - For each augmented 27002 control: same.
   - Compute the disposition deterministically per the §6.1
     decision tree.
   - Honour any matching operator override from
     `iso-27017-csc-csp-overrides.yaml`.

### Phase C — Disposition decision tree (per control)

```
function disposeControl(control, evidenceFacts, inventoryAssets, overrides): Disposition {
  // 1. Service-model gate
  if (!control.applicable_service_models.intersects(orgProfile.service_models_offered))
    return 'not-applicable';

  // 2. Deployment-model gate
  if (!control.applicable_deployment_models.intersects(orgProfile.deployment_models_offered))
    return 'not-applicable';

  // 3. Operator override check
  const matchingOverride = overrides.find(o =>
    o.cld_or_augmented_control_id === control.cld_id &&
    o.cloud_provider === cloudProvider &&
    matchesScopePredicate(o.scope_predicate, inventoryAssets) &&
    isCurrentlyEffective(o.effective_from, o.effective_until)
  );
  if (matchingOverride) {
    // Validate the override has all required fields
    if (!matchingOverride.operator_officer_attestation.name ||
        !matchingOverride.risk_register_ref) {
      throw new OverrideIncompleteError(matchingOverride.override_id);
    }
    return matchingOverride.disposition_override;
  }

  // 4. Apply expected_value_predicate per evidence strategy
  let allMet = true;
  let anyMissing = false;
  for (const strat of control.evidence_strategy) {
    if (strat.provider !== cloudProvider && strat.provider !== 'all') continue;
    const fact = evidenceFacts.find(f => f.sdk_call === strat.sdk_call);
    if (!fact) {
      anyMissing = true;
      continue;
    }
    if (!evaluatePredicate(strat.expected_value_predicate, fact)) {
      allMet = false;
    }
  }

  if (anyMissing) return 'conformant-with-caveat';   // missing evidence != fail; flag it
  if (allMet) return 'conformant';
  return 'non-conformant';
}
```

### Phase D — Envelope composition + signing

8. **Compose per-cloud envelope** per §5.1 shape.
9. **RFC 8785 canonicalize** the JSON via
   `core/canonicalize.ts::rfc8785(obj)` before signing.
10. **Sign envelope** via `core/sign.ts::signEnvelope(env, key_ref)`
    (Ed25519 detached signature; key_id pinned).
11. **Attach RFC 3161 timestamp token** via
    `core/timestamp.ts::attachToken(env, tsa_url)`.
12. **Write envelope** to
    `out/iso-27017-coverage-<provider>-<run_id>.json`.
13. **Render `.docx` supplement** via
    `core/iso-27017-supplement-docx.ts::render(env)`.
14. **Verify SHA-256 round trip** on the `.docx` write (OOXML
    serialization stability check — open the just-written file,
    re-read, recompute hash, confirm match).
15. **Write `.docx`** to
    `out/iso-27017-supplement-<provider>-<run_id>.docx`.

### Phase E — Rollup (when len(in_scope_clouds) > 1)

16. **Compose rollup envelope** per §5.2 shape — for each control,
    take the worst-case disposition across per-cloud envelopes
    (`non-conformant` > `conformant-with-caveat` >
    `conformant-via-compensating-control` > `conformant` >
    `not-applicable`).
17. **Sign + timestamp rollup envelope** as in Phase D.
18. **Write rollup envelope** to
    `out/iso-27017-coverage-rollup-<run_id>.json`.

### Phase F — Tracker DB + downstream

19. **Persist** `iso_27017_coverage` row per envelope (per cloud +
    rollup). Persist `iso_27017_cld_decisions` rows per control.
20. **Emit POA&M items** per non-conformant decision without a
    matching override via `core/oscal-poam.ts::emitPoamItem(...)`
    using the `ISO-27017-CONTROL-GAP` template.
21. **Register submission-bundle entries** via
    `core/submission-bundle.ts::register(...)`.
22. **Notify operator** via `core/notify.ts` (Slack channel
    `#iso-equivalence`) — one summary message per run listing the
    per-cloud rollup counts + links to the tracker UI rows.

### Phase G — Coverage propagation

23. **Update `inventory-coverage.json`** via
    `core/inventory-coverage.ts::record(...)` — increment the
    `iso_27017_per_cloud` coverage section counters so the
    cross-loop coverage report shows the per-cloud control-coverage
    rate.

---

## 7. Files to create / modify

Absolute paths under `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/`.

### 7.1 Create

| Path | Purpose |
|---|---|
| `core/iso-27017-mapper.ts` | Cross-cloud orchestrator: loads catalogs, dispatches to per-cloud collectors, composes envelopes, signs + writes, emits POA&M items, persists tracker rows. |
| `core/iso-27017-supplement-docx.ts` | OOXML renderer for the per-cloud + rollup `.docx` supplement; reuses `core/oscal-ssp-docx.ts` helpers. |
| `providers/aws/iso-27017.ts` | AWS-side collector executing the catalog's `evidence_strategy` SDK calls + computing per-control dispositions. |
| `providers/gcp/iso-27017.ts` | GCP-side collector. |
| `providers/azure/iso-27017.ts` | Azure-side collector. |
| `data/iso-27017-controls.json` | Z.Z3-owned signed catalog snapshot — 7 CLD.* controls + ~37 augmented 27002 controls + shared-responsibility split + NIST + EUCS + CCM cross-walks. |
| `scripts/extract-iso-27017.mjs` | Catalog-extraction tool — implementer runs to re-emit `data/iso-27017-controls.json` when 27017 reissues (currently future-dated). |
| `test/iso-27017-mapper.test.ts` | Unit + integration tests for `core/iso-27017-mapper.ts` (catalog load, signature verify, per-control disposition logic, envelope composition, rollup logic, override handling, POA&M emission). |
| `test/iso-27017-aws.test.ts` | Provider-specific tests for AWS collector (SDK call wiring through AWS mock client; predicate evaluation; inventory join). |
| `test/iso-27017-gcp.test.ts` | Provider-specific tests for GCP collector. |
| `test/iso-27017-azure.test.ts` | Provider-specific tests for Azure collector. |
| `test/iso-27017-docx.test.ts` | OOXML round-trip test for the `.docx` supplement renderer. |
| `tests/fixtures/iso-27017-overrides.yaml` | Operator-override fixture used by test suite. |
| `tracker/migrations/0048_iso_27017_coverage.sql` | DB migration for the two new tracker tables. |
| `tracker/server/iso-27017-routes.ts` | Tracker UI API surface for the per-cloud + rollup coverage dashboard. |
| `tracker/web/src/pages/iso-27017/PerCloud.tsx` | Tracker UI page rendering per-cloud 27017 coverage. |
| `tracker/web/src/pages/iso-27017/Rollup.tsx` | Tracker UI page rendering cross-cloud rollup. |

### 7.2 Modify

| Path | Modification |
|---|---|
| `core/submission-bundle.ts` | Add three new WELL_KNOWN role entries (per §5.5). |
| `core/orchestrator.ts` | Wire `--iso-z-z3` flag dispatch to `core/iso-27017-mapper.ts::run(...)`. |
| `core/notify.ts` | Add `#iso-equivalence` Slack channel template for the per-run summary message. |
| `cloud-evidence/config.yaml` (example template) | Add `international_equivalence.iso_27017.*` block (operator copies + fills). |
| `cloud-evidence/org-profile.yaml` (example template) | Confirm `service_models_offered` + `deployment_models_offered` + `in_scope_clouds` fields are documented. |
| `docs/loops/LOOP-Z-SPEC.md` | Update §11 Status table when Z.Z3 ships (commit hash, status -> done). |
| `docs/STATUS.md` | Mark Z.Z3 row done with commit hash + completion date. |
| `CHANGELOG.md` | Add `Unreleased` entry per CLAUDE.md procedure. |

---

## 8. Test specifications

Minimum 18 tests per the Z.Z3 task brief; the surface below lists 22.

| id | scenario | fixture | expected | acceptance |
|----|----------|---------|----------|------------|
| T01 | Load + signature-verify the 27017 catalog snapshot | `tests/fixtures/iso-27017-controls.signed.json` | catalog parsed; signature valid; cld_count == 7 | catalog loads + control count matches |
| T02 | Load + signature-verify the 27001:2022 Annex A catalog snapshot (Z.Z1 output) | `tests/fixtures/iso-27001-2022-annex-a.signed.json` | catalog parsed; signature valid; control_count == 93 | catalog loads |
| T03 | Tampered 27017 catalog (1-byte mutation after signing) → SignatureInvalidError | `tests/fixtures/iso-27017-controls.tampered.json` | throws `CatalogSignatureInvalidError`; process exit 2 | no envelope written |
| T04 | AWS collector: CLD.6.3.1 disposition `conformant` when SCP segregates CSP-side accounts + IAM admin roles assumed only by CSP principals | AWS mock fixture: Organizations:ListAccounts + IAM:GetAccountAuthorizationDetails | disposition == 'conformant'; evidence_calls len == 2 | envelope produced with all required fields |
| T05 | AWS collector: CLD.9.5.1 disposition `non-conformant` when shared VPC across tenants without per-tenant KMS | AWS mock fixture: EC2:DescribeVpcs + KMS:ListKeys | disposition == 'non-conformant'; POA&M item emitted | POA&M back-ref present in envelope |
| T06 | GCP collector: CLD.9.5.2 disposition `conformant-with-caveat` when Compute instances exist but Security Command Center findings list is empty (caveat: SCC may not be enabled) | GCP mock fixture | disposition == 'conformant-with-caveat'; caveat noted | rationale text includes caveat |
| T07 | Azure collector: CLD.12.4.5 disposition `conformant` when Activity Log diagnostic settings export to Log Analytics + Defender for Cloud secure score > 80% | Azure mock fixture | disposition == 'conformant' | rollup_summary increments correctly |
| T08 | Operator override (`iso-27017-csc-csp-overrides.yaml`) with valid risk_register_ref + officer attestation → `conformant-via-compensating-control` | override fixture | disposition == 'conformant-via-compensating-control'; envelope's compensating_control_override block populated | override fields propagated |
| T09 | Operator override with missing officer attestation → OverrideIncompleteError | override fixture (broken) | throws OverrideIncompleteError | process exit 2; no envelope |
| T10 | Service-model gate: CSP offers only SaaS → CLD.9.5.2 (VM hardening) disposition `not-applicable` | org-profile fixture: service_models = ['SaaS'] | disposition == 'not-applicable'; rationale notes service-model gate | envelope produced |
| T11 | Deployment-model gate: CSP offers only Private → CLD.6.3.1 disposition assigns Private-specific rationale | org-profile fixture: deployment_models = ['Private'] | disposition computed against Private deployment | rationale matches |
| T12 | Missing inventory field (tenant_isolation) → REQUIRES-OPERATOR-INPUT diagnostic per asset | inventory fixture with null tenant_isolation | diagnostic emitted; disposition degrades to `conformant-with-caveat` | requires_operator_input[] populated |
| T13 | RFC 8785 canonicalization stable across runs | sample envelope dict | sha256(canonicalized) identical across reruns | hash matches |
| T14 | Ed25519 signature deterministic for fixed key + canonicalized payload | sample envelope + fixed key | signature bytes identical across reruns | signature matches |
| T15 | RFC 3161 timestamp token round-trip (DER-encoded; verified against TSA cert) | TSA fixture | token decoded; nonce + hash match | timestamp verified |
| T16 | OOXML round-trip integrity for `.docx` supplement: write → read → recompute hash | sample envelope | sha256(write) == sha256(read) | round-trip stable |
| T17 | Multi-cloud rollup composition: AWS conformant + GCP non-conformant for CLD.9.5.1 → rollup non-conformant | three per-cloud envelopes | rollup envelope's CLD.9.5.1 disposition == 'non-conformant' | worst-case logic correct |
| T18 | POA&M emission for each non-conformant decision NOT covered by an override | envelope with 3 non-conformant + 1 override | exactly 2 POA&M items emitted (override suppresses 1) | POA&M count matches |
| T19 | Tracker DB idempotency: re-running same evaluation_run_id + cloud_provider → upsert, not duplicate | DB fixture | unique index honoured; coverage_id stable | no duplicate row |
| T20 | Submission-bundle registration: per-cloud envelopes + supplement + rollup all surface in bundle catalogue | bundler fixture | bundle catalogue contains 3 roles × N clouds + 1 rollup | catalogue assertion passes |
| T21 | EUCS Substantial blocker: Z.Z5 packager refuses to build when a per-cloud Z.Z3 envelope is missing | Z.Z5 invocation with incomplete Z.Z3 set | Z.Z5 surfaces REQUIRES-OPERATOR-INPUT naming Z.Z3 | error references Z.Z3 |
| T22 | Catalog `derivation_source` field surfaces in `.docx` cover page when set to `implementer-reconciliation-to-27002:2022` | sample catalog | `.docx` cover page text includes the derivation note | docx text assertion |

---

## 9. Risks

Minimum 5 risks per the Z.Z3 task brief; the register below lists 7.
Additional cross-loop risks are tracked in
`docs/loops/LOOP-Z-RISKS.md`.

### R1 — ISO publishes 27017 reissue with renamed CLD.* controls

- **Likelihood**: low (no draft circulated as of access date) /
  **Impact**: high (catalog breakage; envelope schema drift)
- **Description**: ISO/IEC JTC 1/SC 27 has signalled a 27017 reissue
  is in development. A reissue may rename CLD.* controls, add new
  CLD.* controls, or reorganize the augmentation table.
- **Mitigation**: `data/iso-27017-controls.json` carries
  `iso_edition` + `snapshot_date`. Z.Z3 loader compares the catalog
  edition against the operator-declared in `config.yaml`; mismatch
  surfaces a `coverage:catalog-edition-mismatch` diagnostic. When
  reissue ships, implementer re-runs
  `scripts/extract-iso-27017.mjs` against the new edition and
  re-signs the catalog. Existing envelopes pinned to the prior
  edition remain valid for the certification cycle they were
  authored for.

### R2 — 27002:2022 reorganization vs 27017:2015 augmentation mapping ambiguity

- **Likelihood**: medium (the reconciliation is operator-judgement-
  driven) / **Impact**: medium (some augmented controls may map
  ambiguously)
- **Description**: 27017:2015 was authored against 27002:2013 (133
  controls). The 27002:2022 reorganization (93 controls + 4 themes)
  requires implementer reconciliation. Some 2013-keyed augmentations
  collapse cleanly to 2022 controls; others split across multiple
  2022 controls or are no longer applicable.
- **Mitigation**: `data/iso-27017-controls.json` carries
  `derivation_source` and `reconciliation_notes_path`. The
  reconciliation table is committed under
  `docs/sources/iso-27017-reconciliation-notes.md` documenting
  every mapping decision. When ISO publishes the 27017 reissue
  against 27002:2022, the reconciliation table is replaced by the
  direct extraction.

### R3 — Read-only Proxy SDK call ceiling (rate-limit / quota exhaustion)

- **Likelihood**: medium (large multi-account orgs may exceed
  default quotas) / **Impact**: medium (collection failures →
  conformant-with-caveat dispositions)
- **Description**: Z.Z3's per-cloud collectors execute dozens of
  SDK calls per CLD.* + augmented control. A large AWS Organization
  (hundreds of accounts) or a multi-region GCP project may hit
  service-quota ceilings during collection.
- **Mitigation**: Z.Z3 collectors honour the existing retry/backoff
  middleware (Phase A.3). Per-control collection is bounded by
  the existing parallel-collection limit (Phase A.4). When a quota
  exhaustion is detected, the collector surfaces a
  `coverage:quota-exhaustion` diagnostic; the affected control's
  disposition degrades to `conformant-with-caveat` with the quota
  exhaustion noted in the rationale. Operator may re-run the
  collector with a smaller cloud-provider subset.

### R4 — Operator override misuse (compensating-control overrides without legitimate basis)

- **Likelihood**: low (operator-policy concern) / **Impact**: high
  (audit finding; potential certification rescission)
- **Description**: An operator could populate
  `iso-27017-csc-csp-overrides.yaml` with overrides that mark
  non-conformant controls as `conformant-via-compensating-control`
  without a legitimate compensating-control basis. The CAB review
  would discover the misuse and could reject the certification.
- **Mitigation**: Z.Z3 enforces override completeness at load time:
  `operator_officer_attestation.{name,title,attestation_date}` +
  `risk_register_ref` + `rationale` + `effective_from` +
  `effective_until` are ALL required. Missing any field →
  `OverrideIncompleteError`. The override's risk_register_ref must
  resolve to an actual row in the LOOP-B risk register (Z.Z3 cross-
  checks; broken reference rejects the override). The override is
  surfaced verbatim in the `.docx` supplement so the CAB sees every
  override in plain text. Tracker UI surfaces a "compensating
  control" filter on the per-cloud dashboard so the compliance
  officer can review every override before sign-off.

### R5 — EUCS Final-adoption schema drift

- **Likelihood**: medium (EU Commission delegated act pending) /
  **Impact**: medium (Z.Z3 → Z.Z5 EUCS package consumption may need
  re-emission)
- **Description**: The ENISA EUCS Candidate Scheme is awaiting
  European Commission adoption as a delegated act. Adoption may
  refine the security-objective set or the assurance-level
  boundaries; Z.Z3's `eucs_article_51_mapping[]` field per control
  is pinned to the candidate scheme.
- **Mitigation**: `data/iso-27017-controls.json` carries
  `eucs_scheme_version` (initially "candidate-2024"). Z.Z5
  packager refuses to build an EUCS submission when the
  `eucs_scheme_version` is older than 180 days from the operator-
  declared target submission date. When EUCS final adoption ships,
  implementer re-runs `scripts/extract-enisa-eucs.mjs` and re-signs
  `data/iso-27017-controls.json` with the updated mapping.

### R6 — Inventory tag completeness (operator has not yet tagged tenant_isolation, hypervisor_type, etc.)

- **Likelihood**: high (operator tagging is usually incomplete on
  first run) / **Impact**: medium (many per-control dispositions
  degrade to conformant-with-caveat on first run)
- **Description**: Z.Z3's per-control disposition depends on
  inventory tags that the operator may not yet have applied
  (tenant_isolation, hypervisor_type, virtual_network_id,
  admin_account_id, monitoring_target). First-run evaluations
  against an untagged inventory degrade most CLD.* dispositions to
  `conformant-with-caveat`.
- **Mitigation**: Z.Z3 emits a per-asset
  `REQUIRES-OPERATOR-INPUT` diagnostic naming the missing tag +
  the inventory asset ID + the operator tagging pathway (cloud
  resource tag with the canonical key). The tracker UI's per-cloud
  dashboard surfaces a "tag coverage" widget showing the percentage
  of in-scope assets that carry each required tag. Operator
  populates tags iteratively; subsequent runs upgrade dispositions
  as tag coverage rises.

### R7 — Cross-cloud rollup worst-case logic surprises the operator

- **Likelihood**: medium (multi-cloud CSPs may not expect the
  worst-case rule) / **Impact**: low (cosmetic; operator can
  reconcile via per-cloud detail)
- **Description**: Z.Z3's rollup envelope takes the worst-case
  disposition across per-cloud envelopes per control. A
  multi-cloud CSP may have CLD.9.5.1 `conformant` on AWS + GCP but
  `non-conformant` on Azure → the rollup shows non-conformant.
  Operator may want to see the per-cloud breakdown and treat the
  rollup as advisory rather than the SoA-defining state.
- **Mitigation**: The rollup envelope's `cloud_provider_envelopes[]`
  field carries paths + sha256s for every per-cloud envelope so the
  CAB can traverse to per-cloud detail. The tracker UI rollup page
  surfaces a per-control matrix (rows: controls; cols: clouds) so
  the operator sees exactly which cloud caused the worst-case. The
  `.docx` supplement includes a per-cloud-vs-rollup comparison
  table on the rollup section so the operator can address per-cloud
  remediation without a surprise.

---

## 10. Open questions

The following questions are unresolved as of 2026-06-08 and should be
closed before or during Z.Z3 implementation:

| # | Question | Affects | Status |
|---|----------|---------|--------|
| OQ-Z3-01 | When ISO publishes the 27017 reissue against 27002:2022, will the CLD.* control IDs renumber (e.g. CLD.6.3.1 → CLD.5.X.X to align with the 27002:2022 theme structure)? | catalog migration | OPERATOR-RESEARCH; monitor ISO/IEC JTC 1/SC 27 published-roadmap pages |
| OQ-Z3-02 | Does the operator's CAB accept the implementer-reconciled 27017-vs-27002:2022 mapping or do they require the original 27017:2015 augmentation table (keyed to 27002:2013) as well? | Z.Z2 SoA + .docx supplement layout | OPERATOR-RESEARCH per CAB; tracker captures the answer per CAB engagement |
| OQ-Z3-03 | For pure SaaS CSPs, are CLD.9.5.1 + CLD.9.5.2 strictly `not-applicable` or are they `not-applicable-with-csc-flow-through` (the SaaS CSP must ensure its underlying IaaS/PaaS provider implements them)? | Z.Z3 service-model gate logic | DOCUMENTED — default is `not-applicable`; operator can override via `iso-27017-csc-csp-overrides.yaml` to switch to `not-applicable-with-csc-flow-through` |
| OQ-Z3-04 | Does the implementer-reconciliation table need a CAB-side sign-off before Z.Z3 production runs? | Z.Z3 catalog snapshot | OPERATOR-RESEARCH; some CABs require pre-audit reconciliation review |
| OQ-Z3-05 | What is the canonical evidence format for CLD.13.1.4 (virtual/physical network alignment) when the cloud provider does not expose physical-network detail to the customer? | Z.Z3 CLD.13.1.4 evidence strategy | DOCUMENTED — evidence-strategy carries `provider-physical-architecture-attestation` as a kind whose evidence is a provider-published attestation document; operator references the provider's SOC 2 / ISO 27001 cert |
| OQ-Z3-06 | Does Z.Z3 need to interlock with LOOP-R (PQC) for CLD.8.1.5 (cryptographic erasure pathway)? | Z.Z3 CLD.8.1.5 + LOOP-R | DOCUMENTED — Z.Z3 reads LOOP-R's PQC inventory + cites in CLD.8.1.5 rationale when PQC keys are in use; LOOP-R does not block Z.Z3 |
| OQ-Z3-07 | Does the EUCS Conformity Assessment Body accept Z.Z3's `.docx` supplement format or require a CAB-specific spreadsheet? | Z.Z5 EUCS submission | OPERATOR-RESEARCH per CAB; Z.Z3 emits both `.json` (canonical) and `.docx` (Annex SL-derived layout) for translation |
| OQ-Z3-08 | When the operator runs Z.Z3 with `in_scope_clouds: [aws]` but their inventory contains GCP + Azure assets, should Z.Z3 ignore the non-configured clouds or fail with a scope-mismatch error? | Z.Z3 scope handling | DOCUMENTED — Z.Z3 ignores non-configured clouds (the operator may intentionally exclude a cloud from the ISO scope); a `coverage:cloud-out-of-iso-scope` warning surfaces in the run log |

---

## 11. REQUIRES-OPERATOR-INPUT

Per CLAUDE.md Rule 4, every operator-supplied data point is itemised
below. Z.Z3 emits a diagnostic for each missing field and the
consumer artefact is named.

| Field | Where operator provides | Default | Consumer artefact | Diagnostic when missing |
|-------|-------------------------|---------|-------------------|-------------------------|
| `csp_name` | `org-profile.yaml::csp_name` | none | `.docx` cover page; envelope `csp_name` | hard-error exit 2 |
| `csp_legal_entity` | `org-profile.yaml::csp_legal_entity` | none | `.docx` cover page | warning (placeholder rendered) |
| `csp_uei` | `org-profile.yaml::csp_uei` | none | `.docx` cover page | warning |
| `service_models_offered` | `org-profile.yaml::service_models_offered` | none | service-model gate logic | hard-error exit 2 |
| `deployment_models_offered` | `org-profile.yaml::deployment_models_offered` | none | deployment-model gate logic | hard-error exit 2 |
| `in_scope_clouds` | `config.yaml::international_equivalence.iso_27017.in_scope_clouds` | none | per-cloud collector dispatch | hard-error exit 2 |
| `iso_certification_body.name` | `config.yaml::international_equivalence.iso_27017.iso_certification_body.name` | none | `.docx` cover page | warning |
| `iso_certification_body.accreditation_chain` | same path | none | `.docx` cover page | warning |
| Inventory `tenant_isolation` per asset | resource tag `fedramp_tenant_isolation` (or `org-profile.yaml` overlay) | none | CLD.9.5.1 + CLD.13.1.4 disposition | per-asset diagnostic; disposition → conformant-with-caveat |
| Inventory `virtual_network_id` per asset | resource tag or `core/inventory.ts` derivation | none | CLD.13.1.4 disposition | per-asset diagnostic |
| Inventory `admin_account_id` per asset | resource tag or `core/inventory.ts` derivation | none | CLD.12.1.5 disposition | per-asset diagnostic |
| Inventory `hypervisor_type` per asset | resource tag (`fedramp_hypervisor`) | none | CLD.9.5.2 disposition | per-asset diagnostic |
| Inventory `monitoring_target` per asset | resource tag (`fedramp_monitoring_target`) | none | CLD.12.4.5 disposition | per-asset diagnostic |
| Override `operator_officer_attestation.{name,title,attestation_date}` | `iso-27017-csc-csp-overrides.yaml` per override | none | envelope override block + `.docx` | OverrideIncompleteError → exit 2 |
| Override `risk_register_ref` | same | none | envelope override block | OverrideIncompleteError (and risk ID must resolve in LOOP-B register) |
| Override `effective_from` + `effective_until` | same | none | override applicability gate | OverrideIncompleteError |

---

## 12. Implementation log

Per `docs/IMPLEMENTATION-LOG-TEMPLATE.md`, every meaningful milestone
during Z.Z3 implementation is appended below.

| date | actor | event | commit | outcome |
|------|-------|-------|--------|---------|
| 2026-06-08 | spec proposed | wf-uvxyz-gapfill | Specification authored via gap-fill workflow | TBD | — |

---

## 13. Completion checklist

Per `docs/SLICE-COMPLETION-PROCEDURE.md` (7-step procedure) +
CLAUDE.md slice-completion directive (step 8 — update STATUS +
loop SPEC row + CHANGELOG + push + verify). The procedure below
is quoted verbatim from `docs/SLICE-COMPLETION-PROCEDURE.md` for
in-band reference; the canonical source remains the procedure doc.

### Quoted from docs/SLICE-COMPLETION-PROCEDURE.md

> ## The 7-step procedure
>
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
>
> ## Failure handling
>
> If ANY step fails:
> - Step 1 (REO guardrails red): fix the issue. DO NOT proceed. DO NOT mark the slice done.
> - Step 5 (signing/commit hook failure): unlock 1Password and retry signing. Do not use --no-gpg-sign without explicit user approval.
> - Step 7 (push rejected): fetch + rebase, then re-push. NEVER force-push to main.

### Step 8 (CLAUDE.md slice-completion directive — additional steps)

Per CLAUDE.md's "Slice-completion directive (apply to EVERY loop /
slice / section completion)" block and the "Strong directive
(REO-enforced)" block, the following additional steps are required:

1. Update STATUS.md status row for Z.Z3 (commit hash, status -> 'done', last_updated). [Step 2 above already covers this; Z.Z3-specific: this is the third row in the LOOP-Z table.]
2. Update the LOOP-Z-SPEC.md status table for Z.Z3 (commit hash, status -> 'done'). [Step 3 above already covers this.]
3. Append a CHANGELOG.md entry naming Z.Z3 (date, slice ID, summary, commit). [Step 4 above already covers this.]
4. **Update Z.Z3.md frontmatter** (THIS file): `status: done`, `commit: <hash>`, `completed_date: <ISO>`, `last_updated: <ISO>`.
5. **Append the final Implementation log entry** to §12 above (per `docs/IMPLEMENTATION-LOG-TEMPLATE.md` — date, outcome, commit reference).
6. **Add any newly-discovered risks to `docs/loops/LOOP-Z-RISKS.md`** in the same commit (if surfaced during implementation).
7. Commit with `LOOP-Z.Z3` in the subject line + Co-Authored-By trailer.
8. Push to origin/main.
9. If a new permanent reference document was created (e.g. `docs/sources/iso-27017-reconciliation-notes.md`), add it to the CLAUDE.md reading list.
10. Verify with `git log --oneline -3` that the commit landed before declaring the slice closed.

**Failure to follow this procedure means the slice is NOT closed.**
The CI guardrails (REO-0) will reject any slice that has stub /
placeholder / TODO / FIXME markers in production paths
(lint:no-stubs), drops inventory-coverage.json fill rates
(check:coverage-regression), or emits artefacts without provenance
(check:provenance). If CI fails on any of these, the slice is NOT
done — fix and re-run from step 1.

---

## End of Z.Z3 specification.
