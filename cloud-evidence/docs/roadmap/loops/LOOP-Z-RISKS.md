# LOOP-Z — Risks Register

> Live document. Implementing sessions add entries during work; resolved
> risks stay in the file with `status=resolved` + resolution note.
> Severity: high = ship-blocking; med = should fix in-loop; low = file
> as follow-up.

> Authoritative companion to `docs/loops/LOOP-Z-SPEC.md` and the
> per-slice docs at `docs/slices/Z/Z.Z[1-5].md`. Read those for context
> before acting on any risk here.

> **CONDITIONAL GATE**: LOOP-Z applies when the CSP (a) serves customers,
> partners, regulators, or supply-chain counterparties outside the United
> States, OR (b) seeks to satisfy a non-U.S. equivalence demand (EU CSR,
> UK G-Cloud, Japan ISMAP, Australia IRAP, GCC CAF, Singapore MTCS, India
> CERT-In) that recognises ISO/IEC 27001 + cloud / privacy add-ons, OR
> (c) responds to an enterprise procurement questionnaire that demands
> 27001:2022 certification, OR (d) is asked for a Statement of
> Applicability (SoA) as a contract artefact. When the operator-supplied
> `--international-equivalence` flag (or `CLOUD_EVIDENCE_INTERNATIONAL_EQUIVALENCE=1`
> env var) is unset, NONE of the LOOP-Z risks below activate. Every risk
> below carries an implicit "WHEN LOOP-Z IS ACTIVE" precondition.

> Last updated: 2026-06-07.

> Companion reading (cross-reference these registers when triaging a
> LOOP-Z risk that interacts with another loop):
> - `LOOP-T-RISKS.md` — SSDF Common Form attestation; A.8.25 evidence
>   cross-walk.
> - `LOOP-W-RISKS.md` — Prohibited-vendor screening; A.5.19 / A.5.20 /
>   A.5.23 evidence cross-walk.
> - `LOOP-R-RISKS.md` — Post-quantum cryptography migration; A.8.24
>   evidence cross-walk.
> - `LOOP-U-RISKS.md` — Privacy framework crosswalk (GDPR / CCPA);
>   Z.Z4 + Z.Z5 reciprocal mapping.
> - `LOOP-V-RISKS.md` — HIPAA + HITRUST; Z.Z4 PII processor overlap
>   with PHI processing.
> - `LOOP-INV-S-RISKS.md` — Inventory + coverage contract; Z.Z3 reads
>   inventory tags for per-cloud control coverage.
> - `LOOP-B-RISKS.md` — Risk register; Z.Z2 SoA emitter reads it for
>   clause 6.1.3(d) justifications.

---

## Table of Contents

- [Cross-cutting risks (apply to ALL slices in LOOP-Z)](#cross-cutting-risks-apply-to-all-slices-in-loop-z)
  - Standards-drift & transition risks (Z-X1..Z-X10)
  - Mapping & equivalence risks (Z-X11..Z-X18)
  - Audit body / conformity assessment risks (Z-X19..Z-X24)
  - Cross-loop interaction risks (Z-X25..Z-X32)
  - REO / provenance / submission-bundle risks (Z-X33..Z-X38)
- [Per-slice risks](#per-slice-risks)
  - Z.Z1 — ISO/IEC 27001:2022 Annex A crosswalk
  - Z.Z2 — ISO 27001 SoA emitter
  - Z.Z3 — ISO/IEC 27017 cloud-controls overlay
  - Z.Z4 — ISO/IEC 27018 PII processor controls
  - Z.Z5 — ISO/IEC 27701 PIMS + ENISA EUCS submission package
- [External dependencies that may change](#external-dependencies-that-may-change)
- [Resolved risks (historical)](#resolved-risks-historical)
- [Resume-from-fresh-session checklist](#resume-from-fresh-session-checklist)

---

## Cross-cutting risks (apply to ALL slices in LOOP-Z)

### Z-X1 — ISO/IEC 27001:2013 → 27001:2022 migration drift (transition expired 2025-10-31)

- **Description**: ISO/IEC 27001:2022 (published Oct 2022) restructured
  the Annex A control set from the legacy 114 controls (in 14 domains)
  to 93 controls organised into four themes — Organizational (37
  controls), People (8 controls), Physical (14 controls), and
  Technological (34 controls). IAF Resolution 2022-15 (issued by the
  International Accreditation Forum) set the transition deadline for
  existing 27001:2013 certificates at **2025-10-31**. After that date,
  IAF-accredited certification bodies cannot recognise a 27001:2013
  certificate as current; an operator who built LOOP-Z's catalog
  against the legacy 2013 numbering, or a 3PAO / certification-body
  reviewer who still references the 2013 numbering in informal
  comments, would inject silent drift. Concrete failure: the operator
  emits an SoA that lists `A.5.1.1` (legacy 2013 "Policies for
  information security" with TWO-level numbering) instead of the 2022
  canonical `A.5.1` (single-level "Policies for information security"),
  and the certification body rejects the SoA as non-conformant.
- **Category**: standards-drift.
- **Severity**: high. **Likelihood**: med (developers familiar with
  the legacy set may default to it). **Impact**: high (SoA rejection
  at audit).
- **Mitigation**: Z.Z1's `core/iso-27001-2022-catalog.ts` constant
  `ISO_27001_EDITION = '2022'` is the single source of truth. The
  legacy 2013 mapping is emitted as a strictly-informative
  `legacy_2013_control_id?: string` field per control row — used for
  cross-referencing the operator's prior-edition certificates ONLY,
  never for emitting an SoA. A CI guard `check:iso-edition` rejects
  any production code path that imports a `2013` numbering constant
  outside the legacy-mapping module. Z.Z2's renderer asserts
  `control_id` matches `/^A\.[5-8]\.\d{1,2}$/` (the 2022 pattern,
  single-level dotted) and rejects three-level legacy IDs with a typed
  `IsoEditionMismatchError`. CHANGELOG entry per catalog refresh
  cites the edition. Cross-references Z.Z1-1, Z.Z2-1.
- **Owner**: LOOP-Z primary; Z.Z1 implementer.
- **Status**: open.
- **References**: ISO/IEC 27001:2022 published Oct 2022; IAF
  Resolution 2022-15 (https://iaf.nu/iaf_system/uploads/documents/IAF_Resolutions_to_2022_15.pdf);
  ANAB transition guidance.

### Z-X2 — Annex A 4-theme reorganisation mismatch (Organizational / People / Physical / Technological)

- **Description**: The 2022 edition's 4-theme reorganisation
  (Organizational, People, Physical, Technological) replaces the
  legacy 14-domain structure (Information Security Policies, Org of
  Info Sec, HR Security, Asset Mgmt, Access Control, Cryptography,
  Physical & Env Security, Operations Security, Communications
  Security, System Acquisition, Supplier Relationships, Info Sec
  Incident Mgmt, BCM, Compliance). The reorganisation merges and
  splits controls non-injectively — e.g. the 2013 control
  `A.6.2.1` ("Mobile device policy") is partly subsumed by 2022
  `A.7.9` ("Security of assets off-premises") and partly by `A.8.1`
  ("User endpoint devices"). A naive 1:1 mapper that ASSUMES
  injective merge produces wrong evidence assignments — evidence
  collected against the 2013 control would be attached to only one
  of the two 2022 successors, leaving the other appearing
  un-evidenced.
- **Category**: standards-drift / mapping.
- **Severity**: high. **Likelihood**: med. **Impact**: high
  (control evidence-coverage holes at audit).
- **Mitigation**: Z.Z1's `data/iso-27001-2022-annex-a.json` carries
  an explicit `legacy_2013_mapping: { control_id: string, relationship: 'merged_from' | 'split_from' | 'identical' | 'new_in_2022' | 'removed_in_2022' }[]`
  array per 2022 control. The mapper resolves split/merge cases
  bidirectionally and surfaces multi-target relationships in the
  Z.Z2 SoA emitter's `legacy_evidence_assignment_review` flag. A
  per-pair regression test in `tests/core/iso-27001-mapping.test.ts`
  pins the 11 NEW controls in 2022 (e.g. A.5.7 Threat intelligence,
  A.5.23 Information security for use of cloud services, A.5.30
  ICT readiness for business continuity, A.7.4 Physical security
  monitoring, A.8.1 User endpoint devices, A.8.9 Configuration
  management, A.8.10 Information deletion, A.8.11 Data masking,
  A.8.12 Data leakage prevention, A.8.16 Monitoring activities,
  A.8.23 Web filtering, A.8.28 Secure coding) — each requires fresh
  evidence, not legacy carry-over. CHANGELOG entry per mapper update.
- **Owner**: Z.Z1 implementer.
- **Status**: open.
- **References**: ISO/IEC 27001:2022 Annex A; ISO/IEC 27002:2022
  (control reference + attribute table).

### Z-X3 — SoA control-applicability false-pass (operator marks 'not applicable' without proper clause-6.1.3(d) justification)

- **Description**: ISO/IEC 27001:2022 clause 6.1.3(d) REQUIRES the
  organisation to "produce a Statement of Applicability that contains
  the necessary controls (see 6.1.3 b) and c)) and justification for
  inclusions, whether they are implemented or not, and the
  justification for exclusions of controls from Annex A." An operator
  under time pressure may mark a control as "not applicable" with a
  trivial / boilerplate justification ("not applicable to our
  environment") that a certification-body auditor will reject as
  non-conformant. The Z.Z2 SoA emitter cannot detect substantive vs
  boilerplate text on its own, but it CAN refuse to emit when the
  justification field is empty / under a minimum length / matches a
  blocked-pattern list.
- **Category**: SoA correctness.
- **Severity**: high (audit non-conformance leads to certification
  delay or denial). **Likelihood**: high (operator pressure is real).
  **Impact**: high.
- **Mitigation**: Z.Z2's `core/iso-27001-soa-emitter.ts` enforces:
  (i) `justification` field MUST be present per control row, MUST be
  ≥ 80 characters, and MUST NOT match any of a blocked-pattern list
  (`/^not applicable$/i`, `/^n\/a$/i`, `/^tbd$/i`, `/^see policy$/i`,
  `/^see ssp$/i`, `/^covered elsewhere$/i`, `/^standard$/i`). (ii)
  When a control is `applicable: false`, the justification MUST cite
  at least one of: a risk-register row from LOOP-B.B1, an inventory
  fact from LOOP-INV-S, a regulatory carve-out from the operator's
  `iso-config.yaml exclusions[]` block, OR a contractual exclusion
  recorded against a customer engagement. (iii) When `applicable:
  true`, the justification MUST reference at least one evidence
  artefact (KSI ID from FRMR, 800-53 control implementation
  statement, SSP narrative section, or operator-supplied evidence
  bundle path). A typed `SoAJustificationInsufficientError(control_id, reason)`
  rejects the emit. CHANGELOG entry per SoA emit lists controls
  marked `not applicable` + the justification lengths. Cross-
  references Z.Z2-3.
- **Owner**: Z.Z2 implementer.
- **Status**: open.
- **References**: ISO/IEC 27001:2022 clause 6.1.3(d); ANAB SoA
  audit guidance.

### Z-X4 — ISO/IEC 27017:2015 cloud-control evidence gap (CSP cannot evidence shared / customer-side controls without CSC input)

- **Description**: ISO/IEC 27017:2015 lays out responsibilities
  split between Cloud Service Provider (CSP) and Cloud Service
  Customer (CSC) per control. Several 27017 controls — notably
  `CLD.6.3.1` ("Shared roles and responsibilities within a cloud
  computing environment"), `CLD.8.1.5` ("Removal of cloud service
  customer assets"), `CLD.12.1.5` ("Administrator's operational
  security"), `CLD.13.1.4` ("Alignment of security management for
  virtual and physical networks") — REQUIRE shared evidence from both
  CSP and CSC. The CSP-side LOOP-Z cannot evidence the CSC-side
  controls; reporting them as fully-evidenced is a false claim that
  a certification body will reject.
- **Category**: per-cloud overlay / CSP-CSC boundary.
- **Severity**: high. **Likelihood**: high. **Impact**: high
  (audit rejection).
- **Mitigation**: Z.Z3's `core/iso-27017-mapper.ts` carries a
  `responsibility_split: 'csp_only' | 'csc_only' | 'shared'` field
  per cloud control. `shared` and `csc_only` controls emit with
  `csp_evidence: <evidence_id>` AND `csc_evidence_required: true`;
  the SoA shows the CSC obligation as a Customer Responsibility
  Matrix (CRM) entry, cross-referencing LOOP-L (CRM + Inheritance).
  The Z.Z3 renderer refuses to mark a `shared` control as
  fully-satisfied unless the operator has uploaded the CSC's
  attestation (signed PDF or signed JSON envelope) via
  `data/iso-27017-csc-attestations/<customer_id>-<date>.json`.
  REQUIRES-OPERATOR-INPUT diagnostic
  `iso-27017-csc-attestation-missing-<control_id>-<customer_id>`
  emits when missing. Cross-references LOOP-L.L1 (CRM emitter)
  and LOOP-L.L2 (Inheritance ledger).
- **Owner**: Z.Z3 implementer.
- **Status**: open.
- **References**: ISO/IEC 27017:2015 §5.1.1 "Responsibilities for
  information security in cloud computing"; LOOP-L-SPEC.md.

### Z-X5 — ISO/IEC 27018:2019 PII processor scope ambiguity (sub-processor chain vs direct processor)

- **Description**: ISO/IEC 27018:2019 frames the protection of
  Personally Identifiable Information (PII) in the public cloud for
  a CSP acting as a **PII Processor**. The CSP's own customers may
  be PII Controllers OR PII Processors themselves; the CSP may
  in turn use sub-processors. The 27018 control set assumes
  unambiguous role assignment, but real-world processor chains can
  span 3-5 hops (Customer → SaaS application → IaaS platform →
  underlying hyperscaler → managed-service backend). A naive
  Z.Z4 emitter that lists "the CSP is the PII Processor" misses
  the sub-processor controls; a Z.Z4 emitter that lists every
  sub-processor in scope over-claims responsibilities the CSP does
  not actually hold.
- **Category**: PII / privacy scope.
- **Severity**: high (GDPR Article 28 conformance). **Likelihood**:
  med. **Impact**: high.
- **Mitigation**: Z.Z4's `core/iso-27018-mapper.ts` reads the
  `core/subprocessors-sheet.ts` registry (LOOP-W reuses the same
  source). Each PII-processing engagement is recorded with
  `csp_role: 'controller' | 'processor' | 'sub_processor'`,
  `data_subject_categories: string[]`, `pii_categories: string[]`,
  `processing_purpose: text`, and `chain_position: 1..N`. The 27018
  controls are emitted per (control, engagement) tuple so the audit
  trail per customer is explicit. The runbook documents the
  ROPA-style processor record (GDPR Article 30) the operator
  maintains; Z.Z4's emit cross-references LOOP-U.U1 (GDPR crosswalk)
  for Article 28 / 30 alignment. The renderer refuses to emit when
  any engagement row is missing `chain_position` or `csp_role`.
  Cross-references LOOP-W-X10 (subprocessor-sheet schema drift).
- **Owner**: Z.Z4 implementer.
- **Status**: open.
- **References**: ISO/IEC 27018:2019 §1 Scope; GDPR Article 28
  + Article 30; LOOP-U-SPEC.md.

### Z-X6 — ISO/IEC 27701:2019 PIMS extension misalignment with GDPR (PIMS clauses 7+8 vs GDPR Articles 28+32+33+34+35+44+46)

- **Description**: ISO/IEC 27701:2019 extends 27001 with PIMS-
  specific clauses 5-8 + Annex A (PII Controllers, 31 controls) +
  Annex B (PII Processors, 18 controls). The PIMS clauses MAP
  informatively to GDPR Articles, but the mapping is non-canonical
  — ISO/IEC publishes a "mapping table" in 27701 Annex D that
  ENISA, the EDPB, and several DPAs interpret differently. A naive
  Z.Z5 emitter that adopts the 27701 Annex D mapping as canonical
  for GDPR conformance risks emitting a PIMS claim that the
  operator's actual DPA-side regulator disagrees with. Concrete
  failure: 27701 §7.2.6 (Records related to processing PII) maps
  informatively to GDPR Article 30 (Records of processing
  activities); a French CNIL inspector who finds the Z.Z5 emit
  cites Article 30 ONLY may demand additional evidence for Article
  32 (Security of processing) that the operator did not anticipate.
- **Category**: PIMS / GDPR alignment.
- **Severity**: high (GDPR enforcement exposure). **Likelihood**:
  med. **Impact**: high.
- **Mitigation**: Z.Z5's `core/iso-27701-pims.ts` carries the
  27701 Annex D mapping as `informative_only: true` flags; the
  PIMS emit cross-references LOOP-U.U1's GDPR crosswalk for every
  Article that any PIMS clause touches, ensuring at least two
  independent mapping perspectives are surfaced. The operator
  runbook documents the EDPB / CNIL / BfDI / ICO interpretations
  the operator's DPA regulator has published; the operator
  selects via `iso-config.yaml dpa_regulator: 'CNIL' | 'BfDI' | 'ICO' | 'AEPD' | 'DPC' | ...`
  + `iso-config.yaml gdpr_mapping_overrides{}`. CHANGELOG entry
  per regulator-mapping update. The Z.Z5 emit's
  `gdpr_alignment_summary` section lists every PIMS clause + every
  GDPR Article it informatively maps to + a regulator-specific
  interpretation note where one exists. Cross-references LOOP-U.U1.
- **Owner**: Z.Z5 implementer.
- **Status**: open.
- **References**: ISO/IEC 27701:2019 Annex D; EDPB Guidelines
  3/2019 on processing of personal data through video devices
  (informative); CNIL guidance on Article 30 ROPA.

### Z-X7 — ENISA EUCS Candidate Scheme final-rule drift from current candidate (delegated act expected 2026-2027)

- **Description**: The EU Cybersecurity Act (Regulation 2019/881)
  established the EU Cybersecurity Certification Framework. ENISA
  published the EUCS Candidate Scheme in 2024 (the latest publicly-
  available draft is the "Cybersecurity Certification: EUCS - Cloud
  Services Scheme" v1.0.4 of March 2024); the European Commission
  is expected to adopt EUCS as a delegated act in 2026-2027.
  Between the candidate draft and the adopted delegated act, ENISA
  has signalled potential changes to: (a) the assurance-level
  control sets (Basic / Substantial / High may be re-tiered), (b)
  the conformity-assessment body (CAB) accreditation path, (c) the
  data-residency / sovereignty clauses (the "EU sovereignty cloud"
  clause that triggered France / Germany / Netherlands amendments
  in 2023-2024). A Z.Z5 emitter that hard-pins the 2024 candidate
  draft would emit a submission package the CAB rejects under the
  adopted delegated act.
- **Category**: EUCS standards-drift.
- **Severity**: high (procurement gating in EU public sector).
  **Likelihood**: high (delegated act not yet adopted). **Impact**:
  high.
- **Mitigation**: Z.Z5's `core/enisa-eucs-mapper.ts` carries
  `eucs_version = '2024-03-candidate'` + `eucs_status = 'candidate'`
  constants; the emit's submission-package manifest includes
  `eucs_version` so the CAB can immediately identify the version
  the operator built against. When the delegated act is adopted,
  bump the constant + add deltas to the mapper + regression-test
  the assurance-level tier table. Operator runbook references
  the ENISA Cybersecurity Certification homepage
  (https://www.enisa.europa.eu/topics/certification) for the
  publication watch; CHANGELOG entry per EUCS-mapper update.
  A `REQUIRES-OPERATOR-INPUT: confirm-eucs-version-against-delegated-act`
  diagnostic emits when `eucs_status === 'candidate'` AND the
  emit-date is more than 60 days after the date the EU Commission
  publishes the delegated act announcement. Cross-references
  Z.Z5-1.
- **Owner**: Z.Z5 implementer.
- **Status**: open.
- **References**: Regulation 2019/881 (EU Cybersecurity Act);
  ENISA EUCS Candidate Scheme v1.0.4 (March 2024); European
  Commission cyber-certification workplan.

### Z-X8 — Audit-body conformity-assessment ISO/IEC 17021-1 mismatch (certification body using wrong accreditation scope)

- **Description**: ISO/IEC 17021-1:2015 ("Conformity assessment —
  Requirements for bodies providing audit and certification of
  management systems — Part 1: Requirements") governs the
  accreditation of certification bodies. Each certification body
  is accredited by a national accreditation body (ANAB in the US,
  UKAS in the UK, DAkkS in Germany, COFRAC in France, JIPDEC in
  Japan) for specific management-system standards (`scope`). A
  certification body accredited for 27001:2022 may not be
  accredited for 27017:2015, 27018:2019, or 27701:2019; using a
  CB outside its accreditation scope produces a certificate the
  acquirer's regulator rejects.
- **Category**: audit body / accreditation.
- **Severity**: high (certificate invalidity). **Likelihood**: low
  (sophisticated operators check). **Impact**: high.
- **Mitigation**: Z.Z2's tracker UI carries a
  `certification_body_registry` table with `cb_name`,
  `accreditation_body`, `accreditation_scope` (e.g.
  `['27001:2022', '27017:2015', '27018:2019']`),
  `accreditation_certificate_url`, `accreditation_expires_at`.
  When the operator selects a CB for an audit engagement, the
  tracker asserts `audit_standard ∈ cb.accreditation_scope`;
  mismatch emits a tracker warning + REQUIRES-OPERATOR-INPUT
  diagnostic. The runbook documents how to verify a CB's
  accreditation status via the IAF CertSearch
  (https://www.iafcertsearch.org/) + national-AB registries
  (ANAB, UKAS, DAkkS, etc.). CHANGELOG entry per CB-registry
  update. Cross-references Z.Z2-9.
- **Owner**: Z.Z2 implementer; tracker UI team.
- **Status**: open.
- **References**: ISO/IEC 17021-1:2015; IAF MD 1:2018 (Mandatory
  Document for the Audit and Certification of a Management
  System Operated by a Multi-Site Organization); IAF CertSearch.

### Z-X9 — NIST OLIR mapping informativeness (OLIR is one-way + non-binding; operators may treat it as canonical)

- **Description**: The NIST Online Informative References (OLIR)
  program (https://csrc.nist.gov/projects/olir) publishes one-way
  informative crosswalks from ISO/IEC 27001 → NIST 800-53 and from
  ISO/IEC 27002 → NIST 800-53. The OLIR mapping is explicitly
  **informative**, **not normative**, and the OLIR documentation
  warns that "mappings should be evaluated and may need to be
  modified to fit your specific organizational needs". Operators
  unfamiliar with OLIR may treat the OLIR mapping as canonical,
  using OLIR rows to back SoA justifications without further
  evaluation. A 3PAO who cross-references the operator's SoA
  against OLIR and finds the operator simply copied OLIR rows
  without adjustment may flag the SoA as a compliance-theater
  artefact.
- **Category**: mapping / NIST OLIR.
- **Severity**: med (3PAO confidence). **Likelihood**: high
  (developer convenience). **Impact**: med.
- **Mitigation**: Z.Z1's `data/iso-27001-2022-annex-a.json`
  records the cross-walk with `mapping_source` (`nist-olir-1.0` /
  `operator-defined` / `cloud-evidence-canonical-mapping`),
  `mapping_confidence` (`high` / `medium` / `low`), `mapping_rationale`
  (text). OLIR-sourced rows are flagged `mapping_source: 'nist-olir-1.0'`
  + `mapping_confidence: 'medium'` by default; the operator is
  prompted in Z.Z2's SoA review UI to either confirm or override
  each OLIR-sourced mapping. CHANGELOG entry per OLIR refresh
  references the OLIR XML version pin. Cross-references Z.Z1-2.
- **Owner**: Z.Z1 implementer.
- **Status**: open.
- **References**: NIST OLIR program https://csrc.nist.gov/projects/olir;
  OLIR Schema v1.0; NIST SP 800-53 Rev 5.

### Z-X10 — ISMAP / IRAP / G-Cloud / MTCS / CERT-In scope-diff (each non-US scheme has its own customisation)

- **Description**: Japan ISMAP (Information system Security
  Management and Assessment Program), Australia IRAP (Information
  Security Registered Assessors Program), UK G-Cloud (Government
  Cloud Framework), Singapore MTCS (Multi-Tier Cloud Security),
  India CERT-In, and GCC CAF (Common Assurance Framework) each
  reference ISO/IEC 27001 + per-scheme overlays / customisations.
  ISMAP adds the "ISMAP Standard Statement" + the ISMAP-specific
  control set (similar to FedRAMP but Japan-government-tailored);
  IRAP adds the Australian ISM (Information Security Manual)
  controls layered on top of 27001; G-Cloud requires Cyber
  Essentials Plus + IL2/3 self-assessment. A LOOP-Z that emits
  only the ISO 27001 / 27017 / 27018 / 27701 / EUCS bundle
  without per-scheme deltas will fail acquirer requirements for
  any of these schemes.
- **Category**: international scheme scope.
- **Severity**: med (scope gap, not code-correctness).
  **Likelihood**: high. **Impact**: med.
- **Mitigation**: LOOP-Z's spec calls out ISMAP / IRAP / G-Cloud
  / MTCS / CERT-In / GCC CAF as out-of-scope for the initial
  Z.Z1..Z.Z5 slices; future loops LOOP-ISMAP, LOOP-IRAP, LOOP-MTCS
  (named in `LOOP-Z-SPEC.md §11`) extend the Z.Z1 + Z.Z3 catalogs
  with per-scheme overlays. Operators serving Japanese /
  Australian / UK / Singaporean / Indian / GCC customers must
  layer the per-scheme loop atop LOOP-Z. The runbook lists each
  scheme + its current status; CHANGELOG entry on per-scheme loop
  addition. Cross-references LOOP-Z-SPEC.md §11.
- **Owner**: LOOP-Z primary; future LOOP-ISMAP / LOOP-IRAP / etc.
  implementers.
- **Status**: open.
- **References**: ISMAP https://www.ismap.go.jp/ ; IRAP
  https://www.cyber.gov.au/irap ; G-Cloud
  https://www.gov.uk/guidance/g-cloud-suppliers-guide ; MTCS
  https://www.imda.gov.sg/ ; CERT-In https://www.cert-in.org.in/ .

### Z-X11 — ISO/IEC 27002:2022 vs Annex A naming inconsistency (27002 is the implementation guide; A.x.y references must match)

- **Description**: ISO/IEC 27001:2022 Annex A lists 93 control
  references; ISO/IEC 27002:2022 provides the implementation
  guidance for each control. The Annex A wording is concise; the
  27002 wording is extensive. Some operators (especially those who
  read 27002 first) copy the 27002 control name into the SoA,
  which differs subtly from the Annex A name. Example: Annex A
  `A.5.1` is "Policies for information security"; ISO 27002:2022
  §5.1 control name is the same, but the 27002 paragraph header
  reads "5.1 Policies for information security" with a
  one-sentence Control statement that some implementers transcribe
  in lieu of the Annex A reference. The certification body uses
  Annex A as the audit source; SoA divergence triggers
  non-conformance.
- **Category**: standards alignment.
- **Severity**: low (cosmetic but real). **Likelihood**: med.
  **Impact**: low.
- **Mitigation**: Z.Z1's catalog stores both `annex_a_name` (the
  exact 27001 Annex A text) AND `iso_27002_name` (the 27002
  implementation-guide text); Z.Z2's SoA renderer uses
  `annex_a_name` for every SoA entry. CI test pins the 93 Annex A
  names byte-for-byte against an extracted reference. Cross-
  references Z.Z1-3.
- **Owner**: Z.Z1 implementer.
- **Status**: open.
- **References**: ISO/IEC 27001:2022 Annex A; ISO/IEC 27002:2022
  §5-§8.

### Z-X12 — 27017 augmented-control vs new-control distinction collapse

- **Description**: ISO/IEC 27017:2015 contains TWO control types:
  (a) cloud-specific extensions of existing 27002 controls (37
  augmented controls, where the 27002 base remains the requirement
  and 27017 adds cloud-specific implementation guidance), and (b)
  new cloud-specific controls in the CLD.x.y namespace (7 entirely-
  new controls — CLD.6.3.1, CLD.8.1.5, CLD.9.5.1, CLD.9.5.2,
  CLD.12.1.5, CLD.12.4.5, CLD.13.1.4). A naive Z.Z3 emitter that
  treats both types identically misses the implementation pattern:
  augmented controls inherit 27002 evidence + add cloud overlay;
  new controls have no 27002 base and require cloud-native
  evidence-only.
- **Category**: 27017 catalog correctness.
- **Severity**: med. **Likelihood**: med. **Impact**: med.
- **Mitigation**: Z.Z3's `data/iso-27017-controls.json` per-control
  row carries `control_type: 'augmented_27002' | 'new_cld'` +
  `base_27002_control_id: string | null`; Z.Z3's mapper joins
  augmented controls back to the 27002 evidence chain and emits
  new CLD controls as cloud-native-evidence-only. CI test asserts
  the 7 CLD controls + the 37 augmented controls match the 27017
  Annex A summary table. Cross-references Z.Z3-2.
- **Owner**: Z.Z3 implementer.
- **Status**: open.
- **References**: ISO/IEC 27017:2015 Annex A.

### Z-X13 — 27018 PII categorisation drift (PII definition vs GDPR personal data vs CCPA personal information)

- **Description**: ISO/IEC 27018:2019 §3 defines PII per ISO/IEC
  29100:2011 ("any information that (a) can be used to identify
  the PII principal to whom such information relates, or (b) is or
  might be directly or indirectly linked to a PII principal"). GDPR
  Article 4(1) defines "personal data" with broader implicit scope
  (any data relating to an identified or identifiable natural
  person). CCPA §1798.140(o) defines "personal information" with
  yet another scope (information that identifies, relates to,
  describes, etc. a particular consumer or household). A Z.Z4
  emitter that uses one definition uniformly may either under-
  scope (miss PII the GDPR considers personal data) or over-
  scope (treat data that is NOT PII under 29100 as PII because
  CCPA defines it as personal information).
- **Category**: PII definition / privacy alignment.
- **Severity**: med (definition mismatch affects audit defensibility).
  **Likelihood**: med. **Impact**: med.
- **Mitigation**: Z.Z4 records every PII category with three
  classification flags: `is_pii_per_29100: bool`, `is_personal_data_per_gdpr: bool`,
  `is_personal_information_per_ccpa: bool`; the emit covers
  whichever flags apply per engagement. The runbook explicitly
  documents the three definitions side-by-side. Cross-references
  LOOP-U.U1 (GDPR + CCPA crosswalk). CHANGELOG entry per
  classification-update.
- **Owner**: Z.Z4 implementer.
- **Status**: open.
- **References**: ISO/IEC 27018:2019 §3; ISO/IEC 29100:2011 §2.9;
  GDPR Article 4(1); CCPA §1798.140(o).

### Z-X14 — 27701 PIMS scope-definition gap (the PIMS scope must include both ISMS scope + privacy-extension scope)

- **Description**: ISO/IEC 27701:2019 §5.2.1 requires the PIMS to
  determine its scope by combining the ISMS scope (per 27001
  clause 4.3) with the additional privacy-extension scope (per
  27701 §5.2.1.1-3). A naive Z.Z5 emitter that re-uses the ISMS
  scope verbatim misses the PIMS-specific scope additions
  (extended-PII processing activities, additional data subjects,
  additional regulatory jurisdictions). The PIMS certification
  body will reject scope statements that don't satisfy 27701
  §5.2.1.
- **Category**: PIMS scope definition.
- **Severity**: high (certification-body rejection at PIMS audit).
  **Likelihood**: med. **Impact**: high.
- **Mitigation**: Z.Z5's `core/iso-27701-pims.ts` carries
  `pims_scope` as `{ isms_scope_reference: string, pii_processing_activities: ProcessingActivity[], data_subject_categories: string[], regulatory_jurisdictions: string[], excluded_processing_with_rationale: ExcludedActivity[] }`;
  the emit refuses to render unless every field is populated +
  `pii_processing_activities.length > 0`. The runbook documents the
  PIMS scope-definition workshop the operator runs annually.
  Cross-references Z.Z5-2.
- **Owner**: Z.Z5 implementer.
- **Status**: open.
- **References**: ISO/IEC 27701:2019 §5.2.1 + Annex A & B.

### Z-X15 — EUCS Substantial vs High assurance-level confusion (operator targets the wrong tier)

- **Description**: ENISA EUCS defines three assurance levels —
  Basic, Substantial, and High — with progressively-stricter
  control sets and conformity-assessment requirements. A CSP
  serving EU public-sector customers may need Substantial OR
  High depending on the data-classification of the customer's
  data; misidentifying the target tier produces a submission
  package that does not align with the customer's actual
  procurement requirements. The High tier additionally requires
  EU-sovereignty controls (EU-based legal entity, EU-located
  data, EU-located support staff with EU-only access) that
  many US-headquartered CSPs cannot satisfy without
  organisational restructuring.
- **Category**: EUCS tier targeting.
- **Severity**: high (procurement-blocker). **Likelihood**: med.
  **Impact**: high.
- **Mitigation**: Z.Z5's `core/enisa-eucs-mapper.ts` carries a
  per-tier control-set diff so the operator can compare Basic
  vs Substantial vs High side-by-side; the emit's submission-
  package cover sheet records the targeted tier + the customer's
  data-classification rationale. The Z.Z5 emit additionally
  surfaces a "High-tier sovereignty gap" report enumerating any
  sovereignty controls the operator's organisation does not
  currently satisfy; the runbook documents the remediation path
  (EU subsidiary, EU data residency, EU support staffing). Cross-
  references Z.Z5-3.
- **Owner**: Z.Z5 implementer.
- **Status**: open.
- **References**: ENISA EUCS Candidate Scheme §3 "Assurance
  Levels"; EU Cybersecurity Act Article 52.

### Z-X16 — ISO 27001 vs FedRAMP Moderate cross-walk false-equivalence

- **Description**: A FedRAMP-authorized CSP is often tempted to
  treat a FedRAMP-Moderate authorization as automatic ISO/IEC
  27001:2022 equivalence. Independent control-mapping work (NIST
  OLIR + community cross-walks + the cloud-evidence canonical
  mapping in Z.Z1) shows that FedRAMP Moderate covers approximately
  85-92% of the 93 Annex A controls in scope; the remaining 8-15%
  (controls like A.5.7 Threat intelligence, A.5.30 ICT readiness
  for business continuity, A.7.4 Physical security monitoring,
  A.8.10 Information deletion, A.8.11 Data masking, A.8.16
  Monitoring activities, A.8.28 Secure coding) require ISO-specific
  evidence the FedRAMP package does not directly provide. An
  operator who emits an SoA marked "satisfied via FedRAMP
  authorization" for ALL controls is making a false claim.
- **Category**: cross-walk / equivalence.
- **Severity**: high (false-attestation). **Likelihood**: high.
  **Impact**: high.
- **Mitigation**: Z.Z1's catalog records `fedramp_moderate_coverage:
  'full' | 'partial' | 'none'` per Annex A control + a
  `fedramp_coverage_rationale: string` field with the specific
  800-53 control(s) backing the FedRAMP coverage; controls marked
  `partial` or `none` MUST receive non-FedRAMP evidence in the
  Z.Z2 SoA. The Z.Z2 emit's `evidence_summary` cross-tabs FedRAMP
  vs non-FedRAMP evidence per control; CHANGELOG entry per
  coverage-update. Cross-references Z.Z1-4.
- **Owner**: Z.Z1 + Z.Z2 implementers.
- **Status**: open.
- **References**: NIST OLIR ISO 27001 → 800-53 mapping; FedRAMP
  Moderate baseline (FedRAMP rev 5 baselines).

### Z-X17 — Multi-edition catalog churn (2013 + 2022 + future 2030 edition simultaneously in use)

- **Description**: Real operators carry MULTIPLE ISO 27001
  certificate eras simultaneously — legacy 2013-edition certificates
  in their archives, current 2022-edition certificates in
  production, and (eventually) a future 2030-or-similar edition as
  ISO issues amendments. A LOOP-Z that hard-codes the 2022 edition
  cannot serve operators in transition (e.g. mid-2025 surveillance
  audits where the operator is moving from 2013 to 2022). The
  catalog must support edition-aware emit + cross-edition
  reconciliation reports.
- **Category**: catalog version management.
- **Severity**: med. **Likelihood**: med. **Impact**: med.
- **Mitigation**: Z.Z1's catalog data structure carries
  `edition: '2013' | '2022' | '2030+'` per row; the loader exposes
  a `getCatalog(edition: '2013' | '2022'): ControlRow[]` API; the
  Z.Z2 SoA emitter defaults to `2022` but the CLI `--iso-edition`
  flag can request `2013` for legacy-certificate maintenance. The
  cross-edition reconciliation report (`out/iso-27001-edition-reconciliation-{cspname}-{date}.json`)
  shows the 2013 → 2022 mapping for every control the operator has
  prior-evidence on. CHANGELOG entry per edition addition.
- **Owner**: Z.Z1 implementer.
- **Status**: open.
- **References**: ISO/IEC 27001:2013; ISO/IEC 27001:2022.

### Z-X18 — ISO 27001 surveillance-audit cadence vs annual SoA refresh

- **Description**: ISO/IEC 17021-1 + IAF MD 5 require certification
  bodies to perform surveillance audits annually + a full
  recertification audit every 3 years. The SoA is reviewed at
  every surveillance + recertification audit; material changes
  (acquisitions, system migrations, threat-landscape shifts,
  remediation of identified non-conformities) require SoA
  updates between audits. A LOOP-Z that treats the SoA as a
  static once-per-3-years artefact misses surveillance-audit
  expectations; a LOOP-Z that re-emits the SoA on every change
  produces an unmaintainable churn.
- **Category**: SoA refresh cadence.
- **Severity**: med. **Likelihood**: med. **Impact**: med.
- **Mitigation**: Z.Z2's tracker records `soa_last_emitted_at`
  + `soa_next_surveillance_audit_at` + `soa_next_recertification_at`
  + `material_change_events[]` (events that triggered an SoA
  refresh). The tracker UI surfaces a "SoA freshness" indicator
  at T-90 / T-30 / T-7 days from the next surveillance audit. The
  runbook documents the material-change-event taxonomy (M&A,
  divestiture, geographic expansion, new product line,
  certification-scope change, identified-non-conformity
  remediation). CHANGELOG entry per SoA emit cites the trigger
  event. Cross-references LOOP-T-X12 (annual cadence drift) for
  the analogous pattern.
- **Owner**: Z.Z2 implementer.
- **Status**: open.
- **References**: ISO/IEC 17021-1:2015 §9; IAF MD 5:2019
  (Determination of Audit Time of Quality and Environmental
  Management Systems).

### Z-X19 — Certification-body independence conflict (CB also provides consulting to the same CSP)

- **Description**: ISO/IEC 17021-1:2015 §5.2 requires
  certification-body independence — the CB MUST NOT provide
  management-system consulting services to the same CSP it
  certifies. Some CBs maintain separate "consulting arms" that
  attempt to circumvent the prohibition; the IAF has issued
  guidance (IAF MD 16) clarifying that the prohibition is
  organisational, not just departmental. A CSP that engages a
  CB's affiliated consulting arm for ISMS implementation prep,
  then engages the same CB's certification arm for the audit,
  invalidates the resulting certificate.
- **Category**: audit body / independence.
- **Severity**: high (certificate invalidity if challenged).
  **Likelihood**: low (sophisticated CBs avoid). **Impact**: high.
- **Mitigation**: Z.Z2's tracker `certification_body_registry`
  table includes a `consulting_engagement_check: boolean` flag;
  the operator records every consulting engagement against the
  CB + the CB's affiliates; the tracker emits a warning when a
  CB selected for audit has any prior consulting engagement
  within 3 years (per IAF MD 16's 2-year minimum + 1-year safety
  buffer). Runbook documents the IAF MD 16 requirement.
  CHANGELOG entry per CB-independence update.
- **Owner**: Z.Z2 implementer; tracker UI team.
- **Status**: open.
- **References**: ISO/IEC 17021-1:2015 §5.2; IAF MD 16
  (Application of ISO/IEC 17021-1 for the Certification of Food
  Safety Management Systems analogue + Resolution 2018-12).

### Z-X20 — Audit-trail tampering (SoA history must be immutable + signed)

- **Description**: An SoA must be reproducible at any historical
  point for surveillance / recertification audits. If the SoA
  file in the repository or the tracker DB is mutated without
  preserving prior versions + signatures, the audit body cannot
  verify the historical state. An attacker with repo-write
  access could swap the file with a tampered version that hides
  prior non-conformities.
- **Category**: audit-trail integrity.
- **Severity**: high (audit defensibility + ISMS trust). **Likelihood**:
  low. **Impact**: high.
- **Mitigation**: Z.Z2's SoA emit produces an Ed25519-signed
  envelope per SoA version + an RFC 3161 timestamp; the
  envelope is stored in `out/iso-27001-soa-{cspname}-{date}.json`
  + `.sig` + `.tsr`. The tracker DB `iso_27001_soa` table is
  append-only — UPDATE is forbidden; new SoA versions create new
  rows linked by `previous_soa_id` (hash-chain). A CI cron
  re-verifies every prior SoA signature daily; verification
  failure pages the team. Cross-references LOOP-W-X24
  (snapshot-tampering pattern).
- **Owner**: Z.Z2 implementer.
- **Status**: open.
- **References**: ISO/IEC 27001:2022 clause 7.5 (documented
  information); FedRAMP 20x signing infrastructure (LOOP-A.A5).

### Z-X21 — Multi-language SoA emit (EU customers may request French / German / Italian / Spanish SoA)

- **Description**: EU public-sector customers may demand the SoA
  in their official language (French, German, Italian, Spanish,
  Polish, Dutch, Portuguese). ISO/IEC 17021-1 §9.2.3 requires
  audit reports to be in a language the certification body's
  audit team understands AND in a language the client
  understands; this can require translation. A LOOP-Z that
  emits English-only SoA misses non-English customer
  requirements; a LOOP-Z that auto-translates risks legal-
  liability (mistranslation of a control justification is the
  operator's responsibility).
- **Category**: localisation.
- **Severity**: med. **Likelihood**: med. **Impact**: med.
- **Mitigation**: Z.Z2's SoA emit defaults to English; CLI flag
  `--soa-language en|fr|de|it|es|pl|nl|pt` selects an
  operator-provided translation; the operator commits per-language
  Annex A control-name translations + per-justification
  translations under `data/iso-27001-translations/<lang>/`. The
  emit refuses to render in a non-English language unless every
  in-scope control has an operator-supplied translation; missing
  translations emit REQUIRES-OPERATOR-INPUT diagnostics. A
  professional-translator workflow is documented in the runbook.
  Cross-references Z.Z2-10.
- **Owner**: Z.Z2 implementer.
- **Status**: open.
- **References**: ISO/IEC 17021-1:2015 §9.2.3.

### Z-X22 — Pre-audit Stage-1 / Stage-2 sequencing mismatch

- **Description**: ISO/IEC 17021-1 §9.3 requires a two-stage
  initial certification audit: Stage 1 (readiness review +
  documentation review) followed by Stage 2 (on-site / remote
  conformity audit). The Stage 1 audit identifies any
  "Major Areas of Concern" that must be addressed before Stage
  2; a CSP that schedules Stage 2 before remediating Stage-1
  findings forces an audit-team return + cost-overrun. LOOP-Z's
  tracker does not currently surface Stage-1 findings as a
  separate state from regular non-conformities.
- **Category**: audit sequencing.
- **Severity**: med. **Likelihood**: med. **Impact**: med.
- **Mitigation**: Z.Z2's tracker `iso_audit_engagements` table
  carries `stage: 'stage_1' | 'stage_2' | 'surveillance' | 'recertification'`
  + `stage_1_findings: AuditFinding[]` + `stage_1_remediation_status:
  'pending' | 'in_progress' | 'complete'` + `stage_2_eligible_at:
  timestamp`. The tracker UI refuses to schedule Stage 2 unless
  `stage_1_remediation_status === 'complete'` AND `stage_2_eligible_at
  > current_time`. Runbook documents the IAF MD 5 audit-time
  guidance. Cross-references Z.Z2-11.
- **Owner**: Z.Z2 implementer.
- **Status**: open.
- **References**: ISO/IEC 17021-1:2015 §9.3; IAF MD 5:2019.

### Z-X23 — Non-conformity classification dispute (minor vs major vs observation)

- **Description**: An audit finding is classified as one of: a
  **major non-conformity** (NC) (system not effective; certificate
  cannot be issued / must be suspended), a **minor non-conformity**
  (system effective but with a gap requiring corrective action
  within 90 days), or an **observation** (no immediate action
  required). The classification is the auditor's judgement and
  is occasionally disputed. A CSP that records a major NC as a
  minor NC in the tracker (perhaps under audit-team pressure or
  through miscommunication) under-states the remediation timeline
  and may lose the certificate.
- **Category**: audit-finding classification.
- **Severity**: med. **Likelihood**: med. **Impact**: med.
- **Mitigation**: Z.Z2's tracker `iso_audit_findings` table
  carries `classification: 'major_nc' | 'minor_nc' | 'observation'`
  + `classification_source: 'auditor_initial' | 'auditor_revised'
  | 'cb_review_panel'` + `dispute_status: 'undisputed' | 'in_review'
  | 'resolved_in_csp_favor' | 'resolved_in_cb_favor'`. Major NCs
  trigger automatic POA&M emit via LOOP-B.B1 with 90-day
  remediation SLA; the runbook documents the CB dispute process
  (typically per IAF MD 1 §G.5). Cross-references Z.Z2-12 and
  LOOP-B-X*.
- **Owner**: Z.Z2 implementer.
- **Status**: open.
- **References**: ISO/IEC 17021-1:2015 §9.4.8; IAF MD 1:2018.

### Z-X24 — IAF MLA recognition vs unaccredited certificate

- **Description**: The International Accreditation Forum (IAF)
  Multilateral Recognition Arrangement (MLA) provides reciprocal
  recognition of certificates issued by IAF-MLA-signatory
  national-accreditation-bodies. A certificate issued by a CB
  accredited by an IAF-MLA signatory is recognised across all
  IAF-MLA jurisdictions. A certificate issued by a CB outside
  the IAF MLA (or by an "unaccredited certification body") is
  NOT recognised by procurement teams that explicitly require
  IAF-MLA recognition. A CSP that selects a cheaper non-IAF-MLA
  CB to save cost may find the certificate rejected by EU /
  Japanese / Australian customers.
- **Category**: certificate recognition / accreditation.
- **Severity**: med. **Likelihood**: low. **Impact**: med.
- **Mitigation**: Z.Z2's `certification_body_registry` table
  records `iaf_mla_signatory: boolean` + `iaf_mla_url`
  per CB; the tracker UI warns when an operator selects a
  non-IAF-MLA CB AND has at least one EU / Japan / Australia /
  UK customer in the customer-registry. Runbook documents the
  IAF MLA + lists the signatories (IAF MLA member list at
  https://iaf.nu/iaf-mla/). Cross-references Z.Z2-13.
- **Owner**: Z.Z2 implementer; tracker UI team.
- **Status**: open.
- **References**: IAF MLA https://iaf.nu/iaf-mla/ ; IAF
  Resolution 2018-15.

### Z-X25 — Cross-loop dependency: LOOP-T SSDF Common Form for A.8.25 evidence

- **Description**: ISO/IEC 27001:2022 A.8.25 "Secure development
  lifecycle" requires the organisation to define + apply rules
  for software development. LOOP-T's CISA Common Form (per OMB
  M-22-18 / M-23-16) provides evidence of SSDF practice
  conformance that maps to A.8.25. If LOOP-T's Common Form is
  withdrawn (per T-X14) or stale (per T-X12), Z.Z2's SoA cites
  a non-current Common Form — a 3PAO who cross-references the
  two artefacts would flag the inconsistency.
- **Category**: cross-loop dependency.
- **Severity**: med. **Likelihood**: med. **Impact**: med.
- **Mitigation**: Z.Z2's SoA emit reads
  `out/ssdf-agency-submissions.json` and verifies the most-recent
  Common Form's `submission_status === 'accepted' || === 'submitted'`
  AND `template_version` is current; mismatch → SoA emit warns
  + does NOT mark A.8.25 as fully-satisfied. Cross-references
  LOOP-T-X14.
- **Owner**: Z.Z2 implementer.
- **Status**: open.
- **References**: LOOP-T-SPEC.md; OMB M-22-18 / M-23-16.

### Z-X26 — Cross-loop dependency: LOOP-W prohibited-vendor screen for A.5.19 / A.5.20 / A.5.23

- **Description**: ISO/IEC 27001:2022 A.5.19 ("Information security
  in supplier relationships"), A.5.20 ("Addressing information
  security within supplier agreements"), and A.5.23 ("Information
  security for use of cloud services") all require evidence of
  supplier-side security control. LOOP-W's prohibited-vendor
  screen (FAR §889 / NDAA §1634 / OFAC / BIS / SAM Exclusions)
  provides supplier-screening evidence. If LOOP-W's screen is
  stale (per W-X1 / W-X2 / W-X3), Z.Z2's SoA cites stale
  supplier evidence.
- **Category**: cross-loop dependency.
- **Severity**: med. **Likelihood**: med. **Impact**: med.
- **Mitigation**: Z.Z2's SoA emit reads
  `out/prohibited-vendors-screen-*.json` and verifies the
  catalog snapshot's `signed_at` is < 24h old (LOOP-W's strict
  mode threshold); mismatch → SoA emit warns + does NOT mark
  A.5.19 / A.5.20 / A.5.23 as fully-satisfied. Cross-references
  LOOP-W-X1, LOOP-W-X3.
- **Owner**: Z.Z2 implementer.
- **Status**: open.
- **References**: LOOP-W-SPEC.md; FAR 52.204-25.

### Z-X27 — Cross-loop dependency: LOOP-R PQC migration for A.8.24

- **Description**: ISO/IEC 27001:2022 A.8.24 "Use of cryptography"
  requires the organisation to define + apply rules for
  cryptographic-key management + cryptography use. LOOP-R's
  post-quantum cryptography migration provides forward-looking
  evidence of A.8.24 conformance (alignment with NIST SP
  800-208 + CNSA 2.0). If LOOP-R is stalled or shows
  RSA-2048-only / ECDSA-P-256-only without a PQC migration
  plan, Z.Z2's SoA citation for A.8.24 may be incomplete from
  the certification body's perspective.
- **Category**: cross-loop dependency.
- **Severity**: low (PQC is forward-looking; current crypto is
  acceptable). **Likelihood**: med. **Impact**: low.
- **Mitigation**: Z.Z2's SoA emit reads
  `out/pqc-migration-readiness-*.json` and surfaces the PQC
  migration status as an `A.8.24 supplementary evidence` note;
  no fail condition. Cross-references LOOP-R-X*.
- **Owner**: Z.Z2 implementer.
- **Status**: open.
- **References**: LOOP-R-SPEC.md; NIST SP 800-208.

### Z-X28 — Cross-loop dependency: LOOP-U privacy crosswalk for Z.Z4 + Z.Z5

- **Description**: LOOP-U.U1 emits the privacy-framework crosswalk
  (GDPR + CCPA + FERPA + COPPA + GLBA to NIST 800-53). Z.Z4
  (27018) and Z.Z5 (27701) cross-reference LOOP-U for GDPR
  Article 28 + 30 + 32 alignment. If LOOP-U's mapping changes
  (e.g. a CCPA amendment changes the §1798.140(o) definition),
  Z.Z4 / Z.Z5 would silently drift.
- **Category**: cross-loop dependency.
- **Severity**: med. **Likelihood**: med. **Impact**: med.
- **Mitigation**: Z.Z4 + Z.Z5 read
  `out/loop-u-privacy-crosswalk.json` and pin the
  `crosswalk_version`; on version bump, the readers emit a
  REQUIRES-OPERATOR-INPUT diagnostic
  `iso-27018-27701-loopu-version-mismatch` until the operator
  re-runs Z.Z4 + Z.Z5 against the new version. Cross-references
  LOOP-U-X*.
- **Owner**: Z.Z4 + Z.Z5 implementers.
- **Status**: open.
- **References**: LOOP-U-SPEC.md.

### Z-X29 — Cross-loop dependency: LOOP-V HIPAA crosswalk for Z.Z4 PHI overlap

- **Description**: LOOP-V emits the HIPAA Security Rule + HITRUST
  CSF crosswalk. Z.Z4 (ISO 27018) overlaps with HIPAA when the
  CSP processes PHI: 27018 frames PII protection in GDPR Article
  28 processor role; HIPAA frames the same protection in the BAA
  (Business Associate Agreement) covered-entity role. Both views
  must be consistent.
- **Category**: cross-loop dependency.
- **Severity**: med (when CSP serves healthcare customer).
  **Likelihood**: med. **Impact**: med.
- **Mitigation**: Z.Z4 + LOOP-V coordinate via
  `out/healthcare-pii-overlap.json` — Z.Z4 emits per-PII-engagement
  records; LOOP-V emits per-PHI-engagement records; an
  integration test asserts no record has `is_phi === true` AND
  `is_pii === false` (PHI is by definition a subset of PII).
  Cross-references LOOP-V-SPEC.md.
- **Owner**: Z.Z4 implementer; LOOP-V coordination.
- **Status**: open.
- **References**: LOOP-V-SPEC.md; HIPAA Security Rule
  45 CFR §164.308; ISO/IEC 27018:2019.

### Z-X30 — Cross-loop dependency: LOOP-INV-S inventory-tag schema drift

- **Description**: Z.Z3 (ISO 27017 per-cloud overlay) reads
  inventory tags from `core/inventory-coverage.ts` to compute
  per-cloud control coverage. If LOOP-INV-S's tag schema
  changes (e.g. `fedramp_cloud_provider` renamed to
  `cloud_csp_id`), Z.Z3 silently reads empty data → false
  coverage report.
- **Category**: cross-loop dependency / inventory.
- **Severity**: med. **Likelihood**: med. **Impact**: med.
- **Mitigation**: Z.Z3 asserts the expected tag names + minimum
  inventory-row count from `inventory-coverage.ts`; a schema
  change throws a typed `Iso27017InventoryTagDriftError` with
  remediation message. Cross-loop test pins the current schema.
  Cross-references LOOP-INV-S risks + LOOP-W-X36.
- **Owner**: Z.Z3 implementer.
- **Status**: open.
- **References**: LOOP-INV-S-SPEC.md.

### Z-X31 — Cross-loop dependency: LOOP-Q marketplace-badge format for ISO + EUCS badges

- **Description**: LOOP-Q.Q1 surfaces FedRAMP Marketplace badges
  ("FedRAMP Authorized", "ISO 27001 Certified", "EUCS Substantial
  Certified") by reading signed envelopes from LOOP-Z. If
  Q.Q1's badge format changes (e.g. requires `certificate_url`
  or `issuing_cb_name` fields Z.Z2 / Z.Z5 do not currently
  emit), the badge is incomplete.
- **Category**: cross-loop dependency.
- **Severity**: low (additive). **Likelihood**: low. **Impact**:
  low.
- **Mitigation**: Z.Z2 + Z.Z5 envelopes are signed JSON; adding
  fields is backward-compatible. Q.Q1 reads named fields only.
  CHANGELOG entry per Q.Q1-required field addition. Cross-
  references LOOP-W-X32.
- **Owner**: Z.Z2 + Z.Z5 implementers.
- **Status**: open.
- **References**: LOOP-Q-SPEC.md.

### Z-X32 — Multi-tenant LOOP-Z isolation deferred to LOOP-H.H3

- **Description**: All LOOP-Z tracker tables (`iso_27001_soa`,
  `iso_27001_soa_controls`, `iso_27017_coverage`,
  `iso_27018_pii_controls`, `iso_27701_pims_scope`,
  `eucs_submissions`) omit a `tenant_id` column. When multi-CSO
  ships (H.H3), all need migration in a single cross-loop
  sweep. Same risk class as LOOP-B-X15, LOOP-R-X15, LOOP-S-X21,
  LOOP-T-X28, LOOP-W-X38.
- **Category**: multi-tenant.
- **Severity**: med (long-tail). **Likelihood**: high. **Impact**:
  med.
- **Mitigation**: Documented in `LOOP-Z-SPEC.md §9 Open Questions`;
  H.H3 spec must enumerate every LOOP-Z table; LOOP-Z ships in
  single-tenant deployments only (documented in runbook). Cross-
  references LOOP-H.H3.
- **Owner**: LOOP-Z primary; LOOP-H.H3 implementer.
- **Status**: open.
- **References**: LOOP-H-SPEC.md.

### Z-X33 — REO Rule 1.8 `process.env.NODE_ENV === 'test'` branch creep

- **Description**: REO Rule 1.8 prohibits the literal in production
  code. The new LOOP-Z emitters (Annex A catalog loader, SoA
  emitter, OOXML renderer, EUCS submission packager, PIMS scope
  manager) are exactly where developers reach for the test-
  short-circuit. Same class as LOOP-B-X6, LOOP-R-X6, LOOP-S-X15,
  LOOP-T-X20, LOOP-W-X26.
- **Category**: REO compliance.
- **Severity**: high (REO violation; CI rejects). **Likelihood**:
  med. **Impact**: high.
- **Mitigation**: `scripts/lint-no-stubs.mjs` catches the literal;
  tests inject seams via dependency-injected HTTP fetcher +
  filesystem helper + clock helper + OOXML-renderer seam; CI gate
  is non-bypassable. Cross-references LOOP-B-X6.
- **Owner**: All Z.Z* implementers.
- **Status**: open.
- **References**: cloud-evidence/CLAUDE.md Rule 1.8.

### Z-X34 — Provenance schema drift across new emit artifacts

- **Description**: Every new emit artifact (`iso-27001-soa-{cspname}-{date}.json`,
  `iso-27001-soa-{cspname}-{date}.docx`,
  `iso-27017-per-cloud-coverage-{cspname}-{date}.json`,
  `iso-27018-pii-processor-records-{cspname}-{date}.json`,
  `iso-27701-pims-{cspname}-{date}.json`,
  `eucs-submission-package-{cspname}-{level}-{date}.zip`,
  `iso-27001-edition-reconciliation-{cspname}-{date}.json`)
  must carry a `provenance` block per REO Rule 2.6.
  `scripts/check-provenance.mjs` enforces the schema (emitter,
  emittedAt, sourceCalls, signingKeyId). A missed block silently
  fails the slice.
- **Category**: REO / provenance.
- **Severity**: high. **Likelihood**: med. **Impact**: high.
- **Mitigation**: Per-slice test verifies provenance via
  `check:provenance`; pattern reused from `core/inventory-coverage.ts`.
  Cross-references LOOP-B-X9, LOOP-R-X9, LOOP-S-X16, LOOP-T-X21,
  LOOP-W-X25. CHANGELOG entry per slice cites the provenance
  block contents.
- **Owner**: All Z.Z* implementers.
- **Status**: open.
- **References**: cloud-evidence/CLAUDE.md Rule 2.6.

### Z-X35 — Submission-bundle role count growth

- **Description**: LOOP-Z adds 8-10 new roles to
  `submission-bundle.ts:WELL_KNOWN`:
  `iso-27001-soa-docx`, `iso-27001-soa-json`,
  `iso-27017-per-cloud-coverage-json`,
  `iso-27018-pii-processor-records-json`,
  `iso-27701-pims-json`, `iso-27701-pims-scope-statement-docx`,
  `eucs-submission-package-zip`,
  `iso-edition-reconciliation-json`,
  `iso-27001-config-yaml`, `iso-translations-{lang}-directory`.
  Role collisions or filename collisions corrupt the bundle.
  Same class as LOOP-W-X27, LOOP-T-X22.
- **Category**: submission bundle.
- **Severity**: med. **Likelihood**: low. **Impact**: med.
- **Mitigation**: `tests/core/submission-bundle.test.ts` pins the
  full role table; per-slice tests assert presence; CHANGELOG
  entry for Z.Z5 (last slice) lists the final inventory.
- **Owner**: All Z.Z* implementers; LOOP-A.A4 maintainer.
- **Status**: open.
- **References**: LOOP-A-SPEC.md A.A4.

### Z-X36 — Tracker schema migration on existing installs

- **Description**: LOOP-Z adds 6+ new tables (`iso_27001_soa`,
  `iso_27001_soa_controls`, `iso_27017_coverage`,
  `iso_27018_pii_controls`, `iso_27701_pims_scope`,
  `eucs_submissions`, `certification_body_registry`,
  `iso_audit_engagements`, `iso_audit_findings`). Existing
  tracker installs have user data — migrations must be additive
  only. Same risk class as LOOP-B-X10, LOOP-R-X10, LOOP-S-X18,
  LOOP-T-X23, LOOP-W-X*.
- **Category**: tracker / migration.
- **Severity**: high. **Likelihood**: med. **Impact**: high.
- **Mitigation**: All tables are additive `CREATE TABLE IF NOT
  EXISTS`; CHANGELOG documents the upgrade path; smoke test on
  a copy of a production DB; no DROP / ALTER COLUMN under any
  circumstance in LOOP-Z; multi-tenant work batches all
  cross-loop migrations under LOOP-H.H3. Cross-references
  LOOP-T-X23.
- **Owner**: Z.Z2 + Z.Z3 + Z.Z4 + Z.Z5 implementers.
- **Status**: open.
- **References**: cloud-evidence/CLAUDE.md Rule 2.
- **Status**: open.

### Z-X37 — Tracker Ed25519 signing-key rotation across SoA edition boundaries

- **Description**: Z.Z2 + Z.Z3 + Z.Z4 + Z.Z5 sign tracker-side
  audit records with the tracker-resident Ed25519 key. Multi-
  edition SoA records (2013 + 2022) persist indefinitely.
  Tracker resident-key rotation across SoA edition boundaries
  could invalidate prior-edition audit-log signatures during
  cross-edition reconciliation reports. Same risk class as
  LOOP-B-X3, LOOP-R-X4, LOOP-S-X6, LOOP-T-X24, LOOP-W-X23.
- **Category**: signing-key rotation.
- **Severity**: med. **Likelihood**: med. **Impact**: med.
- **Mitigation**: Tracker exposes `GET /api/sign/public-keys`
  returning all historical keys keyed by `key_id`; reader
  cross-references each audit record's `signing_key_id`
  against the registry. Pattern reused from LOOP-B-X3.
  Key rotation events written to `audit_log`; runbook
  documents.
- **Owner**: All Z.Z* implementers.
- **Status**: open.
- **References**: LOOP-B-RISKS.md B-X3.

### Z-X38 — Test count expectations / CI thresholds

- **Description**: LOOP-Z adds ~120 new tests across cloud-evidence
  + tracker (per-slice estimates: Z.Z1 ~25, Z.Z2 ~30, Z.Z3 ~25,
  Z.Z4 ~20, Z.Z5 ~25). Existing CI may have hard-coded "expected
  test count" assertions or coverage thresholds that need
  bumping. Same class as LOOP-B-X13, LOOP-R-X13, LOOP-S-X24,
  LOOP-T-X27.
- **Category**: CI thresholds.
- **Severity**: low. **Likelihood**: high. **Impact**: low.
- **Mitigation**: Per slice, the implementing session updates
  any test-count assertion; CHANGELOG entries cite the new
  totals; STATUS.md "Overall → tests" line bumped atomically
  with each slice ship.
- **Owner**: All Z.Z* implementers.
- **Status**: open.
- **References**: LOOP-T-X27.

---

## Per-slice risks

### Z.Z1 — ISO/IEC 27001:2022 Annex A Crosswalk (catalog + NIST OLIR + FedRAMP)

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| Z.Z1-1 | high | 27001:2013 → 2022 edition drift (cross-ref Z-X1) | `ISO_27001_EDITION = '2022'` constant + CI guard + legacy-as-informative-only | open |
| Z.Z1-2 | med | OLIR mapping informativeness misuse (cross-ref Z-X9) | `mapping_source` + `mapping_confidence` per row; OLIR-sourced flagged medium by default | open |
| Z.Z1-3 | low | Annex A vs 27002 naming inconsistency (cross-ref Z-X11) | Store both `annex_a_name` + `iso_27002_name`; SoA renderer uses `annex_a_name` | open |
| Z.Z1-4 | high | FedRAMP Moderate false-equivalence (cross-ref Z-X16) | `fedramp_moderate_coverage: 'full'|'partial'|'none'` + per-control rationale | open |
| Z.Z1-5 | high | Annex A 4-theme reorg mismatch (cross-ref Z-X2) | `legacy_2013_mapping[]` array per control; 11-new-control pin test | open |
| Z.Z1-6 | med | 27001 Rev 2 / 2030+ future-edition horizon (cross-ref Z-X17) | `edition` field; `getCatalog(edition)` API; CLI `--iso-edition` flag | open |
| Z.Z1-7 | med | NIST 800-53 Rev 6 horizon (currently Rev 5) | `nist_53_revision: '5'` constant pinned; bump + regenerate cross-walk on Rev 6 publication | open |
| Z.Z1-8 | med | ISO sources behind paywall (operator must own legal copies); extractor cannot fetch from iso.org anonymously | Operator downloads PDFs to `cloud-evidence/docs/sources/iso/`; extractor asserts SHA-256 against pinned hash; `REQUIRES-OPERATOR-INPUT: confirm-against-pdf` | open |
| Z.Z1-9 | low | Bilingual / accessibility text variants for control descriptions | English-only at launch; future enhancement could add localisation; documented in operator runbook | open |
| Z.Z1-10 | low | Catalog extractor non-deterministic ordering (PDF text extraction may shuffle rows) | Extractor sorts output by `(theme, control_id)` before emit; CHANGELOG documents the sort order | open |
| Z.Z1-11 | med | NIST CSF v2.0 informative references to 27001 drift | Out of Z.Z1 scope; future enhancement could add CSF cross-walk overlay | open |
| Z.Z1-12 | low | 27002 attribute table (Control type / Information security properties / Cybersecurity concepts / Operational capabilities / Security domains) extraction | Z.Z1 catalog includes all 5 attribute dimensions per control; extractor parses 27002 Annex A table | open |
| Z.Z1-13 | med | Operator override drift (cross-ref T-X26 pattern) | `override_for_catalog_version` field on every override row; flagged for review on version bump | open |
| Z.Z1-14 | low | Practice ordering for UI display (alphabetical vs canonical theme order) | Renderer sorts by canonical theme order (Org → People → Physical → Tech) by default; operator override via `iso-config.yaml` | open |
| Z.Z1-15 | low | First-snapshot bootstrap when no prior catalog exists | `--first-catalog` flag opts into emit; CHANGELOG documents bootstrap; no hash-chain prior reference | open |

### Z.Z2 — ISO 27001 Statement of Applicability (SoA) Emitter

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| Z.Z2-1 | high | Edition mismatch in SoA emit (cross-ref Z-X1) | Control-ID regex assertion + `IsoEditionMismatchError` | open |
| Z.Z2-2 | high | Missing clause 6.1.3(d) justifications (cross-ref Z-X3) | Min 80-char justification + blocked-pattern list + cross-reference required | open |
| Z.Z2-3 | high | SoA justification insufficiency (cross-ref Z-X3) | `SoAJustificationInsufficientError` + justification length + cross-reference | open |
| Z.Z2-4 | high | OOXML byte-determinism (similar to T-X25 for PDF) | Pin docx library + strip timestamps + embed font subset + cross-viewer test | open |
| Z.Z2-5 | high | Audit-trail tampering of SoA file (cross-ref Z-X20) | Ed25519 + RFC 3161 + append-only DB + hash-chain + CI cron re-verify | open |
| Z.Z2-6 | med | LOOP-T SSDF Common Form cross-reference for A.8.25 (cross-ref Z-X25) | Read `ssdf-agency-submissions.json`; mark partial if Common Form not current | open |
| Z.Z2-7 | med | LOOP-W prohibited-vendor screen cross-reference for A.5.19/20/23 (cross-ref Z-X26) | Read `prohibited-vendors-screen-*.json`; mark partial if snapshot stale | open |
| Z.Z2-8 | low | LOOP-R PQC migration cross-reference for A.8.24 (cross-ref Z-X27) | Read `pqc-migration-readiness-*.json`; supplementary evidence note | open |
| Z.Z2-9 | high | Certification body accreditation-scope mismatch (cross-ref Z-X8) | `certification_body_registry` + scope assertion + IAF CertSearch | open |
| Z.Z2-10 | med | Multi-language SoA emit (cross-ref Z-X21) | `--soa-language` flag + per-language translations + REQUIRES-OPERATOR-INPUT on missing | open |
| Z.Z2-11 | med | Stage-1 / Stage-2 sequencing mismatch (cross-ref Z-X22) | `iso_audit_engagements` + stage-1-complete assertion before stage-2 scheduling | open |
| Z.Z2-12 | med | Non-conformity classification disputes (cross-ref Z-X23) | `iso_audit_findings.classification` + dispute tracking + auto-POA&M for major NC | open |
| Z.Z2-13 | med | IAF MLA recognition gaps (cross-ref Z-X24) | `certification_body_registry.iaf_mla_signatory` + customer-jurisdiction-aware warning | open |
| Z.Z2-14 | high | CB independence conflict (cross-ref Z-X19) | `consulting_engagement_check` + 3-year history check + IAF MD 16 reference | open |
| Z.Z2-15 | med | SoA refresh cadence vs surveillance audit (cross-ref Z-X18) | `soa_last_emitted_at` + `material_change_events[]` + T-90/30/7 tracker warnings | open |
| Z.Z2-16 | med | Schema migration on existing installs (cross-ref Z-X36) | All tables additive CREATE TABLE IF NOT EXISTS; CHANGELOG documents | open |
| Z.Z2-17 | med | Confidentiality leak: SoA contains customer + vendor identifiers | Restrictive ACLs on `out/iso-27001-soa-*.json`; runbook recommends encrypted transmission to CB | open |
| Z.Z2-18 | med | Massive SoA size (93 controls × multi-paragraph justifications) | Warn at 5 MB, fail at 50 MB; per-control file split optional via `--split-by-theme` | open |
| Z.Z2-19 | low | Annual/recertification SoA archival | `soa_archive_retention_years` constant (default 7); cross-references LOOP-H long-term storage | open |
| Z.Z2-20 | low | Submission bundle role naming collisions (cross-ref Z-X35) | submission-bundle test pins role table | open |

### Z.Z3 — ISO/IEC 27017:2015 Cloud Controls + per-cloud overlay

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| Z.Z3-1 | high | CSP-CSC responsibility split evidence gap (cross-ref Z-X4) | `responsibility_split` field + CRM emit + CSC attestation requirement | open |
| Z.Z3-2 | med | Augmented vs new-CLD control distinction (cross-ref Z-X12) | `control_type` field + `base_27002_control_id` join | open |
| Z.Z3-3 | med | Inventory tag schema drift (cross-ref Z-X30) | Tag-name + min-row assertions; typed error on drift | open |
| Z.Z3-4 | med | Per-cloud coverage report explosion when CSP uses 3+ clouds | Per-cloud sub-reports; aggregated cover sheet; tracker UI tabs | open |
| Z.Z3-5 | high | Cosign / OCI provenance gap for cloud-native services (cross-ref LOOP-J.J3.b) | Z.Z3 reads LOOP-J cosign verification status; fail-closed when verification fails | open |
| Z.Z3-6 | low | 27017 Annex B (relationship between 27017 + 27018) drift | Documented as informative; Z.Z3 + Z.Z4 cross-reference each other | open |
| Z.Z3-7 | med | Multi-region deployment scope (per-region control coverage) | Per-(cloud, region) coverage matrix; tracker UI surfaces region-specific gaps | open |
| Z.Z3-8 | med | Shared-tenancy vs dedicated-tenancy control overlay | `tenancy_model` per cloud-service tag; per-model evidence requirement | open |
| Z.Z3-9 | low | 27017 vs ISO/IEC 22123 (cloud computing vocabulary) terminology drift | English-canonical glossary in operator runbook; cross-reference 22123 for ambiguities | open |
| Z.Z3-10 | med | CSP sub-processor cloud usage (CSP uses other CSPs as sub-processors) | Z.Z3 + Z.Z4 share subprocessors-sheet; per-sub-processor 27017 evidence requirement | open |
| Z.Z3-11 | med | LOOP-INV-S inventory completeness vs SoA coverage drift | Z.Z3 verifies inventory completeness ratio ≥ 95% before emit; below threshold → REQUIRES-OPERATOR-INPUT | open |
| Z.Z3-12 | low | 27017 implementation guidance vs control statement distinction | Catalog stores both implementation guidance (informative) + control statement (normative) | open |
| Z.Z3-13 | med | Per-cloud audit fatigue (CSP runs SOC 2 + ISO 27001 + 27017 audits simultaneously) | Z.Z3 evidence reusable across audits; cross-walk emit `out/iso-27017-vs-soc2-cross-walk.json` | open |
| Z.Z3-14 | low | CLD.6.3.1 "Shared roles" verbiage variability across CSPs | Catalog stores per-CSP recommended verbiage; operator override via `iso-config.yaml` | open |
| Z.Z3-15 | med | Cloud-portability evidence (CLD.8.1.5 customer asset removal) | Z.Z3 emit per-cloud customer-asset-removal procedure; tracker UI surfaces operator-confirmed status | open |

### Z.Z4 — ISO/IEC 27018:2019 PII Processor Controls

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| Z.Z4-1 | high | PII processor scope chain ambiguity (cross-ref Z-X5) | Per-engagement `csp_role` + `chain_position` + `pii_categories` | open |
| Z.Z4-2 | med | PII definition drift (29100 vs GDPR vs CCPA) (cross-ref Z-X13) | Three classification flags per PII category + runbook documentation | open |
| Z.Z4-3 | med | LOOP-U privacy crosswalk version drift (cross-ref Z-X28) | Pin `crosswalk_version`; REQUIRES-OPERATOR-INPUT on bump | open |
| Z.Z4-4 | med | LOOP-V HIPAA PHI overlap (cross-ref Z-X29) | Integration test asserts PHI ⊆ PII; `healthcare-pii-overlap.json` emit | open |
| Z.Z4-5 | high | Article 28 sub-processor authorisation chain | Z.Z4 records customer-side Article 28 contract URL + sub-processor authorisations | open |
| Z.Z4-6 | med | Data-subject rights workflow (DSAR) cross-reference | Z.Z4 emit cross-references LOOP-M (privacy package) DSAR procedure | open |
| Z.Z4-7 | med | Cross-border transfer mechanisms (SCCs, BCRs, adequacy decisions) | Per-engagement `transfer_mechanism` field + supplementary evidence | open |
| Z.Z4-8 | low | Data minimisation evidence (27018 control A.10.1 — PII minimisation) | Z.Z4 emit cross-references LOOP-M data-minimisation analysis | open |
| Z.Z4-9 | med | PII processor-vs-controller boundary disputes | Per-engagement `boundary_dispute_status: 'undisputed' | 'in_review' | 'resolved'` | open |
| Z.Z4-10 | med | Cookie / tracking-tech PII categorisation drift (CCPA Aug 2025 amendments) | Operator runbook documents the CCPA cookie-PII categorisation refresh; CHANGELOG entry per update | open |
| Z.Z4-11 | low | Children's data special category (COPPA + GDPR Art. 8) | Z.Z4 flags engagements with children's data; cross-references LOOP-U COPPA mapping | open |
| Z.Z4-12 | med | Right to erasure / right to portability evidence (GDPR Art. 17 + 20) | Per-engagement `erasure_capability_evidence` field; cross-references LOOP-M | open |
| Z.Z4-13 | low | Pseudonymisation vs anonymisation evidence | Catalog stores both definitions; per-engagement classification flag | open |
| Z.Z4-14 | low | PIA / DPIA cross-reference for high-risk processing | Z.Z4 cross-references LOOP-M DPIA emit; flag missing DPIA for high-risk processing | open |
| Z.Z4-15 | med | Confidentiality-of-customer-data leak in Z.Z4 emit | Restrictive ACLs; encrypted-mail recommendation; tracker audit log | open |

### Z.Z5 — ISO/IEC 27701 PIMS + ENISA EUCS Submission Package

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| Z.Z5-1 | high | EUCS Candidate → Delegated Act drift (cross-ref Z-X7) | `eucs_version` constant + REQUIRES-OPERATOR-INPUT on staleness | open |
| Z.Z5-2 | high | PIMS scope definition gap (cross-ref Z-X14) | Z.Z5 refuses to emit unless `pii_processing_activities.length > 0` + all scope fields populated | open |
| Z.Z5-3 | high | EUCS Substantial / High tier misidentification (cross-ref Z-X15) | Per-tier control-set diff + sovereignty-gap report + customer-data-classification rationale | open |
| Z.Z5-4 | high | PIMS GDPR Article alignment drift (cross-ref Z-X6) | `informative_only: true` flags + per-regulator overrides + dual-mapping summary | open |
| Z.Z5-5 | med | EUCS conformity-assessment-body (CAB) selection | Z.Z5 + tracker CAB registry; CAB must be ENISA-recognised once delegated act published | open |
| Z.Z5-6 | med | EUCS submission-package format change (post-delegated-act adoption) | Version-pinned package schema; CHANGELOG entry per format update; runbook tracks ENISA publications | open |
| Z.Z5-7 | high | EU sovereignty controls (High tier) gap for US-headquartered CSP | Sovereignty-gap report; runbook documents EU subsidiary + EU data residency + EU support staffing remediation paths | open |
| Z.Z5-8 | med | Multi-jurisdiction PIMS (CSP serves customers in multiple EU member states) | Per-jurisdiction PIMS scope override; tracker UI per-jurisdiction view | open |
| Z.Z5-9 | low | LOOP-Q Marketplace badge format drift (cross-ref Z-X31) | Additive JSON fields; backward-compat | open |
| Z.Z5-10 | med | PIMS Annex A (PII Controllers) vs Annex B (PII Processors) scope confusion | Per-engagement `pii_role` drives Annex selection; operator confirms in tracker UI | open |
| Z.Z5-11 | med | EUCS submission audit-trail tampering | Ed25519 + RFC 3161 signed package; hash-chain to prior submission; CI cron re-verify | open |
| Z.Z5-12 | med | EUCS High tier "evaluation by an EU-located CAB" requirement | Tracker CAB registry filters by EU-location for High-tier submissions; runbook documents | open |
| Z.Z5-13 | low | ENISA scheme amendments (post-adoption errata) | CHANGELOG entry per amendment; `eucs_version` constant + amendment-version sub-field | open |
| Z.Z5-14 | med | PIMS surveillance audit cadence (similar to ISMS) | `pims_last_emitted_at` + `pims_next_surveillance_audit_at` + tracker warnings | open |
| Z.Z5-15 | med | EUCS Substantial / High require continuous monitoring evidence — cross-reference LOOP-E.E1 | Z.Z5 reads ConMon outputs; refuses to emit High-tier package without recent ConMon evidence | open |

---

## External dependencies that may change

### ISO/IEC standards documents (paywalled; operator-supplied)

- **ISO/IEC 27001:2022** — purchasable at https://www.iso.org/standard/27001 — Annex A is the SoA control source. Editions: 2005, 2013, 2022; transition to 2022 deadline 2025-10-31.
- **ISO/IEC 27002:2022** — purchasable at https://www.iso.org/standard/75652.html — implementation guidance + attribute table for the 93 Annex A controls.
- **ISO/IEC 27017:2015** — purchasable at https://www.iso.org/standard/43757.html — cloud-specific extensions (7 new CLD controls + 37 augmented 27002 controls).
- **ISO/IEC 27018:2019** — purchasable at https://www.iso.org/standard/76559.html — PII processor controls.
- **ISO/IEC 27701:2019** — purchasable at https://www.iso.org/standard/71670.html — PIMS extension to 27001 + 27002.
- **ISO/IEC 17021-1:2015** — purchasable at https://www.iso.org/standard/61651.html — certification-body accreditation requirements.

### EU regulations + ENISA publications

- **Regulation 2019/881 (EU Cybersecurity Act)** — https://eur-lex.europa.eu/eli/reg/2019/881/oj — established the EU Cybersecurity Certification Framework. Stable since 2019.
- **ENISA EUCS Candidate Scheme** — https://www.enisa.europa.eu/topics/certification/cybersecurity-certification-eucs-cloud-services-scheme — current draft is v1.0.4 of March 2024; delegated act adoption expected 2026-2027.
- **EU Commission cyber-certification workplan** — https://digital-strategy.ec.europa.eu/en/policies/cybersecurity-certification-framework — tracks scheme adoption + workplan updates.

### IAF / National-AB references

- **IAF MLA** — https://iaf.nu/iaf-mla/ — Multilateral Recognition Arrangement signatory list.
- **IAF CertSearch** — https://www.iafcertsearch.org/ — global certificate registry searchable by CB / CSP / standard.
- **ANAB** — https://anab.ansi.org/ (US national AB).
- **UKAS** — https://www.ukas.com/ (UK national AB).
- **DAkkS** — https://www.dakks.de/ (German national AB).
- **COFRAC** — https://www.cofrac.fr/ (French national AB).
- **JIPDEC** — https://www.jipdec.or.jp/ (Japanese national AB).

### NIST references

- **NIST OLIR** — https://csrc.nist.gov/projects/olir — informative crosswalk between ISO/IEC 27001 + NIST 800-53.
- **NIST SP 800-53 Rev 5** — https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final — control catalog Z.Z1 cross-walks against.
- **NIST CSF v2.0** — https://www.nist.gov/cyberframework — referenced for informative cross-walk (out of LOOP-Z scope).

### Privacy regulators (for Z-X6 + Z-X13 references)

- **EDPB** — https://www.edpb.europa.eu/ — European Data Protection Board (GDPR co-ordinator).
- **CNIL** — https://www.cnil.fr/ (France).
- **BfDI** — https://www.bfdi.bund.de/ (Germany).
- **ICO** — https://ico.org.uk/ (UK).
- **AEPD** — https://www.aepd.es/ (Spain).
- **DPC** — https://www.dataprotection.ie/ (Ireland).
- **California AG / CPPA** — https://oag.ca.gov/ + https://cppa.ca.gov/ (CCPA enforcement).

### Future-loop scope (out of LOOP-Z but adjacent)

- **LOOP-ISMAP** — Japan ISMAP overlay. Future loop.
- **LOOP-IRAP** — Australia IRAP overlay. Future loop.
- **LOOP-GCLOUD** — UK G-Cloud overlay. Future loop.
- **LOOP-MTCS** — Singapore MTCS overlay. Future loop.
- **LOOP-CERT-IN** — India CERT-In overlay. Future loop.
- **LOOP-GCC-CAF** — Gulf Cooperation Council CAF overlay. Future loop.

---

## Resolved risks (historical)

(None yet. Resolved risks will move here with a `resolution_commit` + `resolution_note` field per row when slices ship.)

---

## Resume-from-fresh-session checklist

A fresh session opening this risks register MUST verify in order:

1. **Read `cloud-evidence/CLAUDE.md`** — REO standard + slice-completion directive.
2. **Read `docs/STATUS.md`** — find LOOP-Z status + the next Z slice marked `pending` in `Overall → Next priority`.
3. **Read `docs/loops/LOOP-Z-SPEC.md`** — mission + slice list + cross-loop dependencies.
4. **Read this file (`LOOP-Z-RISKS.md`)** in full — identify which cross-cutting risks (Z-X1..Z-X38) and per-slice risks apply to the current slice.
5. **Read `docs/slices/Z/Z.Z{N}.md`** for the target slice — frontmatter + sources + algorithm + tests + REQUIRES-OPERATOR-INPUT + Implementation log.
6. **Read companion risks registers** (LOOP-T-RISKS.md, LOOP-W-RISKS.md, LOOP-R-RISKS.md, LOOP-U-RISKS.md, LOOP-V-RISKS.md, LOOP-INV-S-RISKS.md, LOOP-B-RISKS.md) — identify cross-loop dependencies that affect the current slice.
7. **Read `docs/SLICE-COMPLETION-PROCEDURE.md`** — the 7-step procedure that MUST execute at slice completion.
8. **Read `docs/IMPLEMENTATION-LOG-TEMPLATE.md`** if not already read this session.
9. **Cross-reference `docs/DEPENDENCY-GRAPH.md`** to confirm the target Z slice is unblocked.
10. **Verify operator gate**: confirm `--international-equivalence` flag (or `CLOUD_EVIDENCE_INTERNATIONAL_EQUIVALENCE=1` env var) is set in the run config; LOOP-Z is conditional and only emits when the gate is set.
11. **Verify operator-supplied ISO source documents**: confirm `cloud-evidence/docs/sources/iso/` contains the operator's purchased PDFs for 27001:2022, 27002:2022, 27017:2015, 27018:2019, 27701:2019 with SHA-256 hashes matching `data/iso-source-document-hashes.json`. If any hash mismatches, file a `REQUIRES-OPERATOR-INPUT` + halt before slice work.
12. **Verify upstream loops' shipped artefacts**: LOOP-T's `out/ssdf-agency-submissions.json` for A.8.25 evidence; LOOP-W's `out/prohibited-vendors-screen-*.json` for A.5.19/20/23 evidence; LOOP-R's `out/pqc-migration-readiness-*.json` for A.8.24 evidence; LOOP-U's `out/loop-u-privacy-crosswalk.json` for Z.Z4 + Z.Z5; LOOP-INV-S's `out/inventory-coverage.json` for Z.Z3.
13. **Verify tracker-side prerequisites**: certification_body_registry seeded with at least one IAF-MLA-signatory CB; `iso-config.yaml` populated with `csp_name`, `iso_audit_scope`, `target_eucs_tier`, `dpa_regulator`.
14. **Begin slice work** under the REO standard.
15. **At slice completion**: execute the 8-step procedure (the 7-step from `SLICE-COMPLETION-PROCEDURE.md` + the Step 8 documented in the per-slice doc) — update STATUS.md, loop SPEC status table, per-slice doc frontmatter, append Implementation log, add CHANGELOG entry, push to origin/main, verify with `git log --oneline -3`. Only then is the slice closed.

> **Slice-completion directive (apply to EVERY Z slice completion)**
> 1. Update STATUS.md status row for the slice (commit hash, status -> 'done', last_updated).
> 2. Update LOOP-Z-SPEC.md §12 status table (commit hash, status -> 'done').
> 3. Update the per-slice doc's YAML frontmatter (`status: done`, `commit: <hash>`, `completed_date: <ISO>`, `last_updated: <ISO>`) + append final Implementation log row.
> 4. If the slice surfaced new risks during implementation, add them to this file in the same commit.
> 5. Append a CHANGELOG.md "Unreleased" entry (date, slice ID, summary, commit).
> 6. Commit with the slice ID in the subject line + Co-Authored-By trailer.
> 7. Push to origin/main.
> 8. Verify with `git log --oneline -3` that the commit landed before declaring the slice closed.
>
> Failure to complete steps 1-8 means the slice is NOT closed.
