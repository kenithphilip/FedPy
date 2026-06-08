---
slice_id: Z.Z4
title: ISO/IEC 27018:2019 PII Processor Controls — public-cloud PII processing extension
loop: Z
status: proposed
commit: TBD
completed_date: —
depends_on:
  - Z.Z1                                # ISO/IEC 27001:2022 Annex A control catalog (foundational)
  - LOOP-U.U1                           # Privacy frameworks catalog — GDPR / CCPA / CPRA / state PII regimes
  - LOOP-U.U2                           # Per-datastore applicability matrix
  - LOOP-A.A5                           # Ed25519 + RFC 3161 signing
  - LOOP-A.A4                           # Submission bundler
blocks:
  - Z.Z5                                # ISO 27701 PIMS extends 27001 + 27018
estimated_effort: medium (~5-7 working days for single implementer)
last_updated: 2026-06-08
applicable_conditional: false
condition: |
  Slice Z.Z4 is conditional. It activates when the operator's
  org-profile.yaml declares both:
    seeks_iso_27018: true
    AND
    processes_pii_as_processor: true (LOOP-U.U2 applicability matrix
    surfaces at least one datastore where the CSP is a PII processor
    on behalf of a customer-controller).
  ISO/IEC 27018:2019 is a code of practice published by ISO for
  protection of Personally Identifiable Information in public clouds
  acting as PII processors. It extends ISO/IEC 27002:2022 with cloud-
  and PII-processor-specific implementation guidance and provides a
  set of additional control extensions (the CLD.* and PII-specific
  augmentations).
trigger_flag: "--iso-27018"
trigger_env: CLOUD_EVIDENCE_ISO_27018
---

# Z.Z4 — ISO/IEC 27018:2019 PII Processor Controls

> This slice is part of LOOP-Z (International Equivalence). Z.Z4
> implements the public-cloud-PII-processor extension to the ISO/IEC
> 27001:2022 ISMS by mapping ISO/IEC 27018:2019 controls onto the
> existing Z.Z1 Annex A catalog and the LOOP-U privacy-frameworks
> catalog, emitting a per-control satisfaction matrix + a signed
> 27018 attestation appendix .docx via the LOOP-A.A5 signing pipeline.
>
> Authority: `cloud-evidence/CLAUDE.md` (REO standard) governs every
> step. Every emitted byte traces to a real public ISO source, a real
> LOOP-U applicability decision, a real cloud-inventory query, or
> operator-supplied configuration.

## 1. Mission

Z.Z4 operationalizes the ISO/IEC 27018:2019 code of practice for CSPs
who process Personally Identifiable Information on behalf of customer
controllers. It is a **bridge slice** — it does not introduce a new
statutory regime (GDPR Article 28 and CCPA §1798.140(ah) Service
Provider obligations already live in LOOP-U). Instead, it produces
the audit-grade artifact needed for an ISO/IEC 27018-aligned
certification: a per-control satisfaction matrix that crosswalks 27018
PII-processor controls to the ISO/IEC 27001:2022 Annex A baseline,
LOOP-U privacy framework rights, and the operator-supplied evidence
that demonstrates conformance.

The slice runs **only when both** (a) the operator's `org-profile.yaml`
declares `seeks_iso_27018: true` AND (b) LOOP-U.U2's applicability
matrix surfaces at least one datastore for which the CSP is acting as
a PII processor on behalf of a customer controller. In a typical
multi-tenant SaaS deployment, this is the common case (the SaaS tenant
is the controller; the CSP is the processor); in a single-tenant or
enterprise-owned deployment the slice may not activate.

The 27018 controls are organized into three groups:
(a) The full ISO/IEC 27002:2022 control set, with cloud-and-PII-
    processor-specific implementation guidance per 27018 §6-§18;
(b) The PII-processor extension controls in 27018 §6.x augmenting the
    27002 baseline; and
(c) The cloud-specific extension controls inherited from ISO/IEC
    27017:2015 where applicable (already in Z.Z3 scope; cross-
    referenced).

Z.Z4 emits both the canonical-JSON satisfaction matrix and a
human-readable .docx attestation appendix that a customer controller
(or its 3PAO / ISO certification body) reads as evidence of cloud-
processor conformance.

## 2. Authoritative sources

Access date for this slice: **2026-06-08**.

### 2.1 ISO/IEC 27018:2019

**Pin:** https://www.iso.org/standard/76559.html
**Authority:** ISO/IEC 27018:2019(en), "Information technology —
Security techniques — Code of practice for protection of personally
identifiable information (PII) in public clouds acting as PII
processors," published January 2019. Supersedes ISO/IEC 27018:2014.

The ISO/IEC 27018 introduction states:

> "This document establishes commonly accepted control objectives,
> controls and guidelines for implementing measures to protect
> Personally Identifiable Information (PII) in line with the privacy
> principles in ISO/IEC 29100 for the public cloud computing
> environment.
>
> In particular, this document specifies guidelines based on ISO/IEC
> 27002, taking into consideration the regulatory requirements for the
> protection of PII which might be applicable within the context of
> the information security risk environment(s) of a provider of public
> cloud services."
> — ISO/IEC 27018:2019, Introduction (paraphrased — ISO content is
> license-restricted; specific clause numbers and structural elements
> are public).

> "This document is applicable to all types and sizes of
> organizations, including public and private companies, government
> entities and not-for-profit organizations, which provide
> information processing services as PII processors via cloud
> computing under contract to other organizations."
> — ISO/IEC 27018:2019, §1 Scope (paraphrased).

The 27018 structure parallels ISO/IEC 27002:2022 §5-§8 themes
(Organizational, People, Physical, Technological) and adds
cloud-PII-processor-specific augmentations to each control where
applicable. The standard also includes Annex A "Public cloud PII
processor extended control set" which enumerates additional controls
specific to the cloud-PII-processor role.

### 2.2 ISO/IEC 27001:2022

**Pin:** https://www.iso.org/standard/27001
**Authority:** ISO/IEC 27001:2022(en), "Information security,
cybersecurity and privacy protection — Information security
management systems — Requirements," published October 2022.

ISO/IEC 27001:2022 is the foundational ISMS standard. ISO/IEC 27018
extends it with cloud-PII-processor-specific guidance.

Annex A of ISO/IEC 27001:2022 enumerates 93 controls organized into
4 themes:
- §5 Organizational controls (37 controls)
- §6 People controls (8 controls)
- §7 Physical controls (14 controls)
- §8 Technological controls (34 controls)

(Z.Z1 catalog ingests these 93 controls in detail; Z.Z4 references
Z.Z1's catalog as the foundational baseline.)

### 2.3 ISO/IEC 27002:2022

**Pin:** https://www.iso.org/standard/27002
**Authority:** ISO/IEC 27002:2022(en), "Information security,
cybersecurity and privacy protection — Information security controls,"
published February 2022.

ISO/IEC 27002:2022 is the implementation-guidance companion to
27001:2022. For each of the 93 Annex A controls, 27002:2022 provides
purpose, implementation guidance, and other information. ISO/IEC 27018
augments specific 27002 controls with cloud-PII-processor-specific
guidance.

### 2.4 ISO/IEC 27701:2019

**Pin:** https://www.iso.org/standard/71670.html
**Authority:** ISO/IEC 27701:2019(en), "Security techniques —
Extension to ISO/IEC 27001 and ISO/IEC 27002 for privacy information
management — Requirements and guidelines," published August 2019.

ISO/IEC 27701 establishes a Privacy Information Management System
(PIMS) as an extension to the 27001 ISMS. 27701 incorporates 27018
controls for the PII-processor role. (Z.Z5 implements the PIMS layer;
Z.Z4 is the prerequisite cloud-PII-processor extension.)

### 2.5 GDPR Article 28 — Processor obligations

**Pin:** https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679

> "Article 28 — Processor
> 1. Where processing is to be carried out on behalf of a controller,
> the controller shall use only processors providing sufficient
> guarantees to implement appropriate technical and organisational
> measures in such a manner that processing will meet the requirements
> of this Regulation and ensure the protection of the rights of the
> data subject.
> 3. Processing by a processor shall be governed by a contract or
> other legal act under Union or Member State law, that is binding on
> the processor with regard to the controller and that sets out the
> subject-matter and duration of the processing, the nature and
> purpose of the processing, the type of personal data and categories
> of data subjects and the obligations and rights of the controller."
> — GDPR Article 28(1), (3)

**Operational consequence:** GDPR Article 28 establishes the legal
basis for the cloud-PII-processor role; ISO/IEC 27018 establishes the
operational controls. Z.Z4 cross-walks 27018 controls to GDPR Article
28(3) obligations and emits the mapping in the canonical-JSON
satisfaction matrix.

### 2.6 CCPA — Service Provider definition Cal Civ Code §1798.140(ah)

**Pin:** https://leginfo.legislature.ca.gov/faces/codes_displayText.xhtml?division=3.&part=4.&lawCode=CIV&title=1.81.5

> "Cal Civ Code §1798.140(ah) 'Service provider' means a person that
> processes personal information on behalf of a business and that
> receives from or on behalf of the business a consumer's personal
> information for a business purpose pursuant to a written contract,
> provided that the contract prohibits the person from:
> (1) Selling or sharing the personal information.
> (2) Retaining, using, or disclosing the personal information for any
> purpose other than for the business purposes specified in the
> contract for the business ..."
> — Cal Civ Code §1798.140(ah)

**Operational consequence:** Z.Z4 surfaces the Service Provider
contractual restrictions in the matrix overlay; emits a compliance
attestation that a customer controller can attach to its CCPA Service
Provider agreement.

### 2.7 NIST OLIR ISO 27001 → NIST 800-53 mapping

**Pin:** https://csrc.nist.gov/projects/olir
**Authority:** National Online Informative Reference (OLIR) program;
maintains crosswalks between cybersecurity / privacy reference
documents.

The OLIR ISO/IEC 27001:2022 → NIST 800-53 Rev 5 crosswalk is
informative (not authoritative). Z.Z4 uses it as the secondary
crosswalk source; the primary is the LOOP-B (FedRAMP control
benchmark) crosswalk.

### 2.8 ISO/IEC 29100:2024 — Privacy framework reference

**Pin:** https://www.iso.org/standard/85938.html
**Authority:** ISO/IEC 29100:2024(en), "Information technology —
Security techniques — Privacy framework," 3rd ed., published 2024.

ISO/IEC 29100 establishes the 11 privacy principles that underpin
27018 (Consent and choice; Purpose legitimacy and specification;
Collection limitation; Data minimization; Use, retention and
disclosure limitation; Accuracy and quality; Openness, transparency
and notice; Individual participation and access; Accountability;
Information security; Privacy compliance).

## 3. Scope

### 3.1 In scope
- Per-control satisfaction matrix emission for every 27018 control
  applicable to the CSP-as-PII-processor role.
- Cross-walk overlay: 27018 control ↔ 27001:2022 Annex A control ↔
  LOOP-U privacy-framework right (GDPR / CCPA / CPRA / state PII) ↔
  NIST 800-53 Rev 5 control via LOOP-B + OLIR.
- Signed .docx attestation appendix the customer controller's
  certification body consumes.
- Operator-supplied evidence pointers per control (signed-BAA file,
  contract clauses, technical-evidence envelopes from V.V1 / V.V2 / etc.).
- Tracker DB row per emitted attestation with operator-signed accept.

### 3.2 Out of scope
- ISO certification audit execution itself (the customer engages a
  conformity-assessment body; Z.Z4 emits artifacts they consume).
- ISO/IEC 27001:2022 ISMS implementation (that is Z.Z1 + Z.Z2 + LOOP-B).
- ISO/IEC 27701:2019 PIMS implementation (Z.Z5).
- PII controller controls (Z.Z4 is processor-side only; the customer
  controller implements controller-side controls themselves).
- HIPAA Security Rule (LOOP-V); PHI-as-PII overlap is cross-referenced
  via LOOP-U mapping but not duplicated.
- Federal Tax Information / Criminal Justice Information (LOOP-Y).

## 4. Inputs

```typescript
// From Z.Z1
interface ISO27001AnnexAEntry {
  control_id: string;       // e.g. "5.1", "8.10"
  theme: 'organizational' | 'people' | 'physical' | 'technological';
  title: string;
  source_clause: string;    // ISO 27001:2022 Annex A reference
  source_url: string;
  fedramp_moderate_mapping: string[];  // e.g. ["AC-1", "AC-2"]
}

// From LOOP-U.U1 + U.U2
interface PrivacyFrameworkApplicability {
  datastore_id: string;
  ccpa_applicable: boolean;
  cpra_applicable: boolean;
  gdpr_applicable: boolean;
  uk_gdpr_applicable: boolean;
  ferpa_applicable: boolean;
  glba_applicable: boolean;
  state_pii_jurisdictions: string[];   // ['CA','NY','VA','CO','TX',...]
}

// From operator
interface OperatorConfig {
  seeks_iso_27018: boolean;
  processes_pii_as_processor: boolean;
  ccpa_service_provider_contracts: Array<{
    controller_name: string;
    signed_date: string;
    contract_file_ref: string;
    scope_pii_categories: string[];
  }>;
  gdpr_article_28_contracts: Array<{
    controller_name: string;
    signed_date: string;
    contract_file_ref: string;
    scope_pii_categories: string[];
    sub_processors: string[];
  }>;
  signing_officer: { name: string; title: string; email: string; ed25519_key_ref: string; };
}

// From V.V1 (cross-loop)
interface HIPAACatalogReference {
  control_id: string;   // e.g. "164.308(a)(1)(ii)(A)"
  related_27018_controls: string[];
}
```

### 4.1 Z.Z4 input bundle (composed by the orchestrator)

The Z.Z4 module receives a single bundle (signed via LOOP-A.A5
envelope wrapping):

```typescript
interface ZZ4InputBundle {
  z_z1_catalog: ISO27001AnnexAEntry[];
  loop_u_applicability: PrivacyFrameworkApplicability[];
  operator_config: OperatorConfig;
  v_v1_phi_overlap: HIPAACatalogReference[];   // optional, only if LOOP-V active
  inventory_pii_tagged_datastores: string[];   // from LOOP-INV-S
  run_timestamp: string;                       // ISO 8601
  run_id: string;                              // for evidence-trail
}
```

## 5. Outputs

### 5.1 Canonical-JSON satisfaction matrix

```typescript
interface ZZ4SatisfactionMatrix {
  schema_version: '1.0.0';
  run_id: string;
  emitted_at: string;
  operator_signing_officer: { name: string; title: string; email: string; };
  ed25519_signature: string;
  rfc3161_tst: string;
  matrix: Array<{
    iso_27018_control: string;      // e.g. "A.10.1" (extended control set)
    iso_27001_2022_annex_a: string; // e.g. "8.10" (cross-walk)
    iso_27002_2022_clause: string;  // e.g. "8.10 Information deletion"
    cross_walk: {
      ccpa_service_provider: string[];   // e.g. ["§1798.140(ah)(1)", "§1798.140(ah)(2)"]
      gdpr_article_28: string[];          // e.g. ["28(3)(a)"]
      nist_800_53_r5: string[];           // e.g. ["MP-6", "SI-12"]
      fedramp_moderate: string[];         // e.g. ["MP-6", "SI-12"]
    };
    satisfaction: 'satisfied' | 'partially-satisfied' | 'not-satisfied' | 'not-applicable';
    evidence: Array<{
      source: 'cloud-inventory' | 'v.v1-hipaa' | 'operator-attestation' | 'baa-contract' | 'gdpr-art-28-contract';
      ref: string;
      ed25519_signature?: string;
    }>;
    operator_notes: string;
  }>;
  summary: {
    total_controls: number;
    satisfied: number;
    partially_satisfied: number;
    not_satisfied: number;
    not_applicable: number;
  };
}
```

### 5.2 ISO/IEC 27018:2019 attestation appendix (.docx via OOXML/zip-store)

The .docx is emitted by `cloud-evidence/core/iso-27018-attestation-docx.ts`
(OOXML / zip-store pattern, no dependencies). Sections:
- Cover page (CSP name, customer-controller name, run_id, signing-officer block)
- Executive summary (total controls, % satisfied)
- Per-control table (control_id | iso_27001_2022_ref | satisfaction | evidence summary | operator notes)
- Cross-walk appendix (GDPR Art 28 + CCPA Service Provider + NIST 800-53 R5 + FedRAMP Moderate)
- Operator-supplied signature placeholder

## 6. Algorithm / Steps

```
1. Validate trigger:
   if (!operator_config.seeks_iso_27018) {
     emit("Z.Z4 skipped — seeks_iso_27018 false");
     return EXIT_SKIPPED;
   }
   if (!operator_config.processes_pii_as_processor) {
     emit("Z.Z4 skipped — CSP is not acting as PII processor on any datastore");
     return EXIT_SKIPPED;
   }
   if (!loop_u_applicability.some(d => d.ccpa_applicable || d.gdpr_applicable || d.uk_gdpr_applicable)) {
     warn("Z.Z4 has no applicable PII framework in scope; emitting empty matrix");
   }

2. Load Z.Z1 catalog (93 Annex A controls).

3. Load 27018 control set from data/iso-27018-controls.json (canonical
   JSON of controls + cross-walks).

4. For each 27018 control:
   a. Look up Z.Z1 base control (27001:2022 Annex A reference).
   b. Look up LOOP-B FedRAMP Moderate baseline mapping.
   c. Look up NIST OLIR informative crosswalk.
   d. Determine applicability:
      - Always applicable if processes_pii_as_processor: true
      - Conditionally applicable per PII-category subset
   e. Gather evidence pointers:
      - From inventory_pii_tagged_datastores
      - From v_v1_phi_overlap (if LOOP-V active)
      - From operator-supplied BAA / Article 28 contracts
   f. Compute satisfaction:
      - 'satisfied' iff all evidence pointers present + verifying
      - 'partially-satisfied' iff some evidence missing
      - 'not-satisfied' iff no evidence + control is required
      - 'not-applicable' iff no in-scope datastore

5. Compose ZZ4SatisfactionMatrix.

6. Canonicalize per RFC 8785.

7. Sign via LOOP-A.A5: Ed25519 signature + RFC 3161 TST.

8. Emit canonical JSON to cloud-evidence/out/<run_id>/iso-27018/
   satisfaction-matrix.json.

9. Render .docx via core/iso-27018-attestation-docx.ts.

10. Persist to tracker DB:
    INSERT INTO iso_27018_attestations
      (run_id, emitted_at, customer_controller, total_controls,
       satisfied_count, signed_envelope_ref);

11. Register in submission-bundle catalogue via LOOP-A.A4.

12. If any control 'not-satisfied' AND required, emit POA&M item via
    LOOP-A.A1.

13. Return EXIT_SUCCESS with summary.
```

## 7. Files to create / modify

| File | Purpose |
|------|---------|
| `cloud-evidence/core/iso-27018-mapper.ts` | Main module: applicability + cross-walk + satisfaction computation |
| `cloud-evidence/core/iso-27018-attestation-docx.ts` | OOXML/zip-store .docx emitter |
| `cloud-evidence/core/iso-27018-canonical-json.ts` | RFC 8785 canonicalization helper for the matrix |
| `cloud-evidence/data/iso-27018-controls.json` | Canonical JSON of 27018 controls + cross-walks (Z.Z1 ↔ LOOP-B ↔ OLIR ↔ LOOP-U ↔ GDPR Art 28) |
| `tracker/db/migrations/0057_iso_27018_attestations.sql` | CREATE TABLE iso_27018_attestations |
| `tracker/server/routes/iso-27018.ts` | API endpoints: GET list, GET by id, GET evidence pointers |
| `tracker/ui/iso-27018-status-pane.tsx` | UI for matrix + tier-selector |
| `test/iso-27018-mapper.test.ts` | Per-control + integration tests (>= 18) |
| `test/iso-27018-attestation-docx.test.ts` | .docx rendering + signature tests |

## 8. Test specifications

| id    | scenario                                                                | fixture                              | expected                                                          | acceptance |
|-------|-------------------------------------------------------------------------|--------------------------------------|-------------------------------------------------------------------|------------|
| ZZ4-01 | trigger validation: seeks_iso_27018 false                              | operator_config with flag off        | EXIT_SKIPPED; tracker DB has no new row                          | A          |
| ZZ4-02 | trigger validation: not a PII processor                                | flag on, processor flag off          | EXIT_SKIPPED                                                      | A          |
| ZZ4-03 | empty PII applicability matrix                                          | flag on, U.U2 returns 0 rows         | warning emitted; empty matrix; tracker DB row with summary.total_controls: 0 | A |
| ZZ4-04 | full 27018 control set against GDPR-only datastore                     | inventory with EU-tagged datastore   | matrix has 100% applicable; ccpa rows: not-applicable             | A          |
| ZZ4-05 | full 27018 control set against CCPA-only datastore                     | CA-tagged inventory                  | gdpr rows: not-applicable; ccpa rows: applicable                  | A          |
| ZZ4-06 | mixed CCPA + GDPR datastores                                            | inventory with both tags             | matrix rows differ per datastore-applicability                    | A          |
| ZZ4-07 | LOOP-V PHI overlap (V.V1 active)                                       | v_v1_phi_overlap present             | v.v1-hipaa evidence pointers appear in matrix                     | A          |
| ZZ4-08 | data-erasure obligation traceability                                    | operator's data-erasure procedure ref | A.10.1 (extended) → 27001 Annex A 8.10 → CCPA right-to-delete   | A          |
| ZZ4-09 | data-portability obligation                                             | operator's data-export procedure ref | A.10.2 (extended) → GDPR Article 20                              | A          |
| ZZ4-10 | sub-processor transparency obligation                                   | operator's sub-processor list        | A.7.2 (extended) → GDPR Article 28(2) — operator notification    | A          |
| ZZ4-11 | international transfer addendum                                         | operator declares no cross-border    | A.7.3 (extended) is not-applicable                                | A          |
| ZZ4-12 | satisfaction computation: all evidence present                          | all controls have valid evidence     | summary.satisfied = total_controls                                | A          |
| ZZ4-13 | satisfaction computation: missing evidence                              | operator omits one BAA               | one control 'not-satisfied'; POA&M item emitted via A.A1          | A          |
| ZZ4-14 | satisfaction computation: partial evidence                              | technical evidence present; contract missing | 'partially-satisfied'                                         | A          |
| ZZ4-15 | canonical-JSON output verifies against RFC 8785                         | sample matrix                        | re-canonicalization yields identical bytes                        | A          |
| ZZ4-16 | Ed25519 signature verifies                                              | sample matrix + key                  | signature verifies with public key                                | A          |
| ZZ4-17 | RFC 3161 TST attaches                                                   | sample matrix                        | TST validates against issuing TSA                                 | A          |
| ZZ4-18 | .docx renders + opens in MS Word                                       | sample matrix                        | docx unzips to valid OOXML; opens in Word; sections render        | A          |
| ZZ4-19 | tracker DB row written                                                  | post-emission                        | iso_27018_attestations has new row with correct fields            | A          |
| ZZ4-20 | submission-bundle catalogue registered                                  | post-emission                        | A.A4 catalogue surfaces matrix.json + attestation.docx            | A          |

## 9. Risks

| Risk | Severity | Mitigation |
|---|---|---|
| ISO/IEC 27018:2019 supersession (e.g., 27018:2027 published) | Medium | Catalog version + checksum in `data/iso-27018-controls.json`; CI guardrail blocks unsigned updates |
| Cross-walk drift between Z.Z1 (27001:2022) and Z.Z4 (27018:2019) | Medium | Z.Z1 cross-walk file is single source of truth; Z.Z4 validates against it on every run |
| GDPR Art 28 contract metadata stale | High | Operator confirmation required at each emission; expiration tracking via tracker DB |
| CCPA Service Provider contract scope mismatch | High | Operator-supplied scope_pii_categories validated against inventory tags; warning if mismatch |
| 27018 vs 27701 scope confusion (operator declares both) | Medium | Z.Z4 emits the PII-processor extension; Z.Z5 emits the PIMS extension; both can co-exist |
| NIST OLIR informative mapping treated as authoritative | Low | Crosswalk metadata flags `mapping_authority: 'olir-informative'` |
| Customer controller rejects attestation appendix on .docx-format grounds | Low | OOXML/zip-store output is Word-compatible; tested in INT-V-18 |
| Audit body (certification body) requires different evidence format | Medium | Operator can re-run with `--iso-27018-output-format=<alt>` flag |

## 10. Open questions

1. **27018:2024 (anticipated)** — ISO has periodic 5-year revision
   cycles. Should Z.Z4 anticipate a 27018:2024 update? Currently
   targeting the 27018:2019 stable edition.
2. **EU EUCS overlap** — ENISA EUCS (Z.Z5) maps 27018 controls.
   Should Z.Z4 emit EUCS-aligned envelopes in parallel?
3. **Customer-controller-specific addenda** — Many customer
   controllers have specific addenda to the standard 27018 attestation.
   Should the .docx template be operator-extensible?
4. **PII-processor sub-processor chain depth** — How many levels of
   sub-processor transparency are required by GDPR Art 28(4)?
5. **LOOP-V PHI overlap** — When LOOP-V is active and a datastore
   carries both PHI + PII, should Z.Z4 emit a PHI-specific 27018
   subset?

## 11. REQUIRES-OPERATOR-INPUT fields

| Field | Type | Validator | UI location | Failure mode if missing |
|---|---|---|---|---|
| `seeks_iso_27018` | bool | required-false default | Settings > Compliance > International | Z.Z4 skipped; warning logged |
| `processes_pii_as_processor` | bool | required-false default | Settings > Compliance > International | Z.Z4 skipped if false even if seeks_iso_27018 true |
| `in_scope_pii_categories` | array<string> | enum: ['identifier','contact','financial','health','minor','government-id','biometric','behavioral','location','communications','content'] | Settings > Compliance > PII Categories | validation error |
| `transfer_mechanism_declaration` | enum: ['scc','bcr','adequacy','derogation','idta','none'] | required when GDPR or UK GDPR in U.U2 matrix | Settings > Compliance > Transfer | LOOP-U.U4 not run |
| `sub_processor_list` | array<{name, country, services, signed_subprocessor_agreement_ref}> | required when GDPR in U.U2 matrix | Settings > Compliance > Sub-Processors | matrix marks A.7.2 'partially-satisfied' |
| `ccpa_service_provider_contracts` | array<{controller_name, signed_date, contract_file_ref, scope_pii_categories}> | required when CCPA in U.U2 matrix | Settings > Compliance > CCPA Contracts | matrix marks Service Provider controls 'not-satisfied' |
| `gdpr_article_28_contracts` | array<{controller_name, signed_date, contract_file_ref, scope, sub_processors}> | required when GDPR in U.U2 matrix | Settings > Compliance > GDPR Article 28 | matrix marks Art 28 controls 'not-satisfied' |
| `signing_officer` | object{name,title,email,ed25519_key_ref} | non-empty; key validated at startup | Settings > Compliance > Signing | Z.Z4 cannot emit signed envelope; aborts |

## 12. Implementation log slot

| Date       | Session            | Action                                            | Commit | Notes |
|------------|--------------------|----------------------------------------------------|--------|-------|
| 2026-06-08 | wuvxyz-Z-Z4-inline | Specification authored via inline-Write fallback (workflow content filter) | TBD    | —     |

(Future rows appended at implementation time per SLICE-COMPLETION-PROCEDURE.md.)

## 13. Completion checklist

This slice closes when (and only when) ALL of the following are true.

The 7-step procedure from `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`:

1. `npm run typecheck` passes.
2. `npm test -- z-z4` passes (all >=20 tests green).
3. `npm run check:reo` passes (no stubs, no fake data in production paths).
4. `cloud-evidence/docs/STATUS.md` row for Z.Z4 updated (status: done; commit hash; last_updated: <ISO date>).
5. `cloud-evidence/docs/loops/LOOP-Z-SPEC.md` §3 + §12 status table updated (status: done; commit hash).
6. `cloud-evidence/CHANGELOG.md` entry appended (date; slice ID `Z.Z4`; summary; commit hash).
7. `git commit -m "Z.Z4: ISO/IEC 27018:2019 PII Processor Controls\n\n<details>\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"` then `git push origin main`.

**Step 8 (LOOP-V- / LOOP-U-style closeout):** After the commit lands,
verify with `git log --oneline -3` that the commit is at `origin/main`.
If any new permanent reference document was created (e.g., a Z.Z4
runbook), add it to `cloud-evidence/CLAUDE.md` reading list. Only THEN
is Z.Z4 closed.

This directive is the Z.Z4-scope amplification of the
`cloud-evidence/CLAUDE.md` "Slice-completion directive" block at line
~230 (added in commit `f0cfed7`, the LOOP-W batch).

Failure to complete steps 1-8 means Z.Z4 is NOT closed.

---

**END OF Z.Z4.md**
