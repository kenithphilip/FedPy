---
slice_id: V.V4
title: NIST SP 800-66 Rev 2 (Feb 2024) Crosswalk — HIPAA Security Rule → NIST RMF / 800-53 Rev 5 / CSF v2.0 risk-assessment + control-mapping appendix
loop: V
status: proposed
commit: TBD
completed_date: —
depends_on:
  - V.V1                                # BAA registry + CE→CSP responsibility overlay (provides the BA scope this crosswalk applies to)
  - LOOP-B                              # control benchmark (NIST 800-53 Rev 5 catalog already extracted by LOOP-B.B1; this slice reuses the catalog rather than re-extracting it)
  - LOOP-V-SPEC.md §2 / §4              # authoritative-sources index for HIPAA Security Rule + 800-66 Rev 2 + 800-53 Rev 5 + CSF v2.0 + 800-30 Rev 1
blocks: []
estimated_effort: medium (~5-7 working days for single implementer)
last_updated: 2026-06-07
applicable_conditional: true
condition: |
  Universal for any CSP that activates LOOP-V (i.e. operator-supplied
  `--hipaa-overlay` flag OR `CLOUD_EVIDENCE_HIPAA_OVERLAY` env var is set
  AND V.V1 has produced a non-empty BAA registry). SP 800-66 Rev 2 is the
  implementation-guidance bridge between the HIPAA Security Rule (45 CFR
  §§164.302–.318) and the NIST SP 800-53 Rev 5 control catalog + the
  NIST Risk Management Framework (SP 800-37 Rev 2) + the NIST
  Cybersecurity Framework v2.0 (CSWP 29, Feb 2024). Wherever LOOP-V is
  active, this crosswalk is the canonical mapping artefact that a 3PAO,
  HHS-OCR auditor, or CE customer expects to see in the audit package
  produced by V.V2 (§164.308 administrative-safeguard evidence pack) and
  the breach-risk narratives produced by V.V3.
trigger_flag: "--hipaa-800-66-r2"
trigger_env: CLOUD_EVIDENCE_HIPAA_800_66_R2
---

# V.V4 — NIST SP 800-66 Rev 2 (Feb 2024) Crosswalk

> V.V4 is the **control-mapping spine** of LOOP-V. V.V1 establishes
> *who* the Business Associate relationship is with; V.V2 collects the
> §164.308 administrative-safeguard evidence; V.V3 emits breach
> notifications when something goes wrong. V.V4 sits between V.V1 and
> V.V2: it answers the question *"for each HIPAA Security Rule standard
> and implementation specification, which NIST SP 800-53 Rev 5
> control(s) and which FedRAMP 20x Key Security Indicator(s) satisfy
> the HIPAA requirement, and which 800-30 Rev 1 risk-assessment task is
> the controlling determination?"* — which is exactly the structure
> NIST SP 800-66 Rev 2 Appendix F (the "Mappings of the HIPAA Security
> Rule Standards and Implementation Specifications to NIST
> Cybersecurity Framework Subcategories and SP 800-53, Revision 5
> Security Controls") prescribes. Without V.V4, the V.V2 audit package
> cannot demonstrate the §164.308(a)(1)(ii)(A) "risk-analysis"
> implementation specification, and the V.V3 4-factor breach risk
> assessment lacks the underlying control-attribution chain that an
> HHS-OCR auditor (post-CHSPSC, post-Anthem, post-Premera) now expects
> to see.

## 1. Mission

V.V4 ingests (a) the V.V1 BAA registry (canonical path
`out/baa-registry.json`), (b) the operator-supplied HIPAA-overlay
configuration (`hipaa-overlay-config.yaml`), (c) the LOOP-B.B1 NIST
SP 800-53 Rev 5 control catalog (canonical path
`data/nist-800-53-r5-catalog.json`), and (d) the canonical NIST SP
800-66 Rev 2 Appendix F crosswalk (extracted once, persisted as
`data/sp-800-66-r2-crosswalk.json`, hash-pinned to the 2026-06-07
SHA-256 of the NIST-published PDF). It then emits a **risk-assessment
+ control-mapping appendix** that is consumed by V.V2's audit-package
bundler and V.V3's breach-risk-assessment renderer.

The emit comprises FIVE artefacts, each signed (Ed25519, REO Rule 2.2)
and timestamped (RFC 3161, REO Rule 2.2):

1. `out/sp-800-66-r2-mapping.json` — canonical JSON envelope keyed by
   HIPAA standard (`164.308(a)(1)`) and implementation specification
   (`(ii)(A)` "Risk Analysis"), each row carrying the controlling
   NIST 800-53 Rev 5 control IDs, CSF v2.0 Subcategories, the
   "Required vs Addressable" classification (per §164.306(d)), the
   FedRAMP 20x KSI inheritance link, and the operator-supplied
   implementation status from V.V2.
2. `out/sp-800-66-r2-risk-assessment.json` — canonical JSON envelope
   keyed by Task ID from NIST SP 800-66 Rev 2 §5 (Tasks 1–11 of the
   Risk Assessment process, which Rev 2 derives from NIST SP 800-30
   Rev 1), each row recording the operator's threat-source enumeration,
   vulnerability inventory, likelihood determination, impact
   determination, and risk determination — with hash-chained
   append-only history (V-X8 mitigation: tamper-evident risk record).
3. `out/sp-800-66-r2-appendix.docx` — Word document rendering of the
   above two artefacts in the format consumable by an HHS-OCR audit
   submission (uses the OOXML/zip-store skeleton from LOOP-A.A4
   bundler).
4. `out/sp-800-66-r2-appendix.pdf` — PDF render produced via the same
   wkhtmltopdf-style pipeline LOOP-A uses for the SSP appendix.
5. `out/sp-800-66-r2-coverage.json` — coverage report (per LOOP-C.B4
   pattern) showing fill-rate per HIPAA standard, per implementation
   specification, per CSF Subcategory; used by REO G2
   (check-coverage-regression) and surfaced on the tracker LOOP-V
   dashboard.

V.V4 explicitly does NOT collect cloud-SDK evidence in real time
(that is LOOP-E's role); it consumes the already-collected KSI evidence
through the `ksi_evidence_link[]` indirection so the V.V4 envelope
remains a *mapping appendix*, not a redundant evidence collector. This
keeps V.V4 deterministic (the same inputs always produce the same
output) and aligns with the V-X17 mitigation (avoid double-counting
HIPAA-specific evidence vs FedRAMP 20x KSI evidence).

## 2. Authoritative sources

All quotes accessed 2026-06-07. Hyperlinks pinned to the canonical
publisher (NIST NVL Publications, eCFR, GPO, HHS) — never a mirror.

### 2.1 NIST SP 800-66 Revision 2 — "Implementing the HIPAA Security Rule: A Cybersecurity Resource Guide" (Feb 2024)

- Citation: Marron, J. (2024). *Implementing the HIPAA Security Rule:
  A Cybersecurity Resource Guide* (NIST SP 800-66 Rev. 2). National
  Institute of Standards and Technology.
  https://doi.org/10.6028/NIST.SP.800-66r2
- Canonical PDF:
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-66r2.pdf
- Date of access: 2026-06-07.
- SHA-256 of canonical PDF (pinned in
  `data/sp-800-66-r2-crosswalk.json:source_doc_sha256`): captured by
  the extractor at first run; bench-asserted on every CI run (V-X18
  mitigation: IPD-vs-Final detection).

VERBATIM EXCERPTS:

> "This publication provides guidance for regulated entities, also
>  known as covered entities and business associates in the Health
>  Insurance Portability and Accountability Act of 1996 (HIPAA)
>  Security Rule. The HIPAA Security Rule focuses on safeguarding
>  electronic protected health information (ePHI) held or maintained
>  by regulated entities." (SP 800-66r2, Abstract.)

> "Specifically, this publication includes (1) a brief overview of
>  the HIPAA Security Rule, (2) guidance for regulated entities on
>  assessing and managing risks to ePHI, (3) identifies typical
>  activities a regulated entity might consider implementing as part
>  of an information security program, and (4) lists additional
>  resources regulated entities may find useful in implementing the
>  Security Rule." (SP 800-66r2, Abstract.)

> "Appendix F provides a mapping of the HIPAA Security Rule standards
>  and implementation specifications to Cybersecurity Framework
>  Subcategories and SP 800-53, Revision 5 security controls."
>  (SP 800-66r2, Executive Summary.)

> "Conducting a risk assessment is foundational to the development
>  and implementation of an effective information security program
>  that protects ePHI." (SP 800-66r2, §5 Risk Assessment Guidance.)

> "This publication does not replace, modify, or supersede the HIPAA
>  Security Rule." (SP 800-66r2, §1.2 Scope.)

### 2.2 HIPAA Security Rule — 45 CFR Part 164 Subpart C (§§164.302–.318)

- Citation: 45 C.F.R. §§164.302–.318 (2024); originating rulemaking:
  Health Insurance Reform: Security Standards; Final Rule, 68 Fed. Reg.
  8334 (Feb. 20, 2003); subsequent amendments through the HITECH
  Omnibus Final Rule, 78 Fed. Reg. 5566 (Jan. 25, 2013).
- Canonical eCFR:
  https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C
- Date of access: 2026-06-07.

VERBATIM EXCERPTS:

> "(a) Standard: Security management process. Implement policies and
>  procedures to prevent, detect, contain, and correct security
>  violations. (1) Implementation specifications:
>  (i) Risk analysis (Required). Conduct an accurate and thorough
>  assessment of the potential risks and vulnerabilities to the
>  confidentiality, integrity, and availability of electronic
>  protected health information held by the covered entity or business
>  associate." (45 CFR §164.308(a)(1)(ii)(A).)

> "(ii) Risk management (Required). Implement security measures
>  sufficient to reduce risks and vulnerabilities to a reasonable and
>  appropriate level to comply with § 164.306(a)." (45 CFR
>  §164.308(a)(1)(ii)(B).)

> "(d) Implementation specifications. In this subpart:
>  (1) Implementation specifications are required or addressable. If
>  an implementation specification is required, the word 'Required'
>  appears in parentheses after the title of the implementation
>  specification. If an implementation specification is addressable,
>  the word 'Addressable' appears in parentheses after the title of
>  the implementation specification." (45 CFR §164.306(d).)

### 2.3 NIST SP 800-30 Revision 1 — "Guide for Conducting Risk Assessments" (Sept 2012)

- Citation: Joint Task Force Transformation Initiative. (2012). *Guide
  for Conducting Risk Assessments* (NIST SP 800-30 Rev. 1). NIST.
  https://doi.org/10.6028/NIST.SP.800-30r1
- Canonical PDF:
  https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf
- Date of access: 2026-06-07.

VERBATIM EXCERPT:

> "Risk assessments, carried out at all three tiers in the risk
>  management hierarchy, are part of an overall risk management
>  process — providing senior leaders/executives with the information
>  needed to determine appropriate courses of action in response to
>  identified risks." (SP 800-30 Rev 1, Executive Summary.)

> "The risk assessment process is composed of four steps: (i) prepare
>  for the assessment; (ii) conduct the assessment; (iii) communicate
>  the results of the assessment; and (iv) maintain the assessment."
>  (SP 800-30 Rev 1, §3.)

### 2.4 NIST SP 800-53 Revision 5 — "Security and Privacy Controls for Information Systems and Organizations" (Sept 2020 + errata Dec 2023)

- Citation: Joint Task Force. (2020, 2023 errata). *Security and Privacy
  Controls for Information Systems and Organizations* (NIST SP 800-53
  Rev. 5). NIST. https://doi.org/10.6028/NIST.SP.800-53r5
- Canonical PDF:
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
- Date of access: 2026-06-07.

VERBATIM EXCERPT:

> "This publication provides a catalog of security and privacy
>  controls for information systems and organizations to protect
>  organizational operations and assets, individuals, other
>  organizations, and the Nation from a diverse set of threats and
>  risks, including hostile attacks, human errors, natural disasters,
>  structural failures, foreign intelligence entities, and privacy
>  risks." (SP 800-53 Rev 5, Abstract.)

### 2.5 NIST Cybersecurity Framework (CSF) Version 2.0 — CSWP 29 (Feb 2024)

- Citation: NIST. (2024). *The NIST Cybersecurity Framework (CSF) 2.0*
  (NIST CSWP 29). https://doi.org/10.6028/NIST.CSWP.29
- Canonical PDF:
  https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf
- Date of access: 2026-06-07.

VERBATIM EXCERPT:

> "The CSF describes desired outcomes that any organization —
>  regardless of size, sector, or maturity — can understand, assess,
>  prioritize, and communicate. It does not prescribe how outcomes
>  should be achieved." (CSF 2.0, §1.)

> "The CSF Core is a taxonomy of high-level cybersecurity outcomes
>  that can help any organization manage its cybersecurity risks.
>  Its components are a hierarchy of Functions, Categories, and
>  Subcategories that detail each outcome." (CSF 2.0, §2.1.)

### 2.6 NIST SP 800-37 Revision 2 — "Risk Management Framework for Information Systems and Organizations" (Dec 2018)

- Citation: Joint Task Force. (2018). *Risk Management Framework for
  Information Systems and Organizations: A System Life Cycle Approach
  for Security and Privacy* (NIST SP 800-37 Rev. 2). NIST.
  https://doi.org/10.6028/NIST.SP.800-37r2
- Canonical PDF:
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-37r2.pdf
- Date of access: 2026-06-07.

VERBATIM EXCERPT:

> "The RMF provides a disciplined, structured, and flexible process
>  for managing security and privacy risk that includes information
>  security categorization; control selection, implementation, and
>  assessment; system and common control authorizations; and
>  continuous monitoring." (SP 800-37 Rev 2, Abstract.)

### 2.7 HHS HIPAA Security Rule NPRM (Jan 2025) — "HIPAA Security Rule to Strengthen the Cybersecurity of Electronic Protected Health Information"

- Citation: HHS-OCR, *HIPAA Security Rule to Strengthen the
  Cybersecurity of Electronic Protected Health Information*, Proposed
  Rule, 90 Fed. Reg. 898 (Jan. 6, 2025).
- Canonical Federal Register URL:
  https://www.federalregister.gov/documents/2025/01/06/2024-30983/hipaa-security-rule-to-strengthen-the-cybersecurity-of-electronic-protected-health-information
- Date of access: 2026-06-07.

VERBATIM EXCERPT:

> "The Department of Health and Human Services (HHS or 'Department'),
>  through the Office for Civil Rights (OCR), is issuing this notice
>  of proposed rulemaking (NPRM) to modify the Security Standards for
>  the Protection of Electronic Protected Health Information
>  ('Security Rule') under the Health Insurance Portability and
>  Accountability Act of 1996 (HIPAA), as amended by the Health
>  Information Technology for Economic and Clinical Health (HITECH)
>  Act of 2009." (90 FR 898, Summary section.)

## 3. Scope

### 3.1 In scope (V.V4 SHIPS)

- Extraction of the **complete** NIST SP 800-66 Rev 2 Appendix F
  crosswalk into a canonical JSON form (one row per HIPAA standard ×
  implementation specification × NIST 800-53 Rev 5 control × CSF v2.0
  Subcategory tuple). The Rev 2 Appendix F mapping covers every
  Security Rule standard and implementation specification in
  §§164.308 / 164.310 / 164.312 / 164.314 / 164.316, plus the
  general-requirements references in §164.306.
- Risk-assessment task structure derived from SP 800-66 Rev 2 §5,
  which itself derives from SP 800-30 Rev 1 §3. V.V4 ships Tasks 1–11
  (Prepare → Identify threat sources → Identify threat events →
  Identify vulnerabilities → Determine likelihood → Determine impact
  → Determine risk → Communicate results → Maintain assessment →
  Review applicable implementation specifications → Document the
  decisions).
- Inheritance link to FedRAMP 20x KSI evidence (V-X17 mitigation).
- Append-only hash-chain (V-X8 mitigation) for the
  `sp-800-66-r2-risk-assessment.json` envelope so an HHS-OCR auditor
  cannot be deceived by a retroactive edit.
- "Required vs Addressable" classification per §164.306(d). The
  classification governs the V.V2 audit-package bundler's "required
  evidence missing" vs "addressable evidence with rationale" gating.
- Hash-pinning of the source PDF (V-X18 mitigation).
- Operator-overridable catalog version constant
  (`nist_800_66_version`) so a future Rev 3 / NPRM-aligned revision
  (V-X19 mitigation) is a configuration change, not a code change.
- Coverage report consumable by REO G2 (check-coverage-regression).
- Cross-loop integration with V.V2 (administrative-safeguard
  evidence pack) and V.V3 (breach-risk renderer) via the canonical
  envelope path.

### 3.2 Out of scope (V.V4 DOES NOT SHIP)

- Real-time cloud SDK evidence collection (LOOP-E owns this; V.V4
  consumes already-collected evidence through `ksi_evidence_link[]`).
- HITRUST CSF mapping — V.V2 owns the HITRUST overlay; V.V4's
  envelope deliberately omits HITRUST columns to avoid V-X22
  inaccuracies leaking into the 800-66 Rev 2 attestation chain.
- The HHS-OCR Audit Protocol mapping itself — that lives in V.V2 (the
  audit-package bundler). V.V4 only references the audit protocol via
  a per-row `ocr_audit_protocol_section: text` field that V.V2 reads.
- 800-66 Rev 1 (Oct 2008, withdrawn). V.V4 refuses to load Rev 1
  data (V-X16 mitigation); a separate legacy file
  `data/hipaa-800-66-rev1-legacy.json` is the only place Rev 1
  references may live, and it is flagged `deprecated: true`.
- Automated penalty-tier classification (V-X27 mitigation; REO Rule
  1.1 + 1.10 forbid auto-judging the operator's penalty tier).
- HIPAA Privacy Rule (45 CFR Part 164 Subpart E) — out of scope for
  LOOP-V's Security Rule focus; the Privacy Rule is referenced from
  LOOP-M.M1 (privacy package extension) and partially from LOOP-U
  (privacy frameworks crosswalk).

## 4. Inputs

```ts
// cloud-evidence/core/sp-800-66-r2-mapper.ts

/**
 * V.V4 reads V.V1's BAA registry to determine which CE relationships
 * are in scope (the crosswalk only emits attestations for CEs the
 * operator has an active BAA with).
 */
export interface BaaRegistryRow {
  ce_id: string;                          // canonical CE id (e.g. "ce.example-health-system")
  ce_legal_name: string;
  baa_executed_at: string;                // ISO 8601 date
  template_era:
    | 'pre-omnibus-2013'
    | 'post-omnibus-2013'
    | 'post-2025-nprm'
    | 'unknown';
  termination_status:
    | 'active'
    | 'expired-phi-returned'
    | 'expired-phi-destroyed'
    | 'expired-phi-retained-with-protections';
  ce_organizational_form:
    | 'single-ce'
    | 'hybrid-entity'
    | 'ohca-member'
    | 'affiliated-ce';
}

/**
 * V.V4 reads the operator's overlay config to pick the catalog
 * version. Default is "rev2-2024-02" (V-X19 mitigation).
 */
export interface HipaaOverlayConfig {
  nist_800_66_version: 'rev2-2024-02' | 'rev3-pending' | (string & {});
  sunset_rev1_attestations_after?: string; // ISO date; default 2026-12-31 (V-X16)
  inheritance: {
    use_fedramp_ksi_evidence: boolean;     // default true (V-X17 mitigation)
    ksi_manifest_path: string;             // canonical 'out/ksi-evidence-manifest.json'
  };
  risk_assessment: {
    threat_source_catalog: string;         // path to operator-supplied threat catalog (else SP 800-30 App D defaults)
    vulnerability_inventory_path: string;  // path to LOOP-E.E2 vuln-scan output
  };
}

/**
 * V.V4 reads the LOOP-B.B1 NIST 800-53 Rev 5 catalog.
 */
export interface Nist80053Control {
  control_id: string;                      // e.g. "AC-2", "AC-2(1)", "SC-13"
  control_title: string;
  control_family: string;                  // e.g. "AC", "SC"
  baseline_low: boolean;
  baseline_moderate: boolean;
  baseline_high: boolean;
  catalog_version: 'rev5-2020-09' | 'rev5-errata-2023-12' | (string & {});
}

/**
 * V.V4 reads the FedRAMP 20x KSI manifest (LOOP-E output) so the
 * mapping can record `ksi_evidence_link[]` per HIPAA row.
 */
export interface KsiEvidenceManifestRow {
  ksi_id: string;                          // e.g. "IAM-MFA"
  evidence_envelope_path: string;          // 'out/iam-mfa-evidence.json'
  signed_at: string;                       // ISO 8601 timestamp
  signer_key_id: string;                   // Ed25519 public-key fingerprint
  rfc3161_token_path: string;              // 'out/iam-mfa-evidence.tsr'
}
```

## 5. Outputs

### 5.1 `out/sp-800-66-r2-mapping.json` schema

```json
{
  "envelope_version": "1.0.0",
  "generated_at": "2026-06-07T17:34:21Z",
  "generator": "cloud-evidence/core/sp-800-66-r2-mapper.ts",
  "source_doc": {
    "publisher": "NIST",
    "title": "NIST SP 800-66 Rev 2 — Implementing the HIPAA Security Rule",
    "url": "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-66r2.pdf",
    "sha256": "<pinned at first extraction>",
    "version_label": "rev2-2024-02",
    "appendix": "F"
  },
  "baa_registry_ref": "out/baa-registry.json#sha256=<...>",
  "rows": [
    {
      "hipaa_standard": "164.308(a)(1)",
      "hipaa_standard_title": "Security Management Process",
      "implementation_spec": "(ii)(A)",
      "implementation_spec_title": "Risk Analysis",
      "required_or_addressable": "required",
      "csf_v2_subcategories": ["GV.RM-01", "ID.RA-01", "ID.RA-03", "ID.RA-04", "ID.RA-05"],
      "sp_800_53_r5_controls": ["RA-3", "RA-3(1)", "PM-9", "PM-28"],
      "ksi_evidence_link": [
        { "ksi_id": "AFR-PVA", "envelope_path": "out/afr-pva-evidence.json" }
      ],
      "operator_implementation_status": "implemented",
      "operator_narrative_ref": "tracker:hipaa.164.308.a.1.ii.A:narrative_v3",
      "ocr_audit_protocol_section": "§164.308(a)(1)(ii)(A)",
      "crosswalk_source": "nist-800-66r2-appendix-f",
      "crosswalk_confidence": "high",
      "last_reviewed_at": "2026-06-07T17:34:21Z"
    }
  ],
  "signature": {
    "alg": "ed25519",
    "key_id": "<fingerprint>",
    "signature_b64": "<...>",
    "signed_over": "rows[]"
  },
  "timestamp": {
    "rfc3161_token_path": "out/sp-800-66-r2-mapping.tsr",
    "tsa_url": "<operator-configured>"
  }
}
```

### 5.2 `out/sp-800-66-r2-risk-assessment.json` schema

```json
{
  "envelope_version": "1.0.0",
  "task_set": "nist-sp-800-66r2-section-5",
  "tasks": [
    {
      "task_id": "T1",
      "task_title": "Prepare for the assessment",
      "sp_800_30_r1_ref": "§3.1",
      "version_seq": 1,
      "prior_version_hash": null,
      "saved_at": "2026-06-07T17:34:21Z",
      "saved_by": "user:privacy-officer@example.com",
      "narrative": "<min 200 chars>",
      "evidence_urls": ["tracker:hipaa.ra.t1.evidence#v3"],
      "change_reason": null
    }
  ],
  "risk_determination": {
    "method": "qualitative",
    "scale": ["very-low", "low", "moderate", "high", "very-high"],
    "overall_risk_level": "moderate",
    "overall_risk_narrative": "<min 500 chars>"
  },
  "signature": { "alg": "ed25519", "key_id": "<fingerprint>", "signature_b64": "<...>" },
  "timestamp": { "rfc3161_token_path": "out/sp-800-66-r2-risk-assessment.tsr" }
}
```

### 5.3 `out/sp-800-66-r2-coverage.json` schema

```json
{
  "envelope_version": "1.0.0",
  "by_standard": [
    { "standard": "164.308(a)(1)", "rows_total": 4, "rows_filled": 4, "fill_rate": 1.0 }
  ],
  "by_subpart": [
    { "subpart": "164.308", "rows_total": 22, "rows_filled": 22, "fill_rate": 1.0 },
    { "subpart": "164.310", "rows_total": 8, "rows_filled": 8, "fill_rate": 1.0 },
    { "subpart": "164.312", "rows_total": 10, "rows_filled": 10, "fill_rate": 1.0 },
    { "subpart": "164.314", "rows_total": 4, "rows_filled": 4, "fill_rate": 1.0 },
    { "subpart": "164.316", "rows_total": 4, "rows_filled": 4, "fill_rate": 1.0 }
  ],
  "by_csf_subcategory": [
    { "subcategory": "GV.RM-01", "rows_total": 1, "rows_filled": 1 }
  ]
}
```

### 5.4 `.docx` / `.pdf` layout

- Title page: "NIST SP 800-66 Rev 2 Crosswalk Appendix — <CSP Name> —
  Generated <ISO date> — Signed by <Ed25519 key fingerprint> —
  RFC 3161 timestamp <token id>".
- §1: BAA scope summary (cross-reference V.V1).
- §2: Mapping table (one row per
  `hipaa_standard × implementation_spec`).
- §3: Risk assessment narrative (Tasks 1–11).
- §4: Coverage summary.
- §5: Signature + timestamp evidence (key id, fingerprint, RFC 3161
  token id, TSA URL).

## 6. Algorithm / Steps

```
INPUT:
  baa_registry         (V.V1 output)
  overlay_config       (operator-supplied yaml)
  nist_800_53_catalog  (LOOP-B.B1 output)
  ksi_manifest         (LOOP-E output, if inheritance.use_fedramp_ksi_evidence)

STEP 1 — Load crosswalk catalog.
  catalog := loadJson('data/sp-800-66-r2-crosswalk.json')
  assert catalog.source_doc_sha256 != null
  assert catalog.version_label == overlay_config.nist_800_66_version
        OR overlay_config explicitly overrides
  if catalog.version_label starts with 'rev1' AND today > sunset:
    THROW E_CATALOG_REV1_SUNSET (V-X16 mitigation)

STEP 2 — Verify BAA scope is non-empty.
  active_baas := baa_registry.rows.filter(r => r.termination_status == 'active')
  if active_baas.length == 0:
    EMIT requires_operator_input('baa-registry-empty')
    EXIT 0 (no crosswalk needed if no BAs are active)

STEP 3 — Build mapping rows.
  rows := []
  for each (hipaa_standard, impl_spec) in catalog.entries:
    row := {
      hipaa_standard, impl_spec,
      required_or_addressable: catalog.lookup_classification(...),
      csf_v2_subcategories: catalog.lookup_csf(...),
      sp_800_53_r5_controls: catalog.lookup_53r5(...),
      ksi_evidence_link: [],
      operator_implementation_status: 'unknown',
      operator_narrative_ref: null,
    }
    for each control in row.sp_800_53_r5_controls:
      assert control in nist_800_53_catalog          # deterministic; no fuzz
    if overlay_config.inheritance.use_fedramp_ksi_evidence:
      for each ksi in ksi_manifest.rows:
        if ksi_overlaps_control(ksi, row.sp_800_53_r5_controls):
          row.ksi_evidence_link.push({ ksi_id, envelope_path })
    row.operator_implementation_status :=
      tracker.lookup('hipaa.' + hipaa_standard + impl_spec + '.status') ?? 'unknown'
    row.operator_narrative_ref :=
      tracker.lookup('hipaa.' + hipaa_standard + impl_spec + '.narrative_ref')
    rows.push(row)

STEP 4 — Compute coverage.
  coverage := computeCoverage(rows)
  writeJson('out/sp-800-66-r2-coverage.json', coverage)

STEP 5 — Sign + timestamp the mapping envelope.
  mapping := { envelope_version, generated_at, source_doc, rows }
  sig := ed25519Sign(canonicalize(mapping))
  tsr := rfc3161Stamp(canonicalize(mapping))
  writeJson('out/sp-800-66-r2-mapping.json', { ...mapping, signature: sig })
  writeBinary('out/sp-800-66-r2-mapping.tsr', tsr)

STEP 6 — Build the risk-assessment envelope (append-only).
  prior := readJsonOrNull('out/sp-800-66-r2-risk-assessment.json')
  next_seq := (prior?.tasks[-1]?.version_seq ?? 0) + 1
  prior_hash := prior ? sha256(canonicalize(prior)) : null
  tasks := buildRiskAssessmentTasks(overlay_config)
  assert tasks.every(t => t.narrative.length >= 200)   # V-X8
  envelope := {
    envelope_version, task_set, tasks,
    risk_determination: { method: 'qualitative', overall_risk_level, overall_risk_narrative },
  }
  envelope.tasks[-1].prior_version_hash = prior_hash
  envelope.tasks[-1].version_seq = next_seq
  sig := ed25519Sign(canonicalize(envelope))
  tsr := rfc3161Stamp(canonicalize(envelope))
  writeJson('out/sp-800-66-r2-risk-assessment.json', { ...envelope, signature: sig })

STEP 7 — Render .docx + .pdf.
  renderDocx('out/sp-800-66-r2-appendix.docx', mapping, riskAssessment, coverage)
  renderPdf('out/sp-800-66-r2-appendix.pdf', mapping, riskAssessment, coverage)

STEP 8 — Emit provenance entry per REO Rule 1.7 / G3 check-provenance.
  emitProvenance({
    family: 'hipaa-800-66r2',
    fields_added: ['hipaa_standard', 'implementation_spec', 'required_or_addressable', 'csf_v2_subcategories', 'sp_800_53_r5_controls', 'ksi_evidence_link'],
    coverage_source: 'nist-800-66r2-appendix-f + tracker + ksi-manifest',
  })
```

## 7. Files to create / modify

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sp-800-66-r2-mapper.ts` (NEW) — Steps 1–5, 7–8 of §6.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sp-800-66-r2-risk-assessment.ts` (NEW) — Step 6 (append-only hash chain).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/sp-800-66-r2-crosswalk.json` (NEW) — extracted from the NIST SP 800-66 Rev 2 Appendix F PDF; hash-pinned.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/scripts/extract-sp-800-66-r2-crosswalk.mjs` (NEW) — one-shot extractor that reads the PDF, writes the JSON, asserts the SHA-256.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/sp-800-66-r2-mapper.test.ts` (NEW) — 15+ tests per §8.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/scripts/orchestrator.ts` (MODIFY) — add `--hipaa-800-66-r2` flag wiring; pass through to mapper.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/STATUS.md` (MODIFY at completion) — V.V4 row → done.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/LOOP-V-SPEC.md` (MODIFY at completion) — V.V4 status table row.
- `/Users/kenith.philip/FedRAMP 20x/CHANGELOG.md` (MODIFY at completion) — V.V4 entry.

## 8. Test specifications

| id   | scenario                                                                                 | fixture path                                                                                 | expected                                                                                                  | acceptance                                |
| ---- | ---------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| T1   | Empty BAA registry → coverage:skipped + zero-row mapping                                 | `tests/fixtures/v-v4/baa-empty.json`                                                         | `out/sp-800-66-r2-mapping.json.rows.length == 0`; `requires_operator_input: baa-registry-empty` emitted    | exact match                                |
| T2   | Single active BAA, post-omnibus-2013 template → full mapping emitted                     | `tests/fixtures/v-v4/baa-single-active.json`                                                 | rows.length == catalog.entries.length; every row signed                                                   | exact match                                |
| T3   | Catalog hash mismatch → mapper throws E_CATALOG_HASH_MISMATCH (V-X18)                    | `tests/fixtures/v-v4/catalog-bad-hash.json`                                                  | throws E_CATALOG_HASH_MISMATCH                                                                            | exception type + message                   |
| T4   | Catalog rev1 + sunset passed → throws E_CATALOG_REV1_SUNSET (V-X16)                      | `tests/fixtures/v-v4/catalog-rev1.json`                                                      | throws E_CATALOG_REV1_SUNSET                                                                              | exception type + message                   |
| T5   | Required impl-spec missing operator narrative → coverage fill < 1.0                       | `tests/fixtures/v-v4/tracker-missing-narrative.json`                                         | coverage.by_standard["164.308(a)(1)"].fill_rate < 1.0                                                     | numeric assertion                          |
| T6   | Addressable impl-spec missing → still emits row but rationale required                   | `tests/fixtures/v-v4/tracker-addressable-missing.json`                                       | row.operator_implementation_status == 'addressable-with-rationale'                                        | string equality                            |
| T7   | KSI evidence inheritance link populated when KSI overlaps 800-53 control (V-X17)         | `tests/fixtures/v-v4/ksi-manifest-overlap.json`                                              | row.ksi_evidence_link contains AFR-PVA when row.sp_800_53_r5_controls includes PM-9                       | array contains assertion                   |
| T8   | Risk-assessment Task 1–11 narratives all >= 200 chars → no failure                       | `tests/fixtures/v-v4/risk-assessment-good.json`                                              | assessment envelope signed; coverage 11/11                                                                | numeric + signature verify                 |
| T9   | Risk-assessment Task narrative < 200 chars → throws E_NARRATIVE_TOO_SHORT (V-X8)         | `tests/fixtures/v-v4/risk-assessment-short-narrative.json`                                   | throws E_NARRATIVE_TOO_SHORT                                                                              | exception type                             |
| T10  | Append-only chain: writing a new version computes correct prior_version_hash             | seed via two consecutive mapper runs on same fixture                                          | run2.tasks[-1].prior_version_hash == sha256(canonicalize(run1.envelope))                                  | byte-equal hash                            |
| T11  | Hybrid-entity BAA → notification routing component-level (V-X4)                          | `tests/fixtures/v-v4/baa-hybrid-entity.json`                                                 | mapping rows carry `ce_organizational_form: 'hybrid-entity'` reference                                    | string equality                            |
| T12  | Pre-omnibus BAA → mapping emits but adds `requires_amendment: true` flag (V-X2)          | `tests/fixtures/v-v4/baa-pre-omnibus.json`                                                   | envelope.warnings[] contains "baa-pre-omnibus-amendment-required"                                         | array contains assertion                   |
| T13  | NIST 800-53 control referenced in catalog but absent from catalog file → fail loudly      | `tests/fixtures/v-v4/missing-control.json`                                                   | throws E_53R5_CONTROL_NOT_FOUND with control id                                                           | exception message contains control id      |
| T14  | Deterministic output: same inputs → byte-identical signature payload (signature differs)  | run mapper twice with frozen clock                                                            | sha256(envelope without signature/timestamp) is byte-equal across runs                                    | byte-equal                                 |
| T15  | RFC 3161 timestamp token written to disk with correct path                               | full mapper run                                                                              | `out/sp-800-66-r2-mapping.tsr` exists; openssl ts -verify returns success                                 | exit code 0                                |
| T16  | Ed25519 signature verifies against the key id in envelope                                 | full mapper run                                                                              | ed25519Verify(envelope.signature, canonicalize(envelope.rows)) == true                                    | boolean                                    |
| T17  | Coverage envelope written to `out/sp-800-66-r2-coverage.json` and rises vs main baseline | full mapper run + REO G2 baseline diff                                                       | check-coverage-regression returns exit 0                                                                  | exit code 0                                |
| T18  | Provenance entry emitted for every new emit-field per REO Rule 1.7                       | full mapper run                                                                              | check-provenance returns exit 0; all fields in §5.1 covered                                               | exit code 0                                |
| T19  | Multi-CE BAA registry (10 active CEs, 2 expired) → mapping emitted only for actives      | `tests/fixtures/v-v4/baa-multi-ce.json`                                                      | active CEs reflected in mapping.baa_registry_ref; expired not                                             | structural assertion                       |
| T20  | NPRM-aligned future config (overlay_config.nist_800_66_version == 'rev3-pending')         | `tests/fixtures/v-v4/overlay-nprm-pending.json`                                               | emits warning "nist-800-66-rev3-not-yet-final"; falls back to rev2-2024-02 catalog (V-X19)                | warning emitted; rev2 catalog used         |

## 9. Risks

### R-V4-1 — Rev 1 / Rev 2 / NPRM-aligned future-Rev drift

- Description: A future Rev 3 of SP 800-66 (likely released after the
  Jan 2025 NPRM finalizes) will materially alter Appendix F. V.V4
  pinned to Rev 2 (Feb 2024) drifts the moment the NPRM finalizes.
  Risk surfaced in V-X16 + V-X19; mitigation here is the operator-
  overridable version constant + a sunset enforcement on Rev 1 attestations.
- Severity: med (planned drift, not silent).
- Mitigation: `overlay_config.nist_800_66_version` operator-overridable;
  `data/sp-800-66-r2-crosswalk.json` carries `version_label`;
  `sunset_rev1_attestations_after` default 2026-12-31; runbook adds
  quarterly NIST publications watch.

### R-V4-2 — Appendix F transcription error

- Description: NIST SP 800-66 Rev 2 Appendix F is a 30+ page mapping
  table. A transcription error (wrong CSF Subcategory, missing 800-53
  control row, wrong "Required vs Addressable" classification) would
  cause downstream V.V2 evidence to attribute to the wrong control.
- Severity: high (correctness of HIPAA audit defence).
- Mitigation: `scripts/extract-sp-800-66-r2-crosswalk.mjs` is a
  pdf-based extractor that asserts the source doc SHA-256 before
  emitting JSON. Test T13 cross-checks every referenced 800-53
  control against the LOOP-B.B1 catalog. CHANGELOG entry per
  extraction lists row count and asserts == NIST-published total.

### R-V4-3 — Inheritance double-counting (V-X17 recurrence)

- Description: If V.V4 declares a KSI as "inherited" but the V.V2
  audit-package bundler ALSO emits the underlying KSI evidence again,
  the operator effort doubles and HHS-OCR auditors see two
  inconsistent narratives.
- Severity: med.
- Mitigation: V.V4's `ksi_evidence_link[]` is the SOLE indirection;
  V.V2 reads through V.V4 for HIPAA-attributable evidence rather than
  re-emitting KSI envelopes. Integration test (T7) asserts the link
  populates correctly; coverage REO G2 baseline pins the no-duplicate
  invariant.

### R-V4-4 — Append-only chain corruption (V-X8 recurrence)

- Description: If the hash chain on
  `out/sp-800-66-r2-risk-assessment.json` is corrupted (manual edit,
  filesystem error, partial write), an HHS-OCR auditor reviewing the
  trail will find the gap and lose trust in the entire package.
- Severity: high.
- Mitigation: T10 asserts `prior_version_hash` correctness;
  `core/sp-800-66-r2-risk-assessment.ts` uses an atomic
  rename-on-write pattern (write to temp, fsync, rename); the
  envelope file is read in full on every write to compute the
  prior hash. CHANGELOG entry per change documents the version
  bump.

### R-V4-5 — Operator-supplied threat-source catalog leakage

- Description: If the operator supplies a threat-source catalog
  containing sensitive operational details (insider threat models,
  vulnerability inventory), and V.V4 echoes it into
  `out/sp-800-66-r2-risk-assessment.json`, the artefact may be too
  sensitive to share with the CE customer or post on a marketplace.
- Severity: med.
- Mitigation: The risk-assessment envelope is classified as
  internal-only by default; the V.V2 bundler redacts threat-source
  details when emitting the HHS-OCR audit package vs the CE-customer
  CRM package. Tracker UI marks the envelope "internal — do not
  share" until operator unchecks the redaction.

## 10. Open questions

- O1: Should V.V4 emit a CSF v2.0 Profile artefact in addition to the
  Appendix F mapping? The CSF v2.0 introduces Organizational Profiles
  (Current + Target) as a formal artefact. Decision deferred to LOOP-V
  iteration 2; for now V.V4 lists Subcategory references but does not
  emit a full Profile.
- O2: Should V.V4 attempt to auto-classify HIPAA standards as
  applicable to the CSP's specific service offerings (e.g. a storage-
  only CSP may not implement §164.310 physical safeguards directly)?
  REO Rule 1.7 + 1.10 push toward operator-controlled classification;
  V.V4 records `operator_applicability: enum('applicable',
  'inherited-from-provider', 'not-applicable-with-rationale')` per
  row in the v1.1.0 schema.
- O3: Should V.V4 emit OSCAL Component artefact representations of
  the mapping so other OSCAL tooling can consume it? Pending LOOP-Q
  marketplace integration; deferred.
- O4: When the Jan 2025 NPRM finalizes, the "Required vs Addressable"
  distinction may collapse (the NPRM proposes making most
  Addressable specs Required). V.V4's schema treats the distinction
  as a per-row column so a future rev can mark all rows Required
  without a schema change. Should the v1.1.0 envelope add a deprecation
  flag for the column? Decision pending NPRM finalization.

## 11. REQUIRES-OPERATOR-INPUT

| field name                                           | type                                                                                       | validator                                                                                        | UI location                                                       | failure mode if missing                                                                                                |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `overlay_config.nist_800_66_version`                 | string                                                                                     | matches `^rev[2-9](-\d{4}-\d{2})?$` or `rev3-pending`                                              | tracker → LOOP-V → Overlay Config tab                              | mapper defaults to `rev2-2024-02`; emits warning `coverage:default-catalog-version-used`                                |
| `overlay_config.inheritance.ksi_manifest_path`       | string (path)                                                                              | exists on disk + is signed                                                                       | tracker → LOOP-V → Inheritance tab                                 | inheritance skipped; rows emit with empty `ksi_evidence_link[]`; coverage report flags `inheritance-skipped`            |
| operator_narrative_ref per row                       | tracker reference                                                                          | non-empty; resolvable through `core/tracker.ts`                                                  | tracker → HIPAA Crosswalk → row detail                             | row stays `operator_implementation_status: 'unknown'`; coverage fill rate drops                                         |
| risk_assessment.threat_source_catalog                | path (yaml/json)                                                                           | parseable; rows match SP 800-30 App D structure                                                  | tracker → LOOP-V → Risk Assessment tab                             | mapper falls back to SP 800-30 App D defaults; emits `coverage:default-threat-catalog-used`                              |
| risk_assessment.vulnerability_inventory_path         | path                                                                                       | LOOP-E.E2 vuln-scan JSON envelope; signed                                                        | tracker → LOOP-V → Risk Assessment tab                             | mapper throws `E_VULN_INVENTORY_MISSING` (V-X8 evidence chain requires this); slice fails REO G3                         |
| `risk_determination.overall_risk_narrative`          | string                                                                                     | >= 500 chars                                                                                     | tracker → LOOP-V → Risk Assessment → Determination subtab          | mapper throws `E_NARRATIVE_TOO_SHORT`                                                                                  |
| `signer_key_id` (Ed25519)                            | hex string                                                                                 | matches `^[0-9a-f]{64}$`; key file present                                                       | RUNBOOK key management                                             | mapper throws `E_SIGNING_KEY_MISSING`                                                                                  |
| `tsa_url` (RFC 3161)                                 | URL                                                                                        | reachable; returns valid TSA cert                                                                | RUNBOOK timestamping                                               | mapper throws `E_TSA_UNREACHABLE`                                                                                      |

## 12. Implementation log

| date       | session   | action                                                | commit | notes |
| ---------- | --------- | ----------------------------------------------------- | ------ | ----- |
| 2026-06-07 | wf-uvxyz  | spec proposed — Specification authored via FedPy workflow | TBD    | —     |

## 13. Completion checklist

Per `docs/SLICE-COMPLETION-PROCEDURE.md`. The 7-step procedure is
quoted verbatim below; Step 8 is the LOOP-V-specific extension.

> ### Step 1 — Verify the slice is REO-compliant
> Run all three guardrails. They MUST all be green:
> ```bash
> cd cloud-evidence
> npm run typecheck      # no errors
> npm test               # 100% passing (counts must increase by the slice's new tests)
> npm run check:reo      # G1+G2+G3 all green
> ```

> ### Step 2 — Update STATUS.md
> Open `cloud-evidence/docs/STATUS.md` and for the slice that just shipped:
> - Change `Status` column from `pending` to `done`
> - Fill `Commit` with the PENDING commit's short hash (you'll know it after step 5)
> - Fill `Date` with today's date (ISO format YYYY-MM-DD)
> - If this was the last slice in a loop, change the loop's title section to indicate "(COMPLETE)"
> - Update the "Overall" section: increment loops-complete, change last-shipped, update next-priority

> ### Step 3 — Update the loop's spec doc
> Open `cloud-evidence/docs/loops/LOOP-X-SPEC.md` (where X is your loop letter).
> Find the "Status tracking" section table.
> For your slice row: status=done, commit=<hash>, date=<ISO>.

> ### Step 4 — Add CHANGELOG entry
> Open `/Users/kenith.philip/FedRAMP 20x/CHANGELOG.md`.
> Add a new entry at the TOP of "Unreleased":
>
> ### Added — LOOP-X.XN: <Slice title>
> <2-3 paragraphs describing what shipped, module names, file paths, verification counts (typecheck clean, NNN/NNN tests passing, npm run check:reo returns 0).>

> ### Step 5 — Commit
> ```bash
> cd /Users/kenith.philip/FedRAMP\ 20x
> git add cloud-evidence/<modified files> cloud-evidence/docs/STATUS.md cloud-evidence/docs/loops/LOOP-X-SPEC.md CHANGELOG.md
> git commit -m "LOOP-X.XN: <slice title>
> <detailed commit message describing the slice>
> Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
> ```

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

> ### Step 7 — Push
> ```bash
> git push origin main
> ```

> Step 8: After commit lands, append/update the slice row in STATUS.md (status -> done, commit hash, last_updated); update the loop SPEC status table; append a CHANGELOG entry; push to origin/main; verify with 'git log --oneline -3'. Only THEN is the slice closed.

## 14. Resume-from-fresh-session checklist

If you are picking up V.V4 cold in a new Claude session, read these
files in order before touching code:

1. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/CLAUDE.md` —
   REO standard.
2. This file (`docs/slices/V/V.V4.md`) — frontmatter + §6 algorithm +
   §11 REQUIRES-OPERATOR-INPUT + §12 implementation log to see what
   prior sessions did.
3. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/LOOP-V-RISKS.md`
   — cross-cutting risks V-X16 through V-X19 (the 800-66 Rev 2
   crosswalk drift family) and V-X8 (append-only tamper-evidence).
4. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/slices/V/V.V1.md`
   (when authored) — BAA registry contract this slice consumes.
5. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/STATUS.md` —
   confirm V.V4 is still the next-priority slice in LOOP-V and not
   blocked by a sibling slice.
6. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`
   — re-read the 7-step procedure before shipping.

Then execute §6 step-by-step, updating §12 implementation log at every
meaningful milestone (commit boundary, test failure, research question
answered, risk discovered).
