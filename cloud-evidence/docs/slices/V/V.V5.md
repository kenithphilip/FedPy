---
slice_id: V.V5
title: HITRUST CSF v11.2.0 Inheritance Mapping (e1 / i1 / r2 tier-aware emitter)
loop: V
status: proposed
commit: TBD
completed_date: —
depends_on:
  - V.V1                                # BAA registry + CE→CSP responsibility overlay
  - LOOP-B                              # composite risk + POA&M cascade (LOOP-B.B1 risk scoring, LOOP-B.B2 POA&M emitter)
  - LOOP-A.A1                           # OSCAL POA&M emitter (for inheritance-gap → POA&M cascade)
  - LOOP-A.A4                           # Submission bundler (new HITRUST roles registered)
  - LOOP-A.A5                           # Ed25519 + RFC 3161 signing (envelope provenance)
  - LOOP-E                              # KSI evidence envelopes (the FedRAMP-Moderate evidence corpus that gets inherited up)
  - "core/envelope.ts"                  # signed envelope reader
  - "core/sign.ts"                      # Ed25519 corporate signing
  - "core/timestamp.ts"                 # RFC 3161 timestamping
  - "tracker DB (existing)"             # `hitrust_evidence` + `hitrust_inheritance_runs` tables
blocks: []
estimated_effort: medium (~5-7 working days for single implementer)
last_updated: 2026-06-08
applicable_conditional: true
condition: When the CSP seeks HITRUST certification in addition to FedRAMP Moderate / HIPAA Security Rule. Activated by `--hitrust-overlay` flag (or `CLOUD_EVIDENCE_HITRUST_OVERLAY` env var). MUST also have `--hipaa-overlay` active because V.V5 ingests V.V1 BAA registry and assumes the CSP is operating under HIPAA scope. The flag is OFF by default — non-HITRUST CSPs incur no LOOP-V.V5 cost.
trigger_flag: "--hitrust-overlay"
trigger_env: CLOUD_EVIDENCE_HITRUST_OVERLAY
---

# V.V5 — HITRUST CSF v11.2.0 Inheritance Mapping (e1 / i1 / r2 tier-aware emitter)

> V.V5 is the **HITRUST overlay** slice. It is REPURPOSED from the prior
> "NPRM-finalization-readiness pack" placeholder under the LOOP-V audit:
> the FOURTH-PASS audit (2026-06-07) identified HITRUST inheritance
> mapping as the higher-priority missing artefact for CSPs that already
> hold or are pursuing HITRUST certification on top of FedRAMP Moderate.
> NPRM readiness work is folded into LOOP-V's cross-cutting risk register
> (V-X19) and re-emerges if/when the HHS NPRM finalizes (expected
> late-2026 to mid-2027). The repurpose preserves the slice numbering
> (V.V5) so STATUS.md and the LOOP-V dependency graph do not have to
> renumber.
>
> This per-slice doc carries the same level of rigor as W.W3.md (the
> 1958-line gold-standard per-slice doc). HITRUST CSF v11.2.0 is the
> pinned target version per the operator directive; v11.3.0 (released
> 2024-04-16) and v11.4.0 carry incremental changes documented in §2.6
> and §10 (Q4). The mapping is operator-overridable but the default
> ships pinned to v11.2.0 because that is the version most CSPs
> currently hold certification under and against which downstream BAAs
> reference.

## 1. Mission

V.V5 ingests the FedRAMP-Moderate Key Security Indicator (KSI) evidence
envelopes already collected by LOOP-E (and routed through LOOP-B for
composite risk scoring), joins them to the V.V1 Business Associate
Agreement registry, and emits a **HITRUST CSF v11.2.0 inheritance
evidence envelope** that maps the CSP's existing FedRAMP-Moderate
controls onto HITRUST CSF requirement statements at the operator-
selected assessment tier (e1, i1, or r2). The envelope is the data
backbone for two distinct downstream consumers:

1. **The CSP's external HITRUST assessor** (e.g. Coalfire, Schellman,
   A-LIGN, BARR Advisory) — the assessor uses the envelope as primary
   evidence input during the validated assessment, dramatically
   shortening the audit cycle because most FedRAMP-Moderate controls
   are already attested.
2. **The CSP's CE (Covered Entity) customers** — when a customer asks
   "what HITRUST controls do you inherit from me, and what do I inherit
   from you?", V.V5 emits a CE-facing inheritance matrix derived from
   the same envelope. This is the HITRUST equivalent of the FedRAMP
   Customer Responsibility Matrix (CRM, LOOP-L) and the HHS Sample BAA
   Provisions (V.V1).

Concretely, V.V5:

1. **Loads the HITRUST CSF v11.2.0 catalog** from
   `data/hitrust-csf-v11.2.0-catalog.json` (operator-supplied; see §11
   `REQUIRES-OPERATOR-INPUT` — HITRUST member-portal license is
   required; the catalog is NOT redistributable under HITRUST's IP terms
   so it MUST be operator-supplied per the runbook). Validates the
   catalog's SHA-256 against the operator-recorded value and asserts
   schema conformance.
2. **Selects the assessment tier** via `core/hitrust-tier-selector.ts`
   based on operator configuration (`--hitrust-tier=e1|i1|r2`, with
   `i1` as the default since it is the most common B2B-customer-
   expected tier per §2.4 sources). The selector enforces the
   regulatory expectation matrix: r2 is REQUIRED if the CSP advertises
   "HITRUST Certified" without qualifier; i1 carries the
   "HITRUST Implemented 1-year Validated" label; e1 carries the
   "HITRUST Essentials 1-year" label. Operator-overridable with a
   `--hitrust-tier-override-justification=<text>` flag.
3. **Walks the on-disk corpus of signed KSI evidence envelopes** under
   `out/ksi-evidence/*.json` (every LOOP-B through LOOP-K-emitting
   KSI). Each envelope carries `ksi_id`, `evidence[]`, `findings[]`,
   `provenance`, and an Ed25519 signature. For each HITRUST requirement
   statement at the selected tier, V.V5 looks up the matching KSI(s)
   via the catalog's `crosswalk_fedramp_ksi: string[]` field and
   computes inheritance status.
4. **Ingests V.V1 BAA registry** (`out/baa-registry-YYYYMMDD.json`) to
   stamp each emitted inheritance evidence row with the affected CE
   relationships (for the CE-facing inheritance matrix).
5. **For each HITRUST requirement statement at the selected tier**,
   computes:
   - `inheritance_status` ∈ {`fully-inherited`, `partially-inherited`,
     `not-inherited`, `customer-shared`, `requires-operator-input`}
   - `fedramp_ksi_evidence_pointers[]` — typed pointers (envelope
     SHA-256 hash, observation UUID, finding UUID, KSI ID, evidence
     collection timestamp, signing key ID)
   - `composite_risk_score` — composite risk read from LOOP-B.B1
     `out/risk-register.json` if any contributing risk-register row
     references the same KSI evidence; default `null` if no risk row
     surfaces
   - `ce_inheritance_routing[]` — array of CE relationship IDs from
     V.V1 BAA registry for which this requirement is relevant
   - `provenance` block — sourceCalls listing every input file path,
     sha256 digest, signing key id, fetch timestamp
6. **Rolls up to per-control-category satisfaction** via the
   documented roll-up function (Algorithm §6): the category status is
   the worst contributing requirement status with a
   `partially-satisfied` overlay when requirements are mixed; matches
   HITRUST's official PRISMA-derived 5-level maturity model (Policy,
   Procedures, Implementation, Measurement, Management).
7. **Cascades inheritance gaps into LOOP-B POA&M items** via LOOP-A.A1
   — a `not-inherited` or `requires-operator-input` requirement with
   `composite_risk_score >= medium` auto-creates a POA&M item tagged
   `hitrust-inheritance-gap` so the inheritance gap is tracked as
   formal remediation work.
8. **Emits three artefacts** (all signed Ed25519 + RFC 3161
   timestamped via existing `core/sign.ts` + `core/timestamp.ts`):
   - `out/hitrust-inheritance-evidence-YYYYMMDD.json` — canonical
     JSON envelope (the primary deliverable consumed by the external
     HITRUST assessor).
   - `out/hitrust-ce-inheritance-matrix-YYYYMMDD.xlsx` — operator-
     readable per-CE workbook (one sheet per CE, with the requirements
     applicable to that CE relationship). Uses the existing OOXML/zip
     helper pattern; no new dependency.
   - `out/hitrust-inheritance-gap-poam-YYYYMMDD.json` — the cascade
     POA&M overlay (LOOP-A.A1 reads this to merge with the master
     POA&M).

V.V5 is a **pure aggregator + mapper**: it does no new evidence
collection. Every byte of the inheritance evidence envelope traces back
to a real LOOP-E KSI envelope, the operator-supplied HITRUST catalog,
or the V.V1 BAA registry. The provenance block lists every input path.
The system NEVER attests inheritance status without an underlying signed
KSI envelope (REO Rule 1.1, 1.3, 1.5, 1.9) and NEVER auto-signs on
behalf of the HITRUST assessor (REO Rule 1.10).

## 2. Authoritative sources

Every URL accessed 2026-06-08. Verbatim quotes appear in Markdown
blockquotes. Where a live HITRUST source is behind the member portal
(myCSF / hitrustalliance.net Download Center), the operator-supplied
copy is referenced; public-facing pages (advisories, press releases,
assessment-overview pages) are quoted directly. Each quote pins to a
specific page, section, paragraph, or PDF page number.

### 2.1 HITRUST CSF v11 release advisory (HAA 2023-001) — version structure + threat-adaptive model

URL: https://hitrustalliance.net/advisories/haa-2023-001-csf-version-11-release
(accessed 2026-06-08).

> "v11 is available within MyCSF and for download here as of
> January 18, 2023."

This pins the v11 family baseline date. v11.2.0 is the third minor
release in the v11 family (per HAA 2023-011 below).

The same advisory pins the **e1 / i1 / r2 control counts** that the
V.V5 tier selector enforces:

> "e1 assessment: 44 requirement statements"
> "i1 assessment: 182 requirement statements" (comprising the 44 e1
> statements plus 138 additional ones)
> "r2 assessment: includes the 182 i1 statements plus additional
> tailored requirements"

The r2 tier is risk-based and the requirement count varies per
organization based on the scoping questionnaire (per §2.4 sources,
average r2 size is ~385 requirements).

The advisory describes v11's threat-adaptive design:

> "v11 ... enabling cyber threat adaptive HITRUST Assessments across
> the portfolio that continuously evolve to address emerging threats
> such as ransomware and phishing."

This matters for V.V5 because the tier selector's default of `i1`
specifically maps to HITRUST's "threat-adaptive baseline" tier.

The advisory pins **cross-version inheritance**:

> "External Inheritance can be used between v11 assessments and
> v9.1 – v9.6.2 assessments."

V.V5 does NOT attempt v9.x cross-version inheritance — the operator
runbook documents that v9.x → v11 inheritance is the assessor's
responsibility, not V.V5's. V.V5 emits v11.2.0-native inheritance only.

### 2.2 HITRUST CSF v11.2 release advisory (HAA 2023-011) — v11.2.0 baseline date

URL: https://hitrustalliance.net/advisories/haa-2023-011-csf-version-11.2-release
(accessed 2026-06-08).

> "CSF v11.2 is available within MyCSF and for download as of
> October 10, 2023."

V.V5's pinned target is **v11.2.0 (2023-10-10)** per the operator
directive. The `data/hitrust-csf-v11.2.0-catalog.json` file
`source_release_date` field MUST equal `2023-10-10` and the catalog
extractor MUST validate against this date.

### 2.3 HITRUST CSF v11.3 launch announcement — what v11.2.0 is NOT

URL: https://hitrustalliance.net/press-releases/hitrust-announces-csf-v11.3.0-launch
(accessed 2026-06-08).

> "The HITRUST Framework (HITRUST CSF®) on April 16, 2024 [released
> v11.3.0]"
>
> "Addition of FedRAMP, StateRAMP, and TX-RAMP authoritative sources"
>
> "Integration of NIST SP 800-172: Enhancing protections for Controlled
> Unclassified Information"
>
> "Inclusion of MITRE Adversarial Threat Landscape for
> Artificial-Intelligence Systems (MITRE Atlas) Mitigations"
>
> "Reduced redundancy in requirement statements, significantly
> decreasing the average r2 assessment size"

V.V5 v11.2.0-pinned scope EXCLUDES the four v11.3.0 additions above.
Notably, v11.3.0 introduces a **native FedRAMP authoritative source
mapping** that would, if used, supersede V.V5's crosswalk file. When
the CSP migrates to v11.3.0, the operator runbook (§7
`docs/RUNBOOK-HITRUST-OVERLAY.md`) documents the upgrade path: replace
the `data/hitrust-csf-v11.2.0-catalog.json` with the v11.3.0 catalog,
bump the version constant, and re-run the crosswalk extractor.

### 2.4 HITRUST e1 assessment overview — tier description + control count

URL: https://hitrustalliance.net/assessments-and-certifications/e1
(accessed 2026-06-08).

> "HITRUST e1 delivers fast, independently validated assurance grounded
> in 43 foundational controls."

NOTE: The e1 page says **43 foundational controls**; HAA 2023-001
says **44 requirement statements**. The discrepancy is explained by
HITRUST's distinction between "controls" (parent control IDs) and
"requirement statements" (the actual evaluable items). V.V5's
`hitrust-tier-selector.ts` uses the **44 requirement statements**
count as the authoritative e1 cardinality per the v11 release
advisory; the e1-page wording is documented in §10 Q1 as a known
public-facing discrepancy.

> "HITRUST e1 certifications are valid for 1 year and require annual
> renewal to maintain validated status."

V.V5 records `hitrust_assessment_validity_years: 1` for e1 in the
tier-selector output.

> "Achievable in approximately 4-6 weeks, with many organizations
> completing it in around 30 days. Intended for startups, small
> businesses, growing vendors, and companies seeking vendor assurance.
> Includes independent third-party validation."

This pins the e1 tier as inappropriate for established CSPs that
serve enterprise CE customers; V.V5's tier selector emits a warning
diagnostic `hitrust-tier-selector:tier-too-narrow` when the operator
selects e1 AND `baa-registry-YYYYMMDD.json` lists more than 5 active
CE relationships.

### 2.5 HITRUST i1 assessment — threat-adaptive baseline

URL: https://hitrustalliance.net/assessments-and-certifications/i1
(accessed 2026-06-08; member-portal-gated content quoted from the
operator-supplied PDF copy preserved under `docs/sources/hitrust-i1-
overview-20260608.pdf` per §7).

> "The HITRUST i1 Validated Assessment + Certification provides a
> moderate level of assurance ... [it is the] threat-adaptive
> assessment ... renewed annually."

> "The current version (v11) includes a standardized set of 182
> requirement statements that apply to all organizations seeking this
> certification." (per HAA 2023-001, §2.1 above; verbatim cross-quoted.)

The i1 tier validity is **1 year** (annual renewal).

### 2.6 HITRUST r2 assessment — risk-based + 2-year validity

URL: https://hitrustalliance.net/assessments-and-certifications/r2
(accessed 2026-06-08; same operator-supplied PDF copy under
`docs/sources/hitrust-r2-overview-20260608.pdf`).

> "The r2 Assessment is valid for two years with an interim period in
> between and addresses five key areas — policy, procedures,
> implementation, measurement, and management — and over 200 controls."

The "five key areas" are the **PRISMA maturity model** levels (also
called "PRISMA-derived"; see §2.7). V.V5's roll-up function (§6
Algorithm) implements all five levels for the r2 tier; the e1 and i1
tiers use a simplified roll-up (implementation-only).

> "Customized for each organization based on a scoping exercise, the
> risk-based 2-year assessment assigns the number of requirement
> statements based on the business's risk profile."

The r2 tier requires an **operator-supplied scoping questionnaire
output** (`hitrust-r2-scoping-YYYYMMDD.json`) — V.V5's
`hitrust-tier-selector.ts` REFUSES to emit an r2 inheritance envelope
unless this file is present AND signed by an HITRUST-authorized
external assessor (the scoping is part of the assessor's preparation;
V.V5 cannot self-scope). Average r2 size is ~385 requirements per
the cross-referenced Vanta source (https://www.vanta.com/collection/
hitrust/hitrust-assessments, accessed 2026-06-08):

> "There are over 2,000 controls in total, with the average size of
> the assessment being 385 controls."

### 2.7 PRISMA maturity model — the five evaluation levels

URL: https://csrc.nist.gov/projects/program-review-for-information-security-assistance
(NIST CSRC PRISMA reference, accessed 2026-06-08).

PRISMA (Program Review for Information Security Management
Assistance) is the NIST-derived maturity model HITRUST adopted for
its r2 evaluation. The five levels:

> "Policy: Are formal, up-to-date documented policies stated as
> 'shall' or 'will' statements that exist and are readily available?"
>
> "Procedures: Are formal, up-to-date documented procedures provided
> to implement the security controls identified by the defined
> policies?"
>
> "Implementation: Are the procedures communicated to individuals who
> are required to follow them, and are they consistently applied?"
>
> "Test: Are tests routinely conducted to evaluate the adequacy and
> effectiveness of all implementations?"
>
> "Integration: Is integration with other functional areas such as
> business processes monitored to ensure the security controls remain
> effective and continually improving?"

HITRUST renames "Test" → "Measurement" and "Integration" →
"Management" but preserves the underlying meaning. V.V5's r2 roll-up
function emits a per-requirement maturity score on a 5-level scale
where each level can be `non-compliant` (0%), `somewhat-compliant`
(25%), `partially-compliant` (50%), `mostly-compliant` (75%), or
`fully-compliant` (100%) per HITRUST's official PRISMA-derived
scoring rubric (operator-supplied copy of the rubric under
`docs/sources/hitrust-scoring-rubric-v11.2-20260608.pdf`).

### 2.8 HHS Cloud Computing Guidance — HITRUST-HIPAA inheritance basis

URL: https://www.hhs.gov/hipaa/for-professionals/special-topics/health-information-technology/cloud-computing/index.html
(accessed 2026-06-08; HHS Cloud Computing Guidance, Oct 2016, updated
2020).

> "Generally, a CSP is a business associate when it creates, receives,
> maintains, or transmits protected health information (PHI) on
> behalf of a covered entity."

This anchors V.V5's design assumption that the CSP is a Business
Associate; V.V5 refuses to emit an inheritance envelope if the V.V1
BAA registry is empty AND the operator has not affirmed "we are a
non-PHI HITRUST applicant" via `--hitrust-non-phi-affirmation` (a
narrow exception for HITRUST-without-HIPAA scope; documented in §11).

> "A covered entity (or business associate) that engages a CSP should
> understand the cloud computing environment or solution offered by a
> particular CSP so that the covered entity (or business associate)
> can appropriately conduct its own risk analysis and establish risk
> management policies, as well as enter into appropriate BAAs."

This anchors V.V5's CE-facing inheritance matrix as a contractual
artefact the CSP shares with the CE under the BAA's risk-analysis
support obligation.

### 2.9 NIST SP 800-53 Rev 5 — the FedRAMP-side control baseline being inherited

URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
(accessed 2026-06-08).

> "This publication provides a catalog of security and privacy
> controls for information systems and organizations to protect
> organizational operations and assets, individuals, other
> organizations, and the Nation from a diverse set of threats and
> risks." (NIST SP 800-53 Rev 5, §1.1 "Purpose and Applicability",
> p. 1.)

> "The controls are flexible and customizable and implemented as part
> of an organization-wide process to manage risk." (ibid., §1.1.)

V.V5's crosswalk maps HITRUST CSF v11.2.0 requirement statements onto
the underlying NIST SP 800-53 Rev 5 control IDs that LOOP-E's KSI
evidence already addresses. The crosswalk's `mapping_source` field
distinguishes:
- `'hitrust-csf-v11.2.0-native'` — HITRUST's official cross-reference
  (member-portal-supplied)
- `'fedramp-20x-ksi-inferred'` — FedPy-derived from the KSI
  collector's stated 800-53 mapping
- `'operator-curated'` — operator-supplied mapping override

### 2.10 NIST SP 800-66 Rev 2 — HIPAA Security Rule resource guide

URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-66r2.pdf
(accessed 2026-06-08; NIST SP 800-66 Rev 2, Feb 2024).

> "This publication discusses security considerations and resources
> that may provide value when implementing the requirements of the
> Health Insurance Portability and Accountability Act (HIPAA) Security
> Rule." (NIST SP 800-66 Rev 2, §1, p. 1.)

> "[Appendix F] provides a mapping of the HIPAA Security Rule
> Standards and Implementation Specifications to NIST SP 800-53
> security controls." (NIST SP 800-66 Rev 2 §F, p. F-1 — quoted
> verbatim from the Appendix F header.)

V.V5's HITRUST → 800-53 → HIPAA Security Rule transitivity uses NIST
SP 800-66 Rev 2 Appendix F as the authoritative HIPAA → 800-53
mapping. V.V2 of LOOP-V owns the 800-66 R2 catalog; V.V5 consumes it
read-only via `data/hipaa-800-66-rev2.json`.

### 2.11 HITRUST Inheritance Program (CSF v11) — external inheritance mechanics

URL: https://hitrustalliance.net/product-tool/hitrust-inheritance-program
(accessed 2026-06-08; HITRUST Inheritance Program page).

> "The HITRUST Inheritance Program enables organizations to leverage
> the assessment results of their service providers to reduce the
> scope, effort, and cost of their own HITRUST assessments."

V.V5 emits the inheritance evidence in the canonical HITRUST
inheritance format so the CSP's HITRUST assessor can ingest it into
MyCSF as an inheritance source. The exact MyCSF API import format is
member-portal-gated; V.V5's default emit is a canonical JSON envelope
that the operator (or the assessor) uploads manually per the runbook
(REO Rule 4 — no auto-submit to HITRUST).

> "Inheritance is a critical feature of the HITRUST Assurance Program
> that supports the Assurance Program's mission to provide one
> assessment to address multiple frameworks and regulations."

This pins the inheritance program as the official mechanism V.V5
participates in; it is NOT a FedPy-invented protocol.

### 2.12 FedRAMP 20x Key Security Indicators — the LOOP-E evidence source

URL: https://www.fedramp.gov/rev5/ (accessed 2026-06-08; FedRAMP
Phase Two Rev 5 / 20x KSI page).

The KSI evidence corpus is the authoritative input to V.V5's
inheritance computation. Per the local CLAUDE.md REO Rule 2:

> "End-to-end evidence flows from a real cloud SDK call (or real FRMR
> catalog read, or real tracker DB query) through to the emitted
> output file." (cloud-evidence/CLAUDE.md, REO Rule 2.1, quoted
> verbatim.)

V.V5 inherits this contract: every "inherited" HITRUST requirement
statement in the emitted envelope traces back to at least one
signed KSI envelope under `out/ksi-evidence/*.json`.

## 3. Scope

### In scope

- HITRUST CSF v11.2.0 catalog ingestion + SHA-256-validated loading
  (operator-supplied per HITRUST IP terms).
- Tier selection (e1 / i1 / r2) with enforcement of the regulatory
  expectation matrix per §2.4–§2.6.
- Inheritance computation per HITRUST requirement statement, joining
  to LOOP-E KSI envelopes via the catalog's
  `crosswalk_fedramp_ksi: string[]` field.
- Per-CE inheritance matrix derived from V.V1 BAA registry.
- Inheritance-gap → POA&M cascade via LOOP-A.A1.
- Three signed + timestamped output artefacts (JSON envelope, .xlsx
  CE-facing matrix, POA&M cascade overlay).
- Composite risk overlay from LOOP-B.B1 (per-requirement risk score
  read-only).
- PRISMA-derived 5-level maturity roll-up for r2 tier.
- Implementation-level-only roll-up for e1 and i1 tiers.
- Submission-bundle role registration for the 3 new artefacts (per
  LOOP-A.A4).
- Tracker DB schema additions (`hitrust_evidence`,
  `hitrust_inheritance_runs`) — additive only, per REO Rule + V-X42.

### Out of scope

- Direct submission to HITRUST MyCSF (REO Rule 4 — no auto-submit;
  operator transmits manually).
- v9.x cross-version inheritance (operator runbook documents this
  is the assessor's responsibility).
- v11.3.0 / v11.4.0 catalog support (deferred to a future bump per
  §2.3 and §10 Q4).
- HITRUST-without-HIPAA scope NORMAL path (narrow exception via
  `--hitrust-non-phi-affirmation` only; default is HIPAA-required).
- Catalog redistribution under HITRUST IP terms (operator must
  obtain catalog from HITRUST member portal).
- Auto-signing on behalf of the HITRUST external assessor (REO
  Rule 1.10 — never).
- LOOP-Y CJIS / IRS-1075 mapping (cross-loop with LOOP-Y; deferred).
- LOOP-Z ISO 27001 / EUCS cross-mapping (cross-loop with LOOP-Z;
  v11.3.0+ adds native FedRAMP/StateRAMP/TX-RAMP authoritative
  sources but ISO mappings remain LOOP-Z scope).
- LOOP-O AI/ML governance (NIST AI RMF / OMB M-24-10) — v11.3.0
  added MITRE ATLAS mappings; LOOP-O scope owns AI-specific
  attestation, not V.V5.

## 4. Inputs

```typescript
// core/hitrust-csf-mapper.ts input types

/**
 * The HITRUST CSF v11.2.0 catalog, operator-supplied per HITRUST IP
 * terms. SHA-256 validated against an operator-recorded value at
 * load time; mismatch causes a fatal HitrustCatalogIntegrityError.
 */
export interface HitrustCsfCatalog {
  /** Pinned to "11.2.0" for this slice; operator override possible. */
  csf_version: string;
  /** Pinned to "2023-10-10" per §2.2. */
  source_release_date: string;
  /** SHA-256 of the source PDF / JSON the operator supplied. */
  source_sha256: string;
  /** When the operator last refreshed the catalog. */
  catalog_last_updated_at: string;
  /** The control objectives + categories tree (14 top-level
   *  categories per HITRUST CSF structure). */
  categories: HitrustCategory[];
  /** Cross-reference table (HITRUST → FedRAMP KSI / NIST 800-53 /
   *  HIPAA Security Rule). */
  crosswalks: HitrustCrosswalk[];
}

export interface HitrustCategory {
  category_id: string;          // e.g. "0.0-Information-Security-Management-Program"
  category_name: string;
  objectives: HitrustObjective[];
}

export interface HitrustObjective {
  objective_id: string;         // e.g. "01.a"
  objective_name: string;
  control_specifications: HitrustControlSpec[];
}

export interface HitrustControlSpec {
  control_id: string;           // e.g. "01.a.1"
  control_name: string;
  requirement_statements: HitrustRequirementStatement[];
}

export interface HitrustRequirementStatement {
  requirement_id: string;       // e.g. "01.a.1.001"
  requirement_text: string;     // verbatim text from CSF
  /** Which tier(s) this requirement applies to. */
  applicable_tiers: ('e1' | 'i1' | 'r2')[];
  /** Crosswalk to FedRAMP KSI IDs (e.g. ["IAM-MFA", "IAM-AAM"]). */
  crosswalk_fedramp_ksi: string[];
  /** Crosswalk to NIST 800-53 Rev 5 control IDs (e.g. ["IA-2", "IA-5"]). */
  crosswalk_nist_800_53_r5: string[];
  /** Crosswalk to HIPAA Security Rule citations (e.g. ["164.312(a)(2)(i)"]). */
  crosswalk_hipaa_security_rule: string[];
  /** Confidence in the mapping ('high'/'medium'/'low'). */
  mapping_confidence: 'high' | 'medium' | 'low';
  /** Source of the mapping (HITRUST official, FedPy-derived, operator-curated). */
  mapping_source:
    | 'hitrust-csf-v11.2.0-native'
    | 'fedramp-20x-ksi-inferred'
    | 'operator-curated';
}

export interface HitrustCrosswalk {
  hitrust_requirement_id: string;
  external_framework: 'fedramp-ksi' | 'nist-800-53-r5' | 'hipaa-security-rule'
    | 'iso-27001' | 'pci-dss' | 'cmmc' | 'cobit' | 'cobit-5' | 'nist-csf';
  external_control_id: string;
  relationship: 'equivalent' | 'subset' | 'superset' | 'related';
}

/**
 * The KSI evidence envelope from LOOP-E. Read-only by V.V5.
 * Shape mirrors core/envelope.ts (existing type).
 */
export interface KsiEvidenceEnvelope {
  ksi_id: string;
  evidence: Array<{ source: string; data: unknown; collected_at: string }>;
  findings: Array<{ id: string; status: 'pass' | 'fail' | 'n/a'; observation: string }>;
  provenance: { sdk_calls: string[]; signing_key_id: string; signed_at: string };
  ed25519_signature: string;
  rfc3161_timestamp?: { token: string; tsa_url: string };
}

/**
 * BAA registry from V.V1. Read-only by V.V5.
 */
export interface BaaRegistryEntry {
  ce_id: string;
  ce_legal_name: string;
  baa_executed_at: string;
  baa_status: 'active' | 'expired-phi-returned' | 'expired-phi-destroyed'
    | 'expired-phi-retained-with-protections';
  template_era: 'pre-omnibus-2013' | 'post-omnibus-2013' | 'post-2025-nprm' | 'unknown';
  downstream_baas: Array<{ subprocessor_id: string; baa_executed_at: string }>;
}

/**
 * Tier selector output (from core/hitrust-tier-selector.ts).
 */
export interface HitrustTierSelection {
  tier: 'e1' | 'i1' | 'r2';
  selection_reason: string;
  operator_override_justification?: string;
  hitrust_assessment_validity_years: 1 | 2;
  expected_requirement_count: 44 | 182 | number;  // number for r2 (varies)
  prisma_levels_evaluated: Array<
    'policy' | 'procedures' | 'implementation' | 'measurement' | 'management'
  >;
  diagnostics: string[];  // e.g. ['hitrust-tier-selector:tier-too-narrow']
}
```

Input files (canonical paths under `cloud-evidence/`):

- `data/hitrust-csf-v11.2.0-catalog.json` — operator-supplied HITRUST
  catalog (NOT redistributable; SHA-256-validated)
- `out/ksi-evidence/*.json` — every signed KSI envelope from LOOP-E
- `out/baa-registry-YYYYMMDD.json` — V.V1 BAA registry
- `out/risk-register.json` — LOOP-B.B1 composite risk overlay
- `data/hipaa-800-66-rev2.json` — V.V2 HIPAA Security Rule crosswalk
  (read-only, used for HIPAA-citation transitivity)
- `config.yaml::hitrust_overlay.tier` — operator-selected tier
- `config.yaml::hitrust_overlay.assessor_pii` — external assessor
  organization + lead-assessor name (for the envelope's
  `external_assessor` field)
- `hitrust-r2-scoping-YYYYMMDD.json` — REQUIRED for r2 tier only;
  operator-supplied + assessor-signed

## 5. Outputs

### 5.1 Canonical JSON envelope — `out/hitrust-inheritance-evidence-YYYYMMDD.json`

```json
{
  "schema_version": "1.0.0",
  "envelope_type": "hitrust-inheritance-evidence",
  "csf_version": "11.2.0",
  "csf_source_release_date": "2023-10-10",
  "csf_source_sha256": "<operator-supplied>",
  "selected_tier": "i1",
  "tier_selection_provenance": {
    "selection_reason": "default-tier-most-common-b2b-expectation",
    "operator_override_justification": null,
    "selector_version": "1.0.0"
  },
  "csp_uei": "<from config.yaml org_profile.uei>",
  "csp_name": "<from config.yaml org_profile.legal_name>",
  "evidence_collected_at": "2026-06-08T14:00:00Z",
  "external_assessor": {
    "organization_name": "<operator-supplied>",
    "lead_assessor_name": "<operator-supplied>",
    "assessor_authorization_id": "<HITRUST authorized external assessor ID>"
  },
  "inheritance_summary": {
    "total_requirements_evaluated": 182,
    "fully_inherited": 0,
    "partially_inherited": 0,
    "not_inherited": 0,
    "customer_shared": 0,
    "requires_operator_input": 0
  },
  "requirements": [
    {
      "hitrust_requirement_id": "01.a.1.001",
      "hitrust_requirement_text": "<verbatim from catalog>",
      "inheritance_status": "fully-inherited",
      "fedramp_ksi_evidence_pointers": [
        {
          "ksi_id": "IAM-MFA",
          "envelope_sha256": "<sha256>",
          "observation_uuids": ["<uuid>"],
          "finding_uuids": ["<uuid>"],
          "evidence_collected_at": "2026-06-07T08:00:00Z",
          "signing_key_id": "<kms-key-id>"
        }
      ],
      "composite_risk_score": null,
      "prisma_scores": {
        "policy": "fully-compliant",
        "procedures": "fully-compliant",
        "implementation": "fully-compliant",
        "measurement": "mostly-compliant",
        "management": "mostly-compliant"
      },
      "ce_inheritance_routing": ["ce-001", "ce-007"],
      "provenance": {
        "input_files_read": [
          "data/hitrust-csf-v11.2.0-catalog.json",
          "out/ksi-evidence/iam-mfa-aws-20260607.json",
          "out/baa-registry-20260608.json"
        ],
        "input_file_sha256": {
          "data/hitrust-csf-v11.2.0-catalog.json": "<sha256>",
          "out/ksi-evidence/iam-mfa-aws-20260607.json": "<sha256>",
          "out/baa-registry-20260608.json": "<sha256>"
        },
        "computation_timestamp": "2026-06-08T14:00:00Z",
        "mapper_version": "1.0.0"
      }
    }
  ],
  "signing": {
    "ed25519_signature": "<base64>",
    "signing_key_id": "<kms-key-id>",
    "signed_at": "2026-06-08T14:00:00Z"
  },
  "rfc3161_timestamp": {
    "token": "<base64>",
    "tsa_url": "<operator-configured>",
    "stamped_at": "2026-06-08T14:00:00Z"
  }
}
```

### 5.2 Per-CE inheritance matrix — `out/hitrust-ce-inheritance-matrix-YYYYMMDD.xlsx`

OOXML workbook layout:

- **Cover sheet** — CSP name, CSF version (11.2.0), tier selection,
  evidence collection date, assessor PII, envelope signature
  fingerprint
- **Per-CE sheets** (one per active CE from V.V1 BAA registry):
  - Column A: HITRUST Requirement ID (e.g. 01.a.1.001)
  - Column B: Requirement Text (verbatim from catalog)
  - Column C: Inheritance Status (color-coded)
  - Column D: CSP Evidence Pointer (KSI ID + envelope hash truncated)
  - Column E: Composite Risk Score (if not null)
  - Column F: PRISMA scores (concatenated for r2; "Implementation"
    only for e1/i1)
  - Column G: CE-side Action Required (e.g. "Customer must provide
    workforce training records")

Generated via the existing OOXML/zip-store helper pattern (no new
dependency); pattern reused from `core/inventory-workbook.ts`.

### 5.3 POA&M cascade overlay — `out/hitrust-inheritance-gap-poam-YYYYMMDD.json`

```json
{
  "schema_version": "1.0.0",
  "envelope_type": "hitrust-inheritance-gap-poam",
  "csf_version": "11.2.0",
  "selected_tier": "i1",
  "generated_at": "2026-06-08T14:00:00Z",
  "poam_items": [
    {
      "uuid": "<v4 uuid>",
      "title": "HITRUST inheritance gap: <requirement_id> not inherited from FedRAMP KSI evidence",
      "description": "<verbatim requirement_text>",
      "weakness_source": "hitrust-inheritance-mapper-v1.0.0",
      "severity": "medium",
      "scheduled_completion": "<+90 days from generated_at>",
      "related_findings": ["<finding_uuid_if_any>"],
      "remediation_actions": "<operator fills>",
      "provenance": {
        "source_envelope_sha256": "<hash of hitrust-inheritance-evidence-YYYYMMDD.json>",
        "source_requirement_id": "<id>"
      }
    }
  ]
}
```

This file is read by LOOP-A.A1 and merged into the master OSCAL POA&M
on the next OSCAL POA&M emission run; the merge is idempotent (same
`uuid` for the same requirement gap across runs).

## 6. Algorithm / Steps

V.V5 executes a 14-step deterministic pipeline. All steps are REO-
compliant: no silent fallbacks, no auto-defaults that look like real
data, every output traces to a real input.

```
Step 1 — Initialization + REO preflight
  1.1 Read config.yaml::hitrust_overlay.* block
  1.2 Verify --hitrust-overlay flag OR CLOUD_EVIDENCE_HITRUST_OVERLAY=1
  1.3 Verify --hipaa-overlay also active (required precondition);
      OR --hitrust-non-phi-affirmation present
  1.4 Initialize structured logger with run_id (uuid v4)
  1.5 Lock the run via tracker DB advisory lock
      (hitrust_inheritance_runs.run_id UNIQUE constraint)

Step 2 — Load + validate HITRUST catalog
  2.1 Read data/hitrust-csf-v11.2.0-catalog.json
  2.2 Compute SHA-256; compare to config.yaml::hitrust_overlay.
      catalog_sha256
  2.3 If mismatch: emit HitrustCatalogIntegrityError, exit 2
  2.4 Validate schema against schemas/hitrust-csf-catalog.schema.json
  2.5 Assert csf_version === "11.2.0" AND source_release_date ===
      "2023-10-10"
  2.6 Index catalog by requirement_id for O(1) lookup

Step 3 — Select tier
  3.1 Read --hitrust-tier flag (default: "i1")
  3.2 Run hitrust-tier-selector.ts:
        - e1: 44 requirements, 1-year validity, implementation-only roll-up
        - i1: 182 requirements, 1-year validity, implementation-only roll-up
        - r2: variable (typically ~385), 2-year validity, full PRISMA
  3.3 If tier === "e1" AND baa-registry has >5 active CEs:
        emit diagnostic 'hitrust-tier-selector:tier-too-narrow'
  3.4 If tier === "r2": REQUIRE hitrust-r2-scoping-YYYYMMDD.json AND
        verify assessor signature; else exit 2 with
        HitrustR2ScopingMissingError
  3.5 Persist tier selection to tracker DB hitrust_evidence row

Step 4 — Load LOOP-E KSI envelope corpus
  4.1 Glob out/ksi-evidence/*.json
  4.2 For each: validate Ed25519 signature via core/sign.ts; reject
      tampered envelopes with HitrustKsiEnvelopeTamperedError
  4.3 Build in-memory index: ksi_id → envelope (latest by
      collected_at if multiple)

Step 5 — Load V.V1 BAA registry
  5.1 Read out/baa-registry-YYYYMMDD.json (latest)
  5.2 Filter to baa_status === 'active'
  5.3 If empty AND not --hitrust-non-phi-affirmation: exit 2 with
      HitrustBaaRegistryEmptyError

Step 6 — Load LOOP-B.B1 composite risk register (optional overlay)
  6.1 Read out/risk-register.json if present; else skip
  6.2 Build index: ksi_id → composite_risk_score

Step 7 — Filter requirements to selected tier
  7.1 catalog.crosswalks filtered to entries where
      applicable_tiers.includes(selected_tier)
  7.2 Assert count matches expected (44 for e1; 182 for i1; variable for r2)
  7.3 Log expected vs actual; fail if delta > tolerance (default 0)

Step 8 — Compute per-requirement inheritance status
  For each requirement in filtered set:
    8.1 Resolve crosswalk_fedramp_ksi to KSI envelopes via Step 4 index
    8.2 Count matching KSIs:
          0 matches → not-inherited
          all matching KSIs have findings.status === 'pass' →
            fully-inherited
          some 'pass' some 'fail' → partially-inherited
          all 'fail' → not-inherited
          requires operator narrative (e.g. workforce training) →
            customer-shared OR requires-operator-input
    8.3 Compute PRISMA scores (r2 only):
          policy: read from tracker DB
            hipaa_admin_safeguards.policy_documented (boolean)
          procedures: read tracker DB
            hipaa_admin_safeguards.procedures_documented
          implementation: derive from KSI findings.status pass-rate
          measurement: read from LOOP-E ConMon last-eval timestamp
            (within 90 days = 'fully-compliant'; 90-180 =
            'mostly-compliant'; >180 = 'partially-compliant'; etc.)
          management: read from tracker DB
            governance.last_csp_management_review_at
    8.4 Attach composite_risk_score from Step 6 if KSI matches a risk row
    8.5 Attach ce_inheritance_routing[] from Step 5 (all active CEs,
        unless requirement is tagged customer-only in catalog)
    8.6 Build provenance block listing every input file SHA-256

Step 9 — Roll up to category-level summary
  9.1 For each category in catalog.categories:
        category_status = worst contributing requirement_status
        (severity ordering: requires-operator-input < not-inherited <
         customer-shared < partially-inherited < fully-inherited)
        Apply partial overlay if requirements are mixed (any
        partially-inherited or any not-inherited within a category
        with fully-inherited requirements → overlay to
        'partially-inherited')
  9.2 Build inheritance_summary counts

Step 10 — Build CE-facing matrices
  10.1 For each active CE from Step 5:
         per_ce_matrix[ce_id] = requirements where
           ce_inheritance_routing.includes(ce_id)
  10.2 Emit XLSX per §5.2 layout

Step 11 — Cascade gaps to POA&M
  11.1 For each requirement where inheritance_status in
       ['not-inherited', 'requires-operator-input'] AND
       (composite_risk_score >= medium OR tier === 'r2'):
         build POA&M item per §5.3 schema; UUID is deterministic
         hash of (requirement_id + csp_uei) for idempotency
  11.2 Emit out/hitrust-inheritance-gap-poam-YYYYMMDD.json

Step 12 — Sign + timestamp the canonical envelope
  12.1 Compute canonical JSON serialization (sorted keys, no
       whitespace)
  12.2 Ed25519-sign via core/sign.ts using operator's corporate
       signing key
  12.3 Attach RFC 3161 timestamp via core/timestamp.ts
  12.4 If TSA outage: emit envelope with rfc3161_timestamp.status:
       'pending' + schedule retry job (5-min intervals for 1 hour
       then 15-min for 24 hours; pattern reused from W.W3)

Step 13 — Persist to tracker DB
  13.1 INSERT INTO hitrust_evidence (run_id, csf_version,
       selected_tier, envelope_sha256, signed_at)
  13.2 INSERT INTO hitrust_inheritance_runs (run_id, started_at,
       completed_at, requirements_evaluated, inheritance_summary_json)
  13.3 Update audit_log with the run event

Step 14 — Register in submission-bundle + notify
  14.1 Update out/submission-bundle-manifest.json with three new
       roles: hitrust-inheritance-evidence-json,
       hitrust-ce-inheritance-matrix-xlsx,
       hitrust-inheritance-gap-poam-json
  14.2 Emit notification via core/notify.ts to operator + (if r2)
       to assessor's notification channel
  14.3 Exit 0 with structured summary on stdout
```

Pseudocode for the inheritance status decision (Step 8.2):

```typescript
function decideInheritanceStatus(
  requirement: HitrustRequirementStatement,
  ksiEnvelopes: KsiEvidenceEnvelope[],
  catalogHints: { requires_customer_action: boolean }
): InheritanceStatus {
  if (requirement.crosswalk_fedramp_ksi.length === 0) {
    return catalogHints.requires_customer_action
      ? 'customer-shared'
      : 'requires-operator-input';
  }
  const matching = ksiEnvelopes.filter(e =>
    requirement.crosswalk_fedramp_ksi.includes(e.ksi_id)
  );
  if (matching.length === 0) return 'not-inherited';
  const passCount = matching.flatMap(e => e.findings)
    .filter(f => f.status === 'pass').length;
  const failCount = matching.flatMap(e => e.findings)
    .filter(f => f.status === 'fail').length;
  if (passCount > 0 && failCount === 0) return 'fully-inherited';
  if (passCount > 0 && failCount > 0) return 'partially-inherited';
  return 'not-inherited';
}
```

## 7. Files to create / modify

Files created:

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/hitrust-csf-mapper.ts`
  (~700 LOC: catalog loader, envelope reader, mapper, PRISMA scorer,
  CE-matrix builder, POA&M cascader, envelope signer/timestamper,
  tracker persistence)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/hitrust-tier-selector.ts`
  (~250 LOC: tier validation, regulatory expectation enforcement, r2
  scoping-file validation, diagnostic emission)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/hitrust-csf-v11.2.0-catalog.json`
  (operator-supplied skeleton with schema-conformant structure +
  empty `categories` + `crosswalks` arrays; operator populates from
  member-portal-supplied source; ~50 LOC skeleton + tens of MB
  populated by operator)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/schemas/hitrust-csf-catalog.schema.json`
  (JSON Schema Draft 7 for the catalog structure)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/hitrust-csf-mapper.test.ts`
  (~600 LOC: 15+ test specs per §8)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/hitrust/hitrust-csf-v11.2.0-catalog-minimal.json`
  (test fixture: minimal valid catalog with 3 categories, 5
  requirements covering e1/i1/r2 tier permutations)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/hitrust/ksi-envelope-corpus-minimal.json`
  (test fixture: 3 KSI envelopes covering pass/fail/mixed cases)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/RUNBOOK-HITRUST-OVERLAY.md`
  (operator runbook: how to obtain catalog from HITRUST member
  portal, how to select tier, how to migrate v11.2.0 → v11.3.0/v11.4.0)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/sources/hitrust-i1-overview-20260608.pdf`
  (member-portal-supplied i1 overview; operator-supplied copy)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/sources/hitrust-r2-overview-20260608.pdf`
  (member-portal-supplied r2 overview; operator-supplied copy)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/sources/hitrust-scoring-rubric-v11.2-20260608.pdf`
  (PRISMA-derived scoring rubric; operator-supplied copy)

Files modified:

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
  (register 3 new well-known roles per V-X41)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`
  (dispatch `--hitrust-overlay` flag; precondition check on
  `--hipaa-overlay`)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/migrations/NNNN-hitrust-tables.sql`
  (additive CREATE TABLE IF NOT EXISTS for `hitrust_evidence` +
  `hitrust_inheritance_runs`; pattern per V-X42)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/STATUS.md`
  (V.V5 row update at completion)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/LOOP-V-SPEC.md`
  (V.V5 status table row update at completion; V.V5 in §3 slice
  list re-described as HITRUST mapping)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/LOOP-V-RISKS.md`
  (V.V5 per-slice risks table update to reflect HITRUST scope per
  this slice rather than the prior NPRM-readiness placeholder)
- `/Users/kenith.philip/FedRAMP 20x/CHANGELOG.md`
  (Unreleased entry at completion)

## 8. Test specifications

| id | scenario | fixture path | expected | acceptance |
|----|----------|--------------|----------|------------|
| V.V5-T01 | Catalog loads, SHA-256 validates, schema conforms | tests/fixtures/hitrust/hitrust-csf-v11.2.0-catalog-minimal.json | Loader returns parsed catalog object; no error | Asserts catalog.csf_version === "11.2.0" AND source_release_date === "2023-10-10" |
| V.V5-T02 | Catalog SHA-256 mismatch fatally errors | tests/fixtures/hitrust/catalog-tampered.json (1-byte modified) | HitrustCatalogIntegrityError thrown; exit code 2 | Error message names the file path + expected vs actual SHA-256 |
| V.V5-T03 | Catalog schema violation rejected | tests/fixtures/hitrust/catalog-missing-categories.json | Ajv validation error; exit code 2 | Error message names the missing `categories` field |
| V.V5-T04 | e1 tier selection enforces 44 requirements | catalog-minimal with 60 requirements (44 e1 + 138 i1-only) | Filtered set = 44 | tier-selector emits no diagnostic for 5 active CEs |
| V.V5-T05 | e1 tier with >5 active CEs emits tier-too-narrow diagnostic | catalog-minimal + 7-CE BAA registry | Diagnostic 'hitrust-tier-selector:tier-too-narrow' emitted | Tier still selected (warning, not error) |
| V.V5-T06 | i1 tier selection enforces 182 requirements | catalog-minimal with 182 tagged i1 | Filtered set count === 182 | No diagnostic |
| V.V5-T07 | r2 tier without scoping file fatally errors | catalog-minimal + no hitrust-r2-scoping-*.json | HitrustR2ScopingMissingError; exit code 2 | Error message points to expected file path |
| V.V5-T08 | r2 tier with scoping file but no assessor signature rejected | tests/fixtures/hitrust/r2-scoping-unsigned.json | HitrustR2ScopingUnsignedError; exit code 2 | Error message names missing signature block |
| V.V5-T09 | KSI envelope with valid Ed25519 signature loads | tests/fixtures/hitrust/ksi-envelope-corpus-minimal.json (3 valid) | All 3 envelopes loaded; index built | Asserts ksi_id → envelope map size === 3 |
| V.V5-T10 | KSI envelope with tampered signature rejected | tests/fixtures/hitrust/ksi-envelope-tampered.json | HitrustKsiEnvelopeTamperedError | Error message names the envelope file + signing_key_id |
| V.V5-T11 | Fully-inherited status when all KSI findings pass | KSI envelope with findings: [{status:'pass'}, {status:'pass'}] | inheritance_status === 'fully-inherited' | provenance block lists envelope SHA-256 |
| V.V5-T12 | Partially-inherited when mixed pass/fail | KSI envelope with [{status:'pass'}, {status:'fail'}] | inheritance_status === 'partially-inherited' | composite_risk_score read from LOOP-B if present |
| V.V5-T13 | Not-inherited when no matching KSI | requirement with crosswalk_fedramp_ksi: ['NONEXISTENT-KSI'] | inheritance_status === 'not-inherited' | POA&M cascade entry emitted |
| V.V5-T14 | Requires-operator-input for customer-action-required requirement | requirement with crosswalk_fedramp_ksi: [] AND catalogHints.requires_customer_action: false | inheritance_status === 'requires-operator-input' | UI surfaces operator prompt |
| V.V5-T15 | Customer-shared for customer-action-required requirement | requirement with crosswalk_fedramp_ksi: [] AND catalogHints.requires_customer_action: true | inheritance_status === 'customer-shared' | CE-facing matrix lists in Column G ('CE-side Action Required') |
| V.V5-T16 | PRISMA scoring computed correctly for r2 tier | mock tracker DB with policy=documented, procedures=documented, ConMon last-eval-at = T-60-days | All 5 PRISMA levels emit valid 5-level scores | measurement === 'fully-compliant' (within 90 days) |
| V.V5-T17 | CE-facing XLSX matrix has one sheet per active CE | 3 active CEs in BAA registry | XLSX has 1 cover sheet + 3 CE sheets | Sheet names match ce_legal_name |
| V.V5-T18 | POA&M cascade only triggers for medium+ risk OR r2 tier | requirement with not-inherited + composite_risk_score === 'low' AND tier === 'i1' | NO POA&M item emitted for that requirement | T15 verifies the gate; T18 verifies the inverse: r2 tier emits POA&M item for ALL not-inherited regardless of risk |
| V.V5-T19 | Envelope Ed25519 signature verifies + RFC 3161 timestamp attached | mock TSA returning valid token | Envelope.ed25519_signature verifies AND rfc3161_timestamp present | core/sign.ts verifySignature returns true |
| V.V5-T20 | TSA outage emits envelope with rfc3161_timestamp.status='pending' + schedules retry | mock TSA returns 503 | Envelope emitted with status pending; tracker job scheduled | Tracker DB job-queue row inserted with retry policy |
| V.V5-T21 | Submission-bundle registers 3 new roles | run V.V5 against minimal corpus | out/submission-bundle-manifest.json has hitrust-inheritance-evidence-json, hitrust-ce-inheritance-matrix-xlsx, hitrust-inheritance-gap-poam-json | Schema validated |
| V.V5-T22 | Idempotent POA&M UUID for same requirement gap across runs | run V.V5 twice with same inputs | POA&M item UUID identical across runs | Hash is deterministic (sha256(requirement_id + csp_uei)) |
| V.V5-T23 | BAA registry empty AND not --hitrust-non-phi-affirmation fatally errors | empty baa-registry-*.json | HitrustBaaRegistryEmptyError; exit code 2 | Error message documents the --hitrust-non-phi-affirmation escape hatch |
| V.V5-T24 | --hitrust-non-phi-affirmation bypasses BAA check | empty BAA registry + flag set | Envelope emits with `phi_scope: 'non-phi-affirmation'` block | Envelope.phi_scope field present |
| V.V5-T25 | --hitrust-overlay without --hipaa-overlay fatally errors | flag combination | HitrustOverlayPreconditionError; exit code 2 | Error message documents the precondition |

Total: 25 test specifications (exceeds the 15-minimum requirement).
All tests live under
`/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/hitrust-csf-mapper.test.ts`
with fixtures under
`/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/hitrust/`.

## 9. Risks

### Risk 1 — HITRUST catalog redistribution under HITRUST IP terms

**Cause.** The HITRUST CSF v11.2.0 catalog is licensed to HITRUST
members; redistribution outside the member is prohibited under
HITRUST's IP terms. V.V5 cannot ship the catalog in the FedPy repo.

**Likelihood.** Certain (this is a hard licensing constraint).

**Impact.** High — without the catalog, V.V5 cannot run.

**Mitigation.** `data/hitrust-csf-v11.2.0-catalog.json` ships as an
empty skeleton with the schema structure only; the operator obtains
the actual catalog from the HITRUST member portal and replaces the
skeleton with the populated copy. The runbook
`docs/RUNBOOK-HITRUST-OVERLAY.md` documents the member-portal
download procedure step-by-step. CI runs against a SYNTHETIC test
fixture (`test/fixtures/hitrust/hitrust-csf-v11.2.0-catalog-minimal
.json`) that is FedPy-authored (not derived from HITRUST IP) — the
fixture uses 3 categories + 5 requirements with FedPy-invented
requirement_id values and verbatim-quoted-but-paraphrased
requirement_text (long enough to exercise the mapper but short
enough to be fair-use). REO Rule 3 documents this as the narrow
allowed exception: "operator-supplied data is real data". Cross-
references V-X21 (HITRUST CSF version drift) and V-X22 (HITRUST →
800-66 / FedRAMP crosswalk inaccuracy).

### Risk 2 — Version-vs-release-date discrepancy (v11.2.0 is Oct 2023, NOT Apr 2024)

**Cause.** The slice task description states "HITRUST CSF v11.2.0
(Apr 2024)". Authoritative research (HAA 2023-011, HITRUST
introduction PDF title) confirms v11.2.0 was released **2023-10-10**,
NOT April 2024. The Apr 2024 release is v11.3.0 (HAA 2024-NNN / press
release). Pinning to "v11.2.0 (Apr 2024)" in code or in operator
configuration would create a permanent version-mismatch risk that
silently propagates to operator-supplied catalogs and to assessor
deliverables.

**Likelihood.** High (the date error is in the slice's source
requirements).

**Impact.** Medium — operator confusion + potential mis-pinning of
catalog to wrong release.

**Mitigation.** V.V5's `data/hitrust-csf-v11.2.0-catalog.json` ships
with `source_release_date: "2023-10-10"` (the correct date per §2.2)
and the loader REJECTS catalogs whose `source_release_date` does not
match. The slice description's "(Apr 2024)" reference is documented
in §10 Q4 as REQUIRES-OPERATOR-INPUT: confirm the operator intent —
either (a) pin to v11.2.0 (Oct 2023) per the file name (the path
this slice takes), OR (b) re-target to v11.3.0 (Apr 2024) and
rebuild the catalog. The runbook documents the version-vs-date
mapping table.

### Risk 3 — Tier-selection misalignment with CE customer expectation

**Cause.** A CSP that selects `i1` (default) to reduce assessment
cost may be surprised when CE customers expect `r2` (the "true"
HITRUST certification). V-X20 documents this risk at the cross-
cutting level. V.V5's tier-too-narrow diagnostic at >5 active CEs
catches the common case but not all variants.

**Likelihood.** Medium.

**Impact.** Medium — commercial + audit-expectation mismatch.

**Mitigation.** Tier-selector emits diagnostic
`hitrust-tier-selector:tier-too-narrow` when (a) tier === 'e1' AND
active CE count > 5, OR (b) tier === 'i1' AND any active CE has a
BAA requiring r2 in `baa-registry.yaml::expected_assurance_level`
field. Per-CE expected-assurance-level is a NEW V.V1 schema
addition required for this risk; documented in the V.V5 cross-loop
section. Runbook documents the tier matrix and recommends operator
discussion with each CE customer before selecting non-r2 tier.

### Risk 4 — PRISMA scoring requires tracker DB inputs that may not exist

**Cause.** The r2 tier roll-up requires Policy / Procedures /
Implementation / Measurement / Management scoring per requirement.
The first two (Policy / Procedures) require tracker DB rows in
`hipaa_admin_safeguards.policy_documented` and `.procedures_
documented` that V.V2 emits. If V.V2 has not yet been implemented
(or not yet run), V.V5 cannot compute the policy/procedures axes.

**Likelihood.** High (V.V2 is sequenced after V.V5 in some
implementation orderings).

**Impact.** Medium — r2 PRISMA scores would be incomplete.

**Mitigation.** V.V5's PRISMA computation gracefully degrades: if
the tracker DB rows are missing, the axis emits
`'requires-operator-input'` with a diagnostic
`'hitrust-csf-mapper:prisma-axis-missing-evidence:<axis>'`. The
runbook documents the V.V2 → V.V5 sequencing recommendation.
Cross-references V-X42 (tracker schema migration) — V.V5 ships its
own additive tables and reads V.V2's tables read-only, so V.V5 can
run even if V.V2 has only partially populated.

### Risk 5 — Inheritance-gap POA&M cascade duplicates POA&M items across runs

**Cause.** Every V.V5 run that surfaces the same not-inherited
requirement would create a fresh POA&M item, polluting the master
POA&M with duplicates.

**Likelihood.** Certain if not designed for.

**Impact.** Low — but degrades the POA&M's signal-to-noise ratio.

**Mitigation.** POA&M item UUIDs are computed as
`sha256(requirement_id + csp_uei).slice(0,32)` reshaped to a v4 UUID
format — deterministic across runs. LOOP-A.A1's POA&M merge is
idempotent on UUID; same UUID = same item, updates the `last_seen_at`
timestamp + the `remediation_actions` field if the operator has
filled it. Test V.V5-T22 pins this idempotency.

### Risk 6 — TSA outage at emit time

**Cause.** The RFC 3161 TSA the operator configures may be
unreachable at the moment V.V5 emits the envelope. Same class as
W.W3 Risk 10.

**Likelihood.** Low.

**Impact.** Low — the envelope is still signable; the TST can be
attached asynchronously.

**Mitigation.** TST attachment is best-effort. If the TSA fails,
V.V5 emits with a `rfc3161_timestamp.status: 'pending'` block and
schedules a tracker DB job to retry at 5-minute intervals for 1 hour,
then 15-minute intervals for 24 hours. Operator alerted if the TST
remains pending after 24 hours. Pattern reused from W.W3 Risk 10.
Test V.V5-T20 pins the retry behavior.

### Risk 7 — KSI envelope corpus on disk may be stale (>30 days old)

**Cause.** The V.V5 mapper reads `out/ksi-evidence/*.json` blindly;
if the operator forgot to run LOOP-E recently, the inheritance
envelope would emit using stale evidence. A HITRUST assessor
reviewing stale evidence might issue findings.

**Likelihood.** Medium.

**Impact.** Medium — stale evidence could trigger assessor findings.

**Mitigation.** V.V5 computes per-envelope `evidence_age_days =
now() - envelope.evidence_collected_at`. If any matching envelope
for a requirement is >30 days old, the inheritance row carries
`evidence_freshness_warning: true` + a diagnostic
`hitrust-csf-mapper:stale-evidence:<ksi_id>:<age_days>d`. The
envelope's `inheritance_summary` block surfaces a count of
stale-evidence requirements. Runbook documents the 30-day
freshness expectation.

### Risk 8 — Concurrent V.V5 runs corrupt tracker DB

**Cause.** Two operator-initiated V.V5 runs in parallel would race
on tracker DB writes (`hitrust_evidence` row INSERT).

**Likelihood.** Low (but possible in multi-operator orgs).

**Impact.** Low — DB constraint violation rather than corruption.

**Mitigation.** Step 1.5 acquires an advisory lock via
`hitrust_inheritance_runs.run_id UNIQUE` constraint. Second
concurrent run exits with `HitrustConcurrentRunError`. Operator
runbook documents the single-run-at-a-time expectation. Pattern
reused from W.W3 + LOOP-A.A4 submission-bundle (single-run pattern).

## 10. Open questions

- **Q1 — e1 control count: 43 or 44?** Status: **REQUIRES-RESEARCH**.
  HITRUST e1 page (§2.4) says "43 foundational controls"; HAA
  2023-001 (§2.1) says "44 requirement statements". V.V5 uses the
  44-requirement-statement count as authoritative. The discrepancy
  is likely "controls" (43 parent IDs) vs "requirement statements"
  (44 evaluable items) but this should be confirmed with the
  HITRUST member portal documentation. The runbook flags this as
  the operator's confirmation item at first catalog load.
- **Q2 — Exact MyCSF inheritance import format.** Status:
  **REQUIRES-RESEARCH**. The MyCSF API import format for
  inheritance evidence is member-portal-gated; V.V5's default emit
  is a canonical JSON envelope that the operator (or assessor)
  uploads manually. If MyCSF supports a specific JSON schema for
  programmatic import, V.V5 should align. Operator-supplied via
  the runbook once confirmed with the HITRUST assessor.
- **Q3 — PRISMA scoring rubric variations across HITRUST versions.**
  Status: **REQUIRES-RESEARCH**. HITRUST's scoring rubric may
  evolve across v11.2.0 → v11.3.0 → v11.4.0. V.V5's PRISMA scorer
  hardcodes the v11.2.0 rubric (operator-supplied PDF). On version
  upgrade, the scorer must be re-validated against the new rubric.
  Runbook documents the upgrade procedure.
- **Q4 — Version-vs-date discrepancy in the slice task.** Status:
  **REQUIRES-OPERATOR-INPUT**. Task says "v11.2.0 (Apr 2024)";
  research confirms v11.2.0 = Oct 2023, v11.3.0 = Apr 2024.
  Default: pin to v11.2.0 (Oct 2023) per the file name. Operator
  confirms via `--hitrust-version=11.2.0` (default) or
  `--hitrust-version=11.3.0` (re-targets to the Apr 2024 release;
  requires fresh catalog from member portal).
- **Q5 — r2 scoping signature mechanism.** Status:
  **REQUIRES-RESEARCH**. The r2 scoping file must be assessor-
  signed; what signature mechanism does HITRUST accept?
  (DocuSign / Adobe Sign / PIV-derived?) Default V.V5 acceptance is
  Ed25519 + RFC 3161 (FedPy-native); operator runbook documents
  the alternative formats.
- **Q6 — Multi-tier overlay (some controls evaluated at r2 while
  others at i1).** Status: **REQUIRES-OPERATOR-INPUT**. Some CSPs
  may want to evaluate critical control families at r2 while
  remaining family-level at i1. HITRUST's standard tier model
  treats this as r2 (the highest tier wins). V.V5 currently
  enforces single-tier; multi-tier overlay is a future enhancement.
- **Q7 — v11.3.0 native FedRAMP/StateRAMP/TX-RAMP authoritative
  source — does it supersede V.V5's crosswalk?** Status:
  **REQUIRES-RESEARCH**. On v11.3.0 upgrade, the native FedRAMP
  cross-reference may be authoritative; V.V5's FedPy-curated
  crosswalk becomes a secondary source. Operator runbook
  documents the upgrade migration plan.
- **Q8 — CE-facing matrix distribution mechanism.** Status:
  **REQUIRES-OPERATOR-INPUT**. The .xlsx is intended for sharing
  with the CE under the BAA's risk-analysis support obligation.
  Distribution mechanism (email / customer portal / direct CE
  download) is operator-policy. Runbook documents the recommended
  customer-portal-with-audit-trail pattern.

## 11. REQUIRES-OPERATOR-INPUT fields

| Field name | Type | Validator | UI location | Failure mode if missing |
|------------|------|-----------|-------------|--------------------------|
| `hitrust_catalog_sha256` | string (64-char hex) | hex regex + length=64 | Settings → Compliance → HITRUST → Catalog | Catalog load fails; HitrustCatalogIntegrityError; exit code 2. |
| `hitrust_catalog_file_path` | string (filesystem path) | path exists + readable | Settings → Compliance → HITRUST → Catalog | Catalog load fails; HitrustCatalogMissingError; exit code 2. |
| `hitrust_tier` | enum: `e1` \| `i1` \| `r2` | enum validator | Settings → Compliance → HITRUST → Tier | Default to `i1`; emit warning at startup. |
| `hitrust_tier_override_justification` | string (non-empty) | min-length 50 chars | Settings → Compliance → HITRUST → Tier | If tier selected differs from BAA-recommended tier (via baa-registry expected_assurance_level), emit warning. |
| `hitrust_assessor_organization_name` | string | non-empty, no control chars | Settings → Compliance → HITRUST → Assessor | Envelope still emits with empty `external_assessor.organization_name`; flagged in tracker UI. |
| `hitrust_assessor_lead_name` | string | non-empty | Settings → Compliance → HITRUST → Assessor | Envelope still emits with empty `external_assessor.lead_assessor_name`; flagged. |
| `hitrust_assessor_authorization_id` | string | HITRUST AEA ID format | Settings → Compliance → HITRUST → Assessor | Envelope still emits; assessor field marked `unknown`. |
| `hitrust_r2_scoping_file_path` | string (filesystem path) | path exists + readable + assessor-signed | Settings → Compliance → HITRUST → r2 Scoping | If tier===`r2`: HitrustR2ScopingMissingError; exit code 2. |
| `hitrust_hipaa_precondition_acknowledged` | boolean | bool validator | Settings → Compliance → HITRUST → Preconditions | If false AND --hitrust-non-phi-affirmation not set: HitrustOverlayPreconditionError; exit code 2. |
| `hitrust_non_phi_affirmation` | boolean | bool validator | Settings → Compliance → HITRUST → Preconditions | Default false; if true, bypass HIPAA precondition AND emit envelope with `phi_scope: 'non-phi-affirmation'`. |
| `hitrust_csf_version` | string (semver) | regex `^11\.\d+\.\d+$` | Settings → Compliance → HITRUST → Version | Default `"11.2.0"`; warn if differs from catalog's `csf_version` field. |
| `hitrust_evidence_freshness_threshold_days` | integer | range 1-365 | Settings → Compliance → HITRUST → Freshness | Default `30`; emit warning per stale KSI envelope. |
| `hitrust_poam_cascade_severity_threshold` | enum: `low` \| `medium` \| `high` \| `critical` | enum validator | Settings → Compliance → HITRUST → POA&M Cascade | Default `medium`; only requirements with composite_risk_score >= threshold cascade to POA&M (r2 tier always cascades regardless). |
| `hitrust_envelope_signing_key_ref` | string (KMS resource ARN or GCP KMS resource) | sign-test on startup (`core/sign.ts::testSign(key_ref)`) | Settings → Compliance → Signing | Orchestrator refuses to run; exit code 2 with `KmsKeyUnavailableError`. Inherits from existing LOOP-A.A5 signing key by default. |
| `hitrust_tsa_url` | string (URL) | URL validator + TSA-handshake test | Settings → Signing → Timestamp Authority | Default to the org's existing TSA configured via LOOP-A.A5; warn if missing. |
| `hitrust_notification_channels` | array of channel refs (`slack:#chan` or `pagerduty:service`) | channel-ping test at startup | Settings → Notifications | Default to org's existing channels; emit warning at startup if missing. |
| `hitrust_per_ce_expected_assurance_level` (per CE in baa-registry.yaml) | enum: `e1` \| `i1` \| `r2` \| `unspecified` | enum validator | Settings → Compliance → BAA Registry | Default `unspecified`; tier-selector uses to compute per-CE alignment warnings. |
| `hitrust_catalog_skeleton_acknowledgment` | boolean | bool validator | Settings → Compliance → HITRUST → Catalog | If false (i.e. operator has not acknowledged that the shipped skeleton must be replaced): emit `HitrustCatalogSkeletonInUseError`; exit code 2 in production mode. |

Total: 18 fields. Of these, **6 are blocking** at startup (orchestrator
refuses to run), **5 are soft-warning** (emit with placeholder /
default; operator completes), and **7 are defaulting** (V.V5 chooses
a safe default if missing).

## 12. Implementation log

| date | session | action | commit | notes |
|------|---------|--------|--------|-------|
| 2026-06-07 | wf-uvxyz | Specification authored via FedPy workflow | TBD | — |
| 2026-06-08 | wf-uvxyz (continued) | Slice doc fleshed out to 700+ lines per per-slice gold-standard pattern (W.W3.md) | TBD | Authoritative sources verified via WebSearch + WebFetch; v11.2.0 = Oct 2023 confirmed (task description's "Apr 2024" annotation flagged as REQUIRES-RESEARCH in §10 Q4); HITRUST IP constraints on catalog redistribution documented in Risk 1; 25 test specs authored covering tier permutations, signature validation, PRISMA scoring, POA&M cascade, freshness, TSA outage, idempotency; 18 REQUIRES-OPERATOR-INPUT fields enumerated. |

## 13. Completion checklist

> The following 7 steps are quoted verbatim from
> `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`. They are MANDATORY
> for every slice in every loop. NO EXCEPTIONS. Every session that ships
> a slice MUST execute this checklist atomically with the slice's own
> commit.
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
> ### Step 8 — V.V5-specific addendum
> After the commit lands, append/update the V.V5 row in STATUS.md
> (status -> done, commit hash, last_updated); update the LOOP-V SPEC
> status table (V.V5 row); append a CHANGELOG entry (LOOP-V.V5 — HITRUST
> CSF v11.2.0 Inheritance Mapping); push to origin/main; verify with
> `git log --oneline -3`. Update `docs/loops/LOOP-V-RISKS.md` per-slice
> risks table for V.V5 to replace the prior NPRM-readiness placeholder
> rows with the HITRUST-mapping-specific risks enumerated in §9 of this
> doc. Update `docs/CLAUDE.md` reading-list if any newly-created
> permanent reference documents (`docs/RUNBOOK-HITRUST-OVERLAY.md`)
> warrant addition. Only THEN is V.V5 closed.

REO STANDARD (Rule 1–4) governs every line of production code described
in §7. No invented citations. Apache-2.0 clean-room. All HITRUST CSF
verbatim quotes pin to publicly-accessible HITRUST sources (advisories,
press releases, assessment overview pages); member-portal content is
operator-supplied per §11 and stored under `docs/sources/` with
2026-06-08 access dates.
