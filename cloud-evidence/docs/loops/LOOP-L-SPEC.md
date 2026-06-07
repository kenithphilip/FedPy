# LOOP-L — Customer Responsibility Matrix (CRM) + Leveraged-Authorization Inheritance

> Comprehensive implementation specification for the four slices in LOOP-L.
> Authored as a stand-alone artifact: any future Claude / human session can
> execute LOOP-L end-to-end by reading ONLY this file + the four supporting
> files cited in Section 3 ("Dependencies"). No prior conversation history
> required.
>
> Authority: `cloud-evidence/CLAUDE.md` (Real-Evidence-Only standard) governs
> every slice below. Every byte emitted must trace back to real evidence or
> operator-supplied configuration. Slices ship under the Real Slice Contract
> in CLAUDE.md Rule 2.
>
> Status: PROPOSED — surfaced by `docs/ADDITIONAL-LOOPS-AUDIT.md` (2026-06-06).
> Not yet adopted in `docs/STATUS.md`; this spec is written to be ready the
> moment the human ratifies the audit. Once ratified, STATUS.md adds an
> LOOP-L block + four pending rows (L.L1..L.L4) and the next-priority line
> queues `L.L1` behind `B.B1`.

---

## 1. Why this loop exists

### The gap LOOP-A left open

LOOP-A shipped the end-to-end OSCAL submission chain: SSP → AP → AR → POA&M
plus IIW + RoE + signed manifest + RFC 3161 timestamp + INDEX.json wrapped
in a single signed tarball. From a *FedRAMP submission-package*
completeness perspective, the LOOP-A bundle is missing exactly two
mandatory deliverables that bridge "what the CSP does" to "what the
customer must do":

1. **The Customer Responsibility Matrix (CRM) / Control Implementation
   Summary (CIS) workbook — SSP Appendix J.** Per the FedRAMP CSP
   Authorization Playbook and the FedRAMP Rev5 SSP template package, the
   CIS/CRM workbook is REQUIRED and submitted as Appendix J. Every NIST
   800-53 Rev5 control at the Moderate baseline (≈325 controls) MUST be
   assigned exactly one responsibility bucket: CSP-implemented,
   Customer-implemented, Shared, Inherited, or Not-Applicable. Without
   this workbook the package is incomplete and the 3PAO cannot complete
   the SAR (Section 11.4 of the SAR template explicitly references CRM
   bucket counts in the executive summary).

2. **The Leveraged-Authorization Inheritance Document.** Per FedRAMP
   Authorization Boundary Guidance (RFC-0004) and the OSCAL SSP
   `leveraged-authorization` element + Component Definition model, when a
   CSO is built ON TOP OF an already-FedRAMP-Authorized IaaS/PaaS (e.g.
   AWS GovCloud, GCP Assured Workloads, Azure Government), the CSO MUST
   enumerate which controls it inherits from the underlying provider's
   authorization. The inherited-control list comes from the provider's
   own CRM (the customer-facing side of the provider's
   CSP-implemented/Customer-implemented/Shared/Inherited matrix). Without
   this enumeration, every "Inherited" cell in the CSO's own CRM (per
   slice L.L1) is unsourced.

### Verbatim language from the FedRAMP CSP Authorization Playbook (SSP Appendix J)

The authoritative obligation (paraphrased + cited verbatim in
ADDITIONAL-LOOPS-AUDIT.md §2 LOOP-L):

> "CSPs are required to submit a Control Implementation Summary/Customer
> Responsibility Matrix (CIS/CRM) workbook as Appendix J to the System
> Security Plan (SSP). The CIS/CRM workbook identifies security controls
> that the CSP is responsible for implementing, security controls that
> the customer is responsible for implementing, security controls where
> there is a shared CSP/customer responsibility, and security controls
> that are inherited from an underlying FedRAMP Authorized
> Infrastructure-as-a-Service (IaaS) or Platform-as-a-Service (PaaS)."
> — FedRAMP CSP Authorization Playbook (SSP Appendix J section)

FedRAMP "Important Considerations" (Rev5):

> "Control authors should clearly indicate which portions of the security
> control are inherited and provide a description of what is inherited."

NIST SP 800-53 Rev5 §2.5 (Inheritance and Compensating Controls):

> "Controls are inheritable when their implementation is the
> responsibility of an external system, organization, or service.
> Inherited controls are documented in the security plan along with the
> identifier of the providing entity and a description of the inherited
> control."

NIST SP 800-37 Rev2 §2.5 (RMF Step 3 — Implement Controls / Inheritance):

> "Controls inheritance is an effective way for organizations to reduce
> the cost of implementing security and privacy controls by leveraging
> the work already performed by other organizations (e.g., common control
> providers)."

### Artifacts LOOP-L delivers

| # | Artifact | Source | Consumer |
|---|---|---|---|
| 1 | `core/cis-crm-emit.ts` — CIS/CRM Workbook generator (SSP Appendix J) | L.L1 | OSCAL SSP back-matter resource; included in LOOP-A.A4 bundle |
| 2 | `out/cis-crm-workbook.xlsx` — the .xlsx CRM workbook itself, signed | L.L1 | 3PAO + FedRAMP PMO + AO |
| 3 | `out/cis-crm-workbook.json` — machine-readable companion | L.L1 | OSCAL SSP `implemented-requirements[].by-components[].responsible-roles[]` |
| 4 | `core/inheritance-trace.ts` — inheritance map builder | L.L2 | L.L1 (Inherited bucket), L.L3 (gap detector), L.L4 (renderer) |
| 5 | `out/leveraged-authorizations.json` — per-leveraged-provider enumeration | L.L2 | OSCAL SSP `leveraged-authorization[]` + back-matter `resources[type=service]` |
| 6 | `core/oscal-component-def.ts` — OSCAL Component Definition emitter (per leveraged provider) | L.L2 | SSP back-matter `resources[].rlinks[]` |
| 7 | `out/components/aws-govcloud.component-definition.json` (etc.) | L.L2 | OSCAL chain |
| 8 | `core/crm-gap-report.ts` — gap detector | L.L3 | POA&M (if a Moderate control is neither Implemented nor Inherited, emit a finding) + STATUS.md |
| 9 | `out/cis-crm-gap-report.md` + `out/cis-crm-gap-report.json` | L.L3 | 3PAO + AO + Submission bundle |
| 10 | `core/crm-split-renderer.ts` — per-control responsibility renderer | L.L4 | SSP narrative library + the SSP .docx renderer (LOOP-A SSP-2) |
| 11 | `out/crm-per-control-narratives/*.md` | L.L4 | SSP §13 control implementation narratives |
| 12 | `config/responsibility-matrix.yaml` — committed operator config | L.L1 + L.L4 | Single source of truth for per-control responsibility |
| 13 | `docs/leveraged-authorizations.generated.json` — committed lookup table for PA-IDs | L.L2 | leveraged-authorizations.json provenance |

### Authorization-package gaps closed

| Package gap | Slice | Authoritative source |
|---|---|---|
| SSP Appendix J (CIS/CRM workbook) absent from submission bundle | L.L1 | FedRAMP CSP Authorization Playbook §SSP appendices; FedRAMP CIS/CRM Workbook template (SSP-A12) |
| OSCAL SSP `leveraged-authorization[]` element absent or stub | L.L2 | OSCAL SSP v1.1.2 `system-security-plan.system-implementation.leveraged-authorizations[]` |
| OSCAL Component Definition documents for leveraged IaaS/PaaS absent | L.L2 | OSCAL Component Definition v1.1.2 model |
| Moderate-baseline controls with no responsibility designation (silent gap) | L.L3 | NIST SP 800-53B Rev5 (Moderate baseline = 287 controls + enhancements); FedRAMP Rev5 baseline ≈325 |
| Inherited cells in CRM with no provider citation | L.L3 | FedRAMP CSP Authorization Playbook §SSP Appendix J |
| SSP §13 narratives lack per-control responsibility split | L.L4 | FedRAMP Rev5 SSP Template §13 (Control Implementation); NIST 800-53 Rev5 §2.5 |

---

## 2. Connection to FedPy mission

FedPy's mission (cited verbatim from `README.md` + project memory): a
read-only TypeScript collector + emitter that produces evidence-grade
artifacts for FedRAMP 20x Phase Two Moderate at GA — KSI envelopes,
OSCAL SSP/AP/AR/POA&M, IIW, RoE, signed manifest — under the REO
standard (CLAUDE.md), with operator-supplied data flowing through
trackers / config / tags / CLI and never silently defaulted.

LOOP-L plugs directly into FedPy as follows:

### Existing collectors / modules LOOP-L EXTENDS or READS FROM

- **`core/inventory.json` + `inventory-emit.ts`** — read to determine
  which leveraged-authorization providers are in scope (e.g. if any
  inventory asset has `provider: aws` AND `account_partition: aws-us-gov`,
  AWS GovCloud is a leveraged provider). L.L2 uses this discovery to
  decide which Component Definition documents to emit.
- **`core/control-benchmark.ts`** — already enumerates which NIST 800-53
  Rev5 controls are tested at Low/Moderate/High. L.L1 reads this to drive
  the row set of the CIS/CRM workbook (rows = Moderate baseline controls).
- **`core/oscal-ssp.ts`** — L.L2 extends to populate
  `system-implementation.leveraged-authorizations[]` +
  `back-matter.resources[type=service]`. L.L4 extends to populate
  `control-implementation.implemented-requirements[].by-components[].responsible-roles[]`.
- **`core/oscal-poam.ts`** — L.L3 emits a finding (via
  `core/findings.ts`) for any Moderate-baseline control with no
  responsibility designation. The finding flows into POA&M under
  severity=medium (the gap is documentary, not technical, but it blocks
  submission).
- **`core/submission-bundle.ts`** — extended with new well-known roles
  `cis-crm-workbook-xlsx`, `cis-crm-workbook-json`, `cis-crm-gap-report-md`,
  `cis-crm-gap-report-json`, `leveraged-authorizations-json`,
  `oscal-component-definition`, `crm-per-control-narratives-tarball`.
- **`core/ksi-map.ts`** — read to map KSI → NIST 800-53 control IDs; this
  mapping is the bridge from per-KSI evidence (FedPy's native unit) to
  the per-control rows of the CIS/CRM workbook.
- **`providers/{aws,gcp,azure}/reference-arch.ts`** — already
  cross-references CSP service inventory against the published FedRAMP
  services-in-scope lists. L.L2 reuses this to derive the leveraged-
  authorization PA-id lookup chain.
- **`providers/{aws,gcp,azure}/discover.ts`** — region / account /
  subscription enumeration informs which leveraged auth(s) apply.
- **`docs/oscal/oscal_ssp_schema.v1.1.2.json`** — committed schema; the
  `leveraged-authorization` element keys and `responsible-roles` schema
  drive L.L2 + L.L4.
- **`core/sign.ts`** + **`core/timestamp.ts`** — all LOOP-L emitted
  artifacts ride the existing Ed25519 + RFC 3161 pipeline; nothing in
  LOOP-L re-implements signing.
- **`core/zip.ts`** — used by L.L1 to compose the .xlsx workbook (.xlsx
  is a ZIP-of-XML structure; FedPy already uses pure-JS OOXML composition
  for `core/ssp-docx.ts` and `core/inventory-workbook.ts`).

### NEW modules LOOP-L adds

- `core/cis-crm-emit.ts` — Appendix J workbook + JSON twin.
- `core/inheritance-trace.ts` — pure builder + on-disk emit.
- `core/oscal-component-def.ts` — per-provider Component Definition file.
- `core/crm-gap-report.ts` — gap detector + report.
- `core/crm-split-renderer.ts` — per-control narrative.
- `core/responsibility-matrix.ts` — typed loader for the operator's
  `config/responsibility-matrix.yaml`.
- `docs/oscal/oscal_component-definition_schema.v1.1.2.json` — committed
  schema (download from NIST OSCAL repo); used by L.L2 for ajv validation.
- `docs/leveraged-authorizations.generated.json` — committed lookup of
  PA-IDs per provider (AWS GovCloud, AWS US-East/West GovCloud, AWS
  Commercial, GCP Assured Workloads, GCP Commercial, Azure Government,
  Azure Commercial); operator-supplied per ADDITIONAL-LOOPS-AUDIT.md §5.10.

### NEW tracker surfaces

LOOP-L is largely operator-config-driven (the responsibility-matrix is a
committed YAML), but the audit calls for a tracker UI for matrix
authoring (audit slice listed as "L.L4 — Tracker UI for responsibility-
matrix authoring"). After consultation with the existing tracker
patterns (B.B3, B.B4), LOOP-L's L.L4 is repurposed AWAY from a tracker
UI and INTO the **per-control responsibility-split renderer** — keeping
LOOP-L purely under `cloud-evidence/` and avoiding tracker scope creep.
A future LOOP-L extension or LOOP-I dashboard surface can add the
authoring UI (filed in §6 open questions). This keeps LOOP-L cohesive
and shippable in the 4-slice budget the audit estimates.

---

## 3. Dependencies

### Loops / slices that MUST complete first

| Dep | Why |
|---|---|
| LOOP-A.A0 (SSP-1, SSP-2 — already done) | L.L2 wires `leveraged-authorizations[]` into the OSCAL SSP; L.L4 wires `responsible-roles[]` into `implemented-requirements[]`. The SSP emitter must already exist. |
| LOOP-A.A1 (POA&M emitter — done) | L.L3 emits findings for "no-responsibility" controls into the POA&M pipeline. |
| LOOP-A.A4 (submission bundler — done) | L.L1, L.L2, L.L3 register new roles in the well-known catalogue. |
| `core/control-benchmark.ts` (done) | L.L1 reads this to enumerate Moderate-baseline controls (rows of the workbook). |
| `core/ksi-map.ts` (done) | L.L1 maps KSI evidence to NIST controls for the CSP-implemented column. |
| `core/inventory.json` + `providers/*/discover.ts` (done) | L.L2 derives which leveraged providers are in scope from real fleet enumeration (AWS partition, GCP project metadata, Azure subscription cloud). |
| `providers/{aws,gcp,azure}/reference-arch.ts` (done) | L.L2 inheritable-control list cross-references; the audit module already maps services-in-scope. |
| LOOP-C.C5 (FIPS 199 worksheet — pending) | OPTIONAL — L.L1 emits Low/Moderate/High row sets; if C.C5 is shipped first, L.L1 reads the operator's declared impact tier to pick the row set. If C.C5 is not yet shipped, L.L1 defaults to Moderate (per project memory: 20x Phase Two Moderate at GA). |
| LOOP-J.J2 (subprocessor inventory — pending) | OPTIONAL — distinct from leveraged-authorization but related; L.L2 cross-checks that no subprocessor is also a leveraged-authorization provider (would be a categorization error). |

### Existing files this loop EXTENDS

| File | Modification |
|---|---|
| `cloud-evidence/core/oscal-ssp.ts` | L.L2 adds `system-implementation.leveraged-authorizations[]` from `out/leveraged-authorizations.json`; populates `back-matter.resources[type=service]` with `rlinks[]` to each component-definition file. L.L4 populates `control-implementation.implemented-requirements[].by-components[].responsible-roles[]` from `out/cis-crm-workbook.json`. |
| `cloud-evidence/core/oscal-poam.ts` | L.L3 calls `core/findings.ts` to add findings for no-responsibility controls; flows through the existing POA&M pipeline. |
| `cloud-evidence/core/orchestrator.ts` | New flags: `--crm` (L.L1), `--leveraged-auth` (L.L2), `--crm-gap` (L.L3), `--crm-narratives` (L.L4), `--strict-crm` (gate). Env equivalents. |
| `cloud-evidence/core/submission-bundle.ts` | Add ≥7 new roles (see §2). |
| `cloud-evidence/core/findings.ts` | L.L3 emits a new finding family `crm:no-responsibility` (per-control). |
| `cloud-evidence/core/ssp-docx.ts` | L.L4 reads per-control narratives; renders them into the .docx §13. |
| `cloud-evidence/CHANGELOG.md` | Unreleased entry per slice (see §9). |
| `cloud-evidence/docs/STATUS.md` | Per-slice rows added when audit ratified + per-slice status line per ship. |
| `cloud-evidence/docs/sections/SECTION-A.md` | Reflect new bundled artifacts (A23 CRM workbook, A24 leveraged-authorization Component-Def doc). |
| `cloud-evidence/docs/sections/SECTION-E.md` | Cross-reference: every NIST control now has a per-control responsibility split. |

### Loops UNBLOCKED when LOOP-L is complete

| Unblocked loop | Reason |
|---|---|
| LOOP-C.C7 — Risk Management Strategy doc | RMS narrative references the CRM bucket counts + the leveraged-auth inheritance list. |
| LOOP-C.C8 — Authorization request cover letter | Cover letter cites the CRM workbook by name + page count. |
| LOOP-C.C9 — Baseline Configuration doc | References "controls inherited from <leveraged provider>" using L.L2's enumeration. |
| LOOP-M.M2 — Privacy Continuous Monitoring strategy | PCM strategy mentions which privacy controls are inherited vs customer-implemented (uses L.L1's PT-family rows). |
| LOOP-Q.Q1 — Marketplace metadata emitter | Marketplace listing references leveraged authorizations by PA-id (uses L.L2's enumeration). |
| LOOP-E.E4 — Annual SSP review | Annual review compares last-year CRM bucket counts against this year's (uses L.L1's JSON twin). |
| LOOP-F.F1 — 3PAO sign-off UI | 3PAO sign-off includes per-control responsibility confirmation (uses L.L4's per-control narrative). |

---

## 4. Authoritative sources

Every URL + spec referenced in any LOOP-L slice. Quotes are verbatim
where retrievable; where the source PDF returns HTTP 403 to anonymous
fetches (FedRAMP CSP Authorization Playbook PDF, FedRAMP CIS/CRM
Workbook template .xlsx), the slice records the URL + the implementer
must download the file from the cited URL into
`cloud-evidence/docs/sources/` and re-quote in the slice docstring per
the same pattern LOOP-B.B2 follows for the FedRAMP CMP PDF.

### FedRAMP

- **FedRAMP CSP Authorization Playbook (Rev5)** —
  https://www.fedramp.gov/docs/rev5/playbook/csp/ — landing page; the
  SSP Appendix J section enumerates the CIS/CRM workbook obligation.
  Verbatim quote (from ADDITIONAL-LOOPS-AUDIT.md §2 LOOP-L, sourced
  from this playbook):
  > "CSPs are required to submit a Control Implementation Summary /
  > Customer Responsibility Matrix (CIS/CRM) workbook as Appendix J to
  > the System Security Plan (SSP). The CIS/CRM workbook identifies
  > security controls that the CSP is responsible for implementing,
  > security controls that the customer is responsible for implementing,
  > security controls where there is a shared CSP/customer
  > responsibility, and security controls that are inherited from an
  > underlying FedRAMP Authorized Infrastructure-as-a-Service (IaaS) or
  > Platform-as-a-Service (PaaS)."

- **FedRAMP Authorization Boundary Guidance** —
  https://www.fedramp.gov/assets/resources/documents/CSP_A_FedRAMP_Authorization_Boundary_Guidance.pdf
  — defines the authorization boundary that the CRM partitions by
  responsibility. PDF download required (3PAO + operator path; the
  implementer downloads to `cloud-evidence/docs/sources/`).

- **FedRAMP CIS/CRM Workbook template (SSP Appendix J)** — published at
  https://www.fedramp.gov/templates/ or
  https://www.fedramp.gov/assets/resources/templates/ — the canonical
  .xlsx the implementer mirrors. ADDITIONAL-LOOPS-AUDIT.md §5.5 notes
  the format is "still in revision per 2026 Consolidated Rules
  planning" so L.L1 emits a `package_format_version` analogous to
  LOOP-A.A4's `package_format_version`.

- **FedRAMP Rev5 SSP Template §13 (Control Implementation)** — referenced
  by L.L4. The "Implementation Status" + "Control Origination" tables
  in §13 are FedRAMP's canonical responsibility-split fields. Five
  responsibility "Control Origination" values per FedRAMP:
  Service Provider Corporate, Service Provider System Specific, Service
  Provider Hybrid, Configured by Customer, Provided by Customer,
  Shared, Inherited from pre-existing Provisional Authorization. (FedRAMP
  uses a 7-bucket Origination set in the Word template; L.L1 collapses
  to the 5-bucket workbook set per CIS/CRM convention. The mapping is
  documented in L.L1 §schemas.)

- **FedRAMP Marketplace** — https://marketplace.fedramp.gov/ — source
  of leveraged-authorization PA-ids. ADDITIONAL-LOOPS-AUDIT.md §5.10:
  > "FedRAMP PA-ids (e.g., 'F1411040093' for AWS GovCloud) are committed
  > via PMO; LOOP-L.L2 needs a committed lookup table at
  > cloud-evidence/docs/leveraged-authorizations.generated.json."

- **FedRAMP "Important Considerations" (Rev5)** — verbatim quote (per
  ADDITIONAL-LOOPS-AUDIT.md):
  > "Control authors should clearly indicate which portions of the
  > security control are inherited and provide a description of what is
  > inherited."

### NIST

- **NIST SP 800-53 Rev5** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
  - §2.5 (Inheritance and Compensating Controls):
    > "Controls are inheritable when their implementation is the
    > responsibility of an external system, organization, or service.
    > Inherited controls are documented in the security plan along with
    > the identifier of the providing entity and a description of the
    > inherited control."
  - §3.2 — Control Implementation; the responsibility-split obligation
    derives from PL-2 (System Security Plan), which requires the SSP to
    "identify any security-related restrictions or requirements regarding
    the use of the system."
  - SA-9 (External System Services) — inherited-control documentation
    obligation when services come from an external provider.

- **NIST SP 800-53B Rev5 — Control Baselines** —
  https://csrc.nist.gov/pubs/sp/800/53/b/upd1/final
  - Moderate baseline: 287 base controls (per the published 800-53B
    Rev5 Appendix A Moderate table). FedRAMP Rev5 Moderate baseline adds
    FedRAMP-specific control enhancements pushing the total to ~325; L.L1
    reads the FRMR catalog to settle on the exact row set
    (`docs/frmr-requirements.generated.json` — the authoritative source
    of truth per project memory).
  - Low baseline: 156 base controls; High baseline: 370.

- **NIST SP 800-37 Rev2 — Risk Management Framework** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-37r2.pdf
  - §2.5 (Control Inheritance):
    > "Common controls are inherited by one or more organizational
    > information systems. Authorization is generally inherited from the
    > organization providing the common control to the organization
    > leveraging it."
  - §3.3 — Step 3 (Implement Controls); identifies the SSP `Implementation
    Statement` per control with responsibility designation as a mandatory
    artifact.

### OSCAL

- **OSCAL System Security Plan v1.1.2** — committed at
  `cloud-evidence/docs/oscal/oscal_ssp_schema.v1.1.2.json`. NIST OSCAL
  reference:
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/system-security-plan/json-reference/
  - `system-security-plan.system-implementation.leveraged-authorizations[]`
    — array of objects with required fields:
    - `uuid` (string, UUID v4)
    - `title` (string, name of leveraged authorization)
    - `party-uuid` (string, UUID v4 — references a party in metadata)
    - `date-authorized` (string, ISO date — authorization date of the
      leveraged provider)
    - `links[]` (optional, with `rel: 'leveraged-authorization-package'`
      pointing at the back-matter resource referencing the
      component-definition file)
    - `props[]` (optional, extension point for `fedramp-pa-id` etc.)
    - `remarks` (optional, markdown narrative)
  - `control-implementation.implemented-requirements[].by-components[]`
    — array per OSCAL component (e.g. one for the CSO, one for each
    leveraged provider). Each `by-component` carries:
    - `responsible-roles[]` — role-id + party-uuids referencing who is
      responsible. CRM bucket maps to role-id values:
      `provider`, `customer`, `shared-csp-customer`, `inherited`,
      `not-applicable`.
    - `inherited[]` (where applicable) — per-control inherited statement
      referencing the leveraged-authorization UUID.
  - `back-matter.resources[]` — `type: 'service'` is used per FedRAMP
    convention for leveraged-cloud component descriptions; `rlinks[]`
    point at the per-leveraged-provider component-definition JSON file.

- **OSCAL Component Definition v1.1.2** —
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/component-definition/json-reference/
  - `component-definition.components[]` — each entry has:
    - `uuid`, `type` ('service' for IaaS/PaaS), `title`, `description`,
      `protocols[]` (optional), `props[]`, `links[]`,
      `responsible-roles[]`,
      `control-implementations[]` — each implementation enumerates which
      controls the component implements and which are exposed for
      inheritance.

- **OSCAL Catalog / Profile** — the Moderate Profile (FedRAMP Rev5
  Moderate) committed under `cloud-evidence/docs/oscal/` or fetched at
  https://github.com/GSA/fedramp-automation/blob/master/dist/content/rev5/baselines/json/FedRAMP_rev5_MODERATE-baseline_profile.json
  — the canonical Moderate baseline source. L.L1 may use this as a
  cross-check against the FRMR-catalog-derived row set.

### Cloud provider authoritative pages (for L.L2's PA-ID lookup table)

- **AWS Services in Scope (FedRAMP)** —
  https://aws.amazon.com/compliance/services-in-scope/FedRAMP/ — lists
  every AWS service authorized at Moderate / High in AWS US-East/West
  (Commercial) and AWS GovCloud. The PA-ID for AWS GovCloud
  (`F1411040093` per project memory; to be re-verified by operator from
  marketplace.fedramp.gov), the PA-ID for AWS US-East/West Moderate
  (`F1206051645`), and the PA-IDs for AWS High deployments are
  committed in the lookup table.
- **GCP FedRAMP (Assured Workloads)** —
  https://cloud.google.com/security/compliance/fedramp — GCP's
  FedRAMP page. PA-IDs for GCP High (Assured Workloads US) and GCP
  Moderate.
- **Azure FedRAMP (Azure Government)** —
  https://learn.microsoft.com/en-us/azure/compliance/offerings/offering-fedramp
  — Azure's FedRAMP page. PA-IDs for Azure Government High and Azure
  Commercial High. Verbatim from the page (extracted at planning time):
  > "Both Azure and Azure Government maintain FedRAMP High P-ATOs issued
  > by the JAB in addition to more than 400 Moderate and High ATOs
  > issued by individual federal agencies for the in-scope services."

### KEY caveat (from the audit §5)

ADDITIONAL-LOOPS-AUDIT.md §5.5:

> "**CRM template format final** — the FedRAMP CIS/CRM workbook format
> is still in revision per 2026 Consolidated Rules planning. LOOP-L.L1
> should version-pin the schema and emit a `package_format_version` for
> the CRM analogous to LOOP-A.A4."

L.L1 mirrors LOOP-A.A4's pattern: `cis_crm_format_version: "20x.crm.preview.2026"`.

---

## 5. Per-slice implementation specs

### Slice L.L1 — CRM Workbook generator (SSP Appendix J)

**Why this slice**: The FedRAMP submission package without the CIS/CRM
workbook is incomplete. Today there is no way to emit it from FedPy.
This slice produces the Appendix J workbook (.xlsx) plus a machine-
readable JSON twin (consumed by L.L2 + L.L4 + LOOP-C/E loops).

**Connection to FedPy mission**: The workbook ROWS come from
`docs/frmr-requirements.generated.json` (FRMR catalog) filtered by the
operator's declared impact tier (default Moderate from project memory).
The workbook COLUMNS for CSP-implemented controls draw on per-KSI
evidence (KSI → NIST control mapping from `core/ksi-map.ts`). The
Inherited column for L.L2's leveraged-authorization inheritance map.
The Customer-implemented + Shared columns from the operator's committed
`config/responsibility-matrix.yaml`. Result: the workbook is fully
traceable byte-for-byte to either real catalog data, real cloud evidence,
or operator-supplied YAML.

**Files to create**:
- `cloud-evidence/core/cis-crm-emit.ts` — pure builder + disk emitter:
  reads inputs, computes per-control responsibility row, emits .xlsx +
  .json. ~700 lines.
- `cloud-evidence/core/responsibility-matrix.ts` — typed loader for the
  operator's committed `config/responsibility-matrix.yaml`. Validates
  every control id against the loaded NIST + FRMR catalog. ~200 lines.
- `cloud-evidence/core/cis-crm-xlsx.ts` — pure-JS .xlsx renderer reusing
  the OOXML approach from `core/inventory-workbook.ts` (no external
  dependency; same ZIP + worksheet XML composition). ~400 lines.
- `cloud-evidence/config/responsibility-matrix.example.yaml` — committed
  example YAML the operator copies + customises.
- `cloud-evidence/tests/core/cis-crm-emit.test.ts` — integration tests
  (load fixture FRMR + responsibility YAML; verify workbook structure).
- `cloud-evidence/tests/core/cis-crm-xlsx.test.ts` — pure renderer tests
  (column widths, header row, conditional formatting).
- `cloud-evidence/tests/core/responsibility-matrix.test.ts` — YAML loader
  tests.
- `cloud-evidence/tests/fixtures/cis-crm/` — fixture YAML +
  mini-FRMR-catalog used by tests.

**Files to extend**:
- `core/orchestrator.ts` — new `--crm` flag + env
  `CLOUD_EVIDENCE_CRM`; `--crm-config <path>` defaulting to
  `config/responsibility-matrix.yaml`; `--strict-crm` (gate: refuses to
  emit if any Moderate control has no responsibility). Runs AFTER the
  per-KSI collectors (so KSI evidence is available) and BEFORE
  `--oscal-ssp` (so L.L4 can fill SSP `responsible-roles[]`).
- `core/submission-bundle.ts` — add roles `cis-crm-workbook-xlsx`,
  `cis-crm-workbook-json`. Filenames `cis-crm-workbook.xlsx` and
  `cis-crm-workbook.json`.
- `docs/sections/SECTION-A.md` — add A23 row.

**Schemas / standards**:
- **FedRAMP CIS/CRM Workbook column set** (from the template + the
  audit). Required columns (verbatim FedRAMP labels):
  - **Control ID** (e.g. "AC-2", "AC-2(1)")
  - **Control Description** (verbatim from NIST 800-53)
  - **Responsible Role** (5-bucket: `Service Provider` /
    `Customer` / `Shared` / `Inherited from PA-id` / `Not Applicable`)
  - **Implementation Description** (text)
  - **Implementation Status** ('Implemented', 'Partially Implemented',
    'Planned', 'Alternative Implementation', 'Not Applicable')
  - **Inherited From** (PA-id of leveraged authorization, or null)
  - **Customer Responsibility** (text — what the customer must do)
- **OSCAL responsible-roles role-id values** —
  L.L1 emits the JSON twin keyed off these roles for L.L4 to map into
  the SSP `responsible-roles[]` arrays.
- **NIST 800-53B Rev5 Moderate baseline** — 287 base controls; FedRAMP
  Rev5 Moderate adds enhancements (≈325 total). Row set sourced from
  FRMR catalog `docs/frmr-requirements.generated.json` filtered by
  `impact_tier === 'moderate'`.

**Build steps**:

1. Define typed interfaces in `core/cis-crm-emit.ts`:
   ```ts
   export type ResponsibilityBucket = 'service-provider' | 'customer' | 'shared' | 'inherited' | 'not-applicable';
   export type ImplementationStatus = 'implemented' | 'partially-implemented' | 'planned' | 'alternative-implementation' | 'not-applicable';

   export interface CisCrmRow {
     control_id: string;
     control_title: string;
     control_description: string;
     responsibility: ResponsibilityBucket;
     responsibility_source: 'ksi-evidence' | 'inherited-trace' | 'responsibility-matrix-yaml' | 'REQUIRES-OPERATOR-INPUT';
     implementation_status: ImplementationStatus;
     implementation_status_source: 'ksi-finding' | 'responsibility-matrix-yaml' | 'REQUIRES-OPERATOR-INPUT';
     implementation_description: string;
     implementation_description_source: 'ksi-evidence' | 'responsibility-matrix-yaml' | 'inherited-narrative' | 'REQUIRES-OPERATOR-INPUT';
     inherited_from_pa_id?: string;
     inherited_from_title?: string;
     customer_responsibility: string;
     customer_responsibility_source: 'responsibility-matrix-yaml' | 'REQUIRES-OPERATOR-INPUT' | 'not-applicable';
     ksi_ids?: string[];               // KSIs that contribute evidence to this row
     remarks?: string;
   }

   export interface CisCrmWorkbook {
     metadata: {
       system_name: string;
       system_id: string;
       impact_tier: 'low' | 'moderate' | 'high';
       generated_at: string;          // ISO timestamp
       cis_crm_format_version: '20x.crm.preview.2026';
       frmr_version: string;
       nist_catalog_version: 'Rev5';
       package_format_version: '20x.phase-two.preview.2026';
     };
     leveraged_authorizations: Array<{
       pa_id: string;
       title: string;
       provider: 'aws' | 'gcp' | 'azure' | string;
     }>;
     rows: CisCrmRow[];
     summary: {
       total: number;
       service_provider: number;
       customer: number;
       shared: number;
       inherited: number;
       not_applicable: number;
       requires_operator_input: number;
     };
     provenance: {
       emitter: 'core/cis-crm-emit.ts';
       emittedAt: string;
       sourceCalls: string[];
       signingKeyId?: string;
     };
   }
   ```

2. Pure builder signature:
   ```ts
   export function buildCisCrmWorkbook(inputs: CisCrmInputs): CisCrmWorkbook;
   ```
   where `CisCrmInputs` carries: parsed FRMR catalog (filtered by impact
   tier), parsed responsibility-matrix.yaml, KSI evidence envelopes
   read from `out/KSI-*.json`, leveraged-authorizations.json (when
   L.L2 has run), and system identity (system_name, system_id from
   `core/orchestrator.ts` flags).

3. **Per-control row derivation** (priority cascade):
   - Step A: read responsibility-matrix.yaml entry for this control_id.
     If present, use its `responsibility` + `implementation_description`
     + `customer_responsibility` verbatim. Set sources to
     `'responsibility-matrix-yaml'`.
   - Step B: if no YAML entry AND control_id ∈ inherited-trace.json,
     set `responsibility = 'inherited'`, `inherited_from_pa_id`,
     `inherited_from_title`, `implementation_description` from
     inherited-trace narrative. Sources `'inherited-trace'`.
   - Step C: if no YAML entry AND no inherited match, check KSI
     evidence. For each KSI in `ksi-map.ts` mapping to this control,
     pull pass/fail status. If ALL mapped KSIs pass AND any of them is
     CSP-implemented (per KSI taxonomy in FRMR), set
     `responsibility = 'service-provider'`,
     `implementation_status = 'implemented'`,
     `implementation_description = <auto-narrative from KSI evidence>`.
     Sources `'ksi-evidence'`.
   - Step D: if NONE of A-C applies, emit
     `responsibility_source: 'REQUIRES-OPERATOR-INPUT'`,
     `responsibility: 'not-applicable'` placeholder visible-but-marked,
     and (in `--strict-crm`) abort. This is the gap L.L3 detects.

4. **Implementation status derivation**: when responsibility is
   `service-provider`, status comes from the worst case across mapped
   KSIs: all-pass → 'implemented'; some-pass → 'partially-implemented';
   no KSI mapped → 'planned' (operator action required, marker
   `REQUIRES-OPERATOR-INPUT` on source); KSI catalog says control not
   applicable to this CSO type → 'not-applicable'.

5. **Customer responsibility text**: from YAML when present; otherwise
   `REQUIRES-OPERATOR-INPUT: customer responsibility undefined`.

6. **Inherited row generation**:
   - For each control where `responsibility = 'inherited'`, the row
     reads from `out/inheritance-trace.json` (built by L.L2). Field
     `inherited_from_pa_id` carries the FedRAMP PA-id of the leveraged
     provider; `inherited_from_title` carries the title (e.g. "AWS
     GovCloud — F1411040093").
   - If L.L2 has NOT yet run, L.L1 emits with `inherited_from_pa_id:
     'REQUIRES-OPERATOR-INPUT'`. The orchestrator order
     (`--leveraged-auth` BEFORE `--crm`) prevents this case in normal
     flow.

7. **XLSX rendering** (`core/cis-crm-xlsx.ts`):
   - 7 worksheet structure (one per FedRAMP CIS/CRM convention):
     1. **Cover** — system name, impact tier, generated_at,
        cis_crm_format_version.
     2. **Summary** — counts per responsibility bucket + bar chart.
     3. **AC** family — rows for AC-* controls.
     4. **AU through PS** — one sheet per family group.
     5. **RA + SA + SC** — combined; high column density.
     6. **SI + SR** — combined.
     7. **Inherited Controls** — sub-view of all `inherited` rows with
        the inherited_from columns expanded.
   - Column widths fixed per the FedRAMP template (Control ID 12,
     Description 60, Responsibility 18, Implementation Status 20,
     Implementation Description 80, Inherited From 24, Customer
     Responsibility 60).
   - Header row frozen.
   - Conditional formatting: `REQUIRES-OPERATOR-INPUT` cells highlighted
     red; `inherited` rows shaded light blue; `shared` rows shaded
     light yellow.

8. **Disk emitter**:
   ```ts
   export interface CisCrmEmitOptions {
     outDir: string;
     frmrPath?: string;            // default: docs/frmr-requirements.generated.json
     responsibilityMatrixPath?: string;  // default: config/responsibility-matrix.yaml
     inheritanceTracePath?: string;     // default: outDir/inheritance-trace.json
     leveragedAuthsPath?: string;       // default: outDir/leveraged-authorizations.json
     systemName: string;
     systemId: string;
     impactTier: 'low' | 'moderate' | 'high';
     runId: string;
   }
   export interface CisCrmEmitResult {
     xlsxPath: string;
     jsonPath: string;
     row_count: number;
     bucket_summary: CisCrmWorkbook['summary'];
     requires_operator_input_count: number;
     leveraged_auth_count: number;
   }
   export async function emitCisCrm(opts: CisCrmEmitOptions): Promise<CisCrmEmitResult>;
   ```

9. **Orchestrator wiring**: `--crm` flag invokes `emitCisCrm()`. Runs
   AFTER per-KSI collectors AND L.L2 (`--leveraged-auth`); runs BEFORE
   `--oscal-ssp` (so L.L4 can fill SSP `responsible-roles`).

10. **Provenance block**: `cis-crm-workbook.json` carries
    `provenance.emitter`, `provenance.emittedAt`,
    `provenance.sourceCalls` (every envelope read + every YAML loaded +
    every inheritance-trace lookup), and `provenance.signingKeyId`
    populated by the existing `core/sign.ts` pipeline.

11. **Bundler integration**: add to `submission-bundle.ts:WELL_KNOWN`:
    ```ts
    { role: 'cis-crm-workbook-xlsx', filename: 'cis-crm-workbook.xlsx', description: 'SSP Appendix J — Control Implementation Summary / Customer Responsibility Matrix workbook (LOOP-L.L1)' },
    { role: 'cis-crm-workbook-json', filename: 'cis-crm-workbook.json', description: 'Machine-readable CRM twin (LOOP-L.L1)' },
    ```

12. **Strict mode**: `--strict-crm` refuses to emit if ANY Moderate
    control's `responsibility_source` is `'REQUIRES-OPERATOR-INPUT'`.
    `--strict-crm` implies `--crm`.

**REQUIRES-OPERATOR-INPUT fields** (per REO Rule 4):

| Field | Source | Behavior when missing |
|---|---|---|
| Per-control responsibility (Customer / Shared / Not-Applicable) | `config/responsibility-matrix.yaml` | `responsibility_source = 'REQUIRES-OPERATOR-INPUT'`, surfaced on row + in L.L3 gap report; `--strict-crm` aborts |
| Implementation description (when not derivable from KSI) | YAML `implementation_description` per control | `implementation_description_source = 'REQUIRES-OPERATOR-INPUT'` |
| Customer responsibility text | YAML `customer_responsibility` per control | `customer_responsibility_source = 'REQUIRES-OPERATOR-INPUT'` |
| Impact tier (Low / Moderate / High) | CLI `--impact-level <tier>` OR LOOP-C.C5 worksheet | Defaults to `moderate` per project memory + audit guidance |
| System name + ID | CLI `--system-name`, `--system-id` (existing flags from LOOP-A) | Existing default behavior |
| `cis_crm_format_version` | Constant `'20x.crm.preview.2026'` (per audit §5.5) | N/A |

**Test specifications** (≥12):

1. `it('emits one row per Moderate-baseline control from the FRMR catalog')` — load fixture FRMR with 10 mock Moderate controls; assert 10 rows.
2. `it('respects --impact-level low to switch row set')` — fixture has 5 Low controls; with `impactTier: 'low'` assert 5 rows.
3. `it('derives responsibility from YAML when present')` — YAML maps AC-2 to `customer`; assert row `responsibility === 'customer'`, `responsibility_source === 'responsibility-matrix-yaml'`.
4. `it('marks REQUIRES-OPERATOR-INPUT when YAML missing entry')` — YAML omits AC-2; assert `responsibility_source === 'REQUIRES-OPERATOR-INPUT'`.
5. `it('derives inherited rows from inheritance-trace.json')` — trace contains AC-2 → AWS GovCloud; assert row `responsibility === 'inherited'`, `inherited_from_pa_id === 'F1411040093'`.
6. `it('derives service-provider from KSI evidence when YAML absent')` — fixture KSI IAM-MFA mapping to AC-2 with all-pass; assert row `responsibility === 'service-provider'`, `implementation_status === 'implemented'`.
7. `it('--strict-crm aborts when any control has REQUIRES-OPERATOR-INPUT responsibility')` — assert thrown error names the gap controls.
8. `it('emits all 7 worksheets including Cover + Summary + Inherited Controls')` — open emitted xlsx via SheetJS round-trip; assert sheet names.
9. `it('summary counts equal sum across buckets')` — bucket counts add to total.
10. `it('conditional formatting highlights REQUIRES-OPERATOR-INPUT cells red')` — parse XLSX styles XML; assert RGB FF0000 on those cells.
11. `it('emits provenance block on cis-crm-workbook.json with sourceCalls populated')` — `check:provenance` passes.
12. `it('package_format_version + cis_crm_format_version are pinned')` — assert constants.
13. `it('rejects YAML entry with unknown control_id')` — config loader throws typed error.
14. `it('rejects YAML entry with bucket not in 5-bucket set')` — config loader throws.
15. `it('responsibility-matrix.example.yaml validates against the loader')` — load example, assert no errors.
16. `it('bundler well-known catalogue includes cis-crm-workbook-xlsx + cis-crm-workbook-json')`.

**REO compliance** (specific):
- Every control row traces to either FRMR catalog (control_id +
  description), KSI evidence (CSP-implemented rows), inheritance trace
  (Inherited rows), responsibility-matrix.yaml (Customer / Shared / NA
  rows), OR a `REQUIRES-OPERATOR-INPUT` marker. No silent defaults.
- The .xlsx is composed via pure-JS OOXML (existing pattern); no
  python-docx / external dependency.
- Signed by existing `core/sign.ts` pipeline (both .xlsx + .json land in
  manifest glob).
- Provenance block on the JSON twin per REO Rule 2.6.

**Verification commands**:
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/cis-crm-emit.test.ts tests/core/cis-crm-xlsx.test.ts tests/core/responsibility-matrix.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
```

**Estimated effort**: 6 - 8 working days.

---

### Slice L.L2 — Inherited-controls tracker + Leveraged-Authorization enumeration

**Why this slice**: L.L1's `inherited` rows must point at REAL FedRAMP
PA-ids. L.L2 produces the enumeration: which leveraged-authorization
providers apply to this CSO + which controls each provider exposes for
inheritance. The output also wires into OSCAL SSP
`leveraged-authorizations[]` and emits per-provider Component Definition
JSON documents.

**Connection to FedPy mission**: Detection runs over real
`inventory.json` — if any asset has `provider: aws` AND
`account_partition: aws-us-gov`, AWS GovCloud is a leveraged
authorization. PA-id resolution reads
`docs/leveraged-authorizations.generated.json` (committed lookup,
operator-supplied per audit §5.10). Per-provider inheritable-control
lists come from the operator's
`config/leveraged-authorizations.yaml` (committed; operator transcribes
from the AWS/GCP/Azure FedRAMP CRM published to the FedRAMP Marketplace
secure-package portal). No silent defaults; never fabricate a PA-id;
never claim a control is inherited without a citation in the operator's
yaml.

**Files to create**:
- `cloud-evidence/core/inheritance-trace.ts` — pure builder + emitter
  for `out/inheritance-trace.json`. ~350 lines.
- `cloud-evidence/core/leveraged-auth-discovery.ts` — derives the
  in-scope leveraged providers from `inventory.json` + provider
  reference-arch modules. ~250 lines.
- `cloud-evidence/core/oscal-component-def.ts` — pure builder + per-
  provider OSCAL Component Definition emitter. ~500 lines.
- `cloud-evidence/config/leveraged-authorizations.example.yaml` — example
  operator copies + customises (lists which providers apply + which
  controls inherit from each).
- `cloud-evidence/docs/leveraged-authorizations.generated.json` —
  committed PA-id lookup table (one entry per known provider, per audit
  §5.10).
- `cloud-evidence/docs/oscal/oscal_component-definition_schema.v1.1.2.json`
  — committed schema (download from
  https://github.com/usnistgov/OSCAL/blob/main/json/schema/oscal_component-definition_schema.json).
- `cloud-evidence/tests/core/inheritance-trace.test.ts`.
- `cloud-evidence/tests/core/leveraged-auth-discovery.test.ts`.
- `cloud-evidence/tests/core/oscal-component-def.test.ts`.
- `cloud-evidence/tests/fixtures/leveraged-auth/` — fixture
  inventory.json + yaml + expected output.

**Files to extend**:
- `core/oscal-ssp.ts` — populate
  `system-implementation.leveraged-authorizations[]` from
  `out/leveraged-authorizations.json`; populate
  `back-matter.resources[]` with `type: 'service'` entries pointing at
  the emitted component-definition files.
- `core/orchestrator.ts` — new `--leveraged-auth` flag + env
  `CLOUD_EVIDENCE_LEVERAGED_AUTH`; `--leveraged-auth-config <path>`
  defaulting to `config/leveraged-authorizations.yaml`. Runs AFTER
  inventory collection AND BEFORE `--crm` (L.L1).
- `core/submission-bundle.ts` — add roles
  `leveraged-authorizations-json`, `oscal-component-definition`,
  `inheritance-trace-json`. Component-definition files use a glob
  (`out/components/*.component-definition.json`).
- `core/oscal-validate.ts` — extend with ajv schema validation for
  Component Definition.

**Schemas / standards**:
- **OSCAL System Security Plan v1.1.2** —
  `system-implementation.leveraged-authorizations[]` required fields:
  - `uuid` (string, UUID v4)
  - `title` (string)
  - `party-uuid` (string, UUID v4 — references metadata.parties[].uuid)
  - `date-authorized` (string, ISO date — leveraged provider's
    authorization date)
  - `links[]` (optional, with `rel: 'leveraged-authorization-package'`)
  - `props[]` (extension point for `fedramp-pa-id`,
    `leveraged-authorization-id`, `impact-level`)
  - `remarks` (optional, markdown)
- **OSCAL Component Definition v1.1.2** —
  `component-definition.components[]` per entry:
  - `uuid`, `type: 'service'`, `title`, `description`,
    `purpose` (FedRAMP convention: a one-sentence description of the
    service's purpose),
  - `props[]` — `fedramp-pa-id`, `service-name`,
    `service-region` (e.g. 'us-gov-west-1'),
  - `responsible-roles[]` — role-id 'provider' + party-uuid of the
    leveraged provider,
  - `control-implementations[]` — array of implementations; one entry
    per impact tier (low / moderate / high) the provider exposes for
    inheritance. Each implementation enumerates the controls the
    provider implements.
- **FedRAMP convention** for leveraged-authorization metadata: party
  represented in SSP `metadata.parties[]` as type='organization' with
  `extra-info.fedramp-pa-id`, `extra-info.cloud`, `extra-info.region`.
- **PA-id format**: FedRAMP-issued identifier; per audit §5.10 historic
  example `F1411040093` for AWS GovCloud. Format pattern:
  `^F\d{10}$`. The operator-committed lookup file enforces this regex.

**Build steps**:

1. Define typed interfaces in `core/inheritance-trace.ts`:
   ```ts
   export interface LeveragedAuthorization {
     uuid: string;
     pa_id: string;                  // e.g. 'F1411040093'
     title: string;                  // 'AWS GovCloud'
     provider: 'aws' | 'gcp' | 'azure' | string;
     date_authorized: string;        // ISO date
     impact_level: 'low' | 'moderate' | 'high';
     region: string;                 // 'us-gov-west-1' etc.
     party_uuid: string;             // matches SSP metadata.parties[].uuid
     marketplace_url?: string;       // e.g. 'https://marketplace.fedramp.gov/...'
     source: 'config-yaml' | 'lookup-table' | 'REQUIRES-OPERATOR-INPUT';
   }

   export interface InheritedControl {
     control_id: string;             // 'AC-2', 'AC-2(1)'
     inherited_from_pa_id: string;
     inherited_from_uuid: string;    // LeveragedAuthorization.uuid
     inheritance_scope: 'full' | 'partial' | 'hybrid';
     inheritance_description: string;
     source: 'config-yaml' | 'REQUIRES-OPERATOR-INPUT';
   }

   export interface InheritanceTrace {
     metadata: {
       generated_at: string;
       cis_crm_format_version: '20x.crm.preview.2026';
       impact_tier: 'low' | 'moderate' | 'high';
     };
     leveraged_authorizations: LeveragedAuthorization[];
     inherited_controls: InheritedControl[];
     by_control: Record<string, InheritedControl[]>;  // control_id → entries
     provenance: { emitter, emittedAt, sourceCalls };
   }
   ```

2. `leveraged-auth-discovery.ts` — pure builder:
   ```ts
   export interface DiscoveryInputs {
     inventory: Inventory;
     awsReferenceArch?: AwsReferenceArch;
     gcpReferenceArch?: GcpReferenceArch;
     azureReferenceArch?: AzureReferenceArch;
   }
   export function discoverLeveragedAuthorizations(inputs: DiscoveryInputs): {
     providers: Array<'aws-govcloud' | 'aws-commercial' | 'gcp-assured-workloads' | 'gcp-commercial' | 'azure-government' | 'azure-commercial'>;
     evidence: Array<{ provider: string; sourceCall: string; sample_asset_id: string }>;
   };
   ```
   Discovery rules (concrete):
   - AWS Commercial: any inventory asset with `provider === 'aws'` AND
     `account_partition === 'aws'` (default partition).
   - AWS GovCloud: any inventory asset with `provider === 'aws'` AND
     `account_partition === 'aws-us-gov'`.
   - GCP Commercial: any inventory asset with `provider === 'gcp'` AND
     `project_metadata.parent.type === 'organizations'` AND NOT
     `assured_workloads_enabled === true`.
   - GCP Assured Workloads: any inventory asset with `provider === 'gcp'`
     AND `assured_workloads_enabled === true`.
   - Azure Commercial: any inventory asset with `provider === 'azure'`
     AND `subscription_metadata.cloud === 'AzureCloud'`.
   - Azure Government: any inventory asset with `provider === 'azure'`
     AND `subscription_metadata.cloud === 'AzureUSGovernment'`.

3. `inheritance-trace.ts` — pure builder:
   ```ts
   export function buildInheritanceTrace(
     leveraged: LeveragedAuthorization[],
     config: LeveragedAuthYaml,
     impactTier: 'low' | 'moderate' | 'high',
   ): InheritanceTrace;
   ```
   Per leveraged-authorization, read the yaml's `inherited_controls[]`
   list (operator-supplied per provider, per impact tier). Validate
   every control_id against the loaded NIST Rev5 catalog. Build the
   `by_control` index for L.L1 + L.L3 lookups.

4. `oscal-component-def.ts` — per-provider emitter:
   ```ts
   export function buildComponentDefinition(
     leveraged: LeveragedAuthorization,
     inherited: InheritedControl[],
   ): OscalComponentDefinition;
   export async function emitComponentDefinitions(
     trace: InheritanceTrace,
     outDir: string,
   ): Promise<string[]>;  // returns the list of emitted file paths
   ```
   Emits one file per leveraged authorization:
   `out/components/<provider>-<region>.component-definition.json`.

5. **SSP integration** (`core/oscal-ssp.ts` extension):
   ```ts
   // In buildOscalSsp(), after metadata.parties construction:
   const leveragedAuthsPath = path.join(outDir, 'leveraged-authorizations.json');
   if (fs.existsSync(leveragedAuthsPath)) {
     const trace = JSON.parse(fs.readFileSync(leveragedAuthsPath, 'utf-8'));
     // Add each leveraged provider as a party in metadata.parties[]
     for (const la of trace.leveraged_authorizations) {
       ssp.metadata.parties.push({
         uuid: la.party_uuid,
         type: 'organization',
         name: la.title,
         props: [
           { name: 'fedramp-pa-id', ns: FEDRAMP_NS, value: la.pa_id },
           { name: 'cloud', ns: FEDRAMP_NS, value: la.provider },
           { name: 'region', ns: FEDRAMP_NS, value: la.region },
         ],
       });
       ssp['system-implementation']['leveraged-authorizations'].push({
         uuid: la.uuid,
         title: la.title,
         'party-uuid': la.party_uuid,
         'date-authorized': la.date_authorized,
         links: [{ href: `#component-${la.uuid}`, rel: 'leveraged-authorization-package' }],
         props: [
           { name: 'fedramp-pa-id', ns: FEDRAMP_NS, value: la.pa_id },
           { name: 'impact-level', ns: FEDRAMP_NS, value: la.impact_level },
         ],
       });
       ssp['back-matter'].resources.push({
         uuid: `component-${la.uuid}`,
         type: 'service',
         title: la.title,
         rlinks: [{ href: `./components/${la.provider}-${la.region}.component-definition.json` }],
       });
     }
   }
   ```

6. **Orchestrator wiring**: `--leveraged-auth` flag runs AFTER
   inventory collection AND BEFORE `--crm` and `--oscal-ssp`. Sequence
   in `orchestrator.ts`: collect → inventory → leveraged-auth →
   inheritance-trace → crm → ssp → ap → ar → poam → bundle → sign →
   timestamp.

7. **Strict mode**: `--strict-crm` (re-used from L.L1) ALSO aborts if
   discovery surfaces a provider for which the lookup table has no
   PA-id (i.e. `leveraged-authorizations.generated.json` missing entry).

8. **Bundler integration**: add to `WELL_KNOWN`:
   ```ts
   { role: 'leveraged-authorizations-json', filename: 'leveraged-authorizations.json', description: 'Per-leveraged-provider inheritance map (LOOP-L.L2)' },
   { role: 'inheritance-trace-json', filename: 'inheritance-trace.json', description: 'Per-control inheritance trace (LOOP-L.L2)' },
   // glob handler for components/ subdirectory:
   { role: 'oscal-component-definition', filename_pattern: 'components/*.component-definition.json', description: 'OSCAL Component Definition for each leveraged authorization (LOOP-L.L2)' },
   ```

**REQUIRES-OPERATOR-INPUT fields**:

| Field | Source | Behavior when missing |
|---|---|---|
| PA-id per provider | `docs/leveraged-authorizations.generated.json` lookup | If lookup table missing an entry for a discovered provider, `pa_id: 'REQUIRES-OPERATOR-INPUT'`; `--strict-crm` aborts |
| Per-control inheritance | `config/leveraged-authorizations.yaml` `inherited_controls[]` | Per-control inheritance flagged as REQUIRES-OPERATOR-INPUT until operator transcribes from provider's published CRM |
| `marketplace_url` | YAML | Optional; no marker if absent |
| `date_authorized` | YAML | If absent, `REQUIRES-OPERATOR-INPUT`; SSP emission flags |

**Test specifications** (≥12):

1. `it('discovers AWS GovCloud from inventory asset with account_partition aws-us-gov')`.
2. `it('discovers GCP Assured Workloads from assured_workloads_enabled flag')`.
3. `it('discovers Azure Government from subscription cloud AzureUSGovernment')`.
4. `it('returns empty providers when no leveraged inventory present')`.
5. `it('reads PA-ids from leveraged-authorizations.generated.json lookup')`.
6. `it('marks pa_id REQUIRES-OPERATOR-INPUT when lookup missing entry')`.
7. `it('--strict-crm aborts on missing PA-id')`.
8. `it('reads inherited control list from yaml')`.
9. `it('rejects yaml with control_id not in NIST Rev5 catalog')`.
10. `it('emits inheritance-trace.json with by_control index populated')`.
11. `it('emits one component-definition per leveraged authorization')`.
12. `it('component-definition validates against oscal_component-definition_schema.v1.1.2.json via ajv')`.
13. `it('SSP system-implementation.leveraged-authorizations[] populated')`.
14. `it('SSP back-matter.resources[type=service] populated with rlinks to component files')`.
15. `it('emits provenance block on leveraged-authorizations.json + inheritance-trace.json')`.

**REO compliance** (specific):
- Leveraged-auth discovery reads REAL `inventory.json`; never assumes a
  provider that isn't enumerated by the existing inventory collectors.
- PA-ids come from a committed lookup table OR a `REQUIRES-OPERATOR-
  INPUT` marker; never fabricated.
- Inherited control lists come from operator yaml; never silently
  defaulted to "all of them".
- Component Definition files validated against the OSCAL v1.1.2 schema.
- Signed by `core/sign.ts`.

**Verification commands**:
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/inheritance-trace.test.ts tests/core/leveraged-auth-discovery.test.ts tests/core/oscal-component-def.test.ts
npm run check:reo
npm run check:provenance
```

**Estimated effort**: 5 - 6 working days.

---

### Slice L.L3 — CRM Gap Report

**Why this slice**: A complete CRM means every Moderate-baseline control
has exactly one responsibility designation. L.L1 emits
`REQUIRES-OPERATOR-INPUT` markers for unmapped controls; L.L3 turns
those markers into a structured gap report + a POA&M finding +
documentation page for the AO + 3PAO. This slice is the audit trail of
"what's still undefined" that the operator must complete before
submission.

**Connection to FedPy mission**: Reads `cis-crm-workbook.json` (L.L1
output) + `inheritance-trace.json` (L.L2 output). Emits
`out/cis-crm-gap-report.md` + `out/cis-crm-gap-report.json`. Also calls
into `core/findings.ts` to emit one finding of family
`crm:no-responsibility` per gap control (these flow into the POA&M
pipeline so the gap is tracked alongside technical findings).

**Files to create**:
- `cloud-evidence/core/crm-gap-report.ts` — pure builder + emitter.
  ~300 lines.
- `cloud-evidence/tests/core/crm-gap-report.test.ts`.
- `cloud-evidence/tests/fixtures/crm-gap/` — fixtures.

**Files to extend**:
- `core/findings.ts` — register new finding family
  `crm:no-responsibility` (severity 'medium', not technical but blocks
  submission).
- `core/orchestrator.ts` — new `--crm-gap` flag + env. Runs AFTER
  `--crm`. Implies `--crm`.
- `core/submission-bundle.ts` — add roles
  `cis-crm-gap-report-md`, `cis-crm-gap-report-json`.
- `core/oscal-poam.ts` — automatically include `crm:no-responsibility`
  findings in the POA&M emission (no schema change required — these
  flow through the existing finding → poam-item pipeline).

**Schemas / standards**:
- **NIST SP 800-53 Rev5 CA-5** — POA&M tracks gaps in control
  implementation. A "no-responsibility-designated" control IS a CA-5
  gap; severity medium per FedRAMP conventional 90-day remediation
  window for documentation gaps.
- **FedRAMP CRM completeness rule** — every Moderate-baseline control
  must have a responsibility; absence is a submission blocker.

**Build steps**:

1. Types in `core/crm-gap-report.ts`:
   ```ts
   export type CrmGapType =
     | 'no-responsibility-designated'
     | 'no-implementation-description'
     | 'no-customer-responsibility-text'
     | 'inherited-without-pa-id'
     | 'shared-without-customer-portion'
     | 'partially-implemented-without-plan';

   export interface CrmGap {
     control_id: string;
     control_title: string;
     gap_type: CrmGapType;
     severity: 'high' | 'medium' | 'low';
     remediation_owner: 'iso' | 'so' | 'csp-team' | 'ao';
     remediation_hint: string;     // what the operator needs to do
     current_state: {
       responsibility?: ResponsibilityBucket;
       responsibility_source?: string;
       implementation_description_source?: string;
       customer_responsibility_source?: string;
       inherited_from_pa_id?: string;
     };
   }

   export interface CrmGapReport {
     metadata: { generated_at, system_id, impact_tier };
     gaps: CrmGap[];
     summary: {
       total_controls: number;
       gap_count: number;
       coverage_percent: number;
       high_count: number;
       medium_count: number;
       low_count: number;
       by_type: Record<CrmGapType, number>;
     };
     provenance;
   }
   ```

2. Pure builder:
   ```ts
   export function buildCrmGapReport(workbook: CisCrmWorkbook): CrmGapReport;
   ```
   Iterate workbook rows. For each row check:
   - `responsibility_source === 'REQUIRES-OPERATOR-INPUT'` →
     `no-responsibility-designated`, severity 'high'.
   - `responsibility === 'inherited'` AND
     `inherited_from_pa_id === 'REQUIRES-OPERATOR-INPUT'` →
     `inherited-without-pa-id`, severity 'high'.
   - `implementation_description_source === 'REQUIRES-OPERATOR-INPUT'`
     AND responsibility ∈ {'service-provider', 'shared'} →
     `no-implementation-description`, severity 'medium'.
   - `customer_responsibility_source === 'REQUIRES-OPERATOR-INPUT'`
     AND responsibility ∈ {'customer', 'shared'} →
     `no-customer-responsibility-text`, severity 'medium'.
   - `responsibility === 'shared'` AND customer_responsibility is empty
     → `shared-without-customer-portion`, severity 'medium'.
   - `implementation_status === 'partially-implemented'` AND no plan
     narrative → `partially-implemented-without-plan`, severity 'low'.

3. Markdown emitter:
   ```ts
   export function renderCrmGapReportMarkdown(report: CrmGapReport): string;
   ```
   Sections:
   - Header: system identity, generated_at, summary counts.
   - Coverage chart (text-rendered bar).
   - Per-gap table grouped by severity.
   - Per-control remediation guidance.

4. Finding emission:
   ```ts
   export function emitCrmGapFindings(report: CrmGapReport): Finding[];
   ```
   Each gap becomes one Finding with:
   - `ksi_id: 'CRM-COMPLETE'` (synthetic KSI for documentation
     completeness; registered in `ksi-map.ts`)
   - `rule: gap.gap_type`
   - `provider: 'fedramp-package'`
   - `gap.affected_resources: [{ identifier: gap.control_id }]`
   - `severity: gap.severity`
   - `note: gap.remediation_hint`
   - `references: [{ uri: 'https://www.fedramp.gov/docs/rev5/playbook/csp/', title: 'FedRAMP CSP Authorization Playbook §SSP Appendix J' }]`

5. **Disk emitter**:
   ```ts
   export interface CrmGapReportEmitOptions {
     outDir: string;
     workbookPath?: string;       // default: outDir/cis-crm-workbook.json
   }
   export interface CrmGapReportEmitResult {
     mdPath: string;
     jsonPath: string;
     gap_count: number;
     findings_emitted: number;
   }
   export async function emitCrmGapReport(opts: CrmGapReportEmitOptions): Promise<CrmGapReportEmitResult>;
   ```

6. **Orchestrator wiring**: `--crm-gap` runs AFTER `--crm`. Findings
   flow through `findings.ts` to the existing POA&M emission.

7. **Bundler**: add roles.

8. **Strict mode**: `--strict-crm` aborts the run with the gap report
   filename in the error message; the operator's next step is "open the
   gap report, fill in the matrix, re-run".

**REQUIRES-OPERATOR-INPUT fields**: None NEW to this slice — it reports
on markers L.L1 emitted.

**Test specifications** (≥12):

1. `it('detects no-responsibility-designated gap when responsibility_source is REQUIRES-OPERATOR-INPUT')`.
2. `it('detects inherited-without-pa-id when inherited_from_pa_id is REQUIRES-OPERATOR-INPUT')`.
3. `it('detects no-implementation-description for service-provider rows')`.
4. `it('detects no-customer-responsibility-text for customer rows')`.
5. `it('detects shared-without-customer-portion')`.
6. `it('detects partially-implemented-without-plan')`.
7. `it('summary.coverage_percent calculated correctly')`.
8. `it('renderCrmGapReportMarkdown produces stable output with summary + per-gap rows')`.
9. `it('emitCrmGapFindings produces one Finding per gap')`.
10. `it('Findings use ksi_id CRM-COMPLETE and severity matches gap severity')`.
11. `it('findings reference FedRAMP playbook URL')`.
12. `it('emits provenance block on cis-crm-gap-report.json')`.
13. `it('--strict-crm includes gap report filename in error message')`.
14. `it('bundler well-known catalogue includes cis-crm-gap-report-md + cis-crm-gap-report-json')`.

**REO compliance**:
- Reads from L.L1's emitted artifacts; no fabrication.
- Findings flow through existing POA&M pipeline; no special-case logic.
- Provenance block populated.

**Verification commands**:
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/crm-gap-report.test.ts
npm run check:reo
npm run check:provenance
```

**Estimated effort**: 2 - 3 working days.

---

### Slice L.L4 — Per-control Responsibility Split Renderer

**Why this slice**: The SSP §13 (Control Implementation) section is the
narrative side of the CRM workbook. For each control, the SSP needs a
prose paragraph naming the responsibility split (Customer / CSP /
Hybrid / Inherited) and describing each party's contribution. L.L4
produces these narratives from the L.L1 workbook + the operator's YAML
+ inheritance trace, then wires them into the OSCAL SSP
`implemented-requirements[].by-components[].responsible-roles[]` and
the .docx SSP (`core/ssp-docx.ts`) §13 rendering.

**Connection to FedPy mission**: All inputs are real (L.L1 workbook,
inheritance trace, KSI evidence, operator yaml). Output is per-control
markdown plus OSCAL `responsible-roles` JSON. Existing
`core/ssp-docx.ts` reads the per-control markdown for the §13 control
implementation tables. The OSCAL SSP gets first-class
`responsible-roles` populated.

**Files to create**:
- `cloud-evidence/core/crm-split-renderer.ts` — pure builder + emitter.
  ~400 lines.
- `cloud-evidence/tests/core/crm-split-renderer.test.ts`.
- `cloud-evidence/tests/fixtures/crm-split/`.

**Files to extend**:
- `core/oscal-ssp.ts` — wire per-control `responsible-roles[]` and
  `by-components[]` from the renderer output.
- `core/ssp-docx.ts` — replace the §13 "Implementation Status / Control
  Origination" tables with the renderer's per-control narrative output.
- `core/orchestrator.ts` — new `--crm-narratives` flag + env. Runs
  AFTER `--crm` (L.L1) AND BEFORE `--oscal-ssp` AND `--ssp-docx`.
- `core/submission-bundle.ts` — add role
  `crm-per-control-narratives-tarball` for the per-control md tree
  (glob `out/crm-per-control-narratives/*.md`).

**Schemas / standards**:
- **OSCAL SSP v1.1.2 `responsible-roles[]`** — array of role-id +
  party-uuids:
  ```json
  {
    "role-id": "provider" | "customer" | "shared-csp-customer" | "inherited",
    "party-uuids": ["uuid-of-csp" or "uuid-of-leveraged-auth-party"]
  }
  ```
- **OSCAL SSP v1.1.2 `by-components[]`** — array per component touching
  the control. Per FedRAMP convention there's one for the CSO itself
  (uuid = SSP's primary component) AND one per leveraged authorization
  (uuid = leveraged-authorization.party-uuid). Each by-component carries
  `inherited[]` when the leveraged provider implements part or all of
  the control.
- **FedRAMP Rev5 SSP §13 narrative template** —
  "[Service Provider Corporate / Service Provider System Specific /
  Service Provider Hybrid / Configured by Customer / Provided by
  Customer / Shared / Inherited from pre-existing Provisional
  Authorization]" — the 7-bucket FedRAMP Origination set. L.L4 collapses
  the 5-bucket CIS/CRM workbook responsibility set to the 7-bucket
  Origination set via documented mapping:
  - `service-provider` → "Service Provider System Specific" (default)
    or "Service Provider Hybrid" (when partial)
  - `customer` → "Configured by Customer" (default) or "Provided by
    Customer" (when fully customer-supplied)
  - `shared` → "Shared"
  - `inherited` → "Inherited from pre-existing Provisional
    Authorization"
  - `not-applicable` → emit a "Not Applicable" justification paragraph
  The 7-bucket mapping is documented in `crm-split-renderer.ts` module
  docstring + tested.

**Build steps**:

1. Types:
   ```ts
   export type FedrampOrigination =
     | 'service-provider-corporate'
     | 'service-provider-system-specific'
     | 'service-provider-hybrid'
     | 'configured-by-customer'
     | 'provided-by-customer'
     | 'shared'
     | 'inherited-pa';

   export interface PerControlNarrative {
     control_id: string;
     control_title: string;
     origination: FedrampOrigination;
     responsibility_bucket: ResponsibilityBucket;  // from L.L1
     narrative_markdown: string;                   // composed paragraph
     responsible_roles: Array<{
       role_id: 'provider' | 'customer' | 'shared-csp-customer' | 'inherited';
       party_uuids: string[];
     }>;
     by_components: Array<{
       component_uuid: string;
       implementation_status: ImplementationStatus;
       description: string;
       inherited?: Array<{
         leveraged_authorization_uuid: string;
         description: string;
       }>;
     }>;
     narrative_source: 'composed-from-l1' | 'operator-supplied' | 'REQUIRES-OPERATOR-INPUT';
   }
   ```

2. Bucket → Origination mapping:
   ```ts
   export function mapToFedrampOrigination(
     bucket: ResponsibilityBucket,
     implementationStatus: ImplementationStatus,
     hasCustomerPortion: boolean,
   ): FedrampOrigination;
   ```
   Documented decision table (cited in module docstring + tested):
   - `service-provider` + `implemented` → `service-provider-system-specific`
   - `service-provider` + `partially-implemented` → `service-provider-hybrid`
   - `customer` + `customer fully supplies the service` →
     `provided-by-customer` (when yaml `customer_supplied === true`)
   - `customer` (default) → `configured-by-customer`
   - `shared` → `shared`
   - `inherited` → `inherited-pa`
   - `not-applicable` → emit narrative-only; OSCAL `responsible-roles`
     empty; SSP §13 row marked "Not Applicable" with justification.

3. Per-control narrative composition:
   ```ts
   export function composeNarrative(row: CisCrmRow, leverageds: LeveragedAuthorization[]): string;
   ```
   Template (markdown):
   ```
   ### {control_id} — {control_title}
   
   **Responsibility**: {bucket} (FedRAMP Origination: {origination})
   
   **Implementation Status**: {status}
   
   **CSP Implementation**: {implementation_description}
   
   **Customer Responsibility**: {customer_responsibility}
   
   {if inherited: }
   **Inherited From**: {pa_id} — {provider title}
   
   This control is inherited from the {provider} authorization (PA-id {pa_id}).
   {inheritance_description}
   
   {if responsibility-matrix-yaml source: }
   *(Narrative source: operator-supplied via config/responsibility-matrix.yaml)*
   
   {if KSI evidence: }
   *(CSP-implementation status evidenced by: {ksi_ids[].join(', ')})*
   ```

4. Disk emitter:
   ```ts
   export interface CrmSplitRendererOptions {
     outDir: string;
     workbookPath?: string;
     inheritanceTracePath?: string;
     leveragedAuthsPath?: string;
   }
   export interface CrmSplitRendererResult {
     narrative_count: number;
     dirPath: string;                  // out/crm-per-control-narratives/
     filePaths: string[];               // per-control markdown files
     responsibleRolesByControl: Record<string, PerControlNarrative['responsible_roles']>;
     byComponentsByControl: Record<string, PerControlNarrative['by_components']>;
   }
   export async function emitCrmSplitNarratives(opts: CrmSplitRendererOptions): Promise<CrmSplitRendererResult>;
   ```
   Writes one markdown file per control to
   `out/crm-per-control-narratives/<control-id>.md`.

5. **SSP integration** (`core/oscal-ssp.ts`):
   ```ts
   const narrativeIndex = path.join(outDir, 'crm-per-control-narratives-index.json');
   if (fs.existsSync(narrativeIndex)) {
     const index = JSON.parse(fs.readFileSync(narrativeIndex, 'utf-8'));
     // For each implemented-requirement, attach responsible-roles + by-components
     for (const ir of ssp['control-implementation']['implemented-requirements']) {
       const roles = index.responsibleRolesByControl[ir['control-id']];
       if (roles) {
         ir['responsible-roles'] = roles;
         ir['by-components'] = index.byComponentsByControl[ir['control-id']];
       }
     }
   }
   ```

6. **SSP .docx integration** (`core/ssp-docx.ts`):
   - Replace the existing placeholder §13 control implementation table
     with the renderer output: one row per control, columns
     Control ID / Origination / Implementation Status / Narrative.
   - Read narrative from
     `out/crm-per-control-narratives/<control-id>.md` files.

7. **Orchestrator wiring**: `--crm-narratives` runs AFTER `--crm`,
   BEFORE `--oscal-ssp` + `--ssp-docx`. Implies `--crm`.

8. **Bundler**: add role
   `crm-per-control-narratives-tarball` (or use glob pattern
   `crm-per-control-narratives/*.md` per submission-bundle.ts existing
   `filename_pattern` extension from L.L2).

**REQUIRES-OPERATOR-INPUT fields**:
- Per-control narrative auto-composition produces a narrative for every
  control with a known bucket; when bucket is `REQUIRES-OPERATOR-INPUT`
  (from L.L1), the narrative file is emitted with body
  `REQUIRES-OPERATOR-INPUT: control responsibility undefined; see
  cis-crm-gap-report.md`. `--strict-crm` will already have aborted by
  this point; L.L4 never silently substitutes a fake narrative.

**Test specifications** (≥12):

1. `it('maps service-provider implemented → service-provider-system-specific')`.
2. `it('maps service-provider partially-implemented → service-provider-hybrid')`.
3. `it('maps customer with customer_supplied=true → provided-by-customer')`.
4. `it('maps customer default → configured-by-customer')`.
5. `it('maps shared → shared')`.
6. `it('maps inherited → inherited-pa')`.
7. `it('maps not-applicable → not-applicable with justification paragraph')`.
8. `it('emits one markdown file per control')`.
9. `it('narrative includes inheritance section when row is inherited')`.
10. `it('narrative cites KSI evidence sources when ksi_ids present on row')`.
11. `it('responsible-roles populated for service-provider rows with provider role-id')`.
12. `it('responsible-roles populated for inherited rows with inherited role-id + leveraged-auth party-uuid')`.
13. `it('SSP control-implementation.implemented-requirements[].responsible-roles[] wired from index')`.
14. `it('SSP .docx §13 table rendered from per-control markdown')`.
15. `it('emits provenance block on per-control-narratives index')`.
16. `it('REQUIRES-OPERATOR-INPUT narrative emitted when bucket undefined')`.

**REO compliance**:
- Every narrative composed from real L.L1 / L.L2 / KSI / yaml data;
  never fabricated.
- The bucket-to-Origination mapping is constant and tested.
- OSCAL `responsible-roles[]` populated only when bucket is known.
- Provenance block on the index file.
- Signed by `core/sign.ts`.

**Verification commands**:
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/crm-split-renderer.test.ts
npm run check:reo
npm run check:provenance
```

**Estimated effort**: 4 - 5 working days.

---

## 6. Loop-wide acceptance criteria

LOOP-L is COMPLETE when ALL of the following are true:

1. **L.L1**: `out/cis-crm-workbook.xlsx` + `out/cis-crm-workbook.json`
   emit end-to-end with one row per Moderate-baseline control (sourced
   from FRMR catalog), every row's `responsibility_source` populated
   (either from yaml, inheritance trace, KSI evidence, or
   `REQUIRES-OPERATOR-INPUT`), bundler includes both artifacts, and the
   `cis_crm_format_version` is pinned to `'20x.crm.preview.2026'`.
2. **L.L2**: `out/leveraged-authorizations.json` +
   `out/inheritance-trace.json` +
   `out/components/<provider>.component-definition.json` emit per
   discovered leveraged provider; OSCAL SSP
   `system-implementation.leveraged-authorizations[]` populated; SSP
   `back-matter.resources[type=service]` with `rlinks[]` to component
   definitions; ajv validates every component-definition file.
3. **L.L3**: `out/cis-crm-gap-report.md` +
   `out/cis-crm-gap-report.json` emit with one entry per
   REQUIRES-OPERATOR-INPUT or other gap detected in the workbook;
   Findings flow through to the POA&M; `--strict-crm` aborts run with
   gap report filename in error message.
4. **L.L4**: `out/crm-per-control-narratives/<control-id>.md` emit one
   markdown file per control; SSP
   `implemented-requirements[].responsible-roles[]` and `by-components[]`
   populated from the renderer output; SSP .docx §13 rendered from the
   per-control narratives.
5. All four slices pass `npm run typecheck`, `npm test`, and
   `npm run check:reo`.
6. CHANGELOG "Unreleased" has four entries (one per slice) with module
   names + verification counts + REO compliance notes.
7. STATUS.md per-slice rows updated (LOOP-L section added in the same
   commit as L.L1 ships when the audit is ratified).
8. `docs/sections/SECTION-A.md` gains A23 (CRM workbook), A24
   (Component-def inheritance doc) as enumerated in the audit §6.
9. `docs/DEPENDENCY-GRAPH.md` updated with LOOP-L nodes + downstream
   unblocking edges.

---

## 7. Open questions / caveats

1. **CRM template format final** — per audit §5.5, the FedRAMP CIS/CRM
   workbook format is still in revision per 2026 Consolidated Rules
   planning. L.L1 ships with the documented `cis_crm_format_version
   = '20x.crm.preview.2026'` so a future format shift produces a clean
   version bump rather than silently changing the structure. Operator
   verifies against the latest published template at shipping time.
2. **Leveraged-authorization PA-id lookup table** — per audit §5.10:
   > "FedRAMP PA-ids (e.g., 'F1411040093' for AWS GovCloud) are
   > committed via PMO; LOOP-L.L2 needs a committed lookup table at
   > `cloud-evidence/docs/leveraged-authorizations.generated.json`.
   > Currently no source mechanically extracts this; operator must
   > supply."
   The committed file ships with entries for the major providers
   (AWS GovCloud, AWS Commercial Moderate/High, GCP Assured Workloads
   US Moderate/High, GCP Commercial Moderate/High, Azure Government
   High, Azure Commercial High) with `pa_id_source: 'fedramp-marketplace'`
   (operator confirms each entry against marketplace.fedramp.gov before
   shipping).
3. **CRM authoring sequence** — per audit §5.9:
   > "Does the operator fill in the matrix before or after the SSP is
   > emitted? Typically iteratively. LOOP-L.L4 tracker UI assumes
   > parallel authoring; needs operator confirmation."
   This spec re-scopes L.L4 to a per-control renderer (not a tracker
   UI); iterative authoring is via the committed
   `config/responsibility-matrix.yaml`. A future LOOP-L extension may
   add a tracker UI; out of scope for first ship.
4. **AFR-FSI vs CRM customer-responsibility overlap** — per audit §5.11:
   > "FSI inbox (LOOP-G.G1) requires CSP to acknowledge required
   > actions; some required actions may be customer-responsibility-matrix
   > items. Routing between the two systems needs definition."
   Resolution: L.L3 gap report distinguishes documentation gaps
   (FedRAMP package incomplete) from operational gaps
   (action-required-by-customer). LOOP-G.G1 handles operational FSI;
   LOOP-L.L3 handles documentation. Routing rule: a CRM "shared" cell
   with operational customer action surfaces in BOTH systems with a
   `routing-source: 'crm-shared-cell'` prop.
5. **OSCAL responsible-roles role-id values** — OSCAL doesn't pin a
   role-id vocabulary for CRM responsibility. L.L4 uses
   `'provider'` / `'customer'` / `'shared-csp-customer'` /
   `'inherited'`; FedRAMP may publish a canonical vocabulary; if so,
   migrate in a separate slice.
6. **Component Definition profile resolution** — OSCAL Component
   Definition references controls via a baseline profile URI. L.L2
   ships with FedRAMP Moderate baseline URI; if the CSO is High, the
   URI updates. Operator confirms at shipping time.
7. **Shared multi-tenancy of `config/responsibility-matrix.yaml`** —
   multi-CSO (LOOP-H.H3) requires per-CSO matrix yaml; L.L1 reads from
   `config/<cso-id>/responsibility-matrix.yaml` when H.H3 ships; until
   then, single-CSO assumption.
8. **Inherited-controls list verification** — operator transcribes from
   the leveraged provider's published CRM (downloaded from
   marketplace.fedramp.gov under NDA). There is no mechanical
   verification; the audit trail is the yaml commit + operator
   sign-off. A future slice could add a parser for the published
   CSV/JSON form of provider CRMs when FedRAMP standardises one.
9. **POA&M deadline for CRM gaps** — per LOOP-B.B2, deadlines come from
   FedRAMP CMP table. L.L3 findings carry severity medium; the
   resulting POA&M item gets the 90-day Moderate deadline (per
   FedRAMP CMP). Operator can accept the risk (LOOP-B.B3) or close it
   by filling in the matrix.
10. **Sponsoring-agency overlap** — per audit §5.4, sponsoring agency
    information is a LOOP-Q.Q1 deliverable; if a control's
    `customer_responsibility` cites a specific agency obligation, that
    cross-references LOOP-Q. Out of scope for LOOP-L.
11. **OSCAL `inherited[]` schema completeness** — L.L4 emits
    `by-components[].inherited[]` only when bucket is `'inherited'`;
    OSCAL also supports `provided[]` + `satisfied[]` for partial-
    inheritance scenarios. First cut: collapse to `inherited[]`; future
    enhancement adds `provided[]` / `satisfied[]` per OSCAL Profile
    Resolution conventions.

---

## 8. Status tracking

Update this table when a slice ships (see §9).

| Slice ID | Title | Status | Commit hash | Completed date |
|---|---|---|---|---|
| L.L1 | CRM Workbook generator (SSP Appendix J) | pending | — | — |
| L.L2 | Inherited-controls tracker (leveraged provider authorizations) | pending | — | — |
| L.L3 | CRM gap report (controls neither implemented nor inherited) | pending | — | — |
| L.L4 | Per-control responsibility split renderer | pending | — | — |

---

## 9. Slice completion procedure (REO-enforced)

When a slice ships, the implementer MUST perform these steps. Skipping
any one is a REO Rule 2 violation. See
`docs/SLICE-COMPLETION-PROCEDURE.md` for the canonical 7-step procedure.

1. **Verify green**: from repo root
   ```bash
   cd cloud-evidence
   npm run typecheck            # must be clean
   npm test                     # 100% passing (existing + new slice tests)
   npm run check:reo            # G1 + G2 + G3 all green
   npm run check:provenance     # every new emit-field has provenance entry
   ```

2. **Update Section 8 status table**: edit this file (
   `cloud-evidence/docs/loops/LOOP-L-SPEC.md`). Set the slice's row to
   `status=done`, `commit=<short-sha>`, `date=<YYYY-MM-DD>`.

3. **Update CHANGELOG.md "Unreleased"**: add a new `### Added — LOOP-L.<id>: <title>` block at the top of "Unreleased". Mirror the
   LOOP-A.A* entries for tone and depth. Cite the module names, the
   spec links, and the verification counts:
   - Number of new tests + total tests after slice
   - Whether typecheck + check:reo are green
   - Net new files
   - Brief REO-compliance note

4. **Update `cloud-evidence/docs/STATUS.md`**: set the slice row to
   `done`. (If LOOP-L block doesn't exist yet because the audit was
   just ratified, this slice's commit creates it with one row per
   LOOP-L slice + adds the LOOP-L risks register row.)

5. **Update the per-slice doc's frontmatter** (`docs/slices/L/L.L<n>.md`):
   `status: done`, `commit: <hash>`, `completed_date: <ISO>`,
   `last_updated: <ISO>`.

6. **Append final Implementation log entry** to the per-slice doc per
   `docs/IMPLEMENTATION-LOG-TEMPLATE.md`.

7. **Add any newly-discovered risks** to
   `docs/loops/LOOP-L-RISKS.md` in the same commit.

8. **Commit**: from repo root
   ```bash
   git add -A
   git commit -m "LOOP-L.<id>: <title>"
   ```

9. **Push**: `git push origin main`.

---

## 10. Appendix — worked example (4-slice end-to-end)

To make LOOP-L reviewable, here is the worked example the test suite
encodes. Given a CSO with:

- Inventory: 100 AWS assets (account_partition aws-us-gov), 20 GCP
  assets (assured_workloads_enabled true).
- KSI evidence: IAM-MFA pass on AWS, IAM-MFA fail on GCP; CNA-IBP
  pass on both; SVC-ASM pass on AWS.
- Operator yaml `responsibility-matrix.yaml`: 50 Moderate controls
  mapped (the easy ones — Customer / Shared / Not-Applicable);
  remaining 275 Moderate controls unmapped.
- Operator yaml `leveraged-authorizations.yaml`: AWS GovCloud inherits
  150 controls (per AWS GovCloud SSP Customer Responsibility Matrix
  template); GCP Assured Workloads inherits 80 controls.
- FRMR catalog filtered to Moderate: 325 control rows total.

Run:
```bash
npm run collect -- --crm --crm-gap --crm-narratives --leveraged-auth \
  --impact-level moderate \
  --system-id "ACME-SAAS" --system-name "ACME Production SaaS" \
  --strict-crm
```

Sequence:
1. **L.L2** runs first: discovery finds AWS GovCloud + GCP Assured
   Workloads. Lookup table resolves PA-ids (`F1411040093` +
   `F1XYZ123456`). Emits `out/leveraged-authorizations.json` +
   `out/inheritance-trace.json` (150 + 80 = 230 inherited rows by
   union; some controls inherited from BOTH).
2. **L.L1** runs: builds 325 workbook rows. For each row:
   - Step A (yaml): 50 hits.
   - Step B (inherited): 230 - some overlap. Net new rows from
     inheritance: 180.
   - Step C (KSI): for the remaining 95, check KSI mapping:
     - IAM-MFA maps to IA-2(1), IA-2(2), AC-2(11): 3 controls; AWS-pass
       AND GCP-fail → `partially-implemented` rows.
     - CNA-IBP maps to SI-7, CM-7(2): 2 controls; all-pass →
       `implemented`.
     - SVC-ASM maps to SC-12, SC-12(1), SC-12(2), SC-12(3): 4 controls;
       AWS-pass only → some unmapped on GCP → `partially-implemented`.
     - Net new: 9 service-provider rows.
   - Step D (REQUIRES-OPERATOR-INPUT): 95 - 9 = **86 unmapped controls**.
3. **L.L3** runs: emits gap report with 86
   `no-responsibility-designated` gaps + however many
   `no-implementation-description` / `no-customer-responsibility-text`
   gaps the partially-mapped rows have. Findings emitted to POA&M.
4. `--strict-crm` aborts WITH exit code 4 and message naming the gap
   report filename. Operator opens
   `out/cis-crm-gap-report.md`, sees the 86 unmapped controls grouped
   by family, edits the yaml, re-runs.
5. Eventually: 0 gaps → `--strict-crm` succeeds. L.L1 emits final
   workbook + JSON. L.L4 emits 325 per-control narratives + SSP
   responsible-roles index. SSP .docx renders §13 from the narratives.
   Bundle includes:
   - `cis-crm-workbook.xlsx`
   - `cis-crm-workbook.json`
   - `cis-crm-gap-report.md` (0 gaps now)
   - `cis-crm-gap-report.json`
   - `leveraged-authorizations.json`
   - `inheritance-trace.json`
   - `components/aws-us-gov-west-1.component-definition.json`
   - `components/gcp-assured-workloads-us.component-definition.json`
   - `crm-per-control-narratives-tarball.tar.gz`

That is the LOOP-L value proposition end-to-end: a complete
Appendix-J-equivalent submission artifact, traceable byte-for-byte to
real catalog + real inventory + real KSI evidence + signed operator
yaml, with zero invented data.

---

## 11. Appendix — file inventory at loop close

When LOOP-L completes, the following files exist in the repo (all
created or extended during the four slices):

```
cloud-evidence/
├── core/
│   ├── cis-crm-emit.ts                   (L.L1, new)
│   ├── cis-crm-xlsx.ts                   (L.L1, new)
│   ├── responsibility-matrix.ts           (L.L1, new)
│   ├── inheritance-trace.ts               (L.L2, new)
│   ├── leveraged-auth-discovery.ts        (L.L2, new)
│   ├── oscal-component-def.ts             (L.L2, new)
│   ├── crm-gap-report.ts                  (L.L3, new)
│   ├── crm-split-renderer.ts              (L.L4, new)
│   ├── oscal-ssp.ts                       (L.L2 + L.L4 extension)
│   ├── ssp-docx.ts                        (L.L4 extension)
│   ├── oscal-poam.ts                      (L.L3 extension via findings)
│   ├── orchestrator.ts                    (all four slices: new flags)
│   ├── submission-bundle.ts               (all four slices: new roles)
│   ├── findings.ts                        (L.L3 extension: new finding family)
│   ├── ksi-map.ts                         (L.L3 extension: synthetic KSI CRM-COMPLETE)
│   └── oscal-validate.ts                  (L.L2 extension: component-definition schema)
├── config/
│   ├── responsibility-matrix.example.yaml          (L.L1, new committed)
│   ├── responsibility-matrix.yaml                  (operator-copied, gitignored)
│   ├── leveraged-authorizations.example.yaml       (L.L2, new committed)
│   └── leveraged-authorizations.yaml               (operator-copied, gitignored)
├── docs/
│   ├── leveraged-authorizations.generated.json     (L.L2, committed lookup)
│   ├── oscal/
│   │   └── oscal_component-definition_schema.v1.1.2.json   (L.L2, committed)
│   ├── loops/
│   │   ├── LOOP-L-SPEC.md                          (this file)
│   │   └── LOOP-L-RISKS.md                         (companion register)
│   ├── slices/L/
│   │   ├── L.L1.md
│   │   ├── L.L2.md
│   │   ├── L.L3.md
│   │   └── L.L4.md
│   └── sections/
│       ├── SECTION-A.md                            (extended A23, A24)
│       └── SECTION-E.md                            (extended per-control responsibility)
└── tests/
    ├── core/
    │   ├── cis-crm-emit.test.ts
    │   ├── cis-crm-xlsx.test.ts
    │   ├── responsibility-matrix.test.ts
    │   ├── inheritance-trace.test.ts
    │   ├── leveraged-auth-discovery.test.ts
    │   ├── oscal-component-def.test.ts
    │   ├── crm-gap-report.test.ts
    │   └── crm-split-renderer.test.ts
    └── fixtures/
        ├── cis-crm/
        ├── leveraged-auth/
        ├── crm-gap/
        └── crm-split/
```

When the run executes:
```
out/
├── cis-crm-workbook.xlsx                                       (L.L1)
├── cis-crm-workbook.json                                       (L.L1)
├── cis-crm-gap-report.md                                        (L.L3)
├── cis-crm-gap-report.json                                      (L.L3)
├── leveraged-authorizations.json                                (L.L2)
├── inheritance-trace.json                                       (L.L2)
├── components/
│   ├── aws-us-gov-west-1.component-definition.json              (L.L2)
│   ├── gcp-assured-workloads-us.component-definition.json       (L.L2)
│   └── azure-government-us.component-definition.json            (L.L2)
├── crm-per-control-narratives/
│   ├── AC-2.md
│   ├── AC-2(1).md
│   ├── AC-3.md
│   ... (one file per Moderate-baseline control)
└── crm-per-control-narratives-index.json                        (L.L4)
```

Net new emit artifacts: 6 top-level + 1 components/ subdir + 1
per-control narratives subdir (≈325 files at Moderate) = ≈340 files
under `out/`. All signed by `core/sign.ts` (manifest glob includes all).

---

## 12. Appendix — CHANGELOG entry template per slice

Use this template when shipping a LOOP-L slice (mirrors LOOP-A.A*
verbosity):

```
### Added — LOOP-L.L<n>: <Slice title>

<2-3 paragraphs describing what shipped: module names, paths,
verification counts (typecheck clean, NNN/NNN tests passing,
npm run check:reo returns 0). Cite the FedRAMP playbook / OSCAL
reference / NIST control(s) the slice satisfies. Name the REQUIRES-
OPERATOR-INPUT pattern and why it's defensible per REO Rule 4.>

  - `core/<new-module>.ts`: <line count>, <one-sentence purpose>.
  - `core/<extended-module>.ts`: <extension description>.
  - REO compliance: <which sources fed the output; what's operator-
    supplied; what's REQUIRES-OPERATOR-INPUT; signing + provenance>.

Verification: typecheck clean; NNN/NNN tests passing (+<delta> from
LOOP-L.L<n>); `npm run check:reo` returns 0.
```

---

## 13. Resume-from-fresh-session checklist (loop-level)

If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. Read `docs/STATUS.md` — confirm LOOP-L is the active loop; find the
   "Overall → Next priority" line; identify the next pending L.L<n>.
3. Read `docs/slices/L/L.L<n>.md` (per-slice doc) — that has the
   single-file ground truth for the slice.
4. Read `docs/loops/LOOP-L-RISKS.md` — live risks register.
5. Read `docs/SLICE-COMPLETION-PROCEDURE.md` — the mandatory 7-step
   commit pattern.
6. Read `docs/ADDITIONAL-LOOPS-AUDIT.md §2 LOOP-L` — original audit
   that surfaced this loop; cite verbatim when authoring CHANGELOG.
7. Execute the slice under REO; update the Implementation log section
   of the per-slice doc as you go.
8. Follow the 7-step completion procedure atomically with your final
   commit.

The strong-directive in CLAUDE.md applies in full: STATUS.md, this
spec, per-slice doc frontmatter, Implementation log, LOOP-L-RISKS.md,
CHANGELOG.md, commit, push — all atomic with the slice's final commit.
NO EXCEPTIONS.
