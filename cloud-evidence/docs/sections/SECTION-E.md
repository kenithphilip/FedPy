# SECTION E — NIST 800-53 Rev5 control → artifact mapping (Moderate = 287 controls)

> **Status:** requirements-layer specification.
> **Scope:** 23 named artifacts (E1–E23) that the FedRAMP 20x Moderate
> authorization package must deliver, each anchored to one or more NIST
> SP 800-53 Rev5 controls drawn from the 287-control Moderate baseline
> (FedRAMP Rev5 Moderate Baseline parameters per SP 800-53B).
> **Source-of-truth:** OSCAL 1.1.2 schemas + FedRAMP RFC-0014 / RFC-0024
> + the FedRAMP Rev5 Playbook + `cloud-evidence/CLAUDE.md` (REO standard).
> **Consumers:** 3PAO (assessment), FedRAMP PMO (review), AO (authorization
> decision), Federal Inbox / USDA Connect.gov (submission repository),
> CSP-internal (governance + ConMon).

---

## 1. Purpose

Section E is the cross-walk between the **NIST 800-53 Rev5 control family**
that a FedRAMP authorization is judged against and the **concrete
deliverable artifact** that supplies the evidence for each control. The
287-control Moderate baseline ([SP 800-53B, Appendix C](https://csrc.nist.gov/pubs/sp/800/53/b/upd1/final))
defines *what* the system must do; the FedRAMP authorization framework
defines *which document, sheet, or signed JSON* shows that it does.

Why this section exists in the FedRAMP authorization framework:

1. **Audit traceability.** Every control in the SSP must have an
   implementation statement (the SSP narrative), an assessment objective
   (the AP), an assessor finding (the AR), and — when the finding is a
   gap — a remediation entry (the POA&M). Without an artifact-to-control
   mapping, the 3PAO cannot demonstrate completeness and the AO cannot
   render an informed decision.
2. **Continuous monitoring.** Once authorized, the same artifact set is
   re-issued on a monthly cadence (POA&M, scan reports, inventory) and
   on an annual cadence (SSP review, IRP/ISCP test AAR, AR refresh).
   Section E is the spine of that recurring delivery.
3. **20x automation premise.** RFC-0014 mandates "*truly automated and
   opinionated validation of Key Security Indicators*"; RFC-0024 mandates
   OSCAL JSON as the wire format for SSP/AP/AR/POA&M. The artifact
   inventory in this section is the precise list of OSCAL + .docx +
   .xlsx files that an automated emitter pipeline must produce.
4. **REO compliance.** Per `cloud-evidence/CLAUDE.md`, every artifact's
   payload must trace to real evidence (cloud SDK call, FRMR catalog
   read, NIST publication, tracker DB query) or to operator-supplied
   configuration. Section E records, for every artifact, *where* the
   payload comes from and which loop.slice delivers it.

---

## 2. Artifact catalogue (E1–E23)

The table below enumerates every artifact this section covers. Column
key:

- **ID** — internal id `E<n>` for this section. Slice ids (`LOOP-A.A1`,
  `LOOP-C.C2`, etc.) appear in the rightmost column.
- **Required** — `✅` = REQUIRED unconditionally for Moderate; `⚠️
  conditional` = required only when a precondition is met (e.g. PIA
  required only when PII processed); `RECOMMENDED` = REQUIRED at the
  policy layer but the artifact form is at CSP/3PAO discretion.
- **Consumer(s)** — who reads/depends on this artifact downstream.
- **Format(s)** — wire formats the emitter produces.
- **Source obligation** — the specific FedRAMP RFC, NIST publication,
  or OSCAL spec section that mandates this artifact + its format.
- **Current FedPy status** — `HAVE` = end-to-end emit-able today;
  `PARTIAL` = scaffolded but missing key inputs; `MISSING` = no module
  yet. Module names from existing code are cited.
- **Implementing loop.slice** — the exact slice in
  `cloud-evidence/docs/EXECUTION-PLAN.md` that owns the build.

| ID  | Artifact | Required | Consumer(s) | Format(s) | Source obligation | Current FedPy status | Loop.slice |
|-----|----------|----------|-------------|-----------|-------------------|----------------------|------------|
| E1  | Security Assessment Report (SAR) | ✅ | 3PAO authors, PMO + AO read | OSCAL JSON 1.1.2 + .docx | NIST CA-2; FedRAMP Rev5 SAR template; OSCAL `assessment-results` schema | PARTIAL — `core/oscal.ts` emits AR JSON+XML; SAR-formatted .docx missing | LOOP-A.A3 (chain) + **LOOP-F.F7** (draft .docx) |
| E2  | Plan of Action and Milestones (POA&M) | ✅ | CSP authors, PMO + AO + 3PAO read | OSCAL JSON 1.1.2 + .xlsx + .xml | NIST CA-5; FedRAMP POA&M Template; OSCAL `plan-of-action-and-milestones` schema | **HAVE** — `core/oscal-poam.ts` (LOOP-A.A1) | **LOOP-A.A1** (HAVE) + LOOP-E.E2 (monthly delta) |
| E3  | Continuous Monitoring Strategy + Plan | ✅ | PMO + AO read; CSP executes | .docx + JSON metadata | NIST CA-7; FedRAMP ConMon Strategy Template + ConMon Playbook | MISSING | **LOOP-C.C6** + **LOOP-E.E1** (monthly report) |
| E4  | Penetration Test Report + Rules of Engagement | ✅ | 3PAO authors; PMO + AO read | .docx + OSCAL AR extension | NIST CA-8; FedRAMP PenTest Guidance v3.0 | PARTIAL — RoE template HAVE (`core/roe-emit.ts`, LOOP-A.A5); PenTest ingest missing | LOOP-A.A5 (RoE HAVE) + **LOOP-K.K1** (PenTest ingest) |
| E5  | Configuration Management Plan (CMP) | ✅ | PMO + AO + 3PAO read | .docx | NIST CM-9; FedRAMP CMP Template | MISSING | **LOOP-C.C1** |
| E6  | Baseline Configuration document | ✅ | 3PAO read; CSP maintains | .docx + JSON | NIST CM-2; FedRAMP CMP / Baseline Configuration guidance | PARTIAL — `providers/*/reference-arch.ts` partial scaffolding | **LOOP-C.C9** |
| E7  | Integrated Inventory Workbook (Appendix M) | ✅ | 3PAO read; CSP maintains monthly | .xlsx (FedRAMP IIW template) + JSON | NIST CM-8; FedRAMP IIW v3.0; SSP Appendix M | **HAVE** — `core/inventory-workbook.ts` + INV-S1..S6 24/25-column coverage | INV-P1..S6 (HAVE) + LOOP-E.E2 (monthly refresh) |
| E8  | Information System Contingency Plan (ISCP) | ✅ | PMO + AO read | .docx + ISCP Test AAR .docx | NIST CP-2; FedRAMP ISCP Template | MISSING | **LOOP-C.C2** + **LOOP-E.E7** (annual test runner) |
| E9  | ISCP Test After-Action Report (AAR) | ✅ annually | PMO + AO + 3PAO read | .docx | NIST CP-4; FedRAMP ISCP Test guidance | MISSING | **LOOP-C.C2** + **LOOP-E.E7** |
| E10 | Incident Response Plan (IRP) | ✅ | PMO + AO + 3PAO read | .docx | NIST IR-8; FedRAMP IRP Template | MISSING | **LOOP-C.C3** |
| E11 | IRP Test After-Action Report (AAR) | ✅ annually | PMO + AO + 3PAO read | .docx | NIST IR-3; FedRAMP IRP Test guidance | MISSING | **LOOP-C.C3** + **LOOP-E.E7** |
| E12 | System Security Plan (SSP) | ✅ | PMO + AO + 3PAO read | OSCAL JSON 1.1.2 + .docx (SSP-2) | NIST PL-2; FedRAMP SSP Template; OSCAL `system-security-plan` schema | **HAVE** — `core/oscal-ssp.ts` (SSP-1) + `core/ssp-docx.ts` (SSP-2) | SSP-1 + SSP-2 (HAVE) + **LOOP-I.I4** (narrative library) |
| E13 | Risk Management Strategy (RMS) | ✅ | PMO + AO read; CSP executes | .docx | NIST PM-9; FedRAMP RMS Template | MISSING | **LOOP-C.C7** |
| E14 | Authorization Workflow / ATO package | ✅ | PMO + AO read; CSP submits | INDEX.json + signed tarball + cover letter .docx | NIST PM-10; FedRAMP Authorization Playbook | PARTIAL — bundler HAVE (`core/submission-bundle.ts`, LOOP-A.A4); cover letter + workflow tracker missing | LOOP-A.A4 (HAVE) + **LOOP-C.C8** (cover) + **LOOP-F.F6** (workflow) |
| E15 | User Roles & Privileges Matrix | ✅ | 3PAO read; CSP maintains | .xlsx | NIST AC-2; FedRAMP SSP §9.1 + RFC-0014 KSI-IAM-AAM | PARTIAL — `providers/*/iam.ts` collectors HAVE; matrix emitter MISSING | **LOOP-J.J1** |
| E16 | Least-Privilege Justification log | ✅ | 3PAO read | .xlsx + JSON evidence | NIST AC-6; FedRAMP KSI-IAM-ELP | PARTIAL — IAM-ELP collectors HAVE; justification narrative MISSING | **LOOP-J.J1** + tracker (operator-supplied justifications) |
| E17 | Risk Assessment Report | ✅ | 3PAO read; CSP authors | .docx + JSON | NIST RA-3; FedRAMP Risk Assessment guidance | PARTIAL — covered by SAR + per-finding risk; consolidated RA report MISSING | **LOOP-B.B5** (Central Risk Register) |
| E18 | Vulnerability Scan Reports + KEV reconcile | ✅ monthly | 3PAO + PMO read | JSON (signed) + .csv | NIST RA-5; FedRAMP Vulnerability Scanning Requirements v3.1 | **HAVE** — `providers/*/vdr-scan.ts` + CISA KEV reconcile | (HAVE) + **LOOP-B.B2** (deadline math) + **LOOP-E.E1** (monthly report) |
| E19 | Audit-log Protection evidence | ✅ | 3PAO read | JSON envelope (signed) | NIST AU-9; FedRAMP KSI-MLA-ALA | **HAVE** — `providers/*/logging.ts` MLA-ALA collectors | (HAVE) |
| E20 | Audit-record Retention evidence (3-year) | ✅ | 3PAO read; PMO audit | JSON envelope + archive manifest | NIST AU-11; FedRAMP ConMon Strategy | PARTIAL — log retention checks HAVE; long-term archive MISSING | **LOOP-H.H1** + **LOOP-H.H2** |
| E21 | Privacy Threshold Analysis (PTA) | ✅ | PMO + AO read | .docx | NIST PT-2 / PT-3 / PT-6; FedRAMP PTA Template; OMB M-03-22 | MISSING | **LOOP-C.C4** |
| E22 | Privacy Impact Assessment (PIA) | ⚠️ conditional (PII processed) | PMO + AO read; published if applicable | .docx | NIST PT-2 / PT-3 / PT-6; FedRAMP PIA Template; OMB M-03-22 | MISSING | **LOOP-C.C4** (conditional emit) |
| E23 | Subprocessor Inventory + Supply-Chain Risk Register | ✅ | 3PAO + PMO read | .xlsx + JSON | NIST SA-9 + SR-3; FedRAMP Subprocessor Guidance | PARTIAL — `core/subprocessors-sheet.ts` HAVE; SBOM-backed SR-3 register MISSING | **LOOP-J.J2** + **LOOP-J.J3** |

> **Implicit covered by chain but not separately listed in E1–E23:**
> Assessment Plan (AP, OSCAL `assessment-plan`) is delivered by
> **LOOP-A.A2** (`core/oscal-ap.ts`) and is the precondition for E1 (SAR)
> via `import-ap`. The submission-bundle INDEX (LOOP-A.A4) is part of
> E14. The signed evidence manifest + RFC 3161 timestamp underwrite every
> artifact's provenance.

---

## 3. Per-artifact detail

Each subsection cites the source obligation, the FedRAMP template /
OSCAL schema reference, the split between CSP-authored and 3PAO/PMO-
authored content, and the cross-references to other artifacts that
depend on this one.

### E1 — Security Assessment Report (SAR), CA-2

- **Source citation:**
  - NIST SP 800-53 Rev5 control **CA-2**: "*Develop a control assessment
    plan that describes the scope of the assessment*" and "*produce a
    control assessment report that documents the results of the
    assessment.*" ([NIST SP 800-53 Rev5, CA-2](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home))
  - FedRAMP Rev5 SAR Template (Word) — `https://www.fedramp.gov/assets/resources/templates/FedRAMP-SAR-Template.docx`
  - OSCAL: `assessment-results` model v1.1.2 — `https://pages.nist.gov/OSCAL/concepts/layer/assessment/assessment-results/`
- **OSCAL schema reference:** `oscal_assessment-results_schema.v1.1.2.json`
  (committed at `cloud-evidence/docs/oscal/`). Required root keys:
  `uuid`, `metadata`, `import-ap`, `results[]`. The chain to AP is
  hard-required.
- **CSP delivers:** the AR JSON+XML (via the OSCAL emitter), all
  per-KSI evidence envelopes, the signed manifest, the inventory the
  AR `assessment-subjects` resolves against.
- **3PAO authors:** the SAR narrative, sample selection justification,
  test method elaborations, recommendation language. The AR is the
  machine-readable artifact; the SAR .docx is the human-readable one.
- **Cross-refs:** depends on **E12** (SSP) via SSP→AP→AR chain;
  depends on **E2** (POA&M) for open findings; consumed by **E14**
  (authorization package).
- **Slice:** LOOP-A.A3 wires the chain (`core/oscal.ts` AR's
  `import-ap` resolution); the SAR .docx draft generator is
  **LOOP-F.F7** (`core/sar-draft.ts`).

### E2 — Plan of Action and Milestones (POA&M), CA-5

- **Source citation:**
  - NIST SP 800-53 Rev5 control **CA-5**: "*Develop a plan of action
    and milestones for the system to document the planned remediation
    actions ... to correct weaknesses or deficiencies noted during the
    assessment of the controls.*"
  - FedRAMP POA&M Template (xlsx) — `https://www.fedramp.gov/assets/resources/templates/FedRAMP-POAM-Template.xlsx`
  - OSCAL: `plan-of-action-and-milestones` model v1.1.2 — `https://pages.nist.gov/OSCAL/concepts/layer/assessment/poam/`
  - FedRAMP Rev5 Playbook — ConMon Overview (monthly cadence + USDA
    Connect.gov repo for Low/Mod) — see R2 findings in
    `docs/PRE-LOOP-A-RESEARCH-FINDINGS.md`.
- **OSCAL schema reference:** `oscal_poam_schema.v1.1.2.json`. Required
  keys: `uuid`, `metadata`, `import-ssp`, `system-id`, `poam-items[]`
  (`minItems: 1`). LOOP-A.A1 emits zero-state correctly (returns
  `skipped_reason: "no-failing-findings"` rather than an invalid doc).
- **CSP delivers:** the entire POA&M, monthly. Severity-based
  remediation deadlines computed from `envelope.collected_at`
  (Critical 30d / High 60d / Medium 90d / Low 180d). Risk scoring
  (CVSS+EPSS+criticality+exposure) added in **LOOP-B.B1**.
- **3PAO authors:** nothing directly in the POA&M; the SAR's findings
  drive POA&M items.
- **Cross-refs:** depends on **E12** (SSP for `import-ssp`); feeds
  **E17** (Risk Register), **E14** (submission), **LOOP-E.E2** monthly
  delta.
- **Slice:** **LOOP-A.A1** (HAVE) — `core/oscal-poam.ts`. Monthly
  workflow + Excel companion = LOOP-E.E2.

### E3 — Continuous Monitoring Strategy + Plan, CA-7

- **Source citation:**
  - NIST SP 800-53 Rev5 control **CA-7**: "*Develop a system-level
    continuous monitoring strategy and implement continuous monitoring
    in accordance with the organization-level continuous monitoring
    strategy.*"
  - FedRAMP ConMon Strategy Template — `https://www.fedramp.gov/assets/resources/templates/FedRAMP-Continuous-Monitoring-Strategy-Guide.docx`
  - FedRAMP Rev5 Playbook ConMon section — `https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/overview/`
- **Template reference:** FedRAMP ConMon Strategy Guide v3.0.
- **CSP delivers:** the document, with auto-fill from ksi-map (which
  controls monitored), scan-config (monthly), POA&M cadence (monthly),
  AR cadence (monthly).
- **REQUIRES-OPERATOR-INPUT:** ConMon team roster, deviation request
  process, escalation thresholds — flow through tracker/config.
- **Cross-refs:** drives **E2** monthly cadence + **E18** scan-report
  cadence + **E20** retention windows. Consumed by **E14**.
- **Slice:** **LOOP-C.C6** authors the document; **LOOP-E.E1** emits
  the monthly ConMon report it commits the CSP to.

### E4 — Penetration Test Report + Rules of Engagement, CA-8

- **Source citation:**
  - NIST SP 800-53 Rev5 control **CA-8**: "*Conduct penetration testing
    [Assignment: organization-defined frequency] on [Assignment:
    organization-defined systems or system components].*"
  - FedRAMP Penetration Test Guidance v3.0 (June 2023) — `https://www.fedramp.gov/assets/resources/documents/CSP_Penetration_Test_Guidance.pdf`
- **CSP delivers:** the RoE template seeded from real inventory
  (boundary, IPs, scope, escalation contacts) — `core/roe-emit.ts`
  (LOOP-A.A5). CSP + 3PAO co-sign the RoE.
- **3PAO authors:** the PenTest report .docx itself, including
  vulnerabilities discovered, exploitation paths, severity ratings,
  retest results. Findings flow back into **E1** (AR) and **E2** (POA&M).
- **Cross-refs:** depends on the SSP boundary (**E12**) + inventory
  (**E7**) to define scope; outputs feed **E1** + **E2**.
- **Slice:** RoE template = **LOOP-A.A5** (HAVE); PenTest ingest
  schema + tracker upload = **LOOP-K.K1**; mapping into AR
  test-result-objects per 800-53A = **LOOP-K.K2**.

### E5 — Configuration Management Plan (CMP), CM-9

- **Source citation:**
  - NIST SP 800-53 Rev5 control **CM-9**: "*Develop, document, and
    implement a configuration management plan for the system.*"
  - FedRAMP CMP Template — `https://www.fedramp.gov/assets/resources/templates/FedRAMP-Configuration-Management-Plan-Template.docx`
- **CSP delivers:** full CMP document with auto-fill from
  `inventory.json` (component list), ksi-map (which controls),
  tracker (operator-supplied process narrative).
- **REQUIRES-OPERATOR-INPUT:** approval workflow narrative, roll-back
  authority, baseline-config reference, change windows.
- **Cross-refs:** **E6** (Baseline Configuration) is a deliverable
  produced under the CMP's authority; **E2** SCN events (LOOP-E.E6)
  reference back to the CMP's change-classification rules.
- **Slice:** **LOOP-C.C1**.

### E6 — Baseline Configuration document, CM-2

- **Source citation:**
  - NIST SP 800-53 Rev5 control **CM-2**: "*Develop, document, and
    maintain under configuration control, a current baseline
    configuration of the system.*"
- **Template reference:** FedRAMP CMP Appendix / Baseline Configuration
  guidance (subsumed under the CMP doc family but distinct from CM-8
  inventory).
- **CSP delivers:** the baseline configuration record (per-component
  golden image versions, hardening profiles, approved deviations).
  Auto-fill from `core/inventory.json` + AFR-SCG existing
  reference-arch scaffold + `providers/*/reference-arch.ts`.
- **REQUIRES-OPERATOR-INPUT:** baseline-config approval signature,
  deviation log location, hardening-profile attestation.
- **Cross-refs:** distinct from **E7** (CM-8 inventory). The baseline
  is the *intended* state; the inventory is the *actual* state. Diffs
  feed SCN classification (LOOP-E.E6).
- **Slice:** **LOOP-C.C9**.

### E7 — Integrated Inventory Workbook (Appendix M), CM-8

- **Source citation:**
  - NIST SP 800-53 Rev5 control **CM-8**: "*Develop and document an
    inventory of system components.*"
  - FedRAMP Integrated Inventory Workbook (IIW) Template v3.0 —
    `https://www.fedramp.gov/assets/resources/templates/FedRAMP-Integrated-Inventory-Workbook-Template.xlsx`
  - The IIW is SSP Appendix M.
- **Template reference:** FedRAMP IIW v3.0 — 25 columns (A–Y). Column
  T (Comments) is operator-supplied; columns A–S, U–Y are auto-derived.
- **CSP delivers:** the workbook, monthly. INV-S1..S6 closed 24/25
  columns across AWS+GCP+Azure (column T stays operator-supplied with
  documented tag-override path). Coverage Contract
  (`core/inventory-coverage.ts`) makes regressions detectable.
- **Cross-refs:** referenced by **E12** (SSP Appendix M), **E1** (AR
  assessment-subjects), **E18** (scan scope), **E6** (baseline
  comparison).
- **Slice:** INV-P1..S6 (HAVE) + LOOP-E.E2 (monthly refresh).

### E8 — Information System Contingency Plan (ISCP), CP-2

- **Source citation:**
  - NIST SP 800-53 Rev5 control **CP-2**: "*Develop a contingency plan
    for the system.*"
  - FedRAMP ISCP Template — `https://www.fedramp.gov/assets/resources/templates/FedRAMP-ISCP-Template.docx`
- **CSP delivers:** the ISCP document. Auto-fill from RPL-ABO /
  RPL-TRC / RPL-RRO / RPL-ARP collector evidence (real backup configs,
  geo-redundancy, recovery objectives).
- **REQUIRES-OPERATOR-INPUT:** RTO/RPO commitments, contingency
  activation authority, alternate site details, notification roster.
- **Cross-refs:** depends on **E7** (inventory for scope); feeds
  **E9** (annual test AAR); **LOOP-E.E7** schedules annual test.
- **Slice:** **LOOP-C.C2**.

### E9 — ISCP Test After-Action Report (AAR), CP-4

- **Source citation:**
  - NIST SP 800-53 Rev5 control **CP-4**: "*Test the contingency plan
    for the system [Assignment: organization-defined frequency] using
    the following tests to determine the effectiveness of the plan and
    the readiness to execute the plan: [Assignment: organization-defined
    tests].*"
  - Annual cadence per FedRAMP Moderate parameter (CP-4(a) Parameter 1).
- **CSP delivers:** annually, the test AAR — prefilled with test date,
  participants list from tracker, prior-year findings ledger. Operator
  fills test results.
- **Cross-refs:** depends on **E8** (ISCP) being current; feeds **E1**
  (AR — annual assessment package).
- **Slice:** **LOOP-C.C2** (template) + **LOOP-E.E7** (annual runner).

### E10 — Incident Response Plan (IRP), IR-8

- **Source citation:**
  - NIST SP 800-53 Rev5 control **IR-8**: "*Develop an incident response
    plan that ... addresses sharing of incident information; describes
    the structure and organization of the incident response capability;
    [...] is reviewed and approved by [Assignment: organization-defined
    personnel or roles] [Assignment: organization-defined frequency].*"
  - FedRAMP IRP Template — `https://www.fedramp.gov/assets/resources/templates/FedRAMP-IRP-Template.docx`
- **CSP delivers:** the IRP document. Auto-fill from INR-RIR collector
  evidence + tracker incident records.
- **REQUIRES-OPERATOR-INPUT:** IR team roster, escalation matrix,
  communication plan (internal + FedRAMP + CISA + agency).
- **Cross-refs:** depends on **E7** (inventory for IR scope), AFR-ICP
  (LOOP-G.G2) for the formal Incident Communications Procedures that
  the IRP references; feeds **E11** (annual test AAR).
- **Slice:** **LOOP-C.C3**.

### E11 — IRP Test After-Action Report (AAR), IR-3

- **Source citation:**
  - NIST SP 800-53 Rev5 control **IR-3**: "*Test the effectiveness of
    the incident response capability for the system [Assignment:
    organization-defined frequency] using the following tests:
    [Assignment: organization-defined tests].*"
  - Annual cadence per FedRAMP Moderate parameter.
- **CSP delivers:** annually, the test AAR document.
- **Cross-refs:** depends on **E10** (IRP); feeds **E1** (annual AR).
- **Slice:** **LOOP-C.C3** (template) + **LOOP-E.E7** (annual runner).

### E12 — System Security Plan (SSP), PL-2

- **Source citation:**
  - NIST SP 800-53 Rev5 control **PL-2**: "*Develop security and privacy
    plans for the system that ... describe the security categorization
    of the system [...]; describe the operational context of the system
    [...]; describe the security requirements for the system; describe
    the controls in place or planned for meeting those requirements
    [...].*"
  - FedRAMP Rev5 SSP Template — `https://www.fedramp.gov/assets/resources/templates/FedRAMP-Rev5-SSP-Template.docx`
  - OSCAL: `system-security-plan` model v1.1.2 — `https://pages.nist.gov/OSCAL/concepts/layer/implementation/ssp/`
  - RFC-0024 mandates OSCAL JSON for 20x SSP submissions.
- **OSCAL schema reference:** `oscal_ssp_schema.v1.1.2.json`. Required
  root keys: `uuid`, `metadata`, `import-profile`, `system-characteristics`,
  `system-implementation`, `control-implementation`.
- **CSP delivers:** the SSP JSON+XML+.docx, with implementation
  narratives per control. REO compliance: authorization-boundary
  description + user-roles list now flow through `SspEmitOptions`
  (REO-0 fix) rather than placeholder prose.
- **3PAO reviews; AO approves.** PMO requires both OSCAL JSON (per
  RFC-0024) and a human-readable .docx.
- **Cross-refs:** parent of every other artifact in this section. Every
  control implementation in the SSP must have a corresponding AR finding
  (E1) and a POA&M entry (E2) when failing.
- **Slice:** SSP-1 (`core/oscal-ssp.ts`) + SSP-2 (`core/ssp-docx.ts`)
  HAVE; narrative library + per-control override system =
  **LOOP-I.I4**.

### E13 — Risk Management Strategy (RMS), PM-9

- **Source citation:**
  - NIST SP 800-53 Rev5 control **PM-9**: "*Develop a comprehensive
    strategy to manage [...] security and privacy risk to organizational
    operations and assets, individuals, other organizations, and the
    Nation associated with the operation and use of organizational
    systems.*"
  - FedRAMP RMS Template (subset of authorization-package boilerplate).
- **CSP delivers:** the document. Auto-fill from **E17** (Risk
  Register), **LOOP-B.B3** (acceptance policy), **LOOP-B.B4**
  (compensating-controls registry).
- **REQUIRES-OPERATOR-INPUT:** organizational risk tolerance, executive
  oversight roles, risk-appetite statement.
- **Cross-refs:** depends on **E17** (RA-3 register); feeds **E14**.
- **Slice:** **LOOP-C.C7**.

### E14 — Authorization Workflow / ATO package, PM-10

- **Source citation:**
  - NIST SP 800-53 Rev5 control **PM-10**: "*Manage the security and
    privacy state of organizational systems and the environments in
    which those systems operate through authorization processes [...].*"
  - FedRAMP Authorization Playbook — `https://www.fedramp.gov/docs/rev5/playbook/`
- **CSP delivers:** the signed submission tarball (LOOP-A.A4) +
  INDEX.json + cover letter. Tracker-side: workflow tracker that moves
  the package through `package complete → 3PAO sign-off → AO review →
  ATO decision → publication`.
- **Cross-refs:** consumes **E1**, **E2**, **E12**, **E7**, **E18**
  (and every other artifact in this section).
- **Slice:** **LOOP-A.A4** (bundler HAVE) + **LOOP-C.C8** (cover letter
  .docx) + **LOOP-F.F6** (workflow state machine).

### E15 — User Roles & Privileges Matrix, AC-2

- **Source citation:**
  - NIST SP 800-53 Rev5 control **AC-2**: "*Define and document the
    types of accounts allowed and specifically prohibited for use within
    the system [...]; assign account managers; require [Assignment:
    organization-defined prerequisites and criteria] for group and
    role membership.*"
  - FedRAMP SSP §9.1 (User Privileges + Roles table).
- **CSP delivers:** an .xlsx matrix (roles × privileges) derived from
  IAM-AAM + IAM-ELP collector evidence. Operator-supplied: business
  justification per role.
- **Cross-refs:** depends on **E7** (inventory), feeds **E1** AC-2
  finding test.
- **Slice:** **LOOP-J.J1**.

### E16 — Least-Privilege Justification log, AC-6

- **Source citation:**
  - NIST SP 800-53 Rev5 control **AC-6**: "*Employ the principle of
    least privilege, allowing only authorized accesses for users (or
    processes acting on behalf of users) that are necessary to accomplish
    assigned organizational tasks.*"
  - AC-6(1), AC-6(2), AC-6(7), AC-6(9), AC-6(10) all apply at Moderate.
- **CSP delivers:** the justification log .xlsx + signed JSON evidence
  from IAM-ELP collectors. Each privileged role/permission has an
  operator-entered business justification stored in the tracker.
- **Cross-refs:** companion to **E15**.
- **Slice:** **LOOP-J.J1** + tracker DB (operator-supplied
  justifications).

### E17 — Risk Assessment Report (RA-3) + Central Risk Register

- **Source citation:**
  - NIST SP 800-53 Rev5 control **RA-3**: "*Conduct a risk assessment,
    including: identifying threats to and vulnerabilities in the system;
    determining the likelihood and magnitude of harm [...]; documenting
    the risk assessment results in [Selection: security and privacy
    plans; risk assessment report; [Assignment: organization-defined
    document]].*"
- **CSP delivers:** `out/risk-register.json` + `risk-register.xlsx`.
  Aggregates all POA&M items (LOOP-A.A1) + open risk-acceptances
  (LOOP-B.B3) + organizational risks (operator-entered: third-party,
  supply-chain, environmental).
- **Cross-refs:** depends on **E2** (POA&M) + **LOOP-B.B1** (risk
  scoring); feeds **E13** (RMS).
- **Slice:** **LOOP-B.B5**.

### E18 — Vulnerability Scan Reports + KEV reconcile, RA-5

- **Source citation:**
  - NIST SP 800-53 Rev5 control **RA-5**: "*Monitor and scan for
    vulnerabilities in the system and hosted applications [Assignment:
    organization-defined frequency] [...] and when new vulnerabilities
    potentially affecting the system are identified and reported [...].*"
  - FedRAMP Rev5 Vulnerability Scanning Requirements v3.1 — `https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/vulnerability-scanning/`
  - Monthly cadence; 100% of externally-accessible components scanned;
    sampling allowed for internal components per Appendix B (R4 finding).
  - CISA Known Exploited Vulnerabilities (KEV) catalog — `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`
- **CSP delivers:** signed JSON evidence envelopes from
  `providers/{aws,gcp,azure}/vdr-scan.ts` collectors, reconciled
  against the committed `docs/cisa-kev.generated.json`. KEV-matched
  vulnerabilities get a 21-day deadline (CISA-published `dueDate`)
  rather than the FedRAMP severity baseline.
- **Cross-refs:** depends on **E7** (inventory scope), feeds **E2**
  (each finding → POA&M item), feeds **LOOP-E.E1** (monthly ConMon
  report).
- **Slice:** vdr-scan collectors HAVE; **LOOP-B.B2** computes the
  KEV / PAIN / IRV / LEV deadlines; **LOOP-E.E1** ships monthly
  report.

### E19 — Audit-log Protection evidence, AU-9

- **Source citation:**
  - NIST SP 800-53 Rev5 control **AU-9**: "*Protect audit information
    and audit logging tools from unauthorized access, modification, and
    deletion.*"
- **CSP delivers:** signed JSON evidence from `providers/*/logging.ts`
  MLA-ALA collectors. Verifies log integrity controls (immutable
  storage, retention enforcement, restricted access).
- **Cross-refs:** feeds **E1** AU-9 finding test; complements **E20**.
- **Slice:** HAVE (`providers/{aws,gcp,azure}/logging.ts` MLA-ALA).

### E20 — Audit-record Retention evidence (3-year), AU-11

- **Source citation:**
  - NIST SP 800-53 Rev5 control **AU-11**: "*Retain audit records for
    [Assignment: organization-defined time period consistent with
    records retention policy] to provide support for after-the-fact
    investigations of incidents [...].*"
  - FedRAMP Moderate parameter: **at least 3 years** of audit log
    retention online or accessible.
- **CSP delivers:** log retention checks (HAVE) + immutable archive
  push of submission packages to S3 Glacier Deep Archive / GCS Coldline
  / Azure Archive with object-lock enabled. Annual retention report.
- **Cross-refs:** complements **E19**; archive backbone is shared
  across **E1**, **E2**, **E7**, **E18** (3-year evidence ledger).
- **Slice:** retention collector HAVE; immutable archive +
  policy-enforcement = **LOOP-H.H1** + **LOOP-H.H2**.

### E21 — Privacy Threshold Analysis (PTA), PT-2 / PT-3 / PT-6

- **Source citation:**
  - NIST SP 800-53 Rev5 controls **PT-2** (Authority to Process PII),
    **PT-3** (PII Processing Purposes), **PT-6** (System of Records
    Notice).
  - OMB Memorandum **M-03-22** — "OMB Guidance for Implementing the
    Privacy Provisions of the E-Government Act of 2002" — `https://www.whitehouse.gov/wp-content/uploads/legacy_drupal_files/omb/memoranda/2003/m03_22.pdf`
  - FedRAMP PTA Template — `https://www.fedramp.gov/assets/resources/templates/FedRAMP-PTA-Template.docx`
- **CSP delivers:** the PTA document. Auto-fill from `inventory.json`
  data-classification tags. If no PII-likely tags detected, the PTA
  emits a "no PII processed" determination; otherwise both PTA and
  PIA (E22) are emitted.
- **Cross-refs:** drives **E22** (PIA — conditional emit). Required
  for SSP §15 (Privacy).
- **Slice:** **LOOP-C.C4**.

### E22 — Privacy Impact Assessment (PIA), PT-2 / PT-3 / PT-6

- **Source citation:** same as E21. Triggered when the PTA determines
  PII is processed.
- **CSP delivers:** the PIA document. Public-facing in many cases
  (E-Government Act §208).
- **Cross-refs:** conditional dependency on **E21** PTA determination.
- **Slice:** **LOOP-C.C4** (conditional emit path).

### E23 — Subprocessor Inventory + Supply-Chain Risk Register, SA-9 + SR-3

- **Source citation:**
  - NIST SP 800-53 Rev5 control **SA-9**: "*Require that providers of
    external system services comply with organizational security and
    privacy requirements and employ the following controls [...]; define
    and document organizational oversight and user roles and
    responsibilities with regard to external system services.*"
  - NIST SP 800-53 Rev5 control **SR-3**: "*Establish a process or
    processes to identify and address weaknesses or deficiencies in the
    supply chain elements and processes [...].*"
  - NIST SP 800-161 Rev1 — supply chain risk management guidance —
    `https://csrc.nist.gov/pubs/sp/800/161/r1/upd1/final`
- **CSP delivers:**
  - Subprocessor inventory .xlsx via `core/subprocessors-sheet.ts`
    (Google Sheets reader HAVE) — extended to per-CSO subprocessor
    list with risk-tier classification in **LOOP-J.J2**.
  - Supply-chain risk register integrating E.2 SBOM data (Syft +
    cosign) with CVE / KEV matching, vendor-risk tier per
    subprocessor. Emitted as `out/supply-chain-risk.json` +
    `.xlsx` in **LOOP-J.J3**.
- **Cross-refs:** depends on **E7** inventory + **E18** scan evidence;
  feeds **E17** Risk Register.
- **Slice:** **LOOP-J.J2** + **LOOP-J.J3**.

---

## 4. Acceptance criteria for this section

SECTION E is considered **complete** when every row below is true.
The acceptance test is a deterministic CI assertion: a one-shot
orchestrator run on a real environment produces every required
artifact, the submission bundler classifies all of them, and the
chain-integrity check passes.

1. ✅ **E1 (SAR)** — `core/sar-draft.ts` (LOOP-F.F7) emits a draft
   SAR .docx that references the AR JSON via OSCAL `import-ap` chain.
   The AR JSON (HAVE today) passes ajv against
   `oscal_assessment-results_schema.v1.1.2.json`. RoE + sampling
   methodology back-matter references are populated.
2. ✅ **E2 (POA&M)** — already met. LOOP-A.A1 emits OSCAL POA&M JSON+XML
   + (when LOOP-A.A4 packaging runs) the companion .xlsx via the
   FedRAMP POA&M Template. Monthly delta workflow (LOOP-E.E2) lands.
3. ✅ **E3 (ConMon Strategy)** — LOOP-C.C6 emits the .docx with all
   REQUIRES-OPERATOR-INPUT markers resolved when operator inputs are
   provided via tracker/config. Strategy commits to the cadences
   (monthly POA&M, monthly scans, annual AR refresh) that LOOP-E
   enforces.
4. ✅ **E4 (PenTest + RoE)** — RoE template HAVE. PenTest ingest
   (LOOP-K.K1) parses an uploaded 3PAO report, creates finding+POA&M
   items, and surfaces them in the AR. Mapping into AR test-result-
   objects per 800-53A Rev5 (LOOP-K.K2) closes the chain.
5. ✅ **E5 (CMP)** — LOOP-C.C1 emits the .docx with auto-fill from
   inventory + ksi-map; operator-supplied process narratives validated
   against the REQUIRES-OPERATOR-INPUT marker list.
6. ✅ **E6 (Baseline Configuration)** — LOOP-C.C9 emits the baseline
   doc from inventory + reference-arch scaffold; deviations from
   baseline are detectable by SCN classifier (LOOP-E.E6).
7. ✅ **E7 (IIW Appendix M)** — already met (24/25 columns INV-S1..S6).
   LOOP-E.E2 monthly refresh confirms ongoing fill-rate stability.
8. ✅ **E8 + E9 (ISCP + Test AAR)** — LOOP-C.C2 emits both templates;
   LOOP-E.E7 schedules annual test runs and prefills the AAR with
   participants + prior findings.
9. ✅ **E10 + E11 (IRP + Test AAR)** — LOOP-C.C3 emits both; LOOP-E.E7
   handles annual cadence.
10. ✅ **E12 (SSP)** — already met (SSP-1 OSCAL JSON+XML + SSP-2 .docx
    HAVE). LOOP-I.I4 narrative library reduces manual SSP authoring
    burden across re-emissions.
11. ✅ **E13 (RMS)** — LOOP-C.C7 emits the .docx with operator-supplied
    risk tolerance + auto-fill from risk register (E17) and
    compensating-controls registry (LOOP-B.B4).
12. ✅ **E14 (Authorization package)** — bundler HAVE; LOOP-C.C8 cover
    letter .docx emits with summary counts read from INDEX.json;
    LOOP-F.F6 ATO workflow tracker tracks the package through PMO/AO
    review.
13. ✅ **E15 (Roles & Privileges Matrix)** — LOOP-J.J1 emits the .xlsx
    with operator-supplied business justifications stored in tracker.
14. ✅ **E16 (Least-Privilege Justification log)** — LOOP-J.J1 +
    tracker (per-role / per-privilege justification entries).
15. ✅ **E17 (Risk Register / RA-3)** — LOOP-B.B5 emits `out/risk-register.json`
    + `.xlsx`; aggregates POA&M + risk acceptances + organizational
    risks.
16. ✅ **E18 (Scan Reports + KEV)** — already met for scan side;
    LOOP-B.B2 KEV/PAIN/IRV/LEV deadline math + LOOP-E.E1 monthly report
    close it.
17. ✅ **E19 (Audit-log Protection)** — already met (MLA-ALA collectors).
18. ✅ **E20 (Retention)** — log retention HAVE; LOOP-H.H1 immutable
    archive + LOOP-H.H2 retention policy enforcement land.
19. ✅ **E21 + E22 (PTA + PIA)** — LOOP-C.C4 emits PTA always; PIA
    conditionally when PII tags detected.
20. ✅ **E23 (Subprocessor + Supply Chain Risk)** —
    `core/subprocessors-sheet.ts` HAVE; LOOP-J.J2 + LOOP-J.J3 land.
21. ✅ **Chain integrity** — `core/submission-bundle.ts` chain-check
    (LOOP-A.A4) passes with `--strict-bundle` against a full real-data
    run: every required role in the well-known catalogue has a real
    file; no gaps; no synthetic AP/AR references.
22. ✅ **REO** — `npm run check:reo` green: lint-no-stubs (G1),
    coverage-regression (G2), provenance (G3) all clean against the
    SECTION E artifact set.
23. ✅ **Tests** — every slice's tests pass on the real code path;
    parsers, validators, signers, emitters are never mocked.
24. ✅ **CHANGELOG** — each slice's entry names the artifact, the
    NIST control(s) covered, and the source obligation cited above.

When all 24 checkpoints are true, SECTION E ships and the FedRAMP 20x
Moderate authorization package is end-to-end emit-able from real
evidence.

---

## 5. Open questions

These items may shift during implementation. Each has a documented
fallback so it does NOT block forward progress on the named slices.

1. **POA&M wire format final form.** R2 finding documented ambiguity:
   Excel-only vs OSCAL-only vs both. LOOP-A.A1 emits OSCAL (mandated by
   RFC-0024); LOOP-A.A4 packages the Excel companion. If the PMO
   publishes a definitive single-format mandate post-Phase-Two pilot,
   bump `package_format_version` and re-emit. **Decision:** ship both.
2. **Phase Two pilot post-retrospective format.** R3 finding: no
   post-pilot guidance has been published as of the date of this
   document. LOOP-A.A4 emits `package_format_version:
   "20x.phase-two.preview.2026"` which supports a clean version bump.
   **Decision:** monitor fedramp.gov/blog quarterly; clean patch when
   guidance lands.
3. **Sampling statistical confidence.** R4 finding: FedRAMP delegates
   sample-representativeness to 3PAO judgment + AO sign-off; does not
   prescribe a confidence interval. LOOP-F.F3 uses stratified by
   asset-class + region with a 10% floor; externally-accessible
   components are 100% (hard-coded MUST). **Decision:** ship the
   methodology with AO sign-off requirement; if FedRAMP later
   prescribes a confidence threshold, swap the floor for the
   prescribed minimum.
4. **SAR .docx vs OSCAL AR JSON authority.** RFC-0024 mandates OSCAL
   JSON, but the SAR remains a human-readable .docx the 3PAO signs.
   LOOP-F.F7 emits a SAR draft .docx that *references* the AR JSON.
   **Decision:** OSCAL JSON is the source of truth for findings; the
   SAR .docx is the narrative wrapper.
5. **Risk register format vs RMS document.** RA-3 and PM-9 are
   sometimes documented in a single risk management document, sometimes
   split. LOOP-B.B5 emits a structured register (JSON + XLSX); LOOP-C.C7
   emits the RMS .docx that references it. **Decision:** keep split;
   reduces operator burden during monthly refresh (RMS rarely changes;
   register updates monthly with POA&M).
6. **PIA publication mechanism.** E-Government Act §208 typically
   requires public PIA publication. The CSP may delegate publication to
   the agency consumer. **Decision:** emit the PIA artifact; do NOT
   automate publication — operator decides routing.
7. **AU-11 3-year window — online vs offline.** FedRAMP Moderate allows
   "online or accessible" — interpretations vary on whether Glacier
   Deep Archive (12+ hour retrieval) counts as "accessible". LOOP-H.H2
   policy-enforcement check will alert; AO arbitrates. **Decision:**
   default to online-3-month + cold-archive-3-year-with-retrieval-SLA.
8. **CMP vs SCN vs SSP overlap.** Some PMO reviews treat the CMP as a
   subset of the SSP CM-family narrative; others require a standalone
   CMP. LOOP-C.C1 emits a standalone CMP that the SSP CM-2/CM-3/CM-9
   narratives cross-reference. **Decision:** ship both; redundancy is
   cheap, gap risk is not.
9. **Subprocessor disclosure granularity.** SA-9 + FedRAMP guidance
   allow CSPs to redact specific subprocessor identities in public
   submissions while disclosing fully to PMO/AO under NDA. LOOP-J.J2
   supports a `disclosure_tier` column. **Decision:** keep operator-
   configurable; default to full PMO disclosure.

---

## Appendix — Cross-walk back to the 287-control Moderate baseline

SECTION E names 23 artifacts but covers more than 23 controls.
Below is the explicit mapping (one-to-many where appropriate). Controls
not listed here are covered indirectly through the KSI-collector layer
or via the SSP control-implementation narrative library (LOOP-I.I4).

| Control(s)            | Artifact(s)                              |
|-----------------------|------------------------------------------|
| AC-2                  | E15                                      |
| AC-6 (1/2/7/9/10)     | E16                                      |
| AU-9                  | E19                                      |
| AU-11                 | E20                                      |
| CA-2                  | E1                                       |
| CA-5                  | E2                                       |
| CA-7                  | E3                                       |
| CA-8                  | E4                                       |
| CM-2                  | E6                                       |
| CM-8                  | E7                                       |
| CM-9                  | E5                                       |
| CP-2                  | E8                                       |
| CP-4                  | E9                                       |
| IR-3                  | E11                                      |
| IR-8                  | E10                                      |
| PL-2                  | E12                                      |
| PM-9                  | E13                                      |
| PM-10                 | E14                                      |
| PT-2 / PT-3 / PT-6    | E21, E22                                 |
| RA-3                  | E17                                      |
| RA-5                  | E18                                      |
| SA-9                  | E23 (subprocessor)                       |
| SR-3                  | E23 (supply-chain risk register)         |

The remaining ~260 Moderate controls are covered via:

1. The SSP `control-implementation.implemented-requirements[]` (E12) —
   every Moderate control has an implementation narrative.
2. The KSI collector layer (44 KSIs across 11 domains) — each KSI maps
   to one or more NIST controls; assessment of the KSI is assessment
   of the underlying control(s).
3. The AR `results[0].findings[]` (E1) — every control reviewed
   produces a finding (satisfied / partially-satisfied / other-than-
   satisfied).

The 23 artifacts in this section are the **standalone deliverables**
that exist *outside* the SSP/AR/POA&M chain itself — the documents,
workbooks, and reports a 3PAO or PMO reviewer expects as separate
package items.
