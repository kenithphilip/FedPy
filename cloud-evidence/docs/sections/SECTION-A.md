# SECTION A — Submission package artifacts (pre-authorization)

> Requirements-layer spec for the **authorization-time submission package**:
> every artifact the CSP must deliver, the 3PAO must assess, and the FedRAMP
> PMO / Authorizing Official must review before an Authority To Operate
> (ATO) decision can be issued under FedRAMP 20x Phase Two (Moderate).
>
> Source-of-truth document for LOOP-A through LOOP-C, LOOP-J, LOOP-K slices.
> Every artifact is mapped to (a) its source obligation, (b) its format,
> (c) its consumer, and (d) the implementation slice that ships it. Status
> data (HAVE / PARTIAL / MISSING) is derived from CHANGELOG.md "Unreleased"
> and reflects the post-LOOP-A baseline.

---

## 1. Purpose

Section A covers the **one-time pre-authorization submission package** —
everything the CSP transmits to the 3PAO at assessment-engagement time,
and everything the 3PAO transmits to the FedRAMP PMO + AO at submission
time. It is distinct from:

- **Section B** — 3PAO assessor experience (LOOP-F): sign-off UI, comment
  threads, sample selection methodology, evidence walk-through, SAR draft
  generator, recommendation letter.
- **Section C** — Continuous Monitoring (LOOP-E): monthly POA&M deltas,
  scan reports, ConMon analysis, annual assessment package, deviation
  requests, SCN notifications.
- **Section D** — Stakeholder dashboards (LOOP-I): executive posture,
  burndown, longitudinal trend analysis.

This section exists because FedRAMP 20x — codified in
[RFC-0014](https://www.fedramp.gov/rfcs/0014/) (KSI framework) and
[RFC-0024](https://www.fedramp.gov/rfcs/0024/) (OSCAL submission
mandate) — has shifted the authorization model from a Word-document
package (`.docx` SSP + `.docx` SAR + `.xlsx` POA&M + assorted
attachments) to a **machine-readable, signed, OSCAL-native submission**
that the PMO can ingest, validate, and continuously re-evaluate. The
artifacts below are the union of (a) the historical FedRAMP Rev5
template set, (b) the OSCAL v1.1.2 model set, and (c) the 20x
Key Security Indicator (KSI) framework. Every required artifact is
explicitly enumerated; nothing is implicit.

The CSP's obligation is to **emit, sign, timestamp, and bundle** these
artifacts. The 3PAO's obligation is to **assess and sign off**. The
PMO/AO's obligation is to **ingest, validate, and decide**. This repo's
job is to make the CSP-side obligation automatic, real-evidence-only
(per `cloud-evidence/CLAUDE.md`), and end-to-end-emittable in one
orchestrator run.

---

## 2. Artifact catalogue (A1-A22)

Twenty-two artifact rows. Symbols:

- Required: ✅ = always required at Moderate; ⚠️ = conditional; RECOMMENDED = strongly encouraged but not strictly required.
- Status: **HAVE** = end-to-end emit-able from real evidence today;
  **PARTIAL** = scaffolding or related collector exists but the artifact
  is not yet a deliverable; **MISSING** = no implementation.

| ID | Artifact | Required | Consumer(s) | Format(s) | Source obligation | Current status | Loop.slice |
|---|---|---|---|---|---|---|---|
| **A1** | OSCAL System Security Plan (SSP) | ✅ | 3PAO, PMO, AO | OSCAL JSON + XML; FedRAMP `.docx` projection | RFC-0024; OSCAL v1.1.2 [system-security-plan](https://pages.nist.gov/OSCAL/concepts/layer/implementation/ssp/) model; FedRAMP Rev5 SSP Template | **HAVE** (`core/oscal-ssp.ts`, `core/ssp-docx.ts`) | LOOP-A.A0 (shipped pre-LOOP-A as SSP-1/SSP-2); future enrichment in LOOP-I.I4 |
| **A2** | OSCAL Assessment Plan (SAP / AP) | ✅ | 3PAO authors; PMO + AO review | OSCAL JSON + XML; FedRAMP SAP `.docx` projection (future) | RFC-0024; OSCAL v1.1.2 [assessment-plan](https://pages.nist.gov/OSCAL/concepts/layer/assessment/assessment-plan/) model; FedRAMP Rev5 SAP Template | **HAVE** (`core/oscal-ap.ts`) — seeded by CSP, refined by 3PAO | LOOP-A.A2 |
| **A3** | OSCAL Assessment Results (AR / SAR) | ✅ | 3PAO authors; PMO + AO review | OSCAL JSON + XML; FedRAMP SAR `.docx` projection (LOOP-F.F7) | RFC-0024; OSCAL v1.1.2 [assessment-results](https://pages.nist.gov/OSCAL/concepts/layer/assessment/assessment-results/) model; FedRAMP Rev5 SAR Template | **HAVE** for the OSCAL JSON skeleton + chain wiring (`core/oscal.ts`); SAR draft generator MISSING | LOOP-A.A3 (chain), LOOP-F.F7 (SAR draft) |
| **A4** | OSCAL Plan of Action & Milestones (POA&M) | ✅ | 3PAO, PMO, AO; CSP-internal remediation | OSCAL JSON + XML + FedRAMP POA&M `.xlsx` companion | RFC-0024; OSCAL v1.1.2 [plan-of-action-and-milestones](https://pages.nist.gov/OSCAL/concepts/layer/assessment/poam/) model; [FedRAMP-POAM-Template.xlsx](https://www.fedramp.gov/assets/resources/templates/FedRAMP-POAM-Template.xlsx); FedRAMP Rev5 ConMon Strategy | **HAVE** OSCAL emit (`core/oscal-poam.ts`); .xlsx companion **MISSING** | LOOP-A.A1 (OSCAL); LOOP-A.A4 bundler classifies; .xlsx in LOOP-E.E2 follow-up |
| **A5** | Integrated Inventory Workbook (Appendix M / IIW) | ✅ | 3PAO, PMO, AO | `.xlsx` — 25 columns, multi-tab | FedRAMP SSP Appendix M; [FedRAMP-Integrated-Inventory-Workbook-Template.xlsx](https://www.fedramp.gov/assets/resources/templates/FedRAMP-Integrated-Inventory-Workbook-Template.xlsx) | **HAVE** — 24/25 columns auto-filled across AWS+GCP+Azure (`core/inventory-workbook.ts` + INV-S1..S6); column T (Comments) operator-supplied via tag | LOOP-A.A0 (pre-shipped INV-P1..P5 + INV-S1..S6) |
| **A6** | Rules of Engagement (RoE) | ✅ | 3PAO + CSP sign | `.docx`; OSCAL `terms-and-conditions` reference in AP | FedRAMP SAP RoE addendum; cited in FedRAMP Rev5 Playbook → [Authorization → SAP](https://www.fedramp.gov/docs/rev5/playbook/csp/authorization/sap/) | **HAVE** template seed (`core/roe-emit.ts`) | LOOP-A.A5 |
| **A7** | Configuration Management Plan (CMP) | ✅ | 3PAO, PMO, AO | `.docx` | NIST SP 800-53 CM-9; FedRAMP CMP Template; tied to CM-2 / CM-3 / CM-6 | **MISSING** | LOOP-C.C1 |
| **A8** | Information System Contingency Plan (ISCP) + Test AAR | ✅ | 3PAO, PMO, AO | `.docx` × 2 (ISCP + test AAR template) | NIST SP 800-53 CP-2 + CP-4; NIST SP 800-34 Rev1; FedRAMP ISCP Template; FedRAMP CP-4 Test Template | **MISSING** (`core/backup.ts` collectors exist for RPL-* but no CP plan doc) | LOOP-C.C2 |
| **A9** | Incident Response Plan (IRP) + Test AAR | ✅ | 3PAO, PMO, AO; CISA recipient | `.docx` × 2 (IRP + test AAR template) | NIST SP 800-53 IR-8 + IR-3; NIST SP 800-61 Rev2; FedRAMP IRP Template; AFR-ICP family (LOOP-G.G2) | **MISSING** (`core/scn-classifier.ts` exists for SCN side; INR-RIR collector exists; no IR plan doc) | LOOP-C.C3 (+ LOOP-G.G2 for ICP routing) |
| **A10** | Privacy Threshold Analysis (PTA) + Privacy Impact Assessment (PIA) | ⚠️ Conditional — PTA always; PIA when PII processed | 3PAO, PMO, AO; OMB | `.docx` × 2 (PTA always; PIA conditional) | NIST SP 800-53 PT-2 / PT-3 / PT-6; OMB M-03-22; FedRAMP PTA / PIA Templates | **MISSING** | LOOP-C.C4 |
| **A11** | Authorization Boundary Diagram | ✅ | 3PAO, PMO, AO | `.svg` + `.png` + PlantUML source | SSP §9.2; FedRAMP Authorization Boundary Guidance; cited in FedRAMP Rev5 SSP Template | **MISSING** | LOOP-D.D1 |
| **A12** | Network Diagram | ✅ | 3PAO, PMO, AO | `.svg` + `.png` + PlantUML source | SSP §9.3; FedRAMP Rev5 SSP Template; NIST SP 800-53 CA-3 / SC-7 implementation evidence | **MISSING** | LOOP-D.D2 |
| **A13** | Data Flow Diagram (DFD) | ✅ | 3PAO, PMO, AO | `.svg` + `.png` + PlantUML source | SSP §9.4; FedRAMP Rev5 SSP Template; AFR-MAS-CSO-FLO (info flow) | **MISSING** | LOOP-D.D3 (+ feeds LOOP-G.G4 AFR-MAS) |
| **A14** | User Roles & Privileges Matrix | ✅ | 3PAO, PMO, AO | `.xlsx`; OSCAL `system-implementation.users[]` projection | NIST SP 800-53 AC-2 + AC-6; FedRAMP SSP Section 9 (User Roles); 800-53 AC-5 (Separation of Duties) | **PARTIAL** — IAM-AAM + IAM-ELP collectors run on AWS/GCP/Azure; matrix as a deliverable is **MISSING** | LOOP-J.J1 |
| **A15** | Subprocessor / Leveraged-Authorization Inventory | ✅ | 3PAO, PMO, AO | `.xlsx` + `.json`; OSCAL `back-matter.resources[type=service]` projection | NIST SP 800-53 SA-9; FedRAMP Significant Change Form; FedRAMP Authorization Boundary Guidance §subprocessors | **PARTIAL** — `core/subprocessors-sheet.ts` reads Google Sheets today | LOOP-J.J2 |
| **A16** | FIPS 199 categorization worksheet | ✅ | 3PAO, PMO, AO | `.docx`; impact tier captured in SSP `system-information.security-sensitivity-level` | [FIPS PUB 199](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.199.pdf); [NIST SP 800-60 Vol 1 + 2](https://csrc.nist.gov/publications/detail/sp/800-60/vol-1-rev-1/final) | **PARTIAL** — impact tier flows into SSP via `--impact-level` flag; standalone FIPS 199 doc is **MISSING** | LOOP-C.C5 |
| **A17** | Continuous Monitoring Strategy + Plan | ✅ | 3PAO, PMO, AO | `.docx` | NIST SP 800-53 CA-7; NIST SP 800-137; [FedRAMP ConMon Strategy Template](https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/overview/); FedRAMP ConMon Playbook | **MISSING** (cadence is wired in code but the strategy doc is not emitted) | LOOP-C.C6 |
| **A18** | Risk Management Strategy (RMS) | ✅ | 3PAO, PMO, AO | `.docx` | NIST SP 800-53 PM-9; NIST SP 800-39; FedRAMP RMS template | **MISSING** (LOOP-B.B5 risk register feeds this) | LOOP-C.C7 (depends on LOOP-B.B3/B4/B5) |
| **A19** | Penetration Test Report | ✅ | 3PAO authors; PMO + AO review | `.pdf` ingest schema → OSCAL AR linkage | NIST SP 800-53 CA-8; FedRAMP Penetration Test Guidance Rev3 (Aug 2023); SAR Appendix B | **MISSING** ingest path; OSCAL AR can reference once schema lands | LOOP-K.K1 (+ LOOP-K.K2 for test-result objects) |
| **A20** | Signed submission bundle (tarball) | ✅ | PMO / USDA Connect.gov uploader | `.tar.gz` with `INDEX.json` + Ed25519 signature + RFC 3161 timestamp | RFC-0024 OSCAL submission mandate; FedRAMP Rev5 Playbook → [ConMon → Overview](https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/overview/) (USDA Connect.gov repository); [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) | **HAVE** (`core/submission-bundle.ts`, `core/sign.ts`, `core/timestamp.ts`) | LOOP-A.A4 |
| **A21** | Authorization Request / Package Transmittal cover letter | ✅ | PMO + AO | `.docx` | FedRAMP Authorization Playbook; FedRAMP Rev5 → Authorization Package Submission | **MISSING** | LOOP-C.C8 |
| **A22** | Baseline Configuration document (CM-2) | ✅ | 3PAO, PMO, AO | `.docx`; PlantUML reference architecture diagram | NIST SP 800-53 CM-2; FedRAMP Rev5 SSP §10; reference architecture (`providers/*/reference-arch.ts`) | **PARTIAL** — reference-arch.ts emits per-provider JSON today; standalone CM-2 baseline-config doc is **MISSING** | LOOP-C.C9 |

**Summary**: 11 HAVE (A1, A2, A3 skeleton, A4 OSCAL, A5, A6, A20), 5
PARTIAL (A3 SAR draft, A14, A15, A16, A22), 10 MISSING (A7, A8, A9,
A10, A11, A12, A13, A17, A18, A19, A21). LOOP-A complete; LOOP-C is the
highest-volume remaining loop for this section.

---

## 3. Per-artifact detail

### A1 — OSCAL System Security Plan (SSP)

**Source citation**: [RFC-0024 "OSCAL Submission Standard"](https://www.fedramp.gov/rfcs/0024/) mandates OSCAL JSON for 20x submissions. Schema:
[OSCAL v1.1.2 system-security-plan](https://pages.nist.gov/OSCAL/concepts/layer/implementation/ssp/),
committed at `cloud-evidence/docs/oscal/oscal_ssp_schema.v1.1.2.json`.
Word projection follows the [FedRAMP Rev5 SSP Template](https://www.fedramp.gov/assets/resources/templates/) (the canonical author-time format) so a 3PAO can still read it in `.docx` form during transition.

**CSP delivers**: complete SSP with implemented-requirements per FedRAMP
baseline + system-characteristics + system-implementation +
back-matter.resources[]. Authorization-boundary description and
`system-implementation.users[]` are operator-supplied via
`SspEmitOptions.authorizationBoundaryDescription` and
`SspEmitOptions.userRoles[]`; otherwise emit
`REQUIRES-OPERATOR-INPUT:` per REO Rule 4.

**FedRAMP / 3PAO authors**: nothing. SSP is the CSP's deliverable; the
3PAO assesses against it via the SAP / AR chain.

**Cross-references**: feeds A2 (AP `import-ssp`), A3 (AR transitively
via AP), A4 (POA&M `import-ssp` + `system-id`), A11/A12/A13 (diagrams
embed in `back-matter.resources[]`), A14 (User Roles matrix overlays
SSP §9), A16 (FIPS 199 impact tier appears in
`system-information.security-sensitivity-level`).

---

### A2 — OSCAL Assessment Plan (SAP / AP)

**Source citation**: [OSCAL v1.1.2 assessment-plan](https://pages.nist.gov/OSCAL/concepts/layer/assessment/assessment-plan/);
[FedRAMP Rev5 SAP Playbook](https://www.fedramp.gov/docs/rev5/playbook/csp/authorization/sap/) ("the methodology must be included as an appendix to the SAP").

**CSP delivers**: a **seeded** AP — the OSCAL document with `import-ssp`,
`reviewed-controls` enumerated against the FedRAMP baseline at the
declared impact tier, `local-definitions.activities[]` (one per KSI),
default `tasks[]` (4-phase plan: Scoping → Discovery → Testing →
Reporting), and `assessment-subjects[]` derived from real `inventory.json`.

**3PAO authors**: refines the AP. Adds `terms-and-conditions` (RoE +
Sampling Methodology references — A6, F.F3), adjusts task dates,
populates `assessment-assets`, signs in the tracker (LOOP-F.F1).

**Cross-references**: A1 (`import-ssp`), A6 (RoE referenced in
`terms-and-conditions`), F.F3 (Sampling Methodology in Appendix B),
A3 (AR `import-ap` resolves to this — see LOOP-A.A3 chain wiring).

---

### A3 — OSCAL Assessment Results (AR / SAR)

**Source citation**: [OSCAL v1.1.2 assessment-results](https://pages.nist.gov/OSCAL/concepts/layer/assessment/assessment-results/);
FedRAMP Rev5 SAR Template (Word).

**CSP delivers**: the AR skeleton + `import-ap` linkage + per-KSI
observations + findings rolled up from the evidence envelopes. The CSP
does NOT author the SAR narrative; the AR JSON is the machine-readable
substrate.

**3PAO authors**: the SAR narrative — Executive Summary, Methodology
Recap, per-control findings determination statements, recommendation
language. The SAR draft generator (LOOP-F.F7) turns the AR + tracker
sign-offs (LOOP-F.F1) + comments (LOOP-F.F2) into a Word draft for the
3PAO to finalize and sign.

**Cross-references**: A2 (`import-ap`), A4 (POA&M items derive from
AR.findings with status=open), A19 (PenTest report findings flow in via
LOOP-K.K1), F.F1 (sign-offs), F.F7 (draft generator).

---

### A4 — OSCAL Plan of Action & Milestones (POA&M)

**Source citation**: [OSCAL v1.1.2 plan-of-action-and-milestones](https://pages.nist.gov/OSCAL/concepts/layer/assessment/poam/);
[FedRAMP-POAM-Template.xlsx](https://www.fedramp.gov/assets/resources/templates/FedRAMP-POAM-Template.xlsx);
remediation deadline math per FedRAMP Rev5 baseline (Critical 30d / High
60d / Medium 90d / Low 180d) and FedRAMP CMP severity-to-deadline
table.

**CSP delivers**: complete POA&M with `import-ssp` + `system-id`,
deterministic UUIDs, per-finding `poam-item` + `observation` + `risk`,
FedRAMP-baseline deadlines (LOOP-A.A1), and — once LOOP-B lands — CVSS
+ EPSS + criticality + exposure composite risk scores (LOOP-B.B1) +
KEV-aware deadlines (LOOP-B.B2). The `.xlsx` companion (per R2 finding)
is a planned LOOP-E.E2 follow-up so CSPs that prefer the Excel format
for USDA Connect.gov upload have a real artifact alongside the OSCAL
JSON.

**3PAO authors**: nothing directly; the 3PAO reviews and the AR
findings flow into the POA&M on the CSP side.

**Cross-references**: A3 (findings from AR), A17 (cadence governed by
ConMon Strategy), A18 (RMS describes acceptance policy), LOOP-B.B3
(risk acceptance writes `risk.status = 'deviation-approved'`),
LOOP-B.B4 (compensating controls embed in `risk.mitigating-factors[]`).

---

### A5 — Integrated Inventory Workbook (Appendix M / IIW)

**Source citation**: SSP Appendix M (FedRAMP Rev5 SSP Template);
[FedRAMP-Integrated-Inventory-Workbook-Template.xlsx](https://www.fedramp.gov/assets/resources/templates/FedRAMP-Integrated-Inventory-Workbook-Template.xlsx)
25-column schema; verbatim column ordering enforced via the Coverage
Contract registry (`core/inventory-coverage.ts` — INV-S1).

**CSP delivers**: the workbook auto-generated from real cloud SDK
discovery (AWS + GCP + Azure). Per INV-S1..S6, 24 of 25 columns are
filled across all three clouds; column T (Comments) stays
operator-supplied via the `inventory_comments` / `fedramp_comments` /
`comments` cloud-resource tag with a documented override path.

**3PAO authors**: nothing. The 3PAO consumes the workbook as evidence;
challenges/asks are raised via comment threads (LOOP-F.F2).

**Cross-references**: A1 (SSP Appendix M), A6 (RoE IP ranges
auto-derived from `out/inventory.json`), A11/A12/A13 (diagrams use
`inventory.json` as the topology source), G.G4 (AFR-MAS information-
resource inventory reuses), J.J1 (User Roles matrix joins).

---

### A6 — Rules of Engagement (RoE)

**Source citation**: [FedRAMP Rev5 SAP Playbook](https://www.fedramp.gov/docs/rev5/playbook/csp/authorization/sap/)
("the CSP and 3PAO must sign the SAP, which indicates acknowledgement
of and agreement with the SAP and rules of engagement").

**CSP delivers**: a seeded `.docx` template prefilled from real
`inventory.json` (IP ranges, controls-in-scope KSI list) plus
operator-supplied scan-windows + escalation contacts. The 3PAO refines
and both parties sign.

**3PAO authors**: completes the document, signs. The CSP counter-signs.

**Cross-references**: A2 (AP `terms-and-conditions`), A5 (IP ranges
derive from inventory), F.F1 (signature flow), F.F4 (evidence-walk-
through references RoE constraints).

---

### A7 — Configuration Management Plan (CMP)

**Source citation**: [NIST SP 800-53 Rev5 CM-9](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home);
FedRAMP CMP Template (legacy `.docx`).

**CSP delivers**: documented process covering approval workflow,
roll-back authority, change windows, baseline-config reference,
deviation handling, automated change detection (ties to LOOP-E.E6 SCN
classifier).

**3PAO authors**: nothing; assesses CM-2 / CM-3 / CM-6 / CM-9 against
this plan.

**Cross-references**: A22 (CM-2 baseline-config), A4 (POA&M cadence
for unauthorized-change findings), A17 (ConMon includes config
monitoring).

---

### A8 — Information System Contingency Plan (ISCP) + Test AAR

**Source citation**: [NIST SP 800-53 Rev5 CP-2 + CP-4](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home);
[NIST SP 800-34 Rev1](https://csrc.nist.gov/publications/detail/sp/800-34/rev-1/final);
FedRAMP ISCP Template + CP-4 Test Plan Template.

**CSP delivers**: ISCP `.docx` (RTO/RPO commitments, contingency
activation authority, alternate site details, recovery procedures) +
annual CP-4 test plan + post-test AAR template.

**3PAO authors**: nothing for the plan; assesses CP-2 / CP-4 against
the plan and the annual test results.

**Cross-references**: RPL-ABO / RPL-TRC / RPL-RRO / RPL-ARP collector
output (existing `providers/*/backup.ts`) provides the real backup
configuration evidence that auto-fills RTO/RPO sections; LOOP-E.E7
runs the annual test cadence.

---

### A9 — Incident Response Plan (IRP) + Test AAR

**Source citation**: [NIST SP 800-53 Rev5 IR-8 + IR-3](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home);
[NIST SP 800-61 Rev2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final);
FedRAMP IRP Template.

**CSP delivers**: IRP `.docx` (IR team roster, escalation matrix,
communication plan, IR phases per 800-61) + annual IR-3 test plan +
post-test AAR template.

**3PAO authors**: nothing for the plan; assesses IR-3 / IR-4 / IR-8
against the plan and annual test results.

**Cross-references**: AFR-ICP family (LOOP-G.G2) defines the FedRAMP-
specific reporting routing (FedRAMP, CISA, agency); INR-RIR collector
(`providers/*/logging.ts`) provides past-incident review evidence;
LOOP-E.E7 runs the annual test cadence.

---

### A10 — Privacy Threshold Analysis (PTA) + Privacy Impact Assessment (PIA)

**Source citation**: [NIST SP 800-53 Rev5 PT-2 / PT-3 / PT-6](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home);
[OMB M-03-22](https://www.whitehouse.gov/wp-content/uploads/legacy_drupal_files/omb/memoranda/2003/m03-22.pdf);
FedRAMP PTA + PIA Templates.

**CSP delivers**: PTA always; PIA when the PTA determination is "PII
processed". The conditional emit is auto-detected from
`inventory.json` PII-likely tags (data-classification metadata) and
operator-supplied PII inventory.

**3PAO authors**: nothing; PMO + OMB reviewers consume.

**Cross-references**: A1 (SSP references the privacy posture), A5
(inventory feeds the PII detection), A13 (DFD highlights PII flows).

---

### A11 — Authorization Boundary Diagram

**Source citation**: FedRAMP Rev5 SSP Template §9.2; FedRAMP
Authorization Boundary Guidance (Rev3).

**CSP delivers**: a rendered diagram showing which assets are in-
boundary vs out-of-boundary, peering relationships, shared-services
connections. Auto-generated from `inventory.json` + boundary tags
(`fedramp_boundary=in|out`).

**3PAO authors**: nothing; consumes for scope validation.

**Cross-references**: A1 (embedded in SSP back-matter), A5 (inventory
source), A12 + A13 (related diagrams), A15 (subprocessors appear at
boundary).

---

### A12 — Network Diagram

**Source citation**: FedRAMP Rev5 SSP Template §9.3; implementation
evidence for NIST SP 800-53 CA-3 + SC-7.

**CSP delivers**: VPC/VNet topology from real inventory (subnet, route
table, peering). Firewall rules summarized at the edge. Multi-cloud
aware.

**3PAO authors**: nothing.

**Cross-references**: A1 (SSP §9.3), A5 (inventory source), A11.

---

### A13 — Data Flow Diagram (DFD)

**Source citation**: FedRAMP Rev5 SSP Template §9.4; AFR-MAS-CSO-FLO
(Information Flows and Security Objectives) — see
`docs/AFR-FAMILY-CLASSIFICATION.md` §MAS family.

**CSP delivers**: asset-to-asset edges from existing relationship data
(RDS → EC2, S3 → Lambda, etc.) + data-classification overlay (PII /
CUI / Public).

**3PAO authors**: nothing.

**Cross-references**: A1 (SSP §9.4), G.G4 (AFR-MAS-CSO-FLO reuses
this generator), A10 (PII flows are derived from the DFD).

---

### A14 — User Roles & Privileges Matrix

**Source citation**: NIST SP 800-53 Rev5 AC-2 + AC-5 + AC-6;
FedRAMP SSP Section 9 (User Roles).

**CSP delivers**: a roles × privileges matrix (`.xlsx`) that ties
each role to the controls it touches (AC-2 / AC-3 / AC-5 / AC-6).
Auto-aggregated from existing IAM evidence (IAM-AAM + IAM-ELP
collectors on AWS, GCP, Azure). Operator-supplied business
justification per role.

**3PAO authors**: nothing; assesses AC family against the matrix.

**Cross-references**: A1 (SSP `system-implementation.users[]`
projection), A15 (subprocessor roles), B.B3 (risk-acceptance RBAC
flows through the same role taxonomy).

---

### A15 — Subprocessor / Leveraged-Authorization Inventory

**Source citation**: NIST SP 800-53 Rev5 SA-9; FedRAMP Significant
Change Form §subprocessors; FedRAMP Authorization Boundary
Guidance Rev3 §subprocessors.

**CSP delivers**: enumerated subprocessor list with risk-tier
classification, data-handling scope, contractual basis, SLA, audit
frequency.

**3PAO authors**: nothing; assesses SA-9 + SA-12 against this list.

**Cross-references**: A1 (referenced from SSP), A11 (subprocessors at
boundary), J.J3 (supply chain risk register reuses), G.G4 (AFR-MAS-CSO-TPR
third-party information resources).

---

### A16 — FIPS 199 categorization worksheet

**Source citation**: [FIPS PUB 199](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.199.pdf);
[NIST SP 800-60 Vol 1 Rev 1](https://csrc.nist.gov/publications/detail/sp/800-60/vol-1-rev-1/final) +
[Vol 2 Rev 1](https://csrc.nist.gov/publications/detail/sp/800-60/vol-2-rev-1/final).

**CSP delivers**: per-information-type C/I/A impact determination
mapped to SP 800-60 information types, rolled up to the overall system
impact category.

**3PAO authors**: nothing; AO uses this to validate that the
authorization tier (Low / Moderate / High) matches the data.

**Cross-references**: A1 (SSP `system-information.security-sensitivity-level`),
A4 (POA&M deadline math is tier-aware via the FedRAMP baseline), A10
(PIA leverages C-tier determination).

---

### A17 — Continuous Monitoring Strategy + Plan

**Source citation**: [NIST SP 800-53 Rev5 CA-7](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home);
[NIST SP 800-137](https://csrc.nist.gov/publications/detail/sp/800-137/final);
[FedRAMP Rev5 ConMon Strategy](https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/overview/);
FedRAMP ConMon Playbook.

**CSP delivers**: ConMon Strategy `.docx` (monitoring scope, frequencies,
metrics, escalation thresholds, deviation request process, AO
reporting). Operator-supplied team roster + escalation thresholds;
auto-filled from ksi-map (controls monitored) + scan cadence + POA&M
cadence (monthly per R2).

**3PAO authors**: nothing; assesses CA-7 against the strategy.

**Cross-references**: A4 (POA&M cadence governed here), A18 (RMS
references ConMon strategy), LOOP-E (entire ConMon agent).

---

### A18 — Risk Management Strategy (RMS)

**Source citation**: [NIST SP 800-53 Rev5 PM-9](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home);
[NIST SP 800-39](https://csrc.nist.gov/publications/detail/sp/800-39/final);
FedRAMP RMS Template.

**CSP delivers**: organizational risk tolerance statement, governance
roles, risk acceptance authority, methodology for scoring + accepting
+ mitigating risk. Auto-fills from LOOP-B.B5 risk register + B.B4
compensating-controls registry + B.B3 acceptance policy.

**3PAO authors**: nothing; assesses PM-9 + RA-3 against the strategy.

**Cross-references**: A4 (POA&M acceptance flows through RMS), B.B3
(acceptance workflow), B.B4 (compensating controls), B.B5 (risk
register).

---

### A19 — Penetration Test Report

**Source citation**: [NIST SP 800-53 Rev5 CA-8](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home);
[FedRAMP Penetration Test Guidance v3.0](https://www.fedramp.gov/assets/resources/documents/CSP_Penetration_Test_Guidance.pdf)
(Aug 2023); SAR Appendix B (PenTest Findings).

**CSP delivers**: nothing for the report itself (3PAO-authored). The
CSP delivers (a) the boundary + scope + RoE (A6) and (b) the assets in
scope (A5) so the 3PAO can plan and execute the test.

**3PAO authors**: full PenTest Report `.pdf` with findings. Per LOOP-K.K1,
the findings are ingested via a defined schema into the AR + POA&M.

**Cross-references**: A3 (AR.findings receive PenTest findings), A4
(POA&M items created from CA-8 findings), A6 (RoE constrains scope).

---

### A20 — Signed submission bundle (tarball)

**Source citation**: [RFC-0024 OSCAL Submission Standard](https://www.fedramp.gov/rfcs/0024/);
[FedRAMP Rev5 Playbook → ConMon Overview](https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/overview/)
("CSPs with cloud offerings categorized at LI-SaaS, Low, or Moderate
use the FedRAMP secure repository on USDA Connect.gov"); [RFC 3161
Time-Stamp Protocol](https://www.rfc-editor.org/rfc/rfc3161);
Ed25519 signature ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)).

**CSP delivers**: one `.tar.gz` containing every required artifact
(A1–A19, A21, A22) + the Ed25519-signed manifest + the RFC 3161
timestamp + `INDEX.json` at the top of the archive enumerating each
artifact with sha256 + role + in-manifest flag + chain integrity
verdict. `package_format_version: "20x.phase-two.preview.2026"` per
R3 findings.

**3PAO authors**: nothing; uploads the bundle to USDA Connect.gov on
behalf of (or alongside) the CSP.

**Cross-references**: A1–A19 (every package artifact bundled), A21
(transmittal letter bundled), strict-bundle mode validates the OSCAL
chain integrity SSP → AP → AR → POA&M.

---

### A21 — Authorization Request / Package Transmittal cover letter

**Source citation**: FedRAMP Authorization Playbook (cover-letter
template); FedRAMP Rev5 → Authorization Package Submission.

**CSP delivers**: a cover letter naming the system, impact level,
3PAO, CSP point-of-contact, summary of submission contents (read from
`INDEX.json` per A20).

**3PAO authors**: countersigns.

**Cross-references**: A20 (bundled), A1 (system identity), A2
(assessment period).

---

### A22 — Baseline Configuration document (CM-2)

**Source citation**: [NIST SP 800-53 Rev5 CM-2](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home);
FedRAMP Rev5 SSP §10 (Baseline Configuration); ties into AFR-SCG
(`docs/AFR-FAMILY-CLASSIFICATION.md` §SCG family).

**CSP delivers**: baseline configuration document — the reference
architecture, the build/deploy provenance, the hardened-image
inventory, the deviation log location. Existing
`providers/*/reference-arch.ts` emits per-provider JSON; LOOP-C.C9
turns it into a full CM-2 `.docx` with FedRAMP-Moderate baseline
defaults.

**3PAO authors**: nothing; assesses CM-2 against the baseline.

**Cross-references**: A1 (referenced from SSP §10), A7 (CMP governs
changes), G.G5 (AFR-SCG Secure Configuration Guide extends this).

---

## 4. Acceptance criteria for SECTION A

SECTION A is considered complete when **every required artifact
(A1–A19, A21, A22) emits end-to-end from real evidence in a single
orchestrator run, the result is bundled into A20, and the bundle
passes strict-chain + strict-bundle + strict-schema validation**.
Concretely, all of the following must be true:

1. **A1 OSCAL SSP** ✅ — emits valid OSCAL v1.1.2 JSON + XML +
   FedRAMP `.docx` projection; ajv-validated; `REQUIRES-OPERATOR-INPUT`
   markers absent OR named in the `requires_operator_input[]` list of
   the run summary.
2. **A2 OSCAL AP** ✅ — emits valid OSCAL v1.1.2 JSON + XML; ajv-validated;
   `import-ssp` resolves to A1.
3. **A3 OSCAL AR** ✅ — emits valid OSCAL v1.1.2 JSON + XML; ajv-validated;
   `import-ap` resolves to A2 (`ap_link === 'local-ap'` per
   LOOP-A.A3 result). SAR draft generator ships from LOOP-F.F7.
4. **A4 OSCAL POA&M** ✅ — emits valid OSCAL v1.1.2 JSON + XML; ajv-validated;
   `import-ssp` + `system-id` both populated; LOOP-B.B1/B2 risk scores +
   deadlines populated on every `risk` (or `REQUIRES-OPERATOR-INPUT`
   tracked when CVSS missing). `.xlsx` companion emits from LOOP-E.E2.
5. **A5 IIW** ✅ — emits valid `.xlsx`; per-run
   `inventory-coverage.json` shows ≥95% fill across all three clouds
   for columns A–S; column T blank-or-tag-driven per design; G2 coverage
   regression guardrail green.
6. **A6 RoE** ✅ — emits seeded `.docx`; `ready_for_signature` is true
   when operator-supplied fields are populated, else lists exactly
   what is missing.
7. **A7 CMP** ✅ — LOOP-C.C1 ships; emits `.docx`; CM-9 process is
   documented end-to-end.
8. **A8 ISCP + Test AAR** ✅ — LOOP-C.C2 ships; auto-fills from
   RPL-* collector evidence.
9. **A9 IRP + Test AAR** ✅ — LOOP-C.C3 ships; auto-fills from INR-RIR.
10. **A10 PTA / PIA** ✅ — LOOP-C.C4 ships; PTA always emitted; PIA
    emitted when inventory tags indicate PII processing.
11. **A11 Authorization Boundary Diagram** ✅ — LOOP-D.D1 ships;
    emits PlantUML + SVG + PNG from `inventory.json` boundary tags.
12. **A12 Network Diagram** ✅ — LOOP-D.D2 ships.
13. **A13 DFD** ✅ — LOOP-D.D3 ships; AFR-MAS-CSO-FLO (G.G4) consumes.
14. **A14 User Roles matrix** ✅ — LOOP-J.J1 ships; emits `.xlsx`.
15. **A15 Subprocessor inventory** ✅ — LOOP-J.J2 ships beyond the
    Google Sheets reader; emits YAML/JSON config + per-CSO list.
16. **A16 FIPS 199 worksheet** ✅ — LOOP-C.C5 ships.
17. **A17 ConMon Strategy** ✅ — LOOP-C.C6 ships.
18. **A18 RMS** ✅ — LOOP-C.C7 ships; depends on LOOP-B.B3/B4/B5.
19. **A19 PenTest Report ingest** ✅ — LOOP-K.K1 ships; AR + POA&M
    accept ingested PenTest findings.
20. **A20 Signed bundle** ✅ — `core/submission-bundle.ts`
    `--strict-bundle` mode passes against the full A1–A19, A21, A22
    set; chain integrity check returns `complete` (no synthetic
    `import-ap`); zero gaps in `INDEX.json.gaps[]`.
21. **A21 Cover letter** ✅ — LOOP-C.C8 ships; reads `INDEX.json` for
    package contents summary.
22. **A22 Baseline Configuration doc** ✅ — LOOP-C.C9 ships; emits CM-2
    `.docx` from reference-arch.ts JSON.

**Cross-cutting (REO compliance per `cloud-evidence/CLAUDE.md`)**:

- `npm run lint:no-stubs` (G1) returns 0 against the production tree.
- `npm run check:provenance` (G3) returns 0 — every emit-field has a
  provenance record.
- `npm run check:coverage-regression` (G2) returns 0 — IIW fill rate
  has not regressed vs the published baseline.
- `npm test` passes 100% — at minimum the existing 874 plus tests
  added by LOOP-B / C / D / J / K slices.

**Operator-input traceability**:

- Every `REQUIRES-OPERATOR-INPUT:` marker emitted across A1–A22 is
  collected into the run summary's `requires_operator_input[]` list
  with the field name + the flag / config / tracker route that
  resolves it. No silent defaults per REO Rule 4.

---

## 5. Open questions

1. **POA&M wire format final (R2 caveat)** — Excel-only vs OSCAL-only
   vs both. LOOP-A.A1 ships OSCAL JSON + XML today. The `.xlsx`
   companion (FedRAMP-POAM-Template.xlsx schema) is planned for
   LOOP-E.E2 follow-up. If FedRAMP publishes definitive post-pilot
   guidance that only one wire format is accepted, the unused emitter
   can be removed; we ship both for safety.
2. **Phase Two pilot post-retrospective format (R3 caveat)** — no
   post-pilot guidance has landed on fedramp.gov/blog or
   fedramp.gov/rfcs as of 2026-06-05. LOOP-A.A4 emits
   `package_format_version: "20x.phase-two.preview.2026"` so a future
   format shift produces a clean version bump rather than silently
   changing the bundle structure. **Re-check fedramp.gov/blog
   quarterly.**
3. **Sampling statistical confidence (R4 caveat)** — FedRAMP doesn't
   specify thresholds. LOOP-F.F3 will default to "stratified by asset
   class + region, min 10% per class, externally-accessible 100%,
   operator-overrideable with AO sign-off". If FedRAMP publishes
   numeric thresholds (e.g. 95% confidence at ±5% margin), the
   defaults shift.
4. **PIA conditional trigger** — Section A.10 emits PIA when
   "PII-likely tags" are detected. The detection logic depends on
   operator-supplied `data_classification` tags; if those tags are
   absent, the system emits PTA only with a determination of "no PII
   tagged inventory found — operator must confirm PIA-not-required".
   The PMO's tolerance for tag-driven PIA conditionality is not
   formally documented; we may need explicit operator opt-in via
   `--privacy-determination` flag rather than tag-driven default.
5. **A21 cover letter routing** — the Authorization Request transmittal
   recipient is the FedRAMP PMO inbox + the AO. The FSI inbox (AFR-FSI
   family, G.G1) is the receiving channel for FedRAMP → CSP messages,
   but the outgoing channel (CSP → PMO) is not formally tied to FSI.
   We assume `out/submission-bundle.tar.gz` is uploaded to USDA
   Connect.gov via portal + the cover letter is emailed; if the PMO
   publishes a single-channel API, A21 + A20 transmission consolidate.
6. **Diagrams as `.docx` vs standalone** — A11/A12/A13 ship as
   PlantUML + SVG + PNG today (LOOP-D). The historical FedRAMP SSP
   embeds these inline in the `.docx`. The SSP-2 renderer
   (`core/ssp-docx.ts`) does not yet embed images; LOOP-D may need
   a follow-up slice to wire the rendered diagrams into the SSP `.docx`
   projection rather than leaving them as standalone artifacts in
   the bundle.
7. **A22 vs G.G5 overlap** — A22 (Baseline Configuration / CM-2) and
   G.G5 (AFR-SCG / Secure Configuration Guide) emit overlapping
   content. A22 is the CSP-internal CM-2 deliverable; G.G5 is the
   FedRAMP 20x AFR-SCG deliverable. We will likely consolidate into
   a single emitter with two projections; the boundary needs to be
   nailed before LOOP-C.C9 and LOOP-G.G5 both start.
8. **Penetration Test Report ingest schema (A19 / K.K1)** — no
   public OSCAL extension exists for PenTest findings ingest. We
   will define our own ingest schema with traceability into
   `assessment-results.findings[].target` and document it as
   `cloud-evidence/docs/oscal/oscal_pentest_ingest.schema.v1.json`.
   If FedRAMP / NIST publish an official ingest schema before
   LOOP-K.K1 ships, we adopt theirs.
