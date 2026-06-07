# Additional Loops + Slices Audit

> Result of a thorough audit against FedRAMP Rev5 + NIST 800-53 Rev5 +
> FedRAMP 20x RFC corpus + adjacent NIST publications to surface
> artifacts and capabilities that may need their own loops/slices but
> were not enumerated in the original LOOP-A through LOOP-K roadmap
> (49 slices total — LOOP-A complete, B–K pending). All findings are
> grounded in cited public source obligations and cross-referenced
> against the existing `cloud-evidence/docs/` corpus (EXECUTION-PLAN,
> SECTION-A through SECTION-F, AFR-FAMILY-CLASSIFICATION,
> PRE-LOOP-A-RESEARCH-FINDINGS, CLAUDE.md REO standard).
>
> **Scope of this audit:** Phase Two Moderate at GA — i.e. the
> authorization-tier the existing roadmap targets. High and DoD IL5+
> items are flagged under §4 as out-of-scope, with a documented
> re-visit trigger.

## Status update (2026-06-07)

**LOOP-L through LOOP-Q have been fully specified per the human's
decision.** M (Privacy/SORN/DPIA) and O (AI/ML Governance) are
**confirmed-applicable** (no longer conditional on operator decisions).
The six conditional questions in §5 are resolved: all six loops are
adopted and queued behind LOOP-B.B1. See:

- `docs/loops/LOOP-L-SPEC.md` (4 slices) + `docs/slices/L/*.md`
- `docs/loops/LOOP-M-SPEC.md` (4 slices) + `docs/slices/M/*.md`
- `docs/loops/LOOP-N-SPEC.md` (4 slices) + `docs/slices/N/*.md`
- `docs/loops/LOOP-O-SPEC.md` (5 slices) + `docs/slices/O/*.md`
- `docs/loops/LOOP-P-SPEC.md` (5 slices) + `docs/slices/P/*.md`
- `docs/loops/LOOP-Q-SPEC.md` (3 slices) + `docs/slices/Q/*.md`
- `docs/loops/LOOP-{L,M,N,O,P,Q}-RISKS.md` (6 per-loop risks registers)

A second-pass audit (`docs/SECOND-PASS-AUDIT.md`) was run AFTER L-Q
specification to find anything **still missing** after the L-Q layer.
Read it alongside this file when assessing roadmap completeness.

The §3 single-slice extensions (12 items) remain as scoped — they
have not been promoted to standalone loops; they are absorbed into
their parent slices' implementation plans where applicable.

---

## 1. Methodology

### 1.1 Sources consulted (primary)

1. **FedRAMP Rev5 Playbook** — `https://www.fedramp.gov/docs/rev5/playbook/`
   read end-to-end via the SECTION-A/B/C citations already committed to
   this repo + the search results enumerated under §6 references.
2. **NIST SP 800-53 Rev5** + **SP 800-53B Rev5** (control catalog +
   baselines).
3. **OSCAL v1.1.2** model set (SSP / AP / AR / POA&M / Component
   Definition / Catalog / Profile).
4. **FRMR machine-readable catalog v0.9.43-beta** —
   `github.com/FedRAMP/docs` — direct walk per R1
   (`docs/AFR-FAMILY-CLASSIFICATION.md`).
5. **RFCs**:
   - RFC-0004 (Boundary Policy)
   - RFC-0006 (AFR catalog)
   - RFC-0014 (Phase-Two automated/opinionated KSI validation)
   - RFC-0021 (Marketplace expansion)
   - RFC-0024 (OSCAL submission mandate)
   - RFC-0028, RFC-0029, RFC-0030 (Rev5 baseline updates by control
     family — CP/IA/IR/MA/MP, PE/PL/PM/PS/PT, RA/SA/SC/SI/SR)
6. **CISA Binding Operational Directives**:
   - BOD 20-01 (Vulnerability Disclosure Policy)
   - BOD 22-01 (Known Exploited Vulnerabilities)
   - BOD 23-01 (Asset Visibility / RA-5 cadence reduction)
7. **NIST AI RMF 1.0** (NIST AI 100-1) + OMB **M-24-10** (advancing the
   responsible acquisition + use of AI) + **M-25-21** (AI evaluation in
   federal procurement).
8. **OMB M-03-22** (Privacy provisions of E-Government Act §208).
9. **NIST SP 800-39** (Risk Management — organizational).
10. **NIST SP 800-160 Vol 1 + Vol 2** (Systems Security Engineering;
    Developing Cyber-Resilient Systems).
11. **NIST SP 800-161 Rev1 Update 1** (C-SCRM — Supply Chain Risk
    Management).
12. **NIST SP 800-37 Rev2** (RMF) Steps 4 + 7.
13. **NIST SP 800-30 Rev1** (Risk Assessment).
14. **NIST SP 800-137** (ISCM).
15. **NIST SP 800-61 Rev2** (Computer Security Incident Handling).
16. **NIST SP 800-184** (Cyber Event Recovery).
17. **NIST SP 800-218** (SSDF — Secure Software Development Framework).
18. **NIST Cybersecurity Framework v2.0** (CSF v2.0, Feb 2024).
19. **NISPOM 32 CFR Part 117** (Insider-Threat program obligations).
20. **CMVP FIPS 140-3 Management Manual** + **SSP Appendix Q**
    (Cryptographic Modules Table).
21. **FedRAMP CIS/CRM Workbook template** (SSP Appendix J — Control
    Implementation Summary / Customer Responsibility Matrix).

### 1.2 Cross-referencing approach

For every candidate item:
1. Trace it to an explicit FedRAMP Rev5 baseline parameter, NIST
   control text, or 20x RFC obligation.
2. Confirm it is **Moderate-applicable** (not High-only). If it is
   High-only or IL5+, route to §4 (out-of-scope).
3. Check the existing `EXECUTION-PLAN.md` slice catalogue (49 slices
   across LOOP-A–K) for direct coverage.
4. Check the SECTION-A through SECTION-F per-artifact tables for
   indirect coverage (often a future slice covers an obligation under
   a different name, e.g. "AU-11 retention" rolled into LOOP-H.H2
   rather than its own loop).
5. If neither covers the item, decide between:
   - **§2 New loop** (large enough scope that a new LOOP-L/M/N is
     warranted)
   - **§3 Fold into existing slice** (single extension to an existing
     LOOP-X.Xn rather than new loop overhead).

### 1.3 What I deliberately did NOT do

- I did **not** restate items already covered explicitly in EXECUTION-PLAN.
  Items like CRM (already implicit in LOOP-C SSP appendix work? No —
  see §2 LOOP-L) get flagged only if genuinely uncovered.
- I did **not** propose net-new artifacts that have no source
  obligation. Every new loop/slice in §2 cites a real published
  obligation.
- I did **not** rescope existing loops. Where coverage exists but is
  incomplete, the recommendation is to extend the existing slice (§3),
  not split the loop.

---

## 2. Definitely missing — recommend adding to roadmap

Six new loops surfaced that warrant first-class roadmap placement. They
are LOOP-L (CRM + Inheritance), LOOP-M (Privacy package extension),
LOOP-N (Threat modeling + adversarial validation), LOOP-O (AI/ML
governance), LOOP-P (Insider-threat + Workforce Security), LOOP-Q
(Marketplace + post-ATO publication).

### LOOP-L — Customer Responsibility Matrix (CRM) + Leveraged Authorization Inheritance

**Why this is a separate loop:**
The existing roadmap covers the SSP (LOOP-A.A0, SSP-1/SSP-2),
subprocessor inventory (LOOP-J.J2), and AFR-MAS-CSO-TPR
(LOOP-G.G4 third-party resource enumeration). It does **not** ship the
two artifacts that bridge "what the CSP does" to "what the customer
must do" — the **Control Implementation Summary (CIS) / Customer
Responsibility Matrix (CRM)** workbook (SSP Appendix J) and the
**Leveraged-Authorization Inheritance Document** that names every
control the CSO inherits from an underlying FedRAMP-Authorized IaaS/PaaS
(e.g. AWS GovCloud, GCP Assured Workloads, Azure Government).

**Source obligation (verbatim):**

FedRAMP CSP Authorization Playbook + SSP Appendix J:
> "CSPs are required to submit a Control Implementation
> Summary/Customer Responsibility Matrix (CIS/CRM) workbook as
> Appendix J to the System Security Plan (SSP). The CIS/CRM workbook
> identifies security controls that the CSP is responsible for
> implementing, security controls that the customer is responsible for
> implementing, security controls where there is a shared CSP/customer
> responsibility, and security controls that are inherited from an
> underlying FedRAMP Authorized Infrastructure-as-a-Service (IaaS) or
> Platform-as-a-Service (PaaS)."

FedRAMP "Important Considerations" (rev5):
> "Control authors should clearly indicate which portions of the
> security control are inherited and provide a description of what is
> inherited."

NIST SP 800-53 Rev5 §2.5 (Inheritance + Compensating Controls).

OSCAL v1.1.2 `system-security-plan` model:
`control-implementation.implemented-requirements[].by-components[].responsible-roles[]`
+ `inherited-controls` extension via the OSCAL Component Definition
model.

**Slices:**

- **L.L1 — CIS / CRM workbook emitter (SSP Appendix J)**
  - New `core/cis-crm-emit.ts`. Emits `.xlsx` workbook with five
    columns per control (CSP / Customer / Shared / Inherited /
    Not-Applicable) keyed by NIST 800-53 control id; matrix derives
    from a committed `config/responsibility-matrix.yaml` per CSO that
    operator authors (REQUIRES-OPERATOR-INPUT for any unmapped
    Moderate-baseline control).
  - Tests: ~14 — column completeness against 287-control Moderate
    baseline, responsibility-bucket exclusivity, ajv against the
    FedRAMP-published CIS/CRM template field schema, inheritance
    consistency with L.L3.
  - REO: control IDs from FRMR catalog + NIST CPRT; responsibility
    assignments are operator-supplied (Rule 4); never substitute a
    silent default for an unmapped control.

- **L.L2 — OSCAL Component Definition for leveraged providers**
  - New `core/oscal-component-def.ts`. For each leveraged authorization
    (AWS GovCloud, GCP Assured Workloads, Azure Government, etc.),
    emit an OSCAL `component-definition` document that enumerates the
    inherited controls + the leveraged-package UUID.
  - Wire into SSP as `back-matter.resources[type=service]` with
    `rlinks[]` pointing at the component-definition file.
  - Tests: ~10 — schema validity, leveraged-package UUID chain
    integrity, inherited-controls completeness.

- **L.L3 — Inheritance traceability map**
  - New `core/inheritance-trace.ts`. Produces `out/inheritance-trace.json`
    binding each NIST control → (CSP / Customer / Shared / Inherited
    bucket) → (leveraged authorization PA-id + leveraged control id
    when Inherited). Feeds the CIS/CRM emitter (L.L1) + SSP
    `implemented-requirements[].responsible-roles[]` (L.L2 +
    `core/oscal-ssp.ts`).
  - Tests: ~8.

- **L.L4 — Tracker UI for responsibility-matrix authoring**
  - `tracker/server/routes/responsibility-matrix.ts` + DB migration +
    `tracker/client/src/pages/ResponsibilityMatrix.tsx`. CRUD page so
    the operator can fill in (Customer / Shared / Inherited)
    designations per NIST control. Validates against
    `config/responsibility-matrix.yaml` as the on-disk source of
    truth.
  - Tests: ~10 — RBAC, validation, persistence.

**Dependencies:** LOOP-A (SSP exists), LOOP-C.C5 (FIPS 199 worksheet —
impact-tier alignment), LOOP-J.J2 (subprocessor inventory — distinct
from leveraged auth but related).

**Effort estimate:** 4 weeks single-thread (4 slices × 1 week median).

---

### LOOP-M — Privacy Package Extension (SORN, PTA / PIA, Privacy Continuous Monitoring)

**Why this is a separate loop:**
LOOP-C.C4 already covers PTA + PIA emission per FedRAMP templates +
OMB M-03-22 + NIST 800-53 PT-2/PT-3/PT-6. What's missing:

1. **System of Records Notice (SORN)** triggers when the CSO retrieves
   PII via a unique identifier on behalf of a federal agency — a
   distinct Privacy Act obligation (5 U.S.C. §552a) from the PIA. The
   agency publishes the SORN in the Federal Register, but the CSP
   supplies the structured input: the categories of records, routine
   uses, retention schedule, and safeguards. We currently have no
   structured-input emitter.

2. **Privacy Continuous Monitoring (PCM)** under NIST SP 800-53 Rev5
   PM-31 (Continuous Monitoring) + PT family (PT-1 through PT-7).
   Distinct from the security ConMon LOOP-E covers.

3. **Privacy Threshold-recheck cadence** — the PTA must be re-evaluated
   on a published cadence (annual at FedRAMP Moderate, or whenever a
   significant change affects PII handling). LOOP-C.C4 ships the
   *one-shot* PTA; the *recheck cadence* is uncovered.

**Source obligation (verbatim):**

Privacy Act of 1974 (5 U.S.C. §552a):
> "Each agency that maintains a system of records shall ... publish in
> the Federal Register upon establishment or revision a notice of the
> existence and character of the system of records."

OMB Memorandum M-03-22 §II.B.1:
> "Agencies must conduct a PIA before developing or procuring IT
> systems or projects that collect, maintain, or disseminate
> information in identifiable form from or about members of the
> public."

NIST SP 800-53 Rev5 PT-6 (System of Records Notice):
> "Provide notice to the public and to individuals about the existence
> and character of the system of records."

NIST SP 800-53 Rev5 PM-31:
> "Develop a continuous monitoring strategy and implement a continuous
> monitoring program."

**Slices:**

- **M.M1 — SORN structured-input emitter**
  - New `core/sorn-emit.ts`. Emits a structured Federal Register
    SORN draft (Markdown + JSON) with the 11 required SORN sections
    (system name + number, security classification, system location,
    categories of individuals + records, authority for maintenance,
    purposes, routine uses, retention + disposal, system manager + POC,
    notification procedure, contesting-record procedure). Auto-fills
    from `inventory.json` PII tags + operator-supplied PII inventory.
  - REO: `REQUIRES-OPERATOR-INPUT` markers for legal-authority cites,
    routine uses (cannot infer), retention schedule (operator-supplied).
  - Tests: ~12.

- **M.M2 — Privacy Continuous Monitoring (PCM) strategy doc**
  - New `core/pcm-strategy.ts`. Distinct from CA-7 ConMon (LOOP-C.C6).
    Emits .docx covering PT-1..PT-7 + PM-31 monitoring activities.
  - Tests: ~10.

- **M.M3 — PTA recheck cadence + tracker workflow**
  - Extend `core/pta-recheck.ts` (new) + tracker workflow. Annual
    review prompt + delta-vs-prior comparison.
  - Tests: ~8.

**Dependencies:** LOOP-C.C4 (PTA / PIA emitters); LOOP-E.E4 (annual
review pattern).

**Effort estimate:** 3 weeks (3 slices).

---

### LOOP-N — Threat Modeling + Adversarial Validation

**Why this is a separate loop:**
FedRAMP SSP requires (per Rev5 SSP template §13 + ARP § attack surface
analysis) a documented threat model identifying threat actors, attack
surface, controls mapping. The existing roadmap covers PenTest report
ingest (LOOP-K.K1) but the **CSP-authored threat model** (STRIDE /
PASTA / kill-chain narrative + attack surface enumeration) has no
home. Threat models are also a prerequisite of NIST SSDF (SP 800-218)
PW.1.1 ("Use forms of risk modeling — such as threat modeling,
attack modeling, or attack surface analysis — to help assess the risk
of attack").

Also missing:
- **Tabletop exercise facilitation** — the *live* tabletop, not just
  the AAR template (LOOP-C.C2/C3 cover the AAR template; LOOP-E.E7
  schedules the run; no slice covers facilitating the session itself
  with scenario libraries + injects).
- **Adversarial validation of KSI evidence** — RFC-0014's "truly
  automated and opinionated validation" leaves the door open for
  adversarial tests against the validation pipeline (mutation tests:
  what happens when the evidence is faked / corrupted / replayed). The
  20x trust model depends on this.

**Source obligation (verbatim):**

NIST SP 800-218 (SSDF) PW.1.1:
> "Use forms of risk modeling — such as threat modeling, attack
> modeling, or attack surface analysis — to help assess the risk of
> attack."

FedRAMP Rev5 SSP Template §13 (Control Implementation):
> "Describe the threat sources, threat events, and vulnerabilities
> considered. Include attack surface analysis as appropriate."

NIST SP 800-30 Rev1 §3.2.1 (Identify Threat Sources):
> "Identify and characterize threat sources of concern to the
> organization."

NIST SP 800-184 (Cyber Event Recovery) §3.4 (Tabletop Exercises):
> "Recovery plans should be tested using tabletop exercises and
> functional drills."

**Slices:**

- **N.N1 — STRIDE / attack-surface threat-model emitter**
  - New `core/threat-model-emit.ts`. Emits `.docx` + structured JSON
    threat model: per-component STRIDE bucket × control mitigation
    matrix; attack surface inventory derived from `inventory.json`
    (internet-reachable assets, authentication boundaries,
    administrative interfaces); kill-chain narrative skeleton with
    `REQUIRES-OPERATOR-INPUT` markers.
  - Tests: ~12.

- **N.N2 — Tabletop exercise facilitator + scenario library**
  - New `core/tabletop-runner.ts` + `tracker/server/routes/tabletop.ts`.
    Scenario library (ransomware, supply-chain compromise, insider
    threat, account takeover, KEV mass-exploitation). Tracker UI for
    live session capture (attendees, injects, decisions, AAR draft).
  - Tests: ~10.

- **N.N3 — Adversarial / mutation tests for KSI evidence pipeline**
  - New `tests/adversarial/` suite + CI integration. Faults injected
    at the wire layer (corrupted SDK responses, replayed envelopes,
    signature tampering) verify that the emitter chain detects + fails
    closed.
  - Builds on REO Rule 1.4 (no production-path SDK mocks) — these
    live under `tests/` per Rule 1 boundary.
  - Tests: this slice **is** tests; CI gate fails the run if
    adversarial signals are silently accepted.

**Dependencies:** LOOP-A (inventory + signing), LOOP-D (boundary
diagram informs attack surface), LOOP-K.K1 (PenTest ingest — different
modality than internal threat modeling).

**Effort estimate:** 4 weeks (3 slices, N.N3 is meatier).

---

### LOOP-O — AI/ML Governance (NIST AI RMF + OMB M-24-10)

**Why this is a separate loop:**
OMB M-24-10 and M-25-21 took effect in 2024 and 2025. Federal AI use
cases that touch FedRAMP-authorized CSOs now have to carry the OMB
AI use-case identifier + the NIST AI RMF MEASURE evidence per
inference call (per Section IV of M-24-10). 2026 OMB guidance
explicitly requires NIST AI RMF adoption for federal contractors using
AI in CSOs.

The user-role-profile memory note says the CSP runs SaaS CI/CD on
AWS+GCP w/ subprocessors. If the CSO uses AI/ML anywhere (model-as-a-
service, embedded inference, retrieval-augmented generation, copilot-
style features), this loop is required. If the CSO ships zero AI
surfaces, this loop is N/A and the loop ships a single attestation
emitter that says so.

**Source obligation (verbatim):**

OMB M-24-10 §IV (Risk Management):
> "Agencies shall conduct risk management of their AI use cases
> consistent with the NIST AI RMF and related guidance. This includes
> testing for prohibited and presumed-safety-impacting use cases prior
> to deployment."

OMB M-24-10 Attachment 1 (Minimum Practices):
> "Agencies shall maintain an inventory of AI use cases including a
> use case identifier, owning office, vendor (if applicable), risk
> category, and date of most recent risk evaluation."

NIST AI RMF 1.0 (AI 100-1):
> "GOVERN, MAP, MEASURE, MANAGE — these four functions help
> organizations address the risks of AI systems in practice."

**Slices:**

- **O.O1 — AI use-case inventory emitter**
  - New `core/ai-inventory.ts`. Emits structured JSON inventory of
    every AI/ML surface in the CSO: model identifier + provider, use
    case identifier (matches OMB M-24-10 categories), risk category,
    training data classification, evaluation cadence. Operator-
    supplied via `config/ai-inventory.yaml` + cloud-resource tag
    `ai_use_case=<id>`.
  - Conditional emit: when no `ai_use_case` tags exist, emit a single
    `no-ai-use-cases-attested` JSON with operator-signed attestation
    in the tracker. REO Rule 4 — never silently default to "no AI".
  - Tests: ~10.

- **O.O2 — NIST AI RMF MEASURE evidence collector**
  - New `core/ai-rmf-measure.ts`. For each AI surface in the
    inventory, collect MEASURE evidence: bias / fairness metrics, model
    cards (when supplied), red-team test results, hallucination rate
    measurements, prompt-injection test results. Operator-supplied for
    closed-source models.
  - Tests: ~12.

- **O.O3 — AI audit log + per-call provenance**
  - New `core/ai-audit-log.ts`. For each inference call to a tracked
    AI surface, the audit log captures the OMB M-24-10 use case ID, the
    model version, the input class (PII-scrubbed metadata only — never
    the input itself for REO + privacy reasons), and the NIST AI RMF
    MEASURE evidence reference. Long-term retention per LOOP-H.H2.
  - Tests: ~10.

- **O.O4 — AI risk acceptance + RAI (Responsible AI) decision log**
  - Tracker page + DB. Per OMB M-24-10 Attachment 1, agencies must
    document each AI deployment decision. Extension of LOOP-B.B3
    risk-acceptance pattern, scoped to AI use cases.
  - Tests: ~8.

**Dependencies:** LOOP-B.B3 (risk acceptance pattern reused), LOOP-H.H2
(retention), LOOP-E.E1 (monthly report includes AI MEASURE summary).

**Effort estimate:** 4 weeks (4 slices). May ship as opt-in (off by
default) until the operator confirms AI surfaces exist.

---

### LOOP-P — Insider-Threat Program + Workforce Security (NIST 800-53 Rev5 PM-12 + PS family)

**Why this is a separate loop:**
NIST SP 800-53 Rev5 control **PM-12 (Insider Threat Program)** is in
the FedRAMP Moderate baseline (and is a CSP organization-wide control,
not system-scoped). The PS family (PS-1 through PS-9) is also
Moderate-baseline and currently has zero direct coverage in our 49
slices (the IAM family covers AC-2 etc. but not PS-3 personnel
screening, PS-4 personnel termination, PS-7 third-party personnel
security, PS-8 personnel sanctions). The CED (Continuous Education /
training) family is partial via the tracker process-artifact path but
the PS-side is uncovered.

32 CFR Part 117 (NISPOM) — Insider-Threat Program guidance applies
when the CSP handles or processes data covered by the National
Industrial Security Program.

**Source obligation (verbatim):**

NIST SP 800-53 Rev5 PM-12 (Insider Threat Program):
> "Implement an insider threat program that includes a cross-discipline
> insider threat incident handling team."

NIST SP 800-53 Rev5 PS-3 (Personnel Screening):
> "Screen individuals prior to authorizing access to the system;
> rescreen individuals in accordance with [Assignment: organization-
> defined conditions requiring rescreening and, where rescreening is so
> indicated, the frequency of rescreening]."

NIST SP 800-53 Rev5 PS-4 (Personnel Termination):
> "Upon termination of individual employment ... disable system access
> within [Assignment: organization-defined time period]; terminate or
> revoke any authenticators / credentials associated with the
> individual."

32 CFR Part 117.7 (NISPOM Insider-Threat Program):
> "Contractors shall establish and maintain an insider threat program
> to detect, deter, and mitigate insider threats."

**Slices:**

- **P.P1 — Insider-threat program documentation + tracker workflow**
  - New `core/insider-threat-program.ts` (.docx emitter) + tracker
    DB tables: `insider_threat_indicators`, `insider_threat_cases`,
    `insider_threat_team_roster`.
  - Tests: ~12.

- **P.P2 — Personnel screening + termination evidence collector**
  - New `core/personnel-evidence.ts`. Pulls IAM-AAM evidence (existing)
    + tracker-stored screening records + offboarding-checklist
    evidence. Emits per-PS-control envelope.
  - Tests: ~10.

- **P.P3 — Workforce training records (CED family completion)**
  - Extends existing CED tracker. Per-user training-cadence ledger,
    annual security awareness, role-based training (SA-11 for
    developers), incident-response training (IR-2).
  - Tests: ~8.

**Dependencies:** LOOP-J.J1 (roles matrix), LOOP-A.A1 (POA&M shape for
PS findings).

**Effort estimate:** 3 weeks (3 slices).

---

### LOOP-Q — Marketplace Publication + Post-ATO Customer-Facing Artifacts

**Why this is a separate loop:**
Once a CSO is ATO'd, the FedRAMP Marketplace listing is the public-
facing artifact agencies use to discover the offering (per RFC-0021
and `https://marketplace.fedramp.gov/`). The CSP publishes structured
metadata (CSO name, impact level, 3PAO, authorization date, services-
in-scope, agency reuse list, point-of-contact) that's distinct from
the OSCAL submission package.

This intersects but is **distinct** from AFR-ADS (LOOP-G.G3 covers
the machine-readable Service List and Trust Center publication — those
are *internal CSP* publications; the Marketplace listing is the
*FedRAMP-hosted* public registry the agency consumes).

Also under-covered:
- **Authorization-date transition tracking** — when the CSO moves from
  "In Process" → "Ready" → "Authorized" → "Marketplace-Listed"
  states, each transition has structured metadata the PMO consumes.
- **Agency reuse acknowledgment** — each time a new agency leverages
  the CSO, a structured record is added to the Marketplace. CSP needs
  a tracker workflow.
- **Sponsoring-agency information** — for the JAB-equivalent agency-
  sponsored authorization path under 20x, the sponsoring agency
  metadata is a deliverable.

**Source obligation:**

RFC-0021 (Marketplace expansion):
> "FedRAMP shall publish a machine-readable Marketplace registry of
> all authorized CSOs with metadata supporting agency discovery and
> reuse."

FedRAMP Marketplace help docs (`help.fedramp.gov`):
> "Once a CSO reaches FedRAMP Authorized status, its authorization
> package — the SSP, POA&M, and all supporting artifacts — resides in
> the FedRAMP repository, and the Marketplace listing is what makes the
> vendor findable."

**Slices:**

- **Q.Q1 — Marketplace metadata emitter**
  - New `core/marketplace-metadata.ts`. Emits structured JSON +
    Markdown summary for FedRAMP Marketplace ingest. Fields per the
    Marketplace API: CSO name, impact level, 3PAO, authorization
    date, services-in-scope, POC, agency reuse list, status (In
    Process / Ready / Authorized).
  - Tests: ~10.

- **Q.Q2 — Agency reuse acknowledgment workflow**
  - Tracker route + DB. Each new agency leveraging the CSO produces a
    structured record; emit Marketplace-reuse-update payload.
  - Tests: ~8.

- **Q.Q3 — Status transition state machine**
  - Tracker state machine: In Process → Ready → Authorized →
    Marketplace-Listed. Each transition signed (REO pattern). Distinct
    from LOOP-F.F6 (ATO workflow tracker is pre-ATO; Q.Q3 is post-ATO
    Marketplace lifecycle).
  - Tests: ~8.

**Dependencies:** LOOP-A.A4 (submission bundle is what unlocks ATO),
LOOP-F.F6 (pre-ATO workflow handoff to Q.Q3 post-ATO), LOOP-G.G3
(AFR-ADS publication overlaps but is distinct).

**Effort estimate:** 3 weeks (3 slices).

---

## 3. Should fold into existing loops (extend a slice rather than new loop)

These items have a clear obligation but are tightly scoped enough that
splitting them into their own loops would create overhead. Each
recommendation names the existing slice to extend + the extension
deliverables.

### 3.1 Item — Cryptographic Modules Table (SSP Appendix Q)

- **Source obligation:** FedRAMP Policy for Cryptographic Module
  Selection v1.1.0 + SSP Appendix Q template
  (`SSP-Appendix-Q-Cryptographic-Modules-Table.docx`); NIST FIPS 140-3
  Management Manual.
- **Best home:** **Extend LOOP-G.G** (AFR-UCM verification, already
  marked HAVE) **+ add LOOP-C.C-NEW** under the document template pack.
- **Extension:** New `core/ssp-appendix-q.ts` that emits the .docx
  Appendix Q table from existing `providers/{aws,gcp,azure}/crypto.ts`
  collector output. Per-module rows: module identifier, CMVP
  certificate number, FIPS validation level (140-2 / 140-3), boundary
  description (in-FedRAMP-boundary scope), validation date, sunset
  date, attested by 3PAO via LOOP-F.F1 sign-off.
- **Slice tag:** **LOOP-C.C10** (new C-slice; turns existing crypto
  collector evidence into the FedRAMP-required appendix doc).
- **Effort:** ~1 week.

### 3.2 Item — Vulnerability Disclosure Program (VDP) policy document

- **Source obligation:** CISA BOD 20-01 (Develop and Publish a
  Vulnerability Disclosure Policy); FedRAMP RA-5; the AFR-VDR
  family covers detection + response operationally, but the **VDP
  policy document** (public-facing security.txt + acknowledgment-of-
  receipt SLA + safe-harbor language) is distinct.
- **Best home:** **Extend LOOP-G addendum (currently planned for
  VDR-CSO-DOC under F13 in SECTION-F)**.
- **Extension:** Add `core/vdp-policy-doc.ts` to the LOOP-G VDR
  addendum. Emits a `.docx` VDP policy + a `security.txt` for the
  public endpoint (RFC 9116). Operator-supplied: legal safe-harbor
  language, scope, reporting endpoint.
- **Slice tag:** **LOOP-G.G7** (add a 7th slice to LOOP-G; VDR-DOC
  already in the plan but VDP policy is distinct from recommendation
  documentation).
- **Effort:** ~3 days.

### 3.3 Item — Internal Pre-Assessment Readiness Check (CSP-internal mock 3PAO walkthrough)

- **Source obligation:** No direct FedRAMP mandate; industry-standard
  pre-assessment best practice; reduces re-test cycles + AO-feedback
  rounds.
- **Best home:** **Extend LOOP-F.F6** (Full ATO workflow tracker).
- **Extension:** Add a "Pre-Assessment Self-Review" state to the
  state machine. Runs the existing REO check + LOOP-B.B5 risk register
  + LOOP-A.A4 bundler `--strict-bundle` against the current package +
  emits a self-review report `out/pre-assessment-readiness.md` that
  flags gaps the 3PAO would flag.
- **Slice tag:** LOOP-F.F6 extension (no new slice; folds into the
  existing state machine).
- **Effort:** ~3 days.

### 3.4 Item — Data Residency / Sovereignty Declarations

- **Source obligation:** FedRAMP Moderate has no explicit "US-only data
  residency" requirement (that's IL5+ for DoD CCSRG L5; ITAR / EAR for
  defense exports); FedRAMP High requires US-only operations &
  maintenance personnel. **Moderate** typically declares but does not
  enforce US-only.
- **Best home:** **Extend LOOP-C.C8** (Authorization request cover
  letter) + **LOOP-A.A5** (RoE).
- **Extension:** Add a `data_residency_declaration` block to the cover
  letter and RoE templates. Pull from `org-profile.yaml`
  `data_residency_regions[]`. Document any exceptions (subprocessors
  outside the declared region).
- **Slice tag:** LOOP-C.C8 extension.
- **Effort:** ~2 days.
- **Note:** When the operator declares High or IL5 tier (post-MVP),
  this extension hardens into a gate rather than a declaration.

### 3.5 Item — Configuration Drift Monitoring (CM-3 + CM-6 active monitoring)

- **Source obligation:** NIST 800-53 Rev5 CM-3 (Configuration Change
  Control) + CM-6 (Configuration Settings). Existing coverage: CM-2
  baseline doc (LOOP-C.C9), SCN classifier (LOOP-E.E6), Baseline
  Configuration document. **Active drift monitoring** between baseline
  and live state is uncovered.
- **Best home:** **Extend LOOP-E.E6** (SCN classifier) or **LOOP-I.I3**
  (anomaly detection).
- **Extension:** New collector `providers/*/config-drift.ts` that
  diffs current configuration (AWS Config / GCP Asset Inventory /
  Azure Policy compliance) against the LOOP-C.C9 baseline. Emits drift
  events into the SCN classifier (LOOP-E.E6).
- **Slice tag:** LOOP-E.E6 extension; consider also LOOP-I.I3.
- **Effort:** ~1 week.

### 3.6 Item — Account Lifecycle Attestation (AC-2(3) + AC-2(4))

- **Source obligation:** NIST 800-53 Rev5 AC-2(3) (Disable Accounts —
  inactive account disablement); AC-2(4) (Automated Audit Actions —
  account creation / modification / disabling); AC-6(7) (Review of
  User Privileges — periodic recertification).
- **Best home:** **Extend LOOP-J.J1** (Roles & Privileges matrix).
- **Extension:** Per-user recertification cadence ledger. Tracker
  workflow: every N days, role owner attests "this account still
  needs these privileges." Emits to POA&M when overdue.
- **Slice tag:** LOOP-J.J1 extension.
- **Effort:** ~1 week.

### 3.7 Item — Boundary Protection Traffic-Flow Logs (SC-7(5), (8))

- **Source obligation:** NIST 800-53 Rev5 SC-7(5) (Deny by Default —
  Allow by Exception); SC-7(8) (Route Traffic to Authenticated
  Proxy). Existing: AFR-CNA-RVP collector covers boundary state. **Live
  flow logs** of denied + allowed traffic at the boundary are not yet
  surfaced as evidence.
- **Best home:** **Extend existing `providers/{aws,gcp,azure}/network.ts`**
  + a new collector slot for VPC Flow Logs / NSG Flow Logs / Cloud NAT
  Logs ingestion.
- **Extension:** Per-cloud flow-log collector. Reconciles allowed /
  denied count by source / destination + flags anomalies (e.g. high
  denial rate on a previously-quiet port).
- **Slice tag:** New CNA-class collector slice; consider adding under
  LOOP-K (test artifact ingestion) or as a SECTION-A enrichment.
- **Effort:** ~1.5 weeks.

### 3.8 Item — DevSecOps Pipeline Attestations (SA-11, SA-15, SR-3)

- **Source obligation:** NIST SSDF (SP 800-218) PW.4 + PS.1 + PS.2 +
  PS.3 — secure build attestations. NIST 800-53 SA-11 (Developer
  Testing + Evaluation), SA-15 (Development Process, Standards, and
  Tools), SR-3 (Supply Chain Controls).
- **Best home:** **Extend LOOP-J.J3** (Supply chain risk register +
  SBOM integration).
- **Extension:** Add CI/CD pipeline attestation collector. Reads CI
  output (GitHub Actions / GitLab / Jenkins) to verify required gates
  ran: SAST, DAST, SBOM generation, signature verification, IaC scan.
  Emits per-build attestation JSON signed under the existing chain.
- **Slice tag:** LOOP-J.J3 extension.
- **Effort:** ~1.5 weeks.

### 3.9 Item — Threat Intelligence Ingest (CISA AIS, ISACs)

- **Source obligation:** No direct FedRAMP mandate; implied by NIST
  800-53 PM-15 (Contacts with Security Groups + Associations) + PM-16
  (Threat Awareness Program). CISA AIS (Automated Indicator Sharing)
  is the federal channel.
- **Best home:** **Extend LOOP-E.E1** (Monthly ConMon analysis report).
- **Extension:** New `core/threat-intel-ingest.ts` that pulls CISA AIS
  STIX feeds + reconciles against `inventory.json` + flags inventory
  components with active IOCs. Feeds the ConMon monthly report
  exposure summary.
- **Slice tag:** LOOP-E.E1 extension.
- **Effort:** ~1.5 weeks.

### 3.10 Item — Penetration Test Rules of Engagement (PenTest RoE — distinct from Assessment RoE)

- **Source obligation:** FedRAMP Penetration Test Guidance Rev 3 §3
  (Rules of Engagement for PenTest) — distinct from LOOP-A.A5
  (Assessment RoE).
- **Best home:** **Extend LOOP-K.K1** (PenTest report ingest).
- **Extension:** Add a PenTest-RoE `.docx` emitter that prefills from
  the assessment RoE (LOOP-A.A5) + the boundary diagram (LOOP-D.D1) +
  3PAO-supplied test methodology. Operator + 3PAO co-sign before
  testing starts.
- **Slice tag:** LOOP-K.K1 extension (or new LOOP-K.K3 if scope
  expands).
- **Effort:** ~1 week.

### 3.11 Item — Training Records Completeness Check (CED family)

- **Source obligation:** FRMR CED family (Continuous Education /
  training); NIST 800-53 AT-2 (Literacy Training and Awareness), AT-3
  (Role-Based Training). Coverage in existing process-artifact tracker
  is partial.
- **Best home:** **Extend the CED tracker pages** (already extant) +
  link from LOOP-P.P3.
- **Extension:** Per-user, per-role training record with cadence
  enforcement; CED process-artifact KSI envelope emits with full
  evidence.
- **Slice tag:** LOOP-P.P3 (in the new LOOP-P) covers this; if
  LOOP-P doesn't ship, fold into LOOP-J.J1 extension.
- **Effort:** ~1 week.

### 3.12 Item — RFC 3161 Timestamp Authority redundancy

- **Source obligation:** No direct mandate; NIST 800-53 AU-10
  (Non-repudiation) implies the timestamping authority be
  independently auditable. Single-authority dependency is a
  resilience risk.
- **Best home:** **Extend `core/timestamp.ts`** (existing).
- **Extension:** Multi-TSA failover (DigiCert + GlobalSign + Sectigo
  + FreeTSA fallback). Per-stamp record TSA identity.
- **Slice tag:** Hardening of A.A4 (no new slice; production
  hardening).
- **Effort:** ~2 days.

---

## 4. Out-of-scope (NOT FedRAMP 20x Moderate)

These items are real obligations under adjacent frameworks but not
required at FedRAMP 20x Moderate. They are documented here so a future
session that needs to escalate to High or IL5 has a starting point.

### 4.1 FedRAMP High → US-personnel-only requirement

- **Why out of scope:** FedRAMP High (per NIST 800-53 PS-3(1) + JAB
  guidance) requires US-only operations & maintenance personnel and
  US-only data residency. Moderate has no such requirement.
- **When revisit:** When operator declares `--impact-level high`.
  Currently the orchestrator emits a HIGH-CLARIFY warning that "20x
  High doesn't exist yet"; once it does, fold US-personnel
  attestation into LOOP-J.J1 + LOOP-C.C8.

### 4.2 DoD IL5+ — additional encryption + Crypto Modernization

- **Why out of scope:** IL5+ requires AES-256 minimum, FIPS 140-3
  Level 2+ for HSMs, dedicated tenancy, FedRAMP+ DoD overlay
  controls.
- **When revisit:** When operator declares DoD IL5+ scope; tier is
  outside FedRAMP authority entirely (DISA SCCA / CCSRG).

### 4.3 CMMC Level 2/3 — CUI-scoped controls

- **Why out of scope:** CMMC is DoD-specific for CUI handling. The
  CRM (LOOP-L) covers customer responsibility but CMMC-specific
  controls (CUI marking, ITAR, EAR, NIST 800-171) are out of scope
  for FedRAMP.
- **When revisit:** When CSP also handles CUI for DoD primes; add a
  LOOP-R for CMMC adjacency (NIST 800-171 evidence collector + CMMC
  L2/L3 assessment package).

### 4.4 StateRAMP — State-tier authorization

- **Why out of scope:** StateRAMP is a state-government parallel
  framework. Coverage overlaps but the authorization package is
  state-controlled.
- **When revisit:** When a state customer requires StateRAMP; consider
  using LOOP-I.I4 cross-framework crosswalk to derive the StateRAMP
  package from the FedRAMP package.

### 4.5 SOC 2 / ISO 27001 / HITRUST — commercial-tier authorizations

- **Why out of scope:** Commercial frameworks. Already noted in
  SECTION-D D13 as a LOOP-I.I4 extension (post-MVP).
- **When revisit:** Customer demand for dual-authorization.

### 4.6 Section 508 (Accessibility) for the tracker UI

- **Why out of scope:** Section 508 applies to the federal customer's
  consumption of the CSO; the **tracker UI is CSP-internal** and not
  consumed by federal users. If the tracker becomes customer-facing,
  Section 508 + WCAG 2.1 AA become required.
- **When revisit:** Before any tracker UI is exposed to federal
  customers.

### 4.7 EU AI Act / Brussels-Effect AI obligations

- **Why out of scope:** EU AI Act applies to EU users; FedRAMP is US-
  federal-scoped. If CSP serves EU customers, AI obligations may
  inform LOOP-O design but are not FedRAMP-required.
- **When revisit:** When CSP declares EU customer base.

### 4.8 PCI DSS, HIPAA — sector-specific frameworks

- **Why out of scope:** Sector-specific. The user-role-profile says
  the CSP runs SaaS CI/CD — no explicit healthcare or payments
  surfaces. If those surfaces emerge, HIPAA / PCI become
  customer-responsibility-matrix entries (LOOP-L).
- **When revisit:** When CSP onboards a healthcare or payments
  customer.

### 4.9 BOD 23-01 — Asset Visibility (federal civilian executive branch)

- **Why out of scope:** BOD 23-01 applies to FCEB agencies (the
  customer), not to CSPs directly. Marketplace metadata in LOOP-Q
  helps agencies satisfy their BOD 23-01 obligation.
- **When revisit:** Verify Q.Q1 emits the metadata BOD 23-01
  requires.

---

## 5. Open questions for the human

Items where I could not resolve a clean decision from public sources
alone. Each is decision-bearing before the corresponding loop starts.

1. **Does this CSP use AI/ML anywhere in the CSO?** LOOP-O scope
   hinges on this. If "no", LOOP-O ships as a single attestation
   slice. If "yes", LOOP-O ships all 4 slices.

2. **Does this CSP process PII subject to the Privacy Act (i.e.,
   records retrieved via a unique identifier on behalf of a federal
   agency)?** LOOP-M.M1 (SORN) is conditional on this. The PIA
   conditional emit in LOOP-C.C4 covers the PIA side but the SORN is
   a distinct trigger.

3. **Does this CSP have internal SOPs that already cover insider-
   threat program (PM-12)?** LOOP-P.P1 should consume existing
   documentation rather than scaffold from scratch. If the CSP
   already has an Insider-Threat Program Plan, the slice becomes
   "ingest + reformat" not "author".

4. **Sponsoring-agency vs JAB-equivalent authorization path** —
   20x has eliminated the JAB; replacement is single-agency
   sponsorship + PMO P-ATO. LOOP-Q.Q1 needs the sponsoring agency
   to be declared in config — is the sponsoring agency known yet?

5. **CRM template format final** — the FedRAMP CIS/CRM workbook
   format is still in revision per 2026 Consolidated Rules planning.
   LOOP-L.L1 should version-pin the schema and emit a
   `package_format_version` for the CRM analogous to LOOP-A.A4.

6. **AI use-case identifier source** — OMB M-24-10 Attachment 1
   says use case IDs are agency-assigned. CSP-side LOOP-O.O1 should
   emit a *requested* use case ID + accept the agency-assigned ID via
   tracker. Verify with the sponsoring agency's AI governance office
   before O.O1 ships.

7. **Tabletop exercise cadence** — NIST 800-184 recommends
   semi-annual; FedRAMP requires annual (IR-3 / CP-4). LOOP-N.N2
   should default to annual + operator-overrideable.

8. **VDP safe-harbor language** — operator's legal counsel must
   approve the VDP safe-harbor language before LOOP-G.G7 publishes
   `security.txt`. This is a hard human-gate; no system default.

9. **CRM responsibility-matrix authoring sequence** — does the
   operator fill in the matrix before or after the SSP is emitted?
   Typically iteratively. LOOP-L.L4 tracker UI assumes parallel
   authoring; needs operator confirmation.

10. **Leveraged-authorization PA-id lookup** — FedRAMP PA-ids (e.g.,
    "F1411040093" for AWS GovCloud) are committed via PMO; LOOP-L.L2
    needs a committed lookup table at
    `cloud-evidence/docs/leveraged-authorizations.generated.json`.
    Currently no source mechanically extracts this; operator must
    supply.

11. **AFR-FSI vs CRM customer-responsibility overlap** — FSI inbox
    (LOOP-G.G1) requires CSP to acknowledge required actions; some
    required actions may be customer-responsibility-matrix items.
    Routing between the two systems needs definition.

12. **Post-LOOP-Q Marketplace API authentication** — FedRAMP
    Marketplace API publishes the registry; ingest authentication
    (OAuth? mTLS?) is not yet documented. LOOP-Q.Q1 may need to defer
    publication until PMO publishes the API auth model.

---

## 6. Summary

- **Total existing loops:** 11 (A–K)
- **Existing slices:** 49 (LOOP-A complete = 5 slices done; LOOP-B–K
  pending = 44 slices)
- **New loops proposed:** 6 (LOOP-L, M, N, O, P, Q)
- **New slices in the new loops:** 4 + 3 + 3 + 4 + 3 + 3 = **20 new
  slices**
- **Extensions to existing slices:** 12 (3.1 through 3.12)
- **Out-of-scope items flagged for future:** 9 (§4.1 through §4.9)
- **Open questions to resolve before starting:** 12 (§5.1 through §5.12)

**Revised slice count if all §2 + §3 land:**
49 (existing) + 20 (new loops) + ~3 (slice-tagged extensions in §3
that create new slice IDs: LOOP-C.C10, LOOP-G.G7, plus the LOOP-J.J3
+ LOOP-K.K3 PenTest-RoE addition) = **~72 slices total**.

**Recommended prioritization for adoption:**

1. **LOOP-L (CRM + Inheritance)** — high impact, mandatory at every
   authorization; should land before LOOP-C.C8 (cover letter
   references CRM bucket counts).

2. **LOOP-M (Privacy package extension)** — conditional on §5.2
   answer. If PII processed, near-mandatory; if not, ship the
   attestation-only slice.

3. **LOOP-Q (Marketplace + post-ATO)** — leverages LOOP-A.A4 +
   LOOP-F.F6 already built; relatively cheap.

4. **LOOP-N (Threat modeling)** — under-served; not strictly
   blocking but raises authorization-package quality measurably.

5. **LOOP-P (Insider Threat + PS family)** — addresses an entire
   uncovered NIST control family (PS) and a PM control (PM-12).

6. **LOOP-O (AI/ML governance)** — conditional on §5.1 answer.
   Likely required given 2026 OMB momentum even if CSP says "no
   AI today" — emit at minimum the attestation slice.

7. **§3 extensions** — fold into existing loops as those loops
   land; do not block on §2 new loops.

**Recommended re-cut of the EXECUTION-PLAN.md table** (do this in a
separate slice; this audit is the input):

| Loop | Title | Slices | Effort | Depends on |
|---|---|---|---|---|
| B | Risk + remediation engine | 5 | 4 wk | A.A1 |
| C | Document template pack | 10 (+C10 crypto) | 9 wk | none |
| D | Diagram auto-generation | 3 | 3 wk | none |
| E | Continuous monitoring agent | 7 | 5 wk | A.A1 + C.C6 |
| F | 3PAO assessor experience | 7 | 4 wk | A.A2 + B.B3 |
| G | AFR family + VDP policy | 7 (+G7 VDP) | 6 wk | none |
| H | Long-term storage + multi-CSO | 3 | 3 wk | none |
| I | Stakeholder dashboards | 4 | 3 wk | B.B1 |
| J | Supply chain + privileges | 3 | 3 wk | none |
| K | Test artifact ingestion | 3 (+K3 PenTest-RoE) | 3 wk | A.A3 |
| **L** | **CRM + Inheritance** | **4** | **4 wk** | **A (SSP)** |
| **M** | **Privacy package extension** | **3** | **3 wk** | **C.C4** |
| **N** | **Threat modeling + adversarial validation** | **3** | **4 wk** | **A + D** |
| **O** | **AI/ML governance (conditional)** | **4** | **4 wk** | **B.B3 + H.H2** |
| **P** | **Insider Threat + Workforce Security** | **3** | **3 wk** | **J.J1** |
| **Q** | **Marketplace + post-ATO publication** | **3** | **3 wk** | **A.A4 + F.F6** |
| **TOTAL** | | **~72** | **~64 weeks single-thread** | |

The roadmap grows from 46 weeks single-thread to **~64 weeks single-
thread** (or ~28 weeks 3-stream parallel) if every recommendation
lands. If LOOP-O (AI) and LOOP-M (Privacy SORN-tier) are conditional
N/A, the budget drops to ~57 weeks single-thread (~25 weeks parallel).

**Per-section coverage impact:**

- **SECTION A** gains A23 (CRM workbook), A24 (Component-def
  inheritance doc), A25 (SSP Appendix Q crypto table), A26 (SORN
  structured input — conditional), A27 (Threat model document),
  A28 (VDP policy + security.txt), A29 (Marketplace metadata),
  A30 (AI use-case inventory — conditional).
- **SECTION C** gains C14 (Privacy continuous monitoring strategy),
  C15 (PCM recheck cadence), C16 (Insider-threat program plan).
- **SECTION D** gains D19 (CRM authoring UI), D20 (AI MEASURE
  dashboard), D21 (Tabletop exercise facilitation surface),
  D22 (Marketplace lifecycle tracker), D23 (Pre-assessment
  readiness check).
- **SECTION E** gains E24 (PM-12 Insider Threat coverage),
  E25 (PS family coverage), E26 (PT-6 SORN — conditional),
  E27 (PM-15 + PM-16 threat intel),  E28 (SSDF SP 800-218 DevSecOps
  pipeline).

---

## 7. Acceptance for this audit

This audit's "done" definition (mirroring the per-slice REO contract):

1. ✅ Every §2 new loop has a real source citation + slice
   enumeration + dependency map + effort estimate.
2. ✅ Every §3 extension has a named existing slice + concrete
   extension scope.
3. ✅ Every §4 out-of-scope item has a documented re-visit trigger.
4. ✅ Every §5 open question is decision-bearing (not informational).
5. ✅ §6 summary aligns the revised slice count + dependency-aware
   ordering.

The human (or the next session that reads this audit) should be able
to: (a) accept / reject each §2 loop individually; (b) accept /
defer each §3 extension; (c) confirm / decline each §4 out-of-scope
flag; (d) answer each §5 open question; (e) ratify the revised
EXECUTION-PLAN table proposed in §6.

---

## Appendix — Source URL map (for citation chains in §6)

- FedRAMP Marketplace: `https://marketplace.fedramp.gov/`
- FedRAMP RFCs: `https://www.fedramp.gov/rfcs/` (specifically RFC-0014,
  RFC-0021, RFC-0024, RFC-0028, RFC-0029, RFC-0030)
- FedRAMP Rev5 Playbook (CSP authorization): `https://www.fedramp.gov/docs/rev5/playbook/csp/`
- FedRAMP CIS/CRM Workbook (SSP Appendix J template): per FedRAMP
  template pack at `https://www.fedramp.gov/assets/resources/templates/`
- SSP Appendix Q (Crypto Modules Table): `https://www.fedramp.gov/assets/resources/templates/SSP-Appendix-Q-Cryptographic-Modules-Table.docx`
- FedRAMP Crypto Module Selection Policy v1.1.0: `https://www.fedramp.gov/resources/documents/FedRAMP_Policy_for_Cryptographic_Module_Selection_v1.1.0.pdf`
- FedRAMP PenTest Guidance v3.0: `https://www.fedramp.gov/assets/resources/documents/CSP_Penetration_Test_Guidance.pdf`
- CISA BOD 20-01 (VDP): `https://www.cisa.gov/news-events/directives/bod-20-01-develop-and-publish-vulnerability-disclosure-policy`
- CISA BOD 22-01 (KEV): `https://www.cisa.gov/news-events/directives/binding-operational-directive-22-01`
- CISA BOD 23-01 (Asset Visibility): `https://www.cisa.gov/news-events/directives/bod-23-01-improving-asset-visibility-vulnerability-detection`
- NIST SP 800-53 Rev5: `https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf`
- NIST SP 800-53B Rev5 (Baselines): `https://csrc.nist.gov/pubs/sp/800/53/b/upd1/final`
- NIST SP 800-218 (SSDF): `https://csrc.nist.gov/publications/detail/sp/800-218/final`
- NIST AI RMF 1.0 (AI 100-1): `https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf`
- OMB M-24-10 (AI use cases): `https://www.whitehouse.gov/wp-content/uploads/2024/03/M-24-10-Advancing-Governance-Innovation-and-Risk-Management-for-Agency-Use-of-Artificial-Intelligence.pdf`
- OMB M-03-22 (PIA Guidance, E-Government Act §208): `https://www.whitehouse.gov/wp-content/uploads/legacy_drupal_files/omb/memoranda/2003/m03_22.pdf`
- Privacy Act of 1974 (5 U.S.C. §552a) — SORN obligation
- 32 CFR Part 117 (NISPOM Insider Threat): `https://www.ecfr.gov/current/title-32/subtitle-A/chapter-I/subchapter-D/part-117`
- NIST CMVP FIPS 140-3 Management Manual: `https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS-140-3-CMVP%20Management%20Manual.pdf`
- FRMR machine-readable catalog: `https://github.com/FedRAMP/docs`
- OSCAL v1.1.2: `https://github.com/usnistgov/OSCAL/releases/tag/v1.1.2`
- RFC 9116 (security.txt): `https://www.rfc-editor.org/rfc/rfc9116`
- RFC 3161 (Trusted Timestamping): `https://www.rfc-editor.org/rfc/rfc3161`
