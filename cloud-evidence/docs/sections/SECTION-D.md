# SECTION D — Audit agent UX (industry-standard expectations)

> **Scope:** Requirements-layer specification for the eighteen
> stakeholder-facing UX deliverables a modern FedRAMP 20x audit agent is
> expected to ship beyond the bare OSCAL submission package. Each artifact
> is mapped to its source obligation, format, primary consumer, current
> FedPy build status, and the implementing loop.slice in
> `docs/EXECUTION-PLAN.md`.
>
> **Companion docs:** `cloud-evidence/CLAUDE.md` (Real-Evidence-Only
> standard), `docs/EXECUTION-PLAN.md` (per-slice build steps),
> `docs/AFR-FAMILY-CLASSIFICATION.md` (R1 — all 10 AFR families REQUIRED
> at Moderate), `docs/PRE-LOOP-A-RESEARCH-FINDINGS.md` (R2/R3/R4).

---

## 1. Purpose

### 1.1 What this section covers

SECTION D enumerates the **eighteen audit-agent UX artifacts** that take
the raw OSCAL/REO evidence emitted by LOOP-A and turn it into something a
human stakeholder — executive, control owner, 3PAO assessor, FedRAMP PMO
reviewer, Authorizing Official, ConMon engineer, or downstream automation
— can actually *use*. These are the layers above the wire format:

- **Risk semantics** (D1 risk scoring, D2 remediation deadline math) — how
  raw findings become prioritized work items with defensible due dates.
- **Real-time + cadence signals** (D3 alerting, D5 burndown pipeline,
  D6 trend analysis, D7 anomaly detection) — how the system surfaces
  changes the moment they matter, not at the next monthly POA&M cycle.
- **Stakeholder dashboards** (D4 executive dashboard) — the C-suite /
  AO / agency view of cross-system posture.
- **Multi-system + program-scale concerns** (D8 multi-CSO, D9 audit-trail
  integrity) — the support layer for MSPs and aggregators that run
  many authorizations in parallel and need cross-tenant audit guarantees.
- **Risk-management workflows** (D10 risk acceptance, D11 compensating
  controls) — the human-decision capture layer that converts open POA&Ms
  into governed risk decisions with signed records and expirations.
- **Authoring + cross-mapping** (D12 SSP narrative library, D13
  cross-framework crosswalk) — reduce the manual SSP authoring burden and
  let the same evidence satisfy adjacent frameworks (CMMC, ISO 27001,
  SOC 2, HITRUST, StateRAMP).
- **Integration surfaces** (D14 ticketing/CMDB/SIEM, D16 OpenAPI spec) —
  how the audit agent plays well with the customer's existing operational
  stack rather than forcing a parallel workflow.
- **LLM-assisted authoring** (D15 LLM PR generation) — where it's safe to
  use generative AI, with provenance guarantees and human review gates.

### 1.2 Why it exists in the FedRAMP authorization framework

RFC-0014 mandates "truly automated and opinionated validation of Key
Security Indicators" for 20x Moderate. RFC-0024 mandates OSCAL JSON as
the wire format. **Neither RFC defines the UX layer.** But every real
3PAO assessment, AO review, and ConMon cycle in practice depends on the
UX layer to function: an unprioritized 600-row POA&M with no risk score
and no burndown view is useless even if it's perfectly OSCAL-compliant.
The FedRAMP PMO's published [Continuous Monitoring Strategy
Guide](https://www.fedramp.gov/assets/resources/documents/CSP_Continuous_Monitoring_Strategy_Guide.pdf)
and [ConMon Playbook](https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/overview/)
require monthly risk-prioritized remediation status, trend analysis, and
deviation requests — all of which presuppose the UX artifacts cataloged
here. The [USDA Connect.gov secure
repository](https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/overview/)
ingests the artifacts but does not produce them. **This section is the
contract between "OSCAL-valid" and "audit-ready."**

These are also industry-standard GRC features expected by every modern
3PAO and ConMon vendor (Drata, Vanta, Anecdotes, Hyperproof, ServiceNow
GRC, RegScale). A CSP submitting FedRAMP 20x evidence that *only* emits
OSCAL JSON without the UX layer would be perceived as immature relative
to the market baseline. SECTION D closes that perception gap with real
evidence flows.

---

## 2. Artifact catalogue (D1–D18)

> **Status legend:**
> `HAVE` = code shipped under "Unreleased" in CHANGELOG.md.
> `PARTIAL` = scaffold + partial coverage; named module exists but
> required behavior is not end-to-end.
> `MISSING` = no production code yet; planned in EXECUTION-PLAN.md.
>
> **Required column:** ✅ = explicitly required by FedRAMP RFC / NIST
> publication / OSCAL spec; ⚠️ conditional = required when a precondition
> applies (e.g. multi-CSO when CSP runs > 1 system); RECOMMENDED =
> industry-standard but not FedRAMP-mandated.

| ID  | Artifact                                       | Required        | Consumer(s)                                | Format(s)                                  | Source obligation                                                                                                                                                            | Current FedPy status                                                                                                                | Implementing loop.slice         |
|-----|------------------------------------------------|-----------------|--------------------------------------------|--------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|---------------------------------|
| D1  | Per-finding risk scoring                       | ✅              | 3PAO, PMO, AO, CSP-internal                | OSCAL POA&M `risk.props`, JSON, .xlsx       | NIST SP 800-30 Rev1 §3.2 (Risk Assessment); FedRAMP CMP §4 (vulnerability prioritization); FIRST CVSS v3.1; FIRST EPSS Model                                                  | PARTIAL — `core/oscal-poam.ts` emits severity-bucket only (Critical/High/Medium/Low/Info); CVSS+EPSS+criticality+exposure missing   | LOOP-B.B1                       |
| D2  | Remediation deadline math (KEV/PAIN/IRV/LEV)   | ✅              | 3PAO, PMO, AO, CSP-internal                | OSCAL POA&M `risk.deadline`, JSON, .xlsx    | CISA BOD 22-01 (KEV 21-day SLA); FedRAMP CMP §4.3 (sev-based deadlines); FedRAMP ConMon Strategy Guide §3.4                                                                   | PARTIAL — `core/oscal-poam.ts` emits FedRAMP severity baseline (30/60/90/180/365) only; CISA KEV due-date + PAIN/IRV/LEV math missing | LOOP-B.B2                       |
| D3  | Real-time alerting on emerging vulnerabilities | RECOMMENDED     | CSP-internal, ConMon engineers             | webhook, email, Slack, PagerDuty           | FedRAMP CMP §4.2 (timely awareness); NIST SP 800-137 §3.2.4 (continuous monitoring data analysis); CISA KEV catalog publication                                              | MISSING — no webhook layer; `providers/*/vdr-scan.ts` reconciles KEV at scan time but does not push                                  | LOOP-I.I1 (subset) + LOOP-E.E1  |
| D4  | Executive posture dashboard                    | RECOMMENDED     | CSP exec, AO, agency CISO                  | tracker web UI, PDF snapshot               | Industry-standard GRC feature; FedRAMP CMP §6 (reporting cadence); NIST SP 800-137 §3.6                                                                                      | MISSING — `tracker/client/src/pages/` has Findings/Inventory pages only                                                              | LOOP-I.I1                       |
| D5  | Finding burndown + deadline pipeline           | ✅              | 3PAO, PMO, CSP-internal                    | tracker web UI, .xlsx export, JSON         | FedRAMP CMP §4.4 (POA&M progress reporting); NIST SP 800-137 §3.6.2; OSCAL POA&M `findings[].related-observations[]`                                                          | MISSING — no time-series; current `core/findings.ts` is per-run snapshot only                                                       | LOOP-I.I2                       |
| D6  | Longitudinal trend analysis                    | ✅              | PMO, AO, 3PAO, CSP-internal                | tracker web UI, JSON, .xlsx                | NIST SP 800-137 §3.6.3 (trend analysis); FedRAMP ConMon Strategy Guide §3.5 (Annual Assessment trend section)                                                                 | MISSING — no historical store of per-KSI pass-rate across runs                                                                       | LOOP-I.I3                       |
| D7  | Anomaly detection (regression alerting)        | RECOMMENDED     | CSP-internal, ConMon engineers             | webhook, email, tracker UI                 | NIST SP 800-137 §3.6.4 (anomaly identification); FedRAMP ConMon Strategy Guide §3.4                                                                                          | MISSING — no baseline-vs-current diff alerting                                                                                       | LOOP-I.I3 (regression subset)   |
| D8  | Multi-CSO tenancy                              | ⚠️ conditional  | MSP CSP-internal, multi-CSO 3PAO           | tracker web UI, per-CSO `out/<id>/`, tarball | FedRAMP CMP §1.3 (one POA&M per CSO); RFC-0014 (per-CSO submission identity); AU-2 / AU-3 audit-scope-per-tenant                                                              | MISSING — orchestrator has no `--cso` flag; tracker DB has no tenant column                                                          | LOOP-H.H3                       |
| D9  | Audit-trail integrity                          | ✅              | 3PAO, PMO, AO                              | Ed25519 signatures, RFC 3161 timestamps, hash chain in `out/INDEX.json` | NIST SP 800-53 Rev5 AU-9 (Protection of Audit Information); AU-10 (Non-repudiation); AU-11 (Audit Record Retention 3 years); FedRAMP CMP §5.5                                | HAVE — `core/sign.ts` (Ed25519), RFC 3161 timestamping, LOOP-A.A4 `INDEX.json` with sha256 chain; PARTIAL on AU-11 (no archive push) | HAVE (sign) + LOOP-H.H1 + H.H2  |
| D10 | Risk acceptance workflow                       | ✅              | AO, CSP CISO, 3PAO                         | tracker web UI, DB record, OSCAL POA&M `risk.status='deviation-approved'`, signed audit log | NIST SP 800-53 Rev5 RA-3, RA-7 (Risk Response); CA-5 (POA&M); FedRAMP Deviation Request Form; FedRAMP CMP §5.2                                                                | MISSING — no risk-acceptance route/page in tracker                                                                                   | LOOP-B.B3                       |
| D11 | Compensating-controls registry                 | ✅              | AO, 3PAO, CSP-internal                     | tracker web UI, DB, OSCAL `mitigating-factor`s | NIST SP 800-53 Rev5 §2.5 (Compensating Controls); FedRAMP Significant Change Notification §4 (compensating control reference)                                                | MISSING — no registry table or CRUD UI; `core/oscal-poam.ts` schema supports `mitigating-factors[]` but it's unpopulated              | LOOP-B.B4                       |
| D12 | SSP narrative library                          | ✅              | CSP control owners, 3PAO                   | tracker web UI, JSON library, OSCAL SSP `implementation-statement.description` | NIST SP 800-18 Rev1 §3.10 (SSP narrative requirement); OSCAL SSP `system-implementation`; FedRAMP SSP template                                                                | PARTIAL — `core/oscal-ssp.ts` auto-emits per-KSI narrative; no operator-overrideable library, no UI for editing/versioning           | LOOP-I.I4                       |
| D13 | Cross-framework crosswalk                      | RECOMMENDED     | CSP CISO, multi-framework 3PAO, agencies   | JSON crosswalk, .xlsx, OSCAL `mapping` extension | NIST SP 800-53 Rev5 Appendix H (crosswalk to ISO 27001, CMMC, etc.); CMMC 2.0 Assessment Guide; SOC 2 / ISO 27001 mappings published by AICPA / ISO                           | MISSING — no crosswalk module; baseline NIST 800-53 catalog ingested but adjacent frameworks not                                     | LOOP-I.I4 (extension, post-MVP) |
| D14 | Ticketing/CMDB/SIEM integration                | RECOMMENDED     | CSP-internal, ConMon engineers, IR teams   | webhook, REST, Jira/ServiceNow/Splunk/Sentinel adapters | NIST SP 800-137 §3.6 (operational integration); FedRAMP CMP §4.4 (workflow tracking); FedRAMP IR-4 (Incident Handling)                                                       | MISSING — no integration adapters in `tracker/` or `core/`                                                                            | LOOP-I.I2 (ticketing subset) + LOOP-G.G2 (SIEM/IR) |
| D15 | LLM-assisted PR / narrative generation         | RECOMMENDED     | CSP control owners, ConMon engineers       | tracker UI, git PRs                        | Industry trend; no FedRAMP mandate. NIST AI RMF v1.0 §3 (governance, transparency, provenance for AI-generated content)                                                       | MISSING — no LLM path in production code (REO Rule 1 forbids placeholder LLM output without provenance + human gate)                  | LOOP-I.I4 (narrative-suggest subset, post-MVP) |
| D16 | OpenAPI specification for the tracker          | RECOMMENDED     | Customer integrators, 3PAO automation, MSP | OpenAPI 3.1 YAML, generated TypeScript client | OpenAPI Initiative v3.1.0; Industry-standard for any API consumed externally                                                                                                 | MISSING — `tracker/server/routes/` is Express handlers without an OAS spec emission                                                  | LOOP-H.H3 (multi-CSO API contract) |
| D17 | Real-time alerting transport (companion to D3) | RECOMMENDED     | CSP-internal                               | webhook adapters, email, Slack, PagerDuty  | NIST SP 800-137 §3.2.4; FedRAMP CMP §4.2                                                                                                                                     | MISSING                                                                                                                              | LOOP-E.E1 + LOOP-I.I1 (notify) |
| D18 | Anomaly-detection model / baseline             | RECOMMENDED     | CSP-internal, ConMon engineers             | JSON baseline, tracker UI                  | NIST SP 800-137 §3.6.4                                                                                                                                                       | MISSING                                                                                                                              | LOOP-I.I3 (model subset)        |

> **Total: 18 artifacts. HAVE: 1 (D9 — partial AU-11). PARTIAL: 3
> (D1, D2, D12). MISSING: 14. Implementing slices span LOOP-B, LOOP-E,
> LOOP-G, LOOP-H, LOOP-I.**

---

## 3. Per-artifact detail

### D1 — Per-finding risk scoring (CVSS + EPSS + criticality + exposure)

- **Source citation.** NIST SP 800-30 Rev1 §3.2.2 "Risk Determination":
  *"determine risk by combining the likelihood of threat events …
  with the magnitude of impact."* CVSS v3.1 spec (FIRST.org):
  https://www.first.org/cvss/v3.1/specification-document. EPSS scoring
  model (FIRST.org): https://www.first.org/epss/model.
- **FedRAMP/OSCAL reference.** OSCAL POA&M `poam-item.props[]` and
  `risk.props[]` accept arbitrary namespaced properties; the FedRAMP
  CMP §4 directs CSPs to "track and report" per-finding risk in a
  prioritized manner. The FedRAMP POA&M Template `.xlsx` (LOOP-A.A4
  companion artifact) has columns for CVSS, severity, and risk rating.
- **What the CSP delivers vs what FedRAMP/3PAO authors.** CSP delivers
  the composite computed score per finding; 3PAO reviews scoring logic
  during SAP and tests sampled findings during assessment; PMO/AO consume
  the prioritized list as input to ATO + ConMon decisions.
- **Cross-references.** Drives D2 (deadline math), D4 (executive
  dashboard top-N), D5 (burndown sort order), D10 (acceptance flow
  attaches the score), B.B5 risk register.
- **Implementation.** `core/risk-score.ts` (new in LOOP-B.B1). Composite
  formula `0.4 * cvss_base + 0.3 * epss * 10 + 0.2 * criticality * 10 +
  0.1 * exposure * 10`; weights tunable via config; documented rationale.
  When CVSS is missing for a CVE-class finding,
  `risk_score.cvss_base_source = "REQUIRES-OPERATOR-INPUT"` per REO
  Rule 4 (CLAUDE.md) — never invent CVSS values.

### D2 — Remediation deadline math (CISA KEV / PAIN / IRV / LEV)

- **Source citation.** CISA Binding Operational Directive 22-01 (KEV
  Catalog) — https://www.cisa.gov/news-events/directives/binding-operational-directive-22-01:
  *"Remediate each vulnerability according to the timelines set forth
  in the [CISA-managed] vulnerability catalog"* — typically 21 days for
  newly-added KEV items. FedRAMP CMP §4.3 severity-baseline deadlines
  (Critical 30 / High 60 / Moderate 90 / Low 180). FedRAMP ConMon Strategy
  Guide §3.4 (PAIN/IRV/LEV table).
- **FedRAMP/OSCAL reference.** OSCAL POA&M `risk.deadline` (ISO-8601
  date) + `risk.props[]` carrying `deadline-source` provenance.
- **What the CSP delivers.** Computed deadline per finding with a typed
  source (`kev` | `fedramp-severity` | `pain-irv-lev` | `operator-override`).
- **Cross-references.** Builds on D1 (risk score). Feeds D5 (deadline
  pipeline) and D7 (anomaly: missed-deadline alert).
- **Implementation.** Extension of `core/risk-score.ts` in LOOP-B.B2.
  KEV path: 21 days from CISA's published `dueDate` (already ingested
  via `docs/cisa-kev.generated.json`). PAIN/IRV/LEV table sourced from
  FedRAMP ConMon Strategy + version-pinned. Fall-through to severity
  baseline. Operator override flows through tracker DB.

### D3 — Real-time alerting on emerging vulnerabilities

- **Source citation.** NIST SP 800-137 §3.2.4 (Information Analysis and
  Reporting): *"automated alerts when monitoring detects anomalies."*
  FedRAMP CMP §4.2: timely vulnerability awareness within the ConMon
  cycle.
- **FedRAMP/OSCAL reference.** No mandated wire format; webhook /
  email / Slack / PagerDuty are industry-standard transports.
- **What the CSP delivers.** Subscription / endpoint configuration in
  the tracker, signed alert events, audit log of dispatched alerts.
- **Cross-references.** Companion to D17 (transport adapters). Triggers
  from VDR-class collectors (`providers/*/vdr-scan.ts`) reconciling new
  CISA KEV publications against running inventory.
- **Implementation.** LOOP-I.I1 (executive-dashboard alert surface) +
  LOOP-E.E1 (ConMon monthly cadence). Production code path must never
  drop an alert silently; failed dispatches are logged + retried.

### D4 — Executive posture dashboard

- **Source citation.** Industry-standard. FedRAMP CMP §6 reporting cadence
  + NIST SP 800-137 §3.6 (ongoing reporting to senior leadership).
- **FedRAMP/OSCAL reference.** No specific schema. Backed by tracker DB
  views that aggregate findings, KSI pass-rates, KEV exposure counts,
  next-deliverable countdown.
- **What the CSP delivers.** Web UI page accessible to roles `exec`,
  `ao`, `ciso`. Snapshot PDF export for inclusion in board packets.
- **Cross-references.** Reads from D1 (top-N by composite score), D5
  (burndown summary), D6 (trend mini-charts), D9 (audit-trail integrity
  badge).
- **Implementation.** LOOP-I.I1 — new `tracker/client/src/pages/Dashboard.tsx`.
  RBAC enforced server-side.

### D5 — Finding burndown + deadline pipeline

- **Source citation.** FedRAMP CMP §4.4 (POA&M progress reporting), NIST
  SP 800-137 §3.6.2 (status reporting), OSCAL POA&M `findings[].related-observations[]`
  for time-series traceability.
- **FedRAMP/OSCAL reference.** POA&M observations + statuses across runs
  form the time-series basis. Per R2 in PRE-LOOP-A-RESEARCH-FINDINGS.md,
  monthly re-emission semantics support burndown views.
- **What the CSP delivers.** Time-series visualization grouped by
  severity and by deadline proximity; .xlsx export for offline review;
  JSON for downstream automation.
- **Cross-references.** Consumes D2 (deadline) and D1 (score). Feeds
  D6 (trend) and D14 (ticketing — auto-create tickets when items move
  to "deadline-approaching" bucket).
- **Implementation.** LOOP-I.I2. New tracker page + DB view aggregating
  per-month POA&M snapshots emitted by LOOP-E.E2.

### D6 — Longitudinal trend analysis

- **Source citation.** NIST SP 800-137 §3.6.3 trend analysis. FedRAMP
  ConMon Strategy Guide §3.5 annual-assessment trend section. FedRAMP
  Annual Assessment Plan template (`FedRAMP-Annual-Assessment-Template.docx`).
- **FedRAMP/OSCAL reference.** Per-run KSI pass/fail aggregations stored
  in tracker DB across runs; OSCAL AR `findings[].target.status`
  history.
- **What the CSP delivers.** Per-KSI pass-rate over time with statistical
  smoothing; per-control-family regression detection; per-asset-class
  failure-rate change.
- **Cross-references.** Feeds E.E3 (annual assessment package). Feeds
  D7 (anomaly: regression-flag from trend signal). Consumed by D4
  (executive dashboard mini-chart).
- **Implementation.** LOOP-I.I3 — new `core/trend-analysis.ts` reading
  per-run KSI evidence + tracker historical store.

### D7 — Anomaly detection (regression alerting)

- **Source citation.** NIST SP 800-137 §3.6.4: *"identify anomalies in
  data over time."* FedRAMP ConMon Strategy Guide §3.4.
- **FedRAMP/OSCAL reference.** No specific schema. Alert events carry
  a `provenance` block per REO standard.
- **What the CSP delivers.** Tracker-stored baselines per KSI per cloud;
  alert when a previously-passing rule starts failing OR when a metric
  exceeds n-sigma deviation from baseline.
- **Cross-references.** Uses D6 trend signal. Dispatches via D17
  transport. Surfaces in D4 dashboard.
- **Implementation.** LOOP-I.I3 (regression subset). Baseline is a real
  historical aggregate, never a hardcoded threshold (REO Rule 1.3).

### D8 — Multi-CSO tenancy

- **Source citation.** FedRAMP CMP §1.3 (one POA&M per CSO); RFC-0014
  (per-CSO submission identity); NIST SP 800-53 Rev5 AU-2/AU-3
  (per-tenant audit scope).
- **FedRAMP/OSCAL reference.** Each CSO has its own OSCAL SSP
  (`system-characteristics.system-name`), independent AP/AR/POA&M chain.
- **What the CSP delivers.** Per-CSO `out/<cso-id>/` artifact isolation;
  per-CSO tracker tenancy with RBAC scoping; per-CSO archive prefix in
  long-term storage; per-CSO OpenAPI client (D16).
- **Cross-references.** Affects every other artifact in this section —
  multi-tenant queries underpin D4/D5/D6/D7 cross-CSO views for MSP
  operators. Prerequisite for D16 (OpenAPI must include `cso_id` path
  parameter on all routes).
- **Implementation.** LOOP-H.H3. Orchestrator `--cso <id>` flag, tracker
  DB migration adding `cso_id` column to every table, RBAC scope per
  CSO, per-CSO archive prefix.

### D9 — Audit-trail integrity

- **Source citation.** NIST SP 800-53 Rev5 **AU-9** (Protection of
  Audit Information), **AU-10** (Non-repudiation), **AU-11** (Audit
  Record Retention — *"three (3) year retention period"* per FedRAMP
  Moderate baseline). FedRAMP CMP §5.5.
- **FedRAMP/OSCAL reference.** Ed25519 detached signatures over the
  manifest, RFC 3161 timestamping authority (`rfc3161-timestamp` role
  in `core/submission-bundle.ts` well-known catalog).
- **What the CSP delivers.** Signed manifest covering every emitted
  artifact (`core/sign.ts`), RFC 3161 timestamp, hash chain in
  `INDEX.json` (`core/submission-bundle.ts`), object-lock on archive
  (LOOP-H.H1 + H.H2).
- **Cross-references.** Every other artifact in SECTION D is covered
  by this signature scope when bundled — the integrity layer is
  cross-cutting.
- **Implementation.** HAVE for in-flight signing (LOOP-A.A4
  `core/sign.ts` + `core/submission-bundle.ts`). PARTIAL on AU-11
  long-term retention — LOOP-H.H1 (immutable archive push) and LOOP-H.H2
  (3-year retention enforcement) close the gap.

### D10 — Risk acceptance workflow

- **Source citation.** NIST SP 800-53 Rev5 **RA-3** (Risk Assessment),
  **RA-7** (Risk Response), **CA-5** (Plan of Action and Milestones).
  FedRAMP CMP §5.2 (deviation request process). FedRAMP Deviation
  Request Form (`FedRAMP-Deviation-Request-Form.docx`).
- **FedRAMP/OSCAL reference.** OSCAL POA&M `risk.status` enum includes
  `deviation-approved`; `risk.deadline` extension allowed when
  acceptance has a defined expiration; `risk.threat-ids[]` and
  `risk.mitigating-factors[]` (D11) link the acceptance to compensating
  controls.
- **What the CSP delivers.** Tracker route + UI for per-finding
  "Accept Risk"; signed audit record with accepted_by_user_id,
  business_justification, expiration_date, compensating_control_uuids.
  When expiration passes, acceptance is auto-revoked and the POA&M
  item re-opens.
- **Cross-references.** D11 is a prerequisite (the compensating
  control referenced in the acceptance must exist in the registry).
  D9 (signature) covers the acceptance record's integrity. The
  POA&M emitter (LOOP-A.A1) reads acceptance state and emits
  `risk.status='deviation-approved'`.
- **Implementation.** LOOP-B.B3 — `tracker/server/routes/risk-acceptance.ts`
  + DB migration + `tracker/client/src/pages/RiskAcceptance.tsx`.
  REO note: signatures are real human actions captured via the
  tracker audit log; system never auto-accepts.

### D11 — Compensating-controls registry

- **Source citation.** NIST SP 800-53 Rev5 §2.5 (use of compensating
  controls). FedRAMP Significant Change Notification §4 references
  compensating-control identifiers. NIST SP 800-53A Rev5 §2.6
  (assessment of compensating controls).
- **FedRAMP/OSCAL reference.** OSCAL POA&M `risk.mitigating-factors[]`
  (each entry is a structured `mitigating-factor` with `uuid`,
  `description`, `subjects[]`).
- **What the CSP delivers.** Tracker CRUD page for registry: title,
  description, NIST control IDs covered, implemented_by,
  signed_off_by, expires_at, evidence_url. Registry surfaces in D10
  acceptance flow when operator chooses compensating coverage.
- **Cross-references.** Required input to D10. Referenced by C.C7
  (Risk Management Strategy doc) and C.C6 (ConMon Strategy doc).
- **Implementation.** LOOP-B.B4 — `tracker/server/routes/compensating-controls.ts`
  + DB migration + `tracker/client/src/pages/CompensatingControls.tsx`
  + POA&M emitter extension to populate `risk.mitigating-factors[]`.

### D12 — SSP narrative library

- **Source citation.** NIST SP 800-18 Rev1 §3.10 (SSP narrative
  requirement). OSCAL SSP `control-implementation.implemented-requirements[].statements[].by-components[].description`.
  FedRAMP SSP template `Section 13` (Control Implementation).
- **FedRAMP/OSCAL reference.** Each NIST control's
  `implementation-statement.description` must be a prose narrative
  describing how the system meets the control.
- **What the CSP delivers.** Library of canonical narratives keyed
  by (control_id, system_type, parameter_overlay) with operator-
  editable overrides per (control, system). Reduces manual SSP
  authoring; the OSCAL SSP emitter (`core/oscal-ssp.ts`) pulls from
  the library when emitting `implemented-requirements[]`.
- **Cross-references.** Feeds `core/oscal-ssp.ts` (already HAVE).
  Consumed by C.C7 Risk Management Strategy + C.C1 Configuration
  Management Plan when those docs need narrative excerpts.
- **Implementation.** LOOP-I.I4 — `core/ssp-narrative-library.ts`
  + tracker UI for editing. PARTIAL today: per-KSI auto-narrative
  exists but no operator-overrideable library.

### D13 — Cross-framework crosswalk

- **Source citation.** NIST SP 800-53 Rev5 Appendix H (crosswalk to
  ISO 27001 and CSF v1.1). CMMC 2.0 Assessment Guide
  (https://dodcio.defense.gov/CMMC/). SOC 2 / ISO 27001 mapping
  published by AICPA and ISO. HITRUST CSF v11 mapping.
  StateRAMP Authorization Guide.
- **FedRAMP/OSCAL reference.** OSCAL `mapping` model (v1.1.2+ minor
  extension) — control-to-control mapping with confidence levels.
- **What the CSP delivers.** A `crosswalk.json` per target framework
  + a tracker UI showing "controls satisfied by FedRAMP evidence
  for framework X." Allows the same KSI/control evidence to serve
  multiple authorizations.
- **Cross-references.** No FedRAMP dependency; orthogonal to the
  authorization package. Consumes the same KSI evidence emitted by
  `providers/*/`.
- **Implementation.** LOOP-I.I4 extension (post-MVP). Listed here
  because customer demand for FedRAMP-and-X dual-authorization is
  growing fast and this is the cleanest place to plan for it.

### D14 — Ticketing / CMDB / SIEM integration

- **Source citation.** NIST SP 800-137 §3.6 (operational integration
  of monitoring data). FedRAMP CMP §4.4 (workflow tracking). FedRAMP
  IR-4 (Incident Handling).
- **FedRAMP/OSCAL reference.** No mandated schema; standard webhooks
  + REST adapters (Jira REST API v3, ServiceNow Now Platform REST,
  Splunk HEC, Microsoft Sentinel Logic Apps connector).
- **What the CSP delivers.** Per-target adapter that creates a
  ticket / CMDB entry / SIEM event when a finding crosses a configured
  threshold (e.g. new High severity + KEV-matched + externally-
  accessible). Adapters live in `tracker/server/adapters/`.
- **Cross-references.** Downstream of D2 (deadline) and D5 (burndown
  pipeline). For SIEM specifically, also tied to LOOP-G.G2 AFR-ICP
  (Incident Communications Procedures — incident events flow into
  SIEM as security signals).
- **Implementation.** LOOP-I.I2 (ticketing subset) + LOOP-G.G2
  (SIEM + IR integration). REO Rule 1.4: adapter SDK calls go through
  the real third-party SDK (Atlassian, ServiceNow, Splunk), never
  mocked in production.

### D15 — LLM PR generation (narrative + remediation suggestions)

- **Source citation.** No FedRAMP mandate. NIST AI RMF v1.0 §3
  (governance, transparency, provenance for AI-generated content);
  governs how the system handles AI-authored output without violating
  REO Rule 1.5 (silent fallback masking missing data) or Rule 1.7
  ("synthetic" emit fields without operator opt-in).
- **What the CSP delivers.** A constrained suggestion surface in the
  tracker (e.g. "Suggest SSP narrative for AC-2(1)") that produces
  a draft, marks it `provenance.source = 'llm:<model>:<prompt-hash>'`,
  and requires explicit human accept-or-edit before it lands in any
  emitted artifact. Never auto-applies. Never auto-signs.
- **Cross-references.** Feeds D12 (SSP narrative library) as a
  suggestion source. Drives a PR-style review UI in tracker
  (analogous to GitHub PRs) where the human review and audit log
  are first-class.
- **Implementation.** LOOP-I.I4 extension (post-MVP). REO note: the
  LLM call site must record model name + prompt hash + temperature +
  response in the audit log; the operator's accept/edit action is the
  signed "this is real authored content" event.

### D16 — OpenAPI specification for the tracker

- **Source citation.** OpenAPI Initiative v3.1.0 spec
  (https://spec.openapis.org/oas/v3.1.0). Industry-standard for any
  externally-consumed API.
- **What the CSP delivers.** `tracker/api/openapi.yaml` describing
  every route (findings, evidence, POA&M, risk-acceptance,
  compensating-controls, IIW, RoE, audit log, multi-CSO routes),
  with per-route auth requirements, request/response schemas, and
  example payloads. Generated TypeScript and Python clients for
  customer integrators and 3PAO automation.
- **Cross-references.** Required prerequisite for D14 ticketing
  adapters that consume tracker data, and for D8 multi-CSO MSP
  operator scripts. Closely coupled to D8 (every route gains a
  `cso_id` path parameter or scope claim).
- **Implementation.** LOOP-H.H3 as the multi-CSO API contract.
  Generated from route handlers (single source of truth, no drift).

### D17 — Real-time alerting transport (companion to D3)

- **Source citation.** Same as D3 (NIST SP 800-137 §3.2.4, FedRAMP
  CMP §4.2). Transport choice is operator-configurable.
- **What the CSP delivers.** Adapters under `tracker/server/transports/`
  for webhook (generic), email (SMTP), Slack (Block Kit), PagerDuty
  (Events API v2). Each dispatch is recorded in the signed audit log
  with target + payload hash.
- **Cross-references.** Driven by D3 (event source), D7 (anomaly),
  D5 (deadline-approaching trigger).
- **Implementation.** LOOP-I.I1 + LOOP-E.E1. Real third-party SDK in
  production paths (REO Rule 1.4); failure modes produce retry-able
  audit events, never silent drops.

### D18 — Anomaly-detection model / baseline

- **Source citation.** NIST SP 800-137 §3.6.4 (anomaly identification
  via baselined data).
- **What the CSP delivers.** A per-(KSI, cloud, asset-class) baseline
  computed over the last N runs (default 12 months), stored in tracker
  DB; per-run delta is compared against baseline; deviations above
  configured thresholds raise events to D17.
- **Cross-references.** Built on D6 (trend store). Drives D7 (alert).
- **Implementation.** LOOP-I.I3 — `core/trend-analysis.ts` extension.
  REO note: baseline is a real historical aggregate stored in the
  tracker; no hardcoded thresholds in production code.

---

## 4. Acceptance criteria for SECTION D

SECTION D is **complete** when ALL of the following are true:

1. **D1 ships under LOOP-B.B1.** `core/risk-score.ts` emits composite
   score per finding; POA&M `risk.props` carries the score + factors;
   tests cover formula correctness, fallback behavior, REQUIRES-
   OPERATOR-INPUT marker on missing CVSS; lint:no-stubs returns 0.
2. **D2 ships under LOOP-B.B2.** KEV/PAIN/IRV/LEV deadline math live;
   POA&M `risk.deadline` reflects the computed date with provenance.
3. **D3 + D17 ship under LOOP-I.I1 + LOOP-E.E1.** Real-time alert
   pipeline running with at least webhook + email transports; signed
   audit log of every dispatch; retry-on-failure behavior; no silent
   drops in production paths.
4. **D4 ships under LOOP-I.I1.** Executive posture dashboard renders
   in tracker; RBAC enforced; PDF snapshot export works.
5. **D5 ships under LOOP-I.I2.** Burndown + deadline pipeline view
   reads from per-month POA&M snapshots (LOOP-E.E2 stores them).
6. **D6 + D18 ship under LOOP-I.I3.** Per-KSI pass-rate trend store
   populated across at least 3 historical runs; tracker page renders;
   .xlsx + JSON export works.
7. **D7 ships under LOOP-I.I3.** Regression alerting fires when a
   previously-passing rule flips to failing; alert routes through D17.
8. **D8 ships under LOOP-H.H3.** Orchestrator `--cso <id>` works;
   tracker per-CSO isolation enforced; per-CSO archive prefix
   verified; per-CSO `out/<id>/` directories cleanly separated.
9. **D9 stays HAVE.** AU-9 + AU-10 already shipped (signing chain).
   AU-11 closes when LOOP-H.H1 (immutable archive push) + LOOP-H.H2
   (3-year retention enforcement) ship.
10. **D10 ships under LOOP-B.B3.** Risk-acceptance workflow with
    signed audit record, expiration enforcement, POA&M `risk.status`
    integration; RBAC restricting accept-risk to specific roles.
11. **D11 ships under LOOP-B.B4.** Compensating-controls registry
    with CRUD UI; POA&M `mitigating-factors[]` populated from
    registry references.
12. **D12 ships under LOOP-I.I4.** SSP narrative library with
    operator overrides; SSP emitter pulls from library; PARTIAL →
    HAVE.
13. **D13 ships under LOOP-I.I4 extension** (post-MVP, not required
    for first GA Moderate authorization). Mapping artifact exists
    for at least one adjacent framework (target: SOC 2).
14. **D14 ships under LOOP-I.I2 + LOOP-G.G2.** At least one
    ticketing adapter (Jira or ServiceNow) and one SIEM adapter
    (Splunk or Sentinel) live with real-SDK calls.
15. **D15 ships under LOOP-I.I4 extension** (post-MVP). Tracker
    "Suggest narrative" surface with explicit human accept/edit gate;
    `provenance.source = 'llm:<model>:<prompt-hash>'` recorded in
    audit log.
16. **D16 ships under LOOP-H.H3.** OpenAPI 3.1 YAML emitted from
    tracker routes; generated TypeScript client tested; multi-CSO
    `cso_id` path param threading consistent across all routes.
17. **CI gates green:** `npm run lint:no-stubs`, `npm run check:provenance`,
    `npm run check:coverage-regression` all 0 across LOOP-B + LOOP-I +
    LOOP-H deliverables.
18. **CHANGELOG entries:** Each slice (B.B1, B.B2, B.B3, B.B4, E.E1,
    H.H1, H.H2, H.H3, I.I1, I.I2, I.I3, I.I4, G.G2) lands an "Added"
    entry naming the artifacts it satisfies in this section.

---

## 5. Open questions

1. **D13 OSCAL `mapping` model maturity.** OSCAL v1.1.2 does not yet
   include a finalized cross-framework mapping schema. The NIST OSCAL
   roadmap mentions a `mapping` model under design. If it doesn't land
   by GA Moderate (late 2026), D13 falls back to a custom JSON schema
   under `cloud-evidence/docs/crosswalks/<framework>.json` with our own
   namespace and a documented forward-migration plan.

2. **D15 LLM provenance contract under FedRAMP scrutiny.** Whether the
   3PAO will accept LLM-suggested SSP narrative — even with explicit
   human-accept gate + provenance — is unverified. Conservative
   posture: ship D15 as opt-in only, default-disabled, and treat any
   3PAO objection as a config switch that disables the surface entirely.
   We will not deploy D15 into the first GA Moderate authorization
   without explicit PMO + 3PAO sign-off recorded in the tracker audit
   log.

3. **D7 anomaly threshold defaults.** NIST SP 800-137 leaves thresholds
   to organizational risk tolerance. Default sigma values (e.g.
   3-sigma for hard alert, 2-sigma for warning) are industry-norm but
   not FedRAMP-mandated. Initial defaults will be operator-tunable via
   config.yaml; we will revise after the first 6-month ConMon cycle
   produces real baseline distributions.

4. **D14 SIEM-vs-ticketing precedence on incident events.** When an
   incident triggers BOTH a ticket (D14 ticketing) AND a SIEM event
   (D14 SIEM) AND an IR notification (LOOP-G.G2 AFR-ICP), the order
   of dispatch matters for audit-trail consistency. Current plan:
   audit log records the chronological sequence; downstream consumers
   reconcile against the audit log's signed ordering. Verify with
   3PAO during pilot whether this satisfies AU-10 non-repudiation.

5. **D8 multi-CSO + D16 OpenAPI authentication model.** Multi-CSO
   adds a `cso_id` to every API path; the authentication model
   (per-CSO JWT vs scope claim vs path-parameter access control)
   has security implications. Decision deferred to LOOP-H.H3 build
   time, after a short threat-model review.

6. **D2 PAIN/IRV/LEV table version-pinning.** The FedRAMP ConMon
   Strategy publishes the PAIN/IRV/LEV deadline table but its versioning
   discipline historically has been informal. We pin the version we
   consume in a committed `docs/fedramp-conmon-deadline-table.generated.json`
   and document the source URL + retrieval timestamp; any change will
   produce a clean version bump in the deadline-source provenance.

7. **D6 trend-store size growth.** Per-KSI, per-asset, per-run history
   over 3-year AU-11 retention will be sizeable (estimate: ~10 GB per
   CSO per year at moderate deployments). LOOP-H.H1's archive store
   handles the immutable record; LOOP-I.I3 only needs the hot recent
   12 months in the tracker DB. Boundary between hot and cold tiers
   to be finalized during LOOP-I.I3 build.

8. **D11 acceptance + compensating-control reconciliation across
   monthly POA&M runs.** When a finding is accepted in month N with
   compensating-control X, and month N+1's scan re-detects the same
   underlying issue: does the acceptance carry over automatically,
   or does it require explicit re-affirmation? Initial plan: carry
   over until expiration_date, with a re-affirmation prompt at the
   half-life mark. Verify with FedRAMP CMP guidance.

---

## Appendix — slice mapping summary

| Loop  | Slice | SECTION D artifacts delivered                                         |
|-------|-------|-----------------------------------------------------------------------|
| B     | B.B1  | D1 (per-finding risk scoring)                                         |
| B     | B.B2  | D2 (remediation deadline math)                                        |
| B     | B.B3  | D10 (risk acceptance workflow)                                        |
| B     | B.B4  | D11 (compensating-controls registry)                                  |
| E     | E.E1  | D3 + D17 (real-time alerting + transport)                             |
| G     | G.G2  | D14 (SIEM + IR integration subset — AFR-ICP)                          |
| H     | H.H1  | D9 (AU-11 retention — immutable archive push)                         |
| H     | H.H2  | D9 (AU-11 retention enforcement)                                      |
| H     | H.H3  | D8 (multi-CSO tenancy) + D16 (OpenAPI spec)                           |
| I     | I.I1  | D3 + D4 + D17 (alerting + executive dashboard + transport)            |
| I     | I.I2  | D5 + D14 (burndown + ticketing subset)                                |
| I     | I.I3  | D6 + D7 + D18 (trend + anomaly + baseline model)                      |
| I     | I.I4  | D12 + D13 + D15 (SSP library + crosswalk + LLM PR generation)         |
| HAVE  | A.A4 + sign.ts | D9 (AU-9 + AU-10 in-flight signing chain)                    |

Total slices implicated: 13 slices across LOOP-B (4), LOOP-E (1),
LOOP-G (1), LOOP-H (3), LOOP-I (4), plus already-HAVE work for D9
(AU-9 + AU-10). LOOP-I is the heaviest contributor at 4 slices /
8 artifacts.
