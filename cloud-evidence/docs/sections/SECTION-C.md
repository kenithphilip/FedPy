# SECTION C — Post-authorization continuous monitoring (ConMon)

> **Requirements-layer spec.** Self-contained mapping of every Post-authorization
> ConMon artifact (C1–C13) to its source obligation, format, consumer, current
> FedPy implementation status, and the loop.slice that delivers it.
>
> **Scope:** What the CSP must produce *after* the initial authorization is
> granted — monthly cadence deliverables, annual cadence deliverables, ad-hoc
> deviations / significant changes, and long-term retention. Authorization-time
> deliverables (SSP, SAP, AP, SAR, initial AR, RoE) are covered in SECTION A.
> 3PAO assessor-experience tooling is covered in SECTION B. Stakeholder
> dashboards are covered in SECTION D.

---

## 1. Purpose

FedRAMP authorization is **not a one-time event**. Once the Authorizing Official
(AO) issues an Authority to Operate (ATO), the Cloud Service Provider (CSP)
enters a continuous monitoring (ConMon) regime that lasts for the operational
life of the Cloud Service Offering (CSO). The ConMon regime is the operational
nervous system of FedRAMP: it is how the authorization stays current, how new
risk is detected, how remediation is tracked, and how the AO retains confidence
in the security posture month after month.

The post-authorization obligation is governed by:

- **NIST SP 800-53 Rev 5 — Control CA-7 (Continuous Monitoring).** Establishes
  the requirement for an ongoing monitoring strategy and program.
- **NIST SP 800-137 — Information Security Continuous Monitoring (ISCM) for
  Federal Information Systems and Organizations.** The methodology base.
- **FedRAMP Continuous Monitoring Strategy Guide (Rev 5).** The CSP-facing
  implementation guide.
- **FedRAMP Rev5 Playbook — Continuous Monitoring section** (csp/continuous-monitoring/overview/).
  The current operational playbook (the source we cite for monthly cadence + USDA
  Connect.gov repository — see R2 in `PRE-LOOP-A-RESEARCH-FINDINGS.md`).
- **FedRAMP Configuration Management Plan (CMP) Template.** Defines the
  Significant Change Notification (SCN) lifecycle.
- **FedRAMP Annual Assessment Guidance.** Defines the annual reauthorization
  package contents (annual AR, annual SSP review, IRP test AAR, ISCP test AAR,
  annual PenTest).
- **CISA Binding Operational Directive 22-01 (Known Exploited Vulnerabilities
  Catalog).** Establishes a 21-day mandatory remediation window for federal
  systems for any CVE on the CISA KEV catalog — this overrides the FedRAMP
  severity-based remediation baseline when a finding maps to a KEV CVE.
- **NIST SP 800-37 Rev 2 (Risk Management Framework), Step 7 (Monitor).**
  The Authorizing Official's continuous-authorization decision context.
- **OSCAL v1.1.2 Plan of Action and Milestones model.** The wire format for
  POA&M re-submission (RFC-0024 mandates OSCAL JSON for 20x).
- **FedRAMP RFC-0014 (FedRAMP 20x Phase Two for Moderate).** Truly automated
  + opinionated validation of Key Security Indicators as the 20x continuous
  validation standard.

**Why this exists in the FedRAMP framework.** The FISMA Modernization Act of
2014 obligates federal agencies to maintain *continuous* security posture
visibility for any system handling federal data. FedRAMP operationalizes that
obligation for cloud-service consumption: instead of each agency re-assessing
each CSP every year, the FedRAMP PMO + 3PAO + AO triad maintains continuous
authorization, and the CSP keeps the package current via monthly submissions.
The bargain is: "We grant ATO once + accept your continuous evidence" — the CSP
keeps the evidence flowing.

For a 20x Moderate CSO running on this audit-agent pipeline, the ConMon regime
translates to a small set of repeating jobs:

- **Monthly** — POA&M, vulnerability scans, ConMon analysis report, KEV
  remediation tracking, SCNs (when changes occur), Deviation Requests
  (when needed).
- **Annual** — Annual Assessment package (re-attestation by the 3PAO),
  Annual SSP review, IRP/ISCP test + AAR, Annual Penetration Test, AFR-FSI
  inbox attestation.
- **Continuous** — Long-term immutable archive of every deliverable for the
  3-year AU-11 audit retention window (and beyond, per agency contract).

SECTION C catalogues every one of those artifacts (C1 through C13), cites its
authority, names the consumer, names the format, and pins it to the
loop.slice that ships it.

---

## 2. Artifact catalogue

| ID | Artifact | Required | Consumer(s) | Format(s) | Source obligation | FedPy status | Implementing slice |
|---|---|---|---|---|---|---|---|
| **C1** | Monthly POA&M | ✅ | FedRAMP PMO; AO; Federal Inbox (via USDA Connect.gov) | OSCAL POA&M v1.1.2 JSON + XML; FedRAMP POA&M .xlsx | OSCAL v1.1.2 plan-of-action-and-milestones schema; FedRAMP Rev5 ConMon Playbook (Overview); RFC-0024 | **PARTIAL** — `core/oscal-poam.ts` (LOOP-A.A1) ships authorization-time POA&M (OSCAL JSON+XML, signed); monthly delta workflow + .xlsx companion + Connect.gov push not yet shipped | **LOOP-E.E2** (monthly POA&M delta workflow); **LOOP-A.A4** (.xlsx companion via bundler well-known catalogue) |
| **C2** | Monthly vulnerability scans | ✅ | 3PAO; FedRAMP PMO; AO; Federal Inbox | Raw scanner output (XML/CSV/JSON per scanner) + signed evidence envelope + KEV reconciliation JSON | FedRAMP Rev5 ConMon Vulnerability Scanning Playbook; BOD 22-01 (KEV 21-day); 800-53 RA-5 | **HAVE (cloud-side)** — `providers/{aws,gcp,azure}/vdr-scan.ts` collectors emit per-cloud Defender / Inspector / Security Command Center scan evidence + CISA KEV join (every cloud at parity, INV-S5 closed Azure VDR reconcile); monthly orchestrator schedule + push to Connect.gov MISSING | **LOOP-E.E1** (monthly ConMon report aggregates scans); **LOOP-E.E2** (push to repo); existing `providers/*/vdr-scan.ts` continues to source the evidence |
| **C3** | Monthly ConMon analysis report | ✅ | FedRAMP PMO; AO | PDF + Markdown + structured JSON | FedRAMP ConMon Playbook (monthly report structure); NIST 800-137 ISCM analysis-phase | **MISSING** — no aggregator today; per-month POA&M + scans + KEV + SCN events not yet collated | **LOOP-E.E1** (`core/conmon-report.ts`) |
| **C4** | Significant Change Notification (SCN) | ⚠️ conditional (on event) | FedRAMP PMO; AO | Structured JSON classifier output (HAVE today) + formal .docx notification (MISSING) | FedRAMP CMP Template (SCN procedure); SCN-CSO-EOC / EVA / HMR / INF / REC MUST entries (R1 AFR family classification) | **PARTIAL** — `core/scn-classifier.ts` exists (emits `scn-classification.json`, evaluates change against CMP categories); formal .docx notification + audit-record archive not yet shipped | **LOOP-E.E6** (`core/scn-doc.ts` .docx via OOXML); existing classifier feeds it |
| **C5** | Deviation Request (DR) | ⚠️ conditional (on event) | FedRAMP PMO; AO | .docx (FedRAMP DR template format) | FedRAMP Deviation Request Guidance; ConMon Strategy Guide §6 | **MISSING** — no DR emitter; no tracker workflow | **LOOP-E.E5** (`core/deviation-request.ts` .docx + tracker trigger UI) |
| **C6** | Annual Assessment package | ✅ | 3PAO; FedRAMP PMO; AO | Signed tarball with annual OSCAL AR + delta-from-prior-annual + IRP AAR + ISCP AAR + annual PenTest + annual SSP review | FedRAMP Annual Assessment Guidance; NIST 800-37 Rev2 Step 7 (Monitor); OSCAL v1.1.2 assessment-results | **MISSING** — LOOP-A ships an authorization-time AR + bundler; annual cadence aggregator + 12-month delta + bundler-orchestration not yet shipped | **LOOP-E.E3** (`core/annual-assessment.ts`); reuses LOOP-A.A4 bundler |
| **C7** | Annual SSP review / update | ✅ | 3PAO; FedRAMP PMO; AO | OSCAL SSP delta (JSON+XML) + Markdown diff report | NIST 800-53 PL-2; FedRAMP Annual Assessment Guidance | **PARTIAL** — `core/oscal-ssp.ts` (LOOP-A) emits the SSP; year-over-year delta tracking + review workflow MISSING | **LOOP-E.E4** (extends `core/oscal-ssp.ts` with delta-tracking; new `core/ssp-annual-review.ts`) |
| **C8** | Annual IRP/ISCP test + AAR | ✅ | 3PAO; FedRAMP PMO; AO | .docx AAR per template + structured JSON for tracker | NIST 800-53 IR-3 (IRP test); CP-4 (ISCP test); FedRAMP IRP + ISCP templates | **MISSING** — neither IRP nor ISCP test runner ships today; only collector evidence (`providers/*/backup.ts` for RPL family; `providers/*/iam.ts` for INR family) is wired | **LOOP-E.E7** (`core/annual-test-runner.ts`); depends on **LOOP-C.C2** (ISCP doc template) + **LOOP-C.C3** (IRP doc template) for the AAR template format |
| **C9** | Annual Penetration Test | ✅ | 3PAO; FedRAMP PMO; AO | .docx PenTest report + OSCAL-extended ingest JSON for AR/POA&M flow | FedRAMP Penetration Test Guidance; NIST 800-53 CA-8; OSCAL v1.1.2 assessment-results extended with finding.target | **MISSING** — no ingest pipeline; no 3PAO upload flow; findings can't yet flow into the OSCAL AR/POA&M | **LOOP-K.K1** (`core/pentest-ingest.ts` schema + tracker upload UI); **LOOP-K.K2** (mapping to AR test-result-objects) |
| **C10** | KEV remediation tracking | ✅ | FedRAMP PMO; AO; CSP-internal | OSCAL POA&M `risk.deadline` with `source='kev'` (21d from CISA dueDate); monthly KEV exposure count in C3 report | CISA Binding Operational Directive 22-01; CISA KEV Catalog (machine-readable JSON) | **PARTIAL** — `providers/*/vdr-scan.ts` joins live scan output against committed `docs/cisa-kev.generated.json` (HAVE); KEV-aware deadline math + POA&M risk.deadline source flag MISSING | **LOOP-B.B2** (deadline math `computeDeadline()`: KEV 21d, PAIN/IRV/LEV from ConMon Strategy table, severity fallback); flows into C1 monthly POA&M |
| **C11** | AFR-FSI (FedRAMP Security Inbox) | ✅ | FedRAMP PMO (inbound) + CSP (outbound) | Email endpoint (verified) + inbox config JSON + receipt log + completed-action log + monthly attestation | FedRAMP AFR-FSI family (R1: 6 CSO MUSTs — FSI-CSO-CRA / EMR / INB / NOC / RCV / TFG); RFC-0006 AFR catalog | **MISSING** — no inbox endpoint, no routing, no receipt log, no action tracker | **LOOP-G.G1** (`core/afr-fsi.ts` + tracker DB tables `fsi_inbox_config`, `fsi_message_log`, `fsi_required_actions`) |
| **C12** | AFR-CCM (20x ConMon reporting) | ✅ | FedRAMP PMO; AO; agency customers | Report-availability JSON + feedback-mechanism webhook + next-report-date publication + quarterly-meeting registration link | FedRAMP AFR-CCM family (R1: 4 CSP-actionable OAR + QTR MUSTs — CCM-OAR-AVL / FBM / NRD + CCM-QTR-REG); RFC-0014 | **MISSING** — none of the OAR/QTR publication surfaces exist | **LOOP-G.G6** (`core/afr-ccm.ts`); tightly coupled with **LOOP-E** (it publishes what LOOP-E produces) |
| **C13** | Long-term retention (AU-11) | ✅ | FedRAMP PMO; AO; CSP-internal; future-3PAOs | Immutable object-locked archive (S3 Glacier Deep Archive / GCS Coldline / Azure Archive); annual retention attestation report (JSON + Markdown) | NIST 800-53 AU-11 (3 years minimum); FedRAMP contractual retention (often 6+ years per agency); CISA Cyber Incident Reporting Council guidance | **MISSING** — no archive push; no object-lock verification; no retention attestation report | **LOOP-H.H1** (`core/archive-push.ts`); **LOOP-H.H2** (`core/retention-policy.ts`) |

**Legend**
- **Required ✅** — Mandatory at FedRAMP Moderate per cited authority.
- **Required ⚠️ conditional** — Required only when a triggering event occurs (e.g.,
  a significant change has happened; a control couldn't be implemented as
  planned).
- **HAVE** — Code ships in `main`, REO-compliant, signed evidence path.
- **PARTIAL** — Code ships some of the artifact but not the full deliverable
  (typically: authorization-time emitter exists; ConMon cadence wrapper missing).
- **MISSING** — Nothing ships yet; future loop slice covers it.

---

## 3. Per-artifact detail

### C1 — Monthly POA&M

**Source citation.** FedRAMP Rev5 Playbook — ConMon Overview
(https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/overview/):
> "Each month, the CSP uploads an up-to-date POA&M and inventory, along with raw
> vulnerability scan files (when required by agreements with agency customers)
> and reports to the secure repository."

> "CSPs with cloud offerings categorized at LI-SaaS, Low, or Moderate use the
> FedRAMP secure repository on USDA Connect.gov for posting ConMon deliverables.
> CSPs with cloud offerings categorized at High use their own secure repository."

**FedRAMP template / OSCAL schema reference.** OSCAL Plan of Action and
Milestones v1.1.2 (`oscal_poam_schema.json`,
https://github.com/usnistgov/OSCAL/releases/tag/v1.1.2). RFC-0024 mandates
OSCAL JSON for 20x submissions. The legacy FedRAMP POA&M Template
(`FedRAMP-POAM-Template.xlsx`) remains accepted by USDA Connect.gov in
parallel; LOOP-A.A4 bundler emits both for safety (R2 decision).

**What the CSP delivers vs what FedRAMP/3PAO authors.** CSP delivers the
entire document monthly. The 3PAO and PMO read it; they do not author it. The
AO uses it to maintain (or revoke) the authorization decision.

**Cross-references.**
- **C2 (Monthly vuln scans)** — scan findings are the principal *source* of new
  POA&M items.
- **C10 (KEV remediation tracking)** — KEV-flagged findings drive a 21-day
  deadline override on the relevant POA&M items.
- **C3 (Monthly ConMon report)** — summarizes the month's POA&M deltas.
- **B.B3 (Risk acceptance workflow)** — feeds `risk.status = 'deviation-approved'`
  back into the POA&M.

---

### C2 — Monthly vulnerability scans

**Source citation.** FedRAMP Rev5 Playbook — ConMon Vulnerability Scanning
(https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/vulnerability-scanning/):
> "FedRAMP vulnerability scanning guidelines require at least monthly scans of
> 100% of inventory components."

> "The scan output must display all scan findings with a low risk or higher in
> a structured, machine-readable format (such as XML, CSV, or JSON)."

> "FedRAMP recommends that externally accessible (outside of the boundary,
> without the use of a VPN) system components do not use this sampling
> methodology; 100% of externally accessible system components should be
> scanned." (See R4 in `PRE-LOOP-A-RESEARCH-FINDINGS.md`.)

**FedRAMP template / OSCAL schema reference.** Format is scanner-native (Nessus
.nessus XML, Qualys CSV, Defender for Cloud JSON, etc.). FedRAMP accepts any
structured machine-readable format. Per CISA BOD 22-01, the scan output must be
reconciled against the CISA KEV catalog before submission.

**What the CSP delivers vs what FedRAMP/3PAO authors.** CSP delivers raw scan
output + KEV reconciliation. 3PAO validates that the scan covered 100% of
externally-accessible inventory and the AO-approved sample of internal-only
inventory (F.F3 sampling methodology). FedRAMP PMO + AO consume the reconciled
output.

**Cross-references.**
- **C1 (Monthly POA&M)** — scan findings flow into POA&M items.
- **C10 (KEV remediation tracking)** — KEV reconciliation drives 21-day
  deadlines.
- **F.F3 (Sample selection methodology)** — defines what "100% of inventory"
  resolves to when sampling internal-only assets.
- **R4 finding in `PRE-LOOP-A-RESEARCH-FINDINGS.md`** — the canonical sampling
  rule source.

---

### C3 — Monthly ConMon analysis report

**Source citation.** FedRAMP Continuous Monitoring Strategy Guide; FedRAMP
Rev5 Playbook ConMon section. NIST SP 800-137 §3 (ISCM Process) defines the
analyze + report phases that feed AO continuous-authorization decisions.

**FedRAMP template / OSCAL schema reference.** FedRAMP-published monthly
ConMon report template (PDF + structured tables). No OSCAL schema is mandated
for the narrative wrapper; the OSCAL POA&M and OSCAL Assessment Results models
are referenced by the report.

**What the CSP delivers vs what FedRAMP/3PAO authors.** CSP authors the
narrative. 3PAO does not. AO reads it as the executive summary of the month.

**Cross-references.**
- Aggregates **C1 (POA&M deltas)**, **C2 (scan results)**, **C4 (SCN events)**,
  **C10 (KEV exposure)** into a single executive-format report.

---

### C4 — Significant Change Notification (SCN)

**Source citation.** FedRAMP Configuration Management Plan (CMP) Template +
the AFR-SCN family in `FRMR.documentation.json` (R1 classification: 11 MUSTs at
Moderate, 5 CSO-side). NIST 800-53 CM-3 (Configuration Change Control) is the
control basis.

**FedRAMP template / OSCAL schema reference.** FedRAMP SCN template (.docx
format). Our `core/scn-classifier.ts` emits a structured JSON classification
output and Markdown summary; the formal .docx notification is the format
FedRAMP PMO consumes for the official record.

**What the CSP delivers vs what FedRAMP/3PAO authors.** CSP authors. 3PAO is
notified for SCNs that materially affect the assessment baseline. AO reviews
and authorizes the change or withholds approval.

**Cross-references.**
- **AFR-SCN family in `docs/AFR-FAMILY-CLASSIFICATION.md`** — the 5 CSO MUSTs
  (Evaluate Changes, Historical Notifications, Human-and-Machine-Readable,
  Required Information, Audit Records).
- **C13 (Long-term retention)** — SCN audit records must be retained under
  AU-11.

---

### C5 — Deviation Request (DR)

**Source citation.** FedRAMP Deviation Request Form + Guidance (sometimes
called Deviation Request Form / DRF or Risk Adjustment Request). NIST 800-53
CA-5 (Plan of Action and Milestones) §c provides the control basis for
documenting deviations from planned control implementation.

**FedRAMP template / OSCAL schema reference.** FedRAMP DR template
(`FedRAMP-Deviation-Request-Form.docx`). No OSCAL schema; the form is .docx
historically. The structured fields (justification, compensating control
reference, expiration) flow back into the OSCAL POA&M as
`risk.mitigating-factors[]` once approved.

**What the CSP delivers vs what FedRAMP/3PAO authors.** CSP authors and
requests. 3PAO co-signs (validation that the compensating control is real).
PMO + AO approve or reject.

**Cross-references.**
- **B.B3 (Risk acceptance workflow)** — once a DR is approved, the
  corresponding risk gets `risk.status = 'deviation-approved'` in the POA&M.
- **B.B4 (Compensating-controls registry)** — DR justifications point to
  registered compensating controls.
- **C1 (Monthly POA&M)** — approved DRs flow back into the POA&M risk section.

---

### C6 — Annual Assessment package

**Source citation.** FedRAMP Annual Assessment Guidance; NIST SP 800-37 Rev 2
§ 3.7 Monitor Step (Task M-6, Ongoing Authorization). The package re-attests
that the CSO continues to meet its baseline at the end of each 12-month
authorization period.

**FedRAMP template / OSCAL schema reference.** OSCAL Assessment Results v1.1.2
(annual edition, with `metadata.last-modified` reflecting the annual review
date). Bundled with the annual SSP review (C7), the IRP + ISCP test AARs (C8),
and the annual PenTest report (C9), all wrapped via the LOOP-A.A4 submission
bundler (well-known catalogue role `annual-assessment-package`).

**What the CSP delivers vs what FedRAMP/3PAO authors.** CSP supplies operational
evidence (inventory, control implementation state, monthly POA&M trail). 3PAO
re-tests + signs the annual AR. PMO + AO consume the bundle as the basis for
continued authorization.

**Cross-references.**
- **C7 (Annual SSP review)** — included in the C6 bundle.
- **C8 (Annual IRP/ISCP test AAR)** — included in the C6 bundle.
- **C9 (Annual PenTest)** — included in the C6 bundle.
- **LOOP-A.A4 submission bundler** — the packaging mechanism.

---

### C7 — Annual SSP review/update

**Source citation.** NIST 800-53 PL-2 (System Security Plan) — requires
review and update on an organization-defined frequency, with FedRAMP setting
that frequency at annual. FedRAMP Annual Assessment Guidance.

**FedRAMP template / OSCAL schema reference.** OSCAL System Security Plan
v1.1.2 (the same schema LOOP-A's `core/oscal-ssp.ts` emits, with
`metadata.last-modified` bumped + `metadata.revisions[]` updated). A
year-over-year Markdown diff (`ssp-annual-diff-<YYYY>.md`) accompanies for
3PAO + AO review.

**What the CSP delivers vs what FedRAMP/3PAO authors.** CSP updates the SSP.
3PAO reviews + co-signs that the update reflects reality. AO approves.

**Cross-references.**
- **`core/oscal-ssp.ts`** — the existing emitter, extended in LOOP-E.E4 with
  prior-version diffing.
- **C6 (Annual Assessment package)** — the SSP review ships inside the C6 bundle.

---

### C8 — Annual IRP/ISCP test + AAR

**Source citation.**
- **IRP (Incident Response Plan)**: NIST 800-53 IR-3 (Incident Response
  Testing) — annual at FedRAMP Moderate; IR-8 (IR Plan) governs the plan
  itself.
- **ISCP (Information System Contingency Plan)**: NIST 800-53 CP-4 (Contingency
  Plan Testing) — annual at FedRAMP Moderate; CP-2 (Contingency Plan) governs
  the plan itself.
- AAR = After-Action Report, the formal output of each test.

**FedRAMP template / OSCAL schema reference.** FedRAMP IRP Template + FedRAMP
ISCP Template (both .docx). The AAR is also .docx, with structured fields for
test date, participants, scenarios exercised, findings, and remediation plan.

**What the CSP delivers vs what FedRAMP/3PAO authors.** CSP runs the test
(possibly with 3PAO oversight) + authors the AAR. 3PAO validates the test was
conducted. AO consumes the AAR as evidence the CSP can detect + respond +
recover.

**Cross-references.**
- **LOOP-C.C2 (ISCP doc template)** — generates the ISCP itself + AAR template.
- **LOOP-C.C3 (IRP doc template)** — generates the IRP itself + AAR template.
- **C6 (Annual Assessment package)** — both AARs ship inside the C6 bundle.
- **AFR-ICP family** — the broader incident-communications procedures the IRP
  references; covered in LOOP-G.G2.

---

### C9 — Annual Penetration Test

**Source citation.** FedRAMP Penetration Test Guidance (Rev 5); NIST 800-53
CA-8 (Penetration Testing) — annual at FedRAMP Moderate. The PenTest is
3PAO-led and must cover attack vectors against the externally-accessible
authorization boundary.

**FedRAMP template / OSCAL schema reference.** FedRAMP PenTest Report Template
(.docx). For 20x continuous-validation purposes, the findings need to flow
into the OSCAL AR (extending `finding.target` per OSCAL v1.1.2) + POA&M risk
entries — LOOP-K.K1 + K.K2 define the ingest schema.

**What the CSP delivers vs what FedRAMP/3PAO authors.** 3PAO authors. CSP
provides scope + access. AO consumes findings.

**Cross-references.**
- **LOOP-K.K1 (PenTest ingest schema)** — the upload + ingest path.
- **LOOP-K.K2 (3PAO test results matrix → OSCAL)** — the mapping to OSCAL AR
  test-result-objects.
- **C1 (Monthly POA&M)** — PenTest findings become POA&M items.

---

### C10 — KEV remediation tracking

**Source citation.** CISA Binding Operational Directive 22-01
(https://www.cisa.gov/news-events/directives/bod-22-01-reducing-significant-risk-known-exploited-vulnerabilities):
> "Within 6 months of issuance of this Directive, federal civilian executive
> branch agencies (FCEB) shall review and update agency vulnerability
> management procedures to remediate each vulnerability identified in the CISA
> KEV Catalog by the established due date."

For FedRAMP CSPs that handle FCEB data, the 21-day remediation window applies
to any CVE that appears on the catalog. The catalog is published as
machine-readable JSON at
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
(field `dueDate`).

**FedRAMP template / OSCAL schema reference.** OSCAL POA&M `risk.deadline` +
`risk.props` carrying `source='kev'`. The deadline is `CISA dueDate + 0d` (i.e.,
CISA already published the date; we use it directly), bounded to 21 days
maximum from notification when the catalog adds new entries mid-month.

**What the CSP delivers vs what FedRAMP/3PAO authors.** CSP delivers via C1
(POA&M) + C2 (scan reconciliation) + C3 (monthly report KEV exposure count).
3PAO validates the KEV reconciliation is current. PMO + AO monitor compliance.

**Cross-references.**
- **`providers/{aws,gcp,azure}/vdr-scan.ts`** — already perform the KEV join.
- **`docs/cisa-kev.generated.json`** — committed catalog snapshot.
- **B.B2 (Remediation deadline math)** — the deadline computation that uses
  the catalog.

---

### C11 — AFR-FSI (FedRAMP Security Inbox)

**Source citation.** FedRAMP AFR-FSI family per `FRMR.documentation.json`
v0.9.43-beta. R1 classification (`docs/AFR-FAMILY-CLASSIFICATION.md`) confirms
6 CSO MUSTs at Moderate:

- **FSI-CSO-CRA** (Complete Required Actions) — when FedRAMP issues a required
  action via the inbox, CSP must complete it within the published timeframe.
- **FSI-CSO-EMR** (Emergency Message Routing) — emergency-classified messages
  must auto-route to the right on-call.
- **FSI-CSO-INB** (Maintain a FedRAMP Security Inbox) — verified email endpoint
  monitored by the CSP.
- **FSI-CSO-NOC** (Notification of Changes) — when the inbox config changes,
  notify FedRAMP.
- **FSI-CSO-RCV** (Receive Email Without Disruption) — uptime + receipt
  confirmation.
- **FSI-CSO-TFG** (Trust @fedramp.gov and @gsa.gov) — domain trust + bypass
  spam filtering for those origins.

**FedRAMP template / OSCAL schema reference.** No OSCAL schema; this is an
operational obligation. Our internal schema for inbox config + message log +
required-action tracking is the source of truth.

**What the CSP delivers vs what FedRAMP/3PAO authors.** CSP operates the
inbox. FedRAMP PMO sends inbound messages. 3PAO + AO validate the inbox is
healthy + actions are being completed.

**Cross-references.**
- **R1 finding in `docs/AFR-FAMILY-CLASSIFICATION.md`** — the canonical list of
  the 6 CSO MUSTs.
- **C3 (Monthly ConMon report)** — monthly attestation that the inbox processed
  expected messages and completed required actions.
- **LOOP-G.G1** — the implementing slice.

---

### C12 — AFR-CCM (20x ConMon publication)

**Source citation.** FedRAMP AFR-CCM family per `FRMR.documentation.json`
v0.9.43-beta. R1 classification (`docs/AFR-FAMILY-CLASSIFICATION.md`)
identifies 4 CSP-actionable OAR + QTR MUSTs at Moderate:

- **CCM-OAR-AVL** (Report Availability) — published reports must be available
  to authorized consumers.
- **CCM-OAR-FBM** (Feedback Mechanism) — a way for agencies / PMO to give
  feedback on published reports.
- **CCM-OAR-NRD** (Next Report Date) — published reports name when the next
  report is due.
- **CCM-QTR-REG** (Meeting Registration Info) — quarterly review meeting
  registration link / process.

Authority for the OAR (Ongoing Authorization Report) construct is FedRAMP
RFC-0014 (FedRAMP 20x Phase Two for Moderate) and the RFC-0006 AFR catalog.

**FedRAMP template / OSCAL schema reference.** No OSCAL schema; the
implementations are operational (a webhook URL, a calendar of next dates, a
registration URL). Our internal JSON publication schema is the source of truth.

**What the CSP delivers vs what FedRAMP/3PAO authors.** CSP publishes. Agencies
+ PMO + AO consume.

**Cross-references.**
- **C1, C2, C3** — these are the reports CCM-OAR-AVL publishes.
- **LOOP-G.G6** — the implementing slice.

---

### C13 — Long-term retention (AU-11)

**Source citation.** NIST 800-53 AU-11 (Audit Record Retention):
> "Retain audit records for [Assignment: organization-defined time period
> consistent with records retention policy] to provide support for after-the-
> fact investigations of incidents and to meet regulatory and organizational
> information retention requirements."

FedRAMP sets the AU-11 retention floor at **3 years** (FedRAMP Baseline
Parameter values, `nist-r5-baselines.generated.json`). Some agency contracts
extend this to 6 years.

CISA Cyber Incident Reporting Council guidance + 44 USC §3101 (Federal Records
Act) provide the broader federal records-retention context. Some agencies
(e.g., DoD via CMMC) extend retention to 6 years or more.

**FedRAMP template / OSCAL schema reference.** No FedRAMP-published schema for
the archive itself. Our internal retention-policy schema (object-lock state,
expiration timestamp, manifest sha256, signing key id) is the source of truth.
The archive itself contains the *original signed-manifest tarball* produced by
LOOP-A.A4 — re-signing or re-bundling at archive time would break the trust
chain.

**What the CSP delivers vs what FedRAMP/3PAO authors.** CSP delivers. PMO and
3PAO consume on demand (e.g., during a 3-year-old incident investigation).
Object-lock prevents the CSP (or anyone else) from tampering.

**Cross-references.**
- **LOOP-A.A4 (submission bundler)** — produces the immutable artifact that
  H.H1 pushes to archive.
- **LOOP-H.H1 (`core/archive-push.ts`)** — the push pipeline.
- **LOOP-H.H2 (`core/retention-policy.ts`)** — the annual attestation report.
- **C6 (Annual Assessment package)** — also retained under AU-11.

---

## 4. Acceptance criteria for this section

SECTION C is **complete** when every artifact below ships under the REO
standard (real-evidence-only, signed, tested on the real path, no stubs):

- ✅ **C1 (Monthly POA&M):** Authorization-time emitter complete (LOOP-A.A1
  shipped); monthly delta workflow `core/poam-monthly.ts` (LOOP-E.E2) ships +
  is wired into a monthly orchestrator schedule + writes both OSCAL JSON/XML
  and FedRAMP POA&M .xlsx + computes deltas vs last-month doc + signs all
  three.
- ✅ **C2 (Monthly vuln scans):** Existing `vdr-scan.ts` collectors run on a
  monthly orchestrator schedule + KEV reconciliation + the per-cloud evidence
  envelope flows into the C3 report + the C1 POA&M.
- ✅ **C3 (Monthly ConMon report):** `core/conmon-report.ts` (LOOP-E.E1) ships
  + emits PDF + Markdown + structured JSON + cites real data from
  inventory.json, the month's POA&M, the month's scans, the KEV exposure
  count, and SCN events.
- ✅ **C4 (SCN):** `core/scn-doc.ts` (LOOP-E.E6) ships + emits FedRAMP .docx
  per template + audit-records archive retained.
- ✅ **C5 (Deviation Request):** `core/deviation-request.ts` (LOOP-E.E5) ships
  + tracker UI for operator trigger + .docx emit + integration with B.B3
  risk-acceptance + B.B4 compensating-controls.
- ✅ **C6 (Annual Assessment package):** `core/annual-assessment.ts`
  (LOOP-E.E3) ships + aggregates 12-month POA&M + annual SSP review (C7) +
  IRP AAR + ISCP AAR (C8) + PenTest (C9) + wraps via LOOP-A.A4 bundler with a
  `package_format_version` for annual cadence.
- ✅ **C7 (Annual SSP review):** `core/oscal-ssp.ts` extended with version
  diff tracking + `core/ssp-annual-review.ts` (LOOP-E.E4) ships + emits
  Markdown diff for operator sign-off.
- ✅ **C8 (Annual IRP/ISCP test + AAR):** `core/annual-test-runner.ts`
  (LOOP-E.E7) ships + depends on LOOP-C.C2 (ISCP template) + LOOP-C.C3 (IRP
  template) being shipped first.
- ✅ **C9 (Annual PenTest):** `core/pentest-ingest.ts` (LOOP-K.K1) ships + 3PAO
  upload flow in tracker + findings flow into OSCAL AR (LOOP-K.K2) + POA&M.
- ✅ **C10 (KEV remediation tracking):** `core/risk-score.ts` (LOOP-B.B1) +
  `computeDeadline()` (LOOP-B.B2) ship with KEV-source flag in
  `risk.deadline.source` + 21-day window enforcement.
- ✅ **C11 (AFR-FSI):** `core/afr-fsi.ts` + tracker DB tables ship under
  LOOP-G.G1 covering all 6 CSO MUSTs.
- ✅ **C12 (AFR-CCM):** `core/afr-ccm.ts` ships under LOOP-G.G6 covering the
  4 CSP-actionable OAR/QTR MUSTs.
- ✅ **C13 (Long-term retention):** `core/archive-push.ts` (LOOP-H.H1) +
  `core/retention-policy.ts` (LOOP-H.H2) ship + every signed submission tarball
  + every annual assessment package + every SCN audit record + every PenTest
  report lands in object-lock storage with verified retention.

Each artifact must additionally satisfy:

1. **REO compliance.** No stubs, no placeholder strings, no fabricated data —
   every byte traces to real evidence or operator-supplied input. CI guardrails
   G1 / G2 / G3 (`scripts/lint-no-stubs.mjs`, `scripts/check-coverage-regression.mjs`,
   `scripts/check-provenance.mjs`) return 0 for every slice.
2. **OSCAL chain integrity.** Where the artifact is part of the OSCAL chain
   (C1, C6, C7), `import-ssp` / `import-ap` references resolve and the
   `--strict-chain` mode (LOOP-A.A3) refuses to bundle synthetic references.
3. **Signed + timestamped.** Every emitted artifact is covered by the Ed25519
   signed manifest + the RFC 3161 timestamp produced by `core/sign.ts`.
4. **CHANGELOG entry.** Each slice's CHANGELOG entry names the modules
   touched + the real evidence path + a per-slice REO compliance note.
5. **Tests pass at the real path.** Parsers, validators, signers, emitters
   are exercised on real input; SDK transport may be mocked at the wire layer
   only.

When every box above is ticked, SECTION C is complete and the CSP can operate
indefinitely on this audit-agent pipeline through monthly + annual cadence with
no manual artifact authoring outside `REQUIRES-OPERATOR-INPUT` markers.

---

## 5. Open questions

1. **POA&M wire format final (R2 in `PRE-LOOP-A-RESEARCH-FINDINGS.md`).**
   Excel-only vs OSCAL-only vs both. We emit both via LOOP-A.A1 + LOOP-A.A4 +
   LOOP-E.E2. If FedRAMP publishes guidance that one format becomes
   normative + the other is rejected, LOOP-E.E2 may emit a deprecation warning
   on the non-normative format. Tracking: re-fetch fedramp.gov ConMon section
   quarterly.

2. **PAIN / IRV / LEV deadline table version stability.** FedRAMP's ConMon
   Strategy Guide publishes a PAIN / Internet-Reachable-Vulnerability /
   Likely-Exploited-Vulnerability deadline table that LOOP-B.B2 will consume.
   If FedRAMP republishes that table with revised values, the citation +
   version pin in B.B2 must update. Tracking: cite the version in the
   `risk_score.deadline.source` metadata + alert when the source version
   drifts.

3. **CISA KEV catalog drift.** The CISA KEV catalog is published as a
   continuously-updated JSON feed. Our `docs/cisa-kev.generated.json` is a
   committed snapshot. Open question: do we ship a refresh cron + how often?
   Initial answer: weekly refresh via `scripts/refresh-cisa-kev.mjs`,
   committed via PR by the bot — preserving the audit trail of "what was the
   KEV catalog at the time of submission". Not yet implemented.

4. **C8 IRP/ISCP AAR template format.** FedRAMP has historical AAR templates
   but the format-of-record for 20x Phase Two is not yet published. We will
   emit a structured .docx (LOOP-C.C2 / C3 / LOOP-E.E7) + a parallel JSON for
   tracker storage; if the official template shifts, the .docx layout can be
   re-rendered without changing the structured data.

5. **Annual PenTest scope scaling.** The PenTest scope for a CSO that has
   added significant new functionality during the year is partially defined by
   the operator + 3PAO, partially by FedRAMP guidance. LOOP-K.K1 ingest schema
   needs an explicit `scope_diff_from_prior_year` field for AO review.

6. **C11 FSI emergency-message routing SLA.** FSI-CSO-EMR mandates emergency
   routing but the response-time SLA is not specified in the published FRMR
   v0.9.43-beta beyond "promptly". LOOP-G.G1 will default to a 1-hour
   acknowledgement SLA with operator override + emit a `REQUIRES-OPERATOR-INPUT`
   marker if operator does not confirm the SLA.

7. **C12 AFR-CCM quarterly meeting integration.** CCM-QTR-REG mandates a
   registration mechanism. Open question: do we integrate with a calendar
   system (Google Calendar / Microsoft Graph / iCal feed) or just publish a
   registration URL? Initial answer: publish a registration URL operator-
   supplied via `config.yaml` (`afr_ccm.quarterly_registration_url`), defer
   calendar integration to a later slice.

8. **C13 retention beyond 3 years.** AU-11 mandates 3 years; some agency
   contracts extend to 6+ years. LOOP-H.H2 will read the retention policy
   from `org-profile.yaml` (`audit_retention_years: 3`) and enforce that
   per-object lock duration. Open question: when an agency contract dictates
   longer retention than `org-profile.yaml`, how does that flow? Initial
   answer: per-CSO override in `multi-cso.yaml` (LOOP-H.H3), not yet
   implemented.

9. **OSCAL POA&M `metadata.revisions[]` chain length.** Over a multi-year
   ConMon period, the revisions chain in a single POA&M document grows
   unboundedly. We will cap at 36 revisions (3 years monthly) with rollover
   into a `historical-revisions` back-matter resource. Not yet decided whether
   FedRAMP PMO accepts that pattern.

10. **Phase Two pilot post-retrospective format shift (R3 in
    `PRE-LOOP-A-RESEARCH-FINDINGS.md`).** If FedRAMP publishes a post-pilot
    retrospective with revised monthly submission format guidance before GA
    Moderate (late 2026), LOOP-E.E1 + E.E2 may need format patches. LOOP-A.A4
    already supports clean `package_format_version` bumps; LOOP-E will inherit
    the same versioning convention.

None of these blocks slice implementation. Each is documented here so the
slice that hits it has a clear decision tree.
