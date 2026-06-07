# FedRAMP 20x — execution plan (LOOP-B through LOOP-K)

> **Single source of truth** for every remaining slice in the 46-week
> roadmap. Any session resuming this work loads `cloud-evidence/CLAUDE.md`
> for the REO standard, then reads this document for the per-slice plan.
> LOOP-A is COMPLETE (see CHANGELOG.md unreleased section).

---

## Status snapshot

**LOOP-A: COMPLETE** — submission package is end-to-end emittable:
SSP → AP → AR → POA&M → IIW → RoE → signed manifest → RFC 3161 timestamp
→ INDEX.json → signed tarball ready for USDA Connect.gov upload.

**LOOP-B through LOOP-K: NOT STARTED** — 51 slices remaining.

**Tests:** 874/874 passing. **REO check:** green. **OSCAL chain:** complete.

---

## How to resume

1. Open a fresh session in `/Users/kenith.philip/FedRAMP 20x/`.
2. `CLAUDE.md` auto-loads. Read it. (REO rule + slice contract.)
3. Read this file (`docs/EXECUTION-PLAN.md`).
4. Read `CHANGELOG.md` "Unreleased" to see what's already built.
5. Say: `continue with LOOP-B.B1` (or the next slice in priority).
6. The session creates a TaskCreate entry for the slice, then executes
   under the REO standard.

---

## The 11 loops, 51 remaining slices

| Loop | Title | Slices | Effort | Depends on |
|---|---|---|---|---|
| **B** | Risk + remediation engine | 5 | 4 weeks | LOOP-A.A1 (POA&M) |
| **C** | Document template pack | 9 | 8 weeks | none (parallel-safe with A/B) |
| **D** | Diagram auto-generation | 3 | 3 weeks | none (uses inventory.json) |
| **E** | Continuous monitoring agent | 7 | 5 weeks | A.A1 + C.C6 |
| **F** | 3PAO assessor experience | 7 | 4 weeks | A.A2 + B.B3 |
| **G** | AFR family (20x deliverables) | 6 | 5 weeks | none (R1 already classified) |
| **H** | Long-term storage + multi-CSO | 3 | 3 weeks | none |
| **I** | Stakeholder dashboards | 4 | 3 weeks | B.B1 |
| **J** | Supply chain + privileges | 3 | 3 weeks | none |
| **K** | Test artifact ingestion | 2 | 2 weeks | A.A3 |
| **TOTAL** | | **51** | **~46 weeks single-thread** | |

**Parallelizable streams:**
- Stream 1: B → F → I (12 slices, ~11 weeks)
- Stream 2: C → E → K (18 slices, ~15 weeks)
- Stream 3: D, G, H, J (15 slices, ~14 weeks)

---

## Added loops L-Q (2026-06-07)

LOOP-L through LOOP-Q were surfaced by
`docs/ADDITIONAL-LOOPS-AUDIT.md` (2026-06-06) and the human ratified
the audit on 2026-06-07. All six loops are now fully specified
(`docs/loops/LOOP-{L,M,N,O,P,Q}-SPEC.md` + 25 per-slice docs +
6 RISKS registers) and a second-pass audit
(`docs/SECOND-PASS-AUDIT.md`) confirmed nothing else is still missing.

| Loop | Title | Slices | Effort | Dependencies | Applicability |
|---|---|---|---|---|---|
| **L** | CRM + Leveraged-Authorization Inheritance | 4 | 4 weeks | A.A1, D.D1 | REQUIRED |
| **M** | Privacy Package Extension (SORN + DPIA) | 4 | 4 weeks | C.C4, J.J2 | REQUIRED (confirmed) |
| **N** | Threat Modeling + Adversarial Validation | 4 | 4 weeks | D.D3, B.B1 | REQUIRED |
| **O** | AI/ML Governance | 5 | 5 weeks | B.B1, C.C4 | REQUIRED (confirmed) |
| **P** | Insider Threat + PS-family | 5 | 5 weeks | existing tracker, J.J1 | REQUIRED |
| **Q** | Marketplace + Post-ATO Publication | 3 | 3 weeks | A.A4, E.E1 | REQUIRED |
| **TOTAL** | | **25** | **25 weeks** | | |

Combined roadmap: LOOP-A (5 done) + LOOP-B..K (50) + LOOP-L..Q (25)
= **80 slices, 17 loops**. Implementation priority remains LOOP-B.B1
first (risk scoring is a shared dependency for N.N3 and O.O3).
LOOP-L.L1 is queued immediately behind LOOP-B.B1.

Detailed per-slice specs:
- `docs/loops/LOOP-L-SPEC.md` — CRM Workbook (L.L1), Inherited-controls tracker (L.L2), CRM Gap Report (L.L3), Per-control responsibility split renderer (L.L4)
- `docs/loops/LOOP-M-SPEC.md` — SORN emitter (M.M1), DPIA (M.M2), PT-family inventory (M.M3), Privacy incident response (M.M4)
- `docs/loops/LOOP-N-SPEC.md` — STRIDE threat model (N.N1), Attack surface enumeration (N.N2), PASTA/red-team framework (N.N3), MITRE ATT&CK mapping (N.N4)
- `docs/loops/LOOP-O-SPEC.md` — AI/ML asset inventory (O.O1), NIST AI RMF alignment (O.O2), AI risk register (O.O3), AI evaluation per OMB M-24-10 (O.O4), Model card + datasheet emitter (O.O5)
- `docs/loops/LOOP-P-SPEC.md` — Insider Threat Program (P.P1), Position risk designation (P.P2), Transfer + termination (P.P3), Access agreements + NDA (P.P4), Continuous workforce monitoring (P.P5)
- `docs/loops/LOOP-Q-SPEC.md` — Marketplace listing (Q.Q1), Post-ATO ConMon publication (Q.Q2), Agency authorization tracking (Q.Q3)

---

# LOOP-B — Risk + Remediation Engine

**Why:** LOOP-A.A1 POA&M emits FedRAMP-baseline deadlines per severity
(Critical 30d / High 60d / Medium 90d / Low 180d) but treats all findings
the same. Real CSP risk management uses CVSS + EPSS + criticality +
exposure to prioritize. LOOP-B closes that gap and enables risk-acceptance
workflows that map back to compensating controls.

**Depends on:** LOOP-A.A1 (POA&M shape), `core/findings.ts` schema, VDR ledger.

## B.B1 — Per-finding CVSS+EPSS+criticality+exposure scoring

**Files:** `core/risk-score.ts` (new), extend `core/findings.ts` schema,
extend `core/oscal-poam.ts` to embed risk props.

**Build:**
- Extend `Finding` schema with optional `risk_score: { cvss_base, cvss_temporal?, epss_score?, epss_percentile?, criticality, exposure, composite_score, computed_at, source }`.
- New `core/risk-score.ts` module:
  - `computeRiskScore(finding: Finding, ctx: RiskContext): RiskScore` — pure.
  - Composite formula: `0.4 * cvss_base + 0.3 * epss * 10 + 0.2 * criticality * 10 + 0.1 * exposure * 10` (document the weights + cite the rationale; reviewable + tunable via config).
  - `criticality`: from asset metadata (data_classification, asset_tier in inventory.json).
  - `exposure`: from asset metadata (public_facing, internet_reachable).
  - When CVSS / EPSS missing, fall back to severity baseline + REQUIRES-OPERATOR-INPUT note.
- Wire from VDR-class findings (existing CVE ingestion) and general findings (severity-only baseline).
- Extend `core/oscal-poam.ts` so each `poam-item.props` carries the composite score + the individual factors. A 3PAO can sort the POA&M by risk score.

**Tests:** ~12. Composite formula correctness, fallback behavior, CVSS/EPSS optional, prop emission in POA&M.

**REO:** when CVSS is missing for a CVE-class finding, emit
`REQUIRES-OPERATOR-INPUT` in `risk_score.cvss_base_source` rather than
substituting a default. Never invent CVSS scores.

## B.B2 — Remediation deadline math (KEV / PAIN / IRV / LEV math from VDR)

**Files:** extend `core/risk-score.ts`, extend `core/oscal-poam.ts`.

**Build:**
- New `computeDeadline(finding, riskScore, collectedAt): { deadline: ISO, source: 'kev'|'fedramp-severity'|'pain-irv-lev'|'operator-override' }`.
- CISA KEV: 21d from CISA's published `dueDate`.
- PAIN / IRV / LEV (existing VDR pipeline): use FedRAMP CMP's published table — exact dates per the table, not the severity baseline. Source the table from FedRAMP ConMon Strategy + document the version.
- Default fall-through: B.A1's severity baseline (Critical 30 / High 60 / etc.) only when KEV/VDR data unavailable.
- Extend POA&M `risk.deadline` to use this computation.

**Tests:** ~10. KEV deadline = 21d from CISA dueDate; PAIN/IRV/LEV table application; severity fallback; operator override.

## B.B3 — Risk acceptance workflow (tracker DB + signed audit record)

**Files:** new `tracker/server/routes/risk-acceptance.ts`,
`tracker/server/db/migrations/0XX_risk_acceptance.sql`, new
`tracker/client/src/pages/RiskAcceptance.tsx`.

**Build:**
- DB table: `risk_acceptances (id, finding_uuid, accepted_by_user_id, accepted_at, expiration_date, business_justification, compensating_control_uuids[], signed_at, signature)`.
- Tracker UI: per-finding "Accept Risk" button → form (expiration, justification, link to compensating control). Stores signed record.
- Expiration enforcer: cron-like check in tracker — when `expiration_date < now`, mark acceptance expired + re-open the POA&M item.
- Extend `core/oscal-poam.ts` so risks with active acceptance get `risk.status = 'deviation-approved'` + a `risk.deadline` extension referencing the acceptance record.

**Tests:** ~15. DB constraints, expiration math, signed-record integrity, POA&M status mapping, RBAC (only specific roles can accept).

**REO:** signatures are real human actions captured in the tracker audit
log; system never auto-accepts.

## B.B4 — Compensating-controls registry

**Files:** new `tracker/server/routes/compensating-controls.ts`, DB migration,
new `tracker/client/src/pages/CompensatingControls.tsx`, extend `core/oscal-poam.ts`.

**Build:**
- DB table: `compensating_controls (id, title, description, control_ids[] (NIST), implemented_by, signed_off_by, expires_at, evidence_url)`.
- Tracker UI: CRUD page + sign-off flow.
- Registry surfaces in B.B3 acceptance flow — operator selects which compensating controls cover the accepted risk.
- POA&M emit: when a risk has B.B3 acceptance + B.B4 compensating control, embed the compensating-control reference in `risk.mitigating-factors[]`.

**Tests:** ~12.

## B.B5 — Central Risk Register (RA-3)

**Files:** new `core/risk-register.ts`, new `tracker/client/src/pages/RiskRegister.tsx`.

**Build:**
- Aggregates: all POA&M items (B.A1) + all open risk-acceptances (B.B3) + organizational risks (operator-entered: third-party, supply-chain, environmental).
- Emits `out/risk-register.json` + `risk-register.xlsx`.
- This is the NIST RA-3 deliverable, distinct from per-finding scoring (B.B1).

**Tests:** ~8.

---

# LOOP-C — Document Template Pack

**Why:** Section A of the requirements doc lists 12+ Word documents
required by the FedRAMP authorization package. Each is a `.docx` that
auto-fills from real evidence + operator-supplied fields, with
REQUIRES-OPERATOR-INPUT markers for anything not yet available.

**Pattern:** Reuse `core/zip.ts` + the OOXML approach from `core/roe-emit.ts`
(LOOP-A.A5) and `core/ssp-docx.ts` (SSP-2). Each slice ships:
- `core/<doc>-emit.ts` — pure renderer + disk emitter
- `tests/core/<doc>-emit.test.ts` — ~12 tests
- Orchestrator flag `--<doc>`
- Bundler well-known catalogue entry + role

## C.C1 — Configuration Management Plan (CMP)

**NIST control:** CM-9. **Source:** FedRAMP CMP template.

**Auto-fill from:** inventory.json (component list), ksi-map (which
controls), tracker (operator-supplied process: approval workflow,
roll-back authority, change windows).

**REQUIRES-OPERATOR-INPUT:** approval workflow narrative, roll-back
authority, baseline-config reference.

## C.C2 — Information System Contingency Plan (ISCP) + Test AAR template

**NIST controls:** CP-2 + CP-4. **Source:** FedRAMP ISCP template.

**Auto-fill from:** RPL-ABO / RPL-TRC / RPL-RRO / RPL-ARP existing
collector evidence (real backup configs).

**REQUIRES-OPERATOR-INPUT:** RTO/RPO commitments, contingency activation
authority, alternate site details.

**Test AAR:** separate `core/iscp-test-aar.ts` for annual test results.

## C.C3 — Incident Response Plan (IRP) + Test AAR template

**NIST controls:** IR-8 + IR-3. **Source:** FedRAMP IRP template.

**Auto-fill from:** INR-RIR existing collector + tracker incident records.

**REQUIRES-OPERATOR-INPUT:** IR team roster, escalation matrix, communication plan.

## C.C4 — Privacy Threshold Analysis (PTA) + Privacy Impact Assessment (PIA)

**NIST controls:** PT-2 / PT-3 / PT-6. **Source:** FedRAMP PTA + PIA templates.

**Conditional emit:** when PII-likely tags detected on assets, emit both;
otherwise emit PTA only (with "no PII processed" determination).

**Auto-fill from:** inventory.json data classification tags.

## C.C5 — FIPS 199 categorization worksheet

**Source:** FIPS 199 + NIST SP 800-60.

**Auto-fill from:** operator-supplied impact tier per CIA triad +
information-type list.

**REQUIRES-OPERATOR-INPUT:** confidentiality/integrity/availability
levels, information types per SP 800-60 Volume 2 mapping.

## C.C6 — Continuous Monitoring Strategy + Plan

**NIST control:** CA-7. **Source:** FedRAMP ConMon Strategy template +
ConMon Playbook.

**Auto-fill from:** ksi-map (which controls monitored), scan-config
(monthly), POA&M cadence (monthly), AR cadence (monthly).

**REQUIRES-OPERATOR-INPUT:** ConMon team roster, deviation request process,
escalation thresholds.

## C.C7 — Risk Management Strategy (RMS)

**NIST controls:** PM-9. **Source:** FedRAMP RMS template.

**Auto-fill from:** B.B5 risk register + B.B4 compensating-controls
registry + B.B3 acceptance policy.

**REQUIRES-OPERATOR-INPUT:** organizational risk tolerance, executive
oversight roles.

## C.C8 — Authorization request cover letter / package transmittal

**Source:** FedRAMP authorization playbook template.

**Auto-fill from:** systemName, systemId, impactLevel, 3PAO, CSP, summary
of submission package contents (read from INDEX.json).

## C.C9 — Baseline Configuration document (CM-2)

**NIST control:** CM-2 (separate from CM-8 inventory).

**Auto-fill from:** inventory.json + AFR-SCG existing scaffold + reference-arch.ts.

**REQUIRES-OPERATOR-INPUT:** baseline-config approval signature, deviation log location.

---

# LOOP-D — Diagram Auto-Generation

**Why:** SSP Appendix M requires authorization boundary, network, and data
flow diagrams. Today they're manually drawn. Auto-generate from real
inventory.

**Pattern:** Use `core/inventory.json` + asset metadata. Emit PlantUML
+ render via `node-plantuml` (or pre-render to SVG using a pure-JS
PlantUML-like syntax). PNG export via `sharp` or similar.

**REO:** every node/edge in the diagram comes from real inventory; no
decorative shapes; no fabricated relationships.

## D.D1 — Authorization Boundary Diagram

**Files:** new `core/diagrams/boundary.ts`.

**Build:** Read `inventory.json` + boundary tags (assets tagged
`fedramp_boundary=in` are in-boundary). Render boxes per (provider, asset
type) group. Edges from peering / shared-services tags. Emit PlantUML
source + SVG + PNG.

**REQUIRES-OPERATOR-INPUT:** when no boundary tags exist on any asset,
emit a placeholder diagram with a note explaining the tag scheme + how
to apply it.

## D.D2 — Network Diagram

**Files:** new `core/diagrams/network.ts`.

**Build:** VPC/VNet topology from inventory (subnet, route table, peering
data). Firewall rules summarized at the edge. Multi-cloud aware
(AWS VPC, GCP VPC, Azure VNet).

## D.D3 — Data Flow Diagram

**Files:** new `core/diagrams/dataflow.ts`.

**Build:** Asset-to-asset edges from existing relationship data (RDS →
EC2, S3 → Lambda, etc.) + data classification overlay (assets tagged
with PII/CUI/Public).

---

# LOOP-E — Continuous Monitoring Agent

**Why:** Authorization is a one-time event; ConMon is continuous. CSPs
must publish monthly POA&M deltas + scan reports + analysis to USDA
Connect.gov. LOOP-E automates the recurring delivery.

**Depends on:** LOOP-A.A1 (POA&M shape) + C.C6 (ConMon Strategy doc).

## E.E1 — Monthly ConMon analysis report

**Files:** new `core/conmon-report.ts`. Emits `out/conmon-monthly-<YYYY-MM>.pdf` + `.md` + `.json`.

**Build:** Aggregate the month's POA&M items, scan results, KEV
notifications, SCN events. Format per FedRAMP ConMon Playbook structure.

## E.E2 — Monthly POA&M delta workflow

**Files:** new `core/poam-monthly.ts`. Extends `core/oscal-poam.ts`.

**Build:** Per R2 findings — full-document re-emission with
`metadata.last-modified` bumped + `metadata.revisions[]` appended.
Compare against last month's POA&M; emit `poam-delta-<YYYY-MM>.md`
listing added/closed/status-changed items for operator review.

## E.E3 — Annual Assessment package generator

**Files:** new `core/annual-assessment.ts`.

**Build:** 12-month aggregate. Bundles annualized AR + delta-from-prior-annual
+ annual SSP review (E.E4) + IRP test AAR (E.E7) + ISCP test AAR (E.E7).
Uses LOOP-A.A4 bundler.

## E.E4 — Annual SSP review/update workflow

**Files:** extend `core/oscal-ssp.ts` with delta-tracking, new
`core/ssp-annual-review.ts`.

**Build:** Compare current SSP against prior annual version. Emit
`ssp-annual-diff-<YYYY>.md` for review + commit-to-record after operator
sign-off.

## E.E5 — Deviation Request (DR) emitter

**Files:** new `core/deviation-request.ts` (.docx via OOXML pattern).

**Build:** Operator triggers via tracker UI when a control can't be met
or a scan window missed. Emits structured .docx with all required FedRAMP
DR fields (justification, compensating control reference, expiration).

## E.E6 — Formal SCN doc emitter (extends existing classifier)

**Files:** new `core/scn-doc.ts` (.docx).

**Build:** Existing `core/scn-classifier.ts` emits `scn-classification.json`.
This slice adds a .docx that's the formal notification format per FedRAMP CMP.

## E.E7 — Annual IRP/ISCP test cadence runner

**Files:** new `core/annual-test-runner.ts`. Extends C.C2 + C.C3 templates.

**Build:** Annually generates IRP + ISCP test AAR templates with
prefilled test date, participants list from tracker, prior-year findings
ledger. Operator fills test results.

---

# LOOP-F — 3PAO Assessor Experience

**Why:** Section B of the requirements doc — the 3PAO needs a sign-off
UI, comment threads, sample selection methodology, evidence walk-through,
SAR draft generator, recommendation letter template.

**Depends on:** LOOP-A.A2 (AP exists for the assessor to work against) +
B.B3 (signed action records).

## F.F1 — 3PAO sign-off UI in tracker

**Files:** new tracker routes + UI page. DB: `assessor_signoffs (item_uuid, role, signed_by, signed_at, signature, comments)`.

**Build:** Per-control + per-finding sign-off. RBAC: only users with
`assessor` role can sign. Signatures captured + linked to the OSCAL AR.

## F.F2 — Comment threads on findings

**Files:** extend tracker. DB: `finding_comments` table.

**Build:** Email notifications on new comments. Thread persists across
assessment phases. Read-only after sign-off.

## F.F3 — Sample selection methodology auto-derive (R4-informed)

**Files:** new `core/sampling-methodology.ts`.

**Build:** Per R4 findings — externally-accessible components 100%, internal
sampling with stratified-by-asset-class + min 10% floor. Emit
`sampling-methodology.json` + .md for SAP Appendix B reference.

## F.F4 — Evidence walk-through artifacts

**Files:** new tracker routes for screenshot + transcript upload.

**Build:** 3PAO uploads screenshots + transcripts during testing. Linked
to specific findings. Persisted with finding-uuid.

## F.F5 — 3PAO recommendation letter template

**Files:** new `core/recommendation-letter.ts` (.docx).

**Build:** Pre-filled with system identity, assessment period, summary
counts. 3PAO completes recommendation language + signs.

## F.F6 — Full ATO workflow tracker (PM-10)

**Files:** new tracker workflow page.

**Build:** Tracks the authorization lifecycle: package complete → 3PAO
sign-off → AO review → ATO decision → publication. State machine with
audit trail per transition.

## F.F7 — SAR draft generator

**Files:** new `core/sar-draft.ts`.

**Build:** Takes the OSCAL AR + tracker comments + F.F1 sign-offs and
emits a SAR draft Word doc for 3PAO finalization.

---

# LOOP-G — AFR Family (FedRAMP 20x deliverables)

**Why:** Per R1 (`docs/AFR-FAMILY-CLASSIFICATION.md`), all 10 AFR families
are REQUIRED at Moderate (85 MUST entries). PVA + VDR + UCM + SCN already
have collectors/classifiers. The 6 remaining families need emitters.

**Depends on:** R1 classification (already done).

## G.G1 — AFR-FSI (FedRAMP Security Inbox)

**Files:** new `core/afr-fsi.ts` + tracker routes for inbox config + receipt log.

**Build per R1 6 CSO MUSTs (FSI-CSO-CRA/EMR/INB/NOC/RCV/TFG):**
- DB: `fsi_inbox_config (email_endpoint, trust_list[], operator_acknowledged)`.
- DB: `fsi_message_log (msg_id, from, subject, received_at, classification, required_action, action_completed_at)`.
- Webhook to receive FedRAMP-originated emails.
- Auto-route by classification.
- Notification on missed required-action.

## G.G2 — AFR-ICP (Incident Communications Procedures)

**Files:** new `core/afr-icp.ts` (.docx template + tracker DB for incident records).

**Build per R1 6 CSX MUSTs (ICP-CSX-FIR/ICU/IRA/IRC/IRF/RPT):**
- Incident reporting templates to FedRAMP, CISA, agencies.
- Tracker tables: incidents, incident-updates, final-reports.
- Workflow: discover → report → update → final → archive.

## G.G3 — AFR-ADS (Authorization Data Sharing)

**Files:** new `core/afr-ads.ts` (replaces existing signal-emitter placeholder).

**Build per R1 6 CSO/CSX MUSTs (ADS-CSO-CBF/HAD/PUB/RIS/SVC/CSX-UTC):**
- Machine-readable service-list publication.
- Historical authorization data archive.
- Public-info disclosure mechanism.
- Trust Center usage workflow.

## G.G4 — AFR-MAS (Minimum Assessment Scope)

**Files:** new `core/afr-mas.ts` (replaces signal-emitter placeholder).

**Build per R1 4 CSO MUSTs (MAS-CSO-FLO/IIR/MDI/TPR):**
- Information-flow diagram generator (could reuse D.D3 data flow).
- Information-resource inventory (reuse existing inventory).
- Metadata inclusion in scope doc.
- Third-party resource enumeration (extends J.J2).

## G.G5 — AFR-SCG (Secure Configuration Guide)

**Files:** new `core/afr-scg.ts` (.docx).

**Build per R1 2 CSO MUSTs (SCG-CSO-AUP/RSC):**
- Use-instructions document.
- Recommended secure configuration — extends existing reference-arch.ts
  to a full SCG document with FedRAMP-Moderate-baseline defaults.

## G.G6 — AFR-CCM (Continuous Monitoring per 20x)

**Files:** new `core/afr-ccm.ts`.

**Build per R1 4 CSP-actionable OAR/QTR entries (AVL/FBM/NRD + QTR-REG):**
- Report-availability publication.
- Feedback mechanism (tracker form).
- Next-report-date scheduling.
- Quarterly meeting registration integration.
- Tightly coupled with LOOP-E.

---

# LOOP-H — Long-Term Storage + Multi-CSO

**Why:** FedRAMP requires 3-year audit retention (AU-11). The current
`out/` directory pattern isn't immutable. Also: MSP / large CSPs need
multi-CSO support.

## H.H1 — Immutable evidence archive

**Files:** new `core/archive-push.ts`.

**Build:**
- Push signed submission bundle (LOOP-A.A4 output) to S3 Glacier Deep
  Archive / GCS Coldline / Azure Archive after each run.
- Object-lock enabled (write-once, no deletion).
- Manifest indexed in a queryable catalog.

## H.H2 — Audit retention policy enforcement (AU-11)

**Files:** new `core/retention-policy.ts`.

**Build:**
- Verify archive object-locks are in place.
- Annual report: what's archived, where, retention expiry per object.
- Alert on policy violation.

## H.H3 — Multi-CSO support

**Files:** extend orchestrator + tracker + bundler. DB migration for
tenant column on every table.

**Build:**
- `--cso <id>` flag (or env) per orchestrator run.
- Per-CSO `out/<cso-id>/` output isolation.
- Per-CSO tracker tenancy + RBAC scope.
- Per-CSO archive prefix.

---

# LOOP-I — Stakeholder Dashboards

**Why:** Section D of the requirements doc — exec posture view, finding
burndown, trend analysis. Industry-standard GRC features.

**Depends on:** LOOP-B.B1 (real risk scores) for trend analysis.

## I.I1 — Executive posture dashboard

**Files:** new tracker page `Dashboard.tsx`.

**Build:** Top-10 risks (B.B1 sorted by composite), posture % (passing /
total), KEV exposure count, days-until-next-ConMon-deliverable.

## I.I2 — Finding burndown + deadline pipeline

**Files:** new tracker page.

**Build:** Visualize POA&M lifecycle (open → in-progress → closed) over
time. Group by severity + by deadline proximity.

## I.I3 — Longitudinal trend analysis

**Files:** new tracker page + `core/trend-analysis.ts`.

**Build:** Per-KSI pass-rate over time. Regression detection (alert when
a previously-passing rule starts failing).

## I.I4 — SSP narrative library completion

**Files:** new `core/ssp-narrative-library.ts`.

**Build:** Canonicalize the auto-narratives the SSP emitter generates
into a library, with overrides per (control, system) operator can edit.
Reduces manual SSP authoring.

---

# LOOP-J — Supply Chain + Privileges

## J.J1 — User Roles & Privileges matrix (AC-2 + AC-6)

**Files:** new `core/privileges-matrix.ts`.

**Build:** Aggregate existing IAM evidence (IAM-AAM + IAM-ELP collectors)
into a roles × privileges matrix .xlsx. Operator-supplied: business
justification per role.

## J.J2 — Subprocessor inventory expansion (SA-9)

**Files:** extend existing `core/subprocessors-sheet.ts`.

**Build:** Beyond Google Sheets — support YAML/JSON config + per-CSO
subprocessor list with risk-tier classification.

## J.J3 — Supply chain risk register (SR-3) + SBOM integration

**Files:** new `core/supply-chain-risk.ts`.

**Build:** Integrate existing E.2 SBOM data (Syft + cosign) into a risk
register format. CVE matching against KEV. Vendor risk tier per
subprocessor.

---

# LOOP-K — Test Artifact Ingestion

**Why:** 3PAO authors PenTest reports, sampling justifications, test
results. Today there's no way to ingest those into the OSCAL chain.

**Depends on:** LOOP-A.A3 (AR chain wiring).

## K.K1 — Penetration Test Report ingest schema + tracker display

**Files:** new `core/pentest-ingest.ts`.

**Build:** Define an OSCAL-extended ingest schema for PenTest findings.
3PAO uploads via tracker. Findings flow into the AR + POA&M (LOOP-A.A1).

## K.K2 — 3PAO test results matrix → OSCAL AR test-result-objects

**Files:** extend `core/oscal.ts`.

**Build:** Per 800-53A Rev 5 procedure objects (assessment objectives +
determination statements + methods + objects) — extend the AR's
`finding.target` to reference these explicitly. Maps tracker sign-offs
(F.F1) to specific procedure-object completions.

---

# REO compliance reminder

Every slice ships under `cloud-evidence/CLAUDE.md`:

1. No stubs, no placeholder strings, no fake data in production paths
2. Every slice's "done" definition: real evidence flows end-to-end +
   signed + tested on the real path + no new lint hits + provenance
   recorded + CHANGELOG entry
3. Operator-supplied data flows through tracker / config / tags / CLI —
   never silently defaulted
4. CI guardrails (`npm run check:reo`) block regressions

When in doubt:
- Read `CLAUDE.md` again
- Look at how LOOP-A handled the REQUIRES-OPERATOR-INPUT pattern
  (`core/oscal-ssp.ts`, `core/oscal-ap.ts`, `core/roe-emit.ts`)
- Look at how LOOP-A.A1 cited real SDK calls in `provenance.sourceCalls`

---

# Open caveats (still valid)

1. **RFC-0014 is a Request for Comment**, not final policy. KSI IDs may
   shift before GA. Our FRMR-JSON-as-source-of-truth pattern absorbs
   minor shifts.
2. **Phase Two pilot post-retrospective format**: may shift the
   submission bundle format. LOOP-A.A4's `package_format_version`
   ("20x.phase-two.preview.2026") supports clean version bumps.
3. **POA&M wire format final**: Excel-only vs OSCAL-only vs both.
   LOOP-A.A1 emits both for safety; LOOP-E.E2 monthly workflow
   re-uses this.
4. **Sampling statistical confidence**: FedRAMP doesn't specify
   thresholds. LOOP-F.F3 uses stratified + 10% floor + AO sign-off.

---

# Per-loop priority ordering for resume

If you need to pick what to do next, this priority order maximizes
downstream leverage:

1. **LOOP-B** — risk engine — unblocks I, F, E
2. **LOOP-C** — document templates — high-volume, parallel-safe
3. **LOOP-D** — diagrams — independent
4. **LOOP-G** — AFR family — independent, R1 already classified
5. **LOOP-E** — ConMon — needs B + C.C6
6. **LOOP-F** — 3PAO UX — needs A.A2 + B.B3
7. **LOOP-H** — storage — independent
8. **LOOP-I** — dashboards — needs B
9. **LOOP-J** — supply chain — independent
10. **LOOP-K** — test ingestion — needs A.A3 (done)

---

# Verification commands

After every slice:
```bash
cd cloud-evidence
npm run typecheck      # must be clean
npm test               # must be 100% passing
npm run check:reo      # G1+G2+G3 must all be green
```

Then commit + push.
