# CCM & SCN — Read-Only Evidence Collector Analysis

Scope: every `CCM-*` (Collaborative Continuous Monitoring, 24) and `SCN-*`
(Significant Change Notifications, 17) requirement = **41 total**. Source of
truth: `cloud-evidence/docs/frmr-requirements.generated.json` (filtered to
family ∈ {CCM, SCN}); FRD term definitions from
`/Users/kenith.philip/FedRAMP 20x/docs/FRMR.documentation.json`
(`FRD.data.both[<FRD-ID>].definition`).

## Honest framing

CCM and SCN are almost entirely **process / governance** requirements. They
govern how a provider *reports* to FedRAMP and agencies (Ongoing Authorization
Reports, Quarterly Reviews) and how a provider *evaluates and notifies* on
significant changes — cadence, content, audit trail, deadlines. They are **not**
about a cloud-API-observable resource state. Of the 41, **zero are
fully `api-testable`**. A handful are **`hybrid`**: the tool can detect that a
supporting *system* exists (a change-management/ticketing workflow, scan
timestamps, a published OAR/SCN feed, a 12-month notification archive URL) and
can monitor *due-dates / cadence* against a tracked register, but the substance
(quality of the report, correctness of the change categorization, the actual
meeting happening) is process-artifact-only.

The right home for the overwhelming majority is a **process-artifact tracker**:
a small register the collector reads (analogous to the existing
`core/subprocessors-sheet.ts` external-register reader) plus the existing
`process_artifacts_required[]` envelope field and the existing
`core/ticket-push.ts` / `core/tracker-push.ts` integrations. The collector's job
for CCM/SCN is mostly: (a) name the exact artifact/attestation that proves
compliance, (b) compute and surface **due-date / cadence monitoring** from
timestamps in that register, and (c) detect the *existence and wiring* of the
supporting workflow where one exists.

### Actor / track note

- **`track: both`** on every CCM and SCN requirement → applies to both the
  20x and Rev5-bridge tracks; no track-specific divergence.
- **Actors:** CCM splits across `AGM` (Agencies — *consumer* of the report, not
  the CSP), `OAR` (Ongoing Authorization Report producer = Provider), `QTR`
  (Quarterly Review host = Provider). SCN splits across `CSO` (Provider, the
  change owner), `ADP`/`TRF`/`RTR` (Provider, by change type), and `FRP`
  (FedRAMP itself).
- **Our org is the CSP (Provider).** The 7 `CCM-AGM-*` requirements have
  `affects: Agencies` and `SCN-FRP-CAP` has `affects: FedRAMP` — these are
  **not our obligations**; we track them only as *context / inbound*
  expectations (e.g. an agency may email FedRAMP about our OAR). They are
  recorded here for completeness but flagged **N/A-to-CSP** and need no
  collector beyond an informational note.

## Level model

- **Low / Moderate** come verbatim from the dump `levels.low` / `levels.moderate`
  (`source: 20x-machine-readable`). For almost all CCM/SCN the L and M statements
  and key_words are **identical**. The notable exception is **CCM-QTR-MTG**
  (Low = SHOULD, Moderate = MUST) and **CCM-AGM-SSR** (MAY at L/M, SHOULD at H).
- **High** is **DERIVED from the NIST 800-53 Rev5 High baseline via `controls[]`**.
  Every CCM/SCN requirement has **`controls: []` (empty)** and
  `levels.high.source: "derived-rev5-pending"`, so there is **no Rev5 control
  anchor to derive from** — High is stated explicitly only where the
  machine-readable dump already carries a distinct High statement
  (`CCM-AGM-SSR`, `CCM-QTR-MTG`). For all others, treat High = Moderate, marked
  `derived(rev5: n/a — controls[] empty, pending)`.

---

## CCM — Collaborative Continuous Monitoring (24)

The CSP-facing core is the **OAR** group (publish a human-readable Ongoing
Authorization Report every 3 months + feedback mechanism + next-report date +
disclosure limits) and the **QTR** group (host a synchronous Quarterly Review
every 3 months, publish next-review date + registration info, record/transcribe,
disclosure limits). The **AGM** group is agency obligations (not ours). The
strongest automation opportunities: **cadence/due-date monitoring** of the OAR
3-month cycle and QTR schedule, and **detecting the published artifacts**
(OAR document, next-report/next-review target dates, registration link/calendar
file) on the provider's authorization-data surface (Trust Center / package).

### CCM coverage table

| ID | Name | L/M/H | Testability | Primary signal |
|----|------|-------|-------------|----------------|
| CCM-AGM-CSC | Consider Security Category | SHOULD/SHOULD/SHOULD* | process-artifact | N/A-to-CSP (agency obligation) |
| CCM-AGM-NAR | No Additional Requirements | MUST NOT | process-artifact | N/A-to-CSP (agency obligation) |
| CCM-AGM-NFA | Notify FedRAMP After Requests | MUST | process-artifact | N/A-to-CSP (agency obligation) |
| CCM-AGM-NFR | Notify FedRAMP of Concerns | MUST | process-artifact | N/A-to-CSP (agency obligation) |
| CCM-AGM-NPC | Notify Provider of Concerns | SHOULD | process-artifact | Inbound: agency concern email to CSP security address |
| CCM-AGM-ROR | Review Ongoing Reports | MUST | process-artifact | N/A-to-CSP (agency obligation) |
| CCM-AGM-SSR | Senior Security Reviewer | MAY/MAY/SHOULD | process-artifact | N/A-to-CSP (agency obligation) |
| CCM-OAR-AVL | Report Availability | MUST | hybrid | Published OAR doc + 3-month cadence vs register |
| CCM-OAR-AFS | Anonymized Feedback Summary | MUST | process-artifact | OAR addendum doc exists |
| CCM-OAR-FBM | Feedback Mechanism | MUST | hybrid | Documented async feedback channel (email/portal URL) |
| CCM-OAR-LSI | Limit Sensitive Information | MUST NOT | process-artifact | Disclosure-review attestation |
| CCM-OAR-NRD | Next Report Date | MUST | hybrid | Next-OAR target date present in public auth data |
| CCM-OAR-RPS | Responsible Public Sharing | MAY | process-artifact | Public-share decision record |
| CCM-OAR-SOR | Spread Out Reports | SHOULD | hybrid | OAR cadence anchored to qtr beginning/middle/end |
| CCM-QTR-ACT | Additional Content | SHOULD | process-artifact | QTR agenda/deck |
| CCM-QTR-MTG | Quarterly Review Meeting | SHOULD/MUST/MUST | hybrid | Quarterly meeting held + 3-month cadence vs register |
| CCM-QTR-NID | No Irresponsible Disclosure | MUST NOT | process-artifact | QTR content-review attestation |
| CCM-QTR-NRD | Next Review Date | MUST | hybrid | Next-QTR target date present in public auth data |
| CCM-QTR-REG | Meeting Registration Info | MUST | hybrid | Registration link / .ics in auth data (ADS-CSL-UCP/ADS-CSO-FCT) |
| CCM-QTR-RTP | Restrict Third Parties | SHOULD NOT | process-artifact | QTR invite list review |
| CCM-QTR-RTR | Record/Transcribe Reviews | SHOULD | hybrid | Recording/transcript artifact available with auth data |
| CCM-QTR-SAR | Schedule Around Reports | SHOULD | hybrid | QTR date ≥3 and ≤10 biz days after OAR release |
| CCM-QTR-SCR | Share Content Responsibly | MAY | process-artifact | Content-share decision record |
| CCM-QTR-SRR | Share Recordings Responsibly | MAY | process-artifact | Redaction + share decision record |

\* High for CCM-AGM-CSC = SHOULD by `derived-rev5-pending` (no distinct High in dump; controls[] empty).

---

## SCN — Significant Change Notifications (17)

SCN governs the provider's significant-change lifecycle. **FRD definitions are
load-bearing here:** a **Significant Change** = "a change likely to substantively
affect the security or privacy posture" (NIST 800-37 Rev2). The provider must
**categorize** every potential significant change (`SCN-CSO-EVA`) into one of:
**Impact Categorization** (changes the L/M/H level — requires a *new assessment*,
not the SCN process), **Transformative** (substantive new risk, assess in depth —
TRF timeline: 30 biz-days initial plan → 10 biz-days final plan → execute →
5 biz-days post-finish → 5 biz-days post-verification), **Adaptive** (no
substantive new risk — notify within 10 biz-days *after* finishing), or
**Routine Recurring** (regularly recurring ops/vuln work — *exempt* from formal
notification). The provider must maintain **auditable evaluation records**
(`SCN-CSO-MAR`), keep **12 months of historical notifications**
(`SCN-CSO-HIS`), publish them **human- and machine-readable** (`SCN-CSO-HRM`),
include **10 required content fields** (`SCN-CSO-INF`), and document the
notification mechanism.

The automation sweet spot for SCN is the **change-management workflow** itself:
the provider almost certainly already runs Jira / ServiceNow / GitHub-based
change management and CI/CD release gates. The collector can (a) **detect the
ticketing/change-mgmt system exists and is wired** (via `core/ticket-push.ts`
config + the third-party-tools detector), (b) **monitor SCN due-dates** computed
from change-start timestamps against the TRF/ADP business-day windows, and
(c) verify the **12-month historical SCN archive** and a **machine-readable feed**
(CSV/JSON) are published. The substance — was a change correctly categorized,
was the impact analysis adequate — stays human/3PAO.

### SCN coverage table

| ID | Name | L/M/H | Testability | Primary signal |
|----|------|-------|-------------|----------------|
| SCN-CSO-EVA | Evaluate Changes | MUST | hybrid | Change-mgmt records show per-change categorization step |
| SCN-CSO-MAR | Maintain Audit Records | MUST | hybrid | Auditable eval records exist (ticket history / log) |
| SCN-CSO-HIS | Historical Notifications | MUST | hybrid | ≥12 months of SCNs present in published archive |
| SCN-CSO-HRM | Human + Machine-Readable | MUST | hybrid | SCN published as both human doc + CSV/JSON feed |
| SCN-CSO-INF | Required Information | MUST | hybrid | All 10 required fields present in each SCN record |
| SCN-CSO-NOM | Notification Mechanisms | MAY | process-artifact | Notification mechanism documented in package |
| SCN-CSO-ARI | Additional Relevant Information | MAY | process-artifact | Optional extra content in SCN |
| SCN-CSO-EMG | Emergency Changes | MAY | hybrid | Emergency-change procedure + retroactive SCN records |
| SCN-ADP-NTF | Adaptive Notification (≤10 biz-days post) | MUST | hybrid | Adaptive-change → notification within 10 biz-days |
| SCN-RTR-NNR | Routine Recurring: No Notification | SHOULD NOT | hybrid | RTR changes correctly excluded from SCN feed |
| SCN-TRF-NIP | TRF Initial Plans (≥30 biz-days before) | MUST | hybrid | Initial-plan notice ≥30 biz-days pre-start |
| SCN-TRF-NFP | TRF Final Plans (≥10 biz-days before) | MUST | hybrid | Final-plan notice ≥10 biz-days pre-start |
| SCN-TRF-NAF | TRF Notify After Finish (≤5 biz-days) | MUST | hybrid | Post-finish notice within 5 biz-days |
| SCN-TRF-NAV | TRF Notify After Verification (≤5 biz-days) | MUST | hybrid | Post-validation notice within 5 biz-days + SAR |
| SCN-TRF-UPD | Update Documentation (≤30 biz-days) | MUST | hybrid | Service docs updated within 30 biz-days post-finish |
| SCN-TRF-TPR | Third-Party Review | SHOULD | hybrid | 3PAO engaged pre-TRF (detect 3PAO tool/SA) |
| SCN-FRP-CAP | Corrective Action Plan Conditions | MAY | process-artifact | N/A-to-CSP (FedRAMP obligation) |

---

# Per-requirement detail

## CCM-AGM (Agency obligations — N/A to our CSP role)

### CCM-AGM-CSC — Consider Security Category  [SHOULD]
- **Track / actor / levels:** both / AGM / L:✓ M:✓ H:derived(rev5: n/a — controls[] empty)
- **Requirement (plain English):** Agencies SHOULD weigh the **Security Category** of the federal system that embeds the cloud service offering (CSO) when assigning resources to review **Ongoing Authorization Reports**, attend **Quarterly Reviews**, and handle other **authorization data**.
- **Testability:** process-artifact
- **Automated validation:** N/A to our org — this is an agency-side staffing decision. Tool tracks it only as an *informational* context row (no finding emitted for the CSP).
- **Required permissions & error handling:** n/a — process artifact (no cloud API).
- **Alternative satisfiers:** Agency-side GRC; not detectable from CSP environment.
- **OSCAL / NIST:** controls[]: none. High derivation: n/a (pending).
- **Module connections:** new process-artifact tracker (informational/context register only).
- **Recommended implementation:** process-artifact-tracker; rationale: outside CSP boundary, record for completeness; effort S.

### CCM-AGM-NAR — No Additional Requirements  [MUST NOT]
- **Track / actor / levels:** both / AGM / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Agencies MUST NOT impose security requirements beyond FedRAMP's on a provider unless the agency head/delegate documents a demonstrable need (clarifying questions are fine). Statutory: 44 USC §3613(e), Presumption of Adequacy.
- **Testability:** process-artifact
- **Automated validation:** N/A to CSP. If an agency *does* levy extra requirements on us, the tool can log the inbound demand as a context artifact (a register row) for our compliance team, but emits no CSP finding.
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** none detectable.
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** new process-artifact tracker (inbound-demands log).
- **Recommended implementation:** process-artifact-tracker; rationale: agency-side; effort S.

### CCM-AGM-NFA — Notify FedRAMP After Requests  [MUST]
- **Track / actor / levels:** both / AGM / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** After an agency requests extra info/materials from a provider beyond FedRAMP's baseline, the agency MUST email info@fedramp.gov. (OMB M-24-15 §IV(a).)
- **Testability:** process-artifact
- **Automated validation:** N/A to CSP — agency emails FedRAMP, not us. No CSP-side signal.
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** none detectable.
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** new process-artifact tracker (informational).
- **Recommended implementation:** process-artifact-tracker; rationale: agency-side; effort S.

### CCM-AGM-NFR — Notify FedRAMP of Concerns  [MUST]
- **Track / actor / levels:** both / AGM / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** If an OAR, Quarterly Review, or other authorization data raises concerns that might lead an agency to stop using the CSO, the agency MUST email info@fedramp.gov. (OMB M-24-15 §IV(a).)
- **Testability:** process-artifact
- **Automated validation:** N/A to CSP. Indirectly relevant: our OAR/QTR quality drives whether this fires; tool can correlate to our OAR register but emits no CSP finding.
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** none detectable.
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** new process-artifact tracker (informational).
- **Recommended implementation:** process-artifact-tracker; rationale: agency-side; effort S.

### CCM-AGM-NPC — Notify Provider of Concerns  [SHOULD]
- **Track / actor / levels:** both / AGM / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Agencies SHOULD formally notify the **provider** (us) if an OAR/QTR/authorization data raises concerns that may lead them to remove the CSO from operation. Notification target = CSP security email.
- **Testability:** process-artifact (only inbound-detectable)
- **Automated validation:** This is the one AGM item with a CSP-side touchpoint: the provider *receives* the notice. Tool tracks an **inbound-concern register** keyed to a documented CSP security-contact mailbox; a human logs received concerns + response SLA. No cloud API.
- **Required permissions & error handling:** n/a — process artifact. (If later wired to a shared mailbox/ticket queue, reuse `core/ticket-push.ts` read path.)
- **Alternative satisfiers:** Concerns arriving via the OAR feedback mechanism (CCM-OAR-FBM) channel — shared remediation.
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** new process-artifact tracker (inbound-concern log); relates to CCM-OAR-FBM.
- **Recommended implementation:** process-artifact-tracker; rationale: CSP only receives; effort S.

### CCM-AGM-ROR — Review Ongoing Reports  [MUST]
- **Track / actor / levels:** both / AGM / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Agencies MUST review each OAR to understand how CSO changes affect the risk tolerance in their system's ATO. (44 USC §35, OMB A-130, FIPS-200, M-24-15.)
- **Testability:** process-artifact
- **Automated validation:** N/A to CSP — agency-side review activity. No CSP signal.
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** none detectable.
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** new process-artifact tracker (informational).
- **Recommended implementation:** process-artifact-tracker; rationale: agency-side; effort S.

### CCM-AGM-SSR — Senior Security Reviewer  [MAY → SHOULD@High]
- **Track / actor / levels:** both / AGM / L:MAY ✓ M:MAY ✓ H:SHOULD ✓ (distinct High in dump; derived(rev5: n/a — controls[] empty))
- **Requirement (plain English):** Agencies MAY (SHOULD at High) designate a senior information-security official to review OARs and represent the agency at Quarterly Reviews, scaled to the system's Security Objective (Low/Moderate/High).
- **Testability:** process-artifact
- **Automated validation:** N/A to CSP — agency staffing. No CSP signal. (Note: this is one of only two CCM/SCN reqs with a genuinely distinct High statement.)
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** none detectable.
- **OSCAL / NIST:** controls[]: none. High: explicit SHOULD in dump (not control-derived).
- **Module connections:** new process-artifact tracker (informational).
- **Recommended implementation:** process-artifact-tracker; rationale: agency-side; effort S.

## CCM-OAR (Ongoing Authorization Report — our CSP obligation)

### CCM-OAR-AVL — Report Availability  [MUST]
- **Track / actor / levels:** both / OAR / L:✓ M:✓ H:derived(rev5: n/a — controls[] empty)
- **Requirement (plain English):** We MUST publish an **Ongoing Authorization Report** to **all necessary parties** (always FedRAMP + agency customers) **every 3 months**, covering the whole period since the last one, in a consistent human-readable format. It MUST summarize at least: (1) changes to authorization data, (2) planned changes over the next ≥3 months, (3) **accepted vulnerabilities**, (4) **transformative changes**, (5) updated security/config/usage recommendations.
- **Testability:** hybrid
- **Automated validation:** (a) **Cadence monitoring** — read the OAR register (publish dates + next-due date) and compute whether the 3-month interval is being met; raise a finding when `now > last_publish + ~3mo` or the next-due date has lapsed. (b) **Artifact presence** — detect a published OAR document at the configured authorization-data URL (Trust Center / package). (c) **Section completeness** — if the OAR is published as structured JSON/CSV (encouraged), check the 5 required summary sections exist. Substance/quality stays human. Several inputs (accepted vulnerabilities, transformative changes) can be *cross-fed* from the collector's own VDR/SCN evidence to pre-populate or sanity-check the OAR.
- **Required permissions & error handling:** n/a for the cadence/section check (reads a register/file). If the OAR doc is fetched over HTTP, handle 404/timeout as "artifact-not-found" warning (reuse network-error diagnostics pattern from `core/error-diagnostics.ts`).
- **Alternative satisfiers:** GRC platforms that generate ConMon deliverables (Vanta, Drata, Paramify, SecureFrame) — detect via `core/detect/third-party-tools.ts`; Paramify specifically authors FedRAMP packages. Signal: GRC IAM principal/SA present.
- **OSCAL / NIST:** controls[]: none in dump. Conceptually aligns to CA-7 (Continuous Monitoring) / PM-31 if a Rev5 anchor is later assigned. High derivation: n/a (pending).
- **Module connections:** new **OAR/QTR cadence tracker** (register reader modeled on `core/subprocessors-sheet.ts`); cross-feeds from VDR (accepted vulns) and SCN (transformative changes) evidence; `process_artifacts_required[]` carries "published OAR document".
- **Recommended implementation:** hybrid; rationale: cadence + artifact-presence + section-completeness are automatable, content quality is not; effort M.

### CCM-OAR-AFS — Anonymized Feedback Summary  [MUST]
- **Track / actor / levels:** both / OAR / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We MUST keep an **anonymized, desensitized** summary of feedback/Q&A about each OAR as an **addendum** to that OAR (reduces duplicate agency questions; gives FedRAMP visibility).
- **Testability:** process-artifact
- **Automated validation:** Track that an addendum artifact exists per OAR cycle (register row linking OAR → addendum doc URL + last-updated date). Cannot verify anonymization quality. Optionally check the addendum was updated within the quarter.
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** OAR feedback captured/anonymized in a GRC tool or support portal (Zendesk/Intercom) — process signal only.
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** OAR/QTR tracker (addendum register), tied to CCM-OAR-FBM.
- **Recommended implementation:** process-artifact-tracker; rationale: artifact existence/freshness trackable, content not; effort S.

### CCM-OAR-FBM — Feedback Mechanism  [MUST]
- **Track / actor / levels:** both / OAR / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We MUST establish and share an **asynchronous** channel for all necessary parties to give feedback / ask questions about each OAR (email by default; a more interactive channel is encouraged).
- **Testability:** hybrid
- **Automated validation:** Detect that a documented feedback channel exists and is reachable: a configured email address or portal/form URL in the authorization-data surface. Tool checks the config field is populated and (optionally) the URL resolves. Cannot verify responsiveness.
- **Required permissions & error handling:** n/a — process artifact / optional HTTP reachability check (handle network errors as warning).
- **Alternative satisfiers:** Support desk / community portal / Slack Connect channel documented in package — process signal.
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** OAR/QTR tracker (channel-config presence + reachability); relates to CCM-AGM-NPC.
- **Recommended implementation:** hybrid; rationale: existence/reachability detectable, quality not; effort S.

### CCM-OAR-LSI — Limit Sensitive Information  [MUST NOT]
- **Track / actor / levels:** both / OAR / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We MUST NOT irresponsibly disclose sensitive info in an OAR that would **likely** ("reasonable degree of probability") have an adverse effect on the CSO.
- **Testability:** process-artifact
- **Automated validation:** Track an attestation that each OAR underwent a sensitivity/disclosure review before publication (register row: OAR → reviewer + review-date). Substance is a human judgment; not API-testable. (A DLP/secret-scanner could flag obvious leaks in a published OAR doc, but that is a weak heuristic, not validation.)
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** DLP / secret-scanning pre-publish gate (e.g. gitleaks on the OAR repo) — detectable as a CI step; weak partial signal only.
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** OAR/QTR tracker (disclosure-review attestation).
- **Recommended implementation:** process-artifact-tracker; rationale: judgment call; effort S.

### CCM-OAR-NRD — Next Report Date  [MUST]
- **Track / actor / levels:** both / OAR / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We MUST publicly include the **target date for the next OAR** alongside other public authorization data.
- **Testability:** hybrid
- **Automated validation:** Read the next-OAR target date from the published authorization-data surface (or the OAR register) and assert (a) it is present, (b) it is a future date, (c) it is ≤ ~3 months out. This is a concrete, automatable check off a register/feed.
- **Required permissions & error handling:** n/a — register read; HTTP-fetch errors → "next-report-date not found" warning.
- **Alternative satisfiers:** Trust Center platform (SafeBase, Vanta Trust Center) publishing the date — detect via published-feed presence.
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** OAR/QTR tracker (next-due-date monitor) — shares the cadence machinery with CCM-OAR-AVL.
- **Recommended implementation:** hybrid; rationale: date presence + sanity check fully automatable; effort S.

### CCM-OAR-RPS — Responsible Public Sharing  [MAY]
- **Track / actor / levels:** both / OAR / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We MAY share some/all of an OAR publicly or with other parties **if** we determine it will NOT likely adversely affect the CSO. (Permissive — not an obligation.)
- **Testability:** process-artifact
- **Automated validation:** No compliance gate (MAY). If exercised, track a decision record (what was shared, the no-adverse-effect determination, approver). Tool records but never fails.
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** Public Trust Center publication — detectable as a public feed if used.
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** OAR/QTR tracker (optional decision-record register).
- **Recommended implementation:** process-artifact-tracker; rationale: permissive, record-only; effort S.

### CCM-OAR-SOR — Spread Out Reports  [SHOULD]
- **Track / actor / levels:** both / OAR / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We SHOULD set a **regular** 3-month OAR cycle anchored to the **beginning, middle, or end** of each quarter (so agencies aren't swamped by every CSP reporting in week 1 or the last week).
- **Testability:** hybrid
- **Automated validation:** From the OAR publish-date history in the register, classify the anchor (qtr beginning/middle/end) and check the cadence is *regular* (consistent offset, ~90-day spacing). Raise an advisory finding if dates cluster at quarter edges or are irregular.
- **Required permissions & error handling:** n/a — register read.
- **Alternative satisfiers:** Scheduling discipline enforced by a GRC calendar — process signal.
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** OAR/QTR tracker (cadence-pattern analysis) — shares machinery with CCM-OAR-AVL.
- **Recommended implementation:** hybrid; rationale: cadence/anchor pattern computable from dates; effort S.

## CCM-QTR (Quarterly Review — our CSP obligation)

### CCM-QTR-ACT — Additional Content  [SHOULD]
- **Track / actor / levels:** both / QTR / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We SHOULD include additional info in Quarterly Reviews that we judge useful/relevant to agencies.
- **Testability:** process-artifact
- **Automated validation:** Track that QTR agenda/deck artifacts exist per cycle; cannot judge relevance. Record-only.
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** none detectable.
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** OAR/QTR tracker (QTR-content register).
- **Recommended implementation:** process-artifact-tracker; rationale: judgment; effort S.

### CCM-QTR-MTG — Quarterly Review Meeting  [SHOULD@Low / MUST@Mod / MUST@High]
- **Track / actor / levels:** both / QTR / L:SHOULD ✓ M:MUST ✓ H:MUST ✓ (distinct per-level key_words in dump; H not control-derived)
- **Requirement (plain English):** We SHOULD (Low) / MUST (Moderate & High) host a **synchronous Quarterly Review** every 3 months, open to all necessary parties, covering the most agency-relevant parts of recent OARs. **Level-sensitive** — this is one of only two CCM/SCN reqs where the obligation strengthens with level.
- **Testability:** hybrid
- **Automated validation:** **Cadence monitoring** from the QTR register (meeting-held dates + next-scheduled date): assert a meeting occurred within each 3-month window; raise a finding when overdue. Severity should scale with the selected level (advisory at Low, failing at Mod/High). Cannot verify attendance/content.
- **Required permissions & error handling:** n/a — register read.
- **Alternative satisfiers:** Calendar/webinar platform (Zoom/Teams/On24) event history exported into the register — process signal; could be cross-checked if an export is provided.
- **OSCAL / NIST:** controls[]: none. High: explicit MUST in dump (level-driven, not control-derived).
- **Module connections:** OAR/QTR tracker (meeting-cadence monitor); the level selector must read M/H to flip severity.
- **Recommended implementation:** hybrid; rationale: held-vs-due cadence automatable, level-aware; effort M.

### CCM-QTR-NID — No Irresponsible Disclosure  [MUST NOT]
- **Track / actor / levels:** both / QTR / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We MUST NOT irresponsibly disclose sensitive info in a Quarterly Review that would likely adversely affect the CSO.
- **Testability:** process-artifact
- **Automated validation:** Track a content-review attestation per QTR (reviewer + date). Judgment-based; not API-testable. Mirrors CCM-OAR-LSI.
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** Pre-review of QTR deck by security/legal — process signal.
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** OAR/QTR tracker (QTR disclosure-review attestation).
- **Recommended implementation:** process-artifact-tracker; rationale: judgment; effort S.

### CCM-QTR-NRD — Next Review Date  [MUST]
- **Track / actor / levels:** both / QTR / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We MUST publicly include the **target date for the next Quarterly Review** with other public authorization data.
- **Testability:** hybrid
- **Automated validation:** Same pattern as CCM-OAR-NRD: read next-QTR date from the published surface / register; assert present, future, ≤ ~3 months out.
- **Required permissions & error handling:** n/a — register read; HTTP errors → warning.
- **Alternative satisfiers:** Trust Center publishing the date.
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** OAR/QTR tracker (next-QTR-date monitor).
- **Recommended implementation:** hybrid; rationale: date presence + sanity check automatable; effort S.

### CCM-QTR-REG — Meeting Registration Info  [MUST]
- **Track / actor / levels:** both / QTR / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We MUST include either a **registration link** or a **downloadable calendar file** with QTR meeting info in the authorization data made available to all necessary parties (per **ADS-CSL-UCP** and **ADS-CSO-FCT**).
- **Testability:** hybrid
- **Automated validation:** Check the authorization-data surface / register has a populated registration URL **or** an `.ics` calendar artifact. Optionally validate the URL resolves / the `.ics` parses. Cross-reference the ADS-CSL-UCP / ADS-CSO-FCT evidence (same auth-data surface) for consistency.
- **Required permissions & error handling:** n/a — register/file read; URL fetch errors → warning.
- **Alternative satisfiers:** Webinar platform registration page (On24/Zoom Webinar) linked in package.
- **OSCAL / NIST:** controls[]: none. High: n/a. Cross-req: ADS-CSL-UCP, ADS-CSO-FCT.
- **Module connections:** OAR/QTR tracker (registration-artifact presence); relates to ADS family evidence.
- **Recommended implementation:** hybrid; rationale: artifact presence + format check automatable; effort S.

### CCM-QTR-RTP — Restrict Third Parties  [SHOULD NOT]
- **Track / actor / levels:** both / QTR / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We SHOULD NOT invite third parties to agency-intended Quarterly Reviews unless they have specific relevance (the CSP's own 3PAO is relevant by default; agencies engage less openly with outsiders present).
- **Testability:** process-artifact
- **Automated validation:** Track a QTR invite/attendee-list review attestation. Cannot validate "relevance." Record-only advisory.
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** none detectable.
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** OAR/QTR tracker (invite-list register).
- **Recommended implementation:** process-artifact-tracker; rationale: judgment; effort S.

### CCM-QTR-RTR — Record/Transcribe Reviews  [SHOULD]
- **Track / actor / levels:** both / QTR / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We SHOULD record or transcribe Quarterly Reviews and make them available to all necessary parties with other authorization data.
- **Testability:** hybrid
- **Automated validation:** Check that a recording/transcript artifact (URL or file) is linked in the QTR register per cycle, and (optionally) that it is reachable. Cannot verify content fidelity.
- **Required permissions & error handling:** n/a — register read; fetch errors → warning.
- **Alternative satisfiers:** Auto-transcription (Zoom cloud recording, Otter, Fireflies) feed into the register — process signal.
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** OAR/QTR tracker (recording-artifact presence).
- **Recommended implementation:** hybrid; rationale: artifact presence/reachability automatable; effort S.

### CCM-QTR-SAR — Schedule Around Reports  [SHOULD]
- **Track / actor / levels:** both / QTR / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We SHOULD **regularly** schedule each Quarterly Review to land **≥3 business days after** releasing an OAR **and within 10 business days** of that release.
- **Testability:** hybrid
- **Automated validation:** Cross the OAR-release date and QTR-meeting date from the two registers; compute business-day delta; assert `3 ≤ Δbiz-days ≤ 10`. Fully computable from two timestamps — the strongest QTR automation. Requires a business-day calendar (US federal holidays) helper.
- **Required permissions & error handling:** n/a — register read.
- **Alternative satisfiers:** Scheduling automation in a GRC calendar — process signal.
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** OAR/QTR tracker (cross-date business-day check) — needs a shared `bizdays.ts` helper (also used by all SCN timelines).
- **Recommended implementation:** hybrid; rationale: deterministic date math; effort M (the biz-day helper is shared infra).

### CCM-QTR-SCR — Share Content Responsibly  [MAY]
- **Track / actor / levels:** both / QTR / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We MAY share QTR-prepared content publicly/with others **if** we determine it will NOT likely adversely affect the CSO. (Permissive.)
- **Testability:** process-artifact
- **Automated validation:** No gate (MAY). If exercised, record the share + no-adverse-effect determination. Never fails.
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** Public Trust Center.
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** OAR/QTR tracker (optional decision-record).
- **Recommended implementation:** process-artifact-tracker; rationale: permissive, record-only; effort S.

### CCM-QTR-SRR — Share Recordings Responsibly  [MAY]
- **Track / actor / levels:** both / QTR / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We MAY share QTR recordings/transcripts publicly/with others **only if** we remove all agency info (comments, questions, names) **and** determine sharing won't likely adversely affect the CSO. (Permissive, conditional.)
- **Testability:** process-artifact
- **Automated validation:** No gate (MAY). If exercised, record a redaction attestation + no-adverse-effect determination. Cannot verify redaction completeness.
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** none detectable.
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** OAR/QTR tracker (redaction + share decision-record).
- **Recommended implementation:** process-artifact-tracker; rationale: permissive + judgment; effort S.

---

## SCN-CSO (Significant-change evaluation & publication — our CSP obligation)

### SCN-CSO-EVA — Evaluate Changes  [MUST]
- **Track / actor / levels:** both / CSO / L:✓ M:✓ H:derived(rev5: n/a — controls[] empty)
- **Requirement (plain English):** We MUST evaluate every **potential significant change** ("a change likely to substantively affect the security or privacy posture") and categorize it to apply the right SCN process. Decision tree: significant? → if yes, **Impact Categorization** (changes L/M/H → needs a *new assessment*, not SCN); else **Routine Recurring** (→ RTR process, exempt); else **Transformative** (→ TRF process); else **Adaptive** (→ ADP process).
- **Testability:** hybrid
- **Automated validation:** Detect the change-management workflow exists and carries a **categorization step**: e.g. a required "SCN-type" field/label on change tickets in Jira/ServiceNow, or a PR/release template field in GitHub. Tool reads the change-mgmt source (via `core/ticket-push.ts` read path or a register export) and checks every change in the period has a categorization value from the valid set {impact-categorization, transformative, adaptive, routine-recurring, not-significant}. Cannot judge whether the categorization is *correct* — that is human/3PAO. Detect the system itself via `core/detect/third-party-tools.ts` (extend with ServiceNow/Jira change-mgmt signatures).
- **Required permissions & error handling:** n/a for cloud APIs; if reading Jira/ServiceNow/GitHub via API, needs *read-only* API token for the change project/table; on 401/403 emit "grant read-only access to <project>" diagnostic (mirror `diagnose*Error` pattern).
- **Alternative satisfiers:** Change-management in ServiceNow/Jira with mandatory categorization field; GRC tools (Vanta/Drata) that track change events. Signal: ticketing IAM principal / configured `ticket-push` backend / SA name.
- **OSCAL / NIST:** controls[]: none in dump. Conceptually CM-3 / CM-4 (change control / impact analysis) / RA-3 if a Rev5 anchor is assigned. High: n/a (pending).
- **Module connections:** new **SCN tracker** + extend `core/detect/third-party-tools.ts` (Jira/ServiceNow change-mgmt) + reuse `core/ticket-push.ts` read path.
- **Recommended implementation:** hybrid; rationale: existence + per-change categorization-field presence detectable, correctness not; effort M.

### SCN-CSO-MAR — Maintain Audit Records  [MUST]
- **Track / actor / levels:** both / CSO / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We MUST maintain **auditable records** of the SCN-CSO-EVA evaluation activities and make them available to FedRAMP on request (they need not be in the authorization package by default).
- **Testability:** hybrid
- **Automated validation:** Verify the evaluation records are durable and queryable: change tickets retained with their categorization history, or a maintained evaluation log/CSV. Tool checks the record store is reachable, non-empty for the period, and that records carry evaluator + timestamp. Reuse the existing immutability/audit posture (the tracker already has an audit-log search UI).
- **Required permissions & error handling:** read-only access to the change-mgmt store / log; 403 → diagnostic.
- **Alternative satisfiers:** ServiceNow change audit history; Jira issue history; immutable log store (CloudTrail/Cloud Logging if change actions are logged) — partial signal.
- **OSCAL / NIST:** controls[]: none. CM-3(6)/AU family conceptually. High: n/a.
- **Module connections:** SCN tracker (record-presence + retention check); relates to MLA/audit-log evidence.
- **Recommended implementation:** hybrid; rationale: record existence/retention detectable, completeness partial; effort M.

### SCN-CSO-HIS — Historical Notifications  [MUST]
- **Track / actor / levels:** both / CSO / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We MUST keep **12 months** of historical Significant Change Notifications available with our authorization data.
- **Testability:** hybrid
- **Automated validation:** Read the published SCN archive/feed and assert it contains a continuous trailing **12-month** window (oldest entry ≤ now−12mo, no large gaps). Concrete, date-driven check off the feed.
- **Required permissions & error handling:** n/a — feed read; HTTP errors → "SCN archive not reachable" warning.
- **Alternative satisfiers:** Trust Center / package portal hosting the SCN history; GRC document repository.
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** SCN tracker (archive-window check); shares the published-feed reader with SCN-CSO-HRM.
- **Recommended implementation:** hybrid; rationale: trailing-window check automatable; effort S.

### SCN-CSO-HRM — Human and Machine-Readable  [MUST]
- **Track / actor / levels:** both / CSO / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We MUST make ALL SCNs and related audit records available in both **human-readable** and **machine-readable** ("processable by a computer without human intervention, no semantic loss" — 44 USC §3502(18)) formats. (Beta CSPs often used well-structured CSV to satisfy both at once.)
- **Testability:** hybrid
- **Automated validation:** Detect both representations are published: a human doc (HTML/PDF/Markdown) **and** a machine feed (CSV/JSON). Tool fetches the machine feed, validates it parses and conforms to an expected SCN schema (the 10 fields of SCN-CSO-INF), and checks a human-readable counterpart link exists.
- **Required permissions & error handling:** n/a — feed read + parse; parse/HTTP errors → warning naming the bad format.
- **Alternative satisfiers:** Trust Center exposing JSON/CSV export; OSCAL POA&M/feed (cross-link to `core/oscal.ts` output format).
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** SCN tracker (dual-format presence + schema validation, reuse ajv harness from existing schema-validation work).
- **Recommended implementation:** hybrid; rationale: format presence + machine-feed schema validation automatable; effort M.

### SCN-CSO-INF — Required Information  [MUST]
- **Track / actor / levels:** both / CSO / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Each SCN MUST include at least these **10 fields**: Service Offering FedRAMP ID; Assessor Name (if applicable); Related POA&M (if applicable); Significant Change type + categorization explanation; short change description; reason for change; customer-impact summary (incl. changes to customer config responsibilities); plan & timeline for the change incl. verification/assessment/validation of impacted KSIs/controls (**Persistent Validation**); copy of the business/security impact analysis; approver name & title.
- **Testability:** hybrid
- **Automated validation:** If SCNs are published as the machine-readable feed (SCN-CSO-HRM), **schema-validate each record for the 10 required fields** (treating the "if applicable" ones as conditionally required). This is the most concretely automatable SCN content check. Tool emits per-record findings listing missing fields. Field *accuracy* stays human.
- **Required permissions & error handling:** n/a — feed read; schema validation via ajv (reuse existing harness).
- **Alternative satisfiers:** GRC/ServiceNow SCN template enforcing required fields at entry; Paramify SCN authoring.
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** SCN tracker (per-record field validation) — shares feed reader + ajv with SCN-CSO-HRM.
- **Recommended implementation:** hybrid; rationale: presence-of-required-fields fully automatable against a feed; effort M.

### SCN-CSO-NOM — Notification Mechanisms  [MAY]
- **Track / actor / levels:** both / CSO / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We MAY notify parties in various ways as long as the **mechanism is clearly documented in the authorization package and easily accessible**. (Permissive on *how*, but documentation is the implicit bar.)
- **Testability:** process-artifact
- **Automated validation:** Check the package documents a notification mechanism (config field populated / doc link present). Permissive — record-only with an advisory if undocumented.
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** Documented email distribution list, Trust Center subscription, webhook/RSS feed — process signal (could detect a configured `notify`/webhook backend via `core/notify.ts` / `core/webhook-push.ts`).
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** SCN tracker (mechanism-documented check); relates to `core/notify.ts`.
- **Recommended implementation:** process-artifact-tracker; rationale: permissive; effort S.

### SCN-CSO-ARI — Additional Relevant Information  [MAY]
- **Track / actor / levels:** both / CSO / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We MAY include additional relevant info in SCNs (lets providers convey extra context without template anxiety).
- **Testability:** process-artifact
- **Automated validation:** No gate (MAY). Nothing to validate; do not emit a finding. Record-only if desired.
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** n/a.
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** SCN tracker (no-op / optional note).
- **Recommended implementation:** process-artifact-tracker; rationale: permissive no-op; effort S.

### SCN-CSO-EMG — Emergency Changes  [MAY]
- **Track / actor / levels:** both / CSO / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We MAY execute significant changes (incl. transformative) during an **emergency or incident** ("occurrence jeopardizing CIA of federal customer data") without meeting SCN requirements **in advance** — but then MUST follow all relevant procedures, notify all necessary parties, **retroactively** provide all SCN materials, and complete assessment after the incident. Emergency procedures should be documented in the package.
- **Testability:** hybrid
- **Automated validation:** Two parts: (1) check a documented emergency-change procedure exists in the package (artifact presence). (2) For any change flagged "emergency" in the change-mgmt store, verify retroactive SCN materials were produced and linked, and a post-incident assessment record exists. Detect emergency-change tickets via a label/field; check the follow-up artifacts are attached. Substance is human.
- **Required permissions & error handling:** read-only change-mgmt access; 403 → diagnostic.
- **Alternative satisfiers:** Incident process in PagerDuty/ServiceNow with post-incident review tied to change record — detect via incident-tool signature.
- **OSCAL / NIST:** controls[]: none. IR family / CM-3 emergency-change conceptually. High: n/a.
- **Module connections:** SCN tracker (emergency-flag → retroactive-materials linkage); relates to INR/incident evidence + `core/notify.ts`.
- **Recommended implementation:** hybrid; rationale: procedure presence + retroactive-artifact linkage detectable; effort M.

## SCN-ADP / SCN-RTR / SCN-TRF (change-type processes)

### SCN-ADP-NTF — Adaptive Notification Requirements  [MUST]
- **Track / actor / levels:** both / ADP / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** For **adaptive** changes (no substantive new risk), we MUST notify all necessary parties **within 10 business days after finishing**, by updating authorization data, also including a summary of any new risks/POA&Ms resulting (if applicable).
- **Testability:** hybrid
- **Automated validation:** For each adaptive-categorized change, compute business-day delta between `finish_date` and `notification_date`; assert `Δ ≤ 10 biz-days`. Surface overdue/at-risk items via **due-date monitoring** (the notification is due 10 biz-days after finish; flag amber as the deadline approaches, red when breached). Also check the new-risk/POA&M summary field is present when applicable.
- **Required permissions & error handling:** n/a — register/feed read; needs the shared `bizdays.ts` helper.
- **Alternative satisfiers:** Change-mgmt SLA automation that auto-notifies on close — detect via ticketing/notify config.
- **OSCAL / NIST:** controls[]: none. CM-3 / CM-4 conceptually. High: n/a.
- **Module connections:** SCN tracker (deadline monitor) + `bizdays.ts` + `core/notify.ts` for alerting on approaching deadlines.
- **Recommended implementation:** hybrid; rationale: deterministic biz-day deadline math + monitoring; effort M.

### SCN-RTR-NNR — No Notification Requirements (Routine Recurring)  [SHOULD NOT]
- **Track / actor / levels:** both / RTR / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We SHOULD NOT make formal SCNs for **routine recurring** changes (regularly recurring ops/vuln work) — this type is **exempt** from notification.
- **Testability:** hybrid
- **Automated validation:** Negative/consistency check: confirm changes categorized "routine-recurring" are **excluded** from the formal SCN feed (i.e. no over-notification), and conversely flag if RTR-labeled items are erroneously generating SCNs. Advisory severity (SHOULD NOT).
- **Required permissions & error handling:** n/a — feed/register read.
- **Alternative satisfiers:** Change-mgmt rules that auto-exempt RTR categories — process signal.
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** SCN tracker (categorization-vs-feed consistency); relates to SCN-CSO-EVA.
- **Recommended implementation:** hybrid; rationale: cross-checking categorization against the feed is automatable; effort S.

### SCN-TRF-NIP — Notification of Initial Plans  [MUST]
- **Track / actor / levels:** both / TRF / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** For **transformative** changes (substantive new risk, assessed in depth), we MUST notify all necessary parties of **initial plans at least 30 business days before starting**, including a summary of likely security impacts / risk changes.
- **Testability:** hybrid
- **Automated validation:** For each transformative change, assert `start_date − initial_plan_notification_date ≥ 30 biz-days`. Lead-time monitoring: surface upcoming TRF starts that lack a logged ≥30-biz-day-prior initial notice. Check the security-impact summary field present.
- **Required permissions & error handling:** n/a — register/feed read; `bizdays.ts`.
- **Alternative satisfiers:** Release-planning workflow with mandatory advance-notice gate — process signal.
- **OSCAL / NIST:** controls[]: none. CM-3/CM-4. High: n/a.
- **Module connections:** SCN tracker (lead-time monitor) + `bizdays.ts`.
- **Recommended implementation:** hybrid; rationale: deterministic lead-time math; effort M (shares TRF timeline engine with NFP/NAF/NAV/UPD).

### SCN-TRF-NFP — Notification of Final Plans  [MUST]
- **Track / actor / levels:** both / TRF / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We MUST notify all necessary parties of **final plans at least 10 business days before starting** transformative changes, including updates to all previously sent info.
- **Testability:** hybrid
- **Automated validation:** Assert `start_date − final_plan_notification_date ≥ 10 biz-days`; verify the final-plan notice references/updates the initial-plan info (linkage check).
- **Required permissions & error handling:** n/a — register/feed read; `bizdays.ts`.
- **Alternative satisfiers:** Release-gate workflow — process signal.
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** SCN tracker (TRF timeline engine) + `bizdays.ts`.
- **Recommended implementation:** hybrid; rationale: deterministic lead-time check; effort M (shared engine).

### SCN-TRF-NAF — Notification After Finishing  [MUST]
- **Track / actor / levels:** both / TRF / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We MUST notify all necessary parties **within 5 business days after finishing** transformative changes, including updates to all previously sent info.
- **Testability:** hybrid
- **Automated validation:** Assert `post_finish_notification_date − finish_date ≤ 5 biz-days`; deadline monitoring on each finished TRF change.
- **Required permissions & error handling:** n/a — register/feed read; `bizdays.ts`.
- **Alternative satisfiers:** Auto-notify-on-close automation.
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** SCN tracker (TRF timeline engine) + `bizdays.ts` + `core/notify.ts`.
- **Recommended implementation:** hybrid; rationale: deterministic deadline check; effort M (shared engine).

### SCN-TRF-NAV — Notification After Verification  [MUST]
- **Track / actor / levels:** both / TRF / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We MUST notify all necessary parties **within 5 business days after completing the verification/assessment/validation** (**Persistent Validation** of impacted KSIs) of transformative changes, also including: updates to all previously sent info; summary of new risks/POA&Ms (if applicable); copy of the security assessment report (if applicable).
- **Testability:** hybrid
- **Automated validation:** Assert `post_verification_notification_date − verification_complete_date ≤ 5 biz-days`; check the required attachments (new-risk summary, SAR-if-applicable) are present. The "verification of impacted KSIs" can cross-link to the collector's *own* re-run evidence for the affected KSIs (Persistent Validation tie-in).
- **Required permissions & error handling:** n/a — register/feed read; `bizdays.ts`.
- **Alternative satisfiers:** 3PAO/GRC assessment workflow producing the SAR.
- **OSCAL / NIST:** controls[]: none. CA-2/CA-7. High: n/a.
- **Module connections:** SCN tracker (TRF timeline engine) + cross-link to KSI re-collection evidence (AFR-PVA) + `bizdays.ts`.
- **Recommended implementation:** hybrid; rationale: deadline + attachment-presence check, KSI cross-link; effort M (shared engine).

### SCN-TRF-NFP / NAF / NAV consolidate into one TRF timeline engine

### SCN-TRF-UPD — Update Documentation  [MUST]
- **Track / actor / levels:** both / TRF / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We MUST publish updated **service documentation** (user guides, marketplace listing, similar materials — *not* the SSP/authorization package) to reflect transformative changes **within 30 business days after finishing**.
- **Testability:** hybrid
- **Automated validation:** Assert a doc-update artifact (or doc repo commit / "last updated" timestamp) exists within 30 biz-days of TRF finish. If service docs live in a git repo or docs site, the "last modified" date is directly readable. Cannot verify content adequacy.
- **Required permissions & error handling:** n/a — register/repo read; `bizdays.ts`.
- **Alternative satisfiers:** Docs-as-code pipeline (GitBook/Docusaurus/readme.io) with commit timestamps — strong signal if connected.
- **OSCAL / NIST:** controls[]: none. CM-3 documentation. High: n/a.
- **Module connections:** SCN tracker (doc-freshness vs finish-date) + `bizdays.ts`.
- **Recommended implementation:** hybrid; rationale: deadline math + doc-timestamp detectable; effort M.

### SCN-TRF-TPR — Third-Party Review  [SHOULD]
- **Track / actor / levels:** both / TRF / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** We SHOULD engage a **third-party assessor** to review scope/impact **before starting** transformative changes **if human validation is necessary**; such reviews SHOULD be limited to security decisions that require human validation. (TRF changes are rare for most CSOs.)
- **Testability:** hybrid
- **Automated validation:** For TRF changes where human validation is flagged, check a 3PAO-review artifact (engagement record / signed review) exists pre-start. Detect the presence of a 3PAO/assessor relationship via tooling (extend `core/detect/third-party-tools.ts` — Paramify/3PAO accounts) or a configured assessor in the register. Advisory (SHOULD).
- **Required permissions & error handling:** n/a — register read; tool-detection signals.
- **Alternative satisfiers:** Paramify (FedRAMP authoring) / engaged 3PAO IAM principal; GRC assessment module.
- **OSCAL / NIST:** controls[]: none. CA-2 (independent assessment). High: n/a.
- **Module connections:** SCN tracker (3PAO-engagement-pre-start check) + `core/detect/third-party-tools.ts`.
- **Recommended implementation:** hybrid; rationale: artifact-presence + assessor detection; effort S.

## SCN-FRP (FedRAMP obligation — N/A to our CSP role)

### SCN-FRP-CAP — Corrective Action Plan Conditions  [MAY]
- **Track / actor / levels:** both / FRP / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** **FedRAMP** MAY require a provider to delay significant changes beyond the standard SCN period and/or submit changes for advance approval as a condition of a formal Corrective Action Plan (CAP) or other agreement.
- **Testability:** process-artifact
- **Automated validation:** N/A to our org — this is a FedRAMP power, not a CSP obligation. If we are *subject* to a CAP, track the imposed conditions (delay period, advance-approval gate) as constraints that the SCN tracker then **enforces** against our change timelines. So: no CSP finding for the requirement itself, but its conditions, if present, become inputs/overrides to SCN-TRF/ADP deadline logic.
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** none (FedRAMP-side).
- **OSCAL / NIST:** controls[]: none. High: n/a.
- **Module connections:** SCN tracker (CAP-conditions register feeding into deadline logic).
- **Recommended implementation:** process-artifact-tracker; rationale: FedRAMP-side, but conditions parameterize our SCN engine; effort S.

---

## Implementation summary & recommended modules

Two new collector components cover the automatable surface; everything else is
the existing `process_artifacts_required[]` + register pattern.

1. **`core/conmon-tracker.ts` (OAR/QTR cadence + artifact register).** Reads an
   external register (CSV/Sheet, modeled on `core/subprocessors-sheet.ts`) of
   OAR publish dates, next-OAR/next-QTR target dates, QTR meeting dates,
   recording/registration/addendum artifact links. Computes 3-month cadence,
   next-date sanity, and the OAR↔QTR business-day window (CCM-QTR-SAR). Emits
   `hybrid`-scope findings; carries unverifiable items as
   `process_artifacts_required[]`. Level-aware for CCM-QTR-MTG.

2. **`core/scn-tracker.ts` (significant-change lifecycle + deadline monitor).**
   Reads the change-management source (Jira/ServiceNow/GitHub via the existing
   `core/ticket-push.ts` read path, or a register export). Validates per-change
   categorization presence (SCN-CSO-EVA), the 10 required fields against a
   machine-readable SCN feed (SCN-CSO-INF + HRM via the existing ajv harness),
   the 12-month archive window (SCN-CSO-HIS), and all TRF/ADP **business-day
   deadlines** via a shared `core/bizdays.ts` (US-federal-holiday-aware). Uses
   `core/notify.ts` for approaching-deadline alerts.

3. **Shared `core/bizdays.ts`** — business-day arithmetic used by CCM-QTR-SAR and
   every SCN timeline requirement. Small but load-bearing.

4. **Extend `core/detect/third-party-tools.ts`** with change-management /
   ticketing signatures (ServiceNow, Jira) and 3PAO/assessor signals so
   SCN-CSO-EVA / SCN-TRF-TPR can report "workflow detected."

Read-only is preserved throughout: all signals come from reading registers,
published feeds/URLs, and read-only ticket/cloud APIs. No writes.
