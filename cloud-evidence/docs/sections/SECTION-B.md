# SECTION B — 3PAO assessment workflow (authorization-time)

> **Scope:** Section B of the FedRAMP 20x audit-agent requirements doc — the
> artifacts the **Third-Party Assessment Organization (3PAO)** authors,
> co-authors, captures, or signs during the **authorization-time** assessment
> window (one-shot, prior to ATO issuance). Section A (CSP-authored package),
> Section C (FedRAMP PMO / AO consumption), and Section D (post-ATO dashboards
> + ConMon) are documented in their own SECTION-*.md files.
>
> **REO posture:** Per `cloud-evidence/CLAUDE.md`, the system **never**
> auto-signs on behalf of an assessor, never fabricates assessor opinions,
> and never generates sample-selection rationale absent operator input. The
> system seeds, scaffolds, validates structure, and persists signed human
> actions; the 3PAO does the judgment work.

---

## 1. Purpose

### 1.1 What this section covers

The authorization-time assessment workflow is the discrete set of
interactions between a 3PAO (an A2LA-accredited assessor) and the CSP +
the candidate system during the **assessment period** that precedes
issuance of an Authorization to Operate (ATO). It begins after the SAP +
RoE are signed (Section A artifacts) and ends when the 3PAO transmits a
final SAR + recommendation letter to the FedRAMP PMO and/or Authorizing
Official (AO).

Section B's deliverables are distinct from:

- **Section A (CSP)** — the SSP, AP, POA&M, IIW, RoE that the CSP
  authors and submits to the 3PAO as inputs to the assessment.
- **Section C (PMO/AO)** — the ATO memo, authorization letter, federal
  inbox receipts that downstream stakeholders generate.
- **Section D (ConMon)** — the monthly POA&M deltas, scan reports,
  quarterly meetings that follow ATO.

Section B is **3PAO-owned**: the 3PAO is the legal author or signer of
every artifact in this catalogue, even when our tooling pre-fills,
validates, or persists the artifact.

### 1.2 Why this section exists in the FedRAMP authorization framework

Three obligations converge on Section B:

1. **NIST SP 800-37 Rev 2 (Risk Management Framework) Step 4 (Assess)** —
   mandates an *independent* assessor (the 3PAO under FedRAMP) execute
   the assessment procedures from NIST SP 800-53A Rev 5 against each
   in-scope control, document evidence per assessment objective, and
   produce an SAR.

2. **FedRAMP 20x RFC-0014 (Phase Two automated/opinionated validation)** —
   re-grounds the 3PAO's role from narrative attestation to **machine-
   readable validation oversight**: the 3PAO validates that the CSP's
   continuous-evidence pipeline is truly automated and that exception
   handling, sampling, and human judgment are documented in OSCAL.

3. **A2LA R311 (Accreditation Requirements for 3PAOs)** — requires the
   3PAO to maintain a documented sampling methodology, evidence chain,
   reviewer sign-off chain, and recommendation letter for every
   assessment. These are professional-services obligations that survive
   independent of FedRAMP's own rules.

The 3PAO's product — a signed SAR + recommendation letter + supporting
artifacts — is what the AO uses to make the ATO decision. If any
Section B artifact is missing, falsified, or unsigned, the ATO cannot
defensibly issue.

### 1.3 Relationship to LOOP-F (3PAO assessor experience)

Implementation of every Section B artifact lives in **LOOP-F** (F.F1
through F.F7) in `docs/EXECUTION-PLAN.md`. LOOP-F is positioned as a
follow-on to LOOP-A.A2 (the AP exists for the assessor to work against)
and LOOP-B.B3 (signed human-action audit records). This section
documents the per-artifact contract; LOOP-F documents the per-slice
build plan; both must agree.

---

## 2. Artifact catalogue (B1–B7)

| ID | Artifact name | Required | Consumer(s) | Format(s) | Source obligation | Current FedPy status | Implementing loop.slice |
|---|---|---|---|---|---|---|---|
| **B1** | Sample selection methodology (SAP Appendix B) | ✅ | 3PAO (author) → AO (approver) → PMO (reviewer) | OSCAL JSON (as AP `terms-and-conditions.parts[]`), JSON sidecar (`sampling-methodology.json`), Markdown (`sampling-methodology.md`) | FedRAMP Rev5 Playbook — SAP §"Appendix B"; FedRAMP CSP Vulnerability Scanning Playbook; R4 (PRE-LOOP-A-RESEARCH-FINDINGS) | **PARTIAL** — `core/oscal-ap.ts` emits the *structural* Sampling Methodology back-matter resource and `REQUIRES-OPERATOR-INPUT` marker, but the auto-derivation algorithm (stratified-by-asset-class + 10% floor + externally-accessible 100%) has not shipped | **LOOP-F.F3** |
| **B2** | Control test results matrix | ✅ | 3PAO (author) → PMO (reviewer) → AO (approver) | OSCAL JSON (AR `results[].findings[].target` + `assessment-methods[]`), .xlsx companion, .docx narrative (for SAR §3 inclusion) | NIST SP 800-53A Rev 5 §3.3 (Procedure objects: objectives + determination statements + methods + objects); OSCAL Assessment Results v1.1.2 model | **PARTIAL** — `core/oscal.ts` (Assessment Results emitter, LOOP-A.A3 chain-wired) emits `findings[]` and `observations[]` from real evidence, but `target.target-id` does not yet enumerate the 800-53A assessment-objective IDs explicitly and the .xlsx companion does not exist | **LOOP-K.K2** (OSCAL `target` enrichment) + **LOOP-F.F7** (.xlsx + SAR narrative) |
| **B3** | Evidence walk-through artifacts (screenshots, transcripts, captured-state) | ✅ | 3PAO (author) → AO (audit trail) | PNG / JPEG (screenshots), .txt or .md (transcripts), signed tarball envelope per `finding-uuid` | NIST SP 800-53A Rev 5 §2.4 (examine/interview/test methods produce direct evidence); A2LA R311 §4.6 (evidence retention) | **MISSING** — no `core/walkthrough-*.ts` module; tracker has no upload endpoint or per-finding asset binding | **LOOP-F.F4** |
| **B4** | Sign-off attestations (per-control + per-finding + per-sample) | ✅ | 3PAO (signer) → AO (relies on) → PMO (audits) | Signed JSON row in `tracker` DB (`assessor_signoffs` table); Ed25519 signature; rendered in SAR §4 + AR `responsible-parties` | NIST SP 800-37 Rev 2 §3.4 (assessor independence + documented sign-off); A2LA R311 §6.2 (reviewer signature chain) | **MISSING** — no DB schema, no UI, no signature capture. LOOP-A.A5 RoE signature block is the *CSP/3PAO joint signature* on the RoE itself, not per-control assessor sign-off | **LOOP-F.F1** |
| **B5** | 3PAO recommendation letter | ✅ | 3PAO (author + signer) → AO (decision input) | .docx (FedRAMP template), .pdf (signed), OSCAL `assessment-results.results[].reviewed-controls` reference | FedRAMP Authorization Playbook — "3PAO Recommendation Letter" template; FedRAMP 20x RFC-0014 §"3PAO Attestation" | **MISSING** — no `core/recommendation-letter.ts`; format is .docx-via-OOXML following the LOOP-A.A5 RoE pattern | **LOOP-F.F5** |
| **B6** | Interview minutes (NIST 800-53A "interview" method evidence) | ⚠️ conditional (REQUIRED when interview is a stated method for any in-scope objective; ≥95% of Moderate assessments use interview methods) | 3PAO (author) → PMO (reviewer on request) → AO (audit trail) | Markdown transcripts in tracker `finding_comments`-class table, exported as .pdf bundle per assessment phase, OSCAL `observation.methods[]="INTERVIEW"` + `observation.subjects[]` + `observation.collected` linkage | NIST SP 800-53A Rev 5 §2.4.2 (interview as one of three assessment methods); OSCAL Assessment Results model `observation-method` enum | **MISSING** — `tracker` has no interview-minutes route; observations emitted today are SDK-derived only (method=TEST), never INTERVIEW or EXAMINE | **LOOP-F.F2** (comment threads as the persistence substrate) + **LOOP-F.F7** (export into SAR) |
| **B7** | Findings tracker (live state machine through the assessment window) | ✅ | 3PAO (driver) → CSP (responder) → AO (visibility) | tracker DB tables (`findings`, `finding_comments`, `assessor_signoffs`, `risk_acceptances`), exported as POA&M (OSCAL JSON, .xlsx), exported as SAR §3 narrative | NIST SP 800-37 Rev 2 §3.4 (finding life-cycle tracking); FedRAMP POA&M Template; OSCAL POA&M v1.1.2 model | **PARTIAL** — `core/findings.ts` schema + `core/oscal-poam.ts` (LOOP-A.A1) emit findings end-to-end; `tracker/` has the read-side UI; assessor-driven state transitions (Open → In-Progress → Re-Test → Closed) are NOT yet a first-class workflow with audit log | **LOOP-F.F6** (ATO workflow tracker) + **LOOP-F.F2** (comment threads) + **LOOP-B.B3** (signed action records) |

**Legend:**
- ✅ = REQUIRED for every authorization-time assessment.
- ⚠️ conditional = REQUIRED when a triggering condition holds; otherwise omitted with a documented determination.
- HAVE = production code emits the artifact end-to-end today.
- PARTIAL = scaffolding or partial path exists; one or more LOOP-F slices needed to complete.
- MISSING = no production code; full implementation pending the named slice.

---

## 3. Per-artifact detail

### 3.1 B1 — Sample selection methodology

#### Source citation

**FedRAMP Rev5 Playbook — Authorization SAP** (https://www.fedramp.gov/docs/rev5/playbook/csp/authorization/sap/):

> "the methodology must be included as an appendix to the SAP" and must "align with FedRAMP's vulnerability scanning sampling requirements."

> "Appendix B: Sampling Methodology" — required in the SAP when sampling is used.

> "the CSP and 3PAO must sign the SAP, which indicates acknowledgement of and agreement with the SAP and rules of engagement."

**FedRAMP Rev5 Playbook — ConMon Vulnerability Scanning** (https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/vulnerability-scanning/):

> "FedRAMP vulnerability scanning guidelines require at least monthly scans of 100% of inventory components."

> "FedRAMP recommends that externally accessible (outside of the boundary, without the use of a VPN) system components do not use this sampling methodology; 100% of externally accessible system components should be scanned."

> "Vulnerability scanning using sampling targets the same component asset categories but instead requires scanning of a sample attested to represent the unique inventory by an assessor and approved by the AO."

#### Template / schema reference

- **FedRAMP template:** "Sampling Methodology Appendix B" — narrative
  template attached to the SAP. No machine-readable schema published.
- **OSCAL location:** in the AP, the methodology surfaces as
  `terms-and-conditions.parts[]` (one part with `name="sampling-methodology"`)
  and a back-matter resource of type `methodology` with `rlinks[]`
  pointing to the JSON + Markdown sidecars. The AP emitter
  (`core/oscal-ap.ts`, LOOP-A.A2) already shapes this slot.

#### What the CSP delivers vs what FedRAMP/3PAO authors

- **CSP delivers (input):** the real inventory (`out/inventory.json`,
  via INV-S1..S6), asset tagging (`fedramp_boundary=in`,
  `internet_reachable`, asset class, data classification).
- **3PAO authors (output):** the **methodology** — i.e., the
  attestation that the chosen sample is representative. The 3PAO
  signs the AP after Appendix B is filled.
- **System auto-derives (LOOP-F.F3):** the *candidate sample*
  (externally-accessible 100%, internal stratified-by-class with a
  minimum 10% floor) from the real inventory. The 3PAO reviews,
  adjusts if needed, attests, signs.
- **AO approves:** sampling rationale per the playbook quote above
  ("approved by the AO").

#### Cross-references

- **B1 ↔ A.AP** (`core/oscal-ap.ts`): Appendix B is referenced from
  the AP's back-matter; the AP emitter today already supports
  `--ap-sampling-href` to point at an external doc and emits a
  `REQUIRES-OPERATOR-INPUT: sampling-methodology` marker when absent.
- **B1 ↔ B7 (findings tracker):** every finding records its sample
  basis (asset id, asset class, sampled/full-population flag) so the
  3PAO can defend the linkage from sample → finding.
- **B1 ↔ Section D — ConMon scan reports:** the methodology is
  re-applied monthly; if internal sampling is used, each monthly scan
  re-selects the sample per the same rules.

---

### 3.2 B2 — Control test results matrix

#### Source citation

**NIST SP 800-53A Rev 5** (https://csrc.nist.gov/publications/detail/sp/800-53a/rev-5/final), §3.3:

> "Assessment procedures contain a set of assessment objectives, each with an associated set of potential assessment methods and assessment objects."

> Each finding must reference the *determination statement* (D-statement) the assessor reached against each *assessment objective* (A-objective).

**OSCAL Assessment Results v1.1.2** (https://pages.nist.gov/OSCAL/concepts/layer/assessment/assessment-results/, https://github.com/usnistgov/OSCAL/blob/v1.1.2/json/schema/oscal_assessment-results_schema.json):

> `results[].findings[].target` carries `target-id` (the assessment
> objective ID) and `target-type` (`statement-id` or
> `objective-id`).

> `results[].assessment-log.entries[]` carries the methods used
> (TEST / EXAMINE / INTERVIEW per the OSCAL `observation-method` enum,
> mirroring 800-53A Rev 5 §2.4).

#### Template / schema reference

- **OSCAL schema:** `oscal_assessment-results_schema.v1.1.2.json`
  (committed at `cloud-evidence/docs/oscal/`).
- **FedRAMP template:** SAR §3 "Control Assessment Results Matrix"
  — historically a Word table; 20x submissions use the OSCAL AR as
  the source-of-truth and render the table from the OSCAL JSON.

#### What the CSP delivers vs what FedRAMP/3PAO authors

- **CSP delivers (via Section A artifacts):** the SSP control
  implementation narrative, the per-KSI evidence envelopes
  (`KSI-*.json`), the inventory.
- **3PAO authors (Section B):** the per-objective determination
  (Satisfied / Other Than Satisfied) and the rationale. Their
  judgment becomes `finding.target.status` + `finding.description`.
- **System auto-derives (LOOP-K.K2 + LOOP-F.F7):**
  - The mapping from FedRAMP KSI → NIST 800-53 control ID is real
    today via `core/ksi-map.ts`. The further mapping from
    control → assessment objectives (A-objectives) → determination
    statements is the LOOP-K.K2 gap.
  - The .xlsx companion (one row per A-objective × asset) is
    deferred to LOOP-F.F7 (which generates the SAR draft).

#### Cross-references

- **B2 ↔ A.AR** (`core/oscal.ts`): the AR emitter is the canonical
  source. LOOP-A.A3 already chain-wired `ap → ar` via `import-ap`.
- **B2 ↔ B4 (sign-offs):** each row in the matrix is signed by an
  assessor; the sign-off record (B4) references the
  `finding.uuid` + `target.target-id` pair so a single matrix row
  has a verifiable signer.
- **B2 ↔ B7 (findings tracker):** the matrix is the read-side
  projection of the findings tracker; every "Other Than Satisfied"
  matrix row corresponds to an open finding in B7 + a POA&M item in
  Section A.

---

### 3.3 B3 — Evidence walk-through artifacts

#### Source citation

**NIST SP 800-53A Rev 5** §2.4 (assessment methods):

> "Examine. The process of reviewing, inspecting, observing, studying, or analyzing one or more assessment objects (i.e., specifications, mechanisms, or activities)."

> "Test. The process of exercising one or more assessment objects (i.e., activities or mechanisms) under specified conditions to compare actual with expected behavior."

— and per 800-53A, the **artifacts** of the examine/test methods
(screenshots, captured config snapshots, transcripts of testing
sessions) are direct evidence and must be retained.

**A2LA R311 §4.6** (3PAO accreditation requirements — evidence
retention): assessors must retain testing artifacts for the full
assessment cycle plus 3 years for audit recovery.

**FedRAMP 20x RFC-0014:** when the CSP's evidence pipeline is
automated, the 3PAO's walk-through artifacts demonstrate that the
pipeline was *observed live*, not merely attested.

#### Template / schema reference

- **No FedRAMP-published template.** The 3PAO's evidence package is
  internal to their working file; the SAR §3 cites it by reference.
- **Structural pattern (LOOP-F.F4):** signed tarball envelope per
  `finding-uuid`, containing: original screenshot/transcript files,
  a `manifest.json` with sha256s + capture timestamps + 3PAO operator
  identity, and an Ed25519 signature.

#### What the CSP delivers vs what FedRAMP/3PAO authors

- **CSP delivers:** live access (read-only, time-bounded) to the
  systems for the 3PAO to capture during walk-through.
- **3PAO authors:** the screenshots (with timestamps), the
  transcripts (with attendee list), the observation notes.
- **System provides (LOOP-F.F4):** upload endpoint in the tracker
  UI, per-finding asset binding, signed-storage envelope, and
  retention-policy enforcement (links into LOOP-H.H1/H.H2).

#### Cross-references

- **B3 ↔ B2 (matrix):** every "Other Than Satisfied" determination
  in the matrix should cite at least one walk-through artifact in
  `finding.related-observations[]`.
- **B3 ↔ B7 (findings tracker):** the upload endpoint binds each
  artifact to a finding-uuid in the tracker so retrieval is
  one-click during SAR review.
- **B3 ↔ Section D — ConMon:** monthly ConMon does NOT re-capture
  walk-through artifacts; they are authorization-time only and
  superseded each annual assessment (LOOP-E.E3).

---

### 3.4 B4 — Sign-off attestations

#### Source citation

**NIST SP 800-37 Rev 2** (https://csrc.nist.gov/publications/detail/sp/800-37/rev-2/final), §3.4:

> "The assessor produces an assessment report that contains the results of the assessment and includes the determinations for each control."

— and the report is **signed by the assessor**. Independence + sign-off
chain is a controlling control (CA-2(1) — independent assessors).

**A2LA R311 §6.2** — every assessor finding goes through a
documented reviewer-signature chain (assessor → senior assessor →
quality reviewer). For 3PAOs, that chain is a per-3PAO-firm SOP
that they evidence to A2LA on accreditation renewal.

**OSCAL AR model:** `responsible-parties[]` and `parties[]` in
metadata encode the signers; `assessment-log.entries[]` encode the
sign-off events; props can carry per-finding signer identity.

#### Template / schema reference

- **DB schema (LOOP-F.F1, planned):**
  `assessor_signoffs (id, finding_uuid OR control_id OR sample_id, role,
   signed_by_user_id, signed_at, signature_ed25519, comments)`.
- **OSCAL export (LOOP-F.F1 + LOOP-F.F7):** sign-off rows render
  into the AR's `responsible-parties[]` (per-control or per-finding,
  role=`assessor` / `senior-assessor` / `quality-reviewer`).

#### What the CSP delivers vs what FedRAMP/3PAO authors

- **CSP delivers:** nothing direct. The CSP may dispute findings,
  but does not sign B4 attestations.
- **3PAO authors + signs:** every B4 row. The signature is a real
  human action (Rule 1 #10 of REO: "Auto-generated assessor / 3PAO
  sign-offs are forbidden").
- **System provides (LOOP-F.F1):** the tracker UI for sign-off
  capture, RBAC enforcement (only users with `assessor` role can
  sign), Ed25519 signature on the row at sign time, immutable audit
  log.

#### Cross-references

- **B4 ↔ B2 (matrix):** each matrix row's "signer" column is a
  reference to the B4 record.
- **B4 ↔ B5 (recommendation letter):** the recommendation letter
  cites the count of sign-offs ("All 153 controls reviewed and
  signed off by [3PAO]").
- **B4 ↔ B7 (findings tracker):** state transitions in B7 are
  gated on B4 sign-offs (e.g., "Re-Test → Closed" requires a
  signed assessor attestation).
- **B4 ↔ LOOP-B.B3 (risk acceptance):** risk acceptances are a
  *CSP* action; B4 sign-offs are an *assessor* action. Both live
  in the same audit-log pattern but in distinct DB tables.

---

### 3.5 B5 — 3PAO recommendation letter

#### Source citation

**FedRAMP Authorization Playbook** (https://www.fedramp.gov/docs/rev5/playbook/csp/authorization/sar/):

> "The 3PAO provides a recommendation to the authorizing official based on the results of the assessment."

The recommendation letter is a separate artifact from the SAR — the
SAR contains the results; the letter contains the *attestation +
recommendation* (Authorize / Conditionally Authorize / Do Not
Authorize) plus the 3PAO's rationale.

**FedRAMP 20x RFC-0014:** for Phase-Two pilot CSOs, the
recommendation letter additionally attests that the CSP's automated
validation pipeline was observed working end-to-end (the KSI
evidence is real, the signing chain is intact, the manifest verifies).

**Template:** FedRAMP-published .docx (the "3PAO Recommendation
Letter Template" lives in the same template-pack as the SSP / SAP /
SAR templates on fedramp.gov).

#### Template / schema reference

- **.docx (LOOP-F.F5):** rendered via the OOXML pattern that
  LOOP-A.A5 (RoE) + SSP-2 (`core/ssp-docx.ts`) already use; no
  external dependencies. Sections include:
  1. System identity (auto-fill from `--system-id`).
  2. Assessment period (auto-fill from AP timing).
  3. Scope of testing (auto-fill from AP `reviewed-controls`).
  4. Methods used (auto-fill from AR `assessment-log.entries[]`).
  5. Summary counts (auto-fill: # controls, # findings, # POA&M
     items by severity).
  6. **Recommendation** (`REQUIRES-OPERATOR-INPUT` — the 3PAO writes
     this).
  7. **Rationale** (`REQUIRES-OPERATOR-INPUT`).
  8. **Signature block** (`REQUIRES-OPERATOR-INPUT`; signed via
     B4 sign-off pattern after assertion).

#### What the CSP delivers vs what FedRAMP/3PAO authors

- **CSP delivers:** nothing. This is purely 3PAO-authored.
- **3PAO authors:** every operator-input field; signs.
- **System provides (LOOP-F.F5):** scaffolded .docx with all
  auto-fillable fields populated from real evidence; explicit
  `REQUIRES-OPERATOR-INPUT` markers in the recommendation +
  rationale + signature; emit `ready_for_signature` flag per the
  RoE pattern when all REQUIRES-OPERATOR-INPUT have been resolved.

#### Cross-references

- **B5 ↔ B2 (matrix):** summary counts come from the matrix.
- **B5 ↔ B4 (sign-offs):** the signature is a B4-pattern row.
- **B5 → Section C (AO):** the AO consumes B5 + the SAR + the
  POA&M to make the ATO decision.

---

### 3.6 B6 — Interview minutes

#### Source citation

**NIST SP 800-53A Rev 5** §2.4.2 — INTERVIEW is one of three assessment methods (alongside EXAMINE and TEST). Every control whose assessment procedure stipulates "Interview: [organizational personnel with X responsibility]" requires evidence of the interview taking place.

**OSCAL Assessment Results v1.1.2:** `observation.methods[]` enum
includes `"INTERVIEW"`, `"EXAMINE"`, `"TEST"`, `"UNKNOWN"`. The
emitter today only generates `"TEST"` observations (SDK-derived
machine evidence). INTERVIEW observations are a Section B-only
artifact.

#### Conditional emission

B6 is **conditionally required**: only when the assessment plan
includes interview as a method for any in-scope objective. In
practice, ≥95% of Moderate assessments include personnel interviews
(IR, CP, AT, PM control families typically require interview), so
the system treats B6 as effectively required and emits a
`REQUIRES-OPERATOR-INPUT: interview-minutes` marker when no minutes
have been recorded for a control whose AP says interview is a
method.

#### Template / schema reference

- **Tracker DB (LOOP-F.F2 + LOOP-F.F7):**
  `interview_minutes (id, ap_task_uuid, control_ids[], interviewer_user_id,
   interviewees[] (name, role, org), held_at, transcript_markdown, signed_at,
   signature_ed25519)`.
- **OSCAL export:** one `observation` per interview, with
  `methods=["INTERVIEW"]`, `subjects[]` populated from
  `interviewees[]`, `collected = held_at`, `description = transcript_markdown`.

#### What the CSP delivers vs what FedRAMP/3PAO authors

- **CSP delivers:** interviewee availability + responses during the
  interview. Often the CSP keeps its own notes; those are CSP-internal.
- **3PAO authors:** the official minutes (the binding record).
- **System provides (LOOP-F.F2 + LOOP-F.F7):** persistent transcript
  capture in the tracker (LOOP-F.F2 comment-thread substrate),
  signed at the close of each interview, exported into the SAR as
  observations in §3.

#### Cross-references

- **B6 ↔ B2 (matrix):** every interview-required objective in the
  matrix references its interview minutes by
  `observation.uuid`.
- **B6 ↔ A.AP (`core/oscal-ap.ts`):** the AP enumerates which
  objectives use interview; B6 fulfills those.
- **B6 → B5 (recommendation letter):** the recommendation letter's
  summary counts include "X interviews conducted with Y
  personnel."

---

### 3.7 B7 — Findings tracker (assessment-window state machine)

#### Source citation

**NIST SP 800-37 Rev 2** §3.4: every finding moves through a
documented lifecycle (Open → In-Progress → Re-Tested → Closed or
→ Risk-Accepted). The state transitions are auditable events.

**FedRAMP POA&M Template + OSCAL POA&M v1.1.2:** the POA&M is the
*persistent* view of open findings; the findings tracker is the
*assessment-window working view*, transient until the SAR closes
out the assessment. After ATO, B7's open findings *become* the
initial POA&M.

#### Template / schema reference

- **Tracker DB tables (HAVE for findings; PARTIAL for state machine):**
  - `findings` (HAVE — `core/findings.ts` schema)
  - `finding_comments` (PARTIAL — LOOP-F.F2)
  - `assessor_signoffs` (MISSING — LOOP-F.F1)
  - `finding_state_transitions` (MISSING — LOOP-F.F6)
- **OSCAL export:** B7's "Closed" findings drop out of the AR's
  open-findings set; B7's "Open" findings emit as POA&M items in
  the LOOP-A.A1 emitter (HAVE).

#### What the CSP delivers vs what FedRAMP/3PAO authors

- **CSP delivers:** remediation responses (text + evidence) to
  each finding within the assessment window.
- **3PAO authors:** the state transitions ("Re-Tested",
  "Closed", "Risk-Accepted-with-Compensating-Control"), each
  signed via B4.
- **AO observes (read-only):** the live tracker during the AO's
  review window pre-ATO.
- **System provides (LOOP-F.F6):** the state machine UI + audit
  log + automatic POA&M emission of remaining open findings on
  assessment close.

#### Cross-references

- **B7 ↔ Section A POA&M:** the AR/POA&M chain LOOP-A.A3 already
  wires.
- **B7 ↔ B4:** every state transition is a B4 sign-off.
- **B7 ↔ B3:** every state transition can attach walk-through
  artifacts as supporting evidence.
- **B7 ↔ LOOP-B.B3:** risk-acceptance is a CSP-side action
  inside B7's state machine.
- **B7 → Section D ConMon:** the closing POA&M from B7 is the
  *opening* POA&M for the first monthly ConMon cycle (LOOP-E.E2).

---

## 4. Acceptance criteria for this section

SECTION B is considered **complete** (ready to support a real
authorization-time assessment for a single CSO at Moderate) when
ALL of the following hold:

### 4.1 Per-artifact slice acceptance

| Artifact | Slice | Acceptance check |
|---|---|---|
| B1 | LOOP-F.F3 | `core/sampling-methodology.ts` reads real `out/inventory.json`, applies externally-accessible=100% + internal stratified-by-class with 10% floor, emits `sampling-methodology.json` + `.md`; AP back-matter `--ap-sampling-href` resolves to the emitted file; signed under the run manifest |
| B2 | LOOP-K.K2 + LOOP-F.F7 | AR `findings[].target.target-id` enumerates 800-53A Rev 5 assessment-objective IDs (not just control IDs); `core/sar-draft.ts` emits a SAR .docx with §3 matrix rendered from the OSCAL AR; .xlsx companion ships with one row per A-objective × in-scope asset |
| B3 | LOOP-F.F4 | tracker has `/api/walkthrough-artifacts` POST endpoint; uploads bind to `finding_uuid`; signed envelope persists; retention policy enforces 3-year minimum per A2LA R311 |
| B4 | LOOP-F.F1 | tracker DB has `assessor_signoffs` table; UI gates by `assessor` role (RBAC); signatures are real Ed25519 (Rule 1 #10 of REO: no auto-sign); audit log is immutable; AR exports `responsible-parties[]` from this table |
| B5 | LOOP-F.F5 | `core/recommendation-letter.ts` emits .docx via OOXML pattern; auto-fills system identity + period + scope + methods + counts; emits `REQUIRES-OPERATOR-INPUT` for recommendation + rationale + signature; `ready_for_signature` flag matches the RoE pattern |
| B6 | LOOP-F.F2 + LOOP-F.F7 | tracker `interview_minutes` table exists; signed transcripts persist; OSCAL observations emit with `methods=["INTERVIEW"]` and real `subjects[]`; SAR includes interview-counts summary |
| B7 | LOOP-F.F6 (+ F.F1 + F.F2 + B.B3) | state machine implemented (Open → In-Progress → Re-Tested → Closed / Risk-Accepted); every transition signed via B4 pattern; closing emits POA&M (LOOP-A.A1 path) for remaining open findings |

### 4.2 Cross-artifact integrity checks

1. **Chain integrity:** the AR's `import-ap` resolves (LOOP-A.A3 done).
   B2's matrix rows are reachable from the AP's reviewed-controls.
   B5's summary counts equal the matrix counts.
2. **Signature chain integrity:** every B4 / B6 / B7 transition row
   is signed; signatures verify against the operator's signing key;
   the LOOP-A.A4 submission bundler's `INDEX.json` lists every
   signed Section B artifact.
3. **REO compliance:** running `npm run check:reo` against a tree
   that includes Section B emitters returns 0 (no stubs, no fake
   sign-offs, no fabricated interview minutes, no synthetic
   recommendation text).
4. **Per-control sign-off coverage:** for any in-scope control,
   `B4` has at least one signed attestation **or** the SAR records
   an explicit "Not Applicable" determination signed under the
   same B4 pattern. Coverage report fails CI if a control is
   in-scope per the AP but has neither signoff nor NA determination.

### 4.3 Real-Evidence-Only audit

Every emitted Section B artifact must satisfy the four REO rules:
- **Rule 1:** no placeholder data, no auto-signing, no fabricated
  sample selection rationale, no fake interview minutes.
- **Rule 2:** every slice's "done" includes real end-to-end flow
  + signed + tested on the real path + no new stub lint hits +
  CHANGELOG entry.
- **Rule 3:** the only allowed fixed data is OSCAL schema
  constants, FedRAMP-published IDs, NIST control IDs.
- **Rule 4:** operator input (sampling attestation,
  recommendation text, interview transcripts, sign-off signatures)
  flows through the tracker UI or `config.yaml`; never silently
  defaulted.

---

## 5. Open questions

These are genuinely uncertain and may shift implementation
mid-flight; they do NOT block starting LOOP-F.

### 5.1 Statistical confidence threshold for B1 sampling

FedRAMP does not publish a specific statistical confidence
threshold (e.g., 95% confidence at ±5% margin) for B1. Current
plan: stratified-by-asset-class + 10% floor + AO sign-off. If
post-Phase-Two retrospective lands with explicit thresholds,
LOOP-F.F3 will absorb them as configurable parameters; the OSCAL
back-matter resource versioning handles the format shift.

### 5.2 OSCAL `observation-method` granularity for B6

NIST 800-53A Rev 5 §2.4.2 enumerates interview *types* (e.g.,
abbreviated discussion, in-depth interview, focused session) but
the OSCAL `observation-method` enum is just `INTERVIEW`. Whether
the FedRAMP PMO will require the finer-grained method (encoded
in `observation.props[]`) is undetermined. We emit the broad
method today and reserve a `frmr:interview-type` prop for the
fine-grained value when the operator supplies it.

### 5.3 B5 recommendation letter — recommendation taxonomy

The FedRAMP playbook text suggests a binary "Authorize / Do Not
Authorize" recommendation; some 3PAO firms historically use a
three-state taxonomy (Authorize / Conditionally Authorize / Do
Not Authorize). The .docx template will accept the operator-input
text verbatim (no enum constraint) until the PMO publishes a
canonical list. LOOP-F.F5 will validate against a configurable
enum when one exists.

### 5.4 Walk-through artifact storage location (B3)

LOOP-H.H1 (immutable evidence archive) is the long-term home for
walk-through artifacts; LOOP-F.F4 ships them into the tracker as
the *working* store. Whether the tracker's working store retains
artifacts after ATO or hands them off to LOOP-H.H1 immediately is
a TBD policy decision (likely operator-configurable). The 3-year
A2LA retention floor is the hard constraint; the system enforces
that floor regardless of storage location.

### 5.5 Post-Phase-Two-pilot format shifts

Per R3 in `PRE-LOOP-A-RESEARCH-FINDINGS.md`, no post-pilot
guidance has been published. LOOP-A.A4's
`package_format_version: "20x.phase-two.preview.2026"` will
absorb any shift to the AR / SAR / recommendation-letter wire
format. The Section B artifacts described here are version-stable
under that scheme.

### 5.6 RBAC role granularity for B4

The tracker's `assessor` role is a single role today. A2LA R311
§6.2 implicitly requires a multi-level reviewer chain (assessor
→ senior assessor → quality reviewer). LOOP-F.F1 will start with
a single `assessor` role; if a 3PAO firm needs the finer chain,
they extend the role schema via the tracker's RBAC config (no
code change required) and B4 sign-off records carry the role
verbatim.

---

## Appendix — file-path map

| Artifact | Production source path | Test source path | Output path (post-build) |
|---|---|---|---|
| B1 | `core/sampling-methodology.ts` (PLANNED, LOOP-F.F3) | `tests/core/sampling-methodology.test.ts` (PLANNED) | `out/sampling-methodology.json` + `out/sampling-methodology.md` |
| B2 | `core/oscal.ts` (HAVE for AR), `core/sar-draft.ts` (PLANNED, LOOP-F.F7), `core/oscal.ts` extensions (LOOP-K.K2) | existing `tests/core/oscal.test.ts` + new tests | `out/ar.json` + `out/ar.xml` + `out/sar-draft.docx` + `out/control-matrix.xlsx` |
| B3 | `tracker/server/routes/walkthrough-artifacts.ts` (PLANNED, LOOP-F.F4), `tracker/client/src/pages/WalkthroughCapture.tsx` (PLANNED) | new tracker tests | tracker DB + `out/walkthrough-artifacts/<finding-uuid>/*.tar.gz.sig` |
| B4 | `tracker/server/routes/assessor-signoffs.ts` (PLANNED, LOOP-F.F1), `tracker/server/db/migrations/0XX_assessor_signoffs.sql` (PLANNED) | new tracker tests | tracker DB + AR `responsible-parties[]` |
| B5 | `core/recommendation-letter.ts` (PLANNED, LOOP-F.F5) | `tests/core/recommendation-letter.test.ts` (PLANNED) | `out/recommendation-letter.docx` |
| B6 | `tracker/server/routes/interview-minutes.ts` (PLANNED, LOOP-F.F2), extension to AR observations (LOOP-F.F7) | new tracker tests | tracker DB + AR `observations[]` (`methods=["INTERVIEW"]`) |
| B7 | `tracker/server/routes/findings-workflow.ts` (PLANNED, LOOP-F.F6), `core/findings.ts` (HAVE), `core/oscal-poam.ts` (HAVE — LOOP-A.A1) | existing + new tracker tests | tracker DB + `out/poam.json` + `out/poam.xml` |

---

## Appendix — verification before declaring SECTION B done

```bash
cd cloud-evidence
npm run typecheck                       # green
npm test                                # all Section B tests pass
npm run check:reo                       # G1+G2+G3 green; no Section B emitter introduces a forbidden token, regresses coverage, or skips a provenance entry
node scripts/section-b-acceptance.mjs   # cross-artifact integrity (PLANNED) — verifies signature chain + matrix↔ sign-off coverage + reviewer-chain depth
```

Then commit + push. SECTION B is complete when every artifact in §2's
table moves from PARTIAL/MISSING to HAVE and the acceptance script
returns 0.
