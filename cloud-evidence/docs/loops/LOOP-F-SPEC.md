# LOOP-F — 3PAO Assessor Experience

> Self-contained implementation spec for every slice in LOOP-F. A future
> session reads only this file (plus `cloud-evidence/CLAUDE.md` for the
> REO standard) and can ship every slice end-to-end. No reference to any
> prior planning conversation is required. Every file path is absolute
> relative to the repo root `/Users/kenith.philip/FedRAMP 20x/`.

---

## 1. Why this loop exists

LOOP-A delivered the full *CSP-side* submission package — `SSP → AP → AR →
POA&M → IIW → RoE` are signed, timestamped, and bundled. But the
authorization is awarded by the Authorizing Official (AO) based on a
**3PAO Security Assessment Report** (SAR) plus a **recommendation for
authorization** plus an end-to-end **assessor workflow**: sign-offs on
every control, comment threads on findings, sample-selection rationale
recorded as SAP Appendix B, evidence-walk-through artifacts (screenshots
+ transcripts) attached per finding, and a tracked ATO state machine
through publication.

Today the 3PAO does all of this in Microsoft Word + email + screenshots
on a shared drive. LOOP-F gives them a workflow that:

1. Reads the OSCAL AP (LOOP-A.A2) and presents every control × procedure
   object as a sign-off candidate in the tracker UI.
2. Captures real, signed sign-offs and persists them as OSCAL AR
   `finding.status` + `observation.relevant-evidence` entries.
3. Threads comments per finding so questions, evidence requests, and
   resolutions are auditable.
4. Auto-derives a Sample Selection Methodology from real `inventory.json`
   that the 3PAO can attach to the SAP as Appendix B per R4.
5. Captures evidence-walk-through screenshots + transcripts per finding.
6. Emits a 3PAO Recommendation Letter `.docx` pre-filled with system
   identity + assessment period + finding counts.
7. Tracks the full ATO lifecycle (package complete → 3PAO sign-off → AO
   review → ATO decision → publication) per NIST PM-10.
8. Generates a SAR draft `.docx` (NOT auto-signed — the 3PAO signs
   manually) populated from real evidence + tracker sign-offs + comments.

Artifacts delivered by this loop:
- `assessor_signoffs` DB table + tracker UI page + REST API.
- `finding_comments` DB table + thread UI + email/Slack notifier.
- `out/sampling-methodology.json` + `out/sampling-methodology.md` —
  consumable as SAP Appendix B.
- `out/evidence-walkthrough/<finding-uuid>/` directory with
  screenshots + transcripts.
- `out/recommendation-letter.docx`.
- `ato_workflow_state` DB table + transition audit log.
- `out/sar-draft.docx`.

Authorization-package gaps closed:
- SAR document (FedRAMP SAR template) — slice F.F7.
- SAP Appendix B Sampling Methodology — slice F.F3.
- Recommendation language in SAR Executive Summary §2 — slice F.F5.
- Per-control assessor sign-off captured as OSCAL AR `finding.status` —
  slice F.F1.
- Walk-through evidence (screenshots/transcripts) attached per finding —
  slice F.F4.
- NIST PM-10 Authorization Process tracking — slice F.F6.

---

## 2. Dependencies

**Must complete before LOOP-F begins:**
- **LOOP-A.A2** — `core/oscal-ap.ts` exists and emits an OSCAL Assessment
  Plan v1.1.2 (reviewed-controls + assessment-methods + assessment-
  subjects). F.F1 reads `out/ap.json` to enumerate every control × method
  pair the assessor must sign off on.
- **LOOP-A.A3** — `core/oscal.ts` emits the AR with `import-ap` resolved
  to a real AP. F.F7 reads `out/assessment-results.json` to seed the SAR.
- **LOOP-B.B3** — `tracker/server/routes/risk-acceptance.ts` + the signed-
  action DB pattern. F.F1 reuses the same signed-action pattern (Ed25519
  signature over the canonical request body, persisted in audit log).

**Existing files this loop extends or reads from:**
- `cloud-evidence/core/oscal-ap.ts` — read the AP's reviewed-controls +
  local-definitions.assessment-methods (F.F1, F.F7).
- `cloud-evidence/core/oscal.ts` — extend `OscalEmitResult` so AR
  emission can ingest tracker sign-offs (F.F7) and add walk-through
  evidence as `observation.relevant-evidence` entries (F.F4).
- `cloud-evidence/core/oscal-poam.ts` — read finding-uuids the comment
  threads (F.F2) attach to.
- `cloud-evidence/core/submission-bundle.ts` — add new well-known
  artifact catalogue entries: `sampling-methodology-json`,
  `sampling-methodology-md`, `recommendation-letter-docx`,
  `evidence-walkthrough-bundle`, `sar-draft-docx`.
- `cloud-evidence/core/roe-emit.ts` — reuse the dependency-free `.docx`
  pattern (zip-store + OOXML, see `cloud-evidence/core/zip.ts`) for F.F5
  and F.F7.
- `cloud-evidence/core/ssp-docx.ts` — reuse the OOXML primitives for
  F.F5 and F.F7.
- `cloud-evidence/core/orchestrator.ts` — add `--sampling-methodology`,
  `--recommendation-letter`, `--sar-draft` flags + env vars.
- `cloud-evidence/core/sign.ts` + `cloud-evidence/core/timestamp.ts` —
  every assessor signoff record (F.F1) + sampling methodology JSON (F.F3)
  + recommendation letter (F.F5) + SAR draft (F.F7) gets signed +
  timestamped exactly like the rest of the chain.
- `cloud-evidence/out/inventory.json` — F.F3 reads asset list to compute
  the sampling plan.

**Tracker scaffolding required (does NOT yet exist; this loop creates it):**
- `cloud-evidence/tracker/` is a sibling directory to `cloud-evidence/core/`.
  LOOP-B.B3 creates `tracker/server/` + `tracker/client/`. LOOP-F extends
  it. If LOOP-B has not landed yet, LOOP-F.F1 includes the
  bootstrap scaffolding in its build steps (see slice F.F1).

**Loops unblocked when LOOP-F completes:**
- **LOOP-I (Stakeholder dashboards)** — I.I1 exec dashboard reads F.F1
  signoff progress + F.F6 ATO state.
- **LOOP-K.K1** — PenTest report ingest hangs off the F.F4 walk-through
  evidence model.
- **LOOP-K.K2** — 3PAO test results matrix → OSCAL AR test-result objects
  reads F.F1's signoff DB.

---

## 3. Authoritative sources

Every URL + spec referenced by LOOP-F, with verbatim quotes where
extractable. Citations are mandatory for any string LOOP-F emits that
claims to satisfy a FedRAMP requirement.

### 3.1 FedRAMP 3PAO Readiness Assessment Report Guide

- **URL:** https://www.fedramp.gov/assets/resources/documents/3PAO_Readiness_Assessment_Report_Guide.pdf
- **Version:** 3.2, dated 2024-10-17.
- **Mirror URL (FedRAMP resources directory):** https://www.fedramp.gov/resources/documents/3PAO_Readiness_Assessment_Report_Guide.pdf
- **Verbatim guidance** (from FedRAMP-published summary materials and
  the public training deck
  https://www.fedramp.gov/assets/resources/training/300-G_3PAO-Readiness-Assessment-Report-RAR-Preparation.pdf):
  > "3PAOs should directly and clearly answer RAR requirements and
  > questions, stating what they found (observations and evidence)
  > during their review and HOW they came about determining if a CSP
  > adequately addresses the question area."
  >
  > "The recommendation must be clear, unambiguous, and contain no
  > conditional language."
- **Applies to slices:** F.F5 (recommendation letter wording rules),
  F.F7 (SAR draft wording rules).

### 3.2 FedRAMP Security Assessment Report (SAR) Template

- **URL:** https://www.fedramp.gov/assets/resources/templates/FedRAMP-Security-Assessment-Report-(SAR)-Template.docx
- **Reference page:** https://www.fedramp.gov/docs/rev5/playbook/csp/authorization/sar/
- **Published:** December 6, 2024 (Rev5 SAR template release per
  https://www.fedramp.gov/fedramp-announces-document-and-template-updates/).
- **Structural requirements (verbatim from the SAR template + Rev5 SAR
  playbook page):**
  > "The SAR documents the results of the security assessment for the
  > CSO, including a summary of the risks remaining at the conclusion of
  > the assessment."
  >
  > Required components:
  > - "SAR" (the body document)
  > - "Appendix A: Risk Exposure Table (RET)"
  > - "Appendix B: Security Requirements Traceability Matrix (SRTM)
  >   Workbook"
  > - "Appendix C: Vulnerability Scan Results"
  > - "Appendix D: Documentation Review Findings"
  > - "Appendix E: Auxiliary Documents"
  > - "Appendix F: Penetration Test Report"
  > - "Evidence collected during the assessment"
  >
  > "All instances of controls with an assessment result of 'Other than
  > Satisfied' should be documented as an open risk in the RET, unless
  > the finding was corrected during testing."
  >
  > "Did the 3PAO attest to the accuracy of the SAR and provide an
  > authorization recommendation in Section 2, Executive Summary?"
- **Applies to slices:** F.F5 (Executive Summary §2 wording), F.F7 (full
  SAR draft + RET cross-link + non-conforming controls list).

### 3.3 FedRAMP Rev5 SAP Playbook

- **URL:** https://www.fedramp.gov/docs/rev5/playbook/csp/authorization/sap/
- **Verbatim quotes (already used by LOOP-A.A2 + LOOP-F.F3 research):**
  > "the methodology must be included as an appendix to the SAP" and
  > must "align with FedRAMP's vulnerability scanning sampling
  > requirements."
  >
  > "Appendix B: Sampling Methodology" — required in the SAP when
  > sampling is used.
  >
  > "the CSP and 3PAO must sign the SAP, which indicates acknowledgement
  > of and agreement with the SAP and rules of engagement."
- **Applies to slices:** F.F3 (Appendix B emitter).

### 3.4 FedRAMP Rev5 ConMon Vulnerability Scanning Playbook

- **URL:** https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/vulnerability-scanning/
- **Verbatim sampling rules (carry over from R4 research at
  `cloud-evidence/docs/PRE-LOOP-A-RESEARCH-FINDINGS.md`):**
  > "FedRAMP vulnerability scanning guidelines require at least monthly
  > scans of 100% of inventory components."
  >
  > "Vulnerability scanning using sampling targets the same component
  > asset categories but instead requires scanning of a sample attested
  > to represent the unique inventory by an assessor and approved by the
  > AO."
  >
  > "FedRAMP recommends that externally accessible (outside of the
  > boundary, without the use of a VPN) system components do not use
  > this sampling methodology; 100% of externally accessible system
  > components should be scanned."
  >
  > "The entire inventory (or approved sampling percentage) within the
  > boundary must be scanned at the operating system (OS) level at least
  > once a month. All Web interfaces and services (or approved sampling
  > percentage) must be scanned. All databases (or approved sampling
  > percentage) must be scanned."
- **Applies to slices:** F.F3 (100% external rule hard-coded; internal
  sampling stratified by asset class + region + 10% floor +
  operator-input override).

### 3.5 NIST SP 800-53A Rev 5 — Assessing Security and Privacy Controls

- **URL (PDF):** https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53Ar5.pdf
- **URL (CSRC landing page):** https://csrc.nist.gov/pubs/sp/800/53/a/r5/final
- **URL (assessment-procedures Excel companion):**
  https://csrc.nist.gov/files/pubs/sp/800/53/a/r5/final/docs/sp800-53ar5-assessment-procedures.xlsx
- **NIST CSRC glossary (assessment method):**
  https://csrc.nist.gov/glossary/term/assessment_method
- **Verbatim glossary definition:**
  > "assessment method — One of three types of actions (i.e., examine,
  > interview, test) taken by assessors in obtaining evidence during an
  > assessment."
  > (Source citation on the glossary page: NIST SP 800-53A Rev. 5 and
  > NIST SP 800-137A.)
- **Procedure object structure (verbatim from SP 800-53A Rev 5 §2.3
  and Appendix D):**
  - **Assessment objective**: derived from the security/privacy
    requirement of the control, decomposed into *determination
    statements*.
  - **Assessment methods**: EXAMINE / INTERVIEW / TEST. Each may be
    applied with a depth attribute of `basic`, `focused`, or
    `comprehensive`, and a coverage attribute of `basic`, `focused`, or
    `comprehensive`.
  - **Assessment objects**: specifications, mechanisms, activities, or
    individuals (the targets of the methods).
  - **Finding**: each determination statement is rated either
    *Satisfied* (S) or *Other Than Satisfied* (O).
- **PM-10 Authorization Process (verbatim from NIST SP 800-53 Rev 5,
  Appendix F, control PM-10):**
  > "PM-10: Authorization Process. Manage the security and privacy
  > state of organizational systems and the environments in which those
  > systems operate through authorization processes; designate
  > individuals to fulfill specific roles and responsibilities within
  > the organizational risk management process; and integrate the
  > authorization processes into an organization-wide risk management
  > program."
- **Applies to slices:** F.F1 (sign-off granularity = one signature per
  control × determination statement × method), F.F6 (PM-10 state
  machine), F.F7 (SAR finding wording uses S / O language verbatim).

### 3.6 FedRAMP Penetration Test Guidance

- **URL:** https://www.fedramp.gov/assets/resources/documents/CSP_Penetration_Test_Guidance.pdf
- **Applies to slices:** F.F4 (penetration-test screenshot upload schema
  + redaction expectations), F.F7 (SAR Appendix F PenTest Report seed).

### 3.7 NIST SP 800-115 — Technical Guide to Information Security Testing and Assessment

- **URL:** https://csrc.nist.gov/publications/detail/sp/800-115/final
- **PDF:** https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf
- **Verbatim guidance on evidence handling (§4 + §6):**
  > "Findings should be documented with sufficient detail to allow
  > another technical professional to verify them independently."
- **Applies to slices:** F.F4 (transcript schema requires reproducibility
  fields: timestamp, tool name + version, command + output capture).

### 3.8 NIST OSCAL Assessment Plan v1.1.2 reference

- **URL:** https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-plan/json-reference/
- **Applies to slices:** F.F3 (Appendix B is emitted as `back-matter.resources`
  + linked from `terms-and-conditions`), F.F1 (reviewed-controls →
  signoff table seed).

### 3.9 NIST OSCAL Assessment Results v1.1.2 reference

- **URL:** https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/json-reference/
- **Applies to slices:** F.F1 (sign-off → `finding.target.status.state`),
  F.F4 (walk-through evidence → `observation.relevant-evidence[].href`),
  F.F7 (SAR draft generator reads the full AR model).

### 3.10 FedRAMP RFC-0024 (OSCAL submissions)

- **URL:** https://www.fedramp.gov/rfcs/0024/
- **Applies to slices:** F.F7 (SAR draft is `.docx` for human readability
  but every finding it contains is *also* present in the OSCAL AR JSON
  that the bundler already ships; the `.docx` cites the AR finding-uuid
  for every paragraph).

---

## 4. Per-slice implementation specs

### Slice F.F1 — 3PAO sign-off UI in tracker

**Why this slice**: The OSCAL AR `finding.target.status.state` field is
either `satisfied` or `not-satisfied` — but today nothing in the
codebase captures the assessor's per-control determination. Without a
signed sign-off record, the AR's status fields are auto-derived from
collector pass/fail, which is a REO Rule 1.10 violation
("Auto-generated assessor / 3PAO sign-offs"). This slice captures the
real human action.

**Files to create** (exact paths):
- `cloud-evidence/tracker/server/db/migrations/0FF1_assessor_signoffs.sql`
  — DDL for the `assessor_signoffs` table.
- `cloud-evidence/tracker/server/routes/assessor-signoffs.ts` — REST
  routes: `GET /api/signoffs?run=<id>`, `POST /api/signoffs`,
  `POST /api/signoffs/:uuid/revoke`.
- `cloud-evidence/tracker/server/services/signoff-service.ts` — pure
  business logic (createSignoff, listSignoffs, revokeSignoff). Imports
  `cloud-evidence/core/sign.ts` for the Ed25519 signature over the
  canonical request body.
- `cloud-evidence/tracker/client/src/pages/AssessorSignoffs.tsx` —
  React page rendering the AP-derived control × determination-statement
  × method table with a sign / revoke button per row.
- `cloud-evidence/tracker/client/src/components/SignoffRow.tsx` — row
  component with state badge (unsigned / signed / revoked).
- `cloud-evidence/core/signoff-ingest.ts` — pure reader that pulls the
  tracker signoff records (via HTTP) and returns a normalized
  `SignoffRecord[]` for AR emission to consume.
- `cloud-evidence/tests/core/signoff-ingest.test.ts` — unit tests for
  the ingest reader.
- `cloud-evidence/tests/tracker/server/assessor-signoffs.test.ts` — API
  + DB integration tests.
- `cloud-evidence/tests/tracker/client/AssessorSignoffs.test.tsx` —
  Vitest + React Testing Library tests for the UI.

**Files to extend** (paths + what to add):
- `cloud-evidence/core/oscal.ts` — `OscalEmitOptions` gains
  `signoffSource?: SignoffRecord[]`. When supplied, AR
  `result.findings[].target.status.state` flows from the matching
  signoff record (matched by `control-id + statement-id + method`)
  rather than the collector-derived pass/fail; the original
  collector-derived value moves to a `props[]` entry named
  `cloud-evidence:collector-derived-status` so the chain is auditable.
- `cloud-evidence/core/orchestrator.ts` — new flag
  `--ingest-signoffs[=<tracker-url>]` + env
  `CLOUD_EVIDENCE_TRACKER_URL`. When set, the orchestrator calls
  `loadSignoffsFromTracker(url, runId)` from `signoff-ingest.ts`
  before emitting the AR.
- `cloud-evidence/core/submission-bundle.ts` — new well-known artifact
  role `assessor-signoffs-export` with filename
  `assessor-signoffs.json` (the tracker's signed export of every
  signoff record for the run, included verbatim in the bundle).

**Schemas / standards**:
- OSCAL AR `finding.target.status.state` (enum: `satisfied`,
  `not-satisfied`) — from
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/json-reference/.
- NIST SP 800-53A Rev 5 procedure object: assessment-objective →
  determination-statement → method (EXAMINE / INTERVIEW / TEST) →
  object. Each (control-id, statement-id, method) tuple gets exactly
  one signoff.
- Ed25519 signature format: 64-byte raw signature, base64-encoded in the
  DB record. Signed payload = canonical-JSON serialization of
  `{ run_id, control_id, statement_id, method, decision, assessor_user_id, signed_at }`.

**Build steps**:
1. **DB migration `0FF1_assessor_signoffs.sql`** creates table:
   ```
   CREATE TABLE assessor_signoffs (
     uuid TEXT PRIMARY KEY,
     run_id TEXT NOT NULL,
     control_id TEXT NOT NULL,         -- e.g. "ac-2"
     statement_id TEXT NOT NULL,       -- e.g. "ac-2_smt.a"
     method TEXT NOT NULL CHECK (method IN ('EXAMINE','INTERVIEW','TEST')),
     decision TEXT NOT NULL CHECK (decision IN ('satisfied','not-satisfied')),
     assessor_user_id INTEGER NOT NULL REFERENCES users(id),
     comments TEXT,
     signed_at TEXT NOT NULL,          -- ISO-8601
     signature TEXT NOT NULL,          -- base64 Ed25519
     signing_key_id TEXT NOT NULL,
     revoked_at TEXT,
     revoked_by_user_id INTEGER REFERENCES users(id),
     revoke_reason TEXT,
     UNIQUE (run_id, control_id, statement_id, method, revoked_at)
   );
   CREATE INDEX idx_signoffs_run ON assessor_signoffs (run_id);
   CREATE INDEX idx_signoffs_control ON assessor_signoffs (control_id);
   ```
2. **Pure service function** in `signoff-service.ts`:
   `createSignoff(input: SignoffInput, ctx: { user: User, signer: Ed25519Signer }): SignoffRecord` —
   builds the canonical JSON, signs with the assessor's holder key
   from `cloud-evidence/core/sign.ts`, inserts the row, returns the
   record. Throws `ForbiddenError` if `ctx.user.role !== 'assessor'`.
3. **REST routes** in `assessor-signoffs.ts`:
   - `GET /api/signoffs?run=<id>` — list signoffs for a run.
   - `POST /api/signoffs` — body `{ control_id, statement_id, method, decision, comments? }`.
     Calls `createSignoff`. RBAC: `assessor` role required (reuse the
     LOOP-A.B3-style RBAC middleware).
   - `POST /api/signoffs/:uuid/revoke` — body `{ reason }`. Marks the
     row revoked; the operation itself is signed.
4. **UI page** `AssessorSignoffs.tsx`:
   - Fetches `out/ap.json` via the tracker proxy.
   - Renders one row per (control × determination-statement × method)
     from `ap.reviewed-controls.control-selections` ×
     `ap.local-definitions.assessment-methods` (Cartesian product
     filtered by the AP's `included-controls` set).
   - Each row shows: control id, statement, method, current status
     badge (unsigned / signed / revoked / superseded), assessor name +
     time, sign / revoke buttons.
   - Sign button posts to `POST /api/signoffs` and refreshes the row.
5. **Ingest** in `signoff-ingest.ts`:
   - `loadSignoffsFromTracker(url, runId): Promise<SignoffRecord[]>`
     — calls `GET ${url}/api/signoffs?run=${runId}` with the tracker
     API token from env `CLOUD_EVIDENCE_TRACKER_TOKEN`. Validates the
     response shape against an ajv schema. Returns the active (non-
     revoked) signoffs.
6. **Wire into orchestrator**:
   - Flag `--ingest-signoffs` (with optional `=<url>` override).
   - Env `CLOUD_EVIDENCE_TRACKER_URL`, `CLOUD_EVIDENCE_TRACKER_TOKEN`.
   - When the flag is set, fetch the signoffs and pass them via
     `OscalEmitOptions.signoffSource` to `emitOscalAR()`.
7. **Extend `core/oscal.ts`**: for each `finding.target` whose
   `target-id` matches a `(control_id, statement_id, method)` signoff,
   set `status.state` from the signoff's `decision`; add a
   `props[]` entry `{ name: 'assessor-signoff-uuid', ns: 'urn:fedramp:cloud-evidence', value: signoff.uuid }`
   and a `props[]` entry preserving the original collector-derived
   status under
   `{ name: 'collector-derived-status', ns: 'urn:fedramp:cloud-evidence', value: <orig> }`.
8. **Bundler well-known catalogue**: append
   `{ role: 'assessor-signoffs-export', filename: 'assessor-signoffs.json', description: 'Tracker-exported signed signoff records for the run' }`
   to `WELL_KNOWN` in `submission-bundle.ts`.

**REQUIRES-OPERATOR-INPUT fields**:
- `assessor_user_id`: source = tracker session — the signed-in user
  must hold the `assessor` role. No CLI / config substitute is
  permitted (REO Rule 1.10).
- `signing_key_id`: source = the assessor's Ed25519 holder key
  registered in the tracker. If no key is registered, the API returns
  `409 Conflict` with body `{ error: 'REQUIRES-OPERATOR-INPUT', field: 'assessor.signing_key' }`.
- When the orchestrator's `--ingest-signoffs` flag is set but the
  tracker returns zero signoffs for a control × statement × method
  that the AR will emit, the AR emitter logs a `coverage:miss` line
  AND the AR's `target.status.state` becomes the collector-derived
  value plus a `props[]` entry `{ name: 'signoff-missing', value: 'REQUIRES-OPERATOR-INPUT' }`.

**Test specifications**:
1. `it('createSignoff inserts a row with a valid Ed25519 signature over the canonical payload', ...)` — assert row in DB, assert signature verifies via `core/sign.ts`.
2. `it('createSignoff throws ForbiddenError when user lacks assessor role', ...)` — pass a `reviewer` role user, assert throw.
3. `it('createSignoff is idempotent on (run_id, control_id, statement_id, method) when a non-revoked row already exists', ...)` — assert second call throws `Conflict`.
4. `it('revokeSignoff sets revoked_at + revoked_by_user_id and the row no longer appears in listSignoffs(activeOnly=true)', ...)`.
5. `it('listSignoffs filters by run_id and excludes revoked rows by default', ...)`.
6. `it('POST /api/signoffs returns 401 without auth, 403 without assessor role, 200 with valid input', ...)`.
7. `it('POST /api/signoffs rejects method values not in {EXAMINE, INTERVIEW, TEST}', ...)`.
8. `it('POST /api/signoffs rejects decision values not in {satisfied, not-satisfied}', ...)`.
9. `it('loadSignoffsFromTracker rejects responses missing required fields via ajv', ...)`.
10. `it('AR emit applies signoff status when a matching record exists', ...)` — seed a signoff with `decision=not-satisfied`, run `emitOscalAR`, assert `finding.target.status.state === 'not-satisfied'`.
11. `it('AR emit preserves the collector-derived status under props.collector-derived-status', ...)`.
12. `it('AR emit emits coverage:miss when a control × statement × method has no signoff', ...)`.
13. `it('UI: AssessorSignoffs page renders one row per (control × statement × method) from ap.json', ...)`.
14. `it('UI: sign button is disabled when current user lacks assessor role', ...)`.
15. `it('bundler well-known catalogue includes assessor-signoffs.json with role assessor-signoffs-export', ...)`.

**REO compliance checks specific to this slice**:
- Every emitted `assessor-signoff-uuid` prop traces to a row in
  `assessor_signoffs` created by a real human action recorded in the
  tracker audit log.
- No silent fallbacks: if `--ingest-signoffs` is set but the tracker
  returns nothing, the AR emits a `signoff-missing: REQUIRES-OPERATOR-INPUT`
  prop AND the run log records `coverage:miss`.
- No auto-signing: the orchestrator never inserts a row into
  `assessor_signoffs` directly. The tracker REST API + UI is the only
  path.
- Ed25519 signatures are real (delegated to `core/sign.ts`); they are
  never stubbed in production paths.

**Verification commands**:
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/signoff-ingest.test.ts tests/tracker/server/assessor-signoffs.test.ts tests/tracker/client/AssessorSignoffs.test.tsx
npm run check:reo
```

**Estimated effort**: 4 days.

---

### Slice F.F2 — Comment threads on findings

**Why this slice**: Today, when a 3PAO has a question about a finding
("is this S3 bucket public on purpose?"), the question travels by
email + Word-document margin comments. There is no audit trail. F.F2
threads the conversation in the tracker, links each comment to the
exact OSCAL finding-uuid, and freezes the thread after sign-off.

**Files to create** (exact paths):
- `cloud-evidence/tracker/server/db/migrations/0FF2_finding_comments.sql`
  — DDL for `finding_comments` + `finding_comment_attachments` tables.
- `cloud-evidence/tracker/server/routes/finding-comments.ts` — REST
  routes: `GET /api/findings/:uuid/comments`, `POST /api/findings/:uuid/comments`,
  `PATCH /api/comments/:id` (edit window 15 minutes after creation,
  see step 3), `DELETE /api/comments/:id` (only by author within edit
  window).
- `cloud-evidence/tracker/server/services/comment-service.ts` — pure
  business logic.
- `cloud-evidence/tracker/server/services/comment-notifier.ts` —
  email + Slack notification dispatch (reuses `core/notify.ts`).
- `cloud-evidence/tracker/client/src/components/FindingCommentThread.tsx`
  — chronological thread with edit / delete buttons.
- `cloud-evidence/tracker/client/src/pages/FindingDetail.tsx` — finding
  detail page that embeds the thread.
- `cloud-evidence/tests/tracker/server/finding-comments.test.ts`.
- `cloud-evidence/tests/tracker/server/comment-notifier.test.ts`.
- `cloud-evidence/tests/tracker/client/FindingCommentThread.test.tsx`.

**Files to extend** (paths + what to add):
- `cloud-evidence/core/notify.ts` — add `notifyFindingComment(input: { findingUuid, commentId, author, body, mentionedUserIds })`.
- `cloud-evidence/core/oscal.ts` — when ingesting comments at AR emit
  time (orchestrator flag `--ingest-comments`), embed each comment as
  an OSCAL `finding.remarks` Markdown fragment plus a `props[]` entry
  `{ name: 'comment-uuid', value: comment.id }` so the comment chain
  is recoverable from the AR alone.

**Schemas / standards**:
- OSCAL AR `finding.remarks` is a Markdown field per
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/json-reference/.
- The "freeze after sign-off" rule comes from the FedRAMP RAR Guide
  v3.2 expectation that the SAR is an authoritative artifact — once
  the assessor signs off on a finding (F.F1), no further edits to its
  comment thread are accepted; new content goes into a new thread on a
  follow-up finding-uuid.

**Build steps**:
1. DB migration `0FF2_finding_comments.sql`:
   ```
   CREATE TABLE finding_comments (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,           -- deterministic uuid
     finding_uuid TEXT NOT NULL,
     author_user_id INTEGER NOT NULL REFERENCES users(id),
     body_md TEXT NOT NULL,
     parent_comment_id INTEGER REFERENCES finding_comments(id),
     created_at TEXT NOT NULL,
     edited_at TEXT,
     deleted_at TEXT,
     frozen_at TEXT                       -- set when finding gets signed off
   );
   CREATE INDEX idx_fc_finding ON finding_comments (finding_uuid);
   CREATE TABLE finding_comment_attachments (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     comment_id INTEGER NOT NULL REFERENCES finding_comments(id),
     filename TEXT NOT NULL,
     mime_type TEXT NOT NULL,
     bytes INTEGER NOT NULL,
     sha256 TEXT NOT NULL,
     stored_path TEXT NOT NULL           -- relative to tracker upload dir
   );
   ```
2. **createComment** service:
   - Validates `body_md` non-empty, ≤ 16 KiB.
   - Validates `finding_uuid` exists in the most recent AR (queried
     from the tracker's mirror of `out/assessment-results.json`).
   - Rejects with `409 Locked` if the finding has `frozen_at`
     populated.
3. **15-minute edit window**: `editComment` accepts the request only
   if `now - created_at < 15 minutes` AND the user is the author.
   Outside that window the API returns `403 EditWindowExpired`.
4. **Sign-off freeze hook**: F.F1's `createSignoff` service also writes
   `UPDATE finding_comments SET frozen_at = ? WHERE finding_uuid = ?`
   for every finding-uuid whose every (statement × method) is now
   signed off. The freeze is recorded in the audit log.
5. **Notifier** in `comment-notifier.ts`:
   - On `POST /api/findings/:uuid/comments`, dispatches Slack + email
     via `core/notify.ts` to: (a) the finding's owner-of-record (from
     POA&M `responsible-parties[]`), (b) every prior author in the
     thread (de-duplicated).
   - Mentions: parse `@username` tokens; add those users to the
     notification list.
6. **UI** `FindingCommentThread.tsx`:
   - Chronological list, each comment renders the author + timestamp +
     Markdown body + edit / delete buttons (conditional on author +
     edit-window).
   - "New comment" textarea at the bottom; disabled (with explanation)
     when `frozen_at` is set.
7. **Orchestrator wire**: add `--ingest-comments` flag (mirrors
   `--ingest-signoffs`). When set, the AR emitter reads comments and
   embeds them as described in the OSCAL extension.

**REQUIRES-OPERATOR-INPUT fields**:
- `author_user_id`: real authenticated tracker user; no operator
  substitution.
- The tracker's URL + token are operator-supplied via the same env
  vars as F.F1.

**Test specifications**:
1. `it('createComment inserts a row when body is non-empty and finding exists', ...)`.
2. `it('createComment rejects body > 16 KiB', ...)`.
3. `it('createComment rejects when finding_uuid is unknown', ...)`.
4. `it('createComment rejects when finding is frozen', ...)`.
5. `it('editComment succeeds within 15 minutes for the author', ...)`.
6. `it('editComment fails outside 15-minute window with EditWindowExpired', ...)`.
7. `it('editComment fails for non-author with 403', ...)`.
8. `it('deleteComment soft-deletes (sets deleted_at) and the comment no longer renders', ...)`.
9. `it('signing off on a finding sets frozen_at on every comment for that finding', ...)`.
10. `it('comment-notifier sends Slack + email to POA&M owner + prior authors', ...)`.
11. `it('comment-notifier parses @username mentions and notifies them', ...)`.
12. `it('AR emit with --ingest-comments embeds each comment as finding.remarks Markdown with the comment-uuid prop', ...)`.
13. `it('UI: new-comment textarea is disabled with explanation when frozen', ...)`.
14. `it('UI: edit / delete buttons render only for the author within the edit window', ...)`.

**REO compliance checks specific to this slice**:
- Every comment traces to a real authenticated user. No system-
  generated comments. No placeholder threads.
- Comments are append-only after freeze; the freeze is the artifact of
  a real sign-off action (F.F1).
- Notifier failures bubble up as `partial-failure` warnings; the
  comment is still persisted (so a flaky Slack endpoint does not lose
  the audit trail).

**Verification commands**:
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/tracker/server/finding-comments.test.ts tests/tracker/server/comment-notifier.test.ts tests/tracker/client/FindingCommentThread.test.tsx
npm run check:reo
```

**Estimated effort**: 3 days.

---

### Slice F.F3 — Sample selection methodology auto-derive

**Why this slice**: Per the R4 research in
`cloud-evidence/docs/PRE-LOOP-A-RESEARCH-FINDINGS.md`, FedRAMP requires
a "Sampling Methodology" Appendix B in the SAP whenever sampling is
used. The methodology must follow rules from the Rev5 ConMon
Vulnerability Scanning Playbook (see §3.4): 100% of externally-
accessible components, stratified sample for internal components with
3PAO attestation + AO approval. Today operators write this by hand.
F.F3 derives it from real `inventory.json` so the 3PAO has a precise,
inventory-grounded starting plan.

**Files to create** (exact paths):
- `cloud-evidence/core/sampling-methodology.ts` — pure builder +
  disk emitter.
- `cloud-evidence/tests/core/sampling-methodology.test.ts`.

**Files to extend** (paths + what to add):
- `cloud-evidence/core/orchestrator.ts` — flag
  `--sampling-methodology` + env `CLOUD_EVIDENCE_SAMPLING_METHODOLOGY`.
  Reads `out/inventory.json`, calls `buildSamplingMethodology`, writes
  `out/sampling-methodology.json` + `out/sampling-methodology.md`.
- `cloud-evidence/core/oscal-ap.ts` — when
  `out/sampling-methodology.json` exists on disk, append a
  `back-matter.resources[]` entry pointing at it (rel=`reference`,
  title=`SAP Appendix B — Sampling Methodology`) and add a
  `terms-and-conditions.parts[]` entry titled `Sampling` whose `prose`
  cites the resource by uuid.
- `cloud-evidence/core/submission-bundle.ts` — well-known catalogue:
  `{ role: 'sampling-methodology-json', filename: 'sampling-methodology.json', description: 'SAP Appendix B — Sampling Methodology (machine-readable)' }`
  and `{ role: 'sampling-methodology-md', filename: 'sampling-methodology.md', description: 'SAP Appendix B — Sampling Methodology (Markdown)' }`.

**Schemas / standards**:
- FedRAMP Rev5 ConMon Vulnerability Scanning Playbook
  (https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/vulnerability-scanning/) §3.4
  quotes above. 100% external rule is HARD-CODED (it's a FedRAMP MUST,
  REO Rule 3 "FedRAMP-published constants").
- FedRAMP Rev5 SAP Playbook
  (https://www.fedramp.gov/docs/rev5/playbook/csp/authorization/sap/):
  Appendix B title + signature requirement.
- Sample plan JSON shape (cite as `cloud-evidence:sampling-methodology v1`):
  ```
  {
    schema: 'cloud-evidence:sampling-methodology@1',
    runId, systemId, generatedAt,
    inventory_source: 'out/inventory.json',
    inventory_count: N,
    externally_accessible: {
      rule: '100%',
      rule_source: 'https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/vulnerability-scanning/',
      count: M,
      strata: [{ asset_class, region, count }, ...]
    },
    internal: {
      strata: [{ asset_class, region, total, sampled, percentage }, ...],
      floor_percent: 10,
      operator_overrides: { ... },
      requires_operator_input: ['ao-approval-id', ...]
    },
    provenance: {
      module: 'core/sampling-methodology.ts',
      sourceCalls: ['readFileSync(out/inventory.json)']
    }
  }
  ```

**Build steps**:
1. **Interface**:
   ```
   interface SamplingMethodologyOptions {
     runId: string;
     systemId: string;
     impactTier: ImpactTier;
     /** Override floor percentage per asset_class. Default 10. */
     internalSamplePercent?: Record<string, number>;
     /** Hard-coded externally-accessible at 100%; cannot be overridden. */
     /** ISO-8601 AO approval timestamp once obtained. */
     aoApprovalAt?: string;
     /** AO approval reference number/string. */
     aoApprovalId?: string;
     /** Asset-id allow-list for inventory loading; defaults to all. */
     inventoryPath?: string;   // defaults to out/inventory.json
     outDir?: string;          // defaults to out/
   }

   interface SamplingMethodologyResult {
     jsonPath: string;
     mdPath: string;
     plan: SamplingPlan;       // the JSON above
     requires_operator_input: string[];
   }
   ```
2. **Pure builder**:
   `buildSamplingMethodology(inventory: Inventory, opts: SamplingMethodologyOptions): SamplingPlan` —
   no I/O, no clock dependency (`generatedAt` flows through opts or
   defaults to a deterministic value derived from `runId`).
   - Partition inventory into `externally_accessible` (assets where
     `is_externally_accessible === true` OR
     `is_public === true` OR
     `network.exposure === 'internet'`) and `internal` (everything
     else).
   - For the external bucket, set `rule: '100%'` and group strata by
     `(asset_class, region)`.
   - For the internal bucket:
     - Group by `(asset_class, region)`.
     - Per stratum, `sampled = max(ceil(total * percent / 100), 1)`
       where `percent = opts.internalSamplePercent[asset_class] ?? 10`.
     - Cap `sampled <= total`.
   - When `opts.aoApprovalId` is missing, push
     `'ao-approval-id'` into `requires_operator_input`.
   - When `opts.aoApprovalAt` is missing, push
     `'ao-approval-at'` into `requires_operator_input`.
   - When `inventory.length === 0`, return a plan with
     `requires_operator_input: ['inventory-empty']` and zero strata.
3. **Disk emitter** `emitSamplingMethodology(opts): SamplingMethodologyResult` —
   reads `inventory.json`, calls builder, writes both `.json` and
   `.md` (Markdown rendered with section headings: §1 Source rules
   (with verbatim quote citations), §2 100% externally-accessible
   list, §3 Internal stratified plan, §4 AO approval section
   with REQUIRES-OPERATOR-INPUT placeholders when missing).
4. **Orchestrator wire**: `--sampling-methodology` runs the emitter
   BEFORE `--oscal-ap` so the AP can link the resulting JSON.
5. **AP integration**: in `oscal-ap.ts`, after the existing
   `back-matter.resources` array is built, append the sampling-
   methodology resource when the file exists on disk; deterministic
   uuid from the file sha256.
6. **Bundler integration**: add both well-known catalogue entries.

**REQUIRES-OPERATOR-INPUT fields**:
- `aoApprovalId`: source = CLI flag `--ao-approval-id <id>` or env
  `CLOUD_EVIDENCE_AO_APPROVAL_ID`.
- `aoApprovalAt`: source = CLI flag `--ao-approval-at <ISO>` or env
  `CLOUD_EVIDENCE_AO_APPROVAL_AT`.
- Per-asset-class override percentages: source = `config.yaml` key
  `sampling.internal_percent_by_class: { ec2: 25, rds: 50 }`.
- The 100%-external rule is NOT operator-overrideable (REO Rule 3
  exception: FedRAMP-published constant).

**Test specifications**:
1. `it('partitions inventory into externally-accessible and internal buckets correctly', ...)`.
2. `it('emits 100% rule for externally-accessible bucket', ...)`.
3. `it('stratifies internal bucket by (asset_class, region) and applies default 10% floor', ...)`.
4. `it('applies per-asset-class override when supplied via internalSamplePercent', ...)`.
5. `it('rounds up to at least 1 sample per non-empty stratum', ...)`.
6. `it('caps sampled <= total per stratum', ...)`.
7. `it('emits ao-approval-id + ao-approval-at as REQUIRES-OPERATOR-INPUT when missing', ...)`.
8. `it('handles empty inventory with requires_operator_input=["inventory-empty"]', ...)`.
9. `it('emit writes both .json and .md files; .md cites the playbook URL verbatim', ...)`.
10. `it('AP emit with sampling-methodology.json on disk appends a back-matter.resources entry', ...)`.
11. `it('AP emit links the sampling resource from terms-and-conditions.parts', ...)`.
12. `it('bundler well-known catalogue includes sampling-methodology-json + -md', ...)`.
13. `it('plan is deterministic on identical input (byte-stable .json)', ...)`.
14. `it('JSON output validates against the cloud-evidence:sampling-methodology@1 ajv schema', ...)`.

**REO compliance checks specific to this slice**:
- Every count traces back to a row in `inventory.json` (real cloud
  SDK evidence).
- The 100% external rule is cited verbatim with the FedRAMP playbook
  URL embedded in the output `.md` (REO Rule 3 allowed fixed data).
- Operator AO approval data is never defaulted; missing means
  REQUIRES-OPERATOR-INPUT.
- No silent inventory fallback: empty inventory → explicit
  `inventory-empty` marker, run log emits `coverage:miss`.

**Verification commands**:
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/sampling-methodology.test.ts
npm run check:reo
```

**Estimated effort**: 2 days.

---

### Slice F.F4 — Evidence walk-through artifacts

**Why this slice**: NIST SP 800-115 §4 (Technical Guide to Information
Security Testing and Assessment) requires that findings be documented
"with sufficient detail to allow another technical professional to
verify them independently." 3PAOs do this with screenshots + tool
output transcripts. Today these live in zip files on shared drives.
F.F4 captures them in the tracker, links each artifact to the OSCAL
finding-uuid, and surfaces them as `observation.relevant-evidence[]`
entries in the AR.

**Files to create** (exact paths):
- `cloud-evidence/tracker/server/db/migrations/0FF4_walkthrough_evidence.sql`.
- `cloud-evidence/tracker/server/routes/walkthrough.ts` — REST routes:
  `POST /api/findings/:uuid/walkthrough` (multipart upload),
  `GET /api/findings/:uuid/walkthrough`,
  `DELETE /api/walkthrough/:id` (author within edit window).
- `cloud-evidence/tracker/server/services/walkthrough-service.ts`.
- `cloud-evidence/tracker/server/services/walkthrough-storage.ts` —
  on-disk storage under `tracker/uploads/walkthrough/<finding-uuid>/<artifact-uuid>/`.
- `cloud-evidence/tracker/client/src/components/WalkthroughUploader.tsx` —
  drag-and-drop uploader for `.png`, `.jpg`, `.txt`, `.json`, `.har`,
  `.pcap`.
- `cloud-evidence/tracker/client/src/components/WalkthroughGallery.tsx` —
  per-finding gallery viewer.
- `cloud-evidence/core/walkthrough-bundle.ts` — pure reader that the
  orchestrator calls to ingest the tracker's walk-through directory
  into the AR's observations and into the submission bundle.
- `cloud-evidence/tests/core/walkthrough-bundle.test.ts`.
- `cloud-evidence/tests/tracker/server/walkthrough.test.ts`.
- `cloud-evidence/tests/tracker/client/WalkthroughUploader.test.tsx`.

**Files to extend** (paths + what to add):
- `cloud-evidence/core/oscal.ts` — when
  `WalkthroughBundle` is passed via
  `OscalEmitOptions.walkthroughSource`, for each finding-uuid in the
  bundle, append an `observation` with `methods: ['EXAMINE']` and
  `relevant-evidence: [{ href: 'evidence-walkthrough/<finding>/<artifact>', description, props: [...] }]`
  to the result, linking from the matching `finding.related-observations`.
- `cloud-evidence/core/submission-bundle.ts` — include the
  `evidence-walkthrough/` subdirectory under `outDir` in the bundler
  walk; each artifact ships under
  `evidence-walkthrough/<finding-uuid>/<artifact-uuid>/<filename>` in
  the tarball. New well-known catalogue entry `evidence-walkthrough-bundle`
  matching the regex `^evidence-walkthrough/.+`.

**Schemas / standards**:
- NIST SP 800-115 §4 verbatim quote above.
- FedRAMP Penetration Test Guidance §6 (redaction expectations for any
  credential strings captured in walk-through transcripts).
- OSCAL AR `observation.relevant-evidence` element per
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/json-reference/.

**Build steps**:
1. DB migration:
   ```
   CREATE TABLE walkthrough_artifacts (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     finding_uuid TEXT NOT NULL,
     uploader_user_id INTEGER NOT NULL REFERENCES users(id),
     filename TEXT NOT NULL,
     mime_type TEXT NOT NULL,
     bytes INTEGER NOT NULL,
     sha256 TEXT NOT NULL,
     description TEXT,
     captured_at TEXT,                -- ISO when the screenshot was taken (operator)
     tool_name TEXT,                  -- e.g. "aws cli 2.16.1"
     tool_version TEXT,
     command TEXT,                    -- e.g. "aws s3api get-bucket-policy --bucket X"
     stored_path TEXT NOT NULL,
     redaction_applied INTEGER NOT NULL DEFAULT 0,
     created_at TEXT NOT NULL,
     deleted_at TEXT
   );
   CREATE INDEX idx_walk_finding ON walkthrough_artifacts (finding_uuid);
   ```
2. **Upload route** validates:
   - `finding_uuid` exists in the most recent AR.
   - `filename` extension in allowlist (`.png .jpg .jpeg .txt .json .har .pcap`).
   - `bytes <= 25 MiB` (configurable via env
     `CLOUD_EVIDENCE_WALKTHROUGH_MAX_BYTES`).
   - User role is `assessor` (only the 3PAO uploads).
   - Multipart fields: `file`, `description`, `captured_at`, `tool_name`,
     `tool_version`, `command`.
3. **Storage** writes the file to
   `tracker/uploads/walkthrough/<finding-uuid>/<artifact-uuid>/<sanitized-filename>`
   and records sha256.
4. **Redaction**: when `tool_name` matches `aws cli|gcloud|az`, run a
   regex pass over `command` for known secret patterns (`AKIA[0-9A-Z]{16}`,
   `password=`, `token=`) and set `redaction_applied=1` if any are
   masked. The DB stores the *redacted* command; the original is never
   persisted.
5. **Orchestrator ingest** in `walkthrough-bundle.ts`:
   `loadWalkthroughFromTracker(url, runId): Promise<WalkthroughBundle>`
   downloads every artifact for the run to `outDir/evidence-walkthrough/`
   while verifying sha256 matches.
6. **AR integration**: pass `walkthroughSource` to `emitOscalAR()`.
   For each finding-uuid present in the bundle, append one observation
   per artifact:
   ```
   {
     uuid: deterministicUuid(`walkthrough:${artifact.uuid}`),
     methods: ['EXAMINE'],
     types: ['evidence'],
     description: artifact.description,
     'collected': artifact.captured_at,
     'relevant-evidence': [{
       href: `evidence-walkthrough/${finding}/${artifact.uuid}/${artifact.filename}`,
       description: `${artifact.tool_name} ${artifact.tool_version} :: ${artifact.command}`,
       props: [
         { name: 'sha256', value: artifact.sha256 },
         { name: 'bytes', value: String(artifact.bytes) },
         { name: 'redaction-applied', value: artifact.redaction_applied ? 'true' : 'false' }
       ]
     }]
   }
   ```
7. **Bundler** registers the `evidence-walkthrough/` subdirectory in
   the listOutDir() walk and adds the regex catalogue entry.

**REQUIRES-OPERATOR-INPUT fields**:
- `tool_name`, `tool_version`, `command`, `captured_at`: source =
  multipart form fields. If absent, the upload returns `400
  REQUIRES-OPERATOR-INPUT` and the file is NOT persisted. (SP 800-115
  reproducibility rule.)
- `description`: required.

**Test specifications**:
1. `it('rejects upload with bytes > max', ...)`.
2. `it('rejects upload with file extension not in allowlist', ...)`.
3. `it('rejects upload without required fields (tool_name, command, captured_at, description)', ...)`.
4. `it('rejects upload when finding_uuid does not exist in the AR', ...)`.
5. `it('stores file at <tracker-uploads>/walkthrough/<finding>/<uuid>/<sanitized> with matching sha256', ...)`.
6. `it('applies AKIA-pattern redaction in command and sets redaction_applied=1', ...)`.
7. `it('only assessor role can upload (403 for reviewer)', ...)`.
8. `it('loadWalkthroughFromTracker downloads + sha256-verifies every artifact for the run', ...)`.
9. `it('AR emit with walkthroughSource appends an observation per artifact with methods=["EXAMINE"], types=["evidence"]', ...)`.
10. `it('AR emit links observations to the parent finding via finding.related-observations', ...)`.
11. `it('bundler includes evidence-walkthrough/** files with role evidence-walkthrough-bundle', ...)`.
12. `it('UI: WalkthroughUploader rejects unsupported extensions client-side', ...)`.
13. `it('UI: WalkthroughGallery renders one tile per artifact and shows sha256 + bytes', ...)`.

**REO compliance checks specific to this slice**:
- Every artifact has a real on-disk file with verifiable sha256.
- Tool name + version + command are required and operator-supplied;
  no auto-substitution.
- Redaction is applied at write time; the original unredacted command
  is never persisted to disk.
- The AR's `observation.relevant-evidence[]` href points to a file
  that exists in the submission bundle (verified by the bundler at
  pack time; missing files emit `coverage:miss`).

**Verification commands**:
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/walkthrough-bundle.test.ts tests/tracker/server/walkthrough.test.ts tests/tracker/client/WalkthroughUploader.test.tsx
npm run check:reo
```

**Estimated effort**: 3 days.

---

### Slice F.F5 — 3PAO recommendation letter template

**Why this slice**: The FedRAMP SAR Template requires a "Section 2,
Executive Summary" that contains the 3PAO's authorization recommendation
(quoted in §3.2 above). The 3PAO Readiness Assessment Report Guide v3.2
requires the recommendation to be "clear, unambiguous, and contain no
conditional language" (§3.1). Today the 3PAO authors this letter
from scratch. F.F5 seeds a `.docx` pre-filled with system identity,
assessment period, finding counts, and three checkbox-style
recommendation options that the 3PAO selects and then signs.

**Files to create** (exact paths):
- `cloud-evidence/core/recommendation-letter.ts` — dependency-free
  `.docx` emitter (mirrors `core/roe-emit.ts` pattern).
- `cloud-evidence/tests/core/recommendation-letter.test.ts`.

**Files to extend** (paths + what to add):
- `cloud-evidence/core/orchestrator.ts` — flag
  `--recommendation-letter` + env
  `CLOUD_EVIDENCE_RECOMMENDATION_LETTER`. Runs AFTER the AR + POA&M
  emit (so finding counts are accurate) but BEFORE the submission
  bundler.
- `cloud-evidence/core/submission-bundle.ts` — well-known catalogue:
  `{ role: 'recommendation-letter-docx', filename: 'recommendation-letter.docx', description: '3PAO Authorization Recommendation Letter' }`.

**Schemas / standards**:
- FedRAMP SAR Template §2 Executive Summary structure (URL §3.2).
- FedRAMP 3PAO RAR Guide v3.2 §3.1 unambiguous-recommendation rule.
- OOXML WordprocessingML (same conformance level as `core/roe-emit.ts`).

**Build steps**:
1. **Interface**:
   ```
   interface RecommendationLetterOptions {
     systemName?: string;
     systemId?: string;
     cspOrganization?: string;
     threePaoOrganization?: string;
     impactTier?: ImpactTier;
     assessmentPeriodStart?: string;     // ISO date
     assessmentPeriodEnd?: string;       // ISO date
     /** Read from out/assessment-results.json + out/poam.json when not supplied. */
     findingCounts?: { satisfied: number; otherThanSatisfied: number; high: number; moderate: number; low: number };
     /** Read from inventory.json size when not supplied. */
     componentCount?: number;
     authorizingOfficial?: { name?: string; title?: string; agency?: string };
     /** Operator may pre-select; otherwise three checkbox options render. */
     recommendation?: 'recommend' | 'recommend-with-conditions' | 'do-not-recommend';
     conditionsNarrative?: string;
     outPath?: string;                   // defaults to out/recommendation-letter.docx
     runId: string;
     emittedAt?: string;
   }
   interface RecommendationLetterResult {
     path: string;
     bytes: number;
     requires_operator_input: string[];
     ready_for_signature: boolean;
   }
   ```
2. **Pure renderer** `renderRecommendationLetterDocx(opts): { docxBytes: Buffer; stats: Omit<RecommendationLetterResult, 'path' | 'bytes'> }` —
   structured as 6 sections (verbatim section headings):
   - §1 *Identification* — system name, system id, CSP, 3PAO, impact
     tier, assessment period.
   - §2 *Scope of Assessment* — finding counts (satisfied / other-than-
     satisfied / open POA&M severity), component count.
   - §3 *Methodology Summary* — cites SAP + RoE + Sampling Methodology
     by filename (one row per back-matter resource present in
     `out/ap.json`).
   - §4 *Recommendation* — three checkboxes:
     `[ ] We recommend authorization.`
     `[ ] We recommend authorization with the conditions listed in §5.`
     `[ ] We do NOT recommend authorization.`
     A REQUIRES-OPERATOR-INPUT marker appears next to the unselected
     state until `opts.recommendation` is set.
     **Hard guard**: the renderer NEVER emits prose like "subject to
     successful…" or "pending future remediation of…" (REO Rule + RAR
     Guide unambiguous-language rule). The conditionsNarrative is the
     only place conditional language is allowed.
   - §5 *Conditions and Risks* — conditionsNarrative (if any) +
     enumerated open POA&M items grouped by severity.
   - §6 *Signature Block* — 3PAO Lead Assessor + 3PAO Quality
     Reviewer signature cells (both REQUIRES-OPERATOR-INPUT).
3. **Disk emitter** `emitRecommendationLetter(opts)`: reads
   `out/assessment-results.json` + `out/poam.json` + `out/inventory.json`
   when corresponding opts fields are absent; calls renderer; writes
   to `outPath`. Logs `requires_operator_input` count + `ready_for_signature`.
4. **Orchestrator wire**: flag triggers `emitRecommendationLetter()`
   after `--oscal-ar` and `--oscal-poam`. Console reports finding
   counts + ready-for-signature.
5. **Bundler catalogue**: add the entry above.

**REQUIRES-OPERATOR-INPUT fields**:
- `recommendation` (which of the three checkboxes is selected): source
  = CLI flag `--recommendation=<recommend|recommend-with-conditions|do-not-recommend>`
  or env `CLOUD_EVIDENCE_RECOMMENDATION` (since the recommendation is
  the 3PAO's professional judgment, the orchestrator allows this CLI
  flag but the .docx still emits a signature block — the .docx is the
  *draft*, the 3PAO's *signature* is the binding action).
- `conditionsNarrative`: CLI flag `--conditions-narrative <path>` or
  read from `config.yaml` key `recommendation.conditions`.
- `authorizingOfficial.{name,title,agency}`: `config.yaml` key
  `authorizing_official` or REQUIRES-OPERATOR-INPUT cells.
- `assessmentPeriodStart`, `assessmentPeriodEnd`: CLI flags or
  REQUIRES-OPERATOR-INPUT.
- All signature cells: REQUIRES-OPERATOR-INPUT (the 3PAO signs in
  Word + uploads back; the system NEVER auto-signs — REO Rule 1.10).

**Test specifications**:
1. `it('renders a valid OOXML docx (zip-store, document.xml parses)', ...)`.
2. `it('reads finding counts from out/assessment-results.json when findingCounts not supplied', ...)`.
3. `it('reads POA&M severity counts from out/poam.json', ...)`.
4. `it('reads componentCount from inventory.json when not supplied', ...)`.
5. `it('emits REQUIRES-OPERATOR-INPUT for unsupplied identity fields', ...)`.
6. `it('renders three checkbox options when recommendation is unset', ...)`.
7. `it('marks the chosen checkbox when recommendation is set, leaves others empty', ...)`.
8. `it('refuses to emit conditional language outside §5 (asserts §4 prose has no "subject to" / "pending")', ...)`.
9. `it('renders conditionsNarrative verbatim in §5 when supplied', ...)`.
10. `it('lists open POA&M items grouped by severity in §5', ...)`.
11. `it('ready_for_signature is true only when every operator field is supplied AND recommendation is set', ...)`.
12. `it('cites SAP + RoE + sampling-methodology by filename in §3 when each exists', ...)`.
13. `it('bundler well-known catalogue includes recommendation-letter.docx', ...)`.
14. `it('emits to operator-supplied outPath when provided', ...)`.

**REO compliance checks specific to this slice**:
- All counts trace to real on-disk artifacts (AR + POA&M + inventory).
- Signature cells are NEVER auto-filled.
- Conditional-language guard (test #8) prevents the renderer from ever
  emitting a phrase the RAR Guide §3.1 prohibits.
- No fabricated authorization language — the three checkboxes are
  verbatim from FedRAMP guidance.

**Verification commands**:
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/recommendation-letter.test.ts
npm run check:reo
```

**Estimated effort**: 2 days.

---

### Slice F.F6 — Full ATO workflow tracker (PM-10)

**Why this slice**: NIST PM-10 mandates that the organization "manage the
security and privacy state of organizational systems… through
authorization processes" with documented role assignments and an
integrated workflow (§3.5 verbatim). Today, our tooling ends at the
signed bundle — there is no visibility into AO review, ATO decision,
or publication. F.F6 implements the state machine + audit log so
every transition is captured + signed.

**Files to create** (exact paths):
- `cloud-evidence/tracker/server/db/migrations/0FF6_ato_workflow.sql`.
- `cloud-evidence/tracker/server/services/ato-workflow-service.ts` —
  pure state-machine logic.
- `cloud-evidence/tracker/server/routes/ato-workflow.ts` — REST
  routes: `GET /api/ato/:run`, `POST /api/ato/:run/transition`.
- `cloud-evidence/tracker/client/src/pages/AtoWorkflow.tsx` — Kanban-
  style swimlane page (one column per state).
- `cloud-evidence/tracker/client/src/components/AtoTransitionModal.tsx`.
- `cloud-evidence/core/ato-state-export.ts` — pure reader that exports
  the current ATO state for inclusion in the submission bundle.
- `cloud-evidence/tests/tracker/server/ato-workflow.test.ts`.
- `cloud-evidence/tests/core/ato-state-export.test.ts`.

**Files to extend** (paths + what to add):
- `cloud-evidence/core/submission-bundle.ts` — well-known catalogue:
  `{ role: 'ato-workflow-state', filename: 'ato-workflow-state.json', description: 'PM-10 authorization-workflow state + transition audit log' }`.

**Schemas / standards**:
- NIST SP 800-53 Rev 5 PM-10 Authorization Process control text
  (verbatim above in §3.5).
- State machine (no FedRAMP-published verbatim; this is the FedRAMP
  community-standard ATO lifecycle — document the source of each
  state in the audit log):
  ```
  DRAFT
    → PACKAGE_COMPLETE          (CSP signal: --submission-bundle written)
    → THREE_PAO_REVIEW          (assessor sign-offs in progress)
    → THREE_PAO_SIGNOFF         (every F.F1 signoff present)
    → AO_REVIEW                 (uploaded to FedRAMP / agency AO)
    → ATO_GRANTED               (AO decision: positive)
    → ATO_DENIED                (AO decision: negative)
    → PUBLISHED                 (FedRAMP Marketplace listing live)
  ```
  Each transition requires: `from_state`, `to_state`, `actor_user_id`,
  `evidence_url` (or `evidence_artifact_uuid`), `transitioned_at`,
  signature.

**Build steps**:
1. DB migration:
   ```
   CREATE TABLE ato_workflow_state (
     run_id TEXT PRIMARY KEY,
     current_state TEXT NOT NULL,
     updated_at TEXT NOT NULL
   );
   CREATE TABLE ato_workflow_transitions (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     run_id TEXT NOT NULL,
     from_state TEXT NOT NULL,
     to_state TEXT NOT NULL,
     actor_user_id INTEGER NOT NULL REFERENCES users(id),
     evidence_url TEXT,
     evidence_artifact_uuid TEXT,
     transitioned_at TEXT NOT NULL,
     reason TEXT NOT NULL,
     signature TEXT NOT NULL,
     signing_key_id TEXT NOT NULL
   );
   CREATE INDEX idx_ato_trans_run ON ato_workflow_transitions (run_id);
   ```
2. **State machine** in `ato-workflow-service.ts`:
   - `ALLOWED_TRANSITIONS: Record<State, State[]>` — encodes the DAG
     above plus regression edges (e.g. `AO_REVIEW → THREE_PAO_REVIEW`
     when AO returns the package for rework).
   - `transition(input, ctx)` validates: current_state matches
     `from_state`, the transition is in `ALLOWED_TRANSITIONS`, the
     actor's role permits it (CSP roles for `PACKAGE_COMPLETE`,
     assessor for `THREE_PAO_*`, AO for `AO_*` and `ATO_*`, PMO for
     `PUBLISHED`). Signs the canonical payload via Ed25519. Updates
     `current_state`.
3. **REST routes**: standard get / post + listTransitions. RBAC
   middleware per state.
4. **UI** `AtoWorkflow.tsx`:
   - Swimlane per state with the run id badge in the current column.
   - Transition modal asks for `to_state`, `reason`, optional
     `evidence_url` / `evidence_artifact_uuid`.
5. **Auto-progress hooks**:
   - When `--submission-bundle` writes a bundle, the orchestrator
     POSTs `transition(DRAFT → PACKAGE_COMPLETE)` (actor = the
     `system` service account; signature uses the orchestrator's
     signing key). This is the ONE allowed automated transition because
     it's not a human-judgment step — it's a packaging milestone with
     a real artifact.
   - All subsequent transitions require human actors (REO Rule 1.10).
6. **Export** `ato-state-export.ts`:
   `exportAtoState(runId, outDir): { jsonPath, transitionCount }` —
   reads tracker DB through HTTP, writes `ato-workflow-state.json`.
7. **Bundler integration**: include the file.

**REQUIRES-OPERATOR-INPUT fields**:
- `actor_user_id`: real authenticated tracker user with the matching
  role.
- `evidence_url`: for transitions that require external evidence
  (e.g. `AO_REVIEW → ATO_GRANTED` needs the signed ATO letter URL).
- `reason`: free text, required.

**Test specifications**:
1. `it('rejects a transition not in ALLOWED_TRANSITIONS', ...)`.
2. `it('rejects a transition whose actor lacks the required role for that edge', ...)`.
3. `it('signs the canonical payload with Ed25519 over { run_id, from_state, to_state, actor_user_id, transitioned_at }', ...)`.
4. `it('updates current_state only when the signature persists successfully', ...)`.
5. `it('allows ATO regression edges (AO_REVIEW → THREE_PAO_REVIEW)', ...)`.
6. `it('auto-progresses DRAFT → PACKAGE_COMPLETE when the bundler emits successfully', ...)`.
7. `it('rejects all subsequent auto-progressions (no system-actor allowed)', ...)`.
8. `it('exports ato-workflow-state.json with current_state + transition log', ...)`.
9. `it('bundler well-known catalogue includes ato-workflow-state.json', ...)`.
10. `it('UI: swimlane shows the run only in its current state column', ...)`.
11. `it('UI: transition modal validates required fields (to_state, reason)', ...)`.
12. `it('audit log emits one entry per transition with the signing user', ...)`.
13. `it('every state in ALLOWED_TRANSITIONS appears in the rendered swimlane', ...)`.

**REO compliance checks specific to this slice**:
- One — and only one — auto-progression (DRAFT → PACKAGE_COMPLETE),
  triggered by a real artifact write and signed by the orchestrator's
  service key. Documented exception in the slice; nothing else
  auto-progresses.
- Every other transition is a real human action with a real signed
  audit record.
- Every transition uuid traces to a row in
  `ato_workflow_transitions`.

**Verification commands**:
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/tracker/server/ato-workflow.test.ts tests/core/ato-state-export.test.ts
npm run check:reo
```

**Estimated effort**: 3 days.

---

### Slice F.F7 — SAR draft generator

**Why this slice**: The FedRAMP SAR is the authoritative artifact the
AO uses to make the ATO decision. Today the 3PAO authors it in Word
from a template. F.F7 emits a draft `.docx` populated from the real
OSCAL AR + tracker sign-offs (F.F1) + comments (F.F2) + walk-through
evidence references (F.F4) + recommendation letter (F.F5). The 3PAO
opens it, completes any REQUIRES-OPERATOR-INPUT markers, and signs.

**Files to create** (exact paths):
- `cloud-evidence/core/sar-draft.ts` — dependency-free `.docx`
  emitter.
- `cloud-evidence/core/sar-sections/` — directory of per-section
  render helpers:
  - `cover.ts`, `executive-summary.ts`, `system-overview.ts`,
    `assessment-methodology.ts`, `findings-table.ts`, `risk-exposure.ts`,
    `non-conforming.ts`, `interconnected.ts`, `recommendation.ts`,
    `appendix-pointers.ts`.
- `cloud-evidence/tests/core/sar-draft.test.ts`.

**Files to extend** (paths + what to add):
- `cloud-evidence/core/orchestrator.ts` — flag `--sar-draft` + env
  `CLOUD_EVIDENCE_SAR_DRAFT`. Runs AFTER AR + POA&M + recommendation-
  letter emit; BEFORE submission-bundle.
- `cloud-evidence/core/submission-bundle.ts` — well-known catalogue:
  `{ role: 'sar-draft-docx', filename: 'sar-draft.docx', description: 'FedRAMP SAR — 3PAO draft for finalization' }`.

**Schemas / standards**:
- FedRAMP SAR Template structure (verbatim in §3.2):
  - Section 1: Identification / System Identifier
  - Section 2: Executive Summary (recommendation language §3.1)
  - Section 3: System Overview / Architecture
  - Section 4: Assessment Methodology
  - Section 5: Security Assessment Results (findings table)
  - Section 6: Non-Conforming Controls
  - Section 7: Risks for Interconnected Systems
  - Section 8: Recommendations & Conclusion
  - Appendix A: Risk Exposure Table (RET) — pointer to POA&M
  - Appendix B: SRTM Workbook — pointer to IIW
  - Appendix C: Vulnerability Scan Results — pointer to VDR outputs
  - Appendix D: Documentation Review Findings — pointer to
    process-artifact tracker exports
  - Appendix E: Auxiliary Documents — pointer to ssp.docx, ap.json, etc.
  - Appendix F: Penetration Test Report — pointer to LOOP-K.K1
- NIST SP 800-53A Rev 5 finding wording: every finding states
  Satisfied (S) or Other Than Satisfied (O) per §3.5 above.
- RAR Guide v3.2 §3.1 unambiguous-language rule.

**Build steps**:
1. **Interface** `SarDraftOptions`:
   ```
   {
     runId: string;
     outDir?: string;            // defaults to out/
     outPath?: string;           // defaults to out/sar-draft.docx
     systemName?: string;
     systemId?: string;
     cspOrganization?: string;
     threePaoOrganization?: string;
     impactTier?: ImpactTier;
     assessmentPeriodStart?: string;
     assessmentPeriodEnd?: string;
     /** When false, the appendix-pointers section emits relative paths
      *  to artifacts in the same bundle; when true, embeds an absolute
      *  URL the operator supplies via FEDRAMP_REPO_URL. */
     useAbsoluteUrls?: boolean;
   }
   interface SarDraftResult {
     path: string;
     bytes: number;
     section_counts: Record<string, number>;   // e.g. findings: 142
     requires_operator_input: string[];
     ready_for_signature: boolean;
   }
   ```
2. **Pure builder** reads `out/assessment-results.json`,
   `out/poam.json`, `out/ap.json`, `out/inventory.json`,
   `out/recommendation-letter.docx` (existence only, not content),
   `out/assessor-signoffs.json` (from F.F1 export), and emits per-
   section XML strings. Each section is a function in
   `core/sar-sections/`. Uses the same OOXML + `core/zip.ts` primitives
   as `core/roe-emit.ts`.
3. **Section §2 Executive Summary** wording:
   - Includes finding counts (S vs O per SP 800-53A §3.5 verbatim).
   - Quotes the 3PAO recommendation from `out/recommendation-letter.docx`
     when it exists; otherwise emits REQUIRES-OPERATOR-INPUT.
   - The unambiguous-language guard (mirrors F.F5 test #8) prevents
     "subject to" / "pending" / "conditional on" appearing outside §6
     or §8 Conditions.
4. **Section §5 Findings Table**:
   - One row per `finding` in the AR with columns: control-id,
     statement-id, method, status (S/O), severity, title, evidence
     references (links to the walk-through bundle), assessor sign-off
     uuid (when present), comment count.
   - When a finding has no F.F1 sign-off (orchestrator ran without
     `--ingest-signoffs`), the row's status column emits
     REQUIRES-OPERATOR-INPUT with a note explaining the fix.
5. **Section §6 Non-Conforming Controls** — enumerates every finding
   with `status.state === 'not-satisfied'` and cross-references the
   POA&M item by uuid.
6. **Appendices** — emit a pointer table per appendix listing the
   relative path (or absolute URL when `useAbsoluteUrls`) to the
   underlying artifact, sha256, and bundler-role.
7. **Orchestrator wire**: `--sar-draft` flag triggers the emitter.
8. **Bundler catalogue**: include `sar-draft.docx`.

**REQUIRES-OPERATOR-INPUT fields**:
- All identity / period fields not supplied via opts or config.
- Recommendation language when `out/recommendation-letter.docx` is
  absent.
- Status column per finding when no sign-off exists.
- Signature block (§ following §8): always REQUIRES-OPERATOR-INPUT
  per REO Rule 1.10.

**Test specifications**:
1. `it('reads findings from out/assessment-results.json and emits one row per finding in §5', ...)`.
2. `it('uses S / O status language verbatim from SP 800-53A Rev 5', ...)`.
3. `it('emits REQUIRES-OPERATOR-INPUT in §5 status column when no signoff exists for a finding', ...)`.
4. `it('refuses to emit conditional language in §2 (asserts §2 prose contains no "subject to" / "pending")', ...)`.
5. `it('cross-references POA&M items by uuid in §6 Non-Conforming Controls', ...)`.
6. `it('appendix table contains correct sha256 + relative path per artifact', ...)`.
7. `it('useAbsoluteUrls=true substitutes FEDRAMP_REPO_URL in appendix paths', ...)`.
8. `it('ready_for_signature is false until recommendation language present + all signoffs present', ...)`.
9. `it('emits section_counts.findings = AR findings.length', ...)`.
10. `it('the .docx is a valid OOXML zip (parts list contains document.xml + word/_rels/document.xml.rels)', ...)`.
11. `it('embeds the walk-through bundle hrefs from observation.relevant-evidence[]', ...)`.
12. `it('bundler well-known catalogue includes sar-draft.docx', ...)`.
13. `it('runs without throwing when individual sources (poam.json, signoffs.json) are absent, emitting REQUIRES-OPERATOR-INPUT in their place', ...)`.
14. `it('the recommendation in §2 cites the recommendation-letter.docx by filename + sha256', ...)`.
15. `it('the SAR draft does NOT auto-fill any signature cell', ...)`.

**REO compliance checks specific to this slice**:
- The draft never auto-signs (REO Rule 1.10).
- Every emitted count traces to a real on-disk artifact.
- Conditional-language guard enforced in §2.
- Every appendix pointer has a verifiable sha256 (computed at emit
  time from the on-disk file).
- When the orchestrator's chain integrity check (LOOP-A.A4) reports a
  missing artifact, the corresponding SAR appendix row emits
  REQUIRES-OPERATOR-INPUT instead of a silent fallback.

**Verification commands**:
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/sar-draft.test.ts
npm run check:reo
```

**Estimated effort**: 4 days.

---

## 5. Loop-wide acceptance criteria

When every slice in LOOP-F is complete, the following must all be
simultaneously true:

1. **Sign-off chain**: running the orchestrator with
   `--ingest-signoffs --ingest-comments --oscal-ar --oscal-poam
   --sampling-methodology --recommendation-letter --sar-draft
   --submission-bundle` produces a tarball containing all of:
   - `ap.json` with a `back-matter.resources[]` entry referencing
     `sampling-methodology.json`.
   - `assessment-results.json` whose `finding.target.status.state`
     fields flow from real signoff records (auditable via the
     `assessor-signoff-uuid` prop).
   - `assessment-results.json` whose findings have comments embedded
     as `remarks` and walk-through evidence linked through
     `observation.relevant-evidence`.
   - `assessor-signoffs.json` (tracker export).
   - `sampling-methodology.json` + `.md`.
   - `evidence-walkthrough/<finding-uuid>/...` files matching the
     bundler regex.
   - `recommendation-letter.docx` with the operator-chosen
     recommendation checkbox marked.
   - `sar-draft.docx` with §2 referencing the recommendation letter
     by sha256.
   - `ato-workflow-state.json` showing `PACKAGE_COMPLETE`.
2. **No auto-signatures**: `git grep` for "auto.*sign" /
   "auto.*signoff" / "synthetic.*signature" in
   `cloud-evidence/core/` + `cloud-evidence/tracker/server/` returns no
   matches in production paths.
3. **REO guardrails green**: `npm run lint:no-stubs`,
   `npm run check:provenance`, `npm run check:coverage-regression` all
   exit 0.
4. **Test count**: ~95 new tests across the 7 slices (see per-slice
   counts: F.F1=15, F.F2=14, F.F3=14, F.F4=13, F.F5=14, F.F6=13,
   F.F7=15). Total project test count rises from 874 to ≈ 972.
5. **Bundler catalogue**: 7 new well-known artifact entries shipped.
6. **REQUIRES-OPERATOR-INPUT markers**: when an operator runs the
   orchestrator with no tracker URL set and no operator config, the
   recommendation letter + SAR draft both emit `ready_for_signature=false`
   and each names every missing field.
7. **Documentation**: `cloud-evidence/docs/STATUS.md` reflects all
   seven slices as done; CHANGELOG "Unreleased" carries seven
   `### Added — LOOP-F.<slice>` entries.

---

## 6. Open questions / caveats

1. **Tracker scaffolding location**: This spec assumes
   `cloud-evidence/tracker/` is a sibling of `cloud-evidence/core/`
   created by LOOP-B.B3. If the tracker lands elsewhere (e.g. top-
   level `/tracker/`), every `cloud-evidence/tracker/...` path in §4
   shifts accordingly. Decision point: when the first LOOP-B slice
   ships, update this spec.
2. **OSCAL extension props**: This spec uses
   `ns: 'urn:fedramp:cloud-evidence'` for custom props
   (`assessor-signoff-uuid`, `comment-uuid`, `collector-derived-status`,
   `signoff-missing`, `redaction-applied`). If FedRAMP publishes an
   official OSCAL extension namespace for assessor sign-offs (RFC-0024
   is the current relevant RFC), every emitter should switch to that
   namespace AND ship a one-time migration utility for prior runs.
3. **15-minute comment edit window** (F.F2): chosen to match common
   GRC tool behavior (Jira, ServiceNow). FedRAMP does not publish a
   specific number. The window is configurable via env
   `CLOUD_EVIDENCE_COMMENT_EDIT_WINDOW_MS` if an authoring org needs a
   different value.
4. **Auto-progress exception in F.F6** (DRAFT → PACKAGE_COMPLETE):
   the lone automated state transition. The slice explicitly
   documents this exception (signed by the orchestrator's service key,
   traceable to the bundler artifact). If REO Rule 1.10 review
   considers this still too permissive, change the transition to
   require a one-click human confirmation in the tracker UI.
5. **Walk-through redaction depth** (F.F4): the regex pass catches
   common credential patterns (AKIA, password=, token=). It does NOT
   inspect file contents (PNG screenshots may contain visible
   credentials). Operator must visually review before upload. The
   slice tracks `redaction_applied` for command-string redaction only.
6. **PenTest Report Appendix F** (F.F7 §3.2 Appendix F): a pointer to
   LOOP-K.K1 output. Until LOOP-K.K1 ships, the appendix emits
   REQUIRES-OPERATOR-INPUT with a note pointing to the LOOP-K spec.
7. **Recommendation language final wording**: the three checkbox
   strings in F.F5 §4 are paraphrased from FedRAMP guidance, not
   quoted verbatim from a publicly-published template (the
   recommendation-letter template is not separately published; it's
   embedded in the SAR template). If FedRAMP publishes a standalone
   recommendation-letter template, the renderer must switch to its
   verbatim language.

---

## 7. Status tracking

| Slice ID | Status | Commit hash | Completed date |
|---|---|---|---|
| F.F1 — 3PAO sign-off UI in tracker | pending | — | — |
| F.F2 — Comment threads on findings | pending | — | — |
| F.F3 — Sample selection methodology auto-derive | pending | — | — |
| F.F4 — Evidence walk-through artifacts | pending | — | — |
| F.F5 — 3PAO recommendation letter template | pending | — | — |
| F.F6 — Full ATO workflow tracker (PM-10) | pending | — | — |
| F.F7 — SAR draft generator | pending | — | — |

---

## 8. Slice completion procedure (REO-enforced)

When a slice ships, the implementer MUST:

1. **Verify locally** (all three must exit zero):
   ```bash
   cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
   npm run typecheck
   npm test
   npm run check:reo
   ```
2. **Update Section 7** of this file: set `Status` to `done`,
   `Commit hash` to the short hash of the slice commit, and
   `Completed date` to the ISO date.
3. **Add a CHANGELOG.md "Unreleased" entry** at
   `/Users/kenith.philip/FedRAMP 20x/CHANGELOG.md` with header
   `### Added — LOOP-F.<slice-id>: <title>`. The entry must name
   every new module + test file path, summarize the real evidence
   path (which SDK / DB / file reads → which emitted artifact), and
   cite the verification counts (typecheck clean; N/N tests passing;
   `npm run check:reo` returns 0).
4. **Update `cloud-evidence/docs/STATUS.md`** to mark the slice done.
5. **Commit** with the canonical message format:
   ```
   LOOP-F.<slice-id>: <title>
   ```
   The commit body should mirror the CHANGELOG entry (use a HEREDOC
   to preserve formatting; include the
   `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`
   trailer per the repo's commit-format convention).
6. **Push to `origin/main`** (no force; no hook bypass; no
   `--no-verify`). If a pre-commit hook fails, fix the issue and
   create a NEW commit — do not amend (per the repo's git-safety
   protocol).
7. **If the slice introduced new emit fields**: confirm
   `npm run check:provenance` lists every new field in either an
   output document's `provenance` section or the coverage-source
   registry. The check will fail otherwise.

When all seven slices are `done`, LOOP-F is complete. Open a new
session, read `cloud-evidence/CLAUDE.md`, then
`cloud-evidence/docs/EXECUTION-PLAN.md`, then this file's Section 7,
then say `continue with LOOP-I.I1` (or the next priority slice per
the EXECUTION-PLAN priority ordering).
