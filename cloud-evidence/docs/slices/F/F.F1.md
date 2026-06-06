---
slice_id: F.F1
title: 3PAO sign-off UI in tracker
loop: F
status: pending
commit: —
completed_date: —
depends_on: [A.A2, A.A3, B.B3]
blocks: [F.F2, F.F4, F.F6, F.F7, I.I1, K.K2]
estimated_effort: 4 days
last_updated: 2026-06-06
---

# F.F1 — 3PAO sign-off UI in tracker

## TL;DR
Ships the `assessor_signoffs` DB table, signed REST API, and React UI that
turn the per-control × per-determination-statement × per-method assessment
plan (from OSCAL AP) into real human-signed sign-off records. Without this
slice, the OSCAL AR's `finding.target.status.state` is auto-derived from
collector pass/fail (a REO Rule 1.10 violation); F.F1 captures the human
action and feeds it back into AR emission.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
**Gap closed**: OSCAL AR `finding.target.status.state` is an enum
(`satisfied` | `not-satisfied`) per
https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/json-reference/.
NIST SP 800-53A Rev 5 §2.3 + Appendix D mandate that this status is the
output of a human assessor's determination per control × determination-
statement × method (EXAMINE / INTERVIEW / TEST). Today the cloud-evidence
collector auto-derives the status from pass/fail signal — that is an
"Auto-generated assessor / 3PAO sign-off" per `CLAUDE.md` REO Rule 1.10
and would invalidate the AR.

The slice ships the *only* path by which `finding.target.status.state`
may be set from anything other than the bare collector signal: a signed,
audited, human-actioned row in `assessor_signoffs`.

## Authoritative sources (with verbatim quotes)
- **NIST OSCAL Assessment Results v1.1.2** —
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/json-reference/
  > "`finding/target/status/state` — An indication as to whether the
  > objective is satisfied or not. Possible values: `satisfied`,
  > `not-satisfied`."
- **NIST SP 800-53A Rev 5 §2.3** — Assessment procedures —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53Ar5.pdf
  > "Each assessment procedure consists of an assessment objective and
  > a set of potential assessment methods and assessment objects that
  > can be used to make the determination."
  >
  > "The findings produced by the application of the assessment
  > procedures are characterized as either satisfied (S) or other than
  > satisfied (O)."
- **NIST SP 800-53A Rev 5 Appendix D — Assessment Method Descriptions** —
  > "EXAMINE: The process of reviewing, inspecting, observing, studying,
  > or analyzing one or more assessment objects (i.e., specifications,
  > mechanisms, or activities)."
  >
  > "INTERVIEW: The process of holding discussions with individuals or
  > groups of individuals to facilitate understanding, achieve
  > clarification, or obtain evidence."
  >
  > "TEST: The process of exercising one or more assessment objects
  > (i.e., activities or mechanisms) under specified conditions to
  > compare actual with expected behavior."
- **NIST Glossary — assessment method** —
  https://csrc.nist.gov/glossary/term/assessment_method
  > "One of three types of actions (i.e., examine, interview, test)
  > taken by assessors in obtaining evidence during an assessment."
- **FedRAMP 3PAO Readiness Assessment Report Guide v3.2** —
  https://www.fedramp.gov/assets/resources/documents/3PAO_Readiness_Assessment_Report_Guide.pdf
  > "3PAOs should directly and clearly answer RAR requirements and
  > questions, stating what they found (observations and evidence)
  > during their review and HOW they came about determining if a CSP
  > adequately addresses the question area."

## Files to create (exact paths)
- `cloud-evidence/tracker/server/db/migrations/0FF1_assessor_signoffs.sql`
  — DDL for `assessor_signoffs` table + indices.
- `cloud-evidence/tracker/server/routes/assessor-signoffs.ts` — Express
  REST routes: `GET /api/signoffs?run=<id>`, `POST /api/signoffs`,
  `POST /api/signoffs/:uuid/revoke`.
- `cloud-evidence/tracker/server/services/signoff-service.ts` — pure
  business logic (`createSignoff`, `listSignoffs`, `revokeSignoff`).
  Imports `cloud-evidence/core/sign.ts` for the Ed25519 signature.
- `cloud-evidence/tracker/client/src/pages/AssessorSignoffs.tsx` — React
  page rendering control × determination-statement × method rows.
- `cloud-evidence/tracker/client/src/components/SignoffRow.tsx` — row
  with state badge (unsigned / signed / revoked / superseded).
- `cloud-evidence/core/signoff-ingest.ts` — pure reader that pulls the
  tracker signoff records (over HTTP) and returns a normalized
  `SignoffRecord[]` for AR emission to consume.
- `cloud-evidence/tests/core/signoff-ingest.test.ts` — unit tests for
  the ingest reader (≥4 tests).
- `cloud-evidence/tests/tracker/server/assessor-signoffs.test.ts` — API
  + DB integration tests (≥8 tests).
- `cloud-evidence/tests/tracker/client/AssessorSignoffs.test.tsx` —
  Vitest + React Testing Library UI tests (≥3 tests).

## Files to extend
- `cloud-evidence/core/oscal.ts` — `OscalEmitOptions` gains
  `signoffSource?: SignoffRecord[]`. When supplied, AR
  `result.findings[].target.status.state` flows from the matching
  signoff record (`control-id + statement-id + method`). The original
  collector-derived value is preserved as a `props[]` entry
  `{ name: 'collector-derived-status', ns: 'urn:fedramp:cloud-evidence', value: '...' }`.
- `cloud-evidence/core/orchestrator.ts` — new flag
  `--ingest-signoffs[=<tracker-url>]` + env
  `CLOUD_EVIDENCE_TRACKER_URL`. When set, the orchestrator calls
  `loadSignoffsFromTracker(url, runId)` from `signoff-ingest.ts` before
  emitting the AR.
- `cloud-evidence/core/submission-bundle.ts` — new well-known artifact
  role `assessor-signoffs-export` with filename
  `assessor-signoffs.json` (the tracker's signed export of every signoff
  record, included verbatim in the bundle).

## Schemas / standards
- **OSCAL AR `finding.target.status.state`** — enum {`satisfied`,
  `not-satisfied`} per the json-reference URL above.
- **NIST SP 800-53A Rev 5 procedure object**: assessment-objective →
  determination-statement → method (EXAMINE / INTERVIEW / TEST) →
  object. Each `(control-id, statement-id, method)` tuple gets exactly
  one *active* (non-revoked) signoff row.
- **Ed25519 signature format**: 64-byte raw signature, base64-encoded
  in the DB record. Signed payload = canonical-JSON serialization of
  `{ run_id, control_id, statement_id, method, decision,
    assessor_user_id, signed_at }`. Reuse `core/sign.ts`'s canonical-
  json + `signEd25519()`.
- **Tracker API auth**: bearer token `CLOUD_EVIDENCE_TRACKER_TOKEN` env;
  rejects requests without it (HTTP 401).

## Build steps (concrete, numbered)
1. **DB migration** `0FF1_assessor_signoffs.sql`:
   ```sql
   CREATE TABLE assessor_signoffs (
     uuid TEXT PRIMARY KEY,
     run_id TEXT NOT NULL,
     control_id TEXT NOT NULL,          -- e.g. "ac-2"
     statement_id TEXT NOT NULL,        -- e.g. "ac-2_smt.a"
     method TEXT NOT NULL CHECK (method IN ('EXAMINE','INTERVIEW','TEST')),
     decision TEXT NOT NULL CHECK (decision IN ('satisfied','not-satisfied')),
     assessor_user_id INTEGER NOT NULL REFERENCES users(id),
     comments TEXT,
     signed_at TEXT NOT NULL,           -- ISO-8601
     signature TEXT NOT NULL,           -- base64 Ed25519
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
   builds canonical JSON, signs via `core/sign.ts`'s holder key, inserts
   the row, returns the record. Throws `ForbiddenError` if
   `ctx.user.role !== 'assessor'`. Throws `Conflict` if a non-revoked
   row already exists for `(run_id, control_id, statement_id, method)`.
3. **REST routes** in `assessor-signoffs.ts`:
   - `GET /api/signoffs?run=<id>` — list signoffs for a run.
   - `POST /api/signoffs` — body
     `{ control_id, statement_id, method, decision, comments? }`.
     RBAC: `assessor` role required (reuse the LOOP-B.B3-style RBAC
     middleware).
   - `POST /api/signoffs/:uuid/revoke` — body `{ reason }`. Signs the
     revoke action with the revoker's holder key.
4. **UI page** `AssessorSignoffs.tsx`:
   - Fetches `out/ap.json` via the tracker proxy.
   - Renders one row per `(control × determination-statement × method)`
     from `ap.reviewed-controls.control-selections` ×
     `ap.local-definitions.assessment-methods` (filtered by the AP's
     `included-controls` set).
   - Each row shows: control id, statement, method, current status
     badge (unsigned / signed / revoked / superseded), assessor name +
     time, sign / revoke buttons.
   - Sign posts to `POST /api/signoffs` and refreshes the row.
5. **Ingest** in `signoff-ingest.ts`:
   - `loadSignoffsFromTracker(url, runId): Promise<SignoffRecord[]>`
     calls `GET ${url}/api/signoffs?run=${runId}` with the token from
     env. Validates response shape against an ajv schema (registered
     in `core/oscal-validate.ts` style). Returns only the active rows.
6. **Wire into orchestrator**:
   - Flag `--ingest-signoffs` (with optional `=<url>` override).
   - Env `CLOUD_EVIDENCE_TRACKER_URL`, `CLOUD_EVIDENCE_TRACKER_TOKEN`.
   - When set, fetch the signoffs and pass them via
     `OscalEmitOptions.signoffSource` to `emitOscalAR()`.
7. **Extend `core/oscal.ts`**: for each `finding.target` whose
   `target-id` matches a `(control_id, statement_id, method)` signoff,
   set `status.state` from the signoff's `decision`; add a `props[]`
   entry
   `{ name: 'assessor-signoff-uuid', ns: 'urn:fedramp:cloud-evidence', value: signoff.uuid }`
   and preserve the original collector-derived status under
   `{ name: 'collector-derived-status', ns: 'urn:fedramp:cloud-evidence', value: <orig> }`.
8. **Bundler well-known catalogue**: append
   `{ role: 'assessor-signoffs-export', filename: 'assessor-signoffs.json', description: 'Tracker-exported signed signoff records for the run' }`
   to `WELL_KNOWN` in `submission-bundle.ts`.
9. **Validation pass**: AR validates against
   `core/oscal-validate.ts`'s ajv schema (already required for AR
   emission; the new `props[]` entries do not break the schema).
10. **Sign+timestamp**: AR continues to be signed + RFC 3161
    timestamped by the existing `core/sign.ts` + `core/timestamp.ts`
    pipeline. The individual signoff signatures are *separate*
    Ed25519 signatures over the canonical signoff payload and live
    in the DB.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4 (`CLAUDE.md`):
- **`assessor_user_id`** — source: tracker session. The signed-in user
  must hold the `assessor` role. No CLI / config substitute is
  permitted (REO Rule 1.10). Missing → HTTP 401 / 403.
- **`signing_key_id`** — source: the assessor's Ed25519 holder key
  registered in the tracker. If no key is registered, the API returns
  `409 Conflict` with body
  `{ error: 'REQUIRES-OPERATOR-INPUT', field: 'assessor.signing_key' }`.
- **`comments`** — optional; free text.
- **`decision`** — required body field; enum {`satisfied`,
  `not-satisfied`}.
- When `--ingest-signoffs` is set but the tracker returns zero
  signoffs for a `(control × statement × method)` the AR will emit,
  the AR emitter logs a `coverage:miss` line AND `target.status.state`
  falls back to the collector-derived value PLUS a `props[]` entry
  `{ name: 'signoff-missing', value: 'REQUIRES-OPERATOR-INPUT' }`.

## Test specifications (≥15 tests)
1. `it('createSignoff inserts a row with a valid Ed25519 signature over the canonical payload')` — assert row in DB; assert signature verifies via `core/sign.ts`.
2. `it('createSignoff throws ForbiddenError when user lacks assessor role')` — pass a `reviewer` user, assert throw.
3. `it('createSignoff is idempotent on (run_id, control_id, statement_id, method) when a non-revoked row already exists')` — second call throws `Conflict`.
4. `it('revokeSignoff sets revoked_at + revoked_by_user_id and the row no longer appears in listSignoffs(activeOnly=true)')`.
5. `it('listSignoffs filters by run_id and excludes revoked rows by default')`.
6. `it('POST /api/signoffs returns 401 without auth, 403 without assessor role, 200 with valid input')`.
7. `it('POST /api/signoffs rejects method values not in {EXAMINE, INTERVIEW, TEST}')`.
8. `it('POST /api/signoffs rejects decision values not in {satisfied, not-satisfied}')`.
9. `it('loadSignoffsFromTracker rejects responses missing required fields via ajv')`.
10. `it('AR emit applies signoff status when a matching record exists')` — seed `decision=not-satisfied`, assert `finding.target.status.state === 'not-satisfied'`.
11. `it('AR emit preserves the collector-derived status under props.collector-derived-status')`.
12. `it('AR emit emits coverage:miss when a control × statement × method has no signoff')`.
13. `it('UI: AssessorSignoffs page renders one row per (control × statement × method) from ap.json')`.
14. `it('UI: sign button is disabled when current user lacks assessor role')`.
15. `it('bundler well-known catalogue includes assessor-signoffs.json with role assessor-signoffs-export')`.

## REO compliance specific to this slice
- Every emitted `assessor-signoff-uuid` prop traces to a row in
  `assessor_signoffs` created by a real human action recorded in the
  tracker audit log.
- No silent fallbacks: if `--ingest-signoffs` is set but the tracker
  returns nothing for a `(control × statement × method)`, the AR emits
  `signoff-missing: REQUIRES-OPERATOR-INPUT` AND the run log records
  `coverage:miss`.
- No auto-signing: the orchestrator NEVER inserts a row into
  `assessor_signoffs` directly. The tracker REST API + UI is the only
  path. (REO Rule 1.10.)
- Ed25519 signatures are real (delegated to `core/sign.ts`); no
  signature stubs in production paths.
- Provenance: every AR finding now carries `assessor-signoff-uuid` (or
  `signoff-missing` marker) in `props[]`; `npm run check:provenance`
  passes because the field has a real provenance source.
- Signed by: existing `core/sign.ts` pipeline (Ed25519 + RFC 3161) for
  the AR; individual signoff signatures stored in the DB row.

## Verification commands
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/signoff-ingest.test.ts tests/tracker/server/assessor-signoffs.test.ts tests/tracker/client/AssessorSignoffs.test.tsx
npm run check:reo
```

## Known risks / issues
- **Risk 1 — tracker scaffolding may not exist yet**: LOOP-B.B3 is the
  first slice to create `tracker/server/` + `tracker/client/`. If
  LOOP-B.B3 has not landed, F.F1 must bootstrap the tracker scaffold
  (express server skeleton, sqlite client, RBAC middleware, React
  client with router). Mitigation: scope-out the bootstrap as a
  prerequisite check at the top of the slice; if LOOP-B.B3 is
  pending, ship the scaffold as part of F.F1 with a CHANGELOG note
  ("bootstrap-only — LOOP-B.B3 will extend it").
- **Risk 2 — AP `assessment-methods` may not enumerate every
  `(control × statement × method)` tuple**: OSCAL AP allows method
  selection at multiple granularities. If the AP groups methods at
  the control level only, the UI may render too few rows.
  Mitigation: when expanding the Cartesian product, fall back to the
  control-level method set (default `['EXAMINE']` per
  SP 800-53A baseline) and emit a `coverage:miss` for any statement
  the AP did not explicitly enumerate.
- **Risk 3 — Ed25519 holder-key registration UX**: assessors must
  register their public key in the tracker before signing. If the
  registration flow is unclear, signoffs may fail at 409. Mitigation:
  the `409 REQUIRES-OPERATOR-INPUT` error body must include a
  `register_key_url` hint that links to the tracker's key-management
  page (see LOOP-B.B3 for the assumed page).
- **Risk 4 — race condition on idempotency check**: two assessors
  posting the same `(control × statement × method)` simultaneously
  could both succeed. Mitigation: enforce uniqueness with the
  `UNIQUE (run_id, control_id, statement_id, method, revoked_at)`
  partial index; the second writer hits a SQLite UNIQUE violation,
  the service catches it and returns 409.
- **Risk 5 — AR emitter compatibility with downstream consumers**:
  some consumers may not understand the custom
  `urn:fedramp:cloud-evidence` namespace. Mitigation: the AR remains
  schema-valid (custom props are allowed); downstream consumers see
  the canonical `status.state` and ignore unknown props.

## Open questions (for implementation session to resolve)
- **Q1**: Does the tracker scaffolding (LOOP-B.B3) ship before F.F1?
  If not, who owns the bootstrap and what is the minimum scope?
- **Q2**: How should the UI handle revocation when a downstream
  signoff (later method on the same control) was signed AFTER the
  revoked one? Linear chain or DAG?
- **Q3**: Should the AR's `props[]` carry the assessor's name + key id
  (for SAR readability), or only the signoff UUID (for privacy)?
- **Q4**: The OSCAL AP from LOOP-A.A2 may emit methods only at the
  control level; should F.F1 fan out to statements based on the
  catalog (NIST SP 800-53A Rev 5 procedures Excel) or trust the AP?
- **Q5**: If a finding has multiple methods (EXAMINE + TEST) and the
  signoffs disagree (one satisfied, one not-satisfied), what is the
  AR `finding.target.status.state`? Most-conservative wins
  (any not-satisfied → not-satisfied) is the proposed rule; confirm
  with FedRAMP PMO.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥15 for this slice's new tests)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (slice row + Overall section)
- [ ] LOOP-F-SPEC.md Section 7 status table updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added
- [ ] Commit with slice ID in message (`LOOP-F.F1: 3PAO sign-off UI in tracker`)
- [ ] Commit amended with commit hash recorded in STATUS.md + this file + LOOP-F-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context, here is everything it
needs to start:
1. Read `cloud-evidence/CLAUDE.md` (REO standard, auto-loaded).
2. This file gives you: source obligations + files to create + build
   steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-F-SPEC.md` §2 Dependencies for
   loop-wide context (Tracker scaffolding may not exist yet; this
   slice bootstraps it).
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the
   mandatory commit pattern.
5. If the tracker `tracker/server/` and `tracker/client/` directories
   do not yet exist, check `cloud-evidence/docs/loops/LOOP-B-SPEC.md`
   for the bootstrap scope (B.B3) — F.F1 may need to ship the
   bootstrap inline.
6. Begin implementation; update Implementation log section as you go.
