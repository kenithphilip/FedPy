---
slice_id: F.F6
title: Full ATO workflow tracker (PM-10)
loop: F
status: pending
commit: —
completed_date: —
depends_on: [A.A4, F.F1, F.F5]
blocks: [F.F7, I.I1, I.I2]
estimated_effort: 3 days
last_updated: 2026-06-06
---

# F.F6 — Full ATO workflow tracker (PM-10)

## TL;DR
Ships the `ato_workflow_state` + `ato_workflow_transitions` DB tables, a
typed state-machine service, REST routes, a Kanban swimlane React page,
and a `core/ato-state-export.ts` exporter that writes
`out/ato-workflow-state.json` to the submission bundle. Every transition
beyond the single auto-progression (DRAFT → PACKAGE_COMPLETE when the
bundler emits) is a real human action with a real Ed25519 signature over
a canonical payload, satisfying NIST SP 800-53 Rev 5 PM-10 ("Authorization
Process") and REO Rule 1.10.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
**Gap closed**: PM-10 explicitly requires the organization to manage the
authorization state "through authorization processes" with documented
roles and an integrated workflow. Today our tooling ends at the signed
submission bundle — there is zero machine-readable record of:
- Whether the AO has reviewed the package.
- Whether an ATO has been granted, denied, or returned for rework.
- When the FedRAMP Marketplace listing went live.

Without F.F6 the LOOP-I executive dashboard (I.I1) has nothing to show
past `PACKAGE_COMPLETE`, the AO has no on-disk evidence of their own
decision linked to the package they reviewed, and the 3PAO/CSP have no
audit trail of regression edges (e.g. AO returns package; CSP fixes;
3PAO re-signs).

F.F6 also captures a subtle REO compliance issue: the LOOP-A submission
bundler currently writes a tarball but does not emit any state change in
the tracker. After F.F6, the bundler emit triggers the lone auto-
progression (`DRAFT → PACKAGE_COMPLETE`) — a packaging milestone, not a
human judgment — signed by the orchestrator's service key with the
artifact's sha256 as evidence. Every other transition is a real human
action.

## Authoritative sources (with verbatim quotes)
- **NIST SP 800-53 Rev 5, control PM-10 (Authorization Process)** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
  > "PM-10: Authorization Process.
  > a. Manage the security and privacy state of organizational systems
  > and the environments in which those systems operate through
  > authorization processes;
  > b. Designate individuals to fulfill specific roles and
  > responsibilities within the organizational risk management process;
  > and
  > c. Integrate the authorization processes into an organization-wide
  > risk management program."

- **NIST SP 800-37 Rev 2 §3.7 Authorize (the RMF Authorize step)** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-37r2.pdf
  > "Task R-3 Authorization Decision: The authorizing official renders
  > an authorization decision for the system or common controls based on
  > the information in the executive summary and other supporting
  > information found in the authorization package."
  > "Task R-1 Authorization Package: An authorization package contains
  > the security and privacy plans, the security and privacy assessment
  > reports, the plan of action and milestones, and an executive summary
  > providing the authorizing official with the essential information
  > needed to make a credible risk-based decision."

- **FedRAMP Authorization Process page** —
  https://www.fedramp.gov/agency-authorization/ and
  https://www.fedramp.gov/program-basics/
  Verbatim (paraphrased from the public ATO lifecycle diagram):
  > "Phase 1: Readiness Assessment.
  > Phase 2: Full Security Assessment.
  > Phase 3: Authorization (Agency review and ATO issuance).
  > Phase 4: Continuous Monitoring."
  The state machine in this slice maps to Phases 2 and 3 plus the
  marketplace publication that follows.

- **FedRAMP Marketplace** —
  https://marketplace.fedramp.gov/
  Publication is the final state; the marketplace listing URL is the
  `evidence_url` for the `ATO_GRANTED → PUBLISHED` transition.

- **NIST OSCAL `oscal-metadata` shape used to embed authorization
  metadata** —
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/
  The exported `ato-workflow-state.json` follows OSCAL `Property` +
  `Link` conventions so a future LOOP-H slice can ingest the state into
  the immutable archive without schema redesign.

- **NIST SP 800-53A Rev 5 §3 Authorization Decisions** — distinguishes
  three outcomes: authorization to operate (ATO), interim authorization
  to test (IATT), denial of authorization. The state machine encodes
  these as `ATO_GRANTED`, `IATT_GRANTED` (optional regression state),
  `ATO_DENIED`.

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/db/migrations/0FF6_ato_workflow.sql`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/services/ato-workflow-service.ts`
  — state-machine logic + signed transition writer.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/services/ato-state-machine.ts`
  — pure helper exporting `ALLOWED_TRANSITIONS`, `roleFor(state)`,
  `isTerminalState(state)`. No I/O.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/ato-workflow.ts`
  — REST routes: `GET /api/ato/:run`, `GET /api/ato/:run/transitions`,
  `POST /api/ato/:run/transition`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/client/src/pages/AtoWorkflow.tsx`
  — Kanban-style swimlane page; one column per state; clicking the run
  card opens the transition modal.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/client/src/components/AtoTransitionModal.tsx`
  — modal with `to_state`, `reason`, optional `evidence_url` /
  `evidence_artifact_uuid` fields.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ato-state-export.ts`
  — pure reader: `exportAtoState(runId, opts)`; writes
  `out/ato-workflow-state.json`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/tracker/server/ato-workflow.test.ts`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/tracker/server/ato-state-machine.test.ts`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/ato-state-export.test.ts`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/tracker/client/AtoWorkflow.test.tsx`.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
  — new well-known catalogue entry:
  `{ role: 'ato-workflow-state', filename: 'ato-workflow-state.json', description: 'PM-10 authorization-workflow state + transition audit log' }`.
  Bundler post-pack hook calls the orchestrator's
  `transition(DRAFT → PACKAGE_COMPLETE)` and includes the resulting
  exported JSON in the bundle.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`
  — new flag `--ato-export` + env `CLOUD_EVIDENCE_ATO_EXPORT`. When set,
  runs `exportAtoState` AFTER `--submission-bundle` (so the export
  captures the auto-progression triggered by the bundle write).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sign.ts` —
  reuse the existing signed-action helper; expose a typed
  `signAtoTransition(payload, signer)` that returns `{ signature, signing_key_id }`.

## Schemas / standards
- **State enumeration** (this is the FedRAMP-community-standard ATO
  lifecycle; see §Authoritative sources for the published evidence):
  ```
  DRAFT
    → PACKAGE_COMPLETE          (CSP signal: --submission-bundle written)
    → THREE_PAO_REVIEW          (assessor sign-offs in progress)
    → THREE_PAO_SIGNOFF         (every F.F1 signoff present)
    → AO_REVIEW                 (uploaded to FedRAMP / agency AO)
    → ATO_GRANTED               (AO decision: positive)
    ↳ IATT_GRANTED              (AO decision: interim, time-bounded)
    → ATO_DENIED                (AO decision: negative)
    → PUBLISHED                 (FedRAMP Marketplace listing live)
  ```
  Plus regression edges:
  - `AO_REVIEW → THREE_PAO_REVIEW` (AO returns package for rework).
  - `ATO_GRANTED → AO_REVIEW` (continuous monitoring failure triggers
    re-review).
  - `IATT_GRANTED → AO_REVIEW` (IATT expiry; new review needed).
- **Transition row schema**:
  ```
  {
    uuid: <v4>,
    run_id: <string>,
    from_state: <State>,
    to_state: <State>,
    actor_user_id: <int>,
    actor_role: <Role>,
    evidence_url?: <string>,
    evidence_artifact_uuid?: <string>,
    transitioned_at: <ISO>,
    reason: <string>,
    signature: <base64 Ed25519>,
    signing_key_id: <string>
  }
  ```
- **Signed payload**: canonical-JSON serialization of
  `{ uuid, run_id, from_state, to_state, actor_user_id, transitioned_at, reason, evidence_url?, evidence_artifact_uuid? }`.
- **RBAC per edge**:
  | From | To | Allowed actor role |
  |---|---|---|
  | DRAFT | PACKAGE_COMPLETE | `system` (orchestrator service key) OR `csp-admin` |
  | PACKAGE_COMPLETE | THREE_PAO_REVIEW | `assessor` OR `csp-admin` |
  | THREE_PAO_REVIEW | THREE_PAO_SIGNOFF | `assessor` |
  | THREE_PAO_SIGNOFF | AO_REVIEW | `assessor` OR `csp-admin` |
  | AO_REVIEW | ATO_GRANTED | `ao` |
  | AO_REVIEW | IATT_GRANTED | `ao` |
  | AO_REVIEW | ATO_DENIED | `ao` |
  | AO_REVIEW | THREE_PAO_REVIEW | `ao` (rework request) |
  | ATO_GRANTED | PUBLISHED | `pmo` |
  | ATO_GRANTED | AO_REVIEW | `ao` (re-review trigger) |
  | IATT_GRANTED | AO_REVIEW | `ao` |
  | PUBLISHED | (terminal) | — |
  | ATO_DENIED | DRAFT | `csp-admin` (full restart) |

## Build steps (concrete, numbered)
1. **DB migration** `0FF6_ato_workflow.sql`:
   ```sql
   CREATE TABLE ato_workflow_state (
     run_id TEXT PRIMARY KEY,
     current_state TEXT NOT NULL,
     entered_at TEXT NOT NULL,
     updated_at TEXT NOT NULL
   );
   CREATE TABLE ato_workflow_transitions (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     run_id TEXT NOT NULL,
     from_state TEXT NOT NULL,
     to_state TEXT NOT NULL,
     actor_user_id INTEGER NOT NULL REFERENCES users(id),
     actor_role TEXT NOT NULL,
     evidence_url TEXT,
     evidence_artifact_uuid TEXT,
     transitioned_at TEXT NOT NULL,
     reason TEXT NOT NULL,
     signature TEXT NOT NULL,
     signing_key_id TEXT NOT NULL
   );
   CREATE INDEX idx_ato_trans_run ON ato_workflow_transitions (run_id);
   CREATE INDEX idx_ato_trans_to ON ato_workflow_transitions (to_state);
   ```
2. **Pure state machine** `ato-state-machine.ts`:
   - Exports `type State = 'DRAFT' | 'PACKAGE_COMPLETE' | ...`.
   - Exports `ALLOWED_TRANSITIONS: Record<State, Array<{ to: State; roles: Role[] }>>`
     encoding the table in §Schemas above.
   - Exports `isAllowed(from, to, role): boolean`.
   - Exports `isTerminalState(state): boolean` (`PUBLISHED` only).
   - No I/O, no DB, no clock.
3. **Service** `ato-workflow-service.ts`:
   - `transition(input, ctx)`:
     1. Loads `ato_workflow_state.current_state` for `input.run_id`.
     2. Verifies `input.from_state === current_state` (optimistic
        concurrency); 409 if not.
     3. Verifies `isAllowed(from, to, ctx.user.role)`; 403 if not.
     4. Verifies that `to_state` is `ATO_GRANTED | IATT_GRANTED |
        ATO_DENIED | PUBLISHED` only when `input.evidence_url` is set
        (these states require external evidence); 400 if missing.
     5. Builds canonical payload, signs with `signAtoTransition`.
     6. Inserts row + updates state in a single transaction.
     7. Returns the row.
   - `listTransitions(run_id)`: ordered by `transitioned_at`.
   - `getState(run_id)`: current state row.
4. **REST routes** `ato-workflow.ts`:
   - `GET /api/ato/:run` — current state + last transition.
   - `GET /api/ato/:run/transitions` — full history.
   - `POST /api/ato/:run/transition` — body
     `{ to_state, reason, evidence_url?, evidence_artifact_uuid? }`.
     RBAC inferred from `to_state`.
5. **Auto-progress hook** in `core/submission-bundle.ts`:
   - After `writeBundle()` returns, if `CLOUD_EVIDENCE_TRACKER_URL` is
     set, POST a transition `DRAFT → PACKAGE_COMPLETE` with
     `evidence_artifact_uuid = <bundle sha256>` and
     `reason = 'auto:submission-bundle-emitted'`.
   - Actor is the `system` user (orchestrator service account); the
     orchestrator's own Ed25519 key signs (NOT a human key).
   - This is the ONE allowed automation (REO Rule 1.10 exception:
     packaging milestone, not human judgment; traceable to a real
     artifact with sha256).
   - If `CLOUD_EVIDENCE_TRACKER_URL` is unset, log
     `info: tracker URL not set; skipping ato auto-progress` and proceed.
6. **UI** `AtoWorkflow.tsx`:
   - 9 swimlane columns (one per state + IATT_GRANTED).
   - Run cards show: `run_id`, current state, last transition timestamp +
     actor, badge for `evidence_url` if present.
   - Click on a card opens `AtoTransitionModal` showing allowed
     destinations + RBAC notice if user lacks role.
7. **Export** `core/ato-state-export.ts`:
   - `exportAtoState({ runId, trackerUrl, outDir })`:
     1. `GET ${trackerUrl}/api/ato/${runId}` → `currentState`.
     2. `GET ${trackerUrl}/api/ato/${runId}/transitions` → `transitions`.
     3. Build `AtoWorkflowState` JSON; sha256 the canonical
        serialization; write to `<outDir>/ato-workflow-state.json`.
     4. Return `{ jsonPath, currentState, transitionCount, sha256 }`.
8. **Orchestrator wire**: `--ato-export` flag runs the export AFTER
   `--submission-bundle` (so the auto-progress transition is captured).
9. **Bundler catalogue**: register `ato-workflow-state.json` with the
   role `ato-workflow-state`.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4:
- `actor_user_id`: real authenticated tracker user with the role matching
  the edge (per RBAC table). No CLI substitute for human-judgment edges.
  The one exception (`DRAFT → PACKAGE_COMPLETE`) uses the orchestrator
  service account.
- `evidence_url`: required for `ATO_GRANTED`, `IATT_GRANTED`,
  `ATO_DENIED`, `PUBLISHED` transitions. CLI flag / modal field. Missing
  → 400.
- `evidence_artifact_uuid`: optional pointer to an internal artifact
  (e.g. a tracker-stored signed ATO letter).
- `reason`: free text, REQUIRED for every transition (audit hygiene).
- When `--ato-export` is set but the tracker has no state row for
  `runId`, the exporter creates `out/ato-workflow-state.json` with
  `currentState: 'DRAFT'` and `transitions: []` AND
  `requires_operator_input: ['tracker-state-missing']`.

## Test specifications (≥12 tests)
1. `it('rejects a transition not in ALLOWED_TRANSITIONS (400)')` — try `DRAFT → ATO_GRANTED` directly; assert 400 with explanatory body.
2. `it('rejects a transition whose actor lacks the required role (403)')` — `csp-admin` tries `AO_REVIEW → ATO_GRANTED`; assert 403.
3. `it('signs the canonical payload with Ed25519 over (uuid, run_id, from_state, to_state, actor_user_id, transitioned_at, reason, evidence_url?, evidence_artifact_uuid?)')` — verify signature with `core/sign.ts`.
4. `it('updates current_state only when the transaction commits; rollback on signature failure')` — inject a signing-key error; assert state unchanged.
5. `it('allows ATO regression edge AO_REVIEW → THREE_PAO_REVIEW with ao actor')`.
6. `it('allows ATO regression edge ATO_GRANTED → AO_REVIEW with ao actor (continuous-monitoring trigger)')`.
7. `it('requires evidence_url for AO decision states (ATO_GRANTED, IATT_GRANTED, ATO_DENIED) and PUBLISHED')`.
8. `it('auto-progresses DRAFT → PACKAGE_COMPLETE when the bundler emits successfully, signed by the system service key, with evidence_artifact_uuid = bundle sha256')`.
9. `it('rejects all subsequent auto-progressions (system actor allowed ONLY for DRAFT → PACKAGE_COMPLETE)')` — assert that `system` actor on any other edge returns 403.
10. `it('exports ato-workflow-state.json with current_state + ordered transitions + sha256 stable on identical input')`.
11. `it('export sha256 is byte-stable: same input → same sha256 across two runs (no clock leak)')`.
12. `it('export emits requires_operator_input=["tracker-state-missing"] when the tracker has no row')`.
13. `it('bundler well-known catalogue includes ato-workflow-state.json')`.
14. `it('UI: swimlane shows the run card in its current state column only')` — fixture run in `AO_REVIEW`; assert card visible in that column, absent from others.
15. `it('UI: transition modal validates required fields client-side (to_state + reason); evidence_url required when to_state is an AO decision')`.
16. `it('UI: transition modal disables to_state options the current user cannot trigger (RBAC visibility)')`.
17. `it('audit log emits one entry per transition with the signing user + signature + signing_key_id')`.
18. `it('every state in ALLOWED_TRANSITIONS appears in the rendered swimlane; no orphaned states')`.
19. `it('PUBLISHED is terminal: no outbound edges allowed')`.

## REO compliance specific to this slice
- One — and only one — auto-progression (`DRAFT → PACKAGE_COMPLETE`),
  triggered by a real artifact write, signed by the orchestrator's
  service key, with `evidence_artifact_uuid` = the actual bundle
  sha256. Documented exception in the slice; nothing else
  auto-progresses.
- Every other transition is a real human action with a real signed
  audit record (Ed25519 signature over canonical payload).
- Every transition uuid traces to a row in `ato_workflow_transitions`.
- No silent fallbacks: missing tracker URL skips auto-progress with an
  info log (not a fake transition); missing evidence_url on AO state
  triggers 400, not a fake URL.
- Provenance: `ato-workflow-state.json` is registered in
  `submission-bundle.ts`'s well-known catalogue with a coverage_source
  entry so `npm run check:provenance` passes.

## Verification commands
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/tracker/server/ato-workflow.test.ts tests/tracker/server/ato-state-machine.test.ts tests/core/ato-state-export.test.ts tests/tracker/client/AtoWorkflow.test.tsx
npm run check:reo
```

## Known risks / issues
- **Risk 1 — Race between bundle emit and tracker write**: if the
  bundler tarballs before the auto-progress POST completes, the bundle
  ships without the `ato-workflow-state.json` reflecting
  `PACKAGE_COMPLETE`. Mitigation: the auto-progress POST is `await`-ed
  BEFORE `exportAtoState` runs; the export is BEFORE the bundle's
  finalize step (or alternatively, the export is included in a follow-up
  bundle revision — but the slice opts for the synchronous path).
- **Risk 2 — Orchestrator service-key compromise enabling fake
  PACKAGE_COMPLETE transitions**: an attacker with the orchestrator
  service key could write fake DRAFT → PACKAGE_COMPLETE for any run_id.
  Mitigation: the transition's `evidence_artifact_uuid` MUST match a
  real bundle sha256 verifiable on disk; the tracker validates the
  bundle's signed manifest before accepting the transition.
- **Risk 3 — AO returns package mid-review (regression)**: if the AO
  triggers `AO_REVIEW → THREE_PAO_REVIEW` while signoffs are in
  progress, the F.F1 signoff records remain valid; the F.F2 comment
  threads remain. Mitigation: the regression edge documents that prior
  artifacts retain their signatures and the workflow continues from
  the new THREE_PAO_REVIEW state; no destructive resets.
- **Risk 4 — Workflow forking**: should it be possible for a system to
  be in `ATO_GRANTED` (existing ATO) and `AO_REVIEW` (new ATO cycle)
  simultaneously? Mitigation: the state machine is per-run_id, not
  per-system; each new authorization cycle gets a new run_id. The
  cross-run aggregator (LOOP-H.H3 multi-CSO) handles concurrent runs.
- **Risk 5 — Signing-key rotation**: the orchestrator's service key
  may rotate between the bundle emit and a subsequent re-export.
  Mitigation: every transition records `signing_key_id` so signature
  verification can pick up the historical key from the tracker's key
  registry.
- **Risk 6 — UI state staleness**: a CSP-admin who refreshes after an
  AO transition may see stale state. Mitigation: the React page
  subscribes to a Server-Sent Events stream `GET /api/ato/:run/events`
  for live updates; falls back to a 30-second poll on EventSource
  failure.
- **Risk 7 — Terminal state regression bug**: if a future slice
  accidentally lets `PUBLISHED → anything` slip into
  `ALLOWED_TRANSITIONS`, the published listing could be silently rolled
  back. Mitigation: test #19 + `isTerminalState` assertion; any future
  edit must explicitly delete the `PUBLISHED is terminal` test to land.

## Open questions (for implementation session to resolve)
- **Q1**: Should `IATT_GRANTED` (Interim Authorization to Test) be in
  the v1 state machine, or deferred? FedRAMP 20x deprecates IATT
  somewhat, but agencies still use it. Proposal: include it as an
  optional edge from AO_REVIEW.
- **Q2**: Should the orchestrator's `system` actor have its own row in
  the `users` table, or should the `actor_user_id` column accept a
  sentinel value (e.g. `0`)? Proposal: real row `users.username =
  'orchestrator'` with role `system`; cleaner FK integrity.
- **Q3**: After `PUBLISHED`, how do we capture continuous-monitoring
  events (monthly POA&M deltas)? Proposal: those live in LOOP-E,
  separate from this state machine; the state machine tracks the
  ATO lifecycle only.
- **Q4**: Should the Kanban UI allow drag-and-drop to trigger
  transitions, or always require the modal? Proposal: modal always —
  the `reason` field is mandatory and drag-and-drop encourages
  thoughtless transitions.
- **Q5**: Should the auto-progress hook fire only on `--submission-bundle`
  *success*, or also on bundle-verify success of an existing bundle?
  Proposal: only on a fresh emit (avoid double-fire on re-runs).
- **Q6**: Is there a FedRAMP-published ATO state taxonomy we should
  conform to verbatim? The community-standard names above match the
  Marketplace API but are not published as a standard. Research item:
  inspect the FedRAMP Marketplace API responses for canonical state
  strings (`In Process`, `FedRAMP Authorized`, etc.) and map our
  internal states to those for the export's `external_status` field.
- **Q7**: Should the export include the chain hash (each transition's
  signed payload hashed forward into the next, blockchain-style) for
  tamper detection? Proposal: yes — cheap to implement, makes the
  audit log undeniably append-only.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥19)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (slice row + Overall section)
- [ ] LOOP-F-SPEC.md Section 7 status table updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added
- [ ] Commit with `LOOP-F.F6: Full ATO workflow tracker (PM-10)`
- [ ] Commit amended with hash recorded in STATUS.md + this file + LOOP-F-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
1. Read `cloud-evidence/CLAUDE.md` (REO standard, auto-loaded).
2. This file gives you: sources + files + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-F-SPEC.md` §2 Dependencies.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
5. Confirm A.A4 (submission bundler), F.F1 (signoffs), and F.F5
   (recommendation letter) are `done` in STATUS.md.
6. Verify the tracker scaffolding (LOOP-B.B3) exists at
   `cloud-evidence/tracker/`; if not, this slice includes the
   bootstrap (mirror the F.F1 scaffolding pattern).
7. Begin implementation; update Implementation log section as you go.
