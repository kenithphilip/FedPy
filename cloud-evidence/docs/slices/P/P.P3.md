---
slice_id: P.P3
title: Personnel transfer + termination procedures (PS-4 + PS-5)
loop: P
status: pending
commit: —
completed_date: —
depends_on: [LOOP-A.A1, P.P2]
blocks: [P.P5, E.E1]
estimated_effort: 5-6 working days
last_updated: 2026-06-07
applicable_conditional: false
---

# P.P3 — Personnel transfer + termination procedures (PS-4 + PS-5)

## TL;DR
Add a signed lifecycle-event tracker workflow for NIST 800-53 Rev5
PS-4 (Personnel Termination) + PS-5 (Personnel Transfer). New tracker
table `personnel_lifecycle_events` plus an SLA enforcer that cross-checks
the org-defined PS-4 time window against `providers/*/iam.ts` observed
IAM-principal disable timestamps. New pure builder `core/personnel-
lifecycle.ts` + emitter `core/personnel-lifecycle-emit.ts` correlate
events with IAM-SUS output; SLA breaches emit `psFindingKind:'ps-4-breached'`
Findings flowing into the OSCAL POA&M; transfers without role-baseline
delta emit `psFindingKind:'ps-5-access-not-rebaselined'`. PS-8
(Personnel Sanctions) is absorbed as `event_type='sanction-imposed'`
in this table (no separate slice).

## Status
- Status: pending
- Commit: — (filled when shipped per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
P.P3 is the bridge between HR signals (tracker) and cloud reality
(`providers/aws/iam.ts`, `providers/gcp/iam.ts`, `providers/azure/iam.ts`).
The orchestrator-side reader reads the lifecycle events, then reads the
existing IAM-SUS snapshot, then asserts the IAM principal was in fact
disabled within the org-defined PS-4 time window. Mismatches become OSCAL
POA&M items tied to PS-4 in `related-observations`. Transfers join
LOOP-J.J1 roles matrix deltas: a transferred user whose AC-2 role
membership did not change post-effective-date emits PS-5 Findings. The
new `personnel-lifecycle-snapshot` role in `core/submission-bundle.ts`
makes the snapshot a first-class submission artifact. `core/notify.ts`
fires `termination-recorded` on every tracker POST so on-call IT teams
get a real-time signal of a fresh termination requiring action.

## Why this slice exists
NIST SP 800-53 Rev5 PS-4 ("Upon termination of individual employment …
disable system access within [Assignment: organization-defined time
period]; terminate or revoke any authenticators and credentials …
conduct exit interviews … retrieve all security-related organizational
system-related property; retain access to organizational information …")
+ PS-5 ("Review and confirm ongoing operational need for current
logical and physical access authorizations to systems and facilities
when individuals are reassigned or transferred …") are FedRAMP Moderate
baseline controls. Both demand structured, signed lifecycle events with
SLA evidence — today FedPy has none. P.P3 ships the tracker workflow +
the SLA cross-check against observed IAM disable times, closing the gap.

## Authoritative sources (with verbatim quotes)

- **NIST SP 800-53 Rev5 — PS-4 (Personnel Termination)** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
  Verbatim:
  > "Upon termination of individual employment:
  > a. Disable system access within [Assignment: organization-defined
  > time period];
  > b. Terminate or revoke any authenticators and credentials associated
  > with the individual;
  > c. Conduct exit interviews that include [Assignment: organization-
  > defined topics];
  > d. Retrieve all security-related organizational system-related
  > property; and
  > e. Retain access to organizational information and systems formerly
  > controlled by the terminated individual."

- **NIST SP 800-53 Rev5 — PS-5 (Personnel Transfer)** — verbatim:
  > "a. Review and confirm ongoing operational need for current logical
  > and physical access authorizations to systems and facilities when
  > individuals are reassigned or transferred to other positions within
  > the organization;
  > b. Initiate [Assignment: organization-defined transfer or
  > reassignment actions] within [Assignment: organization-defined time
  > period following the formal transfer action];
  > c. Modify access authorization as needed to correspond with any
  > changes in operational need due to reassignment or transfer; and
  > d. Notify [Assignment: organization-defined personnel or roles]
  > within [Assignment: organization-defined time period]."

- **NIST SP 800-53 Rev5 — PS-8 (Personnel Sanctions)** — verbatim:
  > "a. Employ a formal sanctions process for individuals failing to
  > comply with established information security and privacy policies
  > and procedures; and
  > b. Notify [Assignment: organization-defined personnel or roles]
  > within [Assignment: organization-defined time period] when a formal
  > employee sanctions process is initiated, identifying the individual
  > sanctioned and the reason for the sanction."

  Modelled as `event_type='sanction-imposed'` in the lifecycle table.

- **FedRAMP Rev5 SSP Template — PS-4 / PS-5 implementation guidance**:
  the SSP renderer in LOOP-A.A1 consumes the OSCAL implementation
  statements P.P3 emits.

- **OSCAL POA&M v1.1.2 — `risk.props[]`** —
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/plan-of-action-and-milestones/json-reference/
  Extension props: `ps-finding-kind`, `lifecycle-event-uuid`,
  `iam-principal-id`, `effective-at`, `iam-observed-disabled-at`,
  `sla-deadline`.

## Files to create (exact paths under cloud-evidence/)

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/personnel-lifecycle.ts`
  — pure builder. Reads tracker `personnel_lifecycle_events` snapshot +
  IAM-SUS inventory snapshot; emits `Finding[]`. No IO.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/personnel-lifecycle-emit.ts`
  — disk-side emitter + orchestrator entry point. Writes
  `out/.personnel-lifecycle-snapshot.json` + appends Findings to the
  existing `out/KSI-PIY-PSE.json` envelope (does NOT create a new
  envelope; PSE is the shared workforce-evidence KSI).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/personnel-lifecycle.ts`
  — Express CRUD routes.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/lifecycle-sla-enforcer.ts`
  — periodic task (every 5 minutes) that checks each pending termination
  for SLA breach vs IAM-SUS observed-disable time.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/PersonnelLifecycle.tsx`
  — Lifecycle event log UI with signed-checklist for terminations
  (5 PS-4 checkboxes a-e).
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/PersonnelLifecycleDetail.tsx`
  — per-event signed audit record view.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/personnel-lifecycle.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/personnel-lifecycle-emit.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/personnel-lifecycle.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/lifecycle-sla-enforcer.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/PersonnelLifecycle.test.tsx`

## Files to extend

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` —
  new `--personnel-lifecycle` flag + env `CLOUD_EVIDENCE_PERSONNEL_LIFECYCLE`.
  Runs AFTER providers collect (so IAM-SUS data is fresh), BEFORE POA&M.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/notify.ts` —
  fire `termination-recorded` on tracker POST `/api/personnel-lifecycle`
  (terminations); fire `ps-4-sla-breach` on enforcer transition; fire
  `transfer-recorded` on PS-5 events.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-ssp.ts` —
  PS-4 + PS-5 + PS-8 implementation statements reference the
  signed-termination-checklist procedure; populate
  `implementation-statement.description` with templated narrative +
  cite operator policy time window.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-poam.ts` —
  in `findingProps()`, append PS-4 / PS-5 specific props when
  `psFindingKind` is set.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
  — add role `personnel-lifecycle-snapshot` (filename
  `.personnel-lifecycle-snapshot.json`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/config/workforce-policy.example.yaml`
  — add `ps4_time_period_hours` (default 24), `ps5_transfer_time_period_hours`
  (default 72), `ps8_notification_time_period_hours` (default 8).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/schema.sql` — one new
  table.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/index.ts` — mount
  route with `requireRole(['hr','iso','ao','it'])`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/rbac.ts` — add `it`
  role (used by IT staff who attest credential revocation).
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/App.tsx` — add
  `/personnel-lifecycle` and `/personnel-lifecycle/:uuid` routes.

## Schemas / standards

- **NIST 800-53 Rev5 PS-4 + PS-5 + PS-8** — verbatim above.
- **OSCAL POA&M v1.1.2** — JSON-reference URL +
  `related-observations[].subjects[]` for IAM-principal cite.
- **IAM-SUS inventory contract** — `inventory.assets[]` where
  `asset_type` matches `(aws|gcp|azure):iam-user` carries
  `attributes.user_arn`, `attributes.last_used_at`, `attributes.status`
  (`enabled` | `disabled`), `attributes.disabled_at` (ISO).

## Build steps (concrete, numbered)

1. **Tracker schema** (idempotent additive DDL):
   ```sql
   CREATE TABLE IF NOT EXISTS personnel_lifecycle_events (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     event_type TEXT NOT NULL CHECK (event_type IN ('termination-voluntary','termination-involuntary','transfer-internal','transfer-promotion','transfer-demotion','contractor-end','sanction-imposed')),
     user_id INTEGER NOT NULL REFERENCES users(id),
     prior_position_uuid TEXT NOT NULL,        -- references personnel_positions
     new_position_uuid TEXT,                   -- null for terminations + sanctions
     effective_at TEXT NOT NULL,               -- when termination/transfer took effect (HR-recorded)
     access_revoked_at TEXT,                   -- when IT confirmed access revocation (PS-4 a)
     authenticators_revoked_at TEXT,           -- PS-4 b
     credentials_recovered_at TEXT,            -- PS-4 b
     exit_interview_completed_at TEXT,         -- PS-4 c
     property_returned_at TEXT,                -- PS-4 d
     information_retention_attested_at TEXT,   -- PS-4 e
     org_defined_time_period_hours INTEGER NOT NULL,  -- from workforce-policy.yaml
     sla_status TEXT NOT NULL CHECK (sla_status IN ('within-sla','breached','pending')) DEFAULT 'pending',
     iam_observed_disabled_at TEXT,            -- from IAM-SUS correlation
     processed_by_user_id INTEGER NOT NULL REFERENCES users(id),
     processed_at TEXT NOT NULL,
     signature TEXT NOT NULL,
     signing_key_id TEXT NOT NULL,
     CHECK (event_type LIKE 'termination%' OR event_type = 'sanction-imposed' OR (new_position_uuid IS NOT NULL))
   );
   CREATE INDEX IF NOT EXISTS idx_lifecycle_user ON personnel_lifecycle_events(user_id);
   CREATE INDEX IF NOT EXISTS idx_lifecycle_effective ON personnel_lifecycle_events(effective_at);
   CREATE INDEX IF NOT EXISTS idx_lifecycle_sla ON personnel_lifecycle_events(sla_status);
   ```

2. **SLA enforcer** (`tracker/server/lifecycle-sla-enforcer.ts`):
   ```ts
   export function runEnforcer(db: Database): EnforcerResult {
     const pending = db.prepare(`
       SELECT * FROM personnel_lifecycle_events
       WHERE event_type LIKE 'termination%' AND sla_status = 'pending'
     `).all();
     const transitions: Transition[] = [];
     for (const row of pending) {
       const slaDeadline = new Date(new Date(row.effective_at).getTime() +
         row.org_defined_time_period_hours * 3600 * 1000);
       const observed = row.iam_observed_disabled_at
         ? new Date(row.iam_observed_disabled_at)
         : null;
       if (observed && observed <= slaDeadline) {
         db.prepare(`UPDATE personnel_lifecycle_events SET sla_status='within-sla' WHERE id=?`).run(row.id);
         transitions.push({ uuid: row.uuid, from: 'pending', to: 'within-sla' });
       } else if (new Date() > slaDeadline) {
         db.prepare(`UPDATE personnel_lifecycle_events SET sla_status='breached' WHERE id=?`).run(row.id);
         auditLog.write({ event: 'ps-4-sla-breach', uuid: row.uuid, at: new Date().toISOString() });
         transitions.push({ uuid: row.uuid, from: 'pending', to: 'breached' });
         notify('ps-4-sla-breach', { uuid: row.uuid });
       }
     }
     return { transitions };
   }
   ```

3. **Reader** (`core/personnel-lifecycle.ts`):
   - Pulls events snapshot via `core/tracker-pull.ts`.
   - Pulls inventory `inventory.json` for IAM principals (existing
     `core/inventory-load.ts`).
   - For each termination:
     - Match IAM principal by `user.cloud_identity_arn`.
     - Assert `iam_principal.status === 'disabled'` AND
       `iam_principal.disabled_at <= effective_at + org_defined_time_period_hours`.
     - Mismatch → Finding `psFindingKind: 'ps-4-breached'`.
     - Five-checkbox checklist (PS-4 a-e): each must be set; missing
       any → Finding `psFindingKind: 'ps-4-checklist-incomplete'`
       (severity `medium`).
   - For each transfer:
     - Read LOOP-J.J1 roles matrix snapshot for the user before and
       after `effective_at`.
     - Assert prior AC-2 role membership removed + new role membership
       added.
     - Mismatch → Finding `psFindingKind: 'ps-5-access-not-rebaselined'`.
   - For each `sanction-imposed`:
     - Assert `processed_at - effective_at <= ps8_notification_time_period_hours`.
     - Mismatch → Finding `psFindingKind: 'ps-8-notification-late'`.

4. **Disk emitter** (`core/personnel-lifecycle-emit.ts`):
   ```ts
   export interface LifecycleEmitOptions { outDir: string; inventoryPath: string; workforcePolicyPath?: string; runId: string; }
   export interface LifecycleEmitResult { snapshotPath: string; findings_emitted: number; sla_breaches: number; transfers_unrebaselined: number; }
   export function emitPersonnelLifecycle(opts: LifecycleEmitOptions): Promise<LifecycleEmitResult>;
   ```
   Writes `out/.personnel-lifecycle-snapshot.json` with provenance block;
   appends Findings to `out/KSI-PIY-PSE.json` envelope.

5. **SSP integration** (`core/oscal-ssp.ts`): PS-4 + PS-5 + PS-8
   implementation statements describe the tracker-driven workflow + cite
   operator policy time window (e.g. "PS-4 disable-window: 24h per
   `config/workforce-policy.yaml`").

6. **POA&M integration** (`core/oscal-poam.ts`): in `findingProps()`,
   when `f.gap.psFindingKind` is set, append:
   ```ts
   props.push({ name: 'ps-finding-kind', ns: CE_NS, value: f.gap.psFindingKind });
   if (f.gap.lifecycle_event_uuid) props.push({ name: 'lifecycle-event-uuid', ns: CE_NS, value: f.gap.lifecycle_event_uuid });
   if (f.gap.iam_principal_id) props.push({ name: 'iam-principal-id', ns: CE_NS, value: f.gap.iam_principal_id });
   if (f.gap.effective_at) props.push({ name: 'effective-at', ns: CE_NS, value: f.gap.effective_at });
   if (f.gap.iam_observed_disabled_at) props.push({ name: 'iam-observed-disabled-at', ns: CE_NS, value: f.gap.iam_observed_disabled_at });
   if (f.gap.sla_deadline) props.push({ name: 'sla-deadline', ns: CE_NS, value: f.gap.sla_deadline });
   ```

7. **Orchestrator wiring**: `--personnel-lifecycle` runs AFTER providers
   collect, BEFORE POA&M emission. Documented order: collect → P.P2
   personnel-evidence → P.P3 personnel-lifecycle → POA&M → bundle → sign.

8. **Notify** (`core/notify.ts`): emit `termination-recorded` to Slack +
   PagerDuty on tracker POST; emit `ps-4-sla-breach` on enforcer breach
   transition; emit `transfer-recorded` on PS-5 events. Templates in
   `core/notify-templates.ts` mirror existing patterns.

9. **UI signed-checklist**:
   - PersonnelLifecycle page: list view + "+ New event" button.
   - PersonnelLifecycleDetail page: 5-checkbox PS-4 checklist; each
     checkbox attestation signed individually by `hr` or `it` role;
     audit log captures each click.

## REQUIRES-OPERATOR-INPUT fields

| Field | Source | Behavior when missing |
|---|---|---|
| `org_defined_time_period_hours` | `config/workforce-policy.yaml: ps4_time_period_hours` (default 24) | Documented default; example yaml committed |
| `ps5_transfer_time_period_hours` | `config/workforce-policy.yaml: ps5_transfer_time_period_hours` (default 72) | Documented default |
| `ps8_notification_time_period_hours` | `config/workforce-policy.yaml: ps8_notification_time_period_hours` (default 8) | Documented default |
| Per-event `effective_at`, `access_revoked_at`, etc. | HR/IT UI input | Server-side check: terminations require all 5 PS-4 checkboxes set before sla_status can transition to within-sla |
| `exit_interview_completed_at` / `property_returned_at` / `information_retention_attested_at` | Per-row checkboxes signed by `hr` role | Missing → Finding `psFindingKind: 'ps-4-checklist-incomplete'` |
| User's `cloud_identity_arn` (mapping HR user → IAM principal) | Operator sets on `users` table via UI Settings | Missing → reader cannot correlate; emits `psFindingKind: 'ps-4-iam-unmapped'` |

## Test specifications

1. `it('rejects event_type not in enum')` — `event_type='retirement'`
   → 422.
2. `it('terminations require all five PS-4 a-e checkboxes attested')` —
   missing `exit_interview_completed_at` → Finding emitted.
3. `it('SLA enforcer transitions pending→within-sla when IAM observed_disabled<=deadline')`.
4. `it('SLA enforcer transitions pending→breached when deadline passed without observation')`.
5. `it('reader emits psFindingKind=ps-4-breached on SLA breach')` —
   observed=null + deadline-passed → Finding.
6. `it('reader emits psFindingKind=ps-5-access-not-rebaselined for transfers with no role delta')`
   — pre/post role membership identical → Finding.
7. `it('reader does NOT emit Finding when within SLA + all checkboxes set')`.
8. `it('reader emits psFindingKind=ps-8-notification-late when sanction processed > org window')`.
9. `it('signs lifecycle events with Ed25519')` — verify via core/sign.ts.
10. `it('respects workforce-policy.yaml ps4_time_period_hours override')` —
    override 24→4, assert SLA computed against 4h.
11. `it('correlates with providers/aws/iam.ts IAM-SUS output for disable observation')`.
12. `it('correlates with providers/gcp/iam.ts')`.
13. `it('correlates with providers/azure/iam.ts')`.
14. `it('emits POA&M item with related-observation citing the IAM principal')`.
15. `it('notify.ts fires termination-recorded on tracker termination POST')`.
16. `it('notify.ts fires ps-4-sla-breach on enforcer breach transition')`.
17. `it('UI: signed-checklist requires hr or it role')`.
18. `it('--strict-workforce fails build (exit 2) on any sla_status=breached')`.
19. `it('sanction-imposed event_type stores resolution_summary requirement')`.
20. `it('snapshot provenance block records inventory_fetched_at + tracker URL')`.

## REO compliance specific to this slice

- Every lifecycle event is signed (Ed25519). The 5-checkbox PS-4
  checklist is signed per-checkbox; the audit_log captures each
  signature.
- IAM correlation is REAL — reads the existing `providers/*/iam.ts`
  inventory output, no mocks.
- SLA breach is observable in OSCAL POA&M with cited evidence path (the
  IAM principal id + observation timestamp + sla_deadline prop).
- No silent "passed" status; missing IAM observation flags the SLA as
  `pending` until either observed or deadline; deadline-passed without
  observation → `breached` (visible).
- No `process.env.NODE_ENV === 'test'` branches.
- Provenance block on `out/.personnel-lifecycle-snapshot.json` includes
  `inventory_fetched_at`, tracker snapshot URL + timestamp, signingKeyId.
- Signed by existing `core/sign.ts` pipeline.

## Verification commands

```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/personnel-lifecycle.test.ts tests/core/personnel-lifecycle-emit.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
cd ../tracker
npm run typecheck
npm test -- server/routes/personnel-lifecycle.test.ts server/lifecycle-sla-enforcer.test.ts client/src/pages/PersonnelLifecycle.test.tsx
```

## Known risks / issues

- **Risk 1: IAM-SUS snapshot freshness vs SLA window.** If IAM-SUS
  collector runs daily but PS-4 SLA is 24h, the observed-disable-time
  could land in a snapshot gap. Mitigation: the reader emits
  `psFindingKind: 'ps-4-iam-snapshot-stale'` when
  `inventory_fetched_at > effective_at + sla_window + 4h`; operator
  runbook documents shortening the collector cadence for compliance.
- **Risk 2: cloud_identity_arn mapping on users table may be incomplete.**
  HR records typically don't carry the user's federated cloud identity.
  Mitigation: tracker UI prompts operators to set `cloud_identity_arn`
  per user (one-time); reader emits `psFindingKind: 'ps-4-iam-unmapped'`
  for terminations of users lacking the mapping (visible gap).
- **Risk 3: Race between IAM disable and IAM-SUS pull.** If IT disables
  the IAM principal at T+5h but the next IAM-SUS run is at T+24h, the
  enforcer transitions to `within-sla` only at T+24h. Mitigation: this
  is acceptable for evidence-grade purposes — the disable DID happen
  in-window; the artifact records the observation timestamp; CHANGELOG
  documents the lag semantics.
- **Risk 4: PS-5 transfer detection requires LOOP-J.J1 roles snapshot
  before/after `effective_at`.** If only one snapshot exists,
  comparison is impossible. Mitigation: P.P3 reader requires ≥2 roles
  matrix snapshots in the lookback window (default 7 days); emits
  `psFindingKind: 'ps-5-snapshot-insufficient'` otherwise.
- **Risk 5: PS-8 sanction events handle pre-adverse-action data.**
  Storing raw user_id + reason in audit log could leak. Mitigation:
  sanction events use opaque `subject_user_ref` token (mirroring P.P1
  ITP cases); `processed_by_user_id` is the only direct user link.
- **Risk 6: Lifecycle event uniqueness.** Multiple events for the same
  user (rehire after termination) should not violate uniqueness; the
  uuid is unique but `user_id` is not. Mitigation: documented; UI shows
  full history per user.
- **Risk 7: Contractor-end vs termination semantics.** A contractor
  whose engagement ends is NOT an employee termination; PS-4 applies
  differently. Mitigation: `event_type='contractor-end'` triggers a
  lighter checklist (3 of 5 PS-4 boxes); CHANGELOG documents.

## Open questions

- **Q1**: Should the SLA enforcer auto-create a Jira/ServiceNow ticket
  on breach, or just notify? Recommendation: notify only in P.P3 ship;
  ticket creation is a LOOP-F.F2 enhancement.
- **Q2**: When a termination is followed by a rehire (e.g. 6 months
  later), should the SLA enforcer re-check the prior termination's
  IAM-disable observation, or treat it as historical? Recommendation:
  historical (immutable); rehire creates a new lifecycle event with
  `event_type='internal-transfer'` (re-onboarding flow handled by P.P2
  screening + LOOP-J.J1 role grant).
- **Q3**: PS-5 transfer requires `prior_position_uuid` + `new_position_uuid`
  both to be in `personnel_positions`. If a position is retired between
  effective_at and the orchestrator run, does the reader find it?
  Recommendation: positions are immutable after `designated_at`;
  `status='retired'` is preserved; reader joins on uuid (not status).

## Implementation log

```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist

- [ ] typecheck clean (cloud-evidence + tracker)
- [ ] tests passing 100% (≥20 new tests this slice)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (P.P3 slice row + Overall section)
- [ ] LOOP-P-SPEC.md §8 status table updated (P.P3 row)
- [ ] This file's frontmatter updated (status, commit, completed_date)
- [ ] CHANGELOG.md "Unreleased" entry added (cites PS-4 + PS-5 + PS-8 verbatim)
- [ ] Commit with `LOOP-P.P3:` slice ID in message
- [ ] Commit amended hash recorded in STATUS.md + this file + LOOP-P-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist

1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. Read this file (P.P3.md).
3. Read `cloud-evidence/docs/loops/LOOP-P-SPEC.md` §5 P.P3 + §11
   worked-example end-to-end.
4. Read `cloud-evidence/docs/loops/LOOP-P-RISKS.md` — live risks register.
5. Read `cloud-evidence/docs/slices/P/P.P2.md` — prerequisite for the
   positions table P.P3 references.
6. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
7. Read `cloud-evidence/providers/aws/iam.ts` (IAM-SUS) — observation
   surface for the correlation.
8. Read `cloud-evidence/core/notify.ts` — notification surface.
9. Read `tracker/server/schema.sql` — add the one new table additively.
10. Begin implementation; update Implementation log section as you go.
