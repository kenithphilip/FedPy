---
slice_id: P.P2
title: Position risk designation per role (PS-2 + PS-3 screening)
loop: P
status: pending
commit: —
completed_date: —
depends_on: [LOOP-A.A1, LOOP-A.A2, LOOP-A.A3, LOOP-J.J1, P.P1]
blocks: [P.P3, P.P5, F.F3]
estimated_effort: 6-7 working days
last_updated: 2026-06-07
applicable_conditional: false
---

# P.P2 — Position risk designation per role (PS-2 + PS-3 screening)

## TL;DR
Build the per-position risk register (NIST 800-53 Rev5 PS-2) + per-user
screening + re-screening cadence ledger (PS-3) on top of the LOOP-J.J1
Roles & Privileges matrix. Adds two tracker tables
(`personnel_positions`, `personnel_screening_records`), an hourly cadence
enforcer that flips records to `overdue`, a new emitter
`core/position-risk-emit.ts` that produces `out/position-risk-register.json`,
and the `out/KSI-PIY-PSE.json` envelope. Failing PS-3 status emits POA&M
items via the existing emitter; SSP PS-1..PS-9 implementation statements
pull narrative from policy + register. Public-trust risk levels come from
5 CFR 731.106 (High/Moderate/Low); national-security sensitivity levels
from 32 CFR 147 (SS/CS/NCS/NS).

## Status
- Status: pending
- Commit: — (filled when shipped per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
P.P2 takes the LOOP-J.J1 Roles & Privileges matrix (AC-2 + AC-6 controls)
and overlays PS-family workforce data: each position gets a risk
designation; each user with IAM access gets a screening row; the
orchestrator-side reader correlates against `providers/*/iam.ts` IAM-SUS
output to surface "IAM principal active but no current screening" anomalies
as `psFindingKind: 'screening-missing' | 'screening-overdue'` Findings.
The new `PIY-PSE` KSI token in `core/ksi-map.ts` ties to NIST PS-1..PS-9;
the new `position-risk-register-json` + `screening-records-snapshot`
roles in `core/submission-bundle.ts:WELL_KNOWN` make both artifacts
first-class submission-bundle outputs. No new cloud SDK call is added —
this slice consumes the existing IAM-SUS evidence path.

## Why this slice exists
NIST SP 800-53 Rev5 PS-2 ("Assign a risk designation to all organizational
positions; establish screening criteria; review and update") + PS-3
("Screen individuals prior to authorizing access; rescreen…") are in the
FedRAMP Moderate baseline. 5 CFR 731.106 requires public-trust risk
designations at High / Moderate / Low; 32 CFR 147 supplies the parallel
national-security sensitivity axis (Special-Sensitive / Critical-Sensitive
/ Noncritical-Sensitive / Non-Sensitive). FedPy today has zero coverage:
no position table, no screening ledger, no cadence enforcement, no IAM
correlation. P.P2 closes the gap and unblocks LOOP-F.F3 sample selection
(the position register is the population frame for 3PAO sampling on
PS-3 verification).

## Authoritative sources (with verbatim quotes)

- **NIST SP 800-53 Rev5 — PS-2 (Position Risk Designation)** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
  Verbatim:
  > "a. Assign a risk designation to all organizational positions;
  > b. Establish screening criteria for individuals filling those
  > positions; and
  > c. Review and update position risk designations [Assignment:
  > organization-defined frequency]."

- **NIST SP 800-53 Rev5 — PS-3 (Personnel Screening)** — verbatim:
  > "a. Screen individuals prior to authorizing access to the system;
  > and b. Rescreen individuals in accordance with [Assignment:
  > organization-defined conditions requiring rescreening and, where
  > rescreening is so indicated, the frequency of rescreening]."

- **5 CFR Part 731 — Suitability** —
  https://www.ecfr.gov/current/title-5/chapter-I/subchapter-B/part-731
  5 CFR 731.106 (verbatim):
  > "Each agency head shall designate every covered position within the
  > agency at a high, moderate, or low risk level as determined by the
  > position's potential for adverse impact to the efficiency or
  > integrity of the service."

  Three public-trust risk levels (LOOP-P.P2 uses verbatim as enum):
  - High Risk — broad scope + authority including policy-making, major
    program responsibility, public safety, law enforcement, significant
    fiduciary responsibilities, or other duties demanding highest
    degree of public trust.
  - Moderate Risk — moderate scope and authority.
  - Low Risk — low scope and authority.

- **32 CFR Part 147 / 5 CFR Part 1400** — national-security sensitivity:
  https://www.ecfr.gov/current/title-32/subtitle-A/chapter-I/subchapter-D/part-147
  Four sensitivity levels (LOOP-P.P2 uses verbatim as enum):
  - Special-Sensitive (SS) — top-secret access + sensitive
    compartmented information access.
  - Critical-Sensitive (CS) — top-secret access.
  - Noncritical-Sensitive (NCS) — secret access.
  - Non-Sensitive (NS) — no national security access.

- **OPM Position Designation System** —
  https://www.opm.gov/suitability/suitability-executive-agent/policy/position-designation/
  (Operator downloads policy HTML to `cloud-evidence/docs/sources/` when
  anonymous fetch times out.)

- **OPM Tier 1-5 Investigation Standards** —
  https://nbib.opm.gov/e-qip-background-investigations/position-designation/
  Tier mapping (LOOP-P.P2 uses verbatim as enum value): Tier 1
  (Non-Sensitive, Low Risk); Tier 2 (Moderate Risk Public Trust); Tier 3
  (Noncritical-Sensitive); Tier 4 (High Risk Public Trust); Tier 5
  (Critical-Sensitive + Special-Sensitive).

- **OSCAL POA&M v1.1.2** —
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/plan-of-action-and-milestones/json-reference/
  Extension point: `risk.props[]` carrying `psFindingKind` + the
  related-observation cite to the IAM principal.

## Files to create (exact paths under cloud-evidence/)

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/position-risk-emit.ts`
  — pure builder + disk emitter. Joins positions × screening records ×
  IAM principals (from inventory); writes
  `out/position-risk-register.json` (PS-2 deliverable) with provenance.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/personnel-evidence.ts`
  — KSI envelope builder for `PIY-PSE`. Pulls tracker snapshots + IAM-SUS
  output; emits Findings; writes `out/KSI-PIY-PSE.json`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/personnel-positions.ts`
  — Express CRUD for positions. Bulk-import endpoint accepts CSV.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/screening-records.ts`
  — Express CRUD for screening records.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/screening-record-enforcer.ts`
  — hourly task that flips records to `overdue` when re-screening
  cadence elapses; writes audit-log entry; surfaces UI badge.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/PersonnelPositions.tsx`
  — list + create/edit form UI.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/ScreeningRecords.tsx`
  — list + create/edit form UI with cadence indicator.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/position-risk-emit.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/personnel-evidence.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/personnel-positions.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/screening-records.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/screening-record-enforcer.test.ts`

## Files to extend

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ksi-map.ts` —
  register `PIY-PSE` token entry with NIST PS-1..PS-9 mapping.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` —
  new `--personnel-evidence` flag + env `CLOUD_EVIDENCE_PERSONNEL`;
  new `--strict-workforce` flag fails build when any PS-3 row=overdue.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-ssp.ts` —
  implementation statements for PS-1..PS-9 read `config/workforce-policy.yaml`
  + position register summary; populate `implementation-statement.description`
  + add prop `position-register-snapshot-uuid`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-poam.ts` —
  recognise `psFindingKind` discriminator on Finding; map values to NIST
  PS-3 in `related-observations`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
  — add roles `position-risk-register-json` (filename
  `position-risk-register.json`) and `screening-records-snapshot`
  (filename `.screening-records-snapshot.json`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/control-benchmark.ts`
  — wire PS-1..PS-9 into the benchmark coverage table.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/config/workforce-policy.example.yaml`
  — extend with `rescreening_cadence_days` (per tier), `position_review_cadence_days`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/schema.sql` — two new
  tables (DDL below).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/index.ts` — mount
  routes with `requireRole(['hr','iso','ao','assessor'])`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/App.tsx` — add
  `/personnel-positions` and `/screening-records` routes.

## Schemas / standards

- **NIST 800-53 Rev5 PS-2 + PS-3** — verbatim above.
- **5 CFR Part 731** — public-trust enum.
- **32 CFR Part 147 + 5 CFR 1400** — national-security sensitivity enum.
- **OPM Position Designation System / Tier 1-5** — tier mapping.
- **OSCAL POA&M v1.1.2** — extension prop names (namespaced `CE_NS`):
  `ps-finding-kind`, `position-uuid`, `iam-principal-id`, `screening-uuid`.

## Build steps (concrete, numbered)

1. **Tracker schema** (`tracker/server/schema.sql`):
   ```sql
   CREATE TABLE IF NOT EXISTS personnel_positions (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     position_id TEXT NOT NULL UNIQUE,                -- operator-defined stable identifier
     title TEXT NOT NULL,
     description TEXT NOT NULL,                       -- PS-9 narrative; must include security_responsibilities
     public_trust_level TEXT NOT NULL CHECK (public_trust_level IN ('high','moderate','low','non-sensitive')),
     national_security_level TEXT NOT NULL CHECK (national_security_level IN ('special-sensitive','critical-sensitive','noncritical-sensitive','non-sensitive','not-applicable')),
     designated_at TEXT NOT NULL,
     designated_by_user_id INTEGER NOT NULL REFERENCES users(id),
     review_cadence_days INTEGER NOT NULL DEFAULT 365,
     next_review_due TEXT NOT NULL,
     ac_roles_json TEXT NOT NULL,                     -- linked AC-2 roles (from LOOP-J.J1)
     nist_control_ids TEXT NOT NULL,                  -- JSON array (PS-2 + PS-3 + relevant)
     signature TEXT NOT NULL,
     signing_key_id TEXT NOT NULL,
     status TEXT NOT NULL CHECK (status IN ('active','retired')) DEFAULT 'active'
   );
   CREATE INDEX IF NOT EXISTS idx_pos_review ON personnel_positions(next_review_due);

   CREATE TABLE IF NOT EXISTS personnel_screening_records (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     user_id INTEGER NOT NULL REFERENCES users(id),
     position_uuid TEXT NOT NULL REFERENCES personnel_positions(uuid),
     screening_type TEXT NOT NULL CHECK (screening_type IN ('tier-1','tier-2','tier-3','tier-4','tier-5','contractor-baseline','operator-defined')),
     screening_completed_at TEXT NOT NULL,
     next_rescreening_due TEXT NOT NULL,              -- computed from policy
     screening_evidence_url TEXT,                     -- e.g. link to OPM eApp completion
     screening_evidence_sha256 TEXT,
     status TEXT NOT NULL CHECK (status IN ('current','overdue','expired','revoked')),
     attested_by_user_id INTEGER NOT NULL REFERENCES users(id),
     attested_at TEXT NOT NULL,
     signature TEXT NOT NULL,
     signing_key_id TEXT NOT NULL
   );
   CREATE INDEX IF NOT EXISTS idx_screen_due ON personnel_screening_records(next_rescreening_due);
   CREATE INDEX IF NOT EXISTS idx_screen_user ON personnel_screening_records(user_id);
   ```

2. **Cadence enforcer task** (`tracker/server/screening-record-enforcer.ts`):
   - Runs at boot + every hour (setInterval with jitter).
   - Flips `status` to `overdue` when `next_rescreening_due < now()` AND
     current status is `current`.
   - Writes `audit_log` row `event_type='screening-overdue'`.
   - Emits notify.ts notification when severity bump from `current`→`overdue`.

3. **Reader** (`core/personnel-evidence.ts`):
   - Pulls `personnel_positions` + `personnel_screening_records` snapshots
     via `core/tracker-pull.ts`.
   - Loads inventory `inventory.json` for IAM principals.
   - For each user with `iam_principal_active=true` (existing IAM-SUS
     correlation), match against `personnel_screening_records` by
     `user_id` and assert `status='current'`.
   - Failure → Finding with `psFindingKind` in
     `{ 'screening-missing', 'screening-overdue', 'screening-expired' }`.
   - Aggregate: per-position screening status counts.

4. **Position risk register emitter** (`core/position-risk-emit.ts`):
   - Joins positions × screening records × IAM principals.
   - Emits `out/position-risk-register.json` (PS-2 deliverable) with
     columns:
     - `position_id`, `title`, `description`, `public_trust_level`,
       `national_security_level`, `ac_roles[]`, `current_incumbents[]`,
       `screening_status_counts: { current, overdue, expired, revoked }`,
       `next_review_due`, `signature`, `signing_key_id`.
   - Provenance block: emitter name, emittedAt, sourceCalls listing
     tracker URL + snapshot timestamp + IAM-SUS inventory path.

5. **KSI envelope** (`out/KSI-PIY-PSE.json`):
   - One Finding per failing PS-3 (overdue / missing / expired) — with
     `subject_user_ref` opaque token (not raw user_id).
   - Aggregate gap for PS-2 (any position without designation OR with
     `next_review_due < now()`).
   - References to OSCAL POA&M items for each failure.

6. **SSP integration** (`core/oscal-ssp.ts`): PS-1..PS-9 implementation
   statements pull narrative from:
   - `config/workforce-policy.yaml` (org-defined process text).
   - Position register summary (counts by risk level).
   No fabricated text; missing config emits REQUIRES-OPERATOR-INPUT.

7. **POA&M integration** (`core/oscal-poam.ts`): in `findingProps()`,
   when `f.gap.psFindingKind` is set, append props:
   ```ts
   props.push({ name: 'ps-finding-kind', ns: CE_NS, value: f.gap.psFindingKind });
   if (f.gap.position_uuid) props.push({ name: 'position-uuid', ns: CE_NS, value: f.gap.position_uuid });
   if (f.gap.iam_principal_id) props.push({ name: 'iam-principal-id', ns: CE_NS, value: f.gap.iam_principal_id });
   if (f.gap.screening_uuid) props.push({ name: 'screening-uuid', ns: CE_NS, value: f.gap.screening_uuid });
   ```

8. **Orchestrator wiring**: `--personnel-evidence` runs AFTER LOOP-J.J1
   roles matrix pull + AFTER provider IAM-SUS collection, BEFORE
   `--oscal-poam`. `--strict-workforce` fails the build (exit 2) on any
   psFindingKind present.

9. **Bulk CSV import**: tracker route `POST /api/personnel-positions/bulk`
   accepts multipart CSV; parses with stable column order; upserts
   atomically (one transaction); each row signed individually; audit
   log entry per row.

## REQUIRES-OPERATOR-INPUT fields

| Field | Source | Behavior when missing |
|---|---|---|
| Position list rows | Operator authors via tracker UI; CSV bulk import | Empty register → KSI-PIY-PSE Finding `psFindingKind: 'no-positions-defined'`; SSP PS-2 statement emits marker |
| `public_trust_level` per row | Operator categorises under 5 CFR 731 in UI | Row rejected at server (NOT NULL); operator must declare |
| `national_security_level` per row | Operator declares; default `not-applicable` for non-NS CSPs | Required field; operator declares `not-applicable` explicitly (no silent default) |
| Per-user `screening_completed_at` + evidence URL | Operator records via UI | KSI Finding `psFindingKind: 'screening-missing'` emitted; SSP PS-3 narrative emits count |
| `rescreening_cadence_days` per tier | `config/workforce-policy.yaml` | Default per OPM (Tier 1=5y, Tier 2=5y, Tier 3=10y, Tier 4=5y, Tier 5=5y); documented in example |
| `position.description` security responsibilities (PS-9) | Operator authors per position | Server-side check rejects positions where description lacks at least one of `['security','privacy','responsib']` substrings |
| `next_review_due` | Computed from `designated_at + review_cadence_days` | Auto-computed; no operator input needed |

## Test specifications

1. `it('rejects public_trust_level not in 5 CFR 731 enum')` —
   `public_trust_level='critical'` → 422.
2. `it('rejects national_security_level not in 32 CFR 147 enum')` —
   `national_security_level='unknown'` → 422.
3. `it('enforcer flips status=overdue when next_rescreening_due<now')` —
   load fixture with due-date in past, run enforcer, assert status flip.
4. `it('reader emits psFindingKind=screening-missing for IAM principal w/o screening row')`.
5. `it('reader emits psFindingKind=screening-overdue when status=overdue')`.
6. `it('reader emits psFindingKind=screening-expired when status=expired')`.
7. `it('position-risk-register.json columns match PS-2 schema')` — load
   fixture register, assert each required column present.
8. `it('signs every screening record + position row with Ed25519')` —
   verify signature via `core/sign.ts`.
9. `it('respects review_cadence_days from workforce-policy.yaml')` —
   override default 365 → 180, assert position rows use the override.
10. `it('respects rescreening_cadence_days per tier from policy')`.
11. `it('KSI-PIY-PSE envelope status=fail when any psFindingKind present')`.
12. `it('SSP PS-3 implementation statement cites operator workforce policy')`.
13. `it('rejects screening_evidence_sha256 mismatch when sha provided')` —
   server re-computes sha, asserts match.
14. `it('CSV bulk-import upserts positions atomically with audit-log entries')`
   — N=10 rows, all-or-nothing transaction.
15. `it('RBAC: hr role can write positions; assessor can read; iso can approve')`.
16. `it('reader correlates with IAM-SUS to detect dormant-IAM-principal-with-active-screening anomaly')`.
17. `it('orchestrator --strict-workforce fails build (exit 2) when any PS-3 status=overdue')`.
18. `it('position description must include security_responsibilities verbiage')` —
   server rejects positions lacking PS-9 narrative.

## REO compliance specific to this slice

- Every screening row signed (Ed25519). Operator UI input → audit log →
  signed canonical JSON.
- No synthesised screening dates. Missing → REQUIRES-OPERATOR-INPUT
  visible in SSP PS-3 statement + KSI envelope Finding.
- Position designations come from operator UI / CSV upload, not from
  defaults. `not-applicable` for national_security_level requires
  explicit operator declaration (no silent default that looks real).
- IAM-SUS correlation is a real `providers/*/iam.ts` read; the inventory
  snapshot is the only source of "IAM principal active" truth.
- No `process.env.NODE_ENV === 'test'` branches.
- Provenance block on `out/position-risk-register.json` +
  `out/KSI-PIY-PSE.json` populated per `check:provenance` rules.
- Signed by existing `core/sign.ts` pipeline; both files land in manifest.

## Verification commands

```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/position-risk-emit.test.ts tests/core/personnel-evidence.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
cd ../tracker
npm run typecheck
npm test -- server/routes/personnel-positions.test.ts server/routes/screening-records.test.ts server/screening-record-enforcer.test.ts
```

## Known risks / issues

- **Risk 1: OPM Position Designation Tool (PDT) JSON export schema is
  federal-internal and not publicly stable.** Mitigation: P.P2 does NOT
  integrate with PDT directly; an OPTIONAL CSV importer accepts a
  PDT-flavoured CSV layout but ships independent of PDT API access.
- **Risk 2: 5 CFR 731 public-trust enum could conflict with operator's
  internal risk-rating taxonomy** (some orgs use 4-tier or numeric).
  Mitigation: the database enum is fixed at the 4 values from 5 CFR 731;
  operator-internal taxonomies are mapped at the UI layer; CHANGELOG
  documents the mapping.
- **Risk 3: 32 CFR 147 sensitivity levels typically don't apply to
  commercial CSPs.** Mitigation: most CSPs will set
  `national_security_level='not-applicable'` per position. The schema
  still requires the field to force operator declaration (REO Rule 4);
  the example workforce-policy.yaml documents how to bulk-set.
- **Risk 4: IAM-SUS correlation requires inventory snapshot freshness.**
  If the inventory is stale, screening anomalies surface against
  retired IAM principals. Mitigation: reader records `inventory_fetched_at`
  on each Finding; `--strict-workforce` enforces ≤24h freshness window.
- **Risk 5: User_id ↔ tracker-user vs cloud-identity mapping is
  ambiguous.** Tracker users authenticate via username + role; cloud IAM
  principals authenticate via federation. Mapping requires a join column
  (`cloud_identity_arn` on `users` table). Mitigation: extend `users`
  table with `cloud_identity_arn` (LOOP-J.J1 already added a similar
  column); document mapping in CHANGELOG.
- **Risk 6: Cadence enforcer race condition with manual operator update.**
  If operator updates `next_rescreening_due` while enforcer is running,
  enforcer could re-flip status. Mitigation: enforcer uses
  `UPDATE ... WHERE next_rescreening_due < now() AND status='current'`
  (atomic on SQLite); operator UI runs as separate transaction; the
  audit log captures both rows.

## Open questions

- **Q1**: When a position's `next_review_due` elapses, should the
  enforcer auto-create a tracker task for the reviewer, or just surface
  a UI badge? Recommendation: surface badge + emit
  `core/notify.ts` notification at T-30 / T-7 / T-0 / T+7.
- **Q2**: Should screening evidence URLs be SHA-256 pinned (immutable
  reference) or just URLs (mutable)? P.P2 stores
  `screening_evidence_sha256` as OPTIONAL; recommendation: enforce when
  policy includes `evidence_sha_required: true`; defaults to off for
  back-compat with existing screening packages.
- **Q3**: PS-7 (External Personnel Security) — should contractor
  positions live in `personnel_positions` (with a `position_type` flag)
  or in a separate `external_personnel_positions` table? Recommendation:
  use the same table with `position_type IN ('internal','contractor')`;
  LOOP-J.J2 handles per-subprocessor screening attestations.
- **Q4**: PS-8 (Personnel Sanctions) — modeled here or in P.P3?
  Recommendation: P.P3 lifecycle events table absorbs sanctions as
  `event_type='sanction-imposed'`; documented in P.P3 + LOOP-P-SPEC §7.

## Implementation log

```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist

- [ ] typecheck clean
- [ ] tests passing 100% (≥18 new tests this slice)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (P.P2 slice row + Overall section)
- [ ] LOOP-P-SPEC.md §8 status table updated (P.P2 row)
- [ ] This file's frontmatter updated (status, commit, completed_date)
- [ ] CHANGELOG.md "Unreleased" entry added (cites PS-2 + PS-3 + 5 CFR 731 verbatim)
- [ ] Commit with `LOOP-P.P2:` slice ID in message
- [ ] Commit amended hash recorded in STATUS.md + this file + LOOP-P-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist

1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. Read this file (P.P2.md).
3. Read `cloud-evidence/docs/loops/LOOP-P-SPEC.md` §5 P.P2 + §4 sources.
4. Read `cloud-evidence/docs/loops/LOOP-P-RISKS.md` — live risks register.
5. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
6. Read `cloud-evidence/core/oscal-poam.ts` (extension point for
   `psFindingKind`); `core/oscal-ssp.ts` (PS-1..PS-9 statements);
   `core/ksi-map.ts` (register PIY-PSE token).
7. Read `tracker/server/schema.sql` — add the two new tables additively.
8. Read `tracker/server/rbac.ts` — `hr` role added in P.P1; reuse here.
9. Begin implementation; update Implementation log section as you go.
