---
slice_id: I.I1
title: Executive posture dashboard
loop: I
status: pending
commit: —
completed_date: —
depends_on: [A.A1, A.A4, B.B1, B.B2]
blocks: [F.F5, G.G3]
estimated_effort: 4 days
last_updated: 2026-06-06
---

# I.I1 — Executive posture dashboard

## TL;DR
Ship a `core/posture-snapshot.ts` builder that aggregates the live POA&M
(`out/poam.json`), CSX-SUM passing ratio (`out/csx-sum.json`), CISA KEV exposure
(`docs/cisa-kev.generated.json`), and the LOOP-A.A4 submission chain status
(`out/submission-package/INDEX.json`) into a signed `out/posture-snapshot.json`,
then expose it through a tracker route + a React `/posture` page so a CISO can
read the current FedRAMP posture (top-10 risks, passing %, KEV overdue count,
days until next ConMon deliverable) in under 30 seconds. Every value traces to
a real artifact; missing data emits a `diagnostics[]` entry, never a fabricated
score.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
The signed authorization artifacts produced by LOOP-A (POA&M, SAP, AR, SSP,
RoE, submission package) are authoritative but completely unreadable to a
non-3PAO stakeholder. A CISO opening the tracker today has no single screen
that answers "what is our FedRAMP posture right now?" — the closest proxy is
diff-report which is point-in-time delta only. RFC-0014 KSI-CNA-08 obligates
"persistently assess the security posture of all services"; NIST 800-137 §3.1
defines the ISCM lifecycle whose Step 3 (Implement) and Step 6 (Review and
update) require a human-readable status report. This slice closes that gap by
emitting + ingesting + rendering a stakeholder posture snapshot whose every
field is computed end-to-end from real evidence.

Section D of the FedRAMP 20x requirements doc (stakeholder dashboards) and the
"Trust Center"-style executive view referenced in RFC-0014 KSI ADS-CSO-PUB are
both pointed at this slice as the canonical executive payload. Downstream
LOOP-F.F5 (3PAO recommendation letter) and LOOP-G.G3 (AFR-ADS Trust Center)
both consume `out/posture-snapshot.json` directly, so this slice must be
deterministic and signed.

## Authoritative sources (with verbatim quotes)
- https://csrc.nist.gov/pubs/sp/800/137/final — NIST SP 800-137 ("Information
  Security Continuous Monitoring for Federal Information Systems and
  Organizations"), September 2011, §3.1 ISCM Process:
  > "An ISCM strategy is grounded in a clear understanding of organizational
  > risk tolerance and helps officials set priorities and manage risk
  > consistently throughout the organization." (NIST SP 800-137 §3.1 p.15)

  Implication: the snapshot's `passing_ratio`, `kev_exposure`, and
  `conmon_calendar` collectively satisfy the "set priorities" obligation by
  surfacing the three measurable bands (implementation / effectiveness /
  impact) from Appendix D of the same publication.
- https://www.fedramp.gov/rfcs/0014/ — FedRAMP RFC-0014, KSI-CNA-08:
  > "Use automated services to persistently assess the security posture of
  > all services and automatically enforce secure operations."

  Implication: the posture snapshot is the durable evidence object that
  proves the persistent assessment is happening between formal submissions.
- https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/overview/
  — FedRAMP Rev5 ConMon Playbook (CSP Continuous Monitoring Overview),
  retrieved 2026-06-06:
  > "Each month, the CSP uploads an up-to-date POA&M and inventory, along
  > with raw vulnerability scan files (when required by agreements with
  > agency customers) and reports to the secure repository."

  Implication: the `conmon_calendar.next_poam_due` + `next_inventory_due`
  fields operationalize the monthly cadence so a CISO sees exactly when the
  next deliverable lands.
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog — CISA Known
  Exploited Vulnerabilities Catalog (under BOD 22-01):
  > "Federal agencies must remediate identified vulnerabilities in
  > accordance with the timelines set forth in the catalog."

  Implication: `kev_exposure.overdue_count` flags any open POA&M item whose
  CISA-published `dueDate` is in the past — the highest-criticality posture
  signal for stakeholders.
- https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/plan-of-action-and-milestones/json-reference/
  — OSCAL POA&M v1.1.2 JSON reference, `risks[].deadline` field:
  > "The date by which the risk must be resolved." (OSCAL metaschema
  > definition of `risk-deadline`.)

  Implication: this is the canonical "days_until_deadline" source for every
  TopRisk row in the snapshot.

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/posture-snapshot.ts`
  — pure builder (`buildPostureSnapshot`) + disk emitter
  (`emitPostureSnapshot`) + typed errors (`PostureBuilderError`,
  `MissingPoamError`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/posture-snapshot.test.ts`
  — 12+ unit tests covering builder, emitter, ranking, KEV math, calendar,
  determinism, missing-input errors.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/posture.ts` —
  `POST /api/posture/ingest` + `GET /api/posture/current` +
  `GET /api/posture/history`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/posture.test.ts`
  — 6+ tracker route tests (auth, signature verify, idempotency, cross-
  system isolation).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/db/migrations/010_posture_snapshots.sql`
  — append-only history table + indexes.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/PostureDashboard.tsx`
  — React page rendering tiles + top-10 + diagnostics + footer.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/PostureDashboard.test.tsx`
  — 3+ component tests.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` —
  add `--posture-snapshot` flag, `CLOUD_EVIDENCE_POSTURE_SNAPSHOT` env. Slot
  AFTER `--oscal-poam` and BEFORE `--sign` so the snapshot is included in
  the signed manifest.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
  — register role `'posture-snapshot'`, filename `posture-snapshot.json`,
  `required: false`, description `"Executive posture snapshot for stakeholder
  review (LOOP-I.I1)"`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/index.ts` — mount
  `/api/posture` router.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/schema.sql` — load the
  migration via the existing migration runner.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/lib/api.ts` — add
  `postureCurrent(systemId)` + `postureHistory(systemId, fromIso, toIso)`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/App.tsx` (or main
  router file) — add `/posture` route → `PostureDashboard`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/Dashboard.tsx`
  — add link tile labelled "Executive posture" to `/posture`.

## Schemas / standards
- **OSCAL POA&M v1.1.2 reads** — from `out/poam.json`:
  - `risks[].uuid` → `TopRisk.risk_uuid` (verbatim).
  - `risks[].title` → `TopRisk.title` (verbatim; never reformatted).
  - `risks[].deadline` → `TopRisk.deadline` (ISO 8601 date).
  - `risks[].props[name="composite-score"]` (LOOP-B.B1 emit) →
    `TopRisk.composite_score` (number in [0,100]). Absent → severity-baseline
    fallback `{critical:90, high:70, medium:50, low:30, info:10}` AND push
    `'requires_b1_for_full_ranking'` diagnostic ONCE.
  - `risks[].props[name="kev-flag"]` (LOOP-B.B2 emit) →
    `TopRisk.kev_flagged`.
  - `risks[].props[name="kev-due-date"]` → `KevExposure.overdue_count`
    source.
  - `poam-items[].related-risks[].response.lifecycle` (enum:
    `recommendation`, `planned`, `in-progress`, `completed`) → excludes
    completed from top_risks.
  - `poam.metadata.last-modified` → `ConmonCalendar.next_*_due` base date.
- **CSX-SUM** — read `out/csx-sum.json` from existing
  `core/csx-sum-aggregator.ts`. Use `passing_count` + `total_count` directly.
- **CISA KEV** — read `docs/cisa-kev.generated.json` via existing
  `core/kev-feed.ts` API. `vulnerabilities[].cveId` +
  `vulnerabilities[].dueDate` drive the KEV exposure tile.
- **Submission chain** — read `out/submission-package/INDEX.json`
  `chain_status` (`complete | broken | absent`) via LOOP-A.A4 emit.
- **OSCAL SSP/AR last-modified** — for the triennial review tile, read
  `out/ssp.json` `metadata.last-modified` and `out/ar.json`
  `metadata.last-modified`. Missing → omit tile field + diagnostic.

## Build steps (concrete, numbered)
1. Define interfaces in `core/posture-snapshot.ts`:
   ```ts
   export interface PostureSnapshot {
     snapshot_id: string;          // UUIDv5(systemId+generatedAt, NAMESPACE)
     system_id: string;
     impact_level: 'low' | 'moderate' | 'high';
     generated_at: string;
     passing_ratio: { numerator: number; denominator: number; percent: number;
                      source: 'csx-sum-aggregator' };
     top_risks: TopRisk[];
     kev_exposure: { open_count: number; overdue_count: number;
                     source: 'core/kev-feed.ts + out/poam.json' };
     conmon_calendar: ConmonCalendar;
     chain_status: 'complete' | 'broken' | 'absent';
     diagnostics: string[];
     provenance: { emitter: 'core/posture-snapshot.ts';
                   emittedAt: string; sourceCalls: string[];
                   signingKeyId?: string };
   }
   ```
2. Pure builder: `buildPostureSnapshot(input, opts) → PostureSnapshot`
   exactly as in LOOP-I-SPEC.md §4 / Slice I.I1 / Build step 2.
3. Implement ranking: filter non-completed, read composite-score prop, sort
   desc, tie-break by earlier deadline then by `finding_uuid` lex.
4. Implement KEV math: walk `props[name="kev-flag"]` + `kev-due-date`. If no
   KEV props anywhere, set counts to 0 + push diagnostic
   `'requires_b2_for_kev_overdue_calc'`.
5. Implement ConMon calendar via existing `core/bizdays.ts`:
   - `next_poam_due` + `next_inventory_due` = next biz day on/after 1st of
     month following `metadata.last-modified`.
   - `next_annual_review_due` = `last-modified + 365d`.
   - `next_triennial_due` = AR `last-modified + 1095d` (skip if AR absent).
   - `days_until_next_deliverable` = min of all four.
6. Disk emitter:
   `emitPostureSnapshot({outDir, systemId, impactLevel, now?})`. Reads
   `outDir/poam.json`, `outDir/csx-sum.json`, KEV catalog,
   `outDir/submission-package/INDEX.json`. Writes JSON. Throws
   `MissingPoamError` if `poam.json` absent. Populates
   `provenance.sourceCalls` with every read path.
7. Wire to orchestrator: `--posture-snapshot` /
   `CLOUD_EVIDENCE_POSTURE_SNAPSHOT`. Run after `--oscal-poam`, before
   `--sign`. When POA&M not emitted this run, log
   `posture-snapshot:skipped reason=no-poam` and continue.
8. Register in `core/submission-bundle.ts` well-known catalogue
   (role=`posture-snapshot`, filename=`posture-snapshot.json`).
9. Tracker DB migration `010_posture_snapshots.sql`:
   ```sql
   CREATE TABLE IF NOT EXISTS posture_snapshots (
     snapshot_id TEXT PRIMARY KEY,
     system_id TEXT NOT NULL,
     impact_level TEXT NOT NULL,
     generated_at TEXT NOT NULL,
     passing_percent REAL NOT NULL,
     kev_open_count INTEGER NOT NULL,
     kev_overdue_count INTEGER NOT NULL,
     chain_status TEXT NOT NULL,
     payload_json TEXT NOT NULL,
     signature TEXT NOT NULL,
     ingested_at TEXT NOT NULL DEFAULT (datetime('now'))
   );
   CREATE INDEX IF NOT EXISTS idx_posture_system_time
     ON posture_snapshots(system_id, generated_at DESC);
   ```
10. Tracker routes (`tracker/server/routes/posture.ts`):
    - `POST /api/posture/ingest` — accepts `{snapshot, signature}`. Verifies
      Ed25519 against pinned key. `INSERT OR REPLACE` idempotently.
    - `GET /api/posture/current?system_id=` — most recent row.
    - `GET /api/posture/history?system_id=&from=&to=` — list (for I.I3
      cross-reference).
11. UI component `PostureDashboard.tsx`:
    - 4 top tiles (passing %, KEV overdue, chain status pill,
      days-until-next).
    - Top-10 table (title, composite_score bar, severity pill, deadline w/
      relative-days highlight, KEV badge).
    - Diagnostics panel — verbatim strings + contextual hint.
    - Footer: snapshot_id + signing key id.
    - Empty-state: "Run `npm run collect -- --posture-snapshot` and
      re-ingest."
12. Sign + timestamp: already covered — the orchestrator's existing
    `core/sign.ts` pass picks up the new emit because it's listed in the
    output catalogue.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4 the snapshot has zero new operator-input fields — every value
is auto-derivable. The two upstream parameters required:
- **`system_id`** — Source: existing CLI flag `--system-id` /
  `CLOUD_EVIDENCE_SYSTEM_ID` (LOOP-A.A2). Missing → orchestrator already
  rejects with a typed error before this slice runs.
- **`impact_level`** — Source: existing CLI flag `--impact-level`. Missing →
  same upstream rejection.
- **Any field that cannot be auto-derived in a given run** (e.g.
  composite-score before B.B1 ships, KEV props before B.B2 ships, AR
  last-modified before A.A3 has been re-run) → the emitter falls back to a
  documented baseline AND pushes a single named diagnostic. It NEVER emits
  a fabricated number; the UI surfaces the diagnostic verbatim so the
  stakeholder sees the data lineage gap.

## Test specifications (≥12 tests)
1. `it('builds a snapshot with top-10 risks from a real POA&M')` — Fixture:
   12 risks with composite-score props. Asserts `top_risks.length === 10`
   and that order is descending by composite_score.
2. `it('falls back to severity-baseline and emits requires_b1 diagnostic')`
   — Fixture without `composite-score` props. Asserts every TopRisk has
   `composite_score_source === 'severity-baseline'` and
   `diagnostics.includes('requires_b1_for_full_ranking')` exactly once.
3. `it('computes passing_ratio.percent from csx-sum.json')` — Fixture
   `{passing:73, total:100}`. Asserts `passing_ratio.percent === 73.0`,
   numerator/denominator round-trip.
4. `it('excludes completed risks from top_risks')` — 3 of 5 risks
   `lifecycle === 'completed'`. Asserts only 2 surfaced.
5. `it('marks kev_overdue_count when kev-due-date < now')` — Inject `now`.
   Fixture has 4 KEV risks, 2 with past due-dates, 2 future. Asserts
   `overdue_count === 2`, `open_count === 4`.
6. `it('emits requires_b2_for_kev_overdue_calc when no kev props present')`
   — POA&M with no kev props. Asserts diagnostic present, counts === 0.
7. `it('computes next_poam_due as the next business day on/after the 1st of next month')`
   — Fixture `last-modified=2026-06-15`. Expected: `2026-07-01` (Wednesday;
   same date).
8. `it('skips weekend for next_poam_due')` — Fixture causes 1st to be
   Saturday. Expected: following Monday.
9. `it('marks chain_status absent when INDEX.json missing')` — Asserts
   `chain_status === 'absent'`.
10. `it('throws MissingPoamError when out/poam.json is missing')` — Never
    silent fallback; emitter throws typed error.
11. `it('produces byte-identical JSON when called twice with identical inputs')`
    — Determinism: same `now`, same inputs → `JSON.stringify` equal.
12. `it('emits provenance.sourceCalls listing every file read')` — Asserts
    `sourceCalls` includes `out/poam.json`, `out/csx-sum.json`,
    `docs/cisa-kev.generated.json`.
13. `it('caps top_risks at requested topN')` — Pass `topN: 3`; asserts
    length 3 and order preserved.
14. `it('emits requires_ar_for_triennial diagnostic when AR last-modified absent')`.

Tracker route tests (≥6):
1. `POST /api/posture/ingest` accepts valid signed payload, persists row.
2. Rejects payload with invalid Ed25519 signature → 400.
3. `GET /api/posture/current` returns most recent for system_id.
4. Returns 404 when no rows for system_id.
5. Ingest idempotent on `snapshot_id`: same payload replays 200, no
   duplicate.
6. Cross-system isolation: system A token cannot read system B's snapshot.

UI tests (≥3):
1. Renders 10 rows when API returns 10 top_risks.
2. Empty-state when API returns 404.
3. Renders every diagnostic string verbatim with contextual hint.

## REO compliance specific to this slice
- Every emitted value traces to: `out/poam.json` (LOOP-A.A1),
  `out/csx-sum.json` (existing aggregator), `docs/cisa-kev.generated.json`
  (committed CISA catalog refreshed by `core/kev-feed.ts`),
  `out/submission-package/INDEX.json` (LOOP-A.A4). NO synthetic values.
- No silent fallbacks for: composite_score (falls back to severity-baseline
  + named diagnostic), KEV overdue (zero count + named diagnostic),
  triennial due (omitted + named diagnostic). Every fallback is observable.
- Provenance fields populated: `provenance.emitter`,
  `provenance.emittedAt`, `provenance.sourceCalls[]` (one entry per file
  read), `provenance.signingKeyId` (filled by `core/sign.ts`).
- Signed by: existing `core/sign.ts` Ed25519 + RFC 3161 pipeline (already
  wired through `orchestrator.ts --sign`).
- `npm run check:provenance` will pass because `posture-snapshot.json` has a
  `provenance` block.
- `npm run lint:no-stubs` will pass because the slice emits no TODO /
  placeholder / sample string literals.
- `npm run check:coverage-regression` is N/A (no inventory-coverage delta).

## Verification commands
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/posture-snapshot.test.ts
npm run check:reo

cd "/Users/kenith.philip/FedRAMP 20x/tracker"
npm test -- server/routes/posture.test.ts
npm test -- client/src/pages/PostureDashboard.test.tsx
```

End-to-end smoke:
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run collect -- --posture-snapshot --sign --system-id acme-saas \
  --impact-level moderate --mtime 2026-06-06T00:00:00Z
test -f out/posture-snapshot.json && jq -e '.provenance.sourceCalls | length > 0' \
  out/posture-snapshot.json
```

## Known risks / issues
- **Risk 1 — LOOP-B.B1 ordering.** If implemented before B.B1, every
  TopRisk uses severity-baseline ranking. Mitigation: emit
  `'requires_b1_for_full_ranking'` diagnostic, surface in UI, document
  that re-running after B.B1 lands picks up real scores automatically (no
  LOOP-I code change).
- **Risk 2 — KEV catalog staleness.** `docs/cisa-kev.generated.json` may
  lag the live CISA feed by hours. Mitigation: `provenance.sourceCalls`
  records the local file's mtime so a stakeholder can see catalog freshness.
  The existing `core/kev-feed.ts` refresh job is responsible for the
  rotation.
- **Risk 3 — Determinism vs `now`.** The snapshot embeds `generated_at` +
  `days_until_*`. Mitigation: inject `now: Date` into the pure builder so
  tests pin it; orchestrator passes `new Date()` (or `--mtime` for
  reproducible-build mode).
- **Risk 4 — Cross-system data leakage in tracker.** A malicious caller
  could GET another tenant's snapshot. Mitigation: route MUST resolve
  `system_id` from the authenticated session token, not from query param
  (or check the query param against the session's permitted systems).
- **Risk 5 — UI dependency creep.** Stakeholders will ask for charts; this
  slice ships tiles + table only. Mitigation: defer chart work to I.I2/I.I3
  which already plan dependency-free SVG renderers.
- **Risk 6 — Signature key rotation.** A snapshot ingested under key K1 is
  later queried after rotation to K2. Mitigation: persist `signature` +
  `signingKeyId` in DB so historical entries verify under their original
  key.
- **Risk 7 — Time-zone confusion.** ConMon-calendar dates are computed in
  UTC but a stakeholder might compare them to a local-time mental model.
  Mitigation: UI labels dates with explicit UTC timezone suffix.

## Open questions (for implementation session to resolve)
- **Q1**: Should `next_*_due` calendar dates honour FedRAMP-defined "agency-
  customer" overrides (e.g. monthly cadence shortened to bi-weekly)? Current
  plan: single canonical monthly cadence; agency-specific overrides are out
  of scope for I.I1. Flag for revisit when LOOP-G ships.
- **Q2**: Where does the pinned Ed25519 verification key for the tracker
  ingest route live? Reuse the same `core/sign.ts` keystore + add a
  tracker-side import command, or duplicate the public key in the tracker
  schema? Recommend the first (single source of truth).
- **Q3**: Should `top_risks` cap at 10 or be configurable per role (e.g.
  CISO=10, system-owner=25)? Current plan: server emits 10, UI option to
  page; configurable cap is post-MVP.
- **Q4**: Does `passing_ratio` denominator count `not-collected` KSIs?
  Current plan: matches `csx-sum-aggregator.ts` semantics (counts attempted
  + collected; `not-collected` excluded). Confirm during implementation.
- **Q5**: Should the snapshot embed the full POA&M risk objects or only the
  10 displayed? Current plan: only the top 10 (privacy + signature size).
  The full POA&M is already in `submission-package/`.
- **Q6**: Snapshot retention policy in the tracker — how long? Suggest 13
  months (1y + buffer). Confirm with audit team before shipping.
- **Q7**: Sparkline of `passing_ratio` over time on the dashboard — defer
  to I.I3 (trend analysis) to avoid duplication.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥12 for builder + ≥6 for
  routes + ≥3 for UI)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (I.I1 row + Overall section)
- [ ] LOOP-I-SPEC.md status table updated (Section 7)
- [ ] This file's frontmatter updated (status=done, commit=<hash>,
  completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added under
  `### Added — LOOP-I.I1: Executive posture dashboard`
- [ ] Commit with `LOOP-I.I1:` prefix in message
- [ ] Commit amended with commit hash recorded in STATUS.md + this file +
  LOOP-I-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context, here's everything it
needs to start:
1. Read `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/CLAUDE.md` (REO
   standard, auto-loaded).
2. This file gives you: source obligations + files to create + build steps
   + tests + risks + completion checklist.
3. Read `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/LOOP-I-SPEC.md`
   Section 2 (Dependencies) for context on this loop + Section 4 / Slice
   I.I1 for the canonical spec.
4. Read `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`
   for the mandatory commit pattern.
5. Read `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-poam.ts`
   + `core/csx-sum-aggregator.ts` + `core/kev-feed.ts`
   + `core/submission-bundle.ts` to understand the input shapes you'll
   consume.
6. Read `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sign.ts` to
   understand the signing pipeline + key id propagation.
7. Begin implementation; update Implementation log section as you go.
