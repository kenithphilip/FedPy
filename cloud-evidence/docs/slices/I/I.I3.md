---
slice_id: I.I3
title: Longitudinal trend analysis
loop: I
status: pending
commit: —
completed_date: —
depends_on: [A.A1, B.B1]
blocks: [E.E1, G.G6]
estimated_effort: 5 days
last_updated: 2026-06-07
---

# I.I3 — Longitudinal trend analysis

## TL;DR
Ship a `core/trend-analysis.ts` builder that aggregates per-KSI pass/fail
status across the existing `out/run-ledger.jsonl` history, detects
pass→fail / pass→mixed regressions, and emits a signed
`out/trend-analysis.json` plus a date-stamped
`out/trend-regressions-<YYYY-MM-DD>.json` (only when regressions exist).
Wire regression notification through the existing `core/notify.ts`
(Slack/PagerDuty) and render a per-KSI sparkline grid + open-regression
acknowledgement queue on a tracker `/trends` page. Closes the "KSI-X has
been failing for 3 months" longitudinal gap that
`core/diff-report.ts` leaves open.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
`core/diff-report.ts` already produces point-in-time deltas between two
runs, but it cannot answer "how long has KSI-IAM-MFA been failing?" or
"which KSIs regressed in the last 30 days?". RFC-0014 mandates
"continuously evaluate" (KSI-SVC-01) — a single snapshot does not satisfy
that obligation; durable longitudinal evidence does. This slice provides
that evidence object and the alerting feedback loop that ensures a
regression is acted on, not silently buried in a JSON file.

Downstream LOOP-E.E1 (monthly ConMon analysis report) uses
`trend-analysis.json` to populate its month-over-month section, and
LOOP-G.G6 (AFR-CCM publication) uses it as the canonical attestation that
the CSP is meeting "continuously validate" obligations. Both consumers
require deterministic JSON + cryptographic signature.

## Authoritative sources (with verbatim quotes)
- https://www.fedramp.gov/rfcs/0014/ — FedRAMP RFC-0014, KSI-SVC-01:
  > "Continuously evaluate machine-based information resources for
  > opportunities to improve security."

  KSI-CNA-08:
  > "Use automated services to persistently assess the security posture of
  > all services and automatically enforce secure operations."

  KSI-SVC-09:
  > "continuously validate the authenticity and integrity of communications
  > between information resources."

  Implication: the "continuously evaluate" / "persistently assess" /
  "continuously validate" language obligates a longitudinal evidence
  object; the existing diff-report (point-in-time delta) does not satisfy
  this. `trend-analysis.json` is the durable artifact that does.
- https://csrc.nist.gov/pubs/sp/800/137/final — NIST SP 800-137 §3.6
  ("Review and update the program"):
  > "Reviews ensure that ISCM activities continue to be effective ... The
  > frequency of review should be sufficient to detect and remediate
  > problems before they have a significant impact on the organization."

  Implication: regression detection (pass→fail or pass→mixed transition)
  is the operational manifestation of "detect ... before significant
  impact" — the alert payload is the trigger for review.
- https://csrc.nist.gov/pubs/sp/800/137/final — NIST SP 800-137 Appendix D
  (sample metrics taxonomy):
  > "Implementation metrics measure how an organization has implemented its
  > security controls ... Effectiveness/efficiency metrics measure the
  > results of the controls ... Impact metrics measure the business or
  > mission impact of security activities."

  Implication: per-KSI pass rate is an implementation metric (pass/fail of
  the control); regression-time-to-acknowledge is an effectiveness metric.
  Both feed Appendix D's measurement model.
- https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final — NIST SP 800-53 Rev 5
  control CA-7 (Continuous Monitoring), p. 81:
  > "Develop a continuous monitoring strategy and implement continuous
  > monitoring program that includes ... ongoing assessments of control
  > effectiveness ... ongoing security status monitoring of organizationally
  > defined metrics in accordance with the organizational continuous
  > monitoring strategy."

  Implication: per-KSI pass rate IS the "ongoing security status
  monitoring of organizationally defined metrics" called out by CA-7.
- https://www.cisa.gov/topics/cyber-threats-and-advisories/cybersecurity-best-practices/general-information/known-exploited-vulnerabilities-catalog
  — CISA BOD 22-01: regression metrics complement KEV remediation; a KSI
  regression that fails KEV-covered controls is a high-priority alert.

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/trend-analysis.ts`
  — pure builder + disk emitter + typed errors (`TrendBuilderError`,
  `MissingLedgerError`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/trend-analysis.test.ts`
  — ≥13 unit tests.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/trends.ts` —
  `POST /api/trends/ingest` +
  `GET /api/trends/per-ksi?system_id&ksi_id&from&to` +
  `GET /api/trends/regressions?system_id` +
  `POST /api/trends/regressions/:id/acknowledge`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/trends.test.ts`
  — ≥6 route tests.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/db/migrations/012_trend_history.sql`
  — per-KSI history + open-regression tables.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/TrendAnalysis.tsx`
  — React page (sparkline grid + open-regressions table).
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/TrendAnalysis.test.tsx`
  — ≥4 component tests.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/lib/sparkline.ts` —
  dependency-free SVG sparkline renderer (`buildSparkline(points, opts)
  → string`), reusing the same dep-free pattern from I.I2.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` —
  add `--trend-analysis` flag + `CLOUD_EVIDENCE_TREND_ANALYSIS` env, plus
  `--notify-regressions` opt-in. Slot after `--oscal-poam`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/run-ledger.ts` —
  extend ledger entry with optional `ksi_summary: { ksi_id: string;
  status: 'pass' | 'fail' | 'mixed'; failing_finding_uuids: string[] }[]`.
  Backward compat: legacy entries treated as `status='not-collected'`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/diff-report.ts` —
  extract `snapshotRun()` helper for trend-analysis reuse.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/notify.ts` — add
  `notifyRegression(payload, opts)` wrapper that reuses the existing
  Slack/PagerDuty driver.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
  — register role `'trend-analysis'`, filename `trend-analysis.json`,
  `required: false`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/index.ts` — mount
  `/api/trends` router.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/lib/api.ts` — add
  `trendsPerKsi(...)`, `trendsRegressions(...)`,
  `trendsAcknowledge(...)`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/App.tsx` — add
  `/trends` route.

## Schemas / standards
- **Per-KSI pass/fail status** at a given run: derived from existing
  `core/csx-sum-aggregator.ts` output (`out/csx-sum.json`) — `pass` when
  all findings for the KSI are pass, `fail` when all are fail, `mixed`
  when both, `not-collected` when no finding records found for the KSI.
- **Regression definition** (canonical): for KSI `K`, regression at run `R`
  iff `status(K, R) = 'fail' OR 'mixed'` AND `status(K, R-1) = 'pass'`.
  Pass→mixed is treated as a regression because a previously-fully-passing
  KSI now has at least one failing finding. We do NOT alert on
  fail→mixed or fail→pass.
- **Pass rate window**: default 90 days. `pass_rate = pass_count / (pass_count
  + fail_count + mixed_count)`. `not-collected` excluded.
- **OSCAL CA-7 implementation evidence**: the trend file is the durable
  evidence object cited by CA-7's "ongoing security status monitoring of
  organizationally defined metrics".

## Build steps (concrete, numbered)
1. Define types in `core/trend-analysis.ts`:
   ```ts
   export type KsiStatus = 'pass' | 'fail' | 'mixed' | 'not-collected';
   export interface KsiTrendPoint {
     observed_at: string; run_id: string; ksi_id: string;
     status: KsiStatus; failing_finding_uuids: string[];
   }
   export interface KsiRegression {
     ksi_id: string; regressed_at: string;
     from_status: 'pass'; to_status: 'fail' | 'mixed';
     run_id_before: string; run_id_after: string;
     failing_finding_uuids: string[];
   }
   export interface TrendAnalysis {
     analysis_id: string; system_id: string;
     range: { from: string; to: string };
     points: KsiTrendPoint[]; regressions: KsiRegression[];
     per_ksi_pass_rate: { ksi_id: string; window_days: number;
                          pass_rate: number }[];
     diagnostics: string[];
     provenance: { emitter: 'core/trend-analysis.ts'; emittedAt: string;
                   sourceCalls: string[]; signingKeyId?: string };
   }
   ```
2. Pure builder: `buildTrendAnalysis(input, opts) → TrendAnalysis` per
   LOOP-I-SPEC.md §4 / Slice I.I3 / Build step 2.
3. Per-KSI series: for each unique `ksi_id` across ledger entries in
   range, emit one `KsiTrendPoint` per entry. Use `ksi_summary` from the
   ledger extension; for legacy entries without it, set
   `status = 'not-collected'` and push diagnostic
   `'requires_ksi_summary_for_full_trend'`.
4. Regression detection: sliding window size 2 over points sorted by
   `observed_at`. Emit `KsiRegression` only when `prev.status === 'pass'`
   AND `next.status ∈ {'fail', 'mixed'}`.
5. Per-KSI pass rate over `windowDays` (default 90): count
   `pass / (pass + fail + mixed)`. Skip KSIs with all
   `not-collected` in window.
6. Disk emitter: `emitTrendAnalysis({outDir, systemId, from?, to?,
   windowDays?, now?})`. Writes `trend-analysis.json` always; writes
   `trend-regressions-<YYYY-MM-DD>.json` only when
   `regressions.length > 0`. Throws `MissingLedgerError` if ledger absent.
7. Regression notification: when `--trend-analysis --notify-regressions`
   AND regressions file is written, orchestrator calls
   `notifyRegression(payload, slackUrl, pagerDutyKey)` using existing
   notify driver. Notification payload is the same JSON written to disk
   (single source of truth).
8. Tracker DB migration `012_trend_history.sql`:
   ```sql
   CREATE TABLE IF NOT EXISTS trend_points (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     system_id TEXT NOT NULL,
     ksi_id TEXT NOT NULL,
     observed_at TEXT NOT NULL,
     run_id TEXT NOT NULL,
     status TEXT NOT NULL,
     failing_finding_uuids TEXT NOT NULL,
     UNIQUE(system_id, ksi_id, run_id)
   );
   CREATE TABLE IF NOT EXISTS trend_regressions (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     system_id TEXT NOT NULL,
     ksi_id TEXT NOT NULL,
     regressed_at TEXT NOT NULL,
     run_id_before TEXT NOT NULL,
     run_id_after TEXT NOT NULL,
     acknowledged_at TEXT,
     acknowledged_by INTEGER REFERENCES users(id),
     payload_json TEXT NOT NULL,
     UNIQUE(system_id, ksi_id, regressed_at)
   );
   CREATE INDEX IF NOT EXISTS idx_trend_ksi_time
     ON trend_points(system_id, ksi_id, observed_at);
   ```
9. Tracker routes:
   - `POST /api/trends/ingest` — accepts signed payload, verifies
     signature, `INSERT OR IGNORE` for idempotency on
     `(system_id, ksi_id, run_id)`.
   - `GET /api/trends/per-ksi?...` — returns points for a KSI in range.
   - `GET /api/trends/regressions?system_id=` — returns open (not
     acknowledged) regressions.
   - `POST /api/trends/regressions/:id/acknowledge` — RBAC: only
     `system-owner` or `assessor` role. Records `acknowledged_by` +
     `acknowledged_at`; emits an audit-log entry via existing
     `tracker/server/audit.ts`.
10. UI page `TrendAnalysis.tsx`:
    - Top half: per-KSI sparkline grid (1 mini chart per KSI, dep-free
      SVG). Tooltip shows failing finding count over time. Click → drill
      into `/indicators/<ksi_id>` (existing route).
    - Bottom half: "Open regressions" table ordered by `regressed_at DESC`.
      Acknowledge button per row (RBAC enforced).
    - Range picker default 90 days.
    - Empty state: "No regressions detected in the selected window."
11. Submission-bundle catalogue entry: role=`trend-analysis`,
    filename=`trend-analysis.json`, required=`false`.
12. Sign + timestamp: covered by existing `core/sign.ts` pipeline.

## REQUIRES-OPERATOR-INPUT fields
None for the trend analysis itself — it is fully auto-derived from the
run-ledger. Acknowledging an open regression in the UI is operator action
captured in `acknowledged_by` + audit log (not auto-derived data; that is
the point — human review of system-detected regressions).

## Test specifications (≥13 tests)
1. `it('builds points for every (ksi_id, ledger entry) in range')`.
2. `it('marks status not-collected for legacy ledger entries without ksi_summary')`.
3. `it('detects pass→fail regression')`.
4. `it('detects pass→mixed regression')`.
5. `it('does NOT report fail→pass as a regression')`.
6. `it('does NOT report fail→mixed as a regression')`.
7. `it('emits regressions file only when regressions[] is non-empty')`.
8. `it('computes per_ksi_pass_rate excluding not-collected points')`.
9. `it('is deterministic given identical ledger')`.
10. `it('throws TrendBuilderError when ledger file missing')`.
11. `it('emits provenance.sourceCalls listing every ledger entry sourced')`.
12. `it('windowDays defaults to 90 days')`.
13. `it('treats pass→pass as no-op (no regression)')`.

Route tests (≥6):
1. `ingest is idempotent on (system_id, ksi_id, run_id)`.
2. `per-ksi returns rows in ascending date order`.
3. `acknowledge requires authenticated user with role ∈ {system-owner, assessor}`
   (other roles → 403).
4. `acknowledge records both timestamp and acknowledged_by user id`.
5. `acknowledge writes an audit-log entry via existing audit.ts`.
6. `cross-system isolation` — system A token cannot acknowledge system B
   regression.

UI tests (≥4):
1. Renders one sparkline per KSI returned.
2. Open-regressions table acknowledges via API call (mock 200).
3. Empty state when API returns no regressions.
4. Drill-through navigates to `/indicators/<ksi_id>` route.

## REO compliance specific to this slice
- Trend points trace to real `run-ledger.jsonl` entries; the
  `not-collected` fallback is a true representation (data was genuinely
  not collected), not synthetic.
- Regression detection uses real pass/fail transitions only — no threshold
  tuning that could be gamed or fabricated.
- Acknowledgement is a real human action captured in the audit log; never
  auto-acknowledged. The system MUST NOT auto-resolve regressions on
  pass→fail→pass — that masks a real-evidence signal.
- Notification payload is the same JSON written to disk — single source of
  truth.
- Provenance fields populated: `provenance.emitter`,
  `provenance.emittedAt`, `provenance.sourceCalls[]`,
  `provenance.signingKeyId` (filled by `core/sign.ts`).
- `npm run check:provenance` will pass because `trend-analysis.json` has
  a `provenance` block.
- `npm run lint:no-stubs` will pass because the slice emits no
  TODO / placeholder / sample literals.

## Verification commands
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/trend-analysis.test.ts
npm run check:reo

cd "/Users/kenith.philip/FedRAMP 20x/tracker"
npm test -- server/routes/trends.test.ts
npm test -- client/src/pages/TrendAnalysis.test.tsx
```

End-to-end smoke (requires ≥2 ledger entries):
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run collect -- --trend-analysis --sign --system-id acme-saas
jq -e '.points | length > 0' out/trend-analysis.json
ls out/trend-regressions-*.json 2>/dev/null || \
  echo "no regressions detected (expected when posture is stable)"
```

## Known risks / issues
- **Risk 1 — Transient-error false positives.** A single-finding KSI that
  flips on a transient SDK error would trigger a regression alert.
  Mitigation: the existing `core/retry.ts` retry-with-backoff already
  filters transient errors before they reach findings. Document
  followup option: 2-of-3 confirmation rule (if field experience shows
  residual false positives, add a `--regression-confirm-runs 2` knob).
- **Risk 2 — Notification noise.** A wave of regressions on the same day
  could spam Slack/PagerDuty. Mitigation: notify with a single rolled-up
  message per run, not per regression. The notify wrapper batches by
  default.
- **Risk 3 — Acknowledgement UX bypass.** A 3PAO without proper role
  could attempt to acknowledge. Mitigation: server-side RBAC check is
  authoritative; the UI button is purely cosmetic.
- **Risk 4 — Ledger schema drift.** Older entries lack `ksi_summary`.
  Mitigation: treat as `not-collected` + diagnostic.
- **Risk 5 — Memory pressure on long histories.** A 2-year ledger × 60
  KSIs × daily cadence = ~44k points. Mitigation: stream-process the
  ledger (don't load all entries into memory at once); paginate the API.
- **Risk 6 — Determinism of `analysis_id`.** UUIDv5 from
  `(system_id, range, ledger_tail_hash)` so two runs against the same
  ledger produce the same id.
- **Risk 7 — Notification credentials leak.** The notify wrapper reads
  Slack URL + PagerDuty key from env. Ensure they are NEVER persisted to
  `provenance.sourceCalls` or the disk emit.
- **Risk 8 — Audit-log volume.** Every acknowledge writes an audit entry;
  bulk acknowledgement could spam. Mitigation: bulk-ack flow writes one
  audit entry summarizing the operation.

## Open questions (for implementation session to resolve)
- **Q1**: Should `mixed → fail` be a regression? Current plan: no — a
  KSI already in a failing-mixed state degrading further is not a NEW
  regression. Confirm with stakeholder.
- **Q2**: Should we emit a "recovery" event (fail→pass) for completeness?
  Current plan: no — only regressions trigger alerts. A separate
  recovery feed can be a future slice.
- **Q3**: Per-KSI sparkline color encoding — green=pass, red=fail,
  amber=mixed, gray=not-collected. Confirm accessibility (color-blind)
  with a dual encoding (line style).
- **Q4**: Should the regression file include the FRMR catalog citation
  for the KSI (e.g. KSI-IAM-MFA text)? Current plan: yes, embed the
  catalog `id` + `text` to make the JSON self-contained for downstream
  consumers.
- **Q5**: Should `acknowledged_by` link to `tracker/server/users.ts`
  user_id only, or also store role + name at time of ack? Current
  plan: store the user_id and resolve at render time. Confirm whether
  immutability (role-at-time-of-ack) is required by the audit team.
- **Q6**: Drill-through path — `/indicators/<ksi_id>` exists today?
  Verify in implementation.
- **Q7**: Trend file size — at 60 KSIs × N runs, the points[] array
  grows linearly. Consider segmenting by year if file exceeds 5MB.
- **Q8**: Window for `per_ksi_pass_rate` configurable from UI?
  Current plan: server emits one window (90d); UI can recompute
  client-side for shorter windows.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥13 builder + ≥6 route + ≥4
  UI = ≥23 new tests)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (I.I3 row + Overall section)
- [ ] LOOP-I-SPEC.md status table updated (Section 7)
- [ ] This file's frontmatter updated (status=done, commit=<hash>,
  completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added under
  `### Added — LOOP-I.I3: Longitudinal trend analysis`
- [ ] Commit with `LOOP-I.I3:` prefix in message
- [ ] Commit amended with commit hash recorded in STATUS.md + this file +
  LOOP-I-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context, here's everything it
needs to start:
1. Read `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/CLAUDE.md` (REO
   standard, auto-loaded).
2. This file gives you: source obligations + files to create + build
   steps + tests + risks + completion checklist.
3. Read `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/LOOP-I-SPEC.md`
   Section 2 (Dependencies) + Section 4 / Slice I.I3 for the canonical
   spec.
4. Read `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`
   for the mandatory commit pattern.
5. Read `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/run-ledger.ts`
   + `core/diff-report.ts` + `core/csx-sum-aggregator.ts` + `core/notify.ts`
   to understand the input shapes you'll consume.
6. Read `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sign.ts` for
   signing pipeline. Read `tracker/server/audit.ts` for the audit-log
   API that acknowledge actions must write to.
7. Begin implementation; update Implementation log section as you go.
