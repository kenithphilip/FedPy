---
slice_id: I.I2
title: Finding burndown + deadline pipeline
loop: I
status: pending
commit: —
completed_date: —
depends_on: [A.A1, A.A4]
blocks: [G.G6]
estimated_effort: 5 days
last_updated: 2026-06-06
---

# I.I2 — Finding burndown + deadline pipeline

## TL;DR
Ship a `core/burndown-series.ts` builder that walks the existing
`out/run-ledger.jsonl` history plus the current `out/poam.json` to emit a
deterministic time series of `(date × severity × lifecycle × count)` rows
plus a current-state "deadline pipeline" grouping risks into FedRAMP-defined
deadline buckets, then surface them through a dependency-free SVG
stacked-area chart on a tracker `/burndown` page. Lets a remediation lead see
"are we on track to close the Criticals before their FedRAMP deadlines?".

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
Today `out/poam.json` is point-in-time only — there's no longitudinal series
showing whether the open-risk count is going up or down. A remediation lead
must hand-compile spreadsheet history from prior commits of the POA&M. The
FedRAMP ConMon Playbook obligates monthly POA&M uploads with deadline-based
remediation timelines (Critical=30d, High=60d, Medium=90d, Low=180d,
Info=365d); the only way to forecast deadline-miss risk is to plot the open
count trend against those deadlines. This slice closes that gap by
persisting a real `lifecycle_breakdown` summary at the end of every
collector run (in the existing `core/run-ledger.ts`) and aggregating those
summaries into a queryable burndown series.

`out/burndown-series.json` becomes the durable evidence object that LOOP-E.E1
(monthly ConMon analysis report) and LOOP-G.G6 (AFR-CCM report publication)
both reference for the "month-over-month finding closure rate" section.

## Authoritative sources (with verbatim quotes)
- https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/vulnerability-scanning/
  — FedRAMP Rev5 ConMon Playbook (Vulnerability Scanning), retrieved
  2026-06-06:
  > "FedRAMP vulnerability scanning guidelines require at least monthly
  > scans of 100% of inventory components."

  > "The scan output must display all scan findings with a low risk or
  > higher in a structured, machine-readable format (such as XML, CSV, or
  > JSON)."

  Implication: the monthly cadence + machine-readable format mean a
  burndown series of "(date × severity × lifecycle × count)" is the canonical
  durable artifact, not a periodic screenshot.
- https://www.fedramp.gov/assets/resources/FedRAMP-Continuous-Monitoring-Strategy-Guide.pdf
  — FedRAMP Continuous Monitoring Strategy Guide, §3 Remediation deadlines:
  > "POA&M items shall be remediated within timelines based on the risk
  > level of the finding: Critical = 30 days, High = 60 days, Moderate = 90
  > days, Low = 180 days." (As reflected in the FedRAMP POA&M Template
  > Completion Guide.)

  Implication: these are the canonical deadline-bucket boundaries used by
  the `DeadlinePipelineRow.deadline_bucket` enum.
- https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/plan-of-action-and-milestones/json-reference/
  — OSCAL POA&M v1.1.2, `poam-items[].related-risks[].response.lifecycle`:
  > "The actions taken to address an identified risk. Lifecycle:
  > recommendation, planned, in-progress, completed."

  Implication: these four values are the canonical Y-axis grouping for the
  stacked-area chart; `deviation-approved` is added as an explicit FedRAMP-
  specific value when LOOP-B.B3 ships.
- https://csrc.nist.gov/pubs/sp/800/137/final — NIST SP 800-137 §3.5
  ("Respond to findings"):
  > "Risk responses include responses such as accepting, avoiding,
  > mitigating, sharing, or transferring risk."

  Implication: the lifecycle taxonomy must accommodate `deviation-approved`
  (FedRAMP analogue of "accepting" risk under documented justification).
- https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final — NIST SP 800-53 Rev 5
  control CA-5 (Plan of Action and Milestones), p. 78:
  > "Update the existing plan of action and milestones based on the findings
  > from control assessments, security impact analyses, and continuous
  > monitoring activities; and report the contents of the plan of action and
  > milestones in accordance with organizational reporting requirements."

  Implication: the burndown is the operational evidence that CA-5 is being
  satisfied between assessments.

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/burndown-series.ts`
  — pure builder (`buildBurndownSeries`) + disk emitter
  (`emitBurndownSeries`) + typed errors (`BurndownBuilderError`,
  `MissingLedgerError`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/burndown-series.test.ts`
  — ≥12 unit tests.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/burndown.ts` —
  `POST /api/burndown/ingest`,
  `GET /api/burndown/series?system_id&from&to`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/burndown.test.ts`
  — ≥4 route tests.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/db/migrations/011_burndown_history.sql`
  — append-only point table.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/FindingBurndown.tsx`
  — React page (top half = stacked-area chart; bottom half = pipeline
  table).
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/FindingBurndown.test.tsx`
  — ≥4 component tests.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/lib/burndown-chart.ts`
  — dependency-free SVG renderer (`buildSvg(points, opts) → string`),
  mirroring the dependency-free .docx pattern in `core/ssp-docx.ts` +
  `core/roe-emit.ts`. No `recharts`, no `d3` runtime dependency.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` —
  add `--burndown-series` flag + `CLOUD_EVIDENCE_BURNDOWN_SERIES` env. Slot
  after `--oscal-poam`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
  — register role `'burndown-series'`, filename `burndown-series.json`,
  `required: false`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/run-ledger.ts` —
  extend `RunLedger.append()` payload with optional
  `{poam_risk_count: number, lifecycle_breakdown: Record<Lifecycle,
  Record<Severity, number>>}` so the burndown builder has historical anchors.
  Backward-compatible: old ledger entries without these fields are skipped
  by the builder (treated as historical gap, not synthetic).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/index.ts` — mount
  `/api/burndown` router.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/lib/api.ts` — add
  `burndownSeries({system_id, from, to})` fetch wrapper.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/App.tsx` — add
  `/burndown` route.

## Schemas / standards
- **OSCAL POA&M lifecycle**: enum `recommendation | planned | in-progress |
  completed` (per OSCAL v1.1.2). Augmented with `deviation-approved` for
  LOOP-B.B3 risks and `not-tracked` for legacy ledger entries.
- **FedRAMP severity-to-deadline bucket table** (already encoded in
  `core/oscal-poam.ts`):
  - Critical: 30d → `≤7d | 8-14d | 15-30d | overdue`.
  - High: 60d → `≤14d | 15-30d | 31-60d | overdue`.
  - Medium: 90d → `≤30d | 31-60d | 61-90d | overdue`.
  - Low: 180d → `≤60d | 61-120d | 121-180d | overdue`.
  - Info: 365d → `≤180d | 181-365d | overdue`.
- **Run ledger** (`core/run-ledger.ts`): append-only JSONL at
  `out/run-ledger.jsonl`. The slice EXTENDS the entry schema additively
  (new optional fields).

## Build steps (concrete, numbered)
1. Define types in `core/burndown-series.ts`:
   ```ts
   export type Lifecycle = 'recommendation' | 'planned' | 'in-progress'
     | 'completed' | 'deviation-approved' | 'not-tracked';
   export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
   export interface BurndownPoint {
     date: string; run_id: string; severity: Severity;
     lifecycle: Lifecycle; count: number;
   }
   export interface DeadlinePipelineRow {
     finding_uuid: string; title: string; severity: Severity;
     lifecycle: Lifecycle; deadline: string;
     days_until_deadline: number;
     deadline_bucket: '≤7d' | '8-14d' | '15-30d' | '31-60d' | '61-90d'
       | '91-180d' | '181-365d' | 'overdue' | 'no-deadline';
   }
   export interface BurndownSeries {
     series_id: string; system_id: string;
     range: { from: string; to: string };
     points: BurndownPoint[];
     current_pipeline: DeadlinePipelineRow[];
     diagnostics: string[];
     provenance: { emitter: 'core/burndown-series.ts'; emittedAt: string;
                   sourceCalls: string[]; signingKeyId?: string };
   }
   ```
2. Pure builder:
   `buildBurndownSeries(input, opts) → BurndownSeries`. Signature per
   LOOP-I-SPEC.md §4 / Slice I.I2 / Build step 2.
3. Series computation: for each ledger entry within `[from, to]`, emit one
   `BurndownPoint` per `(severity × lifecycle)` cell using stored
   `lifecycle_breakdown`. For the current POA&M, emit a final-row set at
   `now.toISOString().slice(0,10)`. <2 entries → push
   `'requires_run_history_for_burndown'` diagnostic.
4. Deadline pipeline: walk `currentPoam.risks[]` where
   `lifecycle ≠ 'completed'`. Compute `days_until_deadline =
   daysBetween(now, risk.deadline)`. Assign `deadline_bucket` per the
   severity table above. `'no-deadline'` only when `risk.deadline` literally
   absent.
5. Disk emitter:
   `emitBurndownSeries({outDir, systemId, from?, to?, now?}) → {path,
   series}`. Reads `outDir/run-ledger.jsonl` + `outDir/poam.json`. Throws
   `MissingLedgerError` if ledger absent. Writes JSON with provenance.
6. Wire orchestrator: `--burndown-series` after `--oscal-poam`. The
   run-ledger extension records `lifecycle_breakdown` summary at run
   completion so the NEXT invocation has the historical anchor.
7. SVG chart renderer `tracker/client/src/lib/burndown-chart.ts`:
   `buildSvg(points: BurndownPoint[], opts: {width, height, palette}):
   string`. Renders:
   - `<svg viewBox="0 0 W H">` root.
   - Gridlines + axis tick marks.
   - One `<polygon>` per `(severity × lifecycle)` band (stacked).
   - Date labels along X axis (rotated 30° for density).
   - Severity color encoding: critical=#dc2626, high=#ea580c,
     medium=#ca8a04, low=#16a34a, info=#0284c7.
   - Lifecycle pattern (cross-hatch, dots, solid) so colorblind viewers
     can distinguish lifecycle when severity overlaps.
8. Tracker DB migration `011_burndown_history.sql`:
   ```sql
   CREATE TABLE IF NOT EXISTS burndown_points (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     system_id TEXT NOT NULL,
     observed_at TEXT NOT NULL,
     run_id TEXT NOT NULL,
     severity TEXT NOT NULL,
     lifecycle TEXT NOT NULL,
     count INTEGER NOT NULL,
     UNIQUE(system_id, observed_at, run_id, severity, lifecycle)
   );
   CREATE INDEX IF NOT EXISTS idx_burndown_system_time
     ON burndown_points(system_id, observed_at);
   ```
9. Tracker routes:
   - `POST /api/burndown/ingest` — accepts signed payload, verifies
     signature, `INSERT OR IGNORE` for idempotency.
   - `GET /api/burndown/series?system_id&from&to` — returns points plus
     a server-computed current pipeline snapshot for the latest run.
10. UI page `FindingBurndown.tsx`:
    - Top half: stacked-area chart (full width). Date-range picker
      defaults to 90 days.
    - Bottom half: "Deadline pipeline" table grouped by `deadline_bucket`
      (rows: overdue → ≤7d → 8-14d → …). Each row shows title, severity
      pill, deadline + days-until.
    - Empty state: "Less than 2 runs of history found. Burndown requires
      at least 2 historical POA&M snapshots."
11. Submission-bundle catalogue entry: role=`burndown-series`,
    filename=`burndown-series.json`, required=`false`,
    description=`"Finding burndown + deadline pipeline time-series
    (LOOP-I.I2)"`.
12. Sign + timestamp: covered by existing `core/sign.ts` pipeline.

## REQUIRES-OPERATOR-INPUT fields
None. The burndown is fully auto-derived from the run-ledger + POA&M. The
only operator-input field consumed indirectly is `system_id` (already
established by upstream LOOP-A.A2 wiring).

## Test specifications (≥12 tests)
1. `it('builds a series with one point per (date × severity × lifecycle)')`
   — Fixture: 3 ledger entries with `lifecycle_breakdown`. Asserts point
   count = entries × distinct (sev,life) cells.
2. `it('emits a single-point series + requires_run_history diagnostic when ledger has < 2 entries')`.
3. `it('respects from/to range filtering')` — ledger spans 6 months;
   range=last 30 days. Asserts only in-range points returned.
4. `it('assigns deadline_bucket correctly per FedRAMP severity table')` —
   Table-driven test for all 5 severities × all 4 buckets.
5. `it('marks overdue when deadline < now')`.
6. `it('skips completed risks from current_pipeline')`.
7. `it('handles deviation-approved lifecycle (LOOP-B.B3 hook)')` — Fixture
   with `deviation-approved` lifecycle survives + appears in chart band.
8. `it('is deterministic given identical inputs')` — Run builder twice;
   `JSON.stringify` equal.
9. `it('throws MissingLedgerError when ledger file missing')`.
10. `it('emits provenance.sourceCalls listing each ledger entry source')`.
11. `it('treats ledger entries without lifecycle_breakdown as not-tracked, not synthetic')`.
12. `it('caps points per day to prevent runaway file size')` — sanity check.

Route tests (≥4):
1. `ingest is idempotent on (system_id, observed_at, run_id, severity, lifecycle)`
   — same payload posted twice → no duplicate row.
2. `range query returns rows in ascending date order`.
3. `rejects payload with invalid signature → 400`.
4. `cross-system isolation` — system A token cannot read system B data.

UI tests (≥4):
1. SVG chart renders N bands for N (severity × lifecycle) combinations.
2. Pipeline table sorts overdue → ≤7d → … correctly.
3. Empty-state when API returns < 2 points.
4. Date-range picker propagates new range to API call.

Chart renderer tests (≥3):
1. `buildSvg([])` returns a minimal valid SVG (empty plot area, axes).
2. `buildSvg(points)` includes one polygon per band.
3. Axes have at least one tick per data point + month-grouping label.

## REO compliance specific to this slice
- Series data traces to `out/run-ledger.jsonl` (existing append-only ledger)
  + `out/poam.json` (LOOP-A.A1). NO synthetic historical data.
- When history is insufficient, the system emits a diagnostic + a
  single-point series (a true representation, not a stub).
- Chart renderer is pure-SVG no-runtime-deps; no charting library is
  required to ship under REO Rule 1.4 (no mocked runtime libraries).
- `not-tracked` lifecycle is the honest representation of legacy ledger
  entries — it is NOT a placeholder under REO Rule 1.2.
- Provenance fields populated: `provenance.emitter`,
  `provenance.emittedAt`, `provenance.sourceCalls[]`.
- Signed by existing `core/sign.ts` Ed25519 + RFC 3161 pipeline.

## Verification commands
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/burndown-series.test.ts
npm run check:reo

cd "/Users/kenith.philip/FedRAMP 20x/tracker"
npm test -- server/routes/burndown.test.ts
npm test -- client/src/pages/FindingBurndown.test.tsx
npm test -- client/src/lib/burndown-chart.test.ts
```

End-to-end smoke:
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run collect -- --burndown-series --sign --system-id acme-saas
jq -e '.points | length > 0' out/burndown-series.json
jq -e '.current_pipeline | type == "array"' out/burndown-series.json
```

## Known risks / issues
- **Risk 1 — History bootstrap.** First-ever run has only 1 ledger entry;
  the burndown is a single point and conveys no trend. Mitigation: emit
  `'requires_run_history_for_burndown'` diagnostic; UI shows empty-state
  copy explaining the 2-run minimum.
- **Risk 2 — Ledger schema drift.** Older ledger entries (pre-LOOP-I)
  lack `lifecycle_breakdown`. Mitigation: builder treats them as
  `not-tracked` and pushes a per-entry diagnostic counter. Re-collecting
  history is NOT in scope — that would fabricate data.
- **Risk 3 — Recharts/D3 temptation.** UI engineers may push for a
  charting library. Mitigation: ship pure-SVG renderer per the
  `ssp-docx.ts` precedent; document the REO Rule 1.4 review requirement
  in `burndown-chart.ts` header comment.
- **Risk 4 — Chart legibility at 90 bands.** 5 severities × 6 lifecycles
  = 30 bands; many empty. Mitigation: collapse zero-count bands; tooltip
  reveals the underlying breakdown.
- **Risk 5 — Time-zone drift between collector run and UI.** Mitigation:
  store `observed_at` in ISO 8601 UTC; UI shows UTC by default with a
  toggle to local.
- **Risk 6 — DB row explosion.** 5 severities × 6 lifecycles × daily
  cadence × N years = ~11k rows/yr per system. Mitigation: composite
  unique index + monthly partition pruning script (deferred to LOOP-H.H2
  retention).
- **Risk 7 — Deadline bucket edge case at exact boundary.** A finding
  with exactly 30 days remaining for a Critical → `15-30d` or boundary
  case. Mitigation: spec the boundary explicitly (≤ inclusive lower,
  exclusive upper) in test #4 + comment in code.

## Open questions (for implementation session to resolve)
- **Q1**: Should the "current_pipeline" row include `completed` risks
  closed within the last 30 days for visibility? Current plan: no —
  pipeline shows OPEN findings only. A separate "recently closed"
  section can be added later if requested.
- **Q2**: For the X-axis, sparse-data days should be omitted or shown as
  zero? Current plan: omit days with no ledger entry (chart is event-
  based, not calendar-based). Confirm with stakeholder.
- **Q3**: Should `current_pipeline` be sorted by `deadline` ascending or
  by `deadline_bucket` ordinal? Current plan: deadline_bucket ordinal
  (overdue first), then deadline ascending within bucket.
- **Q4**: Is `info` severity always shown or hidden by default? Some CSPs
  treat `info` as advisory-only. Current plan: shown by default;
  UI checkbox to hide.
- **Q5**: For the LOOP-B.B3 `deviation-approved` lane: should it appear
  in the chart even when the count is zero (to teach the viewer about
  the lifecycle)? Current plan: hide empty bands.
- **Q6**: Range picker presets — 30 / 90 / 180 / 365 days, or 1m / 3m /
  6m / 1y? Current plan: days-based since FedRAMP deadlines are days.
- **Q7**: Does the chart need printable mode for the LOOP-G.G6 monthly
  PDF? If yes, the SVG renderer needs a "print" variant (white
  background, no shadows). Defer to LOOP-G.G6 implementation; the
  renderer should already produce a clean SVG.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥12 builder + ≥4 route + ≥4
  UI + ≥3 chart = ≥23 new tests)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (I.I2 row + Overall section)
- [ ] LOOP-I-SPEC.md status table updated (Section 7)
- [ ] This file's frontmatter updated (status=done, commit=<hash>,
  completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added under
  `### Added — LOOP-I.I2: Finding burndown + deadline pipeline`
- [ ] Commit with `LOOP-I.I2:` prefix in message
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
   Section 2 (Dependencies) + Section 4 / Slice I.I2 for the canonical
   spec.
4. Read `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`
   for the mandatory commit pattern.
5. Read `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/run-ledger.ts`
   + `core/oscal-poam.ts` to understand the input shapes you'll consume.
6. Read `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ssp-docx.ts`
   + `core/roe-emit.ts` to understand the dependency-free renderer
   precedent (mirror that pattern in `burndown-chart.ts`).
7. Begin implementation; update Implementation log section as you go.
