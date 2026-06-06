# LOOP-I — Risks Register

> Live document. Implementing sessions add entries during work; resolved
> risks stay in the file with `status=resolved` + resolution note.

> Scope: This register tracks risks that apply across all four LOOP-I
> slices (I.I1 — I.I4) plus slice-specific risks not already covered by
> the per-slice docs at `docs/slices/I/I.I*.md`.

---

## Cross-cutting risks (apply to ALL slices in this loop)

### CC-1 — LOOP-B.B1 / B.B2 / B.B3 dependency ordering
- **Description**: I.I1 + I.I3 depend on LOOP-B.B1 composite-score props
  for full ranking; I.I1 + I.I2 depend on LOOP-B.B2 KEV props for
  overdue counting; I.I2 depends on LOOP-B.B3 for the
  `deviation-approved` lifecycle lane. If LOOP-B has not landed when
  LOOP-I starts, every dependent slice falls back to documented
  baselines + emits a named diagnostic.
- **Severity**: medium
- **Mitigation**: Each I.I* slice's pure builder emits
  `requires_b1_for_full_ranking` / `requires_b2_for_kev_overdue_calc` /
  `requires_b3_for_deviation_lane` diagnostics. UI surfaces them verbatim.
  When LOOP-B slices land, re-running the orchestrator picks up real
  data automatically with no LOOP-I code change.
- **Status**: open

### CC-2 — Real-Evidence-Only (REO) lint:no-stubs false positives
- **Description**: Three new emit files (`posture-snapshot.json`,
  `burndown-series.json`, `trend-analysis.json`,
  `ssp-narrative-library.json`) may contain strings that the G1
  guardrail's stub-detector flags incorrectly (e.g. `requires_*`
  diagnostic codes, mustache `{{var}}` placeholders).
- **Severity**: high
- **Mitigation**: Run `npm run lint:no-stubs` AFTER each new emit type
  is added. If G1 flags a string, either:
  (a) place the file under `docs/` (excluded), OR
  (b) add a narrow allowlist entry to
      `scripts/lint-no-stubs.mjs` naming the specific pattern,
      following CLAUDE.md Rule 3 documentation requirement.
  Document the allowlist addition in the slice's commit message.
- **Status**: open

### CC-3 — Determinism vs `now`-injection across emitters
- **Description**: All four emitters (posture-snapshot,
  burndown-series, trend-analysis, ssp-narrative-library) embed a
  `generated_at` / `emittedAt` timestamp. Naïve `new Date()` makes
  output non-reproducible.
- **Severity**: medium
- **Mitigation**: Every pure builder must accept `now: Date` as an
  injectable parameter. Tests pin it; orchestrator passes `new Date()`
  OR the existing `--mtime` reproducible-build flag. Verify with a
  test `it('produces byte-identical JSON when called twice')` in each
  slice's test suite.
- **Status**: open

### CC-4 — Tracker DB migration ordering
- **Description**: Three new migrations land in sequence:
  `010_posture_snapshots.sql` (I.I1), `011_burndown_history.sql` (I.I2),
  `012_trend_history.sql` (I.I3). If the migration runner is run between
  slice ships, downstream migrations must not assume prior tables exist.
- **Severity**: medium
- **Mitigation**: Each migration uses `CREATE TABLE IF NOT EXISTS`. The
  existing `tracker/server/schema.sql` migration runner loads them in
  numeric order. Confirm sequence by inspecting the runner at the start
  of each slice implementation.
- **Status**: open

### CC-5 — Signature verification key distribution
- **Description**: The signed JSON emits are verified on tracker ingest
  against a pinned Ed25519 public key. If the key rotates between
  emit-time and ingest-time, ingest fails 400.
- **Severity**: medium
- **Mitigation**: Reuse the existing `core/sign.ts` keystore + add a
  tracker-side import command that pulls the public key from the
  keystore at deploy time. Each ingest persists `signingKeyId` alongside
  the row so historical entries verify under their original key.
- **Status**: open

### CC-6 — Cross-system data leakage in tracker routes
- **Description**: All three new UI pages (`/posture`, `/burndown`,
  `/trends`) take `system_id` from the URL/query. A malicious caller
  could swap the parameter and view another tenant's data.
- **Severity**: high
- **Mitigation**: All three route handlers MUST resolve `system_id`
  from the authenticated session token (via existing
  `tracker/server/auth.ts`), not from the query param. If a query
  param is used, the handler MUST check that the param is in the
  session's permitted-systems list. Route-test coverage REQUIRED for
  every slice (Test ID: `cross-system isolation`).
- **Status**: open

### CC-7 — UI dependency creep (charting libraries)
- **Description**: Stakeholders will request fancier visualizations
  (recharts, d3, chart.js). Adding a runtime charting dep violates REO
  Rule 1.4 (no mocked SDK is the same principle: runtime code must be
  real and reviewable, not opaque library output).
- **Severity**: low
- **Mitigation**: Mirror the dependency-free .docx pattern (`core/ssp-docx.ts`
  + `core/roe-emit.ts`). Ship pure-SVG renderers (`burndown-chart.ts` for
  I.I2, `sparkline.ts` for I.I3). Document this constraint in the file
  header comment of each renderer. If a future engineer wants a runtime
  dep, they must justify it via a CLAUDE.md Rule 3 review.
- **Status**: open

### CC-8 — Time-zone confusion (UTC vs local)
- **Description**: ConMon-calendar dates (I.I1), burndown observed-at
  dates (I.I2), and trend observed-at dates (I.I3) are all UTC, but
  stakeholders mentally translate to local time and may interpret a
  date 1 day off.
- **Severity**: low
- **Mitigation**: All UI tile labels include explicit "(UTC)" suffix.
  Tooltips show the local-time equivalent.
- **Status**: open

### CC-9 — Run-ledger backward compatibility
- **Description**: I.I2 + I.I3 extend the `RunLedger` entry schema with
  new optional fields (`lifecycle_breakdown`, `ksi_summary`,
  `poam_risk_count`). Old ledger entries from before LOOP-I land lack
  these fields.
- **Severity**: medium
- **Mitigation**: Both builders treat missing fields as `'not-tracked'`
  / `'not-collected'` AND emit a diagnostic — NEVER fabricate the data.
  Re-collecting old history is NOT in scope. Tests explicitly verify
  legacy-entry handling (`it('marks status not-collected for legacy
  ledger entries')` in I.I3).
- **Status**: open

### CC-10 — Signature size + JSON payload growth
- **Description**: Embedding full POA&M risk objects (I.I1 top_risks)
  + per-KSI history (I.I3 points) + per-day burndown rows (I.I2) +
  full narrative library (I.I4) can grow individual JSON files past
  practical sizes (>1 MB).
- **Severity**: low
- **Mitigation**: I.I1 embeds only top-N risks (default 10). I.I3 +
  I.I2 stream-process ledger entries; the JSON file is bounded by
  `[from, to]` range. I.I4 seed is ~250 entries × multi-line templates
  (~300 KB acceptable).
- **Status**: open

### CC-11 — Notification noise + credentials
- **Description**: I.I3 regression notifications could spam
  Slack/PagerDuty during a wave of regressions; misconfiguration could
  leak the webhook URL into JSON emit.
- **Severity**: medium
- **Mitigation**: Notify wrapper batches by run (one rolled-up message
  per run, not per regression). Credentials read from env, NEVER
  written to `provenance.sourceCalls` or the disk emit. Add a test
  asserting the regression file does not contain `slackUrl` or
  `pagerDutyKey` strings.
- **Status**: open

### CC-12 — Spec drift between this file and individual slice docs
- **Description**: As implementation progresses, risks change. If this
  file diverges from the per-slice docs, future sessions get
  contradictory guidance.
- **Severity**: low
- **Mitigation**: Implementing sessions MUST update both the
  per-slice doc's "Known risks / issues" section AND this cross-cutting
  register when a risk surfaces or is mitigated. The Implementation log
  section in each per-slice doc tracks the running journal.
- **Status**: open

---

## Per-slice risks

### Slice I.I1 — Executive posture dashboard

#### I.I1-R1 — Orchestrator ordering with --sign
- **Description**: `--posture-snapshot` MUST run after `--oscal-poam` and
  BEFORE `--sign`, so the snapshot is included in the signed manifest.
  Incorrect ordering leaves the snapshot unsigned in `out/`.
- **Severity**: high
- **Mitigation**: Hard-code the ordering in `orchestrator.ts`; add a
  guard test that fails the build if the flag ordering is wrong.
- **Status**: open

#### I.I1-R2 — Stakeholder over-reliance on the snapshot
- **Description**: A CISO reading the dashboard may treat
  `passing_ratio.percent = 98%` as "we're FedRAMP-ready" without
  checking the diagnostics panel (e.g.
  `requires_b1_for_full_ranking`).
- **Severity**: medium
- **Mitigation**: UI surfaces diagnostics panel prominently at the top
  (above tiles); make diagnostic count a banner-level alert when > 0.
- **Status**: open

#### I.I1-R3 — Severity-baseline ranking gives misleading top-10 before B.B1
- **Description**: Without composite-score, top-10 is purely
  severity-based — multiple critical risks with the same severity tie
  by deadline + finding_uuid, which may not match remediation priority.
- **Severity**: medium
- **Mitigation**: Diagnostic clearly states "ranked by severity baseline
  only — true composite scoring available after LOOP-B.B1". UI labels
  the column "Composite score (baseline)" not just "Composite score".
- **Status**: open

#### I.I1-R4 — KEV catalog refresh lag
- **Description**: `docs/cisa-kev.generated.json` may lag the live CISA
  feed. A stakeholder might see `overdue_count = 0` when a new BOD
  22-01 entry exists.
- **Severity**: low
- **Mitigation**: `provenance.sourceCalls` records the local file's
  mtime so freshness is visible in the JSON; UI footer surfaces it.
  The existing `core/kev-feed.ts` refresh is responsible for rotation.
- **Status**: open

---

### Slice I.I2 — Finding burndown + deadline pipeline

#### I.I2-R1 — Bootstrap with single ledger entry
- **Description**: First-ever LOOP-I run has only 1 ledger entry; the
  burndown chart is a single point and conveys no trend.
- **Severity**: low (expected; transient)
- **Mitigation**: Emit `requires_run_history_for_burndown` diagnostic;
  UI shows empty-state copy explaining 2-run minimum.
- **Status**: open

#### I.I2-R2 — Deadline-bucket boundary edge case
- **Description**: A finding with exactly 30 days remaining for a
  Critical maps to either `15-30d` or boundary case depending on
  inclusive/exclusive semantics.
- **Severity**: medium
- **Mitigation**: Bucket boundaries are inclusive lower / exclusive
  upper. Documented in `core/burndown-series.ts` header comment +
  asserted in test #4.
- **Status**: open

#### I.I2-R3 — Chart legibility with 30 distinct bands
- **Description**: 5 severities × 6 lifecycles = 30 potential bands;
  most empty in practice. Legend clutter.
- **Severity**: low
- **Mitigation**: Collapse zero-count bands; tooltip reveals the
  underlying breakdown.
- **Status**: open

#### I.I2-R4 — DB row growth
- **Description**: 5 sev × 6 life × daily × N years ≈ 11k rows/yr per
  system. Multi-year retention pushes hundreds of thousands of rows.
- **Severity**: low
- **Mitigation**: Composite UNIQUE index for fast lookup; monthly
  partition pruning script deferred to LOOP-H.H2 (retention).
- **Status**: open

---

### Slice I.I3 — Longitudinal trend analysis

#### I.I3-R1 — Transient-error false positives in regression detection
- **Description**: A single-finding KSI that flips on a transient SDK
  error triggers a regression alert.
- **Severity**: medium
- **Mitigation**: `core/retry.ts` retry-with-backoff already filters
  transient errors before they reach findings. Document follow-up:
  `--regression-confirm-runs 2` knob (deferred unless field experience
  shows residual false positives).
- **Status**: open

#### I.I3-R2 — Acknowledgement RBAC bypass
- **Description**: A 3PAO without proper role could attempt to
  acknowledge a regression via the UI.
- **Severity**: high
- **Mitigation**: Server-side RBAC check is authoritative (existing
  `tracker/server/auth.ts` role gate); UI button is cosmetic. Route
  test asserts 403 for unauthorized role.
- **Status**: open

#### I.I3-R3 — Audit-log volume from bulk acknowledgement
- **Description**: Bulk-ack flow could spam the audit log.
- **Severity**: low
- **Mitigation**: Bulk-ack writes one summary audit entry, not
  per-regression.
- **Status**: open

#### I.I3-R4 — Notification credentials in emit
- **Description**: Misconfiguration could leak `slackUrl` or
  `pagerDutyKey` into `provenance.sourceCalls` or the disk emit.
- **Severity**: high
- **Mitigation**: Test asserts `JSON.stringify(emit).includes(slackUrl)
  === false`. Credentials read from env at notify time, never persisted.
- **Status**: open

---

### Slice I.I4 — SSP narrative library completion

#### I.I4-R1 — lint:no-stubs false positives on seed placeholders
- **Description**: Seed file contains `{{operator_description_for_*}}`
  mustache markers that look like stubs to G1.
- **Severity**: high
- **Mitigation**: Place seed under `docs/` (excluded from G1) OR add a
  narrow allowlist entry naming the marker pattern. Document the
  decision in the slice's commit message and the CLAUDE.md Rule 3
  allowed-exceptions list if the allowlist route is taken.
- **Status**: open

#### I.I4-R2 — Seed regeneration drift
- **Description**: If `core/requirement-playbooks.ts` changes after the
  seed is generated, the seed becomes stale and inconsistent with the
  actual playbook prose.
- **Severity**: medium
- **Mitigation**: `node scripts/extract-narrative-seed.mjs --verify`
  runs in CI (add to `package.json` scripts); mismatch fails the
  build.
- **Status**: open

#### I.I4-R3 — Override file injection risk (HTML / markdown)
- **Description**: A malicious operator override could inject HTML or
  markdown into the SSP description.
- **Severity**: low
- **Mitigation**: Composer treats `template` as plain text (no HTML
  escaping needed for OSCAL JSON); downstream `.docx` renderer in
  SSP-2 handles its own escaping. Document in code comment.
- **Status**: open

#### I.I4-R4 — Backward-compat with existing SSP test fixtures
- **Description**: Existing `tests/core/oscal-ssp.test.ts` fixtures
  expect REQUIRES-OPERATOR-INPUT markers in well-known positions.
- **Severity**: medium
- **Mitigation**: When no override file is provided, the seed's
  `{{operator_description_for_<control_id>}}` markers flow through
  composeNarrative + still emit REQUIRES-OPERATOR-INPUT, preserving
  the test contract. Test #10 asserts this explicitly.
- **Status**: open

#### I.I4-R5 — YAML parsing edge cases
- **Description**: Multi-line templates with embedded YAML special
  characters (`:`, `>`, `|`) can break naïve parsing.
- **Severity**: low
- **Mitigation**: Use the existing `yaml` dep (already in
  package.json); test #3 covers a multi-line template.
- **Status**: open

---

## External dependencies that may change

### Ext-1 — FedRAMP RFC-0014 published version
- **Description**: RFC-0014 is in Phase Two pilot. The KSI text quoted
  in LOOP-I-SPEC.md §3.3 may shift (e.g. KSI-CNA-08 wording, new KSIs
  added).
- **Mitigation**: All LOOP-I emits cite the KSI by ID + verbatim text.
  When RFC-0014 changes, the regression-detection logic does not break
  (status enum is local); only the diagnostic explanations need a
  refresh.
- **Owner**: implementer to monitor https://www.fedramp.gov/rfcs/0014/
  during LOOP-I work + at every fresh-session resumption.

### Ext-2 — NIST SP 800-53 control catalog (Rev 5)
- **Description**: 800-53 Rev 5 control IDs are stable; minor updates
  (e.g. 5.1.0 → 5.2.0) may add new sub-statements. The narrative
  library seed must regenerate.
- **Mitigation**: `extract-narrative-seed.mjs --verify` catches drift.
  Rebase `core/control-benchmark.ts` to the new revision before
  re-generating.
- **Owner**: implementer + a follow-up slice when Rev 5.x ships.

### Ext-3 — OSCAL v1.1.x metaschema
- **Description**: OSCAL v1.1.2 is the pinned version. v1.2.x may
  introduce new fields in
  `control-implementation.implemented-requirements[].statements[].by-components[]`
  that I.I4 should populate.
- **Mitigation**: Existing `core/oscal-validate.ts` ajv-validates emits
  against the pinned schema; an OSCAL upgrade is a separate slice that
  bumps the schema + re-runs validation.
- **Owner**: implementer to track https://github.com/usnistgov/OSCAL/releases

### Ext-4 — CISA Known Exploited Vulnerabilities (KEV) catalog format
- **Description**: CISA may evolve the KEV JSON schema (new fields, BOD
  changes). I.I1 reads `dueDate`; a schema change could break the
  overdue calculation.
- **Mitigation**: `core/kev-feed.ts` validates the catalog on refresh.
  If the schema breaks, the refresh fails loudly; the local catalog
  is not silently corrupted.
- **Owner**: implementer + the existing kev-feed refresh job.

### Ext-5 — Ajv (OSCAL validation) library version
- **Description**: Ajv major-version bumps (8.x → 9.x) may change error
  message formats that LOOP-I tests parse.
- **Mitigation**: Pin ajv to the existing version in package.json;
  test parsers rely on `error.instancePath` not free-text.
- **Owner**: implementer at package.json maintenance time.

### Ext-6 — Tracker DB engine (SQLite WAL mode)
- **Description**: Tracker uses SQLite with WAL. If the engine version
  changes, migration semantics may shift (e.g. `INSERT OR REPLACE`
  triggers).
- **Mitigation**: All three migrations use plain DDL + no triggers.
  Tested against existing SQLite version pinned in tracker setup.
- **Owner**: implementer at tracker dependency-update time.

### Ext-7 — Notify drivers (Slack incoming webhook, PagerDuty Events v2)
- **Description**: Slack and PagerDuty API contracts change. A breaking
  change in the webhook URL signature could silently drop regression
  alerts.
- **Mitigation**: `core/notify.ts` driver wraps both; existing
  integration tests cover the happy path. Document the version
  expectations in the driver header comment.
- **Owner**: implementer + on-call.

---

## Resolved risks (historical)

(Empty initially — populated as risks are resolved. Each resolved entry
preserves the original description + adds `Status: resolved` and a
one-line `Resolution: <commit hash + brief note>`.)
