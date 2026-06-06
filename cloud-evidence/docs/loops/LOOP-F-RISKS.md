# LOOP-F — Risks Register

> Live document. Implementing sessions add entries during work; resolved
> risks stay in the file with status=resolved + resolution note + resolving
> commit hash. Cross-link from each per-slice doc's "Known risks" section
> to the matching entry here when work begins.

Last updated: 2026-06-07
Owner during open work: the session shipping the relevant slice
Review cadence: at every slice-completion commit (per
SLICE-COMPLETION-PROCEDURE.md), the implementing session updates this file
with any new risks observed and resolution notes for any risks closed.

---

## Cross-cutting risks (apply to ALL slices in this loop)

### CR-1 — Tracker scaffolding (LOOP-B.B3) may not exist yet
- **Description**: The LOOP-F-SPEC §2 states that `cloud-evidence/tracker/`
  is sibling to `cloud-evidence/core/` and is created by LOOP-B.B3. As of
  2026-06-07 LOOP-B has not landed; therefore F.F1, F.F2, F.F4, F.F6
  cannot ship without bootstrapping the tracker server + client
  themselves OR waiting on LOOP-B. The risk is mis-scoped slice work or
  duplicated bootstrap code if both LOOP-B and LOOP-F slices bootstrap
  independently.
- **Severity**: high.
- **Mitigation**:
  1. Coordinate with LOOP-B sequencing: ship LOOP-B.B3 FIRST whenever
     possible.
  2. If F.F1 must ship before B.B3, F.F1 includes a minimal tracker
     bootstrap (auth, users table, sessions, RBAC middleware) that B.B3
     extends rather than replaces.
  3. Whichever slice ships first publishes a `tracker/README.md`
     declaring the bootstrap contract; subsequent slices append to it.
- **Status**: open.
- **Touches slices**: F.F1, F.F2, F.F4, F.F6 (every tracker-modifying
  slice).

### CR-2 — OSCAL extension namespace `urn:fedramp:cloud-evidence`
- **Description**: LOOP-F slices add custom `props[]` entries
  (`assessor-signoff-uuid`, `comment-uuid`, `collector-derived-status`,
  `signoff-missing`, `redaction-applied`, `walkthrough-missing`,
  `sha256`, `bytes`) under namespace `urn:fedramp:cloud-evidence`. If
  FedRAMP publishes an official OSCAL extension namespace (RFC-0024 is
  the current relevant RFC), every emitter must switch namespaces AND
  ship a migration utility for prior runs. Today's namespace is a
  reasonable URN-style placeholder; it is not an officially
  recognized namespace.
- **Severity**: medium.
- **Mitigation**:
  - Centralize the namespace constant `CE_NS` in `core/oscal-poam.ts`
    so a single edit propagates.
  - When FedRAMP publishes guidance, ship one slice that flips the
    constant + a backfill utility that rewrites historical runs.
  - In the meantime, document the namespace in every emitter's header
    comment so downstream consumers know it is non-canonical.
- **Status**: open.
- **Touches slices**: F.F1, F.F2, F.F4, F.F7.

### CR-3 — `--ingest-*` orchestrator-tracker network coupling
- **Description**: F.F1 (`--ingest-signoffs`), F.F2 (`--ingest-comments`),
  F.F4 (`--ingest-walkthrough`) all depend on the orchestrator being
  able to reach the tracker via HTTP at run time. In disconnected /
  airgapped environments (which FedRAMP HIGH and many FedRAMP MOD
  customers operate in), the network call fails and the AR emits with
  REQUIRES-OPERATOR-INPUT markers — but the operator may want a
  fully-populated AR.
- **Severity**: medium.
- **Mitigation**:
  - Each `--ingest-*` flag accepts a `=<file>` form that reads a
    pre-exported tracker JSON instead of hitting the network. The
    tracker UI provides a "download for offline orchestrator" button
    that exports the same JSON the API returns.
  - Document the airgapped flow in `RUNBOOK.md` as a follow-up.
- **Status**: open.
- **Touches slices**: F.F1, F.F2, F.F4.

### CR-4 — Determinism of .docx output across slices
- **Description**: F.F5 (recommendation letter) and F.F7 (SAR draft) emit
  .docx files that must be byte-identical for byte-identical input to
  satisfy the "deterministic output" tests AND to make the bundle's
  signed manifest stable across orchestrator re-runs. Any leak of
  `Date.now()`, `Math.random()`, OOXML attribute ordering, or
  filesystem walk order breaks determinism.
- **Severity**: medium.
- **Mitigation**:
  - All renderers take an `emittedAt` opts field (deterministic default
    from runId).
  - The `core/zip.ts` helper sorts parts deterministically.
  - OOXML attribute serializer uses a canonical ordering.
  - Every .docx slice ships a "byte-identical determinism" test.
- **Status**: open.
- **Touches slices**: F.F5, F.F7.

### CR-5 — Conditional-language guard false positives
- **Description**: The RAR Guide v3.2 §3.1 unambiguous-language rule is
  enforced via a denylist of phrases (`subject to`, `pending`,
  `contingent on`, etc.). The guard fires on word-boundary matches in
  the relevant sections. A legitimate system name like "Pending Action
  Review System" would throw `ForbiddenLanguageError` at render time
  and force the operator to rename the system or rephrase. This is
  intentional but produces operator surprise.
- **Severity**: low.
- **Mitigation**:
  - Document the denylist verbatim in the slice docs.
  - Emit a precise error message naming the phrase and the section so
    the operator can target the fix.
  - Provide an "explanation" doc page describing why the guard exists
    (RAR Guide quote).
- **Status**: open.
- **Touches slices**: F.F5, F.F7.

### CR-6 — Signature-cell auto-fill regression
- **Description**: REO Rule 1.10 forbids auto-generated assessor / 3PAO
  sign-offs. Every .docx slice ships an explicit test that the
  signature block remains REQUIRES-OPERATOR-INPUT regardless of input
  state. A future refactor that "improves" the renderer to "fill in
  obvious cells" could silently violate this rule.
- **Severity**: high.
- **Mitigation**:
  - Test #16 in F.F7, test #17 in F.F5: assert literal
    REQUIRES-OPERATOR-INPUT in signature cells across every input
    permutation.
  - `lint:no-stubs` (REO G1) catches any literal "sign on behalf of"
    string in production paths.
- **Status**: open.
- **Touches slices**: F.F5, F.F7.

### CR-7 — Bundle size growth from walk-through artifacts
- **Description**: F.F4 attaches arbitrary upload-sized artifacts
  (`.png`, `.har`, `.pcap`) per finding. A 100-finding × 5-artifact ×
  20-MiB build is 10 GiB. The submission bundle becomes too large to
  ship through normal mail / portal upload paths.
- **Severity**: medium.
- **Mitigation**:
  - Per-run guardrail in the bundler that warns when
    `evidence-walkthrough/**` exceeds 2 GiB.
  - Document the size budget in `RUNBOOK.md`.
  - Future LOOP-H slice may add an offline-only manifest mode where
    the bundle ships a manifest of external-storage URLs instead of
    the binaries themselves.
- **Status**: open.
- **Touches slices**: F.F4, F.F7, LOOP-A.A4 (consumer).

### CR-8 — REO-G3 (check:provenance) regressions
- **Description**: Every new emit-field needs a `provenance` entry or
  a `coverage_source` entry. LOOP-F adds many new fields across 7
  slices. A missed registration breaks the build.
- **Severity**: medium.
- **Mitigation**:
  - Each slice's "REO compliance specific to this slice" section lists
    every new emit field.
  - The CHANGELOG entry per slice explicitly notes provenance
    registration.
  - Run `npm run check:provenance` locally before commit per
    SLICE-COMPLETION-PROCEDURE.md Step 1.
- **Status**: open.
- **Touches slices**: ALL.

### CR-9 — Ed25519 holder-key rotation across slices
- **Description**: Multiple LOOP-F slices use Ed25519 signatures (F.F1
  for sign-offs, F.F6 for ATO transitions). If a holder rotates their
  signing key mid-run, prior signatures verify only against the prior
  key. The DB stores `signing_key_id` per record so verification can
  walk back to the historical key.
- **Severity**: low.
- **Mitigation**:
  - Tracker maintains a key registry with historical keys (never
    deletes a retired key, only marks it inactive for new signatures).
  - Verification helper checks every signature against the key
    referenced by `signing_key_id`, not the holder's current key.
- **Status**: open.
- **Touches slices**: F.F1, F.F6.

### CR-10 — Test count target drift
- **Description**: LOOP-F-SPEC §5 declares "Total project test count
  rises from 874 to ≈ 972" (~95 new tests). Per-slice targets:
  F.F1=15, F.F2=14, F.F3=14, F.F4=13, F.F5=14, F.F6=13, F.F7=15. The
  per-slice docs target higher counts (F.F4=20, F.F5=18, F.F6=19,
  F.F7=20) reflecting deeper test specs. If implementation only hits
  the spec's lower number, REO test density falls.
- **Severity**: low.
- **Mitigation**:
  - SLICE-COMPLETION-PROCEDURE Step 1 requires "tests passing 100%
    (count increased by N)" — N is the per-slice doc number, not the
    spec's older number.
  - This file is the canonical reconciliation point.
- **Status**: open.
- **Touches slices**: ALL.

### CR-11 — Tracker DB schema migration ordering
- **Description**: LOOP-F adds 4 new migrations: `0FF1_assessor_signoffs.sql`,
  `0FF2_finding_comments.sql`, `0FF4_walkthrough_evidence.sql`,
  `0FF6_ato_workflow.sql`. Out-of-order application could leave the DB
  in an inconsistent state.
- **Severity**: low.
- **Mitigation**:
  - Tracker `db/migrate.ts` orders migrations lexicographically; the
    `0FF<n>` prefix ensures correct ordering.
  - Each migration is idempotent on re-run (uses `CREATE TABLE IF NOT
    EXISTS`).
  - Tests cover the post-migration schema.
- **Status**: open.
- **Touches slices**: F.F1, F.F2, F.F4, F.F6.

---

## Per-slice risks (not duplicated from cross-cutting)

### F.F1 — 3PAO sign-off UI in tracker
- **F1-R1 — Cartesian product blow-up on the UI**: the AP-derived sign-off
  table is `controls × statements × methods`. For Moderate baseline:
  ~325 × ~3 × ~2 = ~2000 rows. A naive table renders slowly in the
  browser. Severity: medium. Mitigation: virtualised list (only render
  visible rows); per-control accordion grouping; server-side
  pagination on `GET /api/signoffs?run=<id>` (cursor by control-id).
- **F1-R2 — Idempotency edge case for re-sign-off after revoke**: the
  unique index `(run_id, control_id, statement_id, method, revoked_at)`
  allows re-signing AFTER a revoke (because `revoked_at` differs), but
  the implementation needs to ensure the latest non-revoked row is the
  authoritative one. Severity: medium. Mitigation: `listSignoffs`
  filters by `revoked_at IS NULL`; explicit test (#3 + #4 in F.F1
  doc).
- **F1-R3 — AP missing or stale**: if `out/ap.json` is missing, the UI
  cannot render the sign-off table. Severity: low. Mitigation: UI shows
  an explanatory error with a link to the LOOP-A.A2 docs.

### F.F2 — Comment threads on findings
- **F2-R1 — `frozen_at` race with sign-off**: F.F1's `createSignoff`
  freezes comments for the finding. A comment posted in the millisecond
  before the freeze could be lost. Severity: low. Mitigation: the
  signoff service freezes within a DB transaction; concurrent comment
  inserts see the freeze and fail with 409 Locked.
- **F2-R2 — Notification fan-out blast**: a popular finding could have
  20+ commenters; a new comment fires 20+ notifications. Severity: low.
  Mitigation: comment-notifier dedupes per (user, finding) within a
  5-minute window; falls back to per-finding email digest mode if
  `CLOUD_EVIDENCE_DIGEST_MODE=true`.
- **F2-R3 — Markdown XSS via embedded HTML**: comments are stored as
  Markdown but the React renderer may inject HTML. Severity: medium.
  Mitigation: sanitize Markdown via the existing `core/log.ts` HTML
  sanitizer pattern; reject `<script>` tags at the API layer.

### F.F3 — Sample selection methodology auto-derive
- **F3-R1 — Inventory tag drift**: the `is_externally_accessible` field
  depends on operator tagging discipline. Mistagged assets distort the
  sample. Severity: medium. Mitigation: cross-check with
  `network.exposure === 'internet'`; emit a warning when the two
  signals disagree. (Inherited from per-slice doc Risk 2.)
- **F3-R2 — Sample plan re-emission overwrites operator edits**: if the
  operator hand-edits `sampling-methodology.json` and then re-runs the
  orchestrator, the edits are lost. Severity: low. Mitigation:
  `--sampling-methodology` reads the existing file's
  `operator_overrides` and preserves them; only regenerates the
  derived strata.

### F.F4 — Evidence walk-through artifacts
- **F4-R1 — Cross-finding artifact deduplication**: an assessor uploads
  the same screenshot to two findings; the storage layer stores it
  twice. Severity: low. Mitigation: storage helper checks
  `(finding_uuid, sha256)` uniqueness; on duplicate, store a soft-link
  row that points at the existing file. Future enhancement (out of
  scope for v1).
- **F4-R2 — Tracker-bundle drift mid-run**: an artifact deleted after
  AR emit but before bundle pack leaves a dangling AR reference.
  Severity: medium. Mitigation: bundler verifies every
  `evidence-walkthrough/` href and emits `coverage:miss`; documented
  in per-slice doc Risk 5.
- **F4-R3 — OCR-redaction gap on images**: the regex redactor only
  inspects command strings. Visible credentials in PNG screenshots
  remain. Severity: high (security). Mitigation: pre-upload visual-
  review tooltip in UI; out-of-scope for v1; future LOOP-K could add
  OCR-based pre-flight scan.

### F.F5 — 3PAO recommendation letter template
- **F5-R1 — Word-version sym/sdt rendering inconsistency**: per-slice
  doc Risk 4. Severity: low. Mitigation: emit both glyph forms.
- **F5-R2 — Recommendation choice mid-render override**: operator sets
  `--recommendation=recommend` but `conditionsNarrative` is non-empty.
  Should the renderer flag the inconsistency? Severity: low.
  Mitigation: warn (not error) when `recommend` + non-empty
  `conditionsNarrative`; the 3PAO might want to attach background
  context without it being a "condition".
- **F5-R3 — Unsupported FedRAMP recommendation template**: per-slice
  doc Risk 6; mitigation via flip-the-string follow-up slice.

### F.F6 — Full ATO workflow tracker (PM-10)
- **F6-R1 — Auto-progress hook fires on bundle re-emit**: per-slice
  doc Open Question Q5. Severity: low. Mitigation: only emit a
  transition on a fresh emit (track via the bundle's `created_at`
  in `core/submission-bundle.ts`).
- **F6-R2 — Terminal-state regression bug**: per-slice doc Risk 7;
  mitigation via test #19.
- **F6-R3 — Marketplace API name mismatch**: per-slice doc Open
  Question Q6; mitigation via the `external_status` mapping field in
  the export.

### F.F7 — SAR draft generator
- **F7-R1 — Source-file drift mid-render**: per-slice doc Risk 1;
  mitigation via up-front sha256 capture + abort-on-mismatch.
- **F7-R2 — Findings table size**: per-slice doc Risk 2;
  mitigation via header rows + page breaks every 50 rows.
- **F7-R3 — Appendix F (PenTest) REQUIRES-OPERATOR-INPUT until
  LOOP-K**: per-slice doc Open Question Q5; mitigation via marker
  with pointer at the LOOP-K spec.

---

## External dependencies that may change

### EXT-1 — FedRAMP guidance updates
- **What**: FedRAMP may publish updated versions of:
  - SAR Template (current: Rev5, 2024-12-06)
  - 3PAO RAR Guide (current: v3.2, 2024-10-17)
  - SAP Playbook (current: Rev5)
  - ConMon Vulnerability Scanning Playbook (current: Rev5)
- **Impact if changed**:
  - SAR Template section ordering or wording changes → F.F7
    section helpers need re-mapping.
  - RAR Guide unambiguous-language denylist may expand → F.F5 +
    F.F7 conditional-language guards extend.
  - SAP Playbook Appendix B requirements may shift → F.F3 plan
    output structure adjusts.
- **Monitoring cadence**: monthly review of
  https://www.fedramp.gov/announcements/ during the LOOP-F build.
- **Owner during open work**: the session shipping F.F5 / F.F7
  rechecks the cited URLs before commit.

### EXT-2 — NIST publication versions
- **What**: NIST publications cited:
  - SP 800-53 Rev 5 (current: 5.1.1 patch release 2023-09)
  - SP 800-53A Rev 5 (current: 5.1.1 patch 2023-12)
  - SP 800-37 Rev 2 (current: 2018-12 with 2020 errata)
  - SP 800-115 (current: 2008; rev process underway, not landed)
  - SP 800-30 Rev 1 (current: 2012)
- **Impact if changed**:
  - 800-53A Rev 6 would change the determination-statement schema →
    F.F1 sign-off granularity may shift.
  - 800-37 Rev 3 would change the Authorize step task numbering →
    F.F6 PM-10 cite needs update.
- **Monitoring cadence**: monthly check of
  https://csrc.nist.gov/publications/sp.

### EXT-3 — NIST OSCAL versions
- **What**: OSCAL is currently v1.1.2. v1.2.0 has been pre-released
  with breaking changes.
- **Impact if changed**:
  - AR / AP / POA&M emitters (LOOP-A.A1/A2/A3) flip schema → LOOP-F
    consumers reading those files (F.F3 AP, F.F4 AR, F.F7 every
    artifact) update their reader signatures.
  - New OSCAL extension namespace registry (per CR-2) may land.
- **Monitoring cadence**: per-release check of
  https://pages.nist.gov/OSCAL/concepts/release-cycle/.

### EXT-4 — Upstream library updates
- **What**:
  - `ajv` (current: 8.x) — used by `core/oscal-validate.ts`; LOOP-F
    F.F3 + F.F4 + F.F7 reuse it for the new schemas they introduce.
  - OSCAL JSON schemas under `docs/oscal/` — periodic refresh from
    `https://pages.nist.gov/OSCAL/`.
  - `better-sqlite3` (tracker DB) — used by F.F1/F2/F4/F6 migrations.
  - React Testing Library — used by F.F1/F2/F4/F6 UI tests.
- **Impact if changed**: typically backward-compatible at minor
  versions; major bumps require slice-level updates.
- **Monitoring cadence**: dependabot / quarterly `npm outdated`
  review.

### EXT-5 — FedRAMP Marketplace API
- **What**: F.F6 export's `external_status` field will eventually
  mirror the Marketplace API state strings (per per-slice doc Open
  Question Q6). The Marketplace API is not currently public.
- **Impact if changed**: when the API publishes, F.F6 export adds a
  one-shot translation map from internal states to Marketplace
  strings.
- **Monitoring cadence**: quarterly check of
  https://marketplace.fedramp.gov/.

### EXT-6 — FedRAMP 20x program updates
- **What**: FedRAMP 20x is itself in active development. RFCs at
  https://www.fedramp.gov/rfcs/ may add or remove KSIs that affect
  the controls-in-scope set, which propagates into F.F1's sign-off
  table size and F.F7's findings table.
- **Impact if changed**: KSI count changes → AP `reviewed-controls`
  changes → sign-off table re-renders. The tracker should not need
  schema changes; the data flows through unchanged.
- **Monitoring cadence**: per-RFC review during the LOOP-F build.

### EXT-7 — Anthropic Claude API for any LLM-augmented features
- **What**: While LOOP-F itself does not call the Claude API,
  follow-up LOOP-I dashboards may surface LOOP-F data through the
  existing `core/llm-pr-generator.ts` consumer. Anthropic API model
  identifiers can shift (e.g. `claude-3-5-sonnet` → `claude-opus-4.7`).
- **Impact if changed**: out of scope for LOOP-F; tracked here for
  cross-loop awareness.
- **Monitoring cadence**: per Anthropic deprecation announcements.

---

## Resolved risks (historical)

(Empty — populated as risks are resolved. Each entry should follow:
`### RID — Title` + `Resolution: <one-paragraph note>` + `Resolved by:
<commit hash>` + `Resolved date: <ISO>`.)

---

## Risk lifecycle conventions

1. **Open**: actively monitored; mitigation in place but not validated.
2. **In progress**: mitigation being implemented in a current slice.
3. **Mitigated**: mitigation shipped + tested; residual risk acceptable.
4. **Resolved**: root cause removed (typically by a refactor); risk no
   longer applies.

When updating a risk's status, also update its `last_updated` field on
this file's header AND link the relevant commit hash in the resolution
note. Resolved risks remain in this file (do not delete) so the
historical record stays accurate.
