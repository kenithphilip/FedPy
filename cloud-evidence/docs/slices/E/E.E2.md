---
slice_id: E.E2
title: Monthly POA&M Delta Workflow
loop: E
status: pending
commit: —
completed_date: —
depends_on: [A.A1, E.E1]
blocks: [E.E3, I.I2]
estimated_effort: 3 days
last_updated: 2026-06-06
---

# E.E2 — Monthly POA&M Delta Workflow

## TL;DR
Closes the monthly POA&M re-emission loop: reads the prior month's POA&M from a ledger, threads `metadata.revisions[]` forward, re-emits the full OSCAL doc, and produces a Markdown delta (`poam-delta-<YYYY-MM>.md`) for operator review before USDA Connect.gov upload. Without this slice, the monthly POA&M ships as a "fresh" doc with no version chain — a regulator-facing chain-of-custody break.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
Per R2 (`docs/PRE-LOOP-A-RESEARCH-FINDINGS.md`), the monthly POA&M submission is a **full re-upload** with bumped `metadata.last-modified` and an appended `metadata.revisions[]` entry. Currently `core/oscal-poam.ts` accepts `revisionsHistory` as a `PoamEmitOptions` field but **nothing computes the prior history** — the orchestrator passes an empty array.

The OSCAL POA&M v1.1.2 spec REQUIRES revisions to be threaded for repeated emissions of the same POA&M, otherwise downstream consumers cannot reconstruct the version chain. Per the OSCAL POA&M concept layer (<https://pages.nist.gov/OSCAL/concepts/layer/assessment/poam/>): *"The metadata of the POA&M MAY contain revisions information; when a POA&M is re-emitted month-over-month, revisions provide the lineage."*

The Markdown delta is the human-facing companion: before the operator hits "Upload" on USDA Connect.gov, they need to see *exactly* what changed in the POA&M since last month (items opened, items closed, items past deadline, status flips). Today that diff is computed manually by eyeballing two Excel sheets.

## Authoritative sources (with verbatim quotes)
- <https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/plan-of-action-and-milestones/json-reference/> — OSCAL v1.1.2 POA&M JSON reference:
  > "metadata [1]: title [1], last-modified [1], version [1], oscal-version [1]; revisions [0 or 1]: an array of revision entries, each with version [1] and last-modified [1]."
  > "Root cardinalities: poam-items [1] (MINIMUM ONE), observations [0 or 1], risks [0 or 1], findings [0 or 1]."

- <https://pages.nist.gov/OSCAL/concepts/layer/assessment/poam/> — OSCAL POA&M concept layer:
  > "The plan of action and milestones, often known as POA&M, ... shows progress over time as findings are remediated."

- <https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/overview/> — FedRAMP Rev5 ConMon Overview:
  > "Each month, the CSP uploads an up-to-date POA&M and inventory, along with raw vulnerability scan files (when required by agreements with agency customers) and reports to the secure repository."

- <https://www.fedramp.gov/docs/rev5/playbook/csp/authorization/poam/> — FedRAMP Rev5 Playbook §POA&M:
  > "FedRAMP requires Critical and High risks to be remediated within 30 days of discovery, Moderate risks within 90 days of discovery, and Low risks within 180 days of discovery."
  > "CSPs are required to check in with the vendor at least once a month to determine the status of the patch/fix."

- <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf> — NIST SP 800-53 Rev5 CA-5 (page 95):
  > "Develop a plan of action and milestones for the system to document the planned remediation actions of the organization to correct weaknesses or deficiencies noted during the assessment of the controls and to reduce or eliminate known vulnerabilities in the system; and Update existing plan of action and milestones [Assignment: organization-defined frequency] based on the findings from control assessments, independent audits or reviews, and continuous monitoring activities."

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/poam-monthly.ts` — orchestrator wrapper around `emitOscalPoam()` that adds the cross-month delta layer.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/poam-ledger.ts` — append-only JSONL ledger at `out/poam-ledger.jsonl` recording each month's POA&M emission.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/poam-monthly.test.ts` — ~12 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/poam-ledger.test.ts` — ~8 tests.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-poam.ts` — NO schema change. Add exported helper `extractRevisionEntries(doc: OscalPoam): RevisionEntry[]` so the ledger can read prior documents and thread forward.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — gate the monthly delta behind `--conmon-monthly` (set by E.E1). When monthly mode is on AND `--oscal-poam` is on, call `runPoamMonthly()` instead of the raw `emitOscalPoam()` path.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add `Role` `'poam-delta-md'` (filename matcher `/^poam-delta-\d{4}-\d{2}\.md$/`) and `'poam-ledger'` (`poam-ledger.jsonl`, exact match). `'poam-archive'` (regex `/^archive\/poam-\d{4}-\d{2}\.json$/`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sign.ts` — confirm `archive/**` is included in the signed manifest scope; extend if not.

## Schemas / standards
- **OSCAL POA&M v1.1.2** (already in `docs/oscal/oscal_poam_schema.v1.1.2.json`):
  - `metadata.revisions[]` — array of `{version: string, last-modified: string, oscal-version?: string, remarks?: string}` entries. Each monthly re-emission pushes the prior `{metadata.version, metadata.last-modified, oscal-version}` triplet onto this array.
  - `risk.status` enum: `open | investigating | remediating | deviation-requested | deviation-approved | closed` (from the v1.1.2 schema).
- **FedRAMP severity remediation table** (already encoded in `REMEDIATION_DEADLINE_DAYS` in `core/oscal-poam.ts`): Critical 30d, High 30d, Moderate 90d, Low 180d (with 192d accepted-vulnerability threshold).
- **Ledger schema** (one JSON object per line):
  ```ts
  interface PoamLedgerEntry {
    run_id: string;
    report_month: string;       // "YYYY-MM"
    last_modified: string;       // ISO from metadata.last-modified
    version: string;             // metadata.version
    oscal_version: string;       // metadata.oscal-version
    sha256: string;              // hex sha256 of the archived poam.json
    path: string;                // "archive/poam-<YYYY-MM>.json" relative to outDir
    item_count: number;          // poam-items.length
    open_count: number;
    closed_count: number;
    appended_at: string;         // ISO when this ledger line was written
  }
  ```
- **Delta shape**:
  ```ts
  interface PoamDelta {
    report_month: string;
    prior_month?: string;
    added: PoamItemRef[];        // uuid in current but not prior
    closed: PoamItemRef[];       // uuid in prior but not current
    status_changed: Array<{uuid: string; prev_status: string; new_status: string}>;
    severity_changed: Array<{uuid: string; prev: string; new: string}>;
    past_deadline_items: PoamItemRef[]; // deadline < now, status != closed
  }
  ```

## Build steps (concrete, numbered)
1. **Ledger** (`core/poam-ledger.ts`):
   - `appendPoamLedger(outDir: string, entry: PoamLedgerEntry): void` — appends one JSON line to `out/poam-ledger.jsonl`. Uses `fs.appendFileSync` (atomic on POSIX for ≤4KB writes).
   - `readPoamLedger(outDir: string): PoamLedgerEntry[]` — reads + parses every line. Skips empty lines. Throws `PoamLedgerCorruptError` on JSON parse failure naming the offending line number.
   - `loadPriorMonthPoam(outDir: string, currentMonth: string): {doc: OscalPoam; entry: PoamLedgerEntry} | null` — finds the most recent entry strictly before `currentMonth`, loads its file from `archive/poam-<YYYY-MM>.json`. Verifies on-disk sha256 matches ledger entry; throws if mismatch.
2. **Monthly emitter** (`core/poam-monthly.ts`):
   - `runPoamMonthly(opts: PoamMonthlyOptions): PoamMonthlyResult`:
     a. Loads the prior ledger entry + prior POA&M doc (if any).
     b. Calls `emitOscalPoam()` with `revisionsHistory = extractRevisionEntries(priorDoc).concat([priorAsRevision])` (prior month becomes a revision; current becomes new top metadata).
     c. Computes the delta by comparing item-uuids across the two docs (deterministic UUIDs from A.A1 make this work).
     d. Renders Markdown `poam-delta-<YYYY-MM>.md` from the delta.
     e. Archives the just-emitted POA&M to `outDir/archive/poam-<YYYY-MM>.json`.
     f. Appends ledger entry.
3. **Markdown delta template**: 6 sections — (1) Header (system, month, tool version), (2) Summary counts, (3) Added items (table: poam-id, severity, rule, ksi, deadline), (4) Closed items (table), (5) Status changes (table: poam-id, prev_status, new_status, ksi), (6) Past-deadline items (table: poam-id, severity, deadline, days_past_deadline, ksi). All values pulled from real OSCAL JSON, deterministic ordering.
4. **Deterministic UUIDs**: preserve existing `deterministicUuid()` pattern from A.A1. Same finding → same `poam-item.uuid` month over month — this is exactly what makes the diff possible.
5. **First-month case**: when ledger is empty, the delta MD emits a single line: "First month of ConMon operation; no prior POA&M to compare against." (true statement, not a placeholder). Ledger entry is still appended.
6. **Orchestrator wiring**: when `--conmon-monthly` AND `--oscal-poam` are both set, route through `runPoamMonthly()` instead of bare `emitOscalPoam()`.
7. **Submission-bundle**: register `poam-delta-md` + `poam-ledger` + `poam-archive` roles.
8. **Manifest**: ensure `archive/**` is in the signed-file enumeration in `core/sign.ts`.

## REQUIRES-OPERATOR-INPUT fields
None — the entire workflow runs on auto-derived data (the prior POA&M is on disk in the ledger; current POA&M is freshly computed from real envelopes). The only "input" is the `--month` flag from E.E1 (already collected).

If the ledger is empty (first month of operation), the delta MD emits a real true statement, not a placeholder. This is NOT a REQUIRES-OPERATOR-INPUT case.

## Test specifications (≥12 tests)
**`poam-ledger.test.ts` (~8):**
1. `it('appends a ledger entry with sha256 + path + last_modified')` — write one entry, read back via `readPoamLedger`, assert all 11 fields present.
2. `it('reads back appended entries in insertion order')` — append 3, assert order preserved.
3. `it('loads the prior month POA&M from archive directory')` — set up `archive/poam-2026-06.json` + ledger entry, call `loadPriorMonthPoam(out, "2026-07")`, assert doc loaded.
4. `it('returns null when no prior month exists')` — empty ledger → `loadPriorMonthPoam(out, "2026-07")` → `null`.
5. `it('throws PoamLedgerCorruptError on malformed JSONL line')` — write invalid line, assert typed error names line number.
6. `it('throws when archived file sha256 does not match ledger entry')` — tamper archived file, assert `PoamArchiveTamperedError`.
7. `it('does not double-write a ledger entry on idempotent re-run')` — assert ledger length unchanged when same (run_id, report_month) re-emits.
8. `it('readPoamLedger skips empty lines (resilient to trailing newlines)')`.

**`poam-monthly.test.ts` (~12):**
9. `it('runPoamMonthly threads revisions history forward')` — assert new doc's `metadata.revisions[]` length === prior length + 1 AND the last entry's `version` matches the prior `metadata.version`.
10. `it('preserves deterministic UUIDs across months')` — same finding → same uuid across two emissions.
11. `it('computes added items correctly')` — uuid in current but not prior, asserted.
12. `it('computes closed items correctly')` — uuid in prior but not current.
13. `it('detects status_changed items')` — `risk.status` flip from `open` to `remediating` recorded.
14. `it('detects past_deadline items')` — items with `deadline < now AND status != closed` are listed with `days_past_deadline` correct.
15. `it('renders a Markdown delta with all 6 sections')` — section headers present in output.
16. `it('first-month case emits "no prior POA&M" delta cleanly')` — empty ledger → MD has the literal "First month of ConMon operation" line + zero count tables.
17. `it('archives the POA&M to archive/poam-<YYYY-MM>.json')`.
18. `it('ledger entry sha256 matches archived file sha256')`.
19. `it('throws when --month is malformed (not YYYY-MM)')`.
20. `it('skipped_reason=no-failing-findings propagates without ledger growth')` — when zero failing findings, no ledger entry written and no delta MD.
21. `it('past_deadline severity rollup matches REMEDIATION_DEADLINE_DAYS')`.
22. `it('integrates with --oscal-poam end-to-end on real fixtures')`.

## REO compliance specific to this slice
- The delta is derived **entirely** from two real OSCAL POA&M docs (no parallel "shadow" diff database). Item uuids are the diff key — they're deterministic and traceable.
- The archive directory is part of the signed manifest scope (extend `core/sign.ts` if not already covering `archive/**`).
- No silent fallbacks: a failed-load of prior POA&M (corrupt JSON, sha256 mismatch) raises a typed `PriorPoamCorruptError` / `PoamArchiveTamperedError` naming the file path — never silently treats it as "first month".
- Ledger entries are append-only; the workflow NEVER mutates a prior entry.
- Provenance: each delta MD's header carries `tool`, `run_id`, `frmrVersion`, `prior_month`, `current_month`, and a link to the signed manifest.
- Signed by: existing `core/sign.ts` pipeline (Ed25519 + RFC 3161).

## Verification commands
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/poam-monthly.test.ts tests/core/poam-ledger.test.ts
npm run check:reo
```

## Known risks / issues
- **Risk 1: Atomic appends.** `fs.appendFileSync` is atomic on POSIX for ≤ PIPE_BUF (4KB) writes but NOT on Windows. Mitigation: serialize via a file lock (`core/run-lock.ts` already exists); add unit test for concurrent append.
- **Risk 2: Archive directory bloat.** 36 months of archived POA&Ms could be tens of MB. Mitigation: LOOP-H.H1 (immutable evidence archive) will push older archives to cold storage; for now, keep all under `out/archive/`.
- **Risk 3: Cross-emission UUID drift.** If `core/oscal-poam.ts` ever changes how it derives item-uuids (e.g. adds a new field to the canonical-JSON key), the diff breaks silently. Mitigation: lock the UUID-derivation key as a versioned constant (`POAM_UUID_KEY_V1 = ['rule','ksi_id','provider','severity']`); add a regression test that bumps the version if the key changes.
- **Risk 4: `last-modified` timezone.** OSCAL spec requires ISO 8601 — but ambiguous timezone strings break diffs. Mitigation: always emit `Z` suffix (UTC); reject non-Z inputs in `extractRevisionEntries`.
- **Risk 5: First-month false negative.** A genuinely first month vs a missing-ledger-due-to-bug both look like "no prior". Mitigation: emit an explicit `provenance.no_prior_reason: "ledger-empty" | "first-month-flag"` so consumers can distinguish.
- **Risk 6: Status-change false positives from OSCAL spec evolution.** If the `risk.status` enum gains a new value mid-cycle, items might appear changed but actually be unchanged. Mitigation: pin enum to v1.1.2 explicitly in the diff function; raise on unknown values.

## Open questions (for implementation session to resolve)
- **Q1**: Should the delta MD include a "Severity changed" section? The data is present but rare; recommend yes for completeness.
- **Q2**: What is the right behavior when prior POA&M's `metadata.version` is non-monotonic (operator manually edited it)? Recommend: warn + still emit, with `provenance.warnings: ["prior-version-non-monotonic"]`.
- **Q3**: Should `past_deadline_items` use `closed_at` if present, or always compute against `now`? Recommend: compute against the current `metadata.last-modified` time of the POA&M being emitted (deterministic).
- **Q4**: Should the ledger record the sha256 of the **delta MD** as well as the POA&M? Helps chain-of-custody. Recommend yes.
- **Q5**: How do we handle the case where the operator runs `--conmon-monthly --oscal-poam` twice in the same calendar month? Recommend: idempotent — same (run_id, report_month) overwrites archive but doesn't append duplicate ledger entry.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ~20 for this slice's new tests)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (slice row + Overall section)
- [ ] LOOP-E-SPEC.md status table updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added
- [ ] Commit with slice ID in message
- [ ] Commit amended with commit hash recorded in STATUS.md + this file + LOOP-E-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context, here's everything it needs to start:
1. Read `cloud-evidence/CLAUDE.md` (REO standard, auto-loaded).
2. This file gives you: source obligations + files to create + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-E-SPEC.md` Section 2 (Dependencies) for context on this loop.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory commit pattern.
5. Read existing emitter for pattern reference: `core/oscal-poam.ts` (especially `extractRevisionEntries` semantics + deterministic UUIDs).
6. Read `docs/PRE-LOOP-A-RESEARCH-FINDINGS.md` R2 (monthly POA&M format research).
7. Begin implementation; update Implementation log section as you go.
