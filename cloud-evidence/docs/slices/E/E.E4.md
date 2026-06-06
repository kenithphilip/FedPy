---
slice_id: E.E4
title: Annual SSP Review / Update Workflow
loop: E
status: pending
commit: —
completed_date: —
depends_on: [A.A2, E.E3]
blocks: [E.E3, F.F7]
estimated_effort: 4 days
last_updated: 2026-06-06
---

# E.E4 — Annual SSP Review / Update Workflow

## TL;DR
Closes the annual System Security Plan (SSP) review loop required by NIST SP 800-53 Rev5 PL-2.b: diffs the current `ssp.json` (emitted by `core/oscal-ssp.ts`) against the prior-year archived SSP, renders a Markdown sign-off doc (`ssp-annual-diff-<YYYY>.md`) with five sections (changed controls, added/removed components, narrative deltas, attestation), and archives the current SSP into `outDir/archive/ssp-<YYYY>.json`. Operator signs the attestation out-of-band; the system never auto-fills the signature cell.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
NIST SP 800-53 Rev5 control PL-2.b requires that system security plans be "reviewed and updated" on a defined frequency — for FedRAMP Moderate the frequency is **annual** per the FedRAMP Rev5 Continuous Monitoring Strategy. Today the codebase emits a fresh SSP on demand via `--oscal-ssp` (LOOP-A.A2) but has no mechanism to (a) prove an annual review took place, (b) diff this year's SSP against last year's, or (c) capture the CSP system owner's attestation that the SSP reflects the current as-built system.

Without this slice, the annual assessment package (E.E3) ships a fresh SSP with no audit trail proving the operator actually reviewed it. The 3PAO has no diff to focus testing on — they must re-test every control, inflating cost. The PMO has no evidence the CSP fulfilled PL-2.b.

E.E4 closes the gap by producing a content-derived diff (sha256 of canonical JSON per control implementation / component / user) and rendering a sign-off Markdown that the operator commits to the tracker after attestation. The diff is content-derived (not narrative-paraphrased) so the diff text is byte-stable and auditable.

Maps to:
- NIST SP 800-53 Rev5 PL-2.b ("Review and update the system security plan [Assignment: organization-defined frequency] or when required due to [Assignment: organization-defined events]")
- NIST SP 800-53 Rev5 CA-7 (b) — ConMon includes "ongoing review and update of system security plans"
- FedRAMP Rev5 ConMon Strategy §"Annual SSP Update"
- FedRAMP 20x Phase Two Moderate KSI requirements for SSP currency

## Authoritative sources (with verbatim quotes)
- <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf> — NIST SP 800-53 Rev5 control PL-2 (page 207):
  > "PL-2 System Security and Privacy Plans — [Assignment: organization-defined personnel or roles] reviews the plans [Assignment: organization-defined frequency]; updates the plans to address changes to the system and environment of operation or problems identified during plan implementation or control assessments; and protects the plans from unauthorized disclosure and modification."
  > "Control Enhancement (3) PLAN / COORDINATE WITH OTHER ORGANIZATIONAL ENTITIES: Plan and coordinate security- and privacy-related activities affecting the system with [Assignment: organization-defined individuals or groups] before conducting such activities to reduce the impact on other organizational entities."

- <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf> — NIST SP 800-53 Rev5 control CA-7 (page 99):
  > "[g.] Reporting the security and privacy status of the system to [Assignment: organization-defined personnel or roles] [Assignment: organization-defined frequency]."

- <https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/overview/> — FedRAMP Rev5 Playbook §ConMon Overview:
  > "Each month, the CSP uploads an up-to-date POA&M and inventory, along with raw vulnerability scan files (when required by agreements with agency customers) and reports to the secure repository."

- <https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/system-security-plan/json-reference/> — OSCAL SSP v1.1.2 JSON Reference (root `system-security-plan`):
  > "system-security-plan [1]: uuid [1], metadata [1], import-profile [1], system-characteristics [1], system-implementation [1], control-implementation [1]; back-matter [0 or 1]"
  > "metadata [1]: title [1], last-modified [1], version [1], oscal-version [1]"
  > "revisions [0 or 1]: array of revision objects each requiring version [1]"

- <https://elevateconsult.com/insights/fedramp-conmon-deliverables-essential-evidence-requirements-guide-2026/> — ConMon Evidence Guide 2026 §Annual Cycle:
  > "Annual Assessment costs will be about 80% of your original Assessment ..."
  > "Fresh evidence each year (previous assessment evidence cannot be reused); Security Assessment Report documenting all findings."

- <https://csrc.nist.gov/glossary/term/system_security_plan> — NIST Glossary (CNSSI 4009 derived):
  > "Formal document that provides an overview of the security requirements for an information system and describes the security controls in place or planned for meeting those requirements."

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ssp-annual-review.ts` — annual-cycle wrapper that orchestrates the diff + archive + sign-off Markdown emission. ~350 LOC.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ssp-diff.ts` — pure function `diffSsp(prior, current): SspDiff` using sha256 of canonical JSON per element. ~400 LOC.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/ssp-annual-review.test.ts` — ~12 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/ssp-diff.test.ts` — ~10 tests.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-ssp.ts` — add an exported helper `extractSspIndex(doc: OscalSsp): { controlImplementations: Map<string, string>; components: Map<string, string>; users: Map<string, string>; metadata: Map<string, string> }`. Pure function that walks the doc once and returns content-hashes per element. No schema change.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — add `--ssp-annual-review` flag + `--prior-ssp-path <path>` flag + `--ssp-attested-by <name>` + matching `CLOUD_EVIDENCE_*` envs. Run AFTER `--oscal-ssp` so current `ssp.json` is on disk.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add Role `'ssp-annual-diff'` (regex `/^ssp-annual-diff-\d{4}\.md$/`, required=false) and `'ssp-archive'` (regex `/^archive\/ssp-\d{4}\.json$/`, required=false) to `WELL_KNOWN`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sign.ts` — verify `archive/**` is in the signed scope; extend the glob if not.

## Schemas / standards
**`SspDiff` shape**:

```ts
export interface SspDiff {
  prior_uuid: string;
  current_uuid: string;
  prior_last_modified: string;
  current_last_modified: string;
  prior_version: string;
  current_version: string;
  changed_controls: Array<{
    control_id: string;           // e.g. "ac-2"
    prev_hash: string;            // sha256 of canonical JSON of the prior control-implementation block
    new_hash: string;
    field_changes: string[];      // e.g. ["description", "responsible-roles[].role-id"]
  }>;
  added_components: Array<{ uuid: string; title: string; type: string }>;
  removed_components: Array<{ uuid: string; title: string; type: string }>;
  added_users: Array<{ uuid: string; title: string }>;
  removed_users: Array<{ uuid: string; title: string }>;
  metadata_changes: string[];     // e.g. ["title", "responsible-parties[].role-id"]
  summary: {
    controls_changed: number;
    components_delta: number;
    users_delta: number;
    narrative_changed: boolean;   // true iff any control's `description` text differs
  };
  provenance: {
    emitter: 'core/ssp-diff.ts';
    prior_source_path: string;
    current_source_path: string;
    diff_algorithm: 'sha256-canonical-json-per-element';
    canonical_serializer: 'json-stable-stringify@1';
  };
}
```

**OSCAL SSP v1.1.2 schema** — required root fields per <https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/system-security-plan/json-reference/>:
- `system-security-plan.uuid [1]`
- `system-security-plan.metadata [1]` (title, last-modified, version, oscal-version)
- `system-security-plan.import-profile [1]` (href)
- `system-security-plan.system-characteristics [1]`
- `system-security-plan.system-implementation [1]` (users, components)
- `system-security-plan.control-implementation [1]` (implemented-requirements[])

**Sign-off Markdown sections** (5):
1. **Header** — system, FedRAMP package ID, review year, prior SSP version → current SSP version, generation timestamp.
2. **Changed controls** — table with columns: control-id, fields-changed, prev-hash (short), new-hash (short).
3. **Added / removed components** — two tables.
4. **Added / removed users** — two tables.
5. **Attestation block** — 4 cells, all `REQUIRES-OPERATOR-INPUT` until operator fills:
   - `reviewed_by`: name + title (CLI `--ssp-attested-by`)
   - `reviewed_at`: ISO date (auto = `generated_at`)
   - `attestation_statement`: literal text "I attest that the System Security Plan reflects the current as-built state of the system as of <date>."
   - `signature`: ALWAYS `REQUIRES-OPERATOR-INPUT` (REO Rule 1.6 — no fake cryptographic operations).

## Build steps (concrete, numbered)
1. **`extractSspIndex` helper** in `core/oscal-ssp.ts`. Walks the SSP doc once and returns four maps:
   - `controlImplementations` keyed by `control-id` → sha256(canonical JSON of the matching `implemented-requirement` block + any `statement` sub-blocks).
   - `components` keyed by component UUID → sha256(canonical JSON of the component object).
   - `users` keyed by user UUID → sha256(canonical JSON of the user object).
   - `metadata` keyed by metadata field name → sha256(canonical JSON of that field's value).
   Uses `json-stable-stringify` for deterministic canonical JSON; if not in dependencies, write a small inline canonicalizer (recursive sort of object keys).
2. **`diffSsp(prior, current): SspDiff`** in `core/ssp-diff.ts`. Pure function:
   a. Call `extractSspIndex(prior)` and `extractSspIndex(current)`.
   b. For each control-id in either index, if `prev_hash !== new_hash`, compute `field_changes` by re-walking both blocks and comparing leaf fields. Push to `changed_controls`.
   c. Set-difference of component UUIDs → `added_components`, `removed_components`.
   d. Set-difference of user UUIDs → `added_users`, `removed_users`.
   e. Compare metadata key hashes → `metadata_changes`.
   f. Compute `summary` counts.
   g. Populate `provenance` block.
3. **`runSspAnnualReview(opts: { outDir, runId, year, priorSspPath?, attestedBy?, fedrampPackageId? }): { diffPath, archivePath, hadChanges, requiresAttestation }`** in `core/ssp-annual-review.ts`:
   a. Load current `ssp.json` from `outDir`. If missing, throw `MissingCurrentSspError` (not silent).
   b. Resolve prior SSP: explicit `priorSspPath` → fall back to `outDir/archive/ssp-<year-1>.json` → emit "first annual cycle; no prior SSP" Markdown if neither exists.
   c. Call `diffSsp(prior, current)`.
   d. Render Markdown with the 5 sections per the spec above.
   e. Archive the current SSP to `outDir/archive/ssp-<year>.json` (atomic write via tmp + rename; refuse to overwrite an existing archive — `ArchiveExistsError`).
   f. Return paths + flags.
4. **Markdown renderer**: simple template literals + `xmlEscape`-style escapes for control characters in narrative cells. No external Markdown lib needed (parallel to LOOP-A.A1's POA&M Markdown rendering).
5. **Orchestrator wiring**: `--ssp-annual-review` triggers `runSspAnnualReview()` AFTER `--oscal-ssp`. When `--prior-ssp-path` provided, that's the diff source; otherwise auto-lookup in archive.
6. **submission-bundle catalogue**: register `ssp-annual-diff` + `ssp-archive` roles so the annual bundle classifies them correctly.
7. **First-year case**: when no prior SSP exists, emit a clean Markdown stating "First annual cycle (calendar year `<YEAR>`); no prior System Security Plan archive found for diff comparison. The currently-emitted SSP (uuid `<current_uuid>`, version `<current_version>`) is established as the baseline for next year's annual review." — REAL true statement, not a placeholder.
8. **Manifest scope**: confirm `core/sign.ts` already includes `archive/**` in the signed set. If not (likely), extend the manifest glob to cover `archive/ssp-*.json`.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4 (CLAUDE.md §"Operator-supplied data is real data"), every operator-only field MUST emit the literal sentinel `REQUIRES-OPERATOR-INPUT` rather than a fabricated default.

- **`attestation.reviewed_by`** — Source: CLI `--ssp-attested-by <name>` / env `CLOUD_EVIDENCE_SSP_ATTESTED_BY`. Format: `"<full name>, <title>"`. Why: PL-2.b explicitly requires the reviewer be identified. Missing → marker in the attestation table cell.
- **`attestation.signature`** — ALWAYS `REQUIRES-OPERATOR-INPUT` regardless of any flag. REO Rule 1.6 forbids auto-signing on behalf of a human. The operator signs out-of-band (digital signature applied to the printed PDF, or wet ink + scan) and re-uploads.
- **`prior-ssp-path`** — Source: CLI `--prior-ssp-path <path>` / env `CLOUD_EVIDENCE_PRIOR_SSP_PATH`. Why: when running for a year whose archive directory was lost / moved / never created, the operator points at the prior SSP file directly. Missing AND archive lookup fails AND not first-year → `MissingPriorSspError` (typed; not silent).
- **`system.fedrampId`** — same as E.E1: CLI `--fedramp-package-id`. Surfaces in the Markdown header.

Sentinel constant: reuse `TBD = 'REQUIRES-OPERATOR-INPUT'` from `core/roe-emit.ts` (or `core/markers.ts` if introduced earlier).

## Test specifications (≥12 tests)
**`ssp-diff.test.ts` (~10)**:
1. `it('returns empty diff for identical docs')` — feeds the same SSP twice; asserts `summary.controls_changed === 0`, all arrays empty.
2. `it('detects changed control implementation')` — flips one control's `description`; asserts one `changed_controls` entry with `field_changes` including `"description"`.
3. `it('detects added component')` — appends a component; asserts `added_components.length === 1`.
4. `it('detects removed user')` — drops a user; asserts `removed_users.length === 1`.
5. `it('detects metadata.title change')` — flips title; asserts `metadata_changes` includes `"title"`.
6. `it('is deterministic on shuffled input arrays')` — shuffles `components[]` order; asserts identical diff output.
7. `it('extractSspIndex hashes are stable across JSON-string-roundtrip')` — parse → re-stringify → re-parse → re-hash; asserts identical.
8. `it('summary counts match the detailed arrays')` — invariant check.
9. `it('handles missing optional fields gracefully')` — SSP without `back-matter`; asserts no throw.
10. `it('narrative_changed flips only on prose changes')` — flip a UUID (structural) vs a description (narrative); asserts only narrative case sets `narrative_changed = true`.
11. `it('canonical JSON serializer sorts object keys')` — internal test of the canonicalizer.

**`ssp-annual-review.test.ts` (~12)**:
12. `it('emits ssp-annual-diff-<YYYY>.md with 5 sections')` — section headers present in correct order.
13. `it('archives the current SSP to archive/ssp-<YYYY>.json')` — file exists, bytes match the source.
14. `it('returns requiresAttestation=true when changes detected')`.
15. `it('returns requiresAttestation=false when no changes (still emits Markdown for audit trail)')`.
16. `it('first-year case emits a clean "no prior SSP" Markdown')` — text matches the prescribed phrasing.
17. `it('honors --prior-ssp-path override')` — explicit prior path takes precedence over archive lookup.
18. `it('attestation block contains all four REQUIRES-OPERATOR-INPUT cells when no operator inputs')`.
19. `it('attestation.reviewed_by is populated when --ssp-attested-by flag set')`.
20. `it('throws MissingCurrentSspError when ssp.json missing and --oscal-ssp not in run')`.
21. `it('throws ArchiveExistsError when archive/ssp-<YYYY>.json already exists')` — refuses to overwrite.
22. `it('Markdown escapes control characters in narratives')` — feeds a control with newlines/pipes in description.
23. `it('archive directory is included in signed manifest')` — verifies sign.ts glob.
24. `it('does not auto-bump metadata.version of the current SSP')` — version bumping is an explicit operator action, not implied by review.
25. `it('integrates with submission-bundle: ssp-annual-diff role recognized')`.

## REO compliance specific to this slice
- **Diff is content-derived** via sha256 of canonical JSON per element. No narrative paraphrasing, no LLM summaries, no fabricated "what changed" prose — only literal field-level differences.
- **Attestation signature is NEVER auto-emitted**. REO Rule 1.6 ("Fake cryptographic operations") explicitly forbids. The cell stays `REQUIRES-OPERATOR-INPUT`.
- **Archive directory grows append-only**. Old SSPs are never silently overwritten; `ArchiveExistsError` enforces.
- **Provenance fields populated**: `prior_source_path`, `current_source_path`, `diff_algorithm`, `canonical_serializer`. Surfaces in the diff JSON and the Markdown footer.
- **Signed by existing `core/sign.ts` pipeline** (Ed25519 + RFC 3161). The diff Markdown and the archived SSP are emitted into `outDir` BEFORE signing so the manifest covers them.
- **No silent fallbacks** — every missing input emits a typed error or a marker, never a fabricated value.

## Verification commands
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/ssp-annual-review.test.ts tests/core/ssp-diff.test.ts
npm run check:reo
```

## Known risks / issues
- **Risk 1: Canonical JSON edge cases.** Float precision, Unicode normalization, and array order semantics can cause spurious diffs. Mitigation: use a vetted canonicalizer (RFC 8785 JCS-compatible if available; otherwise a tested in-house function). Add a stress test that feeds the same logical SSP through `JSON.parse(JSON.stringify(...))` and asserts identical hash. Severity: high — bad canonicalization invalidates the diff.
- **Risk 2: SSP schema evolution.** If OSCAL v1.1.3 / v2.0 adds new top-level elements (e.g. a `risk-management` block), `extractSspIndex` may miss them and silently under-report changes. Mitigation: assert the SSP `oscal-version` field matches a pinned allowlist in `extractSspIndex`; emit a `provenance.warnings: ["unknown-oscal-version"]` entry when mismatched.
- **Risk 3: Archive directory not in signed scope.** Without `core/sign.ts` extension, the archived SSP is not signed and a tampered prior-SSP could produce a false-negative "no changes" diff. Mitigation: explicit test (`archive directory is included in signed manifest`) + RUNBOOK note.
- **Risk 4: Attestation date timezone.** "Reviewed at" in UTC vs CSP-local. Mitigation: always interpret as UTC; surface in ISO-Z format; document in flag help.
- **Risk 5: Prior-SSP file is corrupt.** Truncated or partial JSON write from a prior run. Mitigation: typed `PriorSspCorruptError` naming the file path and the parser line — never silently treat as "first year" (mirrors LOOP-E.E2's `PriorPoamCorruptError`).
- **Risk 6: Field-change reporter explosion.** A trivial whitespace change in a long control narrative would list 100+ "field_changes" entries. Mitigation: collapse adjacent field-change paths; cap at 20 per control with an "...and N more" footer (still real, just truncated).
- **Risk 7: First-year heuristic ambiguity.** `archive/ssp-<year-1>.json` missing could mean (a) genuinely first year, or (b) archive lost. Mitigation: require `--first-year` explicit flag for first-year case; otherwise emit a warning and a typed soft-error that operator can override via flag.

## Open questions (for implementation session to resolve)
- **Q1**: Should the diff include a per-control NIST 800-53 family roll-up (e.g. "3 AC controls changed, 2 AU controls changed") for executive visibility? Adds Markdown rendering complexity but aids review.
- **Q2**: How does this slice interact with C.C7 (Risk Management Strategy) and C.C9 (Baseline Configuration document) — are those plans also annually-reviewable through a similar mechanism, or strictly through the SSP? Recommend reuse of `extractSspIndex` pattern for those docs in a future slice; not in scope here.
- **Q3**: For the `field_changes` array, should each entry include the prior and new values (verbose) or just the field path (terse)? Verbose makes review easier but bloats the Markdown 10x.
- **Q4**: Should `provenance.canonical_serializer` pin a specific algorithm version (e.g. `"json-stable-stringify@1.0.2"`) and fail the diff if the version mismatches? Aligns with REO Rule 1 determinism.
- **Q5**: When the operator changes the SSP `metadata.version` between years (semver bump), should this slice auto-emit a `metadata.revisions[]` entry parallel to E.E2's POA&M pattern? Or is that always operator-driven?
- **Q6**: Should the annual diff link to specific POA&M items that drove control changes (e.g. "AC-2 changed because POA&M item `<uuid>` required a new responsible role")? Requires a separate provenance plumbing layer.
- **Q7**: How does this interact with LOOP-F.F1 (3PAO sign-off UI)? Should the attestation cell be backed by a tracker DB row that the 3PAO can verify, or is the Markdown attestation alone sufficient?

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ~22 for this slice's new tests)
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
5. Read existing emitter for pattern reference: `core/oscal-ssp.ts` (current SSP emitter — the helper extends it), `core/oscal-poam.ts` (the LOOP-A.A1 revisions pattern is the model for SSP revisions).
6. Read `cloud-evidence/docs/slices/E/E.E2.md` (POA&M delta) — analogous ledger / archive / diff pattern.
7. Begin implementation; update Implementation log section as you go.
