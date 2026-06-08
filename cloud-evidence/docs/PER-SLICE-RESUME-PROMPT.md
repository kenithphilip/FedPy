# Per-slice resume prompt — auto-detect + templates + worked examples

This document is the **canonical session-bootstrap prompt** for shipping
any pending slice in FedPy core. It exists because:

1. The slice-level specifications (`docs/slices/X/X.XN.md`) are
   exhaustive (400-1600 lines each) but spread across the corpus —
   without a guided reading order, a fresh session burns 100k+ tokens
   discovering "what should I read first?"
2. The completion procedure (`docs/SLICE-COMPLETION-PROCEDURE.md`)
   touches 4 files atomically and is easy to half-execute.
3. The REO standard (`CLAUDE.md`) has 4 enforcement rules + 3 CI
   guardrails — sessions that don't internalize all of them ship REO
   violations that CI later rejects.

This document gives any future Claude session the **complete
context-load manifest, the implementation contract, the REO compliance
gate, and the file-by-file completion checklist** as one paste-ready
prompt.

## What to paste each session — quick guide

| Scenario | Use |
|---|---|
| Default — ship the next-priority slice per STATUS.md, no per-slice parameters needed | **§1 Auto-detect resume prompt** (paste this 95% of the time) |
| Override — explicitly ship a non-default slice (e.g., user wants to skip a slice or backfill a missed one) | **§2 Explicit-override template** (parameterized) |
| First time learning the pattern + want to see a worked example | **§3 Populated instance for W.W1** |

---

## §1. Auto-detect resume prompt — paste THIS each session

> **This is the canonical paste-ready prompt for shipping any slice.**
> It contains zero per-slice parameters. The session reads STATUS.md,
> picks the next-priority slice itself, and ships it. The same prompt
> works for W.W1, W.W2, W.W3, W.W4, T.T1, ..., the 50 LOOP-B–K base
> slices, through to the last slice of LOOP-X. Paste this each session.

```text
You are resuming work on the FedPy / FedRAMP 20x compliance toolkit
(Apache-2.0, clean-room, REO standard). Your single objective for this
session is to AUTO-DETECT the next-priority pending slice from
STATUS.md and ship it end to end, atomically, following the 7-step
SLICE-COMPLETION-PROCEDURE.md exactly.

═══════════════════════════════════════════════════════════════════════
PHASE −1 — AUTO-DETECTION (do this FIRST, before any other reading)
═══════════════════════════════════════════════════════════════════════

1. Read /Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/STATUS.md

2. Locate the "## Overall (Core only)" section and find the
   "Next priority:" line. It names the next slice(s) in the queue, in
   priority order, sometimes with arrows ("W.W1 → W.W2 → ...").

3. Parse the FIRST slice ID named on that line.
   - The slice ID format is `<LOOP>.<LOOP><N>` (e.g., `W.W1`, `T.T3`,
     `B.B1`, `G.G2`) or with a LOOP- prefix (`LOOP-W.W1`).
   - Normalize to the form `<SLICE-ID>` = `W.W1` (no LOOP- prefix).
   - The loop letter is the character before the dot. So for `W.W1`:
     <LOOP> = `W`, <SLICE-ID> = `W.W1`.

4. Read the slice's per-slice doc to extract metadata:
   /Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/slices/<LOOP>/<SLICE-ID>.md
   From the YAML frontmatter at the top, extract:
   - title:           → <SLICE-TITLE>
   - status:          → must be "proposed" or "pending"
   - depends_on:      → list of <DEPENDENCY-LOOPS>

5. Validate the slice is eligible to ship NOW:
   (a) The per-slice doc exists at the path above.
   (b) The slice doc path is NOT under docs/roadmap/ (that folder is
       out-of-core; refuse to ship and tell me).
   (c) The frontmatter status: is "proposed" or "pending" (NOT "done").
   (d) Every entry in `depends_on:` is either:
       - A loop letter (e.g. "LOOP-A") whose loop is marked COMPLETE in
         STATUS.md, OR
       - A specific slice ID (e.g. "A.A4", "W.W1") whose row in
         STATUS.md shows status=done, OR
       - An existing primitive module (e.g. "tracker DB", "core/sign.ts",
         "existing IAM collectors") that is part of the shipped base
         (LOOP-A is shipped, plus all the pre-loop foundational
         infrastructure documented in CLAUDE.md).
   (e) The slice's row in STATUS.md per-loop status table shows
       status=proposed or pending (consistent with frontmatter).

6. If ANY validation fails, STOP and report to me:
   - The slice ID you detected.
   - Which validation(s) failed.
   - What you suggest I do (e.g., "W.W1 already shipped per STATUS.md;
     should I ship W.W2 instead?", or "S.S2 depends on S.S1 which is
     pending; should I queue S.S1 first?").
   Wait for my response. Do NOT proceed.

7. If all validations pass, announce in chat:
     "Auto-detected next-priority slice: <SLICE-ID> — <SLICE-TITLE>
      Loop: <LOOP>
      Dependencies: <DEPENDENCY-LOOPS>
      Status before this session: pending → starting work now."
   Then proceed to Phase 0.

═══════════════════════════════════════════════════════════════════════
PHASES 0-5 — execute per the universal template
═══════════════════════════════════════════════════════════════════════

Open and read:
/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/PER-SLICE-RESUME-PROMPT.md

In §2 of that file you'll find the universal template. The Phase 0
mandatory reading list, the Phase 1 REO rules (A-J), the Phase 2 test
contract, the Phase 3 REO guardrail commands, the Phase 4 atomic
completion procedure (including the two-pass commit-hash close-out),
and the Phase 5 file-by-file checklist are all defined there.

Execute Phases 0 through 5 verbatim, substituting:
  <SLICE-ID>     ← detected in Phase −1.3
  <LOOP>         ← detected in Phase −1.3
  <SLICE-TITLE>  ← extracted in Phase −1.4
  <DEPENDENCY-LOOPS> ← extracted in Phase −1.4

In Phase 4, when updating consumer files (STATUS.md / loop SPEC /
per-slice doc frontmatter / RISKS register / OPERATOR-GUIDE.md /
CHANGELOG.md), apply the exact rules from the universal template.
The OPERATOR-GUIDE.md updates only apply IF the slice introduces new
CLI flags / env vars / output files — check §7 of the per-slice doc
to determine.

═══════════════════════════════════════════════════════════════════════
PHASE 6 — VERIFY NEXT-PRIORITY LINE IS UPDATED
═══════════════════════════════════════════════════════════════════════

A critical Phase 4 outcome: STATUS.md "Next priority:" line MUST now
name the NEXT slice in the queue (not the one you just shipped). This
makes the next session self-driving — they paste the SAME prompt and
auto-detect the slice AFTER yours.

Verify in your post-push check:
  grep "Next priority" cloud-evidence/docs/STATUS.md

The named slice should be different from the one you just shipped. If
it's the same, you missed the Phase 4 Step 2 (b) Next priority update.
Fix and re-amend.

═══════════════════════════════════════════════════════════════════════
FINAL REPORT (when Phase 5 + Phase 6 are complete)
═══════════════════════════════════════════════════════════════════════

Report to me:
  - Slice that just shipped: <SLICE-ID> — <SLICE-TITLE>
  - Final commit hash (post-push)
  - Test count delta (was N, now N+M, +M)
  - Files created (count + total lines)
  - Files modified (count + lines added per file)
  - REO compliance: G1/G2/G3 all green
  - Open §10 questions resolved (with answers)
  - New risks added to LOOP-<LOOP>-RISKS.md (if any)
  - NEXT-PRIORITY SLICE per the updated STATUS.md
    (this is the slice the next session will auto-detect when I paste
    this same prompt)

Then STOP. Do not auto-start the next slice. New slice = new session
= new paste of this same prompt. Each slice is its own context boundary.

═══════════════════════════════════════════════════════════════════════
OVERRIDE INSTRUCTIONS (if I want to ship a specific slice instead)
═══════════════════════════════════════════════════════════════════════

If I prepend "OVERRIDE: ship LOOP-X.XN" to this prompt, skip Phase −1
auto-detection and use the explicit slice ID I gave. Read its
per-slice doc + frontmatter to extract title and dependencies. Validate
the slice exists in docs/slices/, not docs/roadmap/, and that
dependencies are done. Then proceed to Phase 0.

Use the override only when the auto-detected slice isn't what I want.
Default behavior is: paste the prompt with NO override, let auto-detect
pick whatever STATUS.md says is next.
```

End of auto-detect resume prompt.

---

## §2. Explicit-override template (parameterize for a specific slice)

> Copy this block. Replace `<SLICE-ID>`, `<LOOP>`, `<SLICE-TITLE>`,
> `<DEPENDENCY-LOOPS>` placeholders. Paste into a new Claude session as
> the first message. The session will then have everything it needs
> to ship the slice end-to-end without re-asking.

```text
You are resuming work on the FedPy / FedRAMP 20x compliance toolkit
(Apache-2.0, clean-room, REO standard). Your single objective for this
session is to implement and ship slice <SLICE-ID> — <SLICE-TITLE> — end
to end, atomically, following the 7-step SLICE-COMPLETION-PROCEDURE.md
exactly.

═══════════════════════════════════════════════════════════════════════
PHASE 0 — MANDATORY READING (in this exact order, before any code edits)
═══════════════════════════════════════════════════════════════════════

Read each file in full unless a section narrowing is given. Do NOT skip
ahead. Do NOT rely on summaries. The files are the source of truth.

1. /Users/kenith.philip/FedRAMP 20x/cloud-evidence/CLAUDE.md
   — REO standard (Rules 1-4), the Scope Guard block, the Conditional
     Applicability Matrix, the reading-list ordering, the 7-step
     completion directive at line ~230. This is the constitution.

2. /Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/STATUS.md
   — Confirm <SLICE-ID> is still the next-priority and is marked
     `pending`. If the "Next priority" line names a different slice or
     <SLICE-ID> is already `done`, STOP and ask the user what changed.

3. /Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md
   — The 7 steps you MUST execute atomically with the slice's commit.
     Do not skip steps. Failure-handling rules are non-negotiable.

4. /Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/LOOP-<LOOP>-SPEC.md
   — Loop-level context. Required sections: §1 (Mission), §2 (Statutory
     drivers — your verbatim source material), §3 (slice list — see
     where <SLICE-ID> sits), §5 (reusable primitives — what's already
     built that you'll compose), §11 (cross-references). Skim the rest.

5. /Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/slices/<LOOP>/<SLICE-ID>.md
   — THE IMPLEMENTATION CONTRACT. Read all sections, top to bottom:
     §1  Mission                      — what this slice produces
     §2  Authoritative sources        — verbatim citations + URLs you
                                         must NOT invent or paraphrase
                                         when emitting envelope metadata
     §3  Scope                         — in-scope / out-of-scope
                                         (anything out-of-scope is a
                                         REO violation if you ship it)
     §4  Inputs                        — exact TypeScript interfaces;
                                         these are the contract for
                                         every function you write
     §5  Outputs                        — canonical-JSON envelope shape;
                                         signing flow; bundle catalogue
                                         registration
     §6  Algorithm / Steps              — the numbered pipeline; this is
                                         your implementation outline
     §7  Files to create / modify       — exact absolute paths +
                                         estimated line budgets; do NOT
                                         create files outside this list
     §8  Test specifications            — the ≥15 tests you must ship;
                                         each has id|scenario|fixture|
                                         expected|acceptance
     §9  Risks                          — what can go wrong + the
                                         mitigation pattern to apply
     §10 Open questions                 — resolve in-line during
                                         implementation; document the
                                         resolution in §12
     §11 REQUIRES-OPERATOR-INPUT        — fields the operator supplies
                                         per REO Rule 4; emit clear
                                         requires_operator_input
                                         diagnostics when absent
     §12 Implementation log             — append a session entry as you
                                         work; do NOT overwrite prior
                                         entries
     §13 Completion checklist           — exact files to update at end

6. /Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/LOOP-<LOOP>-RISKS.md
   — Skim for risks tagged with <SLICE-ID> or your slice's scope. If
     during implementation you discover a NEW risk, append it here in
     the same commit as the slice (per CLAUDE.md Strong Directive).

7. /Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/OPERATOR-GUIDE.md
   — Sections to read: §3 (CLI flags reference), §4 (env vars
     reference), §7 (output artifacts catalogue). When you add new
     flags / env vars / output files in this slice, you MUST update
     these sections at completion (per OPERATOR-GUIDE §10
     maintenance contract).

8. Dependency loop SPECs (for each <DEP-LOOP> in <DEPENDENCY-LOOPS>):
   /Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/LOOP-<DEP-LOOP>-SPEC.md
   — Read §5 (reusable primitives) only. You will compose these.

9. Existing reference implementation (study how prior slices wired up
   into the orchestrator + signing + bundle):
   /Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/slices/A/A.A1.md
   /Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/slices/A/A.A4.md
   /Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/slices/A/A.A5.md
   — A.A1 = OSCAL POA&M emitter (the catalog-emitter pattern).
   — A.A4 = submission-bundle (the WELL_KNOWN registration pattern).
   — A.A5 = Ed25519 + RFC 3161 + canonical-JSON (the signing pipeline).

10. Primitive source code (read FIRST, do not duplicate):
    /Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sign.ts
    /Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/timestamp.ts
    /Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/envelope.ts
    /Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts
    /Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/manifest.ts
    /Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/inventory-coverage.ts
    /Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts
    — These already exist. NEVER re-implement what's in them. Always
      compose. If you need a new primitive, add it to the appropriate
      existing file unless the per-slice doc §7 explicitly creates a
      new file for it.

═══════════════════════════════════════════════════════════════════════
PHASE 1 — IMPLEMENTATION (REO-locked)
═══════════════════════════════════════════════════════════════════════

Once Phase 0 is complete, execute the slice's §6 algorithm by creating
and modifying ONLY the files enumerated in §7 of the per-slice doc.

Strict implementation rules (REO standard — CLAUDE.md Rules 1-4):

A. NO STUBS. No `return null // TODO`. No `placeholder`. No
   `not yet implemented`. Every function returns its computed real
   value or throws a typed error.

B. NO FAKE DATA in production paths. String literals in production
   code come from: FRMR catalog, OSCAL schemas, NIST publications,
   cloud SDK responses, tracker DB, or operator-supplied config.
   Fixtures live ONLY under `tests/`.

C. NO MOCKED CLOUD SDKs in production paths. SDK transport may be
   mocked at the wire layer in tests; production code uses real
   read-only SDKs through the existing guardrails.

D. NO SILENT FALLBACKS that mask missing data. If a cell can't be
   filled, emit `null` AND log a `coverage:miss` line with the asset
   id + reason.

E. NO `if (process.env.NODE_ENV === 'test')` BRANCHES. Tests inject
   seams; production code never knows it's being tested.

F. NO EMIT FIELDS WITHOUT PROVENANCE. Every new emitted field gets a
   `provenance` entry in the output OR a `coverage_source` entry in
   the registry. CI guardrail G3 enforces this.

G. NO AUTO-SIGNED HUMAN ATTESTATIONS. Sign-offs from operator / 3PAO /
   AO are captured in the tracker DB; the system never auto-signs on
   their behalf.

H. EVERY FILE WRITE goes through `core/sign.ts` or composes the
   canonical-JSON + Ed25519 + RFC 3161 pipeline from A.A5.

I. EVERY NEW EMITTED FILE is registered in the submission bundle
   catalogue (`WELL_KNOWN` in `core/submission-bundle.ts`) if it
   contributes to the FedRAMP submission package.

J. ALL CLOUD SDK CLIENTS go through the read-only Proxy guardrails
   in `core/readonly-guardrail*.ts`. Never bypass them.

═══════════════════════════════════════════════════════════════════════
PHASE 2 — TESTS (≥15 per §8)
═══════════════════════════════════════════════════════════════════════

Write the tests enumerated in the per-slice doc's §8 table. For each
row, the test must:
- Use the named fixture path (under `cloud-evidence/tests/fixtures/`)
- Assert the stated `expected` outcome
- Meet the stated `acceptance` criterion (often "A" = automated)

Test framework: vitest. Existing test files demonstrate the patterns.
Read `cloud-evidence/tests/oscal-poam-emitter.test.ts` for the
catalog-emitter test pattern; `cloud-evidence/tests/submission-bundle.test.ts`
for the bundle-integration test pattern.

═══════════════════════════════════════════════════════════════════════
PHASE 3 — REO GUARDRAILS (must be green before commit)
═══════════════════════════════════════════════════════════════════════

Run each of the three CI guardrails locally and confirm all green:

cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck       # MUST return 0 errors
npm test                # MUST be 100% passing AND the test count
                        # MUST have increased by ≥15 (your slice's
                        # new tests)
npm run check:reo       # Runs lint:no-stubs (G1) +
                        # check:coverage-regression (G2) +
                        # check:provenance (G3). All three must
                        # exit 0.

If ANY of these fail:
- Fix the issue.
- Do not proceed.
- Do not mark the slice done.

═══════════════════════════════════════════════════════════════════════
PHASE 4 — COMPLETION (SLICE-COMPLETION-PROCEDURE.md 7-step + extensions)
═══════════════════════════════════════════════════════════════════════

These updates MUST all happen in ONE atomic commit. Do not commit code
in one commit and STATUS / spec / CHANGELOG updates in another. Every
file below is touched in the same git transaction.

Step 1 (verify) — already done in Phase 3 above.

Step 2 (STATUS.md) —
  File: /Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/STATUS.md
  Updates:
    a) In the slice's row in the per-loop status table, change `pending`
       to `done`. Date column gets today's ISO date (YYYY-MM-DD).
       Commit column will be filled in Step 6.
    b) "Overall" section:
       - If this is the last slice in the loop: increment "Loops
         complete: N of 22" by 1.
       - Update "Last shipped: <SLICE-ID> (commit `<hash>` — filled in
         Step 6)".
       - Update "Next priority:" to the next-pending slice in the
         queue per the dependency graph.

Step 3 (loop spec) —
  File: /Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/LOOP-<LOOP>-SPEC.md
  Updates:
    In the §3 "Slice list" table or §12 "Status table" row for your
    slice: status=done, commit=<hash filled in Step 6>, date=<ISO>.

Step 4 (CHANGELOG) —
  File: /Users/kenith.philip/FedRAMP 20x/CHANGELOG.md
  Add at the TOP of the "Unreleased" section:
    ### Added — <SLICE-ID>: <SLICE-TITLE>
    2-3 paragraphs covering:
      - What shipped (modules, new files, modified files)
      - Verification counts (typecheck clean, NN/NN tests passing,
        npm run check:reo returns 0, lines added/deleted per file)
      - Statutory / regulatory drivers (cite the §2 sources from the
        per-slice doc — copy the citation, do not paraphrase)
      - REO compliance notes (any operator-supplied fields, the
        provenance entries for new emit fields)

Step 5 (commit) —
  Stage exactly these files in the commit:
    - All new files created (per §7.1 of the per-slice doc)
    - All modified files (per §7.2)
    - All new test files
    - cloud-evidence/docs/STATUS.md
    - cloud-evidence/docs/loops/LOOP-<LOOP>-SPEC.md
    - cloud-evidence/docs/slices/<LOOP>/<SLICE-ID>.md (frontmatter
      updated: status=done, commit=<TBD-step6>, completed_date=<ISO>,
      last_updated=<ISO>; §12 Implementation log gains a final row)
    - cloud-evidence/docs/loops/LOOP-<LOOP>-RISKS.md (only if you
      discovered new risks during implementation)
    - cloud-evidence/docs/OPERATOR-GUIDE.md (only if you added new
      CLI flags / env vars / output files — update §3 / §4 / §7
      respectively)
    - CHANGELOG.md

  Commit message format:
    <SLICE-ID>: <SLICE-TITLE>

    <multi-paragraph description matching the CHANGELOG entry>

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>

  NEVER use --no-gpg-sign without explicit user approval. NEVER
  use --no-verify. If a pre-commit hook fails, fix the issue and
  re-stage; do NOT amend a failed commit (the failed commit didn't
  happen).

Step 6 (commit hash) —
  After the commit lands, run: git log -1 --format=%h
  Use that hash to replace `<TBD-step6>` placeholders in:
    - cloud-evidence/docs/STATUS.md (Commit column of the slice row +
      "Last shipped" line)
    - cloud-evidence/docs/loops/LOOP-<LOOP>-SPEC.md (status table)
    - cloud-evidence/docs/slices/<LOOP>/<SLICE-ID>.md (frontmatter
      commit: field)
  Then amend the commit:
    git add cloud-evidence/docs/STATUS.md \
            cloud-evidence/docs/loops/LOOP-<LOOP>-SPEC.md \
            cloud-evidence/docs/slices/<LOOP>/<SLICE-ID>.md
    git commit --amend --no-edit
  Verify with: git log -1 --format=%h (hash should change because of
  the amend; that's expected. Both STATUS.md and the spec doc now
  reference the AMENDED hash).
  After amend: update those same files AGAIN with the post-amend
  hash, and amend ONCE MORE. (Two-pass: pre-amend hash and
  post-amend hash differ; close the loop.)

Step 7 (push) —
  git push origin main

  Verify the push landed:
    git log --oneline -3
    Expect: <new-commit-hash> <SLICE-ID>: <SLICE-TITLE>
            <previous HEAD>

  If push is rejected (someone else pushed first):
    git fetch origin main
    git rebase origin/main
    Re-run the relevant steps + git push origin main
  NEVER force-push to main.

═══════════════════════════════════════════════════════════════════════
PHASE 5 — FILE-BY-FILE COMPLETION CHECKLIST (do NOT skip)
═══════════════════════════════════════════════════════════════════════

The slice is NOT closed until every checkbox below is true. Do not
report "done" to the user without verifying each one with a real
filesystem / git command.

[ ] All files in §7.1 of <SLICE-ID>.md were CREATED and contain real
    REO-compliant code (no stubs / placeholders / fake data)
[ ] All files in §7.2 of <SLICE-ID>.md were MODIFIED (orchestrator
    flag wiring, submission-bundle WELL_KNOWN, inventory-coverage
    counters, etc.)
[ ] cloud-evidence/tests/<slice-id>.test.ts (or related test file(s))
    contains the ≥15 tests from §8 — verify with: grep -c "^\s*it("
    cloud-evidence/tests/<file>.test.ts
[ ] npm run typecheck returns 0 errors
[ ] npm test passes 100% AND test count increased by ≥15
[ ] npm run check:reo (lint:no-stubs + check:coverage-regression +
    check:provenance) all return 0
[ ] cloud-evidence/docs/STATUS.md row updated (status=done, commit,
    date) AND Overall section updated (Last shipped, Next priority)
[ ] cloud-evidence/docs/loops/LOOP-<LOOP>-SPEC.md status table row
    updated (status=done, commit, date)
[ ] cloud-evidence/docs/slices/<LOOP>/<SLICE-ID>.md frontmatter
    updated (status=done, commit=<hash>, completed_date=<ISO>,
    last_updated=<ISO>) AND §12 Implementation log gained the
    closing-session row
[ ] cloud-evidence/docs/loops/LOOP-<LOOP>-RISKS.md updated (only if
    new risks surfaced during implementation)
[ ] cloud-evidence/docs/OPERATOR-GUIDE.md updated (only if new CLI
    flags / env vars / output files added — §3 / §4 / §7
    respectively)
[ ] CHANGELOG.md "Unreleased" gained a new "### Added — <SLICE-ID>"
    block
[ ] The commit landed: git log --oneline -1 shows the slice commit
    with the slice ID in the subject line
[ ] git push origin main succeeded: git log --oneline origin/main..HEAD
    is empty (no unpushed commits)

═══════════════════════════════════════════════════════════════════════
ANTI-PATTERNS — DO NOT DO THESE
═══════════════════════════════════════════════════════════════════════

1. Do NOT split the implementation across multiple commits. The atomic
   commit + the STATUS/spec/CHANGELOG/per-slice-doc updates are ONE
   transaction. Splitting them breaks the on-disk source of truth.

2. Do NOT skip the per-slice doc §12 implementation log update. The
   log is the on-disk archaeological record. Future sessions need it
   to understand what happened. Add a row with: date, session
   identifier (any short label), action summary, commit hash, notes.

3. Do NOT extend the slice scope beyond §3 of the per-slice doc. If
   you discover something that needs work but is out of scope, either:
     a) File it as a new slice in the appropriate loop SPEC's §3 with
        status: proposed, OR
     b) Add it to the loop's RISKS register with an "untracked work"
        risk and a pointer to STATUS.md "next priority" review.
   Do NOT silently expand the slice.

4. Do NOT add new operator-config fields without documenting them in
   OPERATOR-GUIDE.md §3 (CLI flag) or §4 (env var) or
   org-profile.yaml.example (conditional-loop config).

5. Do NOT spawn nested Workflow runs or multi-agent fan-outs for slice
   implementation. The slice spec is self-contained; implement it
   directly. Workflow tool is for fan-out planning, not single-slice
   execution.

6. Do NOT propose moving anything to docs/roadmap/. The scope-fence
   is set (commit 8329a20 + fbcda3f). If you think a slice is out of
   scope, ask the user — do not unilaterally relocate.

7. Do NOT touch the read-only guardrails (core/readonly-guardrail*.ts)
   unless the slice explicitly says to in §7.

═══════════════════════════════════════════════════════════════════════
WHEN PHASE 5 IS COMPLETE
═══════════════════════════════════════════════════════════════════════

Report to the user:
  - Slice ID + title
  - Commit hash (final, post-push)
  - Test count delta (e.g. "was 396, now 416 (+20)")
  - Files created (count + total lines)
  - Files modified (count)
  - Any open questions resolved (with the answer)
  - Any new risks added to RISKS register
  - Next priority slice per the updated STATUS.md

Then STOP. Do not start the next slice in the same session unless the
user explicitly asks. Each slice is a discrete unit of work; new slice
= new resume prompt = new session.
```

End of universal template.

---

## §3. Populated instance — LOOP-W.W1 (worked example)

> This is the actual paste-ready prompt for the next session.
> Copy from the triple-backtick block below into a new Claude session
> as the first message.

```text
You are resuming work on the FedPy / FedRAMP 20x compliance toolkit
(Apache-2.0, clean-room, REO standard). Your single objective for this
session is to implement and ship slice W.W1 — Prohibited-Vendor List
Ingest (the canonical Ed25519-signed prohibited-vendor catalog merging
OFAC SDN + BIS Entity List + SAM Exclusions + FAR 52.204-25 + NDAA
§1634 + FASCSA) — end to end, atomically, following the 7-step
SLICE-COMPLETION-PROCEDURE.md exactly.

═══════════════════════════════════════════════════════════════════════
PHASE 0 — MANDATORY READING (in this exact order, before any code edits)
═══════════════════════════════════════════════════════════════════════

1. /Users/kenith.philip/FedRAMP 20x/cloud-evidence/CLAUDE.md
   — REO standard + Scope Guard + Conditional Applicability Matrix.

2. /Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/STATUS.md
   — Confirm W.W1 is the next-priority slice and is `pending`.

3. /Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md
   — The 7-step atomic procedure.

4. /Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/LOOP-W-SPEC.md
   — Required sections: §1 (Mission), §2 (Statutory drivers — FAR
     52.204-25 + FAR 52.204-26 + NDAA §889 + NDAA §1634 + OFAC SDN +
     BIS Entity List + SAM Exclusions + FASCSA, all with verbatim
     citations + URLs + 2026-06-07 access dates), §3 (slice list), §5
     (reusable primitives — A.A1 catalog pattern, A.A4 bundle, A.A5
     signing, http-client), §11 (cross-references — W.W2/W3/W4 depend
     on W.W1's output).

5. /Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/slices/W/W.W1.md
   — THE IMPLEMENTATION CONTRACT. Read all 13 sections. The
     1958-line LOOP-W-SPEC.md plus this 540-line per-slice doc is
     everything you need to ship the slice — do not deviate.

6. /Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/LOOP-W-RISKS.md
   — Skim for W.W1-specific risks. If you discover a new one during
     implementation, append it here in the same commit.

7. /Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/OPERATOR-GUIDE.md
   — §3 (CLI flag reference) + §4 (env var reference) + §7 (output
     artifacts catalogue). You will be adding:
       - CLI flag: --prohibited-vendors-catalog
       - Env var: CLOUD_EVIDENCE_PROHIBITED_VENDORS_CATALOG
       - Output file: out/prohibited-vendors-catalog.json (+ snapshot
         directory under out/snapshots/prohibited-vendors-YYYYMMDD/)
     UPDATE these sections at Phase 4 completion.

8. Dependency loop SPECs (W.W1 depends on LOOP-A primitives):
   /Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/LOOP-A-SPEC.md (skim only — §5)
   /Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/slices/A/A.A1.md (catalog-emitter pattern)
   /Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/slices/A/A.A4.md (WELL_KNOWN bundle registration)
   /Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/slices/A/A.A5.md (Ed25519 + RFC 3161 + canonical-JSON)

9. Reference implementation source (read FIRST, do not duplicate):
   /Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sign.ts
   /Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/timestamp.ts
   /Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/envelope.ts
   /Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts
   /Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/manifest.ts
   /Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/inventory-coverage.ts
   /Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts
   /Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-poam.ts (the catalog-emitter pattern from A.A1)

═══════════════════════════════════════════════════════════════════════
PHASE 1 — IMPLEMENTATION
═══════════════════════════════════════════════════════════════════════

Create (per W.W1.md §7.1):
  /Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/prohibited-vendors-catalog.ts
    ~600 lines — main ingester + canonical-JSON emitter + typed loader
  /Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/prohibited-vendors-parsers.ts
    ~500 lines — per-source parsers (OFAC SDN, BIS Entity List, SAM
    Exclusions, FAR 52.204-25, NDAA §1634, FASCSA)
  /Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/prohibited-vendors-config.ts
    ~120 lines — typed YAML loader + validator
  /Users/kenith.philip/FedRAMP 20x/cloud-evidence/scripts/extract-prohibited-vendors.mjs
    ~250 lines — offline one-shot snapshot script, idempotent
  /Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/prohibited-vendors-catalog.test.ts
    ~400 lines — ≥15 tests per W.W1.md §8

Modify (per W.W1.md §7.2):
  /Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts
    +20 lines — add --prohibited-vendors-catalog flag +
    CLOUD_EVIDENCE_PROHIBITED_VENDORS_CATALOG env var; runs BEFORE W.W2
  /Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts
    +10 lines — WELL_KNOWN entry for prohibited-vendors-catalog.json
  /Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/inventory-coverage.ts
    +15 lines — track prohibited_vendors_catalog_entity_count +
    prohibited_vendors_catalog_source_count per run
  /Users/kenith.philip/FedRAMP 20x/cloud-evidence/prohibited-vendors-config.yaml
    NEW — operator config template + inline comments (per W.W1.md §4.2)

Implementation MUST follow REO Rules 1-4 + the 10 anti-patterns from
the universal template (§1 above). Compose from existing primitives
(sign.ts, timestamp.ts, envelope.ts, submission-bundle.ts,
manifest.ts) — never re-implement.

═══════════════════════════════════════════════════════════════════════
PHASE 2 — TESTS (≥15 per W.W1.md §8)
═══════════════════════════════════════════════════════════════════════

Write the ≥15 tests from W.W1.md §8 in:
  /Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/prohibited-vendors-catalog.test.ts

Coverage points (verify each is exercised by ≥1 test):
  - OFAC SDN parser handles the full XML schema
  - BIS Entity List parser handles tabular CSV
  - SAM Exclusions parser handles the JSON API response shape
  - FAR 52.204-25 named-entity constants are inlined (no network)
  - NDAA §1634 Kaspersky covered-entity inclusion
  - FASCSA covered-entity inclusion (or REQUIRES-RESEARCH per §10)
  - Canonical-JSON byte-identical re-serialization (RFC 8785)
  - Ed25519 signature verifies against the issued key
  - RFC 3161 TST attaches and validates
  - SHA-256 source-digest provenance per source
  - Dedupe across overlapping sources (same entity in OFAC + BIS)
  - Snapshot-directory layout + MANIFEST.json correctness
  - Orchestrator --prohibited-vendors-catalog flag wiring
  - inventory-coverage.json counts update
  - submission-bundle WELL_KNOWN registration

Read existing test patterns:
  /Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/oscal-poam.test.ts (catalog-emitter test pattern)
  /Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/submission-bundle.test.ts (bundle-integration pattern)
  /Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/sign.test.ts (signing test pattern)

═══════════════════════════════════════════════════════════════════════
PHASE 3 — REO GUARDRAILS
═══════════════════════════════════════════════════════════════════════

cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck       # MUST return 0 errors
npm test                # MUST be 100% passing + count must increase
                        # by ≥15
npm run check:reo       # G1+G2+G3 all green

═══════════════════════════════════════════════════════════════════════
PHASE 4 — COMPLETION (SLICE-COMPLETION-PROCEDURE.md 7-step)
═══════════════════════════════════════════════════════════════════════

Update atomically in ONE commit:

(a) cloud-evidence/docs/STATUS.md
    - W.W1 row: status=pending → done; date=<ISO>; commit=<TBD-step6>
    - LOOP-W section header: indicate W.W1 done
    - "Overall" section:
      • Last shipped: LOOP-W.W1 (commit `<hash>`)
      • Next priority: LOOP-W.W2 (subprocessor screen — the next slice
        in the W.W1→W.W2→W.W3→W.W4 chain)

(b) cloud-evidence/docs/loops/LOOP-W-SPEC.md
    - §3 Slice list table row for W.W1: status=done, commit=<hash>,
      date=<ISO>
    - §12 Status table row mirrors §3 update

(c) cloud-evidence/docs/slices/W/W.W1.md
    - YAML frontmatter:
        status: proposed → done
        commit: TBD → <hash>
        completed_date: — → <ISO>
        last_updated: 2026-06-07 → <ISO>
    - §12 Implementation log table: append a final row with date,
      session identifier (any short label like "impl-w-w1"), action
      summary ("Shipped end to end per spec. NN tests passing.
      typecheck/test/check:reo all green."), commit hash, notes

(d) cloud-evidence/docs/loops/LOOP-W-RISKS.md
    - Only if new risks surfaced during implementation. Append, do
      not edit existing entries.

(e) cloud-evidence/docs/OPERATOR-GUIDE.md
    - §3.5 (or appropriate sub-section): add --prohibited-vendors-catalog
      flag row
    - §4.3 (Inventory + scope env vars): add
      CLOUD_EVIDENCE_PROHIBITED_VENDORS_CATALOG row
    - §7 Output artifacts catalogue: add prohibited-vendors-catalog.json
      + snapshots/prohibited-vendors-YYYYMMDD/ row

(f) CHANGELOG.md
    - At TOP of "Unreleased": new "### Added — LOOP-W.W1: Prohibited-
      Vendor List Ingest" block. 2-3 paragraphs. Cite all 10 §2 sources
      verbatim. State verification counts + REO compliance.

Commit (Step 5):
  git add cloud-evidence/core/prohibited-vendors-catalog.ts \
          cloud-evidence/core/prohibited-vendors-parsers.ts \
          cloud-evidence/core/prohibited-vendors-config.ts \
          cloud-evidence/scripts/extract-prohibited-vendors.mjs \
          cloud-evidence/tests/prohibited-vendors-catalog.test.ts \
          cloud-evidence/core/orchestrator.ts \
          cloud-evidence/core/submission-bundle.ts \
          cloud-evidence/core/inventory-coverage.ts \
          cloud-evidence/prohibited-vendors-config.yaml \
          cloud-evidence/docs/STATUS.md \
          cloud-evidence/docs/loops/LOOP-W-SPEC.md \
          cloud-evidence/docs/loops/LOOP-W-RISKS.md \
          cloud-evidence/docs/slices/W/W.W1.md \
          cloud-evidence/docs/OPERATOR-GUIDE.md \
          CHANGELOG.md

  git commit -m "LOOP-W.W1: Prohibited-Vendor List Ingest
  <detailed multi-paragraph commit message>
  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"

  NEVER --no-gpg-sign without explicit user approval.
  NEVER --no-verify.

Step 6 — commit hash:
  hash=$(git log -1 --format=%h)
  Replace the <TBD-step6> placeholders in STATUS.md + LOOP-W-SPEC.md +
  slices/W/W.W1.md frontmatter with the real hash.
  git add cloud-evidence/docs/STATUS.md cloud-evidence/docs/loops/LOOP-W-SPEC.md cloud-evidence/docs/slices/W/W.W1.md
  git commit --amend --no-edit
  Get the post-amend hash and update again, then amend a second time.
  (Two-pass close-out because the amend changes the hash.)

Step 7 — push:
  git push origin main
  Verify: git log --oneline -3

═══════════════════════════════════════════════════════════════════════
PHASE 5 — FILE-BY-FILE CHECKLIST (verify every box before reporting done)
═══════════════════════════════════════════════════════════════════════

[ ] cloud-evidence/core/prohibited-vendors-catalog.ts created (~600 lines, REO-compliant)
[ ] cloud-evidence/core/prohibited-vendors-parsers.ts created (~500 lines, REO-compliant)
[ ] cloud-evidence/core/prohibited-vendors-config.ts created (~120 lines)
[ ] cloud-evidence/scripts/extract-prohibited-vendors.mjs created (~250 lines, idempotent)
[ ] cloud-evidence/tests/prohibited-vendors-catalog.test.ts created with ≥15 tests
    (verify with: grep -c "^\s*it(" cloud-evidence/tests/prohibited-vendors-catalog.test.ts)
[ ] cloud-evidence/core/orchestrator.ts modified (--prohibited-vendors-catalog flag added)
[ ] cloud-evidence/core/submission-bundle.ts modified (WELL_KNOWN entry added)
[ ] cloud-evidence/core/inventory-coverage.ts modified (entity/source count tracking)
[ ] cloud-evidence/prohibited-vendors-config.yaml created (operator config template)
[ ] npm run typecheck returns 0
[ ] npm test passes 100% AND count increased by ≥15
[ ] npm run check:reo (G1+G2+G3) all return 0
[ ] cloud-evidence/docs/STATUS.md updated (W.W1 row + Overall section)
[ ] cloud-evidence/docs/loops/LOOP-W-SPEC.md updated (slice list + status table)
[ ] cloud-evidence/docs/slices/W/W.W1.md frontmatter + §12 Implementation log updated
[ ] cloud-evidence/docs/loops/LOOP-W-RISKS.md updated (only if new risks surfaced)
[ ] cloud-evidence/docs/OPERATOR-GUIDE.md updated (§3 flag + §4 env var + §7 output)
[ ] CHANGELOG.md "Unreleased" gained "### Added — LOOP-W.W1" block
[ ] git log --oneline -1 shows "LOOP-W.W1: Prohibited-Vendor List Ingest"
[ ] git log --oneline origin/main..HEAD is empty (push succeeded)

═══════════════════════════════════════════════════════════════════════
ANTI-PATTERNS — DO NOT
═══════════════════════════════════════════════════════════════════════

1. Do NOT split into multiple commits. Atomic = one commit (+ two
   amend-passes for the hash close-out).
2. Do NOT skip the per-slice doc §12 Implementation log update.
3. Do NOT extend scope beyond W.W1.md §3.
4. Do NOT silently add new operator-config fields without OPERATOR-GUIDE.md
   updates.
5. Do NOT spawn nested Workflow runs.
6. Do NOT propose moving anything to docs/roadmap/.
7. Do NOT touch core/readonly-guardrail*.ts.
8. Do NOT invent regulatory citations. If a §2 source is unverifiable,
   mark as REQUIRES-RESEARCH per the per-slice doc §10 and document
   the gap in §12.

═══════════════════════════════════════════════════════════════════════
WHEN PHASE 5 IS COMPLETE — REPORT
═══════════════════════════════════════════════════════════════════════

Report to me:
  - Slice: LOOP-W.W1 — Prohibited-Vendor List Ingest
  - Commit hash (final, post-push)
  - Test count delta (was N, now N+M, +M)
  - Files created: 5 (count + total lines)
  - Files modified: 4 (lines added/deleted per file)
  - REO compliance: G1/G2/G3 all green
  - Any open questions resolved (with answers)
  - Any new risks added to LOOP-W-RISKS.md
  - Next priority slice per the updated STATUS.md (should be W.W2)

Then STOP. Do not start W.W2 in the same session unless I explicitly
say to. Each slice is a discrete unit of work; new slice = new resume
prompt = new session.
```

End of populated W.W1 instance.

---

## §4. How to use this document

### Default workflow — paste §1 each session

1. Open a new Claude Code session in the repo root:
   `cd "/Users/kenith.philip/FedRAMP 20x" && claude`
2. Paste the §1 auto-detect resume prompt (the triple-backtick block
   under "§1. Auto-detect resume prompt — paste THIS each session").
3. The session reads STATUS.md, auto-detects the next-priority slice,
   reads the universal template at §2 of this file, executes Phases
   0-5 for the detected slice, and reports back when done. The same
   prompt works for every slice from now through the final slice of
   the project.
4. Watch for the final report. Verify with:
   ```bash
   git log --oneline -3
   git status -s                           # must be empty
   git log --oneline origin/main..HEAD     # must be empty
   grep "Last shipped" cloud-evidence/docs/STATUS.md
   grep "Next priority" cloud-evidence/docs/STATUS.md
   ```

### Override workflow — when you want a specific slice

Sometimes you'll want to ship a non-default slice — e.g., the auto-
detected slice is blocked on external work, or you want to backfill
a missed slice, or you want to skip ahead in the queue.

Two ways:

(a) **Prepend an OVERRIDE line to the §1 prompt** (least friction):
    ```
    OVERRIDE: ship LOOP-X.XN — <title>
    <then paste the §1 block as-is>
    ```
    The §1 prompt's Override Instructions section at the bottom tells
    the session to skip Phase −1 auto-detection and use your specified
    slice.

(b) **Use §2 explicit-override template** (paste a slice-specific
    prompt directly). Replace the 4 placeholders:
    - `<SLICE-ID>` (e.g. `W.W2`)
    - `<LOOP>` (e.g. `W`)
    - `<SLICE-TITLE>` (from the per-slice doc's frontmatter `title:` field)
    - `<DEPENDENCY-LOOPS>` (from the per-slice doc's frontmatter
      `depends_on:` field)

### Worked example

§3 shows a fully-populated W.W1 prompt with every parameter filled in.
Useful for understanding what auto-detect would produce on the first
session against this STATUS.md.

### For maintenance of this file

When a new core primitive is added (e.g., a new signing scheme or a
new bundle registration mechanism), update §2.10 of this document
(the primitive source-code list in the universal template) so future
prompts include the new file in the mandatory reading list.

When the SLICE-COMPLETION-PROCEDURE.md changes, update §2's Phase 4
to match. The two MUST stay in sync.

This document is the on-disk source of truth for "how to ship a slice
in a new session." It is the documentation-of-the-documentation. Do
not let it drift from CLAUDE.md or SLICE-COMPLETION-PROCEDURE.md.

---

## §5. Reading-order summary (TL;DR for a tired session)

If you somehow get a fresh session and can only read 3 files before
acting:

1. `cloud-evidence/CLAUDE.md` (REO + Scope Guard — the constitution)
2. `cloud-evidence/docs/slices/<LOOP>/<SLICE-ID>.md` (the slice
   implementation contract)
3. `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` (the 7-step
   commit checklist)

Read THIS document fourth — it tells you what else to read and
in what order. Then proceed to Phase 1 implementation.
