# Implementation log — format and update procedure

> Every per-slice doc under `docs/slices/X/X.XN.md` contains an
> **"Implementation log"** section near the bottom. That section is a
> *running journal* the implementing session keeps as work progresses.
>
> This file explains the **format**, **when to update**, and gives
> **example entries**.

---

## 1. Why this exists

A slice may take 4-10 working days. During that time:

1. The session learns things from real cloud SDK calls that contradict
   the per-slice doc's assumptions (e.g. an API field name changed).
2. The session discovers a new risk that belongs in the per-loop risks
   register.
3. The session resolves an "open question" from the per-slice doc and
   the resolution needs to persist.
4. Pre-commit hook fails for a reason that took 2 hours to debug — the
   next session must not re-walk that path.
5. A failed test reveals an edge case the spec missed.

The Implementation log captures all of that **in the same file as the
spec**, so a resuming session sees the spec + the running history in
one read. STATUS.md tracks "done / pending / in-progress"; the
Implementation log tracks "while in-progress, here's what happened".

This is consistent with REO Rule 4 ("operator-supplied data is real
data") applied to the engineering process itself: any decision made
during implementation that diverges from the spec is captured as real
evidence of how the slice came to be, not silently discarded.

---

## 2. Format

Each entry is a **date-stamped block** with four sub-fields:

```
### YYYY-MM-DD [short title]
- **Attempted:** what was tried (file paths, commands, hypotheses).
- **Outcome:** worked / didn't work — concrete signal (test pass/fail, error message, file diff).
- **Learning:** the durable takeaway (a sentence the next session needs).
- **Action:** what changes downstream (updated spec? new risk? open question resolved?).
```

Rules:

- **One block per work session** at minimum. If a session spans multiple
  files / hypotheses, prefer multiple smaller blocks over one
  multi-page block.
- **ISO 8601 date** (YYYY-MM-DD). No timezones — sessions are often
  across timezones; the commit timestamp is the authoritative time.
- **No emoji.** This is engineering log.
- **Cross-reference real file paths** (absolute or repo-root-relative)
  for every claim.
- **Quote real error messages verbatim** (truncated if needed) — never
  paraphrase. Verbatim = searchable by the next session.
- **No silent successes.** Even a "this just worked" entry is useful;
  it tells the next session not to second-guess that path.

---

## 3. When to update

Update the Implementation log at every one of these moments:

### 3.1 At every git commit

Before `git commit`, append a block summarizing what's about to be
committed. The commit message points at the slice ID; the
Implementation log explains the *why* + *learnings*.

### 3.2 At every test failure (transient or persistent)

If `npm test` fails, append a block:
- What the failing test was.
- The full failure output (truncated to the relevant 5-20 lines).
- The hypothesis about cause.
- The fix attempted next.

Persisting transient failures is valuable — a flaky test is a real
signal.

### 3.3 At every research question answered

Per-slice doc has a `## Open questions` section. When the implementing
session resolves one, append an Implementation log block:
- Which open question (Q-number).
- What the answer is + the source.
- What changed in the implementation as a result.

Then, in the same commit, **also update the Open questions section**
in the spec to mark the question resolved (don't delete it — strike it
through or annotate `[resolved YYYY-MM-DD — see Implementation log]`).

### 3.4 At every spec divergence

If the implementing session decides the spec is wrong (a build step in
the per-slice doc isn't workable), append a block:
- What the spec said.
- Why it doesn't work in practice (concrete signal).
- What we did instead.
- Whether the spec should be updated post-merge (recommendation).

### 3.5 At every newly-discovered risk

If implementation surfaces a risk not in the per-loop
`LOOP-X-RISKS.md`, append a block:
- The risk (likelihood + impact + mitigation, same shape as the risks
  register).
- The Implementation log block is the *origin record*; immediately also
  add the entry to `LOOP-X-RISKS.md` in the same commit.

### 3.6 At every external dependency pin

If the slice depends on an external library, API, or schema version
that wasn't pinned in the spec, append a block + capture the pin
in the source (package.json, schema file, etc.).

---

## 4. Example entries

These are real-shaped examples (synthesized) showing the entry shape:

### 4.1 Worked-as-spec example

```
### 2026-06-07 EPSS cache file hash format
- **Attempted:** Implement on-disk cache for FIRST EPSS responses per per-slice doc B.B1 step 5. Default cache path `out/.epss-cache.json`, 24h TTL keyed `{cve}-{date}`.
- **Outcome:** Worked first try. Two tests (`tests/core/risk-score.test.ts:7,8`) pass: API hit on first run, cache hit on second.
- **Learning:** The 24h TTL boundary needs to be exclusive (TTL+epsilon = miss). Spec said "24-hour TTL" without specifying; chose exclusive. Documented in cache loader docstring.
- **Action:** No spec update needed. Adding a single note in B.B1 spec Q3 marking it resolved.
```

### 4.2 Failed-then-fixed example

```
### 2026-06-08 OSCAL POA&M ajv schema rejects new props
- **Attempted:** Run `npm run check:reo` on emitted `out/poam.json` after appending B.B1 props (`composite-score`, `cvss-version`, etc.) to `risk.props[]`.
- **Outcome:** Failed with: `should be equal to one of the allowed values, props[3].name`. Looked at OSCAL v1.1.2 schema (`docs/oscal/oscal_poam_schema.v1.1.2.json` line 4128) — `risk.props[].name` is enum-constrained when `ns` is absent.
- **Learning:** OSCAL v1.1.2 enforces `name` enum only when `ns` defaults. When emitting custom props, ALWAYS set `ns: CE_NS` (`https://cloud-evidence.example/oscal-ns`) — the schema then treats `name` as free-form.
- **Action:** Updated `core/oscal-poam.ts:findingProps()` so every B.B1-added prop sets `ns: CE_NS`. Test added: `tests/core/oscal-poam.test.ts` — every custom prop must carry CE_NS.
```

### 4.3 Open-question-resolved example

```
### 2026-06-09 Q3 resolution: multi-asset criticality aggregation
- **Attempted:** Per-slice doc B.B1 Q3 asks: when a finding's `affected_resources[]` matches multiple inventory assets with different criticality, do we take max, mean, or median? Spec recommends max.
- **Outcome:** Confirmed via test fixture `tests/fixtures/risk-score/multi-asset-finding.json`: 3 assets with criticality 1.0 / 0.5 / 0.1, expected composite uses 1.0 (max). Test passes.
- **Learning:** Max is the right choice — "worst-case" prevents under-scoring when one critical asset is affected alongside non-critical ones. Documented in `core/risk-score.ts` next to the aggregator with a citation to NIST SP 800-30 Rev1 §3.2 (organizational risk = max impact across affected resources).
- **Action:** B.B1 spec Q3 updated: `[resolved 2026-06-09 — max, see Implementation log + risk-score.ts line 248]`.
```

### 4.4 Newly-discovered-risk example

```
### 2026-06-10 New risk: EPSS API CIDR-restricted from corporate networks
- **Attempted:** Test live FIRST EPSS API call from corporate dev environment behind proxy. Expected 200 OK.
- **Outcome:** Got `407 Proxy Authentication Required`. Confirmed with curl: outbound proxy strips Bearer and EPSS rejects.
- **Learning:** Corporate / restricted-egress environments cannot reach `api.first.org` without proxy config. Will affect operator dev workflow + CI runners behind restricted egress.
- **Action:** (1) Added `core/retry.ts` proxy-env support via `HTTPS_PROXY`. (2) Added risk **R-NEW-1** to `LOOP-B-RISKS.md`: "EPSS API may be CIDR-blocked; operator must set HTTPS_PROXY or supply local CVE→EPSS map". (3) Documented in B.B1 spec's `## Known risks` section.
```

### 4.5 Spec-divergence example

```
### 2026-06-11 Spec divergence: risk-config weight validation
- **Attempted:** Per-slice doc step 9 + test #20 says config loader throws when weights don't sum to 1.0. Implemented as documented.
- **Outcome:** Tests passed but breaks the "drop epss term + re-normalize" branch (step 3) — re-normalised weights now violate the validator.
- **Learning:** Validator must check the *input* weights (sum=1.0), not the *runtime* normalized weights. After loading + validation, the engine derives normalized weights per-finding without re-validating.
- **Action:** Split the validation into `validateRiskConfigInput()` (loader) and a separate `normalizeWeights(finding, opts)` (per-finding). Tests adjusted. Spec test #20 still passes; new test added for the normalization path.
```

### 4.6 Pre-commit-hook-failure example

```
### 2026-06-12 lint:no-stubs caught a placeholder in test fixture
- **Attempted:** `git commit -m 'LOOP-B.B1: composite scoring implemented'`.
- **Outcome:** Pre-commit hook failed:
  ```
  lint:no-stubs FAIL
   tests/fixtures/risk-score/sample-finding.json:14
   "title": "TODO: replace with real CVE finding"
  ```
- **Learning:** Even fixture files trigger G1 lint when they contain TODO. The lint allowlist covers `tests/`, `fixtures/`, but NOT fixture *contents*. Path-based + content-based allowlist conflict.
- **Action:** Renamed `TODO:` in the fixture to `[fixture-placeholder]` so the lint passes. Filed a follow-up to clarify G1 allowlist semantics in REO documentation (not blocking this commit). Re-attempted commit, passed.
```

---

## 5. Cross-references

This file is referenced by:

- **Every per-slice doc** under `docs/slices/X/X.XN.md` — the
  Implementation log section there points back here for format
  guidance.
- **`SLICE-COMPLETION-PROCEDURE.md`** — Step 4 (Update spec doc)
  explicitly references the Implementation log update obligation.
- **`cloud-evidence/CLAUDE.md`** — the Strong-Directive section
  mandates Implementation log updates at meaningful milestones.

---

## 6. What NOT to put in the Implementation log

- Vague status updates ("worked on this today"). Be concrete.
- Confidential operator data (PII, credentials, infrastructure
  details). Implementation logs are committed to git; treat them as
  public.
- Speculation about future slices. Use the `## Open questions` section
  of the per-slice doc for that.
- Long verbatim test output. Truncate to the 5-20 lines that matter.
- Cosmetic refactors. Squash into a single entry per session.

---

## 7. Reading an Implementation log

If you're resuming a slice that's partially implemented:

1. Read the per-slice doc top-to-bottom (TL;DR, spec, build steps,
   tests, REQUIRES-OPERATOR-INPUT, risks, open questions, completion
   checklist).
2. **Then read the Implementation log block by block in chronological
   order.** This is the catch-up read. By the end of it you know
   exactly where the previous session left off + why.
3. Look at the most-recent block's `Action:` field. That's your next
   step in 90% of cases.
4. If the most-recent block is `failed` with no resolution, that's
   your starting hypothesis — re-attempt with the documented learning
   in mind.

---

## 8. When the slice ships

The final Implementation log block on a shipped slice should:

- Be dated the day the slice was merged.
- Have `Outcome:` = "Shipped. Commit `<hash>`. STATUS.md + LOOP-X-SPEC
  + per-slice frontmatter all updated."
- Have `Action:` = "Slice complete. See CHANGELOG.md for the
  user-facing summary."

The whole Implementation log remains in the per-slice doc forever; it
is the slice's archaeological record. Future readers (operator
re-investigating a decision, 3PAO asking "why this weight not that
one?", auditor reviewing process) consult it.
