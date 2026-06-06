---
slice_id: F.F5
title: 3PAO recommendation letter template
loop: F
status: pending
commit: —
completed_date: —
depends_on: [A.A1, A.A3, A.A4, A.A5]
blocks: [F.F7, I.I1]
estimated_effort: 2 days
last_updated: 2026-06-06
---

# F.F5 — 3PAO recommendation letter template

## TL;DR
Ships a dependency-free `.docx` emitter (mirrors `core/roe-emit.ts` and
`core/ssp-docx.ts` patterns) that produces `out/recommendation-letter.docx`
pre-filled with system identity, assessment period, finding counts from the
real OSCAL AR + POA&M, and three verbatim FedRAMP-style recommendation
checkbox options. The 3PAO opens the Word file, ticks one box, completes
any REQUIRES-OPERATOR-INPUT fields, signs by hand, and returns the file —
the orchestrator NEVER auto-signs (REO Rule 1.10) and NEVER emits
conditional language outside §5 (RAR Guide v3.2 §3.1 unambiguous-language
rule).

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
**Gap closed**: The FedRAMP SAR Template §2 Executive Summary requires a
3PAO authorization recommendation. The RAR Guide v3.2 demands that the
recommendation be "clear, unambiguous, and contain no conditional
language." Today the 3PAO authors this letter from scratch each cycle —
copying system identity, assessment period, and finding counts from
multiple sources. Errors creep in (mismatched system-id between SSP and
recommendation letter; finding counts that do not match the AR; conditional
language slipping into the Executive Summary).

F.F5 closes the gap by emitting a `.docx` whose every count and identifier
traces back to a real on-disk artifact (`out/assessment-results.json`,
`out/poam.json`, `out/inventory.json`) and whose recommendation language
is constrained at the renderer level: §4 prose is filtered against a
denylist of conditional phrases ("subject to", "pending", "contingent on",
etc.); only §5 *Conditions and Risks* permits qualifying language. The
output is the *draft* — the 3PAO's pen-and-ink (or e-signature) action is
the binding artifact.

## Authoritative sources (with verbatim quotes)
- **FedRAMP 3PAO Readiness Assessment Report Guide v3.2** —
  https://www.fedramp.gov/assets/resources/documents/3PAO_Readiness_Assessment_Report_Guide.pdf
  (and the training deck
  https://www.fedramp.gov/assets/resources/training/300-G_3PAO-Readiness-Assessment-Report-RAR-Preparation.pdf):
  > "3PAOs should directly and clearly answer RAR requirements and
  > questions, stating what they found (observations and evidence)
  > during their review and HOW they came about determining if a CSP
  > adequately addresses the question area."
  >
  > "The recommendation must be clear, unambiguous, and contain no
  > conditional language."

- **FedRAMP Security Assessment Report (SAR) Template** —
  https://www.fedramp.gov/assets/resources/templates/FedRAMP-Security-Assessment-Report-(SAR)-Template.docx
  + the Rev5 SAR playbook
  https://www.fedramp.gov/docs/rev5/playbook/csp/authorization/sar/:
  > "Did the 3PAO attest to the accuracy of the SAR and provide an
  > authorization recommendation in Section 2, Executive Summary?"
  >
  > "All instances of controls with an assessment result of 'Other than
  > Satisfied' should be documented as an open risk in the RET, unless
  > the finding was corrected during testing."

- **NIST OSCAL Assessment Results v1.1.2** —
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/json-reference/
  Defines `finding.target.status.state` ∈ `{satisfied, not-satisfied}` —
  the counts §2 quotes are direct counts over the AR.

- **NIST OSCAL POA&M v1.1.2** —
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/plan-of-action-and-milestones/json-reference/
  Defines `poam-item.props[]` including the FedRAMP severity prop
  (high / moderate / low) that §2 finding counts table consumes.

- **NIST SP 800-37 Rev 2 §3.7 Authorize** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-37r2.pdf
  > "Task 3.7 (Authorization Decision): The authorizing official renders
  > an authorization decision for the system or common controls based on
  > the information in the executive summary [of the SAR] …"
  This is why §2 Executive Summary IS the operative element of the
  recommendation letter and why its language matters disproportionately.

- **ECMA-376 (OOXML)** —
  https://ecma-international.org/publications-and-standards/standards/ecma-376/
  Word document format spec. The renderer emits OOXML using the same
  primitives (`core/zip.ts`, deterministic zip-store, `document.xml`,
  `word/_rels/document.xml.rels`) as the LOOP-A.A5 `core/roe-emit.ts`
  emitter, with NO `python-docx` or npm `docx` dependency (REO Rule 3
  exception: standard ISO/ECMA file format).

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/recommendation-letter.ts`
  — dependency-free `.docx` builder + disk emitter; exports
  `renderRecommendationLetterDocx(opts)` (pure) and
  `emitRecommendationLetter(opts)` (disk).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/recommendation-letter-sections.ts`
  — per-section render helpers (six functions, one per §1..§6) so the
  conditional-language guard test can target individual sections.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/recommendation-letter.test.ts`
  — unit tests for the renderer + emitter.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/recommendation-letter/`
  — fixture directory with sample `assessment-results.json`,
  `poam.json`, `inventory.json` used by the tests.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` —
  new flag `--recommendation-letter` + env
  `CLOUD_EVIDENCE_RECOMMENDATION_LETTER`; runs AFTER `--oscal-ar` and
  `--oscal-poam` (so finding counts are accurate) but BEFORE
  `--submission-bundle`. Add CLI flags:
  `--recommendation=<recommend|recommend-with-conditions|do-not-recommend>`,
  `--conditions-narrative <path>`, `--ao-name <name>`, `--ao-title <title>`,
  `--ao-agency <agency>`, `--assessment-period-start <ISO>`,
  `--assessment-period-end <ISO>`, `--three-pao <organization>`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
  — well-known catalogue:
  `{ role: 'recommendation-letter-docx', filename: 'recommendation-letter.docx', description: '3PAO Authorization Recommendation Letter (draft, pre-signature)' }`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/zip.ts` — no
  changes; reused as-is.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sign.ts` — the
  recommendation letter `.docx` itself is signed + timestamped by the
  existing pipeline (manifest entry); the `.docx` content's signature
  block remains empty REQUIRES-OPERATOR-INPUT.

## Schemas / standards
- **OOXML WordprocessingML (ECMA-376)** — same conformance level as
  `core/roe-emit.ts`. Parts emitted: `[Content_Types].xml`, `_rels/.rels`,
  `word/document.xml`, `word/_rels/document.xml.rels`, `word/styles.xml`,
  `word/numbering.xml` (for the §4 checkbox list). All parts go through
  the existing `core/zip.ts` deterministic zip-store helper (no
  compression so byte-identical output for byte-identical input — needed
  for the determinism test).
- **Conditional-language denylist** (case-insensitive, word-boundary
  matched): `subject to`, `pending`, `contingent on`, `provided that`,
  `assuming that`, `if and only if`, `conditional on`, `dependent on`,
  `to be determined`, `TBD`, `pending future`. Hard-coded per RAR Guide
  §3.1. Operator may NOT override (REO Rule 3: published guidance).
- **Section structure (verbatim headings)**:
  - §1 *Identification*
  - §2 *Scope of Assessment*
  - §3 *Methodology Summary*
  - §4 *Recommendation*
  - §5 *Conditions and Risks*
  - §6 *Signature Block*
- **Result shape**:
  ```ts
  interface RecommendationLetterResult {
    path: string;
    bytes: number;
    sha256: string;
    section_counts: {
      open_poam_high: number;
      open_poam_moderate: number;
      open_poam_low: number;
      findings_satisfied: number;
      findings_other_than_satisfied: number;
      components: number;
    };
    requires_operator_input: string[];
    ready_for_signature: boolean;
    forbidden_language_flags: string[];  // always empty in production output
  }
  ```

## Build steps (concrete, numbered)
1. **Interface** in `recommendation-letter.ts`:
   ```ts
   export interface RecommendationLetterOptions {
     runId: string;
     emittedAt?: string;                         // defaults to deterministic value from runId
     systemName?: string;
     systemId?: string;
     cspOrganization?: string;
     threePaoOrganization?: string;
     impactTier?: ImpactTier;
     assessmentPeriodStart?: string;             // ISO date
     assessmentPeriodEnd?: string;               // ISO date
     /** Auto-read from out/assessment-results.json + out/poam.json when absent. */
     findingCounts?: {
       satisfied: number;
       otherThanSatisfied: number;
       open_poam_high: number;
       open_poam_moderate: number;
       open_poam_low: number;
     };
     componentCount?: number;                    // defaults to inventory.json length
     authorizingOfficial?: { name?: string; title?: string; agency?: string };
     /** Three valid values; renderer marks the chosen checkbox. */
     recommendation?: 'recommend' | 'recommend-with-conditions' | 'do-not-recommend';
     conditionsNarrative?: string;
     /** Paths read for auto-fill; defaults below. */
     assessmentResultsPath?: string;             // defaults to out/assessment-results.json
     poamPath?: string;                          // defaults to out/poam.json
     inventoryPath?: string;                     // defaults to out/inventory.json
     apPath?: string;                            // defaults to out/ap.json (cited in §3)
     outPath?: string;                           // defaults to out/recommendation-letter.docx
   }
   ```
2. **Pure renderer** `renderRecommendationLetterDocx(opts)`:
   - Reads counts/identity from on-disk artifacts when corresponding opts
     fields are absent (via inversion-of-control file-reader passed in
     opts for test seams; production path uses `fs.readFileSync`).
   - Builds an in-memory document model: header table (§1), counts table
     (§2), methodology references (§3) — one row per
     `out/ap.json` `back-matter.resources[]` entry; checkboxes (§4);
     conditions narrative + POA&M table (§5); signature cells (§6).
   - Runs every prose paragraph through the conditional-language guard
     `assertNoConditionalLanguage(text, section)`; if any forbidden
     phrase appears in §1..§4 or §6, the function THROWS with
     `ForbiddenLanguageError(phrase, section)`. §5 is the only section
     where the guard is bypassed.
   - Emits OOXML XML via the same primitives as `core/roe-emit.ts`.
3. **§4 checkbox semantics**:
   - When `opts.recommendation` is unset, all three checkboxes render
     empty and a REQUIRES-OPERATOR-INPUT marker appears beside the §4
     heading.
   - When set to `recommend`, the first checkbox renders as marked (☑);
     the other two render empty.
   - Likewise for the other two values.
   - Verbatim labels (paraphrased from FedRAMP guidance; see §6 Open
     questions Q1):
     - `[ ] We recommend authorization.`
     - `[ ] We recommend authorization with the conditions listed in §5.`
     - `[ ] We do NOT recommend authorization.`
4. **§5 wording**: emits `opts.conditionsNarrative` verbatim followed by
   a table listing every open POA&M item grouped by severity (high
   first), with poam-uuid + title + due-date columns.
5. **§6 signature block**: TWO signature cells — 3PAO Lead Assessor and
   3PAO Quality Reviewer. Each cell is a REQUIRES-OPERATOR-INPUT row.
   The orchestrator NEVER fills these (REO Rule 1.10).
6. **Disk emitter** `emitRecommendationLetter(opts)`:
   - Calls renderer, gets `docxBytes`.
   - Writes to `opts.outPath` (default `out/recommendation-letter.docx`).
   - Computes sha256 of the output.
   - Logs `requires_operator_input` count + `ready_for_signature` to the
     orchestrator log.
   - Returns the `RecommendationLetterResult`.
7. **Orchestrator wire**: flag triggers `emitRecommendationLetter()`
   AFTER `--oscal-ar` and `--oscal-poam`, BEFORE `--submission-bundle`.
   The console reports finding counts + ready-for-signature.
8. **Bundler catalogue**: append the well-known entry.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4 — every field that cannot be auto-derived:
- `recommendation`: CLI flag `--recommendation=<...>` or env
  `CLOUD_EVIDENCE_RECOMMENDATION`. Missing → all three checkboxes empty
  + marker on §4 + `ready_for_signature: false`.
- `conditionsNarrative`: CLI flag `--conditions-narrative <path>`
  pointing at a Markdown file, or `config.yaml` key
  `recommendation.conditions`. Missing AND
  `recommendation === 'recommend-with-conditions'` →
  `requires_operator_input += ['conditionsNarrative']` and
  `ready_for_signature: false`.
- `authorizingOfficial.{name,title,agency}`: `config.yaml` key
  `authorizing_official` or REQUIRES-OPERATOR-INPUT cells in §1.
- `assessmentPeriodStart`, `assessmentPeriodEnd`: CLI flags
  `--assessment-period-start <ISO>` / `--assessment-period-end <ISO>`,
  env vars, or REQUIRES-OPERATOR-INPUT cells.
- `systemName`, `systemId`, `cspOrganization`, `threePaoOrganization`,
  `impactTier`: read from `out/oscal/ssp.json` `system-characteristics`
  when available; otherwise REQUIRES-OPERATOR-INPUT.
- Signature cells: ALWAYS REQUIRES-OPERATOR-INPUT — the 3PAO signs in
  Word and uploads back. The system NEVER auto-signs (REO Rule 1.10).

## Test specifications (≥12 tests)
1. `it('renders a valid OOXML docx (zip-store, document.xml parses via fast-xml-parser, [Content_Types].xml present)')` — assertions: parts list contains every required OOXML part; the .docx opens in MS Word's Office Open XML SDK validator (use a smoke check via `unzip -l`).
2. `it('reads finding counts from out/assessment-results.json when findingCounts not supplied')` — fixture AR with 12 satisfied + 3 other-than-satisfied; §2 counts table shows 12/3 exact.
3. `it('reads POA&M severity counts from out/poam.json')` — fixture POA&M with 2 high / 5 moderate / 7 low open; §5 table rows match exactly.
4. `it('reads componentCount from inventory.json when not supplied')` — fixture inventory with 47 assets; §1 row reads `47 components`.
5. `it('emits REQUIRES-OPERATOR-INPUT marker for each unsupplied identity field')` — assertions: missing system-id renders the cell as literal `REQUIRES-OPERATOR-INPUT: systemId`; `requires_operator_input` array contains the field key.
6. `it('renders three empty checkboxes when recommendation is unset')` — XML contains three `<w:sym ...>` unchecked-box glyphs in §4.
7. `it('marks exactly the chosen checkbox when recommendation is set, leaves others empty')` — sub-test per value `recommend` / `recommend-with-conditions` / `do-not-recommend`.
8. `it('refuses to emit conditional language outside §5 (throws ForbiddenLanguageError when systemName contains "subject to")')` — assertion: `expect(() => render({ systemName: 'Acme System (subject to acceptance)' })).toThrow(ForbiddenLanguageError)`.
9. `it('asserts §4 prose contains none of the denylist phrases regardless of input')` — fuzz over every denylist phrase as an input; assert §4 raw XML excludes them.
10. `it('renders conditionsNarrative verbatim in §5 when supplied (Markdown converted to OOXML paragraphs)')` — fixture narrative with bullet list + bold text; assert OOXML preserves structure.
11. `it('lists every open POA&M item grouped by severity in §5 with high rows first')` — assertions: row order, severity columns.
12. `it('ready_for_signature is true only when every operator field is supplied AND recommendation is set AND conditionsNarrative is present when recommend-with-conditions')`.
13. `it('cites SAP + RoE + sampling-methodology by filename in §3 when each exists on disk')` — fixture out/ with all three; assert §3 references them by filename + bundler role.
14. `it('bundler well-known catalogue includes recommendation-letter.docx with role recommendation-letter-docx')`.
15. `it('emits to operator-supplied outPath when provided')`.
16. `it('output is deterministic: same input → byte-identical output (same sha256)')` — render twice, compare sha256.
17. `it('NEVER fills signature cells: §6 cells always contain REQUIRES-OPERATOR-INPUT marker even when recommendation=recommend and every other field is supplied')`.
18. `it('orchestrator wire: --recommendation-letter triggers the emitter and logs ready_for_signature')` — integration test against the orchestrator entry point.

## REO compliance specific to this slice
- Every value in the emitted `.docx` traces to:
  - `out/assessment-results.json` (finding counts).
  - `out/poam.json` (open POA&M items + severity).
  - `out/inventory.json` (component count).
  - `out/ap.json` (back-matter resources cited in §3).
  - Operator-supplied CLI/env/config (identity + recommendation choice +
    conditions narrative + AO details).
- No silent fallbacks: every missing field surfaces as a
  REQUIRES-OPERATOR-INPUT marker in the .docx AND in
  `requires_operator_input`.
- Provenance: the `.docx` filename is registered in
  `core/submission-bundle.ts` with a `coverage_source` entry so
  `npm run check:provenance` passes.
- Signed by: the `.docx` itself is signed (Ed25519) + RFC 3161
  timestamped by the existing `core/sign.ts` pipeline at bundle time.
  The content's signature cells inside the .docx are operator-signed,
  not system-signed.
- Conditional-language guard: hard-coded denylist enforces RAR Guide
  §3.1 verbatim language rule at the renderer level. No way to bypass.

## Verification commands
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/recommendation-letter.test.ts
npm run check:reo
```

## Known risks / issues
- **Risk 1 — Denylist over-fires on legitimate prose**: the phrase
  "pending" might appear in a system name (e.g. "Pending Validation
  Service"). Mitigation: the guard fires on word-boundary matches in
  §1..§4, §6 only; the §1 identifier cell renders the literal string
  verbatim AND the test #8 explicitly covers the case where the system
  name itself violates the guard (the renderer throws — the operator
  must rename the system or quote it). This is intentional: a SAR with
  "Pending Validation Service" violates the RAR Guide.
- **Risk 2 — POA&M severity prop format mismatch**: the LOOP-A.A1 POA&M
  emitter writes severity as a `prop` with `name='severity'`. If a
  future LOOP-B slice renames the prop, F.F5 silently miscounts.
  Mitigation: F.F5 reads severity via a typed helper
  (`getPoamSeverity(item): 'high'|'moderate'|'low'|null`) that the
  POA&M emitter exports; rename forces a typecheck error.
- **Risk 3 — Component count drift**: `out/inventory.json` may include
  deleted assets if the orchestrator ran with `--include-deleted`.
  Mitigation: the renderer filters `inventory.assets.where(a => !a.deleted_at)`
  and documents this in the §1 cell comment.
- **Risk 4 — Word-version compatibility**: some Word versions reject
  `<w:sym>` checkbox glyphs in favor of `<w:checkbox>` forms.
  Mitigation: emit both — `<w:sym>` for legacy compatibility and a
  `<w:sdt>` content-control checkbox for Word 2013+; test in MS Word
  2019, Word 2021, Word for the web.
- **Risk 5 — Determinism break**: `Date.now()` calls in the renderer
  would break the byte-identical determinism test. Mitigation: the
  renderer takes `emittedAt` via opts (defaulting to a deterministic
  value derived from `runId`); no clock dependency in the pure path.
- **Risk 6 — Recommendation language drift if FedRAMP publishes new
  template**: the three checkbox labels are paraphrased from FedRAMP
  guidance, not quoted verbatim from a published recommendation-letter
  template (the template is not currently published separately; the
  recommendation language is embedded in the SAR template Executive
  Summary). Mitigation: if FedRAMP publishes a standalone template,
  switch the labels to verbatim text; tracked in §6 Open questions Q1.

## Open questions (for implementation session to resolve)
- **Q1**: Are the three checkbox label strings verbatim FedRAMP-published
  language, or are they paraphrased? Audit: review the SAR template
  Executive Summary text and the RAR Guide v3.2 §3.1 sample language;
  if a verbatim sentence is available, replace the paraphrase. If not,
  document the paraphrase in the section comment with the source URL.
- **Q2**: Should §3 *Methodology Summary* enumerate every artifact in
  `out/` or only the SAR-relevant ones (SAP, RoE, sampling-methodology,
  AP, AR, POA&M)? Proposal: only the SAR-relevant set + their
  sha256+bundler role.
- **Q3**: Should `--conditions-narrative` accept a Markdown file or a
  plain-text file? Proposal: Markdown (renderer converts headers /
  bullets / bold to OOXML); plain text is a valid Markdown subset.
- **Q4**: For the `recommend-with-conditions` choice, is the
  conditionsNarrative mandatory or optional? Proposal: mandatory; the
  renderer sets `ready_for_signature: false` when missing.
- **Q5**: The §6 signature block — should it embed an empty digital
  signature field that Word can fill, or only a printed-name + date
  pair? Proposal: both — empty `<w:sdt>` digital-signature placeholder
  AND printed-name table, so the 3PAO can use whichever workflow.
- **Q6**: When the bundler ships the `.docx`, is the file's external
  signature (Ed25519 + RFC 3161) sufficient or does FedRAMP expect a
  PAdES/CAdES signature embedded inside the OOXML? Proposal: external
  (matches the rest of the chain); document in the manifest.
- **Q7**: Should the renderer error or warn when `out/assessment-results.json`
  is missing? Proposal: warn (emit REQUIRES-OPERATOR-INPUT counts and
  proceed) — the 3PAO can produce a recommendation letter draft before
  the full AR is ready.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥18)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (slice row + Overall section)
- [ ] LOOP-F-SPEC.md Section 7 status table updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added
- [ ] Commit with `LOOP-F.F5: 3PAO recommendation letter template`
- [ ] Commit amended with hash in STATUS.md + this file + LOOP-F-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
1. Read `cloud-evidence/CLAUDE.md` (REO standard, auto-loaded).
2. This file gives you: sources + files + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-F-SPEC.md` §2 Dependencies.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
5. Read `cloud-evidence/core/roe-emit.ts` to mirror the dependency-free
   `.docx` OOXML+zip-store pattern.
6. Confirm A.A1 (POA&M), A.A3 (AR), and A.A5 (RoE) are `done` in STATUS.md.
7. Verify `out/assessment-results.json`, `out/poam.json`,
   `out/inventory.json` exist (run the orchestrator end-to-end first
   if not).
8. Begin implementation; update Implementation log section as you go.
