---
slice_id: F.F7
title: SAR draft generator
loop: F
status: pending
commit: —
completed_date: —
depends_on: [A.A1, A.A2, A.A3, A.A4, A.A5, F.F1, F.F2, F.F3, F.F4, F.F5, F.F6]
blocks: [I.I1, K.K1]
estimated_effort: 4 days
last_updated: 2026-06-06
---

# F.F7 — SAR draft generator

## TL;DR
Ships `core/sar-draft.ts` plus the per-section render helpers under
`core/sar-sections/` (a dependency-free `.docx` emitter, mirroring
`core/roe-emit.ts` / `core/ssp-docx.ts`) that produces
`out/sar-draft.docx` populated from every prior LOOP-A + LOOP-F artifact:
OSCAL AR (LOOP-A.A3), POA&M (LOOP-A.A1), AP (LOOP-A.A2), inventory,
signoffs (F.F1), comments (F.F2), sampling methodology (F.F3),
walk-through evidence (F.F4), recommendation letter (F.F5), and the
current ATO state (F.F6). The 3PAO opens the draft, completes any
REQUIRES-OPERATOR-INPUT markers, and signs manually — the renderer NEVER
auto-signs (REO Rule 1.10) and the §2 Executive Summary is filtered for
conditional language (RAR Guide v3.2 §3.1).

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
**Gap closed**: The FedRAMP SAR is the authoritative artifact the AO uses
to make the ATO decision (per NIST SP 800-37 Rev 2 §3.7 task R-3). Today
the 3PAO writes the SAR in Word from scratch, copying findings + counts +
identifiers across multiple documents — each copy a chance for drift. F.F7
emits a `.docx` that is structurally complete (every section the FedRAMP
SAR Template demands, with verbatim section headings) and content-seeded
from real on-disk artifacts. Every paragraph cites its source (sha256 +
filename + AR finding-uuid where applicable), so the AO + future auditors
can re-verify any line item.

The slice also closes a critical REO gap: a SAR `.docx` that *claims* a
finding has assessor signoff but the AR shows no signoff (because the
orchestrator ran without `--ingest-signoffs`) is a fabrication. F.F7
emits explicit REQUIRES-OPERATOR-INPUT markers in those rows, so the
draft visibly flags missing dependencies rather than silently inventing
them.

## Authoritative sources (with verbatim quotes)
- **FedRAMP Security Assessment Report (SAR) Template** —
  https://www.fedramp.gov/assets/resources/templates/FedRAMP-Security-Assessment-Report-(SAR)-Template.docx
  + the Rev5 SAR playbook
  https://www.fedramp.gov/docs/rev5/playbook/csp/authorization/sar/
  > "The SAR documents the results of the security assessment for the
  > CSO, including a summary of the risks remaining at the conclusion
  > of the assessment."
  >
  > Required components:
  > - "SAR" (the body document)
  > - "Appendix A: Risk Exposure Table (RET)"
  > - "Appendix B: Security Requirements Traceability Matrix (SRTM)
  >   Workbook"
  > - "Appendix C: Vulnerability Scan Results"
  > - "Appendix D: Documentation Review Findings"
  > - "Appendix E: Auxiliary Documents"
  > - "Appendix F: Penetration Test Report"
  > - "Evidence collected during the assessment"
  >
  > "All instances of controls with an assessment result of 'Other than
  > Satisfied' should be documented as an open risk in the RET, unless
  > the finding was corrected during testing."

- **NIST SP 800-53A Rev 5** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53Ar5.pdf
  §3 Assessment Procedures defines the Satisfied / Other Than Satisfied
  finding language verbatim:
  > "Finding: each determination statement is rated either Satisfied (S)
  > or Other Than Satisfied (O)."
  The SAR draft's §5 Findings Table uses these single-letter abbreviations
  verbatim (REO Rule 3 allowed fixed data: NIST-published terminology).

- **NIST SP 800-37 Rev 2 §3.7 Authorize** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-37r2.pdf
  > "Task R-3 Authorization Decision: The authorizing official renders
  > an authorization decision for the system or common controls based
  > on the information in the executive summary [of the SAR] and other
  > supporting information found in the authorization package."

- **FedRAMP 3PAO Readiness Assessment Report Guide v3.2** —
  https://www.fedramp.gov/assets/resources/documents/3PAO_Readiness_Assessment_Report_Guide.pdf
  > "The recommendation must be clear, unambiguous, and contain no
  > conditional language."
  Applied to §2 Executive Summary by the conditional-language guard
  inherited from F.F5.

- **NIST OSCAL Assessment Results v1.1.2 reference** —
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/json-reference/
  Provides the field set the §5 Findings Table reads:
  `result.findings[].uuid`, `.title`, `.target.target-id`,
  `.target.status.state`, `.related-observations[].observation-uuid`,
  `.related-risks[].risk-uuid`.

- **NIST OSCAL POA&M v1.1.2 reference** —
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/plan-of-action-and-milestones/json-reference/
  Provides the §6 Non-Conforming Controls + Appendix A RET inputs.

- **FedRAMP RFC-0024 (OSCAL submissions)** —
  https://www.fedramp.gov/rfcs/0024/
  > "FedRAMP is pivoting to OSCAL-first submissions; .docx artifacts
  > should be derivable from the OSCAL truth source so updates only
  > require regenerating the document."
  F.F7 honors this: every cell in the .docx cites the AR finding-uuid
  or POA&M poam-item uuid it derived from.

- **ECMA-376 (OOXML)** —
  https://ecma-international.org/publications-and-standards/standards/ecma-376/
  Same compliance profile as `core/roe-emit.ts` / `core/ssp-docx.ts`.

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sar-draft.ts`
  — top-level emitter + pure renderer; orchestrates the section
  helpers; ~600 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sar-sections/cover.ts`
  — §0 cover page (system identity + impact tier + period).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sar-sections/executive-summary.ts`
  — §2; includes the conditional-language guard.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sar-sections/system-overview.ts`
  — §3; reads the SSP for high-level architecture text.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sar-sections/assessment-methodology.ts`
  — §4; cites SAP + RoE + sampling methodology by sha256 + filename.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sar-sections/findings-table.ts`
  — §5; one row per AR finding with control-id, statement-id, method,
  status (S/O), severity, title, sign-off uuid, comment count,
  walk-through evidence count.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sar-sections/non-conforming.ts`
  — §6; enumerates `status.state === 'not-satisfied'` findings + POA&M
  cross-references.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sar-sections/interconnected.ts`
  — §7 Risks for Interconnected Systems; reads SSP `system-implementation.interconnections[]`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sar-sections/recommendation.ts`
  — §8 Recommendations & Conclusion; quotes the recommendation letter
  by sha256 + filename when it exists; else REQUIRES-OPERATOR-INPUT.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sar-sections/appendix-pointers.ts`
  — Appendices A-F; renders a per-appendix pointer table with
  sha256 + bundler-role + relative path (or absolute URL).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sar-sections/signature-block.ts`
  — §9 (final); 3PAO Lead Assessor + 3PAO Quality Reviewer + AO
  signature cells; always REQUIRES-OPERATOR-INPUT.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sar-sections/index.ts`
  — re-export barrel.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/sar-draft.test.ts`
  — top-level tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/sar-sections/`
  — per-section unit tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/sar-draft/`
  — fixture directory with sample AR + POA&M + AP + inventory + SSP +
  recommendation-letter + ato-workflow-state.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`
  — new flag `--sar-draft` + env `CLOUD_EVIDENCE_SAR_DRAFT`. Runs AFTER
  `--oscal-ar`, `--oscal-poam`, `--recommendation-letter`, AND
  `--ato-export` (so §8 can cite the recommendation + the current ATO
  state); BEFORE `--submission-bundle`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
  — well-known catalogue entry:
  `{ role: 'sar-draft-docx', filename: 'sar-draft.docx', description: 'FedRAMP SAR — 3PAO draft for finalization (REQUIRES-OPERATOR-INPUT markers for fields not derivable from AR/POA&M/SSP)' }`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-poam.ts`
  — expose a typed `getOpenRisks(poam): { uuid, title, severity, due_date, control_id, related_finding_uuid }[]`
  reader used by §6 Non-Conforming Controls and Appendix A RET.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/recommendation-letter.ts`
  — expose `readRecommendationLetterMetadata(path): { sha256, recommendation, ready_for_signature }`
  used by §8.

## Schemas / standards
- **SAR Template structure** (verbatim section headings; REO Rule 3
  exception: FedRAMP-published template):
  - §1 Identification / System Identifier
  - §2 Executive Summary (with recommendation language per RAR §3.1)
  - §3 System Overview / Architecture
  - §4 Assessment Methodology
  - §5 Security Assessment Results (findings table)
  - §6 Non-Conforming Controls
  - §7 Risks for Interconnected Systems
  - §8 Recommendations & Conclusion
  - Appendix A: Risk Exposure Table (RET) → pointer to POA&M
  - Appendix B: SRTM Workbook → pointer to IIW
  - Appendix C: Vulnerability Scan Results → pointer to VDR outputs
  - Appendix D: Documentation Review Findings → pointer to
    process-artifact tracker exports
  - Appendix E: Auxiliary Documents → pointer to ssp.docx, ap.json,
    recommendation-letter.docx, sampling-methodology.json, etc.
  - Appendix F: Penetration Test Report → pointer to LOOP-K.K1 output
    (or REQUIRES-OPERATOR-INPUT until LOOP-K ships)
- **Finding status language**: S / O (Satisfied / Other Than Satisfied)
  per SP 800-53A Rev 5. REO Rule 3 allowed.
- **Result shape**:
  ```ts
  interface SarDraftResult {
    path: string;
    bytes: number;
    sha256: string;
    section_counts: {
      findings_total: number;
      findings_satisfied: number;
      findings_other_than_satisfied: number;
      non_conforming_controls: number;
      open_risks: number;
      interconnections: number;
      appendix_pointers: number;
    };
    requires_operator_input: string[];
    ready_for_signature: boolean;
    forbidden_language_flags: string[];   // always empty in production
  }
  ```

## Build steps (concrete, numbered)
1. **Interface** in `sar-draft.ts`:
   ```ts
   export interface SarDraftOptions {
     runId: string;
     emittedAt?: string;                          // deterministic from runId by default
     outDir?: string;                             // defaults to out/
     outPath?: string;                            // defaults to <outDir>/sar-draft.docx
     systemName?: string;
     systemId?: string;
     cspOrganization?: string;
     threePaoOrganization?: string;
     impactTier?: ImpactTier;
     assessmentPeriodStart?: string;
     assessmentPeriodEnd?: string;
     useAbsoluteUrls?: boolean;                   // appendix pointers use FEDRAMP_REPO_URL when true
     fedrampRepoUrl?: string;                     // operator-supplied
     // File paths overridable for tests
     assessmentResultsPath?: string;
     poamPath?: string;
     apPath?: string;
     inventoryPath?: string;
     sspPath?: string;
     recommendationLetterPath?: string;
     samplingMethodologyPath?: string;
     atoStatePath?: string;
     walkthroughBundlePath?: string;
   }
   ```
2. **Top-level renderer** `renderSarDraftDocx(opts)`:
   - Loads every available source file via the reader functions below.
   - Calls each section helper, passing the loaded data.
   - Concatenates OOXML XML fragments.
   - Aggregates `requires_operator_input` from all sections.
   - Validates: no forbidden language in §1..§5 or §7..§8 (§6 + §8
     Conditions are partial exceptions where conditional language
     describing risks is appropriate; the guard fires only on §2 and
     elsewhere except §6/§8 conditions paragraphs).
3. **Reader helpers** (one function per source artifact, all in
   `sar-draft.ts`):
   - `readArOrNull(path)` → AR + sha256.
   - `readPoamOrNull(path)` → POA&M + sha256.
   - `readApOrNull(path)` → AP + sha256.
   - `readInventoryOrNull(path)` → inventory + sha256.
   - `readSspOrNull(path)` → SSP + sha256.
   - `readRecommendationOrNull(path)` → via
     `readRecommendationLetterMetadata`.
   - `readSamplingMethodologyOrNull(path)` → sampling plan + sha256.
   - `readAtoStateOrNull(path)` → state + transitions + sha256.
   - `readWalkthroughManifestOrNull(path)` → list of artifacts +
     finding-uuid index.
4. **§2 Executive Summary** (`executive-summary.ts`):
   - Finding counts (S / O) from AR.
   - Open POA&M severity summary from POA&M.
   - Component count from inventory.
   - 3PAO recommendation: extract from `recommendation-letter.docx`
     metadata (the checkbox state) when it exists; else
     REQUIRES-OPERATOR-INPUT.
   - Run every prose paragraph through the F.F5-shared
     `assertNoConditionalLanguage` guard.
5. **§5 Findings Table** (`findings-table.ts`):
   - One row per `result.findings[]` in AR.
   - Columns: control-id, statement-id, method (EXAMINE/INTERVIEW/TEST),
     status (S/O), severity (from related POA&M item), title, sign-off
     uuid (from `props.assessor-signoff-uuid` if present; else
     REQUIRES-OPERATOR-INPUT), comment count (from finding.remarks
     parsing or 0), walk-through evidence count.
   - When a finding has no sign-off, the row's Status column emits
     `S/O REQUIRES-OPERATOR-INPUT` with a footnote pointing at the
     F.F1 spec.
6. **§6 Non-Conforming Controls** (`non-conforming.ts`):
   - Filter AR findings where `target.status.state === 'not-satisfied'`.
   - Cross-reference each to the POA&M item via
     `related-risks[].risk-uuid` → POA&M `risks[]`.
   - One row per non-conforming finding with: control-id, finding title,
     POA&M item uuid, planned milestone date.
7. **§7 Risks for Interconnected Systems** (`interconnected.ts`):
   - Read `out/oscal/ssp.json`
     `system-implementation.interconnections[]`.
   - One row per interconnection with: name, direction, protocol,
     authentication, residual-risk narrative (from interconnection
     `remarks` field if present; else REQUIRES-OPERATOR-INPUT).
8. **§8 Recommendations & Conclusion** (`recommendation.ts`):
   - When `recommendation-letter.docx` exists: quote the metadata's
     `recommendation` choice (e.g. "We recommend authorization.") +
     cite the file by sha256 + filename.
   - When absent: REQUIRES-OPERATOR-INPUT.
   - Apply the conditional-language guard.
9. **Appendix pointers** (`appendix-pointers.ts`):
   - One table per appendix (A through F).
   - Each table row: appendix sub-item title, relative path (or absolute
     URL when `useAbsoluteUrls`), sha256, bundler role.
   - For Appendix F (PenTest), emit REQUIRES-OPERATOR-INPUT with a
     pointer to the LOOP-K.K1 spec until LOOP-K ships.
   - For Appendix E (Auxiliary), enumerate every artifact in the
     submission bundle's manifest that does NOT belong to A/B/C/D/F.
10. **§9 Signature block** (`signature-block.ts`):
    - 3PAO Lead Assessor, 3PAO Quality Reviewer, AO cells.
    - ALL REQUIRES-OPERATOR-INPUT — the .docx never auto-signs (REO
      Rule 1.10).
    - Embed an empty `<w:sdt>` digital-signature placeholder per cell
      so Word can fill via its digital signature workflow.
11. **Disk emitter** `emitSarDraft(opts)`:
    - Calls renderer; writes to `outPath`; computes sha256.
    - Logs `requires_operator_input` count + `ready_for_signature`.
12. **Orchestrator wire**: `--sar-draft` triggers the emitter; runs
    AFTER `--oscal-ar`, `--oscal-poam`, `--recommendation-letter`,
    `--ato-export`; BEFORE `--submission-bundle`.
13. **Bundler catalogue**: append `sar-draft.docx` entry.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4:
- All identity / period fields not supplied via opts, env, or SSP.
- §2 recommendation language when `out/recommendation-letter.docx` is
  absent OR `ready_for_signature: false`.
- §5 status column per finding when no sign-off exists for that
  (control-id, statement-id, method).
- §7 residual-risk narrative per interconnection when not in SSP.
- §8 recommendation pointer when no recommendation letter exists.
- Appendix F (PenTest) until LOOP-K.K1 ships.
- §9 signature block: ALWAYS REQUIRES-OPERATOR-INPUT (REO Rule 1.10).
- `useAbsoluteUrls=true` without `fedrampRepoUrl` set →
  REQUIRES-OPERATOR-INPUT marker on every appendix pointer URL.

## Test specifications (≥12 tests)
1. `it('reads findings from out/assessment-results.json and emits one row per finding in §5')` — fixture AR with 24 findings → 24 rows; assert exact count.
2. `it('uses S / O status language verbatim from SP 800-53A Rev 5 (not "Pass"/"Fail")')` — assert §5 cells contain literal `S` or `O` characters, not other strings.
3. `it('emits REQUIRES-OPERATOR-INPUT in §5 status column when no signoff exists for a finding')` — fixture AR finding with no `assessor-signoff-uuid` prop; assert the row's Status cell contains the marker.
4. `it('refuses to emit conditional language in §2 (throws ForbiddenLanguageError when systemName contains forbidden phrase)')` — assert thrown error matches `ForbiddenLanguageError`.
5. `it('asserts no denylist phrases (`subject to`, `pending`, `TBD`) appear in §2 raw XML in production output')` — fuzz across denylist.
6. `it('cross-references POA&M items by uuid in §6 Non-Conforming Controls')` — fixture POA&M risks linked to AR findings by `related-risks[].risk-uuid`; assert §6 rows include the POA&M uuid.
7. `it('appendix table contains correct sha256 + relative path per artifact present in out/')` — assert each row's sha256 matches `crypto.createHash('sha256').update(file).digest('hex')`.
8. `it('useAbsoluteUrls=true substitutes FEDRAMP_REPO_URL in appendix paths; missing fedrampRepoUrl emits REQUIRES-OPERATOR-INPUT')`.
9. `it('ready_for_signature is true only when (a) recommendation letter present + (b) every finding has signoff + (c) all identity fields populated + (d) every required appendix has a real artifact')`.
10. `it('emits section_counts.findings_total = AR result.findings.length')`.
11. `it('the .docx is a valid OOXML zip (parts list contains document.xml + word/_rels/document.xml.rels + [Content_Types].xml)')`.
12. `it('embeds the walk-through bundle hrefs from observation.relevant-evidence[] in §5 evidence column')` — fixture AR with walkthrough observations; assert §5 row's evidence cell links to the per-finding evidence folder.
13. `it('bundler well-known catalogue includes sar-draft.docx')`.
14. `it('runs without throwing when individual sources (poam.json, signoffs export, ato-workflow-state.json) are absent, emitting REQUIRES-OPERATOR-INPUT in their place')`.
15. `it('§8 cites the recommendation-letter.docx by filename + sha256 when it exists; else REQUIRES-OPERATOR-INPUT')`.
16. `it('§9 signature block ALWAYS REQUIRES-OPERATOR-INPUT — never auto-fills a signature cell even when every other field is supplied')`.
17. `it('Appendix F is REQUIRES-OPERATOR-INPUT with a pointer to the LOOP-K.K1 spec until LOOP-K ships (and ships normally once LOOP-K artifacts exist)')`.
18. `it('output is deterministic: same input → byte-identical output (same sha256) across two runs')`.
19. `it('section_counts add up: findings_satisfied + findings_other_than_satisfied === findings_total')` — invariant test.
20. `it('chain integrity: when LOOP-A.A4 reports a missing artifact in the manifest, the corresponding appendix row emits REQUIRES-OPERATOR-INPUT (never a silent fallback)')`.

## REO compliance specific to this slice
- The draft never auto-signs (REO Rule 1.10). §9 signature cells ALWAYS
  REQUIRES-OPERATOR-INPUT; covered by test #16.
- Every emitted count traces to a real on-disk artifact (AR, POA&M,
  inventory, SSP, recommendation-letter, ato-workflow-state, walkthrough
  manifest). Missing artifact → REQUIRES-OPERATOR-INPUT, never silent
  fallback.
- Conditional-language guard enforced in §2 and §8 (test #4 + #5).
- Every appendix pointer has a verifiable sha256 (computed at emit
  time from the on-disk file).
- When the orchestrator's chain-integrity check (LOOP-A.A4) reports a
  missing artifact, the corresponding SAR appendix row emits
  REQUIRES-OPERATOR-INPUT instead of a silent fallback (test #20).
- Provenance: `sar-draft.docx` is registered in
  `submission-bundle.ts`'s well-known catalogue with a coverage_source
  entry; `npm run check:provenance` passes.
- Signed by: the `.docx` itself is signed (Ed25519) + RFC 3161
  timestamped by the existing `core/sign.ts` pipeline at bundle time.
  The content's signature cells inside the .docx are 3PAO/AO-signed,
  not system-signed.

## Verification commands
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/sar-draft.test.ts tests/core/sar-sections/
npm run check:reo
```

## Known risks / issues
- **Risk 1 — Source-artifact drift mid-render**: if the AR is being
  re-emitted while the SAR draft is rendering, the draft could capture
  inconsistent counts. Mitigation: the renderer reads every source
  file UP FRONT with sha256 capture; if any file changes mid-render
  (sha256 mismatch on re-read), abort and re-emit.
- **Risk 2 — Findings-table row count explosion**: a Moderate baseline
  authorizes ~325 controls × ~3 statements × ~2 methods ≈ 2000 rows.
  OOXML tables that large make Word sluggish. Mitigation: render the
  table with `<w:tblPr>` properties for repeating header rows + page
  breaks every 50 rows; document the size in the SAR cover page.
- **Risk 3 — Appendix E enumeration drift**: as new well-known
  artifacts ship in future loops, Appendix E may become stale.
  Mitigation: Appendix E is computed at emit time from the bundle's
  current well-known catalogue + the on-disk manifest, not hard-coded.
- **Risk 4 — SSP-derived interconnections may be empty**: many CSPs
  with no interconnected systems leave the SSP array empty.
  Mitigation: when empty, §7 emits "No interconnected systems"
  literally (NOT REQUIRES-OPERATOR-INPUT — empty is a valid answer).
  The renderer asks the operator to confirm via a CLI flag
  `--confirm-no-interconnections` if the SSP array is empty AND the
  flag is unset.
- **Risk 5 — Recommendation letter has REQUIRES-OPERATOR-INPUT
  markers**: F.F5 emits the letter with markers when fields are
  missing. F.F7's §8 must NOT propagate those markers as if they were
  the actual recommendation. Mitigation: read
  `recommendation-letter.docx` metadata via
  `readRecommendationLetterMetadata` which exposes
  `ready_for_signature: boolean`; when `false`, §8 emits its own
  REQUIRES-OPERATOR-INPUT with a pointer at the letter's markers.
- **Risk 6 — Determinism break via clock**: the renderer must NOT
  call `Date.now()` or read system time. Mitigation: every section
  takes `emittedAt` from opts (deterministic default from runId);
  test #18 verifies byte-identical output across runs.
- **Risk 7 — Walk-through evidence count out-of-sync with AR**: if
  F.F4 ingest ran AFTER the AR emit, the AR may not reference the
  walk-through bundle. Mitigation: orchestrator order forces F.F4
  ingest BEFORE `--oscal-ar`; document the order in the orchestrator
  comments AND the §5 evidence cell counts from `walkthroughBundle`
  manifest directly (not AR observations) so it remains correct even
  if order slips.
- **Risk 8 — Word version compatibility**: heavy use of `<w:sdt>`
  digital-signature placeholders may not render in older Word
  versions. Mitigation: test in MS Word 2019 / 2021 / Word for the
  web; fall back to printed-name table when `<w:sdt>` rejected.

## Open questions (for implementation session to resolve)
- **Q1**: Section heading numbering — the SAR template uses §1..§8 +
  Appendix A..F; should the cover page be §0 or just "Cover"?
  Proposal: "Cover" (no number) followed by §1..§8 + Appendix A..F to
  match the template exactly.
- **Q2**: For multi-row findings (one finding, multiple
  determination-statements), should §5 emit one row per
  (finding, statement, method) tuple or one row per finding with a
  nested table? Proposal: one row per tuple; matches F.F1 signoff
  granularity.
- **Q3**: How should §6 surface POA&M items whose corresponding AR
  finding is `satisfied` (i.e. a stale POA&M item)? Proposal: list in
  a "Resolved Risks" sub-table within §6, sourced from POA&M
  `risks` where `status === 'closed'`.
- **Q4**: §7 Risks for Interconnected Systems — does the SAR template
  expect per-interconnection finding rows, or just a narrative?
  Proposal: a narrative section followed by a table where each row is
  one interconnection × (S/O) status. Verify with FedRAMP SAR sample
  if available.
- **Q5**: Appendix F (PenTest) until LOOP-K.K1 ships — should the
  draft refuse to emit (block) or emit with the marker? Proposal:
  emit with REQUIRES-OPERATOR-INPUT marker; document the path forward.
- **Q6**: Should `useAbsoluteUrls=true` rewrite every appendix path
  with the absolute URL, or only the "public-facing" subset?
  Proposal: only the public-facing subset (the bundle is internal;
  the SAR's external readers need URLs only for public artifacts).
- **Q7**: When `out/ato-workflow-state.json` shows
  `currentState='ATO_GRANTED'`, should §2 Executive Summary include
  the ATO grant date as a historical fact? Proposal: yes — adds
  context; cite the transition record uuid + transitioned_at.
- **Q8**: Should the renderer support a `--lite` mode that omits the
  full findings table (just summarizing counts) for early-draft
  iterations? Proposal: yes — drives faster iteration during 3PAO
  authoring; `--lite` adds a banner that the draft is not
  publication-ready.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥20)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (slice row + Overall section; LOOP-F marked COMPLETE)
- [ ] LOOP-F-SPEC.md Section 7 status table updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added
- [ ] Commit with `LOOP-F.F7: SAR draft generator (closes LOOP-F)`
- [ ] Commit amended with hash recorded in STATUS.md + this file + LOOP-F-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
1. Read `cloud-evidence/CLAUDE.md` (REO standard, auto-loaded).
2. This file gives you: sources + files + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-F-SPEC.md` §2 Dependencies.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
5. Read `cloud-evidence/core/roe-emit.ts` and `cloud-evidence/core/ssp-docx.ts`
   to mirror the dependency-free `.docx` OOXML+zip-store pattern.
6. Confirm A.A1, A.A2, A.A3, A.A4, A.A5, F.F1, F.F2, F.F3, F.F4, F.F5,
   F.F6 are ALL `done` in STATUS.md (F.F7 is the closeout slice; needs
   every prior slice).
7. Verify the on-disk artifact chain by running the orchestrator
   end-to-end on a test config: `out/assessment-results.json`,
   `out/poam.json`, `out/ap.json`, `out/inventory.json`,
   `out/oscal/ssp.json`, `out/recommendation-letter.docx`,
   `out/sampling-methodology.json`, `out/ato-workflow-state.json`
   should all exist.
8. Begin implementation; update Implementation log section as you go.
