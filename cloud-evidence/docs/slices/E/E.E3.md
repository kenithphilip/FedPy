---
slice_id: E.E3
title: Annual Assessment Package Generator
loop: E
status: pending
commit: —
completed_date: —
depends_on: [A.A1, A.A2, A.A3, A.A4, E.E1, E.E2, E.E4, E.E7]
blocks: [F.F1, F.F7, H.H1]
estimated_effort: 5 days
last_updated: 2026-06-06
---

# E.E3 — Annual Assessment Package Generator

## TL;DR
Emits the annual-cycle bundle (`out/annual-assessment-<YYYY>.tar.gz`): aggregates 12 monthly POA&M ledger entries, every monthly bundle's INDEX, the latest SSP + AP + AR, the annual SSP diff (E.E4), IRP + ISCP AARs (E.E7), and the in-scope-this-year control list (Core 129 + rotating subset for 3-year full-baseline coverage). One command produces the deliverable a 3PAO needs to start the annual assessment.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
The 2026 ConMon Evidence Guide is explicit: *"Annual Assessment costs will be about 80% of your original Assessment"*, and the 3PAO must produce a fresh full-package each year, covering 129 predefined Core Controls plus a rotating non-core subset that, over a 3-year window, covers 100% of the baseline. Today's submission-bundle (LOOP-A.A4) emits a per-run bundle — but an "annual" bundle must aggregate 12 months of evidence, not a single snapshot.

Without this slice the operator copies 12 directories into a folder by hand, drops dates from filenames, and ships a tarball that doesn't match the per-run bundle schema. Annual-assessment artifact handoff to the 3PAO becomes an error-prone manual process.

Maps to: NIST SP 800-53 Rev5 controls CA-2 (Control Assessments — annual), CA-7 (Continuous Monitoring), PL-2 (System Security Plan — annual review); FedRAMP Annual Assessment Guidance v3.0 (2024-02-15).

## Authoritative sources (with verbatim quotes)
- <https://www.fedramp.gov/assets/resources/documents/CSP_Annual_Assessment_Guidance.pdf> — FedRAMP Annual Assessment Guidance v3.0 (2024-02-15):
  > "The Annual Assessment is a partial assessment of the security control baseline. The CSP and 3PAO shall test a subset of the security control baseline each year so that, over a three-year cycle, 100% of the baseline has been assessed."
  > "Each annual assessment must test the 'Core Controls' as defined by FedRAMP, plus additional controls selected to round out the three-year cycle."

- <https://elevateconsult.com/insights/fedramp-conmon-deliverables-essential-evidence-requirements-guide-2026/> — ConMon Evidence Guide 2026 (synthesis):
  > "129 predefined Core Controls; Additional control subsets selected to ensure full baseline review within three-year cycle; Fresh evidence each year (previous assessment evidence cannot be reused); Security Assessment Report documenting all findings."
  > "Annual Assessment costs will be about 80% of your original Assessment ..."

- <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf> — NIST SP 800-53 Rev5 CA-2 (page 92):
  > "Select the appropriate assessor or assessment team for the type of assessment to be conducted; Develop a control assessment plan that describes the scope of the assessment ... Produce a control assessment report that documents the results of the assessment."

- <https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/overview/> — FedRAMP Rev5 ConMon Overview:
  > "Each year, the CSP must engage a 3PAO to conduct an Annual Assessment of a subset of the security controls. The Annual Assessment results in an updated Security Assessment Report (SAR) and POA&M."

- <https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/json-reference/> — OSCAL Assessment Results JSON reference v1.1.2:
  > "results [1+]: At least one result is required. Each result contains start, end, assessment-log, attestations, observations, risks, findings."

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/annual-assessment.ts` — annual package builder + emitter.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/annual-control-selection.ts` — deterministic rotation algorithm for non-core controls.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/fedramp-annual-core-controls.generated.json` — pinned list of the 129 Core Controls (output of `scripts/fetch-annual-assessment-guidance.mjs`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/scripts/fetch-annual-assessment-guidance.mjs` — fetches + pins the Core Controls list (human-run, like the FRMR fetcher).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/annual-assessment.test.ts` — ~13 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/annual-control-selection.test.ts` — ~10 tests.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add roles `'annual-assessment-package'` (the tarball), `'annual-control-selection'` (the JSON), `'annual-iscp-test-aar'`, `'annual-irp-test-aar'`, `'annual-ssp-diff'`. Add `buildAnnualBundle()` wrapper that calls `emitSubmissionBundle()` after staging 12 months under a scratch directory.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — `--annual-assessment`, `--annual-year <YYYY>`, `--annual-input-dir <path>`, `--3pao-name`, `--assessment-period-start`, `--assessment-period-end`, `--strict-annual` flags + envs.

## Schemas / standards
- **FedRAMP Annual Assessment Guidance v3.0 (2024-02-15)** — Core Controls list, control-selection worksheet schema, 3-year full-baseline cycle.
- **OSCAL Assessment Results v1.1.2** — `results[]` reused for the annual AR.
- **Package format**: same `INDEX.json` shape as LOOP-A.A4 with `package_format_version = "20x.annual.preview.<YYYY>"`.
- **Pinned core-controls JSON shape**:
  ```json
  {
    "core_controls": ["AC-1", "AC-2", "AC-2(1)", ...],
    "guidance_version": "3.0",
    "guidance_published": "2024-02-15",
    "fetched_at": "<ISO>",
    "sha256": "<hex>",
    "source_url": "https://www.fedramp.gov/.../CSP_Annual_Assessment_Guidance.pdf"
  }
  ```
- **Annual manifest shape** (emitted alongside the tarball):
  ```ts
  interface AnnualAssessmentManifest {
    year: number;
    impactLevel: 'low'|'moderate'|'high';
    generated_at: string;
    monthly_bundles: Array<{ month: string; bundle_sha256: string; bundle_path: string }>;
    poam_ledger_summary: { opened_year: number; closed_year: number; open_at_year_end: number; kev_remediation_compliance_pct: number };
    in_scope_controls: { core: string[]; rotation: string[]; rationale: Record<string, string>; coverage_pct_three_year: number };
    artifacts: { ssp_path: string; ap_path: string; ar_path: string; ssp_annual_diff: string; iscp_aar: string; irp_aar: string };
    package_format_version: string;
    provenance: { emitter: 'core/annual-assessment.ts'; sourceCalls: string[]; pinned_in: string[] };
  }
  ```

## Build steps (concrete, numbered)
1. **Pin the 129 Core Controls**. Author `scripts/fetch-annual-assessment-guidance.mjs`:
   - Downloads `CSP_Annual_Assessment_Guidance.pdf`, sha256-pins it.
   - Extracts the Core Controls list (human-curated table in the PDF) via committed text excerpts (same pattern as `scripts/extract-frmr-requirements.mjs`).
   - Writes `docs/fedramp-annual-core-controls.generated.json` as above.
2. **Control selection** (`core/annual-control-selection.ts`):
   ```ts
   function selectAnnualControls(opts: {
     year: number;
     impactLevel: 'low'|'moderate'|'high';
     coreControls: string[];
     priorYears: { year: number; controls: string[] }[];
   }): {
     in_scope: string[];
     rationale_per_control: Record<string, 'core' | 'rotation-year-X' | 'sample-N-percent'>;
     coverage_pct_three_year: number;
   };
   ```
   - Always include all 129 Core Controls.
   - Add rotating non-core subset so 3-year window covers 100% of baseline.
   - Math: `non_core = baseline - core; recent = union(priorYears[last 2 years].controls); candidates = non_core \ recent`; if `|candidates| < |non_core|/3`, fall back to stratified-by-family sampling.
3. **Annual builder** (`core/annual-assessment.ts`):
   ```ts
   function buildAnnualAssessment(opts: AnnualAssessmentOptions): AnnualAssessmentManifest;
   ```
   - Reads monthly POA&M ledger (E.E2) for the year.
   - Reads every monthly bundle's `INDEX.json` for the year (from `archive/<YYYY-MM>/` or `--annual-input-dir`).
   - Aggregates count of monthly bundles, POA&M items opened-then-closed within year, items still open at year-end, KEV remediation timeline compliance %, scan-coverage compliance per month.
   - Calls `selectAnnualControls()` to compute the in-scope-this-year list.
   - Stages: latest `ssp.json` + `ssp.docx`, latest `ap.json`, latest `assessment-results.json`, `annual-control-selection.json`, `ssp-annual-diff-<YYYY>.md` (E.E4), `iscp-test-<YYYY>.docx` + `irp-test-<YYYY>.docx` (E.E7), all monthly POA&Ms (archived), all monthly inventories.
   - Calls `emitSubmissionBundle()` against the staged dir with `package_format_version = "20x.annual.preview.<YYYY>"`.
4. **Disk emitter**:
   ```ts
   function emitAnnualAssessment(opts): { bundlePath: string; manifestPath: string; indexJsonPath: string };
   ```
5. **submission-bundle integration**: add 5 new roles; annual bundle classifies as `annual-assessment-package` when nested into a higher-level package.
6. **Orchestrator wiring**: `--annual-assessment --annual-year 2026` produces `out/annual-assessment-2026.tar.gz` + a sibling `out/annual-assessment-2026/INDEX.json` for inspection. `--strict-annual` rejects when monthly bundles missing (cf. `--strict-bundle` from A.A4).

## REQUIRES-OPERATOR-INPUT fields
- **`annual-input-dir`** — Source: CLI `--annual-input-dir <path>` / env `CLOUD_EVIDENCE_ANNUAL_INPUT_DIR`. Default: `outDir/archive`. Needed when archive lives elsewhere (e.g. cold storage mount). Missing AND default-not-found → typed error, not silent zero-bundles.
- **`ssp_annual_review_signed_off_by`** — Source: tracker `ssp_reviews` table (LOOP-F.F1 will surface). Until then: REQUIRES-OPERATOR-INPUT marker in the manifest.
- **`assessor_organization`** — Source: CLI `--3pao-name` / env `CLOUD_EVIDENCE_3PAO_NAME` (same as A.A2). Missing → marker.
- **`assessment_period_start`**, **`assessment_period_end`** — Source: CLI `--assessment-period-start YYYY-MM-DD` / `--assessment-period-end YYYY-MM-DD`. Missing → markers; the annual bundle is still emit-able but flagged in `provenance.warnings`.

## Test specifications (≥12 tests)
**`annual-control-selection.test.ts` (~10):**
1. `it('selectAnnualControls always includes all 129 core controls')`.
2. `it('selectAnnualControls covers 100% of baseline across 3 consecutive years')`.
3. `it('selectAnnualControls deduplicates across prior years')`.
4. `it('selectAnnualControls falls back to stratified sampling when rotation pool empty')`.
5. `it('selectAnnualControls is deterministic on same inputs')`.
6. `it('selectAnnualControls coverage_pct_three_year computes correctly')`.
7. `it('selectAnnualControls rejects empty coreControls input')`.
8. `it('selectAnnualControls handles impactLevel=low baseline correctly')`.
9. `it('selectAnnualControls handles impactLevel=moderate baseline correctly')`.
10. `it('selectAnnualControls rationale_per_control covers every in_scope entry')`.

**`annual-assessment.test.ts` (~13):**
11. `it('annual assessment aggregates 12 monthly POA&M ledger entries')`.
12. `it('annual assessment counts opened-then-closed within year correctly')`.
13. `it('emits INDEX.json with package_format_version=20x.annual.preview.<YYYY>')`.
14. `it('throws when fewer than 1 monthly bundle is present (--strict-annual)')`.
15. `it('non-strict mode warns + still emits when months missing')`.
16. `it('reads ssp-annual-diff.md from E.E4 and stages it')`.
17. `it('reads E.E7 IRP/ISCP AARs and stages them')`.
18. `it('emits REQUIRES-OPERATOR-INPUT for assessor_organization when --3pao-name missing')`.
19. `it('annual bundle round-trips through gunzip + POSIX ustar parser')`.
20. `it('annual bundle sha256 is stable on identical inputs (mtime-fixed)')`.
21. `it('honors --annual-input-dir when archive is non-default')`.
22. `it('core controls list comes from pinned generated JSON')`.
23. `it('integrates with submission-bundle: annual-assessment-package role recognized')`.

## REO compliance specific to this slice
- Every aggregated number traces to a real monthly bundle's `INDEX.json`.
- Control selection is reproducible: same `year + priorYears + coreControls` → same `in_scope` (deterministic).
- No fabricated KEV deadline-compliance %: derived only from real POA&M deadlines + closure timestamps.
- The 129 Core Controls list is pinned + cited (`provenance.pinned_in: ["docs/fedramp-annual-core-controls.generated.json"]`).
- Annual bundle reproducibility: mtime-fixed per A.A4 pattern, byte-stable on identical inputs.
- Signed by: existing `core/sign.ts` pipeline (Ed25519 + RFC 3161) — outer tarball signature wraps every inner artifact.

## Verification commands
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/annual-assessment.test.ts tests/core/annual-control-selection.test.ts
npm run check:reo
```

## Known risks / issues
- **Risk 1: Annual Assessment Guidance drift.** FedRAMP may re-publish the guidance with a different Core Controls list. Mitigation: pinned JSON + sha256 verification; `scripts/fetch-annual-assessment-guidance.mjs` is human-run when needed.
- **Risk 2: 3-year cycle bootstrapping.** Year-1 has no prior years → rotation pool is the full non-core set. Mitigation: `priorYears = []` is a valid input; rotation algorithm handles it.
- **Risk 3: Archive-directory contamination.** If `out/archive/` contains stale month-folders from prior years, the annual bundler may pick them up. Mitigation: filter by `--annual-year` prefix; warn on cross-year entries.
- **Risk 4: Sampling fairness.** Stratified-by-family sampling may under-cover small families (e.g. PE Physical/Environmental at Low). Mitigation: minimum-one-per-family floor; document in rationale.
- **Risk 5: Fiscal vs calendar year.** Some CSPs run on fiscal year (e.g. Oct-Sep). Mitigation: track as caveat; `--annual-year-start MM-DD` deferred to a future enhancement.
- **Risk 6: Concurrent annual + monthly runs.** A monthly run in mid-Dec could clash with an annual roll-up. Mitigation: file lock via `core/run-lock.ts`.

## Open questions (for implementation session to resolve)
- **Q1**: How does the rotation algorithm handle parameter overlays? A control like `AC-2` includes 13 enhancements (`AC-2(1)..AC-2(13)`); should the rotation operate on the base control or each enhancement separately? Recommend: each enhancement is a separate selectable item.
- **Q2**: Should the annual bundle include the 12 monthly bundles inline, OR by-reference (sha256 + path)? Inline = bigger tarball but self-contained; by-reference assumes archive co-location. Recommend inline for self-containment.
- **Q3**: What's the precedence between `--annual-input-dir` and `outDir/archive`? Recommend: explicit flag wins, archive is fallback.
- **Q4**: Where does the actual SAR (Security Assessment Report) live in the annual bundle? It's 3PAO-authored, not 20x-emitted. Recommend: leave `sar.docx` slot in INDEX.json as `REQUIRES-OPERATOR-INPUT` until LOOP-F.F7 (SAR draft generator) lands.
- **Q5**: For the rotation algorithm, what's the canonical baseline for Moderate? `core/control-benchmark.ts` already encodes the Rev5 Moderate baseline — reuse it directly.
- **Q6**: Should `kev_remediation_compliance_pct` use 30-day or 14-day deadline? KEV deadlines per BOD 22-01 are CVE-specific; recommend using the per-CVE deadline from `docs/cisa-kev.generated.json`.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ~23 for this slice's new tests)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (slice row + Overall section)
- [ ] LOOP-E-SPEC.md status table updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added
- [ ] Commit with slice ID in message
- [ ] Commit amended with commit hash recorded in STATUS.md + this file + LOOP-E-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (REO standard, auto-loaded).
2. This file gives you: source obligations + files to create + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-E-SPEC.md` Section 2 (Dependencies).
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
5. Read existing pattern references: `core/submission-bundle.ts` (especially `buildSubmissionBundle()` + the `INDEX.json` shape), `core/control-benchmark.ts` (for impact-level baselines).
6. Confirm E.E1 + E.E2 + E.E4 + E.E7 have shipped — this slice depends on them.
7. Begin implementation; update Implementation log section as you go.
