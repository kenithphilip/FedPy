---
slice_id: E.E7
title: Annual IRP / ISCP Test Cadence Runner
loop: E
status: pending
commit: —
completed_date: —
depends_on: [A.A5, E.E3]
blocks: [E.E3, F.F4]
estimated_effort: 5 days
last_updated: 2026-06-06
---

# E.E7 — Annual IRP / ISCP Test Cadence Runner

## TL;DR
Closes the annual Incident Response Plan (IRP) and Information System Contingency Plan (ISCP) test cadence required by NIST SP 800-53 Rev5 IR-3 and CP-4. Emits two pre-fillable After-Action Report (AAR) Word documents per year (`outDir/irp-test-<YYYY>.docx` + `outDir/iscp-test-<YYYY>.docx`) with participants, scenarios, and prior-year findings carried forward from `annual-test-ledger.jsonl`. Operator runs the actual exercise, fills outcomes / observed timings / new findings, then re-runs the command in `--commit-results` mode (deferred). Reuses the dependency-free OOXML pattern from `core/roe-emit.ts`.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
NIST SP 800-53 Rev5 IR-3 (Incident Response Testing) and CP-4 (Contingency Plan Testing) require organizations to test the IRP and ISCP at an organization-defined frequency — for FedRAMP Moderate this is **annual** per the FedRAMP CSP Continuous Monitoring Strategy Guide. The output of each test is an After-Action Report (AAR) documenting:
- Test date, type (tabletop / functional / full-recovery), scope.
- Participants (names, roles, organizations).
- Scenarios executed + outcomes.
- For ISCP: RTO + RPO targets vs observed.
- For IRP: detection / containment / eradication / recovery timing + reporting compliance (FedRAMP, CISA, agency).
- Findings + lessons-learned.
- Status of prior-year findings.

The annual assessment package (E.E3) requires both AARs as referenced artifacts. Without this slice, AARs are written from scratch every year — missing the prefilled context (test participants from tracker, prior-year findings ledger, planned exercise scope) that the test team needs.

E.E7 closes the gap by:
1. Emitting **pre-fillable** AAR `.docx` templates with all known fields populated (year, prior-year findings, scope, participants when available).
2. Maintaining a per-year ledger (`annual-test-ledger.jsonl`) that the next year's run reads to populate "prior_year_findings_status".
3. Marking operator-only fields (outcomes, observed timings, new findings) as `REQUIRES-OPERATOR-INPUT` — operator fills the docx after the exercise.

Maps to:
- NIST SP 800-53 Rev5 IR-3 (a/b/c) — Incident Response Testing
- NIST SP 800-53 Rev5 CP-4 (a/b/c) — Contingency Plan Testing
- NIST SP 800-84 — Guide to Test, Training, and Exercise Programs for IT Plans and Capabilities
- NIST SP 800-61 Rev. 2 — Computer Security Incident Handling Guide
- NIST SP 800-34 Rev. 1 — Contingency Planning Guide for Federal Information Systems
- FedRAMP ISCP Template (Rev4 still authoritative for Rev5)

## Authoritative sources (with verbatim quotes)
- <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf> — NIST SP 800-53 Rev5 control IR-3 (page 159):
  > "IR-3 Incident Response Testing — Test the effectiveness of the incident response capability for the system [Assignment: organization-defined frequency] using the following tests: [Assignment: organization-defined tests]."
  > "IR-3(2) COORDINATION WITH RELATED PLANS — Coordinate incident response testing with organizational elements responsible for related plans."

- <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf> — NIST SP 800-53 Rev5 control CP-4 (page 109):
  > "CP-4 Contingency Plan Testing — Test the contingency plan for the system [Assignment: organization-defined frequency] using the following tests to determine the effectiveness of the plan and the readiness to execute the plan: [Assignment: organization-defined tests]."
  > "[b.] Review the contingency plan test results; [c.] Initiate corrective actions, if needed."

- <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-84.pdf> — NIST SP 800-84 §3.5 (Tests, page 32):
  > "After the test is complete, an after action report (AAR) should be prepared. The AAR documents the test methodology, scope, and findings ... and should include test objectives, scope, dates, locations, participants, scenarios used, results, findings, recommendations, and corrective actions."

- <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf> — NIST SP 800-61 Rev. 2 §3 (Handling an Incident):
  > "The four major phases of the incident response process: preparation; detection and analysis; containment, eradication, and recovery; post-incident activity."

- <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-34r1.pdf> — NIST SP 800-34 Rev. 1 §3.5.3 (Test Plan, page 31):
  > "The objective of the ISCP test is to validate the recovery procedures, identify weaknesses, and provide training to the recovery team."
  > "Functional exercises allow personnel to validate their readiness for emergencies in a stress-free environment by performing their duties in a simulated operational environment."

- <https://www.fedramp.gov/resources/documents/rev4/REV_4_SSP-A06-FedRAMP-ISCP-Template.docx> — FedRAMP ISCP Template (Rev4; still authoritative for Rev5 ISCP per §3 source 10 of LOOP-E-SPEC.md):
  > Template TOC: 1. Introduction; 2. Concept of Operations; 3. Activation and Notification Phase; 4. Recovery Phase; 5. Reconstitution Phase; 6. ISCP Appendices.

- <https://www.cisa.gov/news-events/news/cisa-rule-cyber-incident-reporting-critical-infrastructure-act-cirCia> — CISA CIRCIA reporting rule (final, 2024):
  > "Covered entities must report covered cyber incidents to CISA within 72 hours of having a reasonable belief that a covered cyber incident has occurred."
  > "Covered entities must report ransom payments within 24 hours."

- <https://www.fedramp.gov/assets/resources/documents/CSP_Incident_Communications_Procedures.pdf> — FedRAMP Incident Communications Procedures:
  > "CSPs MUST report security incidents to FedRAMP within 1 hour for US-CERT-reportable incidents."

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/annual-test-runner.ts` — orchestrates emission of both AAR templates per year. ~250 LOC.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/iscp-test-aar.ts` — ISCP AAR `.docx` renderer. ~500 LOC.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/irp-test-aar.ts` — IRP AAR `.docx` renderer. ~500 LOC.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/annual-test-ledger.ts` — per-year ledger of scheduled + completed exercises. ~200 LOC.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/iscp-test-aar.test.ts` — ~10 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/irp-test-aar.test.ts` — ~10 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/annual-test-runner.test.ts` — ~8 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/annual-test-ledger.test.ts` — ~6 tests (covered inline if combined).

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add Roles `'irp-test-aar'` (regex `/^irp-test-\d{4}\.docx$/`, required=false), `'iscp-test-aar'` (regex `/^iscp-test-\d{4}\.docx$/`, required=false), `'annual-test-ledger'` (filename `annual-test-ledger.jsonl`, required=false).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — add flags:
  - `--annual-irp-test --annual-year <YYYY>` + `--irp-scenario <text>` + `--test-participants <path-to-json>`
  - `--annual-iscp-test --annual-year <YYYY>` + `--iscp-scope <text>` + `--iscp-rto-min <num>` + `--iscp-rpo-min <num>`
  - Matching `CLOUD_EVIDENCE_*` envs.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/annual-assessment.ts` (E.E3) — stage AARs from this slice into the annual bundle.

## Schemas / standards
**`IscpTestAar` shape**:

```ts
export interface IscpTestAar {
  year: number;
  test_date: string;                              // ISO; operator-supplied or REQUIRES-OPERATOR-INPUT
  test_type: 'tabletop' | 'functional' | 'full-recovery';
  scope_summary: string;
  participants: Array<{ name: string; role: string; organization: string }> | 'REQUIRES-OPERATOR-INPUT';
  scenarios_executed: Array<{
    id: string;
    description: string;
    outcome: 'pass' | 'fail' | 'partial' | 'REQUIRES-OPERATOR-INPUT';
    notes: string | 'REQUIRES-OPERATOR-INPUT';
  }>;
  rto_target_minutes: number;
  rpo_target_minutes: number;
  observed_rto_minutes?: number | 'REQUIRES-OPERATOR-INPUT';
  observed_rpo_minutes?: number | 'REQUIRES-OPERATOR-INPUT';
  findings: Array<{
    id: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    remediation_owner: string;
    target_date: string;
  }>;
  lessons_learned: string[];
  prior_year_findings_status: Array<{ id: string; status: 'closed' | 'in-progress' | 'open' }>;
  provenance: {
    emitter: 'core/iscp-test-aar.ts';
    run_id: string;
    tool_version: string;
    prior_ledger_path: string;
  };
}
```

**`IrpTestAar` shape**:

```ts
export interface IrpTestAar {
  year: number;
  test_date: string;
  test_type: 'tabletop' | 'functional';
  scenario: string;                               // e.g. "ransomware in customer-data tier"
  participants: Array<{ name: string; role: string; organization: string }> | 'REQUIRES-OPERATOR-INPUT';
  timeline: Array<{ time_offset_min: number; action: string; actor: string }>;
  evaluation: {
    detection_time_min: number | 'REQUIRES-OPERATOR-INPUT';
    containment_time_min: number | 'REQUIRES-OPERATOR-INPUT';
    eradication_time_min: number | 'REQUIRES-OPERATOR-INPUT';
    recovery_time_min: number | 'REQUIRES-OPERATOR-INPUT';
    reporting_compliance: {
      fedramp: boolean | 'REQUIRES-OPERATOR-INPUT';    // 1-hour rule
      cisa: boolean | 'REQUIRES-OPERATOR-INPUT';       // 72-hour CIRCIA rule
      agency: boolean | 'REQUIRES-OPERATOR-INPUT';     // agency-specific
    };
  };
  findings: Array<{ id: string; severity: string; description: string; remediation_owner: string; target_date: string }>;
  lessons_learned: string[];
  prior_year_findings_status: Array<{ id: string; status: 'closed' | 'in-progress' | 'open' }>;
  provenance: { emitter: 'core/irp-test-aar.ts'; run_id: string; tool_version: string; prior_ledger_path: string };
}
```

**`AnnualTestLedgerEntry` shape**:

```ts
export interface AnnualTestLedgerEntry {
  year: number;
  exercise_type: 'irp' | 'iscp';
  scheduled_date: string;                         // ISO
  completed_date: string | null;
  aar_path: string;                               // relative to outDir
  findings: Array<{ id: string; severity: string; status: 'closed' | 'in-progress' | 'open' }>;
  aar_sha256: string;
}
```

**ISCP AAR sections** (per FedRAMP ISCP Template TOC + AAR augmentation = 11 sections):
1. Introduction (purpose, scope, year, FedRAMP package ID).
2. Test methodology (test_type, test_date, location).
3. Participants (name, role, organization).
4. Concept of Operations summary.
5. Activation and Notification phase scenarios + outcomes.
6. Recovery phase scenarios + outcomes (includes RTO/RPO target vs observed).
7. Reconstitution phase scenarios + outcomes.
8. Findings + remediation owners.
9. Lessons learned.
10. Prior-year findings status table (from ledger).
11. Sign-off block (Recovery Coordinator + ISCP Manager — both `REQUIRES-OPERATOR-INPUT`).

**IRP AAR sections** (per NIST SP 800-61 Rev. 2 §3 four-phase outline = 8 sections):
1. Introduction (purpose, scope, year).
2. Test methodology (test_type, test_date, scenario).
3. Participants.
4. Timeline of events (table: time_offset_min, action, actor).
5. Evaluation (detection / containment / eradication / recovery timings + reporting compliance per FedRAMP / CISA / agency).
6. Findings + remediation owners.
7. Lessons learned + prior-year findings status.
8. Sign-off block (Incident Response Manager + System Owner — both `REQUIRES-OPERATOR-INPUT`).

## Build steps (concrete, numbered)
1. **Types** in `core/iscp-test-aar.ts` + `core/irp-test-aar.ts` + `core/annual-test-ledger.ts`. Re-export OOXML helpers from `core/roe-emit.ts`.
2. **Ledger** in `core/annual-test-ledger.ts`:
   - `appendTestEntry(outDir, entry: AnnualTestLedgerEntry)`: atomic append to `outDir/annual-test-ledger.jsonl`.
   - `priorYearFindings(outDir, year, type): { id, status }[]`: read ledger, find entries with `year === target-1 && exercise_type === type`, return `findings[]` mapped to `{ id, status }`.
   - `readTestLedger(outDir): AnnualTestLedgerEntry[]`.
3. **ISCP renderer** in `core/iscp-test-aar.ts` — `renderIscpAarDocx(aar: IscpTestAar): Buffer`. Mirrors `roe-emit.ts` pattern. Each section emits a heading + table or paragraph. For each `REQUIRES-OPERATOR-INPUT` field, render the literal sentinel in the cell.
4. **IRP renderer** in `core/irp-test-aar.ts` — `renderIrpAarDocx(aar: IrpTestAar): Buffer`. Same pattern. Section 5 (Evaluation) includes a `reporting_compliance` table with three rows (FedRAMP 1-hour, CISA 72-hour, agency-defined) — `REQUIRES-OPERATOR-INPUT` until operator marks pass/fail.
5. **Runner** in `core/annual-test-runner.ts`:
   - `runAnnualIscpTest(opts: { outDir, year, runId, testType?, scope?, rtoTargetMin?, rpoTargetMin?, participants?, priorLedger? }): { docxPath, ledgerEntry }`:
     a. Validate year ∈ [2020, current+1].
     b. Refuse to overwrite `outDir/iscp-test-<year>.docx` (throw `AarExistsError`).
     c. Load prior-year findings via `priorYearFindings(outDir, year, 'iscp')`.
     d. Build the `IscpTestAar` object with prefilled fields + `REQUIRES-OPERATOR-INPUT` for everything operator-only.
     e. Render via `renderIscpAarDocx()`.
     f. Write to `outDir/iscp-test-<year>.docx` atomically.
     g. Compute sha256 + append ledger entry with `scheduled_date = today`, `completed_date = null`, `findings = []`, `aar_sha256 = <hash>`.
   - Parallel `runAnnualIrpTest(opts)` for IRP.
6. **First-year case**: when no prior-year ledger entry exists, the AAR's "prior_year_findings_status" section reads the literal real statement *"First annual test cycle; no prior findings to report."* — NOT a marker.
7. **Orchestrator wiring**: `--annual-irp-test` + `--annual-iscp-test` each emit one `.docx`. `--annual-year YYYY` (default = current year). Per-test flags (`--irp-scenario`, `--iscp-scope`, `--iscp-rto-min`, etc.).
8. **`--strict-annual` mode**: when set, the runner THROWS instead of emitting `REQUIRES-OPERATOR-INPUT` for `participants` — i.e. operator must supply real participants before the pre-test docx is generated. Mirrors LOOP-A.A4's `--strict-bundle` pattern.
9. **`--commit-results <filled-docx-path>`**: deferred to a future enhancement. The first ship emits the pre-fill docx; operator fills in Word; the next run reads the operator-filled docx and appends completion fields to the ledger. Out of scope for E.E7 v1; document in Open Questions Q1.
10. **Integration with E.E3 (Annual Assessment Package)**: `core/annual-assessment.ts` stages `irp-test-<year>.docx` + `iscp-test-<year>.docx` from `outDir/` into the annual bundle, classified via the new submission-bundle roles.
11. **submission-bundle catalogue**: register `irp-test-aar`, `iscp-test-aar`, `annual-test-ledger` roles.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4 — everything operator-only emits the sentinel; nothing is fabricated.

- **`participants`** — Source: CLI `--test-participants <path-to-json>` or future LOOP-F.F4 tracker integration. Until LOOP-F.F4: array literal `'REQUIRES-OPERATOR-INPUT'` in the JSON shape; rendered as a marker in the docx cell. Under `--strict-annual`, missing participants throws an error.
- **`scenario` (IRP)** — Source: CLI `--irp-scenario "ransomware in customer-data tier"`. Missing → marker in section 2.
- **`scope_summary` (ISCP)** — Source: CLI `--iscp-scope`. Missing → marker.
- **`scenarios_executed[].outcome`** — Pre-test: literal `REQUIRES-OPERATOR-INPUT`. Post-test: filled by operator (or future `--commit-results` workflow).
- **`scenarios_executed[].notes`** — Same as outcome.
- **All `observed_*` timing fields (ISCP `observed_rto_minutes`, `observed_rpo_minutes`; IRP `detection_time_min`, `containment_time_min`, `eradication_time_min`, `recovery_time_min`)** — Pre-test: `REQUIRES-OPERATOR-INPUT`. Operator fills post-test.
- **`evaluation.reporting_compliance.fedramp` / `cisa` / `agency`** — Pre-test: `REQUIRES-OPERATOR-INPUT`. Operator marks pass/fail after exercise.
- **`findings[]`** — Pre-test: empty array (the test hasn't run, so genuinely no findings). Post-test: operator-authored. NEVER fabricated by the system.
- **`lessons_learned[]`** — Pre-test: empty array. Post-test: operator-authored.
- **Sign-off cells** — ALWAYS `REQUIRES-OPERATOR-INPUT` (REO Rule 1.6). Operator signs out-of-band.
- **`test_date`** — Source: CLI `--test-date <ISO>`. If pre-scheduled, operator provides; otherwise marker. The ledger `scheduled_date` is auto-populated with the run date if `test_date` is absent.

Sentinel constant: reuse `TBD = 'REQUIRES-OPERATOR-INPUT'` from `core/roe-emit.ts`.

## Test specifications (≥10 per AAR + 8 runner)

**`iscp-test-aar.test.ts` (~10)**:
1. `it('renders all 11 sections per FedRAMP ISCP Template TOC')` — parse OOXML and assert section headings in order.
2. `it('prior_year_findings_status reads from annual-test-ledger.jsonl when prior entry exists')` — feed ledger with prior year ISCP findings; assert table populated.
3. `it('participants section emits REQUIRES-OPERATOR-INPUT marker when --test-participants absent')`.
4. `it('includes RTO + RPO target rows from --iscp-rto-min and --iscp-rpo-min flags')`.
5. `it('observed_rto_minutes / observed_rpo_minutes are REQUIRES-OPERATOR-INPUT when omitted')`.
6. `it('is a valid store-only ZIP with [Content_Types].xml + word/document.xml')`.
7. `it('is deterministic on identical inputs (ZIP store + fixed mtime)')`.
8. `it('escapes XML special chars in scope_summary')` — feed `<`, `>`, `&`, `"`.
9. `it('findings table renders all severity columns (critical/high/medium/low)')`.
10. `it('first-year case emits "First annual test cycle" literal statement')`.
11. `it('throws AarExistsError when iscp-test-<year>.docx already exists')`.

**`irp-test-aar.test.ts` (~10)**:
12. `it('renders all 8 sections per NIST 800-61 Rev. 2 four-phase outline')`.
13. `it('includes timeline table with time_offset_min, action, actor columns')`.
14. `it('reporting_compliance row enumerates fedramp (1h), cisa (72h CIRCIA), agency')`.
15. `it('emits REQUIRES-OPERATOR-INPUT for scenario when --irp-scenario missing')`.
16. `it('participants block honors --test-participants JSON path')` — feeds file with 3 participants; asserts all 3 rendered.
17. `it('detection/containment/eradication/recovery minute fields render as numbers when provided, marker when not')`.
18. `it('is a valid store-only ZIP')`.
19. `it('is deterministic on identical inputs')`.
20. `it('prior-year ledger lookup excludes other exercise_type (only irp, not iscp)')`.
21. `it('findings table includes remediation_owner + target_date columns')`.

**`annual-test-runner.test.ts` (~8)**:
22. `it('emits both irp + iscp via runAnnualIrpTest + runAnnualIscpTest')`.
23. `it('appends one ledger entry per exercise')`.
24. `it('integrates with submission-bundle.ts roles irp-test-aar / iscp-test-aar / annual-test-ledger')`.
25. `it('throws AnnualYearOutOfRangeError when --annual-year < 2020 or > current+1')`.
26. `it('does not double-emit for the same (year, type) — second call throws AarExistsError')`.
27. `it('respects --strict-annual: throws AnnualTestParticipantsMissingError when participants absent')`.
28. `it('ledger entry aar_sha256 matches AAR file bytes')`.
29. `it('stages AARs into E.E3 annual-assessment package (when --annual-assessment also enabled)')` — integration test.

**`annual-test-ledger.test.ts` (~6 — may be merged into runner tests)**:
30. `it('priorYearFindings returns findings from year-1 only')`.
31. `it('priorYearFindings respects exercise_type filter')`.
32. `it('appendTestEntry is append-only')`.

## REO compliance specific to this slice
- **Prior-year status comes from a real ledger**, never invented. Empty ledger → real true "First annual test cycle" statement.
- **Observed timing fields are REQUIRES-OPERATOR-INPUT until the exercise actually happens**. The pre-test docx ships with markers; only after the exercise does the operator (or future `--commit-results` workflow) fill them.
- **No fabricated findings**. Pre-test: `findings[] === []` (genuinely no findings yet). Post-test: operator-authored — the system NEVER auto-generates findings.
- **The AAR is pre-fillable before the exercise** (scope, participants, scenarios, prior-year findings) AND **post-fillable after** (outcomes, observed timings, lessons-learned, new findings).
- **Sign-off cells are NEVER auto-filled** (REO Rule 1.6).
- **CISA CIRCIA 72-hour rule + FedRAMP 1-hour rule are encoded** as labels on the reporting-compliance table (per REO Rule 3 — published regulatory cadences).
- **`signed by`**: every `.docx` and `annual-test-ledger.jsonl` are emitted into `outDir` BEFORE signing; the existing `core/sign.ts` pipeline (Ed25519 + RFC 3161) covers them.
- **Provenance**: each AAR embeds `core:custom_properties` with `emitter`, `run_id`, `tool_version`, `prior_ledger_sha256`.

## Verification commands
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/iscp-test-aar.test.ts tests/core/irp-test-aar.test.ts tests/core/annual-test-runner.test.ts
npm run check:reo
```

## Known risks / issues
- **Risk 1: Operator-filled docx round-trip.** The deferred `--commit-results <filled-docx-path>` workflow requires parsing operator-modified Word XML to extract outcomes / observed timings / new findings. OOXML is forgiving — a operator using Word's "track changes" or comments could break the parser. Mitigation: design a strict round-trip format (operator fills designated `<w:sdt>` content controls; runner reads only those). Defer to future slice. Severity: high (UX) but out of scope for v1.
- **Risk 2: AAR template drift.** The FedRAMP ISCP Template is Rev4 — when FedRAMP publishes a Rev5 ISCP template, the section structure may change. Mitigation: pin `fedramp_iscp_template_version` in `core:custom_properties`; surface in `provenance.warnings` if a `scripts/fetch-iscp-template.mjs` (future) detects drift. Severity: low.
- **Risk 3: Calendar-year vs fiscal-year mismatch.** `--annual-year YYYY` assumes calendar Jan-Dec. Some CSPs run on fiscal year. Mitigation: future enhancement `--annual-year-start MM-DD`. Documented in LOOP-E-SPEC §6 caveat 4. Severity: medium (correctness; affects 20% of CSPs).
- **Risk 4: Participants tracker integration.** Currently `participants` is operator-supplied JSON or marker. LOOP-F.F4 will add a tracker DB table for test team members. Until then, operators maintain a JSON file. Mitigation: document in RUNBOOK.md + provide an example participants.json. Severity: low.
- **Risk 5: Reporting-compliance ambiguity.** "fedramp (1h)" assumes US-CERT-reportable; the actual reporting timer starts when the CSP has *"a reasonable belief"* of an incident. Mitigation: render a footnote citing FedRAMP Incident Communications Procedures + CISA CIRCIA Final Rule. Severity: low.
- **Risk 6: Multi-tabletop per year.** Some CSPs run multiple smaller tabletops per year. Current schema: one AAR per (year, type). Mitigation: future enhancement supports `--annual-irp-test --suffix Q1`; out of scope for v1. Severity: medium.
- **Risk 7: Scenario template library.** Operators benefit from prefilled scenarios (ransomware, DDoS, insider threat, supply chain). Current schema: operator hand-types via `--irp-scenario`. Mitigation: future enhancement adds `core/scenario-library.ts` with a curated set of NIST 800-61 scenarios. Out of scope. Severity: low.
- **Risk 8: Date / timezone confusion.** `test_date` in UTC vs local. Mitigation: always interpret as UTC; document in flag help. Severity: low.
- **Risk 9: Findings ID collision.** If two years' AARs use overlapping finding IDs (e.g. "F-001"), the prior-year status lookup would mis-match. Mitigation: require finding IDs to include the year (`F-2025-001`); validator enforces. Severity: medium.
- **Risk 10: Pre-fill docx attractiveness.** Operators may not realize they need to fill the marker cells before submitting to a 3PAO. Mitigation: add a prominent "DRAFT — DO NOT SUBMIT UNTIL COMPLETED" watermark to the pre-fill docx; future `--commit-results` removes the watermark. Defer to v2 enhancement. Severity: medium.

## Open questions (for implementation session to resolve)
- **Q1**: When does `--commit-results <filled-docx-path>` ship? Suggest separating into E.E7-b after v1 establishes the pre-fill pattern. The deferred workflow requires `<w:sdt>` content control parsing — non-trivial. Track as backlog.
- **Q2**: Should the AAR include a section for "test coverage of NIST 800-53 IR-3 / CP-4 control enhancements" (e.g. IR-3(1), IR-3(2))? Adds value for the 3PAO but bloats the docx. Recommend a brief table.
- **Q3**: For ISCP test_type='full-recovery' (most rigorous), should the runner require all 3 phases (Activation/Notification, Recovery, Reconstitution) to be tested, or allow scope reduction? Defer to operator judgment + AO review.
- **Q4**: Should the runner integrate with LOOP-G.G2 (AFR-ICP — Incident Communications Procedures) so the IRP AAR auto-cites the current ICP document version? Recommend yes once LOOP-G.G2 ships.
- **Q5**: Should the ledger track multi-year findings (e.g. a finding from 2024 still open in 2026)? Recommend yes — `prior_year_findings_status` should walk back N years until all findings are closed.
- **Q6**: How should this slice handle a year where neither IRP nor ISCP test was conducted (skipped due to extenuating circumstances)? Recommend emit a "test waiver" `.docx` requiring AO approval, similar to a DR.
- **Q7**: Should the timeline table for IRP support sub-minute granularity (seconds)? NIST 800-61 expects minutes; recommend stay at minutes for v1.
- **Q8**: Should the runner support cross-system testing (multi-CSO scenarios)? Defer to LOOP-H.H3 (multi-CSO support).
- **Q9**: For `evaluation.reporting_compliance`, should "agency" be expanded to per-agency rows (e.g. operator services 5 agencies, each with different reporting cadences)? Defer to enhancement.
- **Q10**: Should the AAR include automated population of the technical findings from the existing `vdr-ledger.json` (for incidents involving vulnerabilities)? Risk: conflates routine vulnerability remediation with incident response. Recommend leave as operator-authored.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ~28 for this slice's new tests)
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
5. Read existing emitter for pattern reference: `core/roe-emit.ts` (`.docx` OOXML pattern), `core/deviation-request.ts` (E.E5 — similar field-by-field marker pattern), `core/scn-doc.ts` (E.E6 — sibling slice).
6. Read `cloud-evidence/docs/slices/E/E.E3.md` — E.E3 stages your AARs into the annual bundle; understand the integration before implementing.
7. Begin implementation; update Implementation log section as you go.
