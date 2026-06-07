---
slice_id: L.L3
title: CRM Gap Report (controls neither implemented nor inherited)
loop: L
status: pending
commit: —
completed_date: —
depends_on: [L.L1, L.L2, LOOP-A.A1 (POA&M emitter), core/findings.ts, core/ksi-map.ts]
blocks: [C.C7, C.C8, F.F1, E.E4]
estimated_effort: 2-3 working days
last_updated: 2026-06-07
applicable_conditional: false
---

# L.L3 — CRM Gap Report (controls neither implemented nor inherited)

## TL;DR
Turn every `REQUIRES-OPERATOR-INPUT` marker L.L1 produced (plus structural defects like inherited-without-PA-id, shared-without-customer-portion, partially-implemented-without-plan) into a structured gap report (`cis-crm-gap-report.md` + `cis-crm-gap-report.json`), emit one `crm:no-responsibility` finding per gap through the existing `core/findings.ts` pipeline so the gap rides the POA&M, and have `--strict-crm` abort the run with the gap report path in the error message. This slice is the audit trail of "what's still undefined" that an AO + 3PAO need before signing.

## Status
- Status: pending
- Commit: — (filled when shipped, per `docs/SLICE-COMPLETION-PROCEDURE.md`)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
L.L3 connects three pieces of the FedPy pipeline:

- **(a) FRMR catalog**: indirectly — `cis-crm-workbook.json` is built from the FRMR catalog by L.L1; L.L3 reads the workbook and counts gaps against the baseline. Coverage percentage is `(total - gap_count) / total`.
- **(b) KSI envelopes**: not consumed directly, but each gap finding emits with a synthetic KSI id `CRM-COMPLETE` (registered in `ksi-map.ts`) so the gap surfaces in `csx-sum-aggregator.ts` rollups and tracker dashboards alongside technical KSIs.
- **(c) OSCAL chain**: gap findings flow through `core/findings.ts` → `core/oscal-poam.ts` → `out/poam.json`. The POA&M consumer (3PAO) sees one `poam-item` per gap with `severity` medium/high, `weakness-id` set to the gap_type, and `related-observations[]` referencing the workbook + gap report.
- **(d) Submission bundle**: `cis-crm-gap-report.md` (human-readable for AO) + `cis-crm-gap-report.json` (machine-readable for 3PAO tooling) added to LOOP-A.A4 `WELL_KNOWN`.
- **(e) Tracker DB**: not consumed in first ship; future LOOP-I dashboard surfaces aggregate gap counts per CSO.

REO compliance: every gap entry traces to a real row of `cis-crm-workbook.json` (which itself traces to FRMR + KSI + YAML + L.L2 inheritance trace). No silent defaults. Findings ride the same signed pipeline as technical findings.

## Why this slice exists
The FedRAMP CSP Authorization Playbook (Rev5) §SSP Appendix J requires the CIS/CRM workbook to assign EVERY Moderate-baseline control a responsibility designation. NIST SP 800-53 Rev5 §2.5 plus PL-2 (System Security Plan) require the SSP to document each control's responsibility split. A workbook with `REQUIRES-OPERATOR-INPUT` markers is by definition non-conforming. Today, when L.L1 produces such a workbook, the gaps are visible only inside the workbook + the JSON twin — there is no separate gap report, no POA&M finding, no submission-blocker gate, and no AO-visible artifact summarising "what's incomplete".

This is the slice that closes the documentation-gap loop:

> NIST SP 800-53 Rev5, **CA-5 (Plan of Action and Milestones)**:
> "Develop a plan of action and milestones for the system to document the planned remediation actions of the organization to correct weaknesses or deficiencies noted during the assessment of the controls and to reduce or eliminate known vulnerabilities in the system."

A "no-responsibility-designated" control IS a CA-5 weakness — documentary, not technical, but submission-blocking. L.L3 emits it as a finding so the POA&M includes it, the SAR can cite it, and the AO has a single gap report to track.

## Authoritative sources (with verbatim quotes)

- https://www.fedramp.gov/docs/rev5/playbook/csp/ — **FedRAMP CSP Authorization Playbook (Rev5), §SSP Appendix J**:
  > "CSPs are required to submit a Control Implementation Summary / Customer Responsibility Matrix (CIS/CRM) workbook as Appendix J to the System Security Plan (SSP). The CIS/CRM workbook identifies security controls that the CSP is responsible for implementing, security controls that the customer is responsible for implementing, security controls where there is a shared CSP/customer responsibility, and security controls that are inherited from an underlying FedRAMP Authorized Infrastructure-as-a-Service (IaaS) or Platform-as-a-Service (PaaS)."
  The phrase "identifies security controls that the CSP is responsible for implementing … customer is responsible … shared … inherited" implies completeness: a control with no designation is non-conforming.

- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf — **NIST SP 800-53 Rev5, CA-5 (Plan of Action and Milestones)**:
  > "Develop a plan of action and milestones for the system to document the planned remediation actions of the organization to correct weaknesses or deficiencies noted during the assessment of the controls."
  > "Update existing plan of action and milestones based on the findings from control assessments, independent audits or reviews, and continuous monitoring activities."

- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf — **NIST SP 800-53 Rev5, PL-2 (System Security Plan)**:
  > "Develop security and privacy plans for the system that: … identify any security-related restrictions or requirements regarding the use of the system …"

- https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/plan-of-action-and-milestones/json-reference/ — **OSCAL POA&M v1.1.2** — the `poam-item.related-observations[]` array is the extension point gap findings populate; each gap becomes one POA&M item.

- https://www.fedramp.gov/assets/resources/documents/CSP_Continuous_Monitoring_Strategy_Guide.pdf — **FedRAMP Continuous Monitoring Strategy & Guide (Rev5)** — documentary gaps default to FedRAMP's Moderate 90-day remediation window unless escalated by AO. L.L3 sets `severity: medium` which the LOOP-B.B2 deadline math maps to 90 days.

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/crm-gap-report.ts` — pure builder + disk emitter. ~300 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/crm-gap-markdown.ts` — pure markdown renderer (separation of concerns mirrors `core/cis-crm-xlsx.ts`). ~150 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/crm-gap-report.test.ts` — integration tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/crm-gap-markdown.test.ts` — markdown snapshot tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/crm-gap/` — fixture workbooks (one with 0 gaps, one with each gap type) + expected outputs.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/findings.ts` — register new finding family `crm:no-responsibility` (and the sub-types: `no-responsibility-designated`, `inherited-without-pa-id`, etc.). `severity: 'medium'` default; structural defects bump to `'high'`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ksi-map.ts` — register synthetic KSI id `CRM-COMPLETE` mapping to NIST controls CA-5 + PL-2 (so the gap surfaces under the right control families when aggregated).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — new `--crm-gap` flag + env `CLOUD_EVIDENCE_CRM_GAP`. Runs AFTER `--crm` (L.L1) AND BEFORE `--oscal-poam`. `--crm-gap` implies `--crm` (so a single flag generates the workbook + gap report). `--strict-crm` already aborts when gaps exist (L.L1 enforces); L.L3 enriches the error message with the gap report path.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-poam.ts` — automatically include `crm:no-responsibility` findings in the POA&M emission. No schema change required — these flow through the existing finding → poam-item pipeline. Add a code-comment naming L.L3 as the source family.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add roles `cis-crm-gap-report-md` (filename `cis-crm-gap-report.md`), `cis-crm-gap-report-json` (filename `cis-crm-gap-report.json`).

## Schemas / standards
- **NIST SP 800-53 Rev5 CA-5** — POA&M tracks gaps in control implementation. A "no-responsibility-designated" control IS a CA-5 gap; severity medium per FedRAMP conventional 90-day remediation window for documentation gaps.
- **NIST SP 800-53 Rev5 PL-2** — SSP must "identify any security-related restrictions or requirements regarding the use of the system." A missing responsibility designation violates PL-2 because the SSP cannot identify who restricts/requires the control.
- **FedRAMP CRM completeness rule** — every Moderate-baseline control must have a responsibility; absence is a submission blocker. L.L3 enforces.
- **OSCAL POA&M v1.1.2** — `poam-item.related-observations[]` + `poam-item.related-risks[]` arrays consumed; new gap findings ride the same pipeline as technical findings.
- **Gap report JSON schema** (defined in this slice):
  ```ts
  export interface CrmGapReport {
    metadata: {
      generated_at: string;
      system_id: string;
      system_name: string;
      impact_tier: 'low' | 'moderate' | 'high';
      cis_crm_format_version: '20x.crm.preview.2026';
      workbook_path: string;       // relative to outDir
    };
    gaps: CrmGap[];
    summary: {
      total_controls: number;
      gap_count: number;
      coverage_percent: number;    // (total - gap_count) / total * 100
      high_count: number;
      medium_count: number;
      low_count: number;
      by_type: Record<CrmGapType, number>;
    };
    provenance: { emitter: 'core/crm-gap-report.ts'; emittedAt: string; sourceCalls: string[]; signingKeyId?: string };
  }
  ```

## Build steps (concrete, numbered)

1. Types in `core/crm-gap-report.ts`:
   ```ts
   export type CrmGapType =
     | 'no-responsibility-designated'
     | 'no-implementation-description'
     | 'no-customer-responsibility-text'
     | 'inherited-without-pa-id'
     | 'shared-without-customer-portion'
     | 'partially-implemented-without-plan';

   export type CrmGapSeverity = 'high' | 'medium' | 'low';

   export type RemediationOwner = 'iso' | 'so' | 'csp-team' | 'ao';

   export interface CrmGap {
     control_id: string;
     control_title: string;
     gap_type: CrmGapType;
     severity: CrmGapSeverity;
     remediation_owner: RemediationOwner;
     remediation_hint: string;          // what the operator needs to do
     current_state: {
       responsibility?: ResponsibilityBucket;       // imported from cis-crm-emit.ts
       responsibility_source?: string;
       implementation_description_source?: string;
       customer_responsibility_source?: string;
       inherited_from_pa_id?: string;
     };
   }
   ```

2. Pure builder:
   ```ts
   export function buildCrmGapReport(
     workbook: CisCrmWorkbook,
     systemContext: { system_id: string; system_name: string; impact_tier: 'low' | 'moderate' | 'high' },
     workbookPath: string,
   ): CrmGapReport;
   ```
   Iterate workbook rows. For each row, apply the gap-detection rules in this priority order:
   - **`no-responsibility-designated`** — `row.responsibility_source === 'REQUIRES-OPERATOR-INPUT'`. Severity `high`. Owner `iso` (Information System Owner). Hint: "Add an entry in `config/responsibility-matrix.yaml` for `<control_id>` with one of the 5 responsibility buckets." Other gap types skipped for this row (top-level gap dominates).
   - **`inherited-without-pa-id`** — `row.responsibility === 'inherited'` AND `row.inherited_from_pa_id === 'REQUIRES-OPERATOR-INPUT'`. Severity `high`. Owner `iso`. Hint: "Run `--leveraged-auth` to populate `leveraged-authorizations.json`, OR add the PA-id to `docs/leveraged-authorizations.generated.json`."
   - **`no-implementation-description`** — `row.implementation_description_source === 'REQUIRES-OPERATOR-INPUT'` AND `row.responsibility` ∈ `{'service-provider', 'shared'}`. Severity `medium`. Owner `csp-team`. Hint: "Add `implementation_description` for `<control_id>` to `config/responsibility-matrix.yaml`, OR ensure a KSI maps to `<control_id>` in `ksi-map.ts`."
   - **`no-customer-responsibility-text`** — `row.customer_responsibility_source === 'REQUIRES-OPERATOR-INPUT'` AND `row.responsibility` ∈ `{'customer', 'shared'}`. Severity `medium`. Owner `so` (System Owner / customer). Hint: "Add `customer_responsibility` for `<control_id>` to `config/responsibility-matrix.yaml` describing what the customer must do."
   - **`shared-without-customer-portion`** — `row.responsibility === 'shared'` AND (customer_responsibility is empty/whitespace). Severity `medium`. Owner `iso`. Hint: "Shared controls must describe both CSP and customer portions; complete `customer_responsibility` for `<control_id>`."
   - **`partially-implemented-without-plan`** — `row.implementation_status === 'partially-implemented'` AND no plan narrative (heuristic: implementation_description does not contain the substring `planned` / `roadmap` / `Q[1-4]`). Severity `low`. Owner `csp-team`. Hint: "Partially-implemented controls require a remediation plan; add a 'Planned:' section to `implementation_description` for `<control_id>`."

3. Markdown renderer (`core/crm-gap-markdown.ts`):
   ```ts
   export function renderCrmGapReportMarkdown(report: CrmGapReport): string;
   ```
   Sections:
   - **Header**: system identity, generated_at, summary counts, coverage percent.
   - **Coverage chart** (text-rendered horizontal bar; e.g. `[==========------] 60.3%`).
   - **Gaps by severity** — three subsections (High / Medium / Low) with a per-gap table:
     | Control ID | Gap Type | Owner | Remediation Hint |
   - **Per-control remediation guidance** — one block per gap with `gap_type`, `current_state`, `remediation_hint`, and a deep-link reference back to the workbook row.
   - **Footer**: workbook path, gap report path, command to re-run after fixes.

4. Finding emission:
   ```ts
   export function emitCrmGapFindings(report: CrmGapReport): Finding[];
   ```
   Each gap becomes one `Finding`:
   ```ts
   {
     ksi_id: 'CRM-COMPLETE',                  // synthetic KSI; registered in ksi-map.ts
     rule: gap.gap_type,                      // e.g. 'no-responsibility-designated'
     provider: 'fedramp-package',
     gap: { affected_resources: [{ identifier: gap.control_id, attributes: { control_title: gap.control_title } }] },
     severity: gap.severity,                  // 'high' | 'medium' | 'low'
     note: gap.remediation_hint,
     references: [
       { uri: 'https://www.fedramp.gov/docs/rev5/playbook/csp/', title: 'FedRAMP CSP Authorization Playbook §SSP Appendix J' },
       { uri: 'https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf', title: 'NIST SP 800-53 Rev5 §2.5 + CA-5 + PL-2' },
     ],
   }
   ```

5. **Disk emitter**:
   ```ts
   export interface CrmGapReportEmitOptions {
     outDir: string;
     workbookPath?: string;                  // default: outDir/cis-crm-workbook.json
     systemContext: { system_id: string; system_name: string; impact_tier: 'low' | 'moderate' | 'high' };
   }
   export interface CrmGapReportEmitResult {
     mdPath: string;
     jsonPath: string;
     gap_count: number;
     findings_emitted: number;
     coverage_percent: number;
   }
   export async function emitCrmGapReport(opts: CrmGapReportEmitOptions): Promise<CrmGapReportEmitResult>;
   ```
   Reads `cis-crm-workbook.json`; builds report; writes both files; returns counts. Findings are appended to the same `findings.ts` queue the POA&M emitter drains downstream.

6. **Orchestrator wiring**: `--crm-gap` runs AFTER `--crm` (L.L1) AND BEFORE `--oscal-poam`. Sequence: collect → inventory → leveraged-auth → inheritance-trace → crm → crm-gap → crm-narratives → ssp → ap → ar → poam → bundle → sign → timestamp. `--crm-gap` implies `--crm`. `--strict-crm` aborts the run with the gap report path (and gap_count) in the error message — even though the abort happens in L.L1, the error builder reads the report path from L.L3 if available.

7. **Bundler integration** — add to `submission-bundle.ts:WELL_KNOWN`:
   ```ts
   { role: 'cis-crm-gap-report-md', filename: 'cis-crm-gap-report.md', description: 'Human-readable CRM gap report for AO/3PAO (LOOP-L.L3)', required: false },
   { role: 'cis-crm-gap-report-json', filename: 'cis-crm-gap-report.json', description: 'Machine-readable CRM gap report (LOOP-L.L3)', required: false },
   ```
   `required: false` because a fully-mapped workbook produces a 0-gap report; the file is still emitted (gaps array empty) so consumers see "coverage 100%" rather than "report absent" ambiguity. Bundler includes the file whenever present.

8. **Strict mode interaction**: `--strict-crm` (introduced in L.L1) reads the gap report path from L.L3's emit result; on abort, the error message includes:
   - The gap report path
   - The number of gaps by severity
   - The next-step command suggestion (e.g. `Edit config/responsibility-matrix.yaml`, `Re-run with --crm-gap`).

9. **Finding family registration** in `core/findings.ts`:
   ```ts
   export const CRM_GAP_FAMILY = 'crm:no-responsibility';
   // findings.ts already supports family registration via the FindingInput shape;
   // L.L3 emits with rule = gap.gap_type which becomes finding.rule.
   ```

10. **Synthetic KSI registration** in `core/ksi-map.ts`:
    ```ts
    {
      ksi_id: 'CRM-COMPLETE',
      title: 'Customer Responsibility Matrix completeness',
      nist_controls: ['CA-5', 'PL-2'],
      family: 'process-artifact',           // not a cloud-evidence KSI
      impact_tier: ['low', 'moderate', 'high'],
      source: 'LOOP-L.L3',
    }
    ```

11. **Provenance** — `cis-crm-gap-report.json` carries `provenance` block: emitter name, emittedAt, sourceCalls (workbook path read, NIST + FedRAMP URLs cited), `signingKeyId` populated by `core/sign.ts`.

12. **Sign + timestamp** — both `.md` + `.json` ride the existing `core/sign.ts` glob.

## REQUIRES-OPERATOR-INPUT fields
None NEW to this slice. L.L3 reports on markers L.L1 + L.L2 emitted; the gap report itself is fully derived from workbook + system context. The remediation_hint strings name what the operator must do — they are not REQUIRES-OPERATOR-INPUT in the L.L3 output.

## Test specifications (≥12 tests)

1. `it('detects no-responsibility-designated gap when responsibility_source is REQUIRES-OPERATOR-INPUT')` — fixture workbook with one row missing yaml; assert one gap of type `no-responsibility-designated`, severity `high`.
2. `it('detects inherited-without-pa-id when inherited_from_pa_id is REQUIRES-OPERATOR-INPUT')` — fixture has inherited row with marker; assert gap type `inherited-without-pa-id`, severity `high`.
3. `it('detects no-implementation-description for service-provider rows')` — fixture has service-provider row missing description; assert gap type + severity `medium`.
4. `it('detects no-customer-responsibility-text for customer rows')` — fixture has customer row missing customer text; assert gap type + severity `medium`.
5. `it('detects shared-without-customer-portion')` — fixture has shared row with empty customer text; assert gap type + severity `medium`.
6. `it('detects partially-implemented-without-plan')` — fixture has partially-implemented row with no plan keywords; assert gap type + severity `low`.
7. `it('no-responsibility-designated dominates other gap types on the same row')` — fixture has REQUIRES-OPERATOR-INPUT responsibility AND missing description; assert only `no-responsibility-designated` reported (not duplicate).
8. `it('summary.coverage_percent calculated correctly')` — workbook with 10 rows, 4 gaps → coverage 60%.
9. `it('summary.by_type counts gaps per CrmGapType')` — fixture with mix; assert counts.
10. `it('summary.high_count + medium_count + low_count == gap_count')` — invariant.
11. `it('renderCrmGapReportMarkdown produces stable output with summary + per-gap rows')` — snapshot test.
12. `it('renderCrmGapReportMarkdown includes coverage chart')` — assert presence of `[` and `%`.
13. `it('emitCrmGapFindings produces one Finding per gap')` — gap_count N → findings.length N.
14. `it('Findings use ksi_id CRM-COMPLETE and severity matches gap severity')` — assert per-finding fields.
15. `it('Findings reference FedRAMP playbook + NIST 800-53 URLs')` — assert `references[]` populated correctly.
16. `it('Findings produce poam-items via the existing oscal-poam pipeline')` — integration: build workbook → gap report → findings → POA&M → assert N new poam-items.
17. `it('--strict-crm error message includes gap report path + gap_count by severity')` — assert thrown error string format.
18. `it('emits provenance block on cis-crm-gap-report.json')` — `check:provenance` passes.
19. `it('bundler well-known catalogue includes cis-crm-gap-report-md + cis-crm-gap-report-json')` — assert table entries.
20. `it('synthetic KSI CRM-COMPLETE registered in ksi-map.ts with CA-5 + PL-2 controls')` — assert.
21. `it('coverage percent rounded to one decimal place')` — assert `toFixed(1)` format.
22. `it('zero-gap workbook still emits the report file with empty gaps[]')` — assert file exists, gaps array empty.

## REO compliance specific to this slice
- Reads from L.L1's emitted `cis-crm-workbook.json`; no fabrication, no defaults.
- Findings flow through the existing `findings.ts` → `oscal-poam.ts` pipeline; no special-case logic in POA&M emission.
- Provenance block populated on the JSON gap report.
- Markdown renderer is deterministic (sorted by severity then control_id) — snapshot test stable across runs.
- Severity assignments documented + tested; no hidden severity escalation logic.
- No `process.env.NODE_ENV === 'test'` branches (REO Rule 1.8).
- Signed by `core/sign.ts`; both `.md` + `.json` land in the manifest glob.
- The synthetic KSI `CRM-COMPLETE` is explicitly named in `ksi-map.ts` (not a magic string); module docstring cites L.L3 as the registering slice.

## Verification commands
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/crm-gap-report.test.ts tests/core/crm-gap-markdown.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
```

## Known risks / issues
- **Risk 1: Heuristic for `partially-implemented-without-plan` could over- or under-fire.** The plan-keyword heuristic (`planned` / `roadmap` / `Q[1-4]`) is approximate. Mitigation: keep severity `low`; reviewer can dismiss; future enhancement: structured `implementation_plan` field in yaml so detection is deterministic.
- **Risk 2: POA&M item count grows large in early adoption.** Hundreds of unmapped controls → hundreds of POA&M items. Mitigation: bundle reviewer guidance in CHANGELOG; first-time operator runs without strict mode + iteratively fills yaml.
- **Risk 3: `crm:no-responsibility` family clutters POA&M alongside technical findings.** 3PAO may want to filter. Mitigation: POA&M item carries `finding.rule = gap.gap_type` and `finding.provider = 'fedramp-package'`; 3PAO tooling can filter by provider; CHANGELOG documents the filter pattern.
- **Risk 4: Coverage percent could mislead.** A workbook with 100% coverage but every row marked `not-applicable` is technically 100% mapped but operationally suspicious. Mitigation: gap report's summary also shows bucket distribution (from L.L1's summary); reviewer notices NA-heavy workbooks.
- **Risk 5: Markdown output not consumed by an existing tool.** AO may want PDF. Mitigation: future LOOP-C slice renders the report to PDF via the existing pandoc pipeline; first ship is markdown only (text-grep-able).
- **Risk 6: Severity inflation if all gaps are `high`.** Currently `no-responsibility-designated` + `inherited-without-pa-id` are both `high`. Mitigation: severity matrix documented + tested; CHANGELOG cites the rationale.
- **Risk 7: Synthetic KSI `CRM-COMPLETE` collides with future real KSI.** Mitigation: namespace check at registration time; runbook documents reserved synthetic KSI ids.

## Open questions
- **Q1**: Should the gap report be emitted even when 0 gaps exist? Recommend: yes — 0-gap report is a positive artifact ("coverage 100%") that supports the submission; bundler includes regardless.
- **Q2**: Should L.L3 emit findings into `findings.ts` BEFORE the POA&M emitter runs, or pass findings directly to a side-channel that POA&M reads later? Recommend: emit into the same queue; orchestrator order guarantees `--crm-gap` < `--oscal-poam`.
- **Q3**: For `partially-implemented-without-plan` heuristic, should `Q[1-4]` be case-sensitive or insensitive? Recommend: case-insensitive regex matched against the whole `implementation_description` string.
- **Q4**: Should the gap report markdown be emitted in a deterministic order (by severity then control_id)? Recommend: yes; snapshot tests pin the order; reviewer sees the same layout across runs.
- **Q5**: Does the gap report need to be versioned with `cis_crm_format_version`? Recommend: yes — `metadata.cis_crm_format_version: '20x.crm.preview.2026'` (matches L.L1 + L.L2).

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses, per docs/IMPLEMENTATION-LOG-TEMPLATE.md)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥22 for this slice's new tests)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (slice row + Overall section)
- [ ] LOOP-L-SPEC.md status table updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>, last_updated=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added per LOOP-L-SPEC.md §12 template
- [ ] Commit with slice ID in message ("LOOP-L.L3: CRM Gap Report (controls neither implemented nor inherited)")
- [ ] Commit amended with commit hash recorded in STATUS.md + this file + LOOP-L-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. This file gives you: source obligations + files to create + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-L-SPEC.md` §5 L.L3 + §6 Loop-wide acceptance criteria.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory 7-step commit pattern.
5. Read `cloud-evidence/docs/slices/L/L.L1.md` — your input format (CisCrmWorkbook).
6. Read `cloud-evidence/docs/slices/L/L.L2.md` — the upstream slice that populates `inherited_from_pa_id`.
7. Read `cloud-evidence/core/findings.ts` — pattern for finding emission (new family `crm:no-responsibility`).
8. Read `cloud-evidence/core/ksi-map.ts` — register synthetic KSI `CRM-COMPLETE`.
9. Read `cloud-evidence/core/oscal-poam.ts` — confirm gap findings flow through existing pipeline (no special-case logic needed).
10. Read `cloud-evidence/core/submission-bundle.ts:WELL_KNOWN` — add 2 new role entries.
11. Read `cloud-evidence/docs/loops/LOOP-L-RISKS.md` — live risks register.
12. Begin implementation; update Implementation log section as you go.

---
