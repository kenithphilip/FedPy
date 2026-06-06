---
slice_id: E.E6
title: Formal SCN Document Emitter
loop: E
status: pending
commit: —
completed_date: —
depends_on: [A.A5, SCN-1]
blocks: [E.E1, E.E3]
estimated_effort: 3 days
last_updated: 2026-06-06
---

# E.E6 — Formal SCN Document Emitter (extends existing classifier)

## TL;DR
Closes the Significant Change Notification (SCN) loop: takes the existing `core/scn-classifier.ts` output (`scn-classification.json` + `scn-notice-draft.md`) and renders the **formal Word document** (`outDir/scn-notice-<scnId>.docx`) with the 10 verbatim FedRAMP-required SCR fields that the authorizing agency expects. Adds an append-only ledger (`scn-ledger.jsonl`) tracking submission state through acknowledged / denied / applied / reverted. Reuses the dependency-free OOXML pattern from `core/roe-emit.ts` and `core/deviation-request.ts` (E.E5).

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
FedRAMP defines an SCN as the formal notification to the authorizing agency when a CSP plans a *"change that is likely to substantively affect the security or privacy posture of a system"* (NIST SP 800-37 Rev. 2). The FedRAMP Significant Change page mandates 10 verbatim required content fields (see Authoritative sources below).

The codebase already (a) harvests changes from finding-diff + inventory-diff + operator-proposed inputs, (b) classifies them via the rule library in `core/scn-classifier.ts`, and (c) emits a `scn-notice-draft.md`. What is missing is the **formal Word document** that goes to the agency on letterhead-style stationery — operators currently re-author this in Word every time, error-prone and inconsistent.

E.E6 closes the gap by rendering the `.docx` directly from the classifier output + operator-supplied SCR fields. The 10 required content fields are encoded as a hardcoded ordered list (per REO Rule 3 "FedRAMP-published constants" exception). Missing operator fields emit the `REQUIRES-OPERATOR-INPUT` sentinel rather than fabricated text — reviewers see exactly what the operator must fill before sending.

A new ledger (`scn-ledger.jsonl`) tracks SCN state through the agency-acknowledgement lifecycle (`submitted` → `acknowledged` → `applied` OR `denied` OR `reverted`). This gives the monthly conmon report (E.E1) and the annual assessment package (E.E3) a single source of truth for "what SCNs happened this period".

Maps to:
- FedRAMP Rev5 Playbook §Significant Changes
- NIST SP 800-37 Rev. 2 §3.6 (Significant Change definition)
- NIST SP 800-53 Rev5 CA-7 (g), CM-3, CM-4

## Authoritative sources (with verbatim quotes)
- <https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/significant-changes/> — FedRAMP Rev5 Playbook §Significant Changes — 10 verbatim required SCR content fields:
  > "Service Offering FedRAMP ID; Assessor Name; Related POA&M (if the change is being implemented to address a known risk); Significant Change type and explanation of categorization; Short description of change; Reason for change; Summary of customer impact, including changes to services and customer configuration responsibilities; Plan and timeline for the change, including for the verification, assessment, and/or validation of impacted security controls; Copy of the security impact analysis; Name and title of CSP approver (typically the system owner)."

- <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-37r2.pdf> — NIST SP 800-37 Rev. 2 §3.6 (page 91):
  > "Significant change — a change that is likely to substantively affect the security or privacy posture of a system."
  > "Examples of significant changes that may trigger an authorization decision include changes to: ... installation of new or upgraded hardware, operating systems, or applications; modifications to security controls; replacement, upgrade, or migration of major elements of the system or its environment of operation; modifications to system interconnections; changes to the threat space; changes to the laws, directives, policies, or regulations affecting the system."

- <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf> — NIST SP 800-53 Rev5 control CM-3 (page 123):
  > "Configuration Change Control — Determine and document the types of changes to the system that are configuration-controlled; Review proposed configuration-controlled changes to the system and approve or disapprove such changes with explicit consideration for security and privacy impact analyses ..."

- <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf> — NIST SP 800-53 Rev5 control CM-4 (Security Impact Analyses, page 127):
  > "Analyze changes to the system to determine potential security and privacy impacts prior to change implementation."

- <https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/overview/> — FedRAMP Rev5 Playbook §ConMon Overview:
  > "Each month, the CSP uploads an up-to-date POA&M and inventory, along with raw vulnerability scan files (when required by agreements with agency customers) and reports to the secure repository."

- <https://www.ecma-international.org/publications-and-standards/standards/ecma-376/> — ECMA-376 Office Open XML, 5th edition (Dec 2016):
  > "Part 1 §17 WordprocessingML — `<w:document>`, `<w:body>`, `<w:p>`, `<w:r>`, `<w:t>`, `<w:tbl>` element definitions."

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/scn-doc.ts` — `.docx` renderer + disk emitter consuming the existing `ScnClassification` from `core/scn-classifier.ts`. ~500 LOC.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/scn-ledger.ts` — append-only JSONL with state transitions. ~150 LOC (mirrors `core/deviation-ledger.ts`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/scn-doc.test.ts` — ~12 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/scn-ledger.test.ts` — ~6 tests.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/scn-classifier.ts` — NO type changes. Ensure `ScnReport` + `ScnClassification` are exported (likely already). Add `renderScnSubmissionBundle(opts)` thin wrapper that loads the classifier output and drives `emitScnDoc()`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add Roles `'scn-doc-docx'` (regex `/^scn-notice-SCN-\d{4}-\d+\.docx$/`, required=false) and `'scn-ledger'` (filename `scn-ledger.jsonl`, required=false). (`scn-classification.json` + `scn-notice-draft.md` are already registered from SCN-1.)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — add `--scn-doc <scn-spec.json>` flag (implies `--scn` if not already enabled), `--update-scn-state <scn_id> <state> <by>` admin sub-command, and matching `CLOUD_EVIDENCE_*` envs.

## Schemas / standards
**`ScnDocOptions` shape** (input to renderer):

```ts
import type { ScnClassification } from './scn-classifier';

export interface ScnDocOptions {
  outDir: string;
  runId: string;
  scnId: string;                          // e.g. "SCN-2026-0001"
  fedrampPackageId: string;               // FedRAMP ID, operator-supplied
  systemName: string;
  csp: string;
  // From classifier (real):
  classification: ScnClassification;      // { change_id, significance, rationale, recommended_notice_days, rule_id }
  // Operator-supplied required fields (per the 10 SCR content fields):
  assessorName?: string;
  relatedPoamUuids?: string[];
  shortDescription?: string;
  reasonForChange?: string;
  customerImpactSummary?: string;
  planAndTimeline?: string;
  securityImpactAnalysisPath?: string;    // path to operator-authored SIA
  cspApproverName?: string;
  cspApproverTitle?: string;
}

export interface ScnLedgerEntry {
  scn_id: string;
  classification_rule_id: string;
  significance: 'significant' | 'advisory' | 'no-action';
  fedramp_package_id: string;
  docx_path: string;                      // relative to outDir
  docx_sha256: string;
  current_state: 'submitted' | 'acknowledged' | 'denied' | 'applied' | 'reverted';
  submitted_at: string;
  transitions: Array<{ state: string; at: string; by: string }>;
}
```

**Word `.docx` structure** (10 verbatim FedRAMP SCR fields + 1 front matter + 1 final block = 12 sections):

| # | Section | Content source | Missing → marker? |
|---|---|---|---|
| 0 | Front matter | scn_id, fedrampPackageId, system, CSP, submission date, classification verdict (significant / advisory), recommended_notice_days | mixed |
| 1 | Service Offering FedRAMP ID | `fedrampPackageId` | yes |
| 2 | Assessor Name | `assessorName` | yes |
| 3 | Related POA&M | `relatedPoamUuids` | NO — empty array reads as literal "No related POA&M item; this change is not addressing a known risk." |
| 4 | Significant Change type and explanation | `classification.significance` + `classification.rationale` (real, from classifier) | no |
| 5 | Short description of change | `shortDescription` | yes |
| 6 | Reason for change | `reasonForChange` | yes |
| 7 | Summary of customer impact | `customerImpactSummary` | yes |
| 8 | Plan and timeline | `planAndTimeline` | yes |
| 9 | Copy of the security impact analysis | `securityImpactAnalysisPath` reference + embedded summary | yes |
| 10 | Name and title of CSP approver | `cspApproverName`, `cspApproverTitle` | yes |
| 11 | NIST SP 800-37 Rev. 2 verbatim definition + acknowledgement signature block (CSP system owner + AO acknowledgement, both `REQUIRES-OPERATOR-INPUT`) | hardcoded text + signature cells | always REQUIRES-OPERATOR-INPUT for signatures |

**FedRAMP SCR field hardcoded list** (per REO Rule 3 "FedRAMP-published constants" — comment in source must cite §3 source 7 of LOOP-E-SPEC.md):

```ts
const FEDRAMP_SCR_REQUIRED_FIELDS: readonly string[] = [
  'Service Offering FedRAMP ID',
  'Assessor Name',
  'Related POA&M',
  'Significant Change type and explanation of categorization',
  'Short description of change',
  'Reason for change',
  'Summary of customer impact',
  'Plan and timeline for the change',
  'Copy of the security impact analysis',
  'Name and title of CSP approver',
] as const;
```

## Build steps (concrete, numbered)
1. **Types** in `core/scn-doc.ts`. Define `ScnDocOptions`, `ScnLedgerEntry`. Re-export `ScnClassification` from `core/scn-classifier.ts`.
2. **Hardcoded SCR field list** with a verbatim citation comment pointing at §3 source 7 of `docs/loops/LOOP-E-SPEC.md`. Per REO Rule 3, FedRAMP-published constants are an allowed exception.
3. **`renderScnDocx(opts: ScnDocOptions): Buffer`** — 12 sections matching the layout above. Reuse OOXML helpers re-exported from `core/roe-emit.ts` (`para`, `heading`, `table`, `fieldTable`, `xmlEscape`, `TBD`). For each operator-supplied field that is undefined / empty string, emit the literal `REQUIRES-OPERATOR-INPUT` (or the prescribed real-true-statement for Section 3 when `relatedPoamUuids` is empty).
4. **`emitScnDoc(opts: ScnDocOptions): { path: string; ledgerEntry: ScnLedgerEntry }`**:
   a. Validate that `opts.classification` is present (real classifier output; not a hand-rolled stub). Throw `ScnMissingClassificationError` if not.
   b. Validate `scnId` matches regex `/^SCN-\d{4}-\d+$/`.
   c. Mkdir `outDir/` (always exists in practice).
   d. Render via `renderScnDocx()`.
   e. Write `outDir/scn-notice-<scnId>.docx` atomically (tmp + rename).
   f. Compute sha256.
   g. Append to `scn-ledger.jsonl` via `appendScn(outDir, entry)` with `current_state='submitted'`, `transitions=[{state:'submitted', at: now, by: opts.cspApproverName ?? 'unknown'}]`.
5. **Ledger** in `core/scn-ledger.ts` — mirror `core/deviation-ledger.ts` (E.E5) verbatim:
   - `appendScn(outDir, entry)`: atomic append to `outDir/scn-ledger.jsonl`.
   - `transitionScn(outDir, scn_id, new_state, by, at?)`: rewrite JSONL with appended transition entry, update `current_state`.
   - `readScnLedger(outDir): ScnLedgerEntry[]`.
   - `activeScns(outDir): ScnLedgerEntry[]` — `current_state` in {`submitted`, `acknowledged`, `applied`}.
6. **Conditional emission**: when classifier finds zero changes with `significance='significant'`, `--scn-doc` exits with code 0 + a clear log line and does NOT write a `.docx`. Mirrors LOOP-A.A1's "no failing findings == clean skip" pattern.
7. **Orchestrator wiring**:
   - `--scn-doc <scn-spec.json>` reads operator spec (referencing classifier's `change.id`), validates, emits the `.docx`. Implies `--scn`; auto-runs the classifier first if not already.
   - `--update-scn-state <scn_id> <state> <by>` → ledger transition (mirrors E.E5's `--update-deviation-state`).
8. **Submission-bundle catalogue**: register `scn-doc-docx` + `scn-ledger` roles so monthly bundles classify them.
9. **`renderScnSubmissionBundle()`** in `core/scn-classifier.ts`: a thin wrapper that loads `scn-classification.json`, accepts an `scn-spec.json` operator file, and drives `emitScnDoc()`. Keeps the existing classifier untouched.
10. **Spec file schema** (`scn-spec.json`): JSON object with `scn_id`, `change_id` (matching the classifier's change.id), and the 8 operator fields. Validator throws if `change_id` is not present in `scn-classification.json`.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4:

- **`assessorName`, `shortDescription`, `reasonForChange`, `customerImpactSummary`, `planAndTimeline`, `securityImpactAnalysisPath`, `cspApproverName`, `cspApproverTitle`** — CLI flags or `scn-spec.json` fields. Missing → marker in the rendered Word cell.
- **`fedrampPackageId`** — CLI `--fedramp-package-id` / env `CLOUD_EVIDENCE_FEDRAMP_PACKAGE_ID` (shared with E.E1).
- **AO acknowledgement signature cell** — ALWAYS `REQUIRES-OPERATOR-INPUT` (REO Rule 1.6). Even when `--update-scn-state acknowledged "Jane AO"` is called, the docx signature cell stays as the marker; only the ledger transition records the structural state change.
- **CSP system owner signature cell (Section 11)** — ALWAYS `REQUIRES-OPERATOR-INPUT`. Operator signs out-of-band.
- **`relatedPoamUuids`** — optional. If omitted, the section reads the literal real statement *"No related POA&M item; this change is not addressing a known risk."* — NOT a marker (this is a real, true, defensible statement when the change is not risk-driven).

Sentinel constant: reuse `TBD = 'REQUIRES-OPERATOR-INPUT'` from `core/roe-emit.ts`.

## Test specifications (≥12)
**`scn-doc.test.ts` (~12)**:
1. `it('renderScnDocx produces a valid store-only ZIP with [Content_Types].xml + word/document.xml + _rels/.rels')`.
2. `it('document includes all 10 verbatim FedRAMP-required SCR fields as section headers in order')` — parse OOXML and assert heading texts equal `FEDRAMP_SCR_REQUIRED_FIELDS`.
3. `it('NIST SP 800-37 Rev. 2 significant-change definition is quoted verbatim in section 11 body')`.
4. `it('REQUIRES-OPERATOR-INPUT marker emitted for missing assessorName')` — feed without `assessorName`; assert the cell contains literal `REQUIRES-OPERATOR-INPUT`.
5. `it('CSP approver signature cell is always REQUIRES-OPERATOR-INPUT regardless of cspApproverName')`.
6. `it('AO acknowledgement signature cell is always REQUIRES-OPERATOR-INPUT')`.
7. `it('classification verdict surfaces in front matter')` — feed `significance='significant'`; assert front matter renders "Significant Change".
8. `it('related POA&M items listed when relatedPoamUuids provided')` — feed 2 uuids; assert both rendered as bulleted list.
9. `it('related POA&M section reads "No related POA&M item" when uuids omitted')` — verbatim text match.
10. `it('emitScnDoc writes to outDir/scn-notice-<scnId>.docx')`.
11. `it('emitScnDoc appends ledger entry with current_state=submitted')`.
12. `it('--scn-doc with zero significant changes exits 0 without writing a .docx')` — assert no file written, exit code 0, log line "no significant changes detected".
13. `it('integrates with submission-bundle: scn-doc-docx role recognized')`.
14. `it('is deterministic: same input → byte-identical .docx (ZIP store + fixed mtime)')`.
15. `it('docx XML escapes special chars in operator narratives')` — feed `<`, `>`, `&` in `reasonForChange`; assert encoded.
16. `it('throws ScnMissingClassificationError when classifier output absent')`.
17. `it('throws ScnInvalidIdError when scnId does not match SCN-YYYY-NNNN')`.

**`scn-ledger.test.ts` (~6)**:
18. `it('appendScn persists a ledger entry in JSONL form')`.
19. `it('readScnLedger returns entries in chronological order')`.
20. `it('transitionScn appends without mutating prior states')`.
21. `it('activeScns excludes denied + reverted entries')`.
22. `it('ledger entry sha256 matches written docx file bytes')` — read written file, recompute sha256, assert equal.
23. `it('transitionScn idempotent on identical (state, at, by) tuple')`.

## REO compliance specific to this slice
- **Classification (significance + rationale + recommended_notice_days + rule_id) comes entirely from the real classifier output** — no override path in the doc emitter. If the operator wants to challenge a classification, they update `core/scn-classifier.ts` rules upstream, not here.
- **AO acknowledgement signature is NEVER auto-filled** (Rule 1.6).
- **CSP system owner signature is NEVER auto-filled**.
- **The 10-field SCR list is hardcoded as a constant array** in `core/scn-doc.ts` with a citation comment pointing at LOOP-E-SPEC §3 source 7. Per REO Rule 3, FedRAMP-published constants are an allowed exception (parallel to OSCAL field names, control IDs, etc.).
- **No fabricated `relatedPoamUuids`**: empty array → real true statement, not a marker.
- **Ledger sha256 matches the on-disk `.docx`**: verifiable by re-reading the file and computing the hash (covered by test #22).
- **`signed by`**: every `.docx` and the `scn-ledger.jsonl` are emitted into `outDir` BEFORE signing; the existing `core/sign.ts` pipeline (Ed25519 + RFC 3161) covers them.
- **Provenance**: each `.docx` embeds `core:custom_properties` (OOXML customXml) with `emitter='core/scn-doc.ts'`, `classification_rule_id`, `run_id`, `tool_version`.

## Verification commands
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/scn-doc.test.ts tests/core/scn-ledger.test.ts
npm run check:reo
```

## Known risks / issues
- **Risk 1: Classifier-doc desynchronization.** If `core/scn-classifier.ts` rule library updates between when the `.docx` is emitted and when the operator submits it to the agency, the rendered classification may not match the current rules. Mitigation: embed `classification.rule_id` + `rules_version` (compute from classifier source sha256) in `core:custom_properties` so the docx is self-describing. Severity: medium.
- **Risk 2: SIA path validity.** `securityImpactAnalysisPath` may point at a relative path that does not exist when the docx is reviewed. Mitigation: resolve the path against the run dir + verify file exists at emit time; if missing, render `REQUIRES-OPERATOR-INPUT` + warning. Severity: low.
- **Risk 3: Concurrent SCN ledger updates.** Two `--update-scn-state` calls colliding. Mitigation: file lock via `proper-lockfile` around `transitionScn` (same pattern as E.E5 ledger). Severity: medium.
- **Risk 4: Agency Word version compatibility.** Some federal agencies use Word 2010 / LibreOffice. Mitigation: stick to ECMA-376 WordprocessingML strict mode (no transitional schema extensions); validate generated XML against the strict schema in tests. Severity: medium.
- **Risk 5: 10-field list drifts.** FedRAMP may add an 11th required field in a future playbook update. Mitigation: the constant array lives in one place; an updated FedRAMP fetch script (`scripts/fetch-conmon-playbook.mjs` from E.E1) can detect new fields and surface a `provenance.warnings: ["scn-required-fields-drift"]`. Severity: low.
- **Risk 6: classifier emits `significance='advisory'`.** Advisory changes don't require a formal SCN, but the emitter currently treats anything non-`no-action` as render-worthy. Mitigation: add a `--allow-advisory-scn` opt-in flag; default behavior emits only for `significance='significant'`. Severity: low.
- **Risk 7: Hardcoded NIST 800-37 quote.** A future SP 800-37 Rev. 3 will likely change the definition wording slightly. Mitigation: pin the quote with `nist_sp_800_37_rev2_published='2018-12'` in the docx custom properties; document in `RUNBOOK.md` that the quote is rev-2 verbatim. Severity: low.
- **Risk 8: Multi-change rollup.** A single monthly run might classify 5 significant changes. Current schema: one `.docx` per `scn_id`. The orchestrator iterates the classifier output, emitting one per. Risk: numbering collisions if operator authors `scn-spec.json` files for only some. Mitigation: orchestrator auto-numbers per fiscal year (`SCN-<year>-<seq>`) based on ledger; operator-authored `scn_id` takes precedence if specified. Severity: medium.

## Open questions (for implementation session to resolve)
- **Q1**: Should `scn-spec.json` allow `change_id: ['change-001', 'change-002']` (multiple classifier changes rolled into one SCN)? Real-world SCNs often bundle several small changes. Recommend yes, with all referenced changes' rationales concatenated.
- **Q2**: For Section 11 signature block, should we render a 2x2 table (CSP, AO) or two separate paragraphs? FedRAMP doesn't specify; recommend table for consistency with E.E5 DR emitter.
- **Q3**: Should the docx include the FedRAMP logo / header image? Adds an embed-image step to the OOXML pipeline (parsed via `core/zip.ts` already supports media files). Recommend defer to a future enhancement.
- **Q4**: When `--update-scn-state denied` is called, should the next monthly run revert any inventory / config changes the SCN documented? Out of scope — the system describes change; it does not effect change in cloud SDKs.
- **Q5**: How should the docx handle `recommended_notice_days` from the classifier when the agency response is overdue (e.g. 45 days since submitted, classifier said 30)? Recommend a `provenance.warnings: ["scn-overdue-acknowledgement"]` in the next monthly run.
- **Q6**: Should there be an "expedited SCN" classification path for security-critical changes? Currently classifier supports `significance='significant'`; an expedited tier would set `recommended_notice_days < 7`. Defer to classifier rule library updates.
- **Q7**: For agency tracking, should the docx include a QR code to the on-disk classifier rationale JSON? Adds rendering complexity; defer.
- **Q8**: Should the ledger track agency acknowledgement turnaround SLA (days from `submitted` to `acknowledged`) and surface in the monthly conmon report? Recommend yes — operator visibility into agency responsiveness is valuable.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ~18 for this slice's new tests)
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
5. Read existing emitter for pattern reference: `core/scn-classifier.ts` (the input — re-use `ScnClassification`), `core/roe-emit.ts` (`.docx` OOXML pattern), `core/deviation-request.ts` + `core/deviation-ledger.ts` (E.E5 — mirror the ledger pattern verbatim).
6. Read `cloud-evidence/docs/slices/E/E.E1.md` — your slice's ledger feeds E.E1's monthly conmon report `scn_events` block.
7. Begin implementation; update Implementation log section as you go.
