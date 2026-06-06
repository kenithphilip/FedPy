---
slice_id: E.E5
title: Deviation Request (DR) Emitter
loop: E
status: pending
commit: —
completed_date: —
depends_on: [A.A1, A.A5]
blocks: [E.E1, E.E3, F.F1]
estimated_effort: 5 days
last_updated: 2026-06-06
---

# E.E5 — Deviation Request (DR) Emitter

## TL;DR
Ships the four-type Deviation Request (DR) workflow — Risk Adjustment (RA), False Positive (FP), Operational Requirement (OR), Vendor Dependency (VD) — that FedRAMP requires when a POA&M item cannot be remediated within the standard 30/90/180-day window. Each DR is rendered as a Word `.docx` on disk (`outDir/deviation-requests/DR-<num>-<type>.docx`), logged in `deviation-ledger.jsonl` with state transitions, and (when approved) drives `core/oscal-poam.ts` to flip the affected item's `risk.status` to `'deviation-approved'`. Enforces the FedRAMP rule that High-severity OR is rejected outright.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
FedRAMP defines four DR types verbatim — *"Risk Adjustments (RA): When mitigating factors reduce exploitation likelihood; False Positives (FP): When vulnerabilities don't actually exist; Operational Requirements (OR): When fixes would affect system functionality; Vendor Dependencies (VD): High-risk must reduce to Moderate within 30 days."* (2026 ConMon Evidence Guide). The FedRAMP POA&M Template `.xlsx` reserves Columns V/W/X/Q to flag each type, but the *narrative* DR document is a separate Word submission attached to the monthly POA&M upload.

Today, operators hand-author DRs in Microsoft Word — error-prone, inconsistent in structure, and (critically) without validation of the FedRAMP MUSTs:
- *"FedRAMP will not approve an OR for a High vulnerability"* — current process catches this only at AO review, weeks after submission.
- *"High-risk VDs must be mitigated to a Moderate level through compensating controls within thirty (30) days"* — manually tracked.
- *"CSPs are required to check in with the vendor at least once a month to determine the status of the patch/fix"* — easily forgotten until the AO points out a stale check-in date.

E.E5 closes the gap by encoding the validation rules in `validateDeviationRequest()`, rendering the formal `.docx` via the dependency-free OOXML pattern from `core/roe-emit.ts`, and threading state into `core/oscal-poam.ts` so the next monthly POA&M emission carries the correct `risk.status`. The DR ledger gives operators a single source of truth for what's pending / approved / expired.

Maps to:
- FedRAMP Rev5 Playbook §POA&M — DR taxonomy and approval rules
- FedRAMP POA&M Template `.xlsx` Columns V/W/X/Q/R/S
- OSCAL POA&M v1.1.2 `risk.status` enum (`deviation-requested`, `deviation-approved`)
- NIST SP 800-53 Rev5 CA-5 (POA&M) and RA-5 (Vulnerability Monitoring and Scanning)

## Authoritative sources (with verbatim quotes)
- <https://www.fedramp.gov/docs/rev5/playbook/csp/authorization/poam/> — FedRAMP Rev5 Playbook §POA&M:
  > "For FPs validated by the 3PAO during the assessment, select 'Yes' in Column W (False Positive) and move the risk to the POA&M's 'Closed' tab."
  > "For RAs validated by the 3PAO during the assessment, select 'Yes' in Column V (Risk Adjustment)."
  > "For ORs validated by the 3PAO during the assessment, select 'Yes' in Column X (Operational Requirement)."
  > "High-risk VDs must be mitigated to a Moderate level through compensating controls within thirty (30) days."
  > "Pending FPs must be approved by the federal agency AO prior to authorization." (same applies to RAs + ORs)
  > "CSPs are required to check in with the vendor at least once a month to determine the status of the patch/fix."
  > "FedRAMP requires Critical and High risks to be remediated within 30 days of discovery, Moderate risks within 90 days of discovery, and Low risks within 180 days of discovery."

- <https://www.fedramp.gov/resources/templates/FedRAMP-POAM-Template.xlsx> — FedRAMP POA&M Template (column letters are FedRAMP-published constants per REO Rule 3):
  > Column V = Risk Adjustment (Y/N); Column W = False Positive (Y/N); Column X = Operational Requirement (Y/N); Column Q = Vendor Dependency (Y/N); Column R = Last Vendor Check-in Date; Column S = Vendor Dependent Product Name.

- <https://elevateconsult.com/insights/fedramp-conmon-deliverables-essential-evidence-requirements-guide-2026/> — ConMon Evidence Guide 2026 §Deviation Requests:
  > "Risk Adjustments (RA): When mitigating factors reduce exploitation likelihood; False Positives (FP): When vulnerabilities don't actually exist; Operational Requirements (OR): When fixes would affect system functionality; Vendor Dependencies (VD): High-risk must reduce to Moderate within 30 days."

- <https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/plan-of-action-and-milestones/json-reference/> — OSCAL POA&M v1.1.2 JSON Reference (`risk.status`):
  > "risk.status [1]: enumeration { 'open', 'investigating', 'remediating', 'deviation-requested', 'deviation-approved', 'closed' }."

- <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf> — NIST SP 800-53 Rev5 control RA-5 (page 230):
  > "RA-5 Vulnerability Monitoring and Scanning — [a.] Monitor and scan for vulnerabilities ... [b.] Employ vulnerability monitoring tools and techniques ... [c.] Analyze vulnerability scan reports and results from vulnerability monitoring ..."

- <https://www.ecma-international.org/publications-and-standards/standards/ecma-376/> — ECMA-376 Office Open XML (OOXML), 5th edition (Dec 2016):
  > "Part 1 §17: WordprocessingML reference — `<w:document>`, `<w:body>`, `<w:p>`, `<w:r>`, `<w:t>`, `<w:tbl>`, `<w:tr>`, `<w:tc>` element schemas."
  > "Part 3 §13: store-only ZIP archive requirements for OPC packages."

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/deviation-request.ts` — types + validator + renderer + disk emitter. ~600 LOC.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/deviation-ledger.ts` — append-only JSONL ledger with state transitions. ~200 LOC.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/deviation-request.test.ts` — ~15 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/deviation-ledger.test.ts` — ~8 tests.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-poam.ts` — add `deviationOverrides?: Map<string, 'deviation-requested' | 'deviation-approved'>` to `PoamEmitOptions` (where the map key is the OSCAL `poam-item.uuid`). Update `severityToRiskStatus()` so an override takes precedence over the auto-computed status. Add a parallel `deviationDeadlineOverrides?: Map<string, string>` (ISO date) for DR `expires_at` to overwrite `risk.deadline`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — add `--emit-deviation-request <dr-spec.json>` flag, `--update-deviation-state <dr_id> <state> <by>` admin sub-command, and matching `CLOUD_EVIDENCE_*` envs. Validate dr-spec.json against the operator-authored schema; emit `.docx` and append ledger entry as state=`pending`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add Roles `'deviation-request-docx'` (regex `/^deviation-requests\/DR-\d+-(RA|FP|OR|VD)\.docx$/`, required=false) and `'deviation-ledger'` (filename `deviation-ledger.jsonl`, required=false).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/roe-emit.ts` — export the OOXML helpers (`para`, `heading`, `table`, `fieldTable`, `xmlEscape`, `TBD` constant) for reuse here. No behavior change in roe-emit.ts itself; just public re-exports.

## Schemas / standards
**`DeviationRequest` shape**:

```ts
export type DrType = 'RA' | 'FP' | 'OR' | 'VD';
export type DrState = 'pending' | 'approved' | 'denied' | 'expired';

export interface DeviationRequest {
  dr_id: string;                          // human-readable, e.g. "DR-2026-0001-RA"
  dr_type: DrType;
  poam_item_uuid: string;                 // the OSCAL poam-item.uuid this DR covers
  finding_rule: string;                   // e.g. "rule:KSI-CNA-RVP-egress-port-open"
  ksi_id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  original_finding_summary: string;       // 1-2 line summary
  justification: string;                  // operator-supplied prose (REQUIRED)
  compensating_controls?: string[];       // NIST control IDs (e.g. ["SC-7", "SC-7(3)"])
  supporting_evidence_refs?: string[];    // URLs or file paths

  // RA-specific:
  adjusted_severity?: 'medium' | 'low';
  adjustment_rationale?: string;

  // VD-specific:
  vendor_name?: string;
  vendor_product?: string;
  vendor_advisory_url?: string;
  last_vendor_check_in_date?: string;     // ISO; must be <= 30d from `now`

  // OR-specific:
  operational_impact_if_remediated?: string;

  // FP-specific:
  reason_finding_does_not_exist?: string;

  // Workflow:
  csp_approver_name: string;              // REQUIRED
  csp_approver_title: string;             // REQUIRED
  submitted_at: string;                   // ISO
  ao_approval_status: DrState;            // start at 'pending'
  ao_approval_date?: string;              // ISO; set on transition to approved/denied
  expires_at?: string;                    // ISO; default submitted_at + 12 months
}

export interface DeviationLedgerEntry {
  dr_id: string;
  dr_type: DrType;
  poam_item_uuid: string;
  current_state: DrState;
  expires_at: string | null;
  docx_path: string;                      // relative to outDir
  docx_sha256: string;
  transitions: Array<{ state: DrState; at: string; by: string }>;
}
```

**Validation rules** (`validateDeviationRequest(dr): Error[]`):
- All four types: `justification` non-empty, `csp_approver_name` + `csp_approver_title` non-empty, `poam_item_uuid` non-empty.
- RA: `adjusted_severity` ∈ {`medium`,`low`}, `adjustment_rationale` non-empty.
- FP: `reason_finding_does_not_exist` non-empty.
- OR: `operational_impact_if_remediated` non-empty.
- OR + `severity === 'high'` → ERROR (FedRAMP MUST: *"FedRAMP will not approve an OR for a High vulnerability"*). Constant: `OR_HIGH_REJECTION_MESSAGE`.
- VD: `vendor_name`, `vendor_product`, `last_vendor_check_in_date` all required.
- VD + `last_vendor_check_in_date` > 30 days from `now` → ERROR (FedRAMP MUST: *"check in with the vendor at least once a month"*).
- VD + `severity === 'high'` → require `compensating_controls.length > 0` AND `adjustment_rationale` (mitigation to moderate within 30d).

**Word `.docx` structure** (7 sections):
1. **Identification table** — `dr_id`, `dr_type`, system name, CSP, POA&M item UUID, finding rule, KSI ID, severity, submitted_at.
2. **Original finding** — `original_finding_summary` paragraph + reference to POA&M doc URL.
3. **Deviation justification** — `justification` paragraph + per-type fields:
   - RA: adjusted_severity, adjustment_rationale.
   - FP: reason_finding_does_not_exist.
   - OR: operational_impact_if_remediated.
   - VD: vendor_name, vendor_product, vendor_advisory_url, last_vendor_check_in_date.
4. **Compensating controls** — table (control_id, description if known).
5. **Supporting evidence** — bulleted list of `supporting_evidence_refs`.
6. **CSP approver block** — `csp_approver_name`, `csp_approver_title`, `signature` (← always `REQUIRES-OPERATOR-INPUT`).
7. **AO sign-off block** — 4 cells: `ao_name`, `ao_title`, `ao_approval_date`, `ao_signature` (all `REQUIRES-OPERATOR-INPUT` until the AO returns the signed copy).

## Build steps (concrete, numbered)
1. **Types + validator** in `core/deviation-request.ts`. Define `DrType`, `DrState`, `DeviationRequest`, `DeviationLedgerEntry`. Implement `validateDeviationRequest(dr): Error[]` per the rules above. Return typed errors (e.g. `DrValidationError`, `DrOrHighRejectionError`, `DrVdStaleCheckInError`).
2. **`renderDeviationRequestDocx(dr): Buffer`**. Reuse OOXML helpers re-exported from `core/roe-emit.ts`: `para`, `heading`, `table`, `fieldTable`, `xmlEscape`, `TBD`. Mirror `roe-emit.ts` structure: build `word/document.xml`, `[Content_Types].xml`, `_rels/.rels`, `word/_rels/document.xml.rels`, then `zipStore()` to ZIP-bytes. Fixed mtime (`0`) for determinism.
3. **`emitDeviationRequest(opts: { outDir, dr }): { path: string; ledgerEntry: DeviationLedgerEntry }`**:
   a. Call `validateDeviationRequest(dr)` — throw on any errors.
   b. Mkdir `outDir/deviation-requests/` if absent.
   c. Compute filename: `DR-<num>-<dr_type>.docx` where `<num>` is the numeric suffix of `dr_id` (regex `/^DR-\d{4}-(\d+)-(RA|FP|OR|VD)$/`).
   d. Render via `renderDeviationRequestDocx(dr)`; write atomically (tmp + rename).
   e. Compute sha256 of file bytes.
   f. Append a ledger entry via `appendDr(outDir, entry)` with `current_state='pending'`, `transitions=[{state:'pending', at: dr.submitted_at, by: dr.csp_approver_name}]`.
4. **Ledger** in `core/deviation-ledger.ts`:
   - `appendDr(outDir, entry)`: atomic append to `outDir/deviation-ledger.jsonl` via `fs.appendFileSync` (POSIX append-only is atomic for our < 4KB lines).
   - `transitionDr(outDir, dr_id, new_state, by, at?)`: read ledger, find entry, append a transitions[] item, update `current_state` and `ao_approval_date`/`expires_at` as needed, REWRITE the file via atomic tmp+rename (the JSONL is small enough that a full rewrite is acceptable; alternative: append a "transition record" line and have readDeviationLedger merge). Choose the rewrite approach for simpler semantics.
   - `readDeviationLedger(outDir): DeviationLedgerEntry[]` — read + JSON.parse line-by-line.
   - `activeDeviations(outDir): DeviationLedgerEntry[]` — filter `current_state==='approved' && (expires_at == null || expires_at > now)`.
5. **OSCAL POA&M integration**:
   a. Extend `PoamEmitOptions` with `deviationOverrides?: Map<string, 'deviation-requested' | 'deviation-approved'>` and `deviationDeadlineOverrides?: Map<string, string>`.
   b. In `severityToRiskStatus()` (or wherever `risk.status` is computed), check the override map first; if uuid is present, use the override.
   c. When `deviationDeadlineOverrides.get(uuid)` is set, replace the computed `risk.deadline` with the DR `expires_at`.
   d. The orchestrator builds the overrides map from `readDeviationLedger(outDir)` BEFORE calling `emitOscalPoam()`.
6. **Operator workflow**:
   - Author `dr-spec.json` per the `DeviationRequest` shape.
   - Run `--emit-deviation-request dr-spec.json` → validates + emits `.docx` + appends ledger as `pending`.
   - When AO approves: `--update-deviation-state DR-2026-0001-RA approved "Jane AO"` → ledger transition.
   - On the next `--conmon-monthly --oscal-poam` run, the POA&M item's `risk.status` flips to `deviation-approved` and `risk.deadline` updates to `expires_at`.
7. **Expiration handling**: monthly run also calls `expireStaleDr(outDir, now)` which finds approved DRs with `expires_at < now` and transitions them to `expired`. On expiration, the next POA&M emission removes the override → item returns to its base computed status (open / remediating / past deadline).
8. **High-OR rejection**: when validator detects `OR + severity=high`, throw `DrOrHighRejectionError` with the verbatim FedRAMP quote ("FedRAMP will not approve an OR for a High vulnerability") so the CLI prints the citation alongside the rejection.
9. **submission-bundle catalogue**: register `deviation-request-docx` + `deviation-ledger` roles so monthly bundles include them automatically.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4 + Rule 1.6 (no fake cryptographic operations):

- **`csp_approver_signature` cell in the `.docx`** — NEVER auto-emitted. Always `REQUIRES-OPERATOR-INPUT`. Operator prints, signs, scans, re-uploads.
- **`ao_approval_signature` cell** — NEVER auto-emitted. Always `REQUIRES-OPERATOR-INPUT`. The `--update-deviation-state` workflow only flips the ledger state; the docx signature cell is never overwritten.
- **`ao_approval_date`, `ao_name`, `ao_title`** — populated only by `--update-deviation-state`. Default = `REQUIRES-OPERATOR-INPUT`.
- **`expires_at`** — auto-defaults to `submitted_at + 12 months` if omitted; operator can override via the `dr-spec.json` field.
- **Per-type narrative fields** (`justification`, `adjustment_rationale`, `reason_finding_does_not_exist`, `operational_impact_if_remediated`) — operator-authored in `dr-spec.json`. The validator REJECTS empty strings (no `REQUIRES-OPERATOR-INPUT` substitution here — the DR is genuinely incomplete and should not be emitted).
- **`compensating_controls`** — optional in general; required (per validator) only for VD + severity=high.

Sentinel constant: reuse `TBD = 'REQUIRES-OPERATOR-INPUT'` from `core/roe-emit.ts`.

## Test specifications (≥15)
**`deviation-request.test.ts` (~15)**:
1. `it('validates RA requires adjusted_severity + adjustment_rationale')` — feeds RA with empty `adjustment_rationale`; asserts `DrValidationError`.
2. `it('validates OR + severity=high throws DrOrHighRejectionError with the verbatim FedRAMP quote')` — asserts the error message contains "FedRAMP will not approve an OR for a High vulnerability".
3. `it('validates VD + last_vendor_check_in_date > 30d ago throws DrVdStaleCheckInError')`.
4. `it('validates FP requires reason_finding_does_not_exist')`.
5. `it('renders .docx with all 7 sections')` — parse OOXML `word/document.xml`, assert section heading texts present in order.
6. `it('docx is a valid store-only ZIP with [Content_Types].xml + word/document.xml + _rels/.rels')`.
7. `it('docx contains the dr_id + poam_item_uuid as literal text in word/document.xml body')`.
8. `it('CSP approver signature cell is literally REQUIRES-OPERATOR-INPUT in the rendered XML')`.
9. `it('AO sign-off cells are all REQUIRES-OPERATOR-INPUT')`.
10. `it('emitDeviationRequest writes to outDir/deviation-requests/DR-2026-0001-RA.docx')`.
11. `it('emitDeviationRequest appends a ledger entry with current_state=pending')`.
12. `it('VD with severity=high requires compensating_controls')` — asserts validator rejects when missing.
13. `it('is deterministic: same dr-spec → byte-identical .docx (ZIP store + fixed mtime)')`.
14. `it('rejects DR pointing at non-existent POA&M item uuid')` — feeds outDir without that uuid; expects `DrUnknownPoamUuidError`.
15. `it('rejects DR with empty justification')`.
16. `it('renderDeviationRequestDocx escapes XML special chars in narratives')` — feed `<` `>` `&` `"` chars; assert encoded.
17. `it('expires_at defaults to submitted_at + 12 months when omitted')`.

**`deviation-ledger.test.ts` (~8)**:
18. `it('appendDr persists a ledger entry')`.
19. `it('readDeviationLedger returns entries in append order')`.
20. `it('transitionDr appends a transitions[] entry (does not delete prior states)')`.
21. `it('transitionDr updates current_state + ao_approval_date')`.
22. `it('activeDeviations excludes denied + expired entries')`.
23. `it('activeDeviations excludes approvals whose expires_at < now')`.
24. `it('ledger handles concurrent appends safely (POSIX O_APPEND atomicity)')`.
25. `it('transitionDr is idempotent on same (state, at, by) tuple')` — re-applying does not double-append.

**OSCAL POA&M integration (additional to `oscal-poam.test.ts`)**:
26. `it('approved DR override flips item risk.status to deviation-approved on next emit')`.
27. `it('approved DR override replaces risk.deadline with DR expires_at')`.
28. `it('expired DR returns item to base computed status (no override)')`.

**Bundle / orchestrator integration**:
29. `it('submission-bundle.ts classifies deviation-requests/*.docx with role=deviation-request-docx')`.

## REO compliance specific to this slice
- **Every emitted DR traces to a real `poam_item_uuid`** in `out/poam.json`. The validator looks up the uuid in the on-disk POA&M and throws `DrUnknownPoamUuidError` if missing — never silently emits a DR for a "ghost" finding.
- **No fake approvals**. The ledger `transitions[]` records only a structural transition (state + at + by); the actual CSP / AO `.docx` signature cells stay `REQUIRES-OPERATOR-INPUT`. REO Rule 1.6 + 1.10 enforced.
- **High-severity OR rejection is a hard-coded MUST** per FedRAMP. The validator citation includes the verbatim FedRAMP quote so the error is auditable.
- **No silent expiration**. When a DR's `expires_at < now` is detected during the monthly run:
  (a) The POA&M item flips back to its computed status (open/remediating/past deadline).
  (b) `core/conmon-report.ts` (E.E1) flags it under `deviation_requests.expiring_within_30d` proactively when within 30 days of `expires_at`.
- **Operator-authored narrative fields are validated for non-emptiness**. The validator does NOT substitute `REQUIRES-OPERATOR-INPUT` — instead, it rejects the DR (the DR is genuinely incomplete and should not be emitted; this differs from optional metadata fields where the marker IS appropriate).
- **`signed by`**: every `.docx` and the `deviation-ledger.jsonl` are emitted into `outDir` BEFORE signing; the existing `core/sign.ts` pipeline (Ed25519 + RFC 3161) covers them.
- **Provenance fields**: each `.docx` carries a `core:custom_properties` block (OOXML `customXml`) with `emitter='core/deviation-request.ts'`, `dr_id`, `run_id`, `tool_version`.

## Verification commands
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/deviation-request.test.ts tests/core/deviation-ledger.test.ts
npm run check:reo
```

## Known risks / issues
- **Risk 1: VD check-in date drift.** A long-running approved VD-DR can have `last_vendor_check_in_date` go stale silently (validator only runs on emit, not on every monthly POA&M run). Mitigation: extend `expireStaleDr` to also flag VDs whose `last_vendor_check_in_date` exceeds 30d, emitting a `provenance.warnings: ["vd-checkin-stale:<dr_id>"]` in the monthly conmon report. Severity: medium.
- **Risk 2: Ledger rewrite race.** `transitionDr` rewrites the JSONL atomically (tmp + rename), but two simultaneous `--update-deviation-state` calls could clobber each other's transitions. Mitigation: file lock via `proper-lockfile` (already in dependency tree per `core/run-lock.ts`) around `transitionDr`. Severity: medium.
- **Risk 3: OOXML rendering edge cases.** Newlines in `justification` need to be split into multiple `<w:p>` elements (Word does not render `\n` inside `<w:t>`). Mitigation: add a `splitParas(text)` helper that emits one `<w:p>` per logical paragraph. Test: feed a justification with `\n\n` and assert 2 `<w:p>` elements. Severity: low.
- **Risk 4: DR-against-multiple-POA&M-items.** A single root-cause vulnerability might span multiple POA&M items (e.g. same CVE on 50 hosts). Current schema: one DR per `poam_item_uuid`. Operator must author 50 DRs OR pre-aggregate the POA&M items first. Mitigation: future enhancement to accept `poam_item_uuids: string[]`; track as scope-creep, NOT this slice. Severity: high (UX) but out of scope.
- **Risk 5: AO email approval workflow.** Real-world AOs approve via email, not by editing the `.docx`. The operator manually fills the AO block from the email content. Mitigation: future LOOP-F.F1 will provide a tracker UI to capture AO approvals; for now, `--update-deviation-state` + operator hand-edit. Severity: medium.
- **Risk 6: Severity downgrade abuse.** RA `adjusted_severity` enum is `medium|low`; nothing prevents an operator from claiming RA-downgrade on every High finding to avoid the 30-day deadline. Mitigation: the rendered `.docx` requires `compensating_controls` for any High→Medium adjustment; future LOOP-F.F1 will surface RA approval rates per CSP for the AO. Severity: high (policy abuse) but the slice cannot enforce — only document.
- **Risk 7: Numbered ID collisions.** `DR-2026-0001-RA` and `DR-2026-0001-FP` differ only by type. If operator double-emits with the same number, the file collision will silently overwrite. Mitigation: `emitDeviationRequest` checks for an existing file with the same `dr_id` prefix and throws `DrIdCollisionError`. Severity: medium.
- **Risk 8: Expired DR rehydration.** When a DR expires and the POA&M item reverts, the original finding's `discovered_at` is preserved — so the 30/90/180-day clock has not reset. The remediation deadline computed by `core/oscal-poam.ts` will likely show `days_past_deadline > 0` immediately. Mitigation: document this in the conmon-monthly report's "deviation_requests" section so the operator is not surprised. Severity: low (correct behavior; just needs documentation).

## Open questions (for implementation session to resolve)
- **Q1**: Should the AO block in the `.docx` include a QR code linking to a Connect.gov approval URL (when LOOP-H.H1 cloud-archive lands)? Adds rendering complexity but enables one-click verification.
- **Q2**: For numeric DR IDs, should the counter be global (DR-2026-0001, DR-2026-0002, ...) or per-type (DR-2026-RA-0001, DR-2026-RA-0002, ...)? Recommend global to avoid same-number-different-type confusion noted in Risk 7.
- **Q3**: Should DR re-submissions (operator authors a v2 after AO denial with new evidence) increment the version (`DR-2026-0001-RA-v2.docx`) or replace? Recommend versioning to preserve audit trail.
- **Q4**: When `--update-deviation-state denied <reason>` is called, should the next POA&M emission revert the item immediately, or wait until the next monthly cycle? Recommend immediate revert with a `denied_at` timestamp in the ledger.
- **Q5**: How should the ledger handle a DR whose underlying POA&M item is closed (e.g. operator remediated despite the active DR)? Recommend auto-transition to `superseded` state.
- **Q6**: Should the `.docx` embed a hash of `dr-spec.json` in the `core:custom_properties` so downstream verifiers can prove provenance? Recommend yes.
- **Q7**: For VD DRs, should the ledger track the vendor advisory URL's last-modified date (HTTP HEAD) and flag when it changes (vendor published a new advisory)? Adds network call; defer to a future automation slice.
- **Q8**: What is the right cardinality of `compensating_controls` for VD-High? FedRAMP guidance does not specify a minimum count. Recommend ≥ 1 with a warning at 1, ≥ 2 ideal.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
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
If a session opens with ONLY this file as context, here's everything it needs to start:
1. Read `cloud-evidence/CLAUDE.md` (REO standard, auto-loaded).
2. This file gives you: source obligations + files to create + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-E-SPEC.md` Section 2 (Dependencies) for context on this loop.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory commit pattern.
5. Read existing emitter for pattern reference: `core/roe-emit.ts` (`.docx` OOXML pattern — copy verbatim), `core/oscal-poam.ts` (the deviationOverrides hook lives here), `core/scn-classifier.ts` (ledger + classifier shape — similar pattern to E.E5 ledger).
6. Read `cloud-evidence/docs/slices/E/E.E1.md` (monthly conmon report) — your slice's expired-DR + expiring-within-30d data lands in that report's `deviation_requests` block.
7. Begin implementation; update Implementation log section as you go.
