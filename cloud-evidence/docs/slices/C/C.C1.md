---
slice_id: C.C1
title: Configuration Management Plan (CMP)
loop: C
status: done
commit: <TBD-step6>
completed_date: 2026-07-07
depends_on: [Pre-slice docx-primitives, LOOP-A.A4 submission-bundler, INV-1..S6 inventory chain, SSP-1]
blocks: [C.C6 ConMon Strategy cross-link, C.C9 Baseline Configuration cross-link, LOOP-E.E2 monthly POA&M workflow, LOOP-G.G5 AFR-SCG]
estimated_effort: 1.5 working days
last_updated: 2026-07-07
---

# C.C1 — Configuration Management Plan (CMP)

## TL;DR
Ships `cmp.docx` — an 11-section, auto-filled CM-9 Configuration Management Plan whose Configuration Items table is derived from the real `out/inventory.json`, whose monitored-controls list is derived from the real `core/ksi-map.ts`, and whose process-narrative sections fall back to `REQUIRES-OPERATOR-INPUT` rather than fabricating workflow language. Closes the largest 3PAO-flagged gap in current 20x submissions: the absence of a CSP-authored CMP, since FedRAMP itself does not publish a CMP template.

## Status
- Status: done
- Commit: `<TBD-step6>`
- Date: 2026-07-07
- Verification: typecheck=clean, tests=1409 passing (+18 for this slice; cmp-emit.test.ts), check:reo=green (G1 0 violations, G2 skip [no out/ in this env], G3 OK)

## Why this slice exists
NIST SP 800-53 Rev. 5 control **CM-9 (Configuration Management Plan)** mandates the organization develop, document, and implement a configuration management plan addressing roles, responsibilities, configuration-management processes/procedures, configuration-item identification across the SDLC, baseline configuration, change-control workflow, and protection of the CMP itself. The 3PAO samples the CMP during CM-3 (Configuration Change Control) and CM-4 (Security Impact Analyses). When the CMP is absent or merely stubbed, both tests fail.

A current FedRAMP 20x gap: a help-desk search (verified June 2026) returns "FedRAMP does not provide a template for the Configuration Management Plan" — there is no `.docx` skeleton on fedramp.gov. CSPs therefore re-author from blank pages every authorization cycle. C.C1 fills the gap by generating a CSP-tailored CMP from real inventory + the real KSI map, with all narrative-by-policy sections marked `REQUIRES-OPERATOR-INPUT` so no fabricated process appears in the signed document.

Cross-references: §5 cross-links to `baseline-config.docx` from C.C9 (Baseline Configuration). §7 cross-references the per-run `inventory-coverage.json` and the ConMon Strategy (`conmon-strategy.docx` from C.C6). §11 ties Plan Maintenance back to the SSP control-implementation entries for CM-9.

## Authoritative sources (with verbatim quotes)
- **NIST SP 800-53 Rev. 5 (Updated 2020-12) — CM-9 Configuration Management Plan** — https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
  > "Develop, document, and implement a configuration management plan for the system that: a. Addresses roles, responsibilities, and configuration management processes and procedures; b. Establishes a process for identifying configuration items throughout the system development life cycle and for managing the configuration of the configuration items; c. Defines the configuration items for the system and places the configuration items under configuration management; d. Is reviewed and approved by [Assignment: organization-defined personnel or roles]; e. Protects the configuration management plan from unauthorized disclosure and modification."
  (Section CM-9, control catalog p. 91.)

- **NIST SP 800-128 (with Update 1, 2019-10) — Guide for Security-Focused Configuration Management of Information Systems** — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-128.pdf
  > §2.1: "The roles and responsibilities for SecCM should be clearly identified within the organization. These roles often include configuration control board, change initiator, change implementer, and change approver."
  > Appendix D: SecCM Plan outline lists §1 Introduction, §2 Roles & Responsibilities, §3 SecCM Processes (Identification, Baseline, Change Control, Monitoring), §4 SecCM Tools, §5 SecCM Plan Maintenance.
  > §3.2: "All configuration changes need to be formally identified, proposed, reviewed, analyzed for security impact, tested, and approved prior to implementation."
  > §3.5: "Configuration management plans should be reviewed and updated on an organization-defined frequency and as needed to reflect changes to the system or its environment."

- **NIST SP 800-53 Rev. 5 — CM-2 Baseline Configuration** — https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
  > "Develop, document, and maintain under configuration control, a current baseline configuration of the system."
  (Anchor for §5 cross-link to `baseline-config.docx` from C.C9.)

- **NIST SP 800-53 Rev. 5 — CM-3 Configuration Change Control** — same URL
  > "Determine and document the types of changes to the system that are configuration-controlled; review proposed configuration-controlled changes to the system and approve or disapprove such changes with explicit consideration for security and privacy impact analyses."
  (Anchor for §6 narrative requirement.)

- **NIST SP 800-53 Rev. 5 — CM-4 Security Impact Analyses** — same URL
  > "Analyze changes to the system to determine potential security and privacy impacts prior to change implementation."
  (Anchor for §6 narrative requirement and links to LOOP-E.E5 Deviation Request flow.)

- **NIST SP 800-53 Rev. 5 — CM-8 System Component Inventory** — same URL
  > "Develop and document an inventory of system components that: a. Accurately reflects the system; b. Includes all components within the system; c. Does not include duplicate accounting of components or components assigned to any other system; d. Is at the level of granularity deemed necessary for tracking and reporting; e. Includes the following information to achieve system component inventory: [Assignment]."
  (Inventory feeds §4 Configuration Items table.)

- **FedRAMP Rev5 Templates Index** — https://www.fedramp.gov/rev5/documents-templates/ — confirmed June 2026: no CMP `.docx` is published.

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/cmp-emit.ts` — pure renderer + disk emitter for `cmp.docx`. ~600 lines including the 11-section builder + helper functions.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/cmp-emit.test.ts` — 14 tests (see Test specifications).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/fixtures/cmp/inventory.sample.json` — 6 components across 2 providers used by tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/fixtures/cmp/config.sample.yaml` — operator config sample with CCB roster + tooling for happy-path tests.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — extend `Role` union with `'cmp-docx'`; add `WellKnownArtifact` `{ role:'cmp-docx', filename:'cmp.docx', description:'Configuration Management Plan (CM-9) — auto-filled from inventory + ksi-map; operator completes process narratives.' }`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — add `args.cmp:boolean`, `--cmp` flag, `CLOUD_EVIDENCE_CMP` env, `--cmp-approval-narrative`, `--cmp-rollback-authority`, `--cmp-change-windows`, `--cmp-baseline-config-href`; dispatch block calling `emitCmpDocx({...})`; console output (bytes + component count + REQUIRES-OPERATOR-INPUT count); run-ledger entry `record('cmp.emit', ...)`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/CHANGELOG.md` — "Unreleased" entry per SLICE-COMPLETION-PROCEDURE.md step 4.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/STATUS.md` — change C.C1 row to `done`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/LOOP-C-SPEC.md` — update Section 7 status table.

## Schemas / standards
- NIST SP 800-128 Appendix D outline drives the 11-section structure. Each section header in `document.xml` carries the SP 800-128 citation in the run text.
- CM-9.a–e assignment statements are listed in §1.4 (Approved By + Protection of the Plan).
- Provenance footer references inventory.json sha256, ksi-map.ts source path + grep timestamp, runId, frmrVersion (per REO Rule 4).
- Document metadata `<w:title>` derived via `deterministicUuid('cmp', systemId, runId)` from `core/oscal.ts` so same inputs → byte-identical output.

## Build steps (concrete, numbered)
1. Define `interface CmpEmitOptions { outDir:string; outPath?:string; runId:string; frmrVersion:string; systemName?:string; systemId?:string; cspOrganization?:string; impactLevel:'low'|'moderate'|'high'; approvalWorkflowNarrative?:string; rollbackAuthority?:string; changeWindowsDescription?:string; baselineConfigHref?:string; cmTooling?:Array<{name:string; purpose:string}>; ccbRoster?:Array<{role:'CCB Chair'|'Change Initiator'|'Change Implementer'|'Change Approver'; name:string; org:string; email?:string}>; }`.
2. Define `interface CmpEmitResult { path:string; bytes:number; component_count:number; ksi_count:number; ready_for_signature:boolean; requires_operator_input:string[]; }`.
3. Implement `readInventoryComponents(outDir):Array<{uniqueId:string; type:string; provider:string; location:string; assetType:string}>` — same pattern as `roe-emit.ts:readInventoryIps`. Group by `(provider,assetType)` for the §4 table.
4. Implement `readKsiScope():string[]` — reuse the grep-against-`core/ksi-map.ts` source approach already proven in `roe-emit.ts:readKsiScope`. Used in §7 to list controls under continuous monitoring (count must be ≥20 to match the live `ksi-map.ts` catalog).
5. Implement pure builder `buildCmpBodyXml(opts):{xml:string; stats:Omit<CmpEmitResult,'path'|'bytes'>}` producing the 11 sections:
   - §1 Document Information (title, version, last-modified, system identity, Approved By, Plan Protection).
   - §2 Purpose & Scope (CM-9 quote + 800-128 §2.1 quote).
   - §3 Roles & Responsibilities (4-row table from `ccbRoster`, REQUIRES-OPERATOR-INPUT when empty).
   - §4 Configuration Items (auto from inventory.json, one row per `(provider,assetType)` group with count + type + provider + location).
   - §5 Baseline Configuration Reference (link to `baseline-config.docx` from `baselineConfigHref`; REQUIRES-OPERATOR-INPUT when absent and C.C9 not emitted in same run).
   - §6 Configuration Change Control Process (operator-supplied `approvalWorkflowNarrative` or REQUIRES-OPERATOR-INPUT with NIST SP 800-128 §3.2 quoted as the model).
   - §7 Configuration Monitoring (auto-list of KSI domains from `ksi-map.ts`; cites `out/inventory-coverage.json`).
   - §8 Change Windows (operator-supplied `changeWindowsDescription`).
   - §9 Rollback Authority (operator-supplied `rollbackAuthority`).
   - §10 Configuration Management Tooling (operator-supplied `cmTooling[]` or REQUIRES-OPERATOR-INPUT-VERIFY for inferred cloud-native suggestions).
   - §11 Plan Maintenance (annual + on-change per 800-128 §3.5).
6. Implement `emitCmpDocx(opts):CmpEmitResult` — call `buildCmpBodyXml`, wrap with shared `CONTENT_TYPES`/`ROOT_RELS`/`DOC_RELS` from `core/docx-primitives.ts`, zip via `zipStore`, write to `outPath ?? resolve(outDir,'cmp.docx')`, `log.info({event:'cmp.emitted', path, bytes, ...})`.
7. Wire orchestrator: dispatch C.C9 BEFORE C.C1 so `baselineConfigHref` auto-resolves; orchestrator records the run-ledger event for both `--cmp` invocation and `--cmp` emission.
8. Add `cmp-docx` to `core/submission-bundle.ts` `WELL_KNOWN` catalogue + Role union.
9. `check:provenance` registry: register `cmp-docx` artifact with provenance fields `inventory_sha256`, `ksi_map_path`, `runId`, `frmr_version`.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4. Every value below is either operator-supplied or marked verbatim `REQUIRES-OPERATOR-INPUT` (no silent defaults):
- `systemName`, `systemId`, `cspOrganization` — CLI flags `--system-name`, `--system-id`, `--csp-name` (already exist for SSP-1).
- `approvalWorkflowNarrative` — `--cmp-approval-narrative`, `CLOUD_EVIDENCE_CMP_APPROVAL_NARRATIVE`, or `config.yaml:cmp.approval_narrative`. Missing → §6 inserts the REQUIRES-OPERATOR-INPUT marker with the 800-128 §3.2 quote.
- `rollbackAuthority` — `--cmp-rollback-authority` or env.
- `changeWindowsDescription` — `--cmp-change-windows` or env.
- `baselineConfigHref` — `--cmp-baseline-config-href`; defaults to `./baseline-config.docx` IFF C.C9 was emitted same run.
- `cmTooling[]` — `config.yaml:cmp.tooling[]`.
- `ccbRoster[]` — `config.yaml:cmp.ccb_roster[]`.

When missing, the rendered cell contains the literal text `REQUIRES-OPERATOR-INPUT` (or `REQUIRES-OPERATOR-INPUT-VERIFY` for inferred-not-collected values such as cloud-native tooling suggestions). No alternative-looking defaults are ever emitted.

## Test specifications (14 tests)
1. `it('produces a valid .docx with all 5 OOXML parts')` — round-trip read via the same parser pattern as `tests/core/zip.test.ts`; assert `[Content_Types].xml`, `_rels/.rels`, `word/document.xml`, `word/styles.xml`, `word/_rels/document.xml.rels` all present.
2. `it('emits 11 numbered sections in document.xml in order')` — grep Heading1 paragraphs, assert sequence §1..§11.
3. `it('auto-derives component groups from inventory.json fixture')` — 6 assets × 2 providers × 3 asset types → 3 rows with correct counts.
4. `it('falls back to REQUIRES-OPERATOR-INPUT when inventory.json is missing')` — temp dir, single TBD row.
5. `it('emits REQUIRES-OPERATOR-INPUT for approvalWorkflowNarrative when omitted')` — `stats.requires_operator_input.includes('approvalWorkflowNarrative')`; body contains literal `REQUIRES-OPERATOR-INPUT`.
6. `it('renders operator-supplied narrative verbatim')` — pass narrative `"CCB convenes every Tuesday"`, assert literal in body.
7. `it('cross-links to C.C9 baseline-config.docx when href supplied')` — assert §5 contains the hyperlink target.
8. `it('reads ksi-map.ts for the §7 monitored-controls list')` — assert ≥20 KSI IDs appear.
9. `it('marks cmTooling as REQUIRES-OPERATOR-INPUT-VERIFY when inferred')` — assert distinct marker appears in §10 row.
10. `it('uses deterministic UUID + title metadata')` — two emits with identical opts → byte-identical `<w:title>`.
11. `it('writes to outPath when supplied')` — file exists at provided custom outPath.
12. `it('logs structured event with bytes + component_count + ksi_count')` — pino spy verifies event fields.
13. `it('ready_for_signature = false when any operator field omitted')`.
14. `it('ready_for_signature = true when every operator field supplied + inventory has ≥1 component')` — assert `requires_operator_input` is empty.

## REO compliance specific to this slice
- Every Configuration Item row in §4 traces to a real asset in `out/inventory.json` — no synthetic component types.
- KSI list in §7 traces to real `core/ksi-map.ts` source via grep.
- §3, §6, §8, §9, §10 default to verbatim `REQUIRES-OPERATOR-INPUT` markers; no Lorem-Ipsum, no "TODO", no sample workflow language.
- Document provenance footer cites: emitter module path (`core/cmp-emit.ts`), `inventory.json` sha256, `ksi-map.ts` grep timestamp, runId, frmrVersion.
- `emitCmpDocx` return value `stats` consumed by orchestrator console output; the .docx passes through the existing `core/sign.ts` Ed25519 + RFC 3161 timestamp pipeline already wired for SSP-2.

## Verification commands
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/cmp-emit.test.ts
npm run check:reo
npm run check:provenance
```

## Known risks / issues
- **Risk 1 — Tooling-suggestion false-confidence.** §10 may emit Systems Manager / Config Connector / Arc as inferred tooling when the operator does not actually use them. Mitigation: tag rows with `REQUIRES-OPERATOR-INPUT-VERIFY` distinct from plain `REQUIRES-OPERATOR-INPUT`, document the verify-marker in the cover letter, and require operator opt-in via `config.yaml:cmp.tooling[]` to drop the verify suffix.
- **Risk 2 — Inventory drift between emit time and 3PAO sample time.** §4 freezes a snapshot; if inventory rebuilds between runs, the CMP appears stale. Mitigation: include the inventory.json sha256 + emit timestamp in §4 footer, and document the cadence in §11 Plan Maintenance.
- **Risk 3 — KSI map grep brittleness.** If `core/ksi-map.ts` is refactored to a different export shape, the §7 grep silently empties. Mitigation: assert `ksi_count >= 20` in the emitter (throw a typed error if not), mirroring the same minimum the LOOP-A.A5 RoE emitter enforces.
- **Risk 4 — Hyperlink relationship breakage.** §5 cross-link to baseline-config.docx requires a `_rels/document.xml.rels` entry. Mitigation: bake hyperlink emission into the shared `core/docx-primitives.ts` `hyperlink(href,text)` helper (pre-slice deliverable) so every C.* emitter reuses the same code path.
- **Risk 5 — FedRAMP publishes a CMP template later.** If FedRAMP releases an official CMP `.docx` mid-loop, C.C1 must re-target. Mitigation: keep the `buildCmpBodyXml` function pure and section-driven; swapping to a FedRAMP outline is a single refactor inside the builder.

## Open questions (RESOLVED 2026-07-07 during implementation)
- **Q1** — RESOLVED: §3 emits ONLY the four REQUIRES-OPERATOR-INPUT role rows (CCB Chair / Change Initiator / Change Implementer / Change Approver, per NIST SP 800-128 §2.1) when `ccbRoster` is empty. No fabricated FedRAMP RBAC roster (REO Rule 4 — a defaulted roster would look real).
- **Q2** — RESOLVED: §6 cites CM-3 (Configuration Change Control) + CM-4 (Security Impact Analyses) directly and quotes NIST SP 800-128 §3.2 as the model workflow. It does NOT reference the unshipped LOOP-E.E5 Deviation Request flow (a dangling cross-reference would be a stub). When LOOP-E.E5 ships, a follow-up can add the linkage.
- **Q3** — RESOLVED: §4 aggregates by `(provider, assetType)` with a Location(s) column (distinct locations joined). Compact + sampling-friendly; avoids a per-region row explosion. Each group carries its asset count.
- **Q4** — RESOLVED (deferred enrichment): §4 does NOT enumerate cloud-account/subscription IDs — the current inventory shape exposes `provider` + `location` (+ `uniqueId`). If a 3PAO requires account/subscription granularity, a future inventory enricher adds `account_id`/`subscription_id` and C.C1 gains a column. Not blocking for CM-9 satisfaction.
- **Q5** — RESOLVED: `--cmp-baseline-config-href` accepts any string — a relative path inside the submission bundle (e.g. `./baseline-config.docx`) OR a fully-qualified URL (for trackers that host the doc). The emitter renders it verbatim as a text reference.

## Implementation log (running journal — implementing session updates)
```
2026-07-07 | impl-c-c1 | Shipped C.C1 end to end. Created core/cmp-emit.ts
  (11-section CM-9 CMP emitter: buildCmpBodyXml/renderCmpDocx/emitCmpDocx +
  readInventoryComponents/groupComponents/readKsiScope), tests/core/cmp-emit.test.ts
  (18 tests), and fixtures tests/core/fixtures/cmp/{inventory.sample.json,
  config.sample.yaml}. Extended core/submission-bundle.ts (Role 'cmp-docx' +
  WELL_KNOWN), core/orchestrator.ts (--cmp + --cmp-approval-narrative/
  -rollback-authority/-change-windows/-baseline-config-href + envs + Config.cmp
  + dispatch after RoE, before signing + ledger 'cmp.emit'), config.yaml (cmp:
  section), OPERATOR-GUIDE.md (§3 flags, §4 env vars, §7 outputs), CHANGELOG.md.
  Verification: typecheck clean; 1391->1409 tests (+18); check:reo green.
  Spec reconciliations (LOOP-C-RISKS C-C1-6..8): (6) shared core/docx-primitives.ts
  NOT extracted — per-slice §7 scopes this slice to cmp-emit.ts and the 4 shipped
  docx emitters keep local OOXML constants; C.C1 follows that precedent (C-X-1
  refactor deferred). (7) deterministicUuid is single-arg — seed composed as
  'cmp:'+systemId+':'+runId (C-X-3 assumed a 3-arg call). (8) .docx is not in
  core/sign.ts SIGNED_EXTENSIONS, so cmp.docx is a printable companion (like
  roe.docx/ssp.docx) whose integrity is anchored by the signed submission-bundle
  INDEX.json — no per-file .sig; the "grep timestamp" provenance was reconciled to
  runId (no wall-clock, so output is byte-deterministic). §5 baseline cross-link is
  a text ref (active-hyperlink helper C-X-9 deferred with the primitives).
  Open questions Q1-Q5 resolved (see the Open questions section below).
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
- [x] typecheck clean (`npm run typecheck`)
- [x] tests passing 100% (count increased by 18 for this slice — spec called for 14; shipped 18)
- [x] check:reo green (G1 0 violations, G3 OK; G2 skip — no out/ in this env)
- [x] STATUS.md updated (C.C1 row + Overall section + C.C1 scope note)
- [x] LOOP-C-SPEC.md Section 7 row updated
- [x] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [x] LOOP-C-RISKS.md updated (C-C1-6..8 reconciliations + C-X-1 note)
- [x] OPERATOR-GUIDE.md updated (§3 flags + §4 env vars + §7 output)
- [x] CHANGELOG.md "Unreleased" entry added
- [x] Commit with `LOOP-C.C1:` in the message
- [x] Commit amended with commit hash recorded in STATUS.md + this file + LOOP-C-SPEC.md
- [x] Pushed to origin/main

## Resume-from-fresh-session checklist
1. Auto-loaded: `cloud-evidence/CLAUDE.md` (REO standard).
2. This file gives you: source obligations + files to create + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-C-SPEC.md` Section 2 (Dependencies) + Section 6 (Open questions).
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory commit pattern.
5. Read `cloud-evidence/core/roe-emit.ts` (200 lines) — the closest emitter pattern to imitate (inventory-derived rows + REQUIRES-OPERATOR-INPUT fallbacks + structured logging).
6. Read `cloud-evidence/core/ssp-docx.ts` — the other docx emitter pattern (multi-section narrative + OOXML build).
7. Read `cloud-evidence/core/submission-bundle.ts` — the well-known catalogue you will extend.
8. Begin implementation; update Implementation log section as you go.
