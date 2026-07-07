---
slice_id: C.C2
title: Information System Contingency Plan (ISCP) + Test AAR
loop: C
status: done
commit: e660109
completed_date: 2026-07-07
depends_on: [Pre-slice docx-primitives, INV-1..S6 inventory chain, RPL-ABO/TRC/RRO/ARP collectors, SSP-1]
blocks: [LOOP-E.E7 IRP/ISCP test cadence runner, LOOP-F.F7 SAR draft generator references]
estimated_effort: 2 working days
last_updated: 2026-07-07
---

# C.C2 — Information System Contingency Plan (ISCP) + Test AAR

## TL;DR
Ships two `.docx` artifacts: `iscp.docx` (CP-2 Contingency Plan, structured per FedRAMP SSP Appendix G + NIST SP 800-34 Rev. 1) and `iscp-test-aar.docx` (CP-4 annual test After-Action Report). Both auto-fill from real `out/KSI-RPL-*.signed.json` evidence files (ABO/TRC/RRO/ARP) when present and from `out/subprocessors.json` for vendor contacts; every operator narrative slot defaults to `REQUIRES-OPERATOR-INPUT`.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
NIST SP 800-53 Rev. 5 control **CP-2 (Contingency Plan)** mandates a documented contingency plan; **CP-4 (Contingency Plan Testing)** mandates annual testing. 3PAOs sample both the plan AND the most-recent test results during the assessment cycle. CSPs currently hand-author both documents from the FedRAMP SSP Appendix G ISCP Template, costing multiple person-days per cycle. The four RPL-family KSIs (ABO=Automated Backups Configured, TRC=Tested Recovery Capability, RRO=Recovery RPO/RTO Objectives, ARP=Alternate Recovery Processing) are already collected as real cloud evidence — the ISCP can cite the signed evidence files rather than transcribing narratives by hand.

## Authoritative sources (with verbatim quotes)
- **FedRAMP SSP Appendix G — Information System Contingency Plan (ISCP) Template** — https://www.fedramp.gov/assets/resources/templates/SSP-Appendix-G-Information-System-Contingency-Plan-(ISCP)-Template.docx
  Section structure (mirrored exactly): §1 Introduction & Scope; §2 Concept of Operations; §3 Activation & Notification; §4 Recovery; §5 Reconstitution; §6 Plan Maintenance; Appendix A Personnel Contact List; Appendix B Vendor Contacts; Appendix C Detailed Recovery Procedures; Appendix D Alternate Site Procedures; Appendix E System Validation Test Plan; Appendix F Contingency Plan Test Report.

- **NIST SP 800-34 Rev. 1 (Updated 2010-11-11) — Contingency Planning Guide for Federal Information Systems** — https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-34r1.pdf
  > §3.1 (p. 17): "The information system contingency planning process includes the following seven steps: 1) Develop the contingency planning policy; 2) Conduct the business impact analysis (BIA); 3) Identify preventive controls; 4) Create contingency strategies; 5) Develop an information system contingency plan; 6) Ensure plan testing, training, and exercises; 7) Ensure plan maintenance."
  > §3.6 (p. 41) defines tabletop, functional, and full-interruption test types verbatim — these are the `testType` enum values in the AAR emitter.
  Sample Moderate-impact ISCP template (referenced) — https://csrc.nist.gov/CSRC/media/Publications/sp/800-34/rev-1/final/documents/sp800-34-rev1_cp_template_moderate_impact_system.docx

- **NIST SP 800-53 Rev. 5 — CP-2 Contingency Plan** — https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
  > "Develop a contingency plan for the system that: a. Identifies essential mission and business functions and associated contingency requirements; b. Provides recovery objectives, restoration priorities, and metrics; c. Addresses contingency roles, responsibilities, assigned individuals with contact information; d. Addresses maintaining essential mission and business functions despite a system disruption, compromise, or failure; e. Addresses eventual, full system restoration without deterioration of the controls originally planned and implemented; f. Addresses the sharing of contingency information; g. Is reviewed and approved by [Assignment]."

- **NIST SP 800-53 Rev. 5 — CP-4 Contingency Plan Testing** — same URL
  > "Test the contingency plan for the system [Assignment: organization-defined frequency] using the following tests to determine the effectiveness of the plan and the readiness to execute the plan: [Assignment: organization-defined tests]; Review the contingency plan test results; Initiate corrective actions, if needed; Coordinate contingency plan testing with organizational elements responsible for related plans."

- **NIST SP 800-53 Rev. 5 — CP-9 System Backup, CP-10 System Recovery and Reconstitution** — same URL — anchors for the RPL-evidence table rows.

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/iscp-emit.ts` — pure renderer + disk emitter for `iscp.docx` (~700 lines incl. 6 sections + 6 appendices).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/iscp-test-aar.ts` — pure renderer + disk emitter for `iscp-test-aar.docx` (~400 lines).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/iscp-emit.test.ts` — 13 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/iscp-test-aar.test.ts` — 10 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/fixtures/iscp/KSI-RPL-ABO.signed.json` — fixture RPL-ABO envelope (pass + 3 evidence rows).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/fixtures/iscp/KSI-RPL-TRC.signed.json` — fixture RPL-TRC envelope.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/fixtures/iscp/KSI-RPL-RRO.signed.json` — fixture RPL-RRO envelope.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/fixtures/iscp/KSI-RPL-ARP.signed.json` — fixture RPL-ARP envelope.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/fixtures/iscp/subprocessors.sample.json` — fixture for Appendix B.

## Files to extend
- `core/submission-bundle.ts` — Role union extended with `'iscp-docx'` + `'iscp-test-aar-docx'`; two new `WellKnownArtifact` entries.
- `core/orchestrator.ts` — `--iscp`, `--iscp-test-aar` flags; `CLOUD_EVIDENCE_ISCP`, `CLOUD_EVIDENCE_ISCP_TEST_AAR` envs; dispatch blocks; run-ledger entries.
- `CHANGELOG.md` "Unreleased" — one entry per emitter.
- `docs/STATUS.md` + `docs/loops/LOOP-C-SPEC.md` — status updates.

## Schemas / standards
- ISCP section mapping (FedRAMP Appendix G ↔ NIST SP 800-34 R1 ↔ Rev5 controls): documented in the module header JSDoc with URL + page citations.
- RPL evidence schema: existing `envelope.ts` shape with `findings[].gap` + `findings[].metadata.last_collected_at`.
- AAR scenario row schema (per FedRAMP Appendix G Appendix F format): id, description, rto_target_hours, rto_actual_hours, rpo_target_hours, rpo_actual_hours, outcome ∈ {pass,fail,partial}.

## Build steps (concrete, numbered)

For `iscp-emit.ts`:
1. Define `IscpEmitOptions`: `outDir; outPath?; runId; frmrVersion; systemName?; systemId?; cspOrganization?; impactLevel; rto?:{hours:number; rationale:string}; rpo?:{hours:number; rationale:string}; recoveryPriority?:'mission-critical'|'mission-essential'|'standard'; alternateSite?:{type:'hot'|'warm'|'cold'|'cloud'; location:string; activationProcedure:string}; activationAuthority?:string; activationCriteria?:string[]; cpCoordinator?:{name; org; email; phone}; teamRoster?:Array<{role; name; org; email; phone; alternate?}>; vendorContacts?:Array<{vendor; contact; role; phone; sla}>; backupStrategySummary?:string`.
2. Implement `readRplEvidence(outDir):{abo?:KsiEvidence; trc?:KsiEvidence; rro?:KsiEvidence; arp?:KsiEvidence}` — JSON-parse-safe reads, no throw.
3. Pure builder `buildIscpBodyXml(opts):{xml; stats}` producing:
   - §1 Introduction (1.1 Background, 1.2 Scope, 1.3 Methodology = 800-34 §3.1 7-step quote verbatim, 1.4 Assumptions).
   - §2 Concept of Operations (system description from `out/ssp.json` when present; component table from inventory.json).
   - §3 Activation & Notification Phase (criteria + roster + sequence-of-events table).
   - §4 Recovery Phase (4.1 RTO/RPO commitments; 4.2 RPL evidence table — KSI ID | passed | last_collected_at | evidence citation; 4.3 Recovery sequence).
   - §5 Reconstitution Phase (validation tests + return-to-normal checklist).
   - §6 Plan Maintenance (annual review + on-change triggers per 800-34 §3.7).
   - Appendix A — Personnel Contact List (teamRoster + REQUIRES-OPERATOR-INPUT rows for blanks).
   - Appendix B — Vendor / Subprocessor Contacts (auto-pull `out/subprocessors.json` when present).
   - Appendix C — Detailed Recovery Procedures (REQUIRES-OPERATOR-INPUT; framework only).
   - Appendix D — Alternate Site Procedures (from `alternateSite`).
   - Appendix E — System Validation Test Plan (cross-ref Appendix F).
   - Appendix F — Contingency Plan Test Report (cross-ref `iscp-test-aar.docx`).
4. Implement `emitIscpDocx(opts):IscpEmitResult` — write `iscp.docx`, log structured event.

For `iscp-test-aar.ts`:
1. Define `IscpTestAarOptions`: `outDir; outPath?; runId; testDate?:string; testType?:'tabletop'|'functional'|'full-interruption'; participants?:Array<{role; name; org}>; scenarios?:Array<{id; description; rto_target_hours; rto_actual_hours; rpo_target_hours; rpo_actual_hours; outcome:'pass'|'fail'|'partial'}>; lessonsLearned?:Array<{id; finding; severity; recommendation; owner; due_date}>; testCoordinator?:string`.
2. Pure builder producing sections per FedRAMP Appendix G Appendix F:
   - §1 Test Overview.
   - §2 Scenarios Executed.
   - §3 Test Results Summary (counts by outcome).
   - §4 Lessons Learned.
   - §5 Recommendations & Action Items.
   - §6 Sign-off (Test Coordinator, IT Director, System Owner, 3PAO Observer; signature lines REQUIRES-OPERATOR-INPUT until signed in-person).
3. When `scenarios` empty: single REQUIRES-OPERATOR-INPUT row "Operator must populate scenarios[] before circulating for signature. AAR template generated <runId>."
4. When any `lessonsLearned[i].severity ∈ {high,critical}`: footer note "file as POA&M via tracker".
5. `emitIscpTestAarDocx(opts):IscpTestAarResult` writes the file + structured log.

## REQUIRES-OPERATOR-INPUT fields
- ISCP: `rto`, `rpo`, `recoveryPriority`, `alternateSite`, `activationAuthority`, `activationCriteria`, `cpCoordinator`, `teamRoster`, `vendorContacts`, `backupStrategySummary` (auto-summarized from RPL evidence when present). Surface preference: `config.yaml:iscp.*`; CLI flags `--iscp-rto-hours`, `--iscp-rpo-hours`, etc.; tracker DB once LOOP-E.E7 lands.
- AAR: every field. `config.yaml:iscp.test.*` once supplied. Until LOOP-E.E7, operator provides via CLI / config.

## Test specifications (ISCP — 13 tests)
1. `it('emits 6 sections + 6 appendices in order')`.
2. `it('auto-fills §4.2 backup-strategy table from RPL-ABO/TRC/RRO/ARP evidence')`.
3. `it('emits REQUIRES-OPERATOR-INPUT when none of the RPL evidence files exist')`.
4. `it('renders RTO/RPO opts verbatim into §4.1')`.
5. `it('renders teamRoster Appendix A')`.
6. `it('auto-pulls vendor contacts from out/subprocessors.json when present')`.
7. `it('handles alternateSite.type="cloud" with cross-region detail')`.
8. `it('cross-references iscp-test-aar.docx in Appendix F')`.
9. `it('rejects unknown impactLevel (must be low|moderate|high)')`.
10. `it('ready_for_signature requires every required-for-signature field')`.
11. `it('produces deterministic output for same inputs')`.
12. `it('quotes NIST SP 800-34 §3.1 verbatim in §1.3')`.
13. `it('logs structured emission event')`.

## Test specifications (AAR — 10 tests)
1. `it('produces 6-section AAR structure')`.
2. `it('scenarios table reflects RTO/RPO target vs actual')`.
3. `it('flags scenarios with outcome=fail in §3 summary')`.
4. `it('lessons-learned of severity=high gets POA&M footer note')`.
5. `it('emits REQUIRES-OPERATOR-INPUT row when scenarios[] empty')`.
6. `it('renders participants verbatim')`.
7. `it('signature block has 4 rows with REQUIRES-OPERATOR-INPUT signature/date cells')`.
8. `it('rejects scenarios with negative RTO actual')`.
9. `it('writes to outPath when supplied')`.
10. `it('deterministic output for same inputs + frozen testDate')`.

## REO compliance specific to this slice
- §4.2 backup-strategy rows trace to real signed evidence files. No "backup is configured" sample row.
- AAR scenarios MUST come from operator input — no fabricated test results.
- Appendix B vendor contacts trace to `subprocessors.json` rows OR emit REQUIRES-OPERATOR-INPUT.
- 7-step quote in §1.3 is verbatim from NIST SP 800-34 R1 §3.1 with URL cited in module-header JSDoc.
- Provenance footer cites: RPL evidence sha256s, subprocessors.json sha256, inventory.json sha256, runId, frmrVersion.

## Verification commands
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/iscp-emit.test.ts tests/core/iscp-test-aar.test.ts
npm run check:reo
npm run check:provenance
```

## Known risks / issues
- **Risk 1 — RPL evidence shape drift.** The RPL-* collectors evolve as cloud providers add features (e.g. AWS Backup Vault Lock); the ISCP reader must tolerate missing / new fields. Mitigation: define `KsiEvidence` interface narrowly (only the fields the emitter consumes), JSON-parse-safe reads, structured log when a field is absent.
- **Risk 2 — Vendor-contact PII leak.** Appendix B pulls real names/emails from `subprocessors.json`. If that file is shared outside the authorization team, PII leaks. Mitigation: per REO + tracker DB AC-3, the .docx is signed and bundled into the tarball that only the authorization team has access to; the orchestrator must NOT log full contact details (only counts).
- **Risk 3 — AAR signature blocks confused as digital signatures.** The §6 sign-off block has signature lines marked REQUIRES-OPERATOR-INPUT; a reader could mistake this for an unsigned section. Mitigation: include an explicit footer note "Wet/electronic signatures captured in tracker — these cells are placeholders pending in-person sign-off."
- **Risk 4 — `testDate` non-determinism.** If `testDate` is undefined, the emitter must NOT inject `new Date()` (REO Rule 1.7 — synthetic emit field without operator opt-in). Mitigation: leave `testDate` as REQUIRES-OPERATOR-INPUT until operator supplies.
- **Risk 5 — Appendix G template revision.** FedRAMP may publish a v3 ISCP template. Mitigation: section-build is data-driven; swapping to a new outline is a single refactor.
- **Risk 6 — RPL-TRC test-evidence age.** If the most recent TRC evidence is >12 months old, the ISCP cites stale data. Mitigation: emit a footer warning when `last_collected_at` is older than 365 days and surface in `requires_operator_input`.

## Open questions (for implementation session to resolve)
- **Q1**: Should the §4.2 evidence table include the RFC 3161 timestamp from each signed envelope? It strengthens the chain-of-custody story but bloats the table.
- **Q2**: When `out/ssp.json` is present, should §2 Concept of Operations pull narrative from `system-characteristics.description`, or treat the ISCP as the canonical narrative? FedRAMP Appendix G implies the ISCP is canonical.
- **Q3**: How should multi-cloud RPL evidence reconcile in §4.2? AWS Backup + GCP Backup-DR + Azure Backup are independent KSIs; the table may have 4 rows × 3 clouds = 12 rows. Group by KSI ID or by cloud?
- **Q4**: Does the AAR need a SHA256 fingerprint of the ISCP it tests against? CP-4 implies the test references the current plan; a fingerprint anchors the AAR to a specific ISCP revision.
- **Q5**: Should `testType` default to `tabletop` when omitted, or REQUIRES-OPERATOR-INPUT? Defaulting may be reasonable since FedRAMP CP-4 allows tabletop for Moderate; but a default risks fabrication.
- **Q6**: Should Appendix C (Detailed Recovery Procedures) link to per-cloud runbooks the CSP maintains in a separate repo? If so, where does the link come from (config.yaml? tracker?)?

## Implementation log (running journal — implementing session updates)
```
| Date       | Session   | Action                                                                                          | Commit   | Notes |
|------------|-----------|-------------------------------------------------------------------------------------------------|----------|-------|
| 2026-07-07 | impl-c-c2 | Shipped both emitters end to end. core/iscp-emit.ts (ISCP, CP-2/CP-9/CP-10, 6 sections + 6      | e660109  | typecheck/test/check:reo all green. cloud-evidence tests 1409→1433 (+24: 14 ISCP + 10 AAR ≥ 23 spec). Both .docx pass `unzip -t`. |
|            |           | appendices) + core/iscp-test-aar.ts (AAR, CP-4, 6 sections). §4.2 auto-fills from real          |          |       |
|            |           | KSI-RPL-*.json; §2.1 + Appendix B compose readInventoryComponents/groupComponents (from         |          |       |
|            |           | cmp-emit.ts) + readSubprocessorContacts. Orchestrator --iscp/--iscp-test-aar + 4 value flags +   |          |       |
|            |           | config.yaml#iscp.*; submission-bundle roles iscp-docx + iscp-test-aar-docx. Deterministic UUIDs; |          |       |
|            |           | testDate defaults to REQUIRES-OPERATOR-INPUT (no new Date()).                                    |          |       |
```

### §12.1 Spec reconciliations (recorded in LOOP-C-RISKS C-C2-7..10)
- **C-C2-7** — RPL evidence file name: the real collector output is `KSI-RPL-*.json`, NOT the §5-listed `.signed.json` (the collector filters `.signed.json` out as a duplicate). `readRplEvidence` reads `KSI-RPL-<id>.json` first, `.signed.json` as a fallback. Fixtures named `.json` to match reality.
- **C-C2-8** — Appendix B source: the real J.J2 output is `subprocessor-inventory.json` (`{rows:[…]}`), NOT the §5-listed `out/subprocessors.json`. `readSubprocessorContacts` reads the real name first, the spec name as a fallback, and tolerates both `{rows:[]}` and bare-array shapes. The SA-9 inventory has no contact/phone, so those cells stay `REQUIRES-OPERATOR-INPUT`.
- **C-C2-9** — envelope shape: the narrow `KsiEvidence` interface consumes the envelope's top-level `collected_at` + `rollup.pass`, NOT the §5-assumed `findings[].metadata.last_collected_at` (no such field in core/envelope.ts).
- **C-C2-10** — the shared `core/docx-primitives.ts` was again NOT extracted (per-slice §7 scope + anti-pattern rule); the two emitters keep local OOXML constants like the five shipped docx emitters. Now 6 emitters to migrate when C-X-1 lands.

### §12.2 Open questions resolved
- **Q1** — No per-row RFC 3161 TST in §4.2 (kept the table compact; chain-of-custody is carried by the per-row SHA-256 evidence citations + the signed bundle INDEX.json).
- **Q2** — The ISCP §2 is the canonical contingency narrative; `readSspDescription` seeds it from `out/ssp.json` `system-characteristics.description` when present (FedRAMP Appendix G implies canonical).
- **Q3** — §4.2 groups by KSI ID (one row per RPL KSI); each envelope already aggregates its providers into one `rollup.pass` + one `collected_at`.
- **Q4** — The AAR anchors to the plan under test by citing the SHA-256 of `out/iscp.docx` when present.
- **Q5** — `testType` defaults to `REQUIRES-OPERATOR-INPUT` (no `tabletop` default — avoids fabrication, REO Rule 1.7).
- **Q6** — Appendix C is framework-only `REQUIRES-OPERATOR-INPUT`; per-cloud runbook linking is deferred (no config surface added this slice).

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by 23 — 13 ISCP + 10 AAR)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (C.C2 row + Overall section)
- [ ] LOOP-C-SPEC.md Section 7 row updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added (one per emitter, or combined)
- [ ] Commit with `LOOP-C.C2:` in the message
- [ ] Commit amended with commit hash recorded in STATUS.md + this file + LOOP-C-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
1. Auto-loaded: `cloud-evidence/CLAUDE.md` (REO standard).
2. This file gives you: source obligations + files to create + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-C-SPEC.md` Section 2 (Dependencies) + Section 6 (Open questions).
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory commit pattern.
5. Read `cloud-evidence/core/roe-emit.ts` (inventory-derived rows + REQUIRES-OPERATOR-INPUT) and `cloud-evidence/core/ssp-docx.ts` (multi-section narrative + OOXML).
6. Read `cloud-evidence/providers/aws/backup.ts` (RPL-ABO/TRC/RRO/ARP source) for the envelope shape `readRplEvidence` consumes.
7. Read FedRAMP SSP Appendix G ISCP Template (URL above) — copy the section ordering exactly.
8. Begin implementation; update Implementation log section as you go.
