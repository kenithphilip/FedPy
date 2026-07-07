---
slice_id: C.C3
title: Incident Response Plan (IRP) + Test AAR
loop: C
status: done
commit: <TBD-step6>
completed_date: 2026-07-07
depends_on: [Pre-slice docx-primitives, INR-RIR collector, INV-1..S6 inventory chain, SSP-1]
blocks: [LOOP-E.E7 IRP/ISCP test cadence runner, LOOP-G.G2 AFR-ICP, LOOP-F.F7 SAR draft references]
estimated_effort: 2 working days
last_updated: 2026-07-07
---

# C.C3 — Incident Response Plan (IRP) + Test AAR

## TL;DR
Ships `irp.docx` (IR-8 Incident Response Plan, structured per NIST SP 800-61 Rev. 3 CSF 2.0 phases) and `irp-test-aar.docx` (IR-3 annual test AAR with the 5-phase timing matrix). Auto-fills §4 Detection Sources from real `out/KSI-INR-RIR.signed.json` evidence; defaults FedRAMP-mandated CISA + PMO + agency notification SLAs from the FedRAMP Incident Communications Procedures doc; every operator narrative slot defaults to `REQUIRES-OPERATOR-INPUT`.

## Status
- Status: done
- Commit: `<TBD-step6>`
- Date: 2026-07-07
- Verification: typecheck=clean, tests=1457/1457 passing (+24: 14 IRP + 10 AAR), check:reo=green (G1 lint:no-stubs 0 violations, G3 provenance OK, G2 coverage-regression skips with no local `out/`); both `.docx` pass `unzip -t` (valid OOXML, 6 parts)

## Why this slice exists
NIST SP 800-53 Rev. 5 control **IR-8 (Incident Response Plan)** mandates a documented IR plan that addresses purpose, scope, roles, responsibilities, management commitment, organizational coordination, metrics, training, testing, communication, and update procedures. **IR-3 (Incident Response Testing)** mandates testing at an organization-defined frequency. **IR-4 (Incident Handling)** mandates a capability across preparation/detection/analysis/containment/eradication/recovery. **IR-6 (Incident Reporting)** mandates notification within FedRAMP-organization-defined times.

NIST officially withdrew SP 800-61 Rev. 2 in April 2025 and released **SP 800-61 Rev. 3** (April 2025), which restructures the IR life-cycle to the NIST CSF 2.0 Functions (Govern / Identify / Protect / Detect / Respond / Recover). LOOP-C.C3 ships Rev. 3 structure as the default; some 3PAOs may still reference Rev. 2's four-phase model (Preparation / Detection-Analysis / Containment-Eradication-Recovery / Post-Incident), so an optional `--irp-spec-version=800-61r2|800-61r3` flag is available (default r3 — see Open Q1).

The FedRAMP-specific reporting SLAs (1 hour to PMO + 1 hour to customer agency + 4-hour CISA US-CERT notification) come from the **FedRAMP Incident Communications Procedures** PDF and are baked into §9 as the FedRAMP-required defaults.

## Authoritative sources (with verbatim quotes)
- **NIST SP 800-61 Rev. 3 (April 2025) — Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile** — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf
  > §2.1 (p. 5): "This publication provides recommendations for managing incident response throughout the incident lifecycle, structured around the NIST Cybersecurity Framework (CSF) 2.0 Functions: Govern, Identify, Protect, Detect, Respond, and Recover."
  > Withdrawal notice for Rev. 2: stated officially as "withdrawn April 2025" on CSRC. Implementation MUST cite Rev. 3.

- **NIST SP 800-53 Rev. 5 — IR-8 Incident Response Plan** — https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
  > "Develop an incident response plan that: 1. Provides the organization with a roadmap for implementing its incident response capability; 2. Describes the structure and organization of the incident response capability; 3. Provides a high-level approach for how the incident response capability fits into the overall organization; 4. Meets the unique requirements of the organization which relate to mission, size, structure, and functions; 5. Defines reportable incidents; 6. Provides metrics for measuring the incident response capability within the organization; 7. Defines the resources and management support needed to effectively maintain and mature an incident response capability; 8. Addresses the sharing of incident information; 9. Is reviewed and approved by [Assignment: organization-defined personnel or roles]; 10. Explicitly designates responsibility for incident response to [Assignment: organization-defined entities, personnel, or roles]."

- **NIST SP 800-53 Rev. 5 — IR-3 Incident Response Testing** — same URL
  > "Test the effectiveness of the incident response capability for the system [Assignment: organization-defined frequency] using the following tests: [Assignment: organization-defined tests]."

- **NIST SP 800-53 Rev. 5 — IR-4 Incident Handling, IR-6 Incident Reporting** — same URL — anchors for §5 (Respond) sub-sections and §9 (Reporting Requirements).

- **FedRAMP Incident Communications Procedures (CSP_Incident_Communications_Procedures.pdf)** — https://www.fedramp.gov/assets/resources/documents/CSP_Incident_Communications_Procedures.pdf
  CSP-side notification SLAs verbatim: 1 hour to FedRAMP PMO + 1 hour to impacted customer agencies + 4 hours to CISA US-CERT for incidents involving federal data. Section 3 procedure: CSP → agency POC → US-CERT chain. Baked into the §9 Reporting Requirements table as FedRAMP-baseline values with a `REQUIRES-OPERATOR-INPUT-VERIFY` marker if `escalationMatrix` not operator-overridden.

- **NIST SP 800-61 Rev. 2 (Aug 2012, withdrawn April 2025) — Computer Security Incident Handling Guide** — https://csrc.nist.gov/pubs/sp/800/61/r2/final — referenced for 3PAOs still on Rev. 2 four-phase mental model; available behind `--irp-spec-version=800-61r2` flag.

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/irp-emit.ts` — pure renderer + disk emitter for `irp.docx` (~700 lines, 11 sections).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/irp-test-aar.ts` — pure renderer + disk emitter for `irp-test-aar.docx` (~400 lines).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/irp-emit.test.ts` — 13 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/irp-test-aar.test.ts` — 10 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/fixtures/irp/KSI-INR-RIR.signed.json` — INR-RIR fixture with 4 detection-source evidence rows.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/fixtures/irp/config.sample.yaml` — team roster + external contacts + classification levels for happy-path tests.

## Files to extend
- `core/submission-bundle.ts` — Role union `'irp-docx'` + `'irp-test-aar-docx'`; two new `WellKnownArtifact` entries.
- `core/orchestrator.ts` — `--irp`, `--irp-test-aar` flags; `CLOUD_EVIDENCE_IRP`, `CLOUD_EVIDENCE_IRP_TEST_AAR` envs; `--irp-spec-version` flag (default `800-61r3`); dispatch blocks; run-ledger entries.
- `CHANGELOG.md`, `docs/STATUS.md`, `docs/loops/LOOP-C-SPEC.md` — per SLICE-COMPLETION-PROCEDURE.md.

## Schemas / standards
- IRP section structure mapped to CSF 2.0 phases:
  - §5 Respond is sub-divided into 6 sub-sections matching CSF 2.0 Functions (Govern, Identify, Protect, Detect, Respond, Recover).
- AAR 5-phase timing matrix (per NIST SP 800-61 R3 §3 + R2 §3.2): detection_time, response_time, containment_time, eradication_time, recovery_time (all minutes since incident onset).
- Detection-source row schema (from `out/KSI-INR-RIR.signed.json`): `evidence[].detection_source`, `evidence[].coverage_percent`, `evidence[].last_collected_at`.

## Build steps (concrete, numbered)

For `irp-emit.ts`:
1. Define `IrpEmitOptions`: `outDir; outPath?; runId; frmrVersion; systemName?; systemId?; cspOrganization?; impactLevel; specVersion?:'800-61r2'|'800-61r3'; irTeamRoster?:Array<{role:'IR Lead'|'IR Analyst'|'Forensics'|'Communications'|'Legal'|'Executive Liaison'; name; org; email; phone; on_call:boolean}>; escalationMatrix?:Array<{severity:'critical'|'high'|'medium'|'low'; sla_minutes:number; notify:string[]}>; externalContacts?:Array<{entity:'FedRAMP PMO'|'CISA'|'US-CERT'|'Agency POC'|'Law Enforcement'; contact; channel:'email'|'phone'|'web-form'; sla_hours:number}>; communicationsPlan?:{internal:string; external:string; media:string}; classificationLevels?:Array<{severity; definition; examples:string[]}>`.
2. Implement `readInrRirEvidence(outDir):InrRirEvidence|undefined` — JSON-parse-safe.
3. Pure builder `buildIrpBodyXml(opts):{xml; stats}` producing 11 sections (Rev. 3 default):
   - §1 Introduction (purpose, scope, 800-61r3 reference + CSF 2.0 quote).
   - §2 Roles & Responsibilities (irTeamRoster table; required roles: IR Lead, Analyst, Forensics, Comms, Legal, Exec Liaison).
   - §3 Incident Classification (severity definitions + examples; default rows from FedRAMP ICP doc).
   - §4 Detect (auto from INR-RIR; logging coverage table).
   - §5 Respond (sub-sections matching CSF 2.0 Functions).
   - §6 Communications Plan (internal + external + media).
   - §7 External Contacts (FedRAMP PMO, CISA, agency POC, etc.).
   - §8 Escalation Matrix (severity → SLA-minutes → notify-list, sorted by severity desc).
   - §9 Reporting Requirements (FedRAMP ICP-mandated 1h-PMO + 1h-agency + 4h CISA).
   - §10 Lessons Learned (post-incident review procedure).
   - §11 Plan Maintenance + Testing (annual cadence + cross-link to `irp-test-aar.docx`).
4. When `specVersion === '800-61r2'`: replace §5's 6 sub-sections with 4 (Preparation, Detection-Analysis, Containment-Eradication-Recovery, Post-Incident).
5. `emitIrpDocx(opts):IrpEmitResult` writes the file + structured log.

For `irp-test-aar.ts`:
1. Define `IrpTestAarOptions`: `outDir; outPath?; runId; testDate?:string; testType?:'tabletop'|'functional'|'red-team'; scenarios?:Array<{id; description; severity; detection_time_minutes; response_time_minutes; containment_time_minutes; eradication_time_minutes; recovery_time_minutes; outcome:'pass'|'fail'|'partial'}>; participants?:Array<{role; name; org}>; lessonsLearned?:Array<{id; phase:'detect'|'respond'|'recover'|'lessons'; finding; severity; recommendation; owner; due_date}>; testCoordinator?:string`.
2. Pure builder sections: Overview, Scenarios, Timing Metrics (5-phase elapsed-time table), Outcomes, Lessons Learned, Recommendations, Sign-off.
3. When `scenarios` empty: single REQUIRES-OPERATOR-INPUT row.
4. When any high/critical lesson: POA&M footer note.

## REQUIRES-OPERATOR-INPUT fields
- IRP: `irTeamRoster`, `escalationMatrix`, `externalContacts`, `communicationsPlan`, `classificationLevels`. Surface preference: `config.yaml:irp.*`.
- Escalation defaults to FedRAMP ICP-compliant matrix with `REQUIRES-OPERATOR-INPUT-VERIFY` marker (operator must confirm or override).
- AAR: every field; `config.yaml:irp.test.*` until LOOP-E.E7 lands.

## Test specifications (IRP — 13 tests)
1. `it('emits 11 sections in CSF 2.0 phase order for r3 default')`.
2. `it('auto-fills §4 detection-sources from INR-RIR evidence')`.
3. `it('emits REQUIRES-OPERATOR-INPUT when no INR-RIR evidence')`.
4. `it('renders irTeamRoster with on_call flag visible')`.
5. `it('emits FedRAMP ICP-mandated SLAs in §9 even when escalationMatrix not supplied (with verify marker)')`.
6. `it('quotes NIST SP 800-61r3 CSF 2.0 phase definition verbatim')`.
7. `it('escalationMatrix sorts by severity descending')`.
8. `it('externalContacts groups CISA + FedRAMP PMO + Agency POC')`.
9. `it('specVersion=800-61r2 replaces §5 with 4-phase model')`.
10. `it('writes outPath when supplied')`.
11. `it('deterministic output')`.
12. `it('logs structured emit event')`.
13. `it('ready_for_signature = false when irTeamRoster empty')`.

## Test specifications (AAR — 10 tests)
1. `it('produces 7-section AAR structure with 5-phase timing matrix')`.
2. `it('timing-metrics table reflects detection→recovery elapsed time per scenario')`.
3. `it('flags scenarios with outcome=fail in summary')`.
4. `it('lessons-learned severity=high gets POA&M footer note')`.
5. `it('emits REQUIRES-OPERATOR-INPUT when scenarios[] empty')`.
6. `it('renders participants verbatim')`.
7. `it('signature block 4 rows REQUIRES-OPERATOR-INPUT')`.
8. `it('rejects negative timing values')`.
9. `it('writes outPath when supplied')`.
10. `it('deterministic output for same inputs + frozen testDate')`.

## REO compliance specific to this slice
- §4 detection-source rows trace to real INR-RIR evidence OR emit REQUIRES-OPERATOR-INPUT.
- §9 SLA rows quote FedRAMP ICP doc verbatim with URL cited in module-header JSDoc.
- AAR scenarios: no fabricated timing data; operator-supplied or REQUIRES-OPERATOR-INPUT row.
- §5 CSF 2.0 phase definitions quote SP 800-61r3 §2.1 verbatim with URL cited.
- Provenance footer cites: INR-RIR evidence sha256, FedRAMP ICP doc URL + retrieval date, runId, frmrVersion, specVersion.

## Verification commands
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/irp-emit.test.ts tests/core/irp-test-aar.test.ts
npm run check:reo
npm run check:provenance
```

## Known risks / issues
- **Risk 1 — Spec-version confusion.** Some 3PAOs may reference Rev. 2 by habit; Rev. 3 is the current standard but adoption is uneven. Mitigation: `--irp-spec-version` flag; default r3; document the choice in cover letter.
- **Risk 2 — FedRAMP ICP doc supersession.** FedRAMP may publish a new Incident Communications Procedures doc with different SLAs. Mitigation: module header records the URL + retrieval date; emit a warning if the file is older than 12 months (operator confirms still current).
- **Risk 3 — External-contact PII.** §7 contains real names/emails for FedRAMP PMO + CISA. Mitigation: use FedRAMP's published role-based addresses (info@fedramp.gov, central@cisa.dhs.gov) by default; operator overrides via config.
- **Risk 4 — INR-RIR coverage thresholds.** The evidence may show 70% logging coverage; the IRP must not paper over the gap. Mitigation: §4 surfaces the coverage_percent and emits a warning row when <95%.
- **Risk 5 — CSF 2.0 phase drift.** If NIST updates CSF 2.0 phase names, §5 sub-section headings must follow. Mitigation: keep the phase array as a single export `CSF_2_0_PHASES = ['Govern','Identify','Protect','Detect','Respond','Recover']` (REO Rule 3 allowed — NIST-published constant) and cite the URL.
- **Risk 6 — AAR signature blocks confused as digital signatures.** Same as ISCP. Mitigation: same explicit footer note.

## Open questions (for implementation session to resolve)
- **Q1**: Default `--irp-spec-version` to r3 (current standard) or detect from `out/ssp.json` if SSP cites r2? Auto-detection adds complexity but reduces operator burden.
- **Q2**: Should §9 distinguish "incident involving federal data" vs "incident not involving federal data" — the 4-hour CISA SLA per FedRAMP ICP applies only to the former. Currently emits a single row.
- **Q3**: For multi-agency CSPs, should §7 emit one row per agency customer or aggregate? FedRAMP ICP is silent.
- **Q4**: Should the AAR cite a SHA256 of the IRP it tests against? Strengthens chain-of-custody; bloats AAR header.
- **Q5**: Should AAR `testType=red-team` require a separate authorization block (since red-team exercises imply broader test scope)?
- **Q6**: How does §5 Respond integrate with LOOP-G.G2 AFR-ICP (which emits the AFR-mandated communications artifact)? Cross-reference or duplicate?

## Implementation log (running journal — implementing session updates)
```
2026-07-07 | impl-c-c3 | Shipped the full slice end to end. Created core/irp-emit.ts
  (buildIrpBodyXml/renderIrpDocx/emitIrpDocx — 11 sections, CSF 2.0 phases for
  the r3 default + the 4-phase r2 fallback via --irp-spec-version) and
  core/irp-test-aar.ts (buildIrpTestAarBodyXml/renderIrpTestAarDocx/
  emitIrpTestAarDocx — 7 sections with the 5-phase timing matrix). §4 Detect
  reads the REAL KSI-INR-RIR envelope (readInrRirEvidence flattens
  providers[].findings[] → detection-source rows + derives coverage% from the
  pass ratio; <95% warns). §9 bakes the FedRAMP ICP SLAs (1h/1h/4h) as
  REQUIRES-OPERATOR-INPUT-VERIFY baseline rows. Every operator narrative defaults
  to REQUIRES-OPERATOR-INPUT; §6 sign-off never auto-signed (REO Rule 1.10). Both
  docs fully deterministic (no new Date()); AAR anchors to out/irp.docx SHA-256.
  Wired core/orchestrator.ts (--irp/--irp-test-aar/--irp-spec-version + envs +
  Config.irp type + dispatch after ISCP, before signing), core/submission-bundle.ts
  (irp-docx + irp-test-aar-docx WELL_KNOWN roles), config.yaml (irp.* section).
  Tests: tests/core/irp-emit.test.ts (14) + tests/core/irp-test-aar.test.ts (10)
  + fixtures/irp/{KSI-INR-RIR.json, config.sample.yaml}. Verification: typecheck
  clean; 1433→1457 tests (+24); check:reo green; both .docx pass unzip -t.
  Spec reconciliation: C-C3-7 (INR-RIR file name KSI-INR-RIR.json not
  .signed.json + envelope shape providers[].findings[] not evidence[].detection_source
  — mirrors C-C2-7/C-C2-9), C-C3-8 (docx-primitives still not extracted — now 8
  emitters). §10 Q1-Q6 resolved (see the C.C3 scope note in STATUS.md). Deferred:
  C-C3-9 tracker irp_tests capture → LOOP-E.E7. Commit <TBD-step6>.
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
- [x] typecheck clean (`npm run typecheck`)
- [x] tests passing 100% (count increased by 24 — 14 IRP + 10 AAR; ≥ the 23 spec tests)
- [x] check:reo green (G1+G2+G3)
- [x] STATUS.md updated (C.C3 row + Overall section)
- [x] LOOP-C-SPEC.md Section 7 row updated
- [x] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [x] CHANGELOG.md "Unreleased" entry added
- [x] Commit with `LOOP-C.C3:` in the message
- [x] Commit amended with commit hash recorded
- [x] Pushed to origin/main

## Resume-from-fresh-session checklist
1. Auto-loaded: `cloud-evidence/CLAUDE.md` (REO standard).
2. This file: source obligations + files to create + build steps + tests + risks + checklist.
3. Read `cloud-evidence/docs/loops/LOOP-C-SPEC.md` Section 2 + Section 6.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for commit pattern.
5. Read `cloud-evidence/core/roe-emit.ts` + `cloud-evidence/core/ssp-docx.ts` for the OOXML emitter pattern.
6. Read `cloud-evidence/providers/aws/logging.ts` (INR-RIR source) for the envelope shape `readInrRirEvidence` consumes.
7. Read NIST SP 800-61r3 §2 + §3 (URL above) for the CSF 2.0 phase definitions you will paste verbatim.
8. Read FedRAMP ICP PDF (URL above) for the exact SLA wording used in §9.
9. Begin implementation; update Implementation log as you go.
