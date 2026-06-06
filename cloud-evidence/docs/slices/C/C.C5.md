---
slice_id: C.C5
title: FIPS 199 categorization worksheet
loop: C
status: pending
commit: —
completed_date: —
depends_on: [Pre-slice docx-primitives, SSP-1 oscal-ssp.ts]
blocks: [C.C8 cover letter cross-link, LOOP-F.F7 SAR reference]
estimated_effort: 1.5 working days
last_updated: 2026-06-07
---

# C.C5 — FIPS 199 categorization worksheet

## TL;DR
Ships `fips199.docx` — the canonical CIA-impact-level categorization worksheet (RA-2). Computes the system-level Security Category as the high-water-mark across operator-supplied Information Types (drawn from NIST SP 800-60 Vol 2 Rev 1 catalogue). Cross-checks the result against `out/ssp.json`'s `system-characteristics.security-impact-level` field and emits CONSISTENT or MISMATCH. Every impact-level definition in §1.2 is quoted verbatim from FIPS 199 §3.

## Status
- Status: pending
- Commit: —
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
NIST SP 800-53 Rev. 5 control **RA-2 (Security Categorization)** mandates the system owner categorize the information system per FIPS 199 + SP 800-60. The categorization drives baseline selection per FIPS 200 (and therefore the entire control catalogue applied). The SSP carries the *result* in `system-characteristics.security-impact-level`; FIPS 199 is the *worksheet* that shows the work. 3PAOs cross-check the worksheet against the SSP value during the RA-2 assessment.

## Authoritative sources (with verbatim quotes)
- **FIPS PUB 199 (2004-02) — Standards for Security Categorization of Federal Information and Information Systems** — https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.199.pdf
  > §3 (p. 2 — loss definitions): "A loss of confidentiality is the unauthorized disclosure of information. A loss of integrity is the unauthorized modification or destruction of information. A loss of availability is the disruption of access to or use of information or an information system."
  > §3 (p. 2 — LOW): "The loss of confidentiality, integrity, or availability could be expected to have a limited adverse effect on organizational operations, organizational assets, or individuals."
  > §3 (p. 2 — MODERATE): "The loss of confidentiality, integrity, or availability could be expected to have a serious adverse effect on organizational operations, organizational assets, or individuals."
  > §3 (p. 2 — HIGH): "The loss of confidentiality, integrity, or availability could be expected to have a severe or catastrophic adverse effect on organizational operations, organizational assets, or individuals."
  > §3 (p. 3 — SC formula): `SC information_type = {(confidentiality, impact), (integrity, impact), (availability, impact)}` where `impact` ∈ {LOW, MODERATE, HIGH, NOT APPLICABLE} (NOT APPLICABLE permitted only for confidentiality).
  > §3 (p. 3 — system-level SC): "The generally accepted practice is to use the 'high water mark' over the security impact levels for confidentiality, integrity, and availability assigned to the information types."

- **FIPS PUB 200 (2006-03) — Minimum Security Requirements for Federal Information and Information Systems** — https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.200.pdf — bridge from FIPS 199 to SP 800-53 baseline; cited in §4 cover.

- **NIST SP 800-60 Vol. 1 Rev. 1 (Aug 2008) — Guide for Mapping Types of Information and Information Systems to Security Categories** — https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-60v1r1.pdf
  > §3.1: identification process for information types — quoted in §2 Methodology.

- **NIST SP 800-60 Vol. 2 Rev. 1 (Aug 2008) — Appendix C + Appendix D — Information Type catalogue** — https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-60v2r1.pdf — source for `core/fips199-types.ts` codes. (NIST SP 800-60 Rev. 2 IWD as of January 2024; not yet final.)

- **FedRAMP SSP Attachment 10 — FIPS 199 Categorization Template (Rev4)** — https://www.fedramp.gov/resources/documents/rev4/REV_4_SSP-A10-FedRAMP-FIPS-199-Categorization-Template.docx — section ordering source: Title page → Information Types table → Overall System SC → Rationale → Signature.

- **NIST SP 800-53 Rev. 5 — RA-2 Security Categorization** — https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
  > "a. Categorize the system and information it processes, stores, and transmits; b. Document the security categorization results, including supporting rationale, in the security plan for the system; c. Verify that the authorizing official or authorizing official designated representative reviews and approves the security categorization decision."

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/fips199-emit.ts` — pure renderer + disk emitter for `fips199.docx` (~500 lines).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/fips199-types.ts` — typed constants: SP 800-60 V2 Rev. 1 SaaS-relevant information-type catalog (D.1.x Information Dissemination, D.2.x System Development, D.3.x General Government, D.4.x Information Sharing, C.2.x Service Delivery Support). Per REO Rule 3 (allowed exceptions): NIST-published codes + names are fixed data; module header explicitly cites SP 800-60 V2 §C and §D and exports `SOURCE_VERSION='SP 800-60 V2 Rev. 1'`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/fips199-emit.test.ts` — 12 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/fips199-types.test.ts` — small sanity tests (codes well-formed, distinct).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/fixtures/fips199/info-types.sample.yaml` — operator-supplied info types for happy-path test.

## Files to extend
- `core/submission-bundle.ts` — Role `'fips199-docx'`; `WellKnownArtifact` entry.
- `core/orchestrator.ts` — `--fips199` flag + `CLOUD_EVIDENCE_FIPS199` env; `--fips199-info-type` repeat flag (colon-separated `code:name:c:i:a:rationale`); dispatch block.
- `CHANGELOG.md`, `docs/STATUS.md`, `docs/loops/LOOP-C-SPEC.md` — per SLICE-COMPLETION-PROCEDURE.md.

## Schemas / standards
- Information type tuple: `{code:string; name:string; confidentiality:'low'|'moderate'|'high'|'n/a'; integrity:'low'|'moderate'|'high'; availability:'low'|'moderate'|'high'; rationale:string}`. `n/a` only valid for confidentiality (per FIPS 199 §3).
- Overall SC = high-water-mark per dimension across info types.
- SSP cross-reference: read `out/ssp.json` `system-characteristics.security-impact-level` ∈ {'fips-199-low','fips-199-moderate','fips-199-high'} (OSCAL enumeration) and map to LOW/MODERATE/HIGH.

## Build steps (concrete, numbered)
1. Define `Fips199EmitOptions`: `outDir; outPath?; runId; frmrVersion; systemName?; systemId?; cspOrganization?; informationTypes?:InformationType[]; overallConfidentialityRationale?; overallIntegrityRationale?; overallAvailabilityRationale?; categorizationApprover?:{name; role; org; date}`.
2. Pure helper `computeOverallSC(types:InformationType[]):{c:Impact; i:Impact; a:Impact}` — high-water-mark per FIPS 199 §3. Exported for unit testing.
3. Pure builder `buildFips199BodyXml(opts):{xml; stats}` producing:
   - Title page (system identity + FIPS 199 reference).
   - §1 Introduction (1.1 Purpose; 1.2 Impact-Level Definitions — verbatim quotes from FIPS 199 §3).
   - §2 Methodology (SP 800-60 V1 §3.1 cite).
   - §3 Information Types Identified (one row per `informationType`).
   - §4 System Security Categorization (overall SC formula display).
   - §5 Categorization Rationale (operator per-objective rationale).
   - §6 Approval Signatures (Categorization Approver + System Owner).
4. SSP cross-reference: if `out/ssp.json` exists, read `security-impact-level`; §4.1 sanity-check note "SSP claims `<level>`; worksheet computes `<level>`; CONSISTENT/MISMATCH". If SSP absent, §4.1 emits "SSP unavailable for cross-reference — operator must verify manually."
5. Fallback: `informationTypes` empty → single REQUIRES-OPERATOR-INPUT row with the SP 800-60 V2 selection guidance quoted verbatim.
6. `emitFips199Docx(opts):Fips199EmitResult` writes the file + structured log.

## REQUIRES-OPERATOR-INPUT fields
- `informationTypes[]` — `config.yaml:fips199.information_types[]` or repeat flag `--fips199-info-type`. Each entry must reference a code in `fips199-types.ts` (else emit `UNKNOWN-TYPE-CODE` warning).
- `overallConfidentialityRationale`, `overallIntegrityRationale`, `overallAvailabilityRationale` — `config.yaml:fips199.{c,i,a}_rationale`.
- `categorizationApprover` — `config.yaml:fips199.approver`.

## Test specifications (12 tests)
1. `it('emits 6 sections in order with FIPS 199 §3 verbatim quotes')`.
2. `it('computeOverallSC takes the high-water-mark across all info types')`.
3. `it('computeOverallSC handles c=n/a per FIPS 199 (only for confidentiality)')`.
4. `it('SC formula displays as {(confidentiality, MODERATE), (integrity, LOW), (availability, LOW)} when computed')`.
5. `it('emits REQUIRES-OPERATOR-INPUT row + SP 800-60 V2 selection note when no information types supplied')`.
6. `it('flags MISMATCH when SSP security-impact-level disagrees with worksheet overall SC')`.
7. `it('flags CONSISTENT when SSP matches')`.
8. `it('rejects information type with C+I+A all "n/a" (invalid per FIPS 199)')`.
9. `it('rejects unknown impact level value')`.
10. `it('writes to outPath when supplied')`.
11. `it('deterministic output')`.
12. `it('ready_for_signature requires ≥1 info type + 3 rationales + approver')`.

## REO compliance specific to this slice
- SC overall computation traces to real `computeOverallSC()` invocation over operator-supplied types — NO hardcoded "moderate/moderate/moderate" default.
- SSP cross-reference cites real `ssp.json` sha256 + path in document footer.
- Impact-level definition quotes are verbatim from FIPS 199 §3 — cite URL + page in module-header JSDoc.
- SP 800-60 V2 codes in `fips199-types.ts` are NIST-published constants per REO Rule 3 (allowed exception); module header declares `SOURCE_VERSION` for later bump traceability.
- Provenance footer: `core/fips199-emit.ts` path, ssp.json sha256, fips199-types.ts source version, runId, frmrVersion.

## Verification commands
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/fips199-emit.test.ts tests/core/fips199-types.test.ts
npm run check:reo
npm run check:provenance
```

## Known risks / issues
- **Risk 1 — SP 800-60 Rev. 2 release.** Rev. 2 IWD as of Jan 2024; when finalized, `fips199-types.ts` catalog must be re-extracted. Mitigation: `SOURCE_VERSION` constant in module header documents the version; a follow-up slice re-extracts; the script lives under `scripts/extract-*.mjs` (allowed per REO Rule 1 exception).
- **Risk 2 — Unknown info-type code passed in config.** Operator passes a code not in `fips199-types.ts`. Mitigation: emit `UNKNOWN-TYPE-CODE` warning log + render the row with the warning marker.
- **Risk 3 — SSP MISMATCH false positives.** SSP may carry the FedRAMP impact-level enum (low/moderate/high) but the worksheet computes via high-water-mark which can disagree if operator under-categorized info types. Mitigation: §4.1 surfaces both values + the cause of mismatch + remediation guidance.
- **Risk 4 — c=n/a edge case.** FIPS 199 permits c=n/a (publicly accessible data) but the SC formula must still produce a valid system-level overall. Mitigation: `computeOverallSC` treats `n/a` as no-contribution to high-water-mark for confidentiality.
- **Risk 5 — Operator under-categorization.** Operator passes 1 info type with c=low when 3 are actually processed at moderate. Mitigation: the worksheet cannot detect this; document in §2 Methodology that operator is responsible for completeness.
- **Risk 6 — Approver signature freshness.** `categorizationApprover.date` may be stale across multiple emits. Mitigation: §6 displays the date verbatim; operator must update on each re-emission.

## Open questions (for implementation session to resolve)
- **Q1**: Should §3 enforce a minimum number of info types (≥1)? FIPS 199 implies ≥1; the test rejects 0 today.
- **Q2**: Should `--fips199-info-type` accept JSON encoding instead of colon-separated for safer rationale text containing colons?
- **Q3**: When `informationTypes[]` includes types outside the SaaS-relevant subset in `fips199-types.ts`, should the catalog accept arbitrary codes (with a warning) or reject? Today: warn + accept.
- **Q4**: Should §4 also render the FIPS 199 baseline selection (low → 800-53 R5 LOW baseline, etc.) or leave that to the SSP? The SSP carries the baseline.
- **Q5**: Does the FedRAMP 20x Phase 2 categorization process introduce additional steps beyond FIPS 199? RFC-0026 + related are silent so far.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by 12 + small fips199-types sanity tests)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (C.C5 row + Overall section)
- [ ] LOOP-C-SPEC.md Section 7 row updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added
- [ ] Commit with `LOOP-C.C5:` in the message
- [ ] Commit amended with commit hash recorded
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
1. Auto-loaded: `cloud-evidence/CLAUDE.md`.
2. This file gives source obligations + files + build steps + tests + risks + checklist.
3. Read `cloud-evidence/docs/loops/LOOP-C-SPEC.md` Section 2 + Section 6 (open Q2 about SP 800-60 Rev. 2).
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for commit pattern.
5. Read `cloud-evidence/core/roe-emit.ts` + `cloud-evidence/core/ssp-docx.ts` for emitter pattern.
6. Read `cloud-evidence/core/oscal-ssp.ts` for the `security-impact-level` field shape the cross-reference reads.
7. Read FIPS 199 PDF (URL above) — §3 impact definitions verbatim.
8. Read SP 800-60 V2 Rev. 1 Appendix C + D (URL above) — info-type catalog source.
9. Read FedRAMP SSP-A10 Rev4 template (URL above) — section ordering.
10. Begin implementation; update Implementation log as you go.
