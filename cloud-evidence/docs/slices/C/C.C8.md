---
slice_id: C.C8
title: Authorization request cover letter
loop: C
status: pending
commit: —
completed_date: —
depends_on: [Pre-slice docx-primitives, LOOP-A.A4 submission-bundle.ts INDEX.json, LOOP-A.A2 ap.json for 3PAO metadata]
blocks: [LOOP-F.F6 ATO workflow tracker]
estimated_effort: 1 working day
last_updated: 2026-06-07
---

# C.C8 — Authorization request cover letter / package transmittal

## TL;DR
Ships `auth-request-cover-letter.docx` — the CSP-side formal cover letter that accompanies the FedRAMP authorization package transmission. Auto-enumerates package contents from `out/INDEX.json` emitted by LOOP-A.A4 with role + sha256-short + bytes per artifact. Auto-pulls 3PAO identity from `out/ap.json` metadata when present. Distinct from the AO-issued ATO Letter (which the FedRAMP-published ATO Letter Template covers — that's the *response* to this cover letter).

## Status
- Status: pending
- Commit: —
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
NIST SP 800-53 Rev. 5 control **PM-10 (Authorization Process)** mandates a documented process for authorization of system operation, including authorization decisions, accountability, and continuous monitoring. The CSP transmits the authorization package (SSP, AP, AR, POA&M, IIW, RoE, and supporting Word docs) to the FedRAMP PMO (or directly to an agency AO under the Agency Authorization track). The package transmission is accompanied by a formal cover letter — distinct from the AO's ATO letter (which the FedRAMP ATO Letter Template covers as the *response*). C.C8 emits the CSP-side cover letter.

## Authoritative sources (with verbatim quotes)
- **FedRAMP Agency Authorization Playbook v4.1 (2025-11-17)** — https://www.fedramp.gov/resources/documents/Agency_Authorization_Playbook.pdf
  > §3 — formal-request structure (CSP letterhead + AO addressee + requested action + package summary + signatures).

- **FedRAMP ATO Letter Template** — https://www.fedramp.gov/assets/resources/templates/FedRAMP-ATO-Letter-Template.docx — the counterpart document the AO returns to the CSP; §5 of our cover letter references the expected ATO response format.

- **FedRAMP Initial Authorization Package Checklist** — https://www.fedramp.gov/assets/resources/templates/FedRAMP-Initial-Authorization-Package-Checklist.xlsx — enumerates the package contents; the §4 Package Contents table mirrors the checklist plus actual sha256 from `INDEX.json`.

- **NIST SP 800-53 Rev. 5 — PM-10 Authorization Process** — https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
  > "a. Manage the security and privacy state of organizational systems and the environments in which those systems operate through authorization processes; b. Designate individuals to fulfill specific roles and responsibilities within the organizational risk management process; c. Integrate the authorization processes into an organization-wide risk management program."

- **NIST SP 800-37 Rev. 2 §3.6 (Authorize Step)** — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-37r2.pdf — cited in §2.

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/auth-cover-letter-emit.ts` — pure renderer + disk emitter (~500 lines).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/auth-cover-letter-emit.test.ts` — 11 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/fixtures/cover-letter/INDEX.sample.json` — fixture index with 12 artifacts (mirroring a full submission bundle).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/fixtures/cover-letter/ap.sample.json` — fixture AP with 3PAO metadata.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/fixtures/cover-letter/config.sample.yaml` — operator config.

## Files to extend
- `core/submission-bundle.ts` — Role `'auth-cover-letter-docx'`; `WellKnownArtifact` entry. CRITICAL ORDERING: the cover letter is emitted AFTER `INDEX.json` is built but BEFORE the bundler tarballs the package. The orchestrator dispatch order must be `INDEX-build → cover-letter-emit → bundle-pack`.
- `core/orchestrator.ts` — `--auth-cover-letter` flag + env; dispatch block placed AFTER `--bundle` index build but BEFORE bundle tar; `--auth-request-type` flag (initial-ato | continued-ato | reauthorization).
- `CHANGELOG.md`, `docs/STATUS.md`, `docs/loops/LOOP-C-SPEC.md` — per SLICE-COMPLETION-PROCEDURE.md.

## Schemas / standards
- INDEX.json shape (from LOOP-A.A4): `{artifacts:Array<{role:string; filename:string; sha256:string; bytes:number; description?:string}>; emitted_at:string; runId:string}`.
- AP metadata shape (from LOOP-A.A2): `{metadata:{title; ...; parties:[{name; org; role:'third-party-assessor-organization'|'third-party-assessor-lead'|'system-owner'|...}]}}`.
- Cover-letter section structure (per FedRAMP Agency Authorization Playbook §3): Letterhead → Date → Addressee → §1 Subject → §2 Request Summary → §3 3PAO Statement → §4 Package Contents → §5 Requested Action → §6 Primary Contacts → §7 Closing + Signature.

## Build steps (concrete, numbered)
1. Define `AuthCoverLetterOptions`: `outDir; outPath?; runId; frmrVersion; systemName?; systemId?; cspOrganization?; cspAddress?:string; cspExecutiveSignatory?:{name; title; email; phone}; thirdPartyAssessor?:string; thirdPartyAssessorLead?:{name; title; email}; aoAddressee?:{name; title; agency; address}; requestedAtoType?:'initial-ato'|'continued-ato'|'reauthorization'; impactLevel; submissionDate?:string`.
2. Implement `readIndexJson(outDir):IndexArtifact[]|undefined` — JSON-parse-safe.
3. Implement `readApMetadata(outDir):{parties?, dates?}|undefined` — JSON-parse-safe.
4. Pure builder `buildCoverLetterBodyXml(opts):{xml; stats}` producing:
   - Letterhead block (CSP org + address).
   - Date line (`submissionDate` or `runId`-derived ISO date).
   - Addressee block (AO name + agency + address; REQUIRES-OPERATOR-INPUT when absent).
   - §1 Subject Line ("FedRAMP `<impactLevel>` Authorization Request — `<systemName>`").
   - §2 Request Summary (`requestedAtoType` + system identity + impact level).
   - §3 3PAO Statement (named 3PAO + lead assessor + assessment-date summary from `ap.json`).
   - §4 Package Contents (auto-table from INDEX.json: artifact filename + role + sha256-short (first 12 chars) + bytes).
   - §5 Requested Action ("We respectfully request your authorization decision within FedRAMP-baseline review timeline; see FedRAMP Agency Authorization Playbook §X for response timing").
   - §6 Primary Contacts (CSP exec signatory + technical lead + 3PAO).
   - §7 Closing + Signature (CSP exec signatory signature line).
5. `emitAuthCoverLetterDocx(opts):AuthCoverLetterResult` writes file + structured log.

## REQUIRES-OPERATOR-INPUT fields
- `cspExecutiveSignatory` — `config.yaml:auth_request.executive_signatory`.
- `cspAddress` — `config.yaml:org.address`.
- `aoAddressee` — `config.yaml:auth_request.ao_addressee` (per-target agency).
- `thirdPartyAssessor`, `thirdPartyAssessorLead` — `config.yaml:auth_request.tpa`; also reuses `--third-party-assessor` flag from LOOP-A.A2.
- `requestedAtoType` — `--auth-request-type initial-ato` (default).

## Test specifications (11 tests)
1. `it('emits 7 sections + letterhead + addressee')`.
2. `it('§4 Package Contents reflects INDEX.json artifacts')`.
3. `it('§4 REQUIRES-OPERATOR-INPUT with note when INDEX.json absent')`.
4. `it('§3 3PAO statement reads from out/ap.json metadata when present')`.
5. `it('§2 requestedAtoType reflects opts')`.
6. `it('addressee REQUIRES-OPERATOR-INPUT when aoAddressee omitted')`.
7. `it('cspExecutiveSignatory REQUIRES-OPERATOR-INPUT when omitted')`.
8. `it('subject line includes systemName + impactLevel')`.
9. `it('writes to outPath when supplied')`.
10. `it('deterministic output for same INDEX.json + opts')`.
11. `it('ready_for_signature requires signatory + addressee + tpa + atoType')`.

## REO compliance specific to this slice
- §4 Package Contents traces to real `INDEX.json` rows. NO synthetic artifacts.
- Sha256-short values are real (first 12 hex chars of full sha256).
- 3PAO statement traces to `ap.json` metadata when present.
- §5 Requested Action language is templated but contains no fabricated commitments from the AO side.
- Provenance footer cites: INDEX.json sha256, ap.json sha256 (if present), runId, frmrVersion, emitter module path.

## Verification commands
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/auth-cover-letter-emit.test.ts
npm run check:reo
npm run check:provenance
```

## Known risks / issues
- **Risk 1 — Orchestrator dispatch order.** Cover letter must run AFTER INDEX.json is built but BEFORE the tar is packed (so it's in the tarball). Mitigation: explicit ordering enforcement in orchestrator + integration test asserting the cover letter is in the tarball.
- **Risk 2 — INDEX.json shape drift.** LOOP-A.A4 may add fields. Mitigation: define a narrow `IndexArtifact` interface that only consumes the fields the emitter needs; tolerate additional fields.
- **Risk 3 — AP metadata absent.** If LOOP-A.A2 not run, `ap.json` missing → §3 3PAO Statement degrades. Mitigation: fall back to operator-supplied `thirdPartyAssessor` + `thirdPartyAssessorLead`; emit REQUIRES-OPERATOR-INPUT only if both sources absent.
- **Risk 4 — `submissionDate` non-determinism.** If undefined, falls back to runId-derived ISO date (deterministic). Document this behavior in §1 footer.
- **Risk 5 — AO addressee may be a delegated authorizing-official designate.** §3 must accommodate dual signatures. Mitigation: `aoAddressee` supports an optional `designee` field.
- **Risk 6 — Cover letter signed twice (Ed25519 + wet/electronic exec signature).** The .docx is digitally signed by the pipeline; the exec signature line is wet/electronic. Mitigation: §7 includes a footer note distinguishing the two signatures, and the signature-block placeholder is REQUIRES-OPERATOR-INPUT for the exec until in-person sign-off.

## Open questions (for implementation session to resolve)
- **Q1**: Should the cover letter cite the SHA256 of the full bundle tarball? It cannot, because the cover letter is INSIDE the tarball — chicken/egg. Alternative: emit a post-tarball companion summary that includes the bundle SHA256.
- **Q2**: Should §4 sort artifacts by role (alphabetical) or by INDEX.json order? Today: alphabetical for stable diffing.
- **Q3**: Does the cover letter need a separate addressee for the FedRAMP PMO (in addition to the agency AO)? Today: single addressee; PMO is cc'd via §6 Primary Contacts.
- **Q4**: Should §5 cite a specific FedRAMP-baseline review timeline number (e.g. "180 calendar days")? FedRAMP guidance varies; default to text reference to the Playbook.
- **Q5**: How should reauthorization differ from initial-ato in §2 Request Summary? Currently a single sentence change; may need more nuance.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by 11)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (C.C8 row + Overall section)
- [ ] LOOP-C-SPEC.md Section 7 row updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added
- [ ] Commit with `LOOP-C.C8:` in the message
- [ ] Commit amended with commit hash recorded
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
1. Auto-loaded: `cloud-evidence/CLAUDE.md`.
2. This file gives source obligations + files + build steps + tests + risks + checklist.
3. Read `cloud-evidence/docs/loops/LOOP-C-SPEC.md` Section 2 + Section 6 (especially the orchestrator dispatch-order constraint).
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for commit pattern.
5. Read `cloud-evidence/core/submission-bundle.ts` — to know INDEX.json shape this slice reads.
6. Read `cloud-evidence/core/oscal-ap.ts` — to know ap.json metadata shape this slice reads.
7. Read FedRAMP Agency Authorization Playbook v4.1 (URL above) — section 3 cover-letter pattern.
8. Read FedRAMP Initial Authorization Package Checklist (URL above) — package-contents enumeration.
9. Read FedRAMP ATO Letter Template (URL above) — to distinguish CSP-side cover letter from AO-side ATO letter.
10. Begin implementation; update Implementation log as you go.
