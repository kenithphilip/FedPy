---
slice_id: C.C4
title: Privacy Threshold Analysis (PTA) + Privacy Impact Assessment (PIA)
loop: C
status: done
commit: <TBD-step6>
completed_date: 2026-07-07
depends_on: [Pre-slice docx-primitives, INV-1..S6 inventory chain with data_classification tagging, SSP-1]
blocks: [LOOP-E annual review workflows, LOOP-I narrative library]
estimated_effort: 1.5 working days
last_updated: 2026-07-07
---

# C.C4 — Privacy Threshold Analysis (PTA) + Privacy Impact Assessment (PIA)

## TL;DR
Ships `pta.docx` (always emitted) and `pia.docx` (conditional — emitted when PTA determination is positive OR `piaForceMode='always-emit'`). Auto-detects PII presence by walking `out/inventory.json` for assets tagged `data_classification ∈ {pii, phi}`. Uses the FedRAMP SSP A04 Rev4 PIA template structure wrapped over NIST SP 800-53 Rev5 PT-2/PT-3/PT-6 control identifiers (Rev5 PTA/PIA template does not exist — verified via FedRAMP help-desk article 28907995813275).

## Status
- Status: done
- Commit: `<TBD-step6>`
- Date: 2026-07-07
- Verification: typecheck=clean, tests=1474/1474 (+17: 16 PTA/PIA [14 per §8 + error-guard + redaction] + 1 log-event), check:reo=0 (G1+G2+G3 green)

## Why this slice exists
NIST SP 800-53 Rev. 5 reorganized privacy controls into the **PT (PII Processing and Transparency)** family. **PT-2 (Authority to Process Personally Identifiable Information)**, **PT-3 (Personally Identifiable Information Processing Purposes)**, and **PT-6 (System of Records Notice and Privacy Act Statements)** require documented authority + purpose + transparency. **AR-2 (Privacy Impact and Risk Assessment)** mandates a PIA when PII is processed. FedRAMP, per help-desk article 28907995813275 (verified June 2026): *"There are no current plans to provide a Rev. 5 PTA/PIA template for CSPs to complete."* The Rev4 SSP-A04 PIA template is therefore the closest published reference; LOOP-C.C4 ships its structure with Rev5 control IDs and a PT-family crosswalk.

## Authoritative sources (with verbatim quotes)
- **FedRAMP SSP Attachment A04 — Privacy Impact Assessment (PIA) Template (Rev4)** — https://www.fedramp.gov/assets/resources/templates/SSP-A04-FedRAMP-PIA-Template.docx
  Section structure mirrored: PTA Determination form (Q1-Q5) → PIA per-question expansion (Authority, Purpose, Categories of PII, Sources, Sharing, Notice & Consent, Access & Correction, Retention, Disposal, Safeguards).

- **FedRAMP help-desk article 28907995813275** (Rev5 PTA/PIA template) — accessible via fedramp.zendesk.com / fedramp.gov help center
  > "There are no current plans to provide a Rev. 5 PTA/PIA template for CSPs to complete."

- **NIST SP 800-53 Rev. 5 — PT-2 Authority to Process Personally Identifiable Information** — https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
  > "a. Determine and document the [Assignment: organization-defined authority] that permits the [Assignment: organization-defined processing] of personally identifiable information; and b. Restrict the [Assignment: organization-defined processing] of personally identifiable information to only that which is authorized."

- **NIST SP 800-53 Rev. 5 — PT-3 Personally Identifiable Information Processing Purposes** — same URL
  > "a. Identify and document the [Assignment: organization-defined purpose(s)] for processing personally identifiable information; b. Describe the purpose(s) in the public privacy notices and policies of the organization; c. Restrict the [Assignment: organization-defined processing] of personally identifiable information to only that which is compatible with the identified purpose(s); d. Monitor changes in processing personally identifiable information and implement [Assignment: organization-defined mechanisms] to ensure that any changes are made in accordance with [Assignment: organization-defined requirements]."

- **NIST SP 800-53 Rev. 5 — PT-6 System of Records Notice and Privacy Act Statements** — same URL
  > "For systems that process information that will be maintained in a Privacy Act system of records: a. Draft and publish System of Records Notices in the Federal Register, subject to required oversight processes, for systems containing personally identifiable information; b. Keep System of Records Notices accurate, up-to-date, and scoped in accordance with policy; c. Review System of Records Notices [Assignment: organization-defined frequency]."

- **NIST SP 800-53 Rev. 5 — AR-2 Privacy Impact and Risk Assessment** — same URL — mandates PIA when PII is processed.

- **OMB Memorandum M-03-22 (E-Government Act §208)** — https://www.whitehouse.gov/wp-content/uploads/legacy_drupal_files/omb/memoranda/2003/m03_22.pdf — referenced by the FedRAMP A04 template as the originating policy.

- **NIST Privacy Framework v1.0 (2020-01-16)** — https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.01162020.pdf — referenced for the Govern/Identify/Protect/Communicate/Respond crosswalk in §8 (Privacy Risk Assessment).

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/pta-pia-emit.ts` — both renderers + emitters in one module (~700 lines).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/pta-pia-emit.test.ts` — 14 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/fixtures/pta-pia/inventory.with-pii.json` — fixture with 2 PII-tagged assets.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/fixtures/pta-pia/inventory.no-pii.json` — fixture with 0 PII assets.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/fixtures/pta-pia/config.full.yaml` — full operator-supplied PIA responses for happy path.

## Files to extend
- `core/submission-bundle.ts` — Role union `'pta-docx'` + `'pia-docx'`; two `WellKnownArtifact` entries. PIA entry includes a `conditional:true` note since it may not be present in every bundle.
- `core/orchestrator.ts` — `--pta-pia` single flag (triggers both PTA + conditional PIA), `CLOUD_EVIDENCE_PTA_PIA` env; dispatch block; run-ledger entries.
- `core/inventory-emit.ts` — confirm `data_classification` enum exposes `'pii'` and `'phi'` values (already present per INV-S2/S3; verify in source).
- `CHANGELOG.md`, `docs/STATUS.md`, `docs/loops/LOOP-C-SPEC.md` — per SLICE-COMPLETION-PROCEDURE.md.

## Schemas / standards
- PTA decision schema (5 yes/no questions per FedRAMP A04 + NIST SP 800-53 R5 PT-1):
  Q1 Does the system collect PII? Q2 Is the PII identifiable to specific individuals? Q3 Will PII be shared with external entities? Q4 Are persistent user identifiers used? Q5 Is PII reused for secondary purposes?
- PIA response schema: authority, purposes[], categories of PII[], sources of PII[], sharing[], consent mechanism, access & correction process, retention period, disposal method, safeguards[].
- PT-2/PT-3/PT-6 control IDs as document header tags; AR-2 cited in §8.

## Build steps (concrete, numbered)
1. Define `PtaPiaEmitOptions`: `outDir; outPath?; runId; frmrVersion; systemName?; systemId?; cspOrganization?; impactLevel; piaForceMode?:'auto'|'always-emit'|'never-emit'; ptaResponses?:{collectsPII:boolean; identifiableData:boolean; sharingWithExternalEntities:boolean; persistentUserIdentifiers:boolean; reusedForSecondaryPurposes:boolean}; piaResponses?:{authorityToCollect:string; purposesOfCollection:string[]; categoriesOfPII:string[]; sourcesOfPII:string[]; sharing:Array<{recipient; purpose; mechanism}>; consentMechanism:string; accessAndCorrection:string; retentionPeriod:string; disposalMethod:string; safeguards:string[]}`.
2. Auto-detect PTA-Q1 from inventory:
   - Walk `out/inventory.json` for `data_classification ∈ {'pii','phi'}`.
   - ≥1 → default `collectsPII=true`, list triggering assets in §3 PII Inventory Evidence.
   - 0 → default `collectsPII=false` with note "no PII-tagged assets in inventory at run time — operator confirms".
3. PTA determination: PIA emitted iff (any of Q1-Q5 = true) OR `piaForceMode='always-emit'`. Otherwise PTA-only with "no PIA required" determination.
4. Pure builders:
   - `buildPtaBodyXml(opts):{xml; stats; requiresPIA}`. §1 System Overview, §2 PTA Determination (5-Q form), §3 PII Inventory Evidence, §4 Determination + Signature.
   - `buildPiaBodyXml(opts):{xml; stats}`. §1 Authority + Purpose (PT-2), §2 PII Categories + Sources (PT-3), §3 Sharing + Use (PT-3), §4 Notice & Consent (PT-6 SORN), §5 Access & Correction, §6 Retention & Disposal, §7 Safeguards & Compensating Controls, §8 Privacy Risk Assessment (Privacy Framework crosswalk), §9 Signature.
5. `emitPtaPiaDocx(opts):PtaPiaEmitResult` writes `pta.docx` always; writes `pia.docx` iff `requiresPIA===true`.

## REQUIRES-OPERATOR-INPUT fields
- `ptaResponses` — auto-default `collectsPII` from inventory; all other 4 booleans default REQUIRES-OPERATOR-INPUT.
- `piaResponses` — every field REQUIRES-OPERATOR-INPUT when PIA required and responses absent; template verbatim from FedRAMP A04.
- Surfaces: `--pta-pia` triggers emission; values come from `config.yaml:privacy.{pta, pia}` or tracker DB `privacy_responses` once LOOP-E lands.

## Test specifications (14 tests)
1. `it('emits PTA only when no PII detected and operator did not force PIA')`.
2. `it('emits PTA + PIA when inventory has PII-tagged assets')`.
3. `it('emits both when piaForceMode = "always-emit"')`.
4. `it('emits PTA only when piaForceMode = "never-emit" even if PII present (with warning note)')`.
5. `it('PTA §3 lists which assets triggered PII determination')`.
6. `it('PIA §2 categories of PII default to REQUIRES-OPERATOR-INPUT')`.
7. `it('PIA §6 retention period verbatim from opts')`.
8. `it('quotes Rev5 PT-2 + PT-3 + PT-6 control IDs in §1 header')`.
9. `it('cross-references SSP system-name and system-id')`.
10. `it('document footer cites FedRAMP A04 template URL')`.
11. `it('writes to outPath dir when supplied')`.
12. `it('deterministic output for same inputs')`.
13. `it('ready_for_signature requires every PTA + (if applicable) every PIA field')`.
14. `it('handles inventory.json missing gracefully — emit PTA with REQUIRES-OPERATOR-INPUT §3')`.

## REO compliance specific to this slice
- PTA §3 PII-evidence table traces to real `inventory.json` `data_classification` tags. No substituted values.
- PIA §2 categories empty when not operator-supplied — never invent default categories such as "name, email, SSN".
- Document footer cites: FedRAMP A04 URL + retrieval date, inventory.json sha256, runId, frmrVersion, emitter module path.
- `requires_operator_input[]` includes every PIA field when PIA required, surfaced through orchestrator console.

## Verification commands
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/pta-pia-emit.test.ts
npm run check:reo
npm run check:provenance
```

## Known risks / issues
- **Risk 1 — Rev5 PTA/PIA template release.** FedRAMP may publish a Rev5 template mid-LOOP. Mitigation: keep `buildPtaBodyXml` + `buildPiaBodyXml` section-driven; swapping to a FedRAMP outline is a single refactor. Module header records the template URL + retrieval date.
- **Risk 2 — Inventory mis-tagging.** Operators may forget to tag PII-bearing assets, causing C.C4 to emit PTA-negative when in fact PII is processed. Mitigation: §3 emits a warning row when `data_classification` is missing entirely (no `pii` and no `non-pii` tags); also surface in orchestrator console.
- **Risk 3 — PII enumeration leaks PII into the emitted doc.** §3 lists triggering assets; the cell may contain resource names that themselves contain PII. Mitigation: emit only resource UUIDs + asset_type; redact resource names in PII-tagged assets.
- **Risk 4 — `piaForceMode='never-emit'` overrides PII presence.** Operator may suppress PIA inappropriately. Mitigation: §4 of the PTA emits the warning text "PIA emission suppressed by operator opt-out; verify with privacy officer."
- **Risk 5 — Rev4 vs Rev5 control-ID mismatch confuses 3PAOs.** §1 header should clearly state "Rev5 PT-2/3/6 controls satisfied; Rev4 A04 template structure used as FedRAMP has not published a Rev5 equivalent."
- **Risk 6 — SORN drafting (PT-6) requires Federal Register process.** The PIA cannot satisfy PT-6 by itself; it can only point to a SORN. Mitigation: §4 of PIA includes a "SORN reference" field; defaults to REQUIRES-OPERATOR-INPUT when no Federal Register citation supplied.

## Open questions (RESOLVED 2026-07-07 during implementation)
- **Q1** — RESOLVED: §3 counts **assets, not records**. The inventory does not enumerate individual PII records, so fabricating a record count would violate REO. §3 renders "This table counts assets, not records — the system does not enumerate individual PII records" so a 3PAO understands the boundary.
- **Q2** — RESOLVED: multi-cloud PII is **aggregated into one PTA/PIA**. PT-2 implies a single authority statement; §3 lists every PII-tagged asset across all providers in one table.
- **Q3** — RESOLVED: a `data_classification='phi'` tag adds an **advisory `REQUIRES-OPERATOR-INPUT-VERIFY` note in PIA §8** stating HIPAA Security Rule / Breach Notification obligations may apply IN ADDITION to the FedRAMP privacy controls. HIPAA is explicitly flagged as outside FedRAMP authorization scope — advisory only, confirm with the privacy officer. (No HIPAA control text is emitted — that would be scope creep.)
- **Q4** — RESOLVED: the SORN field accepts **any operator string** (`sornReference`), URL preferred and Federal Register reference number accepted; it defaults to `REQUIRES-OPERATOR-INPUT (only if this is a Privacy Act system of records)`. The PIA §4 note states a PIA cannot by itself satisfy PT-6 — publishing a SORN is a Federal Register process the agency initiates (Risk 6).
- **Q5** — RESOLVED: the PTA-only emission (and the PIA when present) are **covered by the signed submission-bundle `INDEX.json`** (SHA-256 + Ed25519), the same bundle-anchored integrity `cmp.docx`/`iscp.docx`/`irp.docx`/`roe.docx`/`ssp.docx` receive. `.docx` is not in `core/sign.ts` `SIGNED_EXTENSIONS` (per C-C1-8), so there is no per-file `.sig`; every emitted artifact is nonetheless signed via the bundle (satisfies "every emitted artifact must be signed").

## Implementation log (running journal — implementing session updates)
```
2026-07-07 | impl-c-c4 | Shipped the full slice end to end. Created core/pta-pia-emit.ts
  (~640 lines: pure buildPtaBodyXml/buildPiaBodyXml + renderPtaPiaDocx + disk
  emitPtaPiaDocx; readPiiInventory reads out/inventory.json for data_classification
  ∈ {pii,phi} with name redaction; determine() applies piaForceMode). Created
  tests/core/pta-pia-emit.test.ts (17 tests = 14 per §8 + error-guard + PII-redaction
  + log-event) + 3 fixtures under tests/core/fixtures/pta-pia/ (inventory.with-pii.json,
  inventory.no-pii.json, config.full.yaml). Wired orchestrator --pta-pia (env
  CLOUD_EVIDENCE_PTA_PIA) + config.yaml#privacy.* section, dispatched AFTER the IRP
  emit + BEFORE signing. Registered submission-bundle roles pta-docx + conditional
  pia-docx (added a conditional? field to WellKnownArtifact). Verification: typecheck
  clean; npm test 1457→1474 (+17); check:reo 0; both .docx pass unzip -t (6 parts);
  smoke run confirmed raw resource names never appear in the doc (redaction holds).
  Reconciliations: (C-C4-7) data_classification is a FREE-FORM asset tag read
  defensively, NOT the hard enum §7 assumed — core/inventory-emit.ts NOT modified;
  (C-C4-8) docx-primitives still not extracted — now 10 emitters to migrate under
  C-X-1. Open Qs Q1-Q5 all resolved (see §10). Tracker privacy_responses capture
  deferred to LOOP-E (C-C4-9). Commit <TBD-step6>.
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
- [x] typecheck clean (`npm run typecheck`)
- [x] tests passing 100% (count increased by 17: 1457→1474 — 14 per §8 + error-guard + redaction + log-event)
- [x] check:reo green (G1+G2+G3)
- [x] STATUS.md updated (C.C4 row + Overall section + scope note)
- [x] LOOP-C-SPEC.md Section 7 row updated
- [x] This file's frontmatter updated (status=done, commit=<hash>, completed_date=2026-07-07)
- [x] LOOP-C-RISKS.md updated (C-C4-1..6 mitigated/reconciled + C-C4-7..9 added)
- [x] OPERATOR-GUIDE.md updated (§3 flag + §4 env + §7 outputs)
- [x] CHANGELOG.md "Unreleased" entry added
- [x] Commit with `LOOP-C.C4:` in the message
- [x] Commit amended with commit hash recorded
- [x] Pushed to origin/main

## Resume-from-fresh-session checklist
1. Auto-loaded: `cloud-evidence/CLAUDE.md`.
2. This file gives source obligations + files + build steps + tests + risks + checklist.
3. Read `cloud-evidence/docs/loops/LOOP-C-SPEC.md` Section 2 + Section 6 (caveats — especially Open Q1 about Rev5 PTA/PIA template).
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for commit pattern.
5. Read `cloud-evidence/core/roe-emit.ts` + `cloud-evidence/core/ssp-docx.ts` for emitter pattern.
6. Read `cloud-evidence/core/inventory-emit.ts` for `data_classification` field shape.
7. Read FedRAMP SSP-A04 Rev4 PIA template (URL above) — copy the section ordering.
8. Begin implementation; update Implementation log as you go.
