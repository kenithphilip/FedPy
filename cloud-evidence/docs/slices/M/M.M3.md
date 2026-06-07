---
slice_id: M.M3
title: PT-family controls inventory (PT-1..PT-8 beyond PTA/PIA scope)
loop: M
status: pending
commit: —
completed_date: —
depends_on: [LOOP-A.A1, LOOP-A.A4, LOOP-C.C4, LOOP-C.C5, M.M1, M.M2, INV-S6]
blocks: [C.C7, E.E1]
estimated_effort: 6-7 working days
last_updated: 2026-06-07
applicable_conditional: false
---

# M.M3 — PT-family controls inventory (PT-1..PT-8 beyond PTA/PIA scope)

## TL;DR
NIST SP 800-53 Rev 5 §3.18 introduced the PT (Personally Identifiable Information Processing and Transparency) family with 8 base controls + 10 enhancements ALL in the FedRAMP Moderate baseline per 800-53B Table 3-1. LOOP-C.C4 PTA + PIA partly cover PT-1/2/3/5/6 but PT-4 (Consent), PT-7 (Specific Categories), PT-8 (Computer Matching) and all 10 enhancements have no structured `implemented-requirements` envelope. This slice emits `out/pt-family-controls.json` (KSI-envelope shape) and extends `core/oscal-ssp.ts` `buildControlImplementation()` to surface all 18 PT-family entries.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
- **Extends `core/oscal-ssp.ts`** — `buildControlImplementation()` branches per PT-1..PT-8 + enhancements to the new narrative generators in `core/pt-family-narratives.ts`. Already the SSP's extension point pattern for FedRAMP Moderate.
- **Extends `core/control-benchmark.ts`** — annotates PT-family baseline rows with `responsibility: 'csp-supplied'` markers.
- **Process-artifact KSI** — registers `KSI-PRV-PTF` in `core/ksi-map.ts`; evidence source = tracker `pt_control_evidence` + `consent_records`.
- **Reads `inventory.json`** — PT-7 sensitive-category enumeration pulls from `pii_categories` tag (`ssn`, `biometric`, `medical`, `financial`, `juvenile`, `immigration`, `geolocation`); each triggers a sensitive-category narrative section.
- **Reads M.M1 SORN snapshot** — PT-2 legal authority + PT-6 SORN cross-reference + PT-7 categories of records all read from `out/.sorn-snapshot.json`.
- **Reads LOOP-C.C5 FIPS 199 worksheet** — PT-7 enhancement selection (1)(2) keys off the PII Confidentiality Impact Level per NIST SP 800-122 §3.
- **Submission bundler** — adds `pt-family-controls-json` role.
- **REO** — per-control narrative is operator-supplied via tracker; consent records hash-only; verbatim PT-* control text from NIST 800-53 Rev 5 PDF cited in narrative docstrings.

## Why this slice exists
LOOP-C.C4 PTA + PIA cover the PIA-trigger surface per M-03-22. PT-family controls in NIST 800-53B Moderate baseline include EIGHTEEN entries (8 base + 10 enhancements). Today, none of those 18 have a structured `implemented-requirement` in the emitted OSCAL SSP — they appear as un-narrated control rows with `implementation-status: unknown`. A 3PAO reading the SSP sees the gap immediately. M.M3 closes that gap with one operator-attested narrative per control + enhancement.

## Authoritative sources (with verbatim quotes)
- **NIST SP 800-53 Rev 5 §3.18 PT family** — verbatim quotes for ALL 18 controls in LOOP-M-SPEC.md §11 (PT-1 through PT-8 + enhancements). Each per-control narrative generator's docstring carries the verbatim control text + the page number from the downloaded PDF (`cloud-evidence/docs/sources/nist-sp-800-53-rev5.pdf`).
- **NIST SP 800-53B Rev 5 Moderate Baseline** — https://csrc.nist.gov/pubs/sp/800/53/b/upd1/final — Table 3-1 enumerates which PT controls + enhancements are in the Moderate baseline:
  - PT-1, PT-2, PT-2(1), PT-2(2), PT-3, PT-3(1), PT-3(2), PT-4, PT-5, PT-5(1), PT-5(2), PT-6, PT-6(1), PT-6(2), PT-7, PT-7(1), PT-7(2), PT-8.
  - Total: 18 entries.
- **NIST SP 800-122** "Guide to Protecting the Confidentiality of PII":
  - **§2.1 PII definition**:
    > "Information that can be used to distinguish or trace an individual's identity, such as their name, social security number, biometric records, etc. alone, or when combined with other personal or identifying information which is linked or linkable to a specific individual, such as date and place of birth, mother's maiden name, etc."
  - **§3 PII Confidentiality Impact Level** — Low/Moderate/High factors: identifiability, quantity, sensitivity, context, obligation, access.
  - Drives M.M3 PT-7 enhancement selection.
- **NIST Privacy Framework v1.0** — https://www.nist.gov/privacy-framework — 5 functions (Identify-P, Govern-P, Control-P, Communicate-P, Protect-P); subcategory crosswalk surfaces as `props[]` on each emitted `implemented-requirement`.
- **NIST SP 800-37 Rev 2 Step 1 Privacy Categorize** — drives PT-2 authority-to-process documentation.
- **Privacy Act §552a (o)** — PT-8 Computer Matching scaffold.
- **OMB Circular A-130 §6.j** — Privacy Program Plan content requirements; informs PT-1 policy narrative.

## Files to create (exact paths under cloud-evidence/)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/pt-family-emit.ts` — ~800 lines. Emits `out/pt-family-controls.json` envelope.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/pt-family-narratives.ts` — per-control narrative generators for PT-1..PT-8 + 10 enhancements (18 total). Each generator carries the verbatim PT-* control text in its docstring per CLAUDE.md Rule 3 (published NIST content).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/pt-family-reader.ts` — tracker `pt_control_evidence` + `consent_records` snapshot pull; verifies signatures per row.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/pt-family-emit.test.ts` — ≥13 tests (enumerated below).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/pt-family-narratives.test.ts` — per-control generator tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/pt-family-reader.test.ts` — snapshot tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/pt-family/` — sample fixtures (tracker snapshot + inventory + SORN snapshot).
- `tracker/server/routes/pt-control-evidence.ts` — CRUD; enforces UNIQUE control_id; SAOP review for sensitive controls (PT-7, PT-8).
- `tracker/server/routes/consent-records.ts` — CRUD; stores subject identifier hash only (sha256), never plain identifier.
- `tracker/client/src/pages/PtControls.tsx` — UI: list 18 controls + per-control narrative editor + evidence-link manager + responsible-role picker.
- `tracker/client/src/pages/ConsentRecords.tsx` — UI: consent capture form (operator records consent given by subject; stores hash).
- `tracker/server/routes/pt-control-evidence.test.ts`.
- `tracker/server/routes/consent-records.test.ts`.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-ssp.ts` — `buildControlImplementation()` branches per PT control to new narrative generators; PT-4 emits `implementation-status: not-applicable` with rationale when consent not collected.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/control-benchmark.ts` — annotate PT-family rows with `responsibility: 'csp-supplied'`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — `--pt-family` flag + env `CLOUD_EVIDENCE_PT_FAMILY`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add role `pt-family-controls-json`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ksi-map.ts` — register `KSI-PRV-PTF`.
- `tracker/server/schema.sql` — `pt_control_evidence` + `consent_records` tables.
- `tracker/server/index.ts` — mount routes.
- `tracker/client/src/App.tsx` — add `/privacy/pt-controls` + `/privacy/consent-records` routes.

## Schemas / standards
- **NIST SP 800-53 Rev 5 §3.18** — verbatim quotes per control in narrative docstrings.
- **NIST SP 800-53B Rev 5 Moderate baseline Table 3-1** — 18 PT entries; the emitter validates the emitted control set against this list (test pins the count).
- **NIST Privacy Framework v1.0 subcategory crosswalk** — each emitted `implemented-requirement` carries `props[name='privacy-framework-subcategory', value=<subcategory id>]`.
- **OSCAL SSP v1.1.2 `implemented-requirement`** — schema per https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/system-security-plan/json-reference/#/system-security-plan/control-implementation/implemented-requirements .
- **KSI envelope schema** — `core/envelope.ts` shape; `pt-family-controls.json` conforms.

## Build steps (concrete, numbered)
1. Define `PtControlEvidence` + `PtFamilyEnvelope` in `core/pt-family-emit.ts`:
   ```ts
   export type PtControlId =
     | 'PT-1' | 'PT-2' | 'PT-2(1)' | 'PT-2(2)'
     | 'PT-3' | 'PT-3(1)' | 'PT-3(2)'
     | 'PT-4'
     | 'PT-5' | 'PT-5(1)' | 'PT-5(2)'
     | 'PT-6' | 'PT-6(1)' | 'PT-6(2)'
     | 'PT-7' | 'PT-7(1)' | 'PT-7(2)'
     | 'PT-8';
   export const PT_MODERATE_BASELINE: readonly PtControlId[] = [
     'PT-1', 'PT-2', 'PT-2(1)', 'PT-2(2)',
     'PT-3', 'PT-3(1)', 'PT-3(2)',
     'PT-4',
     'PT-5', 'PT-5(1)', 'PT-5(2)',
     'PT-6', 'PT-6(1)', 'PT-6(2)',
     'PT-7', 'PT-7(1)', 'PT-7(2)',
     'PT-8',
   ];
   export interface PtControlEvidence {
     control_id: PtControlId;
     narrative: string;
     evidence_links: { href: string; title: string; }[];
     responsible_role: string;
     status: 'implemented' | 'partial' | 'planned' | 'not-applicable';
     not_applicable_rationale?: string;
     last_assessed: string;
     attested_by_user_id: number;
     attested_at: string;
     signature: string;
     signing_key_id: string;
   }
   ```
2. **Per-control narrative generators** in `core/pt-family-narratives.ts` — one function per `PtControlId`. Each generator's docstring carries verbatim NIST 800-53 Rev 5 §3.18 control text (allowed under CLAUDE.md Rule 3). Each returns OSCAL `implemented-requirement.description` prose:
   - `narratePT1(opts)` — Policy + Procedures. Auto-fills: SSP system-name, designated official from `org-profile.yaml`, review frequency from `--control-review-frequency`. Operator-supplied: policy URL (tracker `pt_control_evidence`).
   - `narratePT2(opts)` — Authority to Process. Reads tracker `privacy_records.legal_authority` (set in M.M1).
   - `narratePT2_1(opts)` — Data Tagging. Reads inventory `pii_categories` tag schema enumeration.
   - `narratePT2_2(opts)` — Automation. Reads orchestrator audit trail showing automated PII-flow monitoring (per provenance.sourceCalls).
   - `narratePT3(opts)` — Processing Purposes. Reads tracker `pt_control_evidence` per-purpose row.
   - `narratePT3_1(opts)` — Data Tagging. Mirrors PT-2(1) with purpose-tag emphasis.
   - `narratePT3_2(opts)` — Automation. Mirrors PT-2(2) with purpose-monitoring emphasis.
   - `narratePT4(opts)` — Consent. Reads tracker `consent_records` aggregate. When CSO does NOT collect consent (agency-mandated processing), narrative explicitly states legal basis is NOT consent + cites authority + emits `status: not-applicable` with rationale.
   - `narratePT5(opts)` — Privacy Notice. Operator-supplied URL + last-updated date.
   - `narratePT5_1(opts)` — Just-in-Time Notice.
   - `narratePT5_2(opts)` — Privacy Act Statements. Required when M.M1 attested YES.
   - `narratePT6(opts)` — System of Records Notice. Reads M.M1 SORN snapshot (system_name + Federal Register publication ref if available).
   - `narratePT6_1(opts)` — Routine Uses. Reads M.M1 routine_uses[] review cadence.
   - `narratePT6_2(opts)` — Exemption Rules. Reads M.M1 exemptions_claimed[] review cadence.
   - `narratePT7(opts)` — Specific Categories. Reads inventory `pii_categories` matched against sensitive set (ssn, biometric, medical, financial, juvenile, immigration, geolocation). Per category, narrative cites NIST 800-122 §3.2 handling.
   - `narratePT7_1(opts)` — Social Security Numbers. When `ssn` in `pii_categories`: required; else `not-applicable`.
   - `narratePT7_2(opts)` — First Amendment Information. Operator-asserted status; rare.
   - `narratePT8(opts)` — Computer Matching. Reads tracker for any CMA rows; when none, narrative records `not-applicable` with operator-signed rationale.
3. **Emit `out/pt-family-controls.json`** — KSI-envelope-shaped:
   ```json
   {
     "ksi_id": "KSI-PRV-PTF",
     "run_id": "...",
     "collected_at": "ISO datetime",
     "frmr_version": "...",
     "providers": [{
       "provider": "process-artifact",
       "evidence": [
         { "source": "tracker:pt_control_evidence", "control_id": "PT-1", "data": {...}, "fetched_at": "..." },
         ...18 entries total
       ]
     }],
     "findings": [],
     "provenance": {
       "emitter": "core/pt-family-emit.ts",
       "emittedAt": "...",
       "sourceCalls": ["tracker:pt_control_evidence:list", "tracker:consent_records:list", "inventory.json:read", "out/.sorn-snapshot.json:read"],
       "signingKeyId": "..."
     }
   }
   ```
4. **OSCAL SSP integration** — `buildControlImplementation()` calls `narratePT<id>()` for every PT control in `PT_MODERATE_BASELINE`. Each yields an OSCAL `implemented-requirement` with:
   - `control-id`: `'pt-1'` (lowercase per OSCAL convention) or `'pt-2.1'` for enhancement (1).
   - `description`: prose from narrative generator.
   - `responsible-roles[]`: from `tracker.responsible_role`.
   - `by-components[]`: link to component-id `csp-system` (existing).
   - `statements[]`: per-statement narrative when control has sub-elements (PT-1 a/b/c, PT-5 a/b/c/d/e).
   - `props[]`: includes `privacy-framework-subcategory` crosswalk + `responsibility=csp-supplied` + `not-applicable-rationale` when `status=not-applicable`.
5. **Tracker DB**:
   ```sql
   CREATE TABLE IF NOT EXISTS pt_control_evidence (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     control_id TEXT NOT NULL,
     narrative TEXT NOT NULL,
     evidence_links TEXT,
     responsible_role TEXT NOT NULL,
     status TEXT NOT NULL CHECK (status IN ('implemented','partial','planned','not-applicable')),
     not_applicable_rationale TEXT,
     last_assessed TEXT NOT NULL,
     attested_by_user_id INTEGER NOT NULL REFERENCES users(id),
     attested_at TEXT NOT NULL,
     signature TEXT NOT NULL,
     signing_key_id TEXT NOT NULL,
     created_at TEXT NOT NULL,
     updated_at TEXT NOT NULL
   );
   CREATE UNIQUE INDEX IF NOT EXISTS idx_ptce_unique ON pt_control_evidence(control_id);

   CREATE TABLE IF NOT EXISTS consent_records (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     subject_identifier_hash TEXT NOT NULL,
     purpose_id TEXT NOT NULL,
     consent_given INTEGER NOT NULL CHECK (consent_given IN (0,1)),
     consent_mechanism TEXT NOT NULL,
     captured_at TEXT NOT NULL,
     captured_by_system TEXT NOT NULL,
     withdrawn_at TEXT,
     created_at TEXT NOT NULL
   );
   CREATE INDEX IF NOT EXISTS idx_cr_purpose ON consent_records(purpose_id);
   CREATE INDEX IF NOT EXISTS idx_cr_subject ON consent_records(subject_identifier_hash);
   ```
6. **Bundler** — add `pt-family-controls-json` to `WELL_KNOWN`.
7. **Wire orchestrator** — `--pt-family` runs AFTER `--sorn` + `--dpia` (so M.M1/M.M2 snapshots inform PT narratives) and BEFORE `--oscal-ssp` (so SSP picks up narratives).
8. **Sign + timestamp** — `pt-family-controls.json` in manifest glob; SSP signed downstream of M.M3 run.
9. **Validate** — after re-emitting SSP, run `core/oscal-validate.ts`; SSP must still ajv-validate against OSCAL SSP v1.1.2 schema after 18 new `implemented-requirements` added.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4:

| Field | Source | Behavior when missing |
|---|---|---|
| Per-control `narrative` | Tracker `pt_control_evidence` | Emitter renders boilerplate from `pt-family-narratives.ts` with `REQUIRES-OPERATOR-INPUT: tracker /privacy/pt-controls/<id>` marker; `status: planned`; SSP `implementation-status: planned` |
| PT-1 policy URL | Tracker `evidence_links` | REQUIRES-OPERATOR-INPUT |
| PT-2 legal authority | M.M1 SORN snapshot OR tracker `pt_control_evidence` | REQUIRES-OPERATOR-INPUT when neither path supplies |
| PT-4 consent mechanism (when applicable) | Tracker `consent_records` aggregate | REQUIRES-OPERATOR-INPUT or explicit `not-applicable` rationale (operator signs) |
| PT-5 privacy notice URL | Tracker `evidence_links` | REQUIRES-OPERATOR-INPUT |
| PT-6 cross-reference to SORN uuid | M.M1 snapshot | REQUIRES-OPERATOR-INPUT when M.M1 conditional-skip ran |
| PT-7 sensitive-category handling per category | Inventory `pii_categories` union + tracker narrative | REQUIRES-OPERATOR-INPUT per category |
| PT-7(1) SSN handling | Required when `ssn` in `pii_categories`; else `not-applicable` | REQUIRES-OPERATOR-INPUT for handling description |
| PT-8 CMA references | Tracker | Explicit `not-applicable` rationale if no CMA (operator signs) |
| Responsible role per control | Tracker `responsible_role` | REQUIRES-OPERATOR-INPUT |
| Privacy Framework subcategory crosswalk | Operator config OR built-in mapping table | Built-in mapping is published Privacy Framework constant (Rule 3) |

## Test specifications (≥13 tests)
1. `it('emits one implemented-requirement per Moderate-baseline PT control + enhancement — 18 total')` — assert `PT_MODERATE_BASELINE.length === 18` and emitted count matches.
2. `it('PT-2 narrative pulls legal_authority from M.M1 SORN snapshot')`.
3. `it('PT-4 emits not-applicable with rationale when no consent collected AND operator attests')`.
4. `it('PT-6 narrative cites the M.M1 SORN by uuid + Federal Register publication when available')`.
5. `it('PT-7 narrative enumerates sensitive categories from inventory pii_categories union')`.
6. `it('PT-7(1) emits SSN-specific handling when "ssn" in pii_categories; else not-applicable')`.
7. `it('PT-8 emits not-applicable with operator-signed rationale when no CMA records in tracker')`.
8. `it('emits REQUIRES-OPERATOR-INPUT for any unsupplied narrative; status=planned in SSP')`.
9. `it('OSCAL SSP control-implementation gains 18 PT-family entries after M.M3 runs')`.
10. `it('SSP still ajv-validates against OSCAL v1.1.2 schema after PT additions')`.
11. `it('pt-family-controls.json envelope conforms to KSI envelope schema')`.
12. `it('registers KSI-PRV-PTF process-artifact in ksi-map')`.
13. `it('tracker pt_control_evidence enforces UNIQUE control_id constraint')`.
14. `it('consent_records stores sha256 hash, never plain identifier')` — submit plain identifier; assert hash-only stored.
15. `it('bundler includes pt-family-controls-json role in WELL_KNOWN')`.
16. `it('per-control narrative docstring contains verbatim NIST 800-53 Rev 5 §3.18 control text')` — regex search.
17. `it('Privacy Framework subcategory crosswalk prop is set on every implemented-requirement')`.
18. `it('PT-2(1) Authority Tracking narrative references automated mechanism per inventory tag schema')`.
19. `it('PT-3(1) Data Tagging narrative cites inventory pii_purpose_ids tag')`.
20. `it('strictPrivacy mode hard-errors when any PT control has REQUIRES-OPERATOR-INPUT marker')`.

## REO compliance
- PT-family control text quoted verbatim from NIST 800-53 Rev 5 §3.18 in narrative-generator docstrings (Rule 3: allowed published constants).
- Per-control narrative is signed tracker row (operator-supplied).
- Sensitive PII never persisted plain — `consent_records.subject_identifier_hash` is sha256-only.
- Provenance block on `pt-family-controls.json`.
- SSP ajv-validates after extension.
- No silent `not-applicable` — operator MUST supply rationale, signed.
- No `process.env.NODE_ENV === 'test'` branches.

## Verification commands
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/pt-family-emit.test.ts tests/core/pt-family-narratives.test.ts tests/core/pt-family-reader.test.ts tests/core/oscal-ssp.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
cd ../tracker
npm run typecheck
npm test -- server/routes/pt-control-evidence.test.ts server/routes/consent-records.test.ts
```

## Known risks / issues
- **Risk 1: PT-family content overlap with PIA narrative in LOOP-C.C4** — PT-1/2/3/5/6 are partly covered by PIA. Mitigation: M.M3 narratives reference PIA but do NOT duplicate; tracker UI shows PIA cross-reference; CHANGELOG documents the boundary.
- **Risk 2: NIST 800-53B Moderate baseline drift** — future Rev 6 publication could change PT-family selection. Mitigation: `PT_MODERATE_BASELINE` is a typed constant; test pins count; migration is a separate slice.
- **Risk 3: Privacy Framework subcategory crosswalk staleness** — NIST may publish Privacy Framework v2.0. Mitigation: subcategory mapping is in `core/privacy-framework-crosswalk.ts` as a versioned constant; `pf_version: 'v1.0'` prop on every emit.
- **Risk 4: Consent-records plain-identifier leak risk** — if developer mistakenly stores plain identifier, PII exposure. Mitigation: route enforces hashing server-side; tests verify; lint check.
- **Risk 5: PT-8 CMA scope ambiguity** — when CSO supports multiple agencies, CMA may apply to one but not others. Mitigation: per-agency tracker row; operator-supplied rationale per CSO-agency pair.
- **Risk 6: SSP regeneration order** — `--pt-family` MUST run before `--oscal-ssp` or SSP misses narratives. Mitigation: orchestrator documents order; integration test verifies.
- **Risk 7: NIST PDF download blocking** — verbatim PT-* control text requires PDF download into `cloud-evidence/docs/sources/`. Mitigation: per-loop sources/ directory pattern; CHANGELOG documents.
- **Risk 8: Multi-tenant CSO PT-family applicability** — different tenants may have different PT-7 sensitive categories. Mitigation: per-tenant tracker rows; emit aggregates per system_id. Long-tail tied to H.H3 multi-CSO.

## Open questions
- **Q1**: For PT-4 Consent when CSO does NOT collect consent (agency mandate), the narrative is `not-applicable` — but PT-4 is in Moderate baseline. Confirm: not-applicable + rationale is acceptable per FedRAMP review. Recommend: yes; verify with 3PAO + document in runbook.
- **Q2**: Does the Privacy Framework subcategory crosswalk need to be agency-customizable? Recommend: published constant; agencies may override via tracker prop.
- **Q3**: For PT-7 enhancements (1)(2), is enhancement triggered by ANY sensitive category or per-category? Recommend: per-category; PT-7(1) fires for `ssn`, PT-7(2) fires when First Amendment data present.
- **Q4**: Should we ingest tracker `consent_records` aggregate stats (% consent given) into PT-4 narrative? Recommend: yes, with date stamp; surface as prop.
- **Q5**: When M.M1 conditional-skip ran (no SORN), do we still emit PT-6 implemented-requirement? Recommend: PT-6 emits `not-applicable` with rationale "No §552a system of records maintained per M.M1 attestation".

## Implementation log
(empty — implementing session fills this in as work progresses)

## Completion checklist
- [ ] typecheck clean
- [ ] tests passing 100% (count increased by ≥20)
- [ ] check:reo green
- [ ] STATUS.md updated
- [ ] LOOP-M-SPEC.md status row updated
- [ ] This file's frontmatter updated
- [ ] CHANGELOG.md "Unreleased" entry with verbatim NIST 800-53 Rev 5 PT-1/PT-7/PT-8 citations
- [ ] Commit with slice ID
- [ ] Commit amended with hash
- [ ] Pushed to origin/main
- [ ] LOOP-M-RISKS.md updated with new risks

## Resume-from-fresh-session checklist
1. Read `cloud-evidence/CLAUDE.md` (REO standard).
2. Read this file.
3. Read `cloud-evidence/docs/loops/LOOP-M-SPEC.md` §1, §3, §4, §5 (M.M3 sub-section), §11 (verbatim PT-1..PT-8 text).
4. Read `cloud-evidence/docs/slices/M/M.M1.md` + `M.M2.md` — M.M3 reads both snapshots.
5. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
6. Read `cloud-evidence/core/oscal-ssp.ts` `buildControlImplementation()` — your extension point.
7. Read `cloud-evidence/core/control-benchmark.ts` — your responsibility annotation point.
8. Download NIST SP 800-53 Rev 5 PDF into `cloud-evidence/docs/sources/nist-sp-800-53-rev5.pdf` if not already present.
9. Begin implementation; update Implementation log at every milestone.

---
