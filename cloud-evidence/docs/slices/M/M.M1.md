---
slice_id: M.M1
title: System of Records Notice (SORN) emitter — Privacy Act §552a
loop: M
status: pending
commit: —
completed_date: —
depends_on: [LOOP-A.A1, LOOP-A.A4, LOOP-C.C4, INV-S6]
blocks: [M.M2, M.M3, M.M4, C.C7]
estimated_effort: 5-6 working days
last_updated: 2026-06-07
applicable_conditional: true
---

# M.M1 — System of Records Notice (SORN) emitter — Privacy Act §552a

## TL;DR
When a federal agency authorizes this CSO to maintain records retrievable by individual identifier (name, SSN, employee number, customer ID), 5 U.S.C. §552a (e)(4) obligates the agency to publish a SORN in the Federal Register before that retrieval-by-identifier capability goes live. The agency publishes; the CSP supplies the 11 statutory elements as structured input. This slice emits `out/sorn-draft.md` (Federal-Register-formatted) + `out/sorn-input.json` (machine-readable) — or `out/no-system-of-records-attested.json` when the CSP attests it does not maintain a §552a system.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
FedPy is read-only, evidence-grade automation for FedRAMP 20x + Rev5. M.M1 connects as follows:
- **Reads `inventory.json`** — INV-S6 added asset-level tag honouring for `fedramp_data_classification`. M.M1 extends inventory consumption to read new optional `pii_categories`, `pii_subjects`, `retrieval_by_identifier` tags. Assets matching `pii_categories` non-empty AND `retrieval_by_identifier === true` enter the SORN draft.
- **Process-artifact KSI envelope** — registers `KSI-PRV-SORN` in `core/ksi-map.ts` (mirrors `KSI-PRV-PTA` / `KSI-PRV-PIA` from LOOP-C.C4). Evidence source = tracker `sorn_publications` table.
- **OSCAL chain** — `core/oscal-ssp.ts` `back-matter.resources[]` gains a `rel: 'sorn-draft'` resource pointing at the emitted Markdown + JSON.
- **FRMR catalog** — PT-6 (System of Records Notice) is in the FedRAMP Moderate baseline per NIST 800-53B; the catalog row drives M.M3's PT-6 narrative, which cites M.M1's emitted SORN by uuid.
- **Tracker DB** — adds `privacy_records` (per-system PII enumeration + retrieval-by-identifier attestation) + `sorn_publications` (per-SORN draft + agency publication tracking) tables. Operator-supplied content (legal authorities, routine uses, retention schedule) flows from tracker.
- **REO standard** — every value traces to: inventory.json read, tracker DB row (signed), or operator config. No silent default. Conditional skip emits a **signed attestation**, not a silent omission.

## Why this slice exists
LOOP-C.C4 emits PTA + PIA under OMB M-03-22 §II.B.1 (PIA required before procuring IT systems that collect PII from the public). M-03-22 §II.B.1 is the PIA trigger; **Privacy Act §552a (e)(4) is the SORN trigger** — a distinct, narrower statutory obligation that fires when records are *retrievable by an individual identifier*. From the statute verbatim:

> "Each agency that maintains a system of records shall publish in the Federal Register upon establishment or revision a notice of the existence and character of the system of records, which notice shall include —
> (A) the name and location of the system;
> (B) the categories of individuals on whom records are maintained in the system;
> (C) the categories of records maintained in the system;
> (D) each routine use of the records contained in the system, including the categories of users and the purpose of such use;
> (E) the policies and practices of the agency regarding storage, retrievability, access controls, retention, and disposal of the records;
> (F) the title and business address of the agency official who is responsible for the system of records;
> (G) the agency procedures whereby an individual can be notified at his request if the system of records contains a record pertaining to him;
> (H) the agency procedures whereby an individual can be notified at his request how he can gain access to any record pertaining to him contained in the system of records, and how he can contest its content; and
> (I) the categories of sources of records in the system."
> — 5 U.S.C. §552a (e)(4)

The agency publishes the SORN. **The CSP supplies the 11 structured elements** (A)-(I) + (J) source categories + (K) exemptions. M.M1 emits the structured input.

## Authoritative sources (with verbatim quotes)
- **5 U.S.C. §552a (e)(4)** — Cornell LII canonical text https://www.law.cornell.edu/uscode/text/5/552a — the 11-element SORN publication obligation, quoted above.
- **5 U.S.C. §552a (a)(5) "system of records" definition**:
  > "a group of any records under the control of any agency from which information is retrieved by the name of the individual or by some identifying number, symbol, or other identifying particular assigned to the individual."
  This is the trigger: retrieval-by-identifier. M.M1 emits SORN only when `retrieval_by_identifier_attested === true` in tracker.
- **5 U.S.C. §552a (e)(10)** — safeguards:
  > "establish appropriate administrative, technical, and physical safeguards to insure the security and confidentiality of records and to protect against any anticipated threats or hazards to their security or integrity which could result in substantial harm, embarrassment, inconvenience, or unfairness to any individual on whom information is maintained."
  Drives M.M1 SORN sections 18-21 (storage, retrieval, retention, safeguards).
- **NIST SP 800-53 Rev 5 PT-6 "System of Records Notice"** — per the PDF downloaded into `cloud-evidence/docs/sources/nist-sp-800-53-rev5.pdf` §3.18, verbatim:
  > "For systems that process information that will be maintained in a Privacy Act system of records: a. Draft system of records notices in accordance with OMB guidance and submit new and significantly modified system of records notices to the OMB and appropriate congressional committees for advance review; b. Publish system of records notices in the Federal Register; and c. Keep system of records notices accurate, up-to-date, and scoped in accordance with policy."
- **OMB M-03-22 §II.C.1.f** — PIA must cross-reference SORN status; LOOP-C.C4 PIA emission will read M.M1 snapshot to populate the cross-reference field.
- **Federal Register SORN template** — 26-section structure documented in `LOOP-M-SPEC.md` §4. M.M1's Markdown emit follows the section headers verbatim.
- **OMB Circular A-130 Appendix II** — privacy controls and SORN-amendment cadence (informs M.M4 SORN-amendment-on-breach pattern).

## Files to create (exact paths under cloud-evidence/)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sorn-emit.ts` — ~600 lines. Reads inventory + tracker `privacy_records` snapshot. Emits `out/sorn-draft.md` + `out/sorn-input.json` OR `out/no-system-of-records-attested.json`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sorn-schema.ts` — typed schema for the 11 statutory elements (A)-(K) + the 26 Federal Register template sections.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sorn-reader.ts` — HTTP client pulling `sorn_publications` + `privacy_records` rows from the tracker; writes signature-verified snapshot at `out/.sorn-snapshot.json`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/sorn-emit.test.ts` — ≥14 tests (enumerated below).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/sorn-schema.test.ts` — typed schema validation tests (~6 tests).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/sorn-reader.test.ts` — snapshot + signature verification tests (~4 tests).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/sorn/` — sample inventory + tracker snapshot fixtures.
- `tracker/server/routes/privacy-records.ts` — CRUD for the `privacy_records` table; enforces signed attestation on `retrieval_by_identifier_attested`.
- `tracker/server/routes/sorn-publications.ts` — CRUD for SORN draft versions + agency-side publication tracking + SAOP review workflow.
- `tracker/client/src/pages/PrivacyRecords.tsx` — UI page with per-system rows + attestation flow.
- `tracker/client/src/pages/SornPublications.tsx` — UI page for editing the 26 Federal Register sections + sending to agency.
- `tracker/server/routes/privacy-records.test.ts`.
- `tracker/server/routes/sorn-publications.test.ts`.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/inventory.ts` — add optional `pii_categories?: string[]`, `pii_subjects?: string[]`, `pii_purpose_ids?: string[]`, `retrieval_by_identifier?: boolean` to `InventoryAsset`. Backward-compatible (all optional).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — add `--sorn` flag + env `CLOUD_EVIDENCE_SORN`; `--sorn-config <path>`, `--pull-privacy-records <tracker-url>`. `--sorn` runs BEFORE `--oscal-ssp` so SSP picks up back-matter resource.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add roles `sorn-draft-md`, `sorn-input-json`, `no-sorn-attestation` to `WELL_KNOWN`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-ssp.ts` — add SORN reference to `back-matter.resources[]` with `rel='sorn-draft'` when M.M1 emitted; SKIP when conditional `no-system-of-records-attested.json` ran (back-matter has `rel='no-sorn-attestation'` instead).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ksi-map.ts` — register `KSI-PRV-SORN` as process-artifact (no cloud collector dispatch).
- `tracker/server/schema.sql` — append `privacy_records` + `sorn_publications` tables (additive only; SQL in §Build steps).
- `tracker/server/index.ts` — mount privacy routes.
- `tracker/client/src/App.tsx` — add `/privacy/records` + `/privacy/sorn-publications` routes.

## Schemas / standards
- **5 U.S.C. §552a (e)(4)** — 11 statutory elements; verbatim text in `core/sorn-emit.ts` docstring header.
- **Federal Register SORN template** — 26 sections enumerated in `LOOP-M-SPEC.md` §4 (under "Federal Register / SORN template"). Markdown emit uses these as verbatim H2/H3 headers.
- **NIST SP 800-53 Rev 5 PT-6** — control statement; cited in cross-reference props.
- **OMB M-03-22 §II.C.1.f** — PIA-to-SORN cross-reference.
- **OSCAL SSP v1.1.2 back-matter** — `back-matter.resources[]` schema per https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/system-security-plan/json-reference/#/system-security-plan/back-matter/resources . `props[].ns = CE_NS = "https://cloud-evidence.example/oscal-ns"`.

## Build steps (concrete, numbered)
1. **Define `SornDraft` TypeScript interface** in `core/sorn-schema.ts` per the spec in LOOP-M-SPEC.md §5 (M.M1 build steps). Includes `RoutineUse` + `SornHistoryEntry` + administrative fields (agency, action, effective_date, comment_period_close, addresses_for_comments, POC fields) + 11 statutory §552a (e)(4) elements (system_name, system_number, security_classification, system_location, system_manager_title, system_manager_business_address, authority_for_maintenance, purpose, categories_of_individuals, categories_of_records, record_source_categories, routine_uses, storage_practices, retrieval_practices, retention_and_disposal, administrative_safeguards, technical_safeguards, physical_safeguards, record_access_procedures, contesting_procedures, notification_procedures, exemptions_claimed, history).
2. **Builder signature** in `core/sorn-emit.ts`:
   ```ts
   export interface SornEmitOptions {
     outDir: string;
     inventoryPath?: string;
     sornSnapshotPath?: string;             // tracker snapshot path (defaults to out/.sorn-snapshot.json)
     sornConfigPath?: string;               // operator config (optional)
     systemId: string;
     systemName: string;
     impactLevel: 'low' | 'moderate' | 'high';
     runId: string;
     strictPrivacy?: boolean;               // when true, REQUIRES-OPERATOR-INPUT fails the emit
   }
   export interface SornEmitResult {
     md_path: string | null;                // null when conditional-N/A
     json_path: string | null;
     skipped_reason?: 'no-system-of-records-attested';
     attestation_path?: string;             // when skipped, points at the signed attestation
     requires_operator_input: string[];     // field paths missing
     ready_for_signature: boolean;
   }
   export async function emitSorn(opts: SornEmitOptions): Promise<SornEmitResult>;
   ```
3. **Conditional emit** — `core/sorn-reader.ts` returns the snapshot from tracker; when EVERY row has `retrieval_by_identifier_attested === false`, the emitter returns `skipped_reason: 'no-system-of-records-attested'` and writes `out/no-system-of-records-attested.json` with the operator's signed attestation row payload (signature + signing_key_id + attested_by_user_id + attested_at + system_id). Otherwise builds the SORN draft.
4. **Auto-fill from inventory** — for each asset where `pii_categories` non-empty AND `retrieval_by_identifier === true`:
   - `categories_of_individuals` ← union of `asset.pii_subjects[]`.
   - `categories_of_records` ← union of `asset.pii_categories[]` mapped to human-readable phrases via the `PII_CATEGORY_LABELS` map (e.g. `ssn` → "Social Security numbers"). The map is a typed constant in `sorn-schema.ts` and is the ONLY allowed fixed-data block — categories of PII are documented in NIST SP 800-122 §2.1 so they are "published constants" per CLAUDE.md Rule 3.
   - `system_location` ← derived from `asset.location` + `asset.provider` (e.g. "AWS us-gov-west-1 RDS").
5. **Operator-supplied fields** flow through tracker (`privacy_records.legal_authority`, `routine_uses` JSON in `sorn_publications.draft_json`, `retention_and_disposal` per row) OR through `sorn-config.yaml`. Every field that is missing emits `REQUIRES-OPERATOR-INPUT: <field name> — set via tracker /privacy/sorn-publications/<sorn-uuid>` IN THE MARKDOWN, and is ABSENT IN THE JSON (never substituted with placeholder). `ready_for_signature = false` whenever any such marker is present.
6. **Markdown draft format** — emit `out/sorn-draft.md` with the 26 Federal Register section headers verbatim (enumerated in LOOP-M-SPEC.md §4). Any unsupplied field renders as `REQUIRES-OPERATOR-INPUT: <field name> — set via tracker /privacy/sorn-publications/<sorn-uuid>`.
7. **JSON output** — `out/sorn-input.json` is the canonical machine form; provenance block per REO Rule 2.6: `{ emitter: 'core/sorn-emit.ts', emittedAt: <ISO>, sourceCalls: ['tracker:sorn_publications:list', 'tracker:privacy_records:list', 'inventory.json:read'], signingKeyId: <id>, format_version: 'fed-reg.preview.2026' }`.
8. **OSCAL SSP back-matter integration** — after M.M1 ships, `core/oscal-ssp.ts:buildBackMatter()` reads the SORN emit result; appends:
   ```json
   {
     "uuid": "<deterministic, derived from runId + system_id>",
     "title": "System of Records Notice — draft",
     "rlinks": [
       { "href": "./sorn-draft.md", "media-type": "text/markdown" },
       { "href": "./sorn-input.json", "media-type": "application/json" }
     ],
     "props": [{ "name": "rel", "ns": "<CE_NS>", "value": "sorn-draft" }]
   }
   ```
   When conditional-skip ran, append the no-sorn-attestation resource instead (rel=`no-sorn-attestation`).
9. **Tracker DB tables**:
   ```sql
   CREATE TABLE IF NOT EXISTS privacy_records (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     system_id TEXT NOT NULL,
     pii_category TEXT NOT NULL,
     subject_category TEXT NOT NULL,
     legal_authority TEXT NOT NULL,
     retention_period_days INTEGER NOT NULL,
     retrieval_by_identifier_attested INTEGER NOT NULL CHECK (retrieval_by_identifier_attested IN (0,1)),
     attested_by_user_id INTEGER REFERENCES users(id),
     attested_at TEXT,
     signature TEXT,
     signing_key_id TEXT,
     created_at TEXT NOT NULL,
     updated_at TEXT NOT NULL
   );
   CREATE INDEX IF NOT EXISTS idx_pr_system ON privacy_records(system_id);
   CREATE INDEX IF NOT EXISTS idx_pr_category ON privacy_records(pii_category);

   CREATE TABLE IF NOT EXISTS sorn_publications (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     system_id TEXT NOT NULL,
     system_name TEXT NOT NULL,
     system_number TEXT NOT NULL,
     draft_json TEXT NOT NULL,
     status TEXT NOT NULL CHECK (status IN ('draft','submitted-to-agency','published','rescinded')),
     federal_register_volume TEXT,
     federal_register_page TEXT,
     publication_date TEXT,
     created_by_user_id INTEGER NOT NULL REFERENCES users(id),
     reviewed_by_saop_user_id INTEGER REFERENCES users(id),
     reviewed_at TEXT,
     created_at TEXT NOT NULL,
     updated_at TEXT NOT NULL
   );
   CREATE INDEX IF NOT EXISTS idx_sp_system ON sorn_publications(system_id);
   CREATE INDEX IF NOT EXISTS idx_sp_status ON sorn_publications(status);
   CREATE UNIQUE INDEX IF NOT EXISTS idx_sp_system_number ON sorn_publications(system_number);
   ```
10. **Bundler integration** — append to `WELL_KNOWN`:
    ```ts
    { role: 'sorn-draft-md', filename: 'sorn-draft.md', description: 'SORN — Federal Register draft (M.M1)' },
    { role: 'sorn-input-json', filename: 'sorn-input.json', description: 'SORN structured input (M.M1)' },
    { role: 'no-sorn-attestation', filename: 'no-system-of-records-attested.json', description: 'Signed attestation no §552a system exists (M.M1 conditional)' },
    ```
11. **Wire orchestrator** — `--sorn` runs before `--oscal-ssp` so SSP back-matter picks up the resource.
12. **Sign + timestamp** — all three potential outputs (sorn-draft.md, sorn-input.json, no-system-of-records-attested.json) picked up by existing `core/sign.ts` glob; included in RFC 3161 manifest.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4, every field that cannot be auto-derived:

| Field | Source | Behavior when missing |
|---|---|---|
| `agency` | `org-profile.yaml` `customer.agency_name` or CLI flag `--customer-agency` | Renders as `REQUIRES-OPERATOR-INPUT: agency` in MD; absent in JSON; `ready_for_signature = false` |
| `authority_for_maintenance[]` | Tracker `privacy_records.legal_authority` (per system) | Same — never substitute a default statute |
| `routine_uses[]` | Tracker UI `/privacy/sorn-publications/<id>/edit` (structured array) | Same — cannot be inferred from inventory |
| `retention_and_disposal` | Tracker `privacy_records.retention_period_days` + NARA schedule citation (operator-supplied) | Same |
| `system_manager_title` + `system_manager_business_address` | `org-profile.yaml` `privacy.system_manager` | Same |
| `record_access_procedures` | Operator config (template language can be suggested but operator must adopt explicitly via tracker review) | Same |
| `contesting_procedures` | Operator config | Same |
| `notification_procedures` | Operator config | Same |
| `exemptions_claimed[]` | Operator config (most CSOs claim none; explicit empty array required) | Empty array MUST be explicit; absent → REQUIRES-OPERATOR-INPUT |
| `effective_date` + `comment_period_close` | Operator config (typically effective_date = today + 60d, comment_period = effective_date - 30d) | Operator confirms via tracker — never default |
| `poc_name` + `poc_email` + `poc_phone` | `org-profile.yaml` `privacy.public_contact` | REQUIRES-OPERATOR-INPUT when absent |
| Conditional-skip attestation `attested_by_user_id` | Tracker user with `saop` role | Hard-error if no user with that role |

## Test specifications (≥14 tests)
1. `it('emits no-system-of-records-attested.json when retrieval_by_identifier_attested=false for all systems')` — conditional path; verifies signed attestation written.
2. `it('emits full SORN draft when at least one system has retrieval_by_identifier_attested=true')`.
3. `it('renders all 26 Federal Register section headers in the markdown output')` — assert exact header strings.
4. `it('emits REQUIRES-OPERATOR-INPUT for every unsupplied statutory element')` — set up tracker snapshot missing routine_uses, verify marker rendered.
5. `it('auto-fills categories_of_individuals from inventory pii_subjects union')`.
6. `it('auto-fills categories_of_records from inventory pii_categories mapped via PII_CATEGORY_LABELS')` — input `['ssn','biometric']` → output `['Social Security numbers','Biometric records']`.
7. `it('renders structured routine_uses array with id + description + users + purpose in markdown')`.
8. `it('refuses to emit when authority_for_maintenance is empty AND any system requires SORN')` — never silently fall through; `ready_for_signature = false`.
9. `it('emits sorn-input.json with provenance.emitter + emittedAt + sourceCalls + signingKeyId')`.
10. `it('refuses ready_for_signature when any REQUIRES-OPERATOR-INPUT marker present')`.
11. `it('OSCAL SSP back-matter gains sorn-draft resource after M.M1 runs')`.
12. `it('OSCAL SSP back-matter gains no-sorn-attestation resource when conditional-skip ran')`.
13. `it('registers KSI-PRV-SORN process-artifact in ksi-map')`.
14. `it('tracker route POST /privacy/sorn-publications creates draft with SAOP review required')`.
15. `it('tracker route enforces system_number uniqueness per agency')`.
16. `it('snapshot reader verifies Ed25519 signature on every privacy_records row')`.
17. `it('bundle includes sorn-draft-md role + sorn-input-json role')`.
18. `it('bundle includes no-sorn-attestation role when conditional-skip ran')`.
19. `it('CHANGELOG entry for M.M1 cites verbatim 5 U.S.C. §552a (e)(4)')` — assert citation marker.
20. `it('strictPrivacy mode hard-errors when any REQUIRES-OPERATOR-INPUT marker present')`.

## REO compliance
- Every value in `sorn-input.json` traces to: inventory.json read, tracker DB row (signed), or operator config — NO silent defaults.
- `agency`, `system_manager_*`, `authority_for_maintenance[]`, `routine_uses[]`, `retention_and_disposal` are ALL operator-supplied; collector NEVER fabricates.
- `categories_of_individuals` + `categories_of_records` are inventory-derived via tag-honouring (set by INV-S6 pipeline + extended in M.M1).
- `PII_CATEGORY_LABELS` is the only fixed-data constant; falls under CLAUDE.md Rule 3 ("NIST publication identifiers" — categories enumerated in NIST SP 800-122 §2.1).
- Provenance block populated per REO Rule 2.6.
- Signed by existing `core/sign.ts` pipeline (Ed25519 + RFC 3161 manifest).
- Conditional skip (`no-system-of-records-attested`) is itself a signed attestation, NOT a silent omission — preserves REO Rule 5 ("Silent fallbacks that mask missing data" PROHIBITED).
- No `process.env.NODE_ENV === 'test'` branches; tests inject seams via DI'd HTTP fetcher and filesystem helper.

## Verification commands
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/sorn-emit.test.ts tests/core/sorn-schema.test.ts tests/core/sorn-reader.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
cd ../tracker
npm run typecheck
npm test -- server/routes/privacy-records.test.ts server/routes/sorn-publications.test.ts
```

## Known risks / issues
- **Risk 1: Conditional applicability ambiguity** — operator may be unsure whether the CSO maintains a §552a system. Mitigation: tracker `privacy_records` page surfaces a decision tree mirroring §552a (a)(5) "system of records" definition; SAOP signs the attestation; legal review prompt before submit.
- **Risk 2: PII category tag coverage incomplete** — many CSPs have not back-tagged assets with `fedramp_pii_categories`. Mitigation: REQUIRES-OPERATOR-INPUT visibly on every affected SORN section; documented in operator runbook with example `aws ec2 create-tags` + `gcloud labels add` commands; inventory-coverage report tracks fill rates.
- **Risk 3: Federal Register template format drift** — the 26-section structure may be revised by GPO. Mitigation: `format_version: 'fed-reg.preview.2026'` in JSON output; CHANGELOG entry pins version; future migration is a separate slice.
- **Risk 4: Cross-system snapshot age skew** — multiple tracker tables pulled at different times; an attestation could be revoked between two pulls. Mitigation: snapshot reader stamps `fetched_at` per table; orchestrator's `--strict-privacy` mode requires all snapshots within 5 minutes.
- **Risk 5: Ed25519 signing-key drift between tracker + cloud-evidence** — tracker signs attestations; cloud-evidence verifies. Per LOOP-B B-X3 pattern, tracker must expose `GET /api/sign/public-keys` historical registry.

## Open questions
- **Q1**: Does the CSO process Privacy-Act-protected records retrievable by identifier on behalf of a federal agency? (Resolves applicability per ADDITIONAL-LOOPS-AUDIT §5 Q2.) Operator must answer before slice starts.
- **Q2**: For multi-tenant CSOs, is the SORN per-tenant or aggregate? Recommend: per-system_id (one SORN per CSO-system, agency may bundle).
- **Q3**: When the agency submits the SORN to the Federal Register, do we ingest the publication metadata (FR volume + page) back into `sorn_publications.federal_register_*`? Recommend: yes, agency-side UI flow updates the row post-publication.
- **Q4**: Should we ship a SORN diff tool comparing draft versions? Recommend: out of scope for M.M1; file as follow-up (M.M5 candidate).
- **Q5**: Does `PII_CATEGORY_LABELS` need internationalisation? Recommend: no (SORN is English by statute); document in README.
- **Q6**: How do we handle exemptions claimed under §552a (j) / (k)? Recommend: operator-supplied free text per exemption; future slice could structure (j)(2) law-enforcement etc.

## Implementation log
(empty — implementing session fills this in as work progresses)

## Completion checklist
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥20 for this slice)
- [ ] check:reo green (G1 + G2 + G3)
- [ ] STATUS.md updated (slice row + Overall section)
- [ ] LOOP-M-SPEC.md status row updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added with verbatim §552a (e)(4) citation
- [ ] Commit with slice ID in message
- [ ] Commit amended with commit hash recorded
- [ ] Pushed to origin/main
- [ ] LOOP-M-RISKS.md updated with any new risks surfaced

## Resume-from-fresh-session checklist
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. Read this file in full — frontmatter + build steps + tests + risks + completion checklist are exhaustive.
3. Read `cloud-evidence/docs/loops/LOOP-M-SPEC.md` §1, §3, §4, §5 (M.M1 sub-section), §10 (verbatim §552a (e)(4)) for cross-loop context.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory 7-step commit pattern.
5. Read `cloud-evidence/core/inventory.ts` (`InventoryAsset` interface — your extension point) + `cloud-evidence/core/oscal-ssp.ts` `buildBackMatter()` (your second extension point) + `cloud-evidence/core/submission-bundle.ts` `WELL_KNOWN` (your third).
6. Resolve open Q1 (Privacy Act applicability) with the operator BEFORE any code lands. If "no", proceed with the conditional-skip path only.
7. Begin implementation; update the Implementation log section at every meaningful milestone.

---
