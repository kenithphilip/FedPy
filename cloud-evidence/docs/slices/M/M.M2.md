---
slice_id: M.M2
title: Data Protection Impact Assessment (DPIA) for cross-border / agency-partner data
loop: M
status: pending
commit: —
completed_date: —
depends_on: [LOOP-A.A1, LOOP-A.A4, LOOP-C.C4, M.M1, INV-S6]
blocks: [M.M3, C.C7]
estimated_effort: 5-6 working days
last_updated: 2026-06-07
applicable_conditional: false
---

# M.M2 — Data Protection Impact Assessment (DPIA) for cross-border / agency-partner data

## TL;DR
PIA (LOOP-C.C4) covers the US-federal CSP-public surface per OMB M-03-22 §II.B.1. When data crosses jurisdictional boundaries (US ↔ EU under EU-US Data Privacy Framework), is shared with agency partners under Privacy Act §552a (o) Computer Matching Agreements, or triggers GDPR Article 35 "high risk to natural persons" analysis, the obligation becomes a **DPIA** — a deeper analysis with explicit risk × mitigation matrix, necessity + proportionality argument, and DPO recommendation. This slice emits `out/dpia.json` + `out/dpia.docx`.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
- **Reads `inventory.json`** — derives `trigger.jurisdictions` from `inventory.assets[].location` via the region → country mapping table (`AWS_REGION_TO_COUNTRY`, `GCP_REGION_TO_COUNTRY`, `AZURE_REGION_TO_COUNTRY` — all published cloud constants per CLAUDE.md Rule 3).
- **Reads M.M1 snapshot** — `out/.sorn-snapshot.json` provides Privacy-Act-system metadata used to populate `processing_description.legal_basis` and detect computer-matching-agreement trigger.
- **Reads tracker `dpia_findings`** — operator-authored risks + mitigations + consultations + decision. The emitter **consumes** rows; it NEVER fabricates risks.
- **Process-artifact KSI** — registers `KSI-PRV-DPIA` in `core/ksi-map.ts`.
- **OSCAL SSP back-matter** — adds `rel='dpia'` entry pointing at both `.json` + `.docx`.
- **Submission bundler** — adds `dpia-json` + `dpia-docx` roles.
- **REO standard** — risks + mitigations + consultations are operator-authored signed tracker rows; legal_mechanism per data transfer is operator-supplied (cannot be inferred from cloud SDK output); decision is signed by SAOP or AO role.

## Why this slice exists
M-03-22 §II.B PIA covers the US-federal CSP-public surface. It does NOT cover:
- **Cross-jurisdictional data flows** — when a federal agency's data, processed by this CSO, crosses borders (e.g. CSO multi-region replication US ↔ EU; agency partners abroad).
- **Inter-agency sharing under Computer Matching Agreements** — Privacy Act §552a (o) requires a specific written agreement, Data Integrity Board approval, and Federal Register notice.
- **GDPR Article 35 high-risk processing** — when a federal agency holds EU-resident data and contracts a US CSP for processing, GDPR Article 35 applies and demands the deeper DPIA analysis.

The DPIA emit covers all three triggers in a single artifact with structured risk × mitigation matrix.

## Authoritative sources (with verbatim quotes)
- **GDPR Article 35 "Data protection impact assessment"** — https://gdpr-info.eu/art-35-gdpr/ verbatim:
  > "Where a type of processing in particular using new technologies, and taking into account the nature, scope, context and purposes of the processing, is likely to result in a high risk to the rights and freedoms of natural persons, the controller shall, prior to the processing, carry out an assessment of the impact of the envisaged processing operations on the protection of personal data."
  > Art. 35(7) required DPIA content: "(a) a systematic description of the envisaged processing operations and the purposes of the processing, including, where applicable, the legitimate interest pursued by the controller; (b) an assessment of the necessity and proportionality of the processing operations in relation to the purposes; (c) an assessment of the risks to the rights and freedoms of data subjects referred to in paragraph 1; and (d) the measures envisaged to address the risks, including safeguards, security measures and mechanisms to ensure the protection of personal data..."
- **OMB M-03-22 §II.C** — PIA content requirements (superset adopted in M.M2 schema as `processing_description`): data collected, purpose(s), intended use, sharing, notice/consent, security, SORN cross-reference.
- **Privacy Act §552a (o) Computer Matching Agreements** — Cornell LII verbatim:
  > "No record which is contained in a system of records may be disclosed to a recipient agency or non-Federal agency for use in a computer matching program except pursuant to a written agreement between the source agency and the recipient agency or non-Federal agency specifying — (A) the purpose and legal authority for conducting the program; (B) the justification for the program and the anticipated results, including a specific estimate of any savings; (C) a description of the records that will be matched, including each data element that will be used, the approximate number of records that will be matched, and the projected starting and completion dates of the matching program; (D) procedures for providing individualized notice...; (E) procedures for verifying information produced in such matching program...; (F) procedures for the retention and timely destruction of identifiable records...; (G) procedures for ensuring the administrative, technical, and physical security..."
  Drives M.M2 CMA-trigger field set + cross-references M.M3 PT-8.
- **EU-US Data Privacy Framework** — https://www.dataprivacyframework.gov/ replaces Privacy Shield (struck down 2020). When EU-resident data is in scope, `data_transfers[].legal_mechanism = 'eu-us-dpf'` is the dominant choice.
- **OMB Circular A-130 Appendix II** — privacy controls + DPIA pattern (informs section-level mapping).
- **NIST SP 800-30 Rev 1 §3.2** — risk likelihood × severity bands; reused VERBATIM in DPIA risk-assessment schema (already in LOOP-B.B5 organisational-risks).

## Files to create (exact paths under cloud-evidence/)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dpia-emit.ts` — ~700 lines. Emits `out/dpia.json` + `out/dpia.docx`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dpia-schema.ts` — typed DPIA model (Article 35(7) aligned + M-03-22 §II.C superset). Includes `Dpia`, `DpiaTrigger`, `ProcessingDescription`, `DataTransfer`, `DpiaRisk`, `DpiaMitigation`, `ConsultationRecord`, `NecessityProportionalityAnalysis`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dpia-reader.ts` — HTTP client; pulls `dpia_findings` rows from tracker; writes signature-verified snapshot at `out/.dpia-snapshot.json`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/region-jurisdiction.ts` — published mapping table `{ provider, region } → ISO 3166-1 alpha-2 country code`. Sourced from AWS/GCP/Azure published region lists (Rule 3 allowed fixed data).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/dpia-emit.test.ts` — ≥13 tests (enumerated below).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/dpia-schema.test.ts` — typed schema tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/dpia-reader.test.ts` — snapshot + signature tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/region-jurisdiction.test.ts` — mapping coverage tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/dpia/` — sample inventory + tracker snapshot fixtures.
- `tracker/server/routes/dpia-findings.ts` — CRUD; enforces DPO + SAOP role sign-offs.
- `tracker/client/src/pages/Dpia.tsx` — UI page with risk-assessment matrix editor + mitigation linker + DPO recommendation form.
- `tracker/server/routes/dpia-findings.test.ts`.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — `--dpia` + env `CLOUD_EVIDENCE_DPIA`; `--dpia-trigger=<reason>` for explicit high-risk-processing assertion; `--dpia-config <path>`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add `dpia-json` + `dpia-docx` roles to `WELL_KNOWN`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-ssp.ts` — `back-matter.resources[]` gains `rel='dpia'`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ksi-map.ts` — register `KSI-PRV-DPIA` process-artifact.
- `tracker/server/schema.sql` — `dpia_findings` table (additive).
- `tracker/server/index.ts` — mount route.
- `tracker/client/src/App.tsx` — add `/privacy/dpia` route.

## Schemas / standards
- **GDPR Article 35(7)** — 4 mandatory DPIA content sections (a/b/c/d) verbatim in `dpia-emit.ts` header docstring.
- **OMB M-03-22 §II.C** — PIA superset.
- **Privacy Act §552a (o)** — CMA scaffold (7 fields A-G).
- **EU-US Data Privacy Framework** — `legal_mechanism` enum value `'eu-us-dpf'`.
- **NIST SP 800-30 Rev 1** — likelihood × severity bands (5-point: very-low..very-high).
- **OOXML / .docx** — emit follows the same `core/ssp-docx.ts` zip-store deterministic pattern (reused).

## Build steps (concrete, numbered)
1. Define `Dpia` + nested types in `core/dpia-schema.ts` per LOOP-M-SPEC.md §5 (M.M2 build steps). Includes `DpiaTrigger`, `ProcessingDescription` (purposes, legal_basis, pii_categories, data_subjects, data_recipients, data_transfers[], retention_periods), `DataTransfer` (source_jurisdiction, destination_jurisdiction, legal_mechanism, volume_estimate), `DpiaRisk` (id, description, likelihood, severity, affected_population_size, inherent_risk), `DpiaMitigation` (risk_id, description, control_ids[], residual_likelihood, residual_severity), `ConsultationRecord` (consulted_party, consulted_role, date, summary), `NecessityProportionalityAnalysis` (necessity_argument, proportionality_argument, alternatives_considered[]), `decision` ∈ {approved, approved-with-conditions, rejected, pending}.
2. **Auto-derive `trigger`**:
   - If `inventory.assets[].location` spans more than one country (via `region-jurisdiction.ts` lookup): `cross-jurisdictional`.
   - If tracker `privacy_records` rows have any `partner_agencies` non-empty: `agency-partner-sharing`.
   - If `cma_reference` set in config OR any tracker row indicates a CMA: `computer-matching-agreement`.
   - Else: only if operator explicitly sets `--dpia-trigger=high-risk` (NO silent default).
3. **Auto-fill `processing_description`**:
   - `purposes[]` ← M.M3 PT-3 purposes register (when M.M3 has shipped) OR tracker `pt_control_evidence` for PT-3.
   - `pii_categories[]` ← inventory `pii_categories` union.
   - `data_subjects[]` ← inventory `pii_subjects` union.
   - `data_transfers[]` ← derived from each (source_jurisdiction, destination_jurisdiction) pair detected from inventory; per pair, `legal_mechanism` is REQUIRES-OPERATOR-INPUT until tracker row supplies.
   - `legal_basis[]` ← operator config OR tracker per-purpose row.
   - `retention_periods` ← per-pii-category days from M.M1 `privacy_records.retention_period_days`.
4. **Risk assessment** — operator-authored via tracker `dpia_findings` table; each row = one `DpiaRisk`. The emitter consumes; never generates risks.
5. **Mitigations** — same pattern; emitter consumes operator-authored mitigation rows.
6. **Residual risk** — computed as `max(residual_likelihood, residual_severity)` band per mitigation. If any risk lacks mitigation: `residual_risk = REQUIRES-OPERATOR-INPUT` and `ready_for_signature = false`.
7. **DPIA `.json` emit** — full `Dpia` object with provenance block per REO Rule 2.6.
8. **DPIA `.docx` emit** — reuse OOXML + zip-store pattern from `core/roe-emit.ts` + `core/ssp-docx.ts`. 8 sections:
   1. Cover page (system name, impact level, DPIA date, decision).
   2. Trigger + Scope.
   3. Processing Description.
   4. Necessity and Proportionality.
   5. Risk Assessment (table).
   6. Mitigations (table).
   7. Consultations.
   8. Residual Risk + DPO Recommendation + Decision + Sign-off block.
9. **OSCAL SSP back-matter** — `rel='dpia'` entry pointing at `./dpia.json` + `./dpia.docx`.
10. **Tracker DB**:
    ```sql
    CREATE TABLE IF NOT EXISTS dpia_findings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      uuid TEXT NOT NULL UNIQUE,
      dpia_uuid TEXT NOT NULL,
      finding_type TEXT NOT NULL CHECK (finding_type IN ('risk','mitigation','consultation','decision','necessity','proportionality')),
      description TEXT NOT NULL,
      likelihood TEXT CHECK (likelihood IN ('very-low','low','moderate','high','very-high')),
      severity TEXT CHECK (severity IN ('very-low','low','moderate','high','very-high')),
      affected_population_size INTEGER,
      control_ids TEXT,
      linked_risk_uuid TEXT,
      authored_by_user_id INTEGER NOT NULL REFERENCES users(id),
      authored_at TEXT NOT NULL,
      reviewed_by_dpo_user_id INTEGER REFERENCES users(id),
      reviewed_by_saop_user_id INTEGER REFERENCES users(id),
      reviewed_at TEXT,
      signature TEXT NOT NULL,
      signing_key_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_df_dpia ON dpia_findings(dpia_uuid);
    CREATE INDEX IF NOT EXISTS idx_df_type ON dpia_findings(finding_type);
    CREATE INDEX IF NOT EXISTS idx_df_linked ON dpia_findings(linked_risk_uuid);
    ```
11. **Wire orchestrator** — `--dpia` runs AFTER `--sorn` (consumes M.M1 snapshot) and BEFORE `--oscal-ssp` (so SSP back-matter picks up resource).
12. **Bundler** — add `dpia-json` + `dpia-docx` to `WELL_KNOWN`.
13. **Sign + timestamp** — both files in manifest glob; deterministic OOXML zip-store ensures stable SHA-256 for re-signing.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4:

| Field | Source | Behavior when missing |
|---|---|---|
| `trigger.reason` (when not auto-derivable) | CLI `--dpia-trigger=<reason>` or operator config | Default: NO silent default. Strict mode hard-error |
| `risk_assessment[]` | Tracker UI authoring (DPO + SAOP review) | DPIA marked `ready_for_signature=false`; `requires_operator_input` lists field |
| `mitigations[]` | Tracker UI | Same — DPIA cannot ship without mitigations |
| `consultation[]` | Tracker UI | Optional but documented; absence flagged in JSON `consultation_absent_rationale` (operator-supplied) |
| `legal_basis[]` | Operator config or tracker per-purpose row | Never default — REQUIRES-OPERATOR-INPUT |
| `data_transfers[].legal_mechanism` | Operator must classify each transfer | Default: REQUIRES-OPERATOR-INPUT; strict mode hard-error |
| `residual_risk` | Computed from mitigation matrix | If any risk lacks mitigation → REQUIRES-OPERATOR-INPUT |
| `dpo_recommendation` | Tracker UI by user with `dpo` role | REQUIRES-OPERATOR-INPUT |
| `decision` | Tracker UI by user with `saop` or `ao` role | Defaults to `pending` (NOT silent; explicit pending status) |
| `necessity_argument` + `proportionality_argument` | Operator config or tracker `necessity`/`proportionality` rows | REQUIRES-OPERATOR-INPUT |

## Test specifications (≥13 tests)
1. `it('auto-detects cross-jurisdictional trigger when inventory spans US + EU regions')` — fixture with `us-east-1` + `eu-west-1` assets.
2. `it('auto-detects agency-partner-sharing when tracker privacy_records.partner_agencies set')`.
3. `it('detects computer-matching-agreement trigger when cma_reference set')`.
4. `it('requires explicit --dpia-trigger=high-risk; never silent default')`.
5. `it('aggregates pii_categories from inventory.assets across providers')`.
6. `it('builds data_transfers per (source_jurisdiction, destination_jurisdiction) pair')`.
7. `it('rejects transfer without legal_mechanism under --strict-privacy')`.
8. `it('consumes risk_assessment from tracker; emitter never synthesizes risks')`.
9. `it('emits dpia.json with provenance.emitter + sourceCalls + signingKeyId')`.
10. `it('emits dpia.docx with 8 sections in correct order')`.
11. `it('OSCAL SSP back-matter gains dpia resource')`.
12. `it('registers KSI-PRV-DPIA process-artifact')`.
13. `it('tracker dpia_findings row signed with tracker Ed25519 key')`.
14. `it('residual_risk computed from worst remaining (likelihood,severity) cell')`.
15. `it('refuses ready_for_signature when any risk lacks mitigation')`.
16. `it('region-jurisdiction table covers all current AWS commercial + GovCloud regions')`.
17. `it('legal_mechanism enum accepts eu-us-dpf only when transfer source=EU AND destination=US')`.
18. `it('docx zip-store is deterministic across runs (same SHA-256)')`.
19. `it('decision defaults to pending; never approved/rejected silently')`.
20. `it('CHANGELOG entry for M.M2 cites verbatim GDPR Article 35(1)')`.

## REO compliance
- All risks + mitigations + consultations + decisions are operator-authored signed tracker rows.
- `data_transfers[]` source/destination are inventory-derived (real evidence); legal mechanism is operator-supplied per transfer.
- No silent risk-acceptance; explicit `decision` field with audit trail.
- `region-jurisdiction.ts` is CLAUDE.md Rule 3 allowed fixed data (published cloud constants).
- Provenance block on `dpia.json`.
- `.docx` zip-store deterministic for stable signing.
- Signed by existing `core/sign.ts` pipeline.
- No `process.env.NODE_ENV === 'test'` branches.

## Verification commands
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/dpia-emit.test.ts tests/core/dpia-schema.test.ts tests/core/dpia-reader.test.ts tests/core/region-jurisdiction.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
cd ../tracker
npm run typecheck
npm test -- server/routes/dpia-findings.test.ts
```

## Known risks / issues
- **Risk 1: Region-jurisdiction mapping drift** — clouds add new regions; the table needs updates. Mitigation: source URLs in module docstring; test enumerates current regions; CI annual reminder.
- **Risk 2: GDPR applicability ambiguity** — many federal CSPs serve only US-federal users. Mitigation: `--dpia-jurisdictions=US-only` flag short-circuits cross-jurisdictional analysis; documented in operator runbook.
- **Risk 3: DPO role mapping missing** — tracker RBAC must add `dpo` role for sign-offs. Per LOOP-B B-X5 pattern, first-boot prompt for role assignment.
- **Risk 4: Risk × mitigation matrix double-counting** — if a risk references multiple mitigations, residual computation should de-duplicate. Mitigation: documented in code; tests pin behavior.
- **Risk 5: Cross-loop integration with M.M3 PT-3 purposes register** — when M.M3 hasn't shipped yet, purposes auto-fill falls back to tracker `pt_control_evidence` directly. Mitigation: documented; M.M2 ships AFTER M.M1 but does NOT block on M.M3 (independent paths).
- **Risk 6: Article 35(7) interpretation drift** — EU regulators publish guidance updates. Mitigation: schema versioned via `dpia_format_version`; updates handled as follow-up slices.
- **Risk 7: DOCX SHA-256 instability across OOXML library updates** — zip-store + deterministic timestamps required. Mitigation: reuse the proven `core/ssp-docx.ts` pattern (already verified deterministic).

## Open questions
- **Q1**: Should cross-cloud (AWS → GCP) intra-US transfers trigger DPIA? Recommend: no (single jurisdiction = US-federal only).
- **Q2**: How do we handle FedRAMP High GovCloud-only deployments? Recommend: `us-gov-*` regions map to US; never cross-jurisdictional; documented.
- **Q3**: Does the docx need agency branding? Recommend: no, generic template; agencies re-brand on submit.
- **Q4**: Where does the DPO recommendation sit when no DPO is appointed (small agency)? Recommend: SAOP fulfils DPO role; tracker accepts `saop` user for `dpo` review field.
- **Q5**: Should we ingest CISA CIRCIA reporting requirements as a fifth DPIA trigger? Recommend: out of scope for M.M2; file as follow-up.
- **Q6**: For aggregated multi-system DPIAs (one DPIA covering several CSO components), is the schema's `system_id` field singular or array? Recommend: singular, with one DPIA per CSO-system; aggregation handled at the SSP back-matter layer.
- **Q7**: How do we handle a DPIA decision reversal (initially approved, later rejected on review)? Recommend: tracker `dpia_findings.finding_type='decision'` allows multiple decision rows; emit consumes latest by `authored_at`.
- **Q8**: Should the necessity + proportionality analysis section be free-text or structured? Recommend: structured fields (`necessity_argument`, `proportionality_argument`, `alternatives_considered[]`) per Article 35(7)(b); operator authors prose per field.
- **Q9**: When operator declares `--dpia-trigger=high-risk`, does the auto-derived trigger detection still run? Recommend: yes; both flags are surfaced in JSON `trigger.detected_reasons[]` AND `trigger.declared_reason`; final `trigger.reason` is the union.

## Implementation log
(empty — implementing session fills this in as work progresses)

## Completion checklist
- [ ] typecheck clean
- [ ] tests passing 100% (count increased by ≥20)
- [ ] check:reo green
- [ ] STATUS.md updated
- [ ] LOOP-M-SPEC.md status row updated
- [ ] This file's frontmatter updated
- [ ] CHANGELOG.md "Unreleased" entry with verbatim GDPR Article 35(1) citation
- [ ] Commit with slice ID
- [ ] Commit amended with hash
- [ ] Pushed to origin/main
- [ ] LOOP-M-RISKS.md updated with new risks

## Resume-from-fresh-session checklist
1. Read `cloud-evidence/CLAUDE.md` (REO standard).
2. Read this file.
3. Read `cloud-evidence/docs/loops/LOOP-M-SPEC.md` §1, §3, §4, §5 (M.M2 sub-section).
4. Read `cloud-evidence/docs/slices/M/M.M1.md` — M.M2 depends on the M.M1 SORN snapshot pattern.
5. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
6. Read `cloud-evidence/core/ssp-docx.ts` + `core/roe-emit.ts` — your deterministic OOXML zip-store pattern reference.
7. Read `cloud-evidence/core/oscal-ssp.ts` `buildBackMatter()` — your second extension point.
8. Begin implementation; update Implementation log at every milestone.

---
