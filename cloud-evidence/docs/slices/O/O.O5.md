---
slice_id: O.O5
title: Model card + datasheet emitter (Mitchell + Gebru)
loop: O
status: pending
commit: —
completed_date: —
depends_on: [O.O1, O.O2, O.O4]
blocks: [C.C7, I.I1]
estimated_effort: 4-5 working days
last_updated: 2026-06-07
applicable_conditional: true
---

# O.O5 — Model card + datasheet emitter (Mitchell + Gebru)

## TL;DR
Emit one Markdown Model Card per `AiAsset` in `ai-inventory.json` and one Markdown Datasheet per distinct `training_data_source`. The Model Card follows Mitchell et al. (2018)'s nine sections verbatim; the Datasheet follows Gebru et al. (2018)'s seven sections verbatim. Content is operator-supplied via tracker form (or `config/ai-inventory.yaml` extensions); FedPy assembles + signs + bundles. For vendor models (e.g. Anthropic-published Claude card), the operator records the vendor URL + sha256 — FedPy never duplicates vendor content.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
O.O5 is a *process-artifact emitter*: section content is operator-supplied or auto-derived from `ai-inventory.json` data; FedPy renders the Markdown, computes the sidecar JSON, signs both, and ships them in the submission bundle. Auto-derived fields (`Model Details / Model date` ← `AiAsset.deployment_date`) are recorded in `synthesized_fields[]` per REO Rule 1.7. Vendor-published model cards are stored as URL + sha256 — never copied without attribution. The SSP back-matter resources are extended with two new types (`model-card`, `datasheet`); the submission bundle gains two new roles (`model-cards-bundle`, `datasheets-bundle`). The slice closes NIST AI RMF MEASURE 2.8 + 2.9 (transparency, explainability) — verbatim cited above in LOOP-O-SPEC.md.

## Why this slice exists
Per NIST AI RMF:
- MEASURE 2.8: "Risks associated with transparency and accountability – as identified in the map function – are examined and documented."
- MEASURE 2.9: "The AI model is explained, validated, and documented, and AI system output is interpreted within its context."

Per Mitchell et al. (2018), each model deployed in a CSO benefits from a structured Model Card (nine sections). Per Gebru et al. (2018), each training/eval dataset benefits from a structured Datasheet (seven sections). Today the FedPy submission bundle has no Model Card or Datasheet artifacts. Without O.O5:
- The 3PAO assessment package has no transparency artifact per model.
- The agency procurement record (M-25-21) has no documentation artifact per model.
- SSP back-matter has no `model-card` / `datasheet` resource type.

## Authoritative sources (with verbatim quotes)
- **Mitchell et al. (2018) — "Model Cards for Model Reporting"** — https://arxiv.org/abs/1810.03993 — proposes nine sections (each with sub-fields verbatim from §3):
  1. **Model Details** — person/org developing the model, model date, model version, model type, training algorithms / parameters / fairness constraints, paper/citation, license, where to send questions.
  2. **Intended Use** — primary intended uses, primary intended users, out-of-scope use cases.
  3. **Factors** — relevant factors, evaluation factors.
  4. **Metrics** — model performance measures, decision thresholds, variation approaches.
  5. **Evaluation Data** — datasets, motivation, preprocessing.
  6. **Training Data** — link to Datasheet for Datasets if available.
  7. **Quantitative Analyses** — unitary results, intersectional results.
  8. **Ethical Considerations** — data, human life, mitigations, risks and harms, use cases.
  9. **Caveats and Recommendations** — additional concerns + suggestions.

- **Gebru et al. (2018) — "Datasheets for Datasets"** — https://arxiv.org/abs/1803.09010 — proposes seven sections (each with numbered questions verbatim from §3):
  1. **Motivation** — why created, who funded, comments.
  2. **Composition** — what instances, how many, sampling, data per instance, labels, missing info, relationships, recommended splits, errors, external resources, confidential data, offensive content, sub-populations, individual identification, sensitive data.
  3. **Collection Process** — how acquired, mechanisms, sampling strategy, who, timeframe, ethical-review processes, consent, mechanism for revoking consent, analyses of impact.
  4. **Preprocessing/Cleaning/Labeling** — what was done, raw data saved, software used.
  5. **Uses** — what has been done, repository, what could/should not be used for.
  6. **Distribution** — distribution mechanism, when, license, IP restrictions, export controls.
  7. **Maintenance** — who maintains, contact, erratum mechanism, update cadence, retention.

- **NIST AI 100-1 MEASURE 2.8 + 2.9** — quoted above.

- **OMB M-25-21 — procurement record requirements** — https://www.whitehouse.gov/wp-content/uploads/2025/03/M-25-21-Memorandum.pdf — model documentation is a procurement-record artifact.

- **OSCAL SSP v1.1.2 `back-matter.resources[]`** — https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/system-security-plan/json-reference/ — `resource.type` allows custom strings; `model-card` and `datasheet` are introduced as our types in `CE_NS`.

## Files to create (exact paths under cloud-evidence/)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/model-card.ts` — emitter. ~500 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/datasheet.ts` — emitter. ~400 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/model-card-template.generated.md` — canonical template extracted from Mitchell et al. §3.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/datasheet-template.generated.md` — canonical template extracted from Gebru et al. §3.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/scripts/extract-model-card-template.mjs` — extraction script (reads `docs/sources/mitchell-2018.pdf`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/scripts/extract-datasheet-template.mjs` — extraction script (reads `docs/sources/gebru-2018.pdf`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/model-card.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/datasheet.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/scripts/extract-model-card-template.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/scripts/extract-datasheet-template.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/model-card/` — sample sections, vendor card stub.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/datasheet/` — sample sections.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-ssp.ts` — `back-matter.resources[]` gets entries of type `model-card` and `datasheet` with `rlinks[]` pointing to bundle paths + sha256.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add roles `model-cards-bundle` (filename pattern `model-cards/*.md` + `model-cards/*.json`) and `datasheets-bundle` (pattern `datasheets/*.md` + `datasheets/*.json`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — flag `--model-cards` + env; runs AFTER `--ai-inventory` + `--ai-evaluation`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/schema.sql` — add `model_cards` + `datasheets` tables.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/model-cards.ts` — CRUD + signed-evidence upload.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/datasheets.ts` — CRUD.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/ModelCards.tsx` — form-based editor per model card.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/Datasheets.tsx` — form-based editor per dataset.

## Schemas / standards
- **Mitchell 2018 §3 sections** — nine sections, each carrying a fixed sub-field set (verbatim from the paper). Each section is a typed interface in `core/model-card.ts`.
- **Gebru 2018 §3 sections** — seven sections, each carrying a fixed numbered-question set (verbatim). Each section is a typed interface in `core/datasheet.ts`.
- **Markdown output** — pure-text rendering; no images embedded; vendor card path stores URL + sha256 (no embedded binary).
- **JSON sidecar** — per Model Card / Datasheet, a sibling `<id>.json` carries the structured representation + provenance + signature.
- **OSCAL SSP back-matter resource type** — custom strings `model-card` and `datasheet` in `CE_NS` namespace.
- **Ed25519 over canonical JSON** — signature over the sidecar JSON.

## Build steps (concrete, numbered)

1. Extraction scripts:
   - `scripts/extract-model-card-template.mjs` reads `docs/sources/mitchell-2018.pdf` and emits `core/model-card-template.generated.md` — the canonical Markdown skeleton with verbatim section prompts.
   - `scripts/extract-datasheet-template.mjs` reads `docs/sources/gebru-2018.pdf` and emits `core/datasheet-template.generated.md`.
   - Both record `catalog_source` header in the generated file: PDF sha256, extraction date, page references.

2. `core/model-card.ts`:
   ```ts
   export interface ModelDetailsSection {
     person_or_org_developing_model: string;
     model_date: string;
     model_version: string;
     model_type: string;
     training_algorithms: string;
     parameters: string;
     fairness_constraints: string;
     paper_citation: string;
     license: string;
     where_to_send_questions: string;
   }
   export interface IntendedUseSection {
     primary_intended_uses: string;
     primary_intended_users: string;
     out_of_scope_use_cases: string;
   }
   // ... per section ... (Factors, Metrics, EvaluationData, TrainingData, QuantitativeAnalyses, EthicalConsiderations, CaveatsAndRecommendations)
   export interface ModelCard {
     uuid: string;
     ai_asset_uuid: string;                  // joins to AiAsset
     model_id: string;
     emitted_at: string;
     sections: {
       model_details: ModelDetailsSection;
       intended_use: IntendedUseSection;
       factors: FactorsSection;
       metrics: MetricsSection;
       evaluation_data: EvaluationDataSection;
       training_data: TrainingDataSection;
       quantitative_analyses: QuantitativeAnalysesSection;
       ethical_considerations: EthicalConsiderationsSection;
       caveats_and_recommendations: CaveatsAndRecommendationsSection;
     };
     vendor_model_card?: { url: string; sha256: string; vendor_name: string; published_date: string };
     authored_by_user_id?: number;
     signature: string;
     signing_key_id: string;
     synthesized_fields: string[];
   }
   export function emitModelCard(card: ModelCard): { markdown: string; sidecar_json: object };
   ```

3. `core/datasheet.ts` — same pattern for the seven Gebru sections.

4. Per-section schemas explicitly model the verbatim Mitchell / Gebru sub-fields. Where a sub-field can be auto-derived from `ai-inventory.json` (e.g. `Model Details / Model date` ← `AiAsset.deployment_date`; `Intended Use / Primary intended uses` ← `AiAsset.purpose`; `Intended Use / Out-of-scope use cases` ← `AiAsset.out_of_scope_uses`; `Training Data` ← `AiAsset.training_data_sources`), the emitter auto-fills + records `synthesized_fields: [<dot-path>, ...]` per REO Rule 1.7. All other fields are operator-supplied via tracker form.

5. Emission loop:
   - For each `AiAsset` in `ai-inventory.json`:
     - Read or create the tracker `model_cards` row for `ai_asset_uuid`.
     - Auto-fill derivable sub-fields; record in `synthesized_fields[]`.
     - Render Markdown via the template; substitute section values; preserve verbatim section headers + prompts.
     - Emit `out/model-cards/<model-id>.md` + `out/model-cards/<model-id>.json` (sidecar).
     - Sign the sidecar via `core/sign.ts`.
   - For each distinct `training_data_source` across all `AiAsset` entries:
     - Read or create the tracker `datasheets` row for the dataset id.
     - Auto-fill derivable sub-fields; record in `synthesized_fields[]`.
     - Render Markdown; emit `out/datasheets/<dataset-id>.md` + `out/datasheets/<dataset-id>.json`.

6. Vendor models (e.g. Anthropic-published Claude Model Card):
   - When `vendor_model_card.url` is set, the local Markdown stub records vendor URL + sha256 + published date in §Model Details; §Intended Use is operator-supplied (vendor's "primary intended uses" replaced with CSP's bounded usage); §Ethical Considerations is operator-supplied (CSP's CSO-specific risks).
   - `synthesized_fields[]` records which sections are operator-supplied vs vendor-attributed.

7. Datasheet for vendor-supplied datasets (most common when model_provider is vendor):
   - When `vendor_datasheet.url` is set, emit a stub Markdown noting "vendor-published; see external URL" with sha256.
   - When no training dataset is documented (vendor refuses to disclose), emit a `datasheet` stub with `composition.what_instances = 'undisclosed by vendor'` + `coverage:miss` log.

8. SSP integration (`core/oscal-ssp.ts`):
   - For each emitted Model Card, add `back-matter.resources[]`:
     ```json
     { "uuid": "...", "type": "model-card", "title": "Model Card for <ai_asset_uuid>", "rlinks": [{ "href": "model-cards/<model-id>.md", "media-type": "text/markdown", "hashes": [{ "algorithm": "sha-256", "value": "..." }] }] }
     ```
   - Same for Datasheet (type `datasheet`).
   - SSP §13 (Control Implementation) for AI-relevant controls (PT-2, PT-3, SA-11, SR-3) references the back-matter resource via prop `ai-model-card-uuid`.

9. Bundler integration:
   - `WELL_KNOWN` gets two pattern-based roles:
     ```ts
     { role: 'model-cards-bundle', glob: 'model-cards/*.{md,json}', description: 'Per-model Model Cards (Mitchell 2018 nine sections; LOOP-O.O5)' },
     { role: 'datasheets-bundle', glob: 'datasheets/*.{md,json}', description: 'Per-dataset Datasheets (Gebru 2018 seven sections; LOOP-O.O5)' },
     ```
   - This is the first time `WELL_KNOWN` carries a `glob`-based entry; the bundler test suite gains a "glob expansion" path.

10. Tracker UI:
    - "Model Cards" page per AI asset; form-based editor with one tab per section; required-field validation; sign-off button (`cao` or `iso` role).
    - "Datasheets" page per dataset; same pattern.

11. Orchestrator wiring: `--model-cards` invokes `emitAllModelCardsAndDatasheets()` AFTER `--ai-inventory` + `--ai-evaluation` (the latter informs the Metrics section).

12. Provenance: each sidecar JSON carries `provenance` block (emitter, emittedAt, sourceCalls, configReads, signingKeyId); also a top-level `out/model-cards-emit.json` summary file with the full emit roll-up + signature.

## REQUIRES-OPERATOR-INPUT fields
| Field | Source | Behavior when missing |
|---|---|---|
| All Mitchell sections except auto-derivable sub-fields | Tracker form per Model Card | Emit blocked (Markdown rendering throws typed error); coverage:miss logged |
| All Gebru sections except auto-derivable sub-fields | Tracker form per Datasheet | Same |
| Ethical Considerations content (≥200 chars) | Tracker form | Cannot emit Model Card without; typed error |
| Vendor URL + sha256 (when applicable) | Tracker form | Stub Markdown notes "vendor card requested but not yet recorded" + coverage:miss |
| Authoring user_id + signature | Tracker form | Cannot publish without sign-off |
| Caveats and Recommendations (≥100 chars) | Tracker form | Required field |
| Datasheet Maintenance section (contact + erratum mechanism + update cadence + retention) | Tracker form | Required |
| Out-of-scope use cases | Auto-fillable from `AiAsset.out_of_scope_uses`; operator can extend | When AiAsset field empty + no tracker entry, blocked |

## Test specifications (≥12 tests)
1. `it('loads model-card-template.generated.md with all 9 Mitchell sections')` — assert section headers.
2. `it('loads datasheet-template.generated.md with all 7 Gebru sections')` — assert section headers.
3. `it('renders Model Card to Markdown with all sections in canonical order')` — pin order.
4. `it('renders Datasheet to Markdown with all sections in canonical order')` — pin order.
5. `it('auto-derives Model Details / Model date from AiAsset.deployment_date')` — assert.
6. `it('records synthesized_fields[] for every auto-derived sub-field with dot-path')` — REO Rule 1.7.
7. `it('rejects emit when ethical_considerations < 200 chars')` — typed error.
8. `it('rejects emit when caveats_and_recommendations < 100 chars')` — typed error.
9. `it('handles vendor_model_card path: emits stub Markdown with URL + sha256 + vendor_name')` — fixture.
10. `it('rejects vendor_model_card with empty sha256')` — typed error.
11. `it('handles missing vendor_datasheet by emitting stub Markdown with undisclosed marker and coverage:miss')` — assert log line + coverage row.
12. `it('back-matter.resources[] adds one entry per Model Card with rlink + sha256')` — assert SSP re-emit.
13. `it('back-matter.resources[] adds one entry per Datasheet with rlink + sha256')` — same.
14. `it('SSP §13 PT-2 references the Model Card resource via prop ai-model-card-uuid')` — assert prop.
15. `it('bundler includes model-cards-bundle + datasheets-bundle glob-based roles')` — pin WELL_KNOWN.
16. `it('signature is real Ed25519 over canonical JSON of sections')` — verify signature.
17. `it('rejects model card with ai_asset_uuid not present in ai-inventory.json')` — typed error.
18. `it('extraction script emits template with catalog_source header citing Mitchell 2018 PDF sha256')` — script test.

## REO compliance
- Section content is operator-supplied or auto-derived from real `ai-inventory.json` data; nothing synthesized silently.
- Vendor model cards stored as URL + sha256, never copied without attribution.
- Signature real Ed25519 over canonical JSON.
- Bundler includes Model Cards + Datasheets in the canonical submission via glob-based roles.
- `synthesized_fields[]` records every auto-derived sub-field per REO Rule 1.7.
- Provenance populated per emitted file (sidecar JSON) + top-level emit-summary file.
- Signed by: existing `core/sign.ts` Ed25519 pipeline + RFC 3161 timestamp manifest.

## Verification commands
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/model-card.test.ts tests/core/datasheet.test.ts tests/scripts/extract-model-card-template.test.ts tests/scripts/extract-datasheet-template.test.ts
npm run check:reo
npm run check:provenance
cd ../tracker
npm run typecheck
npm test
```

## Known risks / issues
- **Risk 1: Mitchell + Gebru PDFs may need anonymous-fetch workaround (arXiv is generally open but rate-limits).** Mitigation: operator downloads PDFs to `docs/sources/`; extraction script verifies sha256; CHANGELOG pins version.
- **Risk 2: Template extraction may garble verbatim section prompts due to PDF rendering quirks.** Mitigation: extraction script normalizes whitespace; spot-check test pins ≥3 known-good sections byte-for-byte; manual review required at first ship.
- **Risk 3: Vendor model card content is copyright-protected; FedPy must NOT embed.** Mitigation: stub-only emission with URL + sha256 + vendor_name; documented in code comment + operator runbook.
- **Risk 4: `model-cards-bundle` is the first glob-based role in `WELL_KNOWN`; bundler may not support globs today.** Mitigation: verify before starting; extend bundler's role-expansion logic if needed; add a bundler test path.
- **Risk 5: Cross-loop dependency on O.O4 evaluation outputs for the Metrics section means O.O5 cannot ship until O.O4 ships.** Mitigation: dependency declared in frontmatter (`depends_on: [O.O1, O.O2, O.O4]`); when O.O4 has not yet produced output, Metrics section carries `REQUIRES-OPERATOR-INPUT: ai-evaluation-ledger-not-yet-emitted` marker.
- **Risk 6: Multi-model use cases (e.g. ensemble of two vendor models) produce two Model Cards but one use case.** Mitigation: O.O1 schema records each model as a separate `AiAsset` even within one use case; emission walks per-asset; SSP back-matter resource set is per-asset.

## Open questions
- **Q1: For datasets with no operator-supplied Datasheet AND no vendor Datasheet, should O.O5 block emission or emit a stub flagged in coverage?** Recommend: emit stub with `composition.what_instances = 'undisclosed by vendor'` + coverage:miss; under `--strict-ai` for rights/safety-impacting use cases, block.
- **Q2: Should Model Cards include a Performance Across Subgroups section sourced from O.O4 bias evaluation results?** Recommend: yes — `quantitative_analyses.intersectional_results` auto-fills from O.O4 if `evaluation_framework='fairlearn'|'aif360'`; otherwise operator-supplied.
- **Q3: Sidecar JSON is signed; the Markdown is the human-readable artifact. When operator opens the Markdown and edits it, signature invalidates. How is this surfaced?** Recommend: tracker UI is the source of truth; CLI emits read-only Markdown; CHANGELOG documents the read-only convention.
- **Q4: Should Datasheets emit one per dataset OR one per (dataset, model) pair?** Recommend: one per dataset (Gebru's intent); `ai_asset_uuids[]` field on Datasheet records which models the dataset feeds.

## Implementation log
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥18 for this slice)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (slice row + Overall section)
- [ ] LOOP-O-SPEC.md status table updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added
- [ ] Commit with slice ID in message
- [ ] Commit amended with commit hash recorded
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. This file gives you: source obligations + files to create + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-O-SPEC.md` Section 5 (slice O.O5).
4. Read `cloud-evidence/docs/slices/O/O.O1.md` + `O.O2.md` + `O.O4.md` — O.O5 reads their outputs.
5. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
6. Read `cloud-evidence/core/oscal-ssp.ts` — your `back-matter.resources[]` extension point.
7. Read `cloud-evidence/core/submission-bundle.ts` — verify glob support exists; add two new roles.
8. Read the existing extraction scripts under `cloud-evidence/scripts/extract-*.mjs` for the script idiom.
9. Read `cloud-evidence/core/sign.ts` — verify it picks up Markdown + JSON sibling pairs from the `out/model-cards/` and `out/datasheets/` directories.
10. Begin implementation; update Implementation log section as you go.

---
