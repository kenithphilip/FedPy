---
slice_id: O.O2
title: NIST AI RMF alignment (GOVERN / MAP / MEASURE / MANAGE)
loop: O
status: pending
commit: —
completed_date: —
depends_on: [O.O1, LOOP-A.A2, LOOP-A.A3]
blocks: [O.O3, O.O4, O.O5, C.C7]
estimated_effort: 5-7 working days
last_updated: 2026-06-07
applicable_conditional: true
---

# O.O2 — NIST AI RMF alignment (GOVERN / MAP / MEASURE / MANAGE)

## TL;DR
Generate `core/ai-rmf-catalog.generated.json` containing all 71 NIST AI 100-1 subcategories (19 GOVERN + 18 MAP + 21 MEASURE + 13 MANAGE) with verbatim definitions sourced from the NIST AI 100-1 PDF + AIRC Playbook. For each AI use case in `ai-inventory.json` (O.O1), collect per-subcategory evidence from cloud signals + tracker uploads, emit `out/ai-rmf-evidence.json` with operator-signed sign-offs, and wire the result into OSCAL AP `assessment-assets` + SSP back-matter `resources`.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
O.O2 is a *hybrid collector* — part real cloud signal (CloudWatch alarms targeting an inference endpoint prove MEASURE 2.4 monitoring is active), part process-artifact (operator-uploaded model risk review proves MAP 1.1 intended-purpose documentation). The slice mirrors the AFR process-artifact pattern already shipped in `core/process-artifact-tracker.ts`: each AI RMF subcategory is a playbook item the operator records evidence against; the cloud side automatically populates signals where they exist. The output joins LOOP-A's AR `observation[]` stream (via the existing import-AP chain wired in LOOP-A.A3) and the SSP `back-matter.resources[]` (via the existing pattern in `core/oscal-ssp.ts`). Every quoted subcategory definition is verbatim from NIST AI 100-1 — no paraphrase. The slice extends the FedPy submission bundle with one new role (`ai-rmf-evidence`).

## Why this slice exists
NIST AI 100-1 §5 defines 71 subcategories across four functions. OMB M-24-10 §IV mandates AI risk management consistent with the AI RMF. For each AI use case in O.O1's inventory, the CSP needs structured evidence that the four functions are addressed. Today no such evidence emit exists in FedPy. Without O.O2:
- The AR cannot ship AI RMF observations.
- The SSP back-matter cannot link to AI risk-management evidence.
- The Chief AI Officer (per M-24-10 §II) has no machine-readable evidence package.
- LOOP-A submission bundle has no `ai-rmf-evidence` role.

OMB M-24-10 §IV states verbatim:
> "Agencies shall conduct risk management of their AI use cases consistent with the NIST AI RMF and related guidance."

## Authoritative sources (with verbatim quotes)
- **NIST AI 100-1 §5 (AI RMF Core)** — https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf — the four functions:
  > "**GOVERN**: A culture of risk management is cultivated and present"
  > "**MAP**: Context is recognized and risks related to context are identified"
  > "**MEASURE**: Identified risks are assessed, analyzed, or tracked"
  > "**MANAGE**: Risks are prioritized and acted upon based on a projected impact"
  Selected subcategory definitions (verbatim):
  > "**GOVERN 1.1** — Legal and regulatory requirements involving AI are understood, managed, and documented."
  > "**GOVERN 1.6** — Mechanisms are in place to inventory AI systems and are resourced according to organizational risk priorities."
  > "**MAP 1.1** — Intended purposes, potentially beneficial uses, context-specific laws, norms and expectations, and prospective settings in which the AI system will be deployed are understood and documented."
  > "**MEASURE 2.5** — The AI system to be deployed is demonstrated to be valid and reliable. Limitations of the generalizability beyond the conditions under which the technology was developed are documented."
  > "**MEASURE 2.7** — AI system security and resilience – as identified in the map function – are evaluated and documented."
  > "**MEASURE 2.8** — Risks associated with transparency and accountability – as identified in the map function – are examined and documented."
  > "**MEASURE 2.11** — Fairness and bias – as identified in the map function – are evaluated and results are documented."
  > "**MANAGE 4.1** — Post-deployment AI system monitoring plans are implemented, including mechanisms for capturing and evaluating input from users and other relevant AI actors, appeal and override, decommissioning, incident response, recovery, and change management."

- **NIST AI 600-1 — Generative AI Profile** — https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf — GenAI-specific overlay. The catalog carries `gen_ai_overlay: true` per subcategory that has a GenAI annotation in the profile.

- **NIST AI RMF Playbook (AIRC)** — https://airc.nist.gov/AI_RMF_Knowledge_Base/Playbook — per-subcategory suggested actions, transparency-documentation prompts, references. Each catalog row carries these arrays.

- **OMB M-24-10 §IV** (verbatim quoted above) — the regulatory hook.

- **OSCAL Assessment Plan v1.1.2** — https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-plan/json-reference/ — `assessment-assets.assessment-platforms[]` is the extension point; LOOP-A.A2's `oscal-ap.ts` is reused.

- **NIST SP 800-53 Rev 5** — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf — cross-walk targets: SR-3, SR-5, SR-11 (supply chain — for model provenance); SI-7 (software integrity); CA-7 (continuous monitoring — for drift); RA-3 (risk assessment); PT family (privacy/transparency). The cross-walk is documented in LOOP-O-SPEC.md Section 10.

- **ISO/IEC 42001:2023 — AI Management System** — voluntary; cross-reference recorded in the catalog when published mappings exist.

## Files to create (exact paths under cloud-evidence/)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ai-rmf.ts` — collector + emitter. ~600 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ai-rmf-catalog.generated.json` — the 71 subcategories with verbatim definitions + suggested actions + transparency documentation + references + NIST 800-53 crosswalk + ISO 42001 clauses (where known) + `gen_ai_overlay` flag. ~3500 lines committed.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/scripts/extract-ai-rmf-catalog.mjs` — extraction script that reads `docs/sources/nist-ai-100-1.pdf` + `docs/sources/nist-airc-playbook.snapshot.html` and writes the generated catalog. REO-compliant: input from authoritative source; output is the generated JSON; no synthetic content.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/ai-rmf.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/scripts/extract-ai-rmf-catalog.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/ai-rmf/` — sample catalog, sample tracker snapshots.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/control-benchmark.ts` — add AI RMF subcategory → NIST 800-53 control crosswalk reader; surface AI RMF subcategories in the benchmark report.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-ap.ts` — add `assessment-assets.assessment-platforms[]` entry "AI RMF self-assessment" with `props["ai-rmf-version"]` + `props["use-cases-assessed"]`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-ar.ts` — add `observation[]` entries (one per use case × subcategory pair) tying the AR back to the SSP's AI RMF resources.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-ssp.ts` — `back-matter.resources[]` adds entries of type `evidence` pointing to `out/ai-rmf-evidence.json` per use case.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add role `ai-rmf-evidence`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — new flag `--ai-rmf` + env `CLOUD_EVIDENCE_AI_RMF`; runs AFTER `--ai-inventory` (which provides the use-case list).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/schema.sql` — add `ai_rmf_evidence` table: `(id, use_case_id, subcategory_id, status, evidence_uri, evidence_sha256, notes, operator_signoff_user_id, signed_at, signature, signing_key_id, created_at, updated_at)`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/ai-rmf.ts` — CRUD + signed-evidence upload + signature verification.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/index.ts` — mount `/api/ai-rmf-evidence`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/AiRmf.tsx` — per-use-case / per-subcategory evidence UI.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/App.tsx` — add navigation entry `/ai-rmf`.

## Schemas / standards
- **NIST AI 100-1 §5 Core** — 71 subcategories total, verbatim definitions. The catalog header carries a `catalog_source` block with PDF page numbers + extraction timestamp + AIRC URL snapshot hash.
- **NIST AI 600-1 GenAI Profile** — `gen_ai_overlay: true/false` per subcategory; per-subcategory GenAI-specific suggested actions are stored in a separate `gen_ai_suggested_actions` array.
- **NIST AI RMF Playbook (AIRC)** — per-subcategory `suggested_actions[]`, `transparency_documentation[]`, `references[]` arrays. Each is verbatim from the AIRC HTML.
- **OSCAL AP v1.1.2** — `assessment-assets.assessment-platforms[].props[].name` with `CE_NS` namespace; new platform has `uuid` deterministic across runs.
- **OSCAL AR v1.1.2** — `observation[]` carries `methods=["TEST"]` (per AI RMF MEASURE function), `relevant-evidence[].href` to `out/ai-rmf-evidence.json#/use_cases/<id>/subcategories/<sid>`.
- **Ed25519 over canonical JSON** — operator sign-off uses the rfc8785-canonicalized subcategory payload.

## Build steps (concrete, numbered)

1. Extraction script `scripts/extract-ai-rmf-catalog.mjs`:
   - Input: `docs/sources/nist-ai-100-1.pdf` (operator-downloaded) + `docs/sources/nist-airc-playbook.snapshot.html` (operator-snapshotted, since AIRC is a live site).
   - PDF extraction: use `pdf-parse` or `pdfjs-dist` (existing dep in repo) to extract §5 subcategory definitions. Each definition is one `description` string verbatim.
   - HTML parse: use `node-html-parser` to extract per-subcategory suggested actions, transparency docs, references.
   - Output: `core/ai-rmf-catalog.generated.json`:
     ```ts
     export interface AiRmfSubcategory {
       id: string;                              // e.g. "GOVERN-1.1"
       function: 'GOVERN' | 'MAP' | 'MEASURE' | 'MANAGE';
       title: string;
       description: string;                     // verbatim from NIST AI 100-1
       trustworthy_characteristics: ('valid-reliable' | 'safe' | 'secure-resilient' | 'accountable-transparent' | 'explainable-interpretable' | 'privacy-enhanced' | 'fair-bias-managed')[];
       gen_ai_overlay: boolean;
       gen_ai_suggested_actions?: string[];
       suggested_actions: string[];             // from Playbook
       transparency_documentation: string[];    // from Playbook
       references: string[];                    // from Playbook
       nist_800_53_crosswalk: string[];         // O.O2-added; reviewed by operator
       iso_42001_clauses?: string[];            // O.O2-added when known
     }
     ```
   - Catalog header:
     ```ts
     export interface AiRmfCatalog {
       schema_version: 'ai-rmf-catalog.v1';
       ai_rmf_version: '1.0 (Jan 2023)';
       gen_ai_profile_version: '1.0 (Jul 2024)';
       extraction_date: string;
       catalog_source: {
         nist_ai_100_1_pdf_path: string;
         nist_ai_100_1_pdf_sha256: string;
         airc_playbook_url: string;
         airc_playbook_snapshot_path: string;
         airc_playbook_snapshot_sha256: string;
       };
       subcategories: AiRmfSubcategory[];
     }
     ```

2. Collector `core/ai-rmf.ts:collectAiRmfEvidence(ctx)`:
   - Loads catalog from `core/ai-rmf-catalog.generated.json`.
   - Reads `ai-inventory.json` for use-case list.
   - For each use case × subcategory:
     - **Cloud signal collection** for select subcategories: e.g. MEASURE 2.4 (production monitoring) → CloudWatch / Cloud Monitoring / Azure Monitor alarms targeting the inference endpoint. GOVERN 1.6 (inventory) → presence of the use case in `ai-inventory.json`. MEASURE 2.7 (security) → SSP §13 SC-family control coverage.
     - **Tracker evidence read** from `ai_rmf_evidence` table snapshot at `out/.ai-rmf-evidence.json` (written by tracker push step).
     - **Cross-reference**: O.O3 risk register for MAP 5.1; O.O4 evaluation for MEASURE 2.5/2.6; O.O5 model cards for MEASURE 2.8/2.9.
   - For each pair, determine status: `addressed` | `partial` | `not-addressed` | `not-applicable`. `not-applicable` requires a justification (≥50 chars) and operator sign-off.
   - Emit:
     ```json
     {
       "schema_version": "ai-rmf-evidence.v1",
       "ai_rmf_version": "1.0 (Jan 2023)",
       "gen_ai_profile_version": "1.0 (Jul 2024)",
       "use_cases": [
         {
           "use_case_id": "AIUC-001",
           "subcategories": [
             {
               "id": "GOVERN-1.1",
               "status": "addressed",
               "evidence_refs": [
                 { "type": "tracker", "uri": "tracker://ai-rmf-evidence/123", "sha256": "..." },
                 { "type": "cloud-signal", "source": "aws.cloudwatch.alarm.invoke-endpoint-errors", "value": "active" }
               ],
               "notes": "Operator memo dated 2026-03-15; CloudWatch alarm provisioned in same period.",
               "operator_signoff": {
                 "user_id": 12,
                 "role": "cao",
                 "signed_at": "2026-04-01T13:24:11Z",
                 "signature": "...",
                 "key_id": "..."
               }
             }
           ]
         }
       ],
       "provenance": { ... }
     }
     ```

3. NIST 800-53 cross-walk in `core/control-benchmark.ts`:
   - New `ai_rmf_crosswalk` table mapping subcategory → 800-53 controls (defaults documented in LOOP-O-SPEC.md §10).
   - Operator override via `config/ai-rmf-crosswalk.yaml`.

4. OSCAL AP wiring (`core/oscal-ap.ts`):
   - `assessment-assets.assessment-platforms[]` gets a new platform entry:
     ```json
     {
       "uuid": "deterministic-uuid-v5",
       "title": "AI RMF self-assessment",
       "props": [
         { "name": "ai-rmf-version", "ns": "<CE_NS>", "value": "1.0 (Jan 2023)" },
         { "name": "gen-ai-profile-version", "ns": "<CE_NS>", "value": "1.0 (Jul 2024)" },
         { "name": "use-cases-assessed", "ns": "<CE_NS>", "value": "AIUC-001,AIUC-002,..." }
       ],
       "remarks": "Self-assessment per NIST AI 100-1 §5 + AIRC Playbook."
     }
     ```

5. OSCAL AR wiring (`core/oscal-ar.ts`):
   - For each use case × subcategory pair with `status ∈ {addressed, partial}`, emit one `observation[]` entry:
     ```json
     {
       "uuid": "...",
       "title": "AI RMF subcategory <id> for use case <use_case_id>",
       "methods": ["TEST"],
       "props": [
         { "name": "ai-rmf-subcategory", "ns": "<CE_NS>", "value": "GOVERN-1.1" },
         { "name": "ai-use-case-id", "ns": "<CE_NS>", "value": "AIUC-001" }
       ],
       "relevant-evidence": [{ "href": "out/ai-rmf-evidence.json#/use_cases/AIUC-001/subcategories/GOVERN-1.1" }]
     }
     ```

6. OSCAL SSP wiring (`core/oscal-ssp.ts`):
   - `back-matter.resources[]` gets one `evidence` entry per use case pointing to `out/ai-rmf-evidence.json#/use_cases/<id>` with sha256.

7. Tracker UI (`AiRmf.tsx`):
   - List view: per use case, percent-complete progress bar over 71 subcategories.
   - Per-subcategory detail page: verbatim subcategory description + suggested actions (from Playbook) + transparency-documentation prompts + evidence-upload form + sign-off button (gated to `cao` or `iso` role).
   - Cross-reference panel: when MAP 5.1 / MEASURE 2.11 / MANAGE 4.1 are opened, show pointer to corresponding O.O3 risk / O.O4 eval / O.O5 model card.

8. Orchestrator wiring (`core/orchestrator.ts`):
   - `--ai-rmf` invokes `collectAiRmfEvidence()` AFTER `--ai-inventory` (since each use case is walked).
   - `--strict-ai` requires every use case to have `status ∈ {addressed, partial, not-applicable}` for every subcategory; if any subcategory is `not-addressed` and the use case has risk_category ∈ {rights-impacting, safety-impacting, both}, exit non-zero.

9. Bundler integration: add role `ai-rmf-evidence` with filename `ai-rmf-evidence.json` and description "NIST AI RMF GOVERN/MAP/MEASURE/MANAGE evidence per AI use case (LOOP-O.O2)".

10. Sign + timestamp: `ai-rmf-evidence.json` + `ai-rmf-catalog.generated.json` flow through `core/sign.ts` glob.

11. Provenance block on `ai-rmf-evidence.json`: emitter name, emittedAt, sourceCalls (tracker route, cloud signals consulted per subcategory), catalogPath, signingKeyId.

12. Coverage: count of subcategories addressed/partial/not-addressed/not-applicable per use case surfaces in `coverage.json` + log.

## REQUIRES-OPERATOR-INPUT fields
| Field | Source | Behavior when missing |
|---|---|---|
| Per-subcategory operator sign-off | Tracker form; `cao` or `iso` role required | Subcategory marked `not-addressed`; coverage:miss logged |
| `not-applicable` justification (≥50 chars) | Tracker form | Cannot set status to `not-applicable` without justification |
| Catalog header citation chain (PDF sha256, AIRC snapshot sha256) | Operator runs extraction script | Until run, catalog carries `REQUIRES-OPERATOR-INPUT: confirm-against-nist-ai-100-1-pdf` marker |
| NIST 800-53 crosswalk overrides | `config/ai-rmf-crosswalk.yaml` | Defaults used; documented in LOOP-O-SPEC.md §10 |
| Cross-reference uploads (e.g. MAP 1.1 purpose memo, MANAGE 4.1 monitoring plan) | Tracker form, files attached with sha256 | Cannot mark subcategory `addressed` without at least one evidence_ref |

## Test specifications (≥12 tests)
1. `it('loads ai-rmf-catalog.generated.json with all 71 subcategories')` — assert 19 GOVERN + 18 MAP + 21 MEASURE + 13 MANAGE = 71.
2. `it('verifies every subcategory description is verbatim from NIST AI 100-1')` — checksum fixture comparison.
3. `it('catalog header carries citation chain with PDF sha256 + AIRC snapshot sha256')` — provenance check.
4. `it('cross-walks GOVERN 6.1 to NIST 800-53 SR-3 in default crosswalk')` — assert mapping.
5. `it('collects MEASURE 2.4 evidence from CloudWatch alarm presence')` — mock SDK; assert evidence_ref source set.
6. `it('reads tracker evidence from .ai-rmf-evidence.json snapshot')` — fixture; assert merged into output.
7. `it('emits ai-rmf-evidence.json keyed by use_case_id then subcategory id')` — JSON shape.
8. `it('marks subcategory as not-addressed when no evidence and no signoff')` — default path.
9. `it('rejects not-applicable status without justification ≥50 chars')` — typed error.
10. `it('requires cao or iso role on operator_signoff')` — RBAC check.
11. `it('emits OSCAL AP assessment-platform for AI RMF with deterministic uuid')` — re-emit AP; assert presence.
12. `it('emits OSCAL AR observation per addressed subcategory')` — re-emit AR; assert observation count = sum of addressed/partial.
13. `it('joins to ai-inventory.json by use_case_id; rejects when use case unknown')` — typed error.
14. `it('GenAI Profile subcategories carry gen_ai_overlay: true and gen_ai_suggested_actions populated')` — pin sample.
15. `it('--strict-ai exits non-zero when rights-impacting use case has not-addressed subcategory')` — strict mode behavior.
16. `it('bundler includes ai-rmf-evidence role')` — pin WELL_KNOWN.
17. `it('check:provenance passes on emitted ai-rmf-evidence.json')` — guardrail green.

## REO compliance
- Every value traces to: a real NIST AI 100-1 PDF extraction (verbatim), a real AIRC Playbook snapshot, a real cloud SDK signal, or an operator-uploaded + signed tracker record.
- No silent fallbacks for: subcategory status (defaults to `not-addressed` — visible, never hidden).
- No paraphrase of NIST definitions — verbatim only; the extraction script's checksum gate enforces this.
- Operator sign-off is real Ed25519 signature over canonical JSON.
- Provenance populated on `ai-rmf-evidence.json` + `ai-rmf-catalog.generated.json` — emitter, emittedAt, catalog source, sourceCalls.
- Signed by: existing `core/sign.ts` Ed25519 pipeline + RFC 3161 timestamp manifest.

## Verification commands
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/ai-rmf.test.ts tests/scripts/extract-ai-rmf-catalog.test.ts
npm run check:reo
npm run check:provenance
cd ../tracker
npm run typecheck
npm test
```

## Known risks / issues
- **Risk 1: NIST AI 100-1 PDF anonymous fetch may return 403 (same pattern as FedRAMP CMP PDF).** Mitigation: operator downloads to `docs/sources/nist-ai-100-1.pdf`; `--strict-ai` mode blocks ship if `REQUIRES-OPERATOR-INPUT: confirm-against-nist-ai-100-1-pdf` marker remains. Cross-ref O-X2.
- **Risk 2: AIRC Playbook is a live site — content drifts.** Mitigation: snapshot file with sha256 stored under `docs/sources/`; extraction script verifies sha256; CHANGELOG entry pins the snapshot date.
- **Risk 3: Cross-walk to NIST 800-53 is partially subjective (e.g. MEASURE 2.11 fairness → no exact 800-53 control).** Mitigation: defaults documented in LOOP-O-SPEC.md §10; operator can override via `config/ai-rmf-crosswalk.yaml`; the prop carries the source ("default" vs "operator-override").
- **Risk 4: GenAI profile overlay may be incomplete — NIST may add subcategories in future revisions.** Mitigation: catalog header carries `gen_ai_profile_version`; extraction script idempotent; re-run on profile update produces a new generated catalog with a CHANGELOG diff.
- **Risk 5: PDF text extraction may garble verbatim text (whitespace, hyphenation).** Mitigation: extraction script post-processing normalizes whitespace + reflows hyphenated line breaks; spot-checks via test that pins ≥10 known-good descriptions byte-for-byte.

## Open questions
- **Q1: Should the catalog also include AI RMF's Trustworthy Characteristics enumeration as a separate table?** Recommend: yes — store in `core/ai-rmf-trustworthy-characteristics.generated.json` as a sibling artifact; useful for O.O3 risk taxonomy joins.
- **Q2: For not-applicable status, should the operator be required to cite which subcategory it's deferred to (e.g. "deferred to vendor model card")?** Recommend: yes — add `not_applicable_deferred_to` field with options {vendor, parent-system, not-yet-applicable}.
- **Q3: ISO 42001 cross-references are partially published; should we fill them in this slice or defer?** Recommend: include where known (cite published mapping URLs in catalog header), leave others null with a `REQUIRES-OPERATOR-INPUT: iso-42001-mapping-pending` marker.

## Implementation log
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥17 for this slice)
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
3. Read `cloud-evidence/docs/loops/LOOP-O-SPEC.md` Sections 3 (Dependencies) + 5 (slice O.O2) + 10 (cross-walks).
4. Read `cloud-evidence/docs/slices/O/O.O1.md` — O.O2 reads the `ai-inventory.json` O.O1 emits.
5. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
6. Read `cloud-evidence/core/oscal-ap.ts` + `core/oscal-ar.ts` + `core/oscal-ssp.ts` — your three OSCAL extension points.
7. Read `cloud-evidence/core/process-artifact-tracker.ts` — the hybrid collector pattern you'll mirror.
8. Read `cloud-evidence/core/control-benchmark.ts` — extension point for the AI RMF crosswalk.
9. Read the existing extraction scripts under `cloud-evidence/scripts/extract-*.mjs` — the pattern for the new `extract-ai-rmf-catalog.mjs`.
10. Begin implementation; update Implementation log section as you go.

---
