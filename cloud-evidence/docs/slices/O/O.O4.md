---
slice_id: O.O4
title: AI evaluation per OMB M-24-10 (pre-deployment + ongoing)
loop: O
status: pending
commit: —
completed_date: —
depends_on: [O.O1, O.O2, O.O3, AFR-PVA]
blocks: [O.O5, C.C7, E.E1, I.I1]
estimated_effort: 6-8 working days
last_updated: 2026-06-07
applicable_conditional: true
---

# O.O4 — AI evaluation per OMB M-24-10 (pre-deployment + ongoing)

## TL;DR
Treat each AI use case in `ai-inventory.json` as an AFR-PVA "rule" with operator-tunable cadence. Capture pre-deployment + ongoing evaluation results (HELM, OpenAI Evals, BIG-bench, MMLU, TruthfulQA, custom JSONL) uploaded by the operator to the tracker; verify signatures + sha256 at ledger-emit time; emit `out/ai-evaluation-ledger.json` keyed by use case; flag any rights-impacting / safety-impacting use case lacking passing pre-deployment evidence as a finding that flows into the LOOP-A POA&M. Never run the models — FedPy verifies, signs, ledger-records, and schedules.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
O.O4 extends `core/pva-collector.ts` (the AFR-PVA persistent-validation collector) to treat each AI use case as a PVA rule whose cadence is `evaluation_cadence_days` from O.O1's `AiAsset`. Pre-deployment results are captured once and gated by tracker form; ongoing results re-run on cadence and surface as `coverage:miss` when overdue. FedPy never executes a model — operator uploads evaluation output through the tracker, FedPy verifies provenance (signature, sha256), assembles the ledger, and signs the ledger. LOOP-E.E1 monthly ConMon report picks up the deltas. LOOP-A POA&M receives findings when safety/rights-impacting use cases lack passing evidence. The slice extends the FedPy submission bundle with one new role (`ai-evaluation-ledger`).

## Why this slice exists
OMB M-24-10 §V.B mandates pre-deployment + ongoing evaluation for "rights-impacting" AI; §V.C for "safety-impacting" AI. NIST AI RMF MEASURE 2.5 + 2.6 + 2.11 require ongoing documented evaluation. Today FedPy has AFR-PVA (persistent validation for KSIs) but no AI-evaluation scheduler. Without O.O4:
- The M-24-10 §V.B and §V.C compliance evidence has no structured destination.
- The AFR-PVA cadence machinery has no AI rule type.
- Multi-format evaluation outputs (HELM, OpenAI Evals, BIG-bench, MMLU) have no canonical adapter.
- POA&M cannot flag overdue or failing AI evaluations.

## Authoritative sources (with verbatim quotes)
- **OMB M-24-10 §V.B (Rights-impacting AI minimum practices)** — https://www.whitehouse.gov/wp-content/uploads/2024/03/M-24-10-Advancing-Governance-Innovation-and-Risk-Management-for-Agency-Use-of-Artificial-Intelligence.pdf
  Lists minimum practices including: identify + mitigate disparate impact; ongoing monitoring; consideration + remedy; opt-out where appropriate; consultation + feedback. Until operator downloads the PDF to `docs/sources/m-24-10.pdf`, the slice carries `REQUIRES-OPERATOR-INPUT: confirm-against-m-24-10-pdf` marker on the minimum-practice constants.

- **OMB M-24-10 §V.C (Safety-impacting AI minimum practices)** — same source:
  Lists pre-deployment independent evaluation; ongoing testing for performance degradation; procedures to mitigate emergent risks; human override.

- **NIST AI 100-1 §5 MEASURE 2.5** — https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf
  > "The AI system to be deployed is demonstrated to be valid and reliable. Limitations of the generalizability beyond the conditions under which the technology was developed are documented."

- **NIST AI 100-1 MEASURE 2.6**:
  > "The AI system is evaluated regularly for safety risks – as identified in the map function. The AI system to be deployed is demonstrated to be safe, its residual negative risk does not exceed the risk tolerance, and it can fail safely."

- **NIST AI 100-1 MEASURE 2.11**:
  > "Fairness and bias – as identified in the map function – are evaluated and results are documented."

- **HELM (Stanford CRFM)** — https://crfm.stanford.edu/helm/ — published evaluation framework; per-scenario JSON output with `runs[]` carrying `stats` keyed by metric name. Result schema documented at https://crfm.stanford.edu/helm/latest/.

- **OpenAI Evals** — https://github.com/openai/evals — JSONL per eval; each line `{ "spec": {...}, "final_report": { "accuracy": 0.82, ... }, "events": [...] }`.

- **BIG-bench (Google)** — https://github.com/google/BIG-bench — task-by-task JSON output with `score_dict` and `metric` fields.

- **MMLU** — https://arxiv.org/abs/2009.03300 — per-subject accuracy table.

- **TruthfulQA** — https://arxiv.org/abs/2109.07958 — per-question true/false + BLEURT scores.

- **NIST SP 800-53 Rev 5 CA-7 (Continuous Monitoring)** — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
  > "CA-7a. Develop a system-level continuous monitoring strategy and implement continuous monitoring …" — AI evaluation cadence is a CA-7 task; the strategy is recorded in the CA-7 family.

## Files to create (exact paths under cloud-evidence/)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ai-evaluation.ts` — orchestrator + ledger emitter. ~500 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ai-evaluation-readers/index.ts` — adapter registry. ~100 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ai-evaluation-readers/helm.ts` — HELM JSON parser.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ai-evaluation-readers/openai-evals.ts` — JSONL parser.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ai-evaluation-readers/big-bench.ts` — BIG-bench parser.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ai-evaluation-readers/mmlu.ts` — MMLU parser.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ai-evaluation-readers/truthfulqa.ts` — TruthfulQA parser.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ai-evaluation-readers/custom-jsonl.ts` — generic JSONL adapter.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/config/ai-evaluation-thresholds.example.yaml` — committed example.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/ai-evaluation.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/ai-evaluation-readers/helm.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/ai-evaluation-readers/openai-evals.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/ai-evaluation-readers/big-bench.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/ai-evaluation-readers/mmlu.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/ai-evaluation-readers/truthfulqa.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/ai-evaluation-readers/custom-jsonl.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/ai-evaluation/` — one fixture file per reader.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/pva-collector.ts` — extend cadence scheduler to register one AI-eval PVA rule per use case × evaluation_type; emit `coverage:miss` when overdue.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/findings.ts` — add `category='ai-evaluation-overdue'` (already covered in O.O3 finding-category extension).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-poam.ts` — `findingProps()` adds `ai-evaluation-type`, `ai-evaluation-framework`, `ai-pass-fail`, `ai-completed-at` props on ai-evaluation findings.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add role `ai-evaluation-ledger`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — flag `--ai-evaluation` + env; runs AFTER `--ai-inventory` + `--ai-rmf`; honors `--strict-ai`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/schema.sql` — add `ai_evaluations` + `ai_evaluation_runs` tables.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/ai-evaluations.ts` — CRUD + signed upload + framework dispatch.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/AiEvaluations.tsx` — UI per use case.

## Schemas / standards
- **OMB M-24-10 §V.B / §V.C minimum-practice constants** — typed array per category {safety-impacting, rights-impacting}; each constant carries the verbatim practice text + `REQUIRES-OPERATOR-INPUT: confirm-against-m-24-10-pdf` marker until the PDF is downloaded.
- **AFR-PVA cadence rule schema** — already in `core/pva-collector.ts`. New rule type `ai-eval` carries fields: `use_case_id`, `evaluation_type`, `cadence_days`, `last_completed_at`, `next_due_at`.
- **Framework output schemas** — per-reader documented in the adapter; the adapter's job is to translate to `metrics: Record<string, number>`.
- **Ed25519 + sha256 over upload** — every uploaded result file carries `sha256`; tracker computes at upload + verifies on read; signature is operator's Ed25519 over canonical-JSON envelope.
- **OSCAL POA&M v1.1.2** — new props `ai-evaluation-type`, `ai-evaluation-framework`, `ai-pass-fail`, `ai-completed-at` in `CE_NS`.

## Build steps (concrete, numbered)

1. `AiEvaluation` schema in `core/ai-evaluation.ts`:
   ```ts
   export interface AiEvaluation {
     uuid: string;
     use_case_id: string;
     evaluation_type: 'pre-deployment' | 'ongoing-monthly' | 'ongoing-quarterly' | 'incident-triggered' | 'change-triggered';
     evaluation_framework: 'helm' | 'openai-evals' | 'big-bench' | 'mmlu' | 'truthfulqa' | 'custom-jsonl' | 'operator-narrative';
     framework_version: string;
     minimum_practice_compliance_tag: 'safety-impacting' | 'rights-impacting' | 'neither' | 'both';
     scheduled_at: string;
     completed_at?: string;
     status: 'scheduled' | 'in-progress' | 'completed' | 'failed' | 'waived';
     uploaded_by_user_id: number;
     result_summary_uri?: string;
     result_summary_sha256?: string;
     pass_fail: 'pass' | 'fail' | 'partial' | 'not-yet-evaluated';
     metrics: Record<string, number | string>;
     human_override_path_documented: boolean;
     human_override_sop_uri?: string;
     consultation_record_uri?: string;
     consultation_record_sha256?: string;
     waiver_justification?: string;
     signature: string;
     signing_key_id: string;
     created_at: string;
     updated_at: string;
   }
   ```

2. Scheduler hook in `core/pva-collector.ts`:
   - For each AI use case in `ai-inventory.json`, register a PVA rule:
     ```ts
     { rule_id: `ai-eval:${use_case_id}:${evaluation_type}`, cadence_days, last_completed_at, next_due_at }
     ```
   - Pre-deployment rule fires once (when use case deployment_date is set + pre-deployment row absent).
   - Ongoing rules (monthly/quarterly) recur per cadence_days.
   - Incident-triggered + change-triggered fire on tracker-recorded events (link to AFR-PVA event hooks).
   - When a scheduled evaluation is overdue (now > next_due_at + grace), PVA emits a `coverage:miss` + the aggregator creates a finding with `category='ai-evaluation-overdue'`.

3. Reader adapters: each plug-in is a pure function:
   ```ts
   export function parseHelmResult(input: string): { metrics: Record<string, number>; framework_version: string; raw_summary: string };
   export function parseOpenAiEvalsResult(input: string): { metrics: Record<string, number>; framework_version: string; raw_summary: string };
   // ... per framework
   ```
   Custom-jsonl adapter requires operator-supplied schema mapping in `config/ai-evaluation-thresholds.yaml` (`custom_jsonl_metric_paths: {accuracy: "final.accuracy", ...}`).

4. Tracker upload route (`POST /api/ai-evaluations/:use_case_id`):
   - Accepts multipart upload + JSON envelope.
   - Computes sha256 server-side.
   - Verifies operator's signature over canonical envelope.
   - Calls reader adapter based on `evaluation_framework`.
   - Stores row in `ai_evaluations`; appends run row in `ai_evaluation_runs`.

5. Aggregator `emitAiEvaluationLedger(opts)`:
   - Reads `ai-inventory.json` + tracker snapshot `out/.ai-evaluations.json`.
   - For each use case, groups evaluations by type.
   - Determines minimum-practice compliance:
     - For `rights-impacting`: at least one `pre-deployment` row in `pass` state + at least one `ongoing-monthly` row within cadence + `consultation_record_uri` set + `human_override_path_documented=true`.
     - For `safety-impacting`: at least one `pre-deployment` row in `pass` state (independent evaluator metadata required) + at least one `ongoing-monthly` row within cadence + `human_override_path_documented=true`.
   - Emits:
     ```json
     {
       "schema_version": "ai-evaluation-ledger.v1",
       "use_cases": [
         {
           "use_case_id": "AIUC-001",
           "evaluations": [
             {
               "uuid": "...",
               "evaluation_type": "pre-deployment",
               "evaluation_framework": "helm",
               "framework_version": "v0.4.0",
               "completed_at": "...",
               "pass_fail": "pass",
               "metrics": { "MMLU.accuracy": 0.82, "TruthfulQA.bleurt": 0.71 },
               "uri": "tracker://ai-evaluations/123",
               "sha256": "...",
               "signature": "...",
               "key_id": "..."
             }
           ],
           "minimum_practice_compliance": {
             "safety_impacting": "compliant",
             "rights_impacting": "not-applicable"
           }
         }
       ],
       "provenance": { ... }
     }
     ```

6. Compliance check + finding emission:
   - For each use case with `risk_category ∈ {rights-impacting, safety-impacting, both}`, verify minimum-practice compliance.
   - Non-compliant use cases produce a `Finding` with `category='ai-evaluation-overdue'` (or `ai-evaluation-missing`, see Open Q1), `severity='high'`, `gap.description` listing which practices are missing.
   - LOOP-A.A1 POA&M emitter picks these up via the existing pipeline.

7. Orchestrator wiring:
   - `--ai-evaluation` invokes aggregator AFTER `--ai-inventory` + `--ai-rmf`.
   - `--strict-ai` mode fails the build if any safety-impacting or rights-impacting use case lacks passing pre-deployment evidence OR is overdue on ongoing.

8. Bundler: add role `ai-evaluation-ledger` with filename `ai-evaluation-ledger.json` and description "Pre-deployment + ongoing AI evaluation results per OMB M-24-10 §V.B/§V.C (LOOP-O.O4)".

9. Sign + timestamp: `ai-evaluation-ledger.json` flows through `core/sign.ts` glob.

10. Provenance: emitter, emittedAt, sourceCalls (tracker route, PVA cadence), use_cases_walked count, signing_key_id.

11. Tracker UI: per use case, list scheduled + completed evaluations; upload form selects framework; verification of file signature shown after upload; cadence countdown.

## REQUIRES-OPERATOR-INPUT fields
| Field | Source | Behavior when missing |
|---|---|---|
| Evaluation result files | Tracker upload by operator | Without uploads, scheduled rows stay `pass_fail='not-yet-evaluated'` |
| `human_override_path_documented` (boolean) | Operator attestation in tracker | Required for safety/rights-impacting; cannot mark minimum-practice as compliant without it |
| `human_override_sop_uri` | Tracker URL field + sha256 | Required when `human_override_path_documented=true` |
| `consultation_record_uri` | Tracker URL field + sha256 | Required for rights-impacting per M-24-10 §V.B |
| `waiver_justification` (≥100 chars) | Tracker form when `status='waived'` | Cannot waive without justification |
| Framework version | Operator-supplied at upload (or auto-detected by reader from result file) | When reader cannot detect, REQUIRES-OPERATOR-INPUT |
| Pre-deployment independent evaluator metadata | Operator tracker form | Required for safety-impacting per §V.C |
| Thresholds (per-metric pass/fail thresholds) | `config/ai-evaluation-thresholds.yaml` | Defaults documented; CHANGELOG explains |
| Minimum-practice constants verbatim | Extracted from M-24-10 PDF by operator | REQUIRES-OPERATOR-INPUT marker until PDF downloaded |

## Test specifications (≥12 tests)
1. `it('schedules an ai-eval PVA rule per use case × evaluation_type')` — fixture inventory; assert rule count.
2. `it('emits coverage:miss when an ongoing evaluation is overdue beyond cadence + grace')` — time-travel test.
3. `it('parses HELM result JSON into metrics map')` — fixture HELM file; pin metric values.
4. `it('parses OpenAI Evals JSONL into metrics map with final_report fields')` — fixture JSONL.
5. `it('parses BIG-bench output into metrics map across tasks')` — fixture file; assert task count.
6. `it('parses MMLU per-subject accuracy table into metrics map')` — fixture.
7. `it('parses TruthfulQA BLEURT scores')` — fixture.
8. `it('rejects evaluation upload without signature')` — typed error.
9. `it('rejects evaluation upload with sha256 mismatch')` — typed error.
10. `it('emits ai-evaluation-ledger.json with all use cases and evals')` — JSON shape.
11. `it('flags safety-impacting use case without passing pre-deployment as POA&M finding')` — re-emit POA&M; assert finding present.
12. `it('flags rights-impacting use case without consultation_record_uri as POA&M finding')` — same.
13. `it('--strict-ai exits non-zero when safety-impacting eval missing')` — strict mode behavior.
14. `it('verifies pre-deployment completed_at < deployment_date')` — temporal constraint.
15. `it('emits provenance block on ledger including PVA rule count')` — `check:provenance` passes.
16. `it('waiver evaluation requires justification ≥ 100 chars')` — typed error.
17. `it('PVA persistent-validation cadence advances next_due_at after completion')` — pin schedule logic.
18. `it('custom-jsonl reader honours operator-supplied metric paths from config')` — config-driven mapping.
19. `it('bundler includes ai-evaluation-ledger role')` — pin WELL_KNOWN.

## REO compliance
- Evaluation results uploaded with sha256 + signature; verified at ledger-emit time.
- Pass/fail derives from operator-set thresholds in `config/ai-evaluation-thresholds.yaml`, not from synthetic metrics.
- Overdue evaluations surface as findings via existing LOOP-A pipeline — not silent gaps.
- FedPy never executes evaluation harnesses — strict read-only boundary.
- Provenance populated on `ai-evaluation-ledger.json` (emitter, emittedAt, sourceCalls, use_cases_walked, signingKeyId).
- M-24-10 minimum-practice constants carry `REQUIRES-OPERATOR-INPUT` marker until operator downloads PDF.
- Signed by: existing `core/sign.ts` Ed25519 pipeline + RFC 3161 timestamp manifest.

## Verification commands
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/ai-evaluation.test.ts tests/core/ai-evaluation-readers/*.test.ts
npm run check:reo
npm run check:provenance
cd ../tracker
npm run typecheck
npm test
```

## Known risks / issues
- **Risk 1: M-24-10 PDF anonymous fetch returns 403.** Mitigation: operator downloads to `docs/sources/m-24-10.pdf`; `--strict-ai` blocks ship if marker remains. Cross-ref O-X2.
- **Risk 2: Framework output formats evolve.** HELM, OpenAI Evals, BIG-bench publish schema changes regularly. Mitigation: permissive parsers; missing required field → `REQUIRES-OPERATOR-INPUT`; per-reader fixture pinned at framework_version; CHANGELOG records adapter version per framework.
- **Risk 3: Operator may upload very large eval result files.** Mitigation: tracker enforces upload size limit (256 MB default; configurable); sha256 computed via stream; ledger stores URI not body.
- **Risk 4: Cadence overdue logic could fire false-positives at clock skew.** Mitigation: 24-hour grace period configurable; CHANGELOG documents.
- **Risk 5: Independent evaluator metadata for safety-impacting use cases is ambiguous — what qualifies?** Mitigation: operator declares evaluator identity + relationship in tracker form; reviewer accepts/rejects; defer detailed qualification rubric to operator runbook.
- **Risk 6: PVA collector might not have a cadence hook for AI rules at slice start.** Mitigation: verify existing `core/pva-collector.ts` extension points before starting; add a new rule-type registry if absent.
- **Risk 7: `pass_fail` interpretation differs across frameworks (e.g. HELM has no global pass/fail).** Mitigation: operator-supplied thresholds in `config/ai-evaluation-thresholds.yaml` map per-metric values to pass/fail; default thresholds documented per framework.

## Open questions
- **Q1: Should the finding category be `ai-evaluation-overdue` (existing in finding enum) OR a new `ai-evaluation-missing` for never-evaluated use cases?** Recommend: split — `ai-evaluation-overdue` for cadence breach, `ai-evaluation-missing` for pre-deployment absence. Add both to the enum in this slice.
- **Q2: For change-triggered evaluations, what triggers a "change"?** Recommend: operator-declared events in tracker (`model_version_change`, `endpoint_url_change`, `training_data_source_change`); each event creates a one-shot `change-triggered` evaluation row.
- **Q3: Should `incident-triggered` evaluations link to LOOP-K (incident artifacts) when LOOP-K is built?** Recommend: yes; add `incident_uuid?: string` field now; cross-loop link comes online when LOOP-K ships.
- **Q4: For external API models (e.g. Anthropic API), the operator may rely on the vendor's published evaluations.** How should `evaluation_framework='operator-narrative'` represent that? Recommend: dedicated framework value; metrics map carries `vendor_published_url` + `vendor_evaluation_date`; pass_fail still operator-attested.

## Implementation log
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥19 for this slice)
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
3. Read `cloud-evidence/docs/loops/LOOP-O-SPEC.md` Section 5 (slice O.O4) + Section 10 (M-24-10 cross-walk).
4. Read `cloud-evidence/docs/slices/O/O.O1.md` + `O.O3.md` — O.O4 reads their outputs.
5. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
6. Read `cloud-evidence/core/pva-collector.ts` — your AFR-PVA extension point.
7. Read `cloud-evidence/core/findings.ts` — the category enum you'll extend with `ai-evaluation-overdue` and `ai-evaluation-missing`.
8. Read `cloud-evidence/core/oscal-poam.ts:findingProps()` — POA&M props extension point.
9. Read the existing reader patterns in `cloud-evidence/core/*-reader*.ts` (e.g. `risk-acceptance-reader.ts`) for the adapter idiom.
10. Begin implementation; update Implementation log section as you go.

---
