---
slice_id: O.O3
title: AI risk register (bias, fairness, robustness, adversarial)
loop: O
status: pending
commit: —
completed_date: —
depends_on: [O.O1, O.O2, LOOP-A.A1, LOOP-B.B1, LOOP-B.B3, LOOP-B.B5]
blocks: [O.O4, C.C7, E.E1, I.I1]
estimated_effort: 4-5 working days
last_updated: 2026-06-07
applicable_conditional: true
---

# O.O3 — AI risk register (bias, fairness, robustness, adversarial)

## TL;DR
Aggregate AI-specific risks (bias, fairness, robustness, adversarial, drift, hallucination, prompt-injection, data-poisoning, model-theft, PII-leak, IP-leak, plus the 12 NIST AI 600-1 GenAI categories) into `out/ai-risk-register.json`, sourced from operator-uploaded test results + cloud-monitor signals + tracker entries. Join the result into LOOP-B.B5's `risk-register.json` as `source='ai'` rows, project high+open AI risks into POA&M items via the existing `core/oscal-poam.ts` pipeline with new `ai-*` props.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
O.O3 reuses the LOOP-B.B5 risk-register pattern (signed tracker records → snapshot → core aggregator → emit) and extends LOOP-B.B1's composite-score qualitative bands ({very-low, low, moderate, high, very-high}) into the AI domain. The slice does NOT have FedPy run any AI models — bias / fairness / hallucination evidence is operator-uploaded; cloud signals are limited to read-only detection of monitoring artifacts (e.g. SageMaker Model Monitor alarms, Vertex Model Monitoring jobs, Azure ML data-drift alerts). The output joins LOOP-B's `risk-register.json` so a single XLSX/JSON report carries all risk classes (finding, organisational, AI). High+open AI risks flow into LOOP-A's POA&M with new finding categories (`ai-bias`, `ai-drift`, `ai-hallucination`, `ai-prompt-injection`, `ai-data-poisoning`, `ai-supply-chain`, `ai-pii-leak`, `ai-ip-leak`).

## Why this slice exists
NIST AI 100-1 MAP 5.1 mandates documenting likelihood + magnitude of each identified AI impact:
> "Likelihood and magnitude of each identified impact (both potentially beneficial and harmful) based on expected use, past uses of AI systems in similar contexts, public incident reports, feedback from those external to the team that developed or deployed the AI system, or other data are identified and documented."

NIST AI 600-1 enumerates 12 GenAI-specific risk categories. LOOP-B.B5's risk-register aggregates per-finding + organisational + operational risks but has no seat for AI-specific risks. Today:
- AI bias / fairness / hallucination test results have no structured destination.
- The 12 GenAI categories have no canonical enumeration in FedPy.
- POA&M finding-category enum has no AI categories.
- LOOP-B.B5 register has no `source='ai'` discriminator.

O.O3 closes all four gaps.

## Authoritative sources (with verbatim quotes)
- **NIST AI 100-1 MAP 5.1** — https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf
  > "Likelihood and magnitude of each identified impact (both potentially beneficial and harmful) based on expected use, past uses of AI systems in similar contexts, public incident reports, feedback from those external to the team that developed or deployed the AI system, or other data are identified and documented."

- **NIST AI 100-1 MEASURE 2.11** — same source:
  > "Fairness and bias – as identified in the map function – are evaluated and results are documented."

- **NIST AI 100-1 MANAGE 1.3** — same source:
  > "Responses to the AI risks deemed high priority, as identified by the map function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting."

- **NIST AI 600-1 §3 (GenAI Profile risk categories)** — https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf — 12 categories verbatim:
  > "(1) CBRN Information or Capabilities; (2) Confabulation; (3) Dangerous, Violent, or Hateful Content; (4) Data Privacy; (5) Environmental Impacts; (6) Harmful Bias and Homogenization; (7) Human-AI Configuration; (8) Information Integrity; (9) Information Security; (10) Intellectual Property; (11) Obscene, Degrading, and/or Abusive Content; (12) Value Chain and Component Integration."

- **NIST AI 100-1 §4 (Trustworthiness characteristics)** — same source — seven characteristics used as risk-impact dimensions:
  > "Valid and Reliable; Safe; Secure and Resilient; Accountable and Transparent; Explainable and Interpretable; Privacy-Enhanced; Fair – with Harmful Bias Managed."

- **NIST SP 800-30 Rev 1 §3.2 + Appendix G** — https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf — qualitative likelihood/impact scales {Very Low, Low, Moderate, High, Very High} reused verbatim from LOOP-B.B5.

- **NIST SP 800-53 Rev 5 RA-3** — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
  > "RA-3a. Conduct a risk assessment, including: identifying threats to and vulnerabilities in the system; the likelihood and magnitude of harm, from unauthorized access, use, disclosure, disruption, modification, or destruction of the system, the information it processes, stores, or transmits, and any related information; …"
  AI risks contribute to the system-wide risk assessment per RA-3a; O.O3 supplies the AI rows.

- **MITRE ATLAS — Adversarial Threat Landscape for Artificial-Intelligence Systems** — https://atlas.mitre.org/ — adversarial tactic/technique taxonomy used for the `adversarial` category sub-typing; cited in code comments.

## Files to create (exact paths under cloud-evidence/)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ai-risk-register.ts` — aggregator + emitter. ~500 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ai-risk-taxonomy.generated.json` — canonical AI-risk taxonomy with NIST AI 600-1 GenAI Profile cross-references + MITRE ATLAS tactic IDs. Extraction script writes this; checked in. ~1200 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/scripts/extract-ai-risk-taxonomy.mjs` — extraction script.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/ai-risk-register.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/scripts/extract-ai-risk-taxonomy.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/ai-risk-register/` — sample test-result uploads, sample tracker snapshots.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/config/ai-risk-thresholds.example.yaml` — committed example for operator-tunable thresholds.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/risk-register.ts` (LOOP-B.B5) — join AI risks as `source='ai'` entries; the consolidated `RiskRegisterEntry` interface gains `ai_rmf_subcategory_ids: string[]` + `ai_use_case_id?: string` fields.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/findings.ts` — extend `category` enum to include `ai-bias`, `ai-drift`, `ai-hallucination`, `ai-prompt-injection`, `ai-data-poisoning`, `ai-supply-chain`, `ai-pii-leak`, `ai-ip-leak`, `ai-evaluation-overdue`, `ai-adversarial`, `ai-cbrn`, `ai-confabulation`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/envelope.ts` — add `ai_risk_score?: AiRiskScore` optional field on `Finding` (parallel to LOOP-B.B1's `risk_score`); the `AiRiskScore` carries likelihood, impact, inherent, residual, treatment.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-poam.ts` — `findingProps()` adds `ai-use-case-id`, `ai-risk-category`, `ai-rmf-subcategory`, `ai-gen-ai-profile-category` props on AI-sourced findings.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add role `ai-risk-register`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — flag `--ai-risk-register` + env; runs AFTER `--ai-inventory` + `--ai-rmf`; BEFORE `--risk-register` (LOOP-B.B5) so the join sees AI rows.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/schema.sql` — add `ai_risk_assessments` + `ai_risk_treatments` tables.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/ai-risk-assessments.ts` — CRUD + signed evidence upload.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/AiRiskRegister.tsx` — per-use-case AI risk UI.

## Schemas / standards
- **NIST AI 600-1 12 GenAI categories** — verbatim; stored as `gen_ai_profile_categories[]` enum in the taxonomy.
- **NIST AI RMF MAP 5.1 / MEASURE 2.11 / MANAGE 1.3** — quoted above; the AI risk row schema mirrors the subcategory IDs.
- **NIST SP 800-30 Rev 1 likelihood/impact qualitative scales** — reused from LOOP-B.B5: {Very Low, Low, Moderate, High, Very High}.
- **NIST AI 100-1 §4 trustworthiness characteristics** — 7 characteristics; each AI risk has `trustworthy_characteristic_affected[]`.
- **MITRE ATLAS** — adversarial taxonomy reference; per-risk `mitre_atlas_technique_ids[]` optional.
- **OSCAL POA&M v1.1.2** — new finding-class taxonomy entries surface via `findingProps()` with `CE_NS` namespace.

## Build steps (concrete, numbered)

1. Extraction script `scripts/extract-ai-risk-taxonomy.mjs`:
   - Input: `docs/sources/nist-ai-600-1.pdf` (operator-downloaded) + MITRE ATLAS JSON export from https://atlas.mitre.org/.
   - Output: `core/ai-risk-taxonomy.generated.json`:
     ```ts
     export interface AiRiskCategory {
       id: string;                                  // e.g. 'bias', 'fairness', 'cbrn'
       name: string;                                // verbatim from source
       source: 'nist-ai-600-1' | 'mitre-atlas' | 'mitchell-2018' | 'industry';
       gen_ai_profile_category?: string;            // 1..12 from AI 600-1
       description: string;                         // verbatim from source
       trustworthy_characteristic_affected: ('valid-reliable' | 'safe' | 'secure-resilient' | 'accountable-transparent' | 'explainable-interpretable' | 'privacy-enhanced' | 'fair-bias-managed')[];
       ai_rmf_subcategory_ids: string[];            // mapping into O.O2 catalog
       mitre_atlas_technique_ids?: string[];
       common_indicators: string[];                 // operator-readable
       suggested_evaluation_frameworks: string[];   // 'fairlearn', 'aif360', 'helm', 'openai-evals', ...
     }
     ```

2. `AiRisk` schema in `core/ai-risk-register.ts`:
   ```ts
   export interface AiRisk {
     uuid: string;
     use_case_id: string;                            // joins to O.O1
     category: 'bias' | 'fairness' | 'robustness' | 'adversarial' | 'drift'
             | 'hallucination' | 'confabulation' | 'prompt-injection'
             | 'data-poisoning' | 'model-theft' | 'pii-leak' | 'ip-leak'
             | 'cbrn' | 'safety' | 'privacy' | 'environmental'
             | 'supply-chain' | 'value-chain' | 'human-ai-configuration'
             | 'information-integrity' | 'information-security'
             | 'obscene-degrading-abusive' | 'dangerous-violent-hateful'
             | 'harmful-bias-homogenization';
     title: string;                                  // ≥10 chars
     description: string;                            // ≥100 chars
     ai_rmf_subcategory_ids: string[];               // e.g. ['MEASURE-2.11']
     gen_ai_profile_category?: string;               // required for {cbrn, dangerous-violent-hateful, ...}
     trustworthy_characteristic_affected: ('valid-reliable' | 'safe' | 'secure-resilient' | 'accountable-transparent' | 'explainable-interpretable' | 'privacy-enhanced' | 'fair-bias-managed')[];
     likelihood: 'very-low' | 'low' | 'moderate' | 'high' | 'very-high';
     impact: 'very-low' | 'low' | 'moderate' | 'high' | 'very-high';
     inherent_risk: 'very-low' | 'low' | 'moderate' | 'high' | 'very-high';
     residual_risk: 'very-low' | 'low' | 'moderate' | 'high' | 'very-high';
     treatment: 'accept' | 'mitigate' | 'transfer' | 'avoid';
     treatment_actions: string[];
     compensating_control_uuids?: string[];          // joins to LOOP-B.B4 CCs
     owner_user_id: number;
     review_date: string;
     status: 'open' | 'closed';
     evidence_refs: { type: string; uri: string; sha256?: string }[];
     mitre_atlas_technique_ids?: string[];
     created_at: string;
     updated_at: string;
   }
   ```

3. Discovery hooks:
   - `bias` / `fairness`: operator uploads test results (Fairlearn, AIF360, IBM AI Fairness 360). Tracker route accepts upload + sha256. Risk auto-created when result exceeds threshold in `config/ai-risk-thresholds.yaml`.
   - `drift`: cloud-monitoring alarm presence (SageMaker Model Monitor, Vertex Model Monitoring, Azure ML data-drift) creates an observation; ABSENCE of monitoring creates a risk row marked `category='drift', status='open'`.
   - `adversarial`: operator-uploaded red-team / pen-test results.
   - `hallucination` / `confabulation` / `pii-leak`: operator-uploaded eval results from O.O4 framework (HELM-truthfulness, custom).
   - `prompt-injection` / `data-poisoning`: operator-uploaded threat-model + pen-test results; mapped to MITRE ATLAS techniques.
   - Risk creation via `POST /api/ai-risk-assessments` requires `iso` or `cao` role.

4. Aggregator:
   ```ts
   export function buildAiRiskRegister(inputs: AiRiskInputs): AiRisk[];
   ```
   Reads from `ai-inventory.json` + `ai-rmf-evidence.json` + tracker snapshot `out/.ai-risk-assessments.json`. Validates every `ai_rmf_subcategory_ids` entry exists in `core/ai-rmf-catalog.generated.json`. Validates every `use_case_id` exists in `ai-inventory.json`. Emits `out/ai-risk-register.json` with provenance.

5. Inherent risk derivation: from likelihood × impact via NIST SP 800-30 Table I-2 (reused from LOOP-B.B5's `INHERENT_RISK_MATRIX` constant).

6. Residual risk derivation: when `compensating_control_uuids[]` is non-empty AND each linked CC is active, residual drops one band from inherent. Operator can override; the override is logged.

7. Join into LOOP-B.B5 risk-register (`core/risk-register.ts:buildRiskRegister()`):
   - When `--ai-risk-register` is set, the LOOP-B join emits AI risks as `RiskRegisterEntry` with `source='ai'`, `category='ai.<category>'`, `references.ai_use_case_id = ...`, `references.ai_rmf_subcategory_ids = [...]`.
   - De-duplication: prefer the AI risk row over a finding-source row with overlapping `references.finding_uuid` (rare; documented).

8. POA&M projection (`core/oscal-poam.ts:findingProps()`):
   - AI risks with `status='open'` AND `inherent_risk ∈ {high, very-high}` produce poam-items via the existing emission pipeline.
   - Props added:
     ```ts
     if (f.category.startsWith('ai-')) {
       props.push({ name: 'ai-use-case-id', ns: CE_NS, value: f.ai_use_case_id });
       props.push({ name: 'ai-risk-category', ns: CE_NS, value: f.ai_risk_category });
       props.push({ name: 'ai-rmf-subcategory', ns: CE_NS, value: f.ai_rmf_subcategory_ids.join(',') });
       if (f.gen_ai_profile_category) props.push({ name: 'ai-gen-ai-profile-category', ns: CE_NS, value: f.gen_ai_profile_category });
     }
     ```

9. Orchestrator wiring: `--ai-risk-register` invokes the aggregator AFTER `--ai-inventory` + `--ai-rmf` and BEFORE `--risk-register` (LOOP-B.B5) and `--oscal-poam`.

10. Bundler: add role `ai-risk-register` with filename `ai-risk-register.json` and description "AI-specific risks (NIST AI 600-1 + AI 100-1) per use case (LOOP-O.O3)".

11. Sign + timestamp: `ai-risk-register.json` + `ai-risk-taxonomy.generated.json` flow through `core/sign.ts` glob.

12. Tracker UI: list view per use case with severity heatmap; per-risk detail page with treatment + compensating control selector + sign-off. Status transitions auditable in `audit_log`.

## REQUIRES-OPERATOR-INPUT fields
| Field | Source | Behavior when missing |
|---|---|---|
| `likelihood`, `impact` | Operator-supplied at risk creation | Cannot create AI risk row without both |
| `treatment` | Operator-supplied | Required field |
| `owner_user_id` | Operator-supplied | Required |
| `gen_ai_profile_category` | Operator-supplied; required when category ∈ {cbrn, dangerous-violent-hateful, obscene-degrading-abusive, value-chain} | Typed validation error |
| Bias / fairness test result uploads | Tracker form; sha256 + signature | Risk row blocked from `addressed` status until evidence uploaded |
| Drift threshold | `config/ai-risk-thresholds.yaml` | Defaults used; documented in CHANGELOG |
| `compensating_control_uuids[]` (when treatment=mitigate) | Tracker form linking to LOOP-B.B4 CCs | Recommended but not required at creation; surfaces in coverage |
| `review_date` | Operator-supplied; ≥30 days forward | Typed validation error |
| Red-team / pen-test results (adversarial, prompt-injection, data-poisoning) | Operator-uploaded | Risk row stays `category='adversarial'` with `evidence_refs=[]` and surfaces as REQUIRES-OPERATOR-INPUT |

## Test specifications (≥12 tests)
1. `it('loads ai-risk-taxonomy.generated.json with 12 GenAI categories from NIST AI 600-1')` — assert count + names.
2. `it('rejects AiRisk with description < 100 chars')` — typed error.
3. `it('rejects AiRisk where likelihood/impact not in 800-30 enum')` — typed error.
4. `it('creates a bias risk when Fairlearn upload exceeds operator threshold')` — fixture upload; threshold breach; risk auto-created.
5. `it('creates a drift risk when SageMaker Model Monitor alarm absent for in-operation use case')` — no alarm signal; risk emitted.
6. `it('does NOT create drift risk when use case is in-design or decommissioned')` — lifecycle gate.
7. `it('emits ai-risk-register.json with provenance block')` — guardrail check.
8. `it('joins to LOOP-B.B5 risk-register.json with source=ai and category prefixed ai.*')` — fixture join.
9. `it('projects high+open AI risk to poam-item with ai-* props')` — re-emit POA&M; assert props.
10. `it('does NOT project open AI risk to poam-item when severity is moderate or below')` — band gate.
11. `it('rejects ai_rmf_subcategory_ids not present in catalog')` — typed validation.
12. `it('tracker iso/cao role can create risk; viewer role cannot')` — RBAC check.
13. `it('residual_risk drops one band when active compensating control linked')` — pin matrix.
14. `it('GenAI profile category is required when category ∈ {cbrn, dangerous-violent-hateful, obscene-degrading-abusive, value-chain}')` — typed validation.
15. `it('bundler includes ai-risk-register role')` — pin WELL_KNOWN.
16. `it('MITRE ATLAS technique ids surface in poam-item props for adversarial/prompt-injection/data-poisoning')` — pin props.

## REO compliance
- Every risk derives from a cloud signal, tracker evidence, or operator-uploaded evaluation result. No synthetic risks.
- The 12 GenAI categories sourced verbatim from NIST AI 600-1 (extraction script enforced).
- Aggregator is a join, not a generator.
- POA&M projection uses existing LOOP-A.A1 + LOOP-B.B1 pipelines — no parallel emission path.
- Provenance populated on `ai-risk-register.json` + `ai-risk-taxonomy.generated.json`.
- Signed by: existing `core/sign.ts` Ed25519 pipeline + RFC 3161 timestamp manifest.
- No silent fallback band derivation: when likelihood or impact missing, the row is rejected — never assigned a default band.

## Verification commands
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/ai-risk-register.test.ts tests/scripts/extract-ai-risk-taxonomy.test.ts
npm run check:reo
npm run check:provenance
cd ../tracker
npm run typecheck
npm test
```

## Known risks / issues
- **Risk 1: NIST AI 600-1 PDF anonymous fetch may return 403 (same pattern as M-24-10 PDF).** Mitigation: operator downloads to `docs/sources/nist-ai-600-1.pdf`; `--strict-ai` mode blocks ship if `REQUIRES-OPERATOR-INPUT: confirm-against-nist-ai-600-1-pdf` marker remains.
- **Risk 2: Bias/fairness thresholds are domain-specific — defaults may not fit operator's use case.** Mitigation: `config/ai-risk-thresholds.example.yaml` documents the default + operator-tunable values; CHANGELOG explains thresholds.
- **Risk 3: Drift detection relies on monitoring artifacts being present (SageMaker Model Monitor, Vertex Model Monitoring); absence may mean "not yet provisioned" OR "intentionally not using"** — Mitigation: operator can declare `drift_monitoring_strategy: 'monitoring-service'|'custom-scripts'|'manual'|'not-applicable'` in `config/ai-inventory.yaml`; only `not-applicable` suppresses the risk creation.
- **Risk 4: MITRE ATLAS taxonomy evolves continuously.** Mitigation: snapshot file with sha256; CHANGELOG entry pins the snapshot date; re-run extraction script bumps version in provenance.
- **Risk 5: Cross-source de-duplication (AI risk vs finding) could surprise operators.** Mitigation: documented in code comment; the dedupe step logs the de-dupe key for audit; tests pin the behavior.
- **Risk 6: Composite-score-equivalent for AI risks deferred to a future O.O6.** Mitigation: O.O3 ships qualitative bands only; LOOP-O-SPEC.md §7 Q4 records the deferral; CHANGELOG calls it out.

## Open questions
- **Q1: When an AI risk's residual_risk is high BUT a compensating control is linked AND active, should the POA&M projection fire?** Recommend: yes — residual_risk is the projection trigger; operator should aim to drive inherent down via the CC. Pin in test.
- **Q2: For `prompt-injection` and `data-poisoning` risks, should the row require an associated MITRE ATLAS technique id?** Recommend: yes — typed validation; surfaces taxonomy linkage in poam props.
- **Q3: When the same AI risk applies to multiple use cases (e.g. shared model across use cases), how do we represent — one row per use_case_id, or one row with `use_case_ids[]`?** Recommend: one row per use_case_id (mirror LOOP-B finding model); operator UI links them via "duplicate to next use case" action.

## Implementation log
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥16 for this slice)
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
3. Read `cloud-evidence/docs/loops/LOOP-O-SPEC.md` Section 5 (slice O.O3).
4. Read `cloud-evidence/docs/slices/O/O.O1.md` + `O.O2.md` — O.O3 reads their outputs.
5. Read `cloud-evidence/docs/slices/B/B.B5.md` + `B.B1.md` + `B.B4.md` — the patterns you're extending (risk-register join, score bands, compensating control link).
6. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
7. Read `cloud-evidence/core/risk-register.ts` — the LOOP-B.B5 aggregator you'll extend.
8. Read `cloud-evidence/core/oscal-poam.ts:findingProps()` — your POA&M props extension point.
9. Read `cloud-evidence/core/findings.ts` — the category enum you'll extend.
10. Begin implementation; update Implementation log section as you go.

---
