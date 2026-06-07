# LOOP-O — AI/ML Governance (NIST AI RMF + OMB M-24-10)

> Comprehensive implementation specification for the five slices in LOOP-O.
> Authored as a stand-alone artifact: any future Claude / human session can
> execute LOOP-O end-to-end by reading ONLY this file + the five supporting
> files cited in Section 3 ("Dependencies"). No prior conversation history
> required.
>
> Authority: `cloud-evidence/CLAUDE.md` (Real-Evidence-Only standard) governs
> every slice below. Every byte emitted must trace back to real evidence or
> operator-supplied configuration. Slices ship under the Real Slice Contract
> in CLAUDE.md Rule 2.
>
> Loop classification: **conditional**. LOOP-O is required when the CSO
> uses AI/ML anywhere (model-as-a-service, embedded inference, retrieval-
> augmented generation, agentic copilots, ML-based detection, recommendation
> systems, content moderation, automated decisioning). If the CSO ships
> zero AI surfaces, the loop is N/A but O.O1 still ships as a single
> operator-signed `no-ai-use-cases-attested` envelope — REO Rule 4 forbids
> a silent "no AI" default.

---

## 1. Why this loop exists

### The regulatory shift (2023 - 2026)

Between October 2023 and March 2025, the United States stood up the most
explicit federal AI-governance regime in its history:

1. **Executive Order 14110** (Oct 30 2023) — "Safe, Secure, and Trustworthy
   Development and Use of Artificial Intelligence." Directed agencies to
   adopt NIST AI RMF and required risk-management practices for federal
   AI use cases.
2. **NIST AI Risk Management Framework 1.0** (AI 100-1, Jan 2023) — the
   normative four-function (GOVERN / MAP / MEASURE / MANAGE) framework
   that EO 14110 promulgates.
3. **NIST AI 600-1 GenAI Profile** (Jul 2024) — the generative-AI-specific
   subcategory overlay for the AI RMF.
4. **OMB Memorandum M-24-10** (Mar 28 2024) — "Advancing Governance,
   Innovation, and Risk Management for Federal Agencies' Use of
   Artificial Intelligence." Mandated agency AI-use-case inventories,
   Chief AI Officer designations, and minimum practices for "safety-
   impacting" and "rights-impacting" AI.
5. **OMB Memorandum M-25-21** (Mar 2025) — "Driving Efficient Acquisition
   of Artificial Intelligence in Government." Procurement-side flow-down
   of M-24-10. Required vendors (i.e. CSPs) supplying AI capabilities to
   federal agencies to evidence their risk-management practices in the
   contract record.
6. **Executive Order 14179** (Jan 2025) — "Removing Barriers to AI
   Leadership." Re-tuned but did NOT rescind M-24-10's inventory and
   minimum-practice requirements; instead emphasised pro-innovation
   posture for agency adoption.

The net effect at FedRAMP 20x Moderate is that any CSP whose CSO surfaces
AI capabilities to a federal customer carries a fresh, structured AI
governance burden that the existing 49 LOOP-A through LOOP-K slices do
NOT cover. The gaps:

| Gap | Source | Closed by |
|---|---|---|
| AI/ML asset inventory does not exist as a structured artifact | OMB M-24-10 Attachment 1 §1; AI RMF GOVERN 1.6 | O.O1 |
| NIST AI RMF four-function evidence not collected per AI surface | NIST AI 100-1 §5 (Core); OMB M-24-10 §IV | O.O2 |
| AI-specific risks (bias, fairness, robustness, adversarial, drift, hallucination) not enumerated alongside LOOP-B risks | AI RMF MAP 5.1, MEASURE 2.11, MANAGE 1.3 | O.O3 |
| Pre-deployment + ongoing AI evaluation not evidenced per OMB M-24-10 §V | OMB M-24-10 §V.B + §V.C; AI RMF MEASURE 2.1-2.13 | O.O4 |
| Per-model documentation (Model Cards) and per-dataset documentation (Datasheets) not emitted | Mitchell et al. 2018 (Model Cards); Gebru et al. 2018 (Datasheets); AI RMF MEASURE 2.8 | O.O5 |

### What LOOP-O delivers

| # | Artifact | Source | Consumer |
|---|---|---|---|
| 1 | `out/ai-inventory.json` + `.xlsx` — per-AI-surface structured inventory | O.O1 | OMB M-24-10 §III; LOOP-A SSP §13 (architecture); LOOP-I exec dashboard |
| 2 | `out/ai-rmf-evidence.json` — GOVERN+MAP+MEASURE+MANAGE evidence per AI use case | O.O2 | NIST AI RMF self-assertion; LOOP-A AR; agency AI governance office |
| 3 | `out/ai-risk-register.json` — AI-specific risks beside LOOP-B's risk register | O.O3 | LOOP-A POA&M (when AI risks trigger findings); LOOP-B risk register; RMS doc |
| 4 | `out/ai-evaluation-ledger.json` — pre-deployment + ongoing evaluation results | O.O4 | OMB M-24-10 §V.B/§V.C evidence; AFR-PVA continuous loop; LOOP-E monthly report |
| 5 | `out/model-cards/<model-id>.md` + `out/datasheets/<dataset-id>.md` — per-model + per-dataset documentation | O.O5 | 3PAO assessment package; agency procurement record (M-25-21); SSP back-matter |
| 6 | `no-ai-use-cases-attested.json` — when CSO has zero AI surfaces, operator-signed attestation | O.O1 conditional | OMB M-24-10 §III conditional path; CHANGELOG record |

### Authorization-package gaps closed (FedRAMP Moderate)

| Package gap | Slice | Authoritative source |
|---|---|---|
| SSP §13 AI architecture: no structured listing of model providers, training data flows, inference endpoints | O.O1 | FedRAMP Rev5 SSP Template §13 + OMB M-24-10 Attachment 1 |
| AI risk-management practices not evidenced in AR | O.O2 | NIST AI 100-1 §5 (Core functions); OMB M-24-10 §IV |
| Bias / fairness / robustness / adversarial assessments not in POA&M-source pipeline | O.O3 | NIST AI 100-1 MEASURE 2.11 (Fairness and bias); MEASURE 2.7 (Security and resilience) |
| Pre-deployment safety testing not retained as evidence | O.O4 | OMB M-24-10 §V.C ("safety-impacting AI") + §V.B ("rights-impacting AI") |
| Model + dataset provenance not part of submission bundle | O.O5 | OMB M-25-21 procurement-record requirements; NIST AI 100-1 MEASURE 2.8 (Transparency) |

### Connection to FedPy mission (read-only evidence-grade)

LOOP-O extends — never replaces — FedPy's core pattern of cloud-evidence
collection. Every AI-related claim in the emitted artifacts derives from
one of:

1. **A read-only SDK call** to detect AI services (AWS SageMaker / Bedrock,
   GCP Vertex AI, Azure ML / OpenAI Service, etc.).
2. **A real cloud resource tag** declaring the AI use case (`ai_use_case`,
   `ai_model_provider`, `ai_data_classification`, etc.).
3. **An operator-supplied `config/ai-inventory.yaml`** entry (REO Rule 4
   path: when the cloud cannot self-report the model identity, the
   operator commits it).
4. **A tracker DB record** with signed sign-off (e.g. an
   `ai_risk_assessments` row signed by the AI governance lead).

No model output is ever materialised by FedPy. Inference content is NEVER
captured for evidence (privacy + REO + scope reasons). FedPy captures
configuration, control, and assessment metadata — not data.

---

## 2. Connection to FedPy mission

### Which existing FedPy collectors LOOP-O EXTENDS or READS FROM

| Collector / module | Modification | Slice |
|---|---|---|
| `providers/aws/inventory.ts` | Extended to identify SageMaker Notebooks, Endpoints, Pipelines; Bedrock model invocations (CloudTrail); Comprehend, Rekognition, Textract, Translate, Transcribe service usage | O.O1 |
| `providers/gcp/inventory.ts` | Extended to identify Vertex AI Endpoints, Workbench, Pipelines, Model Garden uses, Document AI, Natural Language, Vision, Speech, Translate | O.O1 |
| `providers/azure/inventory.ts` | Extended to identify Azure ML workspaces, Azure OpenAI Service deployments, Cognitive Services, Form Recognizer, Speech, Translator, Anomaly Detector | O.O1 |
| `core/inventory.ts` | Adds `ai_assets[]` array on the inventory model; per-asset attributes: `model_provider`, `model_family`, `model_version`, `inference_endpoint_url`, `training_data_classification`, `training_data_source`, `m24_10_use_case_id` | O.O1, O.O5 |
| `core/control-benchmark.ts` | Adds AI-specific control mapping: NIST 800-53 SR-3/SR-11 (supply chain — for model provenance), SI-7 (software integrity — for model integrity), CA-7 (continuous monitoring — for drift), RA-3 (risk assessment — for AI risks). Cross-references AI RMF subcategories to 800-53 controls | O.O2 |
| `core/oscal-ssp.ts` | Adds back-matter resource entries for AI inventory + AI RMF evidence; adds component-of-type `software` for major AI surfaces; populates `implemented-requirements[].statements[].props` with AI-relevant evidence pointers | O.O1, O.O2 |
| `core/oscal-poam.ts` | Adds AI-specific finding categories (`ai-bias`, `ai-drift`, `ai-hallucination`, `ai-prompt-injection`, `ai-data-poisoning`) to the finding-class taxonomy. AI risks from O.O3 produce poam-items via existing emission pipeline | O.O3 |
| `core/pva-collector.ts` (AFR-PVA persistent-validation meta) | Extended to schedule AI-evaluation re-runs at the cadence O.O4 dictates (default monthly, configurable per-use-case) | O.O4 |
| `core/risk-register.ts` (LOOP-B.B5) | Joined with AI risk register from O.O3; output `risk-register.json` carries `source='ai'` rows alongside `source='finding'` and `source='organisational'` | O.O3 |
| `tracker/server/schema.sql` | Adds tables `ai_assets`, `ai_use_cases`, `ai_risk_assessments`, `ai_evaluations`, `ai_evaluation_runs`, `model_cards`, `datasheets`, `ai_governance_signoffs` | O.O1, O.O2, O.O3, O.O4, O.O5 |
| `core/submission-bundle.ts` | Adds 8 new roles: `ai-inventory-json`, `ai-inventory-xlsx`, `ai-rmf-evidence`, `ai-risk-register`, `ai-evaluation-ledger`, `model-cards-bundle`, `datasheets-bundle`, `ai-attestation` | All slices |
| `scripts/check-reo.mjs` / `scripts/check-provenance.mjs` | Augmented to verify every AI emit field carries provenance + no silent "no AI" defaults appear | All slices |

### NEW modules created in LOOP-O

| Module | Purpose | Slice |
|---|---|---|
| `core/ai-inventory.ts` | Discovers AI/ML assets across providers; emits structured JSON inventory | O.O1 |
| `core/ai-inventory-xlsx.ts` | OMB M-24-10 Attachment-1-aligned XLSX renderer for the inventory | O.O1 |
| `core/ai-rmf.ts` | Collects GOVERN / MAP / MEASURE / MANAGE evidence per AI use case; reads from tracker + cloud signals; maps to AI RMF subcategories with verbatim quoted definitions | O.O2 |
| `core/ai-rmf-catalog.generated.json` | The 71 AI RMF subcategories (19 GOVERN + 18 MAP + 21 MEASURE + 13 MANAGE) extracted from NIST AI 100-1 + AIRC | O.O2 |
| `core/ai-risk-register.ts` | Aggregates AI-specific risks (bias, fairness, robustness, adversarial, drift, hallucination, prompt-injection, data-poisoning, IP-leak) | O.O3 |
| `core/ai-risk-taxonomy.generated.json` | The canonical AI-risk taxonomy with NIST AI 600-1 GenAI Profile cross-references | O.O3 |
| `core/ai-evaluation.ts` | Pre-deployment + ongoing evaluation orchestrator: schedules runs, records results, ties to AFR-PVA | O.O4 |
| `core/ai-evaluation-readers/` | Adapters for evaluation harness output formats (HELM, BIG-bench, MMLU, TruthfulQA, OpenAI evals, Anthropic Constitutional AI evals — when operator opts in to publish results) | O.O4 |
| `core/model-card.ts` | Per-model Markdown emitter following Mitchell et al. (2018) sections | O.O5 |
| `core/datasheet.ts` | Per-dataset Markdown emitter following Gebru et al. (2018) sections | O.O5 |
| `core/ai-attestation.ts` | When CSO declares no AI surfaces, emits the operator-signed `no-ai-use-cases-attested.json` envelope | O.O1 |

---

## 3. Dependencies

### Loops / slices that MUST complete first

| Dep | Why |
|---|---|
| LOOP-A.A1 (`core/oscal-poam.ts`) | O.O3 adds AI-specific finding categories; needs the POA&M emission pipeline + risk-status enum |
| LOOP-A.A2 (`core/oscal-ap.ts`) | O.O2 adds AI RMF GOVERN/MAP/MEASURE/MANAGE coverage to the AP's `assessment-assets` block |
| LOOP-A.A3 (SSP→AP→AR chain) | O.O2's AI RMF evidence appears in AR as `observation[]`; chain validation ensures back-references work |
| LOOP-A.A4 (`core/submission-bundle.ts`) | O.O1–O.O5 add eight new roles to the well-known role catalog |
| LOOP-B.B1 (`core/risk-score.ts`) | O.O3's AI risks reuse the composite-score pattern for prioritisation |
| LOOP-B.B3 (risk-acceptance + tracker DB pattern) | O.O3 reuses the signed-record pattern for AI risk acceptances; O.O4 reuses for evaluation sign-offs |
| LOOP-B.B5 (`core/risk-register.ts`) | O.O3's AI risks are joined into the consolidated register with `source='ai'` discrimination |
| INV-P1..S6 (`inventory.json`) | O.O1 extends the inventory model with `ai_assets[]`; collectors must already populate the asset-tier + data-classification fields |
| `core/pva-collector.ts` (AFR-PVA) | O.O4 schedules AI evaluations via the AFR-PVA cadence machinery |
| `core/control-benchmark.ts` | O.O2 cross-references AI RMF subcategories to 800-53 controls via the benchmark engine |
| `core/inventory.ts` model definitions | O.O1 ADDS to it; the existing schema must not be regressed |

### Existing files this loop EXTENDS

| File | Modification |
|---|---|
| `cloud-evidence/core/inventory.ts` | Add `ai_assets: AiAsset[]` to the inventory model; add `AiAsset` interface (model_provider, model_family, model_version, inference_endpoint_url, training_data_classification, training_data_source, m24_10_use_case_id, risk_category, deployment_date, last_evaluation_date, evaluation_cadence_days) |
| `cloud-evidence/providers/aws/inventory.ts` | Add `discoverAiAssets(region)` — enumerates SageMaker, Bedrock, Comprehend, Rekognition, Textract, Translate, Transcribe, Personalize, Forecast, Lex |
| `cloud-evidence/providers/gcp/inventory.ts` | Add `discoverAiAssets(project)` — Vertex AI Endpoints/Workbench/Pipelines/Model Garden uses, Document AI, Natural Language, Vision, Speech, Translate |
| `cloud-evidence/providers/azure/inventory.ts` | Add `discoverAiAssets(subscription)` — Azure ML workspaces, Azure OpenAI deployments, Cognitive Services |
| `cloud-evidence/core/envelope.ts` | Add `ai_risk_score?: AiRiskScore` optional field on `Finding` (parallel to `risk_score` from LOOP-B.B1); add `AiRiskScore` type |
| `cloud-evidence/core/findings.ts` | Allow `category` enum to include the new `ai-bias`, `ai-drift`, `ai-hallucination`, `ai-prompt-injection`, `ai-data-poisoning`, `ai-supply-chain`, `ai-pii-leak`, `ai-ip-leak` values |
| `cloud-evidence/core/oscal-ssp.ts` | Add `back-matter.resources[]` of type `model-card`, `datasheet`, `ai-rmf-evidence`; populate `system-characteristics.system-information.information-type[]` for AI-handled data when relevant |
| `cloud-evidence/core/oscal-poam.ts` | `findingProps()` adds `ai-use-case-id`, `ai-risk-category`, `ai-rmf-subcategory` props on AI-sourced findings |
| `cloud-evidence/core/orchestrator.ts` | New flags: `--ai-inventory`, `--ai-rmf`, `--ai-risk-register`, `--ai-evaluation`, `--model-cards`, `--ai-attestation`, `--strict-ai` plus env equivalents (`CLOUD_EVIDENCE_AI_*`) |
| `cloud-evidence/core/submission-bundle.ts` | Add 8 roles to `WELL_KNOWN` catalogue |
| `cloud-evidence/CHANGELOG.md` | "Unreleased" entry per slice |
| `cloud-evidence/docs/STATUS.md` | Per-slice status line updated on slice ship |
| `tracker/server/schema.sql` | 8 new tables (see Section 4 per-slice schemas) |
| `tracker/server/index.ts` | Mount routes `/api/ai-inventory`, `/api/ai-use-cases`, `/api/ai-risk-assessments`, `/api/ai-evaluations`, `/api/model-cards`, `/api/datasheets`, `/api/ai-governance-signoffs` |
| `tracker/client/src/App.tsx` | Add navigation entries: `/ai-inventory`, `/ai-rmf`, `/ai-risks`, `/ai-evaluations`, `/model-cards`, `/datasheets` |

### Loops UNBLOCKED when LOOP-O is complete

| Unblocked loop | Reason |
|---|---|
| LOOP-C.C7 — Risk Management Strategy doc | RMS pulls AI risks from O.O3's register alongside LOOP-B risks |
| LOOP-E.E1 — Monthly ConMon analysis | Monthly report includes AI evaluation deltas + AI risk burndown |
| LOOP-G.G3 — AFR-ADS publication | Service list disclosure includes AI surfaces declared in O.O1 |
| LOOP-I.I1 — Executive posture dashboard | AI risk burndown + evaluation cadence panel |
| LOOP-Q.Q1 (proposed) — Marketplace metadata | AI capability declaration is a Marketplace field |
| LOOP-N.N1 (proposed) — Threat modeling | AI adversarial threats (prompt injection, data poisoning, model theft) flow into threat model |

---

## 4. Authoritative sources

Every URL + spec referenced in any LOOP-O slice. All quotes are verbatim
where retrievable from public sources. Where the source PDF returns binary
content unsuitable for inline quotation, the implementer downloads the PDF
to `cloud-evidence/docs/sources/` and re-quotes from the local copy.

### NIST AI Risk Management Framework

- **NIST AI 100-1 — Artificial Intelligence Risk Management Framework
  (AI RMF 1.0)** (Jan 2023) —
  https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf
  - §3 ("Framing AI Risks") frames AI risk as "the composite measure of
    an event's probability of occurring and the magnitude or degree of the
    consequences of the corresponding events."
  - §4 ("AI Risks and Trustworthiness") enumerates the seven characteristics
    of trustworthy AI: "Valid and Reliable; Safe; Secure and Resilient;
    Accountable and Transparent; Explainable and Interpretable; Privacy-
    Enhanced; Fair – with Harmful Bias Managed."
  - §5 ("AI RMF Core") defines the four functions:
    - **GOVERN** — "A culture of risk management is cultivated and present"
    - **MAP** — "Context is recognized and risks related to context are
      identified"
    - **MEASURE** — "Identified risks are assessed, analyzed, or tracked"
    - **MANAGE** — "Risks are prioritized and acted upon based on a
      projected impact"
  - Subcategory list (verbatim from
    https://airc.nist.gov/AI_RMF_Knowledge_Base/AI_RMF/Core_And_Profiles/5-sec-core):
    71 subcategories total. Selected examples cited in O.O2:
    - **GOVERN 1.1** — "Legal and regulatory requirements involving AI are
      understood, managed, and documented."
    - **GOVERN 1.6** — "Mechanisms are in place to inventory AI systems and
      are resourced according to organizational risk priorities."
    - **MAP 1.1** — "Intended purposes, potentially beneficial uses,
      context-specific laws, norms and expectations, and prospective
      settings in which the AI system will be deployed are understood and
      documented."
    - **MEASURE 2.5** — "The AI system to be deployed is demonstrated to be
      valid and reliable. Limitations of the generalizability beyond the
      conditions under which the technology was developed are documented."
    - **MEASURE 2.6** — "The AI system is evaluated regularly for safety
      risks – as identified in the map function. The AI system to be
      deployed is demonstrated to be safe, its residual negative risk does
      not exceed the risk tolerance, and it can fail safely."
    - **MEASURE 2.7** — "AI system security and resilience – as identified
      in the map function – are evaluated and documented."
    - **MEASURE 2.8** — "Risks associated with transparency and
      accountability – as identified in the map function – are examined
      and documented."
    - **MEASURE 2.9** — "The AI model is explained, validated, and
      documented, and AI system output is interpreted within its context."
    - **MEASURE 2.10** — "Privacy risk of the AI system – as identified in
      the map function – is examined and documented."
    - **MEASURE 2.11** — "Fairness and bias – as identified in the map
      function – are evaluated and results are documented."
    - **MEASURE 2.12** — "Environmental impact and sustainability of AI
      model training and management activities – as identified in the map
      function – are assessed and documented."
    - **MANAGE 1.3** — "Responses to the AI risks deemed high priority, as
      identified by the map function, are developed, planned, and
      documented. Risk response options can include mitigating,
      transferring, avoiding, or accepting."
    - **MANAGE 4.1** — "Post-deployment AI system monitoring plans are
      implemented, including mechanisms for capturing and evaluating input
      from users and other relevant AI actors, appeal and override,
      decommissioning, incident response, recovery, and change management."

- **NIST AI 600-1 — Artificial Intelligence Risk Management Framework:
  Generative Artificial Intelligence Profile** (Jul 2024) —
  https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
  - Defines 12 GenAI-specific risk categories: CBRN information; confabulation;
    dangerous, violent, or hateful content; data privacy; environmental;
    harmful bias and homogenization; human-AI configuration; information
    integrity; information security; intellectual property; obscene,
    degrading, and/or abusive content; value chain and component integration.
  - These 12 categories form the seed taxonomy in
    `core/ai-risk-taxonomy.generated.json` (O.O3).

- **NIST AI RMF Playbook** (continuously updated) —
  https://airc.nist.gov/AI_RMF_Knowledge_Base/Playbook
  - The Playbook provides per-subcategory suggested actions, transparency
    and documentation items, references. Used by O.O2 to map each
    subcategory to an evidence-collection prompt.

### OMB Memoranda

- **OMB M-24-10** — "Advancing Governance, Innovation, and Risk Management
  for Federal Agencies' Use of Artificial Intelligence" (Mar 28 2024) —
  https://www.whitehouse.gov/wp-content/uploads/2024/03/M-24-10-Advancing-Governance-Innovation-and-Risk-Management-for-Agency-Use-of-Artificial-Intelligence.pdf
  - **§II (Strengthening AI Governance)**: each agency designates a Chief
    AI Officer; establishes AI Governance Board; assigns roles for AI
    risk-management practices.
  - **§III (Advancing Responsible AI Innovation)**: agencies must publish
    annual AI use-case inventories per the Federal AI Use Case Inventory
    methodology (M-24-10 Attachment 1).
  - **§IV (Managing Risks from the Use of Artificial Intelligence)**:
    > "Agencies shall conduct risk management of their AI use cases
    > consistent with the NIST AI RMF and related guidance."
  - **§V.B ("rights-impacting" AI minimum practices)**: pre-deployment
    testing for disparate impact + ongoing monitoring + human consideration
    and remedy + opt-out where appropriate + consultation and feedback.
  - **§V.C ("safety-impacting" AI minimum practices)**: pre-deployment
    independent evaluation + ongoing testing for performance degradation
    + procedures to mitigate emergent risks + human override.
  - **Attachment 1 (Federal AI Use Case Inventory)**:
    > "Agencies shall maintain an inventory of AI use cases including a
    > use case identifier, owning office, vendor (if applicable), risk
    > category, and date of most recent risk evaluation."
  - The verbatim minimum-practice list at §V.B/§V.C — operator MUST
    download M-24-10 PDF to `cloud-evidence/docs/sources/m-24-10.pdf` and
    quote in `core/ai-evaluation.ts` docstring; until then, O.O4 carries
    `REQUIRES-OPERATOR-INPUT: confirm-against-m-24-10-pdf` marker on the
    minimum-practice constants.

- **OMB M-25-21** — "Driving Efficient Acquisition of Artificial
  Intelligence in Government" (Mar 2025) —
  https://www.whitehouse.gov/wp-content/uploads/2025/03/M-25-21-Memorandum.pdf
  - Procurement-side flow-down of M-24-10. CSPs providing AI to federal
    agencies must include risk-management practice evidence in the contract
    record; the AI inventory the CSP supplies to the agency feeds the
    agency's own M-24-10 inventory.

### Executive Orders

- **Executive Order 14110** — "Safe, Secure, and Trustworthy Development
  and Use of Artificial Intelligence" (Oct 30 2023) —
  https://www.whitehouse.gov/briefing-room/presidential-actions/2023/10/30/executive-order-on-the-safe-secure-and-trustworthy-development-and-use-of-artificial-intelligence/
  - §10.1(b): directs OMB to issue M-24-10 (preceding source).
  - Cited in LOOP-O introductions.

- **Executive Order 14179** — "Removing Barriers to American Leadership
  in Artificial Intelligence" (Jan 2025).
  - Re-tunes priorities but the M-24-10 inventory + minimum-practice
    obligations remain in force.

### Model Cards + Datasheets

- **Mitchell et al. (2018) — "Model Cards for Model Reporting"** —
  https://arxiv.org/abs/1810.03993
  - Proposes nine sections per Model Card:
    1. **Model Details** — person/org developing the model, model date,
       model version, model type, training algorithms, parameters, fairness
       constraints, paper/citation, license, where to send questions.
    2. **Intended Use** — primary intended uses, primary intended users,
       out-of-scope use cases.
    3. **Factors** — relevant factors, evaluation factors.
    4. **Metrics** — model performance measures, decision thresholds,
       variation approaches.
    5. **Evaluation Data** — datasets, motivation, preprocessing.
    6. **Training Data** — link to Datasheet for Datasets if available.
    7. **Quantitative Analyses** — unitary results, intersectional results.
    8. **Ethical Considerations** — data, human life, mitigations, risks
       and harms, use cases.
    9. **Caveats and Recommendations** — additional concerns + suggestions.
  - These nine sections are the canonical structure O.O5's
    `model-card.ts` emits, with one Markdown subsection per section.

- **Gebru et al. (2018) — "Datasheets for Datasets"** —
  https://arxiv.org/abs/1803.09010
  - Proposes seven sections per Datasheet:
    1. **Motivation** — why the dataset was created, who funded, comments.
    2. **Composition** — what instances represent, how many, sampling,
       data per instance, labels, missing info, relationships, recommended
       splits, errors, external resources, confidential data, offensive
       content, sub-populations, individual identification, sensitive data.
    3. **Collection Process** — how data was acquired, mechanisms used,
       sampling strategy, who was involved, timeframe, ethical-review
       processes, consent, mechanism for revoking consent, analyses of
       impact.
    4. **Preprocessing/Cleaning/Labeling** — what was done, was raw data
       saved, software used.
    5. **Uses** — what has been done, repository, what could/should not be
       used for.
    6. **Distribution** — distribution mechanism, when, license, IP
       restrictions, export controls.
    7. **Maintenance** — who maintains, contact, erratum mechanism, update
       cadence, retention.
  - These seven sections are the canonical structure O.O5's
    `datasheet.ts` emits.

### Cross-jurisdiction context (for awareness; not FedRAMP-required)

- **EU AI Act** — https://artificialintelligenceact.eu/
  - Risk-based classification: unacceptable / high / limited / minimal.
  - Out-of-scope for FedRAMP Moderate (§4.7 of ADDITIONAL-LOOPS-AUDIT.md);
    informs O.O3 risk-category enum where overlap with NIST exists.

- **ISO/IEC 42001:2023 — Artificial intelligence — Management system** —
  - Voluntary AI management system standard; AI RMF + 42001 align on the
    GOVERN function in particular.
  - O.O2 records the cross-reference in `ai-rmf-catalog.generated.json`
    `iso_42001_clause` field when published mappings exist.

### NIST 800-53 Rev 5 controls cross-referenced

- **NIST SP 800-53 Rev 5** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
  - **RA-3** — Risk Assessment: AI risks contribute to the system-wide
    risk assessment LOOP-B.B5 produces. O.O3 supplies the AI rows.
  - **CA-7** — Continuous Monitoring: O.O4's ongoing AI evaluation is a
    CA-7 task; the evaluation cadence is recorded in the CA-7 strategy.
  - **SI-7** — Software, Firmware, and Information Integrity: model
    artifact integrity (signed weights, signed prompts) is an SI-7 control.
  - **SR-3** — Supply Chain Controls: model provider, training data
    provenance fall under SR-3.
  - **SR-11** — Component Authenticity: model integrity verification fits
    here when a third-party model is integrated.

### CISA / Federal AI-security guidance

- **CISA + UK NCSC "Guidelines for secure AI system development"** (Nov 2023) —
  - Supplementary guidance referenced by O.O2 for the secure-development
    portion of GOVERN 4 + MAP 4. Cited in operator runbook.

### FedRAMP cross-references

- **FedRAMP Rev5 SSP Template §13 (Control Implementation)** — currently
  lacks an explicit AI section; LOOP-O surfaces AI evidence into §13 via
  the existing component+resource pattern; SSP §11 (System Environment)
  gets an "AI/ML services" subsection populated from O.O1's inventory.
- **FedRAMP Authorization Boundary (RFC-0004)** — when AI inference
  calls cross a CSP boundary to a model provider, O.O1 + O.O5 capture
  the boundary crossing as a trust-boundary edge (cross-references LOOP-D
  diagram if implemented).
- **AFR-PVA** (FRMR AFR family) — O.O4 reuses the AFR-PVA cadence
  scheduling. Each AI use case is a PVA "rule" that re-runs on cadence.

---

## 5. Per-slice implementation specs

### Slice O.O1 — AI/ML asset inventory (models, training data, inference endpoints)

**Why this slice**: OMB M-24-10 Attachment 1 mandates an AI use-case
inventory. NIST AI RMF GOVERN 1.6 mandates organizational AI-system
inventory mechanisms. Today the FedPy `inventory.json` covers compute,
network, data, IAM — but has no first-class concept of an AI/ML asset.
O.O1 closes that gap by extending the inventory model and adding per-
provider AI discovery.

**Connection to FedPy mission**: O.O1 is a *cloud-evidence collector* in
the FedPy mode. It uses real read-only SDK calls (already gated by
`core/readonly-guardrail.ts`) to enumerate AWS SageMaker / Bedrock,
GCP Vertex AI / Document AI, Azure ML / Azure OpenAI surfaces. Cloud-
tag-supplied metadata (`ai_use_case`, `ai_data_classification`,
`ai_model_provider`) augments the SDK signal. The operator supplies
`config/ai-inventory.yaml` for the non-cloud bits (e.g. embedded models
shipped in container images, third-party model APIs called from
application code). When the CSO has zero AI surfaces, O.O1 emits a
single operator-signed `no-ai-use-cases-attested.json` envelope (REO
Rule 4 — never default to "no AI").

**Files to create**:
- `cloud-evidence/core/ai-inventory.ts` — discovery + emission core
- `cloud-evidence/core/ai-inventory-xlsx.ts` — OMB M-24-10 Attachment-1
  aligned XLSX renderer
- `cloud-evidence/core/ai-attestation.ts` — the "no AI" attestation path
- `cloud-evidence/providers/aws/ai-services.ts` — SageMaker/Bedrock/
  Comprehend/Rekognition/Textract/Translate/Transcribe/Lex/Personalize/
  Forecast/Q discovery
- `cloud-evidence/providers/gcp/ai-services.ts` — Vertex AI/Document AI/
  Natural Language/Vision/Speech/Translate discovery
- `cloud-evidence/providers/azure/ai-services.ts` — Azure ML/Azure OpenAI/
  Cognitive Services discovery
- `cloud-evidence/config/ai-inventory.example.yaml` — committed example
- `cloud-evidence/tests/core/ai-inventory.test.ts`
- `cloud-evidence/tests/core/ai-attestation.test.ts`
- `cloud-evidence/tests/providers/aws/ai-services.test.ts`
- `cloud-evidence/tests/providers/gcp/ai-services.test.ts`
- `cloud-evidence/tests/providers/azure/ai-services.test.ts`

**Files to extend**:
- `cloud-evidence/core/inventory.ts` — add `ai_assets: AiAsset[]` + the
  `AiAsset` interface
- `cloud-evidence/core/orchestrator.ts` — new `--ai-inventory` and
  `--ai-attestation` flags + env equivalents
- `cloud-evidence/core/submission-bundle.ts` — add roles
  `ai-inventory-json`, `ai-inventory-xlsx`, `ai-attestation`
- `cloud-evidence/core/oscal-ssp.ts` — populate SSP §11 AI/ML services
  subsection + `system-implementation.components[]` for each major AI
  surface

**Schemas / standards**:
- **OMB M-24-10 Attachment 1 Federal AI Use Case Inventory format** —
  per-row fields: `agency`, `bureau`, `use_case_id`, `use_case_name`,
  `summary`, `purpose_benefits`, `outputs`, `lifecycle_stage` (in-design,
  pilot, in-development, in-operation, decommissioned), `risk_category`
  (rights-impacting, safety-impacting, both, neither),
  `vendor_or_internally_developed`, `vendor_name` (if vendor),
  `contract_vehicle`, `model_provider`, `commercial_or_government_model`,
  `training_data_sources`, `purpose_authorities`, `recent_evaluation_date`,
  `next_evaluation_date`, `decommission_date_if_planned`,
  `safety_minimum_practice_compliance`, `rights_minimum_practice_compliance`,
  `safety_waiver_in_effect` (yes/no + justification),
  `rights_waiver_in_effect` (yes/no + justification).
- **AI RMF GOVERN 1.6** — inventory completeness covers all AI systems
  including pilots and decommissioned use cases (within retention window).

**Build steps**:

1. Define `AiAsset` interface in `core/inventory.ts`:
   ```ts
   export interface AiAsset {
     uuid: string;                                    // deterministic uuid v5
     m24_10_use_case_id?: string;                    // OMB inventory id
     name: string;
     provider_cloud: 'aws' | 'gcp' | 'azure' | 'other';
     provider_service: string;                       // e.g. 'aws.sagemaker', 'azure.openai'
     model_provider: string;                         // e.g. 'aws.bedrock.anthropic', 'openai', 'gcp.vertex.gemini', 'self-hosted'
     model_family: string;                           // e.g. 'claude-4-5-sonnet', 'gpt-4o', 'gemini-1.5-pro'
     model_version: string;
     deployment_type: 'inference-endpoint' | 'batch' | 'embedded' | 'external-api' | 'training-job';
     inference_endpoint_url?: string;                // when applicable
     training_data_classification: 'public' | 'internal' | 'confidential' | 'cui' | 'pii' | 'unknown';
     training_data_sources: string[];                // operator-supplied; required if vendor or self-trained
     lifecycle_stage: 'in-design' | 'pilot' | 'in-development' | 'in-operation' | 'decommissioned';
     risk_category: 'rights-impacting' | 'safety-impacting' | 'both' | 'neither';
     purpose: string;                                // free text, ≥50 chars
     intended_users: string[];                       // e.g. ['internal-staff', 'federal-customer']
     out_of_scope_uses: string[];                    // operator-declared limitations
     authority_to_use: string;                       // legal/policy authority
     deployment_date?: string;                       // ISO; null if not yet deployed
     decommission_date?: string;                     // ISO; null if not planned
     last_evaluation_date?: string;                  // ISO; null if never evaluated
     evaluation_cadence_days: number;                // default 90; per use case
     safety_minimum_practice_compliance?: 'compliant' | 'waiver' | 'in-progress' | 'not-applicable';
     rights_minimum_practice_compliance?: 'compliant' | 'waiver' | 'in-progress' | 'not-applicable';
     waiver_justification?: string;                  // required if waiver
     attributes: {
       discovered_via: 'cloud-sdk' | 'config-yaml' | 'tracker';
       cloud_resource_arn?: string;
       cloud_resource_self_link?: string;
       cloud_resource_id?: string;
       tags?: Record<string, string>;
     };
     synthesized_fields?: string[];                  // REO Rule 1.7
   }
   ```

2. Implement provider discovery:
   - `providers/aws/ai-services.ts`:
     ```ts
     export async function discoverSageMakerAssets(region: string): Promise<AiAsset[]>;
     export async function discoverBedrockUsage(region: string): Promise<AiAsset[]>;
     export async function discoverComprehendUsage(region: string): Promise<AiAsset[]>;
     // ... per service
     export async function discoverAllAiAssets(regions: string[]): Promise<AiAsset[]>;
     ```
     - SageMaker: `ListNotebookInstances`, `ListEndpoints`, `ListModels`,
       `ListPipelines`, `ListProcessingJobs`, `ListTrainingJobs` (read-only).
     - Bedrock: `ListFoundationModels`, `ListCustomModels`, CloudTrail
       lookup for `InvokeModel` events to detect runtime usage.
     - Comprehend: `ListEndpoints`, `ListEntityRecognizers`,
       `ListDocumentClassifiers`.
     - Rekognition / Textract / Translate / Transcribe: presence detection
       via resource enumeration (e.g. Rekognition collections, Translate
       custom terminologies).

   - `providers/gcp/ai-services.ts`:
     - Vertex AI: `aiplatform.endpoints.list`, `aiplatform.models.list`,
       `aiplatform.pipelineJobs.list`, `aiplatform.notebookInstances.list`.
     - Document AI: `documentai.processors.list`.
     - Natural Language / Vision / Speech / Translate: enable-state check
       via Service Usage API.

   - `providers/azure/ai-services.ts`:
     - Azure ML: `Microsoft.MachineLearningServices/workspaces` enumeration,
       per-workspace endpoints + models + pipelines.
     - Azure OpenAI: `Microsoft.CognitiveServices/accounts` filtered by
       `kind=OpenAI`; deployments enumerated per account.
     - Cognitive Services: `Microsoft.CognitiveServices/accounts` for all
       kinds (FormRecognizer, SpeechServices, TextAnalytics, etc.).

3. Operator-supplied augmentation (`config/ai-inventory.yaml`):
   ```yaml
   ai_use_cases:
     - use_case_id: AIUC-001
       name: customer-support-copilot
       model_provider: anthropic.api
       model_family: claude-4-5-sonnet
       model_version: claude-4-5-sonnet-20251022
       deployment_type: external-api
       training_data_classification: public
       training_data_sources:
         - anthropic-published-training-data
       lifecycle_stage: in-operation
       risk_category: neither
       purpose: |
         Customer support routing recommendations for federal customers...
       intended_users: [internal-support-team]
       out_of_scope_uses: [authorization decisions, automated remediation]
       authority_to_use: |
         Acquisition under M-25-21; pre-deployment evaluation per M-24-10 §V.C.
       deployment_date: 2026-04-15
       evaluation_cadence_days: 90
   ```

4. Discovery + merge:
   ```ts
   export async function buildAiInventory(
     ctx: AiInventoryContext,
   ): Promise<AiInventory>;
   ```
   Where `AiInventoryContext = { providers, configYamlPath, inventoryPath, runId }`.
   - Walks all providers' `discoverAllAiAssets` results.
   - Merges with `config/ai-inventory.yaml` entries (config wins on
     metadata conflicts; cloud-discovered status wins on presence).
   - Cross-references cloud-resource-tags `ai_use_case`, `ai_model_provider`,
     `ai_data_classification` to populate fields not in the SDK.
   - Emits coverage report rows for assets discovered but lacking
     mandatory metadata (`m24_10_use_case_id`, `risk_category`,
     `purpose`) — these surface as REQUIRES-OPERATOR-INPUT.

5. JSON emit `out/ai-inventory.json` with provenance block:
   ```json
   {
     "schema_version": "ai-inventory.v1",
     "run_id": "...",
     "emitted_at": "2026-06-07T...",
     "ai_assets": [ ... ],
     "coverage": {
       "discovered_assets": N,
       "operator_supplied_assets": M,
       "assets_missing_use_case_id": K,
       "assets_missing_risk_category": K2,
       "assets_missing_purpose": K3
     },
     "provenance": {
       "emitter": "cloud-evidence/core/ai-inventory.ts",
       "sourceCalls": [ ... ],
       "configReads": [ "config/ai-inventory.yaml" ],
       "signingKeyId": "..."
     }
   }
   ```

6. XLSX emit `out/ai-inventory.xlsx` via `core/ai-inventory-xlsx.ts`:
   columns mirror OMB M-24-10 Attachment 1 (use_case_id, name, summary,
   risk_category, vendor, model_provider, training_data_sources,
   safety_minimum_practice_compliance, rights_minimum_practice_compliance,
   deployment_date, last_evaluation_date, next_evaluation_date, etc.).
   Pure-JS XLSX pattern matches `core/inventory-workbook.ts`.

7. Conditional "no AI" attestation (`core/ai-attestation.ts`):
   - Triggered when the discovery phase returns zero assets AND
     `--ai-attestation` flag is set.
   - Reads operator's signed attestation from
     `out/.ai-attestation.json` (a tracker snapshot).
   - The attestation requires `signed_by_user_id` with `iso` or `cao`
     (Chief AI Officer) role + signature + signing key + `attested_at`.
   - Without an operator attestation, the orchestrator under
     `--strict-ai` exits non-zero and the CHANGELOG/STATUS line for the
     run shows "REQUIRES-OPERATOR-INPUT: AI attestation".

8. Wire orchestrator: `--ai-inventory` invokes `buildAiInventory()`;
   `--ai-attestation` is the no-AI path. Both run BEFORE `--oscal-ssp`
   so the SSP can populate §11 from the inventory.

9. SSP integration (`core/oscal-ssp.ts`):
   - When `ai-inventory.json` is present and `ai_assets.length > 0`,
     `system-characteristics.system-information.information-type[]` gets
     an entry for each `training_data_classification` value seen.
   - `system-implementation.components[]` adds one `software`-typed
     component per major AI surface (Bedrock model, Vertex endpoint,
     Azure OpenAI deployment) with `type=software` + `props["ai-use-case-id"]`.
   - `back-matter.resources[]` adds an entry of type `data` pointing to
     `out/ai-inventory.json`.

10. Bundler integration: add three roles to `submission-bundle.ts:WELL_KNOWN`:
    ```ts
    { role: 'ai-inventory-json', filename: 'ai-inventory.json', description: 'AI/ML asset inventory (LOOP-O.O1; OMB M-24-10 Attachment 1)' },
    { role: 'ai-inventory-xlsx', filename: 'ai-inventory.xlsx', description: 'AI/ML asset inventory in OMB Attachment 1 format' },
    { role: 'ai-attestation', filename: 'no-ai-use-cases-attested.json', description: 'Signed operator attestation that the CSO surfaces zero AI use cases' },
    ```

11. Sign + timestamp: `ai-inventory.json` + `ai-inventory.xlsx` +
    `no-ai-use-cases-attested.json` flow through `core/sign.ts` glob.

12. Coverage: every AI asset with REQUIRES-OPERATOR-INPUT on
    `m24_10_use_case_id`, `risk_category`, or `purpose` is logged via
    `coverage:miss` in the run log + counted in `coverage.json`.

**REQUIRES-OPERATOR-INPUT fields**:
- `m24_10_use_case_id` — agency-assigned identifier; CSP-side may emit
  a *requested* id (`AIUC-REQ-<sha8>`) until agency confirms. Per Q.6
  of ADDITIONAL-LOOPS-AUDIT.md §5.
- `risk_category` — operator-supplied; cloud SDK cannot derive
  "rights-impacting" or "safety-impacting".
- `purpose` — operator-supplied; ≥50 chars.
- `intended_users`, `out_of_scope_uses`, `authority_to_use` — operator-supplied.
- `training_data_sources` — operator-supplied; required when
  `model_provider` is vendor or self-trained.
- `safety_minimum_practice_compliance` / `rights_minimum_practice_compliance` —
  operator-supplied; cross-references O.O4 evaluation evidence.
- `no-ai-use-cases-attested.json` requires a signed operator action.

**Test specifications** (≥12 tests):
1. `it('discovers SageMaker Endpoints and emits AiAsset rows with cloud_resource_arn', ...)`.
2. `it('discovers Bedrock InvokeModel events via CloudTrail lookup', ...)`.
3. `it('discovers Vertex AI Endpoints with self-link', ...)`.
4. `it('discovers Azure OpenAI deployments per workspace', ...)`.
5. `it('merges config/ai-inventory.yaml with discovered cloud assets', ...)`.
6. `it('honours operator-supplied risk_category over discovered defaults', ...)`.
7. `it('emits REQUIRES-OPERATOR-INPUT for assets missing m24_10_use_case_id', ...)`.
8. `it('emits REQUIRES-OPERATOR-INPUT for assets missing risk_category', ...)`.
9. `it('rejects ai_use_case entry with purpose < 50 chars', ...)`.
10. `it('writes ai-inventory.json with provenance block', ...)`.
11. `it('writes ai-inventory.xlsx with all OMB Attachment 1 columns', ...)`.
12. `it('no-ai path emits no-ai-use-cases-attested.json when discovery returns zero assets and operator signed', ...)`.
13. `it('no-ai path fails under --strict-ai when no operator attestation present', ...)`.
14. `it('SSP system-implementation.components[] adds one entry per major AI surface', ...)`.
15. `it('bundler includes ai-inventory-json + ai-inventory-xlsx in well-known roles', ...)`.
16. `it('rejects ai_use_case entries where vendor flag is true and vendor_name is empty', ...)`.

**REO compliance specific to this slice**:
- Cloud discovery uses real read-only SDK calls behind `core/readonly-guardrail.ts`.
- Operator-supplied fields are visibly tagged `discovered_via: 'config-yaml'`.
- No silent "no AI" default; the attestation requires a signed operator
  action, gated by `--strict-ai`.
- Mandatory metadata gaps surface as REQUIRES-OPERATOR-INPUT, never
  faked.

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/ai-inventory.test.ts tests/core/ai-attestation.test.ts tests/providers/aws/ai-services.test.ts tests/providers/gcp/ai-services.test.ts tests/providers/azure/ai-services.test.ts
npm run check:reo
npm run check:provenance
```

**Estimated effort**: 5 - 6 working days.

---

### Slice O.O2 — NIST AI RMF alignment (GOVERN / MAP / MEASURE / MANAGE)

**Why this slice**: NIST AI RMF 1.0 §5 defines 71 subcategories across
four functions. OMB M-24-10 §IV requires agencies to conduct AI risk
management consistent with the AI RMF. For each AI use case in O.O1's
inventory, the CSP needs structured evidence that the four functions are
addressed. Today no such evidence emit exists.

**Connection to FedPy mission**: O.O2 is a hybrid collector — part real
cloud signal (e.g. CloudTrail entries proving an AI use case is
monitored), part process-artifact (e.g. operator-uploaded model risk
review). It mirrors the AFR/process-artifact pattern already established
in `core/process-artifact-tracker.ts`: each subcategory is a "playbook"
item the operator records evidence against; the cloud-side collects
machine-readable signals where they exist.

**Files to create**:
- `cloud-evidence/core/ai-rmf.ts` — collector + emitter
- `cloud-evidence/core/ai-rmf-catalog.generated.json` — the 71 subcategories
  with verbatim definitions extracted from NIST AI 100-1 + AIRC
- `cloud-evidence/scripts/extract-ai-rmf-catalog.mjs` — extraction script
  (REO-compliant: input from NIST AIRC Playbook HTML or PDF; output is
  the generated JSON; no synthetic content)
- `cloud-evidence/tests/core/ai-rmf.test.ts`
- `cloud-evidence/tests/scripts/extract-ai-rmf-catalog.test.ts`

**Files to extend**:
- `cloud-evidence/core/control-benchmark.ts` — add AI RMF subcategory →
  NIST 800-53 control crosswalk
- `cloud-evidence/core/oscal-ap.ts` — add AI RMF assessment-asset entries
- `cloud-evidence/core/oscal-ssp.ts` — link AI RMF evidence into
  back-matter resources
- `tracker/server/schema.sql` — add `ai_rmf_evidence` table
- `tracker/server/routes/ai-rmf.ts` — CRUD + evidence upload
- `tracker/client/src/pages/AiRmf.tsx` — per-subcategory evidence UI

**Schemas / standards**:
- **NIST AI 100-1 §5 (Core)** — four functions + 71 subcategories
  (verbatim list captured in `ai-rmf-catalog.generated.json`).
- **NIST AI 600-1 GenAI Profile** — GenAI-specific overlay; the catalog
  carries `gen_ai_overlay: true/false` per subcategory.
- **NIST AI RMF Playbook** — per-subcategory suggested actions; used to
  prompt operator evidence collection.

**Build steps**:

1. Extraction script `scripts/extract-ai-rmf-catalog.mjs`:
   - Input: operator-downloaded NIST AI 100-1 PDF + AIRC Playbook HTML
     snapshot at `cloud-evidence/docs/sources/nist-ai-100-1.pdf` and
     `cloud-evidence/docs/sources/nist-airc-playbook.snapshot.html`.
   - Output: `core/ai-rmf-catalog.generated.json` — schema:
     ```ts
     export interface AiRmfSubcategory {
       id: string;                              // e.g. "GOVERN-1.1"
       function: 'GOVERN' | 'MAP' | 'MEASURE' | 'MANAGE';
       title: string;
       description: string;                     // verbatim from spec
       trustworthy_characteristics: ('valid-reliable' | 'safe' | 'secure-resilient' | 'accountable-transparent' | 'explainable-interpretable' | 'privacy-enhanced' | 'fair-bias-managed')[];
       gen_ai_overlay: boolean;
       suggested_actions: string[];             // from Playbook
       transparency_documentation: string[];    // from Playbook
       references: string[];                    // from Playbook
       nist_800_53_crosswalk: string[];         // O.O2-added; reviewed by operator
       iso_42001_clauses?: string[];            // O.O2-added; when known
     }
     ```
   - Spec compliance: every `description` field is verbatim from NIST
     AI 100-1 + AIRC (no paraphrase). Citation chain recorded in
     `catalog_source` block at the top of the JSON.

2. Collector `core/ai-rmf.ts`:
   - For each AI use case in `ai-inventory.json`:
     - Walk all 71 subcategories.
     - For each subcategory, collect evidence from:
       - **Cloud signal** (when applicable): e.g. for MEASURE 2.4
         ("monitored when in production"), check that CloudWatch /
         Cloud Monitoring / Azure Monitor has an active alarm targeting
         the inference endpoint.
       - **Tracker `ai_rmf_evidence` table** — operator-uploaded
         evidence (URL, sha256, signed by AI governance lead).
       - **Cross-reference** to other slices' evidence (O.O1 inventory
         for GOVERN 1.6; O.O3 risk register for MAP 5.1; O.O4
         evaluation for MEASURE 2.5/2.6; O.O5 model cards for MEASURE
         2.8/2.9).
   - Emit `out/ai-rmf-evidence.json`:
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
               "status": "addressed" | "partial" | "not-addressed" | "not-applicable",
               "evidence_refs": [
                 { "type": "tracker", "uri": "tracker://ai-rmf-evidence/123", "sha256": "..." },
                 { "type": "cloud-signal", "source": "aws.cloudwatch.alarm.invoke-endpoint-errors", "value": "active" }
               ],
               "notes": "...",
               "operator_signoff": {
                 "user_id": 12,
                 "role": "cao",
                 "signed_at": "...",
                 "signature": "...",
                 "key_id": "..."
               }
             }
             // ... per subcategory
           ]
         }
       ],
       "provenance": { ... }
     }
     ```

3. Cross-walk to NIST 800-53 Rev 5 in `core/control-benchmark.ts`:
   - Add `ai_rmf_crosswalk` table mapping each subcategory → 800-53
     controls (e.g. GOVERN 6.1 → SR-3; MEASURE 2.7 → SC family; MANAGE
     4.1 → CA-7). Where mappings are operator-tunable, the default is
     recorded with citation; operator overrides via config.

4. OSCAL AP wiring: `core/oscal-ap.ts` `assessment-assets.assessment-platforms[]`
   gets an entry "AI RMF self-assessment" with `props["ai-rmf-version"]`
   + `props["use-cases-assessed"]` enumerating ids.

5. OSCAL SSP back-matter: `back-matter.resources[]` adds entries of
   type `evidence` pointing to `out/ai-rmf-evidence.json` per use case.

6. Tracker UI (`AiRmf.tsx`):
   - List view: per use case, percent-complete bar over 71 subcategories.
   - Per-subcategory detail: verbatim subcategory description + suggested
     actions + transparency-documentation prompts + evidence-upload form.
   - Sign-off field requires `cao` (Chief AI Officer) or `iso` role.

7. Wire orchestrator: `--ai-rmf` flag invokes `collectAiRmfEvidence()`
   AFTER `--ai-inventory` (because each use case is walked).

8. Bundler: add role `ai-rmf-evidence` with description "NIST AI RMF
   GOVERN/MAP/MEASURE/MANAGE evidence per AI use case (LOOP-O.O2)".

**REQUIRES-OPERATOR-INPUT fields**:
- Operator must sign off each subcategory's evidence assertion.
- For subcategories with no cloud signal, the entire evidence_refs
  payload is operator-supplied.
- `not-applicable` status requires a justification field ≥50 chars.

**Test specifications** (≥12 tests):
1. `it('loads ai-rmf-catalog.generated.json with all 71 subcategories', ...)`.
2. `it('verifies every subcategory description is verbatim from NIST AI 100-1', ...)`.
3. `it('cross-walks GOVERN 6.1 to NIST 800-53 SR-3', ...)`.
4. `it('collects evidence for MEASURE 2.4 from CloudWatch alarm presence', ...)`.
5. `it('reads operator evidence from tracker ai_rmf_evidence table', ...)`.
6. `it('emits ai-rmf-evidence.json with use-case-keyed structure', ...)`.
7. `it('marks subcategory as not-addressed when no evidence and no signoff', ...)`.
8. `it('requires justification on not-applicable status', ...)`.
9. `it('requires cao or iso role on operator_signoff', ...)`.
10. `it('emits OSCAL AP assessment-platform for AI RMF', ...)`.
11. `it('joins to ai-inventory.json by use_case_id (rejects when use case unknown)', ...)`.
12. `it('catalog_source block carries citation chain', ...)`.
13. `it('check:provenance passes on emitted ai-rmf-evidence.json', ...)`.
14. `it('GenAI Profile subcategories carry gen_ai_overlay: true', ...)`.

**REO compliance specific to this slice**:
- Every subcategory description is verbatim from NIST AI 100-1 (no
  paraphrase, no summary).
- Cloud signals come from real read-only SDK queries.
- Operator sign-off is real Ed25519 signature over canonical-JSON
  payload.
- Not-addressed status is visible — not silently buried.

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/ai-rmf.test.ts tests/scripts/extract-ai-rmf-catalog.test.ts
npm run check:reo
npm run check:provenance
```

**Estimated effort**: 5 - 7 working days (catalog extraction + UI).

---

### Slice O.O3 — AI risk register (bias, fairness, robustness, adversarial)

**Why this slice**: NIST AI 100-1 MAP 5.1 mandates documenting likelihood
and magnitude of each identified impact. NIST AI 600-1 GenAI Profile
enumerates 12 GenAI-specific risk categories. LOOP-B.B5's Risk Register
aggregates per-finding + organisational + operational risks but has no
seat for AI-specific risks. O.O3 fills the gap.

**Connection to FedPy mission**: O.O3 produces a structured risk register
sourced from real signals: bias-metric collectors (operator-runnable test
harnesses whose results are tracker-uploaded), drift detectors (cloud
monitoring alarms), adversarial assessments (operator pen-test results).
The output joins LOOP-B.B5's `risk-register.json` as `source='ai'` rows.

**Files to create**:
- `cloud-evidence/core/ai-risk-register.ts` — aggregator + emitter
- `cloud-evidence/core/ai-risk-taxonomy.generated.json` — extracted from
  NIST AI 600-1 §3 (12 GenAI categories) + AI RMF MAP/MEASURE subcategories
- `cloud-evidence/scripts/extract-ai-risk-taxonomy.mjs` — extraction
- `cloud-evidence/tests/core/ai-risk-register.test.ts`

**Files to extend**:
- `cloud-evidence/core/risk-register.ts` (LOOP-B.B5) — join AI risks as
  `source='ai'` entries; the consolidated register interface gains an
  `ai_rmf_subcategory_ids: string[]` field per AI row
- `cloud-evidence/core/findings.ts` — extend `category` enum (already
  in O.O extends list)
- `cloud-evidence/core/oscal-poam.ts` — AI risk → poam-item path when
  status is "open"
- `tracker/server/schema.sql` — add `ai_risk_assessments` + `ai_risk_treatments` tables
- `tracker/server/routes/ai-risk-assessments.ts`
- `tracker/client/src/pages/AiRiskRegister.tsx`

**Schemas / standards**:
- **NIST AI 600-1 §3 (GenAI Profile risk categories)** — 12 categories
  verbatim:
  - CBRN Information or Capabilities
  - Confabulation
  - Dangerous, Violent, or Hateful Content
  - Data Privacy
  - Environmental Impacts
  - Harmful Bias and Homogenization
  - Human-AI Configuration
  - Information Integrity
  - Information Security
  - Intellectual Property
  - Obscene, Degrading, and/or Abusive Content
  - Value Chain and Component Integration
- **NIST AI 100-1 §4 (Trustworthiness characteristics)** — 7 characteristics
  used as risk-impact dimensions.
- **NIST SP 800-30 Rev 1 likelihood/impact qualitative scales** — reused
  from LOOP-B.B5 (very-low / low / moderate / high / very-high).
- **Mitchell et al. 2018 Ethical Considerations section** — informs the
  risk identification prompts.

**Build steps**:

1. Define `AiRisk` schema:
   ```ts
   export interface AiRisk {
     uuid: string;
     use_case_id: string;                            // joins to O.O1
     category: 'bias' | 'fairness' | 'robustness' | 'adversarial' | 'drift'
             | 'hallucination' | 'prompt-injection' | 'data-poisoning'
             | 'model-theft' | 'pii-leak' | 'ip-leak' | 'cbrn' | 'safety'
             | 'privacy' | 'environmental' | 'supply-chain' | 'value-chain';
     title: string;                                  // ≥10 chars
     description: string;                            // ≥100 chars
     ai_rmf_subcategory_ids: string[];               // e.g. ['MEASURE-2.11']
     gen_ai_profile_category?: string;               // when applicable
     trustworthy_characteristic_affected: ('valid-reliable' | 'safe' | 'secure-resilient' | 'accountable-transparent' | 'explainable-interpretable' | 'privacy-enhanced' | 'fair-bias-managed')[];
     likelihood: 'very-low' | 'low' | 'moderate' | 'high' | 'very-high';
     impact: 'very-low' | 'low' | 'moderate' | 'high' | 'very-high';
     inherent_risk: 'very-low' | 'low' | 'moderate' | 'high' | 'very-high';
     residual_risk: 'very-low' | 'low' | 'moderate' | 'high' | 'very-high';
     treatment: 'accept' | 'mitigate' | 'transfer' | 'avoid';
     treatment_actions: string[];                    // operator-listed
     owner_user_id: number;                          // tracker user id
     review_date: string;
     status: 'open' | 'closed';
     evidence_refs: { type: string; uri: string; sha256?: string }[];
     created_at: string;
     updated_at: string;
   }
   ```

2. Discovery hooks:
   - `bias` / `fairness` risks: operator uploads test results
     (Fairlearn, AIF360, etc.) — risk auto-created when result
     exceeds operator-set threshold (`config/ai-risk-thresholds.yaml`).
   - `drift` risks: cloud-monitoring alarm presence (SageMaker Model
     Monitor, Vertex Model Monitoring, Azure ML data drift) creates an
     observable; absence creates a risk row.
   - `adversarial` risks: operator-uploaded pen-test results.
   - `hallucination` / `pii-leak` risks: operator-uploaded eval results.
   - Risk created via tracker `POST /api/ai-risk-assessments` requires
     `iso` or `cao` role.

3. Aggregator:
   ```ts
   export function buildAiRiskRegister(inputs: AiRiskInputs): AiRisk[];
   ```
   Reads from `ai-inventory.json` + tracker snapshot
   `out/.ai-risk-assessments.json`. Emits `out/ai-risk-register.json`
   with provenance.

4. Join into LOOP-B.B5 risk-register:
   - In `core/risk-register.ts:buildRiskRegister()`, when
     `--ai-risk-register` is also set, the join emits AI risks as
     `RiskRegisterEntry` with `source='ai'`, `category=ai.<category>`,
     `references.ai_use_case_id = ...`, `references.ai_rmf_subcategory_ids = [...]`.

5. POA&M projection:
   - AI risks with `status='open'` AND `inherent_risk` in
     {high, very-high} produce poam-items (existing pipeline) carrying
     `props["ai-use-case-id"]`, `props["ai-risk-category"]`,
     `props["ai-rmf-subcategory"]`.

6. Bundler: add role `ai-risk-register` with filename
   `ai-risk-register.json`.

**REQUIRES-OPERATOR-INPUT fields**:
- `likelihood`, `impact`, `treatment`, `owner_user_id` — operator-supplied.
- Risk discovery thresholds in `config/ai-risk-thresholds.yaml`.
- Bias / fairness test results are operator-uploaded (FedPy never runs
  models).

**Test specifications** (≥12 tests):
1. `it('loads ai-risk-taxonomy.generated.json with 12 GenAI categories', ...)`.
2. `it('rejects AiRisk where description < 100 chars', ...)`.
3. `it('rejects AiRisk where likelihood/impact not in 800-30 enum', ...)`.
4. `it('creates a bias risk when Fairlearn upload exceeds threshold', ...)`.
5. `it('creates a drift risk when SageMaker Model Monitor alarm absent', ...)`.
6. `it('emits ai-risk-register.json with provenance', ...)`.
7. `it('joins to LOOP-B.B5 risk-register.json with source=ai', ...)`.
8. `it('projects high+open AI risk to poam-item with ai-* props', ...)`.
9. `it('does NOT project open AI risk to poam-item when risk severity is moderate', ...)`.
10. `it('rejects ai_rmf_subcategory_ids not present in catalog', ...)`.
11. `it('tracker iso role can create risk; viewer role cannot', ...)`.
12. `it('residual_risk drops one band when compensating control linked', ...)`.
13. `it('GenAI profile category is required when category in CBRN/data-privacy/etc.', ...)`.
14. `it('bundler includes ai-risk-register role', ...)`.

**REO compliance specific to this slice**:
- Risks derive from cloud signals, tracker evidence, or operator-supplied
  evaluation results. No synthetic risks.
- The 12 GenAI categories are sourced verbatim from NIST AI 600-1.
- Aggregator is a join, not a generator.

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/ai-risk-register.test.ts
npm run check:reo
npm run check:provenance
```

**Estimated effort**: 4 - 5 working days.

---

### Slice O.O4 — AI evaluation per OMB M-24-10 (pre-deployment + ongoing)

**Why this slice**: OMB M-24-10 §V.B requires pre-deployment + ongoing
evaluation for "rights-impacting" AI; §V.C for "safety-impacting" AI.
NIST AI RMF MEASURE 2.5 ("demonstrated to be valid and reliable") +
MEASURE 2.6 (safety) + MEASURE 2.11 (fairness/bias) require ongoing
documented evaluation. Today FedPy has AFR-PVA (persistent validation
for KSIs) but no AI-evaluation scheduler.

**Connection to FedPy mission**: O.O4 extends `core/pva-collector.ts`
(the AFR-PVA persistent-validation collector) to treat each AI use case
as a PVA "rule" with operator-tunable cadence. Pre-deployment results
are captured once (gated by tracker form); ongoing results re-run on
cadence. FedPy never runs the models — operator uploads evaluation
output (HELM, BIG-bench, MMLU, OpenAI Evals, custom). FedPy verifies
provenance, signs, and times-stamps; LOOP-E.E1 monthly report picks
up the deltas.

**Files to create**:
- `cloud-evidence/core/ai-evaluation.ts` — orchestrator + emitter
- `cloud-evidence/core/ai-evaluation-readers/index.ts` — adapter registry
- `cloud-evidence/core/ai-evaluation-readers/helm.ts` — HELM result parser
- `cloud-evidence/core/ai-evaluation-readers/openai-evals.ts` — OpenAI Evals parser
- `cloud-evidence/core/ai-evaluation-readers/big-bench.ts` — BIG-bench parser
- `cloud-evidence/core/ai-evaluation-readers/mmlu.ts` — MMLU result parser
- `cloud-evidence/core/ai-evaluation-readers/custom-jsonl.ts` — generic JSONL adapter
- `cloud-evidence/tests/core/ai-evaluation.test.ts`
- `cloud-evidence/tests/core/ai-evaluation-readers/*.test.ts`

**Files to extend**:
- `cloud-evidence/core/pva-collector.ts` — extend the cadence scheduler
  to include AI evaluations (one "rule" per AI use case + evaluation
  type)
- `tracker/server/schema.sql` — add `ai_evaluations` + `ai_evaluation_runs`
  tables
- `tracker/server/routes/ai-evaluations.ts`
- `tracker/client/src/pages/AiEvaluations.tsx`

**Schemas / standards**:
- **OMB M-24-10 §V.B** — rights-impacting minimum practices: identify
  + mitigate disparate impact; ongoing monitoring; consideration + remedy;
  opt-out where appropriate; consultation + feedback.
- **OMB M-24-10 §V.C** — safety-impacting minimum practices: pre-deployment
  independent evaluation; ongoing testing for performance degradation;
  procedures to mitigate emergent risks; human override.
- **NIST AI 100-1 MEASURE 2.5-2.13** — evaluation subcategories.
- **HELM (Stanford CRFM Holistic Evaluation of Language Models)** —
  https://crfm.stanford.edu/helm/ — result format (JSON per scenario).
- **OpenAI Evals** — https://github.com/openai/evals — result format
  (JSONL per eval).
- **BIG-bench** — https://github.com/google/BIG-bench — result format.
- **MMLU (Massive Multitask Language Understanding)** —
  https://arxiv.org/abs/2009.03300.

**Build steps**:

1. Define `AiEvaluation` schema:
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
     consultation_record_uri?: string;
     waiver_justification?: string;
     signature: string;
     signing_key_id: string;
   }
   ```

2. Scheduler hook into `core/pva-collector.ts`:
   - Each AI use case from `ai-inventory.json` registers a PVA rule
     `ai-eval:<use_case_id>:<evaluation_type>` with cadence from
     `evaluation_cadence_days`.
   - PVA emits `coverage:miss` when a scheduled evaluation is overdue.

3. Reader plug-ins translate framework-specific output to
   `metrics: Record<string, number>`. Each adapter is a pure function
   with operator-supplied input file.

4. Tracker UI: per use case, list evaluations + upload form +
   verification of file signature.

5. Aggregator emits `out/ai-evaluation-ledger.json`:
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

6. Compliance check:
   - For use cases with `risk_category` in {rights-impacting, safety-impacting},
     verify that at least one `pre-deployment` evaluation in
     `pass` state exists AND `ongoing-monthly` or `ongoing-quarterly`
     is current within cadence.
   - When not satisfied, emit a finding via `core/findings.ts`
     `category='ai-supply-chain'` (closest existing category until
     `category='ai-evaluation-overdue'` is added) and the LOOP-A.A1
     POA&M emitter creates a poam-item.

7. Wire orchestrator: `--ai-evaluation` flag invokes the aggregator
   AFTER `--ai-inventory` and `--ai-rmf`. `--strict-ai` mode fails the
   build if any safety-impacting or rights-impacting use case lacks
   passing pre-deployment evidence.

8. Bundler: add role `ai-evaluation-ledger` with filename
   `ai-evaluation-ledger.json`.

**REQUIRES-OPERATOR-INPUT fields**:
- All evaluation results uploaded by operator (FedPy never runs models).
- `human_override_path_documented` — operator boolean attestation +
  link to override SOP.
- `consultation_record_uri` — when use case is rights-impacting per
  M-24-10 §V.B, operator uploads consultation record.

**Test specifications** (≥12 tests):
1. `it('schedules an ai-eval PVA rule per inventoried use case', ...)`.
2. `it('emits coverage:miss when an ongoing evaluation is overdue', ...)`.
3. `it('parses HELM result JSON into metrics map', ...)`.
4. `it('parses OpenAI Evals JSONL into metrics map', ...)`.
5. `it('parses BIG-bench output into metrics map', ...)`.
6. `it('rejects evaluation upload without signature', ...)`.
7. `it('emits ai-evaluation-ledger.json with all use cases and evals', ...)`.
8. `it('flags safety-impacting use case without passing pre-deployment as POA&M finding', ...)`.
9. `it('flags rights-impacting use case without consultation_record_uri', ...)`.
10. `it('--strict-ai exits non-zero when safety-impacting eval missing', ...)`.
11. `it('verifies pre-deployment evidence completed_at < deployment_date', ...)`.
12. `it('emits provenance on ledger', ...)`.
13. `it('waiver evaluation requires justification ≥ 100 chars', ...)`.
14. `it('PVA persistent-validation re-runs cadence triggers next ongoing evaluation', ...)`.

**REO compliance specific to this slice**:
- Evaluation results uploaded with sha256 + signature; verified at
  ledger-emit time.
- Pass/fail derives from operator-set thresholds in
  `config/ai-evaluation-thresholds.yaml`, not from synthetic metrics.
- Overdue evaluations surface as findings, not silent gaps.
- FedPy never executes evaluation harnesses; the boundary is read-only.

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/ai-evaluation.test.ts tests/core/ai-evaluation-readers/*.test.ts
npm run check:reo
npm run check:provenance
```

**Estimated effort**: 6 - 8 working days (multi-format parsers + UI).

---

### Slice O.O5 — Model card + datasheet emitter

**Why this slice**: Per NIST AI RMF MEASURE 2.8 ("Risks associated with
transparency and accountability are examined and documented") and
MEASURE 2.9 ("The AI model is explained, validated, and documented"),
each model deployed in the CSO requires structured documentation.
Mitchell et al. (2018) "Model Cards for Model Reporting" defines nine
sections that are the de-facto industry standard; Gebru et al. (2018)
"Datasheets for Datasets" defines seven sections for training/eval
datasets. Today the FedPy submission bundle has no Model Card or
Datasheet artifacts.

**Connection to FedPy mission**: O.O5 emits one Markdown Model Card per
AI asset in `ai-inventory.json` + one Datasheet per
`training_data_source`. Content is operator-supplied via tracker form
(or `config/ai-inventory.yaml` extensions); FedPy assembles + signs +
bundles. For vendor models (e.g. Anthropic-published model card for
Claude), the operator uploads the vendor's published Model Card and
records its checksum + URL.

**Files to create**:
- `cloud-evidence/core/model-card.ts` — emitter
- `cloud-evidence/core/datasheet.ts` — emitter
- `cloud-evidence/core/model-card-template.generated.md` — canonical
  template extracted from Mitchell et al. 2018 §3
- `cloud-evidence/core/datasheet-template.generated.md` — canonical
  template extracted from Gebru et al. 2018 §3
- `cloud-evidence/tests/core/model-card.test.ts`
- `cloud-evidence/tests/core/datasheet.test.ts`

**Files to extend**:
- `cloud-evidence/core/oscal-ssp.ts` — add `back-matter.resources[]`
  entries of type `model-card` and `datasheet`
- `cloud-evidence/core/submission-bundle.ts` — add roles
  `model-cards-bundle`, `datasheets-bundle`
- `tracker/server/schema.sql` — `model_cards` + `datasheets` tables
- `tracker/server/routes/model-cards.ts`
- `tracker/server/routes/datasheets.ts`
- `tracker/client/src/pages/ModelCards.tsx`
- `tracker/client/src/pages/Datasheets.tsx`

**Schemas / standards**:
- **Mitchell et al. 2018 — "Model Cards for Model Reporting"** — nine
  sections (Model Details, Intended Use, Factors, Metrics, Evaluation
  Data, Training Data, Quantitative Analyses, Ethical Considerations,
  Caveats and Recommendations). Each section has 3–10 sub-fields
  verbatim from the paper.
- **Gebru et al. 2018 — "Datasheets for Datasets"** — seven sections
  (Motivation, Composition, Collection Process,
  Preprocessing/Cleaning/Labeling, Uses, Distribution, Maintenance).
  Each has 4–18 numbered questions.

**Build steps**:

1. Canonical template files are extracted from the cited papers (operator
   downloads PDFs to `cloud-evidence/docs/sources/`; extraction script
   parses them into the `*-template.generated.md` artifacts with
   verbatim question prompts).

2. `core/model-card.ts`:
   ```ts
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
     vendor_model_card?: { url: string; sha256: string };  // when vendor-supplied
     authored_by_user_id?: number;
     signature: string;
     signing_key_id: string;
   }

   export function emitModelCard(card: ModelCard): { markdown: string; sidecar_json: object };
   ```

3. `core/datasheet.ts`:
   ```ts
   export interface Datasheet {
     uuid: string;
     dataset_id: string;
     ai_asset_uuids: string[];               // datasets often span multiple models
     emitted_at: string;
     sections: {
       motivation: MotivationSection;
       composition: CompositionSection;
       collection_process: CollectionProcessSection;
       preprocessing_cleaning_labeling: PreprocessingSection;
       uses: UsesSection;
       distribution: DistributionSection;
       maintenance: MaintenanceSection;
     };
     vendor_datasheet?: { url: string; sha256: string };
     authored_by_user_id?: number;
     signature: string;
     signing_key_id: string;
   }
   ```

4. Per-section schemas explicitly model the verbatim Mitchell / Gebru
   sub-fields. Where a sub-field can be auto-derived from the AI
   inventory (e.g. `Model Details / Model date` ← `AiAsset.deployment_date`),
   the emitter auto-fills + records `synthesized_fields: [...]` per
   REO Rule 1.7. All other fields are operator-supplied.

5. Emission:
   - Per AI asset, walk to model-card record (created by tracker if
     not yet present, with REQUIRES-OPERATOR-INPUT markers).
   - Render Markdown using the canonical template.
   - Emit alongside a JSON sidecar `<model-id>.json` carrying the
     structured representation + provenance + signature.
   - Vendor models: when `vendor_model_card.url` is set, the local
     Markdown stub points to the vendor URL + sha256 + records
     "vendor-published; see external URL" in §Model Details.

6. SSP integration:
   - For each `model-card` + `datasheet`, add a
     `back-matter.resources[]` entry of type `model-card` /
     `datasheet` with `rlinks[]` pointing to the file in the
     submission bundle + sha256.
   - SSP §13 (Control Implementation) for any AI-relevant control
     references the back-matter resource via prop.

7. Bundler integration: add roles `model-cards-bundle` (filename
   pattern `model-cards/*.md` + `model-cards/*.json`) and
   `datasheets-bundle` (pattern `datasheets/*.md` + `datasheets/*.json`).

8. Tracker UI: per AI asset, "Model Card" tab with form-based editor;
   sign-off requires `cao` or `iso` role.

**REQUIRES-OPERATOR-INPUT fields**:
- All section content is operator-supplied except auto-derivable fields
  (auto-fills marked in `synthesized_fields`).
- Vendor URL + sha256 for vendor-published model cards.
- Authoring user id + sign-off signature.

**Test specifications** (≥12 tests):
1. `it('loads model-card-template.generated.md with all 9 sections', ...)`.
2. `it('loads datasheet-template.generated.md with all 7 sections', ...)`.
3. `it('renders Model Card to Markdown with all sections in order', ...)`.
4. `it('renders Datasheet to Markdown with all sections in order', ...)`.
5. `it('auto-derives Model Details / Model date from AiAsset.deployment_date', ...)`.
6. `it('records synthesized_fields for every auto-derived sub-field', ...)`.
7. `it('rejects emit when ethical_considerations < 200 chars', ...)`.
8. `it('handles vendor_model_card path: emits stub Markdown with URL + sha256', ...)`.
9. `it('rejects vendor_model_card with empty sha256', ...)`.
10. `it('back-matter.resources[] adds one entry per Model Card', ...)`.
11. `it('back-matter.resources[] adds one entry per Datasheet', ...)`.
12. `it('bundler includes model-cards-bundle + datasheets-bundle roles', ...)`.
13. `it('signature is real Ed25519 over canonical JSON of sections', ...)`.
14. `it('rejects model card with ai_asset_uuid not present in ai-inventory.json', ...)`.

**REO compliance specific to this slice**:
- Section content is operator-supplied or auto-derived from real
  inventory data; nothing synthesised silently.
- Vendor model cards: stored as URL + sha256, never copied without
  attribution.
- Signature real Ed25519.
- Bundler includes Model Cards + Datasheets in the canonical submission.

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/model-card.test.ts tests/core/datasheet.test.ts
npm run check:reo
npm run check:provenance
```

**Estimated effort**: 4 - 5 working days.

---

## 6. Loop-wide acceptance criteria

LOOP-O is COMPLETE when ALL of the following are true:

1. **O.O1**: `out/ai-inventory.json` + `out/ai-inventory.xlsx` exist
   with provenance block. Cloud-side discovery covers AWS SageMaker /
   Bedrock / Comprehend / Rekognition / Textract / Translate /
   Transcribe + GCP Vertex AI / Document AI / Natural Language / Vision
   / Speech / Translate + Azure ML / Azure OpenAI / Cognitive Services.
   When the CSO declares zero AI surfaces, `no-ai-use-cases-attested.json`
   is signed and present. Bundler includes three roles.
2. **O.O2**: `out/ai-rmf-evidence.json` covers all 71 subcategories per
   use case with verbatim definitions sourced from NIST AI 100-1 +
   AIRC. `core/ai-rmf-catalog.generated.json` is in place. Cross-walk
   to NIST 800-53 controls is implemented. Tracker UI ships. Bundler
   includes `ai-rmf-evidence` role.
3. **O.O3**: `out/ai-risk-register.json` aggregates AI risks per the 12
   GenAI categories + LOOP-B's 800-30 likelihood/impact scales. Joins
   into LOOP-B.B5 `risk-register.json` as `source='ai'` rows. POA&M
   emits high+open AI risks as poam-items with `ai-*` props. Tracker
   UI ships. Bundler includes `ai-risk-register` role.
4. **O.O4**: `out/ai-evaluation-ledger.json` covers every use case with
   pre-deployment + ongoing evidence. Reader adapters for HELM,
   OpenAI Evals, BIG-bench, MMLU, custom JSONL all ship. `--strict-ai`
   blocks the build when safety-impacting or rights-impacting use
   cases lack passing evidence. Tracker UI ships. Bundler includes
   `ai-evaluation-ledger` role.
5. **O.O5**: One `out/model-cards/<model-id>.md` per AI asset + one
   `out/datasheets/<dataset-id>.md` per dataset. Mitchell + Gebru
   sections all present + signed. SSP back-matter resources updated.
   Bundler includes `model-cards-bundle` + `datasheets-bundle` roles.
6. All five slices pass `npm run typecheck`, `npm test`, and
   `npm run check:reo` in both `cloud-evidence/` and `tracker/`.
7. CHANGELOG "Unreleased" has five entries (one per slice) with module
   names + verification counts + REO compliance notes.
8. STATUS.md per-slice rows updated.

---

## 7. Open questions / caveats

1. **Operator confirmation that CSO uses AI** — LOOP-O is conditional
   (per ADDITIONAL-LOOPS-AUDIT.md §5.1). Before O.O1 ships, the operator
   must decide: ship full slice (CSO uses AI) OR ship attestation-only
   path (CSO surfaces no AI). The orchestrator emits a CONFIRM-AI
   warning until the choice is recorded in `config/ai-inventory.yaml`
   `loop_o_mode: full | attestation` field.
2. **Agency-assigned use case IDs** — OMB M-24-10 Attachment 1
   identifiers are agency-assigned. CSP-side O.O1 emits a *requested*
   id (`AIUC-REQ-<sha8>` derived from canonical input) until the
   sponsoring agency confirms. Tracker workflow lets operator update
   the id once confirmed.
3. **NIST AI 100-1 PDF anonymous fetch** — same pattern as LOOP-B's
   FedRAMP CMP PDF (B-X1). Operator downloads NIST AI 100-1 +
   AI 600-1 + AIRC Playbook to `cloud-evidence/docs/sources/` before
   the extraction script (`scripts/extract-ai-rmf-catalog.mjs`) runs.
   Until then, `ai-rmf-catalog.generated.json` carries
   `REQUIRES-OPERATOR-INPUT: confirm-against-nist-ai-100-1-pdf` marker.
4. **CVSS-equivalent scoring for AI risks** — LOOP-B.B1 scores
   findings via CVSS+EPSS. O.O3 does NOT yet adopt an equivalent for
   AI risks; bands are derived from operator-supplied likelihood +
   impact (per 800-30 scales). A future O.O6 could add
   "AI-CVSS-equivalent" — out of scope for this loop.
5. **OMB M-24-10 PDF anonymous fetch** — same pattern. Operator
   downloads to `cloud-evidence/docs/sources/m-24-10.pdf` before O.O4
   constants are pinned.
6. **Vendor model lifecycle drift** — when a vendor publishes a new
   model version (e.g. Anthropic publishes a new Claude version),
   O.O1 inventory drifts. The PVA cadence catches it on next run; the
   monthly ConMon delta picks up the model version change. O.O5
   Model Card re-emit is triggered by version change.
7. **Cross-region / cross-account AI assets** — for AWS Org accounts
   running Bedrock or SageMaker across regions, the existing
   `core/aws-org-fanout.ts` pattern is reused.
8. **GenAI-specific overlay vs. base AI RMF** — the 71 subcategories
   are the base AI RMF; NIST AI 600-1 GenAI Profile adds suggested
   actions per subcategory plus 12 GenAI risk categories. O.O2 catalog
   includes `gen_ai_overlay: true/false` per subcategory and per
   suggested-action group.
9. **Multi-CSO tenant isolation deferred to H.H3** — the 8 new tracker
   tables omit `tenant_id` columns. H.H3 batches the migration. LOOP-O
   ships single-tenant.
10. **EU AI Act overlap** — LOOP-O is FedRAMP-scoped; if CSP serves
    EU customers, EU AI Act obligations layer on top (out of scope per
    ADDITIONAL-LOOPS-AUDIT.md §4.7).
11. **AI incident reporting** — NIST AI 100-1 MANAGE 4.3 +
    OMB M-24-10 incident-handling requirements. LOOP-O.O3 captures
    incident-triggered evaluations (O.O4 evaluation type); a dedicated
    "AI incident ledger" is deferred to a hypothetical O.O6.
12. **Subprocessor AI use** — if a CSP subprocessor uses AI on the
    CSP's behalf, the AI inventory must include the subprocessor's
    AI surfaces. LOOP-J.J2 (subprocessor inventory) is the operator
    UX path; O.O1 reads from there when the subprocessor declares AI.

---

## 8. Status tracking

Update this table when a slice ships (see Section 9).

| Slice ID | Title | Status | Commit hash | Completed date |
|---|---|---|---|---|
| O.O1 | AI/ML asset inventory (models, training data, inference endpoints) | pending | — | — |
| O.O2 | NIST AI RMF alignment (GOVERN / MAP / MEASURE / MANAGE) | pending | — | — |
| O.O3 | AI risk register (bias, fairness, robustness, adversarial) | pending | — | — |
| O.O4 | AI evaluation per OMB M-24-10 (pre-deployment + ongoing) | pending | — | — |
| O.O5 | Model card + datasheet emitter (Mitchell + Gebru) | pending | — | — |

---

## 9. Slice completion procedure (REO-enforced)

Reference: `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` — the
canonical 7-step procedure. Specific to LOOP-O:

1. **Verify green**: from repo root
   ```bash
   cd cloud-evidence
   npm run typecheck            # must be clean
   npm test                     # 100% passing (existing + new slice tests)
   npm run check:reo            # G1 + G2 + G3 all green
   npm run check:provenance     # every new emit-field has provenance entry
   ```
   For slices touching the tracker (every LOOP-O slice does):
   ```bash
   cd ../tracker
   npm run typecheck
   npm test
   ```

2. **Update Section 8 status table** in this file: set slice's row to
   `status=done`, `commit=<short-sha>`, `date=<YYYY-MM-DD>`.

3. **Update CHANGELOG.md "Unreleased"**: add `### Added — LOOP-O.<id>: <title>`
   block. Cite module names, the spec links (NIST AI 100-1, AI 600-1,
   OMB M-24-10, M-25-21, Mitchell 2018, Gebru 2018), verification
   counts, REO compliance note.

4. **Update `cloud-evidence/docs/STATUS.md`**: set slice row to `done`.

5. **Update the per-slice doc's frontmatter** (in
   `docs/slices/O/<slice-id>.md`): `status: done`, `commit: <hash>`,
   `completed_date: <ISO>`, `last_updated: <ISO>`.

6. **Append Implementation log entry** to the per-slice doc per
   `docs/IMPLEMENTATION-LOG-TEMPLATE.md`.

7. **Update LOOP-O-RISKS.md**: move any resolved risks to the
   resolved table + add any newly-discovered risks atomically with the
   slice commit.

8. **Commit**:
   ```bash
   git add -A
   git commit -m "LOOP-O.<id>: <title>"
   ```

9. **Push**: `git push origin main`.

10. **Sanity check**: re-clone into a scratch dir, run orchestrator on
    a fixture inventory, verify the new artifact lands in `out/`.

---

## 10. Appendix — Loop-O specific cross-walks

### AI RMF subcategory → NIST 800-53 Rev 5 control crosswalk (initial)

| AI RMF | 800-53 Rev 5 | Rationale |
|---|---|---|
| GOVERN 1.1 (legal/regulatory) | PL-1, PM-1, SR-1 | Organisational policies/programmes |
| GOVERN 1.6 (inventory) | CM-8, PM-5 | Asset inventory controls |
| GOVERN 2.1 (roles) | PM-2, PM-29 | Senior official designation |
| GOVERN 6.1 (third-party IP) | SR-3, SR-5 | Supply chain controls |
| GOVERN 6.2 (third-party contingency) | CP-2(8), SR-3(2) | Supply chain contingency |
| MAP 1.1 (intended purposes) | PL-2, PM-7 | System security plan + enterprise architecture |
| MAP 4.1 (third-party legal) | SR-3, SR-5, SR-11 | Supply chain risk |
| MAP 5.1 (likelihood/magnitude) | RA-3 | Risk assessment |
| MEASURE 2.4 (production monitoring) | CA-7, SI-4 | Continuous monitoring |
| MEASURE 2.5 (validity/reliability) | SA-11 | Developer testing/evaluation |
| MEASURE 2.6 (safety) | SR-3, SI-7 | Safety + integrity |
| MEASURE 2.7 (security/resilience) | SC family (esp. SC-7, SC-8), SI-7 | Security architecture |
| MEASURE 2.8 (transparency) | PT-2, PT-3 | Privacy + transparency |
| MEASURE 2.9 (explainability) | AU-2, AU-12 | Audit + accountability |
| MEASURE 2.10 (privacy) | PT family, AC-21 | Privacy + information sharing |
| MEASURE 2.11 (fairness/bias) | PT family + organisational policy | Fairness evidence |
| MEASURE 3.3 (feedback) | IR-6, SI-10 | Reporting + remediation |
| MANAGE 1.3 (risk responses) | RA-7, PM-9 | Risk response |
| MANAGE 4.1 (post-deployment monitoring) | CA-7, IR-4, IR-6 | Continuous monitoring + incident response |
| MANAGE 4.3 (incident communication) | IR-6, AU-12 | Incident response + accountability |

(Full table in `core/ai-rmf-catalog.generated.json` `nist_800_53_crosswalk` field
per subcategory.)

### OMB M-24-10 minimum practice mapping to LOOP-O slices

| M-24-10 obligation | Slice | Evidence artifact |
|---|---|---|
| §III AI use-case inventory | O.O1 | `out/ai-inventory.{json,xlsx}` |
| §IV AI risk management consistent with NIST AI RMF | O.O2 | `out/ai-rmf-evidence.json` |
| §V.B pre-deployment testing for disparate impact | O.O4 | Pre-deployment evaluation row (rights-impacting tag) |
| §V.B ongoing monitoring | O.O4 + O.O2 (MEASURE 2.4) | Ongoing eval rows + CloudWatch alarms |
| §V.B consideration + remedy | O.O3 + tracker | Risk register treatment column |
| §V.B opt-out where appropriate | O.O1 + operator narrative | `out_of_scope_uses` + operator SOP |
| §V.B consultation + feedback | O.O4 `consultation_record_uri` | Tracker upload |
| §V.C pre-deployment independent evaluation | O.O4 | Independent evaluator-supplied row |
| §V.C ongoing performance-degradation testing | O.O4 ongoing-monthly | Cadence in PVA |
| §V.C emergent-risk mitigation procedures | O.O3 treatment + SOP | Risk register + back-matter SOP link |
| §V.C human override | O.O4 `human_override_path_documented` | Boolean attestation + SOP link |
| Attachment 1 inventory format | O.O1 XLSX | Column-exact match |

### Worked example: a single AI use case end-to-end

Given a CSP that ships a "customer support copilot" using
`anthropic.claude-4-5-sonnet` as the upstream model, fronted by an
internal Bedrock invocation, processing customer prompts that contain
agency-confidential text:

- **O.O1**: `AiAsset` row id `AIUC-001`, model_provider=`aws.bedrock.anthropic`,
  model_family=`claude-4-5-sonnet`, training_data_classification=`unknown`
  (vendor-supplied; reflected in vendor Model Card),
  risk_category=`rights-impacting` (operator-declared because outputs
  might affect customer support decisions).
- **O.O2**: 71 subcategories addressed. GOVERN 1.6 satisfied by O.O1
  inventory; MAP 1.1 satisfied by operator-uploaded purpose memo;
  MEASURE 2.4 satisfied by CloudWatch alarm on `Bedrock.InvokeModel`
  error rate; MEASURE 2.11 fairness assessment per O.O4 evaluation;
  MANAGE 4.1 post-deployment monitoring plan uploaded as a tracker
  artifact.
- **O.O3**: One open AI risk row: "Hallucination on customer prompts
  may yield incorrect product recommendations" (category=`hallucination`,
  likelihood=`moderate`, impact=`high`, inherent_risk=`high`,
  residual_risk=`moderate` once human-in-loop control kicks in).
- **O.O4**: Pre-deployment evaluation row referencing the operator-
  uploaded HELM result JSON (sha256, signed); ongoing-monthly cadence
  triggered by PVA every 30 days.
- **O.O5**: One `out/model-cards/AIUC-001.md` referencing the vendor
  Model Card URL (Anthropic-published) + the CSP's intended-use
  narrative + ethical considerations; one `out/datasheets/<no
  datasets — vendor model>.md` stub explaining the absence.

The same use case becomes:
- 1 row in `ai-inventory.json` + 1 row in `ai-inventory.xlsx`.
- 71 rows in `ai-rmf-evidence.json` (under the `AIUC-001` use case).
- 1 row in `ai-risk-register.json` joined into LOOP-B.B5's combined
  register as `source='ai'`.
- 2+ rows in `ai-evaluation-ledger.json` (one pre-deployment + N
  ongoing).
- 1 file in `out/model-cards/`.
- A poam-item in `poam.json` when the open AI risk's
  `inherent_risk='high'` AND `status='open'`.
- A resource in the SSP back-matter pointing to the Model Card.

That is the LOOP-O value proposition end-to-end: from an AI use case
in code to a fully-evidenced, signed, OSCAL-linked authorization
artifact set that satisfies OMB M-24-10 + NIST AI RMF + supports
M-25-21 procurement records.
