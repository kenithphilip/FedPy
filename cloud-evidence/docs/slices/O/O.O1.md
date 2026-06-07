---
slice_id: O.O1
title: AI/ML asset inventory (models, training data, inference endpoints)
loop: O
status: pending
commit: —
completed_date: —
depends_on: [INV-P1, INV-P2, INV-P3, INV-P4, INV-P5, INV-S1, INV-S2, INV-S3, INV-S4, INV-S5, INV-S6]
blocks: [O.O2, O.O3, O.O4, O.O5, C.C7, E.E1, G.G3, I.I1]
estimated_effort: 5-6 working days
last_updated: 2026-06-07
applicable_conditional: true
---

# O.O1 — AI/ML asset inventory (models, training data, inference endpoints)

## TL;DR
Extend `core/inventory.ts` with a first-class `AiAsset` model and add per-provider read-only discovery for AWS SageMaker/Bedrock, GCP Vertex AI, Azure ML/OpenAI plus 15+ adjacent AI/ML services. Merge cloud-derived assets with operator-supplied `config/ai-inventory.yaml` to produce `out/ai-inventory.json` + `out/ai-inventory.xlsx` aligned to the OMB M-24-10 Attachment 1 column layout. When the CSO surfaces zero AI use cases, emit an operator-signed `no-ai-use-cases-attested.json` envelope — never silently default to "no AI".

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
O.O1 is a *cloud-evidence collector* in the same idiom as INV-P1..S6: real read-only SDK calls gated by `core/readonly-guardrail.ts` enumerate AWS SageMaker/Bedrock/Comprehend/Rekognition/Textract/Translate/Transcribe/Personalize/Forecast/Lex, GCP Vertex AI/Document AI/Natural Language/Vision/Speech/Translate, and Azure ML/Azure OpenAI/Cognitive Services. Tag-driven metadata (`ai_use_case`, `ai_model_provider`, `ai_data_classification`) augments the SDK signal. The `config/ai-inventory.yaml` REO Rule 4 path captures non-cloud surfaces (embedded models, third-party APIs called from application code, vendor models reachable via SaaS). Every emitted byte traces back to a real SDK call, a real resource tag, or an operator-committed YAML entry — never a synthesized default. The output feeds LOOP-A SSP §11 (System Environment), the OMB M-24-10 use-case inventory, and the rest of LOOP-O's slices (O.O2's per-use-case AI RMF evidence; O.O3's risk register joined by `use_case_id`; O.O4's per-use-case evaluation cadence; O.O5's per-asset Model Card + Datasheet).

## Why this slice exists
OMB M-24-10 §III (Advancing Responsible AI Innovation) and Attachment 1 (Federal AI Use Case Inventory) mandate a structured inventory of every AI use case an agency consumes. NIST AI RMF 1.0 GOVERN 1.6 mandates organizational AI-system inventory mechanisms. The FedPy inventory model today covers compute, network, data stores, and IAM — but has no first-class concept of an AI asset. Without O.O1:
- Every other LOOP-O slice has no anchor for `use_case_id`.
- SSP §11 cannot enumerate AI services.
- LOOP-A submission bundle cannot ship the M-24-10 attachment XLSX.
- AFR-PVA cadence machinery has no place to register AI evaluations.

OMB M-24-10 §III states verbatim:
> "Agencies shall maintain an inventory of AI use cases including a use case identifier, owning office, vendor (if applicable), risk category, and date of most recent risk evaluation."

NIST AI 100-1 GOVERN 1.6 states verbatim:
> "Mechanisms are in place to inventory AI systems and are resourced according to organizational risk priorities."

O.O1 closes both gaps with the existing FedPy collector + tag + config pattern.

## Authoritative sources (with verbatim quotes)
- **OMB M-24-10 Attachment 1 — "Federal AI Use Case Inventory"** — https://www.whitehouse.gov/wp-content/uploads/2024/03/M-24-10-Advancing-Governance-Innovation-and-Risk-Management-for-Agency-Use-of-Artificial-Intelligence.pdf
  > "Agencies shall maintain an inventory of AI use cases including a use case identifier, owning office, vendor (if applicable), risk category, and date of most recent risk evaluation." The XLSX column set (verbatim): agency, bureau, use_case_id, use_case_name, summary, purpose_benefits, outputs, lifecycle_stage (in-design, pilot, in-development, in-operation, decommissioned), risk_category (rights-impacting, safety-impacting, both, neither), vendor_or_internally_developed, vendor_name, contract_vehicle, model_provider, commercial_or_government_model, training_data_sources, purpose_authorities, recent_evaluation_date, next_evaluation_date, decommission_date_if_planned, safety_minimum_practice_compliance, rights_minimum_practice_compliance, safety_waiver_in_effect, rights_waiver_in_effect.

- **NIST AI 100-1 §5 GOVERN 1.6** — https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf
  > "Mechanisms are in place to inventory AI systems and are resourced according to organizational risk priorities."

- **OMB M-25-21 — "Driving Efficient Acquisition of Artificial Intelligence in Government"** (Mar 2025) — https://www.whitehouse.gov/wp-content/uploads/2025/03/M-25-21-Memorandum.pdf
  Procurement flow-down: CSPs supplying AI to federal agencies must surface inventory evidence in the contract record. The O.O1 XLSX is the canonical artifact for this contract surface.

- **FedRAMP Rev5 SSP Template §11 (System Environment)** — implicit consumer of the inventory; §13 (Control Implementation) references back-matter resources of type `data` that point to `out/ai-inventory.json` (added via `core/oscal-ssp.ts` extension in this slice).

- **AWS SageMaker API reference** — https://docs.aws.amazon.com/sagemaker/latest/APIReference/Welcome.html — read-only operations used: `ListNotebookInstances`, `ListEndpoints`, `ListModels`, `ListPipelines`, `ListProcessingJobs`, `ListTrainingJobs`. AWS Bedrock: `ListFoundationModels`, `ListCustomModels`, plus CloudTrail `LookupEvents` for `InvokeModel`.

- **GCP Vertex AI API reference** — https://cloud.google.com/vertex-ai/docs/reference/rest — read-only operations: `aiplatform.endpoints.list`, `aiplatform.models.list`, `aiplatform.pipelineJobs.list`, `aiplatform.notebookInstances.list`. Document AI: `documentai.processors.list`.

- **Azure ML / Cognitive Services REST reference** — https://learn.microsoft.com/en-us/rest/api/azureml/ + https://learn.microsoft.com/en-us/rest/api/cognitiveservices/ — used to enumerate workspaces, endpoints, deployments. Azure OpenAI is filtered via `Microsoft.CognitiveServices/accounts?kind=OpenAI`.

## Files to create (exact paths under cloud-evidence/)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ai-inventory.ts` — discovery orchestrator + merger + emitter. ~700 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ai-inventory-xlsx.ts` — pure-JS OOXML XLSX renderer mirroring `core/inventory-workbook.ts`. ~400 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ai-attestation.ts` — the "no AI" attestation envelope emitter. ~150 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/providers/aws/ai-services.ts` — SageMaker, Bedrock, Comprehend, Rekognition, Textract, Translate, Transcribe, Personalize, Forecast, Lex, Q discovery. ~600 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/providers/gcp/ai-services.ts` — Vertex AI, Document AI, Natural Language, Vision, Speech, Translate discovery. ~500 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/providers/azure/ai-services.ts` — Azure ML, Azure OpenAI, Cognitive Services discovery. ~500 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/config/ai-inventory.example.yaml` — committed example showing operator UX.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/ai-inventory.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/ai-inventory-xlsx.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/ai-attestation.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/providers/aws/ai-services.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/providers/gcp/ai-services.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/providers/azure/ai-services.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/ai-inventory/` — fixtures: vendor model card stub, sample SDK responses, sample config yaml.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/inventory.ts` — add `ai_assets: AiAsset[]` to the inventory model + the `AiAsset` interface (full field set per Build steps §1). Backward-compatible: `ai_assets` defaults to `[]` for older serialized inventories.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — new flags `--ai-inventory`, `--ai-attestation`, `--strict-ai` + env equivalents `CLOUD_EVIDENCE_AI_INVENTORY`, `CLOUD_EVIDENCE_AI_ATTESTATION`, `CLOUD_EVIDENCE_STRICT_AI`. Execution order: discovery runs BEFORE `--oscal-ssp` so SSP §11 can populate from the inventory.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add three roles to `WELL_KNOWN`: `ai-inventory-json`, `ai-inventory-xlsx`, `ai-attestation`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-ssp.ts` — populate §11 AI/ML services subsection; add `system-implementation.components[]` entries (type=`software`) for each major AI surface with `props["ai-use-case-id"]`; add `back-matter.resources[]` entry of type `data` for `out/ai-inventory.json`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/providers/aws/inventory.ts` — call `discoverAllAiAssets(regions)` and merge results into `inventory.ai_assets`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/providers/gcp/inventory.ts` — same pattern per project.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/providers/azure/inventory.ts` — same pattern per subscription.

## Schemas / standards
- **OMB M-24-10 Attachment 1 XLSX columns** — exact column set documented above; column order is preserved verbatim. Cell-level validation: `risk_category` ∈ {rights-impacting, safety-impacting, both, neither}; `lifecycle_stage` ∈ {in-design, pilot, in-development, in-operation, decommissioned}; date columns ISO 8601.
- **NIST AI 100-1 GOVERN 1.6** — inventory completeness includes pilots + decommissioned use cases (within operator-defined retention window; default 24 months from `decommission_date`).
- **OSCAL SSP v1.1.2** — `cloud-evidence/docs/oscal/oscal_ssp_schema.v1.1.2.json` is the schema; new components carry `type=software` per the `component-definition` v1.1.2 enum; props use `CE_NS = "https://cloud-evidence.example/oscal-ns"` (already declared in `core/oscal-ssp.ts`).
- **Pure-JS XLSX OOXML** — pattern matches `core/inventory-workbook.ts`. No SheetJS in production paths.
- **Ed25519 + RFC 3161** — `no-ai-use-cases-attested.json` flows through `core/sign.ts` glob + RFC 3161 timestamp manifest.

## Build steps (concrete, numbered)

1. Define the `AiAsset` interface in `core/inventory.ts`:
   ```ts
   export interface AiAsset {
     uuid: string;                                    // deterministic uuid v5
     m24_10_use_case_id?: string;                    // OMB inventory id
     name: string;
     provider_cloud: 'aws' | 'gcp' | 'azure' | 'other';
     provider_service: string;                       // e.g. 'aws.sagemaker', 'azure.openai'
     model_provider: string;                         // e.g. 'aws.bedrock.anthropic', 'openai', 'gcp.vertex.gemini', 'self-hosted'
     model_family: string;                           // e.g. 'claude-4-5-sonnet'
     model_version: string;
     deployment_type: 'inference-endpoint' | 'batch' | 'embedded' | 'external-api' | 'training-job';
     inference_endpoint_url?: string;
     training_data_classification: 'public' | 'internal' | 'confidential' | 'cui' | 'pii' | 'unknown';
     training_data_sources: string[];
     lifecycle_stage: 'in-design' | 'pilot' | 'in-development' | 'in-operation' | 'decommissioned';
     risk_category: 'rights-impacting' | 'safety-impacting' | 'both' | 'neither';
     purpose: string;                                // ≥50 chars
     intended_users: string[];
     out_of_scope_uses: string[];
     authority_to_use: string;
     deployment_date?: string;
     decommission_date?: string;
     last_evaluation_date?: string;
     evaluation_cadence_days: number;                // default 90
     safety_minimum_practice_compliance?: 'compliant' | 'waiver' | 'in-progress' | 'not-applicable';
     rights_minimum_practice_compliance?: 'compliant' | 'waiver' | 'in-progress' | 'not-applicable';
     waiver_justification?: string;
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

2. Provider discovery: per-provider modules implement `discoverAllAiAssets(scope)` (regions for AWS, projects for GCP, subscriptions for Azure) and return `AiAsset[]`. Each per-service helper (e.g. `discoverSageMakerEndpoints(region)`) is a small read-only SDK wrapper behind the existing Proxy guardrail. SDK calls live ONLY in the provider module; the `core/` orchestrator never touches a cloud SDK.

3. Operator augmentation: `config/ai-inventory.yaml` loader honours an `ai_use_cases` array with the same shape as `AiAsset` (snake_case keys); each entry is validated against a typed Zod-like checker. Required operator fields: `use_case_id`, `purpose` (≥50 chars), `risk_category`, `intended_users`, `out_of_scope_uses`, `authority_to_use`.

4. Merge:
   ```ts
   export async function buildAiInventory(ctx: AiInventoryContext): Promise<AiInventory>;
   ```
   - Walk provider discovery results.
   - Merge with `config/ai-inventory.yaml` entries (config wins on declarative metadata: `m24_10_use_case_id`, `risk_category`, `purpose`, `intended_users`, `authority_to_use`; cloud signal wins on presence + cloud-derived fields: `cloud_resource_arn`, `tags`, `inference_endpoint_url`).
   - Cross-reference cloud tags `ai_use_case`, `ai_model_provider`, `ai_data_classification` to fill fields not in the SDK response.
   - Coverage report rows for assets missing mandatory metadata (`m24_10_use_case_id`, `risk_category`, `purpose`, `intended_users`, `out_of_scope_uses`, `authority_to_use`) surface as `coverage:miss` log lines + counted in the JSON.

5. JSON emit `out/ai-inventory.json`:
   ```json
   {
     "schema_version": "ai-inventory.v1",
     "run_id": "...",
     "emitted_at": "2026-06-07T...Z",
     "ai_assets": [ ... ],
     "coverage": {
       "discovered_assets": N,
       "operator_supplied_assets": M,
       "assets_missing_use_case_id": K,
       "assets_missing_risk_category": K2,
       "assets_missing_purpose": K3,
       "assets_missing_authority_to_use": K4
     },
     "provenance": {
       "emitter": "cloud-evidence/core/ai-inventory.ts",
       "emittedAt": "...",
       "sourceCalls": [
         { "provider": "aws", "service": "sagemaker", "operation": "ListEndpoints", "regions": [...] },
         { "provider": "aws", "service": "bedrock", "operation": "ListFoundationModels", "regions": [...] },
         { "provider": "gcp", "service": "aiplatform", "operation": "endpoints.list", "projects": [...] },
         { "provider": "azure", "service": "cognitiveservices", "operation": "accounts.list", "subscriptions": [...] }
       ],
       "configReads": ["config/ai-inventory.yaml"],
       "signingKeyId": "..."
     }
   }
   ```

6. XLSX emit `out/ai-inventory.xlsx` via `core/ai-inventory-xlsx.ts`:
   - One sheet per OMB attachment (single sheet at first ship; future enhancement: per-bureau sheets).
   - Header row exactly matches Attachment 1 column order.
   - Data validation lists for `risk_category`, `lifecycle_stage`.
   - Conditional formatting: missing required cells flagged in red.

7. Conditional "no AI" attestation:
   - `core/ai-attestation.ts:emitAiAttestation(opts)` runs when discovery returns zero assets AND `--ai-attestation` flag is set.
   - Reads operator's signed attestation row from tracker via snapshot at `out/.ai-attestation.json` written by the tracker push step.
   - The attestation row requires: `signed_by_user_id` with role ∈ {`iso`, `cao`}, `signed_at` (ISO), `signature` (Ed25519 over canonical JSON), `signing_key_id`.
   - Without an attestation, `--strict-ai` exits non-zero; the CHANGELOG/STATUS line for the run shows "REQUIRES-OPERATOR-INPUT: AI attestation".
   - Output `out/no-ai-use-cases-attested.json` carries the attestation + provenance + signature.

8. Orchestrator wiring (`core/orchestrator.ts`): `--ai-inventory` invokes `buildAiInventory()`; `--ai-attestation` is the no-AI path. Both run BEFORE `--oscal-ssp`. `--strict-ai` requires either `ai-inventory.json` with ≥1 asset OR `no-ai-use-cases-attested.json` to be present; otherwise fail.

9. SSP integration (`core/oscal-ssp.ts`):
   - When `ai-inventory.json` is present and `ai_assets.length > 0`:
     - `system-characteristics.system-information.information-type[]` gets an entry per distinct `training_data_classification` value seen.
     - `system-implementation.components[]` adds one `software`-typed component per distinct `provider_service` × `model_family` pair, with `props["ai-use-case-id"]`, `props["ai-model-provider"]`, `props["ai-risk-category"]`.
     - `back-matter.resources[]` gets one `data` entry pointing to `out/ai-inventory.json` (with sha256 + rlinks).

10. Bundler integration (`core/submission-bundle.ts:WELL_KNOWN`):
    ```ts
    { role: 'ai-inventory-json', filename: 'ai-inventory.json', description: 'AI/ML asset inventory (LOOP-O.O1; OMB M-24-10 Attachment 1)' },
    { role: 'ai-inventory-xlsx', filename: 'ai-inventory.xlsx', description: 'AI/ML asset inventory in OMB Attachment 1 column layout' },
    { role: 'ai-attestation', filename: 'no-ai-use-cases-attested.json', description: 'Signed operator attestation that the CSO surfaces zero AI use cases (LOOP-O.O1 conditional)' },
    ```

11. Signing + timestamping: `ai-inventory.json`, `ai-inventory.xlsx`, `no-ai-use-cases-attested.json` are included in the existing `core/sign.ts` glob + the RFC 3161 manifest.

12. Coverage check: every AI asset with REQUIRES-OPERATOR-INPUT on `m24_10_use_case_id`, `risk_category`, `purpose`, `intended_users`, `out_of_scope_uses`, or `authority_to_use` is counted in `coverage.json`; `scripts/check-provenance.mjs` verifies the provenance block.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4, fields that cannot be auto-derived from cloud SDKs:

| Field | Source | Behavior when missing |
|---|---|---|
| `m24_10_use_case_id` | Agency-assigned; tracker form OR `config/ai-inventory.yaml` | CSP emits requested id `AIUC-REQ-<sha8>`; surfaces in coverage report; tracker workflow lets operator update once agency confirms |
| `risk_category` | Operator-supplied in `config/ai-inventory.yaml` or tracker | REQUIRES-OPERATOR-INPUT marker; asset row blocked from SSP component emission until set |
| `purpose` (≥50 chars) | Operator-supplied | Asset row blocked; coverage:miss logged |
| `intended_users` | Operator-supplied | Same |
| `out_of_scope_uses` | Operator-supplied | Same |
| `authority_to_use` | Operator-supplied; cites M-25-21 contract authority where applicable | Same |
| `training_data_sources` (when vendor or self-trained) | Operator-supplied | Required when `model_provider` is vendor or self-trained; cloud-only SDK signal insufficient |
| `safety_minimum_practice_compliance` / `rights_minimum_practice_compliance` | Operator-supplied; cross-references O.O4 evaluation evidence when O.O4 ships | REQUIRES-OPERATOR-INPUT marker until O.O4 ships |
| `no-ai-use-cases-attested.json` | Tracker form signed by `iso` or `cao` role | Without signature, `--strict-ai` exits non-zero |
| `evaluation_cadence_days` | Defaults to 90; operator override via config | Default used; documented in CHANGELOG |

## Test specifications (≥12 tests)
1. `it('discovers SageMaker Endpoints and emits AiAsset rows with cloud_resource_arn')` — mock the AWS SDK at the wire layer (CLAUDE.md Rule 2.4); assert one row per endpoint with discovered_via=cloud-sdk.
2. `it('discovers Bedrock InvokeModel events via CloudTrail LookupEvents and synthesizes one AiAsset per distinct model_family')` — verify the runtime-usage detection path.
3. `it('discovers Vertex AI Endpoints with self-link populated')` — assert cloud_resource_self_link is set.
4. `it('discovers Azure OpenAI deployments per workspace')` — filter Microsoft.CognitiveServices/accounts by kind=OpenAI.
5. `it('merges config/ai-inventory.yaml entries with discovered cloud assets')` — provide overlapping entries, assert config wins on declarative metadata, cloud wins on presence fields.
6. `it('honours operator-supplied risk_category from config over default')` — assert override flows through.
7. `it('emits REQUIRES-OPERATOR-INPUT for assets missing m24_10_use_case_id')` — surfaces in coverage; uuid is requested id.
8. `it('emits REQUIRES-OPERATOR-INPUT for assets missing risk_category')` — coverage:miss logged; row not included in SSP components.
9. `it('rejects ai_use_case entry with purpose < 50 chars')` — typed config error.
10. `it('rejects ai_use_case entry with vendor=true and vendor_name empty')` — typed config error.
11. `it('writes ai-inventory.json with provenance block including sourceCalls per provider')` — `check:provenance` passes.
12. `it('writes ai-inventory.xlsx with all 23 OMB Attachment 1 columns in spec order')` — open via SheetJS in test only; verify cell A1..W1.
13. `it('no-ai path emits no-ai-use-cases-attested.json when discovery returns zero and operator signed')` — verify signature, key_id, attested_at.
14. `it('no-ai path fails under --strict-ai when no operator attestation present')` — exit code non-zero, REQUIRES-OPERATOR-INPUT message.
15. `it('SSP system-implementation.components[] adds one entry per major AI surface')` — re-emit SSP with non-empty inventory; verify component count + props.
16. `it('SSP back-matter.resources[] adds a data resource pointing to ai-inventory.json with sha256')` — assert rlink href + sha256.
17. `it('bundler includes ai-inventory-json + ai-inventory-xlsx + ai-attestation in well-known roles')` — pin the role table.
18. `it('Azure ML workspace discovery enumerates endpoints under each workspace')` — verify nested enumeration.

## REO compliance
- Every value traces to: a real SDK ListXxx response, a real resource tag, or an operator-committed YAML entry / tracker form.
- No silent fallbacks for: `risk_category`, `purpose`, `m24_10_use_case_id` (these surface as REQUIRES-OPERATOR-INPUT markers).
- No silent "no AI" default: zero-asset path requires the `no-ai-use-cases-attested.json` envelope signed by `iso` or `cao`.
- Provenance populated on `ai-inventory.json` + `no-ai-use-cases-attested.json`: emitter, emittedAt, sourceCalls, configReads, signingKeyId.
- `synthesized_fields` array on each `AiAsset` records any value auto-derived from related signals (e.g. `model_family` parsed from a SageMaker endpoint name pattern) — never silently invented.
- Signed by: existing `core/sign.ts` Ed25519 pipeline + RFC 3161 timestamp manifest.

## Verification commands
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/ai-inventory.test.ts tests/core/ai-inventory-xlsx.test.ts tests/core/ai-attestation.test.ts tests/providers/aws/ai-services.test.ts tests/providers/gcp/ai-services.test.ts tests/providers/azure/ai-services.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
```

## Known risks / issues
- **Risk 1: SDK call surface area (10+ AWS services, 6+ GCP, 8+ Azure) inflates IAM permission requirements.** Mitigation: produce an updated `docs/IAM-CATALOG.md` row per new permission used; document optional-vs-required per AI service so operators with partial coverage can ship. Cross-ref O-X1.
- **Risk 2: Bedrock InvokeModel discovery requires CloudTrail `LookupEvents` which is rate-limited (2 TPS).** Mitigation: only enumerate the last 90 days by default; cache results in `out/.bedrock-usage-cache.json` with 24h TTL; document the trade-off in CHANGELOG.
- **Risk 3: Vendor-supplied training data classification typically `unknown` (e.g. Anthropic model on Bedrock).** Mitigation: `training_data_classification = 'unknown'` is a first-class enum value; operator runbook describes when to mark `unknown` vs request the vendor's published value.
- **Risk 4: Embedded models in container images cannot be SDK-discovered.** Mitigation: documented in operator runbook; `config/ai-inventory.yaml` is the path; coverage report tracks operator-supplied vs cloud-discovered ratio.
- **Risk 5: Cross-region Bedrock model discovery duplicates assets when an endpoint is replicated.** Mitigation: deduplicate by `model_family` × `model_version` within the same account; preserve per-region inference endpoint URLs as a list field.

## Open questions
- **Q1: When the cloud tag `ai_use_case` collides with a `config/ai-inventory.yaml` entry, which wins?** Recommend: config wins on declarative metadata; tag wins as a presence/discovery signal only. Pin in code comment + test.
- **Q2: Should `model_version` be auto-detected from Bedrock model identifier strings (e.g. `anthropic.claude-3-5-sonnet-20241022-v2:0`) or operator-supplied?** Recommend: auto-detect with regex; record in `synthesized_fields`; operator can override.
- **Q3: Does `provider_service: 'aws.bedrock-runtime'` differ from `'aws.bedrock'` (data plane vs control plane)?** Recommend: collapse to `aws.bedrock` at first ship; both surfaces share the same model_family.
- **Q4: Should retired/decommissioned assets stay in the inventory after `decommission_date + retention_window_months`?** Recommend: yes by default (retention=24 months) — matches OMB inventory practice; operator can configure shorter retention.

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
- [ ] Commit amended with commit hash recorded in STATUS.md + this file + LOOP-O-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. This file gives you: source obligations + files to create + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-O-SPEC.md` Sections 2 (Connection) + 3 (Dependencies) + 5 (slice O.O1) for cross-loop context.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory 7-step commit pattern.
5. Read `cloud-evidence/core/inventory.ts` — the existing inventory model you'll extend with `ai_assets[]`.
6. Read `cloud-evidence/core/inventory-workbook.ts` — the pure-JS XLSX pattern you'll mirror in `ai-inventory-xlsx.ts`.
7. Read `cloud-evidence/core/oscal-ssp.ts` — the SSP back-matter integration point.
8. Read `cloud-evidence/core/submission-bundle.ts` — the `WELL_KNOWN` array; add three roles.
9. Begin implementation; update Implementation log section as you go.

---
