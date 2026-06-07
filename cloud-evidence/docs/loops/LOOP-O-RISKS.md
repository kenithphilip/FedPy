# LOOP-O — Risks Register

> Live document. Implementing sessions add entries during work; resolved risks stay in the file with `status=resolved` + resolution note. Severity: high = ship-blocking; med = should fix in-loop; low = file as follow-up.

> Authoritative companion to `docs/loops/LOOP-O-SPEC.md` and the per-slice docs at `docs/slices/O/O.O[1-5].md`. Read those for context before acting on any risk here.

> LOOP-O is **conditional** (per `docs/ADDITIONAL-LOOPS-AUDIT.md` §5.1). Required when the CSO uses AI/ML anywhere; N/A when zero AI surfaces (but O.O1 still ships as an operator-signed `no-ai-use-cases-attested.json` envelope per REO Rule 4).

> Last updated: 2026-06-07.

---

## Cross-cutting risks (apply to ALL slices in LOOP-O)

### O-X1 — IAM permission inflation across AWS/GCP/Azure AI services
- **Description**: O.O1 alone touches 10+ AWS services (SageMaker, Bedrock, Comprehend, Rekognition, Textract, Translate, Transcribe, Personalize, Forecast, Lex, Q), 6+ GCP services (Vertex AI, Document AI, Natural Language, Vision, Speech, Translate), and 8+ Azure services (Azure ML workspaces + Endpoints + Models + Pipelines, Azure OpenAI, Cognitive Services). Each requires read-only IAM permissions to enumerate. The cumulative `docs/IAM-CATALOG.md` grows by ~40 permissions in LOOP-O — operators with partial coverage may receive AccessDenied on services they don't use.
- **Severity**: med.
- **Mitigation**: Per-service discovery is independent — AccessDenied on one service produces a `coverage:miss` row, not a hard failure. `docs/IAM-CATALOG.md` updated atomically with the slice commit; per-permission "required vs optional" column added; operator runbook documents minimal-permissions baseline + per-service add-on.
- **Status**: open.

### O-X2 — Authoritative PDFs gated by 403 on anonymous fetch
- **Description**: NIST AI 100-1, NIST AI 600-1, OMB M-24-10, OMB M-25-21, Mitchell 2018, and Gebru 2018 PDFs underpin LOOP-O. NIST PDFs are generally open; OMB PDFs may return 403 to anonymous HTTPS fetches; arXiv (Mitchell, Gebru) is open but rate-limits. Each affected slice carries a `REQUIRES-OPERATOR-INPUT: confirm-against-<source>-pdf` marker on its constants until the PDF is downloaded to `cloud-evidence/docs/sources/`.
- **Severity**: high (O.O2, O.O3, O.O4, O.O5 blocked until PDFs in place).
- **Mitigation**: Per-slice marker visible until PDF in place; `--strict-ai` orchestrator mode fails the build if any marker remains; CHANGELOG entry for each slice cites verbatim section text with PDF page + section; documented runbook step to download all six PDFs before LOOP-O work begins.
- **Status**: open.

### O-X3 — AI RMF + GenAI Profile version drift
- **Description**: NIST publishes AI 100-1 minor updates (a 2.0 is anticipated). NIST AI 600-1 GenAI Profile is a separate publication and is on its own update cadence. The extracted catalogs (`ai-rmf-catalog.generated.json`, `ai-risk-taxonomy.generated.json`) pin specific versions; an upstream revision requires a re-extraction + CHANGELOG diff.
- **Severity**: med.
- **Mitigation**: Catalog headers carry `ai_rmf_version` + `gen_ai_profile_version`; extraction script idempotent; CHANGELOG entry per slice pins the version; a future minor-version migration is a single-script run.
- **Status**: open.

### O-X4 — Cloud SDK call surface drift (SageMaker, Bedrock, Vertex AI, Azure OpenAI)
- **Description**: AI/ML cloud services evolve faster than core IAM / compute / network APIs. SDK method renames or response-shape changes could break O.O1 discovery. Bedrock in particular is rapidly evolving (new model families monthly).
- **Severity**: med.
- **Mitigation**: Provider modules use defensive parsing (Zod-like schemas with permissive extras); per-service version pinned in CHANGELOG; `tests/providers/<cloud>/ai-services.test.ts` uses recorded fixtures replayed at the wire layer; CI catches drift on next test run.
- **Status**: open.

### O-X5 — Operator-supplied evaluation file integrity
- **Description**: O.O4 accepts operator-uploaded evaluation results (HELM, OpenAI Evals, BIG-bench, MMLU, TruthfulQA, custom JSONL). The tracker computes sha256 + verifies the operator's Ed25519 signature over the envelope; reader adapters parse the body. A malformed or manipulated upload could pass signature checks while carrying corrupted metrics. The reader's permissiveness vs. strictness is a tradeoff.
- **Severity**: med.
- **Mitigation**: Strict schema validation in each reader; missing required field → `pass_fail='not-yet-evaluated'` + `REQUIRES-OPERATOR-INPUT` marker; framework version captured in upload envelope; CHANGELOG documents per-reader strict-mode behavior; future enhancement: deterministic checksum chain from evaluation harness to upload.
- **Status**: open.

### O-X6 — Ed25519 signing-key rotation across cloud-evidence + tracker
- **Description**: O.O1 (attestation), O.O2 (per-subcategory sign-off), O.O3 (AI risk creation), O.O4 (evaluation upload), and O.O5 (model card sign-off) all sign records in the tracker using a tracker-resident Ed25519 key. Readers verify tracker signatures using the tracker's published public key. Cross-loop dependency on the same key registry pattern from LOOP-B.B3 + B.B4 (cross-ref B-X3).
- **Severity**: med.
- **Mitigation**: Tracker `/api/sign/public-keys` returns ALL historical public keys keyed by `key_id`; readers cross-reference each record's `signing_key_id` against the registry; key rotation events written to `audit_log`; runbook documents the procedure.
- **Status**: open.

### O-X7 — OSCAL POA&M v1.1.2 schema constraints on AI-* props
- **Description**: O.O3 adds new finding-class categories (`ai-bias`, `ai-drift`, `ai-hallucination`, `ai-prompt-injection`, `ai-data-poisoning`, `ai-supply-chain`, `ai-pii-leak`, `ai-ip-leak`, `ai-evaluation-overdue`, `ai-adversarial`, `ai-cbrn`, `ai-confabulation`). Each must surface in `findingProps()` with `CE_NS` namespace; a typo (missing `ns: CE_NS`) would silently fail the bundle (cross-ref B-X2).
- **Severity**: high.
- **Mitigation**: `core/oscal-validate.ts` runs after every slice's POA&M re-emission; `ns: CE_NS` is required by lint rule; CI fails if any new prop lacks `ns`.
- **Status**: open.

### O-X8 — Conditional-loop UX: zero-AI attestation must not be a silent default
- **Description**: REO Rule 4 forbids a silent "no AI" default. O.O1's `no-ai-use-cases-attested.json` path requires a real operator signature + role (`iso` or `cao`). If the orchestrator runs without `--ai-inventory` AND `--ai-attestation` flags, the submission bundle omits AI evidence — which a 3PAO could misinterpret as "this CSP has no AI".
- **Severity**: high.
- **Mitigation**: `--strict-ai` requires either `ai-inventory.json` (≥1 asset) OR `no-ai-use-cases-attested.json` to be present; CHANGELOG entry for O.O1 documents the gate; CI default sets `--strict-ai`; orchestrator emits CONFIRM-AI warning until `config/ai-inventory.yaml` `loop_o_mode: full | attestation` field is recorded.
- **Status**: open.

### O-X9 — Provenance schema drift
- **Description**: Every new emit artifact (`ai-inventory.json`, `ai-inventory.xlsx`, `no-ai-use-cases-attested.json`, `ai-rmf-evidence.json`, `ai-rmf-catalog.generated.json`, `ai-risk-register.json`, `ai-risk-taxonomy.generated.json`, `ai-evaluation-ledger.json`, `model-cards/*.json`, `datasheets/*.json`, `model-cards-emit.json`) must carry a `provenance` block per REO Rule 2.6. `scripts/check-provenance.mjs` enforces the schema. A missed block fails the slice (cross-ref B-X9).
- **Severity**: high.
- **Mitigation**: Per-slice test verifies provenance via `check:provenance`; pattern reused from `core/inventory-coverage.ts`; CHANGELOG entry per slice cites the provenance block contents.
- **Status**: open.

### O-X10 — Tracker schema migration on existing installs
- **Description**: LOOP-O adds 8 new tables (`ai_assets`, `ai_use_cases`, `ai_rmf_evidence`, `ai_risk_assessments`, `ai_risk_treatments`, `ai_evaluations`, `ai_evaluation_runs`, `model_cards`, `datasheets`, `ai_governance_signoffs`). Existing tracker installs have user data — migrations must be additive only. The repo uses idempotent `CREATE TABLE IF NOT EXISTS`; any non-additive change is breaking (cross-ref B-X10).
- **Severity**: high.
- **Mitigation**: All ALTERs additive; CHANGELOG documents the upgrade path; smoke test on a copy of a production DB; no DROP / ALTER COLUMN under any circumstance in LOOP-O; future `H.H3` multi-tenant work batches all cross-loop migrations.
- **Status**: open.

### O-X11 — Submission bundle role count growth
- **Description**: LOOP-O adds 8 new roles to `submission-bundle.ts:WELL_KNOWN`: `ai-inventory-json`, `ai-inventory-xlsx`, `ai-attestation`, `ai-rmf-evidence`, `ai-risk-register`, `ai-evaluation-ledger`, `model-cards-bundle`, `datasheets-bundle`. Each role must have a stable canonical filename or glob + description; collisions would corrupt the bundle. `model-cards-bundle` + `datasheets-bundle` are the FIRST glob-based roles — bundler may not support globs today (cross-ref B-X8).
- **Severity**: med.
- **Mitigation**: `tests/core/submission-bundle.test.ts` pins the role table; per-slice tests assert presence; CHANGELOG entry for O.O5 lists the final role inventory at loop close; bundler glob-expansion path added in O.O5 if absent.
- **Status**: open.

### O-X12 — Multi-CSO tenant isolation deferred to H.H3
- **Description**: All eight LOOP-O tracker tables omit a `tenant_id` column. When multi-CSO ships (H.H3), all eight need migration in a single cross-loop sweep. If LOOP-O users start storing multi-tenant data via app-level filtering, the H.H3 migration becomes destructive (cross-ref B-X15).
- **Severity**: med (long-tail).
- **Mitigation**: Documented in LOOP-O-SPEC.md §7.9; H.H3 spec must enumerate every LOOP-O table; LOOP-O ships in single-tenant deployments only (documented in runbook).
- **Status**: open.

### O-X13 — `process.env.NODE_ENV === 'test'` branch creep
- **Description**: REO Rule 1.8 prohibits this branch in production code. New cross-cutting infrastructure (signing, HTTP fetch, snapshot writes, framework adapters) is exactly where developers reach for `if (NODE_ENV === 'test')` shortcuts (cross-ref B-X6).
- **Severity**: high (REO violation; CI rejects).
- **Mitigation**: `scripts/lint-no-stubs.mjs` catches the literal; tests inject seams via dependency-injected HTTP fetcher + filesystem helper; CI gate is non-bypassable.
- **Status**: open.

### O-X14 — Cross-loop coupling: AFR-PVA + LOOP-A + LOOP-B
- **Description**: O.O4 extends `core/pva-collector.ts` (AFR-PVA); O.O3 joins LOOP-B.B5 risk-register; O.O2/O.O3/O.O4 all extend LOOP-A.A1 POA&M finding-class taxonomy. A regression in any of these cross-loop integrations breaks LOOP-O. Conversely, LOOP-O changes can regress LOOP-A/B/AFR-PVA — version coordination required.
- **Severity**: med.
- **Mitigation**: Each LOOP-O slice's test suite includes a regression test for the integrated LOOP-A/B/AFR-PVA path; CI runs the full cross-loop test set on every slice ship; CHANGELOG entries name the integration points; SLICE-COMPLETION-PROCEDURE.md §1 verification step is non-skippable.
- **Status**: open.

### O-X15 — RBAC roles `cao` and `iso` not in tracker today
- **Description**: LOOP-O sign-offs require `cao` (Chief AI Officer) or `iso` role. The tracker's `rbac.ts` defines roles; `iso` already exists (from LOOP-B). `cao` is NEW to LOOP-O; first-boot tracker installs will not have a `cao` user, blocking sign-offs.
- **Severity**: med.
- **Mitigation**: O.O1 ship adds `cao` role to `tracker/server/rbac.ts`; first boot prompts admin to assign at least one `cao`; the tracker UI's "Settings → Roles" page documents the mapping. Cross-ref B-X5.
- **Status**: open.

### O-X16 — Vendor model lifecycle drift
- **Description**: When a vendor publishes a new model version (e.g. Anthropic publishes new Claude version), O.O1 inventory drifts (model_version changes), O.O5 Model Card needs re-emit, O.O4 ongoing-evaluation cadence may need a `change-triggered` row. Without explicit detection, the change is silent.
- **Severity**: med.
- **Mitigation**: PVA cadence catches it on next run; LOOP-E.E1 monthly ConMon delta picks up model_version changes; O.O5 Model Card emission detects `AiAsset.model_version` change and forces re-emit with `synthesized_fields.includes('model_version_changed_detected')`.
- **Status**: open.

### O-X17 — Cross-region / cross-account AI assets
- **Description**: For AWS Org accounts running Bedrock or SageMaker across regions, the existing `core/aws-org-fanout.ts` pattern must be reused — but never extended in a way that increases the AI provider's IAM blast radius.
- **Severity**: low.
- **Mitigation**: O.O1 reuses `core/aws-org-fanout.ts` unchanged; per-account read-only role assumption; same pattern documented for GCP project fan-out + Azure subscription fan-out.
- **Status**: open.

---

## Per-slice risks

### O.O1 — AI/ML asset inventory (models, training data, inference endpoints)

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| O.O1-1 | med | SDK call surface (10+ AWS, 6+ GCP, 8+ Azure) inflates IAM permission requirements (cross-ref O-X1) | Per-service discovery independent; AccessDenied → `coverage:miss`; `IAM-CATALOG.md` updated per slice | open |
| O.O1-2 | med | Bedrock InvokeModel discovery requires CloudTrail `LookupEvents` (rate-limited 2 TPS) | Only last 90 days enumerated; cache results in `out/.bedrock-usage-cache.json` (24h TTL); CHANGELOG documents | open |
| O.O1-3 | low | Vendor-supplied `training_data_classification` typically `unknown` | `unknown` is a first-class enum value; runbook describes when to mark unknown vs request vendor's published value | open |
| O.O1-4 | med | Embedded models in container images cannot be SDK-discovered | `config/ai-inventory.yaml` is the path; coverage report tracks operator-supplied vs cloud-discovered ratio | open |
| O.O1-5 | low | Cross-region Bedrock duplicates assets when an endpoint is replicated | De-duplicate by `model_family` × `model_version`; preserve per-region endpoint URLs as a list field | open |
| O.O1-6 | med | OMB Attachment 1 column set may shift in future revisions | XLSX header sourced from constants; CHANGELOG records the version; format-shift bumps version | open |
| O.O1-7 | high | Conditional-loop zero-AI attestation must not be silent default (cross-ref O-X8) | `--strict-ai` requires inventory OR attestation; CONFIRM-AI warning until operator records mode | open |
| O.O1-8 | low | Agency-assigned `m24_10_use_case_id` is sponsor-driven; CSP emits requested id | `AIUC-REQ-<sha8>` until agency confirms; tracker workflow lets operator update once confirmed | open |

### O.O2 — NIST AI RMF alignment (GOVERN / MAP / MEASURE / MANAGE)

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| O.O2-1 | high | NIST AI 100-1 PDF may return 403 on anonymous fetch (cross-ref O-X2) | Operator downloads to `docs/sources/`; `--strict-ai` blocks ship if marker remains | open |
| O.O2-2 | med | AIRC Playbook is a live site; content drifts | Snapshot file with sha256 stored under `docs/sources/`; extraction script verifies; CHANGELOG pins snapshot date | open |
| O.O2-3 | med | Cross-walk to NIST 800-53 partially subjective (e.g. MEASURE 2.11 has no exact 800-53 control) | Defaults documented in LOOP-O-SPEC.md §10; operator override via config; prop carries source ("default" vs "operator-override") | open |
| O.O2-4 | low | GenAI profile overlay may grow in future revisions | Catalog header carries `gen_ai_profile_version`; extraction script idempotent; re-run produces new generated catalog with CHANGELOG diff | open |
| O.O2-5 | med | PDF text extraction garbles verbatim text (whitespace, hyphenation) | Extraction script normalizes; spot-check test pins ≥10 known-good descriptions byte-for-byte | open |
| O.O2-6 | low | ISO 42001 mapping is partial | Include where known; leave others null with `REQUIRES-OPERATOR-INPUT: iso-42001-mapping-pending` marker | open |
| O.O2-7 | med | `not-applicable` status easily over-used by operators | Requires `not_applicable_deferred_to` field with controlled enum + justification ≥50 chars | open |

### O.O3 — AI risk register (bias, fairness, robustness, adversarial)

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| O.O3-1 | high | NIST AI 600-1 PDF may return 403 (cross-ref O-X2) | Operator downloads; `--strict-ai` blocks ship if marker remains | open |
| O.O3-2 | med | Bias/fairness thresholds are domain-specific; defaults may not fit operator | `config/ai-risk-thresholds.example.yaml` documents defaults; CHANGELOG explains | open |
| O.O3-3 | med | Drift detection relies on monitoring artifacts being present | Operator declares `drift_monitoring_strategy` in inventory; only `not-applicable` suppresses risk creation | open |
| O.O3-4 | low | MITRE ATLAS evolves continuously | Snapshot file with sha256; CHANGELOG pins date; re-run extraction bumps version in provenance | open |
| O.O3-5 | med | Cross-source de-duplication (AI risk vs finding) could surprise operators | Documented in code comment; dedupe step logs key for audit; tests pin the behavior | open |
| O.O3-6 | low | Composite-score-equivalent for AI risks deferred to future O.O6 | LOOP-O ships qualitative bands only; LOOP-O-SPEC.md §7 Q4 records deferral; CHANGELOG calls out | open |
| O.O3-7 | med | When same AI risk applies to multiple use cases, model is one-row-per-use-case (cf. LOOP-B finding) | Operator UI links via "duplicate to next use case" action; documented | open |

### O.O4 — AI evaluation per OMB M-24-10 (pre-deployment + ongoing)

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| O.O4-1 | high | M-24-10 PDF may return 403 (cross-ref O-X2) | Operator downloads; `--strict-ai` blocks ship if marker remains | open |
| O.O4-2 | med | Framework output formats evolve (HELM, OpenAI Evals, BIG-bench publish schema changes) | Permissive parsers; missing required field → REQUIRES-OPERATOR-INPUT; per-reader fixture pinned at framework_version; CHANGELOG records adapter version | open |
| O.O4-3 | med | Operator may upload very large eval result files | Tracker enforces upload size limit (256 MB default; configurable); sha256 via stream; ledger stores URI not body | open |
| O.O4-4 | low | Cadence overdue logic could fire false-positives at clock skew | 24-hour grace period configurable; CHANGELOG documents | open |
| O.O4-5 | med | Independent evaluator metadata for safety-impacting is ambiguous | Operator declares evaluator identity + relationship in tracker form; reviewer accepts/rejects; rubric in runbook | open |
| O.O4-6 | med | PVA collector may not have an AI rule-type hook at slice start | Verify existing extension points before starting; add new rule-type registry if absent | open |
| O.O4-7 | med | `pass_fail` interpretation differs across frameworks (HELM has no global pass/fail) | Operator-supplied thresholds in config; default thresholds documented per framework | open |
| O.O4-8 | low | Operator-uploaded file integrity tradeoff (cross-ref O-X5) | Strict schema validation; missing required field → not-yet-evaluated + marker | open |

### O.O5 — Model card + datasheet emitter (Mitchell + Gebru)

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| O.O5-1 | med | Mitchell + Gebru PDFs may need anonymous-fetch workaround (arXiv rate-limits; cross-ref O-X2) | Operator downloads; extraction script verifies sha256; CHANGELOG pins version | open |
| O.O5-2 | med | Template extraction may garble verbatim section prompts | Extraction script normalizes whitespace; spot-check test pins ≥3 known-good sections byte-for-byte; manual review at first ship | open |
| O.O5-3 | high | Vendor model card content is copyright-protected; FedPy must NOT embed | Stub-only emission with URL + sha256 + vendor_name; documented in code comment + runbook | open |
| O.O5-4 | med | `model-cards-bundle` is first glob-based role; bundler may not support globs (cross-ref O-X11) | Verify before starting; extend bundler's role-expansion logic if needed; add bundler test path | open |
| O.O5-5 | med | Cross-loop dependency on O.O4 for Metrics section means O.O5 cannot ship until O.O4 ships | Dependency declared in frontmatter; when O.O4 absent, Metrics carries REQUIRES-OPERATOR-INPUT marker | open |
| O.O5-6 | low | Multi-model use cases produce multiple Model Cards but one use case | O.O1 records each as separate AiAsset; emission per-asset; SSP back-matter resource set per-asset | open |
| O.O5-7 | low | Operator may edit emitted Markdown directly; signature invalidates | Tracker UI is source of truth; CLI emits read-only Markdown; CHANGELOG documents convention | open |

---

## External dependencies that may change

### FedRAMP guidance updates that could affect LOOP-O
- **FedRAMP Rev5 SSP Template §11 (System Environment)** — current consumer of AI inventory subsection. Format changes here would update O.O1 SSP integration. URL: https://www.fedramp.gov/
- **FedRAMP Authorization Boundary (RFC-0004)** — AI inference cross-boundary calls may be re-classified; cross-references LOOP-D diagram when implemented.
- **AFR-PVA family (FRMR catalog)** — O.O4 reuses cadence; FRMR catalog updates could change cadence semantics.

### NIST publication versions
- **NIST AI 100-1 (AI RMF 1.0, Jan 2023)** — current. A 2.0 anticipated. URL: https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf
- **NIST AI 600-1 (GenAI Profile 1.0, Jul 2024)** — current; expected to update with GenAI category additions. URL: https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
- **NIST AI RMF Playbook (AIRC)** — continuously updated. URL: https://airc.nist.gov/AI_RMF_Knowledge_Base/Playbook
- **NIST SP 800-53 Rev 5 (Sep 2020, errata Dec 2023)** — cross-walked to AI RMF subcategories. Rev 6 long-tail; would require catalog regen + crosswalk refresh.
- **NIST SP 800-30 Rev 1 (2012)** — likelihood/impact bands reused. A Rev 2 publication would update qualitative tokens; O.O3 schema would need migration.

### OMB memoranda
- **OMB M-24-10 (Mar 28 2024)** — current. EO 14179 (Jan 2025) re-tuned priorities but inventory + minimum-practice obligations remain. URL: https://www.whitehouse.gov/wp-content/uploads/2024/03/M-24-10-Advancing-Governance-Innovation-and-Risk-Management-for-Agency-Use-of-Artificial-Intelligence.pdf
- **OMB M-25-21 (Mar 2025)** — current. Procurement flow-down. URL: https://www.whitehouse.gov/wp-content/uploads/2025/03/M-25-21-Memorandum.pdf
- **Future OMB AI memoranda** — anticipated; any incident-reporting requirement could trigger a hypothetical O.O6.

### Executive orders
- **EO 14110 (Oct 30 2023)** — directed agencies to adopt NIST AI RMF.
- **EO 14179 (Jan 2025)** — re-tuned but did NOT rescind M-24-10 inventory + minimum-practice requirements.

### Academic / industry standards
- **Mitchell et al. (2018) Model Cards** — stable; arXiv-published. URL: https://arxiv.org/abs/1810.03993
- **Gebru et al. (2018) Datasheets** — stable; arXiv-published. URL: https://arxiv.org/abs/1803.09010
- **MITRE ATLAS** — evolving adversarial taxonomy. URL: https://atlas.mitre.org/
- **ISO/IEC 42001:2023** — AI Management System standard; voluntary; cross-references in O.O2 catalog where published.
- **EU AI Act** — out of FedRAMP scope; informs O.O3 risk-category enum where overlap with NIST exists.

### Evaluation framework upstream
- **HELM (Stanford CRFM)** — https://crfm.stanford.edu/helm/ — schema changes regularly; reader pins framework_version.
- **OpenAI Evals** — https://github.com/openai/evals — JSONL format stable but new eval types appear.
- **BIG-bench (Google)** — https://github.com/google/BIG-bench — frozen but referenced.
- **MMLU** — https://arxiv.org/abs/2009.03300 — stable scoring.
- **TruthfulQA** — https://arxiv.org/abs/2109.07958 — stable.

### Cloud provider AI service SDKs
- **AWS SageMaker / Bedrock APIs** — evolving rapidly; SDK shape changes possible. Defensive parsing required.
- **GCP Vertex AI / Document AI / Cognitive APIs** — evolving; defensive parsing.
- **Azure ML / Azure OpenAI / Cognitive Services** — evolving; defensive parsing.

### Upstream library updates
- **ajv (^8.x)** — used by `core/oscal-validate.ts`; pin major version.
- **OSCAL JSON Schema v1.1.2** — pinned within LOOP-O; future v1.2.x migration is separate cross-loop refactor.
- **better-sqlite3 (~9.x or ~11.x)** — used by tracker; SQL dialect stable.
- **rfc8785 / canonicalize** — pin one canonical-JSON library across cloud-evidence + tracker.
- **@noble/ed25519 (^2.x)** — Ed25519 signing; stable API.
- **pdfjs-dist / pdf-parse** — used by extraction scripts; pin version.
- **node-html-parser** — used by AIRC Playbook snapshot parser; pin version.
- **React (^18.x)** — tracker UI; pin major within LOOP-O.

### Subprocessor + supply chain
- **LOOP-J.J2 (subprocessor inventory)** — when a CSP subprocessor uses AI on the CSP's behalf, the AI inventory must include the subprocessor's AI surfaces; O.O1 reads from J.J2 when LOOP-J ships.

---

## Resolved risks (historical)

> Empty initially — populated as risks are resolved.

| ID | Resolved date | Resolution note | Resolved by |
|---|---|---|---|
| — | — | — | — |

---

## Procedure for adding / updating a risk in this register

1. New risks discovered during implementation: add a row in the appropriate per-slice section with a fresh ID (e.g. `O.O3-8`); commit alongside the slice's implementation log update.
2. Risks resolved during implementation: move the row to the "Resolved risks" table at the bottom with date + resolution note + responsible session/commit. Do NOT delete the original entry — historical record matters.
3. Severity bump (low → med → high): add a `note` line under the original entry describing why; do not edit history.
4. Cross-cutting risks that affect multiple slices: keep in the cross-cutting section; reference from per-slice tables via "(cross-ref O-X<n>)".
5. Cross-loop risks (where the same risk pattern also tracked in LOOP-B-RISKS or LOOP-A-RISKS): reference via "(cross-ref B-X<n>)" or "(cross-ref A-X<n>)" without duplicating the full text.

---

## Resume-from-fresh-session checklist

If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. Read `cloud-evidence/docs/loops/LOOP-O-SPEC.md` Section 7 (open questions) — overlaps with this register.
3. Read the specific per-slice doc at `docs/slices/O/O.O<n>.md` for the slice you're implementing — risks here are the LIVE working set; risks in the per-slice docs are the spec snapshot.
4. Before shipping a slice, update this file's per-slice section + move any resolved risks to the resolved table atomically with the slice's commit (per SLICE-COMPLETION-PROCEDURE.md).
5. If working on cross-loop integration with LOOP-A / LOOP-B / AFR-PVA, also read `docs/loops/LOOP-A-RISKS.md` (when exists) + `docs/loops/LOOP-B-RISKS.md` — many O.O risks reference B-X* and A-X* counterparts.
