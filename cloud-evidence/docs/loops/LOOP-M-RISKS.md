# LOOP-M — Risks Register

> Live document. Implementing sessions add entries during work; resolved risks stay in the file with `status=resolved` + resolution note. Severity: high = ship-blocking; med = should fix in-loop; low = file as follow-up.

> Authoritative companion to `docs/loops/LOOP-M-SPEC.md` and the per-slice docs at `docs/slices/M/M.M[1-4].md`. Read those for context before acting on any risk here.

> Last updated: 2026-06-07.

---

## Cross-cutting risks (apply to ALL slices in LOOP-M)

### M-X1 — Privacy Act applicability ambiguity (conditional adoption)
- **Description**: Per ADDITIONAL-LOOPS-AUDIT.md §5 open question #2, LOOP-M.M1 is conditional on whether the CSP processes Privacy-Act-protected records retrievable by identifier on behalf of a federal agency. M.M2/M.M3/M.M4 do not have the same conditional gate but their semantics depend on whether a §552a system exists (e.g. M.M3 PT-6 narrative cross-references the SORN; M.M4 SORN-amendment finding requires SORN existence). Without resolving the applicability question first, every slice ships in an unstable state.
- **Severity**: high (M.M1 blocker; M.M3/M.M4 partial blockers).
- **Mitigation**: Operator (SAOP + Legal Counsel) MUST answer the §552a (a)(5) applicability question BEFORE M.M1 starts. The answer flows into tracker `privacy_records.retrieval_by_identifier_attested` per system. M.M3 PT-6 + M.M4 SORN-amendment logic reads the tracker rather than assuming.
- **Status**: open.

### M-X2 — Authoritative PDF gated by 403 / large-file / binary on anonymous fetch
- **Description**: Three load-bearing source PDFs cannot be fetched anonymously:
  - **NIST SP 800-53 Rev 5** (5.8 MB binary) — WebFetch returns un-parseable binary stream.
  - **OMB M-17-12** (HTTP 404 on anonymous fetch) — required for M.M4 §V verbatim quote.
  - **OMB M-03-22** (HTTP 404) — required for M.M1 §II.C.1.f cross-reference.
  - **NIST SP 800-122** (799 KB binary).
  The implementer must download these PDFs manually into `cloud-evidence/docs/sources/` before per-slice docstrings can carry verbatim quotes.
- **Severity**: high (all slices need verbatim PT-* / harm-factor quotes for REO compliance).
- **Mitigation**: Each affected slice (M.M1 PT-6 ref, M.M3 all 18 controls, M.M4 §V five factors) carries a `REQUIRES-OPERATOR-INPUT: confirm-against-<source>-pdf` marker on its quotes until the PDF lands in `cloud-evidence/docs/sources/`. `--strict-privacy` orchestrator mode fails the build if the marker remains. CHANGELOG entries quote verbatim with PDF page + section atomically with the slice ship.
- **Status**: open.

### M-X3 — OSCAL SSP back-matter + control-implementation schema constraints
- **Description**: M.M1 + M.M2 + M.M3 all extend `core/oscal-ssp.ts`. M.M1 adds back-matter resource `sorn-draft`, M.M2 adds back-matter resource `dpia`, M.M3 adds 18 `implemented-requirements` for PT family. OSCAL SSP v1.1.2 schema is strict: every prop needs `name`, optional `ns` (must match `CE_NS` = `https://cloud-evidence.example/oscal-ns`), back-matter `rlinks[].media-type` MUST match registered IANA types. A typo would silently fail `oscal-validate.ts`.
- **Severity**: high (all SSP-extending slices).
- **Mitigation**: `core/oscal-validate.ts` runs after every slice's SSP re-emission; `ns: CE_NS` is required by lint rule; CI fails on missing ns. Pattern matches LOOP-B B-X2.
- **Status**: open.

### M-X4 — Ed25519 signing-key rotation across cloud-evidence + tracker
- **Description**: M.M1 (privacy_records, sorn_publications), M.M2 (dpia_findings), M.M3 (pt_control_evidence, consent_records), M.M4 (privacy_incidents) ALL sign rows in the tracker using the tracker-resident Ed25519 key. Cloud-evidence side reads + verifies via signature checks in the snapshot readers (`sorn-reader.ts`, `dpia-reader.ts`, `pt-family-reader.ts`, `privacy-incident-reader.ts`). If the tracker rotates its signing key without exposing a historical key registry, snapshots written under the old key fail verification.
- **Severity**: med (impacts all M slices).
- **Mitigation**: Tracker exposes `GET /api/sign/public-keys` returning ALL historical public keys keyed by `key_id`; each reader cross-references each record's `signing_key_id` against the registry. Pattern matches LOOP-B B-X3.
- **Status**: open.

### M-X5 — Cross-system snapshot age skew (multi-slice integration)
- **Description**: When `--sorn`, `--dpia`, `--pt-family`, `--privacy-irp` are run together in one orchestrator pass, each pulls a different snapshot from tracker. If the tracker is being actively edited during a run (operator updating SORN draft while emit runs), snapshots could be inconsistent — e.g. M.M2 DPIA references a privacy_record that M.M1 emitter saw with `retrieval_by_identifier_attested=true` but the tracker now reads `false`.
- **Severity**: med.
- **Mitigation**: Each reader records `fetched_at`; orchestrator's `--strict-privacy` mode requires all snapshots within a 5-minute window; UI surfaces "Stale snapshot" warning when bound exceeded. Pattern matches LOOP-B B-X4.
- **Status**: open.

### M-X6 — RBAC role definitions drift (saop, dpo, breach-team)
- **Description**: LOOP-M depends on three new tracker roles: `saop` (Senior Agency Official for Privacy — M.M1, M.M2, M.M4 sign-offs), `dpo` (Data Protection Officer — M.M2 review), `breach-team` (M.M4 roster). The tracker's `rbac.ts` defines these constants, but the operator's identity provider (Okta / Azure AD / GitHub OIDC) may not map any user to these roles, leaving the tracker with admin-only access and no audit-meaningful sign-offs.
- **Severity**: med.
- **Mitigation**: First boot prompts admin to assign at least one `saop` and `dpo`; tracker UI's "Settings → Roles" page documents the mapping; operator runbook explains IDP-side configuration. Pattern matches LOOP-B B-X5.
- **Status**: open.

### M-X7 — `process.env.NODE_ENV === 'test'` branch creep
- **Description**: REO Rule 1.8 prohibits this branch in production code. New cross-cutting infrastructure (signed-row reading, HTTP fetch with retry, OOXML zip-store, classifier suggestion engine) is exactly where developers reach for `if (NODE_ENV === 'test')` shortcuts.
- **Severity**: high (REO violation; CI rejects).
- **Mitigation**: `scripts/lint-no-stubs.mjs` catches the literal; tests inject seams via DI'd HTTP fetcher + filesystem helper + signature-verifier seam; CI gate non-bypassable. Pattern matches LOOP-B B-X6.
- **Status**: open.

### M-X8 — Tracker schema migration on existing installs (6 new tables)
- **Description**: LOOP-M adds 6 new tracker tables: `privacy_records`, `sorn_publications` (M.M1), `dpia_findings` (M.M2), `pt_control_evidence`, `consent_records` (M.M3), `privacy_incidents` (M.M4). Existing tracker installs have user data — migrations must be additive only. The repo uses idempotent `CREATE TABLE IF NOT EXISTS`; any non-additive change is a breaking change.
- **Severity**: high.
- **Mitigation**: All 6 CREATEs are additive; CHANGELOG documents upgrade path; smoke test on copy of production DB; no DROP / ALTER COLUMN under any circumstance in LOOP-M; future H.H3 multi-tenant work batches all cross-loop migrations.
- **Status**: open.

### M-X9 — Provenance schema drift across new emit artifacts
- **Description**: Every new emit artifact in LOOP-M (`sorn-draft.md`, `sorn-input.json`, `no-system-of-records-attested.json`, `dpia.json`, `dpia.docx`, `pt-family-controls.json`, `privacy-irp-docx`, `privacy-breach-runbook.json`) must carry a `provenance` block per REO Rule 2.6. `scripts/check-provenance.mjs` enforces emitter, emittedAt, sourceCalls, signingKeyId. A missed block fails the slice. `.docx` artifacts use embedded metadata (`docProps/core.xml`) for provenance.
- **Severity**: high.
- **Mitigation**: Per-slice test verifies provenance via `check:provenance`; pattern reused from `core/inventory-coverage.ts`; CHANGELOG entries cite block contents.
- **Status**: open.

### M-X10 — PII tagging coverage gaps on existing fleet
- **Description**: M.M1 + M.M2 + M.M3 derive categories_of_individuals, categories_of_records, pii_categories[], data_subjects[] from inventory tags `fedramp_pii_categories`, `fedramp_pii_subjects`, `fedramp_pii_purposes`, `fedramp_data_classification`. Real CSPs have not back-tagged all assets; large fractions return REQUIRES-OPERATOR-INPUT.
- **Severity**: med (correctness signal, not a blocker).
- **Mitigation**: REQUIRES-OPERATOR-INPUT visibly on every affected emit; inventory-coverage CI guardrail tracks fill rates; documented in operator runbook with example tagging commands per provider (AWS `aws ec2 create-tags`, GCP `gcloud labels add`, Azure `az tag update`). Pattern matches LOOP-B B-X11.
- **Status**: open.

### M-X11 — OSCAL SSP regeneration order dependency
- **Description**: When all LOOP-M flags run in one pass, the order MATTERS: M.M1 → M.M2 → M.M3 → M.M4 → SSP regeneration. M.M1 supplies SORN snapshot; M.M2 supplies DPIA snapshot; M.M3 supplies PT-family narratives; M.M4 supplies POA&M findings (SORN-amendment). The SSP regeneration must run AFTER ALL FOUR. If the orchestrator runs `--oscal-ssp` mid-pass, the SSP will be missing later resources.
- **Severity**: med.
- **Mitigation**: Orchestrator documents flag-order invariant; CHANGELOG calls out; integration test in `tests/core/orchestrator-loop-m.test.ts` verifies; `--strict-privacy` mode enforces.
- **Status**: open.

### M-X12 — `.docx` zip-store determinism for re-signing
- **Description**: M.M2 + M.M4 emit `.docx` files via OOXML zip-store. Across OOXML library updates (different `archiver` / `JSZip` versions), file ordering or compression flags could drift; resulting SHA-256 changes; re-signing fails determinism check.
- **Severity**: med.
- **Mitigation**: Reuse existing proven `core/ssp-docx.ts` deterministic pattern (locked zip-store mode, deterministic file ordering, fixed timestamps); pin OOXML library version in package.json; tests assert SHA-256 stability across runs. Pattern matches LOOP-B B-X14 (POA&M XML).
- **Status**: open.

### M-X13 — Submission bundle role count growth
- **Description**: LOOP-M adds 7 new roles to `submission-bundle.ts:WELL_KNOWN`: sorn-draft-md, sorn-input-json, no-sorn-attestation, dpia-json, dpia-docx, pt-family-controls-json, privacy-irp-docx, privacy-breach-runbook-json. Each role must have stable canonical filename + description; collisions would corrupt the bundle.
- **Severity**: med.
- **Mitigation**: `tests/core/submission-bundle.test.ts` pins the role table; per-slice tests assert presence; CHANGELOG entry for M.M4 lists final role inventory at loop close. Pattern matches LOOP-B B-X8.
- **Status**: open.

### M-X14 — Cross-loop integration with LOOP-G.G2 AFR-ICP
- **Description**: M.M4 privacy classifier is meant to be called by LOOP-G.G2 AFR-ICP when an incident has `pii_implicated=true`. If G.G2 ships first, M.M4 must EXTEND G.G2's classifier registry; if M.M4 ships first, G.G2 must call M.M4's `classifyPrivacyIncident()`. Either way, the integration point must be documented and tested.
- **Severity**: med.
- **Mitigation**: M.M4 exports `classifyPrivacyIncident()` as a public function with stable signature; G.G2 documents the dependency; integration test in whichever ship-order applies. Documented in LOOP-M-SPEC.md §7 Q7.
- **Status**: open.

### M-X15 — NARA records schedule integration gap
- **Description**: M.M1 SORN section 20 (Retention and Disposal) references NARA general records schedule (GRS). We do not ingest GRS programmatically in LOOP-M; operator supplies the GRS citation as free text. A typo or stale citation could ship.
- **Severity**: low.
- **Mitigation**: Tracker UI provides GRS reference link; operator review prompt; future slice could automate GRS lookup (M.M5 candidate).
- **Status**: open.

### M-X16 — Test count expectations / CI thresholds
- **Description**: LOOP-M adds ≥80 new tests across cloud-evidence + tracker (≥20 per slice). Existing CI may have hard-coded "expected test count" assertions or coverage thresholds that need bumping.
- **Severity**: low.
- **Mitigation**: Per slice, implementing session updates any test-count assertion; CHANGELOG entries cite new totals; STATUS.md "Overall → tests" line bumped atomically with each slice ship. Pattern matches LOOP-B B-X13.
- **Status**: open.

### M-X17 — Multi-CSO tenant isolation deferred to H.H3
- **Description**: All 6 LOOP-M tables omit `tenant_id` column. When multi-CSO ships (H.H3), all 6 need migration in a single cross-loop sweep. If LOOP-M users start storing multi-tenant data via app-level filtering, the H.H3 migration becomes destructive.
- **Severity**: med (long-tail).
- **Mitigation**: Documented in LOOP-M-SPEC.md §7 Q10; H.H3 spec must enumerate every LOOP-M table; LOOP-M ship in single-tenant deployments only (documented in runbook). Pattern matches LOOP-B B-X15.
- **Status**: open.

### M-X18 — SAOP and DPO concept conflation
- **Description**: SAOP (Senior Agency Official for Privacy) is a U.S.-federal-specific role per OMB; DPO (Data Protection Officer) is a GDPR/EU role. M.M2 + M.M4 may need both in different contexts. If tracker conflates them (e.g. single column for sign-off), audit trail loses precision.
- **Severity**: low.
- **Mitigation**: Tracker maintains separate `reviewed_by_saop_user_id` and `reviewed_by_dpo_user_id` columns where both apply; UI surfaces which role is required for which artifact.
- **Status**: open.

---

## Per-slice risks

### M.M1 — System of Records Notice (SORN) emitter

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| M.M1-1 | high | Conditional applicability ambiguity — operator unsure whether CSO maintains §552a system (cross-ref M-X1) | Tracker `privacy_records` page provides §552a (a)(5) decision tree; SAOP signs attestation; legal review prompt | open |
| M.M1-2 | med | PII category tag coverage incomplete on existing fleet (cross-ref M-X10) | REQUIRES-OPERATOR-INPUT visibly on every affected SORN section; runbook documents per-provider tagging | open |
| M.M1-3 | low | Federal Register template format drift — GPO may revise 26-section structure | `format_version: 'fed-reg.preview.2026'` in JSON; CHANGELOG pins; future migration separate slice | open |
| M.M1-4 | med | Cross-system snapshot age skew (cross-ref M-X5) | `fetched_at` per table; `--strict-privacy` requires within 5 min | open |
| M.M1-5 | med | Ed25519 signing-key drift between tracker + cloud-evidence (cross-ref M-X4) | Tracker exposes historical public key registry | open |
| M.M1-6 | low | PII_CATEGORY_LABELS table may need i18n later | Out of scope; SORN is English by statute; documented in README | open |
| M.M1-7 | low | Exemptions (j)(2) / (k) handling is free-text — operator may misclassify | Future slice could structure; tracker UI prompts standard categories | open |

### M.M2 — Data Protection Impact Assessment (DPIA)

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| M.M2-1 | med | Region-jurisdiction mapping table drift — clouds add new regions over time | Source URLs in module docstring; test enumerates current regions; CI annual reminder | open |
| M.M2-2 | low | GDPR applicability ambiguity — many federal CSPs serve only US-federal users | `--dpia-jurisdictions=US-only` flag short-circuits cross-jurisdictional analysis; documented in runbook | open |
| M.M2-3 | med | DPO role mapping may not exist in operator IDP (cross-ref M-X6) | First-boot prompt for role assignment; SAOP can fulfil DPO when explicitly configured | open |
| M.M2-4 | med | Risk × mitigation matrix double-counting if a risk references multiple mitigations | Documented in code; tests pin de-dupe behavior | open |
| M.M2-5 | med | Cross-loop dependency on M.M3 PT-3 purposes register; M.M3 may not have shipped | Falls back to tracker `pt_control_evidence` directly; documented; independent paths | open |
| M.M2-6 | low | Article 35(7) interpretation drift — EU regulators publish updated guidance | Schema versioned via `dpia_format_version`; updates handled as follow-up slices | open |
| M.M2-7 | med | DOCX SHA-256 instability across OOXML library updates (cross-ref M-X12) | Reuse proven `core/ssp-docx.ts` pattern; pin library version | open |
| M.M2-8 | low | CIRCIA reporting overlay not yet supported | Out of scope; future enhancement | open |

### M.M3 — PT-family controls inventory (PT-1..PT-8)

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| M.M3-1 | med | PT-family content overlap with PIA narrative in LOOP-C.C4 — duplication risk | M.M3 narratives reference PIA; tracker UI shows PIA cross-reference; CHANGELOG documents boundary | open |
| M.M3-2 | low | NIST 800-53B Moderate baseline drift — future Rev 6 could change PT-family selection | `PT_MODERATE_BASELINE` typed constant; test pins count; future migration separate slice | open |
| M.M3-3 | low | Privacy Framework subcategory crosswalk staleness — v2.0 publication | `core/privacy-framework-crosswalk.ts` versioned constant; `pf_version: 'v1.0'` prop on emit | open |
| M.M3-4 | high | Consent-records plain-identifier leak risk — developer error could store plain identifier | Route enforces server-side hashing; tests verify hash-only; lint check | open |
| M.M3-5 | med | PT-8 CMA scope ambiguity for multi-agency CSO | Per-agency tracker row; operator-supplied rationale per CSO-agency pair | open |
| M.M3-6 | med | SSP regeneration order — `--pt-family` MUST run before `--oscal-ssp` (cross-ref M-X11) | Orchestrator documents order; integration test verifies | open |
| M.M3-7 | high | NIST PDF download blocking for verbatim PT-* control text (cross-ref M-X2) | `cloud-evidence/docs/sources/` pattern; CHANGELOG documents | open |
| M.M3-8 | med | Multi-tenant PT-family applicability — different tenants may have different PT-7 sensitive categories (cross-ref M-X17) | Per-tenant tracker rows; emit aggregates per system_id | open |
| M.M3-9 | med | PT-4 Consent not-applicable acceptability with 3PAO | Verify path with 3PAO + document in runbook | open |

### M.M4 — Privacy incident response procedures

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| M.M4-1 | high | OMB M-17-12 PDF download blocking for verbatim §V quote (cross-ref M-X2) | `cloud-evidence/docs/sources/omb-m-17-12.pdf` pattern; LOOP-M-SPEC.md §12 documents | open |
| M.M4-2 | med | Major-incident threshold drift — FISMA + OMB may revise 100,000-individual default | `--major-incident-threshold` CLI flag; CHANGELOG pins | open |
| M.M4-3 | med | CISA US-CERT endpoint may rotate per agency relationship | Operator-supplied via tracker; documented in runbook | open |
| M.M4-4 | med | AFR-ICP integration order ambiguity — M.M4 may ship before or after LOOP-G.G2 (cross-ref M-X14) | M.M4 exports `classifyPrivacyIncident()` with stable signature; G.G2 documents dependency; integration test in whichever ship-order applies | open |
| M.M4-5 | low | Substitute notice threshold (e.g. 50K w/o contact info) is OMB practice not statute | Operator-supplied via tracker; documented in plan | open |
| M.M4-6 | med | SAOP role mapping missing (cross-ref M-X6) | First-boot RBAC assignment | open |
| M.M4-7 | med | Multi-agency incident scoping — breach affects one tenant of CSO (cross-ref M-X17) | Per-tenant tracker rows; aggregate per agency | open |
| M.M4-8 | low | CIRCIA 72h overlay not modeled (when applicable) | Plan section 2 cites CIRCIA; operator config `circia_applicable`; future slice could expand | open |
| M.M4-9 | med | POA&M deadline drift for SORN-amendment-required finding | Pulled from `core/deadline-table.ts` (LOOP-B.B2); shared constant | open |
| M.M4-10 | med | Plan tabletop cadence enforcement — if `tabletop_date` not updated annually, plan ships stale | CI guardrail checks `tabletop_date` within 365d; warns at 330d; CHANGELOG documents | open |
| M.M4-11 | low | Runbook integration with PagerDuty / Opsgenie not in scope | Future enhancement; current emit is on-call-readable JSON | open |
| M.M4-12 | low | EU GDPR Article 33 72h overlay not in plan main flow | Cited in section 2 Authorities; M.M2 DPIA covers cross-jurisdictional scope | open |

---

## External dependencies that may change

### FedRAMP guidance updates that could affect LOOP-M
- **FedRAMP PTA + PIA templates** — https://www.fedramp.gov/assets/resources/templates/ — when GSA updates the PTA + PIA template pack, LOOP-C.C4 narratives change AND M.M3 PT-2/PT-3/PT-5/PT-6 cross-reference fields drift. Re-validation per slice.
- **FedRAMP 20x Phase Two requirements** — published RFCs (RFC-0014 already incorporated). A new RFC affecting privacy-package handling would reshape LOOP-M scope.
- **FedRAMP Continuous Monitoring Strategy & Guide** — drives the FedRAMP CMP deadline table that M.M4's POA&M emit for SORN-amendment uses (60-day high-severity slot).

### NIST publication versions
- **NIST SP 800-53 Rev 5 (Sep 2020, errata Dec 2023)** — current source for PT family + IR-6 + IR-8. A Rev 6 publication would require catalog regeneration + M.M3 narrative updates for any PT-family changes (control additions, statement rewording, enhancement re-selection). URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
- **NIST SP 800-53B Rev 5 Moderate Baseline (errata Dec 2023)** — current selection for PT-1..PT-8 + enhancements. Rev 6 baseline reselection would change `PT_MODERATE_BASELINE` constant. URL: https://csrc.nist.gov/pubs/sp/800/53/b/upd1/final
- **NIST SP 800-122 (Apr 2010)** — PII confidentiality impact level + categories. Long-stable but a SP 800-122 Rev 1 has been long-rumored. URL: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-122.pdf
- **NIST SP 800-37 Rev 2 (2018)** — RMF Step 1 Privacy Categorize. Stable.
- **NIST Privacy Framework v1.0 (Jan 2020)** — subcategory crosswalk. Rumored v2.0; would require `pf_version: 'v2.0'` migration.
- **NIST SP 800-30 Rev 1 (2012)** — likelihood/severity bands reused in DPIA risk-assessment schema. Rev 2 would change qualitative tokens.

### OMB guidance versions
- **OMB M-03-22** "OMB Guidance for Implementing the Privacy Provisions of the E-Government Act of 2002" — drives PIA scope and SORN cross-reference. Stable since 2003 but a rescission + replacement is possible.
- **OMB M-17-12** "Preparing for and Responding to a Breach of Personally Identifiable Information" (Jan 3, 2017) — drives M.M4 breach response framework. Supersedes M-07-16; could itself be revised.
- **OMB M-22-05** "Fiscal Year 2021-2022 Guidance" — codifies 7-day Congressional notification for major incidents. Annual FISMA memo; later FY versions may update threshold or timeline.
- **OMB Circular A-130 Appendix II** — privacy controls. Periodic re-issuance.

### Federal statutes (extremely stable but cited)
- **5 U.S.C. §552a (Privacy Act of 1974)** — drives M.M1 SORN obligation + M.M2 §552a (o) CMA scaffold. Statutory; amendments rare.
- **FISMA §3554(b)(7)(C)** — "major incident" definition. Statutory.
- **CIRCIA (2022)** — 72-hour reporting overlay. Rulemaking ongoing as of source date.
- **EU-US Data Privacy Framework** — successor to Privacy Shield. Could be invalidated by EU court (Schrems III hypothetical).
- **GDPR Article 35** — DPIA obligation. EU regulation.

### Upstream library updates
- **ajv (^8.x)** — used by `core/oscal-validate.ts`. Schema validation; lock major version.
- **OSCAL JSON Schema v1.1.2** — committed at `cloud-evidence/docs/oscal/oscal_ssp_schema.v1.1.2.json`. NIST OSCAL WG periodically publishes new minor versions; pin v1.1.2 within LOOP-M.
- **better-sqlite3 (~9.x or ~11.x)** — tracker DB. SQL dialect stable.
- **rfc8785 / canonicalize** — canonical JSON for signing. Lock library across repos.
- **noble-ed25519 (^2.x) or @noble/ed25519** — Ed25519 signing. Stable.
- **OOXML builder (`archiver` or `JSZip`)** — DOCX emit. Pin version for deterministic SHA-256.
- **React (^18.x)** — tracker UI.

### Cloud provider / infrastructure
- **AWS / GCP / Azure region → country mapping** — clouds add new regions over time; LOOP-M `region-jurisdiction.ts` requires periodic refresh. Documented in module header.
- **AWS / GCP / Azure resource-tag schemas** — `fedramp_pii_categories`, `fedramp_pii_subjects`, `fedramp_pii_purposes` are operator-defined custom tags. No upstream change risk; tag name conventions documented in operator runbook.

---

## Resolved risks (historical)

> Empty initially — populated as risks are resolved.

| ID | Resolved date | Resolution note | Resolved by |
|---|---|---|---|
| — | — | — | — |

---

## Procedure for adding / updating a risk in this register

1. New risks discovered during implementation: add a row in the appropriate per-slice section with a fresh ID (e.g. `M.M3-10`); commit alongside the slice's implementation log update.
2. Risks resolved during implementation: move the row to the "Resolved risks" table at the bottom with date + resolution note + responsible session/commit. Do NOT delete the original entry — historical record matters.
3. Severity bump (low → med → high): add a `note` line under the original entry describing why; do not edit history.
4. Cross-cutting risks that affect multiple slices: keep in the cross-cutting section; reference from per-slice tables via "(cross-ref M-X<n>)".

---

## Resume-from-fresh-session checklist

If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. Read `cloud-evidence/docs/loops/LOOP-M-SPEC.md` §7 (open questions) — overlaps with this register.
3. Read the specific per-slice doc at `docs/slices/M/M.M<n>.md` for the slice you're implementing — risks here are the LIVE working set; risks in the per-slice docs are the spec snapshot.
4. Before shipping a slice, update this file's per-slice section + move any resolved risks to the resolved table atomically with the slice's commit (per SLICE-COMPLETION-PROCEDURE.md).

---

End of LOOP-M-RISKS.md.
