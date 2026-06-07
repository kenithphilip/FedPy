# LOOP-L — Risks Register

> Live document. Implementing sessions add entries during work; resolved risks stay in the file with `status=resolved` + resolution note. Severity: high = ship-blocking; med = should fix in-loop; low = file as follow-up.

> Authoritative companion to `docs/loops/LOOP-L-SPEC.md` and the per-slice docs at `docs/slices/L/L.L[1-4].md`. Read those for context before acting on any risk here.

> Last updated: 2026-06-07.

---

## Cross-cutting risks (apply to ALL slices in LOOP-L)

### L-X1 — FedRAMP CIS/CRM template format is in revision per 2026 Consolidated Rules planning
- **Description**: Per `docs/ADDITIONAL-LOOPS-AUDIT.md` §5.5, the FedRAMP CIS/CRM workbook format is still in revision. Column labels + worksheet layouts + 5- vs 7-bucket responsibility set may shift before FedRAMP 20x Phase Two GA. L.L1 mirrors current convention but a published format shift would invalidate every emitted workbook.
- **Severity**: high (L.L1 + L.L4 affected; L.L2 + L.L3 partial).
- **Mitigation**: Every emitted artifact carries `cis_crm_format_version: '20x.crm.preview.2026'` (mirrors LOOP-A.A4's `package_format_version` pattern). Future format shift gets a clean version bump in a single follow-up slice rather than silently re-shaping output. CHANGELOG entries for L.L1 + L.L4 quote the FedRAMP template version + URL at ship time. Operator runbook documents how to re-emit when version bumps.
- **Status**: open.

### L-X2 — FedRAMP CSP Authorization Playbook PDF gated by 403 on anonymous fetch
- **Description**: The FedRAMP CSP Authorization Playbook PDF (the authoritative source for the SSP Appendix J obligation L.L1 + L.L4 rely on) returns HTTP 403 to anonymous HTTPS fetches. The PDF must be downloaded manually by the operator into `cloud-evidence/docs/sources/fedramp-csp-playbook.pdf` before L.L1 ship can pin verbatim quotes. Same pattern as LOOP-B.B2's CMP PDF (LOOP-B-RISKS B-X1).
- **Severity**: high (L.L1 ship-blocking for verbatim quotes; L.L4 partial).
- **Mitigation**: Each affected slice carries a `REQUIRES-OPERATOR-INPUT: confirm-against-fedramp-csp-playbook-pdf` marker on its constants until the PDF is downloaded; `--strict-crm` orchestrator mode fails the build if the marker remains; CHANGELOG entry for L.L1 quotes the §SSP Appendix J text verbatim with PDF page + section, atomically with the operator-downloaded source.
- **Status**: open.

### L-X3 — OSCAL SSP v1.1.2 schema constraints on responsible-roles + by-components
- **Description**: L.L2 + L.L4 attach new fields to OSCAL SSP `metadata.parties[]`, `system-implementation.leveraged-authorizations[]`, `back-matter.resources[]`, and `control-implementation.implemented-requirements[].{responsible-roles[],by-components[]}`. OSCAL v1.1.2 requires every field be schema-legal; ajv strict mode rejects malformed values. A typo (missing `uuid` field, wrong enum value for `implementation-status.state`) would silently fail the bundle.
- **Severity**: high (L.L2 + L.L4 affected).
- **Mitigation**: `core/oscal-validate.ts` runs after every SSP re-emission; per-slice tests pin every field; ajv strict mode is the gate; CI fails if any new field violates schema. L.L4 maps `partially-implemented` → `partial`, `alternative-implementation` → `alternative` to match OSCAL enum.
- **Status**: open.

### L-X4 — Operator YAML transcription error introduces invalid control_id
- **Description**: L.L1 + L.L2 both rely on operator-committed YAML for the bulk of responsibility data. A typo (`AC-2(99)` instead of `AC-2(9)`, `AC-02` instead of `AC-2`) is silent if loader doesn't validate against the NIST Rev5 catalog. Result: workbook row references a nonexistent control; SSP `implemented-requirements[]` missing the control; non-conforming submission.
- **Severity**: med (all four slices).
- **Mitigation**: `core/responsibility-matrix.ts` (L.L1) + `core/leveraged-auth-config.ts` (L.L2) loaders validate every `control_id` against `core/nist-r5.ts` (NIST Rev5 catalog); throw typed error naming offending id; per-slice test pins. CHANGELOG entries reference the catalog version.
- **Status**: open.

### L-X5 — Multi-CSO YAML scoping deferred to LOOP-H.H3
- **Description**: All four LOOP-L slices read single-tenant operator YAML (`config/responsibility-matrix.yaml`, `config/leveraged-authorizations.yaml`). When multi-CSO ships (H.H3), every CSO needs its own YAML at `config/<cso-id>/responsibility-matrix.yaml`. If LOOP-L users start storing multi-CSO data via filename hacks, H.H3 migration becomes destructive.
- **Severity**: med (long-tail; L.L1 + L.L2 affected).
- **Mitigation**: Documented in LOOP-L-SPEC.md §7.7; H.H3 spec must enumerate every LOOP-L YAML; LOOP-L ships in single-CSO deployments only (documented in runbook). Future H.H3 migration is additive: add path resolver that defaults to single-tenant for backward compat.
- **Status**: open.

### L-X6 — Provenance schema drift across new emit artifacts
- **Description**: LOOP-L adds ≥7 new emit artifacts (`cis-crm-workbook.xlsx` + `.json`, `cis-crm-gap-report.md` + `.json`, `leveraged-authorizations.json`, `inheritance-trace.json`, `crm-per-control-narratives-index.json`, plus per-provider Component Definition files). Each must carry a `provenance` block per REO Rule 2.6. `scripts/check-provenance.mjs` enforces the schema (emitter, emittedAt, sourceCalls, signingKeyId). A missed block fails the slice.
- **Severity**: high (all four slices).
- **Mitigation**: Per-slice test verifies provenance via `check:provenance`; pattern reused from `core/inventory-coverage.ts`; CHANGELOG entry per slice cites the provenance block contents.
- **Status**: open.

### L-X7 — Submission bundle role count growth
- **Description**: LOOP-L adds ≥7 new roles to `submission-bundle.ts:WELL_KNOWN` (cis-crm-workbook-xlsx, cis-crm-workbook-json, cis-crm-gap-report-md, cis-crm-gap-report-json, leveraged-authorizations-json, inheritance-trace-json, oscal-component-definition, crm-per-control-narratives-tarball, crm-per-control-narratives-index). Each role must have a stable canonical filename + description; collisions would corrupt the bundle.
- **Severity**: med (all four slices).
- **Mitigation**: `tests/core/submission-bundle.test.ts` pins the role table; per-slice tests assert presence; LOOP-L SPEC §11 enumerates the final inventory at loop close. The `oscal-component-definition` role uses `filename_pattern` (glob) — verify pattern uniqueness against existing roles.
- **Status**: open.

### L-X8 — `process.env.NODE_ENV === 'test'` branch creep
- **Description**: REO Rule 1.8 prohibits this branch in production code. L.L4 in particular touches OOXML composition + filesystem path sanitisation — exactly where developers might reach for the shortcut.
- **Severity**: high (REO violation; CI rejects).
- **Mitigation**: `scripts/lint-no-stubs.mjs` catches the literal; tests inject seams via dependency-injected file readers + dependency-injected `runId` + dependency-injected UUID generator; CI gate is non-bypassable. Per-slice tests pin the absence.
- **Severity**: high.
- **Status**: open.

### L-X9 — Tests injecting SheetJS at the runtime layer rather than the test layer
- **Description**: L.L1 uses pure-JS OOXML composition (no SheetJS in production paths) but tests round-trip the emitted .xlsx via SheetJS to verify structure. Per CLAUDE.md Rule 2.4, "SDK transport may be mocked at the wire layer; parsers, validators, signers, and emitters are never mocked." The line is subtle: SheetJS in tests is fine; SheetJS in production would be REO violation (introducing an external dep that hides OOXML defects).
- **Severity**: med (L.L1 + L.L4 affected).
- **Mitigation**: SheetJS imported ONLY in `tests/core/cis-crm-xlsx.test.ts`; production code imports only the in-repo `core/zip.ts` + native `node:zlib`; `npm run lint:no-stubs` and CI scan catch any production import of `xlsx`/`exceljs` packages.
- **Status**: open.

### L-X10 — Coverage regression from new conditional emit paths
- **Description**: LOOP-L adds many `if (path-exists)` branches in `core/oscal-ssp.ts` (only populate `leveraged-authorizations[]` if `inheritance-trace.json` exists). Coverage measurement (`scripts/check-coverage-regression.mjs`) compares fill rates to `main` baseline. New conditional paths could cause regression if tests don't cover both branches.
- **Severity**: med.
- **Mitigation**: Per-slice tests exercise BOTH the "L.L2 has run" and "L.L2 has not run" SSP paths; coverage report explicitly inspected for new emit fields; CHANGELOG entries cite the per-slice coverage delta.
- **Status**: open.

### L-X11 — FedRAMP Marketplace PA-id lookup table cannot be fetched mechanically
- **Description**: Per `docs/ADDITIONAL-LOOPS-AUDIT.md` §5.10: "FedRAMP PA-ids ... are committed via PMO; LOOP-L.L2 needs a committed lookup table ... Currently no source mechanically extracts this; operator must supply." Marketplace.fedramp.gov has no JSON API. Each entry in `docs/leveraged-authorizations.generated.json` is operator-confirmed.
- **Severity**: high (L.L2 ship-blocking until lookup populated).
- **Mitigation**: Lookup file is committed under `docs/` with `operator_confirmed: true/false` per entry; `--strict-crm` refuses to ship until every discovered deployment has a confirmed entry; runbook documents the operator's check-marketplace-and-commit workflow; future LOOP-E (ConMon) slice may add automated polling if FedRAMP exposes a JSON API.
- **Status**: open.

### L-X12 — POA&M item explosion in early adoption
- **Description**: L.L3 emits one finding per gap. Early-adoption CSO with ~325 Moderate controls and only 50 yaml entries → ~275 gap findings → ~275 new POA&M items, dwarfing technical findings. AO + 3PAO triage workflow could break.
- **Severity**: med (L.L3 + LOOP-B.B1 interaction).
- **Mitigation**: All gap findings share `finding.provider = 'fedramp-package'` so 3PAO tooling can filter; runbook documents the filter pattern; CHANGELOG entry for L.L3 cites the expected initial item count; future LOOP-I dashboard surface adds aggregate roll-up.
- **Status**: open.

### L-X13 — Inheritance scope ambiguity (full / partial / hybrid)
- **Description**: L.L2's `inheritance_scope` field has 3 values, but the FedRAMP CRM template uses different language ("Yes", "No", "Hybrid"). Operator transcribing from provider's published CRM may interpret inconsistently.
- **Severity**: med (L.L2 + L.L4 affected).
- **Mitigation**: Module docstring documents the mapping (`full` = "Yes", `partial` = (subset described in description), `hybrid` = "Hybrid"); per-slice test pins; CHANGELOG entry includes the mapping for operator reference.
- **Status**: open.

### L-X14 — Test count threshold and CI counter expectations
- **Description**: LOOP-L adds ≥80 new tests across the 4 slices. Existing CI may have hard-coded "expected test count" assertions or coverage thresholds that need bumping. Same pattern as LOOP-B-X13.
- **Severity**: low.
- **Mitigation**: Per slice, the implementing session updates any test-count assertion; CHANGELOG entries cite the new totals; STATUS.md "Overall → tests" line bumped atomically with each slice ship.
- **Status**: open.

### L-X15 — OSCAL `inherited[]` requires `provided-uuid` for full conformance
- **Description**: OSCAL SSP `by-component.inherited[]` schema includes optional `provided-uuid` that references a `provided[]` element in the leveraged provider's Component Definition. First-cut L.L4 emits `inherited[]` with `description` + `links[]` but not `provided-uuid` because the leveraged provider's CD is not always available with that level of correlation. OSCAL ajv may warn but not fail; FedRAMP convention may eventually require.
- **Severity**: med (L.L4).
- **Mitigation**: First cut documents the gap; future enhancement adds correlation when leveraged provider's CD is loaded with `provided[]` array; CHANGELOG explicit about the deferral; risk is recorded for follow-up slice.
- **Status**: open.

### L-X16 — `responsible-roles` role-id vocabulary not FedRAMP-canonical
- **Description**: OSCAL doesn't pin a role-id vocabulary for CRM responsibility. L.L4 uses `'provider'` / `'customer'` / `'shared-csp-customer'` / `'inherited'`; FedRAMP may publish a canonical vocabulary (likely with kebab-case names) before GA. If they do, every SSP emitted under the L.L4 first cut would need re-emission.
- **Severity**: med (L.L4 + downstream SSP consumers).
- **Mitigation**: Role-id values defined as exported constants in `core/crm-split-renderer.ts` (`PROVIDER_ROLE_ID`, etc.); future migration is a single-file constant change + re-emit; CHANGELOG documents.
- **Status**: open.

### L-X17 — `cis-crm-workbook.xlsx` could grow large at High baseline (370+ controls)
- **Description**: Moderate at ~325 rows is manageable; future High deployment at ~370 base + enhancements pushes the workbook to 7 sheets × ~50-70 rows each. .xlsx file size + Excel rendering performance could surface as risk.
- **Severity**: low (L.L1 + L.L4).
- **Mitigation**: Pure-JS OOXML composition is streaming-friendly; file size measured per ship; CHANGELOG entry for L.L1 cites Moderate row count + file size. Future High support is a separate slice that re-baselines.
- **Status**: open.

---

## Per-slice risks

### L.L1 — CRM Workbook generator (SSP Appendix J)

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| L.L1-1 | high | FedRAMP CIS/CRM template format in revision (cross-ref L-X1) | Pin `cis_crm_format_version: '20x.crm.preview.2026'`; CHANGELOG cites audit §5.5 | open |
| L.L1-2 | med | Operator yaml may be incomplete on first run; many CSPs have not authored a per-control responsibility matrix | `--strict-crm` makes gaps visible (exits non-zero); without strict, REQUIRES-OPERATOR-INPUT markers surface in workbook; L.L3 gap report enumerates | open |
| L.L1-3 | med | `ksi-map.ts` may be incomplete for long-tail Moderate controls | Fall through to Step D (REQUIRES-OPERATOR-INPUT) rather than synthesising; documentation says operator can extend `ksi-map.ts` or fill via yaml | open |
| L.L1-4 | med | OOXML composition error producing invalid .xlsx | SheetJS round-trip test in `cis-crm-xlsx.test.ts` (TEST LAYER ONLY per CLAUDE.md Rule 2.4); mirror proven approach from `core/inventory-workbook.ts` | open |
| L.L1-5 | med | Bundler `required: true` bumps gap-detection list; existing `tests/core/submission-bundle.test.ts` may break | Ship bundler change atomically with L.L1 + test updates; CHANGELOG calls out new required artifacts | open |
| L.L1-6 | high | Inheritance trace not yet written when L.L1 runs first (operator skipped `--leveraged-auth`) | L.L1 detects missing `inheritance-trace.json`; emits `REQUIRES-OPERATOR-INPUT` on inherited rows + logs warning naming `--leveraged-auth` as the fix | open |
| L.L1-7 | med | Multi-CSO single yaml (cross-ref L-X5) | Documented in spec §7.7; H.H3 will migrate | open |
| L.L1-8 | low | Operator confuses `responsibility-matrix.yaml` (gitignored) with `responsibility-matrix.example.yaml` (committed) | README + runbook document; defaults work without operator config | open |
| L.L1-9 | low | Conditional formatting RGB colour may not render in non-Excel readers (LibreOffice, Google Sheets) | Colours documented; tests verify XML structure not visual rendering; CHANGELOG notes Excel as primary target | open |

### L.L2 — Inherited-controls tracker + Leveraged-Authorization enumeration

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| L.L2-1 | high | FedRAMP Marketplace PA-id lookup cannot be fetched mechanically (cross-ref L-X11) | Committed `docs/leveraged-authorizations.generated.json` with `operator_confirmed` flag; `--strict-crm` blocks ship until confirmed | open |
| L.L2-2 | med | Committed PA-id lookup may go stale | `pa_id_source: 'fedramp-marketplace'` + `operator_confirmed` flag; CHANGELOG cites snapshot date; future ConMon polls if FedRAMP exposes JSON | open |
| L.L2-3 | med | Operator transcription error in YAML (cross-ref L-X4 + L-X13) | NIST Rev5 control_id validation; inheritance_scope enum enforced; CHANGELOG documents source provider CRM version + date | open |
| L.L2-4 | med | OSCAL Component Definition schema not fetchable at build time | Schema committed under `docs/oscal/oscal_component-definition_schema.v1.1.2.json` (offline-resilient) | open |
| L.L2-5 | low | Inventory may use unexpected partition / cloud strings (e.g. new AWS partition `aws-iso-b`) | Discovery rules are typed enum; unknown partition logs warning + skips classification (does NOT silently classify as Commercial); future slice adds partition explicitly | open |
| L.L2-6 | med | Component Definition impact-tier vs CSO impact tier mismatch (provider FedRAMP-High; CSO Moderate) | Trace records both `provider.impact_level` and `cso.impact_tier`; yaml `inherited_controls[]` scoped to CSO tier; CHANGELOG documents resolution rule | open |
| L.L2-7 | med | Multi-cloud CSO with overlapping inherited controls (AC-2 inherited from both AWS + GCP) | `by_control['AC-2']` is array (not single value); L.L4 narrative composes "shared inheritance" paragraph naming both | open |
| L.L2-8 | low | Lookup-table commit history accidentally exposes embargoed PA-ids | Only commit confirmed marketplace-public entries; runbook documents | open |
| L.L2-9 | med | `--strict-crm` blocking on PA-id missing creates chicken-and-egg first-run problem | Non-strict mode emits with markers; operator copies marker list into lookup; subsequent run uses strict | open |
| L.L2-10 | low | `marketplace_url` link rot | Optional field; absence non-blocking; broken link is documentary only | open |

### L.L3 — CRM Gap Report

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| L.L3-1 | low | Heuristic for `partially-implemented-without-plan` could over- or under-fire | Keep severity `low`; reviewer dismisses; future structured `implementation_plan` field in yaml makes detection deterministic | open |
| L.L3-2 | med | POA&M item explosion in early adoption (cross-ref L-X12) | Bundle reviewer guidance in CHANGELOG; first-time operator runs without strict mode + iteratively fills yaml; 3PAO tooling filters by `provider: 'fedramp-package'` | open |
| L.L3-3 | med | `crm:no-responsibility` family clutters POA&M alongside technical findings | POA&M item carries `finding.rule = gap.gap_type` and `finding.provider = 'fedramp-package'`; 3PAO tooling can filter by provider | open |
| L.L3-4 | low | Coverage percent could mislead (100% mapped but all `not-applicable`) | Gap report summary shows bucket distribution; reviewer notices NA-heavy workbooks | open |
| L.L3-5 | low | Markdown output not consumed by existing tool; AO may want PDF | Future LOOP-C slice renders gap report to PDF via existing pandoc pipeline; first ship markdown only (text-grep-able) | open |
| L.L3-6 | med | Severity inflation if all gaps are `high` (no-responsibility + inherited-without-pa-id both high) | Severity matrix documented + tested; CHANGELOG cites rationale | open |
| L.L3-7 | med | Synthetic KSI `CRM-COMPLETE` collides with future real KSI | Namespace check at registration time; runbook documents reserved synthetic KSI ids | open |
| L.L3-8 | low | Gap report path threading through L.L1 strict-error message is brittle | L.L1 builds error string using L.L3 emit result if present; test pinned | open |

### L.L4 — Per-control Responsibility Split Renderer

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| L.L4-1 | med | 5-bucket → 7-bucket collapse loses information; yaml hints (`corporate_control`, `customer_supplied`) needed | Hints documented + tested; default mapping documented in module docstring + CHANGELOG | open |
| L.L4-2 | med | OSCAL `by-component.inherited[]` schema mandates `provided-uuid` for full conformance (cross-ref L-X15) | First cut documents gap; future enhancement adds `provided-uuid` correlation when leveraged provider's CD is loaded; OSCAL validator may warn but not fail | open |
| L.L4-3 | low | SSP .docx §13 table large at Moderate (~325 rows); Word may render slowly | Pure-JS OOXML composition is efficient; streaming write; CHANGELOG notes size; .docx remains under 5MB at Moderate per current tests | open |
| L.L4-4 | low | Filesystem path collisions on control_id with parens (AC-2(1) vs AC-2_1) | Enhancement ids unique by NIST convention; tests pin sanitisation rule; collision detection throws | open |
| L.L4-5 | low | Narrative composition re-emits all 325 files every yaml change | Composer fast (microseconds per control); idempotent; signed manifest catches changes; CHANGELOG documents | open |
| L.L4-6 | med | Multi-cloud inherited control (inherited from both AWS + GCP) needs both providers in narrative | Composer iterates `inheritedFor[]` array; tests fix this case | open |
| L.L4-7 | med | `responsible-roles` role-id vocabulary not FedRAMP-canonical (cross-ref L-X16) | Role-id values defined as exported constants; future migration single-file change + re-emit; CHANGELOG documents | open |
| L.L4-8 | med | SSP .docx pre-existing §13 layout may differ from L.L4's output | Ship L.L4 with explicit replacement of §13 block; tests render full .docx + assert §13 contents; CHANGELOG documents layout change | open |
| L.L4-9 | low | KSI citation in narrative could be stale if KSI evidence changes mid-run | Narrative captures `ksi_ids[]` at composition time; composer runs after KSI evidence fixed; signed snapshot consistent | open |
| L.L4-10 | low | `not-applicable` rows with empty `responsible-roles[]` may not validate under stricter OSCAL profiles | Verify ajv per-slice; first cut emits empty array which is schema-legal per OSCAL v1.1.2; CHANGELOG documents | open |

---

## External dependencies that may change

### FedRAMP guidance updates that could affect LOOP-L
- **FedRAMP CSP Authorization Playbook (Rev5)** — primary source for SSP Appendix J obligation L.L1 + L.L4 rely on. Format revision (2026 Consolidated Rules) would shift column labels + bucket set. URL: https://www.fedramp.gov/docs/rev5/playbook/csp/
- **FedRAMP CIS/CRM Workbook template (.xlsx)** — canonical column set L.L1 mirrors. Format revision per audit §5.5. URL: https://www.fedramp.gov/templates/
- **FedRAMP Rev5 SSP Template (.docx)** — drives L.L4 §13 layout + 7-bucket Origination labels. URL: https://www.fedramp.gov/templates/
- **FedRAMP Authorization Boundary Guidance** — defines the boundary the CRM partitions by responsibility. URL: https://www.fedramp.gov/assets/resources/documents/CSP_A_FedRAMP_Authorization_Boundary_Guidance.pdf
- **FedRAMP Marketplace** — single source of truth for PA-ids. Listing add/remove/revoke is operationally significant. URL: https://marketplace.fedramp.gov/
- **FedRAMP 20x Phase Two requirements** — published RFCs (RFC-0014 incorporated) could redefine inheritance semantics or move CRM into a different artifact family.

### NIST publication versions
- **NIST SP 800-53 Rev5 (Sep 2020, errata Dec 2023)** — current source for §2.5 (Inheritance), PL-2 (SSP), CA-5 (POA&M), SA-9 (External System Services). Rev6 in long-tail; would require catalog regeneration + L.L1 + L.L2 + L.L4 validator refresh. URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
- **NIST SP 800-53B Rev5 (errata 2023)** — Moderate baseline 287 controls. FedRAMP Rev5 Moderate adds enhancements (~325 total via FRMR). Rev6 baseline shift would re-baseline row set. URL: https://csrc.nist.gov/pubs/sp/800/53/b/upd1/final
- **NIST SP 800-37 Rev2 (2018)** — RMF inheritance language for L.L2 + L.L4. Stable. URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-37r2.pdf
- **NIST SP 800-53A Rev5** — assessment guide. Affects 3PAO procedures consuming the CRM. URL: https://csrc.nist.gov/publications/detail/sp/800-53a/rev-5/final

### OSCAL versions
- **OSCAL SSP v1.1.2** — committed at `cloud-evidence/docs/oscal/oscal_ssp_schema.v1.1.2.json`. NIST OSCAL Working Group periodically publishes new minor versions (v1.2.x in progress as of source date). Migration to v1.2 is a separate cross-loop refactor; pin v1.1.2 within LOOP-L. https://pages.nist.gov/OSCAL/
- **OSCAL Component Definition v1.1.2** — committed at `cloud-evidence/docs/oscal/oscal_component-definition_schema.v1.1.2.json`. Same version pin as SSP.
- **OSCAL Catalog / Profile v1.1.2** — Moderate Profile (FedRAMP Rev5 Moderate). URL: https://github.com/GSA/fedramp-automation/blob/master/dist/content/rev5/baselines/json/FedRAMP_rev5_MODERATE-baseline_profile.json

### Cloud provider authoritative pages
- **AWS Services in Scope (FedRAMP)** — L.L2's deployment-discovery validation source. URL: https://aws.amazon.com/compliance/services-in-scope/FedRAMP/
- **GCP FedRAMP page** — L.L2's GCP deployment discriminant. URL: https://cloud.google.com/security/compliance/fedramp
- **Azure FedRAMP page** — L.L2's Azure deployment discriminant. URL: https://learn.microsoft.com/en-us/azure/compliance/offerings/offering-fedramp

### Upstream library updates
- **ajv (^8.x)** — used by `core/oscal-validate.ts` for SSP + Component Definition v1.1.2 schemas. Schema validation behaviour changes are rare but possible; lock major version. https://ajv.js.org
- **js-yaml (^4.x)** — used by L.L1 + L.L2 YAML loaders. Stable; permissive parser; lock major.
- **xml-parser / fast-xml-parser** — used by L.L1 OOXML composition + L.L4 .docx generation. SSP .docx + .xlsx pipeline depends on stable XML escaping; pin major.
- **node:zlib / `core/zip.ts`** — used by L.L1 .xlsx ZIP composition + L.L4 .docx ZIP. Native; stable across Node 18+.
- **better-sqlite3 (~11.x)** — not directly consumed by LOOP-L production code; tracker DB only.
- **noble-ed25519 / @noble/ed25519 (^2.x)** — Ed25519 signing via `core/sign.ts`. Stable API.

### Cloud / infrastructure
- **AWS / GCP / Azure resource-tag schemas** — `fedramp_data_classification`, `assured_workloads_enabled`, `subscription_metadata.cloud` are existing inventory enrichment fields from INV-S2/S3/S4; LOOP-L's discovery rules depend on them remaining populated. Coverage-regression CI guardrail tracks; runbook documents operator tagging.

---

## Resolved risks (historical)

> Empty initially — populated as risks are resolved.

| ID | Resolved date | Resolution note | Resolved by |
|---|---|---|---|
| — | — | — | — |

---

## Procedure for adding / updating a risk in this register

1. New risks discovered during implementation: add a row in the appropriate per-slice section with a fresh ID (e.g. `L.L2-11`); commit alongside the slice's implementation log update.
2. Risks resolved during implementation: move the row to the "Resolved risks" table at the bottom with date + resolution note + responsible session/commit. Do NOT delete the original entry — historical record matters.
3. Severity bump (low → med → high): add a `note` line under the original entry describing why; do not edit history.
4. Cross-cutting risks that affect multiple slices: keep in the cross-cutting section; reference from per-slice tables via "(cross-ref L-X<n>)".

---

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. Read `cloud-evidence/docs/loops/LOOP-L-SPEC.md` Section 7 (Open questions) — overlaps with this register.
3. Read the specific per-slice doc at `docs/slices/L/L.L<n>.md` for the slice you're implementing — risks here are the LIVE working set; risks in the per-slice docs are the spec snapshot.
4. Before shipping a slice, update this file's per-slice section + move any resolved risks to the resolved table atomically with the slice's commit (per SLICE-COMPLETION-PROCEDURE.md).
