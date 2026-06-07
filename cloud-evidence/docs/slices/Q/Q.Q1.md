---
slice_id: Q.Q1
title: FedRAMP Marketplace listing emitter (per RFC-0021 format)
loop: Q
status: pending
commit: —
completed_date: —
depends_on: [LOOP-A.A1, LOOP-A.A2, LOOP-A.A3, LOOP-A.A4, Q.Q3, LOOP-G.G3]
blocks: [LOOP-G.G3, LOOP-I.I1, Q.Q2]
estimated_effort: 5 working days
last_updated: 2026-06-07
applicable_conditional: true
---

# Q.Q1 — FedRAMP Marketplace listing emitter (per RFC-0021 format)

## TL;DR
Emit a machine-readable `out/marketplace-listing.json` + human-readable `out/marketplace-listing.md` mirror, derived 100% from the real OSCAL submission package (SSP / AP / AR / POA&M / inventory / KSI envelopes / Q.Q3 agency snapshot / operator `config.yaml`). The listing is the canonical content a Marketplace consumer + leveraging-agency procurement officer ingests; without it a FedRAMP-Authorized CSO is commercially invisible. Schema is FedPy-local `marketplace-listing.v1` (forward-compatible with FedRAMP CR26).

## Status
- Status: pending
- Commit: —
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
LOOP-A produced the *submission* package (SSP + AP + AR + POA&M + IIW + RoE + bundle + manifest + timestamp). Q.Q1 produces the *publication* artifact — the structured listing JSON the FedRAMP Marketplace registry ingests once CR26 lands, and that the CSP's Trust Center serves at `<trust-center>/.well-known/fedramp-marketplace.json` per the 20x Authorization Data Sharing standard. Every field traces to real evidence: CSO identity → SSP `system-characteristics`; impact level → FIPS-199 max from SSP; services in scope → `inventory.json` from real AWS/GCP/Azure SDK reads; controls in scope → `core/control-benchmark.ts`; KSI baseline → `core/ksi-map.ts` + `out/KSI-*.json` envelopes; POA&M counts → `out/poam.json`; agencies → Q.Q3 tracker snapshot. No invented data; missing operator fields surface as `requires_operator_input[]` markers per REO Rule 4.

## Why this slice exists
The gap: the FedRAMP Marketplace (`https://marketplace.fedramp.gov/`) is the public-facing registry every federal agency uses to discover authorized cloud services for "leverage" (reuse) under OMB Circular A-130 §III.A.2. A CSO that completes ATO is technically authorized but not discoverable until the structured Marketplace listing is published. RFC-0021 ("Expanding the FedRAMP Marketplace") explicitly mandates a machine-readable + human-readable listing per the CR26 schema (publication committed by end of June 2026 per NTC-0005). Today the FedPy pipeline emits the OSCAL chain but no Marketplace-shaped artifact. Q.Q1 closes that gap by deriving the listing from the same real-evidence sources the OSCAL chain consumes, signing it under the existing pipeline, and surfacing every operator-supplied field as REQUIRES-OPERATOR-INPUT when missing.

## Authoritative sources (with verbatim quotes)

- **RFC-0021 "Expanding the FedRAMP Marketplace"** — https://www.fedramp.gov/rfcs/0021/
  - **MKT-GEN-DOD (Ongoing Demand)**:
    > "Providers MUST demonstrate ongoing demand and utility by including… A list of all _agencies_ that are directly using the product"
    > "A list of all _agencies_ that have requested access to _authorization data_, covering the period since the previous _Ongoing Authorization Report_"
  - **MKT-FRX-PAD (FedRAMP Data Transparency)**:
    > "FedRAMP MUST publish activity data showing the status of all non-sensitive Marketplace-related activities"
  - **Schema reference**:
    > "FedRAMP will publish a JSON Schema for the required machine-readable data"
  - RFC closed 2026-02-19; outcome at https://www.fedramp.gov/notices/0005/.

- **NTC-0005 — RFC-0021 initial outcome notice** — https://www.fedramp.gov/notices/0005/
  - JSON Schema commitment:
    > "FedRAMP will provide a JSON schema for the required web information"
    > "this schema will be included in the Consolidated Rules for 2026, along with information about validation"
  - Field removal:
    > "MKT-GEN-SPI Service Pricing Information will be struck"
  - Timeline:
    > "FedRAMP will publish the FedRAMP Consolidated Rules for 2026 (CR26) by the end of June, 2026"

- **FedRAMP 20x Authorization Data Sharing standard** — https://www.fedramp.gov/docs/20x/authorization-data-sharing/
  - Required Trust Center fields:
    > "FedRAMP Marketplace link; service and deployment models; business category and UEI number; contact information; service description with detailed list of specific services and their security objectives; customer responsibility summary; trust center access process; support information; next Ongoing Authorization Report date"
  - Automation requirement:
    > "MUST use automation to ensure information remains consistent between human-readable and machine-readable formats"

- **FedRAMP Agency Authorization Playbook v4.1 (2025-11-17)** — https://www.fedramp.gov/resources/documents/Agency_Authorization_Playbook.pdf
  - Defines three Marketplace statuses Q.Q1 emits (`fedramp_ready`, `in_process`, `authorized`):
    - FedRAMP Ready — 3PAO-attested readiness, FedRAMP-reviewed RAR; Mod/High only.
    - FedRAMP In Process — active authorization with sponsoring agency partnership.
    - FedRAMP Authorized — AO ATO letter signed; the only status enabling "assess once, use many."

- **FIPS 199 — Standards for Security Categorization of Federal Information and Information Systems** — https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.199.pdf
  - Categorization rule (referenced for `impact_level` derivation):
    > "The high water mark for the security category of an information system... is the highest impact value among the security categories of the information types resident on the system."
  - Q.Q1 takes max of SSP `security-objective-{confidentiality,integrity,availability}` to derive `impact_level` per the high-water-mark rule.

- **OMB Circular A-130, Appendix III §III.A.2** — https://www.whitehouse.gov/wp-content/uploads/legacy_drupal_files/omb/circulars/A130/a130revised.pdf
  - Federal agencies must use FedRAMP-authorized services for cloud; the Marketplace is the canonical discovery surface.

- **OSCAL System Security Plan v1.1.2** — https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/system-security-plan/json-reference/
  - Q.Q1 reads `system-characteristics.system-name`, `system-characteristics.security-impact-level.security-objective-*`, `system-characteristics.system-information.information-type[]` per the schema.

- **OSCAL Plan of Action and Milestones v1.1.2** — https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/plan-of-action-and-milestones/json-reference/
  - Q.Q1 reads `poam-items[].risks[]` for the `poam_summary` counts.

## Files to create (exact paths under cloud-evidence/)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/marketplace-listing.ts` — pure builder + disk emitter. `buildMarketplaceListing(inputs)` (pure, no IO) + `emitMarketplaceListing(opts)` (thin disk wrapper writing JSON + Markdown + provenance).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/marketplace-listing-markdown.ts` — Markdown renderer mirroring the JSON field set 1:1 with section headings.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/schemas/marketplace-listing.v1.json` — local JSON Schema (ajv) for the listing, forward-compatible with CR26.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/risk-config.example.yaml` — extend with `marketplace:` section (CSP name + UEI + sponsoring agency + 3PAO + trust center + contact + support).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/marketplace-listing.test.ts` — ≥18 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/marketplace-listing-markdown.test.ts` — ≥6 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/marketplace-listing/` — directory: fixture SSP, AP, AR, POA&M, inventory, KSI envelopes, agency-authorizations snapshot, config.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — append roles `marketplace-listing-json` (filename `marketplace-listing.json`) and `marketplace-listing-md` (filename `marketplace-listing.md`) to `WELL_KNOWN` with descriptions citing Q.Q1.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — new `--marketplace-listing` flag + env `CLOUD_EVIDENCE_MARKETPLACE_LISTING`; new `--strict-marketplace` flag that exits non-zero when `requires_operator_input[]` non-empty. Wire AFTER POA&M + AR emission + AFTER Q.Q3 agency-authorizations snapshot.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/CHANGELOG.md` — "Unreleased" entry with module names + verification counts + REO compliance note.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/STATUS.md` — slice row + Overall section bump.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/LOOP-Q-SPEC.md` — Section 8 status table row.

## Schemas / standards
- **Locally-authored `marketplace-listing.v1.json` JSON Schema** at `cloud-evidence/docs/schemas/marketplace-listing.v1.json`. Top-level fields:
  - `schema_version`: const `marketplace-listing.v1`.
  - `package_format_version`: const `20x.phase-two.preview.2026`.
  - `emitted_at`: ISO datetime (string format=date-time).
  - `cso_name`, `csp_name`, `csp_uei`: strings.
  - `impact_level`: enum `low | moderate | high`.
  - `service_models[]`: enum array `iaas | paas | saas`.
  - `deployment_models[]`: enum array `public | private | community | hybrid | government`.
  - `marketplace_status`: enum `fedramp_ready | in_process | authorized` (per Agency Authorization Playbook v4.1).
  - `marketplace_id`, `package_id`: nullable string (FedRAMP-assigned; null until PMO assigns).
  - `sponsoring_agency`: nullable object `{ name, uei?, ato_date, signing_official_name? }`.
  - `three_pao`: object `{ name, uei?, assessment_date }`.
  - `services_in_scope[]`: array of `{ provider, service_id, service_name }`.
  - `controls_in_scope[]`: array of `{ control_id, control_family }`.
  - `ksi_baseline[]`: array of `{ ksi_id, domain, status }`.
  - `poam_summary`: `{ open_count, critical_count, high_count, moderate_count, low_count, deviation_approved_count }`.
  - `agencies_directly_using[]`: array of agency entries from Q.Q3 (RFC-0021 MKT-GEN-DOD).
  - `agencies_requested_access[]`: array of access-request entries from Q.Q3 (RFC-0021 MKT-GEN-DOD).
  - `next_ongoing_authorization_report_date`: ISO date (first of next month).
  - `trust_center`: `{ url, access_process, data_formats[] }` per 20x ADS.
  - `contact`: `{ name, email, phone?, role }`.
  - `customer_responsibility_summary`, `service_description`: strings.
  - `support_information`: `{ url?, email?, sla? }`.
  - `business_category`: string.
  - `fedramp_marketplace_link`: nullable string (FedRAMP-assigned).
  - `provenance`: `{ emitter, emitted_at, source_calls[], signing_key_id }`.
  - `requires_operator_input[]`: array of strings (one per unfilled operator field).
- **CR26 forward-compat**: every CR26-required field has a placeholder in v1. When CR26 publishes, implementer migrates to `marketplace-listing.cr26.v1` and emits CHANGELOG migration note. `package_format_version: "20x.phase-two.preview.2026"` surfaces lineage to consumers.
- **Markdown renderer** mirrors JSON 1:1 with section headings: CSO Identity → Authorization Status → 3PAO + Assessment → Services in Scope → Agency Reuse → Trust Center + Contact → POA&M Summary → Provenance.

## Build steps (concrete, numbered)

1. Define types in `core/marketplace-listing.ts` (full TypeScript interface set: `MarketplaceStatus`, `ServiceModel`, `DeploymentModel`, `ImpactLevel`, `AgencyReuseEntry`, `MarketplaceListing`). See LOOP-Q-SPEC.md §5 Q.Q1 step 1 for the verbatim type block.
2. Pure builder signature: `export function buildMarketplaceListing(inputs: { ssp, ap?, ar?, poam?, inventory, ksiMap, ksiEnvelopes, controlBenchmark, agencyAuthorizations, configMarketplace, emittedAt? }): MarketplaceListing;` — no IO, returns a fully-populated listing object with `requires_operator_input[]` populated for every missing operator field.
3. **Derive `impact_level`** from SSP `system-characteristics.security-impact-level.security-objective-{confidentiality,integrity,availability}` per FIPS 199 high-water-mark rule. Q.Q1 emits {low, moderate}; if `high` surfaces, append `REQUIRES-OPERATOR-INPUT: 20x-high-not-yet-supported` marker (consistent with existing HIGH-CLARIFY behaviour).
4. **Derive `services_in_scope`** from `inventory.assets[]` aggregated by `(provider, service)` distinct pair. AWS: distinct `service` field; GCP: distinct `service`; Azure: distinct `resource_provider`. Display names from a small lookup table (operator-tunable via config) — never invented.
5. **Derive `controls_in_scope`** from `core/control-benchmark.ts` filtered by impact_level (moderate by default). Output `{control_id, control_family}` per row.
6. **Derive `ksi_baseline`** by joining `core/ksi-map.ts` with `out/KSI-*.json` envelope summaries. Each registered KSI produces one row with `status` from the envelope's `summary.status`.
7. **Derive `poam_summary`** from `out/poam.json` `poam-items[].risks[]` counted by `props['severity']` enum value and `risk.status`. `deviation_approved_count` matches `risks` flagged with `deviation-approved` (per LOOP-B.B3 prop convention).
8. **Derive `agencies_directly_using`** from `out/.agency-authorizations.json` snapshot (Q.Q3 reader output) WHERE `status === 'active'`. When Q.Q3 snapshot absent, emit empty array + `requires_operator_input[]` entry: `"agencies_directly_using: Q.Q3 snapshot at out/.agency-authorizations.json not present"`.
9. **Derive `agencies_requested_access`** from Q.Q3 `agency_reuse_events` WHERE `event_type IN ('access-requested', 'access-granted', 'access-denied')` and `occurred_at >= previous_ongoing_authorization_report_date` (RFC-0021 MKT-GEN-DOD scope). When prior report date unknown, default to last 12 months.
10. **Operator-supplied fields** sourced from `config.yaml` `marketplace.*`: `csp_name`, `csp_uei`, `sponsoring_agency` (with sub-fields), `three_pao` (with sub-fields), `business_category`, `service_description`, `customer_responsibility_summary`, `trust_center` (with sub-fields), `contact` (with sub-fields), `support_information` (with sub-fields), `marketplace_id`, `package_id`. Each absent field → `requires_operator_input[]` entry with field path + remediation pointer.
11. **Compute `next_ongoing_authorization_report_date`** as first day of the month FOLLOWING `emittedAt` (mirrors monthly ConMon cadence). Q.Q2 publication updates the tracker `marketplace_listing_history` row when the actual report is created.
12. **Schema validation** via `core/oscal-validate.ts` ajv harness re-used. Compile schema at boot; validate listing object. Validation failure under `--strict-marketplace` exits non-zero with the failing field path.
13. **Disk emitter** in `core/marketplace-listing.ts`:
    ```ts
    export interface MarketplaceListingEmitOptions {
      outDir: string;
      sspPath?: string;
      apPath?: string;
      arPath?: string;
      poamPath?: string;
      inventoryPath?: string;
      configPath?: string;
      agencyAuthorizationsPath?: string;
      strict?: boolean;
      runId: string;
    }
    export interface MarketplaceListingEmitResult {
      jsonPath: string;
      mdPath: string;
      requires_operator_input: string[];
      schema_validation_passed: boolean;
    }
    export function emitMarketplaceListing(opts: MarketplaceListingEmitOptions): Promise<MarketplaceListingEmitResult>;
    ```
14. **Wire orchestrator**: `--marketplace-listing` calls `emitMarketplaceListing()` AFTER `--oscal-poam` + `--oscal-ar` + `--agency-auth-export`. `--strict-marketplace` is checked at the orchestrator level (in addition to inside the emitter) so the entire run exits non-zero.
15. **Add to `submission-bundle.ts` WELL_KNOWN**:
    ```ts
    { role: 'marketplace-listing-json', filename: 'marketplace-listing.json', description: 'FedRAMP Marketplace listing per RFC-0021 / NTC-0005 (LOOP-Q.Q1)' },
    { role: 'marketplace-listing-md', filename: 'marketplace-listing.md', description: 'Marketplace listing Markdown mirror (LOOP-Q.Q1)' },
    ```
16. **Sign + timestamp**: both files picked up by the existing `core/sign.ts` glob; included in RFC 3161 manifest via `core/timestamp.ts`. Trust Center publication serves the same signed bytes (LOOP-G.G3 reads them).

## REQUIRES-OPERATOR-INPUT fields

| Field | Source | Behavior when missing |
|---|---|---|
| `csp_name` / `csp_uei` | `config.yaml` `marketplace.csp_name` + `csp_uei` | `requires_operator_input[]` entry; `--strict-marketplace` blocks emission |
| `sponsoring_agency.{name,uei,ato_date,signing_official_name}` | `config.yaml` `marketplace.sponsoring_agency` OR Q.Q3 tracker row with `is_sponsoring_agency=1` | When absent OR `marketplace_status` would be `authorized`, force status → `in_process`; marker emitted |
| `three_pao.{name,uei,assessment_date}` | `config.yaml` `marketplace.three_pao` OR RoE signature block (`core/roe-emit.ts` output) | Marker emitted; Markdown surfaces "TBD - REQUIRES-OPERATOR-INPUT: 3PAO identity" |
| `business_category` | `config.yaml` `marketplace.business_category` (controlled vocabulary) | Marker emitted |
| `service_description` | `config.yaml` `marketplace.service_description` | Marker emitted; Markdown surfaces a notice |
| `customer_responsibility_summary` | `config.yaml` `marketplace.customer_responsibility_summary` (overlaps LOOP-L.L1 CRM when ratified) | Marker emitted |
| `trust_center.{url,access_process,data_formats}` | `config.yaml` `marketplace.trust_center` (overlaps LOOP-G.G3 ADS) | Marker emitted; if G.G3 incomplete, the field points at FedPy local Trust Center stub |
| `contact.{name,email,role,phone}` | `config.yaml` `marketplace.contact` | Marker emitted; `contact.email` required for Marketplace listing per RFC-0021 |
| `support_information.{url,email,sla}` | `config.yaml` `marketplace.support_information` | Marker emitted |
| `marketplace_id` / `package_id` | FedRAMP PMO-assigned; recorded in tracker via Q.Q3 UI on assignment | Null until assigned; Q.Q3 UI captures + back-fills on next emit |
| `agencies_directly_using` | Q.Q3 tracker `agency_authorizations` snapshot at `out/.agency-authorizations.json` | Empty array + marker; Markdown surfaces "No agencies tracked yet — see tracker /agency-authorizations" |
| Impact level `high` | SSP FIPS-199 derivation | Marker `REQUIRES-OPERATOR-INPUT: 20x-high-not-yet-supported`; emission proceeds but consumer is warned |

## Test specifications (≥12 tests)

1. `it('builds a valid listing from fixture SSP + AP + POA&M + inventory + KSI envelopes')` — pure builder; result validates against `marketplace-listing.v1.json` ajv.
2. `it('derives impact_level=moderate from FIPS-199 max of confidentiality/integrity/availability when each is moderate')`.
3. `it('derives impact_level=high and flags REQUIRES-OPERATOR-INPUT: 20x-high-not-yet-supported when any objective is high')`.
4. `it('enumerates services_in_scope from inventory.json aggregated per (provider, service) distinct pair')`.
5. `it('reads agency_authorizations from Q.Q3 snapshot and populates agencies_directly_using[] with status=active rows only')`.
6. `it('emits empty agencies_directly_using[] + marker when Q.Q3 snapshot absent')`.
7. `it('reads operator-supplied sponsoring_agency from config.yaml')`.
8. `it('forces marketplace_status=in_process when sponsoring_agency absent regardless of operator-set value')`.
9. `it('emits requires_operator_input[] containing every missing operator field with field path')`.
10. `it('--strict-marketplace blocks emission when requires_operator_input[] non-empty (orchestrator exit code 2)')`.
11. `it('writes marketplace-listing.json + marketplace-listing.md atomically; both files emit with matching sha256 in manifest')`.
12. `it('Markdown renderer produces section headings 1:1 with JSON field groups')`.
13. `it('schema validation rejects unknown enum value for marketplace_status (e.g. "fedramp-Authorized" mis-cased)')`.
14. `it('next_ongoing_authorization_report_date is first day of next month from emittedAt')`.
15. `it('poam_summary counts critical / high / moderate / low / deviation_approved from poam.json poam-items[].risks[]')`.
16. `it('ksi_baseline reads PASS/FAIL/PARTIAL/NOT-APPLICABLE from real KSI envelope summary.status')`.
17. `it('provenance.source_calls lists every file the emitter read (deterministic order)')`.
18. `it('submission-bundle WELL_KNOWN includes both marketplace-listing-json + marketplace-listing-md roles after Q.Q1 ships')`.
19. `it('writes Markdown table-of-contents at top with anchors matching section headings')`.
20. `it('agencies_requested_access[] populated from Q.Q3 agency_reuse_events of type access-requested/granted/denied within last 12 months')`.

## REO compliance
- Every value traces to: SSP (CSO identity, impact level), AP/AR/RoE (3PAO, assessment date), POA&M (item counts), inventory (services), KSI envelopes (KSI baseline status), Q.Q3 tracker (agencies), `config.yaml` (operator-authored prose).
- No silent fallbacks for: missing operator fields surface as `requires_operator_input[]` entries in both JSON and Markdown.
- Provenance fields populated: `emitter: "marketplace-listing.ts"`, `emitted_at` (ISO), `source_calls[]` (each file path + tracker endpoint read), `signing_key_id` (Ed25519 fingerprint).
- Signed by: existing `core/sign.ts` pipeline (Ed25519 detached signature + manifest); included in RFC 3161 manifest via `core/timestamp.ts`.
- Schema-validated: `marketplace-listing.v1.json` via `core/oscal-validate.ts` ajv harness.
- No `process.env.NODE_ENV === 'test'` branches (REO Rule 1.8); tests inject seams via dependency-injected fixture paths.

## Verification commands
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/marketplace-listing.test.ts tests/core/marketplace-listing-markdown.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
```

## Known risks / issues
- **Risk 1: CR26 Marketplace JSON Schema not yet published (NTC-0005 commits end of June 2026).** Q.Q1 ships `marketplace-listing.v1` as a forward-compatible FedPy-local schema. When CR26 publishes, the implementer migrates to `marketplace-listing.cr26.v1` and emits a CHANGELOG entry quoting the diff. Mitigation: `package_format_version: "20x.phase-two.preview.2026"` field surfaces lineage; CHANGELOG migration note documents every field rename.
- **Risk 2: Sponsoring-agency identity may be unknown at first run.** Per `docs/ADDITIONAL-LOOPS-AUDIT.md` §5.4, 20x eliminated the JAB; replacement is single-agency sponsorship + PMO P-ATO. If operator hasn't declared, status forces to `in_process` and marker emitted. Mitigation: Q.Q3 tracker UI captures sponsoring agency at first run; `--strict-marketplace` blocks `authorized` status emission until set.
- **Risk 3: 3PAO identity drift between RoE signature block and `config.yaml`.** Q.Q1 prefers `config.yaml` when both present (operator wins). Mitigation: test pinning the precedence; CHANGELOG entry documents.
- **Risk 4: Trust Center URL may overlap with LOOP-G.G3 ADS slice; coordination required to avoid duplicate config.** Mitigation: Q.Q1 reads `config.yaml marketplace.trust_center.*`; G.G3 reads the same path; single source of truth.
- **Risk 5: Markdown renderer formatting drift across Markdown engines (GitHub vs PMO Trust Center).** Mitigation: pin to CommonMark + a small set of GFM extensions (tables); test the rendered output against a CommonMark validator.
- **Risk 6: HIGH impact level emission semantics conflict with existing HIGH-CLARIFY warning in orchestrator.** Mitigation: when `impact_level=high`, Q.Q1 marker matches existing HIGH-CLARIFY language; CHANGELOG documents the cross-reference.

## Open questions
- **Q1**: Should `config.yaml` `marketplace.*` keys live in a separate `marketplace-config.yaml` file (separation of concerns) or stay in the existing `config.yaml`? Recommendation: extend `config.yaml`; one config file is easier for operators to maintain.
- **Q2**: When the FedRAMP PMO assigns `marketplace_id` + `package_id`, the operator records via Q.Q3 tracker — but does Q.Q1 re-emit on next run only, or should there be a "sync now" CLI? Recommendation: emit on next orchestrator run; document re-emit pattern in operator runbook.
- **Q3**: Schema-validation failure under `--strict-marketplace` — what's the exit code? Recommendation: 2 (consistent with existing `--strict-chain` in LOOP-A.A3).

## Implementation log
(empty — implementing session fills this in as work progresses)

## Completion checklist
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥24 for this slice)
- [ ] check:reo green (G1+G2+G3)
- [ ] check:provenance green
- [ ] STATUS.md updated (slice row + Overall section)
- [ ] LOOP-Q-SPEC.md Section 8 status row updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>, last_updated=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added (### Added — LOOP-Q.Q1: ...)
- [ ] Commit with slice ID in message
- [ ] Commit amended with hash recorded in STATUS.md + LOOP-Q-SPEC.md + this file
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. Read `cloud-evidence/docs/loops/LOOP-Q-SPEC.md` Sections 1-5 for loop context + dependencies + Q.Q1 narrative.
3. This file gives you: sources, files to create, build steps, tests, REO checks, REQUIRES-OPERATOR-INPUT table, risks, open questions, completion checklist.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory 7-step commit pattern.
5. Read `cloud-evidence/core/submission-bundle.ts` (WELL_KNOWN array) + `core/oscal-validate.ts` (ajv harness) + `core/sign.ts` + `core/timestamp.ts` — these are the extension/integration surfaces. Begin implementation; update the Implementation log section as you go.
