---
slice_id: G.G4
title: AFR-MAS (Minimum Assessment Scope)
loop: G
status: pending
commit: —
completed_date: —
depends_on: [LOOP-A.A1, LOOP-A.A2, LOOP-A.A4, LOOP-A.A5, REO-0, R1, INV-P1, INV-P2, INV-P3, INV-P4, INV-P5]
blocks: [LOOP-F.F7, LOOP-J.J2, LOOP-I.I1]
estimated_effort: 6 working days
last_updated: 2026-06-06
---

# G.G4 — AFR-MAS (Minimum Assessment Scope)

## TL;DR
Ship the formal Minimum Assessment Scope document set: a machine-readable `out/afr-mas/minimum-assessment-scope.json`, the human-readable `.docx` counterpart, an information-flow SVG + PlantUML source diagram, and a `third-party-resources.json` register. Wraps the pre-existing `core/mas-reconcile.ts` documented-vs-discovered diff into a published artifact set that closes MAS-CSO-IIR, MAS-CSO-FLO, MAS-CSO-MDI and MAS-CSO-TPR. Every information resource, flow, and third-party row traces to real `inventory.json`, real SSP components, or operator-curated tracker rows — no synthetic resources, no silent "yes" on `handles_federal_data`.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
MAS-CSO-IIR is the anchor of the FedRAMP 20x scope contract: it requires the CSP to identify "the cloud service offering" as the set of information resources likely to handle federal customer data or to impact its CIA. The companion MUSTs require:
- Information-flow diagrams and per-resource security objectives (MAS-CSO-FLO).
- Metadata-about-federal-customer-data inclusion (MAS-CSO-MDI).
- Documented third-party information resources with prescribed fields per resource (MAS-CSO-TPR / FRR-MAS-02 + FRR-MAS-03).

Today `core/mas-reconcile.ts` computes a documented-vs-discovered set diff, which proves the inventory is honest but does NOT serve as the published scope document. The 3PAO needs a single artifact set they can sign off as the scope of record, the SAR can reference by hash, and the customer can read. G.G4 fills that gap by:

1. Reading the real `out/inventory.json` (already populated by INV-P1..S6 + AZ-1 + AZ-2) and the real SSP `system-implementation.components[]`.
2. Constructing one machine-readable scope JSON + one human-readable `.docx` (dependency-free OOXML, mirroring `core/roe-emit.ts` + `core/ssp-docx.ts`).
3. Generating an information-flow SVG (no external `plantuml` dep — same pure-JS approach the rest of the project takes) + a `.puml` source companion.
4. Producing a `third-party-resources.json` by consuming `core/subprocessors-sheet.ts` + the tracker subprocessor table, with the MAS-CSO-TPR prescribed field list per row.
5. Embedding the `mas-reconcile` drift block so any silent inventory drift surfaces in the published document.

Without G.G4, the SAR (LOOP-F.F7) cannot cite a published scope-of-record, J.J2 has no canonical third-party register to risk-tier, and the published service list (G.G3) cannot reference a coherent scope when the customer asks "what is in / out of the assessment boundary?".

## Authoritative sources (with verbatim quotes)

- https://github.com/FedRAMP/docs (FRMR.documentation.json v0.9.43-beta) — **MAS-CSO-IIR / FRR-MAS-01**:
  > "Providers MUST identify a set of information resources to assess for FedRAMP authorization that includes all information resources that are likely to handle federal customer data or likely to impact the confidentiality, integrity, or availability of federal customer data handled by the cloud service offering; this set of information resources is the cloud service offering."

- https://github.com/FedRAMP/docs (FRMR.documentation.json v0.9.43-beta) — **MAS-CSO-TPR / FRR-MAS-02 + FRR-MAS-03**:
  > "Providers MUST address the potential impact to federal customer data from third-party information resources used by the cloud service offering, ONLY IF MAS-CSO-IIR APPLIES, by documenting the following information about each applicable third-party information resource: …"
  (Sub-bullet list: legal entity, marketplace status, data types, processing location, supply-chain risk tier, contract identifier — re-quoted in `third-party-resources.json` schema and rendered verbatim in `.docx` §5.)

- https://github.com/FedRAMP/docs (FRMR.documentation.json v0.9.43-beta) — **MAS-CSO-MDI / FRR-MAS-04**:
  > "Providers MUST include metadata (including metadata about federal customer data) in the Minimum Assessment Scope ONLY IF MAS-CSO-IIR APPLIES."

- https://github.com/FedRAMP/docs (FRMR.documentation.json v0.9.43-beta) — **MAS-CSO-FLO / FRR-MAS-05**:
  > "Providers MUST clearly identify, document, and explain information flows and security objectives for ALL information resources or sets of information resources in the cloud service offering."

- https://www.fedramp.gov/rfcs/0024/ — **FedRAMP RFC-0024 (Machine-Readable Submissions)**:
  > "Authorization data MUST be available in both human-readable and machine-readable formats; machine-readable formats SHOULD align with the OSCAL data model where applicable."
  Drives the dual `.json` + `.docx` deliverable shape and the OSCAL-friendly key naming inside the scope JSON.

- https://www.fedramp.gov/docs/rev5/playbook/csp/authorization/sap/ — **FedRAMP Rev5 Playbook — Authorization SAP**:
  > "The Security Assessment Plan must describe the authorization boundary, all in-scope information resources, all information flows, and any third-party information resources upon which the cloud service offering depends."
  Establishes that the SAP (LOOP-A.A2 emits this) cites a scope document of record — which G.G4 is producing.

- https://pages.nist.gov/OSCAL/concepts/layer/implementation/component-definition/ — **OSCAL v1.1.2 Component Definition Model**:
  > "A component represents a discrete unit of functionality that can be used to satisfy one or more security requirements."
  Used to align `information_resources[].component_uuids` with SSP `system-implementation.components[].uuid` so the scope doc cross-references the SSP without divergence.

- https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final — **NIST SP 800-53 Rev 5 §CA-2 (Control Assessments)**:
  > "Develop, document, and disseminate to [Assignment: organization-defined personnel or roles]: an assessment plan that describes the … assessment boundary."
  Anchors the regulatory basis for publishing a scope-of-record.

- https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final — **NIST SP 800-53 Rev 5 §PM-5 (System Inventory)** + **§SA-9 (External System Services)**:
  > "Develop and update [Assignment: organization-defined frequency] an inventory of organizational systems."
  > "Require that providers of external system services comply with organizational security and privacy requirements …"
  Anchor the inventory + third-party legs.

- https://www.w3.org/Graphics/SVG/ — **SVG 1.1 (Second Edition) W3C Recommendation** §1.2 (Compatibility):
  > "SVG is a language for describing two-dimensional graphics in XML."
  Cited for the hand-rolled SVG emitter (no external dep, mirrors zero-dep philosophy of LOOP-D).

- https://plantuml.com/sequence-diagram — **PlantUML reference (sequence + activity grammar)** — used to produce a `.puml` companion source the operator can optionally render with their own PlantUML if they want richer styling.

## Files to create (exact paths)

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/afr-mas.ts` — pure builders + disk emitter. Exports:
  - `buildScopeJson(input: MasScopeInput): MasScopeJson`
  - `buildScopeDocx(input: MasScopeInput): { bytes: Uint8Array }`
  - `buildInformationFlowSvg(input: InfoFlowInput): string`
  - `buildInformationFlowPuml(input: InfoFlowInput): string`
  - `buildThirdPartyResourcesJson(input: ThirdPartyInput): ThirdPartyResourcesJson`
  - `emitAfrMas(outDir: string, ctx: OrchestratorContext): Promise<MasEmitResult>`
  ~700 lines including the SVG renderer.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/afr-mas.test.ts` — unit tests (≥13) for builders, SVG determinism, PlantUML grammar sanity, third-party row construction, REQUIRES-OPERATOR-INPUT emission.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/afr-mas.ts` — REST: `GET/POST /api/afr-mas/info-flows`, `GET/POST /api/afr-mas/metadata-in-scope`, `GET/POST /api/afr-mas/third-party-contracts`. RBAC: `security` for POST, `viewer` for GET.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/afr-mas.test.ts` — route tests + DB constraint tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/client/src/pages/MasScope.tsx` — operator UI: tabbed view (Information Flows | Metadata In Scope | Third-Party Contracts) with table + row-edit modals.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/client/src/pages/MasScope.test.tsx` — React Testing Library tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/AFR-MAS-RUNBOOK.md` — operator runbook: how to tag inventory assets with `fedramp_data_types`, `handles_federal_data`, `customer_facing`; how to declare info-flows; how to associate subprocessor contracts.

## Files to extend

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/mas-reconcile.ts` — re-export `MasReconcileResult` from `core/afr-mas.ts` (no new code in mas-reconcile; G.G4 consumes it as-is and embeds the diff in the scope JSON).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/subprocessors-sheet.ts` — extend with `getSubprocessorRowsForMas(): SubprocessorRowForMas[]` exporter that maps the existing subprocessor list to the MAS-CSO-TPR prescribed fields (legal entity name, marketplace status, data types, processing location, supply-chain risk tier). No SDK changes — just a typed projection.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — new `--afr-mas` flag + `CLOUD_EVIDENCE_AFR_MAS` env. Optional `--mas-aggregate` flag (group inventory by provider×type to reduce row count when inventory >100 assets).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — well-known catalogue rows for:
  - `{ role: 'afr-mas-scope-json', filename: 'afr-mas/minimum-assessment-scope.json' }`
  - `{ role: 'afr-mas-scope-docx', filename: 'afr-mas/minimum-assessment-scope.docx' }`
  - `{ role: 'afr-mas-info-flow-svg', filename: 'afr-mas/info-flow-diagram.svg' }`
  - `{ role: 'afr-mas-info-flow-puml', filename: 'afr-mas/info-flow-diagram.puml' }`
  - `{ role: 'afr-mas-third-party', filename: 'afr-mas/third-party-resources.json' }`
  All `required: true` for the L1 ATO submission bundle.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/schema.sql` — additive migrations:
  - `CREATE TABLE IF NOT EXISTS mas_info_flows (id INTEGER PRIMARY KEY AUTOINCREMENT, from_resource_id TEXT NOT NULL, to_resource_id TEXT NOT NULL, data_classification TEXT NOT NULL, transport TEXT NOT NULL CHECK (transport IN ('TLS-1.2','TLS-1.3','mTLS','private-network','other')), security_objective TEXT NOT NULL CHECK (security_objective IN ('C','I','A','CIA')), created_at TEXT NOT NULL, created_by_user_id TEXT NOT NULL);`
  - `CREATE TABLE IF NOT EXISTS mas_metadata_in_scope (id INTEGER PRIMARY KEY AUTOINCREMENT, resource_id TEXT NOT NULL, metadata_about TEXT NOT NULL CHECK (metadata_about IN ('federal-customer-data','system-operations','audit')), description TEXT NOT NULL, created_at TEXT NOT NULL, created_by_user_id TEXT NOT NULL);`
  - `CREATE TABLE IF NOT EXISTS mas_third_party_contracts (subprocessor_id TEXT PRIMARY KEY, contract_id TEXT NOT NULL, notes TEXT, updated_at TEXT NOT NULL, updated_by_user_id TEXT NOT NULL);`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/client/src/App.tsx` — register `/mas-scope` route.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/client/src/components/Nav.tsx` — nav entry.

## Schemas / standards

**`MasScopeJson`**:

```ts
interface MasScopeJson {
  $schema: 'https://fedramp.gov/schemas/afr-mas/scope/2026.json';
  system_id: string;          // from out/ssp.json system-id
  system_name: string;        // from out/ssp.json metadata.title
  csp_name: string;
  generated_at: string;       // RFC 3339
  information_resources: InformationResource[];
  information_flows: InformationFlow[];
  metadata_in_scope: MetadataInScope[];
  third_party_resources_ref: 'afr-mas/third-party-resources.json';
  documented_vs_discovered_diff: MasReconcileResult; // from core/mas-reconcile.ts
  provenance: {
    emitter: 'cloud-evidence/core/afr-mas.ts';
    emittedAt: string;
    sourceCalls: string[];   // ['out/ssp.json', 'out/inventory.json', 'tracker:mas_info_flows', ...]
    requirementTexts: Record<'MAS-CSO-IIR'|'MAS-CSO-FLO'|'MAS-CSO-MDI'|'MAS-CSO-TPR', string>;
    runId: string;
  };
}

interface InformationResource {
  id: string;                                              // sha256-derived stable id
  name: string;                                            // human-friendly name
  kind: 'compute'|'storage'|'database'|'network'|'identity'|'logging'|'integration';
  handles_federal_data: boolean;                           // tag fedramp_handles_federal_data; DEFAULT false
  data_types: string[];                                    // tag fedramp_data_types
  security_objectives: { c: Level; i: Level; a: Level };   // Level = 'Low'|'Moderate'|'High'
  provider: 'aws'|'gcp'|'azure'|'subprocessor';
  location: string;                                        // region or geographic identifier
  component_uuids: string[];                               // cross-ref to SSP components
}

interface InformationFlow {
  id: string;
  from: string;                                            // resource id
  to: string;
  data_classification: string;                             // e.g. 'CUI', 'public', 'internal'
  transport: 'TLS-1.2'|'TLS-1.3'|'mTLS'|'private-network'|'other';
  security_objective: 'C'|'I'|'A'|'CIA';
}

interface MetadataInScope {
  resource_id: string;
  metadata_about: 'federal-customer-data'|'system-operations'|'audit';
  description: string;
}
```

**`ThirdPartyResourcesJson`** (array root, per MAS-CSO-TPR):

```ts
interface ThirdPartyResourceRow {
  entity_name: string;                                       // legal entity
  fedramp_marketplace_status: 'authorized'|'in-process'|'not-listed';
  data_types_processed: string[];
  processing_location: { country: string; region: string };
  contract_id: string;                                       // REQUIRES-OPERATOR-INPUT
  supply_chain_risk_tier: 'low'|'moderate'|'high'|'critical';
  notes: string;
}
```

**SVG schema** — hand-rolled `<svg viewBox="0 0 W H" xmlns="http://www.w3.org/2000/svg">` with `<g class="resource">` for each information resource (rect + label) and `<g class="flow">` for each flow (line + arrowhead via `<marker>` def + label). Deterministic layout: nodes sorted ASC by id, placed in a grid (`columns = ceil(sqrt(N))`); edges drawn afterwards.

**PlantUML schema** — bracket-style activity / component grammar:
```
@startuml
skinparam handwritten false
component "<resource-id>" as <resource-id>
<resource-id> --> <other> : <classification> over <transport>
@enduml
```
Sorted deterministically.

## Build steps (concrete, numbered)

1. Define typed interfaces in `core/afr-mas.ts`. Determinism via `sortBy(arr, key)` helper at the top of the file.
2. Pure `buildScopeJson(input: MasScopeInput): MasScopeJson`:
   - Walk `out/inventory.json` assets → one `InformationResource` per asset (or aggregated per `provider×kind` when `opts.aggregate === true`).
   - Cross-reference SSP `system-implementation.components[]` by asset arn / id → populate `component_uuids[]`.
   - Read tracker `mas_info_flows` rows.
   - Read tracker `mas_metadata_in_scope` rows.
   - Embed `mas-reconcile.reconcileMas({ documented, discovered })` result into `documented_vs_discovered_diff`.
3. Pure `buildInformationFlowSvg(flows, resources)`:
   - Compute grid layout: `cols = ceil(sqrt(N))`; spacing 200x120.
   - Emit `<svg>` root with `<defs><marker id="arrow"/></defs>`.
   - One `<rect>` + `<text>` per resource; one `<line>` + `<text>` per flow.
   - Sort nodes ASC by `id`; sort flows ASC by `(from, to)`. Determinism is byte-stable.
4. Pure `buildInformationFlowPuml(flows, resources)`:
   - Emit `@startuml … @enduml` block.
   - Sorted deterministically.
5. Pure `buildThirdPartyResourcesJson(subprocessorList, contracts)`:
   - Map each subprocessor row to a `ThirdPartyResourceRow`.
   - Pull `contract_id` from tracker `mas_third_party_contracts.contract_id` keyed by `subprocessor_id`. If missing → emit `REQUIRES-OPERATOR-INPUT` marker for that row.
   - Carry `supply_chain_risk_tier` from `subprocessors-sheet.ts` mapping.
6. Pure `buildScopeDocx(input)` — mirror `core/roe-emit.ts` OOXML structure. 7 sections:
   1. **System Identity** — name, ID, run id, FRMR version (auto from SSP).
   2. **Information Resources** — table from `information_resources[]`.
   3. **Information Flows** — table + SVG/PUML reference.
   4. **Metadata In Scope** — table from `metadata_in_scope[]`.
   5. **Third-Party Resources** — verbatim MAS-CSO-TPR statement + table from `third-party-resources.json`.
   6. **Documented-vs-Discovered Reconciliation** — embeds `mas-reconcile` diff.
   7. **Provenance** — emitter + run id + commit hash + sourceCalls.
7. Disk emitter `emitAfrMas(outDir, ctx)`:
   - Read inventory + SSP + tracker rows.
   - Build all 5 artifacts.
   - Write to `out/afr-mas/`.
   - Append `provenance.requirementTexts` with the 4 verbatim MAS MUSTs.
   - Return `MasEmitResult` with `requires_operator_input: string[]` + `ready_for_signature: boolean`.
8. Orchestrator wiring: `--afr-mas` flag + env. Runs before signing.
9. Submission bundle catalogue: 5 new role rows.
10. Tracker routes: full CRUD on the three new tables; rate-limited per existing limiter.
11. Tracker UI: tabbed page with info-flows / metadata / third-party-contracts.
12. Validation pass: `npm run typecheck`; `npm test`; `npm run check:reo`.

## REQUIRES-OPERATOR-INPUT fields

| Field | Source | Behavior when missing |
|---|---|---|
| `information_flows[]` | tracker `mas_info_flows` table OR derived from inventory edges | when no rows AND no derivable edges → marker `information_flows.empty`; section in .docx shows REQUIRES-OPERATOR-INPUT box |
| `metadata_in_scope[]` | tracker `mas_metadata_in_scope` table | marker `metadata_in_scope.empty` |
| `third_party_resources[].contract_id` | tracker `mas_third_party_contracts` table | per-row marker `third_party_resources[<entity>].contract_id` |
| `data_types[]` per resource | inventory tag `fedramp_data_types` OR tracker UI | empty array allowed; per-resource marker emitted when `handles_federal_data === true` but `data_types` empty |
| `handles_federal_data` per resource | inventory tag `fedramp_handles_federal_data` (boolean) | DEFAULT `false` (REO Rule 4 — never silently assume yes) |
| `security_objectives.{c,i,a}` per resource | SSP `system-characteristics.system-information.information-types[]` aggregated → inventory tag fallback | when ambiguous → per-resource marker |
| `customer_facing` per resource | inventory tag `customer_facing` | DEFAULT `false`; informational only |

## Test specifications (≥13 tests)

1. `it('builds scope JSON from inventory + SSP with one resource per asset')` — assert `information_resources.length === inventory.assets.length`; assert SSP component-uuid cross-ref populated.
2. `it('aggregates inventory by provider×kind when --mas-aggregate flag is set')` — assert row count reduces; assert aggregated `component_uuids[]` is union of contributing assets.
3. `it('emits REQUIRES-OPERATOR-INPUT for information_flows when no tracker rows and no derivable edges')` — flag in `requires_operator_input`; `.docx` §3 shows the marker.
4. `it('embeds reconcileMas drift result in documented_vs_discovered_diff')` — synthetic drift → drift surfaces in JSON + `.docx`.
5. `it('emits one third_party_resources row per registered subprocessor')` — fixture subprocessor list of 3 → output JSON has 3 rows; each row has MAS-CSO-TPR fields populated.
6. `it('REQUIRES-OPERATOR-INPUT for contract_id when no tracker mas_third_party_contracts row')` — marker per-entity.
7. `it('quotes verbatim MAS-CSO-IIR/FLO/MDI/TPR statements in provenance.requirementTexts')` — 4 keys present; values byte-equal to FRMR statements.
8. `it('renders deterministic info-flow SVG with sorted nodes + edges')` — same input twice → identical bytes; mutate one flow → bytes change.
9. `it('writes valid PlantUML source')` — output starts with `@startuml`, ends with `@enduml`, has no duplicate component declarations.
10. `it('respects handles_federal_data tag default=false')` — asset with no tag → `handles_federal_data === false`; asset with tag `fedramp_handles_federal_data=true` → `true`.
11. `it('docx contains the third-party resources table with verbatim MAS-CSO-TPR statement')` — XML body parse; assert FRMR statement substring present.
12. `it('archives prior-period scope-doc for delta tracking when --mas-archive-prior is set')` — moves prior `minimum-assessment-scope.json` to `out/afr-mas/archive/<YYYY-MM>/` before overwriting.
13. `it('cross-references inventory.assets[].arn with SSP components[].props.uuid')` — synthetic SSP with 3 components → resource rows populate `component_uuids[]` correctly.
14. `it('reads subprocessor risk-tier from subprocessors-sheet.ts mapping')` — fixture with 1 high-risk subprocessor → row has `supply_chain_risk_tier === 'high'`.

## REO compliance specific to this slice

- `information_resources[]` is derived strictly from real `out/inventory.json`; no synthetic resources. If inventory is empty → orchestrator exits 4 in `--strict-bundle` mode.
- `documented_vs_discovered_diff` comes from `mas-reconcile.ts` (pure set diff). Drift items aren't silently reconciled — they surface as findings in the SAR.
- `handles_federal_data` DEFAULTS FALSE per REO Rule 4 — operator must explicitly tag `fedramp_handles_federal_data=true`; the system never silently assumes yes.
- `third_party_resources[].contract_id` is operator-only (contracts aren't in cloud SDKs). REQUIRES-OPERATOR-INPUT per row when missing.
- Every value in the scope JSON traces to: (a) inventory.json row, (b) SSP component, (c) tracker DB row, or (d) REQUIRES-OPERATOR-INPUT marker.
- `provenance.requirementTexts` carries 4 verbatim MAS MUSTs so a 3PAO cites them from the artifact.
- Signed by: existing `core/sign.ts` Ed25519 + RFC 3161 pipeline.
- No silent fallback diagrams — SVG with zero resources emits a REQUIRES-OPERATOR-INPUT block; never renders a "sample" architecture.

## Verification commands

```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/afr-mas.test.ts
npm test -- tracker/server/routes/afr-mas.test.ts
npm test -- tracker/client/src/pages/MasScope.test.tsx
npm run check:reo
```

End-to-end smoke:
```bash
npm run collect -- --impact-level moderate --afr-mas --submission-bundle --sign
ls -la out/afr-mas/
# Verify all 5 artifacts present, each manifest-listed + signed
```

## Known risks / issues

- **Risk 1: Inventory volume explosion in the .docx.** A real-world inventory of >500 assets yields a giant table that breaks Word rendering on smaller machines. *Mitigation*: `--mas-aggregate` flag groups by `provider×kind`; `--mas-max-rows N` truncates with a "view machine-readable JSON for full list" footer. Default: aggregate when assets>100.
- **Risk 2: PlantUML grammar drift.** PlantUML versions occasionally break older syntax. *Mitigation*: emit the most-stable subset (`component`, `-->`); test against a grammar sanity regex (no full PlantUML parser dep). Operator may regenerate SVG with their own PlantUML; the SVG we ship is the always-valid fallback.
- **Risk 3: Information-flow auto-derivation false positives.** Auto-deriving "S3 → Lambda" from SDK metadata can mark a flow that doesn't actually carry federal data. *Mitigation*: derived flows are tagged `derived: true` in the JSON; the .docx renders them in a separate "Auto-derived (verify)" subsection so the operator confirms.
- **Risk 4: Subprocessor row drift between sheet + tracker.** The Google Sheets backing `subprocessors-sheet.ts` may go out of sync with the tracker's `mas_third_party_contracts` table (e.g. a contract is signed but the sheet hasn't been updated). *Mitigation*: emit a `subprocessor_sync.json` sidecar listing entries-in-tracker-not-in-sheet and vice versa; surface as a finding.
- **Risk 5: `handles_federal_data` mass-misclassification.** If the operator doesn't tag any asset, the scope doc declares "0 resources handle federal data" — which 3PAO will reject. *Mitigation*: console summary on `--afr-mas` run prints "X of Y assets tagged handles_federal_data"; orchestrator emits a high-severity diagnostic when ratio < 5%.
- **Risk 6: Cross-resource UUID alignment with SSP.** SSP components are operator-named; inventory assets carry arns/ids. *Mitigation*: match by `arn ∈ component.props['inventory-arn']` OR `name === component.title`; fallback to fuzzy match flagged as such; emit drift report.
- **Risk 7: SVG layout becomes unreadable past ~30 nodes.** Hand-rolled grid layout doesn't do edge routing. *Mitigation*: switch SVG to a force-directed layout in a follow-up (pure JS via Barnes-Hut quad-tree); for v1 the `.puml` is the production-quality alternative for large graphs.

## Open questions (for implementation session to resolve)

- **Q1**: Should auto-derived information flows be opt-in (`--mas-derive-flows`) or default-on? Recommendation: default-on but always tagged `derived: true`; operator confirms via tracker.
- **Q2**: How do we cross-reference Azure assets (Resource Manager IDs) vs AWS arns vs GCP self-links when SSP component naming differs? Recommendation: define a `InventoryRef` union type `{ kind: 'arn'|'self-link'|'resource-id', value: string }` and require SSP components carry `props['inventory-ref']` with that shape.
- **Q3**: Does the scope `.docx` need digital signing as a Word property or is the OOXML payload signed by `core/sign.ts` sufficient? Recommendation: latter — same as RoE; never embed signatures inside docx (Word handles this poorly and signatures churn).
- **Q4**: Should `third-party-resources.json` include subprocessor risk tier source (sheet vs tracker)? Recommendation: yes, add `risk_tier_source: 'sheet'|'tracker'|'operator'` for provenance.
- **Q5**: What's the canonical resource id format? Recommendation: `sha256(provider + ':' + kind + ':' + arn-or-id).slice(0, 16)` — short stable ID immune to tag changes.
- **Q6**: Do we ship a JSON Schema (Draft 2020-12) for `MasScopeJson`? Recommendation: yes — emit alongside under `out/afr-mas/minimum-assessment-scope.schema.json` so 3PAO can ajv-validate.
- **Q7**: How do we handle a subprocessor that goes from `authorized` to `in-process` on Marketplace mid-period? Recommendation: archive snapshots per period (links to LOOP-H.H2 retention); the current scope JSON always reflects "as-of generated_at".

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)

The implementing session MUST check every box:
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ~18 for this slice: 14 unit + 4 route/UI)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (slice row + Overall section: increment next-priority to G.G5)
- [ ] LOOP-G-SPEC.md §7 status table updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added under `### Added — LOOP-G.G4: AFR-MAS (Minimum Assessment Scope)`
- [ ] Commit with `LOOP-G.G4:` in message
- [ ] Commit amended with commit hash recorded in STATUS.md + this file + LOOP-G-SPEC.md
- [ ] Pushed to origin/main
- [ ] AFR-MAS-RUNBOOK.md authored
- [ ] End-to-end orchestrator smoke produces all 5 `out/afr-mas/` artifacts + manifest entries

## Resume-from-fresh-session checklist

If a session opens with ONLY this file as context, here's everything it needs to start:
1. Read `cloud-evidence/CLAUDE.md` (REO standard, auto-loaded).
2. This file gives you: source obligations + files to create + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-G-SPEC.md` §2 (Dependencies) + §4 G.G4 + §6 caveats.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory commit pattern.
5. Read `cloud-evidence/core/roe-emit.ts` + `core/ssp-docx.ts` for the dependency-free .docx + OOXML pattern.
6. Read `cloud-evidence/core/zip.ts` for `zipStore` helper used by .docx emit.
7. Read `cloud-evidence/core/mas-reconcile.ts` for the documented-vs-discovered diff shape we embed.
8. Read `cloud-evidence/core/subprocessors-sheet.ts` for the subprocessor list shape.
9. Read `cloud-evidence/core/inventory-coverage.ts` for the coverage contract pattern (mirrored for resource-coverage in this slice).
10. Read `cloud-evidence/core/submission-bundle.ts` for catalogue-row pattern.
11. Begin implementation; update Implementation log section as you go.
